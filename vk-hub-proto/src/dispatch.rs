//! What a hub and a node exchange from protocol version [`JOBS`](crate::JOBS) to place jobs:
//! [`HubJobMsg`] inside [`HubMsg::Job`](crate::HubMsg::Job) one way, [`NodeJobMsg`] inside
//! [`NodeMsg::Job`](crate::NodeMsg::Job) the other.
//!
//! **Reservations.** The hub offers a node an [`Envelope`] for a lease ([`HubJobMsg::Offer`]);
//! the node decides through its admission ledger, at once, without queueing behind other
//! asks, and answers [`NodeJobMsg::OfferReply`]. A lease is a duration counted on the node's
//! own monotonic clock from the moment it accepts; no wall-clock time crosses the wire. The
//! hub extends it with [`HubJobMsg::Renew`] and gives it back with [`HubJobMsg::Release`];
//! the node reports each lease's end with [`NodeJobMsg::Lease`], including expiry without
//! renewal. A job started on a reservation takes it over: the ledger entry
//! becomes the job's, sized to what the job turns out to need.
//!
//! **Jobs.** [`HubJobMsg::Start`] hands the node a job, which it journals before answering
//! [`NodeJobMsg::Job`] `accepted`, so a start redelivered after a reconnect is recognized by
//! its ID. Output goes up as [`NodeJobMsg::Output`] chunks at byte offsets; the hub acks the
//! offset it has stored durably ([`HubJobMsg::OutputAck`]) and the node keeps everything
//! past the last ack, resending it from there in the next session. The node sends the
//! [`JobResult`] once the job's output is all acked, and repeats it until the hub answers
//! [`HubJobMsg::Recorded`]. [`HubJobMsg::Cancel`] stops a job.
//!
//! **Reconnects.** A session at version [`JOBS`](crate::JOBS) opens, after the report, with
//! [`NodeJobMsg::Held`]: every reservation and job the node holds. The hub releases a
//! reservation it no longer wants, cancels a job it has given up on, and answers each job's
//! output with the offset it stored, from which the node resends.

use serde::{Deserialize, Serialize};

use crate::job::{Envelope, JobResult, JobSpec};

/// The longest lease a node grants; a longer ask is cut to it.
pub const MAX_LEASE_SECS: u32 = 600;

/// The most output bytes one [`NodeJobMsg::Output`] carries, before base64.
pub const MAX_OUTPUT_CHUNK: usize = 256 * 1024;

/// The maximum unacked output in bytes. At this limit, the node waits for an ack before
/// sending more.
pub const OUTPUT_WINDOW: u64 = 4 << 20;

/// Hub → node, from version [`JOBS`](crate::JOBS).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HubJobMsg {
    /// Set `envelope` aside for `lease_secs`. Answered with [`NodeJobMsg::OfferReply`].
    Offer {
        /// The reservation's ID, the hub's ([`valid_id`](crate::valid_id)).
        reservation: String,
        envelope: Envelope,
        lease_secs: u32,
    },
    /// Extend a lease to `lease_secs` from now, on the node's clock. Answered with
    /// [`NodeJobMsg::Lease`].
    Renew {
        reservation: String,
        lease_secs: u32,
    },
    /// Give a reservation back. Answered with [`NodeJobMsg::Lease`] `gone`.
    Release { reservation: String },
    /// Run a job. Answered with [`NodeJobMsg::Job`].
    Start(Box<JobStart>),
    /// The hub has stored this job's output durably up to `offset`.
    OutputAck { job: String, offset: u64 },
    /// Stop a job.
    Cancel { job: String, mode: CancelMode },
    /// The hub has stored this job's result; the node stops repeating it and may drop the
    /// job's output.
    Recorded { job: String },
}

/// A job for a node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobStart {
    /// The job's ID, the hub's ([`valid_id`](crate::valid_id)).
    pub job: String,
    /// The reservation the job takes over; `None` for a job placed without one, which the
    /// node admits like any other ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation: Option<String>,
    /// What the hub placed the job for. The node sizes the job by its own rules, from the
    /// spec; a job needing more than this waits for the rest in the ledger, and one needing
    /// less hands the difference back.
    pub envelope: Envelope,
    pub spec: JobSpec,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CancelMode {
    /// GitLab's `canceling`: stop the running step, run `after_script`, then end the job as
    /// canceled. Caches and artifacts are not archived.
    Graceful,
    /// Stop the job's processes and VM now; nothing more of it runs or uploads.
    Immediate,
    /// A mode from a later peer; a receiver treats it as [`CancelMode::Immediate`].
    #[serde(other)]
    Other,
}

/// Node → hub, from version [`JOBS`](crate::JOBS).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeJobMsg {
    /// Every reservation and job the node holds, sent once per session after its report.
    Held(Held),
    /// The node's answer to [`HubJobMsg::Offer`].
    OfferReply {
        reservation: String,
        reply: OfferReply,
    },
    /// Where a lease stands: after a renew or a release, and when it lapses or is taken
    /// over by a job.
    Lease {
        reservation: String,
        state: LeaseState,
    },
    /// Where a job stands: after a start, and at each stage.
    Job { job: String, state: RunState },
    /// The job's output from `offset`, base64. Offsets count bytes of the output as the job's
    /// readers see it: masked, with section markers, cut at the trace limit.
    Output {
        job: String,
        offset: u64,
        data: String,
    },
    /// How the job ended; repeated until [`HubJobMsg::Recorded`].
    Result { job: String, result: JobResult },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    pub reservations: Vec<HeldReservation>,
    pub jobs: Vec<HeldJob>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldReservation {
    pub reservation: String,
    pub envelope: Envelope,
    pub remaining_secs: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldJob {
    pub job: String,
    pub state: RunState,
    /// The output's length so far.
    pub output_len: u64,
    /// Whether the job has ended and its result is waiting for [`HubJobMsg::Recorded`].
    pub finished: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum OfferReply {
    /// Set aside for `lease_secs`, at most [`MAX_LEASE_SECS`].
    Accepted { lease_secs: u32 },
    Refused {
        reason: Refusal,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
}

/// Why a node refused an offer or a job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Refusal {
    /// Not enough memory left in the ledger's budget or on the host.
    Memory,
    Disk,
    Cpus,
    /// Draining, drained, quarantined or in maintenance.
    NotReady,
    /// The node's configuration does not take this kind of job or this envelope.
    Policy,
    /// The reservation a job names is not held: expired, released or never granted.
    NoReservation,
    /// The job's spec could not be read.
    Invalid,
    /// A reason from a later node.
    #[serde(other)]
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LeaseState {
    Held { remaining_secs: u32 },
    Gone { why: LeaseEnd },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseEnd {
    /// Nobody renewed it in time.
    Expired,
    Released,
    /// A job took it over.
    Started,
    /// The node does not know it: never granted, or ended before a restart.
    Unknown,
    #[serde(other)]
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RunState {
    /// Journaled; admission and preparation under way.
    Accepted,
    /// Not taken; the job ran nowhere and the hub may place it elsewhere.
    Refused {
        reason: Refusal,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// In `stage`, named as gitlab-runner names its build stages: `prepare_executor`,
    /// `get_sources`, `restore_cache`, `download_artifacts`, `step_<name>`, `after_script`,
    /// `archive_cache`, `upload_artifacts_on_success` and so on.
    Running { stage: String },
    /// Ended; the result follows in [`NodeJobMsg::Result`].
    Finished,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::job::{ArtifactOutcome, FailureClass, UploadState};
    use crate::{HubMsg, NodeMsg};

    fn envelope() -> Envelope {
        Envelope {
            mem_mib: 8192,
            cpus: 4,
            disk_bytes: 8 << 30,
        }
    }

    fn id(c: &str) -> String {
        c.repeat(32)
    }

    fn hub_messages() -> Vec<HubJobMsg> {
        vec![
            HubJobMsg::Offer {
                reservation: id("a"),
                envelope: envelope(),
                lease_secs: 90,
            },
            HubJobMsg::Renew {
                reservation: id("a"),
                lease_secs: 90,
            },
            HubJobMsg::Release {
                reservation: id("a"),
            },
            HubJobMsg::Start(Box::new(JobStart {
                job: id("b"),
                reservation: Some(id("a")),
                envelope: envelope(),
                spec: JobSpec::GitlabCi(crate::job::tests::ci_job()),
            })),
            HubJobMsg::OutputAck {
                job: id("b"),
                offset: 4096,
            },
            HubJobMsg::Cancel {
                job: id("b"),
                mode: CancelMode::Graceful,
            },
            HubJobMsg::Recorded { job: id("b") },
        ]
    }

    fn node_messages() -> Vec<NodeJobMsg> {
        vec![
            NodeJobMsg::Held(Held {
                reservations: vec![HeldReservation {
                    reservation: id("a"),
                    envelope: envelope(),
                    remaining_secs: 30,
                }],
                jobs: vec![HeldJob {
                    job: id("b"),
                    state: RunState::Running {
                        stage: "step_script".into(),
                    },
                    output_len: 8192,
                    finished: false,
                }],
            }),
            NodeJobMsg::OfferReply {
                reservation: id("a"),
                reply: OfferReply::Accepted { lease_secs: 90 },
            },
            NodeJobMsg::OfferReply {
                reservation: id("c"),
                reply: OfferReply::Refused {
                    reason: Refusal::Memory,
                    message: Some("6 GiB of 8 left".into()),
                },
            },
            NodeJobMsg::Lease {
                reservation: id("a"),
                state: LeaseState::Gone {
                    why: LeaseEnd::Started,
                },
            },
            NodeJobMsg::Job {
                job: id("b"),
                state: RunState::Accepted,
            },
            NodeJobMsg::Output {
                job: id("b"),
                offset: 0,
                data: crate::to_base64(b"$ cargo test\n"),
            },
            NodeJobMsg::Result {
                job: id("b"),
                result: JobResult {
                    failure: Some(FailureClass::Script),
                    exit_code: Some(101),
                    message: None,
                    output_len: 8192,
                    artifacts: vec![ArtifactOutcome {
                        name: "artifacts".into(),
                        artifact_type: "archive".into(),
                        state: UploadState::Skipped,
                    }],
                    usage: None,
                },
            },
        ]
    }

    #[test]
    fn every_job_message_round_trips_in_the_session() {
        for msg in hub_messages() {
            let wrapped = HubMsg::Job(msg);
            let json = serde_json::to_string(&wrapped).unwrap();
            assert!(json.len() < crate::MAX_MESSAGE);
            assert_eq!(
                serde_json::from_str::<HubMsg>(&json).unwrap(),
                wrapped,
                "{json}"
            );
        }
        for msg in node_messages() {
            let wrapped = NodeMsg::Job(msg);
            let json = serde_json::to_string(&wrapped).unwrap();
            assert_eq!(
                serde_json::from_str::<NodeMsg>(&json).unwrap(),
                wrapped,
                "{json}"
            );
        }
    }

    #[test]
    fn job_messages_keep_their_wire_shape() {
        let offer = HubMsg::Job(hub_messages().remove(0));
        assert_eq!(
            serde_json::to_value(offer).unwrap(),
            json!({
                "type": "job",
                "kind": "offer",
                "reservation": id("a"),
                "envelope": {"mem_mib": 8192, "cpus": 4, "disk_bytes": 8u64 << 30},
                "lease_secs": 90,
            })
        );
        let refused = NodeMsg::Job(node_messages().remove(2));
        assert_eq!(
            serde_json::to_value(refused).unwrap(),
            json!({
                "type": "job",
                "kind": "offer_reply",
                "reservation": id("c"),
                "reply": {"state": "refused", "reason": "memory", "message": "6 GiB of 8 left"},
            })
        );
        let output = NodeMsg::Job(node_messages().remove(5));
        assert_eq!(
            serde_json::to_value(output).unwrap(),
            json!({
                "type": "job",
                "kind": "output",
                "job": id("b"),
                "offset": 0,
                "data": "JCBjYXJnbyB0ZXN0Cg==",
            })
        );
        let result = NodeMsg::Job(node_messages().remove(6));
        assert_eq!(
            serde_json::to_value(result).unwrap(),
            json!({
                "type": "job",
                "kind": "result",
                "job": id("b"),
                "result": {
                    "failure": "script",
                    "exit_code": 101,
                    "output_len": 8192,
                    "artifacts": [{"name": "artifacts", "artifact_type": "archive", "state": "skipped"}],
                },
            })
        );
        let start = serde_json::to_value(HubMsg::Job(hub_messages().remove(3))).unwrap();
        assert_eq!(start["kind"], "start");
        assert_eq!(start["spec"]["kind"], "gitlab_ci");
    }

    #[test]
    fn reasons_and_ends_from_a_later_node_read_as_other() {
        let reply: OfferReply =
            serde_json::from_value(json!({"state": "refused", "reason": "gpu"})).unwrap();
        assert_eq!(
            reply,
            OfferReply::Refused {
                reason: Refusal::Other,
                message: None
            }
        );
        let end: LeaseEnd = serde_json::from_value(json!("preempted")).unwrap();
        assert_eq!(end, LeaseEnd::Other);
    }

    #[test]
    fn a_cancel_mode_from_a_later_peer_reads_as_other() {
        let mode: CancelMode = serde_json::from_value(json!("abort")).unwrap();
        assert_eq!(mode, CancelMode::Other);
    }

    #[test]
    fn an_output_chunk_fits_a_message() {
        let data = crate::to_base64(&vec![0xff; MAX_OUTPUT_CHUNK]);
        let msg = NodeMsg::Job(NodeJobMsg::Output {
            job: id("b"),
            offset: u64::MAX,
            data,
        });
        assert!(serde_json::to_string(&msg).unwrap().len() < crate::MAX_MESSAGE);
    }
}
