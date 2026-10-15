//! The hub's client API: how a job producer — `vk-gitlab` first, `vk submit` later — asks
//! for capacity, reserves it, submits jobs and follows them. HTTP/1.1 and JSON over TLS 1.3 on
//! the hub's node listener, versioned by its `/v1/` paths under the same rule as enrollment:
//! once released, a path's bodies only gain optional fields.
//!
//! Every request carries an API key as `authorization: Bearer <key>` ([`AUTHORIZATION`]); the
//! key is the principal its jobs are recorded under, and the hub's policy for it decides the
//! pools it may use and the largest envelope it may ask for. A request that creates something
//! carries a client-generated `request_id` ([`valid_id`](crate::valid_id)). Reusing the ID
//! returns the original answer without creating another reservation or job, so the client
//! can retry after losing an answer. Failed requests return [`ClientError`].
//!
//! A client may also name its instance in [`INSTANCE_HEADER`] on every request, and describe
//! it with a [`ClientHello`] at start and about every minute, so the hub can tell apart the
//! daemons sharing one key. Both are optional: a hub records a request without the header,
//! or with a malformed one, under its key alone, and a hub that predates [`CLIENTS_PATH`]
//! ignores the header and answers a hello with a plain 404.
//!
//! | Request | Body | Answer |
//! |---|---|---|
//! | `POST` [`CAPACITY_PATH`] | [`CapacityRequest`] | 200 [`Capacity`] |
//! | `POST` [`RESERVATIONS_PATH`] | [`ReservationRequest`] | 201 [`ReservationGrant`] |
//! | `POST` [`RESERVATIONS_PATH`]`/<id>/renew` | [`RenewRequest`] | 200 [`ReservationGrant`] |
//! | `DELETE` [`RESERVATIONS_PATH`]`/<id>` | — | 204 |
//! | `POST` [`JOBS_PATH`] | [`JobSubmission`] | 201 [`JobView`] |
//! | `GET` [`JOBS_PATH`]`/<id>?after=<revision>&wait=<secs>` | — | 200 [`JobView`] |
//! | `GET` [`JOBS_PATH`]`/<id>/output?offset=<n>&wait=<secs>` | — | 200 the output's bytes |
//! | `POST` [`JOBS_PATH`]`/<id>/cancel` | [`CancelRequest`] | 202 [`JobView`] |
//! | `POST` [`JOBS_PATH`]`/<id>/settle` | — | 204 |
//! | `POST` [`CLIENTS_PATH`] | [`ClientHello`] | 204 |
//!
//! `wait` on the two `GET`s, and `wait_secs` in a [`CapacityRequest`], make a request
//! long-poll for at most that many seconds, capped at [`MAX_WAIT_SECS`]: a job view returns
//! once its revision passes `after`, output once there are bytes past `offset` or the output
//! is complete, capacity once its revision passes `after`. A long poll that times out
//! answers as a plain request would.

use serde::{Deserialize, Serialize};

pub use crate::dispatch::CancelMode;
use crate::job::{Envelope, JobResult, JobSpec};

pub const CAPACITY_PATH: &str = "/v1/capacity";
/// Followed by `/<id>` for one reservation.
pub const RESERVATIONS_PATH: &str = "/v1/reservations";
/// Followed by `/<id>` for one job.
pub const JOBS_PATH: &str = "/v1/jobs";
pub const CLIENTS_PATH: &str = "/v1/clients";

/// The header an API key rides in, as `Bearer <key>`.
pub const AUTHORIZATION: &str = "authorization";

/// The header naming the client instance a request comes from ([`valid_instance`]).
pub const INSTANCE_HEADER: &str = "vk-client-instance";

/// The longest instance name, in bytes ([`valid_instance`]).
pub const MAX_INSTANCE_LEN: usize = 64;

/// The most runners one [`ClientHello`] lists.
pub const MAX_CLIENT_RUNNERS: usize = 64;

/// The most labels one [`ClientRunner`] lists.
pub const MAX_CLIENT_RUNNER_LABELS: usize = 32;

/// On an output answer: the offset of its first byte.
pub const OUTPUT_OFFSET_HEADER: &str = "vk-output-offset";
/// On an output answer, and a 416 for an offset past the end: the output's length so far.
pub const OUTPUT_LENGTH_HEADER: &str = "vk-output-length";
/// On an output answer: `true` once the job has ended and the answer reaches the end of its
/// output — nothing more will follow.
pub const OUTPUT_COMPLETE_HEADER: &str = "vk-output-complete";

/// The longest a request long-polls.
pub const MAX_WAIT_SECS: u32 = 60;

/// The most bytes one output answer carries.
pub const MAX_OUTPUT_READ: usize = 1 << 20;

/// Where a producer wants work to run: its pool, labels each node must carry, and the
/// envelope one job takes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    pub pool: String,
    #[serde(default)]
    pub labels: Vec<String>,
    pub envelope: Envelope,
}

/// `POST` [`CAPACITY_PATH`]: is there room for this placement?
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapacityRequest {
    pub placement: Placement,
    /// Wait for a revision past this one; `None` answers at once.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    #[serde(default)]
    pub wait_secs: u32,
}

/// The hub's estimate of how many jobs of a placement its ready nodes could take now: their
/// latest heartbeats, less the reservations and starting jobs those do not show yet.
/// Advisory: only a reservation holds anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capacity {
    /// Moves whenever `fits` does.
    pub revision: u64,
    pub fits: u32,
}

/// `POST` [`RESERVATIONS_PATH`]: set one envelope aside on a node of the placement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationRequest {
    pub request_id: String,
    pub placement: Placement,
    /// At most [`MAX_LEASE_SECS`](crate::dispatch::MAX_LEASE_SECS).
    pub lease_secs: u32,
    /// How long the hub may spend finding a node that accepts before it answers
    /// [`ErrorCode::NoCapacity`].
    #[serde(default)]
    pub wait_secs: u32,
}

/// A reservation a node holds for the client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationGrant {
    pub reservation: String,
    pub node: String,
    pub envelope: Envelope,
    /// The lease the node granted. It runs on the node's clock from when the node accepted,
    /// so a client counts it from when it sent its request.
    pub lease_secs: u32,
}

/// `POST` [`RESERVATIONS_PATH`]`/<id>/renew`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewRequest {
    pub lease_secs: u32,
}

/// `POST` [`JOBS_PATH`]: run a job.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSubmission {
    pub request_id: String,
    pub placement: Placement,
    /// A reservation of the client's to start the job on. When it is gone, the hub places
    /// the job afresh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation: Option<String>,
    /// How long the job may wait to be placed before it ends as
    /// [`FailureClass::NoCapacity`](crate::job::FailureClass::NoCapacity).
    pub place_within_secs: u32,
    pub spec: JobSpec,
}

/// A job as the hub knows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobView {
    pub id: String,
    /// Moves with every change below but the output's length.
    pub revision: u64,
    pub state: JobState,
    /// The node it is placed on, once it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// The stage it is in while running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// How much output the hub holds.
    pub output_len: u64,
    /// The cancellation asked for, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancel: Option<CancelMode>,
    /// Present once finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<JobResult>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Waiting to be placed.
    Queued,
    /// Sent to its node, not yet accepted.
    Starting,
    Running,
    /// Ended, its [`JobResult`] known — a hub that lost the job's node past its grace, or
    /// lost the job before it started, ends it as
    /// [`FailureClass::Lost`](crate::job::FailureClass::Lost).
    Finished,
    #[serde(other)]
    Other,
}

/// `POST` [`JOBS_PATH`]`/<id>/cancel`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CancelRequest {
    pub mode: CancelMode,
}

/// `POST` [`CLIENTS_PATH`]: what one instance of a client is. Informational: the hub shows
/// it, and decides nothing on it. Its strings are shown cut to
/// [`MAX_DISPLAY`](crate::MAX_DISPLAY); a longer one is not an error.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// The instance's name, as its requests carry it in [`INSTANCE_HEADER`]; a hello whose
    /// name fails [`valid_instance`] is refused.
    pub instance: String,
    /// The client program, such as `vk-gitlab`.
    pub program: String,
    pub version: String,
    pub hostname: String,
    /// How many jobs the instance runs at once, when it has such a limit: gitlab-runner's
    /// global `concurrent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concurrent: Option<u32>,
    /// At most [`MAX_CLIENT_RUNNERS`]; a hello with more is refused.
    #[serde(default)]
    pub runners: Vec<ClientRunner>,
}

/// One runner a [`ClientHello`] reports: where the instance takes jobs from and the pool it
/// sends them to. Never a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientRunner {
    pub name: String,
    /// The server it takes jobs from, without credentials, query or fragment.
    pub url: String,
    pub pool: String,
    /// At most [`MAX_CLIENT_RUNNER_LABELS`]; a hello with more is refused.
    #[serde(default)]
    pub labels: Vec<String>,
    /// How many of its jobs run at once, when limited: the runner's `limit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Whether `s` may name a client instance: 1 to [`MAX_INSTANCE_LEN`] bytes, each an ASCII
/// letter, digit, `.`, `_` or `-`, the first a letter or digit.
pub fn valid_instance(s: &str) -> bool {
    (1..=MAX_INSTANCE_LEN).contains(&s.len())
        && s.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Any failed client request's body: [`ErrorBody`](crate::ErrorBody)'s `error`, and a code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientError {
    pub error: String,
    pub code: ErrorCode,
    /// When to try again, for [`ErrorCode::NoCapacity`] and [`ErrorCode::Unavailable`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// 401: no key, or not one the hub knows: expired or revoked.
    Unauthorized,
    /// 403: the key's policy does not allow this pool, envelope or job.
    Forbidden,
    /// 404.
    NotFound,
    /// 400: a body that does not parse, or a malformed ID.
    Invalid,
    /// 409: a `request_id` used before with another body.
    Conflict,
    /// 503: no node accepted within `wait_secs`.
    NoCapacity,
    /// 410: the reservation lapsed, was released, or its node was lost.
    ReservationGone,
    /// 413: a job spec over [`MAX_JOB_SPEC`](crate::job::MAX_JOB_SPEC).
    TooLarge,
    /// 503: the hub cannot serve this now; retry after the delay.
    Unavailable,
    /// 500.
    Internal,
    /// A code from a later hub.
    #[serde(other)]
    Other,
}

impl ErrorCode {
    /// Whether the same request may succeed later.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            ErrorCode::NoCapacity | ErrorCode::Unavailable | ErrorCode::Internal
        )
    }
}

#[cfg(test)]
mod tests {
    use serde::de::DeserializeOwned;
    use serde_json::json;

    use super::*;
    use crate::job::FailureClass;

    fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(value: &T) {
        let json = serde_json::to_string(value).unwrap();
        assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), value, "{json}");
    }

    fn placement() -> Placement {
        Placement {
            pool: "ci".into(),
            labels: vec!["large-memory".into()],
            envelope: Envelope {
                mem_mib: 16384,
                cpus: 8,
                disk_bytes: 16 << 30,
            },
        }
    }

    fn hello() -> ClientHello {
        ClientHello {
            instance: "s_0123456789ab".into(),
            program: "vk-gitlab".into(),
            version: "0.91.1".into(),
            hostname: "ci-1".into(),
            concurrent: Some(4),
            runners: vec![ClientRunner {
                name: "docker".into(),
                url: "https://gitlab.example.com".into(),
                pool: "ci".into(),
                labels: vec!["large-memory".into()],
                limit: Some(2),
            }],
        }
    }

    #[test]
    fn every_body_round_trips() {
        round_trip(&CapacityRequest {
            placement: placement(),
            after: Some(7),
            wait_secs: 30,
        });
        round_trip(&Capacity {
            revision: 8,
            fits: 3,
        });
        round_trip(&ReservationRequest {
            request_id: "1".repeat(32),
            placement: placement(),
            lease_secs: 90,
            wait_secs: 10,
        });
        round_trip(&ReservationGrant {
            reservation: "a".repeat(32),
            node: "c".repeat(32),
            envelope: placement().envelope,
            lease_secs: 90,
        });
        round_trip(&RenewRequest { lease_secs: 90 });
        round_trip(&JobSubmission {
            request_id: "2".repeat(32),
            placement: placement(),
            reservation: Some("a".repeat(32)),
            place_within_secs: 300,
            spec: JobSpec::GitlabCi(crate::job::tests::ci_job()),
        });
        round_trip(&JobView {
            id: "b".repeat(32),
            revision: 4,
            state: JobState::Finished,
            node: Some("c".repeat(32)),
            stage: None,
            output_len: 8192,
            cancel: Some(CancelMode::Immediate),
            result: Some(JobResult {
                failure: Some(FailureClass::Lost),
                exit_code: None,
                message: Some("node lost".into()),
                output_len: 8192,
                artifacts: vec![],
                usage: None,
                events: Vec::new(),
            }),
        });
        round_trip(&CancelRequest {
            mode: CancelMode::Graceful,
        });
        round_trip(&hello());
        round_trip(&ClientError {
            error: "no node took it".into(),
            code: ErrorCode::NoCapacity,
            retry_after_secs: Some(5),
        });
    }

    #[test]
    fn bodies_keep_their_wire_shape() {
        let request = ReservationRequest {
            request_id: "1".repeat(32),
            placement: placement(),
            lease_secs: 90,
            wait_secs: 10,
        };
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({
                "request_id": "1".repeat(32),
                "placement": {
                    "pool": "ci",
                    "labels": ["large-memory"],
                    "envelope": {"mem_mib": 16384, "cpus": 8, "disk_bytes": 16u64 << 30},
                },
                "lease_secs": 90,
                "wait_secs": 10,
            })
        );
        let view = JobView {
            id: "b".repeat(32),
            revision: 2,
            state: JobState::Running,
            node: Some("c".repeat(32)),
            stage: Some("step_script".into()),
            output_len: 10,
            cancel: None,
            result: None,
        };
        assert_eq!(
            serde_json::to_value(view).unwrap(),
            json!({
                "id": "b".repeat(32),
                "revision": 2,
                "state": "running",
                "node": "c".repeat(32),
                "stage": "step_script",
                "output_len": 10,
            })
        );
        let error = ClientError {
            error: "gone".into(),
            code: ErrorCode::ReservationGone,
            retry_after_secs: None,
        };
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            json!({"error": "gone", "code": "reservation_gone"})
        );
        assert_eq!(
            serde_json::to_value(hello()).unwrap(),
            json!({
                "instance": "s_0123456789ab",
                "program": "vk-gitlab",
                "version": "0.91.1",
                "hostname": "ci-1",
                "concurrent": 4,
                "runners": [{
                    "name": "docker",
                    "url": "https://gitlab.example.com",
                    "pool": "ci",
                    "labels": ["large-memory"],
                    "limit": 2,
                }],
            })
        );
        let mut bare = hello();
        bare.concurrent = None;
        bare.runners[0].limit = None;
        let bare = serde_json::to_value(bare).unwrap();
        assert!(bare.get("concurrent").is_none(), "{bare}");
        assert!(bare["runners"][0].get("limit").is_none(), "{bare}");
    }

    #[test]
    fn a_client_error_reads_as_an_error_body_and_unknown_codes_as_other() {
        let body: crate::ErrorBody =
            serde_json::from_value(json!({"error": "nope", "code": "forbidden"})).unwrap();
        assert_eq!(body.error, "nope");
        let error: ClientError =
            serde_json::from_value(json!({"error": "later", "code": "quota_exceeded"})).unwrap();
        assert_eq!(error.code, ErrorCode::Other);
        assert!(!error.code.is_retryable());
        assert!(ErrorCode::NoCapacity.is_retryable());
    }

    #[test]
    fn requests_read_without_their_optional_fields() {
        let request: CapacityRequest = serde_json::from_value(json!({
            "placement": {"pool": "ci", "envelope": {"mem_mib": 1, "cpus": 1, "disk_bytes": 1}},
        }))
        .unwrap();
        assert_eq!(request.after, None);
        assert!(request.placement.labels.is_empty());
        let state: JobState = serde_json::from_value(json!("suspended")).unwrap();
        assert_eq!(state, JobState::Other);
        let hello: ClientHello = serde_json::from_value(json!({
            "instance": "s_0123456789ab",
            "program": "vk-gitlab",
            "version": "0.91.1",
            "hostname": "ci-1",
        }))
        .unwrap();
        assert_eq!(hello.concurrent, None);
        assert!(hello.runners.is_empty());
        let runner: ClientRunner = serde_json::from_value(json!({
            "name": "docker", "url": "https://gitlab.example.com", "pool": "ci",
        }))
        .unwrap();
        assert!(runner.labels.is_empty());
        assert_eq!(runner.limit, None);
    }

    #[test]
    fn instance_names_are_short_and_plain() {
        for good in [
            "s_0123456789ab",
            "r_AbC",
            "ci-1.example",
            &"a".repeat(MAX_INSTANCE_LEN),
        ] {
            assert!(valid_instance(good), "{good}");
        }
        for bad in [
            "",
            &"a".repeat(MAX_INSTANCE_LEN + 1),
            "a b",
            "a/b",
            "é",
            "a\n",
            ".",
            "..",
            "-x",
            "_x",
        ] {
            assert!(!valid_instance(bad), "{bad:?}");
        }
    }
}
