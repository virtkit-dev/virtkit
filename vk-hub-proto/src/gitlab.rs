//! What `vk-gitlab` and `vk-hub` exchange when `vk-gitlab` runs as a relay: a peer that
//! takes jobs from one GitLab server and has the hub run them.
//!
//! A relay enrolls as a node does — `POST` [`ENROLL_PATH`] with an
//! [`EnrollRequest`](crate::EnrollRequest) whose token was issued for a relay, answered with
//! an [`EnrollResponse`] naming the relay's ID — and holds a session at [`SESSION_PATH`] that
//! opens with the handshake every peer shares: [`NodeMsg::Hello`](crate::NodeMsg::Hello) (its
//! `node_id` the relay's ID, its `incarnation` new each time `vk-gitlab` starts, its
//! `vk_version` `vk-gitlab`'s version) → [`HubMsg::Challenge`](crate::HubMsg::Challenge) →
//! [`NodeMsg::Auth`](crate::NodeMsg::Auth) → [`HubMsg::Welcome`](crate::HubMsg::Welcome),
//! versioned by [`PROTOCOL`]. After the welcome the relay sends [`RelayMsg`]s and the hub
//! [`HubRelayMsg`]s. The relay's ID and key live in a table of their own on the hub, so no
//! other peer's enrollment or session is taken for a relay's, nor the reverse.
//!
//! The relay says what it is in an [`Inventory`], on connect and whenever it changes. The hub
//! binds the relay to the GitLab server its first inventory names and answers with that
//! server's [`ServerStatus`], again whenever it changes: a relay polls GitLab only while its
//! server is [`ServerState::Approved`].
//!
//! Jobs do not ride on the session: the relay submits them through the [`client`](crate::client)
//! API, each request signed with its key over
//! [`client_request_message`](crate::client::client_request_message).
//!
//! Version 1 is the first; it follows the crate's rule: only optional fields are added within
//! a version. Version 2 adds capacity arbitration: runners' `request_concurrency` in the
//! inventory, their admission IDs in each heartbeat, and the client API's runner names,
//! queued reservations and admission outcomes, which a relay relies on only once its session
//! negotiated version 2.

use serde::{Deserialize, Serialize};

use crate::client::Placement;
use crate::{RefusalCode, VersionRange, display_safe, valid_sha256};

/// Where a relay enrolls.
pub const ENROLL_PATH: &str = "/v1/gitlab/enroll";

/// Where a relay holds its session.
pub const SESSION_PATH: &str = "/v1/gitlab/session";

/// The protocol versions of a relay's session.
pub const PROTOCOL: VersionRange = VersionRange { min: 1, max: 2 };

/// The relay requires admission-aware scheduling, introduced in version 2.
pub const RELAY_PROTOCOL: VersionRange = VersionRange { min: 2, max: 2 };

/// The most runners an [`Inventory`], a [`Heartbeat`] or a [`Report`] keeps once made
/// display-safe.
pub const MAX_RUNNERS: usize = 64;

/// The most labels a runner's placement keeps once made display-safe.
pub const MAX_LABELS: usize = 32;

/// The most admission IDs a runner's heartbeat keeps in each of its two lists once made
/// display-safe.
pub const MAX_ADMISSIONS: usize = 128;

/// The hub's answer to a relay's enrollment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// The relay's ID ([`valid_id`](crate::valid_id)); its `Hello.node_id`.
    pub relay_id: String,
}

/// A relay's messages after the welcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayMsg {
    /// On connect, and when it changes.
    Inventory(Inventory),
    /// Every heartbeat interval the hub asked for.
    Heartbeat(Heartbeat),
    /// What each runner is doing: on connect and whenever it changes.
    Report(Report),
}

/// The hub's messages after the welcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HubRelayMsg {
    /// What the hub makes of the relay's GitLab server: after each inventory, and whenever
    /// an operator changes it.
    Server(ServerStatus),
    /// The session is ended — the relay was removed, or a newer session took over — and the
    /// connection closes after this. Frozen as [`HubMsg::Refused`](crate::HubMsg::Refused)
    /// is, with the same JSON, so a relay reads it before or after the welcome.
    Refused { code: RefusalCode, reason: String },
}

/// What a relay is: sent on connect and when it changes. Never a token.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    /// `vk-gitlab`'s version.
    pub version: String,
    pub hostname: String,
    /// The system ID it gives GitLab, as gitlab-runner does (`s_` or `r_` and 12
    /// alphanumerics).
    pub system_id: String,
    /// How many jobs it runs at once across its runners: gitlab-runner's global `concurrent`.
    pub concurrent: u32,
    pub server: Server,
    /// At most [`MAX_RUNNERS`].
    #[serde(default)]
    pub runners: Vec<Runner>,
}

/// The GitLab server a relay takes jobs from.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Server {
    /// Its URL, without credentials, query or fragment.
    pub url: String,
    /// The sha256 of its TLS certificate's public key (SPKI), lowercase hex: what an operator
    /// checks when approving the server. `None` over plain http, or before the relay reached
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spki_sha256: Option<String>,
    /// Its version, when known: a runner token cannot ask GitLab for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// One of a relay's runners: a runner token, where its jobs go, and how many at once.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runner {
    /// Its name in the relay's config.
    pub name: String,
    /// GitLab's ID for it, once `verify` gave it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_id: Option<u64>,
    /// The pool, labels and envelope of each of its jobs.
    pub placement: Placement,
    /// How many of its jobs run at once, when limited: the runner's `limit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// How many job requests it keeps open with GitLab at once: the runner's
    /// `request_concurrency`, at least 1. A version-1 inventory lacks it and means 1.
    #[serde(default = "one")]
    pub request_concurrency: u32,
    /// Whether GitLab took its token at the relay's last `verify`.
    pub verified: bool,
}

fn one() -> u32 {
    1
}

impl Inventory {
    /// Apply [`display_safe`] to strings, drop the server's SPKI digest unless
    /// [`valid_sha256`], truncate runners to [`MAX_RUNNERS`] and their labels to
    /// [`MAX_LABELS`], and raise a `request_concurrency` of 0 to 1.
    pub fn make_display_safe(&mut self) {
        for s in [&mut self.version, &mut self.hostname, &mut self.system_id] {
            *s = display_safe(s);
        }
        self.server.url = display_safe(&self.server.url);
        self.server.spki_sha256 = self.server.spki_sha256.take().filter(|s| valid_sha256(s));
        self.server.version = self.server.version.as_deref().map(display_safe);
        self.runners.truncate(MAX_RUNNERS);
        for r in &mut self.runners {
            r.name = display_safe(&r.name);
            r.request_concurrency = r.request_concurrency.max(1);
            r.placement.pool = display_safe(&r.placement.pool);
            r.placement.labels.truncate(MAX_LABELS);
            for l in &mut r.placement.labels {
                *l = display_safe(l);
            }
        }
    }
}

/// A relay's load, every heartbeat.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// At most [`MAX_RUNNERS`].
    #[serde(default)]
    pub runners: Vec<RunnerLoad>,
}

/// One runner's load.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerLoad {
    pub name: String,
    /// Job requests to GitLab outstanding.
    pub requests: u32,
    /// Jobs it holds: taken from GitLab and not yet settled.
    pub jobs: u32,
    /// The admission of each of its `requests` ([`valid_id`](crate::valid_id)). Version 2;
    /// empty from a version-1 relay.
    #[serde(default)]
    pub request_admissions: Vec<String>,
    /// The admission of each of its `jobs`, as above.
    #[serde(default)]
    pub job_admissions: Vec<String>,
    /// When GitLab last answered it, and the HTTP status it answered with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_answer_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<u16>,
}

impl Heartbeat {
    /// Truncate runners to [`MAX_RUNNERS`] and apply [`display_safe`] to their names.
    /// Keep the first [`MAX_ADMISSIONS`] distinct valid IDs in each admission list.
    pub fn make_display_safe(&mut self) {
        self.runners.truncate(MAX_RUNNERS);
        for r in &mut self.runners {
            r.name = display_safe(&r.name);
            for ids in [&mut r.request_admissions, &mut r.job_admissions] {
                let mut seen = std::collections::HashSet::new();
                ids.retain(|id| crate::valid_id(id) && seen.insert(id.clone()));
                ids.truncate(MAX_ADMISSIONS);
            }
        }
    }
}

/// What each of a relay's runners is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// At most [`MAX_RUNNERS`].
    #[serde(default)]
    pub runners: Vec<RunnerReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunnerReport {
    pub name: String,
    pub state: RunnerState,
    /// What went wrong, for [`RunnerState::Unhealthy`] and [`RunnerState::TokenRefused`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// What a runner is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerState {
    /// Asking GitLab for jobs.
    Polling,
    /// Waiting for the hub to have room for one more of its jobs.
    WaitingCapacity,
    /// Not polling: its server is not approved on the hub.
    ServerPending,
    /// Not polling: GitLab or the hub has been failing.
    Unhealthy,
    /// Not polling: GitLab refused its token.
    TokenRefused,
    /// A state from a later relay.
    #[serde(other)]
    Other,
}

impl Report {
    /// Truncate runners to [`MAX_RUNNERS`] and apply [`display_safe`] to their strings.
    pub fn make_display_safe(&mut self) {
        self.runners.truncate(MAX_RUNNERS);
        for r in &mut self.runners {
            r.name = display_safe(&r.name);
            r.message = r.message.as_deref().map(display_safe);
        }
    }
}

/// What the hub makes of a relay's GitLab server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerStatus {
    pub state: ServerState,
    /// The URL the relay is bound to, normalized as the hub compares them.
    pub url: String,
    /// The name the hub gives the server, what registry namespaces and egress rules call
    /// `{gitlab}`: set when [`ServerState::Approved`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    /// An operator approved the server: its relays poll it.
    Approved,
    /// Waiting for an operator's approval.
    Pending,
    /// An operator rejected the server: the hub refuses its jobs.
    Rejected,
    /// The relay reports a server other than `url`, the one it is bound to: the hub refuses
    /// its jobs until it enrolls again.
    Rebound,
    /// A state from a later hub: as good as not approved.
    #[serde(other)]
    Other,
}

impl ServerState {
    /// Whether a relay may poll its server.
    pub fn approved(self) -> bool {
        self == ServerState::Approved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::Envelope;

    fn pinned<T>(value: &T, wire: &str)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let wire: serde_json::Value = serde_json::from_str(wire).unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), wire);
        assert_eq!(&serde_json::from_value::<T>(wire).unwrap(), value);
    }

    fn runner() -> Runner {
        Runner {
            name: "ci".into(),
            runner_id: Some(42),
            placement: Placement {
                pool: "ci".into(),
                labels: vec!["large-memory".into()],
                envelope: Envelope {
                    mem_mib: 16384,
                    cpus: 8,
                    disk_bytes: 16 << 30,
                },
            },
            limit: Some(8),
            request_concurrency: 2,
            verified: true,
        }
    }

    /// Pin every message's JSON for compatibility across peer versions.
    #[test]
    fn messages_keep_their_json() {
        pinned(
            &RelayMsg::Inventory(Inventory {
                version: "0.96.0".into(),
                hostname: "ci-relay-1".into(),
                system_id: "s_0123456789ab".into(),
                concurrent: 16,
                server: Server {
                    url: "https://gitlab.example.com".into(),
                    spki_sha256: Some("ab".repeat(32)),
                    version: Some("18.4.1".into()),
                },
                runners: vec![runner()],
            }),
            &format!(
                r#"{{"type":"inventory","version":"0.96.0","hostname":"ci-relay-1","system_id":"s_0123456789ab","concurrent":16,"server":{{"url":"https://gitlab.example.com","spki_sha256":"{}","version":"18.4.1"}},"runners":[{{"name":"ci","runner_id":42,"placement":{{"pool":"ci","labels":["large-memory"],"envelope":{{"mem_mib":16384,"cpus":8,"disk_bytes":17179869184}}}},"limit":8,"request_concurrency":2,"verified":true}}]}}"#,
                "ab".repeat(32)
            ),
        );
        pinned(
            &RelayMsg::Heartbeat(Heartbeat {
                runners: vec![RunnerLoad {
                    name: "ci".into(),
                    requests: 1,
                    jobs: 3,
                    request_admissions: vec![],
                    job_admissions: vec![],
                    last_answer_at: Some(7),
                    last_status: Some(204),
                }],
            }),
            r#"{"type":"heartbeat","runners":[{"name":"ci","requests":1,"jobs":3,"request_admissions":[],"job_admissions":[],"last_answer_at":7,"last_status":204}]}"#,
        );
        pinned(
            &RelayMsg::Report(Report {
                runners: vec![
                    RunnerReport {
                        name: "ci".into(),
                        state: RunnerState::WaitingCapacity,
                        message: None,
                    },
                    RunnerReport {
                        name: "old".into(),
                        state: RunnerState::TokenRefused,
                        message: Some("403 Forbidden".into()),
                    },
                ],
            }),
            r#"{"type":"report","runners":[{"name":"ci","state":"waiting_capacity"},{"name":"old","state":"token_refused","message":"403 Forbidden"}]}"#,
        );
        pinned(
            &HubRelayMsg::Server(ServerStatus {
                state: ServerState::Approved,
                url: "https://gitlab.example.com".into(),
                name: Some("gl".into()),
            }),
            r#"{"type":"server","state":"approved","url":"https://gitlab.example.com","name":"gl"}"#,
        );
        pinned(
            &HubRelayMsg::Server(ServerStatus {
                state: ServerState::Pending,
                url: "https://gitlab.example.com".into(),
                name: None,
            }),
            r#"{"type":"server","state":"pending","url":"https://gitlab.example.com"}"#,
        );
        for (state, wire) in [
            (ServerState::Rejected, "rejected"),
            (ServerState::Rebound, "rebound"),
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), wire);
        }
        for (state, wire) in [
            (RunnerState::Polling, "polling"),
            (RunnerState::ServerPending, "server_pending"),
            (RunnerState::Unhealthy, "unhealthy"),
        ] {
            assert_eq!(serde_json::to_value(state).unwrap(), wire);
        }
        pinned(
            &HubRelayMsg::Refused {
                code: RefusalCode::Revoked,
                reason: "r".into(),
            },
            r#"{"type":"refused","code":"revoked","reason":"r"}"#,
        );
        pinned(
            &EnrollResponse {
                relay_id: "r".into(),
            },
            r#"{"relay_id":"r"}"#,
        );
        assert_eq!(
            (ENROLL_PATH, SESSION_PATH),
            ("/v1/gitlab/enroll", "/v1/gitlab/session")
        );
    }

    /// Older peers' messages still parse when optional fields are absent.
    #[test]
    fn minimal_messages_read() {
        let inventory: RelayMsg = serde_json::from_str(
            r#"{"type":"inventory","version":"1","hostname":"h","system_id":"s","concurrent":1,"server":{"url":"https://gl"}}"#,
        )
        .unwrap();
        assert_eq!(
            inventory,
            RelayMsg::Inventory(Inventory {
                version: "1".into(),
                hostname: "h".into(),
                system_id: "s".into(),
                concurrent: 1,
                server: Server {
                    url: "https://gl".into(),
                    ..Server::default()
                },
                runners: vec![],
            })
        );
        let runner: Runner = serde_json::from_str(
            r#"{"name":"ci","placement":{"pool":"ci","envelope":{"mem_mib":1,"cpus":1,"disk_bytes":1}},"verified":false}"#,
        )
        .unwrap();
        assert_eq!((runner.runner_id, runner.limit), (None, None));
        let heartbeat: RelayMsg = serde_json::from_str(r#"{"type":"heartbeat"}"#).unwrap();
        assert_eq!(heartbeat, RelayMsg::Heartbeat(Heartbeat::default()));
        let report: RelayMsg = serde_json::from_str(r#"{"type":"report"}"#).unwrap();
        assert_eq!(report, RelayMsg::Report(Report::default()));
    }

    /// States a later peer adds read as `other`, a server's as not approved.
    #[test]
    fn unknown_states_read_as_other() {
        let status: HubRelayMsg =
            serde_json::from_str(r#"{"type":"server","state":"paused","url":"https://gl"}"#)
                .unwrap();
        let HubRelayMsg::Server(status) = status else {
            panic!("{status:?}");
        };
        assert_eq!(status.state, ServerState::Other);
        assert!(!status.state.approved());
        assert!(ServerState::Approved.approved());
        let state: RunnerState = serde_json::from_str(r#""draining""#).unwrap();
        assert_eq!(state, RunnerState::Other);
    }

    /// Both enums parse the hub's refusal identically.
    #[test]
    fn a_refusal_reads_as_the_nodes() {
        let node = crate::HubMsg::Refused {
            code: RefusalCode::Superseded,
            reason: "r".into(),
        };
        let wire = serde_json::to_string(&node).unwrap();
        assert_eq!(
            serde_json::from_str::<HubRelayMsg>(&wire).unwrap(),
            HubRelayMsg::Refused {
                code: RefusalCode::Superseded,
                reason: "r".into(),
            }
        );
    }

    #[test]
    fn an_inventory_is_made_fit_to_show() {
        let mut r = runner();
        r.name = "ci\u{1b}".into();
        r.placement.pool = "p\n".into();
        r.placement.labels = vec!["l\u{202e}".into(); MAX_LABELS + 1];
        let mut i = Inventory {
            version: "1\u{7}".into(),
            hostname: "h\u{200b}".into(),
            system_id: "s\r".into(),
            server: Server {
                url: "https://gl\u{1b}[2J".into(),
                spki_sha256: Some("AB".repeat(32)),
                version: Some("18\n".into()),
            },
            runners: vec![r; MAX_RUNNERS + 1],
            ..Inventory::default()
        };
        i.make_display_safe();
        assert_eq!(
            (
                i.version.as_str(),
                i.hostname.as_str(),
                i.system_id.as_str()
            ),
            ("1", "h", "s")
        );
        assert_eq!(
            i.server,
            Server {
                url: "https://gl[2J".into(),
                spki_sha256: None,
                version: Some("18".into()),
            }
        );
        assert_eq!(i.runners.len(), MAX_RUNNERS);
        let r = &i.runners[0];
        assert_eq!((r.name.as_str(), r.placement.pool.as_str()), ("ci", "p"));
        assert_eq!(r.placement.labels, vec!["l".to_string(); MAX_LABELS]);

        let mut i = Inventory {
            server: Server {
                spki_sha256: Some("ab".repeat(32)),
                ..Server::default()
            },
            ..Inventory::default()
        };
        i.make_display_safe();
        assert_eq!(i.server.spki_sha256, Some("ab".repeat(32)));
    }

    #[test]
    fn heartbeat_drops_invalid_duplicate_and_excess_admissions() {
        let ids: Vec<String> = (0..=MAX_ADMISSIONS).map(|i| format!("{i:032x}")).collect();
        let mut heartbeat = Heartbeat {
            runners: vec![RunnerLoad {
                request_admissions: std::iter::once("not-an-id".to_owned())
                    .chain(ids.iter().cloned())
                    .collect(),
                job_admissions: vec!["b".repeat(32), "invalid".into(), "b".repeat(32)],
                ..RunnerLoad::default()
            }],
        };
        heartbeat.make_display_safe();
        assert_eq!(
            heartbeat.runners[0].request_admissions,
            ids[..MAX_ADMISSIONS]
        );
        assert_eq!(heartbeat.runners[0].job_admissions, vec!["b".repeat(32)]);
    }

    #[test]
    fn a_version_1_runner_asks_one_request_at_a_time() {
        let mut i: Inventory = serde_json::from_str(
            r#"{"version":"0.96.0","hostname":"h","system_id":"s","concurrent":1,"server":{"url":"https://g"},"runners":[{"name":"ci","placement":{"pool":"ci","envelope":{"mem_mib":1,"cpus":1,"disk_bytes":1}},"verified":true}]}"#,
        )
        .unwrap();
        assert_eq!(i.runners[0].request_concurrency, 1);
        i.runners[0].request_concurrency = 0;
        i.make_display_safe();
        assert_eq!(i.runners[0].request_concurrency, 1);
    }

    #[test]
    fn largest_heartbeat_fits_the_session_message_limit() {
        let load = RunnerLoad {
            name: "r".repeat(crate::MAX_DISPLAY),
            requests: u32::try_from(MAX_ADMISSIONS).unwrap(),
            jobs: u32::try_from(MAX_ADMISSIONS).unwrap(),
            request_admissions: vec!["a".repeat(32); MAX_ADMISSIONS],
            job_admissions: vec!["b".repeat(32); MAX_ADMISSIONS],
            ..RunnerLoad::default()
        };
        let msg = RelayMsg::Heartbeat(Heartbeat {
            runners: vec![load; MAX_RUNNERS],
        });
        assert!(serde_json::to_vec(&msg).unwrap().len() < crate::MAX_MESSAGE);
        assert_eq!(PROTOCOL.negotiate(RELAY_PROTOCOL), Some(2));
        assert_eq!(
            VersionRange { min: 1, max: 1 }.negotiate(RELAY_PROTOCOL),
            None
        );
    }

    #[test]
    fn heartbeats_and_reports_are_made_fit_to_show() {
        let mut h = Heartbeat {
            runners: vec![
                RunnerLoad {
                    name: "ci\u{1b}".into(),
                    ..RunnerLoad::default()
                };
                MAX_RUNNERS + 1
            ],
        };
        h.make_display_safe();
        assert_eq!(h.runners.len(), MAX_RUNNERS);
        assert!(h.runners.iter().all(|r| r.name == "ci"));
        let mut r = Report {
            runners: vec![
                RunnerReport {
                    name: "ci\n".into(),
                    state: RunnerState::Unhealthy,
                    message: Some("m\u{202e}".into()),
                };
                MAX_RUNNERS + 1
            ],
        };
        r.make_display_safe();
        assert_eq!(r.runners.len(), MAX_RUNNERS);
        let first = &r.runners[0];
        assert_eq!(
            (first.name.as_str(), first.message.as_deref()),
            ("ci", Some("m"))
        );
    }
}
