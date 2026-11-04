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
//! A relay whose config lets the hub update it (`[hub] allow = ["update"]`) says so in its
//! inventory's `allow`. In a session at version [`UPDATES`] or later, the hub then sends it
//! [`HubRelayMsg::Command`]s, and the relay answers each with a [`RelayMsg::Ack`], repeated
//! until the hub answers with [`HubRelayMsg::Recorded`], and reports the update's progress in
//! its [`Report`]. It downloads
//! the release an [`Operation::Update`] names from [`RELEASE_PATH`], as a node does from its
//! own: its ID, the time and its signature over [`download_message`](crate::download_message)
//! in the [`RELAY_HEADER`](crate::client::RELAY_HEADER),
//! [`TIME_HEADER`](crate::TIME_HEADER) and [`SIGNATURE_HEADER`](crate::SIGNATURE_HEADER)
//! headers. A release is signed over this module's [`release_message`], not a `vk` or
//! `vk-registry` one's.
//!
//! Version 1 is the first; it follows the crate's rule: only optional fields are added within
//! a version. Version 2 adds capacity arbitration: runners' `request_concurrency` in the
//! inventory, their admission IDs in each heartbeat, and the client API's runner names,
//! queued reservations and admission outcomes, which a relay relies on only once its session
//! negotiated version 2. Version 3 adds updates: the commands, acks and records, which
//! neither side sends in a session below it, and the inventory's `allow` and
//! `requires_signed` and the report's `update`, optional fields a version-2 peer ignores.
//! Version 4 adds runners added on the hub: [`Operation::AddRunner`] and
//! [`Operation::RemoveRunner`], sent only in a session at it or later, for a relay whose
//! `allow` lists [`ALLOW_RUNNERS`], and the inventory runner's `source` and `command`, optional
//! fields an older hub ignores. A runner command that fails is answered with a
//! [`RunnerFailure`]'s code, never GitLab's text.

use serde::{Deserialize, Serialize};

use crate::client::Placement;
use crate::{
    CommandAck, Outcome, RefusalCode, SHA256_LEN, UpdateProgress, VersionRange, display_safe, part,
    valid_id, valid_sha256,
};

/// Where a relay enrolls.
pub const ENROLL_PATH: &str = "/v1/gitlab/enroll";

/// Where a relay holds its session.
pub const SESSION_PATH: &str = "/v1/gitlab/session";

/// The protocol versions of a relay's session.
pub const PROTOCOL: VersionRange = VersionRange { min: 1, max: 4 };

/// The relay requires admission-aware scheduling, introduced in version 2.
pub const RELAY_PROTOCOL: VersionRange = VersionRange { min: 2, max: 4 };

/// The version that adds updates: [`HubRelayMsg::Command`], [`RelayMsg::Ack`] and
/// [`HubRelayMsg::Recorded`] are sent only in a session at it or later.
pub const UPDATES: u32 = 3;

/// The version that adds runners added on the hub: [`Operation::AddRunner`] and
/// [`Operation::RemoveRunner`] are sent only in a session at it or later.
pub const RUNNERS: u32 = 4;

/// The most runners an [`Inventory`], a [`Heartbeat`] or a [`Report`] keeps once made
/// display-safe.
pub const MAX_RUNNERS: usize = 64;

/// The most labels a runner's placement keeps once made display-safe.
pub const MAX_LABELS: usize = 32;

/// The most admission IDs a runner's heartbeat keeps in each of its two lists once made
/// display-safe.
pub const MAX_ADMISSIONS: usize = 128;

/// Where a relay downloads a release: this, then its sha256 in lowercase hex.
pub const RELEASE_PATH: &str = "/v1/gitlab/releases/";

/// `[hub] allow`'s value letting the hub update the relay.
pub const ALLOW_UPDATE: &str = "update";

/// `[hub] allow`'s value letting the hub add runners to the relay and remove them.
pub const ALLOW_RUNNERS: &str = "runners";

/// The most entries an inventory's `allow` keeps once made display-safe.
pub const MAX_ALLOW: usize = 16;

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
    /// What each runner is doing, and the update under way: on connect and whenever it
    /// changes.
    Report(Report),
    /// A command's outcome, repeated until the hub answers with [`HubRelayMsg::Recorded`].
    /// Version [`UPDATES`].
    Ack(CommandAck),
}

/// The hub's messages after the welcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HubRelayMsg {
    /// What the hub makes of the relay's GitLab server: after each inventory, and whenever
    /// an operator changes it.
    Server(ServerStatus),
    /// Issued only to a relay whose inventory's `allow` lists what it needs
    /// ([`Operation::allowed_by`]); one that no longer does refuses it. Version [`UPDATES`].
    Command(Command),
    /// The hub has stored this outcome; the relay stops repeating it. Version [`UPDATES`].
    Recorded(CommandAck),
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
    /// What its config lets the hub do (`[hub] allow`): [`ALLOW_UPDATE`], [`ALLOW_RUNNERS`]. At most
    /// [`MAX_ALLOW`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Whether an update must be signed by one of its own `[hub] release_keys`.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub requires_signed: bool,
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
    /// Where it was defined. Version 4; absent from an older relay, and for
    /// [`RunnerSource::Config`].
    #[serde(default, skip_serializing_if = "RunnerSource::is_config")]
    pub source: RunnerSource,
    /// For [`RunnerSource::Hub`], the [`Operation::AddRunner`] command that added it
    /// ([`valid_id`]). Version 4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

fn one() -> u32 {
    1
}

/// Where a relay's runner was defined.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerSource {
    /// A `[[runners]]` table of the relay's config.
    #[default]
    Config,
    /// Added on the hub, by an [`Operation::AddRunner`].
    Hub,
    /// A source from a later relay: as one the hub cannot remove.
    #[serde(other)]
    Other,
}

impl RunnerSource {
    fn is_config(&self) -> bool {
        *self == RunnerSource::Config
    }
}

impl Inventory {
    /// Apply [`display_safe`] to strings, drop the server's SPKI digest unless
    /// [`valid_sha256`], truncate runners to [`MAX_RUNNERS`] and their labels to
    /// [`MAX_LABELS`], `allow` to [`MAX_ALLOW`], drop a runner's `command` unless [`valid_id`],
    /// and raise a `request_concurrency` of 0 to 1.
    pub fn make_display_safe(&mut self) {
        for s in [&mut self.version, &mut self.hostname, &mut self.system_id] {
            *s = display_safe(s);
        }
        self.allow.truncate(MAX_ALLOW);
        for a in &mut self.allow {
            *a = display_safe(a);
        }
        self.server.url = display_safe(&self.server.url);
        self.server.spki_sha256 = self.server.spki_sha256.take().filter(|s| valid_sha256(s));
        self.server.version = self.server.version.as_deref().map(display_safe);
        self.runners.truncate(MAX_RUNNERS);
        for r in &mut self.runners {
            r.name = display_safe(&r.name);
            r.command = r.command.take().filter(|c| valid_id(c));
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

/// What each of a relay's runners is doing, and its update.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// At most [`MAX_RUNNERS`].
    #[serde(default)]
    pub runners: Vec<RunnerReport>,
    /// The update in progress, or the last one's end. A relay's
    /// [`UpdatePhase::Draining`](crate::UpdatePhase::Draining) waits for its job requests to
    /// GitLab, not its jobs: those go on across the restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateProgress>,
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
    /// Truncate runners to [`MAX_RUNNERS`] and apply [`display_safe`] to their strings. Drop
    /// the update unless its command is [`valid_id`] and its sha256 [`valid_sha256`].
    pub fn make_display_safe(&mut self) {
        self.runners.truncate(MAX_RUNNERS);
        for r in &mut self.runners {
            r.name = display_safe(&r.name);
            r.message = r.message.as_deref().map(display_safe);
        }
        self.update = self
            .update
            .take()
            .filter(|u| valid_id(&u.command) && valid_sha256(&u.sha256));
        if let Some(u) = &mut self.update {
            u.version = display_safe(&u.version);
            u.message = u.message.as_deref().map(display_safe);
        }
    }
}

/// A command to a relay. Its ID is one [`valid_id`] takes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    /// After this, the relay refuses the command rather than starting it.
    pub expires_at: u64,
    pub op: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    /// Install this `vk-gitlab` release, downloaded from [`RELEASE_PATH`].
    Update {
        version: String,
        sha256: String,
        size: u64,
        /// base64 ed25519 over this module's [`release_message`], when the release is signed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    /// Add a runner GitLab created, under `name`, with the settings a `[[runners]]` table
    /// has. Version [`RUNNERS`].
    AddRunner {
        name: String,
        /// Its runner authentication token (`glrt-…`). Empty, and then absent from the JSON,
        /// only where the hub keeps the command once sent: it never stores the token.
        #[serde(default, skip_serializing_if = "RunnerToken::is_empty")]
        token: RunnerToken,
        placement: Placement,
        /// The runner's `limit`, when limited.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        limit: Option<u32>,
        /// The runner's `request_concurrency`, at least 1.
        #[serde(default = "one")]
        request_concurrency: u32,
    },
    /// Remove a runner added on the hub. Refused [`RunnerFailure::RunnerGone`] unless the
    /// relay runs a runner added on the hub with this name, this GitLab ID, added by this
    /// command. Version [`RUNNERS`].
    RemoveRunner {
        name: String,
        runner_id: u64,
        /// The [`Operation::AddRunner`] command that added it.
        command: String,
    },
}

impl Operation {
    /// The `[hub] allow` value a relay needs to take this command.
    pub fn allowed_by(&self) -> &'static str {
        match self {
            Operation::Update { .. } => ALLOW_UPDATE,
            Operation::AddRunner { .. } | Operation::RemoveRunner { .. } => ALLOW_RUNNERS,
        }
    }

    /// The protocol version a session needs before the hub sends this command.
    pub fn min_version(&self) -> u32 {
        match self {
            Operation::Update { .. } => UPDATES,
            Operation::AddRunner { .. } | Operation::RemoveRunner { .. } => RUNNERS,
        }
    }

    /// This operation as the hub keeps it: an [`Operation::AddRunner`]'s token emptied.
    pub fn without_token(&self) -> Operation {
        let mut op = self.clone();
        if let Operation::AddRunner { token, .. } = &mut op {
            *token = RunnerToken::default();
        }
        op
    }
}

/// A runner authentication token. `Debug` and `Display` never print it; [`RunnerToken::expose`]
/// is the one way to the value.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RunnerToken(String);

impl RunnerToken {
    pub fn new(token: impl Into<String>) -> Self {
        Self(token.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for RunnerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RunnerToken([redacted])")
    }
}

impl std::fmt::Display for RunnerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// Why a runner command failed: the code a relay answers with, never GitLab's text. A relay
/// sends it as [`RunnerFailure::outcome`] makes it, and the hub reads it back with
/// [`RunnerFailure::of`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerFailure {
    /// GitLab answered `verify` with 401 or 403.
    TokenRefused,
    /// GitLab could not be reached, answered with a 5xx, or gave no positive runner ID:
    /// adding again retries.
    GitlabUnreachable,
    /// The name is the config's, another runner file's, or a runner's being removed.
    NameTaken,
    /// The relay already runs the token's GitLab runner, under another name.
    RunnerTaken,
    /// The relay runs [`MAX_RUNNERS`] already.
    TooManyRunners,
    /// The relay's `[hub] allow` lacks [`ALLOW_RUNNERS`].
    NotAllowed,
    /// The command arrived past its `expires_at`.
    Expired,
    /// A removal names no runner the relay runs with that name, GitLab ID and command.
    RunnerGone,
    /// Set by the hub, never sent: it lost the token of an add the relay never accepted.
    TokenLost,
    /// A code from a later peer.
    #[serde(other)]
    Other,
}

impl RunnerFailure {
    const ALL: [RunnerFailure; 9] = [
        RunnerFailure::TokenRefused,
        RunnerFailure::GitlabUnreachable,
        RunnerFailure::NameTaken,
        RunnerFailure::RunnerTaken,
        RunnerFailure::TooManyRunners,
        RunnerFailure::NotAllowed,
        RunnerFailure::Expired,
        RunnerFailure::RunnerGone,
        RunnerFailure::TokenLost,
    ];

    /// The code, as the JSON spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            RunnerFailure::TokenRefused => "token_refused",
            RunnerFailure::GitlabUnreachable => "gitlab_unreachable",
            RunnerFailure::NameTaken => "name_taken",
            RunnerFailure::RunnerTaken => "runner_taken",
            RunnerFailure::TooManyRunners => "too_many_runners",
            RunnerFailure::NotAllowed => "not_allowed",
            RunnerFailure::Expired => "expired",
            RunnerFailure::RunnerGone => "runner_gone",
            RunnerFailure::TokenLost => "token_lost",
            RunnerFailure::Other => "other",
        }
    }

    /// The outcome a relay acks with: [`Outcome::Expired`] for [`RunnerFailure::Expired`],
    /// [`Outcome::Refused`] for [`RunnerFailure::NotAllowed`], [`Outcome::Failed`] otherwise,
    /// the code its reason or message.
    pub fn outcome(self) -> Outcome {
        match self {
            RunnerFailure::Expired => Outcome::Expired,
            RunnerFailure::NotAllowed => Outcome::Refused {
                reason: self.as_str().into(),
            },
            _ => Outcome::Failed {
                message: self.as_str().into(),
            },
        }
    }

    /// The failure an outcome stands for: `None` for one that did not fail, and
    /// [`RunnerFailure::Other`] for a code this side does not know.
    pub fn of(outcome: &Outcome) -> Option<RunnerFailure> {
        let code = match outcome {
            Outcome::Accepted | Outcome::Done => return None,
            Outcome::Expired => return Some(RunnerFailure::Expired),
            Outcome::Failed { message: code } | Outcome::Refused { reason: code } => code,
        };
        Some(
            Self::ALL
                .into_iter()
                .find(|f| f.as_str() == code)
                .unwrap_or(RunnerFailure::Other),
        )
    }
}

/// A `vk-gitlab` release signature covers the same payload as [`crate::release_message`],
/// under a distinct label so signatures cannot verify across programs.
pub fn release_message(sha256: &[u8; SHA256_LEN], version: &str) -> Vec<u8> {
    let mut m = b"vk-fleet gitlab-release v1\0".to_vec();
    part(&mut m, sha256);
    part(&mut m, version.as_bytes());
    m
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
            ..Runner::default()
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
                ..Inventory::default()
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
                ..Report::default()
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
            (ENROLL_PATH, SESSION_PATH, RELEASE_PATH),
            (
                "/v1/gitlab/enroll",
                "/v1/gitlab/session",
                "/v1/gitlab/releases/"
            )
        );
    }

    /// The update's messages, and the inventory and report fields it adds, keep their JSON.
    #[test]
    fn update_messages_keep_their_json() {
        use crate::{Outcome, UpdatePhase};
        let sha = "ab".repeat(SHA256_LEN);
        pinned(
            &HubRelayMsg::Command(Command {
                id: "c".into(),
                expires_at: 9,
                op: Operation::Update {
                    version: "0.102.0".into(),
                    sha256: sha.clone(),
                    size: 5,
                    signature: Some("s".into()),
                },
            }),
            &format!(
                r#"{{"type":"command","id":"c","expires_at":9,"op":{{"kind":"update","version":"0.102.0","sha256":"{sha}","size":5,"signature":"s"}}}}"#
            ),
        );
        let ack = CommandAck {
            id: "c".into(),
            outcome: Outcome::Refused { reason: "r".into() },
        };
        pinned(
            &RelayMsg::Ack(ack.clone()),
            r#"{"type":"ack","id":"c","outcome":{"state":"refused","reason":"r"}}"#,
        );
        pinned(
            &HubRelayMsg::Recorded(ack),
            r#"{"type":"recorded","id":"c","outcome":{"state":"refused","reason":"r"}}"#,
        );
        pinned(
            &RelayMsg::Report(Report {
                runners: vec![],
                update: Some(UpdateProgress {
                    command: "c".into(),
                    version: "0.102.0".into(),
                    sha256: sha.clone(),
                    phase: UpdatePhase::Draining,
                    message: None,
                }),
            }),
            &format!(
                r#"{{"type":"report","runners":[],"update":{{"command":"c","version":"0.102.0","sha256":"{sha}","phase":"draining"}}}}"#
            ),
        );
        let inventory = Inventory {
            allow: vec![ALLOW_UPDATE.into()],
            requires_signed: true,
            ..Inventory::default()
        };
        let wire = serde_json::to_value(RelayMsg::Inventory(inventory)).unwrap();
        assert_eq!(wire["allow"], serde_json::json!(["update"]));
        assert_eq!(wire["requires_signed"], serde_json::json!(true));
        // A relay that allows nothing sends neither field, as one from before updates.
        let wire = serde_json::to_value(RelayMsg::Inventory(Inventory::default())).unwrap();
        assert!(wire.get("allow").is_none() && wire.get("requires_signed").is_none());
    }

    fn add_runner(token: &str) -> Operation {
        Operation::AddRunner {
            name: "big".into(),
            token: RunnerToken::new(token),
            placement: runner().placement,
            limit: Some(4),
            request_concurrency: 2,
        }
    }

    /// The runner commands, and the inventory fields they add, keep their JSON.
    #[test]
    fn runner_messages_keep_their_json() {
        let placement = r#"{"pool":"ci","labels":["large-memory"],"envelope":{"mem_mib":16384,"cpus":8,"disk_bytes":17179869184}}"#;
        pinned(
            &HubRelayMsg::Command(Command {
                id: "c".into(),
                expires_at: 9,
                op: add_runner("glrt-secret"),
            }),
            &format!(
                r#"{{"type":"command","id":"c","expires_at":9,"op":{{"kind":"add_runner","name":"big","token":"glrt-secret","placement":{placement},"limit":4,"request_concurrency":2}}}}"#
            ),
        );
        pinned(
            &HubRelayMsg::Command(Command {
                id: "d".into(),
                expires_at: 9,
                op: Operation::RemoveRunner {
                    name: "big".into(),
                    runner_id: 42,
                    command: "c".into(),
                },
            }),
            r#"{"type":"command","id":"d","expires_at":9,"op":{"kind":"remove_runner","name":"big","runner_id":42,"command":"c"}}"#,
        );
        // The settings take a `[[runners]]` table's defaults.
        let op: Operation = serde_json::from_str(&format!(
            r#"{{"kind":"add_runner","name":"big","token":"t","placement":{placement}}}"#
        ))
        .unwrap();
        assert!(matches!(
            op,
            Operation::AddRunner {
                limit: None,
                request_concurrency: 1,
                ..
            }
        ));
        let hub = Runner {
            source: RunnerSource::Hub,
            command: Some("c".into()),
            ..runner()
        };
        let wire = serde_json::to_value(&hub).unwrap();
        assert_eq!(
            (&wire["source"], &wire["command"]),
            (&serde_json::json!("hub"), &serde_json::json!("c"))
        );
        assert_eq!(serde_json::from_value::<Runner>(wire).unwrap(), hub);
        // Config runners omit both fields, matching older relays; unknown sources read as Other.
        let wire = serde_json::to_value(runner()).unwrap();
        assert!(wire.get("source").is_none() && wire.get("command").is_none());
        let mut wire = wire;
        wire["source"] = serde_json::json!("cloud");
        let r: Runner = serde_json::from_value(wire).unwrap();
        assert_eq!(r.source, RunnerSource::Other);
        assert_eq!(ALLOW_RUNNERS, "runners");
    }

    /// A runner token is never printed, and the hub's kept command has none.
    #[test]
    fn a_runner_token_stays_secret() {
        let command = Command {
            id: "c".into(),
            expires_at: 9,
            op: add_runner("glrt-secret"),
        };
        let Operation::AddRunner { token, .. } = &command.op else {
            unreachable!()
        };
        assert_eq!(token.expose(), "glrt-secret");
        for shown in [
            format!("{command:?}"),
            format!("{command:#?}"),
            format!("{token}"),
        ] {
            assert!(!shown.contains("secret"), "{shown}");
        }
        let kept = command.op.without_token();
        let wire = serde_json::to_value(&kept).unwrap();
        assert!(wire.get("token").is_none(), "{wire}");
        assert_eq!(serde_json::from_value::<Operation>(wire).unwrap(), kept);
        assert_eq!(kept, add_runner(""));
        let update = Operation::Update {
            version: "1".into(),
            sha256: "ab".repeat(SHA256_LEN),
            size: 1,
            signature: None,
        };
        assert_eq!(update.without_token(), update);
    }

    /// Runner commands need `runners` allowed and version 4; updates `update` and version 3.
    #[test]
    fn runner_commands_need_runners_allowed_and_version_4() {
        let remove = Operation::RemoveRunner {
            name: "n".into(),
            runner_id: 1,
            command: "c".into(),
        };
        for op in [add_runner("t"), remove] {
            assert_eq!(
                (op.allowed_by(), op.min_version()),
                (ALLOW_RUNNERS, RUNNERS)
            );
        }
        let update = Operation::Update {
            version: "1".into(),
            sha256: String::new(),
            size: 1,
            signature: None,
        };
        assert_eq!(
            (update.allowed_by(), update.min_version()),
            (ALLOW_UPDATE, UPDATES)
        );
    }

    /// Each failure code is its JSON spelling, rides in an ack's outcome and reads back.
    #[test]
    fn runner_failures_ride_in_outcomes() {
        let failed = |code: &str| format!(r#"{{"state":"failed","message":"{code}"}}"#);
        for (f, wire) in [
            (RunnerFailure::TokenRefused, failed("token_refused")),
            (
                RunnerFailure::GitlabUnreachable,
                failed("gitlab_unreachable"),
            ),
            (RunnerFailure::NameTaken, failed("name_taken")),
            (RunnerFailure::RunnerTaken, failed("runner_taken")),
            (RunnerFailure::TooManyRunners, failed("too_many_runners")),
            (
                RunnerFailure::NotAllowed,
                r#"{"state":"refused","reason":"not_allowed"}"#.into(),
            ),
            (RunnerFailure::Expired, r#"{"state":"expired"}"#.into()),
            (RunnerFailure::RunnerGone, failed("runner_gone")),
            (RunnerFailure::TokenLost, failed("token_lost")),
        ] {
            pinned(&f.outcome(), &wire);
        }
        for f in RunnerFailure::ALL {
            assert_eq!(serde_json::to_value(f).unwrap(), f.as_str());
            assert_eq!(RunnerFailure::of(&f.outcome()), Some(f));
        }
        assert_eq!(RunnerFailure::Expired.outcome(), Outcome::Expired);
        assert!(matches!(
            RunnerFailure::NotAllowed.outcome(),
            Outcome::Refused { reason } if reason == "not_allowed"
        ));
        assert_eq!(
            RunnerFailure::TokenRefused.outcome(),
            Outcome::Failed {
                message: "token_refused".into()
            }
        );
        assert_eq!(RunnerFailure::of(&Outcome::Done), None);
        assert_eq!(RunnerFailure::of(&Outcome::Accepted), None);
        assert_eq!(
            RunnerFailure::of(&Outcome::Failed {
                message: "quota".into()
            }),
            Some(RunnerFailure::Other)
        );
        let f: RunnerFailure = serde_json::from_str(r#""quota""#).unwrap();
        assert_eq!(f, RunnerFailure::Other);
    }

    /// A relay's release is signed under a label of its own.
    #[test]
    fn a_relay_release_is_signed_apart() {
        let sha = [7u8; SHA256_LEN];
        let relay = release_message(&sha, "1.0.0");
        assert_ne!(relay, crate::release_message(&sha, "1.0.0"));
        assert_ne!(relay, crate::registry::release_message(&sha, "1.0.0"));
    }

    /// A report's update is dropped unless its command and sha256 are well formed, and its
    /// strings are made fit to show.
    #[test]
    fn a_report_s_update_is_made_fit_to_show() {
        use crate::UpdatePhase;
        let progress = |command: &str, sha256: String| UpdateProgress {
            command: command.into(),
            version: "1\u{1b}".into(),
            sha256,
            phase: UpdatePhase::Failed,
            message: Some("m\n".into()),
        };
        let mut r = Report {
            runners: vec![],
            update: Some(progress(&"0".repeat(32), "ab".repeat(SHA256_LEN))),
        };
        r.make_display_safe();
        let u = r.update.unwrap();
        assert_eq!((u.version.as_str(), u.message.as_deref()), ("1", Some("m")));
        for bad in [
            progress("c", "ab".repeat(SHA256_LEN)),
            progress(&"0".repeat(32), "AB".repeat(SHA256_LEN)),
        ] {
            let mut r = Report {
                runners: vec![],
                update: Some(bad),
            };
            r.make_display_safe();
            assert!(r.update.is_none());
        }
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
                ..Inventory::default()
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
            runners: vec![
                Runner {
                    source: RunnerSource::Hub,
                    command: Some("c\n".into()),
                    ..runner()
                },
                Runner {
                    source: RunnerSource::Hub,
                    command: Some("0".repeat(32)),
                    ..runner()
                },
            ],
            ..Inventory::default()
        };
        i.make_display_safe();
        assert_eq!(i.runners[0].command, None);
        assert_eq!(i.runners[1].command, Some("0".repeat(32)));

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
        assert_eq!(PROTOCOL.negotiate(RELAY_PROTOCOL), Some(RUNNERS));
        assert_eq!(
            VersionRange { min: 1, max: 1 }.negotiate(RELAY_PROTOCOL),
            None
        );
        // Either peer can still negotiate version 3 with a version-3 peer.
        let before = VersionRange { min: 1, max: 3 };
        assert_eq!(before.negotiate(RELAY_PROTOCOL), Some(UPDATES));
        assert_eq!(
            PROTOCOL.negotiate(VersionRange { min: 2, max: 3 }),
            Some(UPDATES)
        );
        // A hub or a relay from before updates still meets the other at version 2.
        let before = VersionRange { min: 1, max: 2 };
        assert_eq!(before.negotiate(RELAY_PROTOCOL), Some(2));
        assert_eq!(PROTOCOL.negotiate(VersionRange { min: 2, max: 2 }), Some(2));
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
            ..Report::default()
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
