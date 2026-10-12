//! What `vk-registry` and `vk-hub` exchange when the hub manages a registry.
//!
//! A registry enrolls as a node does — `POST` [`ENROLL_PATH`] with an
//! [`EnrollRequest`](crate::EnrollRequest), answered with an [`EnrollResponse`] naming the
//! registry's ID — and holds a session at [`SESSION_PATH`] that opens with the handshake every
//! peer shares: [`NodeMsg::Hello`](crate::NodeMsg::Hello) (its `node_id` the registry's ID) →
//! [`HubMsg::Challenge`](crate::HubMsg::Challenge) → [`NodeMsg::Auth`](crate::NodeMsg::Auth) →
//! [`HubMsg::Welcome`](crate::HubMsg::Welcome), versioned by [`PROTOCOL`]. After the welcome
//! the registry sends [`RegistryMsg`]s and the hub [`HubRegistryMsg`]s. The registry's ID and
//! key live in a table of their own on the hub, so a node's enrollment or session is never
//! taken for a registry's, nor the reverse.
//!
//! A registry downloads the release an [`Operation::Update`] names from [`RELEASE_PATH`], as a
//! node does from its own, with its ID in [`ID_HEADER`] and signed over
//! [`download_message`](crate::download_message).
//!
//! Version 1 is the first; it follows the crate's rule: only optional fields are added within
//! a version.

use serde::{Deserialize, Serialize};

use crate::{CommandAck, UpdateProgress, VersionRange};

/// Where a registry enrolls.
pub const ENROLL_PATH: &str = "/v1/registry/enroll";

/// Where a registry holds its session.
pub const SESSION_PATH: &str = "/v1/registry/session";

/// Where a registry downloads a release: this, then its sha256 in lowercase hex.
pub const RELEASE_PATH: &str = "/v1/registry/releases/";

/// A registry's release download's header carrying its ID.
pub const ID_HEADER: &str = "vk-registry";

/// The protocol versions of a registry's session.
pub const PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };

/// The most repositories a [`Usage`] lists: the largest ones.
pub const MAX_REPOS: usize = 256;

/// The hub's answer to a registry's enrollment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub registry_id: String,
}

/// A registry's messages after the welcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RegistryMsg {
    /// On connect, and when it changes.
    Inventory(Inventory),
    /// Every heartbeat interval the hub asked for.
    Heartbeat(Heartbeat),
    /// After each gc, and every few minutes.
    Usage(Usage),
    /// What it applied and what it is doing: on connect and whenever it changes.
    Report(Report),
    /// A command's outcome, repeated until the hub answers with [`HubRegistryMsg::Recorded`].
    Ack(CommandAck),
}

/// The hub's messages after the welcome.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HubRegistryMsg {
    Desired(DesiredState),
    Command(Command),
    /// The hub has stored this outcome; the registry stops repeating it.
    Recorded(CommandAck),
}

/// What a registry is: sent on connect and when it changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub hostname: String,
    /// `vk-registry`'s version, and the sha256 of its binary when it could be read.
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// The address it listens on, and whether over TLS.
    pub listen: String,
    pub tls: bool,
    /// `shared-secret` or `accounts`.
    pub mode: String,
    pub webdav: bool,
    /// The pull-through upstreams' prefixes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<String>,
    /// The store's directory, and its filesystem's size and free space.
    pub store: String,
    pub store_size_bytes: u64,
    pub store_free_bytes: u64,
    /// A hash of the effective configuration, so drift between registries shows.
    pub config_hash: String,
    /// What its config lets the hub do (`[hub] allow`): [`ALLOW_READ_ONLY`], [`ALLOW_GC`],
    /// [`ALLOW_UPDATE`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Whether an update must be signed by one of its own `[hub] release_keys`.
    #[serde(default)]
    pub requires_signed: bool,
}

/// `[hub] allow`'s value letting the hub make the registry read-only.
pub const ALLOW_READ_ONLY: &str = "read-only";
/// `[hub] allow`'s value letting the hub schedule gc and run it.
pub const ALLOW_GC: &str = "gc";
/// `[hub] allow`'s value letting the hub update the registry.
pub const ALLOW_UPDATE: &str = "update";

/// A registry's load, every heartbeat.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Connections open, and the most it takes.
    pub connections: u32,
    pub max_connections: u32,
    /// Uploads in progress.
    pub uploads: u32,
    /// Build-once locks held.
    pub locks: u32,
    /// Free space on the store's filesystem.
    pub store_free_bytes: u64,
}

/// What a registry's store holds, as `vk-registry status` counts it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    /// When it was counted.
    pub at: u64,
    /// Blobs stored, and their bytes on disk.
    pub blobs: u64,
    pub stored_bytes: u64,
    /// Of those bytes, what tags reference.
    pub referenced_bytes: u64,
    pub tags: u64,
    pub manifests: u64,
    /// The largest repositories, at most [`MAX_REPOS`], by referenced size.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoUsage>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepoUsage {
    pub name: String,
    pub tags: u64,
    /// The bytes its tags reference, uncompressed and counted once.
    pub bytes: u64,
}

/// What a registry applied and what it is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The generation of the desired state it last applied; `None` before any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied: Option<u64>,
    pub read_only: bool,
    /// The gc it runs on its own, from the hub's desired state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gc: Option<GcPolicy>,
    /// The last gc it ran, scheduled or commanded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_gc: Option<GcRun>,
    /// The update in progress, or the last one's end.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateProgress>,
    /// Desired-state fields its config does not let the hub set, so not applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<String>,
}

/// The state the hub wants a registry in. Every field is optional: one left out leaves the
/// registry as its own config has it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredState {
    pub generation: u64,
    /// Refuse writes — pushes, uploads, deletions — while reads go on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// Run gc on this schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gc: Option<GcPolicy>,
}

/// A gc schedule: every `every_secs`, with `vk-registry gc`'s windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcPolicy {
    pub every_secs: u64,
    pub retention_days: u64,
    pub grace_days: u64,
}

/// A gc pass, as `vk-registry gc` reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcRun {
    pub at: u64,
    #[serde(default)]
    pub dry_run: bool,
    pub tags_dropped: u64,
    pub manifests_dropped: u64,
    pub blobs_dropped: u64,
    pub bytes_freed: u64,
    pub uploads_dropped: u64,
    /// Why it failed, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A command to a registry. Its ID is [`ID_BYTES`](crate::ID_BYTES) of lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    /// After this, the registry refuses the command rather than starting it.
    pub expires_at: u64,
    pub op: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    /// Run gc now, with the windows given.
    Gc {
        retention_days: u64,
        grace_days: u64,
        #[serde(default)]
        dry_run: bool,
    },
    /// Install this `vk-registry` release, downloaded from [`RELEASE_PATH`].
    Update {
        version: String,
        sha256: String,
        size: u64,
        /// base64 ed25519 over [`release_message`](crate::release_message), when the release
        /// is signed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
}

impl Operation {
    /// The `[hub] allow` value a registry needs to take this command.
    pub fn allowed_by(&self) -> &'static str {
        match self {
            Operation::Gc { .. } => ALLOW_GC,
            Operation::Update { .. } => ALLOW_UPDATE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Outcome, UpdatePhase};

    /// The JSON every message is: what a peer of another version reads.
    #[test]
    fn messages_keep_their_json() {
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                serde_json::to_value(RegistryMsg::Heartbeat(Heartbeat {
                    connections: 3,
                    max_connections: 1024,
                    uploads: 1,
                    locks: 2,
                    store_free_bytes: 10,
                }))
                .unwrap(),
                r#"{"type":"heartbeat","connections":3,"max_connections":1024,"uploads":1,"locks":2,"store_free_bytes":10}"#,
            ),
            (
                serde_json::to_value(RegistryMsg::Report(Report {
                    applied: Some(4),
                    read_only: true,
                    gc: Some(GcPolicy {
                        every_secs: 86_400,
                        retention_days: 30,
                        grace_days: 1,
                    }),
                    last_gc: None,
                    update: Some(UpdateProgress {
                        command: "c".into(),
                        version: "0.89.0".into(),
                        sha256: "s".into(),
                        phase: UpdatePhase::Validating,
                        message: None,
                    }),
                    refused: vec![],
                }))
                .unwrap(),
                r#"{"type":"report","applied":4,"read_only":true,"gc":{"every_secs":86400,"retention_days":30,"grace_days":1},"update":{"command":"c","version":"0.89.0","sha256":"s","phase":"validating"}}"#,
            ),
            (
                serde_json::to_value(RegistryMsg::Ack(CommandAck {
                    id: "c".into(),
                    outcome: Outcome::Done,
                }))
                .unwrap(),
                r#"{"type":"ack","id":"c","outcome":{"state":"done"}}"#,
            ),
            (
                serde_json::to_value(HubRegistryMsg::Desired(DesiredState {
                    generation: 2,
                    read_only: Some(false),
                    gc: None,
                }))
                .unwrap(),
                r#"{"type":"desired","generation":2,"read_only":false}"#,
            ),
            (
                serde_json::to_value(HubRegistryMsg::Command(Command {
                    id: "c".into(),
                    expires_at: 9,
                    op: Operation::Gc {
                        retention_days: 30,
                        grace_days: 1,
                        dry_run: true,
                    },
                }))
                .unwrap(),
                r#"{"type":"command","id":"c","expires_at":9,"op":{"kind":"gc","retention_days":30,"grace_days":1,"dry_run":true}}"#,
            ),
            (
                serde_json::to_value(EnrollResponse {
                    registry_id: "r".into(),
                })
                .unwrap(),
                r#"{"registry_id":"r"}"#,
            ),
        ];
        for (value, want) in cases {
            let want: serde_json::Value = serde_json::from_str(want).unwrap();
            assert_eq!(value, want);
        }
    }

    #[test]
    fn a_command_names_what_allows_it() {
        let update = Operation::Update {
            version: "1.0.0".into(),
            sha256: "s".into(),
            size: 1,
            signature: None,
        };
        assert_eq!(update.allowed_by(), ALLOW_UPDATE);
        let gc = Operation::Gc {
            retention_days: 1,
            grace_days: 1,
            dry_run: false,
        };
        assert_eq!(gc.allowed_by(), ALLOW_GC);
    }
}
