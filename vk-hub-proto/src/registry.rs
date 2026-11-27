//! What `vk-registry` and `vk-hub` exchange when the hub manages a registry.
//!
//! A registry enrolls as a node does — `POST` [`ENROLL_PATH`] with an
//! [`EnrollRequest`](crate::EnrollRequest), answered with an [`EnrollResponse`] naming the
//! registry's ID — and holds a session at [`SESSION_PATH`] that opens with the handshake every
//! peer shares: [`NodeMsg::Hello`](crate::NodeMsg::Hello) (its `node_id` the registry's ID, its
//! `incarnation` new each time `vk-registry` starts, its `vk_version` `vk-registry`'s version) →
//! [`HubMsg::Challenge`](crate::HubMsg::Challenge) → [`NodeMsg::Auth`](crate::NodeMsg::Auth) →
//! [`HubMsg::Welcome`](crate::HubMsg::Welcome), versioned by [`PROTOCOL`]. After the welcome
//! the registry sends [`RegistryMsg`]s and the hub [`HubRegistryMsg`]s. The registry's ID and
//! key live in a table of their own on the hub, so a node's enrollment or session is never
//! taken for a registry's, nor the reverse.
//!
//! A registry downloads the release an [`Operation::Update`] names from [`RELEASE_PATH`], as a
//! node does from its own: its ID, the time and its signature over
//! [`download_message`](crate::download_message) in the [`REGISTRY_HEADER`],
//! [`TIME_HEADER`](crate::TIME_HEADER) and [`SIGNATURE_HEADER`](crate::SIGNATURE_HEADER)
//! headers. A release is signed over this module's [`release_message`], not a `vk` one's.
//!
//! Version 1 is the first; it follows the crate's rule: only optional fields are added within
//! a version.

use serde::{Deserialize, Serialize};

use crate::{
    CommandAck, RefusalCode, SHA256_LEN, UpdateProgress, VersionRange, display_safe, part,
    valid_id, valid_sha256,
};

/// Where a registry enrolls.
pub const ENROLL_PATH: &str = "/v1/registry/enroll";

/// Where a registry holds its session.
pub const SESSION_PATH: &str = "/v1/registry/session";

/// Where a registry downloads a release: this, then its sha256 in lowercase hex.
pub const RELEASE_PATH: &str = "/v1/registry/releases/";

/// A registry's release download's header carrying its ID.
pub const REGISTRY_HEADER: &str = "vk-registry";

/// Where a registry takes a file streamed in whole: `PUT` this, then `<dir>/<name>`, and
/// optionally `?under=<path>`. The file is stored as one blob, tagged
/// `[<path>/]files/sha256:<its sha256>` and `[<path>/]files/<dir>:<name>`, the manifest's
/// layer titled `<name>`, and answered with a [`FilePut`] once both tags are written. The
/// writer needs write on both repositories. An [`Inventory::files_put`] registry takes it.
pub const FILES_PATH: &str = "/files/";

/// A [`FILES_PATH`] put's header naming the sha256 the file must hash to, lowercase hex.
pub const FILE_SHA256_HEADER: &str = "vk-sha256";

/// A [`FILES_PATH`] put's header asking the tags be marked [`RETENTION_KEEP`]: kept however
/// long they sit idle, unless a retention window the registry configures for their prefix
/// says otherwise.
pub const FILE_RETENTION_HEADER: &str = "vk-retention";

/// [`FILE_RETENTION_HEADER`]'s one value.
pub const RETENTION_KEEP: &str = "keep";

/// A [`FILES_PATH`] put's header carrying annotations for the tags' manifest: a JSON object
/// of strings, base64url without padding, at most [`MAX_FILE_ANNOTATIONS`] bytes once decoded.
pub const FILE_ANNOTATIONS_HEADER: &str = "vk-annotations";

/// The most a [`FILE_ANNOTATIONS_HEADER`] may carry, decoded.
pub const MAX_FILE_ANNOTATIONS: usize = 16 * 1024;

/// A registry's answer to a [`FILES_PATH`] put it stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilePut {
    /// What the bytes hash to, lowercase hex, and how many there were.
    pub sha256: String,
    pub size: u64,
    /// The digest of the manifest both tags name, `sha256:<hex>`.
    pub manifest: String,
}

/// The protocol versions of a registry's session.
pub const PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };

/// The most repositories a [`Usage`] lists: the largest ones.
pub const MAX_REPOS: usize = 256;

/// The most entries a list of names keeps once made display-safe: an [`Inventory`]'s
/// upstreams and `[hub] allow`, a [`Report`]'s refused fields.
pub const MAX_NAMES: usize = 64;

/// The hub's answer to a registry's enrollment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    /// The registry's ID ([`valid_id`]); its `Hello.node_id`.
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
    /// The session is ended — the registry was removed, or a newer session took over — and
    /// the connection closes after this. Frozen as [`HubMsg::Refused`](crate::HubMsg::Refused)
    /// is, with the same JSON, so a registry reads it before or after the welcome.
    Refused {
        code: RefusalCode,
        reason: String,
    },
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
    /// Current registries send `false` for compatibility with hubs that require this field.
    #[serde(default)]
    pub webdav: bool,
    /// The pull-through upstreams' prefixes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<String>,
    /// The store's directory, and its filesystem's size; its free space moves, so it rides on
    /// the [`Heartbeat`].
    pub store: String,
    pub store_size_bytes: u64,
    /// A hash of the effective configuration, so drift between registries shows.
    pub config_hash: String,
    /// What its config lets the hub do (`[hub] allow`): [`ALLOW_READ_ONLY`], [`ALLOW_GC`],
    /// [`ALLOW_UPDATE`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<String>,
    /// Whether an update must be signed by one of its own `[hub] release_keys`.
    #[serde(default)]
    pub requires_signed: bool,
    /// Whether it checks hub tokens (`[hub] tokens = true`): the hub mints tokens only for
    /// a registry that does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub tokens: bool,
    /// Whether it refuses the tokens of [`DesiredState::revoked_subjects`]: the hub mints node
    /// tokens only for a registry that does.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub revokes_subjects: bool,
    /// Whether it takes files streamed to [`FILES_PATH`].
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub files_put: bool,
    /// Whether the registry serves its plain files to sccache under `/s3/`.
    /// The hub reads this as false when an older registry omits the field.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub s3: bool,
    /// Whether it takes flat store bindings from [`DesiredState::flat`]. The hub reads this
    /// as false when an older registry omits the field.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub flat: bool,
}

impl Inventory {
    /// Apply [`display_safe`] to strings, drop the sha256 unless [`valid_sha256`],
    /// and truncate lists to [`MAX_NAMES`].
    pub fn make_display_safe(&mut self) {
        for s in [
            &mut self.hostname,
            &mut self.version,
            &mut self.listen,
            &mut self.mode,
            &mut self.store,
            &mut self.config_hash,
        ] {
            *s = display_safe(s);
        }
        self.sha256 = self.sha256.take().filter(|s| valid_sha256(s));
        safe_names(&mut self.upstreams);
        safe_names(&mut self.allow);
    }
}

fn safe_names(names: &mut Vec<String>) {
    names.truncate(MAX_NAMES);
    for s in names {
        *s = display_safe(s);
    }
}

/// `[hub] allow`'s value letting the hub make the registry read-only.
pub const ALLOW_READ_ONLY: &str = "read-only";
/// `[hub] allow`'s value letting the hub schedule gc and run it.
pub const ALLOW_GC: &str = "gc";
/// `[hub] allow`'s value letting the hub update the registry.
pub const ALLOW_UPDATE: &str = "update";
/// `[hub] allow`'s value letting the hub bind prefixes to flat stores.
pub const ALLOW_FLAT: &str = "flat";

/// The field a [`Report`] lists among those refused when the registry refused the hub's
/// retention windows on prefixes.
pub const REFUSED_PREFIX_RETENTION: &str = "prefix-retention";

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
    /// Usage by flat store prefix, the config's and the hub's, excluded from the totals above.
    /// At most [`MAX_NAMES`] entries. Older registries omit this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flat: Vec<FlatUsage>,
}

impl Usage {
    /// Keep at most [`MAX_REPOS`] repositories and [`MAX_NAMES`] flat stores. Apply
    /// [`display_safe`] to repository names and flat store prefixes.
    pub fn make_display_safe(&mut self) {
        self.repos.truncate(MAX_REPOS);
        for r in &mut self.repos {
            r.name = display_safe(&r.name);
        }
        self.flat.truncate(MAX_NAMES);
        for f in &mut self.flat {
            f.prefix = display_safe(&f.prefix);
        }
    }
}

/// Object count, size and cap for a prefix below `files/`. Both sizes are in bytes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatUsage {
    pub prefix: String,
    pub objects: u64,
    pub bytes: u64,
    pub cap: u64,
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
    /// The update in progress, or the last one's end. A registry has nothing to drain: its
    /// phases run from [`UpdatePhase::Downloading`](crate::UpdatePhase::Downloading) on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update: Option<UpdateProgress>,
    /// What its config does not let the hub set, so not applied: the `[hub] allow` value each
    /// refused desired-state field needs ([`ALLOW_READ_ONLY`], [`ALLOW_GC`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<String>,
    /// Prefixes whose requested bindings the registry refused. Local `[[flat]]` overlaps
    /// are refused individually. Missing [`ALLOW_FLAT`], an invalid list or an open failure
    /// refuses the whole request. An earlier binding can still serve a refused prefix.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub flat_refused: Vec<String>,
}

impl Report {
    /// Apply [`display_safe`] to strings and truncate refused fields to [`MAX_NAMES`].
    /// Drop the last gc's command unless [`valid_id`], and the update unless its
    /// command is [`valid_id`] and its sha256 [`valid_sha256`].
    pub fn make_display_safe(&mut self) {
        safe_names(&mut self.refused);
        safe_names(&mut self.flat_refused);
        if let Some(gc) = &mut self.last_gc {
            gc.command = gc.command.take().filter(|c| valid_id(c));
            gc.error = gc.error.as_deref().map(display_safe);
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

/// The state the hub wants a registry in. Every field but `generation` is optional: one left
/// out leaves the registry as its own config has it, except `gc`: the config has no gc
/// schedule, so `None` leaves none; and `token_keys`, `revoked_subjects` and `flat`, which keep
/// what was sent last.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredState {
    pub generation: u64,
    /// Refuse writes — pushes, uploads, deletions — while reads go on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
    /// Run gc on this schedule; `None` schedules none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gc: Option<GcPolicy>,
    /// The keys hub tokens are signed with, the current signer and those whose tokens may
    /// still be live; `None` leaves the registry's keys as they are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_keys: Option<Vec<crate::token::TokenKey>>,
    /// Retention windows on prefixes, from the hub's namespaces: each may lengthen the
    /// registry's own window on that prefix, never shorten it, and stays within its floors
    /// elsewhere. `None` leaves only the registry's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix_retention: Option<Vec<PrefixRetention>>,
    /// Token subjects to refuse whatever their tokens say, as `node:<id>` for a removed node,
    /// each until no token for it can be live; `None` leaves the registry's list as it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_subjects: Option<Vec<String>>,
    /// Additional flat stores. Local `[[flat]]` bindings take precedence over equal, parent
    /// and child prefixes. `None` keeps the last valid list. An empty list clears the hub's
    /// bindings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flat: Option<Vec<FlatSetting>>,
}

/// A prefix below `files/` the hub binds to a flat store ([`DesiredState::flat`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatSetting {
    pub prefix: String,
    /// The store's size cap in bytes.
    pub cap: u64,
    /// Evict down to this percentage of the cap; the registry's default (90) when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evict_to_percent: Option<u8>,
    /// Sync each object before acknowledging it; off when `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable: Option<bool>,
}

/// The most flat store bindings [`DesiredState::flat`] holds.
pub const MAX_FLAT: usize = 64;

/// A servable repository prefix outside `sha256`, the digest namespace under `/files/`.
/// `files/<prefix>` may occupy at most 255 bytes. Including a leaf, the path may have
/// at most 16 components.
pub fn valid_flat_prefix(prefix: &str) -> bool {
    crate::token::servable_prefix(prefix)
        && prefix.split('/').next() != Some("sha256")
        && prefix.split('/').count() <= crate::token::MAX_PREFIX_COMPONENTS - 2
        && prefix.len() + "files/".len() <= crate::token::MAX_PREFIX_LEN
}

/// Whether two prefixes are equal or one is below the other, component-wise.
pub fn flat_prefixes_overlap(a: &str, b: &str) -> bool {
    let under = |a: &str, b: &str| a == b || a.strip_prefix(b).is_some_and(|r| r.starts_with('/'));
    under(a, b) || under(b, a)
}

/// Accept up to [`MAX_FLAT`] nonoverlapping bindings. Each needs a [`valid_flat_prefix`],
/// a positive cap and an eviction target of at most 100%.
pub fn check_flat(settings: &[FlatSetting]) -> Result<(), String> {
    if settings.len() > MAX_FLAT {
        return Err(format!("more than {MAX_FLAT} flat stores"));
    }
    for (i, s) in settings.iter().enumerate() {
        let p = display_safe(&s.prefix);
        if !valid_flat_prefix(&s.prefix) {
            return Err(format!(
                "{p:?} is not a directory below files/ (lowercase components, at most 14, \
                 not sha256)"
            ));
        }
        if s.cap == 0 {
            return Err(format!("{p:?} has a cap of 0 bytes"));
        }
        if s.evict_to_percent.is_some_and(|e| e > 100) {
            return Err(format!("{p:?} evicts to more than 100% of its cap"));
        }
        if let Some(o) = settings[..i]
            .iter()
            .find(|o| flat_prefixes_overlap(&o.prefix, &s.prefix))
        {
            return Err(format!(
                "{p:?} overlaps {:?}: an object can live in one store only",
                display_safe(&o.prefix)
            ));
        }
    }
    Ok(())
}

/// A size: bytes, or a number with a binary `K`, `M`, `G` or `T` suffix (`"50G"`).
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (digits, shift) = match s.char_indices().last()? {
        (i, 'K' | 'k') => (&s[..i], 10),
        (i, 'M' | 'm') => (&s[..i], 20),
        (i, 'G' | 'g') => (&s[..i], 30),
        (i, 'T' | 't') => (&s[..i], 40),
        _ => (s, 0),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok()?.checked_mul(1 << shift)
}

/// The most subjects [`DesiredState::revoked_subjects`] holds: a registry refuses a longer
/// list, keeping the one it has.
pub const MAX_REVOKED_SUBJECTS: usize = 4096;

/// A retention window on the tags under a prefix ([`crate::token::under`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixRetention {
    pub prefix: String,
    pub retention_days: u64,
}

/// A gc schedule: every `every_secs`, with `vk-registry gc`'s windows. A registry refuses an
/// `every_secs` of 0, and windows below its own floors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcPolicy {
    pub every_secs: u64,
    pub retention_days: u64,
    pub grace_days: u64,
}

/// A gc pass, as `vk-registry gc` reports it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcRun {
    /// The command's ID, when a command ran it rather than the schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub at: u64,
    #[serde(default)]
    pub dry_run: bool,
    pub tags_dropped: u64,
    pub manifests_dropped: u64,
    pub blobs_dropped: u64,
    pub bytes_freed: u64,
    pub uploads_dropped: u64,
    /// Unreferenced blobs it kept because a running build still reads them.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub blobs_leased: u64,
    /// Why it failed, when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// A command to a registry. Its ID is one [`valid_id`] takes.
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
        /// base64 ed25519 over this module's [`release_message`], when the release is signed.
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

/// What a release key signs for a `vk-registry` release: what
/// [`crate::release_message`] signs for a `vk` one, under a label of its own, so a signed
/// `vk` release never verifies as a registry's, nor the reverse.
pub fn release_message(sha256: &[u8; SHA256_LEN], version: &str) -> Vec<u8> {
    let mut m = b"vk-fleet registry-release v1\0".to_vec();
    part(&mut m, sha256);
    part(&mut m, version.as_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Outcome, UpdatePhase};

    const ID: &str = "0123456789abcdef0123456789abcdef";

    fn sha() -> String {
        "ab".repeat(SHA256_LEN)
    }

    fn pinned<T>(value: &T, wire: &str)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let wire: serde_json::Value = serde_json::from_str(wire).unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), wire);
        assert_eq!(&serde_json::from_value::<T>(wire).unwrap(), value);
    }

    /// Older peers' messages still parse when optional fields are absent.
    #[test]
    fn minimal_messages_read() {
        let inventory: RegistryMsg = serde_json::from_str(
            r#"{"type":"inventory","hostname":"h","version":"1","listen":"l","tls":false,"mode":"m","webdav":true,"store":"/s","store_size_bytes":1,"config_hash":"c"}"#,
        )
        .unwrap();
        assert_eq!(
            inventory,
            RegistryMsg::Inventory(Inventory {
                hostname: "h".into(),
                version: "1".into(),
                listen: "l".into(),
                mode: "m".into(),
                webdav: true,
                store: "/s".into(),
                store_size_bytes: 1,
                config_hash: "c".into(),
                ..Inventory::default()
            })
        );
        let gc: HubRegistryMsg = serde_json::from_str(
            r#"{"type":"command","id":"c","expires_at":9,"op":{"kind":"gc","retention_days":30,"grace_days":1}}"#,
        )
        .unwrap();
        assert_eq!(
            gc,
            HubRegistryMsg::Command(Command {
                id: "c".into(),
                expires_at: 9,
                op: Operation::Gc {
                    retention_days: 30,
                    grace_days: 1,
                    dry_run: false,
                },
            })
        );
    }

    /// Flat bindings are servable prefixes apart from one another.
    #[test]
    fn flat_settings_are_checked() {
        let s = |p: &str| FlatSetting {
            prefix: p.into(),
            cap: 1,
            evict_to_percent: None,
            durable: None,
        };
        check_flat(&[s("sccache"), s("dev/sccache"), s("a"), s("ab")]).unwrap();
        check_flat(&[s(&vec!["x"; 14].join("/"))]).unwrap();
        for bad in [
            vec![s("Bad")],
            vec![s("files/x")],
            vec![s("sha256")],
            vec![s("a/tags")],
            vec![s(&vec!["x"; 15].join("/"))],
            vec![s("a"), s("a/b")],
            vec![s("a/b"), s("a")],
            vec![FlatSetting { cap: 0, ..s("a") }],
            vec![FlatSetting {
                evict_to_percent: Some(101),
                ..s("a")
            }],
            (0..=MAX_FLAT).map(|i| s(&format!("p{i}"))).collect(),
        ] {
            assert!(check_flat(&bad).is_err(), "{bad:?}");
        }
        assert!(flat_prefixes_overlap("a/b", "a"));
        assert!(!flat_prefixes_overlap("ab", "a"));
        assert_eq!(parse_size("50G"), Some(50 << 30));
        assert_eq!(parse_size("1.5G"), None);
    }

    /// Pin every message's JSON for compatibility across peer versions.
    #[test]
    fn messages_keep_their_json() {
        pinned(
            &RegistryMsg::Inventory(Inventory {
                hostname: "h".into(),
                version: "0.89.0".into(),
                sha256: Some("s".into()),
                listen: "0.0.0.0:5000".into(),
                tls: true,
                mode: "accounts".into(),
                webdav: false,
                upstreams: vec!["docker.io".into()],
                store: "/srv".into(),
                store_size_bytes: 100,
                config_hash: "c".into(),
                allow: vec![ALLOW_GC.into()],
                requires_signed: true,
                tokens: false,
                revokes_subjects: false,
                files_put: false,
                s3: false,
                flat: false,
            }),
            r#"{"type":"inventory","hostname":"h","version":"0.89.0","sha256":"s","listen":"0.0.0.0:5000","tls":true,"mode":"accounts","webdav":false,"upstreams":["docker.io"],"store":"/srv","store_size_bytes":100,"config_hash":"c","allow":["gc"],"requires_signed":true}"#,
        );
        pinned(
            &RegistryMsg::Inventory(Inventory {
                hostname: "h".into(),
                version: "0.93.0".into(),
                listen: "l".into(),
                mode: "accounts".into(),
                store: "/srv".into(),
                config_hash: "c".into(),
                tokens: true,
                ..Inventory::default()
            }),
            r#"{"type":"inventory","hostname":"h","version":"0.93.0","listen":"l","tls":false,"mode":"accounts","webdav":false,"store":"/srv","store_size_bytes":0,"config_hash":"c","requires_signed":false,"tokens":true}"#,
        );
        pinned(
            &RegistryMsg::Inventory(Inventory {
                hostname: "h".into(),
                version: "0.118.0".into(),
                listen: "l".into(),
                mode: "accounts".into(),
                store: "/srv".into(),
                config_hash: "c".into(),
                flat: true,
                ..Inventory::default()
            }),
            r#"{"type":"inventory","hostname":"h","version":"0.118.0","listen":"l","tls":false,"mode":"accounts","webdav":false,"store":"/srv","store_size_bytes":0,"config_hash":"c","requires_signed":false,"flat":true}"#,
        );
        pinned(
            &RegistryMsg::Inventory(Inventory {
                hostname: "h".into(),
                version: "0.108.0".into(),
                listen: "l".into(),
                mode: "accounts".into(),
                store: "/srv".into(),
                config_hash: "c".into(),
                tokens: true,
                revokes_subjects: true,
                ..Inventory::default()
            }),
            r#"{"type":"inventory","hostname":"h","version":"0.108.0","listen":"l","tls":false,"mode":"accounts","webdav":false,"store":"/srv","store_size_bytes":0,"config_hash":"c","requires_signed":false,"tokens":true,"revokes_subjects":true}"#,
        );
        pinned(
            &RegistryMsg::Inventory(Inventory {
                hostname: "h".into(),
                version: "0.109.0".into(),
                listen: "l".into(),
                mode: "accounts".into(),
                store: "/srv".into(),
                config_hash: "c".into(),
                files_put: true,
                ..Inventory::default()
            }),
            r#"{"type":"inventory","hostname":"h","version":"0.109.0","listen":"l","tls":false,"mode":"accounts","webdav":false,"store":"/srv","store_size_bytes":0,"config_hash":"c","requires_signed":false,"files_put":true}"#,
        );
        pinned(
            &RegistryMsg::Inventory(Inventory {
                hostname: "h".into(),
                version: "0.117.0".into(),
                listen: "l".into(),
                mode: "accounts".into(),
                store: "/srv".into(),
                config_hash: "c".into(),
                files_put: true,
                s3: true,
                ..Inventory::default()
            }),
            r#"{"type":"inventory","hostname":"h","version":"0.117.0","listen":"l","tls":false,"mode":"accounts","webdav":false,"store":"/srv","store_size_bytes":0,"config_hash":"c","requires_signed":false,"files_put":true,"s3":true}"#,
        );
        pinned(
            &RegistryMsg::Heartbeat(Heartbeat {
                connections: 3,
                max_connections: 1024,
                uploads: 1,
                locks: 2,
                store_free_bytes: 10,
            }),
            r#"{"type":"heartbeat","connections":3,"max_connections":1024,"uploads":1,"locks":2,"store_free_bytes":10}"#,
        );
        pinned(
            &RegistryMsg::Usage(Usage {
                at: 7,
                blobs: 5,
                stored_bytes: 50,
                referenced_bytes: 40,
                tags: 3,
                manifests: 4,
                repos: vec![RepoUsage {
                    name: "r".into(),
                    tags: 3,
                    bytes: 40,
                }],
                flat: vec![],
            }),
            r#"{"type":"usage","at":7,"blobs":5,"stored_bytes":50,"referenced_bytes":40,"tags":3,"manifests":4,"repos":[{"name":"r","tags":3,"bytes":40}]}"#,
        );
        pinned(
            &RegistryMsg::Usage(Usage {
                at: 7,
                flat: vec![FlatUsage {
                    prefix: "sccache".into(),
                    objects: 2,
                    bytes: 30,
                    cap: 100,
                }],
                ..Usage::default()
            }),
            r#"{"type":"usage","at":7,"blobs":0,"stored_bytes":0,"referenced_bytes":0,"tags":0,"manifests":0,"flat":[{"prefix":"sccache","objects":2,"bytes":30,"cap":100}]}"#,
        );
        pinned(
            &RegistryMsg::Report(Report {
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
                flat_refused: vec![],
            }),
            r#"{"type":"report","applied":4,"read_only":true,"gc":{"every_secs":86400,"retention_days":30,"grace_days":1},"update":{"command":"c","version":"0.89.0","sha256":"s","phase":"validating"}}"#,
        );
        pinned(
            &RegistryMsg::Report(Report {
                last_gc: Some(GcRun {
                    command: Some("c".into()),
                    at: 8,
                    dry_run: true,
                    tags_dropped: 1,
                    manifests_dropped: 2,
                    blobs_dropped: 3,
                    bytes_freed: 4,
                    uploads_dropped: 5,
                    blobs_leased: 0,
                    error: Some("e".into()),
                }),
                refused: vec!["gc".into()],
                ..Report::default()
            }),
            r#"{"type":"report","read_only":false,"last_gc":{"command":"c","at":8,"dry_run":true,"tags_dropped":1,"manifests_dropped":2,"blobs_dropped":3,"bytes_freed":4,"uploads_dropped":5,"error":"e"},"refused":["gc"]}"#,
        );
        pinned(
            &RegistryMsg::Ack(CommandAck {
                id: "c".into(),
                outcome: Outcome::Done,
            }),
            r#"{"type":"ack","id":"c","outcome":{"state":"done"}}"#,
        );
        pinned(
            &HubRegistryMsg::Desired(DesiredState {
                generation: 2,
                read_only: Some(false),
                gc: None,
                token_keys: None,
                prefix_retention: None,
                revoked_subjects: None,
                flat: None,
            }),
            r#"{"type":"desired","generation":2,"read_only":false}"#,
        );
        pinned(
            &HubRegistryMsg::Desired(DesiredState {
                generation: 4,
                flat: Some(vec![
                    FlatSetting {
                        prefix: "sccache".into(),
                        cap: 50,
                        evict_to_percent: Some(80),
                        durable: Some(true),
                    },
                    FlatSetting {
                        prefix: "cc".into(),
                        cap: 9,
                        evict_to_percent: None,
                        durable: None,
                    },
                ]),
                ..DesiredState::default()
            }),
            r#"{"type":"desired","generation":4,"flat":[{"prefix":"sccache","cap":50,"evict_to_percent":80,"durable":true},{"prefix":"cc","cap":9}]}"#,
        );
        pinned(
            &RegistryMsg::Report(Report {
                refused: vec!["flat".into()],
                flat_refused: vec!["sccache".into()],
                ..Report::default()
            }),
            r#"{"type":"report","read_only":false,"refused":["flat"],"flat_refused":["sccache"]}"#,
        );
        pinned(
            &HubRegistryMsg::Desired(DesiredState {
                generation: 3,
                read_only: None,
                gc: None,
                token_keys: Some(vec![crate::token::TokenKey {
                    kid: "k".into(),
                    public_key: "p".into(),
                }]),
                prefix_retention: Some(vec![PrefixRetention {
                    prefix: "team/a".into(),
                    retention_days: 90,
                }]),
                revoked_subjects: Some(vec!["node:n".into()]),
                flat: None,
            }),
            r#"{"type":"desired","generation":3,"token_keys":[{"kid":"k","public_key":"p"}],"prefix_retention":[{"prefix":"team/a","retention_days":90}],"revoked_subjects":["node:n"]}"#,
        );
        pinned(
            &HubRegistryMsg::Command(Command {
                id: "c".into(),
                expires_at: 9,
                op: Operation::Gc {
                    retention_days: 30,
                    grace_days: 1,
                    dry_run: true,
                },
            }),
            r#"{"type":"command","id":"c","expires_at":9,"op":{"kind":"gc","retention_days":30,"grace_days":1,"dry_run":true}}"#,
        );
        pinned(
            &HubRegistryMsg::Command(Command {
                id: "c".into(),
                expires_at: 9,
                op: Operation::Update {
                    version: "0.89.0".into(),
                    sha256: "s".into(),
                    size: 6,
                    signature: Some("g".into()),
                },
            }),
            r#"{"type":"command","id":"c","expires_at":9,"op":{"kind":"update","version":"0.89.0","sha256":"s","size":6,"signature":"g"}}"#,
        );
        pinned(
            &HubRegistryMsg::Recorded(CommandAck {
                id: "c".into(),
                outcome: Outcome::Failed {
                    message: "m".into(),
                },
            }),
            r#"{"type":"recorded","id":"c","outcome":{"state":"failed","message":"m"}}"#,
        );
        pinned(
            &HubRegistryMsg::Refused {
                code: RefusalCode::Revoked,
                reason: "r".into(),
            },
            r#"{"type":"refused","code":"revoked","reason":"r"}"#,
        );
        pinned(
            &EnrollResponse {
                registry_id: "r".into(),
            },
            r#"{"registry_id":"r"}"#,
        );
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
            serde_json::from_str::<HubRegistryMsg>(&wire).unwrap(),
            HubRegistryMsg::Refused {
                code: RefusalCode::Superseded,
                reason: "r".into(),
            }
        );
    }

    #[test]
    fn a_registry_release_signs_apart_from_a_vk_one() {
        let sha = [7; SHA256_LEN];
        let release = release_message(&sha, "0.89.0");
        assert!(release.starts_with(b"vk-fleet registry-release v1\0"));
        assert_ne!(release, crate::release_message(&sha, "0.89.0"));
        assert_ne!(release, release_message(&sha, "0.89.1"));
        assert_ne!(release, release_message(&[8; SHA256_LEN], "0.89.0"));
    }

    #[test]
    fn an_inventory_is_made_fit_to_show() {
        let mut i = Inventory {
            hostname: "h\u{1b}[2J".into(),
            version: "1\u{202e}".into(),
            sha256: Some("S".into()),
            listen: "l\n".into(),
            mode: "m\r".into(),
            store: "/s\u{200b}".into(),
            config_hash: "c\t".into(),
            upstreams: vec!["u\u{7}".into(); MAX_NAMES + 1],
            allow: vec!["gc\u{0}".into()],
            ..Inventory::default()
        };
        i.make_display_safe();
        let want = Inventory {
            hostname: "h[2J".into(),
            version: "1".into(),
            sha256: None,
            listen: "l".into(),
            mode: "m".into(),
            store: "/s".into(),
            config_hash: "c".into(),
            upstreams: vec!["u".into(); MAX_NAMES],
            allow: vec!["gc".into()],
            ..Inventory::default()
        };
        assert_eq!(i, want);

        let mut i = Inventory {
            sha256: Some(sha()),
            ..Inventory::default()
        };
        i.make_display_safe();
        assert_eq!(i.sha256, Some(sha()));
    }

    #[test]
    fn usage_is_made_fit_to_show() {
        let repo = RepoUsage {
            name: "r\u{1b}".into(),
            tags: 1,
            bytes: 2,
        };
        let flat = FlatUsage {
            prefix: "f\u{1b}".into(),
            ..FlatUsage::default()
        };
        let mut u = Usage {
            repos: vec![repo; MAX_REPOS + 1],
            flat: vec![flat; MAX_NAMES + 1],
            ..Usage::default()
        };
        u.make_display_safe();
        assert_eq!(u.repos.len(), MAX_REPOS);
        assert!(u.repos.iter().all(|r| r.name == "r"));
        assert_eq!(u.flat.len(), MAX_NAMES);
        assert!(u.flat.iter().all(|f| f.prefix == "f"));
    }

    #[test]
    fn a_report_is_made_fit_to_show() {
        let update = |command: &str, sha256: String| UpdateProgress {
            command: command.into(),
            version: "1\n".into(),
            sha256,
            phase: UpdatePhase::Failed,
            message: Some("m\u{202e}".into()),
        };
        let mut r = Report {
            last_gc: Some(GcRun {
                command: Some(ID.into()),
                error: Some("e\u{1b}".into()),
                ..GcRun::default()
            }),
            update: Some(update(ID, sha())),
            refused: vec!["f\n".into(); MAX_NAMES + 1],
            ..Report::default()
        };
        r.make_display_safe();
        let gc = r.last_gc.as_ref().unwrap();
        assert_eq!(gc.command.as_deref(), Some(ID));
        assert_eq!(gc.error.as_deref(), Some("e"));
        let u = r.update.as_ref().unwrap();
        assert_eq!((u.version.as_str(), u.message.as_deref()), ("1", Some("m")));
        assert_eq!(r.refused, vec!["f".to_string(); MAX_NAMES]);

        for bad in [update("c", sha()), update(ID, "s".into())] {
            let mut r = Report {
                last_gc: Some(GcRun {
                    command: Some("c".into()),
                    ..GcRun::default()
                }),
                update: Some(bad),
                ..Report::default()
            };
            r.make_display_safe();
            assert_eq!(r.last_gc.unwrap().command, None);
            assert_eq!(r.update, None);
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
