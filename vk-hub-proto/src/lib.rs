//! Shared formats for `vk` and local readers such as `vk-hub`, and for `vk node` and
//! `vk-hub` in fleet mode. Shared message types and signing payloads prevent format drift;
//! each side handles its own transport, storage and crypto.
//!
//! Three exchanges exist:
//!
//! - **Workloads**: `vk workloads` prints the VMs running on its host for its user as a
//!   [`WorkloadList`], one JSON document per line, for a local UI or any other reader on the
//!   host. The list's fields are only ever added to, each optional, and [`WORKLOADS_VERSION`]
//!   changes only for a change an older reader would misread.
//! - **Enrollment**: `POST` [`ENROLL_PATH`] with an [`EnrollRequest`] — a single-use token and
//!   the node's ed25519 public key, signed with the matching private key so the hub pins a
//!   key the caller actually holds. The hub answers with an [`EnrollResponse`] naming the
//!   node's ID, or an [`ErrorBody`].
//! - **The session**: a WebSocket at [`NODE_PATH`], JSON in text frames, [`NodeMsg`] one way
//!   and [`HubMsg`] the other. It opens with [`NodeMsg::Hello`] → [`HubMsg::Challenge`] →
//!   [`NodeMsg::Auth`] → [`HubMsg::Welcome`]; after that the node sends its inventory,
//!   heartbeats and a [`Report`] of its VMs.
//!
//! **Versioning.** Each side of a session speaks a [`VersionRange`], and the hub picks the
//! highest version both ranges contain ([`VersionRange::negotiate`]); every message after the
//! challenge is in that version. The node checks the pick against both ranges
//! ([`VersionRange::accepts_pick`]), and both ranges and the pick are signed into the auth
//! ([`auth_message`]), so a peer in the middle cannot steer a session down to an older
//! version. The hello, the challenge and a refusal are read before a version is agreed, so
//! their shapes are frozen: a later version may add optional fields to them and nothing else.
//! Enrollment is versioned by its `/v1/` path. Version 1, first released in 0.83.0, is
//! frozen: a message or variant an older peer could not parse takes a new version, and only
//! optional fields are added within one. Enrollment's `/v1/` request and response fall under
//! the same rule, and [`TLS_EXPORTER_LABEL`] and the signed payloads' layout are part of
//! version 1 too. Tests pin every message's JSON and the signed payloads' bytes.
//!
//! **Display.** Every string a host reports is the host's to choose; whoever prints one to a
//! terminal, a log or a page passes it through [`display_safe`] first. Escaping it for the
//! markup it lands in — HTML, say — stays the printer's job.
//!
//! Node IDs and incarnations are 16 random bytes as lowercase hex ([`valid_id`]): the node ID
//! the hub assigns at enrollment and the incarnation a node draws each time `vk node run`
//! starts. Keys, signatures and nonces are lowercase hex too, read with [`from_hex_lower`].
//! Timestamps are seconds since the Unix epoch.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Where a node enrolls.
pub const ENROLL_PATH: &str = "/v1/enroll";

/// Where a node holds its session.
pub const NODE_PATH: &str = "/v1/node";

/// The [`WorkloadList`] version this build writes and reads.
pub const WORKLOADS_VERSION: u32 = 1;

/// The most workloads a [`WorkloadList`] or a node's [`Report`] carries.
pub const MAX_WORKLOADS: usize = 256;

/// The most bytes a [`WorkloadList`]'s workloads take, serialized.
pub const MAX_WORKLOADS_BYTES: usize = 256 * 1024;

/// The protocol versions this build speaks.
pub const PROTOCOL: VersionRange = VersionRange { min: 1, max: 1 };

/// The largest message either side accepts, as a WebSocket message or an enrollment body.
/// An inventory is a few kilobytes; this bounds what a confused or hostile peer can make the
/// other buffer.
pub const MAX_MESSAGE: usize = 1 << 20;

/// Length of an ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Length of the nonce in a [`HubMsg::Challenge`].
pub const CHALLENGE_LEN: usize = 32;

/// Length of an ID's random bytes (see [`valid_id`]).
pub const ID_BYTES: usize = 16;

/// An inclusive range of protocol versions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    pub min: u32,
    pub max: u32,
}

impl VersionRange {
    /// The highest version both ranges contain, or `None` when they do not overlap. An
    /// inverted range contains nothing.
    pub fn negotiate(self, theirs: VersionRange) -> Option<u32> {
        let low = self.min.max(theirs.min);
        let high = self.max.min(theirs.max);
        (self.min <= self.max && theirs.min <= theirs.max && low <= high).then_some(high)
    }

    /// Whether `picked`, the version a hub's challenge names, is the one
    /// [`negotiate`](Self::negotiate) gives for these ranges. A node checks this before it
    /// signs, so nobody else gets to choose the session's version.
    pub fn accepts_pick(self, theirs: VersionRange, picked: u32) -> bool {
        self.negotiate(theirs) == Some(picked)
    }
}

/// Whether `s` is a node ID or incarnation as this protocol writes one: [`ID_BYTES`] bytes
/// of lowercase hex. IDs become database keys and log fields, so anything else is refused at
/// the boundary.
pub fn valid_id(s: &str) -> bool {
    from_hex_lower::<ID_BYTES>(s).is_some()
}

/// `bytes` as lowercase hex.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Hex back to bytes; `None` for an odd length or a non-hex digit. Either case is accepted.
/// Wire fields use [`from_hex_lower`].
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    fn digit(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[high, low]| Some((digit(high)? << 4) | digit(low)?))
        .collect()
}

/// Decode exactly `N` bytes of lowercase hex; return `None` otherwise, including uppercase.
/// Every hex wire field uses this reader so each value has one spelling.
pub fn from_hex_lower<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    from_hex(s)?.try_into().ok()
}

/// What a node signs to enroll: the token under the key being enrolled. Proves the caller
/// holds the private half of the key the hub is about to pin, and binds the signature to this
/// one token so it cannot be replayed with another.
///
/// Each signed payload starts with its own label, so a signature made for one purpose is
/// never valid for another, and length-prefixes every variable-length part, so no two
/// different inputs encode alike.
pub fn enroll_message(token: &str, public_key: &[u8]) -> Vec<u8> {
    let mut m = b"vk-fleet enroll v1\0".to_vec();
    part(&mut m, public_key);
    part(&mut m, token.as_bytes());
    m
}

/// The label both sides export TLS keying material under for [`Channel::Tls`] (RFC 5705),
/// which reserves the `EXPERIMENTAL` prefix for labels not registered with IANA.
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPERIMENTAL-vk-fleet-node-auth";

/// Length of the keying material exported under [`TLS_EXPORTER_LABEL`].
pub const TLS_EXPORTER_LEN: usize = 32;

/// The transport a session's auth is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel<'a> {
    /// A TLS connection, identified by the [`TLS_EXPORTER_LEN`] bytes both ends export under
    /// [`TLS_EXPORTER_LABEL`] with no context: a signature relayed onto another connection —
    /// by a proxy terminating TLS with a certificate the node was tricked into trusting —
    /// does not verify there.
    Tls(&'a [u8; TLS_EXPORTER_LEN]),
    /// Plain TCP, which a hub serves only on loopback. Signed as its own label, so a TLS
    /// session's signature can never be presented as a plaintext one or the reverse.
    Plaintext,
}

/// What a node signs to open a session: the hub's challenge, the node ID and incarnation the
/// hello announced, both version ranges and the version the hub chose from them, and the
/// channel the session runs on. A signature answers exactly one hello, on one connection, at
/// the version both sides meant. A node signs only once [`VersionRange::accepts_pick`] holds
/// for the challenge.
///
/// Every variable-length part is length-prefixed, so no two different inputs encode alike.
pub fn auth_message(
    challenge: &[u8],
    node_id: &str,
    incarnation: &str,
    node_versions: VersionRange,
    hub_versions: VersionRange,
    version: u32,
    channel: Channel<'_>,
) -> Vec<u8> {
    let mut m = b"vk-fleet node-auth v1\0".to_vec();
    part(&mut m, challenge);
    part(&mut m, node_id.as_bytes());
    part(&mut m, incarnation.as_bytes());
    for n in [
        node_versions.min,
        node_versions.max,
        hub_versions.min,
        hub_versions.max,
        version,
    ] {
        m.extend_from_slice(&n.to_be_bytes());
    }
    channel_part(&mut m, channel);
    m
}

/// Append `bytes` to `m` with a big-endian `u64` length prefix to keep inputs unambiguous.
fn part(m: &mut Vec<u8>, bytes: &[u8]) {
    m.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    m.extend_from_slice(bytes);
}

fn channel_part(m: &mut Vec<u8>, channel: Channel<'_>) {
    match channel {
        Channel::Tls(exported) => {
            part(m, b"tls-exporter");
            part(m, exported);
        }
        Channel::Plaintext => part(m, b"plaintext"),
    }
}

/// The longest string of a host's that is kept for display.
pub const MAX_DISPLAY: usize = 256;

/// `s` made safe to print, cut to [`MAX_DISPLAY`] characters. Dropped: control characters
/// and the [`invisible`] ones.
pub fn display_safe(s: &str) -> String {
    s.chars()
        .filter(|&c| !c.is_control() && !invisible(c))
        .take(MAX_DISPLAY)
        .collect()
}

/// Whether `c` is one of the characters that can rewrite or hide what a terminal or a page
/// shows around it without showing itself: the line and paragraph separators, and the
/// invisible format characters — bidirectional marks, overrides and isolates, zero-width and
/// blank fillers, variation selectors, the byte-order mark, tags.
pub fn invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{034f}'
            | '\u{061c}'
            | '\u{115f}'
            | '\u{1160}'
            | '\u{17b4}'
            | '\u{17b5}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{3164}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{ffa0}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{e0000}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

/// `POST` [`ENROLL_PATH`]'s body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// The single-use enrollment token an operator issued.
    pub token: String,
    /// The node's ed25519 public key, hex.
    pub public_key: String,
    /// The node's signature over [`enroll_message`], hex.
    pub signature: String,
    /// The node's hostname, as the hub names it until an inventory arrives. Not signed:
    /// untrusted display text.
    pub hostname: String,
}

/// A successful enrollment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub node_id: String,
}

/// Any failed request's body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/// Node → hub.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeMsg {
    /// The first message of a session. Frozen in shape; see the module docs.
    Hello {
        versions: VersionRange,
        node_id: String,
        /// New each time `vk node run` starts, so the hub tells a reconnect from a restart.
        incarnation: String,
        /// The `vk` release, for display and the hub's log.
        vk_version: String,
    },
    /// The node's ed25519 signature over [`auth_message`], hex, sent only once
    /// [`VersionRange::accepts_pick`] holds for the challenge.
    Auth { signature: String },
    /// Sent once a session is up and again whenever it changes.
    Inventory(Inventory),
    /// Sent every [`HubMsg::Welcome`] `heartbeat_secs`.
    Heartbeat(Heartbeat),
    /// Sent once a session is up and again whenever it changes.
    Report(Report),
}

/// Hub → node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HubMsg {
    /// The version the session runs at and the nonce the node signs.
    Challenge {
        version: u32,
        /// The range the hub speaks, for the node to check `version` against
        /// ([`VersionRange::accepts_pick`]).
        versions: VersionRange,
        /// [`CHALLENGE_LEN`] random bytes, hex.
        nonce: String,
    },
    /// The node is authenticated.
    Welcome {
        /// How often the node sends a heartbeat. The hub picks it because the hub decides
        /// when a node that has gone quiet counts as unreachable. A hub sends at least 1; a
        /// node takes 0 as 1.
        heartbeat_secs: u32,
    },
    /// The session is refused or ended; the connection closes after this.
    Refused { code: RefusalCode, reason: String },
}

/// Why a session was refused or ended, for the node to decide whether redialing can help.
/// Frozen with [`HubMsg::Refused`]: a code a node does not know reads as [`RefusalCode::Other`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalCode {
    /// The hub has no such node: never enrolled, or removed. Permanent.
    NotEnrolled,
    /// The auth does not verify against the node's pinned key. Permanent. A proxy in front of
    /// the hub must pass TLS through: one terminating it breaks the [`Channel::Tls`] binding,
    /// and shows up as this refusal.
    BadSignature,
    /// The node was removed during its session. Permanent.
    Revoked,
    /// The two sides share no protocol version: one of them must be updated.
    Version,
    /// A newer session of the same node took over.
    Superseded,
    /// The node broke the protocol or took too long.
    Protocol,
    /// Something failed on the hub.
    Internal,
    /// A code from a later hub; never permanent.
    #[serde(other)]
    Other,
}

impl RefusalCode {
    /// Whether redialing cannot help: the node's enrollment is gone or not its own.
    pub fn is_permanent(self) -> bool {
        matches!(
            self,
            RefusalCode::NotEnrolled | RefusalCode::BadSignature | RefusalCode::Revoked
        )
    }
}

/// What a node is: hardware, storage, versions and runner configuration. Facts that change
/// only when the host or its configuration does — readings that move by the second ride on
/// the [`Heartbeat`] instead, so an inventory is sent again only when something real changed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    pub hostname: String,
    pub hardware: Hardware,
    pub storage: Vec<Filesystem>,
    pub versions: Versions,
    /// `None` when no gitlab-runner configuration could be read.
    pub runner: Option<Runner>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hardware {
    /// Logical CPUs online on the host, whatever this process's own affinity or cgroup allows.
    pub cpus: u32,
    pub cpu_model: Option<String>,
    pub mem_total_mib: Option<u64>,
    /// Empty on a host with a single memory node.
    pub memory_nodes: Vec<MemoryNode>,
    /// The `vk check` results the node gates enrollment on.
    pub checks: Vec<Check>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryNode {
    pub id: u32,
    pub cpus: u32,
    pub mem_total_mib: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    /// Why it failed; empty when it passed.
    pub detail: String,
}

/// What a filesystem holds on a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageRole {
    /// The CI job directories: rootfs overlays and per-job state.
    Jobs,
    /// Host-side checkouts.
    Checkouts,
}

/// How fast the operator says a filesystem is. Declared, not measured: a measurement would
/// be a transient reading, and one never changes a node's declared capabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeedClass {
    Fast,
    Slow,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filesystem {
    pub role: StorageRole,
    pub path: String,
    /// The device the filesystem is on, `major:minor`: two roles on one device share it.
    pub device: String,
    pub size_bytes: u64,
    pub tmpfs: bool,
    pub speed: Option<SpeedClass>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Versions {
    pub vk: String,
    /// The embedded guest kernel's release; `None` when this `vk` embeds none.
    pub guest_kernel: Option<String>,
    /// A hash of the node's effective configuration, so drift between nodes that should
    /// match shows up.
    pub config_hash: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runner {
    /// The gitlab-runner configuration file read.
    pub config: String,
    pub concurrent: Option<u32>,
    /// The `name` of each `[[runners]]` entry.
    pub runners: Vec<String>,
}

/// What a node is doing now.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// `None` when the admission ledger could not be read.
    pub admission: Option<Admission>,
    /// The runner concurrency the node's controller last asked for.
    pub desired_concurrency: Option<u32>,
    pub mem_available_mib: Option<u64>,
    /// Free space on each [`Filesystem`] of the inventory, by role.
    pub storage: Vec<FsUsage>,
    /// What each of the report's [`Workload`]s holds on the host now, in bytes, by its ID.
    /// Here rather than on the workload, so a figure that moves every second does not resend
    /// the report. A workload missing here could not be measured.
    #[serde(default)]
    pub workload_mem_bytes: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admission {
    pub committed_mib: u64,
    /// `None` when no memory budget is configured.
    pub budget_mib: Option<u64>,
    /// Jobs holding a reservation.
    pub running: u32,
    /// Jobs waiting for one.
    pub waiting: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsUsage {
    pub role: StorageRole,
    pub free_bytes: u64,
    pub free_inodes: u64,
    /// The inode total, a reading rather than a fact: XFS and others derive it from free
    /// space. `0` on a filesystem with no inode count.
    pub inodes: u64,
}

/// What a node observes of itself.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The VMs running on the node for its user, oldest first. `None` until the node has
    /// looked. At most [`MAX_WORKLOADS`] of them and [`MAX_WORKLOADS_BYTES`]: a node keeps its
    /// CI jobs first, then its newest VMs, and counts the rest in `workloads_omitted`.
    pub workloads: Option<Vec<Workload>>,
    /// VMs running but left out of `workloads`.
    #[serde(default)]
    pub workloads_omitted: u32,
}

/// The VMs running on a host, as `vk workloads` prints them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadList {
    /// [`WORKLOADS_VERSION`].
    pub version: u32,
    /// Oldest first. At most [`MAX_WORKLOADS`] of them and [`MAX_WORKLOADS_BYTES`]: CI jobs
    /// first, then the newest of the rest, the others counted in `omitted`.
    pub workloads: Vec<Workload>,
    /// VMs running but left out of `workloads`.
    #[serde(default)]
    pub omitted: u32,
    /// What each workload holds on the host, in bytes, by its ID: its managing process's
    /// whole tree, counted proportionally. A workload missing here could not be measured.
    #[serde(default)]
    pub mem_bytes: BTreeMap<String, u64>,
}

/// A VM running on a host. Only what changes when the VM starts or stops: what it holds on
/// the host now is apart from it ([`WorkloadList::mem_bytes`], and a node's
/// [`Heartbeat::workload_mem_bytes`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    /// The first 16 hex digits of the SHA-256 of the state directory's raw path bytes,
    /// before display sanitization. Stable while running and across boots in the same dir.
    pub id: String,
    pub kind: WorkloadKind,
    /// The VM's state directory; the job dir for a CI job. Made fit to show: decoded lossily
    /// where it is not UTF-8, and [`display_safe`].
    pub state_dir: String,
    /// What it boots: the image or compose primary, or a CI job's image as the job asked.
    pub label: Option<String>,
    /// A CI job's project, by its full path.
    pub project: Option<String>,
    pub job_name: Option<String>,
    pub job_id: Option<String>,
    /// The directory it works on: a dev environment's workspace, a run's project directory.
    pub workspace: Option<String>,
    /// A dev environment's name.
    pub environment: Option<String>,
    /// The process managing the VM, whose process tree is what it holds on the host: the
    /// `vk run`, or a CI job's supervisor.
    pub pid: Option<u32>,
    pub cpus: Option<u32>,
    /// A CI job's admission reservation; otherwise the memory the VM was booted with.
    pub mem_reserved_mib: Option<u64>,
    /// When it started, in seconds since the epoch.
    pub started_at: Option<u64>,
    /// A dev environment's SSH host alias, as `vk dev ssh-config` names it; `None` without an
    /// SSH setup in its state dir, and when it is not display-safe as it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_alias: Option<String>,
    /// The guest directory a dev environment's workspace is at; `None` when it is not
    /// display-safe as it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_workspace: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadKind {
    /// A job of the host's gitlab-runner.
    CiJob,
    /// A `vk dev` environment.
    Dev,
    /// A pinned `vk run --state-dir`.
    Run,
    /// A kind this build does not know, from a later `vk`.
    #[serde(other)]
    Other,
}

/// Bytes in a workload's ID ([`Workload::id`]), which `vk` writes as lowercase hex.
pub const WORKLOAD_ID_BYTES: usize = 8;

/// Whether `id` has the shape `vk` gives a workload's ID: [`WORKLOAD_ID_BYTES`] in lowercase
/// hex.
pub fn is_workload_id(id: &str) -> bool {
    from_hex_lower::<WORKLOAD_ID_BYTES>(id).is_some()
}

/// Make `w` fit to show: every string [`display_safe`], except the SSH alias and guest
/// workspace, which are put into a link as they are and so are dropped rather than altered
/// when not display-safe already. `false` when its ID is not one `vk` gives
/// ([`is_workload_id`]): such a workload is not to be listed.
pub fn make_display_safe(w: &mut Workload) -> bool {
    if !is_workload_id(&w.id) {
        return false;
    }
    w.state_dir = display_safe(&w.state_dir);
    for s in [
        &mut w.label,
        &mut w.project,
        &mut w.job_name,
        &mut w.job_id,
        &mut w.workspace,
        &mut w.environment,
    ]
    .into_iter()
    .flatten()
    {
        *s = display_safe(s);
    }
    for s in [&mut w.ssh_alias, &mut w.guest_workspace] {
        if s.as_deref().is_some_and(|v| display_safe(v) != v) {
            *s = None;
        }
    }
    true
}

/// Sanitize `found` with [`make_display_safe`] and limit its JSON array to [`MAX_WORKLOADS`]
/// and [`MAX_WORKLOADS_BYTES`], preserving each workload's attached caller data.
/// Keep CI jobs first because they guide host capacity, then the newest other workloads.
/// Stop at the first that does not fit; never skip it for a lower-priority workload.
/// Return retained workloads oldest first and an omitted count, including invalid IDs.
pub fn bound_workloads<T>(found: Vec<(Workload, T)>) -> (Vec<(Workload, T)>, u32) {
    let total = found.len();
    let mut found: Vec<(Workload, T)> = found
        .into_iter()
        .filter_map(|(mut w, t)| make_display_safe(&mut w).then_some((w, t)))
        .collect();
    found.sort_by(|(a, _), (b, _)| {
        let key = |w: &Workload| {
            (
                w.kind != WorkloadKind::CiJob,
                std::cmp::Reverse(w.started_at),
            )
        };
        key(a).cmp(&key(b)).then_with(|| a.id.cmp(&b.id))
    });
    // The array's brackets, and a comma before every item but the first: 1 + Σ(len + 1).
    let mut bytes = 1usize;
    let mut kept = Vec::new();
    for (w, t) in found {
        let size = serde_json::to_vec(&w).map_or(usize::MAX, |j| j.len().saturating_add(1));
        if kept.len() == MAX_WORKLOADS || bytes.saturating_add(size) > MAX_WORKLOADS_BYTES {
            break;
        }
        bytes = bytes.saturating_add(size);
        kept.push((w, t));
    }
    let omitted = u32::try_from(total - kept.len()).unwrap_or(u32::MAX);
    kept.sort_by(|(a, _), (b, _)| (a.started_at, &a.id).cmp(&(b.started_at, &b.id)));
    (kept, omitted)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn round_trip<T>(value: &T)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let json = serde_json::to_string(value).unwrap();
        let back: T = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, value, "{json}");
    }

    fn inventory() -> Inventory {
        Inventory {
            hostname: "ci-7".into(),
            hardware: Hardware {
                cpus: 64,
                cpu_model: Some("AMD EPYC 7543".into()),
                mem_total_mib: Some(515_000),
                memory_nodes: vec![
                    MemoryNode {
                        id: 0,
                        cpus: 32,
                        mem_total_mib: 257_000,
                    },
                    MemoryNode {
                        id: 1,
                        cpus: 32,
                        mem_total_mib: 258_000,
                    },
                ],
                checks: vec![Check {
                    name: "kvm".into(),
                    ok: true,
                    detail: String::new(),
                }],
            },
            storage: vec![Filesystem {
                role: StorageRole::Checkouts,
                path: "/builds/vk".into(),
                device: "0:45".into(),
                size_bytes: 1 << 37,
                tmpfs: true,
                speed: Some(SpeedClass::Fast),
            }],
            versions: Versions {
                vk: "0.80.0".into(),
                guest_kernel: Some("6.18.52".into()),
                config_hash: "ab".repeat(32),
            },
            runner: Some(Runner {
                config: "/home/ci/.gitlab-runner/config.toml".into(),
                concurrent: Some(8),
                runners: vec!["ci-7".into()],
            }),
        }
    }

    fn workload() -> Workload {
        Workload {
            id: "ab".repeat(8),
            kind: WorkloadKind::CiJob,
            state_dir: "/var/lib/vk/jobs/4242".into(),
            label: Some("rust:1.90".into()),
            project: Some("acme/web".into()),
            job_name: Some("test:unit".into()),
            job_id: Some("4242".into()),
            workspace: None,
            environment: None,
            pid: Some(1234),
            cpus: Some(4),
            mem_reserved_mib: Some(8192),
            started_at: Some(1_800_000_000),
            ssh_alias: None,
            guest_workspace: None,
        }
    }

    /// A list from a `vk` that measured nothing and omitted nothing reads all the same.
    #[test]
    fn a_list_reads_without_its_optional_fields() {
        let list: WorkloadList = serde_json::from_str(r#"{"version":1,"workloads":[]}"#).unwrap();
        assert_eq!(
            list,
            WorkloadList {
                version: 1,
                ..WorkloadList::default()
            }
        );
        let list = WorkloadList {
            version: WORKLOADS_VERSION,
            workloads: vec![workload()],
            omitted: 2,
            mem_bytes: BTreeMap::from([("abababababababab".into(), 5)]),
        };
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(serde_json::from_str::<WorkloadList>(&json).unwrap(), list);
    }

    fn workload_bare() -> Workload {
        Workload {
            id: "cd".repeat(8),
            kind: WorkloadKind::Dev,
            state_dir: "/home/u/.local/state/virtkit/dev/w-1".into(),
            label: None,
            project: None,
            job_name: None,
            job_id: None,
            workspace: Some("/home/u/w".into()),
            environment: Some("dev".into()),
            pid: None,
            cpus: None,
            mem_reserved_mib: None,
            started_at: None,
            ssh_alias: None,
            guest_workspace: None,
        }
    }

    fn heartbeat() -> Heartbeat {
        Heartbeat {
            admission: Some(Admission {
                committed_mib: 4096,
                budget_mib: Some(400_000),
                running: 1,
                waiting: 2,
            }),
            desired_concurrency: Some(9),
            mem_available_mib: Some(300_000),
            storage: vec![FsUsage {
                role: StorageRole::Jobs,
                free_bytes: 1 << 30,
                free_inodes: 1000,
                inodes: 1 << 20,
            }],
            workload_mem_bytes: BTreeMap::from([("ab".repeat(8), 1 << 30)]),
        }
    }

    #[test]
    fn every_message_round_trips() {
        let id = "0123456789abcdef0123456789abcdef".to_string();
        for msg in [
            NodeMsg::Hello {
                versions: PROTOCOL,
                node_id: id.clone(),
                incarnation: id.clone(),
                vk_version: "0.80.0".into(),
            },
            NodeMsg::Auth {
                signature: "00".repeat(SIGNATURE_LEN),
            },
            NodeMsg::Inventory(inventory()),
            NodeMsg::Inventory(Inventory::default()),
            NodeMsg::Heartbeat(heartbeat()),
            NodeMsg::Heartbeat(Heartbeat::default()),
            NodeMsg::Report(Report::default()),
            NodeMsg::Report(Report {
                workloads: Some(vec![workload(), workload_bare()]),
                workloads_omitted: 3,
            }),
            NodeMsg::Report(Report {
                workloads: Some(Vec::new()),
                ..Report::default()
            }),
        ] {
            round_trip(&msg);
        }
        for msg in [
            HubMsg::Challenge {
                version: 1,
                versions: PROTOCOL,
                nonce: "11".repeat(CHALLENGE_LEN),
            },
            HubMsg::Welcome { heartbeat_secs: 5 },
            HubMsg::Refused {
                code: RefusalCode::NotEnrolled,
                reason: "unknown node".into(),
            },
        ] {
            round_trip(&msg);
        }
        round_trip(&EnrollRequest {
            token: "vkh_x".into(),
            public_key: "22".repeat(PUBLIC_KEY_LEN),
            signature: "33".repeat(SIGNATURE_LEN),
            hostname: "ci-7".into(),
        });
    }

    /// The hello, the challenge and a refusal are read before a version is agreed, so their
    /// wire shapes are pinned here: a change that breaks this test breaks every mixed-version
    /// fleet.
    #[test]
    fn the_pre_negotiation_messages_keep_their_wire_shape() {
        let wire = r#"{"type":"challenge","version":2,"versions":{"min":1,"max":2},"nonce":"ab","added_later":1}"#;
        assert_eq!(
            serde_json::from_str::<HubMsg>(wire).unwrap(),
            HubMsg::Challenge {
                version: 2,
                versions: VersionRange { min: 1, max: 2 },
                nonce: "ab".into(),
            }
        );
        let wire = r#"{"type":"refused","code":"revoked","reason":"r"}"#;
        assert_eq!(
            serde_json::from_str::<HubMsg>(wire).unwrap(),
            HubMsg::Refused {
                code: RefusalCode::Revoked,
                reason: "r".into(),
            }
        );
        // A code from a later hub is not a parse error, and not taken as permanent.
        let wire = r#"{"type":"refused","code":"maintenance","reason":"r"}"#;
        let HubMsg::Refused { code, .. } = serde_json::from_str::<HubMsg>(wire).unwrap() else {
            panic!("expected a refusal");
        };
        assert_eq!(code, RefusalCode::Other);
        assert!(!code.is_permanent());
        assert!(RefusalCode::NotEnrolled.is_permanent());
        assert!(!RefusalCode::Superseded.is_permanent());

        let wire = r#"{"type":"hello","versions":{"min":1,"max":3},"node_id":"n","incarnation":"i","vk_version":"9.9.9","added_later":true}"#;
        let msg: NodeMsg = serde_json::from_str(wire).unwrap();
        assert_eq!(
            msg,
            NodeMsg::Hello {
                versions: VersionRange { min: 1, max: 3 },
                node_id: "n".into(),
                incarnation: "i".into(),
                vk_version: "9.9.9".into(),
            }
        );
        pinned(
            &msg,
            json!({
                "type": "hello",
                "versions": {"min": 1, "max": 3},
                "node_id": "n",
                "incarnation": "i",
                "vk_version": "9.9.9",
            }),
        );
        pinned(
            &HubMsg::Challenge {
                version: 2,
                versions: VersionRange { min: 1, max: 2 },
                nonce: "ab".into(),
            },
            json!({
                "type": "challenge",
                "version": 2,
                "versions": {"min": 1, "max": 2},
                "nonce": "ab",
            }),
        );
    }

    fn pinned<T>(value: &T, wire: serde_json::Value)
    where
        T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        assert_eq!(serde_json::to_value(value).unwrap(), wire);
        assert_eq!(&serde_json::from_value::<T>(wire).unwrap(), value);
    }

    /// Every version 1 message as it goes on the wire. The hello and the challenge are pinned
    /// with the pre-negotiation messages, a workload with the workloads, and the signed
    /// payloads with their bytes. A new optional field is added to the literals here; any other
    /// change that breaks this test needs a new protocol version.
    #[test]
    fn version_1_keeps_its_wire_shape() {
        pinned(
            &NodeMsg::Auth {
                signature: "ab".into(),
            },
            json!({"type": "auth", "signature": "ab"}),
        );
        pinned(
            &HubMsg::Welcome { heartbeat_secs: 5 },
            json!({"type": "welcome", "heartbeat_secs": 5}),
        );
        for (code, wire) in [
            (RefusalCode::NotEnrolled, "not_enrolled"),
            (RefusalCode::BadSignature, "bad_signature"),
            (RefusalCode::Revoked, "revoked"),
            (RefusalCode::Version, "version"),
            (RefusalCode::Superseded, "superseded"),
            (RefusalCode::Protocol, "protocol"),
            (RefusalCode::Internal, "internal"),
            (RefusalCode::Other, "other"),
        ] {
            pinned(
                &HubMsg::Refused {
                    code,
                    reason: "r".into(),
                },
                json!({"type": "refused", "code": wire, "reason": "r"}),
            );
        }

        let mut inv = inventory();
        inv.storage.push(Filesystem {
            role: StorageRole::Jobs,
            path: "/var/lib/vk".into(),
            device: "8:1".into(),
            size_bytes: 1 << 40,
            tmpfs: false,
            speed: Some(SpeedClass::Slow),
        });
        inv.storage.push(Filesystem {
            role: StorageRole::Jobs,
            path: "/scratch".into(),
            device: "8:2".into(),
            size_bytes: 1 << 30,
            tmpfs: false,
            speed: None,
        });
        pinned(
            &NodeMsg::Inventory(inv),
            json!({
                "type": "inventory",
                "hostname": "ci-7",
                "hardware": {
                    "cpus": 64,
                    "cpu_model": "AMD EPYC 7543",
                    "mem_total_mib": 515_000,
                    "memory_nodes": [
                        {"id": 0, "cpus": 32, "mem_total_mib": 257_000},
                        {"id": 1, "cpus": 32, "mem_total_mib": 258_000},
                    ],
                    "checks": [{"name": "kvm", "ok": true, "detail": ""}],
                },
                "storage": [
                    {
                        "role": "checkouts",
                        "path": "/builds/vk",
                        "device": "0:45",
                        "size_bytes": 1_u64 << 37,
                        "tmpfs": true,
                        "speed": "fast",
                    },
                    {
                        "role": "jobs",
                        "path": "/var/lib/vk",
                        "device": "8:1",
                        "size_bytes": 1_u64 << 40,
                        "tmpfs": false,
                        "speed": "slow",
                    },
                    {
                        "role": "jobs",
                        "path": "/scratch",
                        "device": "8:2",
                        "size_bytes": 1_u64 << 30,
                        "tmpfs": false,
                        "speed": null,
                    },
                ],
                "versions": {
                    "vk": "0.80.0",
                    "guest_kernel": "6.18.52",
                    "config_hash": "ab".repeat(32),
                },
                "runner": {
                    "config": "/home/ci/.gitlab-runner/config.toml",
                    "concurrent": 8,
                    "runners": ["ci-7"],
                },
            }),
        );
        pinned(
            &NodeMsg::Heartbeat(heartbeat()),
            json!({
                "type": "heartbeat",
                "admission": {
                    "committed_mib": 4096,
                    "budget_mib": 400_000,
                    "running": 1,
                    "waiting": 2,
                },
                "desired_concurrency": 9,
                "mem_available_mib": 300_000,
                "storage": [{
                    "role": "jobs",
                    "free_bytes": 1_u64 << 30,
                    "free_inodes": 1000,
                    "inodes": 1_u64 << 20,
                }],
                "workload_mem_bytes": {"abababababababab": 1_u64 << 30},
            }),
        );
        pinned(
            &NodeMsg::Inventory(Inventory::default()),
            json!({
                "type": "inventory",
                "hostname": "",
                "hardware": {
                    "cpus": 0,
                    "cpu_model": null,
                    "mem_total_mib": null,
                    "memory_nodes": [],
                    "checks": [],
                },
                "storage": [],
                "versions": {"vk": "", "guest_kernel": null, "config_hash": ""},
                "runner": null,
            }),
        );
        pinned(
            &NodeMsg::Heartbeat(Heartbeat::default()),
            json!({
                "type": "heartbeat",
                "admission": null,
                "desired_concurrency": null,
                "mem_available_mib": null,
                "storage": [],
                "workload_mem_bytes": {},
            }),
        );
        pinned(
            &NodeMsg::Heartbeat(Heartbeat {
                admission: Some(Admission {
                    committed_mib: 0,
                    budget_mib: None,
                    running: 0,
                    waiting: 0,
                }),
                ..Heartbeat::default()
            }),
            json!({
                "type": "heartbeat",
                "admission": {"committed_mib": 0, "budget_mib": null, "running": 0, "waiting": 0},
                "desired_concurrency": null,
                "mem_available_mib": null,
                "storage": [],
                "workload_mem_bytes": {},
            }),
        );
        pinned(
            &NodeMsg::Report(Report {
                workloads: Some(vec![workload(), workload_bare()]),
                workloads_omitted: 3,
            }),
            json!({
                "type": "report",
                "workloads": [
                    serde_json::to_value(workload()).unwrap(),
                    {
                        "id": "cdcdcdcdcdcdcdcd",
                        "kind": "dev",
                        "state_dir": "/home/u/.local/state/virtkit/dev/w-1",
                        "label": null,
                        "project": null,
                        "job_name": null,
                        "job_id": null,
                        "workspace": "/home/u/w",
                        "environment": "dev",
                        "pid": null,
                        "cpus": null,
                        "mem_reserved_mib": null,
                        "started_at": null,
                    },
                ],
                "workloads_omitted": 3,
            }),
        );
        for (kind, wire) in [
            (WorkloadKind::CiJob, "ci_job"),
            (WorkloadKind::Dev, "dev"),
            (WorkloadKind::Run, "run"),
            (WorkloadKind::Other, "other"),
        ] {
            pinned(&kind, json!(wire));
        }
        pinned(
            &NodeMsg::Report(Report::default()),
            json!({"type": "report", "workloads": null, "workloads_omitted": 0}),
        );

        pinned(
            &EnrollRequest {
                token: "vkh_x".into(),
                public_key: "22".into(),
                signature: "33".into(),
                hostname: "ci-7".into(),
            },
            json!({
                "token": "vkh_x",
                "public_key": "22",
                "signature": "33",
                "hostname": "ci-7",
            }),
        );
        pinned(
            &EnrollResponse {
                node_id: "n".into(),
            },
            json!({"node_id": "n"}),
        );
        pinned(&ErrorBody { error: "e".into() }, json!({"error": "e"}));
    }

    /// A report and a heartbeat without workloads still read, as "not looked" and "none
    /// measured". A workload's own shape is pinned here, and a kind from a later node reads as
    /// `Other`.
    #[test]
    fn workloads_keep_their_wire_shape() {
        let report: Report = serde_json::from_str("{}").unwrap();
        assert_eq!((report.workloads, report.workloads_omitted), (None, 0));
        let hb: Heartbeat = serde_json::from_str(
            r#"{"admission":null,"desired_concurrency":null,"mem_available_mib":null,"storage":[]}"#,
        )
        .unwrap();
        assert!(hb.workload_mem_bytes.is_empty());

        let wire = r#"{"id":"abababababababab","kind":"ci_job","state_dir":"/var/lib/vk/jobs/4242","label":"rust:1.90","project":"acme/web","job_name":"test:unit","job_id":"4242","workspace":null,"environment":null,"pid":1234,"cpus":4,"mem_reserved_mib":8192,"started_at":1800000000}"#;
        assert_eq!(serde_json::to_string(&workload()).unwrap(), wire);
        assert_eq!(serde_json::from_str::<Workload>(wire).unwrap(), workload());
        let later: Workload =
            serde_json::from_str(r#"{"id":"x","kind":"service","state_dir":"/s","added_later":1}"#)
                .unwrap();
        assert_eq!(later.kind, WorkloadKind::Other);
        assert_eq!((later.pid, later.label), (None, None));
        let hb = Heartbeat {
            workload_mem_bytes: BTreeMap::from([("abababababababab".into(), 5)]),
            ..Heartbeat::default()
        };
        assert!(
            serde_json::to_string(&hb)
                .unwrap()
                .ends_with(r#""workload_mem_bytes":{"abababababababab":5}}"#)
        );
        let dev = Workload {
            kind: WorkloadKind::Dev,
            ssh_alias: Some("vk-w-1".into()),
            guest_workspace: Some("/workdir".into()),
            ..workload()
        };
        let json = serde_json::to_string(&dev).unwrap();
        assert!(
            json.ends_with(r#""ssh_alias":"vk-w-1","guest_workspace":"/workdir"}"#),
            "{json}"
        );
        assert_eq!(serde_json::from_str::<Workload>(&json).unwrap(), dev);
    }

    #[test]
    fn negotiation_picks_the_highest_common_version() {
        let r = |min, max| VersionRange { min, max };
        assert_eq!(r(1, 3).negotiate(r(2, 5)), Some(3));
        assert_eq!(r(2, 5).negotiate(r(1, 3)), Some(3));
        assert_eq!(r(1, 1).negotiate(r(1, 1)), Some(1));
        assert_eq!(r(1, 2).negotiate(r(3, 4)), None);
        assert_eq!(r(3, 4).negotiate(r(1, 2)), None);
        // An inverted range contains nothing, even where its bounds straddle the other's.
        assert_eq!(r(3, 1).negotiate(r(1, 3)), None);
        assert_eq!(r(1, 3).negotiate(r(3, 1)), None);
        assert_eq!(PROTOCOL.negotiate(PROTOCOL), Some(PROTOCOL.max));
    }

    #[test]
    fn a_node_accepts_only_the_negotiated_version() {
        let r = |min, max| VersionRange { min, max };
        assert!(r(1, 3).accepts_pick(r(2, 5), 3));
        assert!(r(2, 5).accepts_pick(r(1, 3), 3));
        assert!(!r(1, 3).accepts_pick(r(2, 5), 2));
        assert!(!r(1, 3).accepts_pick(r(2, 5), 4));
        assert!(!r(1, 2).accepts_pick(r(3, 4), 2));
        assert!(PROTOCOL.accepts_pick(PROTOCOL, PROTOCOL.max));
    }

    #[test]
    fn hex_round_trips_and_rejects_what_is_not_hex() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(from_hex(&to_hex(&bytes)), Some(bytes));
        assert_eq!(from_hex("ABcd"), Some(vec![0xab, 0xcd]));
        assert_eq!(from_hex(""), Some(vec![]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("é1"), None);
    }

    #[test]
    fn wire_hex_is_lowercase_and_exactly_sized() {
        let key = [0x5a; PUBLIC_KEY_LEN];
        assert_eq!(from_hex_lower(&to_hex(&key)), Some(key));
        assert_eq!(from_hex_lower::<2>("abcd"), Some([0xab, 0xcd]));
        assert_eq!(from_hex_lower::<0>(""), Some([]));
        assert_eq!(from_hex_lower::<2>("ABCD"), None);
        assert_eq!(from_hex_lower::<2>("abCd"), None);
        assert_eq!(from_hex_lower::<2>("abc"), None);
        assert_eq!(from_hex_lower::<2>("abcdef"), None);
        assert_eq!(from_hex_lower::<1>("zz"), None);
        assert_eq!(from_hex_lower::<1>("+1"), None);
        assert_eq!(from_hex_lower::<1>("é"), None);
    }

    #[test]
    fn only_lowercase_hex_of_the_right_length_is_an_id() {
        assert!(valid_id(&to_hex(&[0xab; ID_BYTES])));
        assert!(!valid_id(&to_hex(&[0xab; ID_BYTES]).to_uppercase()));
        assert!(!valid_id(&to_hex(&[0xab; ID_BYTES - 1])));
        assert!(!valid_id(&"g".repeat(ID_BYTES * 2)));
        assert!(!valid_id("../../etc/passwd"));
    }

    #[test]
    fn signed_payloads_are_labelled_and_bound_to_their_inputs() {
        let key = [7u8; PUBLIC_KEY_LEN];
        let c = [9u8; CHALLENGE_LEN];
        let r = |min, max| VersionRange { min, max };
        let pt = Channel::Plaintext;
        let tls = Channel::Tls(&[1; TLS_EXPORTER_LEN]);
        let base = auth_message(&c, "t", "i", r(1, 2), r(1, 2), 2, pt);
        let enroll = enroll_message("t", &key);
        assert_ne!(enroll, base);
        assert!(enroll.starts_with(b"vk-fleet enroll v1\0"));
        assert!(base.starts_with(b"vk-fleet node-auth v1\0"));
        assert_ne!(enroll_message("t1", &key), enroll_message("t2", &key));
        // Lengths keep the key and the token from sliding into each other.
        assert_ne!(enroll_message("c", b"ab"), enroll_message("bc", b"a"));
        // Every input changes the payload; lengths keep adjacent parts from sliding into each
        // other.
        for other in [
            auth_message(&[8; CHALLENGE_LEN], "t", "i", r(1, 2), r(1, 2), 2, pt),
            auth_message(&c, "ti", "", r(1, 2), r(1, 2), 2, pt),
            auth_message(&c, "t", "i", r(2, 2), r(1, 2), 2, pt),
            auth_message(&c, "t", "i", r(1, 2), r(1, 3), 2, pt),
            auth_message(&c, "t", "i", r(1, 2), r(1, 2), 1, pt),
            auth_message(&c, "t", "i", r(1, 2), r(1, 2), 2, tls),
        ] {
            assert_ne!(other, base);
        }
        assert_ne!(
            auth_message(&c, "t", "i", r(1, 2), r(1, 2), 2, tls),
            auth_message(
                &c,
                "t",
                "i",
                r(1, 2),
                r(1, 2),
                2,
                Channel::Tls(&[2; TLS_EXPORTER_LEN])
            ),
        );
    }

    /// The exact bytes each side signs: a change here breaks every signature between peers of
    /// different builds.
    #[test]
    fn signed_payloads_keep_their_bytes() {
        assert_eq!(TLS_EXPORTER_LABEL, b"EXPERIMENTAL-vk-fleet-node-auth");
        assert_eq!((ENROLL_PATH, NODE_PATH), ("/v1/enroll", "/v1/node"));
        assert_eq!(
            enroll_message("tok", b"KEY"),
            b"vk-fleet enroll v1\0\
              \0\0\0\0\0\0\0\x03KEY\
              \0\0\0\0\0\0\0\x03tok"
        );
        let r = |min, max| VersionRange { min, max };
        let tls = Channel::Tls(&[b'Z'; TLS_EXPORTER_LEN]);
        let head: &[u8] = b"vk-fleet node-auth v1\0\
              \0\0\0\0\0\0\0\x02ch\
              \0\0\0\0\0\0\0\x01n\
              \0\0\0\0\0\0\0\x01i\
              \0\0\0\x01\0\0\0\x02\0\0\0\x01\0\0\0\x03\0\0\0\x02";
        assert_eq!(
            auth_message(b"ch", "n", "i", r(1, 2), r(1, 3), 2, Channel::Plaintext),
            [head, b"\0\0\0\0\0\0\0\x09plaintext"].concat()
        );
        assert_eq!(
            auth_message(b"ch", "n", "i", r(1, 2), r(1, 3), 2, tls),
            [
                head,
                b"\0\0\0\0\0\0\0\x0ctls-exporter\0\0\0\0\0\0\0\x20",
                b"ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
            ]
            .concat()
        );
    }

    #[test]
    fn display_safe_drops_what_rewrites_a_terminal() {
        assert_eq!(display_safe("ci-1\u{1b}[2J\r\n"), "ci-1[2J");
        assert_eq!(display_safe("a\u{202e}b\u{2066}c\u{200f}"), "abc");
        assert_eq!(display_safe("a\u{2028}b\u{2029}c"), "abc");
        assert_eq!(
            display_safe("p\u{200b}a\u{200d}y\u{2060}p\u{feff}a\u{00ad}l\u{e0041}"),
            "paypal"
        );
        assert_eq!(
            display_safe(
                "a\u{034f}b\u{115f}\u{1160}c\u{3164}\u{ffa0}d\u{17b4}\u{17b5}e\u{fe0f}\u{e0100}f"
            ),
            "abcdef"
        );
        assert_eq!(display_safe("héllo ✓"), "héllo ✓");
        assert_eq!(display_safe(&"x".repeat(1000)).len(), MAX_DISPLAY);
    }

    /// What is shown is made display-safe; what a link is built of is kept as it is or
    /// dropped; a workload whose ID `vk` cannot have given is not listed.
    #[test]
    fn a_workload_is_made_fit_to_show() {
        let hostile = "a\u{1b}[2J\u{202e}<b>";
        let mut w = Workload {
            state_dir: hostile.into(),
            label: Some(hostile.into()),
            workspace: Some(hostile.into()),
            ssh_alias: Some(hostile.into()),
            guest_workspace: Some("/workdir".into()),
            ..workload_bare()
        };
        assert!(make_display_safe(&mut w));
        assert_eq!(w.state_dir, "a[2J<b>");
        assert_eq!(w.label.as_deref(), Some("a[2J<b>"));
        assert_eq!(w.workspace.as_deref(), Some("a[2J<b>"));
        assert_eq!(w.ssh_alias, None);
        assert_eq!(w.guest_workspace.as_deref(), Some("/workdir"));
        for id in ["ABABABABABABABAB", "abab", "x\u{1b}", &"ab".repeat(16)] {
            let mut w = Workload {
                id: id.into(),
                ..workload()
            };
            assert!(!make_display_safe(&mut w), "{id:?}");
        }
        let (kept, omitted) = bound_workloads(vec![
            (
                Workload {
                    id: "nope".into(),
                    ..workload()
                },
                1,
            ),
            (workload_bare(), 2),
        ]);
        assert_eq!((kept.len(), kept[0].1, omitted), (1, 2, 1));
    }

    /// CI jobs are kept first, then the newest; what is kept comes back oldest first.
    #[test]
    fn the_cut_keeps_ci_jobs_then_the_newest() {
        let at = |i: usize, kind| Workload {
            id: format!("{i:016x}"),
            kind,
            started_at: Some(i as u64),
            ..workload_bare()
        };
        let mut all: Vec<_> = (0..MAX_WORKLOADS + 3)
            .map(|i| (at(i, WorkloadKind::Run), ()))
            .collect();
        all.push((at(MAX_WORKLOADS + 10, WorkloadKind::CiJob), ()));
        all[0].0.kind = WorkloadKind::CiJob;
        let (kept, omitted) = bound_workloads(all);
        assert_eq!((kept.len(), omitted), (MAX_WORKLOADS, 4));
        let started: Vec<u64> = kept.iter().map(|(w, _)| w.started_at.unwrap()).collect();
        assert_eq!(started[0], 0, "the oldest, but a CI job");
        assert_eq!(started[1], 5);
        assert!(started.windows(2).all(|p| p[0] <= p[1]));
    }

    /// A list exactly as long as the budget, as a JSON array, is kept whole; a byte more and
    /// the last is cut.
    #[test]
    fn the_byte_budget_is_the_json_array_s() {
        // A workload whose strings take `lens` bytes, each of one- and two-byte characters
        // and at most MAX_DISPLAY of them.
        let with = |i: usize, lens: [usize; 7]| {
            let text = |b: usize| {
                let wide = b.saturating_sub(MAX_DISPLAY);
                "é".repeat(wide) + &"x".repeat(b - 2 * wide)
            };
            Workload {
                id: format!("{i:016x}"),
                kind: WorkloadKind::Run,
                state_dir: text(lens[0]),
                label: Some(text(lens[1])),
                project: Some(text(lens[2])),
                job_name: Some(text(lens[3])),
                job_id: Some(text(lens[4])),
                workspace: Some(text(lens[5])),
                environment: Some(text(lens[6])),
                // As many digits for every one, so each full one is as long as the next.
                started_at: Some(1_000_000 + i as u64),
                ..workload_bare()
            }
        };
        let size = |w: &Workload| serde_json::to_vec(w).unwrap().len();
        let unit = size(&with(1, [MAX_DISPLAY; 7]));
        let bare = size(&with(0, [0; 7]));
        // One of `bytes`, the oldest and so the last considered.
        let sized = |bytes: usize| {
            let mut left = bytes - bare;
            let lens = [(); 7].map(|()| {
                let b = left.min(2 * MAX_DISPLAY);
                left -= b;
                b
            });
            let w = with(0, lens);
            assert_eq!(size(&w), bytes);
            w
        };
        // `k` like the first, and one of `rest` bytes: brackets, items and the commas between
        // come to the budget exactly.
        let mut k = (MAX_WORKLOADS_BYTES - 2) / (unit + 1);
        let mut rest = MAX_WORKLOADS_BYTES - 2 - k * (unit + 1);
        if rest < bare {
            k -= 1;
            rest += unit + 1;
        }
        let list = |last: Workload| {
            let mut all: Vec<_> = (1..=k).map(|i| (with(i, [MAX_DISPLAY; 7]), ())).collect();
            all.push((last, ()));
            all
        };
        let exact = list(sized(rest));
        let array: Vec<&Workload> = exact.iter().map(|(w, _)| w).collect();
        assert_eq!(
            serde_json::to_vec(&array).unwrap().len(),
            MAX_WORKLOADS_BYTES
        );
        assert_eq!(bound_workloads(exact).1, 0);
        let over = bound_workloads(list(sized(rest + 1)));
        assert_eq!((over.0.len(), over.1), (k, 1));
    }
}
