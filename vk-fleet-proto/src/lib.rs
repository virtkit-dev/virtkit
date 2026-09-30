//! What `vk`, `vk node` and `vk-hub` say to each other, and nothing about how they say it.
//! Transport, storage and crypto stay with the sides; this crate is the one place they read
//! the shapes and the signed payloads from, so they cannot drift apart.
//!
//! Four exchanges exist:
//!
//! - **Workloads**: `vk workloads` prints the VMs running on its host for its user as a
//!   [`WorkloadList`], one JSON document per line; `vk-hub local` reads it. The list's fields
//!   are only ever added to, each optional, and [`WORKLOADS_VERSION`] changes only for a
//!   change an older reader would misread.
//! - **Enrollment**: `POST` [`ENROLL_PATH`] with an [`EnrollRequest`] — a single-use token and
//!   the node's ed25519 public key, signed with the matching private key so the hub pins a
//!   key the caller actually holds. The hub answers with an [`EnrollResponse`] naming the
//!   node's ID, or an [`ErrorBody`].
//! - **The session**: a WebSocket at [`NODE_PATH`], JSON in text frames, [`NodeMsg`] one way
//!   and [`HubMsg`] the other. It opens with [`NodeMsg::Hello`] → [`HubMsg::Challenge`] →
//!   [`NodeMsg::Auth`] → [`HubMsg::Welcome`]; after that the node sends its inventory and
//!   heartbeats, and the hub may send desired state and commands.
//! - **A release download**: `GET` [`RELEASE_PATH`]`<sha256>`, which a node makes to fetch the
//!   `vk` an [`Operation::Update`] names. It carries the node's ID, the time, and the node's
//!   signature over [`download_message`] in the [`NODE_HEADER`], [`TIME_HEADER`] and
//!   [`SIGNATURE_HEADER`] headers; the body is the binary.
//!
//! **Versioning.** Each side of a session speaks a [`VersionRange`], and the hub picks the
//! highest version both ranges contain ([`VersionRange::negotiate`]); every message after the
//! challenge is in that version. The node checks the pick against the hub's range, and both
//! ranges and the pick are signed into the auth ([`auth_message`]), so a peer in the middle
//! cannot steer a session down to an older version. The hello, the challenge and a refusal
//! are read before a version is agreed, so their shapes are frozen: a later version may add
//! optional fields to them and nothing else.
//!
//! **Display.** Every string a host reports is the host's to choose; whoever prints one to a
//! terminal, a log or a page passes it through [`display_safe`] first.
//!
//! **Steering.** Once a session is up the node sends a [`Report`] of its observed state —
//! the desired-state generation it last applied, its [`NodeState`], whether its runner is
//! taking jobs, its concurrency — and again whenever that changes, along with an ack for
//! every command whose outcome the hub has not yet recorded. The hub answers each ack with
//! [`HubMsg::Recorded`], resends desired state to a node whose report shows it behind, and
//! resends commands that have no final outcome; the node recognizes a command it journaled
//! by its ID and answers with the outcome it recorded rather than acting twice.
//!
//! Version 1 has not shipped in a release, so these messages are version 1's own. From the
//! first release on, a message or variant an older peer could not parse takes a new version,
//! and only optional fields are added within one.
//!
//! Every ID is 16 random bytes as lowercase hex ([`valid_id`]): the node ID the hub assigns
//! at enrollment, the incarnation a node draws each time `vk node run` starts, and command
//! IDs. Timestamps are seconds since the Unix epoch.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Where a node enrolls.
pub const ENROLL_PATH: &str = "/v1/enroll";

/// Where a node holds its session.
pub const NODE_PATH: &str = "/v1/node";

/// Where a node downloads a release: this, then the release's sha256 in lowercase hex.
pub const RELEASE_PATH: &str = "/v1/releases/";

/// A release download's headers: the node's ID, the time it signed at (seconds since the
/// epoch), and its signature over [`download_message`], hex.
pub const NODE_HEADER: &str = "vk-node";
pub const TIME_HEADER: &str = "vk-time";
pub const SIGNATURE_HEADER: &str = "vk-signature";

/// How far a download's signed time may be from the hub's clock. The signature is bound to
/// the connection as well, so this bounds only how long a signature made for one connection
/// could sit before it is used on it.
pub const DOWNLOAD_SKEW_SECS: u64 = 300;

/// Length of a sha256 digest.
pub const SHA256_LEN: usize = 32;

/// The [`WorkloadList`] version this build writes and reads.
pub const WORKLOADS_VERSION: u32 = 1;

/// The most workloads a [`WorkloadList`] carries.
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
}

/// Whether `s` is an ID as this protocol writes one: [`ID_BYTES`] bytes of lowercase hex.
/// IDs become database keys and log fields, so anything else is refused at the boundary.
pub fn valid_id(s: &str) -> bool {
    s.len() == ID_BYTES * 2 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
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

/// What a node signs to enroll: the token under the key being enrolled. Proves the caller
/// holds the private half of the key the hub is about to pin, and binds the signature to this
/// one token so it cannot be replayed with another.
///
/// Each signed payload starts with its own label, so a signature made for one purpose is
/// never valid for another.
pub fn enroll_message(token: &str, public_key: &[u8]) -> Vec<u8> {
    let mut m = b"vk-fleet enroll v1\0".to_vec();
    m.extend_from_slice(public_key);
    m.extend_from_slice(token.as_bytes());
    m
}

/// The label both sides export TLS keying material under for [`Channel::Tls`] (RFC 5705).
pub const TLS_EXPORTER_LABEL: &[u8] = b"EXPORTER-vk-fleet-node-auth";

/// Length of the keying material exported under [`TLS_EXPORTER_LABEL`].
pub const TLS_EXPORTER_LEN: usize = 32;

/// The transport a session's auth is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel<'a> {
    /// A TLS connection, identified by the [`TLS_EXPORTER_LEN`] bytes both ends export under
    /// [`TLS_EXPORTER_LABEL`] with no context: a signature relayed onto another connection —
    /// by a proxy terminating TLS with a certificate the node was tricked into trusting —
    /// does not verify there.
    Tls(&'a [u8]),
    /// Plain TCP, which a hub serves only on loopback. Signed as its own label, so a TLS
    /// session's signature can never be presented as a plaintext one or the reverse.
    Plaintext,
}

/// What a node signs to open a session: the hub's challenge, the node ID and incarnation the
/// hello announced, both version ranges and the version the hub chose from them, and the
/// channel the session runs on. A signature answers exactly one hello, on one connection, at
/// the version both sides meant.
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

/// Append `bytes` to `m` behind its length, so no two different inputs encode alike.
fn part(m: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    m.extend_from_slice(&len.to_be_bytes());
    m.extend_from_slice(bytes);
}

/// What a node signs to download release `sha256` (hex): its node ID, the release, the time,
/// and the channel the request arrives on. A signature fetches that one release, on that one
/// connection, near that time.
pub fn download_message(node_id: &str, sha256: &str, at: u64, channel: Channel<'_>) -> Vec<u8> {
    let mut m = b"vk-fleet release-download v1\0".to_vec();
    part(&mut m, node_id.as_bytes());
    part(&mut m, sha256.as_bytes());
    m.extend_from_slice(&at.to_be_bytes());
    channel_part(&mut m, channel);
    m
}

/// What a release key signs: the binary's sha256 and the version it is released as. A
/// signature vouches for those bytes as that version and for nothing else — not for another
/// version string a hub might pair them with.
pub fn release_message(sha256: &[u8], version: &str) -> Vec<u8> {
    let mut m = b"vk-fleet release v1\0".to_vec();
    part(&mut m, sha256);
    part(&mut m, version.as_bytes());
    m
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

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// `bytes` as standard, padded base64 (RFC 4648 §4): how release keys and signatures are
/// written in configuration and beside a binary.
pub fn to_base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                let index = (n >> (18 - 6 * i)) & 0x3f;
                out.push(char::from(BASE64[index as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Standard, padded base64 back to bytes; `None` for anything else — a wrong length, a
/// character outside the alphabet, padding anywhere but the end, or bits the padding says
/// are not there. Surrounding whitespace is ignored, since the text often comes from a file.
pub fn from_base64(s: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u32> {
        BASE64.iter().position(|&b| b == c).map(|v| v as u32)
    }
    let s = s.trim().as_bytes();
    let (quads, rest) = s.as_chunks::<4>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(quads.len() * 3);
    for (i, quad) in quads.iter().enumerate() {
        let last = i + 1 == quads.len();
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &quad[..4 - pad] {
            n = (n << 6) | value(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        // Bits below what the padding keeps must be zero: one encoding per input.
        let keep = 3 - pad;
        if bytes[keep..].iter().any(|&b| b != 0) {
            return None;
        }
        out.extend_from_slice(&bytes[..keep]);
    }
    Some(out)
}

/// The longest string of a node's that is kept for display.
pub const MAX_DISPLAY: usize = 256;

/// `s` made safe to print: control characters and the Unicode bidirectional overrides and
/// isolates dropped — either can rewrite what a terminal shows around it — and cut to
/// [`MAX_DISPLAY`] characters.
pub fn display_safe(s: &str) -> String {
    s.chars()
        .filter(|&c| {
            !c.is_control()
                && !matches!(c, '\u{200e}' | '\u{200f}' | '\u{061c}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(MAX_DISPLAY)
        .collect()
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
    /// The node's hostname, as the hub names it until an inventory arrives.
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeMsg {
    /// The first message of a session. Frozen in shape; see the module docs.
    Hello {
        versions: VersionRange,
        node_id: String,
        /// New each time `vk node run` starts, so the hub tells a reconnect from a restart.
        incarnation: String,
        /// The `vk` release, for a hub refusing a version it cannot talk to.
        vk_version: String,
    },
    /// The node's ed25519 signature over [`auth_message`], hex.
    Auth { signature: String },
    /// Sent once a session is up and again whenever it changes.
    Inventory(Inventory),
    /// Sent every [`HubMsg::Welcome`] `heartbeat_secs`.
    Heartbeat(Heartbeat),
    /// What became of a [`HubMsg::Command`]; repeated until the hub answers
    /// [`HubMsg::Recorded`].
    Ack(CommandAck),
    /// Sent once a session is up and again whenever it changes.
    Report(Report),
}

/// Hub → node.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HubMsg {
    /// The version the session runs at and the nonce the node signs.
    Challenge {
        version: u32,
        /// The range the hub speaks, for the node to check `version` against.
        versions: VersionRange,
        /// [`CHALLENGE_LEN`] random bytes, hex.
        nonce: String,
    },
    /// The node is authenticated.
    Welcome {
        /// How often the node sends a heartbeat. The hub picks it because the hub decides
        /// when a node that has gone quiet counts as unreachable.
        heartbeat_secs: u32,
    },
    /// The state the hub wants the node in, applied at most once per generation.
    Desired(DesiredState),
    /// An operation, journaled by the node before it acts on it.
    Command(Command),
    /// The hub has stored this ack; the node stops repeating it.
    Recorded(CommandAck),
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
    /// The auth does not verify against the node's pinned key. Permanent.
    BadSignature,
    /// The node was removed during its session. Permanent.
    Revoked,
    /// The two sides share no protocol version: one of them must be updated.
    Version,
    /// A newer session of the same node took over.
    Superseded,
    /// The node broke the protocol or took too long.
    Protocol,
    /// Too many connections are in their handshake; try again later.
    Busy,
    /// Something failed on the hub.
    Internal,
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
    /// The sha256 of the running `vk` binary, hex: which release it is, where two builds
    /// can share a version. `None` when the binary could not be read.
    #[serde(default)]
    pub vk_sha256: Option<String>,
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

/// The state the hub wants a node in. It only ever narrows local policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesiredState {
    /// Increases with every change; a node applies each generation at most once.
    pub generation: u64,
    /// The hub's cap on the runner's concurrency; `None` leaves it to the node.
    pub ceiling: Option<u32>,
    pub acquisition: Acquisition,
}

/// A node's own state, persisted on the node: losing the hub changes none of it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeState {
    #[default]
    Ready,
    Draining,
    Drained,
    /// Drained, and being worked on: an update downloading and switching, a reset clearing.
    Maintenance,
    /// Checking itself after maintenance before it goes back to the state it was in.
    Validating,
    /// Left only by [`Operation::Release`].
    Quarantined,
}

/// How the node's gitlab-runner is run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerMode {
    /// `vk node run` supervises it, and can stop and resume its acquisition.
    Managed,
    /// Something else runs it; only its concurrency can be steered.
    #[default]
    External,
}

/// What a node observes of itself: the answer to the desired state and commands it was sent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    /// The last desired-state generation applied; `None` before the first.
    pub applied_generation: Option<u64>,
    /// What of the applied desired state this node cannot carry out, in words.
    #[serde(default)]
    pub unsupported: Vec<String>,
    pub state: NodeState,
    /// Whether the runner can take jobs: `Stop` only once a stopped runner has exited, since
    /// a runner still quitting may yet be one that never heard the signal.
    pub acquisition: Acquisition,
    pub runner: RunnerMode,
    /// The supervised runner's process; `None` for an external runner.
    pub runner_state: Option<RunnerState>,
    /// `None` until the node's concurrency loop has run once.
    pub concurrency: Option<Concurrency>,
    /// Why the node's last attempt to set its runner's concurrency failed, if it did.
    #[serde(default)]
    pub concurrency_error: Option<String>,
    /// Present while draining: which of the conditions for `drained` hold.
    pub drain: Option<DrainProgress>,
    /// The update under way, or the last one, with how it ended.
    #[serde(default)]
    pub update: Option<UpdateProgress>,
}

/// How far an [`Operation::Update`] has got.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateProgress {
    /// The command's ID.
    pub command: String,
    pub version: String,
    pub sha256: String,
    pub phase: UpdatePhase,
    /// Why it failed or was rolled back.
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdatePhase {
    /// Waiting for the running jobs to finish.
    Draining,
    /// Fetching and checking the release.
    Downloading,
    /// Running the new binary on trial, checking it before it is kept.
    Validating,
    /// The new binary is installed and the node is back where it was.
    Done,
    /// The new binary did not pass its trial; the previous one runs again.
    RolledBack,
    /// Given up before the switch; the binary is unchanged.
    Failed,
}

/// `effective = min(estimate, hub_ceiling, local_ceiling)`, as the node last worked it out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Concurrency {
    pub estimate: Option<u32>,
    pub hub_ceiling: Option<u32>,
    pub local_ceiling: Option<u32>,
    pub effective: Option<u32>,
}

/// A supervised runner's process.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunnerState {
    Running,
    /// Sent `SIGQUIT`: taking no new jobs, finishing the ones it has. gitlab-runner has no way
    /// back from this, so acquisition resumes only with a new runner once this one exits.
    Quitting,
    #[default]
    Stopped,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrainProgress {
    /// The runner has exited, having finished its jobs.
    pub runner_stopped: bool,
    /// No reservation is held or waited for in the admission ledger.
    pub ledger_empty: bool,
    /// Job supervisors still running.
    pub active_jobs: u32,
}

/// Whether the runner may take new jobs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Acquisition {
    #[default]
    Run,
    Stop,
}

/// An operation for a node, identified so a redelivery after a reconnect is recognized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Command {
    pub id: String,
    /// After this, the node refuses the command rather than starting it.
    pub expires_at: u64,
    pub op: Operation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    /// Stop taking jobs, let running ones finish, then report [`NodeState::Drained`].
    Drain,
    /// Back to [`NodeState::Ready`] from a drain, taking jobs again.
    Undrain,
    /// Stop taking jobs until an operator releases the node, whatever else it is told.
    Quarantine,
    /// Leave a quarantine for [`NodeState::Ready`].
    Release,
    /// Drain, replace the node's `vk` with release `sha256`, validate it, and return to the
    /// state the node was in; roll back to the previous binary if it does not pass.
    Update {
        /// The version the release's `--version` must report.
        version: String,
        /// The binary's sha256, hex: what it is downloaded by and checked against.
        sha256: String,
        /// Its size in bytes; a download longer than this is refused.
        size: u64,
        /// A release key's ed25519 signature over [`release_message`], base64.
        #[serde(default)]
        signature: Option<String>,
        /// Update a node whose runner is external, which cannot be drained, while its jobs
        /// may still be running.
        #[serde(default)]
        force: bool,
        /// How long the update may take once the drain is over: past it, the node rolls the
        /// release back rather than keep it. A drain still under way at the command's
        /// `expires_at` calls the update off. `None`: the node's own trial deadline alone.
        #[serde(default)]
        within_secs: Option<u64>,
    },
    Reset,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandAck {
    pub id: String,
    pub outcome: Outcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Outcome {
    /// Journaled and under way.
    Accepted,
    Done,
    Failed {
        message: String,
    },
    /// Not permitted by local policy, or not supported by this node.
    Refused {
        reason: String,
    },
    /// It arrived past its `expires_at`.
    Expired,
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
/// the host now is apart from it ([`WorkloadList::mem_bytes`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workload {
    /// Stable while the VM runs, and the same for a VM booted again on the same state dir:
    /// derived from the state dir.
    pub id: String,
    pub kind: WorkloadKind,
    /// The VM's state directory; the job dir for a CI job.
    pub state_dir: String,
    /// What it boots: the image or compose primary, or a CI job's image as the job asked.
    #[serde(default)]
    pub label: Option<String>,
    /// A CI job's project, by its full path.
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub job_name: Option<String>,
    #[serde(default)]
    pub job_id: Option<String>,
    /// The directory it works on: a dev environment's workspace, a run's project directory.
    #[serde(default)]
    pub workspace: Option<String>,
    /// A dev environment's name.
    #[serde(default)]
    pub environment: Option<String>,
    /// The process managing the VM, whose process tree is what it holds on the host: the
    /// `vk run`, or a CI job's supervisor.
    #[serde(default)]
    pub pid: Option<u32>,
    #[serde(default)]
    pub cpus: Option<u32>,
    /// A CI job's admission reservation; otherwise the memory the VM was booted with.
    #[serde(default)]
    pub mem_reserved_mib: Option<u64>,
    /// When it started, in seconds since the epoch.
    #[serde(default)]
    pub started_at: Option<u64>,
    /// A dev environment's SSH host alias, as `vk dev ssh-config` names it; `None` without an
    /// SSH setup in its state dir.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_alias: Option<String>,
    /// The guest directory a dev environment's workspace is at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    /// A kind this build does not know, from a later node.
    #[serde(other)]
    Other,
}

#[cfg(test)]
mod tests {
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
                vk_sha256: Some("cd".repeat(SHA256_LEN)),
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

    /// A workload's shape is pinned here, and a kind from a later `vk` reads as `Other`.
    #[test]
    fn workloads_keep_their_wire_shape() {
        let wire = r#"{"id":"abababababababab","kind":"ci_job","state_dir":"/var/lib/vk/jobs/4242","label":"rust:1.90","project":"acme/web","job_name":"test:unit","job_id":"4242","workspace":null,"environment":null,"pid":1234,"cpus":4,"mem_reserved_mib":8192,"started_at":1800000000}"#;
        assert_eq!(serde_json::to_string(&workload()).unwrap(), wire);
        assert_eq!(serde_json::from_str::<Workload>(wire).unwrap(), workload());
        let later: Workload =
            serde_json::from_str(r#"{"id":"x","kind":"service","state_dir":"/s","added_later":1}"#)
                .unwrap();
        assert_eq!(later.kind, WorkloadKind::Other);
        assert_eq!((later.pid, later.label), (None, None));
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
            NodeMsg::Heartbeat(Heartbeat {
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
            }),
            NodeMsg::Heartbeat(Heartbeat::default()),
            NodeMsg::Ack(CommandAck {
                id: id.clone(),
                outcome: Outcome::Failed {
                    message: "no".into(),
                },
            }),
            NodeMsg::Ack(CommandAck {
                id: id.clone(),
                outcome: Outcome::Expired,
            }),
            NodeMsg::Report(Report::default()),
            NodeMsg::Report(Report {
                applied_generation: Some(4),
                unsupported: vec!["stop acquisition".into()],
                state: NodeState::Draining,
                acquisition: Acquisition::Stop,
                runner: RunnerMode::Managed,
                runner_state: Some(RunnerState::Quitting),
                concurrency: Some(Concurrency {
                    estimate: Some(8),
                    hub_ceiling: Some(4),
                    local_ceiling: None,
                    effective: Some(4),
                }),
                drain: Some(DrainProgress {
                    runner_stopped: false,
                    ledger_empty: true,
                    active_jobs: 1,
                }),
                concurrency_error: Some("invalid [executor.vm] mem".into()),
                update: Some(UpdateProgress {
                    command: id.clone(),
                    version: "0.81.0".into(),
                    sha256: "ab".repeat(SHA256_LEN),
                    phase: UpdatePhase::RolledBack,
                    message: Some("validation failed".into()),
                }),
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
            HubMsg::Desired(DesiredState {
                generation: 3,
                ceiling: Some(4),
                acquisition: Acquisition::Stop,
            }),
            HubMsg::Command(Command {
                id: id.clone(),
                expires_at: 1_800_000_000,
                op: Operation::Update {
                    version: "0.81.0".into(),
                    sha256: "ab".repeat(SHA256_LEN),
                    size: 1 << 26,
                    signature: Some(to_base64(&[1; SIGNATURE_LEN])),
                    force: false,
                    within_secs: Some(1800),
                },
            }),
            HubMsg::Command(Command {
                id: id.clone(),
                expires_at: 0,
                op: Operation::Drain,
            }),
            HubMsg::Command(Command {
                id: id.clone(),
                expires_at: 0,
                op: Operation::Quarantine,
            }),
            HubMsg::Recorded(CommandAck {
                id,
                outcome: Outcome::Done,
            }),
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
        let r = |min, max| VersionRange { min, max };
        let auth =
            |c: &[u8], id: &str, inc: &str, nv, hv, v, ch| auth_message(c, id, inc, nv, hv, v, ch);
        let base = auth(&key, "t", "i", r(1, 2), r(1, 2), 2, Channel::Plaintext);
        let enroll = enroll_message("t", &key);
        assert_ne!(enroll, base);
        assert!(enroll.starts_with(b"vk-fleet enroll v1\0"));
        assert!(base.starts_with(b"vk-fleet node-auth v1\0"));
        assert_ne!(enroll_message("t1", &key), enroll_message("t2", &key));
        // Every input changes the payload; lengths keep adjacent parts from sliding into each
        // other.
        for other in [
            auth(&key, "ti", "", r(1, 2), r(1, 2), 2, Channel::Plaintext),
            auth(&key, "t", "i", r(2, 2), r(1, 2), 2, Channel::Plaintext),
            auth(&key, "t", "i", r(1, 2), r(1, 3), 2, Channel::Plaintext),
            auth(&key, "t", "i", r(1, 2), r(1, 2), 1, Channel::Plaintext),
            auth(&key, "t", "i", r(1, 2), r(1, 2), 2, Channel::Tls(&[])),
            auth(
                &key,
                "t",
                "i",
                r(1, 2),
                r(1, 2),
                2,
                Channel::Tls(b"plaintext"),
            ),
        ] {
            assert_ne!(other, base);
        }
        assert_ne!(
            auth(&key, "t", "i", r(1, 2), r(1, 2), 2, Channel::Tls(&[1; 32])),
            auth(&key, "t", "i", r(1, 2), r(1, 2), 2, Channel::Tls(&[2; 32])),
        );
    }

    #[test]
    fn base64_round_trips_and_rejects_every_other_spelling() {
        // RFC 4648's test vectors.
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(to_base64(plain.as_bytes()), encoded);
            assert_eq!(from_base64(encoded).unwrap(), plain.as_bytes());
        }
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(from_base64(&to_base64(&bytes)), Some(bytes));
        assert_eq!(from_base64(" Zm9v\n"), Some(b"foo".to_vec()));
        for bad in [
            "Zg", "Zg=", "Zg===", "Z===", "Zh==", "Zm9=v", "Zg==Zg==", "Zm9-", "Zm 9v",
        ] {
            assert_eq!(from_base64(bad), None, "{bad}");
        }
    }

    #[test]
    fn release_and_download_payloads_are_labelled_and_bound() {
        let sha = [7u8; SHA256_LEN];
        let release = release_message(&sha, "0.81.0");
        assert!(release.starts_with(b"vk-fleet release v1\0"));
        assert_ne!(release, release_message(&sha, "0.81.1"));
        assert_ne!(release, release_message(&[8; SHA256_LEN], "0.81.0"));
        let hex = to_hex(&sha);
        let download = |id: &str, at, ch| download_message(id, &hex, at, ch);
        let base = download("n", 5, Channel::Plaintext);
        assert!(base.starts_with(b"vk-fleet release-download v1\0"));
        for other in [
            download("m", 5, Channel::Plaintext),
            download("n", 6, Channel::Plaintext),
            download("n", 5, Channel::Tls(&[1; 32])),
            download_message("n", &to_hex(&[8; SHA256_LEN]), 5, Channel::Plaintext),
        ] {
            assert_ne!(other, base);
        }
        assert_ne!(release, base);
    }

    #[test]
    fn display_safe_drops_what_rewrites_a_terminal() {
        assert_eq!(display_safe("ci-1\u{1b}[2J\r\n"), "ci-1[2J");
        assert_eq!(display_safe("a\u{202e}b\u{2066}c\u{200f}"), "abc");
        assert_eq!(display_safe("héllo ✓"), "héllo ✓");
        assert_eq!(display_safe(&"x".repeat(1000)).len(), MAX_DISPLAY);
    }
}
