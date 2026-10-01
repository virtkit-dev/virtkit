//! What `vk` and `vk-hub` say to each other, and nothing about how they say it. Transport,
//! storage and crypto stay with the two sides; this crate is the one place both read the
//! shapes from, so they cannot drift apart.
//!
//! **Workloads.** `vk workloads` prints the VMs running on its host for its user as a
//! [`WorkloadList`], one JSON document per line; `vk-hub local` reads it. The list's fields are
//! only ever added to, each optional, and [`WORKLOADS_VERSION`] changes only for a change an
//! older reader would misread.
//!
//! **Display.** Every string a host reports is the host's to choose; whoever prints one to a
//! terminal, a log or a page passes it through [`display_safe`] first.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The [`WorkloadList`] version this build writes and reads.
pub const WORKLOADS_VERSION: u32 = 1;

/// The most workloads a [`WorkloadList`] carries.
pub const MAX_WORKLOADS: usize = 256;

/// The most bytes a [`WorkloadList`]'s workloads take, serialized.
pub const MAX_WORKLOADS_BYTES: usize = 256 * 1024;

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

/// The longest string of a host's that is kept for display.
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
    fn display_safe_drops_what_rewrites_a_terminal() {
        assert_eq!(display_safe("ci-1\u{1b}[2J\r\n"), "ci-1[2J");
        assert_eq!(display_safe("a\u{202e}b\u{2066}c\u{200f}"), "abc");
        assert_eq!(display_safe("héllo ✓"), "héllo ✓");
        assert_eq!(display_safe(&"x".repeat(1000)).len(), MAX_DISPLAY);
    }
}
