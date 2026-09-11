//! Per-directory eviction policies in `files/.policy/<dir>.toml`: idle TTL, size cap, or both.
//! Only local store access can change policies; DAV write grants cannot raise limits. Server
//! sweeps and offline gc reread policies on each pass. Invalid policies are reported and their
//! directories are skipped; directories without policies are never swept.

use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::Store;

/// The reserved name under `files/` that holds the policy files, beside `.staging/`.
pub(crate) const POLICY_DIR: &str = ".policy";

/// Maximum policy file size, limiting memory use when reading invalid files.
const MAX_POLICY_FILE: u64 = 4096;

/// Policy file mode: owner-writable and group-readable.
const POLICY_MODE: u32 = 0o644;

/// Eviction limits for one directory. At least one must be set; remove the policy to disable
/// eviction.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PolicyFile", into = "PolicyFile")]
pub struct FilesPolicy {
    /// Objects idle this long are dropped. `Some(0)` drops everything on the next pass.
    pub ttl: Option<Duration>,
    /// Past this many bytes, the idlest objects are dropped until under it.
    pub max_bytes: Option<u64>,
}

/// On-disk policy format: TTL in days and a byte count or size string.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ttl_days: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_bytes: Option<Size>,
}

/// Accept a size string such as `"200G"` or an integer byte count.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Size {
    Text(String),
    Bytes(u64),
}

impl TryFrom<PolicyFile> for FilesPolicy {
    type Error = anyhow::Error;

    fn try_from(f: PolicyFile) -> Result<Self> {
        let ttl = f
            .ttl_days
            .map(|d| {
                d.checked_mul(86_400)
                    .map(Duration::from_secs)
                    .ok_or_else(|| anyhow::anyhow!("ttl_days = {d} is past any calendar"))
            })
            .transpose()?;
        let max_bytes = match f.max_bytes {
            None => None,
            Some(Size::Bytes(n)) => Some(n),
            Some(Size::Text(s)) => Some(parse_bytes(&s)?),
        };
        if ttl.is_none() && max_bytes.is_none() {
            bail!("a policy needs ttl_days, max_bytes, or both; to sweep nothing, remove it");
        }
        Ok(FilesPolicy { ttl, max_bytes })
    }
}

impl From<FilesPolicy> for PolicyFile {
    fn from(p: FilesPolicy) -> Self {
        PolicyFile {
            ttl_days: p.ttl.map(|t| t.as_secs() / 86_400),
            max_bytes: p.max_bytes.map(|n| Size::Text(render_bytes(n))),
        }
    }
}

impl FilesPolicy {
    /// Parse and validate a policy.
    pub fn parse(text: &str) -> Result<FilesPolicy> {
        toml::from_str(text).context("parsing a files/ policy")
    }

    /// The file for this policy, as `parse` reads it back.
    pub fn render(&self) -> String {
        toml::to_string(self).expect("a policy is two optional scalars")
    }

    /// The policy as one line for a report: `30d / 200 GiB`, `30d`, `200 GiB`.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if let Some(t) = self.ttl {
            parts.push(format!("{}d", t.as_secs() / 86_400));
        }
        if let Some(n) = self.max_bytes {
            parts.push(crate::human_bytes(n));
        }
        parts.join(" / ")
    }
}

/// A byte count as an operator types it: an integer with an optional binary suffix
/// `K`/`M`/`G`/`T`/`P`, optionally followed by `B` or `iB`, in any case, spaces allowed
/// before the suffix. `200G`, `200GiB`, `200 gb` and `214748364800` are the same size.
pub fn parse_bytes(s: &str) -> Result<u64> {
    let s = s.trim();
    let digits_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (digits, suffix) = s.split_at(digits_end);
    if digits.is_empty() {
        bail!("{s:?} is not a size: it has to start with a number");
    }
    let n: u64 = digits
        .parse()
        .with_context(|| format!("{s:?} is not a size: {digits:?} is too large"))?;
    let suffix = suffix.trim_start().to_ascii_lowercase();
    let suffix = suffix
        .strip_suffix("ib")
        .or_else(|| suffix.strip_suffix('b'))
        .unwrap_or(&suffix);
    let shift = match suffix {
        "" => 0,
        "k" => 10,
        "m" => 20,
        "g" => 30,
        "t" => 40,
        "p" => 50,
        _ => bail!("{s:?} is not a size: the unit has to be one of K, M, G, T, P"),
    };
    n.checked_shl(shift)
        .filter(|v| shift == 0 || v >> shift == n)
        .ok_or_else(|| anyhow::anyhow!("{s:?} is not a size: it overflows"))
}

/// Format whole binary units when possible, otherwise raw bytes, preserving the exact value.
fn render_bytes(n: u64) -> String {
    for (shift, unit) in [(50, 'P'), (40, 'T'), (30, 'G'), (20, 'M'), (10, 'K')] {
        if n != 0 && n.trailing_zeros() >= shift {
            return format!("{}{unit}", n >> shift);
        }
    }
    n.to_string()
}

/// Accept one valid repository-name component, excluding reserved dot-names.
pub(crate) fn valid_dir(dir: &str) -> bool {
    !dir.contains('/') && !crate::dav::reserved(dir) && crate::valid_name(dir)
}

/// One top-level directory as `status` and `files policy` report it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FilesDirStats {
    pub objects: u64,
    pub bytes: u64,
}

impl Store {
    /// Where the policy files live.
    pub fn files_policy_dir(&self) -> PathBuf {
        self.files_dir().join(POLICY_DIR)
    }

    /// Policy path after validating the directory name.
    pub fn files_policy_path(&self, dir: &str) -> Result<PathBuf> {
        if !valid_dir(dir) {
            bail!("{dir:?} is not a name a files/ directory can have");
        }
        Ok(self.files_policy_dir().join(format!("{dir}.toml")))
    }

    /// Read policies in directory-name order. Report invalid names, symlinks, oversized files
    /// and parse errors as Err entries. A missing `.policy/` yields an empty list.
    pub fn read_files_policies(&self) -> Result<Vec<(String, Result<FilesPolicy>)>> {
        let dir = self.files_policy_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
        };
        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.with_context(|| format!("listing {}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let policy = match name.strip_suffix(".toml").filter(|d| valid_dir(d)) {
                Some(d) => (d.to_string(), read_policy_file(&entry.path())),
                None => (
                    name.clone(),
                    Err(anyhow::anyhow!(
                        "{name:?} is not `<dir>.toml` for a directory files/ can hold"
                    )),
                ),
            };
            out.push(policy);
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    /// `dir`'s policy: `None` when there is no file, `Some(Err)` when the file is not a
    /// policy.
    pub fn read_files_policy(&self, dir: &str) -> Result<Option<Result<FilesPolicy>>> {
        let path = self.files_policy_path(dir)?;
        match std::fs::symlink_metadata(&path) {
            Ok(_) => Ok(Some(read_policy_file(&path))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("looking for {}", path.display())),
        }
    }

    /// Atomically replace the policy, or remove it with None. Removing an absent policy
    /// succeeds.
    pub fn write_files_policy(&self, dir: &str, policy: Option<&FilesPolicy>) -> Result<()> {
        let path = self.files_policy_path(dir)?;
        match policy {
            Some(p) => {
                let parent = self.files_policy_dir();
                std::fs::create_dir_all(&parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
                vk_fs::write_atomic(&path, p.render().as_bytes(), POLICY_MODE)
                    .with_context(|| format!("writing {}", path.display()))
            }
            None => match std::fs::remove_file(&path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
            },
        }
    }

    /// List valid top-level directories in sorted order, excluding reserved names.
    pub fn files_dirs(&self) -> Result<Vec<String>> {
        let dir = self.files_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
        };
        let mut names: Vec<String> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| valid_dir(n))
            .collect();
        names.sort();
        Ok(names)
    }

    /// Count regular files and bytes with the sweep's depth limit, skipping symlinks. A missing
    /// directory is empty.
    pub fn files_stats(&self, dir: &str) -> Result<FilesDirStats> {
        if !valid_dir(dir) {
            bail!("{dir:?} is not a name a files/ directory can have");
        }
        let mut stats = FilesDirStats::default();
        walk_files(&self.files_dir().join(dir), 0, &mut |_, meta| {
            stats.objects += 1;
            stats.bytes += meta.len();
        });
        Ok(stats)
    }
}

/// Read one policy file: a regular file, opened without following a symlink, no larger
/// than [`MAX_POLICY_FILE`], and a policy once parsed.
fn read_policy_file(path: &Path) -> Result<FilesPolicy> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("stat of {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a regular file", path.display());
    }
    if meta.len() > MAX_POLICY_FILE {
        bail!(
            "{} is {} bytes; a policy is a few lines",
            path.display(),
            meta.len()
        );
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut file, &mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    FilesPolicy::parse(&text).with_context(|| format!("in {}", path.display()))
}

/// Visit regular files using lstat, skipping symlinks and limiting depth to the DAV maximum.
/// Skip unreadable directories; this may undercount usage or leave objects unswept.
pub(crate) fn walk_files(
    dir: &Path,
    depth: usize,
    visit: &mut dyn FnMut(&Path, &std::fs::Metadata),
) {
    if depth > crate::dav::MAX_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            walk_files(&path, depth + 1, visit);
        } else if meta.is_file() {
            visit(&path, &meta);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "vk-registry-files-policy-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn days(n: u64) -> Duration {
        Duration::from_secs(n * 86_400)
    }

    /// Policies round-trip with either or both limits, including a zero TTL.
    #[test]
    fn a_policy_round_trips_through_its_file() {
        for p in [
            FilesPolicy {
                ttl: Some(days(30)),
                max_bytes: None,
            },
            FilesPolicy {
                ttl: None,
                max_bytes: Some(200 << 30),
            },
            FilesPolicy {
                ttl: Some(days(7)),
                max_bytes: Some(1234),
            },
            FilesPolicy {
                ttl: Some(Duration::ZERO),
                max_bytes: None,
            },
        ] {
            let text = p.render();
            assert_eq!(FilesPolicy::parse(&text).unwrap(), p, "{text}");
        }
        assert_eq!(
            FilesPolicy::parse("ttl_days = 30\nmax_bytes = \"200G\"\n").unwrap(),
            FilesPolicy {
                ttl: Some(days(30)),
                max_bytes: Some(200 << 30)
            }
        );
        // A bare integer is a size too.
        assert_eq!(
            FilesPolicy::parse("max_bytes = 4096").unwrap().max_bytes,
            Some(4096)
        );
        assert_eq!(
            FilesPolicy {
                ttl: Some(days(30)),
                max_bytes: Some(200 << 30)
            }
            .describe(),
            "30d / 200.0 GiB"
        );
    }

    /// Reject empty policies, unknown keys and invalid limits.
    #[test]
    fn what_is_not_a_policy_is_refused() {
        for bad in [
            "",
            "# nothing\n",
            "ttl_days = 30\nmax_byte = \"1G\"\n",
            "ttl_days = -1\n",
            "ttl_days = 1.5\n",
            "ttl_days = \"30\"\n",
            "max_bytes = \"12 pears\"\n",
            "max_bytes = \"G\"\n",
            "max_bytes = -5\n",
            "max_bytes = \"99999999999999999999\"\n",
            "ttl_days = 999999999999999\n",
            "not toml at all",
        ] {
            assert!(FilesPolicy::parse(bad).is_err(), "{bad:?}");
        }
    }

    /// Sizes as people write them, all binary, and the overflow refused.
    #[test]
    fn sizes_parse_in_binary_units() {
        for (text, n) in [
            ("0", 0),
            ("1024", 1024),
            ("1k", 1 << 10),
            ("1K", 1 << 10),
            ("1KiB", 1 << 10),
            ("1 kb", 1 << 10),
            ("200G", 200 << 30),
            ("200GiB", 200 << 30),
            ("200gb", 200 << 30),
            ("3T", 3 << 40),
            ("1P", 1 << 50),
            (" 7M ", 7 << 20),
        ] {
            assert_eq!(parse_bytes(text).unwrap(), n, "{text}");
        }
        for bad in [
            "",
            "G",
            "1X",
            "1.5G",
            "-1",
            "18446744073709551616",
            "16777216P",
        ] {
            assert!(parse_bytes(bad).is_err(), "{bad}");
        }
        assert_eq!(render_bytes(200 << 30), "200G");
        assert_eq!(render_bytes(1536), "1536");
        assert_eq!(render_bytes(0), "0");
    }

    /// The names a top-level directory may have: a repository-name component, never a
    /// reserved dot-name.
    #[test]
    fn only_a_plain_name_is_a_directory() {
        for ok in ["sccache", "ccache", "team-a.artifacts", "x_1"] {
            assert!(valid_dir(ok), "{ok}");
        }
        for bad in [
            ".staging", ".policy", ".", "..", "a/b", "bad dir", "", "tags",
        ] {
            assert!(!valid_dir(bad), "{bad}");
        }
    }

    /// Test policy reads, replacement, sorted listing, idempotent removal and name validation.
    #[test]
    fn the_store_writes_and_lists_policies() {
        let dir = tmp("store");
        let store = Store::new(dir.clone()).unwrap();
        assert!(store.read_files_policies().unwrap().is_empty());
        assert!(store.read_files_policy("sccache").unwrap().is_none());

        let sccache = FilesPolicy {
            ttl: Some(days(30)),
            max_bytes: Some(200 << 30),
        };
        let ccache = FilesPolicy {
            ttl: Some(days(7)),
            max_bytes: None,
        };
        store.write_files_policy("sccache", Some(&sccache)).unwrap();
        store.write_files_policy("ccache", Some(&ccache)).unwrap();
        let listed: Vec<(String, FilesPolicy)> = store
            .read_files_policies()
            .unwrap()
            .into_iter()
            .map(|(d, p)| (d, p.unwrap()))
            .collect();
        assert_eq!(
            listed,
            vec![
                ("ccache".to_string(), ccache.clone()),
                ("sccache".to_string(), sccache.clone())
            ]
        );
        assert_eq!(
            store
                .read_files_policy("sccache")
                .unwrap()
                .unwrap()
                .unwrap(),
            sccache
        );
        // The file is where the DAV layer keeps it out of reach, and readable.
        let path = dir.join("files/.policy/sccache.toml");
        assert!(path.is_file());

        // Replaced whole, not merged.
        store.write_files_policy("sccache", Some(&ccache)).unwrap();
        assert_eq!(
            store
                .read_files_policy("sccache")
                .unwrap()
                .unwrap()
                .unwrap(),
            ccache
        );

        store.write_files_policy("sccache", None).unwrap();
        store.write_files_policy("sccache", None).unwrap();
        assert!(store.read_files_policy("sccache").unwrap().is_none());
        assert_eq!(store.read_files_policies().unwrap().len(), 1);

        for bad in [".policy", ".staging", "a/b", "tags", ""] {
            assert!(
                store.write_files_policy(bad, Some(&ccache)).is_err(),
                "{bad}"
            );
            assert!(store.files_policy_path(bad).is_err(), "{bad}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Report malformed policies, symlinks, oversized files and invalid filenames.
    #[test]
    fn a_file_that_is_not_a_policy_is_reported_not_ignored() {
        let dir = tmp("invalid");
        let store = Store::new(dir.clone()).unwrap();
        let policy_dir = store.files_policy_dir();
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(policy_dir.join("garbage.toml"), "ttl_days = \"soon\"\n").unwrap();
        std::fs::write(policy_dir.join("huge.toml"), vec![b' '; 1 << 20]).unwrap();
        std::fs::write(policy_dir.join("notes.txt"), "ttl_days = 1\n").unwrap();
        std::fs::write(policy_dir.join(".hidden.toml"), "ttl_days = 1\n").unwrap();
        std::fs::write(dir.join("elsewhere.toml"), "ttl_days = 1\n").unwrap();
        std::os::unix::fs::symlink(dir.join("elsewhere.toml"), policy_dir.join("link.toml"))
            .unwrap();
        store
            .write_files_policy(
                "good",
                Some(&FilesPolicy {
                    ttl: Some(days(1)),
                    max_bytes: None,
                }),
            )
            .unwrap();

        let listed = store.read_files_policies().unwrap();
        let names: Vec<&str> = listed.iter().map(|(d, _)| d.as_str()).collect();
        assert_eq!(
            names,
            [
                ".hidden.toml",
                "garbage",
                "good",
                "huge",
                "link",
                "notes.txt"
            ]
        );
        for (name, policy) in &listed {
            assert_eq!(policy.is_ok(), name == "good", "{name}: {policy:?}");
        }
        assert!(store.read_files_policy("link").unwrap().unwrap().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Count regular files; exclude symlinks and reserved directories.
    #[test]
    fn directories_and_their_contents_are_counted() {
        let dir = tmp("stats");
        let store = Store::new(dir.clone()).unwrap();
        assert!(store.files_dirs().unwrap().is_empty());
        assert_eq!(store.files_stats("none").unwrap(), FilesDirStats::default());

        let files = store.files_dir();
        std::fs::create_dir_all(files.join("sccache/ab/cd")).unwrap();
        std::fs::create_dir_all(files.join("ccache")).unwrap();
        std::fs::create_dir_all(files.join(".staging")).unwrap();
        std::fs::create_dir_all(files.join(".policy")).unwrap();
        std::fs::write(files.join("stray-file"), "x").unwrap();
        std::fs::write(files.join("sccache/ab/cd/one"), vec![0u8; 100]).unwrap();
        std::fs::write(files.join("sccache/two"), vec![0u8; 50]).unwrap();
        std::fs::write(files.join(".staging/1-2"), vec![0u8; 999]).unwrap();
        std::os::unix::fs::symlink(files.join(".staging/1-2"), files.join("sccache/link")).unwrap();

        assert_eq!(store.files_dirs().unwrap(), ["ccache", "sccache"]);
        assert_eq!(
            store.files_stats("sccache").unwrap(),
            FilesDirStats {
                objects: 2,
                bytes: 150
            }
        );
        assert_eq!(
            store.files_stats("ccache").unwrap(),
            FilesDirStats::default()
        );
        assert!(store.files_stats(".staging").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
