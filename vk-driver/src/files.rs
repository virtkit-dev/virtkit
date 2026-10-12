//! Plain files in the build cache registry: `vk registry put|get`. They live in the
//! registry's `files/` area, the one its WebDAV view serves under `/dav/files/`:
//! `files/<dir>:<name>` is `/dav/files/<dir>/<name>`. Every file put is also tagged by its
//! digest in [`BY_DIGEST`], so whatever names it carries it can be fetched by content alone.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use crate::config::Registry;
use crate::registry::RawFile;

/// The repository holding every file put under its sha256 hex as the tag.
pub(crate) const BY_DIGEST: &str = "files/sha256";

/// How long the registry keeps a file put (`vk-registry gc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Retention {
    /// While it gets used: dropped once unused for the gc's retention window.
    Idle,
    /// For this long after the put, used or not.
    Ttl(Duration),
    /// Until a put says otherwise.
    Keep,
}

impl Retention {
    /// The manifest annotations that ask the registry for this retention, as of `now`.
    fn annotations(self, now: SystemTime) -> BTreeMap<String, String> {
        match self {
            Retention::Idle => BTreeMap::new(),
            Retention::Keep => BTreeMap::from([(
                vk_registry::RETENTION_ANNOTATION.to_string(),
                vk_registry::RETENTION_KEEP.to_string(),
            )]),
            Retention::Ttl(ttl) => {
                let at = (now + ttl)
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                BTreeMap::from([(vk_registry::EXPIRES_ANNOTATION.to_string(), at.to_string())])
            }
        }
    }
}

/// `30m`, `12h`, `7d`, or a bare number of seconds.
pub(crate) fn parse_ttl(text: &str) -> Result<Duration> {
    let (digits, unit) = text.split_at(
        text.find(|c: char| !c.is_ascii_digit())
            .unwrap_or(text.len()),
    );
    let n: u64 = digits
        .parse()
        .ok()
        .filter(|&n| n > 0)
        .with_context(|| format!("{text:?}: expected a duration such as 30m, 12h or 7d"))?;
    let unit = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => bail!("{text:?}: expected a duration such as 30m, 12h or 7d"),
    };
    Ok(Duration::from_secs(n.saturating_mul(unit)))
}

/// The repository and tag a file reference names: `sha256:<hex>` for [`BY_DIGEST`], or a
/// `files/` path, `[files/]<dir>/<name>`.
pub(crate) fn parse_ref(text: &str) -> Result<(String, String)> {
    if let Some(hex) = text.strip_prefix("sha256:") {
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{text:?}: a digest is sha256: and 64 hex digits");
        }
        return Ok((BY_DIGEST.to_string(), hex.to_ascii_lowercase()));
    }
    let path = text.strip_prefix("files/").unwrap_or(text);
    match path.rsplit_once('/') {
        Some((dir, name)) if !dir.is_empty() && !name.is_empty() => {
            Ok((format!("files/{dir}"), name.to_string()))
        }
        _ => bail!("{text:?}: expected sha256:<hex> or <dir>/<name>"),
    }
}

/// Put the file at `path` in `rg`, tagged by its digest and, given `dir`, as `<dir>/<its
/// name>`. Returns its sha256 hex and the references it can be fetched by.
pub(crate) fn put(
    rg: &Registry,
    path: &Path,
    dir: Option<&str>,
    retention: Retention,
) -> Result<(String, Vec<String>)> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("{}: no file name", path.display()))?;
    let dir = dir.map(|d| d.trim_matches('/').trim_start_matches("files/").to_string());
    let sha256 = crate::winiso::sha256_file(path)?;
    let mut tags: Vec<(String, String)> = vec![(BY_DIGEST.to_string(), sha256.clone())];
    if let Some(dir) = &dir {
        tags.push((format!("files/{dir}"), name.to_string()));
    }
    let pairs: Vec<(&str, &str)> = tags.iter().map(|(r, t)| (r.as_str(), t.as_str())).collect();
    let annotations = retention.annotations(SystemTime::now());
    crate::registry::put_raw_file(rg, &pairs, path, &sha256, Some(name), &annotations)?;
    let mut refs = vec![format!("sha256:{sha256}")];
    if let Some(dir) = dir {
        refs.push(format!("{dir}/{name}"));
    }
    Ok((sha256, refs))
}

/// Fetch the file `reference` names ([`parse_ref`]) to `dest`, or, without one, to its
/// name in the current directory. `None` when the registry has no such file.
pub(crate) fn get(
    rg: &Registry,
    reference: &str,
    dest: Option<&Path>,
) -> Result<Option<(RawFile, std::path::PathBuf)>> {
    let (repo, tag) = parse_ref(reference)?;
    let dest = match dest {
        Some(d) => d.to_path_buf(),
        None => {
            let Some(file) = crate::registry::raw_file(rg, &repo, &tag)? else {
                return Ok(None);
            };
            // The title is the uploader's: only its last component, never a path.
            let name = file
                .title
                .as_deref()
                .and_then(|t| Path::new(t).file_name())
                .map_or_else(|| tag.clone().into(), |n| n.to_os_string());
            name.into()
        }
    };
    Ok(crate::registry::pull_raw_file(rg, &repo, &tag, &dest)?.map(|f| (f, dest)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_name_a_repository_and_tag() {
        let hex = "ab".repeat(32);
        assert_eq!(
            parse_ref(&format!("sha256:{hex}")).unwrap(),
            (BY_DIGEST.to_string(), hex.clone())
        );
        for r in ["iso/ws2025.iso", "files/iso/ws2025.iso"] {
            assert_eq!(
                parse_ref(r).unwrap(),
                ("files/iso".to_string(), "ws2025.iso".to_string())
            );
        }
        assert_eq!(
            parse_ref("a/b/c").unwrap(),
            ("files/a/b".to_string(), "c".to_string())
        );
        for bad in ["sha256:abc", "name", "dir/", "/name"] {
            assert!(parse_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ttls_read_as_durations() {
        assert_eq!(parse_ttl("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_ttl("7d").unwrap(), Duration::from_secs(7 * 86_400));
        for bad in ["", "0", "7w", "d", "-1h"] {
            assert!(parse_ttl(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_retention_is_the_annotations_gc_reads() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        assert!(Retention::Idle.annotations(now).is_empty());
        assert_eq!(
            Retention::Ttl(Duration::from_secs(60)).annotations(now)
                [vk_registry::EXPIRES_ANNOTATION],
            "1060"
        );
        assert_eq!(
            Retention::Keep.annotations(now)[vk_registry::RETENTION_ANNOTATION],
            vk_registry::RETENTION_KEEP
        );
    }

    /// Through a store on disk: put under a digest and a name, read back by either.
    #[test]
    fn a_file_round_trips_through_a_local_store() {
        let dir = std::env::temp_dir().join(format!("vk-files-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let rg = Registry::for_share(
            dir.join("store").display().to_string(),
            false,
            None,
            String::new(),
            None,
            None,
            None,
        );
        let src = dir.join("medium.iso");
        std::fs::write(&src, b"an install medium").unwrap();
        let (sha256, refs) = put(&rg, &src, Some("iso"), Retention::Keep).unwrap();
        assert_eq!(
            refs,
            [format!("sha256:{sha256}"), "iso/medium.iso".to_string()]
        );
        for r in &refs {
            let out = dir.join("out");
            let (file, _) = get(&rg, r, Some(&out)).unwrap().unwrap();
            assert_eq!(file.title.as_deref(), Some("medium.iso"));
            assert_eq!(std::fs::read(&out).unwrap(), b"an install medium");
        }
        assert!(
            get(&rg, "iso/absent", Some(&dir.join("none")))
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
