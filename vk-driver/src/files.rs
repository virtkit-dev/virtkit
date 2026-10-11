//! Plain files in the build cache registry: `vk registry put|get` and the install media a
//! `winiso:` stage pins. WebDAV serves `files/<dir>:<name>` at `/dav/files/<dir>/<name>`.
//! Every file is also tagged by digest in [`BY_DIGEST`], so a Dockerfile pinning
//! `<file>@sha256:<hex>` can fetch it by content regardless of its names.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};

use crate::config::Registry;
use crate::registry::RawFile;

/// The repository holding every file put under its sha256 hex as the tag.
pub(crate) const BY_DIGEST: &str = "files/sha256";

/// How long the registry keeps a file put (`vk-registry gc`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PutRetention {
    /// While it gets used: dropped once unused for the gc's retention window.
    Idle,
    /// For this long after the put, used or not.
    Ttl(Duration),
    /// Until a put says otherwise.
    Keep,
}

impl PutRetention {
    /// Manifest retention annotations as of `now`. A TTL beyond `SystemTime` uses the
    /// maximum expiry, which the registry treats as keep. An expiry before the Unix epoch
    /// is rejected.
    fn annotations(self, now: SystemTime) -> Result<BTreeMap<String, String>> {
        Ok(match self {
            PutRetention::Idle => BTreeMap::new(),
            PutRetention::Keep => BTreeMap::from([(
                vk_registry::RETENTION_ANNOTATION.to_string(),
                vk_registry::RETENTION_KEEP.to_string(),
            )]),
            PutRetention::Ttl(ttl) => {
                let at = match now.checked_add(ttl) {
                    Some(t) => t
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .context("the clock is set before 1970: no expiry to give")?
                        .as_secs(),
                    None => u64::MAX,
                };
                BTreeMap::from([(vk_registry::EXPIRES_ANNOTATION.to_string(), at.to_string())])
            }
        })
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
    n.checked_mul(unit)
        .map(Duration::from_secs)
        .with_context(|| format!("{text:?}: too long a duration"))
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
            let repo = format!("files/{dir}");
            check_name(&repo, name)?;
            Ok((repo, name.to_string()))
        }
        _ => bail!("{text:?}: expected sha256:<hex> or <dir>/<name>"),
    }
}

/// Refuse a `(repo, tag)` a registry would refuse: the store's path rules and the OCI
/// reference grammar (lowercase repositories, tags of at most 128 characters) alike.
fn check_name(repo: &str, tag: &str) -> Result<()> {
    if !vk_registry::valid_name(repo)
        || !vk_registry::valid_tag(tag)
        || format!("example.invalid/{repo}:{tag}")
            .parse::<oci_client::Reference>()
            .is_err()
    {
        bail!("{repo}/{tag} is not a name the registry takes");
    }
    Ok(())
}

/// Put the file at `path` in `rg`, tagged by its digest and, given `dir`, as `<dir>/<its
/// name>`. Every name is checked before the file is read, so a put that the registry would
/// refuse fails before it hashes or uploads anything. Returns its sha256 hex and the
/// references it can be fetched by.
pub(crate) fn put(
    rg: &Registry,
    path: &Path,
    dir: Option<&str>,
    retention: PutRetention,
) -> Result<(String, Vec<String>)> {
    // Without --dir, a non-UTF-8 file name only omits the title.
    let name = path.file_name().and_then(|n| n.to_str());
    let dir = dir.map(|d| {
        let d = d.trim_matches('/');
        let d = if d == "files" { "" } else { d };
        d.strip_prefix("files/").unwrap_or(d).to_string()
    });
    let named = match &dir {
        Some(dir) => {
            let repo = format!("files/{dir}");
            if repo == BY_DIGEST || repo.starts_with(&format!("{BY_DIGEST}/")) {
                bail!("--dir {dir} is where files are named by digest; pick another");
            }
            let name =
                name.with_context(|| format!("{}: --dir needs a UTF-8 file name", path.display()))?;
            check_name(&repo, name)?;
            Some((dir, name))
        }
        None => None,
    };
    let annotations = retention.annotations(SystemTime::now())?;
    let (sha256, size) = crate::registry::hash_file(path)?;
    let mut tags: Vec<(String, String)> = vec![(BY_DIGEST.to_string(), sha256.clone())];
    if let Some((dir, name)) = named {
        tags.push((format!("files/{dir}"), name.to_string()));
    }
    let pairs: Vec<(&str, &str)> = tags.iter().map(|(r, t)| (r.as_str(), t.as_str())).collect();
    crate::registry::put_raw_file(rg, &pairs, path, &sha256, size, name, &annotations)?;
    let mut refs = vec![format!("sha256:{sha256}")];
    if let Some((dir, name)) = named {
        refs.push(format!("{dir}/{name}"));
    }
    Ok((sha256, refs))
}

/// The raw file tagged `<repo>:<tag>`. One tagged by digest must be the file of that digest:
/// whoever can write [`BY_DIGEST`] could otherwise tag any file under any other's hex.
fn locate(rg: &Registry, repo: &str, tag: &str) -> Result<Option<RawFile>> {
    let file = crate::registry::raw_file(rg, repo, tag)?;
    if let Some(file) = &file
        && repo == BY_DIGEST
        && file.sha256 != tag
    {
        bail!("sha256:{tag} names a file whose sha256 is {}", file.sha256);
    }
    Ok(file)
}

/// Where [`get`] writes the file it fetches.
pub(crate) enum Dest<'a> {
    /// This path, replacing whatever is there.
    File(&'a Path),
    /// This directory, under the file's name — the one the reference gives, or for a digest
    /// the last component of the name it was put with unless that is a dotfile, else the
    /// digest — and never over a file that exists.
    Into(&'a Path),
}

/// Fetch the file `reference` names ([`parse_ref`]) to `dest`. `None` when the registry has
/// no such file.
pub(crate) fn get(
    rg: &Registry,
    reference: &str,
    dest: Dest,
) -> Result<Option<(RawFile, PathBuf)>> {
    let (repo, tag) = parse_ref(reference)?;
    let Some(file) = locate(rg, &repo, &tag)? else {
        return Ok(None);
    };
    let (dest, replace) = match dest {
        Dest::File(path) => (path.to_path_buf(), true),
        Dest::Into(dir) => {
            // The title is the uploader's: only its last component, never a path, and never
            // a dotfile, which tools run in that directory may load as their configuration.
            let titled = (repo == BY_DIGEST)
                .then_some(file.title.as_deref())
                .flatten();
            let name = titled
                .and_then(|t| Path::new(t).file_name())
                .filter(|n| !n.as_encoded_bytes().starts_with(b"."))
                .map_or_else(|| tag.clone().into(), |n| n.to_os_string());
            (dir.join(name), false)
        }
    };
    crate::registry::pull_raw_file(rg, &repo, &tag, &file, &dest, replace)?;
    Ok(Some((file, dest)))
}

/// Fetch the file whose sha256 is `sha256` to `dest`, replacing what is there: `false` when
/// the registry has none.
pub(crate) fn fetch(rg: &Registry, sha256: &str, dest: &Path) -> Result<bool> {
    let Some(file) = locate(rg, BY_DIGEST, sha256)? else {
        return Ok(false);
    };
    crate::registry::pull_raw_file(rg, BY_DIGEST, sha256, &file, dest, true)?;
    Ok(true)
}

/// Whether the registry holds the file whose sha256 is `sha256`. Asking counts as a use,
/// so it keeps an idle file from expiring.
pub(crate) fn exists(rg: &Registry, sha256: &str) -> bool {
    crate::registry::exists(rg, BY_DIGEST, sha256)
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
        for bad in [
            "sha256:abc",
            "name",
            "dir/",
            "/name",
            "ISO/x",
            "iso/..",
            "iso/a b",
        ] {
            assert!(parse_ref(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ttls_read_as_durations() {
        assert_eq!(parse_ttl("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_ttl("7d").unwrap(), Duration::from_secs(7 * 86_400));
        for bad in ["", "0", "7w", "d", "-1h", "213503982334602d"] {
            assert!(parse_ttl(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_retention_is_the_annotations_gc_reads() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        assert!(PutRetention::Idle.annotations(now).unwrap().is_empty());
        assert_eq!(
            PutRetention::Ttl(Duration::from_secs(60))
                .annotations(now)
                .unwrap()[vk_registry::EXPIRES_ANNOTATION],
            "1060"
        );
        assert_eq!(
            PutRetention::Keep.annotations(now).unwrap()[vk_registry::RETENTION_ANNOTATION],
            vk_registry::RETENTION_KEEP
        );
        // A TTL past what a SystemTime holds asks for the furthest expiry, without panicking.
        assert_eq!(
            PutRetention::Ttl(Duration::MAX).annotations(now).unwrap()
                [vk_registry::EXPIRES_ANNOTATION],
            u64::MAX.to_string()
        );
    }

    /// Through a store on disk: put under a digest and a name, read back by either, and
    /// the digest is what a `winiso:` stage fetches by.
    #[test]
    fn a_file_round_trips_through_a_local_store() {
        let dir = std::env::temp_dir().join(format!("vk-files-{}", std::process::id()));
        let rg = local_registry(&dir);
        let src = dir.join("medium.iso");
        std::fs::write(&src, b"an install medium").unwrap();
        let (sha256, refs) = put(&rg, &src, Some("iso"), PutRetention::Keep).unwrap();
        assert_eq!(
            refs,
            [format!("sha256:{sha256}"), "iso/medium.iso".to_string()]
        );
        assert!(exists(&rg, &sha256));
        for r in &refs {
            let out = dir.join("out");
            let (file, _) = get(&rg, r, Dest::File(&out)).unwrap().unwrap();
            assert_eq!(file.title.as_deref(), Some("medium.iso"));
            assert_eq!(std::fs::read(&out).unwrap(), b"an install medium");
        }
        let fetched = dir.join("fetched");
        assert!(fetch(&rg, &sha256, &fetched).unwrap());
        assert_eq!(std::fs::read(&fetched).unwrap(), b"an install medium");
        assert!(!fetch(&rg, &"0".repeat(64), &dir.join("none")).unwrap());
        assert!(
            get(&rg, "iso/absent", Dest::File(&dir.join("none")))
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The retention a put asks for is the one the stored manifest carries, under the digest
    /// as under the name; a later put of the same file sets the digest's anew, even from
    /// another `--dir` and without a flag.
    #[test]
    fn a_put_sets_the_retention_of_its_digest_anew() {
        let dir = std::env::temp_dir().join(format!("vk-files-ret-{}", std::process::id()));
        let rg = local_registry(&dir);
        let src = dir.join("medium.iso");
        std::fs::write(&src, b"an install medium").unwrap();
        let store = vk_registry::Store::new(dir.join("store")).unwrap();
        let retention = |repo: &str, tag: &str| {
            let (_, manifest, _) = store.get_manifest(repo, tag).unwrap().unwrap();
            vk_registry::Retention::of_manifest(&manifest)
        };
        let before = SystemTime::now();
        let ttl = Duration::from_secs(3600);
        let (sha256, _) = put(&rg, &src, Some("iso"), PutRetention::Ttl(ttl)).unwrap();
        for (repo, tag) in [(BY_DIGEST, sha256.as_str()), ("files/iso", "medium.iso")] {
            let vk_registry::Retention::Until(at) = retention(repo, tag) else {
                panic!("{repo}:{tag} has no expiry");
            };
            // Whole seconds: the expiry is at most a second short of the put's own clock.
            assert!(at + Duration::from_secs(1) >= before + ttl, "{repo}:{tag}");
            assert!(at <= SystemTime::now() + ttl, "{repo}:{tag}");
        }
        put(&rg, &src, Some("iso"), PutRetention::Keep).unwrap();
        assert_eq!(retention(BY_DIGEST, &sha256), vk_registry::Retention::Keep);
        put(&rg, &src, Some("other"), PutRetention::Idle).unwrap();
        assert_eq!(retention(BY_DIGEST, &sha256), vk_registry::Retention::Idle);
        assert_eq!(
            retention("files/iso", "medium.iso"),
            vk_registry::Retention::Keep
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A registry on a store under a fresh `dir`.
    fn local_registry(dir: &Path) -> Registry {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).unwrap();
        Registry::for_share(
            dir.join("store").display().to_string(),
            false,
            None,
            String::new(),
            None,
            None,
            None,
        )
    }

    /// A name the registry would refuse fails the put before anything is stored, and no
    /// `--dir` can pose as the digest area.
    #[test]
    fn a_bad_name_fails_the_put_up_front() {
        let dir = std::env::temp_dir().join(format!("vk-files-bad-{}", std::process::id()));
        let rg = local_registry(&dir);
        let src = dir.join("medium.iso");
        std::fs::write(&src, b"an install medium").unwrap();
        let spaced = dir.join("a name");
        std::fs::write(&spaced, b"x").unwrap();
        for (path, d) in [
            (&src, "ISO"),
            (&src, "/"),
            (&src, "sha256"),
            (&src, "files/sha256"),
            (&src, "sha256/sub"),
            (&src, "files"),
            (&src, "files/"),
            (&spaced, "iso"),
        ] {
            assert!(put(&rg, path, Some(d), PutRetention::Idle).is_err(), "{d}");
        }
        let (sha256, _) = crate::registry::hash_file(&src).unwrap();
        assert!(
            crate::registry::raw_file(&rg, BY_DIGEST, &sha256)
                .unwrap()
                .is_none()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file tagged under a digest that is not its own is refused, not fetched.
    #[test]
    fn a_digest_tag_must_name_its_own_file() {
        let dir = std::env::temp_dir().join(format!("vk-files-forged-{}", std::process::id()));
        let rg = local_registry(&dir);
        let src = dir.join("planted.iso");
        std::fs::write(&src, b"not the medium").unwrap();
        let (sha256, size) = crate::registry::hash_file(&src).unwrap();
        let other = "ab".repeat(32);
        crate::registry::put_raw_file(
            &rg,
            &[(BY_DIGEST, &other)],
            &src,
            &sha256,
            size,
            None,
            &BTreeMap::new(),
        )
        .unwrap();
        let out = dir.join("out");
        assert!(get(&rg, &format!("sha256:{other}"), Dest::File(&out)).is_err());
        assert!(!out.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fetched into a directory, a file takes the last component of the name it was put
    /// with — never a path — and never replaces a file already there.
    #[test]
    fn a_file_fetched_into_a_directory_is_named_safely() {
        let dir = std::env::temp_dir().join(format!("vk-files-into-{}", std::process::id()));
        let rg = local_registry(&dir);
        let into = dir.join("into");
        std::fs::create_dir(&into).unwrap();
        std::fs::write(into.join("Makefile"), b"mine").unwrap();
        let mut expected = vec!["Makefile".to_string()];
        for (title, landed) in [
            ("../x", "x"),
            ("/etc/passwd", "passwd"),
            ("..", ""),
            (".envrc", ""),
        ] {
            let src = dir.join("src");
            std::fs::write(&src, title).unwrap();
            let (sha256, size) = crate::registry::hash_file(&src).unwrap();
            let tags = [(BY_DIGEST, sha256.as_str())];
            crate::registry::put_raw_file(
                &rg,
                &tags,
                &src,
                &sha256,
                size,
                Some(title),
                &BTreeMap::new(),
            )
            .unwrap();
            let (_, dest) = get(&rg, &format!("sha256:{sha256}"), Dest::Into(&into))
                .unwrap()
                .unwrap();
            // No usable last component, or a dotfile: the digest names it.
            let landed = if landed.is_empty() { &sha256 } else { landed };
            assert_eq!(dest, into.join(landed), "{title}");
            expected.push(landed.to_string());
            assert_eq!(std::fs::read(&dest).unwrap(), title.as_bytes());
        }
        let src = dir.join("Makefile");
        std::fs::write(&src, b"theirs").unwrap();
        let (sha256, _) = put(&rg, &src, Some("dot"), PutRetention::Idle).unwrap();
        for r in [format!("sha256:{sha256}"), "dot/Makefile".to_string()] {
            assert!(get(&rg, &r, Dest::Into(&into)).is_err(), "{r}");
            assert_eq!(std::fs::read(into.join("Makefile")).unwrap(), b"mine");
        }
        // Nothing staged is left behind: the directory holds exactly what landed.
        let mut left: Vec<_> = std::fs::read_dir(&into)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        expected.sort();
        assert_eq!(left, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
