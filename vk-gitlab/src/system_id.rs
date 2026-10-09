//! The system ID GitLab tells runner managers apart by. Port of gitlab-runner's
//! `commands/internal/configfile/system_id_state.go`: `s_` and twelve hex digits derived
//! from the machine ID, or `r_` and twelve random alphanumerics without one, kept in a
//! state file so it survives restarts.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use ring::hmac;

use crate::backoff::{hex, random_bytes};

const ID_LEN: usize = 12;

/// `^[sr]_[0-9a-zA-Z]{12}$`
pub fn is_valid(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("s_").or_else(|| id.strip_prefix("r_")) else {
        return false;
    };
    rest.len() == ID_LEN && rest.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// The ID derived from `machine_id`. Keyed on this program's name rather than
/// gitlab-runner's, so a vk-gitlab and a gitlab-runner on one host stay distinct managers.
pub fn from_machine_id(machine_id: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, machine_id.as_bytes());
    let tag = hmac::sign(&key, b"vk-gitlab");
    let digest = hex(tag.as_ref());
    format!("s_{}", &digest[..ID_LEN])
}

fn random_id() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // 62 does not divide 256: reject the top of the byte range to stay uniform.
    let limit = 256 - 256 % CHARSET.len();
    let mut out = String::from("r_");
    while out.len() < 2 + ID_LEN {
        for b in random_bytes::<32>() {
            let b = usize::from(b);
            if b < limit && out.len() < 2 + ID_LEN {
                out.push(char::from(CHARSET[b % CHARSET.len()]));
            }
        }
    }
    out
}

fn machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// A fresh system ID for this host.
pub fn generate() -> String {
    machine_id().map_or_else(random_id, |m| from_machine_id(&m))
}

/// The system ID stored at `path`, created there (mode 0600) when missing or malformed. A
/// file that cannot be written leaves the ID in effect for this run only, as upstream.
pub fn load_or_create(path: &Path) -> Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) if is_valid(s.trim()) => return Ok(s.trim().to_owned()),
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    let id = generate();
    log::info!(system_id = id.as_str(); "Created missing unique system ID");
    if let Err(e) = store(path, &id) {
        log::warn!(
            state_file = path.display().to_string().as_str(),
            system_id = id.as_str(),
            error = format!("{e:#}").as_str();
            "Couldn't save the new system ID; the next start will use another one"
        );
    }
    Ok(id)
}

/// Writes `id` beside `path` and renames it into place, so a reader never sees half a file,
/// then syncs the directory so the rename survives a crash.
fn store(path: &Path, id: &str) -> Result<()> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let tmp = dir.join(format!(
        ".{}.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("system-id"),
        hex(&random_bytes::<6>())
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let written = f.write_all(id.as_bytes()).and_then(|()| f.sync_all());
    drop(f);
    if let Err(e) = written.and_then(|()| std::fs::rename(&tmp, path)) {
        // The temporary file is ours and useless now; failing to remove it changes nothing.
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("syncing {}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let s = from_machine_id("0123456789abcdef0123456789abcdef");
        assert!(is_valid(&s), "{s}");
        assert!(s.starts_with("s_"));
        assert_eq!(s, from_machine_id("0123456789abcdef0123456789abcdef"));
        let r = random_id();
        assert!(is_valid(&r), "{r}");
        assert!(r.starts_with("r_"));
        for bad in [
            "",
            "s_",
            "x_abcdefabcdef",
            "s_abc",
            "s_abcdefabcde!",
            "s_abcdefabcdefg",
        ] {
            assert!(!is_valid(bad), "{bad}");
        }
    }
}
