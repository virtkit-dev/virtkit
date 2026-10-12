//! The pieces of a self-update on trial: a release downloaded from the hub under the peer's
//! signature, published by rename, and executed in place of the running process with
//! `alarm(2)` armed so that a release that hangs is ended.

use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::identity::Identity;

/// How long a download may go without a byte arriving.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long past a trial's deadline `alarm(2)` ends the release: the release's own rollback
/// at the deadline comes first, and the alarm is there for one that hangs.
pub const ALARM_MARGIN: u64 = 60;

/// An open binary: [`exec`] runs the file checked through this descriptor, even if its
/// path has changed.
pub struct Binary {
    path: PathBuf,
    file: std::fs::File,
}

impl Binary {
    /// `path`, opened, and hashing to `sha256` when given.
    pub fn open(path: &Path, sha256: Option<&str>) -> Result<Self> {
        let file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        if let Some(want) = sha256 {
            let got =
                hash_reader(&file, None).with_context(|| format!("reading {}", path.display()))?;
            if got != want {
                bail!("{} hashes to {got}, not {want}", path.display());
            }
        }
        Ok(Binary {
            path: path.to_path_buf(),
            file,
        })
    }

    /// Where it was opened from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The open file, checked when it was opened.
    pub fn file(&self) -> &std::fs::File {
        &self.file
    }
}

/// Whether `path` is inside `dir`, both resolved.
pub fn under(path: &Path, dir: &Path) -> bool {
    match (std::fs::canonicalize(path), std::fs::canonicalize(dir)) {
        (Ok(p), Ok(d)) => p.starts_with(d),
        // What cannot be resolved is not taken as outside.
        _ => true,
    }
}

/// Arm `alarm(2)` for [`ALARM_MARGIN`] past the trial deadline `deadline`, or disarm it.
pub fn alarm(deadline: Option<u64>, now: u64) {
    let secs = alarm_secs(deadline, now);
    if secs != 0 {
        // An ignored or blocked SIGALRM is inherited across exec, and would leave no deadline
        // at all. This thread's mask is the one `fexecve` passes on.
        // SAFETY: restores the default action, no handler of this process's is replaced, and
        // unblocks SIGALRM in this thread through a local, initialized set.
        unsafe {
            libc::signal(libc::SIGALRM, libc::SIG_DFL);
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGALRM);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        }
    }
    // SAFETY: `alarm` takes a count and touches no memory.
    unsafe { libc::alarm(secs) };
}

/// The count [`alarm`] passes to `alarm(2)`: 0 disarms, else at least a second from `now`.
pub fn alarm_secs(deadline: Option<u64>, now: u64) -> libc::c_uint {
    deadline.map_or(0, |d| {
        let at = d.saturating_add(ALARM_MARGIN);
        libc::c_uint::try_from(at.saturating_sub(now).max(1)).unwrap_or(libc::c_uint::MAX)
    })
}

/// Execute `binary` in place of this process, with its arguments and environment; returns
/// only on failure. It runs from its open file, which is close-on-exec, so it must be an ELF
/// binary: a script's interpreter could not open it. `alarm(2)` is armed for the trial
/// deadline `alarm_at` across the exec, so a release that never gets as far as arming its own
/// — one that hangs before, or is not a `vk` at all — is ended all the same; without one, it
/// is disarmed.
pub fn exec(binary: &Binary, alarm_at: Option<u64>) -> anyhow::Error {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;
    let shown = binary.path.display();
    let cstrings = |items: Vec<Vec<u8>>| -> Result<Vec<CString>> {
        items
            .into_iter()
            .map(|b| CString::new(b).context("a NUL in an argument or the environment"))
            .collect()
    };
    let argv = cstrings(
        std::env::args_os()
            .map(|a| a.into_encoded_bytes())
            .collect(),
    );
    let envp = cstrings(
        std::env::vars_os()
            .map(|(k, v)| {
                let mut kv = k.into_encoded_bytes();
                kv.push(b'=');
                kv.extend_from_slice(v.as_encoded_bytes());
                kv
            })
            .collect(),
    );
    let (argv, envp) = match (argv, envp) {
        (Ok(a), Ok(e)) => (a, e),
        (Err(e), _) | (_, Err(e)) => return e.context(format!("executing {shown}")),
    };
    let pointers = |v: &[CString]| -> Vec<*const libc::c_char> {
        v.iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect()
    };
    let (argv_p, envp_p) = (pointers(&argv), pointers(&envp));
    alarm(alarm_at, crate::now_secs());
    // SAFETY: both arrays are NULL-terminated and point into `argv` and `envp`, which outlive
    // the call; the descriptor is open.
    unsafe { libc::fexecve(binary.file.as_raw_fd(), argv_p.as_ptr(), envp_p.as_ptr()) };
    let e = std::io::Error::last_os_error();
    // Not executed: no alarm is left to end this process.
    alarm(None, 0);
    anyhow!(e).context(format!("executing {shown}"))
}

/// Whether this process runs the file at `path`: the same inode, not the same name.
pub fn running_is(path: &Path) -> bool {
    match (std::fs::metadata("/proc/self/exe"), std::fs::metadata(path)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

static OWN_SHA256: OnceLock<Option<String>> = OnceLock::new();

/// The sha256 of the running binary, hex, read once: a few hundred megabytes, so `vk node
/// run` reads it before its first session rather than in the middle of one.
pub fn own_sha256() -> Option<String> {
    OWN_SHA256
        .get_or_init(|| hash_file(Path::new("/proc/self/exe")).ok())
        .clone()
}

/// [`own_sha256`] if it has been read, without reading it.
pub fn known_sha256() -> Option<String> {
    OWN_SHA256.get().cloned().flatten()
}

pub fn hash_file(path: &Path) -> Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    hash_reader(file, None).with_context(|| format!("reading {}", path.display()))
}

/// The sha256 of what `from` reads, hex, written on to `to` as it goes when given.
pub fn hash_reader(
    mut from: impl std::io::Read,
    mut to: Option<&mut std::fs::File>,
) -> Result<String> {
    use std::io::Write;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = from.read(&mut buf)?;
        let Some(chunk) = buf.get(..n).filter(|c| !c.is_empty()) else {
            break;
        };
        hasher.update(chunk);
        if let Some(out) = to.as_mut() {
            out.write_all(chunk)?;
        }
    }
    Ok(vk_hub_proto::to_hex(&hasher.finalize()))
}

/// Build the message a download is signed over, from the peer's ID, the digest, the time and
/// the channel.
pub type SignFn =
    fn(&str, &[u8; vk_hub_proto::SHA256_LEN], u64, vk_hub_proto::Channel<'_>) -> Vec<u8>;

/// A file a peer downloads from its hub by digest, under its signature.
pub struct Download<'a> {
    /// The hub's base URL, and the TLS it is reached with.
    pub hub: &'a str,
    pub tls: &'a Arc<rustls::ClientConfig>,
    /// Who asks: the peer's key, its ID and the header the ID goes in.
    pub identity: &'a Identity,
    pub id: &'a str,
    pub id_header: &'static str,
    /// Where the hub serves it, the sha256 to follow, and what the peer signs to download it.
    pub path: &'static str,
    pub sign: SignFn,
    /// Its sha256, lowercase hex.
    pub sha256: &'a str,
    /// Maximum size in bytes.
    pub size: u64,
    /// The permission bits it is published with.
    pub mode: u32,
}

/// Download `fetch` from the hub, publishing it at `dest` after validation.
/// Only individual reads time out; callers must bound the whole transfer.
pub async fn download(fetch: &Download<'_>, dest: &Path) -> Result<()> {
    let digest = vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SHA256_LEN }>(fetch.sha256)
        .with_context(|| format!("the sha256 {:?} is not valid", fetch.sha256))?;
    if fetch.mode & !0o777 != 0 {
        bail!("mode {:o} is more than permission bits", fetch.mode);
    }
    let dir = dest.parent().context("the download has no directory")?;
    let tmp = dir.join(format!(".{}.{}.tmp", fetch.sha256, std::process::id()));
    let outcome = download_into(fetch, &digest, &tmp).await.and_then(|()| {
        std::fs::rename(&tmp, dest).with_context(|| format!("publishing {}", dest.display()))?;
        if let Ok(d) = std::fs::File::open(dir) {
            // Best effort, as vk-selfupdate's publish: the rename has happened.
            let _ = d.sync_all();
        }
        Ok(())
    });
    if outcome.is_err() {
        // Best-effort cleanup preserves the download error; the caller's sweep handles leftovers.
        let _ = std::fs::remove_file(&tmp);
    }
    outcome
}

async fn download_into(
    fetch: &Download<'_>,
    digest: &[u8; vk_hub_proto::SHA256_LEN],
    tmp: &Path,
) -> Result<()> {
    use http_body_util::BodyExt;
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let (io, exported, authority) = crate::session::dial(fetch.hub, fetch.tls).await?;
    let channel = match &exported {
        Some(e) => vk_hub_proto::Channel::Tls(e),
        None => vk_hub_proto::Channel::Plaintext,
    };
    let at = crate::now_secs();
    let signature = fetch
        .identity
        .sign(&(fetch.sign)(fetch.id, digest, at, channel));
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
            .await
            .context("opening the download")?;
    let driver = tokio::spawn(conn);
    let request = hyper::Request::get(format!("{}{}", fetch.path, fetch.sha256))
        .header(hyper::header::HOST, authority)
        .header(fetch.id_header, fetch.id)
        .header(vk_hub_proto::TIME_HEADER, at.to_string())
        .header(vk_hub_proto::SIGNATURE_HEADER, signature)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .context("building the download request")?;
    let resp = sender
        .send_request(request)
        .await
        .context("asking the hub for the download")?;
    let status = resp.status();
    let mut body = resp.into_body();
    if !status.is_success() {
        let mut said = Vec::new();
        while let Ok(Some(Ok(frame))) = tokio::time::timeout(READ_TIMEOUT, body.frame()).await {
            if let Ok(data) = frame.into_data() {
                said.extend_from_slice(&data);
            }
            if said.len() > 4096 {
                break;
            }
        }
        driver.abort();
        let why = serde_json::from_slice::<vk_hub_proto::ErrorBody>(&said)
            .map(|e| vk_hub_proto::display_safe(&e.error))
            .unwrap_or_else(|_| format!("HTTP {status}"));
        bail!("the hub refused the download: {why}");
    }
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    loop {
        let frame = tokio::time::timeout(READ_TIMEOUT, body.frame())
            .await
            .map_err(|_| anyhow!("the hub sent nothing for {READ_TIMEOUT:?}"))?;
        let Some(frame) = frame else { break };
        let frame = frame.context("reading the download")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        written = written.saturating_add(data.len() as u64);
        if written > fetch.size {
            driver.abort();
            bail!(
                "the download is longer than the {} bytes the command named",
                fetch.size
            );
        }
        hasher.update(&data);
        file.write_all(&data)
            .with_context(|| format!("writing {}", tmp.display()))?;
    }
    driver.abort();
    let got = vk_hub_proto::to_hex(&hasher.finalize());
    if got != fetch.sha256 {
        bail!(
            "the download hashes to {got}, not the {} the command named",
            fetch.sha256
        );
    }
    file.set_permissions(std::fs::Permissions::from_mode(fetch.mode & 0o777))
        .with_context(|| format!("setting the mode on {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", tmp.display()))?;
    Ok(())
}

/// Copy the running binary to `<releases>/<sha256>`, unless it is there already: the
/// previous release, kept to go back to.
pub fn keep_previous(releases: &Path, sha256: &str) -> Result<()> {
    let dest = releases.join(sha256);
    if dest.is_file() && hash_file(&dest).ok().as_deref() == Some(sha256) {
        return Ok(());
    }
    copy_published(Path::new("/proc/self/exe"), &dest, 0o700, Some(sha256))
}

/// Copy `from` to `to` through a private staging file beside it — named afresh, so nothing
/// a crash left can stand in the way — flushed, with `mode`, and published by rename, once
/// what was copied hashes to `sha256` when given.
pub fn copy_published(from: &Path, to: &Path, mode: u32, sha256: Option<&str>) -> Result<()> {
    let dir = to
        .parent()
        .with_context(|| format!("{} has no directory", to.display()))?;
    let src = std::fs::File::open(from).with_context(|| format!("opening {}", from.display()))?;
    let (tmp, mut out) = staging(dir, to)?;
    let copied = (|| {
        let got = hash_reader(src, Some(&mut out))
            .with_context(|| format!("copying {} to {}", from.display(), tmp.display()))?;
        if let Some(want) = sha256
            && got != want
        {
            bail!("{} hashes to {got}, not {want}", from.display());
        }
        out.set_permissions(std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting the mode on {}", tmp.display()))?;
        out.sync_all()
            .with_context(|| format!("flushing {}", tmp.display()))?;
        vk_selfupdate::publish(&tmp, to, dir)
    })();
    if copied.is_err() {
        // Best effort: the error is what matters.
        let _ = std::fs::remove_file(&tmp);
    }
    copied
}

/// A new private file beside `to` to stage it in, `.<name>.<random>.tmp`.
pub fn staging(dir: &Path, to: &Path) -> Result<(PathBuf, std::fs::File)> {
    for _ in 0..8 {
        let mut random = [0u8; 8];
        crate::fill_random(&mut random)?;
        let mut name = std::ffi::OsString::from(".");
        name.push(to.file_name().unwrap_or_default());
        name.push(format!(".{}.tmp", vk_hub_proto::to_hex(&random)));
        let tmp = dir.join(name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e).with_context(|| format!("creating {}", tmp.display())),
        }
    }
    bail!("no free staging name beside {}", to.display())
}

/// Remove the staging files [`staging`] made for `to` that a run cut short left beside it:
/// `.<name>.<16 hex digits>.tmp`, and nothing else.
pub fn sweep_staging(to: &Path) {
    let (Some(dir), Some(name)) = (to.parent(), to.file_name()) else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let prefix = [b".", name.as_encoded_bytes(), b"."].concat();
    for entry in entries.flatten() {
        let file = entry.file_name();
        let random = file
            .as_encoded_bytes()
            .strip_prefix(prefix.as_slice())
            .and_then(|rest| rest.strip_suffix(b".tmp"));
        if random.is_some_and(|r| {
            r.len() == 16 && r.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        }) {
            // Best effort: a leftover costs space, not correctness.
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Remove interrupted [`download`] files: all dot-named entries in `dir`.
/// Requires a directory with no other dot-named entries or other `vk node` downloading into it.
pub fn sweep_partial(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_name().as_encoded_bytes().starts_with(b".") {
            // Best effort: a leftover costs space, not correctness.
            let _ = std::fs::remove_file(entry.path());
        }
    }
}
