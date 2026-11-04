//! Trial self-update helpers: download a release from the hub under the peer's signature,
//! publish by rename, and replace the running process with `alarm(2)` armed to end hangs.

use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::identity::Identity;

/// How long a download may go without a byte arriving, and an attempt at it without its
/// connection made or the hub's answer.
const READ_TIMEOUT: Duration = Duration::from_secs(60);

/// How long past a trial's deadline `alarm(2)` ends the release: the release's own rollback
/// at the deadline comes first, and the alarm is there for one that hangs.
const ALARM_MARGIN: u64 = 60;

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
    arm(alarm_secs(deadline, now));
}

/// Arm `alarm(2)` for `secs`, 0 disarming it. An ignored or blocked SIGALRM is inherited across
/// exec, and would leave no deadline at all, so a non-zero `secs` resets SIGALRM to its default
/// action, losing any handler of the caller's, and unblocks it in this thread, whose mask an
/// exec passes on. Async-signal-safe: `signal`, `sigemptyset`, `sigaddset`, `pthread_sigmask`
/// and `alarm` are all on POSIX's list, so a child may call it between fork and exec.
fn arm(secs: libc::c_uint) {
    if secs != 0 {
        // SAFETY: restores the default action and unblocks SIGALRM through a local, initialized
        // set; no memory of the caller's is touched.
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
fn alarm_secs(deadline: Option<u64>, now: u64) -> libc::c_uint {
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
    exec_with(binary, alarm_at, &[])
}

/// [`exec`], with `env` set in the release's environment over what this process has. What
/// [`crate::handoff::ENV`] names is never passed on unless `env` sets it: those descriptors
/// are this process's, close-on-exec, unless it hands them over.
pub fn exec_with(
    binary: &Binary,
    alarm_at: Option<u64>,
    env: &[(std::ffi::OsString, std::ffi::OsString)],
) -> anyhow::Error {
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
        release_env(std::env::vars_os(), env)
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

/// Overlay `env` on `inherited` for the release, dropping [`crate::handoff::ENV`] unless
/// `env` explicitly sets it.
fn release_env<'a>(
    inherited: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)> + 'a,
    env: &'a [(std::ffi::OsString, std::ffi::OsString)],
) -> impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)> + 'a {
    inherited
        .filter(|(k, _)| k != crate::handoff::ENV && env.iter().all(|(set, _)| set != k))
        .chain(env.iter().cloned())
}

/// Start `binary` as a child while this process continues serving its open resources.
/// The child inherits this process's arguments and environment, with `env` overlaid.
/// Like [`exec_with`], it runs the open file, which must be an ELF binary; `/proc` must
/// be mounted. Descriptors in `keep` retain their numbers and stay open, as do other
/// descriptors without close-on-exec. `alarm(2)` is armed for the trial deadline
/// `alarm_at`. What [`crate::handoff::ENV`] names is passed on only if `env` sets it.
pub fn spawn_with(
    binary: &Binary,
    alarm_at: Option<u64>,
    env: &[(std::ffi::OsString, std::ffi::OsString)],
    keep: &[std::os::fd::RawFd],
) -> Result<std::process::Child> {
    let mut args = std::env::args_os();
    let arg0 = args
        .next()
        .unwrap_or_else(|| binary.path.clone().into_os_string());
    spawn_args(binary, arg0, args, alarm_at, env, keep)
}

/// [`spawn_with`], with `arg0` and `args` in place of this process's arguments.
fn spawn_args(
    binary: &Binary,
    arg0: std::ffi::OsString,
    args: impl IntoIterator<Item = std::ffi::OsString>,
    alarm_at: Option<u64>,
    env: &[(std::ffi::OsString, std::ffi::OsString)],
    keep: &[std::os::fd::RawFd],
) -> Result<std::process::Child> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    // The child's inherited descriptor names the checked file even if its path has changed.
    let mut cmd = std::process::Command::new(format!("/proc/self/fd/{}", binary.file.as_raw_fd()));
    cmd.arg0(arg0)
        .args(args)
        .env_clear()
        .envs(release_env(std::env::vars_os(), env));
    let secs = alarm_secs(alarm_at, crate::now_secs());
    let keep = keep.to_vec();
    // SAFETY: between fork and exec the closure allocates nothing (`keep` was copied before)
    // and calls only fcntl and `arm`, both async-signal-safe; a SIGALRM handler the child
    // inherited would be reset by the exec anyway.
    unsafe {
        cmd.pre_exec(move || {
            for &fd in &keep {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            arm(secs);
            Ok(())
        });
    }
    cmd.spawn()
        .with_context(|| format!("starting {}", binary.path.display()))
}

/// Whether this process runs the file at `path`: the same inode, not the same name.
pub fn running_is(path: &Path) -> bool {
    match (std::fs::metadata("/proc/self/exe"), std::fs::metadata(path)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

static OWN_SHA256: OnceLock<Option<String>> = OnceLock::new();

/// The sha256 of the running binary, hex, read once: a few hundred megabytes, so a peer reads
/// it before its first session rather than in the middle of one.
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
fn hash_reader(mut from: impl std::io::Read, mut to: Option<&mut std::fs::File>) -> Result<String> {
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

/// Delays between [`download`] attempts and the retry window without incoming bytes.
struct Backoff {
    /// Initial delay, doubled after each attempt without progress up to `cap`.
    /// [`crate::jittered`] keeps a disconnected fleet from reconnecting in lockstep.
    first: Duration,
    cap: Duration,
    /// Retry window after the last byte, to allow hub updates or restarts.
    /// An attempt under way runs to its own timeouts.
    window: Duration,
}

/// 1 s, 2 s, 4 s … up to 15 s, each up to a quarter longer, for two minutes without a byte.
const BACKOFF: Backoff = Backoff {
    first: Duration::from_secs(1),
    cap: Duration::from_secs(15),
    window: Duration::from_secs(120),
};

/// Download `fetch` from the hub, publishing it at `dest` after validation.
///
/// A hub not reached, a connection lost, a connection, answer or read that times out, or the
/// hub answering 5xx or 429 is retried with backoff, 1 s doubling to 15 s, for two minutes
/// without a byte; each attempt resumes the partial file with a `Range` where the last one
/// stopped, and a hub that ignores it sends the file again from the start. A 416 naming the
/// size already received ends the download. The whole file is checked against its sha256. Any
/// other answer is final. Callers must bound the whole transfer.
pub async fn download(fetch: &Download<'_>, dest: &Path) -> Result<()> {
    download_with(fetch, dest, &BACKOFF).await
}

async fn download_with(fetch: &Download<'_>, dest: &Path, backoff: &Backoff) -> Result<()> {
    let digest = vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SHA256_LEN }>(fetch.sha256)
        .with_context(|| format!("the sha256 {:?} is not valid", fetch.sha256))?;
    if fetch.mode & !0o777 != 0 {
        bail!("mode {:o} is more than permission bits", fetch.mode);
    }
    let dir = dest.parent().context("the download has no directory")?;
    let tmp = dir.join(format!(".{}.{}.tmp", fetch.sha256, std::process::id()));
    let outcome = download_into(fetch, &digest, &tmp, backoff)
        .await
        .and_then(|()| {
            std::fs::rename(&tmp, dest)
                .with_context(|| format!("publishing {}", dest.display()))?;
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

/// How an attempt at a download failed.
enum Failed {
    /// Retry an unreachable hub, a lost or stalled connection, or a busy or restarting hub.
    Retry(anyhow::Error),
    /// Final: the hub's refusal, a file that is not what was named, or a local failure.
    Final(anyhow::Error),
}

/// A bare `?` is final; retryable failures map to [`Failed::Retry`] at their source.
impl<E: Into<anyhow::Error>> From<E> for Failed {
    fn from(e: E) -> Self {
        Failed::Final(e.into())
    }
}

/// Download progress backed by the partial file.
struct Partial {
    file: std::fs::File,
    hasher: Sha256,
    written: u64,
    /// When the last byte arrived, or the download started.
    last_byte: tokio::time::Instant,
}

impl Partial {
    /// Start over: the hub sends the file from its first byte.
    fn restart(&mut self) -> std::io::Result<()> {
        use std::io::Seek;
        self.file.set_len(0)?;
        self.file.rewind()?;
        self.hasher = Sha256::new();
        self.written = 0;
        Ok(())
    }
}

async fn download_into(
    fetch: &Download<'_>,
    digest: &[u8; vk_hub_proto::SHA256_LEN],
    tmp: &Path,
    backoff: &Backoff,
) -> Result<()> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp)
        .with_context(|| format!("creating {}", tmp.display()))?;
    let mut partial = Partial {
        file,
        hasher: Sha256::new(),
        written: 0,
        last_byte: tokio::time::Instant::now(),
    };
    // Attempts since the last one that got a byte.
    let (mut pause, mut attempts) = (backoff.first, 1);
    loop {
        let before = partial.last_byte;
        let e = match attempt(fetch, digest, tmp, &mut partial).await {
            Ok(()) => break,
            Err(Failed::Final(e)) => return Err(e),
            Err(Failed::Retry(e)) => e,
        };
        if partial.last_byte != before {
            (pause, attempts) = (backoff.first, 1);
        }
        let delay = crate::jittered(pause);
        let since = partial.last_byte.elapsed();
        if since + delay > backoff.window {
            return Err(e.context(format!(
                "no byte of the download arrived for {}s, over {attempts} attempts",
                since.as_secs()
            )));
        }
        tokio::time::sleep(delay).await;
        pause = (pause * 2).min(backoff.cap);
        attempts += 1;
    }
    let got = vk_hub_proto::to_hex(&partial.hasher.finalize());
    if got != fetch.sha256 {
        bail!(
            "the download hashes to {got}, not the {} the command named",
            fetch.sha256
        );
    }
    let file = partial.file;
    file.set_permissions(std::fs::Permissions::from_mode(fetch.mode & 0o777))
        .with_context(|| format!("setting the mode on {}", tmp.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", tmp.display()))?;
    Ok(())
}

/// One request for the rest of `fetch` past what `partial` holds, on a new connection, signed
/// afresh: a signature is bound to its time and its connection.
async fn attempt(
    fetch: &Download<'_>,
    digest: &[u8; vk_hub_proto::SHA256_LEN],
    tmp: &Path,
    partial: &mut Partial,
) -> Result<(), Failed> {
    use http_body_util::BodyExt;
    use std::io::Write;
    let crate::session::Dialed {
        io,
        exported,
        authority,
        ..
    } = match tokio::time::timeout(READ_TIMEOUT, crate::session::dial(fetch.hub, fetch.tls)).await {
        Err(_) => {
            return Err(Failed::Retry(anyhow!(
                "the hub was not reached within {READ_TIMEOUT:?}"
            )));
        }
        Ok(Err(e)) if hub_not_reached(&e) => return Err(Failed::Retry(e)),
        Ok(Err(e)) => return Err(Failed::Final(e)),
        Ok(Ok(dialled)) => dialled,
    };
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
            .context("opening the download")
            .map_err(Failed::Retry)?;
    // Abort the task on every exit from the attempt.
    let driver = AbortOnDrop(tokio::spawn(conn));
    let mut request = hyper::Request::get(format!("{}{}", fetch.path, fetch.sha256))
        .header(hyper::header::HOST, authority)
        .header(fetch.id_header, fetch.id)
        .header(vk_hub_proto::TIME_HEADER, at.to_string())
        .header(vk_hub_proto::SIGNATURE_HEADER, signature);
    if partial.written > 0 {
        request = request.header(hyper::header::RANGE, format!("bytes={}-", partial.written));
    }
    let request = request
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .context("building the download request")?;
    let resp = tokio::time::timeout(READ_TIMEOUT, sender.send_request(request))
        .await
        .map_err(|_| {
            Failed::Retry(anyhow!(
                "the hub did not answer the download within {READ_TIMEOUT:?}"
            ))
        })?
        .context("asking the hub for the download")
        .map_err(Failed::Retry)?;
    let (parts, mut body) = resp.into_parts();
    let status = parts.status;
    let resumed_at = match status {
        hyper::StatusCode::PARTIAL_CONTENT => Some(content_range_start(&parts.headers)?),
        _ => None,
    };
    if status == hyper::StatusCode::RANGE_NOT_SATISFIABLE && partial.written > 0 {
        // Nothing past what arrived: the last attempt got the whole file, and lost the
        // connection only after. The sha256 says whether it did.
        let held = content_range_size(&parts.headers);
        if held != Some(partial.written) {
            return Err(Failed::Final(anyhow!(
                "the hub holds {} bytes of the download, not the {} that arrived",
                held.map_or_else(|| "an unknown number of".to_string(), |n| n.to_string()),
                partial.written
            )));
        }
        return Ok(());
    }
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
        drop(driver);
        let why = serde_json::from_slice::<vk_hub_proto::ErrorBody>(&said)
            .map(|e| vk_hub_proto::display_safe(&e.error))
            .unwrap_or_else(|_| format!("HTTP {status}"));
        let e = anyhow!("the hub refused the download: {why}");
        return Err(
            if status.is_server_error() || status == hyper::StatusCode::TOO_MANY_REQUESTS {
                Failed::Retry(e)
            } else {
                Failed::Final(e)
            },
        );
    }
    match resumed_at {
        Some(start) if start == partial.written => {}
        Some(start) => {
            return Err(Failed::Final(anyhow!(
                "the hub resumed the download at byte {start}, not {}",
                partial.written
            )));
        }
        // The whole file again: a hub that does not serve ranges.
        None if partial.written > 0 => partial
            .restart()
            .with_context(|| format!("truncating {}", tmp.display()))?,
        None => {}
    }
    loop {
        let frame = tokio::time::timeout(READ_TIMEOUT, body.frame())
            .await
            .map_err(|_| Failed::Retry(anyhow!("the hub sent nothing for {READ_TIMEOUT:?}")))?;
        let Some(frame) = frame else { break };
        let frame = frame
            .context("reading the download")
            .map_err(Failed::Retry)?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let written = partial.written.saturating_add(data.len() as u64);
        if written > fetch.size {
            return Err(Failed::Final(anyhow!(
                "the download is longer than the {} bytes the command named",
                fetch.size
            )));
        }
        partial
            .file
            .write_all(&data)
            .with_context(|| format!("writing {}", tmp.display()))?;
        partial.hasher.update(&data);
        partial.written = written;
        partial.last_byte = tokio::time::Instant::now();
    }
    Ok(())
}

/// Whether `dial` failed to reach the hub — a connection not made or cut, a handshake
/// unfinished, or a name that does not resolve, likely a resolver hiccup — rather than for a
/// reason that would fail again: a URL that cannot be used, or a TLS failure such as a
/// certificate that is not trusted.
fn hub_not_reached(e: &anyhow::Error) -> bool {
    let tls = |e: &(dyn std::error::Error + 'static)| e.downcast_ref::<rustls::Error>().is_some();
    let mut io = false;
    for cause in e.chain() {
        if tls(cause) {
            return false;
        }
        if let Some(io_error) = cause.downcast_ref::<std::io::Error>() {
            // `source` skips the error an `io::Error` wraps, as tokio-rustls wraps its own.
            if io_error.get_ref().is_some_and(|inner| tls(inner)) {
                return false;
            }
            io = true;
        }
    }
    io
}

/// The size a 416's `Content-Range: bytes */<size>` gives.
fn content_range_size(headers: &hyper::HeaderMap) -> Option<u64> {
    headers
        .get(hyper::header::CONTENT_RANGE)?
        .to_str()
        .ok()?
        .strip_prefix("bytes */")?
        .parse()
        .ok()
}

/// The first byte a 206's `Content-Range: bytes <first>-<last>/<size>` names.
fn content_range_start(headers: &hyper::HeaderMap) -> Result<u64, Failed> {
    headers
        .get(hyper::header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("bytes "))
        .and_then(|v| v.split_once('-'))
        .and_then(|(first, _)| first.parse().ok())
        .ok_or_else(|| {
            Failed::Final(anyhow!(
                "the hub sent part of the download, not saying which"
            ))
        })
}

/// A task aborted when this is dropped.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
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
fn staging(dir: &Path, to: &Path) -> Result<(PathBuf, std::fs::File)> {
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
/// Requires a directory with no other dot-named entries or other peer downloading into it.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// What the fake hub does with a connection.
    #[derive(Clone, Copy)]
    enum Answer {
        /// Read the request and close, unanswered.
        Close,
        /// Answer this status, with no body.
        Status(u16),
        /// Serve the file — from the `Range` asked when `ranges` — closing after `cut` bytes
        /// of the body when given.
        Serve { ranges: bool, cut: Option<usize> },
        /// Send the whole file, but say it is a byte longer, and close.
        Overlong,
        /// Answer 206 from the second byte, whatever was asked.
        Misplaced,
    }

    /// Serve one connection per entry in `answers` on `socket`, then stop.
    /// Listen after `after`, refusing connections until then.
    /// Return each request's `Range`.
    fn fake_hub(
        socket: tokio::net::TcpSocket,
        body: Vec<u8>,
        answers: Vec<Answer>,
        after: Duration,
    ) -> tokio::task::JoinHandle<Vec<Option<String>>> {
        tokio::spawn(async move {
            tokio::time::sleep(after).await;
            let listener = socket.listen(16).unwrap();
            let mut ranges = Vec::new();
            for answer in answers {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    let mut buf = [0u8; 1024];
                    let n = stream.read(&mut buf).await.unwrap();
                    assert_ne!(n, 0, "the client closed before its request");
                    head.extend_from_slice(&buf[..n]);
                }
                let head = String::from_utf8(head).unwrap();
                let range = head
                    .lines()
                    .find_map(|l| l.strip_prefix("range: ").or(l.strip_prefix("Range: ")))
                    .map(str::to_string);
                ranges.push(range.clone());
                let reply = match answer {
                    Answer::Close => Vec::new(),
                    Answer::Status(code) => format!(
                        "HTTP/1.1 {code} X\r\nContent-Range: bytes */{}\r\n\
                         Content-Length: 0\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .into_bytes(),
                    Answer::Overlong => {
                        let mut reply = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len() + 1
                        )
                        .into_bytes();
                        reply.extend_from_slice(&body);
                        reply
                    }
                    Answer::Misplaced => {
                        let mut reply = format!(
                            "HTTP/1.1 206 X\r\nContent-Range: bytes 1-{}/{}\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len() - 1,
                            body.len(),
                            body.len() - 1
                        )
                        .into_bytes();
                        reply.extend_from_slice(&body[1..]);
                        reply
                    }
                    Answer::Serve { ranges, cut } => {
                        let start = range
                            .filter(|_| ranges)
                            .and_then(|r| r.strip_prefix("bytes=")?.strip_suffix('-')?.parse().ok())
                            .unwrap_or(0usize);
                        let rest = &body[start..];
                        let mut reply = if start > 0 {
                            format!(
                                "HTTP/1.1 206 X\r\nContent-Range: bytes {start}-{}/{}\r\n",
                                body.len() - 1,
                                body.len()
                            )
                        } else {
                            "HTTP/1.1 200 OK\r\n".to_string()
                        };
                        reply.push_str(&format!(
                            "Content-Length: {}\r\nConnection: close\r\n\r\n",
                            rest.len()
                        ));
                        let mut reply = reply.into_bytes();
                        reply.extend_from_slice(&rest[..cut.unwrap_or(rest.len())]);
                        reply
                    }
                };
                stream.write_all(&reply).await.unwrap();
                stream.flush().await.unwrap();
            }
            ranges
        })
    }

    /// Delays short enough for a test.
    const QUICK: Backoff = Backoff {
        first: Duration::from_millis(10),
        cap: Duration::from_millis(40),
        window: Duration::from_secs(2),
    };

    /// Reserve a port for this test without listening. Connections are refused until
    /// [`fake_hub`] listens, and other tests cannot take the port meanwhile.
    fn reserve() -> (tokio::net::TcpSocket, std::net::SocketAddr) {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = socket.local_addr().unwrap();
        (socket, addr)
    }

    struct Fixture {
        dir: PathBuf,
        identity: Identity,
        tls: Arc<rustls::ClientConfig>,
        body: Vec<u8>,
        sha256: String,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("vk-peer-dl-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let identity = Identity::load_or_create(&dir).unwrap();
            let tls = Arc::new(
                rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(rustls::RootCertStore::empty())
                .with_no_client_auth(),
            );
            let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
            let sha256 = vk_hub_proto::to_hex(&Sha256::digest(&body));
            Fixture {
                dir,
                identity,
                tls,
                body,
                sha256,
            }
        }

        async fn download(&self, addr: std::net::SocketAddr) -> Result<Vec<u8>> {
            let hub = format!("http://{addr}");
            let fetch = Download {
                hub: &hub,
                tls: &self.tls,
                identity: &self.identity,
                id: "n1",
                id_header: vk_hub_proto::NODE_HEADER,
                path: vk_hub_proto::RELEASE_PATH,
                sign: vk_hub_proto::download_message,
                sha256: &self.sha256,
                size: self.body.len() as u64,
                mode: 0o600,
            };
            let dest = self.dir.join("release");
            let got = download_with(&fetch, &dest, &QUICK).await;
            // Published, or nothing left behind.
            let left: Vec<_> = std::fs::read_dir(&self.dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .filter(|n| n.ends_with(".tmp"))
                .collect();
            assert!(left.is_empty(), "{left:?}");
            got.map(|()| std::fs::read(&dest).unwrap())
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A download cut short resumes where it stopped, asking the rest with a `Range`.
    #[tokio::test]
    async fn a_download_cut_short_resumes_where_it_stopped() {
        let f = Fixture::new("resume");
        let (socket, addr) = reserve();
        let serve = |cut| Answer::Serve { ranges: true, cut };
        let hub = fake_hub(
            socket,
            f.body.clone(),
            vec![serve(Some(70_000)), serve(Some(50_000)), serve(None)],
            Duration::ZERO,
        );
        assert_eq!(f.download(addr).await.unwrap(), f.body);
        assert_eq!(
            hub.await.unwrap(),
            [
                None,
                Some("bytes=70000-".into()),
                Some("bytes=120000-".into())
            ]
        );
    }

    /// A hub that ignores the `Range` — one from before ranges — has the file sent again from
    /// the start, and it is still whole.
    #[tokio::test]
    async fn a_hub_ignoring_the_range_has_the_download_start_over() {
        let f = Fixture::new("norange");
        let (socket, addr) = reserve();
        let hub = fake_hub(
            socket,
            f.body.clone(),
            vec![
                Answer::Serve {
                    ranges: false,
                    cut: Some(90_000),
                },
                Answer::Serve {
                    ranges: false,
                    cut: None,
                },
            ],
            Duration::ZERO,
        );
        assert_eq!(f.download(addr).await.unwrap(), f.body);
        assert_eq!(hub.await.unwrap(), [None, Some("bytes=90000-".into())]);
    }

    /// A hub restarting — refusing connections, then closing them unanswered, then busy — is
    /// waited out.
    #[tokio::test]
    async fn a_restarting_hub_is_waited_out() {
        let f = Fixture::new("restart");
        let (socket, addr) = reserve();
        let hub = fake_hub(
            socket,
            f.body.clone(),
            vec![
                Answer::Close,
                Answer::Status(503),
                Answer::Serve {
                    ranges: true,
                    cut: None,
                },
            ],
            Duration::from_millis(300),
        );
        assert_eq!(f.download(addr).await.unwrap(), f.body);
        assert_eq!(hub.await.unwrap(), [None, None, None]);
    }

    /// All of it arrived before the connection was lost: the hub has nothing past it, and
    /// what arrived is checked rather than fetched again.
    #[tokio::test]
    async fn a_download_already_whole_is_not_fetched_again() {
        let f = Fixture::new("whole");
        let (socket, addr) = reserve();
        let hub = fake_hub(
            socket,
            f.body.clone(),
            vec![Answer::Overlong, Answer::Status(416)],
            Duration::ZERO,
        );
        assert_eq!(f.download(addr).await.unwrap(), f.body);
        assert_eq!(
            hub.await.unwrap(),
            [None, Some(format!("bytes={}-", f.body.len()))]
        );
    }

    /// A hub not reached is retried; a URL that cannot be dialled, or a TLS handshake that
    /// fails, is not.
    #[tokio::test]
    async fn only_a_hub_not_reached_is_dialled_again() {
        let f = Fixture::new("dial");
        let (_socket, addr) = reserve();
        let refused = crate::session::dial(&format!("http://{addr}"), &f.tls)
            .await
            .err()
            .unwrap();
        assert!(hub_not_reached(&refused), "{refused:#}");
        for hub in ["not a url", "http://"] {
            let e = crate::session::dial(hub, &f.tls).await.err().unwrap();
            assert!(!hub_not_reached(&e), "{hub}: {e:#}");
        }
        // Plain HTTP where TLS was asked: rustls's error, wrapped in an `io::Error`.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let plain = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.write_all(b"HTTP/1.1 400 X\r\n\r\n").await;
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
        });
        let e = crate::session::dial(&format!("https://{addr}"), &f.tls)
            .await
            .err()
            .unwrap();
        assert!(!hub_not_reached(&e), "{e:#}");
        plain.abort();
    }

    /// A wrong resume offset or a size differing from the bytes received is final.
    #[tokio::test]
    async fn a_hub_contradicting_what_arrived_fails_the_download() {
        let f = Fixture::new("contradict");
        for second in [Answer::Misplaced, Answer::Status(416)] {
            let (socket, addr) = reserve();
            let hub = fake_hub(
                socket,
                f.body.clone(),
                vec![
                    Answer::Serve {
                        ranges: true,
                        cut: Some(70_000),
                    },
                    second,
                ],
                Duration::ZERO,
            );
            let err = f.download(addr).await.unwrap_err();
            let err = format!("{err:#}");
            assert!(
                err.contains("not 70000") || err.contains("not the 70000"),
                "{err}"
            );
            assert_eq!(hub.await.unwrap().len(), 2);
        }
    }

    /// A refusal is final; a hub gone for longer than the window is given up on.
    #[tokio::test]
    async fn a_refusal_or_a_hub_gone_for_good_fails_the_download() {
        let f = Fixture::new("final");
        let (socket, addr) = reserve();
        let hub = fake_hub(
            socket,
            f.body.clone(),
            vec![Answer::Status(403)],
            Duration::ZERO,
        );
        let err = f.download(addr).await.unwrap_err();
        assert!(format!("{err:#}").contains("refused"), "{err:#}");
        assert_eq!(hub.await.unwrap().len(), 1);

        let (_socket, gone) = reserve();
        let start = std::time::Instant::now();
        let err = f.download(gone).await.unwrap_err();
        assert!(format!("{err:#}").contains("no byte"), "{err:#}");
        assert!(start.elapsed() < QUICK.window + Duration::from_secs(1));

        // A file longer than the command named is refused, not resumed.
        let (socket, addr) = reserve();
        let mut longer = f.body.clone();
        longer.push(0);
        let hub = fake_hub(
            socket,
            longer,
            vec![Answer::Serve {
                ranges: true,
                cut: None,
            }],
            Duration::ZERO,
        );
        let err = f.download(addr).await.unwrap_err();
        assert!(format!("{err:#}").contains("longer"), "{err:#}");
        assert_eq!(hub.await.unwrap().len(), 1);
    }

    /// The child runs the file opened, even once its path names another, with the descriptors
    /// kept open and the others closed, and the environment given.
    #[test]
    fn a_release_spawned_runs_the_file_opened_with_the_descriptors_kept() {
        use std::os::fd::{AsRawFd, FromRawFd};
        let dir = std::env::temp_dir().join(format!("vk-peer-spawn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sh = dir.join("sh");
        std::fs::copy("/bin/sh", &sh).unwrap();
        let binary = Binary::open(&sh, None).unwrap();
        // Another file at the path: the child still runs the one opened.
        std::fs::remove_file(&sh).unwrap();
        std::fs::write(&sh, b"not a shell").unwrap();
        // Both close-on-exec, and numbered above what the shell or its loader might open.
        let high = || {
            let null = std::fs::File::open("/dev/null").unwrap();
            // SAFETY: duplicates an open descriptor into a new one owned below.
            let fd = unsafe { libc::fcntl(null.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 200) };
            assert!(fd >= 200);
            // SAFETY: just created, owned by nothing else.
            unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) }
        };
        let (kept, closed) = (high(), high());
        let (k, c) = (kept.as_raw_fd(), closed.as_raw_fd());
        let script =
            format!("test -e /proc/self/fd/{k} && ! test -e /proc/self/fd/{c} && test \"$X\" = 1");
        let mut child = spawn_args(
            &binary,
            "sh".into(),
            ["-c".into(), script.into()],
            None,
            &[("X".into(), "1".into())],
            &[k],
        )
        .unwrap();
        assert!(child.wait().unwrap().success());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_release_inherits_the_sockets_only_when_told_to() {
        let kv = |k: &str, v: &str| (std::ffi::OsString::from(k), std::ffi::OsString::from(v));
        let inherited = || {
            vec![
                kv("PATH", "/bin"),
                kv(crate::handoff::ENV, "a=5"),
                kv("X", "1"),
            ]
        };
        let env: Vec<_> = release_env(inherited().into_iter(), &[]).collect();
        assert_eq!(env, vec![kv("PATH", "/bin"), kv("X", "1")]);
        let set = [kv("X", "2"), kv(crate::handoff::ENV, "b=6")];
        let env: Vec<_> = release_env(inherited().into_iter(), &set).collect();
        assert_eq!(
            env,
            vec![
                kv("PATH", "/bin"),
                kv("X", "2"),
                kv(crate::handoff::ENV, "b=6")
            ]
        );
    }

    #[test]
    fn the_alarm_is_a_margin_past_the_trial_deadline() {
        assert_eq!(alarm_secs(None, 100), 0);
        assert_eq!(
            alarm_secs(Some(200), 100),
            100 + ALARM_MARGIN as libc::c_uint
        );
        // Past the deadline, the margin still runs; past both, a second is left.
        assert_eq!(
            alarm_secs(Some(100), 130),
            ALARM_MARGIN as libc::c_uint - 30
        );
        assert_eq!(alarm_secs(Some(100), 100 + ALARM_MARGIN + 5), 1);
        assert_eq!(alarm_secs(Some(u64::MAX), 0), libc::c_uint::MAX);
    }
}
