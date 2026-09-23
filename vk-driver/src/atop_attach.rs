//! `vk atop` against a running VM: start a sampler in its guest over the exec channel
//! and stream the samples onto the host, so any VM can be watched as it runs — no flag
//! at boot, no restart, systemd guests included (their agent still serves the channel).
//!
//! A virtio-fs share cannot be added to a running VM, so unlike the executor's per-job
//! recording there is no share: the guest sampler writes samples to its stdout
//! (`vk-agent atop - <interval>`) and this module appends the stream to
//! `<state dir>/atop/atop.log`, where the follow panel reads it as it grows and a later
//! `vk atop <path> --summary` reads it back. The recording lives as long as the attach:
//! closing the sampler's stdin asks it for one final sample — the streaming counterpart
//! of `--stop`'s SIGUSR2 — and it then exits on its own.

use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::io::AsRawFd as _;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures::SinkExt as _;
use tokio_util::sync::CancellationToken;
use vk_core::addr::SocketAddr;
use vk_core::messages::{CmdExec, CmdResult, Fd, Message, RunMode};

use crate::vms;

/// What a `vk atop` target names.
#[derive(Debug)]
pub enum Target {
    /// A running VM, to attach to and record now.
    Live(Box<vms::VmEntry>),
    /// A recorded job to read back: an id, a name fragment, or a path.
    Recorded(String),
}

/// Decide what `target` names. A running VM answers first — `vk atop` beside a VM means
/// "watch it now" — but only for a target that selects VMs the way `vk exec`/`vk stop`
/// do: nothing (the current directory), or a directory on disk. A target no running VM
/// matches reads the archive, so every recorded-job lookup keeps answering as before.
pub fn classify(target: Option<&str>) -> Result<Target> {
    let dir = match target {
        // No target asks about *here*, which only a running VM can answer.
        None => None,
        Some(t) => match Path::new(t).is_dir() {
            true => Some(Path::new(t)),
            // Not a directory, so no VM can match it: the registry is never consulted.
            false => return Ok(Target::Recorded(t.to_string())),
        },
    };
    let (selected, matched) = vms::matching(dir)?;
    decide(target, &selected, matched)
}

/// What a directory's [`vms::matching`] result means, apart from reading the registry so a
/// test can pin every arm. A directory no VM matches falls through to the archive — that is
/// how a path to a recording still answers — while one that several match is an error rather
/// than a fall-through: the operator pointed into a tree of running VMs, and answering out of
/// the archive would dress the ambiguity up as a different question.
fn decide(target: Option<&str>, selected: &Path, mut matched: Vec<vms::VmEntry>) -> Result<Target> {
    match (matched.len(), target) {
        (0, Some(t)) => Ok(Target::Recorded(t.to_string())), // e.g. a recording directory
        (0, None) => bail!(
            "no running vk VM for {} — attach to one by its directory, or name a recorded \
             job (an id, part of its name, or a path to a recording)",
            selected.display()
        ),
        (1, _) => Ok(Target::Live(Box::new(matched.pop().unwrap()))),
        (n, _) => bail!(
            "{n} running vk VMs match {} — name a more specific directory",
            selected.display()
        ),
    }
}

/// How long a stop waits for the final sample and the sampler's exit before hanging up
/// (which also ends it, just without that sample).
const STOP_WAIT: Duration = Duration::from_secs(5);

/// How long to wait for the first sample. It is written the moment the sampler starts,
/// so this is generous — it exists so a guest that cannot run the sampler at all turns
/// into an error rather than a panel that never fills.
const FIRST_SAMPLE_WAIT: Duration = Duration::from_secs(10);

/// A recording under way: where its samples are landing, the task relaying them, and the
/// token that asks the guest sampler for its final one.
///
/// Held by whoever wants the recording to carry on, and ended by letting go of it: a caller
/// that can wait [`Recording::finish`]es it and gets that final sample, and one that cannot
/// simply drops it, which ends the pump and with it the connection — a guest whose exec
/// channel hangs up has its sampler killed along with the rest of its process group.
pub(crate) struct Recording {
    /// Where the samples are being written.
    pub(crate) log: PathBuf,
    /// `None` once it has been waited out, so the drop below has nothing left to end.
    pump: Option<tokio::task::JoinHandle<Result<CmdResult>>>,
    stop: CancellationToken,
}

impl Recording {
    /// Ask the guest for its final sample and let the stream drain.
    pub(crate) async fn finish(mut self) {
        self.stop.cancel();
        if let Some(mut pump) = self.pump.take() {
            wait_out_stop(&mut pump).await;
        }
    }

    /// End it now, and wait until it has actually ended.
    ///
    /// Dropping a recording only *asks* for that: the pump is aborted, and the task — with
    /// the connection and the file holding the log's lock inside it — is dropped on a
    /// runtime thread some time after. A caller that hands the same log straight on to a
    /// `vk atop`, which takes the same lock, has to wait for that to have happened, and an
    /// aborted handle resolves exactly then. No final sample: this is the way out for a
    /// caller that has none to wait for.
    pub(crate) async fn stop_now(mut self) {
        self.stop.cancel();
        if let Some(pump) = self.pump.take() {
            pump.abort();
            // Aborted on purpose, so neither the cancellation nor the sampler's own last
            // word is news; what this waits for is the task having been dropped.
            let _ = pump.await;
        }
    }

    /// Why a pump that ended before the recording had its first sample did, in the terms an
    /// operator can act on. Leaves nothing behind for the drop to end.
    async fn ended_early(&mut self) -> anyhow::Error {
        let Some(pump) = self.pump.take() else {
            return anyhow!("the guest sampler ended before its first sample");
        };
        match pump.await {
            Ok(Ok(result)) => anyhow!(
                "the guest sampler ended before its first sample{} — is this VM's \
                 vk-agent older than `vk atop`?",
                result
                    .code
                    .map(|c| format!(" (exit {c})"))
                    .unwrap_or_default()
            ),
            Ok(Err(e)) => e,
            Err(e) => anyhow!(e),
        }
    }

    /// Wait for the recording to end by itself, which is the VM going down mid-attach, and
    /// say how it ended. Cancel-safe: dropping this future leaves the recording as it was.
    async fn ended(&mut self) -> std::result::Result<Result<CmdResult>, tokio::task::JoinError> {
        let Some(pump) = self.pump.as_mut() else {
            // Already waited out: there is nothing left for this to be the end of.
            return std::future::pending().await;
        };
        pump.await
    }
}

impl Drop for Recording {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(pump) = &self.pump {
            pump.abort();
        }
    }
}

/// Where the dashboard's guest pane records, beside `vk atop`'s [`vk_core::atop::LOG_NAME`]
/// rather than over it: a pane opened is not a recording anyone asked to keep, and must not
/// cost the one a `vk atop` said it had saved.
pub(crate) const DASH_LOG_NAME: &str = "dash.log";

/// Start recording the guest behind `addr` into `<state_dir>/atop/<name>`, replacing any
/// previous recording there, and wait for its first sample.
///
/// The recording lives as long as the [`Recording`] returned. `relay_stderr` puts whatever
/// the guest sampler complains about onto this process's stderr, which is for a caller that
/// has a stderr to spare — not one drawing on the terminal.
pub(crate) async fn start(
    addr: &SocketAddr,
    state_dir: &Path,
    name: &str,
    interval_secs: u64,
    relay_stderr: bool,
) -> Result<Recording> {
    if interval_secs == 0 {
        bail!("--interval must be at least 1 second (got 0)");
    }
    let dir = state_dir.join("atop");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let log = dir.join(name);
    // Opened without following a symlink, and written only once it is the regular file a
    // recording is — the same footing every reader of one opens it on. Non-blocking for the
    // same reason theirs is: a FIFO the guest left in its place would otherwise hold the
    // open until something read it, and the check below would never be reached. On a
    // regular file the flag changes nothing.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&log)
        .with_context(|| format!("opening {}", log.display()))?;
    if !file.metadata()?.file_type().is_file() {
        bail!("{} is not a regular file", log.display());
    }
    // One attach at a time per VM. Two would each write from their own offset into one
    // file, leaving a hole between them and interleaving two samplers' records into a log
    // that reads as neither. SAFETY: the fd is owned by `file`, which outlives the call;
    // flock returns 0 or -1. The lock goes when this process does, which is the attach.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!(
            "{} is already being recorded by another `vk atop` or `vk dash` — stop that one \
             first",
            log.display()
        );
    }
    // A fresh attach is a fresh recording: what the panel walks — and what the path this
    // returns names — is what this attach saw, never a tail behind an earlier one. Truncated
    // only once the lock is held, so it can never cut a recording still being written.
    file.set_len(0)
        .with_context(|| format!("truncating {}", log.display()))?;
    // Kept back from the pump so the wait below can size the recording off the descriptor
    // it was written through, rather than whatever the path resolves to a second time.
    let probe = file
        .try_clone()
        .with_context(|| format!("reopening {}", log.display()))?;

    let (mut stream, mut sink) = vk_core::net::connect(addr)
        .await
        .context("connecting to the VM's vk-agent")?;
    sink.send(Message::CmdExec(CmdExec {
        name: crate::run::GUEST_AGENT.to_string(),
        args: vec!["atop".into(), "-".into(), interval_secs.to_string()],
        env: vec![],
        clear_env: false,
        mode: RunMode::Interactive,
        dir: None,
        tty: None,
        // uid 0 by number: the sampler reads every process's /proc entries, and an
        // image without a `root` passwd entry would not resolve the name.
        user: Some("0".into()),
    }))
    .await?;
    // Bounded like the first sample below: an agent that took the connection and then
    // never answers would otherwise leave the caller starting for ever.
    let reply = tokio::time::timeout(FIRST_SAMPLE_WAIT, crate::executor::next(&mut stream))
        .await
        .map_err(|_| {
            anyhow!(
                "the VM's vk-agent did not answer within {}s",
                FIRST_SAMPLE_WAIT.as_secs()
            )
        })??;
    match reply {
        Message::StartOK => {}
        Message::StartErr { msg } => bail!("starting the sampler in the VM: {msg}"),
        other => bail!("unexpected reply to exec: {other:?}"),
    }

    let stop = CancellationToken::new();
    // The pump belongs to the recording from the moment it is spawned. A bare handle held
    // across the wait below would be *detached* by every way out of it — an early return,
    // and a caller that drops this future — leaving the connection, the file holding the
    // log's lock and the guest's sampler alive for the rest of the process.
    let mut recording = Recording {
        log,
        pump: Some(tokio::spawn(pump(
            stream,
            sink,
            file,
            relay_stderr,
            stop.clone(),
        ))),
        stop,
    };

    // The sampler writes its first sample the moment it starts: wait for it, so the
    // panel opens with something to show — and so a guest that cannot run the sampler
    // (an agent predating the streaming mode, say) fails here, with its exit status,
    // rather than as a panel that never fills.
    let deadline = tokio::time::Instant::now() + FIRST_SAMPLE_WAIT;
    while !probe.metadata().is_ok_and(|m| m.len() > 0) {
        if recording
            .pump
            .as_ref()
            .is_some_and(|pump| pump.is_finished())
        {
            return Err(recording.ended_early().await);
        }
        if tokio::time::Instant::now() >= deadline {
            break; // record anyway; the follow panel copes with a log still empty
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok(recording)
}

/// What a VM's exec address failing to parse is about. Said in one place because two callers
/// dial the same registry field: `vk atop` here, and the dashboard's guest pane.
pub(crate) fn exec_addr_context(addr: &str) -> String {
    format!("the VM's exec address {addr:?}")
}

/// Attach to `entry`'s guest and record it, laying the log down at
/// `<state dir>/atop/atop.log` (replacing any previous attach's recording). With a
/// terminal — and without `summary`, which records headless on purpose — the follow
/// panel opens on the growing log and quitting it ends the recording; otherwise the
/// recording runs in the foreground until Ctrl-C. Returns the log's path.
pub async fn attach(entry: &vms::VmEntry, interval_secs: u64, summary: bool) -> Result<PathBuf> {
    let addr: SocketAddr = entry
        .exec_addr
        .parse()
        .with_context(|| exec_addr_context(&entry.exec_addr))?;
    // The panel only where somebody is watching one: `--summary` is the headless form,
    // and without a terminal the panel can draw on there is nothing to open it on (the
    // recording still runs). Decided here rather than left to the panel to refuse, so a
    // terminal it cannot drive costs the operator the panel, not the recording.
    let panel = !summary && crate::term::can_draw();
    let mut recording = start(
        &addr,
        &entry.state_dir,
        vk_core::atop::LOG_NAME,
        interval_secs,
        !panel,
    )
    .await?;
    let log = recording.log.clone();

    if panel {
        let view_log = log.clone();
        let view = tokio::task::spawn_blocking(move || crate::atop_view::view(&view_log, true));
        let outcome = view.await;
        // The panel is gone: ask for the final sample and let the stream drain.
        recording.finish().await;
        // A panel that could not run still leaves the samples it was to draw, so the path
        // is said here — the error returned below carries the operator past the caller
        // that would otherwise have printed it.
        if !matches!(outcome, Ok(Ok(()))) {
            eprintln!("virtkit: recorded -> {}", log.display());
        }
        outcome.context("the panel task failed")??;
    } else {
        eprintln!(
            "virtkit: recording {} every {interval_secs}s -> {} (Ctrl-C for the final sample)",
            entry.label,
            log.display()
        );
        let interrupted = tokio::select! {
            r = recording.ended() => {
                // The guest ended the recording on its own: the VM went down mid-attach.
                // The log so far is still the answer, so report and keep it.
                match r.context("the recording task failed")? {
                    Ok(_) => eprintln!("virtkit: the VM ended the recording"),
                    Err(e) => eprintln!("virtkit: the recording ended: {e:#}"),
                }
                false
            }
            _ = tokio::signal::ctrl_c() => true,
        };
        if interrupted {
            recording.finish().await;
        }
    }
    Ok(log)
}

/// Wait out the stop: the sampler owes one final sample, and the stream owes its end. Never
/// fatal — the samples already on disk are the answer — but a recording that ended early, or
/// a sampler that never sent that final sample, is the difference between a whole account and
/// a short one, so it is said rather than swallowed. A pump past the deadline is abandoned
/// rather than waited on any longer; what reads the log next reads it as a recording torn at
/// the tail, which every reader of one already copes with.
async fn wait_out_stop(pump: &mut tokio::task::JoinHandle<Result<CmdResult>>) {
    match tokio::time::timeout(STOP_WAIT, &mut *pump).await {
        Ok(Ok(Ok(_))) => {}
        Ok(Ok(Err(e))) => eprintln!("virtkit: the recording ended: {e:#}"),
        Ok(Err(e)) => eprintln!("virtkit: the recording task failed: {e}"),
        Err(_) => {
            pump.abort();
            eprintln!(
                "virtkit: the guest sampler did not send its final sample within {}s",
                STOP_WAIT.as_secs()
            );
        }
    }
}

/// Relay the sampler's stream: samples (its stdout) onto the log, its stderr onto ours —
/// only while no panel owns the terminal — until it exits. Once `stop` fires, its stdin
/// is closed, which asks it for one final sample and its exit.
async fn pump(
    mut stream: vk_core::framing::SerStream,
    mut sink: vk_core::framing::DeSink,
    mut file: std::fs::File,
    relay_stderr: bool,
    stop: CancellationToken,
) -> Result<CmdResult> {
    let mut stopping = false;
    loop {
        let msg = tokio::select! {
            biased;
            () = stop.cancelled(), if !stopping => {
                stopping = true;
                sink.send(Message::Close { fd: Fd::Stdin, error: None }).await?;
                continue;
            }
            m = crate::executor::next(&mut stream) => m?,
        };
        match msg {
            Message::Data {
                fd: Fd::Stdout,
                msg,
            } => file.write_all(&msg).context("writing the recording")?,
            Message::Data {
                fd: Fd::Stderr,
                msg,
            } => {
                if relay_stderr {
                    let _ = std::io::stderr().write_all(&msg);
                }
            }
            Message::Data { .. } => {}
            Message::Close { .. } => {}
            Message::ExecDone(result) => return Ok(result),
            other => bail!("unexpected message: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt as _;

    /// Only a directory on disk can name a running VM: everything else goes to the
    /// recorded lookups without the VM registry being consulted at all, so ids, name
    /// fragments and paths keep answering exactly as before.
    #[test]
    fn a_target_that_is_no_directory_reads_the_archive() {
        for t in ["42137", "test_unit", "no/such/path", "-", ""] {
            match classify(Some(t)) {
                Ok(Target::Recorded(job)) => assert_eq!(job, t),
                _ => panic!("{t:?} should read the archive"),
            }
        }
    }

    fn entry(label: &str) -> vms::VmEntry {
        vms::VmEntry {
            state_dir: PathBuf::from("/state/vm"),
            project_dir: None,
            pid: std::process::id(),
            label: label.into(),
            exec_addr: "vsock-auto:///state/vm/vsock.sock:4444".into(),
            ssh_addr: None,
            atop_log: None,
            created_secs: 0,
            vmm: None,
            vmm_pid: None,
            cpus: None,
            mem: None,
            nested: None,
            guest_ip: None,
            stale_recipe: None,
            services: Vec::new(),
        }
    }

    /// What a directory means once the registry has answered. The one VM it matches is
    /// attached to; a directory no VM matches falls back to the archive, which is how a
    /// path to a recording still reads; and several matches is a refusal rather than a
    /// silent fall-through to a different question.
    #[test]
    fn a_directory_selects_a_vm_and_otherwise_falls_back_to_the_archive() {
        let dir = Path::new("/proj");
        match decide(Some("/proj"), dir, vec![entry("web")]) {
            Ok(Target::Live(e)) => assert_eq!(e.label, "web"),
            _ => panic!("one matching VM is the one to attach to"),
        }
        // A directory that is a recording rather than a VM: the archive answers for it.
        match decide(Some("/proj"), dir, vec![]) {
            Ok(Target::Recorded(t)) => assert_eq!(t, "/proj"),
            _ => panic!("no VM there: the archive answers"),
        }
        // Nothing was named, so there is no archive lookup to fall back to.
        let e = decide(None, dir, vec![]).expect_err("nothing here to watch");
        assert!(format!("{e:#}").contains("no running vk VM"), "{e:#}");
        let e = decide(Some("/proj"), dir, vec![entry("a"), entry("b")])
            .expect_err("an ambiguous directory is refused");
        assert!(format!("{e:#}").contains("2 running vk VMs match"), "{e:#}");
    }

    /// A zero interval would have the guest sampling without pause. Refused before the
    /// VM is dialled, so it costs an operator who fat-fingers it nothing.
    #[tokio::test]
    async fn a_zero_interval_is_refused() {
        let e = attach(&entry("web"), 0, false)
            .await
            .expect_err("zero is not an interval");
        assert!(format!("{e:#}").contains("--interval"), "{e:#}");
    }

    /// A FIFO where the log goes — the guest can make one through its atop share — is
    /// refused at once rather than waited on until something reads it.
    #[tokio::test]
    async fn a_fifo_where_the_log_goes_is_refused_rather_than_waited_on() {
        use std::os::unix::ffi::OsStrExt;

        let dir = std::env::temp_dir().join(format!("vk-atop-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("atop")).unwrap();
        let path = dir.join("atop").join(vk_core::atop::LOG_NAME);
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: `name` is a valid NUL-terminated path for the length of the call; mkfifo
        // returns 0 or -1.
        if unsafe { libc::mkfifo(name.as_ptr(), 0o600) } != 0 {
            let _ = std::fs::remove_dir_all(&dir);
            return; // no FIFOs on this filesystem, so there is nothing to refuse
        }
        let mut vm = entry("web");
        vm.state_dir = dir.clone();
        let e = tokio::time::timeout(Duration::from_secs(5), attach(&vm, 1, true))
            .await
            .expect("the open waited on the FIFO")
            .expect_err("a FIFO is not a recording");
        assert!(format!("{e:#}").contains(&*path.to_string_lossy()), "{e:#}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The pump's contract: the guest's stdout is the recording, byte for byte; its
    /// stderr is not the recording and stays off it; and the exit ends the pump with the
    /// sampler's own result.
    #[tokio::test]
    async fn the_pump_writes_stdout_to_the_log_and_ends_on_exec_done() {
        let dir = std::env::temp_dir().join(format!("vk-atop-pump-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("atop.log");
        let file = std::fs::File::create(&log).unwrap();

        let (host, guest) = tokio::io::duplex(64 * 1024);
        let (stream, sink) = vk_core::framing::wrap_stream(host);
        let (_gstream, mut gsink) = vk_core::framing::wrap_stream(guest);
        let stop = CancellationToken::new();
        let pump = tokio::spawn(pump(stream, sink, file, false, stop.clone()));

        for msg in [b"RESET\n".to_vec(), b"SEP 1\n".to_vec()] {
            gsink
                .send(Message::Data {
                    fd: Fd::Stdout,
                    msg,
                })
                .await
                .unwrap();
        }
        // Not the recording: it must not reach the log and turn a sample unparseable.
        gsink
            .send(Message::Data {
                fd: Fd::Stderr,
                msg: b"vk-agent atop: sampling\n".to_vec(),
            })
            .await
            .unwrap();
        gsink
            .send(Message::ExecDone(CmdResult {
                code: Some(0),
                signal: None,
            }))
            .await
            .unwrap();

        let result = pump.await.unwrap().unwrap();
        assert_eq!(result.code, Some(0));
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "RESET\nSEP 1\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A recording ends the pump it owns when it is dropped — which is how every way out of
    /// [`start`] short of returning one ends it. A detached pump would keep the connection,
    /// the file holding the log's lock and the guest's own sampler for the rest of the
    /// process, and the next `vk atop` against that VM would be refused the log.
    #[tokio::test]
    async fn dropping_a_recording_ends_the_pump_it_owns() {
        let (gone, ended) = tokio::sync::oneshot::channel::<()>();
        let recording = Recording {
            log: PathBuf::from("/state/vm/atop/atop.log"),
            pump: Some(tokio::spawn(async move {
                // Stands in for the connection and the locked file the real pump holds:
                // it goes when the task is dropped, and not when it is merely asked to be.
                let _gone = gone;
                std::future::pending::<()>().await;
                Ok(CmdResult {
                    code: Some(0),
                    signal: None,
                })
            })),
            stop: CancellationToken::new(),
        };
        // So the drop below is a running task's, not a task that never started.
        tokio::task::yield_now().await;
        drop(recording);
        tokio::time::timeout(Duration::from_secs(5), ended)
            .await
            .expect("the pump outlived the recording that owned it")
            .expect_err("the pump ended by itself rather than being ended");
    }

    /// Stopping now is a happens-after: once it returns, the pump has been dropped, and
    /// with it the connection and the file holding the log's lock. An abort on its own only
    /// asks for that, which is not enough for a caller about to hand the same log to a
    /// `vk atop --follow` that takes the same lock.
    #[tokio::test]
    async fn stopping_now_returns_only_once_the_pump_has_gone() {
        let held = std::sync::Arc::new(());
        let carried = std::sync::Arc::clone(&held);
        let recording = Recording {
            log: PathBuf::from("/state/vm/atop/atop.log"),
            pump: Some(tokio::spawn(async move {
                // Stands in for the connection and the locked file the pump holds.
                let _carried = carried;
                std::future::pending::<()>().await;
                Ok(CmdResult {
                    code: Some(0),
                    signal: None,
                })
            })),
            stop: CancellationToken::new(),
        };
        // So the stop below is a running task's, not a task that never started.
        tokio::task::yield_now().await;
        recording.stop_now().await;
        assert_eq!(
            std::sync::Arc::strong_count(&held),
            1,
            "the pump was still holding the recording"
        );
    }

    /// Stopping asks the guest for its final sample by closing its stdin — exactly once,
    /// however long the sampler then takes. A cancelled token that kept re-firing would
    /// spin the pump's select instead of waiting for the samples still coming.
    #[tokio::test]
    async fn a_stop_closes_stdin_once_and_keeps_reading() {
        let log = std::env::temp_dir().join(format!("vk-atop-stop-{}.log", std::process::id()));
        let file = std::fs::File::create(&log).unwrap();
        let (host, guest) = tokio::io::duplex(64 * 1024);
        let (stream, sink) = vk_core::framing::wrap_stream(host);
        let (mut gstream, mut gsink) = vk_core::framing::wrap_stream(guest);
        let stop = CancellationToken::new();
        let pump = tokio::spawn(pump(stream, sink, file, false, stop.clone()));

        stop.cancel();
        match gstream.next().await.unwrap().unwrap() {
            Message::Close { fd: Fd::Stdin, .. } => {}
            other => panic!("a stop closes the sampler's stdin, got {other:?}"),
        }
        // Still reading: the final sample the stop asked for is still to come.
        gsink
            .send(Message::Data {
                fd: Fd::Stdout,
                msg: b"SEP last\n".to_vec(),
            })
            .await
            .unwrap();
        gsink
            .send(Message::ExecDone(CmdResult {
                code: Some(0),
                signal: None,
            }))
            .await
            .unwrap();
        pump.await.unwrap().unwrap();
        // Exactly one Close: the guest saw nothing else before its exit was accepted.
        assert!(
            gstream.next().await.is_none(),
            "the pump sent a second stop"
        );
        std::fs::remove_file(&log).unwrap();
    }
}
