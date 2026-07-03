//! Tied helper subprocesses: children the kernel SIGTERMs when their owning
//! virtkit process dies (PR_SET_PDEATHSIG), so a crashed or kill -9'd owner
//! never leaks a switch, virtiofsd, or VMM. Used by every foreground owner
//! (`run` and the build path) and the CI job supervisor.

use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Spawn a foreground-owned helper tied to this process: a pre-exec hook asks the kernel to
/// SIGTERM the child when its parent dies, so a crashed or `kill -9`'d virtkit cannot leak it
/// (a stuck virtiofsd would, e.g., keep this binary's file busy for the next build). For
/// foreground owners only — the `run`/build VMs, where one virtkit process
/// owns the helper for its whole lifetime. NOT for the gitlab job VM, whose helpers are
/// deliberately detached (`spawn_detached`) to outlive the short `prepare`.
///
/// PR_SET_PDEATHSIG ties the death signal to the SPAWNING THREAD, not the process. These
/// helpers are spawned from async code that tokio may run on a blocking-pool thread, which
/// the runtime retires after an idle keepalive — spawning inline would then fire the signal
/// and kill a perfectly healthy guest mid-boot. So the spawn is done from a dedicated
/// process-lifetime thread, leaving the signal tied to a thread that lives exactly as long
/// as virtkit. The caller configures `cmd` (args + stdio) first, then hands it over.
pub(crate) fn spawn_tied(mut cmd: Command) -> std::io::Result<Child> {
    use std::sync::OnceLock;
    use std::sync::mpsc::{Sender, channel};

    // SAFETY: prctl(PR_SET_PDEATHSIG) is async-signal-safe, so it is valid in a pre-exec
    // hook (which runs in the forked child between fork and exec).
    unsafe {
        cmd.pre_exec(
            || match libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error()),
            },
        );
    }

    type Reply = Sender<std::io::Result<Child>>;
    static SPAWNER: OnceLock<Sender<(Command, Reply)>> = OnceLock::new();
    let tx = SPAWNER.get_or_init(|| {
        let (tx, rx) = channel::<(Command, Reply)>();
        std::thread::Builder::new()
            .name("vk-helper-spawner".into())
            .spawn(move || {
                while let Ok((mut cmd, reply)) = rx.recv() {
                    let _ = reply.send(cmd.spawn());
                }
            })
            .expect("spawning the vk-helper-spawner thread");
        tx
    });
    let (rtx, rrx) = channel();
    tx.send((cmd, rtx)).expect("vk-helper-spawner thread alive");
    rrx.recv().expect("vk-helper-spawner thread replied")
}

/// Start the bundled virtiofsd (this executable's `vk virtiofsd` subcommand) on
/// `shared_dir` (optionally read-only) and wait for its socket to appear. A read-only
/// share is a host-side guarantee the guest can never write back to the shared tree.
/// `uid_maps` / `gid_maps` are soft_idmap spec strings (`type:from:to[:count]`) forwarded
/// as `--uid-map` / `--gid-map` to virtiofsd; empty slices = identity (no remapping).
pub(crate) fn spawn_virtiofsd(
    sock: &Path,
    shared_dir: &Path,
    readonly: bool,
    uid_maps: &[String],
    gid_maps: &[String],
) -> Result<Child> {
    let _ = std::fs::remove_file(sock);
    let exe = std::env::current_exe().context("locating the virtkit binary for virtiofsd")?;
    let mut cmd = Command::new(exe);
    cmd.arg("virtiofsd")
        .arg(format!("--socket-path={}", sock.display()))
        .arg(format!("--shared-dir={}", shared_dir.display()))
        .arg("--cache=auto")
        .arg("--sandbox=none");
    if readonly {
        cmd.arg("--readonly");
    }
    for m in uid_maps {
        cmd.arg(format!("--uid-map={m}"));
    }
    for m in gid_maps {
        cmd.arg(format!("--gid-map={m}"));
    }
    // self-reap if virtkit dies before the normal teardown runs (spawn_tied)
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = spawn_tied(cmd).context("spawning the bundled virtiofsd (vk virtiofsd)")?;
    for _ in 0..50 {
        if sock.exists() {
            return Ok(child);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("virtiofsd socket {} never appeared", sock.display());
}
