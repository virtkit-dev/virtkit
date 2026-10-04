//! The boot child answers pause, resume, snapshot and quit requests for a running VM on a
//! Unix socket in the run's directory ([`crate::vmm::VmSpec::control`]).
//!
//! One request per line, one answer per line: `ok`, or `error: <why>`. Requests:
//! - `pause`: freeze every vCPU; the guest's devices stay as they are.
//! - `resume`: run the vCPUs a `pause` froze.
//! - `snapshot <dir>`: pause the VM and write its snapshot (CPU and device state, RAM) into
//!   `<dir>`; the VM stays paused.
//! - `quit`: end the VM as a guest power-off does; it may end before it answers.
//!
//! The socket is for its user only: the run's directory is 0700.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// How long either end waits for the other's line: a silent client must not hold the socket,
/// which answers one client at a time, and a wedged VMM must not hold the caller.
const LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a client waits for `snapshot` to answer: writing the guest's RAM takes far longer
/// than a pause.
const SLOW_TIMEOUT: Duration = Duration::from_secs(600);

/// The VMM behind its libkrun handle, driven by the control socket.
pub trait Control: Send + 'static {
    fn pause(&self) -> Result<()>;
    fn resume(&self) -> Result<()>;
    fn snapshot(&self, dir: &Path) -> Result<()>;
    fn quit(&self) -> Result<()>;
}

/// Answer requests on `path` for `ctl` on a dedicated thread for the process's lifetime.
pub fn serve(path: &Path, ctl: impl Control) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = vk_core::unixpath::bind(path)
        .with_context(|| format!("binding the VM control socket {}", path.display()))?;
    std::thread::Builder::new()
        .name("vk-vmm-control".into())
        .spawn(move || {
            for conn in listener.incoming().flatten() {
                // One client at a time: requests are rare and quick.
                let _ = answer(conn, &ctl);
            }
        })
        .context("spawning the VM control thread")?;
    Ok(())
}

fn answer(conn: std::os::unix::net::UnixStream, ctl: &impl Control) -> std::io::Result<()> {
    conn.set_read_timeout(Some(LINE_TIMEOUT))?;
    let mut writer = conn.try_clone()?;
    for line in BufReader::new(conn).lines() {
        let line = line?;
        let line = line.trim();
        let result = match line.split_once(' ') {
            None if line == "pause" => ctl.pause(),
            None if line == "resume" => ctl.resume(),
            None if line == "quit" => ctl.quit(),
            Some(("snapshot", dir)) => ctl.snapshot(&PathBuf::from(dir)),
            _ => Err(anyhow::anyhow!("unknown request {line:?}")),
        };
        match result {
            Ok(()) => writeln!(writer, "ok")?,
            Err(e) => writeln!(writer, "error: {e:#}")?,
        }
    }
    Ok(())
}

/// Snapshot the VM behind the control socket at `path` into `dir` ([`request`]).
pub fn snapshot(path: &Path, dir: &Path) -> Result<()> {
    let dir = dir
        .to_str()
        .filter(|d| !d.contains('\n'))
        .with_context(|| format!("snapshot directory {}", dir.display()))?;
    request_within(path, &format!("snapshot {dir}"), SLOW_TIMEOUT)
}

/// Ask the VM behind control socket `path` to end without waiting for an answer: it may end
/// before answering. The caller watches for the VM to be gone.
pub fn quit(path: &Path) -> Result<()> {
    let mut conn = vk_core::unixpath::connect(path)
        .with_context(|| format!("connecting to the VM control socket {}", path.display()))?;
    writeln!(conn, "quit").context("asking the VM to end")
}

/// Send `request` to the control socket at `path` and wait for its answer.
pub fn request(path: &Path, request: &str) -> Result<()> {
    request_within(path, request, LINE_TIMEOUT)
}

/// [`request`], waiting up to `timeout` for the answer.
fn request_within(path: &Path, request: &str, timeout: Duration) -> Result<()> {
    let mut conn = vk_core::unixpath::connect(path)
        .with_context(|| format!("connecting to the VM control socket {}", path.display()))?;
    conn.set_read_timeout(Some(timeout))?;
    writeln!(conn, "{request}")?;
    let mut answer = String::new();
    BufReader::new(&conn)
        .read_line(&mut answer)
        .with_context(|| format!("waiting for the VM to answer {request:?}"))?;
    match answer.trim_end() {
        "ok" => Ok(()),
        "" => bail!("the VM closed its control socket without answering {request:?}"),
        other => bail!("{}", other.strip_prefix("error: ").unwrap_or(other)),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// A control that records what it was asked and refuses to resume.
    struct Fake(Arc<Mutex<Vec<&'static str>>>);

    impl Control for Fake {
        fn pause(&self) -> Result<()> {
            self.0.lock().unwrap().push("pause");
            Ok(())
        }

        fn resume(&self) -> Result<()> {
            bail!("not paused")
        }

        fn snapshot(&self, dir: &Path) -> Result<()> {
            assert_eq!(dir, Path::new("/tmp/a dir"));
            self.0.lock().unwrap().push("snapshot");
            Ok(())
        }

        fn quit(&self) -> Result<()> {
            self.0.lock().unwrap().push("quit");
            Ok(())
        }
    }

    #[test]
    fn requests_reach_the_control_and_errors_come_back() {
        let dir = std::env::temp_dir().join(format!("vk-vmmctl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("vmm.sock");
        let asked = Arc::new(Mutex::new(Vec::new()));
        serve(&sock, Fake(asked.clone())).unwrap();

        request(&sock, "pause").unwrap();
        snapshot(&sock, Path::new("/tmp/a dir")).unwrap();
        quit(&sock).unwrap();
        // One client at a time: this one is answered after `quit` was acted on.
        let err = request(&sock, "resume").unwrap_err();
        assert_eq!(format!("{err:#}"), "not paused");
        assert_eq!(*asked.lock().unwrap(), ["pause", "snapshot", "quit"]);
        for unknown in ["reboot", "snapshot", "pause now"] {
            let err = request(&sock, unknown).unwrap_err();
            assert!(format!("{err:#}").contains("unknown request"), "{err:#}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
