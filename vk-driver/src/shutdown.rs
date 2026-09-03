//! Graceful guest shutdown. Killing a VMM cuts power, losing cached writes and leaving every
//! filesystem dirty. When guest state persists in a `disk` volume or `--disk` image, the owner
//! first runs `vk-agent poweroff`, then waits up to [`STOP_GRACE`] for the VMM to exit before
//! killing it. See the agent's `poweroff` module for init-specific behavior.

use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::Result;
use vk_core::addr::SocketAddr;

/// Maximum guest shutdown time, including the poweroff request. A systemd guest stops its units
/// within this (its per-unit default is 90 s, though a service unit rarely approaches it).
/// `vk-agent init` gives its service 20 s (`SERVICE_STOP_GRACE_SECS` in
/// `vk-agent/src/init.rs`), then powers off regardless.
pub(crate) const STOP_GRACE: Duration = Duration::from_secs(60);

/// Maximum time for the poweroff request to reach the guest. The request returns when shutdown
/// begins, so exceeding this budget means the guest cannot answer.
const REQUEST_BUDGET: Duration = Duration::from_secs(10);

/// Request concurrent poweroff from every live guest. Accepted requests share one [`STOP_GRACE`]
/// deadline; rejected requests trigger an immediate kill. Kill and reap every remaining VMM,
/// returning the names still alive when killed; those guests suffered a power cut.
pub(crate) fn power_off_then_kill(vmms: &mut [(&str, &SocketAddr, &mut Child)]) -> Vec<String> {
    let deadline = Instant::now() + STOP_GRACE;
    let requests: Vec<_> = vmms
        .iter_mut()
        .map(|(_, addr, child)| {
            // An unreadable status counts as alive; the kill below settles it.
            let alive = child.try_wait().ok().flatten().is_none();
            alive.then(|| spawn_poweroff_request(addr))
        })
        .collect();
    let mut killed = Vec::new();
    let mut powering_off = Vec::new();
    for (i, ((name, _, child), request)) in vmms.iter_mut().zip(requests).enumerate() {
        if request.is_some_and(|request| poweroff_accepted(format_args!("service {name}"), request))
        {
            powering_off.push(i);
            continue;
        }
        // Refused or already exited: there is nothing to await. A live VMM suffers a power cut;
        // one that exited meanwhile stopped on its own.
        if child.try_wait().ok().flatten().is_none() {
            killed.push(name.to_string());
        }
        kill_and_reap(child);
    }
    for i in powering_off {
        let Some((name, _, child)) = vmms.get_mut(i) else {
            continue;
        };
        wait_exit(child, deadline);
        // As above: a status that cannot be read is taken as alive.
        if child.try_wait().ok().flatten().is_none() {
            killed.push(name.to_string());
        }
        kill_and_reap(child);
    }
    killed
}

pub(crate) fn kill_and_reap(child: &mut Child) {
    // A child that already exited makes kill fail; wait then just returns its status.
    let _ = child.kill();
    let _ = child.wait();
}

/// Run `vk-agent poweroff` over the guest's exec channel. Use a dedicated thread because a
/// synchronous caller may run on the owner's runtime; [`poweroff_accepted`] collects the result
/// without blocking that runtime on its own futures.
pub(crate) fn spawn_poweroff_request(
    addr: &SocketAddr,
) -> std::io::Result<std::thread::JoinHandle<Result<bool>>> {
    let addr = addr.clone();
    let request = move || -> Result<bool> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let result = rt.block_on(async {
            tokio::time::timeout(
                REQUEST_BUDGET,
                crate::executor::exec_script(
                    &addr,
                    &[crate::run::GUEST_AGENT.to_string(), "poweroff".to_string()],
                    Vec::new(),
                    None,
                    &crate::executor::OutputSink::Inherit,
                    None,
                ),
            )
            .await
        })??;
        Ok(result.code == Some(0))
    };
    // Treat thread creation failure as refusal; panicking would poison the held units lock.
    std::thread::Builder::new().spawn(request)
}

/// Ask the guest at `addr` to power off and report whether it accepted — for a single guest,
/// such as a `vk run` VM. A refusal (unreachable guest, no thread) means the caller kills the
/// VMM, the power cut this exists to avoid.
pub(crate) fn request_poweroff(addr: &SocketAddr) -> bool {
    poweroff_accepted("run VM", spawn_poweroff_request(addr))
}

/// Return whether the guest labelled `who` accepted the poweroff `request`. A refusal is
/// logged and the caller kills the VMM, which the guest takes as a power cut.
pub(crate) fn poweroff_accepted(
    who: impl std::fmt::Display,
    request: std::io::Result<std::thread::JoinHandle<Result<bool>>>,
) -> bool {
    let request = match request {
        Ok(request) => request,
        Err(e) => {
            eprintln!(
                "virtkit: {who}: no thread for the poweroff request ({e}) — killing the VM instead"
            );
            return false;
        }
    };
    match request.join() {
        Ok(Ok(accepted)) => accepted,
        Ok(Err(e)) => {
            eprintln!("virtkit: {who}: poweroff request failed ({e:#}) — killing the VM instead");
            false
        }
        Err(_) => {
            eprintln!("virtkit: {who}: poweroff request panicked — killing the VM instead");
            false
        }
    }
}

/// Wait for SIGTERM, as sent by `vk stop` and `vk publish stop`.
/// If the handler cannot be installed, wait forever and leave SIGTERM's default termination
/// in place.
pub(crate) async fn terminate_signal() {
    match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(mut sig) => {
            sig.recv().await;
        }
        Err(_) => std::future::pending().await,
    }
}

/// Wait until `deadline` for the VMM `child` to exit.
pub(crate) fn wait_exit(child: &mut Child, deadline: Instant) {
    while Instant::now() < deadline {
        // An unreadable status is taken as alive: keep waiting, the deadline bounds it.
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spawn(cmd: &str, args: &[&str]) -> Child {
        std::process::Command::new(cmd).args(args).spawn().unwrap()
    }

    #[test]
    fn wait_exit_returns_once_the_child_is_gone() {
        let mut child = spawn("true", &[]);
        let started = Instant::now();
        wait_exit(&mut child, started + Duration::from_secs(30));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn wait_exit_gives_up_at_the_deadline() {
        let mut child = spawn("sleep", &["30"]);
        let started = Instant::now();
        wait_exit(&mut child, started + Duration::from_millis(200));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert!(child.try_wait().unwrap().is_none());
        kill_and_reap(&mut child);
    }

    #[test]
    fn power_off_then_kill_reports_a_guest_that_could_not_be_asked() {
        // With no VMM socket, the request is refused immediately and the VMM is killed.
        let dir = std::env::temp_dir().join(format!("vk-shutdown-test-{}", std::process::id()));
        let addr = crate::vmm::exec_addr(&dir.join("vsock.sock"), crate::units::VSOCK_PORT);
        let mut child = spawn("sleep", &["30"]);
        let started = Instant::now();
        let killed = power_off_then_kill(&mut [("db", &addr, &mut child)]);
        assert_eq!(killed, ["db"]);
        assert!(started.elapsed() < REQUEST_BUDGET);
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn power_off_then_kill_leaves_an_exited_vmm_out_of_the_killed() {
        let addr = crate::vmm::exec_addr(
            &std::env::temp_dir().join("vsock.sock"),
            crate::units::VSOCK_PORT,
        );
        let mut child = spawn("true", &[]);
        let _ = child.wait();
        assert!(power_off_then_kill(&mut [("db", &addr, &mut child)]).is_empty());
    }
}
