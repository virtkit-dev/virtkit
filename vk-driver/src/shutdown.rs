//! Graceful guest shutdown. Killing a VMM cuts power, losing cached writes and leaving every
//! filesystem dirty. When guest state persists in a `disk` volume or `--disk` image, the owner
//! first runs `vk-agent poweroff`, then waits up to [`STOP_GRACE`] for the VMM to exit before
//! killing it. See the agent's `poweroff` module for init-specific behavior.
//!
//! A guest whose agent cannot be reached still gets an orderly stop: [`press_power_button`]
//! SIGTERMs the VMM, whose libkrun boot child turns that into an ACPI power-button press.
//! [`request_reboot`] and [`hard_reset`] are the reboot equivalents — the agent over vsock, or
//! SIGUSR1 to the boot child's keeper, which relaunches the VM in place (see `libkrun_sys::keep`).

use std::process::Child;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::Result;
use vk_core::addr::SocketAddr;
use vk_core::status::{BOOT_PROBE_BUDGET, get_status_within};

/// Maximum guest shutdown time, including the poweroff request. A systemd guest stops its units
/// within this (its per-unit default is 90 s, though a service unit rarely approaches it).
/// `vk-agent init` gives its service 20 s (`SERVICE_STOP_GRACE_SECS` in
/// `vk-agent/src/init.rs`), then powers off regardless.
pub(crate) const STOP_GRACE: Duration = Duration::from_secs(60);

/// Maximum time for the poweroff request to reach the guest. The request returns when shutdown
/// begins, so exceeding this budget means the guest cannot answer.
const REQUEST_BUDGET: Duration = Duration::from_secs(10);

/// Request poweroff from every live guest, each watched on a thread of its own so one guest's
/// probes and requests never delay another's. Accepted requests share one [`STOP_GRACE`]
/// deadline, and a guest that turns out to have rebooted instead is asked again. A refused
/// request is retried if the guest answers within [`REFUSED_WAIT`] — a guest caught between
/// two boots has no agent to ask — and the VMM is killed otherwise. Kill and reap every
/// remaining VMM, returning the names still alive when killed; those guests suffered a power
/// cut.
pub(crate) fn power_off_then_kill(vmms: &mut [(&str, &SocketAddr, &mut Child)]) -> Vec<String> {
    power_off_then_kill_within(vmms, REFUSED_WAIT)
}

/// How long a guest that refused its poweroff has to answer before its VMM is killed. A reset
/// between two boots is refused, and the next boot's agent answers within a few seconds. It is
/// also what a guest that cannot be reached, or keeps refusing, costs the stop before the kill.
const REFUSED_WAIT: Duration = Duration::from_secs(10);

fn power_off_then_kill_within(
    vmms: &mut [(&str, &SocketAddr, &mut Child)],
    refused_wait: Duration,
) -> Vec<String> {
    let deadline = Instant::now() + STOP_GRACE;
    // A watcher that cannot be spawned drops its closure, so the child is reached through a
    // lock rather than moved in: the kill that replaces the watcher needs it back.
    let guests: Vec<_> = vmms
        .iter_mut()
        .map(|(name, addr, child)| (*name, *addr, Mutex::new(&mut **child)))
        .collect();
    std::thread::scope(|s| {
        let watchers: Vec<_> = guests
            .iter()
            .map(|(name, addr, child)| {
                let watcher = std::thread::Builder::new().spawn_scoped(s, move || {
                    watch_stop(name, addr, &mut lock(child), deadline, refused_wait)
                });
                // Without a watcher, kill it now rather than after the others are joined.
                if let Err(e) = &watcher {
                    kill_for(
                        name,
                        &mut lock(child),
                        &format!("no thread to stop it ({e})"),
                    );
                }
                (*name, child, watcher.ok())
            })
            .collect();
        watchers
            .into_iter()
            .filter_map(|(name, child, watcher)| {
                let killed = watcher.is_none_or(|watcher| {
                    watcher.join().unwrap_or_else(|_| {
                        kill_for(name, &mut lock(child), "its stop watcher panicked");
                        true
                    })
                });
                killed.then(|| name.to_string())
            })
            .collect()
    })
}

/// Lock a guest's VMM. A poisoned lock only means its watcher panicked; the
/// child is still there to kill.
fn lock<'a, 'c>(child: &'a Mutex<&'c mut Child>) -> MutexGuard<'a, &'c mut Child> {
    child.lock().unwrap_or_else(PoisonError::into_inner)
}

fn kill_for(name: &str, child: &mut Child, why: &str) {
    eprintln!("virtkit: service {name}: {why} — killing the VM");
    kill_and_reap(child);
}

/// Ask guest `name` at `addr` to power off, then retry after each reset until its VMM exits
/// or its [`Watch`] expires. Return whether the VMM had to be killed.
fn watch_stop(
    name: &str,
    addr: &SocketAddr,
    child: &mut Child,
    deadline: Instant,
    refused_wait: Duration,
) -> bool {
    // An unreadable status counts as alive; the kill below settles it.
    if child.try_wait().ok().flatten().is_some() {
        // Exited on its own before it could be asked.
        kill_and_reap(child);
        return false;
    }
    // This thread is the guest's own, so it blocks on a runtime of its own.
    let rt = match own_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            kill_for(name, child, &format!("no runtime to stop it ({e})"));
            return true;
        }
    };
    let ask = |budget| rt.block_on(agent_command(addr, "poweroff", budget));
    let mut watch = Watch::new(ask(REQUEST_BUDGET), Instant::now(), deadline, refused_wait);
    let mut next_probe = Instant::now();
    loop {
        let now = Instant::now();
        let answers = (now >= next_probe).then(|| {
            next_probe = now + REBOOT_PROBE_EVERY;
            let budget = BOOT_PROBE_BUDGET.min(watch.until.saturating_duration_since(now));
            rt.block_on(get_status_within(addr, budget)).is_ok()
        });
        // An unreadable status is taken as alive: keep waiting, the deadline bounds it.
        let exited = child.try_wait().ok().flatten().is_some();
        let now = Instant::now();
        match watch.step(now, exited, answers) {
            Action::Keep => std::thread::sleep(Duration::from_millis(50)),
            Action::Ask => watch.asked(ask(
                REQUEST_BUDGET.min(watch.until.saturating_duration_since(now))
            )),
            Action::Kill(why) => {
                kill_for(name, child, &why);
                return true;
            }
            Action::Reaped => {
                kill_and_reap(child);
                return false;
            }
        }
    }
}

/// Track a stopping guest's agent history, wait limit, and refusal reason to report if
/// it never answers.
struct Watch {
    reboots: Reboots,
    until: Instant,
    /// Shared [`STOP_GRACE`] deadline for an accepted request.
    deadline: Instant,
    refused: Option<String>,
    /// Last failed retry after a reset, following an accepted request.
    last_ask: Option<String>,
}

/// What a guest's watcher does next.
#[derive(Debug, PartialEq)]
enum Action {
    Keep,
    /// The guest is back from a reset: ask this boot to power off.
    Ask,
    Kill(String),
    /// The VMM exited: reap it.
    Reaped,
}

impl Watch {
    /// Watch a guest whose first poweroff request had `outcome`.
    fn new(outcome: Result<bool>, now: Instant, deadline: Instant, refused_wait: Duration) -> Self {
        match refusal(outcome) {
            None => Self {
                reboots: Reboots::default(),
                until: deadline,
                deadline,
                refused: None,
                last_ask: None,
            },
            why => Self {
                // Silent so far: its first answer is a boot to ask.
                reboots: Reboots::silent(),
                until: (now + refused_wait).min(deadline),
                deadline,
                refused: why,
                last_ask: None,
            },
        }
    }

    /// Choose the next action at `now` from the VMM's `exited` state and optional agent
    /// probe result, `answers`.
    fn step(&mut self, now: Instant, exited: bool, answers: Option<bool>) -> Action {
        if exited {
            return Action::Reaped;
        }
        if now >= self.until {
            let grace = STOP_GRACE.as_secs();
            return Action::Kill(match (self.refused.take(), self.last_ask.take()) {
                (Some(why), _) => why,
                (None, Some(why)) => {
                    format!("did not power off within {grace} s (last re-ask: {why})")
                }
                (None, None) => format!("did not power off within {grace} s"),
            });
        }
        if let Some(answers) = answers
            && self.reboots.observe(answers)
        {
            return Action::Ask;
        }
        Action::Keep
    }

    /// Record a poweroff retry's `outcome` after a reset. Only acceptance changes the wait
    /// limit: failure likely caught another reset, so retry when the next boot answers.
    /// After an accepted request, a failed retry only adds context to the timeout report.
    fn asked(&mut self, outcome: Result<bool>) {
        match refusal(outcome) {
            None => {
                self.refused = None;
                self.last_ask = None;
                self.until = self.deadline;
            }
            why if self.refused.is_some() => self.refused = why,
            why => self.last_ask = why,
        }
    }
}

/// Return the poweroff refusal reason, or `None` if the guest accepted the request.
fn refusal(outcome: Result<bool>) -> Option<String> {
    match outcome {
        Ok(true) => None,
        Ok(false) => Some("poweroff refused".to_string()),
        Err(e) => Some(format!("poweroff request failed ({e:#})")),
    }
}

/// How often a stop checks whether a guest that accepted its poweroff has rebooted instead.
/// A guest reset leaves the agent silent from the old boot's end to the new boot's agent
/// start, about a second for `vk-agent init`; probing faster than that sees the gap.
const REBOOT_PROBE_EVERY: Duration = Duration::from_millis(250);

/// A guest's agent across a stop: a poweroff it accepted while already rebooting resets the
/// guest, and the VMM keeper relaunches it rather than exiting. The agent then goes silent
/// and answers again, from a boot nobody asked to power off. One missed probe is enough: a
/// slow answer taken for a reset only asks a guest already powering off again, which is
/// harmless.
#[derive(Default)]
struct Reboots {
    silent: bool,
}

impl Reboots {
    /// An agent already taken for silent, as one that could not be asked.
    fn silent() -> Self {
        Self { silent: true }
    }

    /// Record one probe; true when the agent answers after having gone silent — a new boot.
    fn observe(&mut self, answers: bool) -> bool {
        let rebooted = self.silent && answers;
        self.silent = !answers;
        rebooted
    }
}

/// Create a current-thread runtime for a dedicated shutdown thread.
fn own_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

/// Run `task` on a dedicated thread with its own runtime: a synchronous caller may be on the
/// owner's runtime, which must not block on its own futures. Thread creation failure is
/// returned for the caller to treat as a refusal; panicking would poison the held units lock.
fn on_own_runtime<T, F, Fut>(task: F) -> std::io::Result<JoinHandle<Result<T>>>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = Result<T>>,
{
    std::thread::Builder::new().spawn(move || own_runtime()?.block_on(task()))
}

/// Run `vk-agent <command>` over the guest's exec channel within `budget`.
/// Return whether it exited with status 0.
async fn agent_command(addr: &SocketAddr, command: &str, budget: Duration) -> Result<bool> {
    let result = tokio::time::timeout(
        budget,
        crate::executor::exec_script(
            addr,
            &[crate::run::GUEST_AGENT.to_string(), command.to_string()],
            Vec::new(),
            None,
            &crate::executor::OutputSink::Inherit,
            None,
        ),
    )
    .await??;
    Ok(result.code == Some(0))
}

pub(crate) fn kill_and_reap(child: &mut Child) {
    // A child that already exited makes kill fail; wait then just returns its status.
    let _ = child.kill();
    let _ = child.wait();
}

/// Ask the guest at `addr` to power off and report whether it accepted — for a single guest,
/// such as a `vk run` VM. A refusal (unreachable guest, no thread) is logged, and the caller
/// kills the VMM, the power cut this exists to avoid.
pub(crate) fn request_poweroff(addr: &SocketAddr) -> bool {
    let addr = addr.clone();
    let request =
        on_own_runtime(
            move || async move { agent_command(&addr, "poweroff", REQUEST_BUDGET).await },
        );
    let outcome = match request {
        Ok(request) => request
            .join()
            .unwrap_or_else(|_| Err(anyhow::anyhow!("the request panicked"))),
        Err(e) => {
            eprintln!(
                "virtkit: run VM: no thread for the poweroff request ({e}) — killing the VM instead"
            );
            return false;
        }
    };
    match outcome {
        Ok(accepted) => accepted,
        Err(e) => {
            eprintln!("virtkit: run VM: poweroff request failed ({e:#}) — killing the VM instead");
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

/// Ask the guest at `addr` to reboot (`vk-agent reboot` over the exec channel) and report
/// whether it accepted. The guest resets in place; the boot child's keeper relaunches it. A
/// refusal means the caller falls back to a hard reset. Runs on [`on_own_runtime`].
pub(crate) fn request_reboot(addr: &SocketAddr) -> bool {
    let addr = addr.clone();
    let request =
        on_own_runtime(move || async move { agent_command(&addr, "reboot", REQUEST_BUDGET).await });
    matches!(request.map(JoinHandle::join), Ok(Ok(Ok(true))))
}

/// SIGTERM the VMM `child`: its libkrun boot child presses the guest's ACPI power button (an
/// orderly power-off) rather than dying. The stop fallback when the agent is
/// unreachable. Returns false only if the pid is unusable.
pub(crate) fn press_power_button(child: &Child) -> bool {
    signal_child(child, libc::SIGTERM)
}

/// SIGUSR1 the VMM `child`: its keeper hard-resets the guest (SIGKILL) and relaunches it in
/// place — the reboot equivalent of the power button, for an unreachable agent.
pub(crate) fn hard_reset(child: &Child) -> bool {
    signal_child(child, libc::SIGUSR1)
}

fn signal_child(child: &Child, sig: libc::c_int) -> bool {
    match i32::try_from(child.id()) {
        // SAFETY: kill(2); the worst case is ESRCH if the child already exited.
        Ok(pid) => {
            unsafe { libc::kill(pid, sig) };
            true
        }
        Err(_) => false,
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
        // With no VMM socket, poweroff is refused immediately. Kill the guest after its
        // wait for an answer expires.
        let dir = std::env::temp_dir().join(format!("vk-shutdown-test-{}", std::process::id()));
        let addr = crate::vmm::exec_addr(&dir.join("vsock.sock"), crate::units::VSOCK_PORT);
        let mut child = spawn("sleep", &["30"]);
        let started = Instant::now();
        let wait = Duration::from_millis(500);
        let killed = power_off_then_kill_within(&mut [("db", &addr, &mut child)], wait);
        assert_eq!(killed, ["db"]);
        assert!(started.elapsed() >= wait);
        assert!(started.elapsed() < REQUEST_BUDGET);
        assert!(child.try_wait().unwrap().is_some());
    }

    #[test]
    fn a_guest_that_goes_silent_and_answers_again_has_rebooted() {
        let mut r = Reboots::default();
        // Still up while it shuts down, then gone across the reset, then back.
        let seen: Vec<bool> = [true, true, false, false, true, true]
            .into_iter()
            .map(|answers| r.observe(answers))
            .collect();
        assert_eq!(seen, [false, false, false, false, true, false]);
    }

    #[test]
    fn a_guest_never_heard_from_again_is_not_taken_for_rebooted() {
        let mut r = Reboots::default();
        assert!(![true, false, false].into_iter().any(|a| r.observe(a)));
    }

    const WAIT: Duration = Duration::from_secs(10);

    fn at(t0: Instant, secs: u64) -> Instant {
        t0 + Duration::from_secs(secs)
    }

    fn kill_reason(action: Action) -> String {
        match action {
            Action::Kill(why) => why,
            other => panic!("expected a kill, got {other:?}"),
        }
    }

    #[test]
    fn a_refusing_guest_that_answers_is_asked_and_its_acceptance_waits_for_the_deadline() {
        let t0 = Instant::now();
        let deadline = t0 + STOP_GRACE;
        let mut w = Watch::new(Ok(false), t0, deadline, WAIT);
        assert_eq!(w.until, t0 + WAIT);
        assert_eq!(w.step(at(t0, 1), false, Some(false)), Action::Keep);
        assert_eq!(w.step(at(t0, 2), false, Some(true)), Action::Ask);
        w.asked(Ok(true));
        assert_eq!(w.until, deadline);
        assert_eq!(w.refused, None);
        assert_eq!(w.step(at(t0, 30), false, Some(true)), Action::Keep);
        assert_eq!(
            kill_reason(w.step(deadline, false, None)),
            "did not power off within 60 s"
        );
    }

    #[test]
    fn a_refusing_guest_asked_again_in_vain_is_killed_as_refused() {
        let t0 = Instant::now();
        let mut w = Watch::new(Ok(false), t0, t0 + STOP_GRACE, WAIT);
        assert_eq!(w.step(at(t0, 1), false, Some(true)), Action::Ask);
        w.asked(Err(anyhow::anyhow!("reset")));
        assert_eq!(w.until, t0 + WAIT);
        assert_eq!(
            kill_reason(w.step(t0 + WAIT, false, None)),
            "poweroff request failed (reset)"
        );
    }

    #[test]
    fn an_exit_wins_over_an_expired_watch() {
        let t0 = Instant::now();
        let mut w = Watch::new(Ok(false), t0, t0 + STOP_GRACE, WAIT);
        assert_eq!(w.step(w.until, true, None), Action::Reaped);
    }

    #[test]
    fn the_refused_wait_ends_at_the_deadline() {
        let t0 = Instant::now();
        let deadline = t0 + Duration::from_secs(5);
        assert_eq!(Watch::new(Ok(false), t0, deadline, WAIT).until, deadline);
    }

    #[test]
    fn a_guest_that_never_answers_is_killed_as_refused() {
        let t0 = Instant::now();
        let mut w = Watch::new(Err(anyhow::anyhow!("no agent")), t0, t0 + STOP_GRACE, WAIT);
        assert_eq!(w.step(at(t0, 5), false, Some(false)), Action::Keep);
        assert_eq!(
            kill_reason(w.step(t0 + WAIT, false, Some(false))),
            "poweroff request failed (no agent)"
        );
    }

    #[test]
    fn an_accepting_guest_that_resets_is_asked_again() {
        let t0 = Instant::now();
        let deadline = t0 + STOP_GRACE;
        let mut w = Watch::new(Ok(true), t0, deadline, WAIT);
        let seen: Vec<Action> = [true, false, false, true]
            .into_iter()
            .map(|answers| w.step(at(t0, 1), false, Some(answers)))
            .collect();
        assert_eq!(
            seen,
            [Action::Keep, Action::Keep, Action::Keep, Action::Ask]
        );
        w.asked(Ok(true));
        assert_eq!(w.until, deadline);
        assert_eq!(w.step(at(t0, 2), false, Some(true)), Action::Keep);
    }

    #[test]
    fn an_accepting_guest_whose_vmm_exits_is_reaped_not_asked() {
        let t0 = Instant::now();
        let mut w = Watch::new(Ok(true), t0, t0 + STOP_GRACE, WAIT);
        assert_eq!(w.step(at(t0, 1), false, Some(true)), Action::Keep);
        assert_eq!(w.step(at(t0, 2), false, Some(false)), Action::Keep);
        assert_eq!(w.step(at(t0, 3), true, None), Action::Reaped);
    }

    #[test]
    fn a_failed_ask_after_a_reset_keeps_the_watch_and_names_the_kill() {
        let cases: [(Result<bool>, &str); 2] = [
            (Ok(false), "poweroff refused"),
            (
                Err(anyhow::anyhow!("reset")),
                "poweroff request failed (reset)",
            ),
        ];
        for (outcome, why) in cases {
            let t0 = Instant::now();
            let deadline = t0 + STOP_GRACE;
            let mut w = Watch::new(Ok(true), t0, deadline, WAIT);
            assert_eq!(w.step(at(t0, 1), false, Some(false)), Action::Keep);
            assert_eq!(w.step(at(t0, 2), false, Some(true)), Action::Ask);
            w.asked(outcome);
            assert_eq!(w.until, deadline);
            assert_eq!(w.step(at(t0, 50), false, None), Action::Keep);
            assert_eq!(
                kill_reason(w.step(deadline, false, None)),
                format!("did not power off within 60 s (last re-ask: {why})")
            );
        }
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
