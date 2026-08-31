//! Scheduling priority for the work a build does.
//!
//! A build saturates the machine — every stage boots a guest sized for the whole host, and
//! `jobs` of them run at once — and on a workstation that machine is also the one being used.
//! So everything a build runs starts at a lower CPU priority (and, where the block scheduler
//! honours it, a lower I/O priority): the build gives way, instead of the desktop stuttering
//! while it runs. `[build] nice` and `[build] ionice` set the policy; `nice = 0` leaves the
//! CPU priority alone and `ionice = "none"` the I/O priority.
//!
//! Three properties shape how it is applied:
//!
//! - Both priorities are **per-thread** on Linux, and a thread or child process inherits them
//!   from its creator. Applying the policy once at the start of a build's own thread therefore
//!   covers everything that thread goes on to do, including the threads it spawns.
//! - Lowering is **one-way** without privilege: `RLIMIT_NICE` is normally 0, so a thread that
//!   niced itself can never come back. Nothing shared with the interactive paths may be niced
//!   in place — hence a policy applied to threads at birth ([`lower_this_thread`]) and to
//!   children in a `pre_exec` hook ([`Prio::apply`]), and never to the process.
//! - Inheritance cannot be leaned on for children, and must be kept off the shared threads.
//!   [`crate::spawn::spawn_tied`] hands every helper to one long-lived spawner thread, so a
//!   child would inherit that thread's priority and not the caller's; callers say which
//!   children are a build's with [`Prio`]. That thread and the shared runtime behind
//!   [`crate::blockrt`] are both built on first use, so a build worker reaching one first
//!   would fix it at the build's priority for the life of the process. Closing that is a
//!   caller obligation, not something [`lower_this_thread`] can do for itself: whoever is
//!   about to create deferred threads calls [`pin_shared_threads`] first, from a thread
//!   still at the driver's own priority. [`lower_this_thread`] debug-asserts that it has.
//!
//! What is deferred, then: the stage guests (a VMM subprocess, so its vCPU threads with it)
//! and the switch and virtiofsd serving them, and the parallel stage workers, whose own
//! [`crate::blockrt`] calls — the image pulls and cache pushes — inherit it. What is not: the
//! driver's own orchestration, including the final ext4 export, which runs on the thread that
//! drove the stages and goes on to boot a `vk run -f Dockerfile`'s guest; the threads those
//! two shared facilities own; the VM of a `vk run` the user is waiting on; and a CI job's VM
//! — a runner has nothing else to be responsive for.

use std::process::Command;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

/// `[build] nice`: how much a build's threads and children raise their nice value over the
/// driver's own, capped at the kernel's 19. 0 = leave scheduling priority alone.
static NICE: AtomicI32 = AtomicI32::new(0);

/// `[build] ionice` as the raw `ioprio_set` word (class << 13 | level), or 0 for
/// `IOPRIO_CLASS_NONE` = leave the I/O priority alone.
static IOPRIO: AtomicU32 = AtomicU32::new(0);

/// Default `[build] nice`: enough that the build loses a contended CPU to anything the user
/// is doing, while still getting the whole machine when nothing else wants it.
const DEFAULT_NICE: u8 = 10;

/// The kernel's highest nice value, and so the most a policy can ask for.
const NICE_MAX: i32 = 19;

/// `who` selector for the ioprio calls: the thread named by the second argument, which is
/// the calling one when that argument is 0.
const IOPRIO_WHO_PROCESS: libc::c_int = 1;
/// The class occupies the top 3 bits of the priority word; the level the low 13.
const IOPRIO_CLASS_SHIFT: u32 = 13;
const IOPRIO_CLASS_NONE: u32 = 0;
const IOPRIO_CLASS_BE: u32 = 2;
const IOPRIO_CLASS_IDLE: u32 = 3;
/// Lowest best-effort level, i.e. the least the class can ask for.
const IOPRIO_BE_LOWEST: u32 = 7;

/// Whether a spawned child is part of a build, and so gets `[build]`'s priority.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Prio {
    /// Something the user is waiting on: a `vk run` guest, a compose service, a CI job VM.
    /// Left at the driver's own priority.
    Normal,
    /// Part of a build: a stage guest, or a helper serving one.
    Build,
}

impl Prio {
    /// Apply this priority to `cmd`'s child, through a `pre_exec` hook — so it lands on the
    /// child alone and not on the spawner thread every helper is spawned from. A no-op for
    /// [`Prio::Normal`], and for a `[build]` policy that asks for nothing.
    pub(crate) fn apply(self, cmd: &mut Command) {
        let (nice, ioprio) = (NICE.load(Ordering::Relaxed), IOPRIO.load(Ordering::Relaxed));
        if self == Prio::Normal || (nice == 0 && ioprio == 0) {
            return;
        }
        use std::os::unix::process::CommandExt;
        // SAFETY: the hook runs in the forked child between fork and exec, where only
        // async-signal-safe work is allowed — which is all `lower` does.
        unsafe {
            cmd.pre_exec(move || {
                lower(nice, ioprio);
                Ok(())
            });
        }
    }
}

/// Read the host's `[build]` priority policy. Called once from [`crate::build::set_tuning`],
/// before any build starts; a plain store rather than a `OnceLock` so the re-exec'd
/// `gitlab supervise` and the tests can set it again.
pub(crate) fn set_policy(build: &crate::config::Build) {
    NICE.store(
        i32::from(build.nice.unwrap_or(DEFAULT_NICE)).min(NICE_MAX),
        Ordering::Relaxed,
    );
    IOPRIO.store(
        ioprio_word(build.ionice.unwrap_or_default()),
        Ordering::Relaxed,
    );
}

/// The raw priority word a `[build] ionice` class asks for.
fn ioprio_word(io: crate::config::IoNice) -> u32 {
    use crate::config::IoNice;
    match io {
        IoNice::None => 0,
        IoNice::BestEffort => (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | IOPRIO_BE_LOWEST,
        IoNice::Idle => IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT,
    }
}

/// Put the calling thread on the `[build]` priority, for a thread that exists to do a
/// build's work: the parallel stage workers. Everything the thread goes on to create
/// inherits it, the per-call thread of a [`crate::blockrt`] call included.
///
/// Never call it on a thread shared with the interactive paths: without `RLIMIT_NICE` the
/// nice value cannot be lowered again, so such a thread would stay deferred for the life of
/// the process.
pub(crate) fn lower_this_thread() {
    debug_assert!(
        PINNED.load(Ordering::Relaxed),
        "pin_shared_threads must run before any thread defers itself"
    );
    lower(NICE.load(Ordering::Relaxed), IOPRIO.load(Ordering::Relaxed));
}

/// Build the two process-lifetime facilities that are otherwise created on first use, from a
/// caller still at the driver's own priority: the helper spawner every
/// [`crate::spawn::spawn_tied`] goes through, and the shared runtime behind
/// [`crate::blockrt`]. Both are shared with the paths a user waits on, and a thread born
/// inside a deferred build would carry that priority, with no way back, to every `vk run`
/// guest, switch and virtiofsd of a `vk run -f Dockerfile` that builds first and boots after.
///
/// Call it once, before any thread defers itself — [`crate::build`] does, on the thread that
/// spawns the stage workers, which is the only place [`lower_this_thread`] is reached from
/// and the last point at which the driver's own priority is still what a new thread inherits.
pub(crate) fn pin_shared_threads() {
    crate::spawn::pin_spawner();
    crate::blockrt::pin_runtime();
    PINNED.store(true, Ordering::Relaxed);
}

/// Whether [`pin_shared_threads`] has run, for [`lower_this_thread`] to assert on. Only the
/// debug assertion reads it, so a release build carries the store and nothing else.
static PINNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Raise the calling thread's nice value by `nice` and lower its I/O priority to `ioprio`.
/// Both are best-effort: a kernel that refuses either leaves the caller at the priority it
/// had, which is never a reason to fail a build.
///
/// Called from a `pre_exec` hook as well as from a thread start, so it must stay
/// async-signal-safe: these four syscalls neither allocate nor take a lock.
fn lower(nice: i32, ioprio: u32) {
    // Decided before the nice value moves: on a kernel that still derives an unset I/O
    // priority from the nice value, renicing first would make the current class read back as
    // the one being asked for, and the call be skipped as no lowering at all.
    let lower_io = ioprio != 0 && lowers_io(ioprio);
    if nice > 0 {
        // Relative to what this thread already has, and only ever upward: a `vk` started
        // under `nice` stays deferred further, and an absolute target below the current value
        // would be refused outright (raising priority needs `RLIMIT_NICE`).
        //
        // `getpriority` returns -1 both for an error and for the nice value -1, told apart
        // only by errno. Read it as 0 rather than clearing and re-reading errno: a thread
        // that really is at -1 (privileged, so never this one) then gets an absolute target
        // of `nice`, which the guard below still only applies as a lowering.
        //
        // SAFETY: both calls read and write only the calling thread's own nice value.
        let cur = match unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) } {
            -1 => 0,
            n => n,
        };
        let want = cur.saturating_add(nice).min(NICE_MAX);
        if want > cur {
            unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, want) };
        }
    }
    if lower_io {
        // SAFETY: `ioprio_set` with `who` 0 writes only the calling thread's I/O priority.
        unsafe {
            libc::syscall(
                libc::SYS_ioprio_set,
                IOPRIO_WHO_PROCESS,
                0,
                ioprio as libc::c_int,
            )
        };
    }
}

/// Whether `want` asks for less I/O than the calling thread already has. `IOPRIO_CLASS_NONE`
/// is what a kernel before 5.19 reports for a thread that has never been given a priority —
/// "derived from the nice value", which nothing here can compare against — so it counts as
/// unset and anything lowers it. Since 5.19 such a thread reads back as best-effort at the
/// default level instead, which compares directly.
fn lowers_io(want: u32) -> bool {
    // SAFETY: `ioprio_get` with `who` 0 reads only the calling thread's I/O priority.
    let cur = unsafe { libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0) };
    if cur < 0 {
        return true; // unreadable: make the call and let the kernel decide
    }
    let cur = cur as u32;
    if cur >> IOPRIO_CLASS_SHIFT == IOPRIO_CLASS_NONE {
        return true;
    }
    // A higher class number is a lower priority, and within a class a higher level is.
    want > cur
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The policy is process-wide, so the tests that set it take turns rather than reading
    /// each other's. Guards `()`, so a poisoning carries nothing to propagate.
    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn policy(nice: Option<u8>, ionice: crate::config::IoNice) -> crate::config::Build {
        crate::config::Build {
            nice,
            ionice: Some(ionice),
            ..Default::default()
        }
    }

    /// The nice value `pid` runs at (0 = the calling thread), straight from the kernel. -1 is
    /// both an error and a legitimate nice value, so errno is what tells them apart.
    fn nice_of(pid: u32) -> i32 {
        // SAFETY: `getpriority` reads the scheduling attributes of the pid it is given, and
        // `__errno_location` the calling thread's own errno slot.
        unsafe {
            *libc::__errno_location() = 0;
            let n = libc::getpriority(libc::PRIO_PROCESS, pid);
            assert!(
                n != -1 || *libc::__errno_location() == 0,
                "the priority of {pid} must be readable"
            );
            n
        }
    }

    /// The I/O priority word of `pid`, or `None` when the kernel will not say.
    fn ioprio_of(pid: u32) -> Option<u32> {
        // SAFETY: `ioprio_get` reads the I/O priority of the pid it is given.
        let raw = unsafe { libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, pid as i32) };
        (raw >= 0).then_some(raw as u32)
    }

    /// A sleeping child, killed and reaped when the assertions on it are done.
    fn sleeper(prio: Prio) -> std::process::Child {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        prio.apply(&mut cmd);
        cmd.spawn().expect("spawning sleep")
    }

    fn reap(mut child: std::process::Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    /// A build's child starts deferred, and one the user waits on does not — the whole point
    /// of the split, checked against the kernel rather than the flags that were passed.
    #[test]
    fn a_build_child_is_niced_and_a_normal_one_is_not() {
        let _serial = serial();
        set_policy(&policy(Some(7), crate::config::IoNice::Idle));
        let ours = nice_of(0);

        for (prio, want) in [
            (Prio::Build, (ours + 7).min(NICE_MAX)),
            (Prio::Normal, ours),
        ] {
            let child = sleeper(prio);
            assert_eq!(nice_of(child.id()), want, "{prio:?}");
            if prio == Prio::Build {
                // Best-effort like the syscall itself: a kernel that refuses the class (or a
                // seccomp filter that hides it) must not fail the test, only the assertion
                // that it landed when it is readable.
                if let Some(io) = ioprio_of(child.id()) {
                    assert_eq!(io >> IOPRIO_CLASS_SHIFT, IOPRIO_CLASS_IDLE);
                }
            }
            reap(child);
        }
    }

    /// `nice = 0` (and `ionice = "none"`) leaves a build's children alone, so a host that
    /// wants the old behaviour back gets it exactly.
    #[test]
    fn a_zero_policy_defers_nothing() {
        let _serial = serial();
        set_policy(&policy(Some(0), crate::config::IoNice::None));
        let ours = nice_of(0);
        let child = sleeper(Prio::Build);
        assert_eq!(nice_of(child.id()), ours);
        reap(child);
    }

    /// A build worker thread defers itself, and the threads it spawns inherit that — which is
    /// what lets one call at the top of a worker cover everything it goes on to do.
    #[test]
    fn a_deferred_thread_passes_its_priority_to_the_threads_it_spawns() {
        let _serial = serial();
        set_policy(&policy(Some(5), crate::config::IoNice::BestEffort));
        let ours = nice_of(0);
        // In a thread of its own: the nice value cannot be lowered again, so the test must
        // not leave the harness's own thread deferred.
        let (worker, child) = std::thread::spawn(|| {
            lower_this_thread();
            let mine = nice_of(0);
            let theirs = std::thread::spawn(|| nice_of(0)).join().unwrap();
            (mine, theirs)
        })
        .join()
        .unwrap();
        assert_eq!(worker, (ours + 5).min(NICE_MAX));
        assert_eq!(child, worker);
    }

    /// Every helper is forked from the one shared spawner thread, so what a deferred build
    /// worker asks for must not follow the *next* caller's helper out. A `vk run -f
    /// Dockerfile` builds and then boots in one process: its stage helpers go through that
    /// thread first, and the guest's own switch, virtiofsd and VMM must still come up
    /// undeferred. Spawned from inside the deferred thread, which is where a worker spawns
    /// them and where an unpinned spawner thread would be born.
    #[test]
    fn the_shared_spawner_does_not_carry_a_build_priority_to_a_normal_helper() {
        let _serial = serial();
        set_policy(&policy(Some(9), crate::config::IoNice::Idle));
        let ours = nice_of(0);
        // What `build::run_dag` does before it spawns a worker, and the whole reason the
        // helpers below come out at the priority they do. Also what `lower_this_thread`
        // asserts on, so the ordering is pinned even when another test wins the race to
        // create the process-wide spawner thread.
        pin_shared_threads();
        let tied = |prio: Prio| {
            let mut cmd = Command::new("sleep");
            cmd.arg("30");
            prio.apply(&mut cmd);
            crate::spawn::spawn_tied(cmd).expect("spawning sleep")
        };
        let (build, normal) = std::thread::spawn(move || {
            lower_this_thread();
            let (b, n) = (tied(Prio::Build), tied(Prio::Normal));
            let got = (nice_of(b.id()), nice_of(n.id()));
            reap(b);
            reap(n);
            got
        })
        .join()
        .unwrap();
        assert_eq!(build, (ours + 9).min(NICE_MAX), "the build's own helper");
        assert_eq!(normal, ours, "a helper for something the user waits on");
    }

    /// The nice value is an increment on the driver's own and stops at the kernel's ceiling,
    /// so a `vk` already started under `nice` defers its build further rather than resetting
    /// it, and an over-large setting is clamped instead of refused.
    #[test]
    fn the_increment_is_relative_and_capped() {
        let _serial = serial();
        set_policy(&policy(Some(200), crate::config::IoNice::None));
        assert_eq!(
            NICE.load(Ordering::Relaxed),
            NICE_MAX,
            "clamped to the ceiling"
        );

        set_policy(&policy(Some(4), crate::config::IoNice::None));
        let already = std::thread::spawn(|| {
            // Stand in for a `vk` launched under `nice 15`.
            // SAFETY: sets only this thread's own nice value.
            unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, 15) };
            lower_this_thread();
            nice_of(0)
        })
        .join()
        .unwrap();
        assert_eq!(already, NICE_MAX, "15 + 4, at the ceiling");
    }

    /// The default policy is the one a host gets without saying anything, and it defers.
    #[test]
    fn the_default_policy_defers_the_build() {
        let _serial = serial();
        set_policy(&crate::config::Build::default());
        assert_eq!(NICE.load(Ordering::Relaxed), i32::from(DEFAULT_NICE));
        assert_eq!(
            IOPRIO.load(Ordering::Relaxed),
            (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | IOPRIO_BE_LOWEST
        );
    }
}
