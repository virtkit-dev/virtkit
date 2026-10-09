//! Remove a build's scratch dirs when SIGTERM or SIGINT ends the process. Their default action
//! ends it on the spot, running no destructor, so a build cancelled with its job would leave
//! its scratch for a sweep to find. Best-effort: SIGKILL cannot be caught, and a process that
//! handles either signal itself is left to do so — the handler goes in only over the default
//! action, for as long as a dir is registered.
//!
//! The handler only writes the signal's number to a pipe. A thread of its own reads it, resets
//! the handlers it installed to the default action, so a second signal ends the process at
//! once, removes the registered dirs through descriptors (`vk_fs::remove_tree_in`), and then
//! lets the signal end the process as it would have. A dir is registered by the descriptor its
//! owner holds, and only that inode is removed, while its name still leads to it.
//!
//! A signal counts only when delivered to this handler itself, which the handler tells at
//! delivery; one delivered then ends the process even if the last dir has been unregistered
//! since. A handler installed later, such as tokio's, may call the one it replaced, this one,
//! on every signal; that signal is its own to act on, and this module leaves it be. A process
//! forked from this one and signalled before it execs dies of the signal, as it would have.

use std::ffi::OsString;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

/// The signals a registration covers.
const SIGNALS: [libc::c_int; 2] = [libc::SIGTERM, libc::SIGINT];

/// A registered dir: the descriptors it is removed through, and its path for messages.
struct Target {
    parent: OwnedFd,
    name: OsString,
    dir: OwnedFd,
    path: PathBuf,
}

/// Open the parent of `dir` and clone `opened`; return `None` if either fails.
fn open_target(dir: &Path, opened: BorrowedFd<'_>) -> Option<Target> {
    let (parent, name) = (dir.parent()?, dir.file_name()?);
    Some(Target {
        parent: vk_fs::open_dir(parent).ok()?,
        name: name.to_os_string(),
        dir: opened.try_clone_to_owned().ok()?,
        path: dir.to_path_buf(),
    })
}

struct State {
    /// The registered dirs, by registration.
    dirs: Vec<(u64, Target)>,
    /// The signals whose handler this installed, to restore once no dir is registered.
    installed: Vec<libc::c_int>,
}

static STATE: Mutex<State> = Mutex::new(State {
    dirs: Vec::new(),
    installed: Vec::new(),
});

static NEXT: AtomicU64 = AtomicU64::new(0);

/// The pipe's write end, for the handler; -1 until the remover runs.
static WAKE: AtomicI32 = AtomicI32::new(-1);

/// The process the remover runs in, the only one the handler wakes it for.
static OWNER: AtomicI32 = AtomicI32::new(0);

/// Set once the remover has stopped reading, after which nothing is registered any more.
static GONE: AtomicBool = AtomicBool::new(false);

/// Keeps a dir registered for removal on SIGTERM or SIGINT; dropping it unregisters it.
pub(crate) struct Registration(u64);

/// Remove `dir`, which the caller holds open as `opened`, if SIGTERM or SIGINT ends the process
/// before the returned registration drops. Register a dir only while this process owns it
/// outright. A dir whose parent cannot be opened now is not registered.
pub(crate) fn remove_on_signal(dir: &Path, opened: BorrowedFd<'_>) -> Registration {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let Some(target) = open_target(dir, opened) else {
        return Registration(id);
    };
    let mut state = lock();
    if state.dirs.is_empty() {
        install(&mut state);
    }
    if !state.installed.is_empty() {
        state.dirs.push((id, target));
    }
    Registration(id)
}

impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = lock();
        state.dirs.retain(|(id, _)| *id != self.0);
        if state.dirs.is_empty() {
            uninstall(&mut state);
        }
    }
}

fn lock() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// This module's handler, as `sigaction` reports it.
fn ours() -> libc::sighandler_t {
    on_signal as *const () as libc::sighandler_t
}

/// Put the handler in for each signal still at its default action.
fn install(state: &mut State) {
    if !remover_started() {
        return;
    }
    for signal in SIGNALS {
        if action(signal) != Some(libc::SIG_DFL) {
            continue;
        }
        if set_action(signal, ours()) {
            state.installed.push(signal);
        }
    }
}

/// Restore the default action wherever the handler is still the one installed.
fn uninstall(state: &mut State) {
    for signal in state.installed.drain(..) {
        if action(signal) == Some(ours()) {
            set_action(signal, libc::SIG_DFL);
        }
    }
}

/// The current action for `signal`.
fn action(signal: libc::c_int) -> Option<libc::sighandler_t> {
    // SAFETY: `sigaction` is a plain C struct for which all-zero is valid, and the call only
    // writes it.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        (libc::sigaction(signal, std::ptr::null(), &mut old) == 0).then_some(old.sa_sigaction)
    }
}

/// Set the action for `signal` to `handler`; whether it took. Async-signal-safe.
fn set_action(signal: libc::c_int, handler: libc::sighandler_t) -> bool {
    // SAFETY: as in `action`; `SA_RESTART` keeps the interrupted thread's syscalls going, the
    // handler being one `write`.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(signal, &sa, std::ptr::null_mut()) == 0
    }
}

/// Marks a wakeup for a signal delivered to the handler itself, not passed on by another.
const DIRECT: u8 = 0x80;

/// Async-signal-safe: atomic loads, `getpid`, `sigaction` and a `write` — or, in a forked
/// child, `raise` — with `errno` kept.
extern "C" fn on_signal(signal: libc::c_int) {
    // SAFETY: `errno` is this thread's own, and every call is async-signal-safe. A full pipe
    // only drops the wakeup, which a second signal repeats. In a child, the signal raised is
    // blocked until this handler returns, and then ends the child under the default action.
    unsafe {
        let errno = *libc::__errno_location();
        if libc::getpid() != OWNER.load(Ordering::Acquire) {
            set_action(signal, libc::SIG_DFL);
            libc::raise(signal);
        } else {
            // Delivered to this handler itself, or passed on by one installed over it: decided
            // here, at delivery, as the remover cannot tell later. The default action means the
            // handler was taken out after this delivery began.
            let direct = action(signal).is_some_and(|a| a == ours() || a == libc::SIG_DFL);
            let byte = signal as u8 | if direct { DIRECT } else { 0 };
            libc::write(
                WAKE.load(Ordering::Acquire),
                (&raw const byte).cast::<libc::c_void>(),
                1,
            );
        }
        *libc::__errno_location() = errno;
    }
}

/// Start the remover thread and its pipe once; whether it runs.
fn remover_started() -> bool {
    static STARTED: OnceLock<bool> = OnceLock::new();
    let started = *STARTED.get_or_init(|| {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors `pipe2` returns.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return false;
        }
        // SAFETY: two fresh descriptors this call owns.
        let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
        // Never block the handler.
        // SAFETY: `fcntl` on a descriptor this call owns.
        unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) };
        let spawned = std::thread::Builder::new()
            .name("vk-termclean".into())
            .spawn(move || remover(read));
        if spawned.is_err() {
            return false;
        }
        // SAFETY: getpid(2) has no preconditions and cannot fail.
        OWNER.store(unsafe { libc::getpid() }, Ordering::Relaxed);
        // Keep the write end for the process lifetime: the handler may write at any time.
        WAKE.store(
            std::os::fd::IntoRawFd::into_raw_fd(write),
            Ordering::Release,
        );
        true
    });
    started && !GONE.load(Ordering::Acquire)
}

/// Wait for a signal's number on `read`; on one delivered to the handler itself, remove the
/// dirs still registered and end the process with that signal.
fn remover(read: OwnedFd) {
    loop {
        let mut byte = 0u8;
        // SAFETY: `read` is open and `byte` has room for the one byte asked for.
        let n = unsafe { libc::read(read.as_raw_fd(), (&raw mut byte).cast::<libc::c_void>(), 1) };
        if n != 1 {
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // Nothing can be read any more: hand the signals back to their default action and
            // take no registration from now on. The read end stays open, so the handler, should
            // another one still chain to it, fills the pipe rather than raise SIGPIPE.
            let mut state = lock();
            GONE.store(true, Ordering::Release);
            uninstall(&mut state);
            state.dirs.clear();
            std::mem::forget(read);
            return;
        }
        if byte & DIRECT == 0 {
            continue; // passed on by a handler installed over this one: that one's to act on
        }
        let signal = libc::c_int::from(byte & !DIRECT);
        // Held to the end, so no registration comes or goes meanwhile. The signal ends the
        // process even when the last registration went since it arrived.
        let mut state = lock();
        uninstall(&mut state);
        // A panic in the removal still ends the process with the signal below.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            for (_, target) in &state.dirs {
                say(&format!("interrupted; removing {}", target.path.display()));
                remove(target);
            }
        }));
        die(signal);
    }
}

/// End the process with `signal`, as its default action would have.
fn die(signal: libc::c_int) -> ! {
    // SAFETY: restoring the default action, unblocking the signal for this thread and raising
    // it end the process as the signal would have; `_exit` is the fallback should it not.
    unsafe {
        set_action(signal, libc::SIG_DFL);
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signal);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut());
        libc::raise(signal);
        libc::_exit(128 + signal);
    }
}

/// Write `virtkit: <line>` to stderr with one `write(2)`, whatever comes of it: `eprintln!`
/// panics when stderr is gone, as a cancelled job's log pipe may be, and could wait on a lock
/// another thread holds while blocked writing.
fn say(line: &str) {
    let line = format!("virtkit: {line}\n");
    // SAFETY: writing a buffer this call owns to a raw fd.
    unsafe { libc::write(libc::STDERR_FILENO, line.as_ptr().cast(), line.len()) };
}

/// The `errno` an error from `vk_fs` carries, if any.
fn errno(e: &anyhow::Error) -> Option<i32> {
    e.chain()
        .find_map(|c| c.downcast_ref::<std::io::Error>()?.raw_os_error())
}

/// Remove `target` only while its name still identifies it. Retry if the build adds or
/// removes entries during cleanup. Report failures and retained entries for the next sweep.
fn remove(target: &Target) {
    let shown = target.path.display();
    for attempt in 1..=3 {
        let e = match vk_fs::remove_tree_in(target.parent.as_fd(), &target.name, target.dir.as_fd())
        {
            Ok(done) => {
                if !done.skipped.is_empty() {
                    let kept: Vec<_> = done
                        .skipped
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect();
                    say(&format!("left in place under {shown}: {}", kept.join(", ")));
                }
                return;
            }
            Err(e) => e,
        };
        let changed = match errno(&e) {
            Some(libc::ENOTEMPTY) => true,
            // Gone itself, renamed away or removed: nothing of it left here.
            Some(libc::ENOENT) if vk_fs::entry_in(target.parent.as_fd(), &target.name).is_err() => {
                return;
            }
            Some(libc::ENOENT) => true,
            _ => false,
        };
        if !changed || attempt == 3 {
            say(&format!("not removing {shown}: {e:#}"));
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::sync::atomic::AtomicUsize;
    use std::time::{Duration, Instant};

    use super::*;

    /// What the stand-in registers, the signal it is sent, and what it does around registering:
    /// `drop` the registration, `swap` the dir for another under its name, put in a handler of
    /// its `own` first, `chain` one over this module's that calls it, or none of these; `late`
    /// signals itself and lets the build end before the remover can act.
    const DIR_VAR: &str = "VK_TERMCLEAN_TEST_DIR";
    const SIGNAL_VAR: &str = "VK_TERMCLEAN_TEST_SIGNAL";
    const MODE_VAR: &str = "VK_TERMCLEAN_TEST_MODE";

    /// How a stand-in that handles the signal itself exits.
    const HANDLED: i32 = 42;

    extern "C" fn exit_handled(_: libc::c_int) {
        // SAFETY: `_exit` is async-signal-safe.
        unsafe { libc::_exit(HANDLED) };
    }

    /// The action [`chained`] replaced, and whether it ran.
    static REPLACED: AtomicUsize = AtomicUsize::new(0);
    static CHAINED: AtomicBool = AtomicBool::new(false);

    /// A handler as tokio's: it calls the one it replaced, and leaves the rest to the process.
    extern "C" fn chained(signal: libc::c_int) {
        let replaced = REPLACED.load(Ordering::Acquire);
        if replaced != libc::SIG_DFL && replaced != libc::SIG_IGN {
            // SAFETY: a handler `sigaction` reported, of the type it was installed with.
            let replaced: extern "C" fn(libc::c_int) = unsafe { std::mem::transmute(replaced) };
            replaced(signal);
        }
        CHAINED.store(true, Ordering::Release);
    }

    /// A process that registers a dir, says it is ready, and waits to be signalled.
    #[test]
    #[ignore = "a stand-in process for the termclean tests, run by them"]
    fn stand_in() {
        let Some(dir) = std::env::var_os(DIR_VAR).map(PathBuf::from) else {
            return;
        };
        let signal: libc::c_int = std::env::var(SIGNAL_VAR).unwrap().parse().unwrap();
        let mode = std::env::var(MODE_VAR).unwrap_or_default();
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("sub/data"), b"x").unwrap();
        if mode == "own" {
            set_action(signal, exit_handled as *const () as libc::sighandler_t);
        }
        let opened = vk_fs::open_dir(&dir).unwrap();
        let registration = remove_on_signal(&dir, opened.as_fd());
        match mode.as_str() {
            "drop" => drop(registration),
            "swap" => {
                std::mem::forget(registration);
                std::fs::rename(&dir, dir.with_extension("promoted")).unwrap();
                std::fs::create_dir(&dir).unwrap();
                std::fs::write(dir.join("new"), b"x").unwrap();
            }
            "own" => {
                drop(registration);
                if action(signal) != Some(exit_handled as *const () as libc::sighandler_t) {
                    // SAFETY: plain `_exit`.
                    unsafe { libc::_exit(1) };
                }
            }
            "late" => {
                std::mem::forget(registration);
                // The remover waits on the state while the build ends: nothing is registered
                // and the default action is back by the time it looks.
                let mut state = lock();
                // SAFETY: raise(3) on this thread; the handler only writes to the pipe.
                unsafe { libc::raise(signal) };
                state.dirs.clear();
                uninstall(&mut state);
                drop(state);
                std::thread::sleep(Duration::from_secs(5));
                // SAFETY: plain `_exit`: the signal was lost.
                unsafe { libc::_exit(1) };
            }
            "chain" => {
                std::mem::forget(registration);
                REPLACED.store(action(signal).unwrap(), Ordering::Release);
                set_action(signal, chained as *const () as libc::sighandler_t);
            }
            _ => std::mem::forget(registration),
        }
        std::fs::write(dir.with_extension("ready"), b"").unwrap();
        let until = Instant::now() + Duration::from_secs(60);
        while Instant::now() < until {
            if CHAINED.load(Ordering::Acquire) {
                // Long enough for the remover to act, were it to.
                std::thread::sleep(Duration::from_millis(500));
                // SAFETY: plain `_exit`.
                unsafe { libc::_exit(HANDLED) };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Configure the stand-in with `dir`, `mode`, and `signal`.
    fn stand_in_cmd(dir: &Path, mode: &str, signal: libc::c_int) -> std::process::Command {
        let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
        cmd.args(["--ignored", "--exact", "termclean::tests::stand_in"])
            .env(DIR_VAR, dir)
            .env(SIGNAL_VAR, signal.to_string())
            .env(MODE_VAR, mode)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd
    }

    /// Run the stand-in on `dir` in `mode`, send it `signal` once ready, and return how it
    /// ended.
    fn signalled(dir: &Path, mode: &str, signal: libc::c_int) -> std::process::ExitStatus {
        let mut child = stand_in_cmd(dir, mode, signal).spawn().unwrap();
        let ready = dir.with_extension("ready");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "the stand-in never got ready");
            std::thread::sleep(Duration::from_millis(20));
        }
        // SAFETY: plain kill(2) on our own child, not yet reaped.
        unsafe { libc::kill(i32::try_from(child.id()).unwrap(), signal) };
        child.wait().unwrap()
    }

    #[test]
    fn a_registered_dir_goes_with_a_sigterm_and_the_process_still_dies_of_it() {
        let root = std::env::temp_dir().join(format!("vk-termclean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let dir = root.join("held");
        let status = signalled(&dir, "", libc::SIGTERM);
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
        assert!(!dir.exists(), "a registered dir must be removed");

        // Unregistered, the default action is back: the process dies, the dir stays.
        let dir = root.join("dropped");
        let status = signalled(&dir, "drop", libc::SIGTERM);
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
        assert!(
            dir.join("sub/data").is_file(),
            "an unregistered dir must stay"
        );

        // Renamed away (promoted), the dir registered is no longer at its name: neither it nor
        // what took the name goes.
        let dir = root.join("swapped");
        let status = signalled(&dir, "swap", libc::SIGTERM);
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
        assert!(dir.with_extension("promoted").join("sub/data").is_file());
        assert!(dir.join("new").is_file());

        std::fs::remove_dir_all(&root).unwrap();
    }

    // A process that handles the signal itself keeps it: its handler stays in place across a
    // registration, and one chained over this module's, calling it, decides alone.
    #[test]
    fn a_signal_the_process_handles_itself_is_left_to_it() {
        let root = std::env::temp_dir().join(format!("vk-termclean-own-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();

        let dir = root.join("own");
        let status = signalled(&dir, "own", libc::SIGINT);
        assert_eq!(status.code(), Some(HANDLED), "{status:?}");
        assert!(dir.join("sub/data").is_file());

        let dir = root.join("chain");
        let status = signalled(&dir, "chain", libc::SIGTERM);
        assert_eq!(status.code(), Some(HANDLED), "{status:?}");
        assert!(dir.join("sub/data").is_file());

        std::fs::remove_dir_all(&root).unwrap();
    }

    // A delivered signal still ends the process if the build unregisters its directory
    // before the remover handles it.
    #[test]
    fn a_signal_outlives_the_registration_it_arrived_under() {
        let root = std::env::temp_dir().join(format!("vk-termclean-late-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dir = root.join("late");
        let status = stand_in_cmd(&dir, "late", libc::SIGTERM).status().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGTERM), "{status:?}");
        assert!(
            dir.join("sub/data").is_file(),
            "nothing was registered any more"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }
}
