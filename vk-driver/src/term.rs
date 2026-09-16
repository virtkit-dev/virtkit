//! Shared terminal support for full-screen panels: terminal detection, the alternate
//! screen, raw-mode restoration on signals, key decoding and two drawing helpers.
//!
//! The terminal is left exactly as it was found. The alternate screen is held by a guard that
//! restores on drop, so a panic or an error path cannot leave a shell without its cursor — and
//! because a signal is neither, the terminating ones are caught long enough to restore it and
//! then re-raised. What that handler puts back is settled before it is installed and read
//! from a plain static: a handler runs between two instructions of whatever it interrupted,
//! so everything it touches has to be safe to touch there, locks included.
//!
//! The keys are decoded here rather than by a library, because an arrow key is several bytes
//! and the terminal gives no promise about delivering them in one read: a decoder that gives
//! up on a half-read sequence loses the key, which under a multiplexer is most of them.
//! [`Keys`] holds an unfinished sequence until it either completes or a moment passes with
//! nothing following — the same rule that tells a bare Escape from the start of an arrow — and
//! being a function over bytes it is tested without a terminal at all.

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};

/// Whether this terminal can carry a panel at all — for a caller that has something else
/// to do when it cannot (a live attach records headless), rather than a flag to refuse. The
/// same conditions [`crate::atop_view::view`] refuses on, so the two cannot disagree.
pub(crate) fn can_draw() -> bool {
    std::io::stdout().is_terminal()
        && std::io::stdin().is_terminal()
        && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
}

/// Terminal settings captured before raw mode. The handler reads this cell without a lock:
/// a nested signal could deadlock on a lock held by the interrupted handler, leaving the
/// terminal in raw mode. All settings must be initialized before the handler can read them.
struct OnSignal(std::cell::UnsafeCell<std::mem::MaybeUninit<libc::termios>>);

// SAFETY: written once by `catch_terminating_signals`, before the handlers that read it are
// installed, and not touched again. `ON_SIGNAL_SET` is what publishes that write to them.
unsafe impl Sync for OnSignal {}

static ON_SIGNAL: OnSignal = OnSignal(std::cell::UnsafeCell::new(std::mem::MaybeUninit::uninit()));

/// Publishes initialized settings to the signal handler.
static ON_SIGNAL_SET: AtomicBool = AtomicBool::new(false);

/// This terminal's settings as they stand, or `None` where stdin is not one.
pub(crate) fn current_termios(fd: libc::c_int) -> Option<libc::termios> {
    // SAFETY: tcgetattr only fills the termios it is given.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    match unsafe { libc::tcgetattr(fd, &mut t) } {
        0 => Some(t),
        _ => None,
    }
}

/// Restore the terminal and re-raise, so the process still dies of what it was sent and the
/// shell it dies in is usable. `tcsetattr`, `write`, `signal` and `raise` are all this runs,
/// and all four are async-signal-safe — which matters because these signals are not blocked
/// for each other: a SIGTERM and a SIGQUIT in quick succession run this twice, nested.
extern "C" fn restore_and_reraise(sig: libc::c_int) {
    if ON_SIGNAL_SET.load(Ordering::Acquire) {
        // SAFETY: a termios read from this same fd before raw mode was entered, written
        // before this handler was installed and never written again.
        unsafe {
            libc::tcsetattr(
                libc::STDIN_FILENO,
                libc::TCSANOW,
                (*ON_SIGNAL.0.get()).as_ptr(),
            )
        };
    }
    const RESTORE: &[u8] = b"\x1b[?25h\x1b[?1049l";
    // SAFETY: writing a fixed buffer to a raw fd.
    unsafe {
        libc::write(libc::STDOUT_FILENO, RESTORE.as_ptr().cast(), RESTORE.len());
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Catch the signals that would otherwise end a panel without unwinding. SIGINT is not among
/// them: raw mode clears ISIG, so Ctrl-C arrives as a byte and leaves through the loop.
///
/// Called once per process, by the panel about to take the terminal.
pub(crate) fn catch_terminating_signals(saved: libc::termios) {
    // SAFETY: the settings are written before the handlers that read them exist, so there is
    // no reader to race with; the store below is what makes the write visible to them.
    unsafe { (*ON_SIGNAL.0.get()).write(saved) };
    ON_SIGNAL_SET.store(true, Ordering::Release);
    for sig in [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        // SAFETY: the handler only calls async-signal-safe functions.
        unsafe {
            libc::signal(sig, restore_and_reraise as *const () as libc::sighandler_t);
        }
    }
}

/// A key a panel understands, whatever the terminal spelled it as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Press {
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    PageUp,
    PageDown,
    Enter,
    Tab,
    /// Shift-Tab, which terminals spell `ESC [ Z` rather than as a byte of its own.
    BackTab,
    Backspace,
    Escape,
    /// Ctrl-C, which raw mode delivers as a byte rather than as a signal.
    Interrupt,
    Char(char),
}

/// How long an unfinished escape sequence waits for the rest of itself. Long enough for a
/// multiplexer to pass the bytes through, short enough that a bare Escape still feels instant.
const ESC_WAIT: Duration = Duration::from_millis(60);

/// The bytes of a terminal turned into presses. An escape sequence arrives in pieces, so a
/// sequence in progress is held until it completes or [`Keys::flush`] gives up on it.
#[derive(Default)]
pub(crate) struct Keys {
    /// The escape sequence read so far, empty when no sequence is in progress.
    pending: Vec<u8>,
}

impl Keys {
    /// The press this byte completes, if any.
    pub(crate) fn feed(&mut self, byte: u8) -> Option<Press> {
        if self.pending.is_empty() {
            return match byte {
                0x1b => {
                    self.pending.push(byte);
                    None
                }
                0x03 => Some(Press::Interrupt),
                b'\r' | b'\n' => Some(Press::Enter),
                b'\t' => Some(Press::Tab),
                0x7f | 0x08 => Some(Press::Backspace),
                b if b.is_ascii_graphic() || b == b' ' => Some(Press::Char(b as char)),
                _ => None,
            };
        }
        // Escape opens a sequence; `[` and `O` are the two introducers a terminal uses for
        // the movement keys, and anything else after Escape is a key there is none for.
        if self.pending.as_slice() == [0x1b] {
            // A second Escape is an Escape, not the start of a sequence: a reader pressing it twice
            // to leave gets an answer to the first press rather than to the third.
            if byte == 0x1b {
                return Some(Press::Escape);
            }
            if byte != b'[' && byte != b'O' {
                self.pending.clear();
                return None;
            }
            self.pending.push(byte);
            return None;
        }
        self.pending.push(byte);
        // A sequence runs until its final byte; the parameters before it vary by terminal (a
        // modifier makes `ESC [ D` arrive as `ESC [ 1 ; 5 D`), so it is the end that is read.
        // Consuming to the end is what keeps an unknown sequence's own letters from being
        // taken for commands.
        let final_byte = (0x40..=0x7e).contains(&byte);
        if !final_byte {
            if self.pending.len() > 16 {
                self.pending.clear(); // not a sequence any terminal sends
            }
            return None;
        }
        let sequence = std::mem::take(&mut self.pending);
        match (sequence.as_slice(), byte) {
            (_, b'D') => Some(Press::Left),
            (_, b'C') => Some(Press::Right),
            (_, b'A') => Some(Press::Up),
            (_, b'B') => Some(Press::Down),
            (_, b'H') => Some(Press::Home),
            (_, b'F') => Some(Press::End),
            (_, b'Z') => Some(Press::BackTab),
            // the numbered forms tmux and rxvt send for the same two jumps
            ([0x1b, b'[', b'1' | b'7', b'~'], _) => Some(Press::Home),
            ([0x1b, b'[', b'4' | b'8', b'~'], _) => Some(Press::End),
            ([0x1b, b'[', b'5', b'~'], _) => Some(Press::PageUp),
            ([0x1b, b'[', b'6', b'~'], _) => Some(Press::PageDown),
            _ => None,
        }
    }

    /// The press an unfinished sequence turns out to have been: Escape typed on its own.
    pub(crate) fn flush(&mut self) -> Option<Press> {
        match std::mem::take(&mut self.pending).as_slice() {
            [0x1b] => Some(Press::Escape),
            _ => None,
        }
    }
}

/// Poll interval for checking the stop flag, short enough to avoid losing the first keys
/// when handing the terminal to a child.
const STOP_TICK: Duration = Duration::from_millis(100);

/// Presses from a thread of its own: reading a byte blocks, and a panel's own work must not
/// wait for it, so a channel joins the two. The thread ends when stdin does.
pub(crate) fn key_thread() -> Receiver<Press> {
    key_thread_until(Arc::new(AtomicBool::new(false))).0
}

/// Stop the reader when `stop` is raised. Return its thread handle with the channel so a
/// caller handing stdin to a child can wait for the read to end; concurrent readers would
/// steal each other's keystrokes.
pub(crate) fn key_thread_until(stop: Arc<AtomicBool>) -> (Receiver<Press>, JoinHandle<()>) {
    let (tx, rx) = channel();
    let reading = std::thread::spawn(move || {
        let mut keys = Keys::default();
        let mut byte = [0u8; 1];
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            // A sequence in progress waits only a moment for the rest of itself; anything else
            // waits until there is a key or the flag is worth another look.
            let timeout = match keys.pending.is_empty() {
                true => STOP_TICK.as_millis() as libc::c_int,
                false => ESC_WAIT.as_millis() as libc::c_int,
            };
            let mut fds = libc::pollfd {
                fd: libc::STDIN_FILENO,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one caller-owned pollfd, and the count matches.
            let ready = unsafe { libc::poll(&mut fds, 1, timeout) };
            if ready == 0 {
                // Nothing followed: an escape sequence that never completed was a bare Escape.
                if let Some(press) = keys.flush()
                    && tx.send(press).is_err()
                {
                    return;
                }
                continue;
            }
            if ready < 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return;
            }
            // SAFETY: a one-byte buffer this thread owns.
            let n = unsafe { libc::read(libc::STDIN_FILENO, byte.as_mut_ptr().cast(), 1) };
            if n <= 0 {
                return; // stdin closed: nobody is left to drive the panel
            }
            if let Some(press) = keys.feed(byte[0])
                && tx.send(press).is_err()
            {
                return;
            }
        }
    });
    (rx, reading)
}

/// The alternate screen: a panel draws on a screen of its own, and the shell's scrollback
/// comes back untouched when it leaves.
pub(crate) struct AltScreen;

impl AltScreen {
    pub(crate) fn enter() -> Result<AltScreen> {
        let mut out = std::io::stdout();
        // hide the cursor too: it would otherwise sit wherever the last line ended
        out.write_all(b"\x1b[?1049h\x1b[?25l")
            .context("switching to the alternate screen")?;
        out.flush().context("switching to the alternate screen")?;
        Ok(AltScreen)
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
    }
}

/// A proportional bar `width` cells wide. Full blocks with a partial one at the edge, so a
/// short bar still shows the difference between nothing and a little.
pub(crate) fn bar(share: f64, width: usize) -> String {
    const PARTIAL: [char; 8] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
    let share = share.clamp(0.0, 1.0);
    let eighths = (share * (width * 8) as f64).round() as usize;
    let mut out = String::from("[");
    let (full, rest) = (eighths / 8, eighths % 8);
    for _ in 0..full.min(width) {
        out.push('█');
    }
    let mut drawn = full.min(width);
    if rest > 0 && drawn < width {
        out.push(PARTIAL[rest.saturating_sub(1)]);
        drawn += 1;
    }
    for _ in drawn..width {
        out.push(' ');
    }
    out.push(']');
    out
}

/// A line cut to the width of the screen, counted in characters — a bar and a command line
/// are both full of multi-byte ones.
pub(crate) fn clip(line: &str, cols: usize) -> String {
    match line.chars().count() > cols {
        true => line.chars().take(cols).collect(),
        false => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An arrow key is several bytes and a terminal gives no promise about delivering them in
    /// one read: every form of them decodes, whether the bytes arrive together or one at a
    /// time, and a bare Escape is told from the start of a sequence by nothing following it.
    #[test]
    fn the_keys_decode_however_their_bytes_arrive() {
        let feed = |bytes: &[u8]| {
            let mut keys = Keys::default();
            let mut out = Vec::new();
            for b in bytes {
                if let Some(press) = keys.feed(*b) {
                    out.push(press);
                }
            }
            (out, keys)
        };
        // xterm's arrows and jumps, and the numbered forms tmux and rxvt send
        assert_eq!(feed(b"\x1b[D").0, vec![Press::Left]);
        assert_eq!(feed(b"\x1b[C").0, vec![Press::Right]);
        assert_eq!(feed(b"\x1b[A").0, vec![Press::Up]);
        assert_eq!(feed(b"\x1b[B").0, vec![Press::Down]);
        assert_eq!(feed(b"\x1b[H").0, vec![Press::Home]);
        assert_eq!(feed(b"\x1b[F").0, vec![Press::End]);
        assert_eq!(feed(b"\x1bOD").0, vec![Press::Left], "application mode");
        assert_eq!(feed(b"\x1bOA").0, vec![Press::Up], "application mode");
        assert_eq!(feed(b"\x1bOB").0, vec![Press::Down], "application mode");
        assert_eq!(feed(b"\x1b[1~").0, vec![Press::Home]);
        assert_eq!(feed(b"\x1b[4~").0, vec![Press::End]);
        assert_eq!(feed(b"\x1b[7~").0, vec![Press::Home]);
        assert_eq!(feed(b"\x1b[8~").0, vec![Press::End]);
        // the keys a list is walked with, and the two spellings of a tab
        assert_eq!(feed(b"\x1b[5~").0, vec![Press::PageUp]);
        assert_eq!(feed(b"\x1b[6~").0, vec![Press::PageDown]);
        assert_eq!(feed(b"\t").0, vec![Press::Tab]);
        assert_eq!(feed(b"\x1b[Z").0, vec![Press::BackTab]);
        // several keys in one read, and the letters and controls a panel uses
        assert_eq!(
            feed(b"\x1b[Dq").0,
            vec![Press::Left, Press::Char('q')],
            "a sequence does not swallow the key after it"
        );
        assert_eq!(feed(b"cmd/a").0.len(), 5);
        assert_eq!(feed(b"\r").0, vec![Press::Enter]);
        assert_eq!(feed(b"\n").0, vec![Press::Enter]);
        assert_eq!(feed(&[0x7f]).0, vec![Press::Backspace]);
        assert_eq!(feed(&[0x03]).0, vec![Press::Interrupt]);
        // A sequence in progress yields nothing until it completes...
        let (presses, mut keys) = feed(b"\x1b[");
        assert!(presses.is_empty());
        assert_eq!(keys.feed(b'D'), Some(Press::Left));
        let (presses, mut split) = feed(b"\x1b[6");
        assert!(presses.is_empty());
        assert_eq!(split.feed(b'~'), Some(Press::PageDown));
        // ...and an escape that never completes was a bare Escape.
        let (_, mut alone) = feed(b"\x1b");
        assert_eq!(alone.flush(), Some(Press::Escape));
        assert_eq!(alone.flush(), None, "and only once");
        // A sequence there is no key for is dropped whole, letters included.
        let (presses, mut unknown) = feed(b"\x1b[200~");
        assert!(presses.is_empty(), "{presses:?}");
        assert_eq!(unknown.flush(), None);
    }

    /// The bars are a panel's only picture, and a reader compares them against each other:
    /// nothing is empty, everything is full, and the width is exactly what was asked for.
    #[test]
    fn a_bar_fills_from_nothing_to_full() {
        assert_eq!(bar(0.0, 4), "[    ]");
        assert_eq!(bar(1.0, 4), "[████]");
        assert_eq!(bar(0.5, 4), "[██  ]");
        // Out-of-range shares (a counter that moved backwards) are clamped, not panicked on.
        assert_eq!(bar(-1.0, 4), "[    ]");
        assert_eq!(bar(2.0, 4), "[████]");
        // A sliver still shows: the smallest partial block, not an empty bar.
        assert!(bar(0.02, 4).contains('▏'));
        for width in [1, 8, 12] {
            assert_eq!(bar(0.37, width).chars().count(), width + 2);
        }
    }
}
