//! Walking a recorded job sample by sample: the panel `vk atop --view` draws, and
//! `--follow` keeps up to date while the job is still running.
//!
//! The summary answers what a job did; this answers *when*. One sample fills the screen —
//! the guest's processors, memory, pressure, disks and network, then its processes ordered by
//! what they were using — and the arrow keys walk the recording. `--follow` polls the log for
//! samples the guest has since committed and, while the view sits on the last one, moves with
//! them; stepping back pins it where it is until `End` asks for the live tail again.
//!
//! The terminal is left exactly as it was found. Raw mode and the alternate screen are both
//! held by guards that restore on drop, so a panic or an error path cannot leave a shell
//! without its echo — and because a signal is neither, the terminating ones are caught long
//! enough to restore it and then re-raised: `--follow` is precisely the invocation somebody
//! `kill`s. Each repaint is one buffer written in one call, with the size read fresh
//! — a window resized between frames is simply drawn at its new size, which needs no signal
//! handler. Keys are read on a thread of their own: the read blocks, and the poll for new
//! samples must not wait for it.
//!
//! The keys are decoded here rather than by a library, because an arrow key is several bytes
//! and the terminal gives no promise about delivering them in one read: a decoder that gives
//! up on a half-read sequence loses the key, which under a multiplexer is most of them.
//! [`Keys`] holds an unfinished sequence until it either completes or a moment passes with
//! nothing following — the same rule that tells a bare Escape from the start of an arrow — and
//! being a function over bytes it is tested without a terminal at all.
//!
//! The panel is drawn in no colour: what it has to say it says in figures, bars and the marker
//! on the sorted column, so it reads the same on a terminal that has colour and one that has
//! not, and `NO_COLOR` needs no branch. A terminal it cannot address (`TERM=dumb`, or a stdout
//! that is not a terminal at all) is refused with a pointer at `--summary`, which answers over
//! the same log in text.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::atop_report::{Totals, plain, secs_of};
use crate::atoplog::{SECTOR, Sample};
use crate::usage::{fmt_bytes, fmt_cpu};

/// How often `--follow` looks for samples the guest has committed since the last look. Well
/// under the shortest interval a job can record at, so a new sample shows up as it lands.
const POLL: Duration = Duration::from_millis(400);

/// Whether this terminal can carry the panel at all — for a caller that has something else
/// to do when it cannot (a live attach records headless), rather than a flag to refuse. The
/// same conditions [`view`] refuses on, so the two cannot disagree.
pub fn can_draw() -> bool {
    std::io::stdout().is_terminal()
        && std::io::stdin().is_terminal()
        && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
}

/// Draw `path` as a panel and walk it. `follow` keeps reading the log while the job runs.
pub fn view(path: &Path, follow: bool) -> Result<()> {
    // A panel is a terminal program; without a terminal there is a report that is not.
    // Both ends: the panel is drawn on stdout and raw mode is set on stdin, so either one
    // missing is a terminal this cannot drive.
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        bail!(
            "--view needs a terminal on both stdin and stdout — `vk atop {} --summary` \
             accounts the same log as text",
            path.display()
        );
    }
    if std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false) {
        bail!(
            "--view needs a terminal that can address its own screen (TERM=dumb) — \
             `--summary` accounts the same log as text"
        );
    }
    let mut tail = Tail::open(path)?;
    let samples = tail.read()?;
    if samples.is_empty() && !follow {
        bail!(
            "{} holds no complete sample yet (a job records its first one an interval in)",
            path.display()
        );
    }
    let mut state = View::new(path, samples, follow);

    // Both guards restore on drop, and the screen is left as it was found whichever way this
    // returns — including a panic, which unwinds through them.
    let saved = current_termios(libc::STDIN_FILENO);
    let _raw = vk_core::pty::RawModeGuard::enable(libc::STDIN_FILENO)
        .context("putting the terminal in raw mode")?;
    let _screen = AltScreen::enter()?;
    // A signal that ends the process unwinds nothing, so the guards above never run: without
    // this a SIGTERM or a closed terminal leaves the operator's shell in raw mode, with no
    // cursor and the alternate screen still on.
    if let Some(saved) = saved {
        catch_terminating_signals(saved);
    }
    let keys = key_thread();

    loop {
        paint(&state)?;
        match keys.recv_timeout(POLL) {
            Ok(key) => {
                if state.key(key) == Flow::Quit {
                    return Ok(());
                }
            }
            // Nothing typed: look for samples the guest has committed since.
            Err(RecvTimeoutError::Timeout) if state.follow => {
                let fresh = tail.read()?;
                state.extend(fresh);
            }
            Err(RecvTimeoutError::Timeout) => {}
            // The reader is gone (stdin closed): there is nobody left to drive the panel.
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
    }
}

/// The terminal settings to put back from a signal handler, and the fd to put them on. Read
/// once before raw mode is entered: a handler may touch nothing that is not already there.
static ON_SIGNAL: std::sync::Mutex<Option<libc::termios>> = std::sync::Mutex::new(None);

/// This terminal's settings as they stand, or `None` where stdin is not one.
fn current_termios(fd: libc::c_int) -> Option<libc::termios> {
    // SAFETY: tcgetattr only fills the termios it is given.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    match unsafe { libc::tcgetattr(fd, &mut t) } {
        0 => Some(t),
        _ => None,
    }
}

/// Restore the terminal and re-raise, so the process still dies of what it was sent and the
/// shell it dies in is usable. Only `tcsetattr` and `write` run here, both async-signal-safe.
extern "C" fn restore_and_reraise(sig: libc::c_int) {
    if let Ok(saved) = ON_SIGNAL.lock()
        && let Some(saved) = saved.as_ref()
    {
        // SAFETY: a termios read from this same fd before raw mode was entered.
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, saved) };
    }
    const RESTORE: &[u8] = b"\x1b[?25h\x1b[?1049l";
    // SAFETY: writing a fixed buffer to a raw fd.
    unsafe {
        libc::write(libc::STDOUT_FILENO, RESTORE.as_ptr().cast(), RESTORE.len());
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Catch the signals that would otherwise end the panel without unwinding. SIGINT is not among
/// them: raw mode clears ISIG, so Ctrl-C arrives as a byte and leaves through the loop.
fn catch_terminating_signals(saved: libc::termios) {
    if let Ok(mut slot) = ON_SIGNAL.lock() {
        *slot = Some(saved);
    }
    for sig in [libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        // SAFETY: the handler only calls async-signal-safe functions.
        unsafe {
            libc::signal(sig, restore_and_reraise as *const () as libc::sighandler_t);
        }
    }
}

/// A key the panel understands, whatever the terminal spelled it as.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Press {
    Left,
    Right,
    Home,
    End,
    Enter,
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
struct Keys {
    /// The escape sequence read so far, empty when no sequence is in progress.
    pending: Vec<u8>,
}

impl Keys {
    /// The press this byte completes, if any.
    fn feed(&mut self, byte: u8) -> Option<Press> {
        if self.pending.is_empty() {
            return match byte {
                0x1b => {
                    self.pending.push(byte);
                    None
                }
                0x03 => Some(Press::Interrupt),
                b'\r' | b'\n' => Some(Press::Enter),
                0x7f | 0x08 => Some(Press::Backspace),
                b if b.is_ascii_graphic() || b == b' ' => Some(Press::Char(b as char)),
                _ => None,
            };
        }
        // Escape opens a sequence; `[` and `O` are the two introducers a terminal uses for
        // the movement keys, and anything else after Escape is a key this panel has none for.
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
            (_, b'H') => Some(Press::Home),
            (_, b'F') => Some(Press::End),
            // the numbered forms tmux and rxvt send for the same two jumps
            ([0x1b, b'[', b'1' | b'7', b'~'], _) => Some(Press::Home),
            ([0x1b, b'[', b'4' | b'8', b'~'], _) => Some(Press::End),
            _ => None,
        }
    }

    /// The press an unfinished sequence turns out to have been: Escape typed on its own.
    fn flush(&mut self) -> Option<Press> {
        match std::mem::take(&mut self.pending).as_slice() {
            [0x1b] => Some(Press::Escape),
            _ => None,
        }
    }
}

/// Presses from a thread of its own: reading a byte blocks, and the poll for new samples must
/// not wait for it, so a channel joins the two.
fn key_thread() -> Receiver<Press> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let mut keys = Keys::default();
        let mut byte = [0u8; 1];
        loop {
            // A sequence in progress waits only a moment for the rest of itself; anything
            // else waits for as long as it takes.
            let timeout = match keys.pending.is_empty() {
                true => -1,
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
    rx
}

/// The alternate screen: the panel draws on a screen of its own, and the shell's scrollback
/// comes back untouched when it leaves.
struct AltScreen;

impl AltScreen {
    fn enter() -> Result<AltScreen> {
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

/// The log as it grows: what has been read, and where to read on from.
struct Tail {
    path: PathBuf,
    file: std::fs::File,
    /// Bytes of the file already accounted for — always the end of a complete sample, so a
    /// read resumes on a record boundary.
    offset: u64,
}

impl Tail {
    fn open(path: &Path) -> Result<Tail> {
        // The same descriptor a report reads from: no symlink followed, nothing but a regular
        // file accepted. A guest owns the directory its log is in and can swap the log for a
        // FIFO between the moment it was resolved and the moment it is opened.
        let file = crate::atoplog::open_log(path)?.0;
        Ok(Tail {
            path: path.to_path_buf(),
            file,
            offset: 0,
        })
    }

    /// Every sample committed since the last read. The tail after the last `SEP` is a sample
    /// the guest is still writing: it stays unread until its own `SEP` arrives.
    fn read(&mut self) -> Result<Vec<Sample>> {
        use std::io::{Read, Seek, SeekFrom};
        self.file
            .seek(SeekFrom::Start(self.offset))
            .with_context(|| format!("seeking in {}", self.path.display()))?;
        let mut bytes = Vec::new();
        self.file
            .read_to_end(&mut bytes)
            .with_context(|| format!("reading {}", self.path.display()))?;
        // Resume on a record boundary in the *file*. `Parsed::consumed` counts decoded text,
        // where a byte that is not text widens to three, so adding it to a file offset would
        // walk past the samples — and once past the end, every later read returns nothing and
        // the panel stops taking up samples for good.
        let end = end_of_last_sample(&bytes);
        // Lossy for the same reason the report reads lossily: a byte that is not text means a
        // damaged log, and what is still there is worth showing.
        let text = String::from_utf8_lossy(bytes.get(..end).unwrap_or_default());
        let parsed = crate::atoplog::parse(&text);
        self.offset = self.offset.saturating_add(end as u64);
        Ok(parsed.samples)
    }
}

/// One past the `SEP` closing the last complete sample, counted in bytes of `bytes`.
fn end_of_last_sample(bytes: &[u8]) -> usize {
    let (mut at, mut end) = (0usize, 0usize);
    for line in bytes.split_inclusive(|b| *b == b'\n') {
        at = at.saturating_add(line.len());
        if line.trim_ascii_end() == vk_core::atop::SEP.as_bytes() {
            end = at;
        }
    }
    end
}

/// What the process table is ordered by.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Cpu,
    Memory,
    Disk,
}

impl Sort {
    fn name(self) -> &'static str {
        match self {
            Sort::Cpu => "cpu",
            Sort::Memory => "memory",
            Sort::Disk => "disk",
        }
    }
}

/// Whether the loop carries on after a key.
#[derive(PartialEq, Eq, Debug)]
enum Flow {
    Continue,
    Quit,
}

/// Everything the panel draws from.
struct View {
    job: String,
    samples: Vec<Sample>,
    /// The sample on screen.
    cursor: usize,
    sort: Sort,
    /// Show each process's whole-job totals instead of this sample's activity.
    accumulate: bool,
    filter: String,
    /// Typing a filter: keys go into it rather than to the panel.
    editing: bool,
    /// Reading a log that is still being written.
    follow: bool,
    /// Following the end of the log. Stepping back drops it; `End` takes it up again.
    live: bool,
    /// Each process's whole-job totals, rebuilt when samples arrive rather than per frame: a
    /// long job holds a million process records and a frame is drawn on every poll.
    totals: Vec<Totals>,
}

impl View {
    fn new(path: &Path, samples: Vec<Sample>, follow: bool) -> View {
        let cursor = samples.len().saturating_sub(1);
        View {
            job: path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string()),
            totals: Totals::over(&samples),
            samples,
            cursor,
            sort: Sort::Cpu,
            accumulate: false,
            filter: String::new(),
            editing: false,
            follow,
            live: true,
        }
    }

    /// Take on samples the guest has committed, following the end of the log if that is where
    /// the view was sitting.
    fn extend(&mut self, fresh: Vec<Sample>) {
        if fresh.is_empty() {
            return;
        }
        self.samples.extend(fresh);
        self.totals = Totals::over(&self.samples);
        if self.live {
            self.cursor = self.samples.len().saturating_sub(1);
        }
    }

    fn key(&mut self, key: Press) -> Flow {
        // While a filter is being typed every key belongs to it, or the letters of a search
        // would be read as commands.
        if self.editing {
            match key {
                Press::Enter | Press::Escape => self.editing = false,
                Press::Backspace => {
                    self.filter.pop();
                }
                Press::Char(c) => self.filter.push(c),
                _ => {}
            }
            return Flow::Continue;
        }
        match key {
            Press::Char('q' | 'Q') | Press::Escape | Press::Interrupt => return Flow::Quit,
            // Stepping anywhere but the end means the view is being read, not watched.
            Press::Left | Press::Char('h') => {
                self.cursor = self.cursor.saturating_sub(1);
                self.live = false;
            }
            Press::Right | Press::Char('l') => {
                self.cursor = (self.cursor.saturating_add(1)).min(self.last());
                self.live = self.cursor == self.last();
            }
            Press::Home => {
                self.cursor = 0;
                self.live = false;
            }
            Press::End => {
                self.cursor = self.last();
                self.live = true;
            }
            Press::Char('c') => self.sort = Sort::Cpu,
            Press::Char('m') => self.sort = Sort::Memory,
            Press::Char('d') => self.sort = Sort::Disk,
            Press::Char('a') => self.accumulate = !self.accumulate,
            Press::Char('/') => {
                self.editing = true;
                self.filter.clear();
            }
            _ => {}
        }
        Flow::Continue
    }

    fn last(&self) -> usize {
        self.samples.len().saturating_sub(1)
    }

    fn current(&self) -> Option<&Sample> {
        self.samples.get(self.cursor)
    }
}

/// Draw one frame: the whole screen, built in one buffer and written in one call, with the
/// size read fresh so a resized window is simply drawn at its new size.
fn paint(state: &View) -> Result<()> {
    // A terminal that will not report its size is drawn at the size terminals had before
    // they could be asked.
    let (rows, cols) = vk_core::pty::get_winsize(libc::STDOUT_FILENO).unwrap_or((24, 80));
    // The real size, floored only at what a frame needs to exist at all: a line longer than
    // the screen wraps, and a wrap scrolls the panel one row further up on every repaint.
    let frame = frame(state, rows.max(2), cols.max(1));
    let mut out = std::io::stdout();
    out.write_all(frame.as_bytes())
        .context("drawing the panel")?;
    out.flush().context("drawing the panel")?;
    Ok(())
}

/// The frame for a screen of `rows` by `cols`. Lines are terminated `\r\n` — the terminal is
/// in raw mode, where a newline alone drops down a row without returning to the left edge.
fn frame(state: &View, rows: u16, cols: u16) -> String {
    let cols = cols as usize;
    let mut out = String::with_capacity(rows as usize * cols);
    // Home the cursor rather than clearing the screen: every frame overwrites the last, and each
    // line clears its own tail, so nothing flickers between frames.
    out.push_str("\x1b[H");
    let mut lines: Vec<String> = Vec::new();
    lines.push(status(state, cols));
    match state.current() {
        Some(sample) => {
            lines.extend(system_panel(sample, cols));
            lines.push(String::new());
            // Whatever is left of the screen under the panel, minus the key line at the
            // bottom — measured from what was actually built, so a system line added or a
            // sample missing a record cannot silently eat a process row.
            let room = (rows as usize).saturating_sub(lines.len() + 1);
            lines.extend(process_table(state, sample, room, cols));
        }
        None => lines.push("no sample yet — waiting for the guest to commit one".to_string()),
    }
    // The keys belong on the bottom row, where a reader looks for them, so the screen is
    // filled to there whatever the sample had to say.
    let body = (rows as usize).saturating_sub(1);
    lines.truncate(body);
    lines.resize(body, String::new());
    lines.push(help(state));
    for (i, line) in lines.iter().enumerate() {
        out.push_str(&clip(line, cols));
        out.push_str("\x1b[K"); // clear whatever the last frame left on this row
        // No line break after the bottom row: writing one there scrolls the screen, which
        // would push the top line away and creep the whole panel upwards every repaint.
        if i + 1 < lines.len() {
            out.push_str("\r\n");
        }
    }
    out.push_str("\x1b[J"); // and whatever the last frame left below
    out
}

/// The line that says which job, which sample, and how the panel is set.
fn status(state: &View, cols: usize) -> String {
    let (place, when) = match state.current() {
        Some(s) => (
            format!("{}/{}", state.cursor.saturating_add(1), state.samples.len()),
            format!("{} +{}s", vk_core::atop::date_time(s.epoch).1, s.interval),
        ),
        None => ("0/0".to_string(), "-".to_string()),
    };
    let mode = match (state.follow, state.live) {
        (true, true) => " [following]",
        (true, false) => " [paused]",
        _ => "",
    };
    let boot = match state.current().is_some_and(|s| s.boot) {
        true => " [boot sample: counters cover the whole boot]",
        false => "",
    };
    let filter = match (state.editing, state.filter.is_empty()) {
        (true, _) => format!("  /{}_", state.filter),
        (false, false) => format!("  /{}", state.filter),
        (false, true) => String::new(),
    };
    let accumulated = match state.accumulate {
        true => "  whole job",
        false => "",
    };
    clip(
        &format!(
            "{} — sample {place} at {when}{mode}{boot}{accumulated}{filter}",
            state.job
        ),
        cols,
    )
}

/// The system half: what the guest's processors, memory, pressure, disks and network were
/// doing in this one sample.
fn system_panel(s: &Sample, cols: usize) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(cpu) = &s.cpu {
        let mut line = format!(
            "cpu   {:>3.0}% {}  user {:>3.0}%  sys {:>3.0}%  wait {:>3.0}%  steal {:>3.0}%",
            cpu.percent(cpu.busy()),
            bar(cpu.percent(cpu.busy()) / 100.0, 12),
            cpu.percent(cpu.user.saturating_add(cpu.nice)),
            cpu.percent(
                cpu.system
                    .saturating_add(cpu.irq)
                    .saturating_add(cpu.softirq)
            ),
            cpu.percent(cpu.iowait),
            cpu.percent(cpu.steal),
        );
        line.push_str(&format!("  {} of cpu time", ticks(cpu.busy(), cpu.hertz)));
        lines.push(line);
    }
    // One bar per processor, so a job driving a single core flat is visible at a glance.
    if !s.cores.is_empty() {
        let mut line = String::from("cores ");
        for core in &s.cores {
            let share = core.percent(core.busy());
            line.push_str(&format!(
                "{}{} {:>3.0}%  ",
                core.core.map(|n| format!("{n}:")).unwrap_or_default(),
                bar(share / 100.0, 8),
                share
            ));
        }
        lines.push(line.trim_end().to_string());
    }
    if let Some(mem) = &s.mem {
        let used = mem.bytes(mem.used());
        let total = mem.bytes(mem.physmem);
        let share = match total {
            0 => 0.0,
            total => used as f64 / total as f64,
        };
        let swap = match &s.swap {
            Some(sw) if sw.total > 0 => format!(
                "  swap {} of {}",
                fmt_bytes(sw.used_bytes()),
                fmt_bytes(sw.total_bytes())
            ),
            _ => "  no swap".to_string(),
        };
        lines.push(format!(
            "mem   {:>3.0}% {}  {} of {}  cache {}{swap}",
            share * 100.0,
            bar(share, 12),
            fmt_bytes(used),
            fmt_bytes(total),
            fmt_bytes(mem.bytes(mem.cache())),
        ));
    }
    lines.push(match &s.psi {
        Some(psi) if psi.supported => format!(
            "psi   cpu {:>4.1}%  mem {:>4.1}%  mem-full {:>4.1}%  io {:>4.1}%  io-full {:>4.1}%",
            psi.cpu_some.avg10,
            psi.mem_some.avg10,
            psi.mem_full.avg10,
            psi.io_some.avg10,
            psi.io_full.avg10
        ),
        _ => "psi   not recorded — this guest's kernel has no pressure stall information".into(),
    });
    lines.push(match s.disks.is_empty() {
        true => "disk  idle".to_string(),
        false => {
            let mut line = String::from("disk  ");
            for d in &s.disks {
                line.push_str(&format!(
                    "{} read {} write {} busy {}ms   ",
                    plain(&d.name),
                    rate(d.sectors_read.saturating_mul(SECTOR), s.interval),
                    rate(d.sectors_written.saturating_mul(SECTOR), s.interval),
                    d.io_ms
                ));
            }
            line.trim_end().to_string()
        }
    });
    let mut net = String::from("net   ");
    for i in s
        .ifaces
        .iter()
        .filter(|i| i.bytes_in > 0 || i.bytes_out > 0)
    {
        net.push_str(&format!(
            "{} in {} out {}   ",
            plain(&i.name),
            rate(i.bytes_in, s.interval),
            rate(i.bytes_out, s.interval)
        ));
    }
    if let Some(n) = &s.net {
        net.push_str(&format!(
            "{} tcp connections, {} resent",
            n.tcp_established, n.tcp_retrans
        ));
    }
    lines.push(net.trim_end().to_string());
    lines.into_iter().map(|l| clip(&l, cols)).collect()
}

/// The process half: what was running, ordered by the column the panel is sorted on. With
/// `a` the figures are each process's whole-job totals instead of this sample's.
fn process_table(state: &View, sample: &Sample, room: usize, cols: usize) -> Vec<String> {
    let filter = state.filter.to_lowercase();
    let matches = |command: &str| filter.is_empty() || command.to_lowercase().contains(&filter);
    /// A row is a command with four figures and the state it was in, whichever set of samples
    /// they came from. Named rather than a tuple: the three sorts below each pick a different
    /// one of them.
    struct Row {
        cpu: Duration,
        mem: u64,
        /// `None` where the guest's kernel accounted no disk traffic for the process.
        disk: Option<u64>,
        pid: i32,
        /// `E` for a task that ended while the job ran, as atop marks an exited one.
        state: char,
        command: String,
    }
    let mut rows_out: Vec<Row> = match state.accumulate {
        true => state
            .totals
            .iter()
            .filter(|t| matches(&t.command()))
            .map(|t| Row {
                cpu: t.cpu_time(),
                mem: t.peak_rss_bytes(),
                disk: t.disk_bytes(),
                pid: t.pid(),
                state: t.state(),
                command: t.command(),
            })
            .collect(),
        false => sample
            .procs
            .iter()
            .filter(|p| matches(p.command()))
            .map(|p| Row {
                cpu: secs_of(p.cpu_seconds()),
                mem: p.rsize.saturating_mul(1024),
                disk: p.io_stats.then(|| {
                    p.sectors_read
                        .saturating_add(p.sectors_written)
                        .saturating_mul(SECTOR)
                }),
                pid: p.pid,
                state: p.state,
                command: plain(p.command()),
            })
            .collect(),
    };
    // The pid last, for the same reason the report orders on it: the whole-job totals come out
    // of a map, and rows that tie must not swap places between one frame and the next.
    match state.sort {
        Sort::Cpu => rows_out.sort_by_key(|r| (std::cmp::Reverse(r.cpu), r.pid)),
        Sort::Memory => rows_out.sort_by_key(|r| (std::cmp::Reverse(r.mem), r.pid)),
        Sort::Disk => {
            rows_out.sort_by_key(|r| (std::cmp::Reverse(r.disk.unwrap_or(0)), r.pid));
        }
    }
    let mut out = vec![clip(
        &format!(
            "{:>7}  st  {:>8}  {:>9}  {:>9}  {}",
            "pid",
            heading("cpu", state.sort == Sort::Cpu),
            heading("memory", state.sort == Sort::Memory),
            heading("disk", state.sort == Sort::Disk),
            match state.accumulate {
                true => "command (whole job)",
                false => "command",
            }
        ),
        cols,
    )];
    for row in rows_out.into_iter().take(room.saturating_sub(1)) {
        out.push(clip(
            &format!(
                "{:>7}  {:>2}  {:>8}  {:>9}  {:>9}  {}",
                row.pid,
                row.state,
                fmt_cpu(row.cpu),
                fmt_bytes(row.mem),
                // Unaccounted traffic is not no traffic, and the report says `-` for it too.
                match row.disk {
                    Some(bytes) => fmt_bytes(bytes),
                    None => "-".to_string(),
                },
                row.command,
            ),
            cols,
        ));
    }
    out
}

/// The column a table is sorted on, marked so the keys that change it have somewhere to
/// point. Plain text, since a panel that must work under NO_COLOR cannot say it in colour.
fn heading(name: &str, sorted: bool) -> String {
    match sorted {
        true => format!(">{name}"),
        false => name.to_string(),
    }
}

/// The keys, on the last line where a reader looks for them.
fn help(state: &View) -> String {
    match state.editing {
        true => "filter: type to narrow, enter to keep, esc to drop".to_string(),
        false => format!(
            "←/→ step  home/end jump  c/m/d sort by {}  a whole job  / filter  q quit",
            state.sort.name()
        ),
    }
}

/// A proportional bar `width` cells wide. Full blocks with a partial one at the edge, so a
/// short bar still shows the difference between nothing and a little.
fn bar(share: f64, width: usize) -> String {
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

/// Bytes per second, from a figure counted over an interval.
fn rate(bytes: u64, interval: u64) -> String {
    format!("{}/s", fmt_bytes(bytes / interval.max(1)))
}

/// Ticks as the time they stand for.
fn ticks(ticks: u64, hertz: u64) -> String {
    fmt_cpu(secs_of(match hertz {
        0 => 0.0,
        hz => ticks as f64 / hz as f64,
    }))
}

/// A line cut to the width of the screen, counted in characters — a bar and a command line
/// are both full of multi-byte ones.
fn clip(line: &str, cols: usize) -> String {
    match line.chars().count() > cols {
        true => line.chars().take(cols).collect(),
        false => line.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three samples of a guest: one core busy, some memory, a disk and an interface, and two
    /// processes whose order differs by which column the table is sorted on.
    fn samples() -> Vec<Sample> {
        let mut s = String::from("RESET\n");
        for (epoch, interval, idle, rss, sectors) in [
            (1_000i64, 40u64, 700u64, 40_000u64, 8u64),
            (1_030, 30, 2_800, 60_000, 800),
            (1_060, 30, 1_000, 20_000, 0),
        ] {
            let h = |label: &str| {
                let (d, t) = vk_core::atop::date_time(epoch);
                format!("{label} runner {epoch} {d} {t} {interval}")
            };
            s.push_str(&format!(
                "{} 100 2 20 80 0 {idle} 4 0 6 2 0 0 100 0 0\n",
                h("CPU")
            ));
            s.push_str(&format!(
                "{} 100 0 10 70 0 {idle} 2 0 3 1 0 0 100 0 0\n",
                h("cpu")
            ));
            s.push_str(&format!(
                "{} 100 1 10 10 0 {idle} 2 0 3 1 0 0 100 0 0\n",
                h("cpu")
            ));
            s.push_str(&format!(
                "{} 4096 250000 150000 20000 500 3000 40 1500 0 700 0 0 2097152 0 0 0 0 0 0 0 250\n",
                h("MEM")
            ));
            s.push_str(&format!(
                "{} 4096 1000 900 0 41026 126424 0 0 0\n",
                h("SWP")
            ));
            s.push_str(&format!(
                "{} y 0.5 0.2 0.1 1000 0.0 0.0 0.0 0 0.0 0.0 0.0 0 1.5 0.4 0.2 4000 0.0 0.0 0.0 0\n",
                h("PSI")
            ));
            if sectors > 0 {
                s.push_str(&format!(
                    "{} vda 200 10 {sectors} 5 {sectors} -1 0 1 2.50\n",
                    h("DSK")
                ));
            }
            s.push_str(&format!(
                "{} upper 1 2 9 10 13 14 15 16 11 12 3 4 7 6 7 8\n",
                h("NET")
            ));
            s.push_str(&format!("{} eth0 100 20000 90 9000 10000 1\n", h("NET")));
            s.push_str(&format!(
                "{} 412 (sh) S 0 0 412 1 0 900 (sh -c make test) 1 1 0 0 0 0 0 0 0 0 0 y 0 0 - N ()\n",
                h("PRG")
            ));
            s.push_str(&format!(
                "{} 99 (dd) R 0 0 99 1 0 900 (dd if=/dev/zero of=big) 412 1 0 0 0 0 0 0 0 0 0 y 0 0 - - ()\n",
                h("PRG")
            ));
            s.push_str(&format!(
                "{} 412 (sh) S 100 90 10 5 25 0 0 1 0 412 y 900 (do_wait) 0 -3 -3\n",
                h("PRC")
            ));
            s.push_str(&format!(
                "{} 99 (dd) R 100 5 5 0 20 0 0 1 0 99 y 0 (0) 0 -3 -3\n",
                h("PRC")
            ));
            s.push_str(&format!(
                "{} 412 (sh) S 4096 20000 {rss} 700 0 0 900 2 2400 1100 132 0 412 y 0 0 -3 -3 -3 -3\n",
                h("PRM")
            ));
            s.push_str(&format!(
                "{} 99 (dd) R 4096 8000 4000 700 0 0 10 0 2400 1100 132 0 99 y 0 0 -3 -3 -3 -3\n",
                h("PRM")
            ));
            s.push_str(&format!("{} 412 (sh) S n y 1 8 1 8 0 412 n y\n", h("PRD")));
            s.push_str(&format!(
                "{} 99 (dd) R n y 100 {sectors} 100 {sectors} 0 99 n y\n",
                h("PRD")
            ));
            // a short-lived command the kernel reported the death of, which no sweep saw
            s.push_str(&format!(
                "{} 700 (true) E 0 0 700 1 0 {} (true) 412 0 0 0 0 0 0 0 0 0 2 y 0 0 - N ()\n",
                h("PRG"),
                epoch - 1
            ));
            s.push_str(&format!(
                "{} 700 (true) E 100 1 1 0 0 0 0 -1 0 700 y 0 () 0 -3 -3\n",
                h("PRC")
            ));
            s.push_str(&format!(
                "{} 700 (true) E 4096 0 512 0 0 0 20 0 0 0 0 0 700 y 0 0 -3 -3 -3 -3\n",
                h("PRM")
            ));
            s.push_str(&format!(
                "{} 700 (true) E n y 1 2 0 0 0 700 n y\n",
                h("PRD")
            ));
            s.push_str("SEP\n");
        }
        crate::atoplog::parse(&s).samples
    }

    /// A frame with the panel's own control sequences taken out, so what is left is what the
    /// reader sees — and any escape still in it came from the log.
    fn visible(frame: &str) -> String {
        frame
            .replace("\x1b[H", "")
            .replace("\x1b[K", "")
            .replace("\x1b[J", "")
    }

    fn view(follow: bool) -> View {
        View::new(
            Path::new("/var/lib/virtkit/atop/2026-08-12/42137-acme-web-test_unit/atop.log"),
            samples(),
            follow,
        )
    }

    /// The panel fills the screen it is given, says where in the recording it is, and shows
    /// the guest's system and its processes.
    #[test]
    fn the_panel_draws_a_sample() {
        let state = view(false);
        let out = frame(&state, 24, 100);
        println!("{}", out.replace('\r', ""));

        // Homed, every line clearing its own tail, and the rest of the screen after.
        assert!(out.starts_with("\x1b[H"));
        assert!(
            out.ends_with("\x1b[K\x1b[J"),
            "the bottom row ends without a line break"
        );
        assert_eq!(
            out.matches("\x1b[K\r\n").count(),
            23,
            "a break between rows, and none after the last: writing one there would scroll"
        );

        let lines: Vec<&str> = out.split("\x1b[K\r\n").collect();
        // It opens on the last sample of the recording.
        assert!(
            lines[0].contains("42137-acme-web-test_unit — sample 3/3"),
            "{:?}",
            lines[0]
        );
        assert!(lines[1].starts_with("cpu "), "{:?}", lines[1]);
        assert!(lines[1].contains('█'), "a bar: {:?}", lines[1]);
        assert!(lines[2].starts_with("cores "), "{:?}", lines[2]);
        assert!(lines[3].starts_with("mem "), "{:?}", lines[3]);
        assert!(lines[3].contains("swap"), "{:?}", lines[3]);
        assert!(lines[4].starts_with("psi "), "{:?}", lines[4]);
        assert!(lines[5].starts_with("disk "), "{:?}", lines[5]);
        assert!(lines[6].starts_with("net "), "{:?}", lines[6]);
        // the table: its heading marks the sorted column, and both processes are listed
        let table = lines
            .iter()
            .position(|l| l.contains("pid"))
            .expect("a heading");
        assert!(lines[table].contains(">cpu"), "{:?}", lines[table]);
        assert!(
            lines[table + 1].contains("sh -c make test"),
            "{:?}",
            lines[table + 1]
        );
        assert!(
            lines[table + 2].contains("dd if=/dev/zero"),
            "{:?}",
            lines[table + 2]
        );
        assert!(
            lines.iter().any(|l| l.contains("q quit")),
            "the keys: {lines:?}"
        );
        for line in &lines {
            assert!(
                line.chars().count() <= 100 + 3,
                "wider than the screen: {line:?}"
            );
        }
    }

    /// A narrow, short terminal gets a frame that fits it: lines cut to the width, and no
    /// more rows than the screen has.
    #[test]
    fn the_panel_fits_the_terminal_it_is_given() {
        let out = frame(&view(false), 12, 44);
        assert_eq!(out.matches("\x1b[K\r\n").count(), 11);
        for line in out.split("\x1b[K\r\n") {
            let visible = line
                .trim_start_matches("\x1b[H")
                .trim_end_matches("\x1b[J")
                .trim_end_matches("\x1b[K");
            assert!(visible.chars().count() <= 44, "{visible:?}");
        }
    }

    /// The keys walk the recording, and stepping away from the end stops the view following
    /// it — a reader looking at a sample does not want it moving.
    #[test]
    fn the_keys_walk_the_recording() {
        let mut state = view(true);
        assert_eq!((state.cursor, state.live), (2, true));

        assert_eq!(state.key(Press::Left), Flow::Continue);
        assert_eq!(
            (state.cursor, state.live),
            (1, false),
            "stepping back pauses"
        );
        state.key(Press::Home);
        assert_eq!(state.cursor, 0);
        state.key(Press::Left);
        assert_eq!(
            state.cursor, 0,
            "the first sample is as far back as it goes"
        );
        state.key(Press::Right);
        assert_eq!((state.cursor, state.live), (1, false));
        state.key(Press::End);
        assert_eq!(
            (state.cursor, state.live),
            (2, true),
            "end takes up the tail again"
        );
        state.key(Press::Right);
        assert_eq!(
            state.cursor, 2,
            "the last sample is as far forward as it goes"
        );

        // A fresh sample moves the view only while it is following the end.
        state.extend(samples());
        assert_eq!((state.cursor, state.live), (5, true));
        state.key(Press::Left);
        state.extend(samples());
        assert_eq!(
            state.cursor, 4,
            "paused: the new samples wait to be stepped to"
        );
        assert_eq!(state.samples.len(), 9);

        assert_eq!(state.key(Press::Char('q')), Flow::Quit);
        assert_eq!(state.key(Press::Interrupt), Flow::Quit);
        assert_eq!(state.key(Press::Escape), Flow::Quit);
    }

    /// The sort keys reorder the table, and each is visible in its heading: `dd` moved the
    /// most disk while `sh` used the most cpu, so the two orders differ.
    #[test]
    fn a_sort_key_reorders_the_table() {
        let mut state = view(false);
        // The middle sample, where both processes were doing something.
        state.key(Press::Left);
        let first_row = |state: &View| {
            let sample = state.current().expect("a sample").clone();
            let rows = process_table(state, &sample, 24, 100);
            rows.get(1).cloned().unwrap_or_default()
        };
        assert!(first_row(&state).contains("sh -c make test"), "by cpu");
        state.key(Press::Char('d'));
        assert!(
            first_row(&state).contains("dd if="),
            "by disk: {}",
            first_row(&state)
        );
        state.key(Press::Char('m'));
        assert!(first_row(&state).contains("sh -c make test"), "by memory");
        state.key(Press::Char('c'));
        assert!(
            first_row(&state).contains("sh -c make test"),
            "by cpu again"
        );
        // The heading says which column the order rests on.
        let sample = state.current().expect("a sample").clone();
        assert!(process_table(&state, &sample, 24, 100)[0].contains(">cpu"));
    }

    /// `a` swaps this sample's figures for each process's whole-job totals, which is a
    /// different question: `dd` wrote for two of the three samples.
    #[test]
    fn accumulating_shows_the_whole_job() {
        let mut state = view(false);
        let sample = state.current().expect("a sample").clone();
        let now = process_table(&state, &sample, 24, 100);
        state.key(Press::Char('a'));
        let whole = process_table(&state, &sample, 24, 100);
        assert!(whole[0].contains("whole job"), "{:?}", whole[0]);
        assert_ne!(now[1], whole[1], "the figures are not the same question");
        // sh burned 100 ticks a sample over three samples, at 100 Hz
        assert!(
            whole
                .iter()
                .any(|r| r.contains("sh -c make test") && r.contains("3.0s")),
            "{whole:?}"
        );
    }

    /// A task the kernel reported the death of reads as one in the panel: atop marks an exited
    /// process, and a table that showed it like a running one would be lying about it.
    #[test]
    fn an_exited_task_is_marked_in_the_table() {
        let state = view(false);
        let sample = state.current().expect("a sample").clone();
        let rows = process_table(&state, &sample, 24, 100);
        assert!(rows[0].contains("st"), "a state column: {:?}", rows[0]);
        let dead = rows
            .iter()
            .find(|r| r.contains("true"))
            .expect("the exited task");
        assert!(dead.contains(" E "), "marked as exited: {dead:?}");
        let live = rows.iter().find(|r| r.contains(" sh")).expect("a live one");
        assert!(live.contains(" S "), "still sleeping: {live:?}");

        // Accumulated over the job, the same task reads as one that ended.
        let mut state = state;
        state.key(Press::Char('a'));
        let rows = process_table(&state, &sample, 24, 100);
        let dead = rows
            .iter()
            .find(|r| r.contains("true"))
            .expect("the exited task");
        assert!(dead.contains(" E "), "{dead:?}");
        assert!(
            dead.contains("×3"),
            "three runs of it, one per sample: {dead:?}"
        );
    }

    /// A filter narrows the table to the commands it matches, and while it is being typed
    /// the letters go into it rather than being read as commands.
    #[test]
    fn a_filter_narrows_the_table() {
        let mut state = view(false);
        state.key(Press::Char('/'));
        assert!(state.editing);
        for c in "dd".chars() {
            state.key(Press::Char(c));
        }
        // `d` would sort by disk outside the filter; inside it is just a letter.
        assert_eq!(state.sort.name(), "cpu");
        assert_eq!(state.filter, "dd");
        state.key(Press::Enter);
        assert!(!state.editing);

        let sample = state.current().expect("a sample").clone();
        let rows = process_table(&state, &sample, 24, 100);
        assert_eq!(rows.len(), 2, "a heading and the one match: {rows:?}");
        assert!(rows[1].contains("dd if="));
        assert!(
            frame(&state, 24, 100).contains("/dd"),
            "the filter is on screen"
        );

        // Backspacing it away brings the rest back.
        state.key(Press::Char('/'));
        state.key(Press::Backspace);
        state.key(Press::Escape);
        assert!(state.filter.is_empty());
        // a heading, the two live processes, and the task that exited
        assert_eq!(process_table(&state, &sample, 24, 100).len(), 4);
    }

    /// The boot sample is marked: its counters cover the guest's whole boot, so its
    /// percentages are an average over that and not over an interval like the rest.
    #[test]
    fn the_boot_sample_says_what_it_is() {
        let mut state = view(false);
        state.key(Press::Home);
        assert!(frame(&state, 24, 100).contains("[boot sample"));
        state.key(Press::End);
        assert!(!frame(&state, 24, 100).contains("[boot sample"));
    }

    /// Following says so, and pausing says that instead — the panel never leaves a reader
    /// guessing whether what is on screen is still moving.
    #[test]
    fn following_and_pausing_are_both_visible() {
        let mut state = view(true);
        assert!(frame(&state, 24, 100).contains("[following]"));
        state.key(Press::Left);
        assert!(frame(&state, 24, 100).contains("[paused]"));
        // Without --follow there is nothing to follow, so neither is claimed.
        let plain = view(false);
        let out = frame(&plain, 24, 100);
        assert!(!out.contains("[following]") && !out.contains("[paused]"));
    }

    /// A recording with nothing complete in it yet — `--follow` on a job that has just
    /// started — draws a screen that says so instead of nothing at all.
    #[test]
    fn a_recording_with_no_samples_yet_still_draws() {
        let state = View::new(Path::new("atop.log"), Vec::new(), true);
        let out = frame(&state, 24, 80);
        assert!(out.contains("no sample yet"), "{out}");
        assert!(out.contains("sample 0/0"), "{out}");
    }

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
        assert_eq!(feed(b"\x1b[H").0, vec![Press::Home]);
        assert_eq!(feed(b"\x1b[F").0, vec![Press::End]);
        assert_eq!(feed(b"\x1bOD").0, vec![Press::Left], "application mode");
        assert_eq!(feed(b"\x1b[1~").0, vec![Press::Home]);
        assert_eq!(feed(b"\x1b[4~").0, vec![Press::End]);
        assert_eq!(feed(b"\x1b[7~").0, vec![Press::Home]);
        assert_eq!(feed(b"\x1b[8~").0, vec![Press::End]);
        // several keys in one read, and the letters and controls the panel uses
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
        // ...and an escape that never completes was a bare Escape.
        let (_, mut alone) = feed(b"\x1b");
        assert_eq!(alone.flush(), Some(Press::Escape));
        assert_eq!(alone.flush(), None, "and only once");
        // A sequence the panel has no key for is dropped whole, letters included.
        let (presses, mut unknown) = feed(b"\x1b[200~");
        assert!(presses.is_empty(), "{presses:?}");
        assert_eq!(unknown.flush(), None);
    }

    /// A follower resumes on a record boundary in the *file*, so it must not add an offset
    /// counted in decoded text: a byte that is not text widens to three, and once the drift
    /// pushes past the end every later read returns nothing and the panel freezes for good.
    #[test]
    fn a_follower_resumes_past_a_byte_that_is_not_text() {
        let dir = std::env::temp_dir().join(format!("vk-atop-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("atop.log");

        // A first sample whose command line holds two bytes that are not text: decoded
        // lossily each becomes a three-byte replacement, so the text is longer than the file.
        let mut one: Vec<u8> = b"RESET\nPRG runner 1000 1970/01/01 00:16:40 40 7 (sh) S 0 0 7 \
             1 0 900 (sh "
            .to_vec();
        one.extend_from_slice(&[0xff, 0xfe]);
        one.extend_from_slice(b") 1 1 0 0 0 0 0 0 0 0 0 y 0 0 - N ()\nSEP\n");
        std::fs::write(&path, &one).unwrap();
        let mut tail = Tail::open(&path).expect("a recording");
        assert_eq!(tail.read().unwrap().len(), 1, "the first sample");
        // The offset is where the file's own SEP ended, not where the decoded text did.
        assert_eq!(tail.offset, one.len() as u64);
        assert!(
            String::from_utf8_lossy(&one).len() > one.len(),
            "the decoded text really is longer than the file"
        );

        // A second sample appended after it is seen exactly once, and nothing before it again.
        let two = "PRC runner 1030 1970/01/01 00:17:10 30 7 (sh) S 100 5 5 0 20 0 0 1 0 7 \
                   y 0 (-) 0 -3 -3\nSEP\n";
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(two.as_bytes())
            .unwrap();
        assert_eq!(tail.read().unwrap().len(), 1, "only what is new");
        assert!(tail.read().unwrap().is_empty(), "and nothing twice");

        // A tail the guest has not closed with a SEP yet is not taken up.
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"CPU runner 1060 1970/01/01 00:17:40 30 100 2 1")
            .unwrap();
        assert!(
            tail.read().unwrap().is_empty(),
            "an unfinished sample waits"
        );

        // A symlink where the log goes is not a recording, whatever it points at.
        let planted = dir.join("planted.log");
        std::os::unix::fs::symlink(&path, &planted).unwrap();
        assert!(Tail::open(&planted).is_err());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A guest writes its own tick counters and the `hertz` they are counted in, so the
    /// quotient can be a figure no duration names. The panel draws something rather than
    /// dying with the terminal in raw mode.
    #[test]
    fn an_absurd_tick_count_draws_rather_than_panics() {
        let huge = u64::MAX;
        let text = format!(
            "RESET\n\
             CPU runner 1000 1970/01/01 00:16:40 30 1 1 {huge} {huge} 0 0 0 0 0 0 0 0 100 0 0\n\
             PRC runner 1000 1970/01/01 00:16:40 30 7 (sh) S 1 {huge} {huge} 0 20 0 0 0 0 7 \
             y 0 (-) 0 -3 -3\n\
             SEP\n"
        );
        let state = View::new(
            Path::new("atop.log"),
            crate::atoplog::parse(&text).samples,
            false,
        );
        let out = frame(&state, 24, 100);
        assert!(out.contains("cpu"), "{out}");
        // And with the whole-job totals on, which sum the same figures.
        let mut acc = state;
        acc.accumulate = true;
        assert!(!frame(&acc, 24, 100).is_empty());
    }

    /// The log is written on a directory the job's guest had read-write, so a command line can
    /// hold an escape sequence — which drawn into a full-screen panel would drive the
    /// operator's terminal rather than name a process.
    #[test]
    fn guest_text_cannot_drive_the_terminal() {
        assert_eq!(plain("sh -c echo"), "sh -c echo");
        assert_eq!(plain("sh \x1b[2J\r x"), "sh .[2J. x");
        let text = "RESET\nPRG runner 1000 1970/01/01 00:16:40 40 7 (sh) S 0 0 7 1 0 900                     (sh -c \x1b[2Jecho\rx) 1 1 0 0 0 0 0 0 0 0 0 y 0 0 - N ()\nSEP\n";
        let state = View::new(
            Path::new("atop.log"),
            crate::atoplog::parse(text).samples,
            false,
        );
        let out = frame(&state, 24, 100);
        // The only escapes in the frame are the panel's own: homing, clearing a line, and the
        // cursor. A `[2J` from the guest would clear the screen; a bare `\r` would overwrite.
        let body: String = visible(&out)
            .lines()
            .filter(|l| l.contains("sh -c"))
            .collect::<Vec<_>>()
            .join("");
        assert!(
            !body.contains('\x1b'),
            "no escape of the guest's reaches it: {body:?}"
        );
        assert!(body.contains("sh -c .[2Jecho.x"), "{body:?}");
    }

    /// Rows that tie must not swap places between one frame and the next: the whole-job totals
    /// come out of a map, whose order is nobody's to rely on.
    #[test]
    fn tied_rows_keep_their_order_between_frames() {
        let mut state = view(false);
        state.accumulate = true;
        let sample = state.current().cloned().expect("a sample");
        let once = process_table(&state, &sample, 10, 100);
        let twice = process_table(&state, &sample, 10, 100);
        assert_eq!(once, twice, "the same table, drawn twice");
    }

    /// A screen too small for the panel is drawn at the size it is: a line longer than the
    /// terminal wraps, and a wrap scrolls the panel a row further up on every repaint.
    #[test]
    fn a_tiny_terminal_is_never_drawn_wider_than_it_is() {
        let state = view(false);
        for (rows, cols) in [(1u16, 1u16), (2, 8), (5, 20), (24, 100)] {
            let out = frame(&state, rows.max(2), cols.max(1));
            for line in visible(&out).split("\r\n") {
                let width = line.chars().count();
                assert!(
                    width <= cols.max(1) as usize,
                    "{rows}x{cols}: {width} chars in {line:?}"
                );
            }
        }
    }

    /// The bars are the panel's only picture, and a reader compares them against each other:
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
