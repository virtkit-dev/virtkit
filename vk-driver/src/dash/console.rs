//! The selected environment's console: what is on disk, what is kept, and what is shown.
//!
//! [`Tail`] follows the VMM's file and classifies new bytes into lines. [`Buffer`] keeps
//! the last few thousand lines; [`Filter`] only controls which are displayed. Hiding kernel
//! lines to inspect an agent complaint, then restoring them, preserves the scrollback and
//! requires only a redraw, with no re-read.
//!
//! Classification uses [`crate::consolelog`], matching `vk logs`. It avoids
//! [`crate::consolelog::select`], which would re-classify the whole file on every call.
//!
//! The file is the guest's to write and the guest is not trusted. It is opened without
//! following symlinks and refused unless it is a regular file — the same rule
//! [`crate::atoplog::open_log`] holds — and without blocking, because that refusal can only
//! come after the open: a FIFO left where the console goes would otherwise hold the open
//! itself until something wrote to it, and this thread with it. What the lines say is made
//! inert where it is drawn, by [`crate::dash::render::Painter`], which drops every character
//! a terminal would take as an instruction rather than as a cell.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::consolelog::{Level, Line, Source, classify};

/// How many lines are kept for the selected environment. A boot is a few hundred and a
/// chatty build is unbounded, so this is where "enough scrollback to find the failure" is
/// traded against a dashboard that grows without limit while nobody is looking at it.
const CAPACITY: usize = 5000;

/// How much of an existing console is read when the reader selects an environment. A console
/// that has been running for days is megabytes, and only its end is scrollback anyone wants.
const BACKLOG: u64 = 1 << 20;

/// How much is read in one pass. A guest that dumped ten megabytes between two ticks is
/// caught up over the next few rather than in one frame that stalls the loop.
const CHUNK: u64 = 1 << 18;

/// How long a line without a newline is allowed to get before it is shown anyway. A guest
/// can write for ever without ending a line, and an unbounded buffer waiting for one is a
/// way to spend this process's memory from inside the VM.
const MAX_LINE: usize = 64 * 1024;

/// The three writers a console carries, in the order the status line names them.
const SOURCES: [Source; 3] = [Source::Kernel, Source::Agent, Source::Guest];

/// What a source is called, for the status line and the help.
fn source_word(source: Source) -> &'static str {
    match source {
        Source::Kernel => "kernel",
        Source::Agent => "agent",
        Source::Guest => "guest",
    }
}

/// The letter that marks a line's writer in the gutter. A letter and not only a colour: the
/// dashboard is read on terminals with no colour at all, and in screenshots of them.
pub(crate) fn source_mark(source: Source) -> char {
    match source {
        Source::Kernel => 'k',
        Source::Agent => 'a',
        Source::Guest => 'g',
    }
}

/// What a level is called.
fn level_word(level: Level) -> &'static str {
    match level {
        Level::Error => "error",
        Level::Warn => "warn",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    }
}

/// The floor, from admitting everything to admitting only what stopped something working.
/// `None` is the loosest: a kernel line and a guest program's line carry no level at all, so
/// any floor at all hides them.
const FLOORS: [Option<Level>; 6] = [
    None,
    Some(Level::Trace),
    Some(Level::Debug),
    Some(Level::Info),
    Some(Level::Warn),
    Some(Level::Error),
];

/// Which of the kept lines are shown. Changing one changes the screen and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Filter {
    /// Never empty: the last source cannot be turned off, because an empty pane that cannot
    /// say why it is empty reads as a broken dashboard rather than as a working filter.
    sources: Vec<Source>,
    floor: Option<Level>,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            sources: SOURCES.to_vec(),
            floor: None,
        }
    }
}

impl Filter {
    /// Whether this line is shown.
    pub(crate) fn admits(&self, line: &Line) -> bool {
        if !self.sources.contains(&line.source) {
            return false;
        }
        match (self.floor, line.level) {
            (None, _) => true,
            // `Level` is ordered most severe first, so `level <= floor` reads "at least as
            // severe as the floor".
            (Some(floor), Some(level)) => level <= floor,
            (Some(_), None) => false,
        }
    }

    pub(crate) fn shows(&self, source: Source) -> bool {
        self.sources.contains(&source)
    }

    /// Show a source, or stop showing it. The last one stays on.
    pub(crate) fn toggle(&mut self, source: Source) {
        match self.sources.iter().position(|held| *held == source) {
            Some(at) if self.sources.len() > 1 => {
                self.sources.remove(at);
            }
            Some(_) => {}
            None => self.sources.push(source),
        }
    }

    /// Hide everything less severe than the next level up.
    pub(crate) fn raise(&mut self) {
        self.step(1);
    }

    /// Show one level more.
    pub(crate) fn lower(&mut self) {
        self.step(-1);
    }

    fn step(&mut self, delta: isize) {
        let at = FLOORS.iter().position(|floor| *floor == self.floor);
        let Some(at) = at else { return };
        let moved = at
            .saturating_add_signed(delta)
            .min(FLOORS.len().saturating_sub(1));
        if let Some(floor) = FLOORS.get(moved) {
            self.floor = *floor;
        }
    }

    /// How the filter reads on the status line, so what is hidden is never a mystery. No
    /// floor is written as no floor at all rather than as a level that happens to admit
    /// everything.
    pub(crate) fn summary(&self) -> String {
        let shown: Vec<&str> = SOURCES
            .iter()
            .filter(|source| self.shows(**source))
            .map(|source| source_word(*source))
            .collect();
        match self.floor {
            Some(floor) => format!("{} ≥{}", shown.join("+"), level_word(floor)),
            None => shown.join("+"),
        }
    }
}

/// The lines kept for one environment, oldest first and bounded.
#[derive(Debug)]
pub(crate) struct Buffer {
    lines: VecDeque<Line>,
    capacity: usize,
    /// How many have fallen off the front, so the pane can say the scrollback does not reach
    /// the beginning rather than imply that it does.
    dropped: usize,
}

impl Default for Buffer {
    fn default() -> Self {
        Self::new(CAPACITY)
    }
}

impl Buffer {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            capacity: capacity.max(1),
            dropped: 0,
        }
    }

    pub(crate) fn push(&mut self, line: Line) {
        if self.lines.len() >= self.capacity {
            self.lines.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.lines.push_back(line);
    }

    pub(crate) fn clear(&mut self) {
        self.lines.clear();
        self.dropped = 0;
    }

    pub(crate) fn len(&self) -> usize {
        self.lines.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    pub(crate) fn dropped(&self) -> usize {
        self.dropped
    }

    /// The lines a filter admits, oldest first.
    pub(crate) fn shown<'a>(&'a self, filter: &'a Filter) -> impl Iterator<Item = &'a Line> {
        self.lines.iter().filter(move |line| filter.admits(line))
    }
}

/// What one pass over the console file found.
#[derive(Debug, Default)]
pub(crate) struct Batch {
    /// Which selection asked for it. A pass that began before the reader moved is dropped
    /// rather than shown under the environment they moved to.
    pub(crate) epoch: u64,
    pub(crate) lines: Vec<Line>,
    /// The file went backwards — truncated, or replaced by a fresh boot's. What was read
    /// before is no longer the beginning of what is being read now.
    pub(crate) restarted: bool,
    /// There is no console file at all: an environment that has never booted.
    pub(crate) missing: bool,
}

/// The file being followed, and how far into it has been read.
pub(crate) struct Tail {
    path: PathBuf,
    open: Option<Open>,
}

/// An opened console, identified by what the kernel resolved rather than by its name.
struct Open {
    file: File,
    dev: u64,
    ino: u64,
    /// bytes consumed, which is also the descriptor's position
    read: u64,
    /// a line that has arrived without its newline yet
    partial: Vec<u8>,
    /// whether the first line to complete is a fragment of one that began before the
    /// backlog window and so is not a line at all
    fragment: bool,
}

impl Tail {
    /// Follow the console of the environment whose state lives in `dir`.
    pub(crate) fn new(dir: &Path) -> Self {
        Self {
            path: dir.join(crate::run::CONSOLE_LOG),
            open: None,
        }
    }

    /// Everything that has arrived since the last pass.
    ///
    /// The path is re-examined every pass rather than resolved once: a console appears when
    /// an environment first boots and is replaced when it boots again, and a reader watching
    /// a `vk dev up` is watching exactly that moment.
    pub(crate) fn drain(&mut self, epoch: u64) -> Batch {
        let mut batch = Batch {
            epoch,
            ..Batch::default()
        };
        let Ok(stat) = std::fs::metadata(&self.path) else {
            self.open = None;
            batch.missing = true;
            return batch;
        };
        let replaced = self
            .open
            .as_ref()
            .is_none_or(|open| open.dev != stat.dev() || open.ino != stat.ino());
        if replaced {
            // A console that was being followed and has become another file took its
            // scrollback with it; one opened for the first time had none to lose.
            batch.restarted = self.open.is_some();
            match attach(&self.path, stat.len()) {
                Some(open) => self.open = Some(open),
                None => {
                    self.open = None;
                    batch.missing = true;
                    return batch;
                }
            }
        }
        let Some(open) = self.open.as_mut() else {
            return batch;
        };
        // Shorter than what has already been read: the same file, emptied. Whatever the
        // buffer holds describes bytes that are gone.
        if stat.len() < open.read && open.rewind() {
            batch.restarted = true;
        }
        open.read_into(&mut batch.lines, stat.len());
        batch
    }
}

/// Open the console for reading, starting [`BACKLOG`] bytes before its end.
///
/// Without following symlinks and only if it is a regular file: the guest has this directory
/// read-write, so the name may lead anywhere by the time it is opened. The descriptor is what
/// is read from afterwards, so the check and the read are about the same object.
fn attach(path: &Path, len: u64) -> Option<Open> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        // Non-blocking as well, so the check below is reached at all: opening a FIFO for
        // reading waits for a writer, and a FIFO is exactly what the check is there to
        // refuse. A regular file reads the same either way — it is never short of data.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let stat = file.metadata().ok()?;
    if !stat.is_file() {
        return None;
    }
    let mut open = Open {
        file,
        dev: stat.dev(),
        ino: stat.ino(),
        read: 0,
        partial: Vec::new(),
        fragment: false,
    };
    let from = len.saturating_sub(BACKLOG);
    if from > 0 && open.file.seek(SeekFrom::Start(from)).is_ok() {
        open.read = from;
        // Whatever the window opened in the middle of is half a line.
        open.fragment = true;
    }
    Some(open)
}

impl Open {
    /// Start over from the beginning of the same file.
    fn rewind(&mut self) -> bool {
        if self.file.seek(SeekFrom::Start(0)).is_err() {
            return false;
        }
        self.read = 0;
        self.partial.clear();
        self.fragment = false;
        true
    }

    /// Read what is there, up to [`CHUNK`], and classify the lines it completes.
    fn read_into(&mut self, lines: &mut Vec<Line>, len: u64) {
        let want = len.saturating_sub(self.read).min(CHUNK);
        if want == 0 {
            return;
        }
        let mut bytes = Vec::new();
        // A read that failed leaves `read` where it was, so the next pass asks for the same
        // bytes again rather than skipping them.
        if (&self.file).take(want).read_to_end(&mut bytes).is_err() {
            return;
        }
        self.read = self.read.saturating_add(bytes.len() as u64);
        let mut data = std::mem::take(&mut self.partial);
        data.extend_from_slice(&bytes);

        let mut pieces: Vec<&[u8]> = data.split(|byte| *byte == b'\n').collect();
        // `split` always yields at least one piece, and the last of them has no newline
        // after it yet — so it is not a line, it is the start of one.
        let remainder = pieces.pop().unwrap_or(&[]);
        for piece in pieces {
            if self.fragment {
                // The backlog window opened in the middle of this one.
                self.fragment = false;
                continue;
            }
            lines.push(line_of(piece));
        }
        self.partial = remainder.to_vec();
        if self.partial.len() > MAX_LINE {
            // A guest writing for ever without a newline is shown what it has written
            // rather than kept in memory until it stops. What went out is the half-line the
            // backlog window opened in, where there was one, so what completes it next is a
            // line of its own rather than the piece that is skipped.
            lines.push(line_of(&std::mem::take(&mut self.partial)));
            self.fragment = false;
        }
    }
}

/// One raw console line, classified.
///
/// Decoded lossily: a serial console is bytes, not promised text, and a single byte the
/// guest wrote outside UTF-8 must not discard the line it is in — the same decision
/// [`crate::run`] makes when it reads a console for a boot failure.
fn line_of(raw: &[u8]) -> Line {
    classify(&String::from_utf8_lossy(raw))
}

#[cfg(test)]
mod tests {
    // An assertion is how a test reports; the panic lints this module gates on exist to
    // keep a live terminal intact, which no test has.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )]

    use super::*;
    use std::io::Write;

    fn line(raw: &str) -> Line {
        classify(raw)
    }

    /// A directory of this test's own, removed when it is done with.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(what: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "vk-dash-console-{what}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, text: &str) {
            let mut file = std::fs::File::create(self.0.join(crate::run::CONSOLE_LOG)).unwrap();
            file.write_all(text.as_bytes()).unwrap();
        }

        fn append(&self, text: &str) {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(self.0.join(crate::run::CONSOLE_LOG))
                .unwrap();
            file.write_all(text.as_bytes()).unwrap();
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn texts(lines: &[Line]) -> Vec<&str> {
        lines.iter().map(|line| line.text.as_str()).collect()
    }

    /// A filter decides what is shown. What is kept is the same either way, which is the
    /// whole reason the buffer and the filter are two things.
    #[test]
    fn a_filter_changes_what_is_shown_and_not_what_is_kept() {
        let mut buffer = Buffer::default();
        buffer.push(line("[    1.000000] kernel says"));
        buffer.push(line("13:46:39 [INFO] vk-agent: agent says"));
        buffer.push(line("guest says"));

        let mut filter = Filter::default();
        assert_eq!(buffer.shown(&filter).count(), 3);

        filter.toggle(Source::Kernel);
        assert!(!filter.shows(Source::Kernel));
        assert_eq!(buffer.shown(&filter).count(), 2);
        assert_eq!(buffer.len(), 3, "the buffer was rebuilt to change a filter");

        filter.toggle(Source::Kernel);
        assert_eq!(buffer.shown(&filter).count(), 3);

        // The level floor hides the lines that carry no level at all — a kernel line and a
        // guest program's — because neither is known to be a complaint.
        filter.raise();
        assert_eq!(
            texts(&buffer.shown(&filter).cloned().collect::<Vec<_>>()),
            ["13:46:39 [INFO] vk-agent: agent says"]
        );
        assert!(filter.summary().contains("≥trace"));
        filter.lower();
        assert_eq!(buffer.shown(&filter).count(), 3);
        assert_eq!(filter.summary(), "kernel+agent+guest");
    }

    /// The floor stops at both ends rather than wrapping round to the other one.
    #[test]
    fn the_level_floor_stops_at_both_ends() {
        let mut filter = Filter::default();
        for _ in 0..10 {
            filter.raise();
        }
        assert!(filter.summary().ends_with("≥error"));
        let oom = line("[   48.291057] Out of memory: Killed process 7 (cc1plus)");
        assert!(filter.admits(&oom), "a guest OOM was filtered out");
        assert!(!filter.admits(&line("[    1.000000] Linux version 6.18.49")));
        for _ in 0..10 {
            filter.lower();
        }
        assert_eq!(filter.summary(), "kernel+agent+guest");
    }

    /// The last source stays on: a pane showing nothing, with nothing on screen saying why,
    /// reads as a broken dashboard.
    #[test]
    fn the_last_source_cannot_be_turned_off() {
        let mut filter = Filter::default();
        for source in SOURCES {
            filter.toggle(source);
        }
        assert_eq!(SOURCES.iter().filter(|s| filter.shows(**s)).count(), 1);
        assert!(filter.shows(Source::Guest));
    }

    /// The buffer is bounded and says how much it has forgotten, rather than implying the
    /// scrollback reaches the first line of the boot.
    #[test]
    fn the_buffer_forgets_the_oldest_lines_and_says_so() {
        let mut buffer = Buffer::new(3);
        for n in 0..5 {
            buffer.push(line(&format!("line {n}")));
        }
        assert_eq!((buffer.len(), buffer.dropped()), (3, 2));
        let everything = Filter::default();
        let kept: Vec<&Line> = buffer.shown(&everything).collect();
        assert_eq!(
            kept.iter().map(|l| l.text.as_str()).collect::<Vec<_>>(),
            ["line 2", "line 3", "line 4"]
        );
        buffer.clear();
        assert!(buffer.is_empty());
        assert_eq!(buffer.dropped(), 0);
    }

    /// A tail reads what has arrived and nothing twice, and it classifies as it goes.
    #[test]
    fn a_tail_reads_each_line_once() {
        let scratch = Scratch::new("once");
        scratch.write("[    1.000000] Linux version 6.18.49\n13:46:39 [WARN] vk-agent: slow\n");
        let mut tail = Tail::new(&scratch.0);

        let batch = tail.drain(1);
        assert_eq!(batch.epoch, 1);
        assert!(!batch.missing && !batch.restarted);
        assert_eq!(batch.lines.len(), 2);
        assert_eq!(batch.lines[0].source, Source::Kernel);
        assert_eq!(batch.lines[1].level, Some(Level::Warn));

        assert!(tail.drain(1).lines.is_empty(), "the same bytes came twice");

        // A line that arrives without its newline is not a line until it has one.
        scratch.append("still ");
        assert!(tail.drain(1).lines.is_empty());
        scratch.append("writing\n");
        assert_eq!(texts(&tail.drain(1).lines), ["still writing"]);
    }

    /// A console that is emptied and written again is read from its start, rather than the
    /// tail sitting past the end of a file that is now shorter than what it has read.
    #[test]
    fn a_log_that_shrank_is_read_from_its_start() {
        let scratch = Scratch::new("shrank");
        scratch.write("first boot line one\nfirst boot line two\n");
        let mut tail = Tail::new(&scratch.0);
        assert_eq!(tail.drain(1).lines.len(), 2);

        // Truncated in place and written again: the same file, a shorter one.
        let path = scratch.0.join(crate::run::CONSOLE_LOG);
        let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(0).unwrap();
        drop(file);
        scratch.append("second boot\n");

        let batch = tail.drain(1);
        assert!(batch.restarted, "a truncated console was not noticed");
        assert_eq!(texts(&batch.lines), ["second boot"]);
    }

    /// An environment that has never booted has no console, which is something to say on the
    /// screen rather than an error that ends the session.
    #[test]
    fn a_console_that_is_not_there_is_not_a_failure() {
        let scratch = Scratch::new("missing");
        let mut tail = Tail::new(&scratch.0);
        let batch = tail.drain(7);
        assert!(batch.missing);
        assert!(batch.lines.is_empty());
        assert_eq!(batch.epoch, 7);

        // And it is picked up when it appears, without the tail being rebuilt.
        scratch.write("13:46:39 [INFO] vk-agent: booting\n");
        let batch = tail.drain(7);
        assert!(!batch.missing);
        assert_eq!(batch.lines.len(), 1);
    }

    /// Only the end of a long console is scrollback anyone wants, and the window it opens in
    /// lands in the middle of a line — which is not a line and is not shown as one.
    #[test]
    fn a_long_console_is_read_from_near_its_end() {
        let scratch = Scratch::new("backlog");
        let filler = "x".repeat(4095);
        let mut text = String::new();
        for _ in 0..400 {
            text.push_str(&filler);
            text.push('\n');
        }
        text.push_str("the last line\n");
        scratch.write(&text);

        let mut tail = Tail::new(&scratch.0);
        let mut lines = Vec::new();
        // The backlog is larger than one pass, so it arrives over several of them.
        for _ in 0..16 {
            lines.extend(tail.drain(1).lines);
        }
        assert!(!lines.is_empty());
        assert_eq!(lines.last().map(|l| l.text.as_str()), Some("the last line"));
        assert!(
            lines
                .iter()
                .all(|l| l.text.len() == 4095 || l.text == "the last line"),
            "a fragment of a line was shown as a line"
        );
        assert!(lines.len() < 400, "the whole console was read back");
    }
}
