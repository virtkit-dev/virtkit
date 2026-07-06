//! `vk build` progress reporting — a Docker/buildkit-style overview of where a build is.
//!
//! One [`Progress`] is created per interactive build and shared (an `Arc`) across the
//! parallel stage workers. It tracks every step the build will touch — one `FROM` line
//! plus one line per `RUN`/`COPY` per needed stage, and a final `exporting` line.
//!
//! Rendering is delegated to [`indicatif`], which handles the terminal quirks that a
//! hand-rolled ANSI renderer gets wrong across emulators and multiplexers (tmux/zellij):
//! a header bar plus one live spinner line per in-flight step stay pinned at the bottom,
//! while completed/cached steps and each guest command's (stage-prefixed) output scroll
//! into history above them via [`MultiProgress::println`]. Three modes, picked once:
//! - **Tty**: the live indicatif dashboard (stdout is a terminal).
//! - **Plain**: no cursor control — each event and output line prints as a `#N …` line
//!   (buildkit `--progress=plain`). Used off-terminal (CI logs) or `VIRTKIT_PROGRESS=plain`.
//! - **Disabled**: every method is a no-op (used by `--print-plan`, which owns stdout).
//!
//! Because stages build concurrently, RUN output is routed here (via
//! [`crate::executor::OutputSink`]) rather than written straight to stdout, so it can be
//! line-buffered and stage-prefixed instead of interleaving unattributed.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use vk_core::messages::Fd;

use crate::executor::OutputSink;

/// Stage identity as the build driver knows it (the plan's stage index).
pub type StageId = usize;

/// Whether a step actually ran or was served from the instruction cache.
#[derive(Clone, Copy)]
pub enum Outcome {
    Ran,
    Cached,
}

/// One needed stage's display shape, handed to [`Progress::init`] in build order.
pub struct StageInit {
    pub id: StageId,
    pub name: String,
    /// the `FROM` line label, e.g. `FROM docker.io/library/rust:1.75`.
    pub base_label: String,
    /// one label per filesystem-changing step (`RUN …` / `COPY … -> …`), in order.
    pub steps: Vec<String>,
}

/// A stage's display metadata: its cells are numbered `1..=total`, cell 1 the `FROM`
/// line and cells `2..` the `RUN`/`COPY` steps, each with a global `#N` id.
struct StageMeta {
    name: String,
    total: usize,
    /// labels index 0 = `FROM`, 1.. = steps (so cell `num` is `labels[num - 1]`).
    labels: Vec<String>,
    /// global `#N` ids aligned with `labels`.
    seqs: Vec<usize>,
}

impl StageMeta {
    fn label(&self, num: usize) -> &str {
        &self.labels[num - 1]
    }
    fn seq(&self, num: usize) -> usize {
        self.seqs[num - 1]
    }
}

struct Meta {
    stages: HashMap<StageId, StageMeta>,
    /// the `#N` id of the `exporting to image` tail.
    export_seq: usize,
}

/// The indicatif dashboard: a rule + header bar pinned at the bottom, plus one live bar
/// per in-flight step/export. The rule divides the pinned live block from the scrolling
/// log above it.
struct Tty {
    mp: MultiProgress,
    /// a dim horizontal rule at the top of the pinned block (the visual separator).
    sep: ProgressBar,
    header: ProgressBar,
    /// running bars keyed by (stage, cell num); export uses [`EXPORT_KEY`].
    bars: Mutex<HashMap<(StageId, usize), ProgressBar>>,
}

/// bars-map key for the export tail (no real stage has this id).
const EXPORT_KEY: (StageId, usize) = (usize::MAX, 0);

enum Backend {
    Tty(Tty),
    Plain,
    Disabled,
}

pub struct Progress {
    backend: Backend,
    color: bool,
    start: Instant,
    meta: OnceLock<Meta>,
    done: AtomicUsize,
    total: AtomicUsize,
    /// partial (not-yet-newline-terminated) guest output per (stage, fd) — 1 stdout, 2 stderr.
    line_buf: Mutex<HashMap<(StageId, u8), Vec<u8>>>,
    /// the cell num currently running per stage, for prefixing that stage's output.
    cur: Mutex<HashMap<StageId, usize>>,
}

/// braille spinner frames + a trailing space (the finished frame, never shown — bars are
/// cleared, not finished in place).
const SPINNER_TICKS: &str = "⣷⣯⣟⡿⢿⣻⣽⣾ ";

impl Progress {
    /// A disabled reporter — every method is a no-op. For `--print-plan`.
    pub fn disabled() -> Arc<Self> {
        Arc::new(Progress::new_backend(Backend::Disabled, false))
    }

    /// A reporter for a real build. Picks the live dashboard vs plain streaming from stdout
    /// and the environment; [`Progress::init`] must be called before any event.
    pub fn new() -> Arc<Self> {
        let forced_plain = std::env::var("VIRTKIT_PROGRESS")
            .map(|v| v == "plain")
            .unwrap_or(false);
        let dumb = std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false);
        let color = std::env::var_os("NO_COLOR").is_none();
        if !forced_plain && !dumb && std::io::stdout().is_terminal() {
            Arc::new(Progress::new_backend(Backend::Tty(Tty::new()), color))
        } else {
            Arc::new(Progress::new_backend(Backend::Plain, false))
        }
    }

    fn new_backend(backend: Backend, color: bool) -> Self {
        Progress {
            backend,
            color,
            start: Instant::now(),
            meta: OnceLock::new(),
            done: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            line_buf: Mutex::new(HashMap::new()),
            cur: Mutex::new(HashMap::new()),
        }
    }

    /// Populate the step metadata (in build order, assigning each cell its `#N` id) and
    /// prime the header. No-op when disabled.
    pub fn init(self: &Arc<Self>, stages: Vec<StageInit>) {
        if matches!(self.backend, Backend::Disabled) {
            return;
        }
        let mut seq = 0usize;
        let mut total = 0usize;
        let mut map = HashMap::new();
        for s in stages {
            let cells = s.steps.len() + 1;
            total += cells;
            let mut labels = Vec::with_capacity(cells);
            let mut seqs = Vec::with_capacity(cells);
            let mut push = |label: String, labels: &mut Vec<String>, seqs: &mut Vec<usize>| {
                seq += 1;
                labels.push(label);
                seqs.push(seq);
            };
            push(s.base_label, &mut labels, &mut seqs);
            for st in s.steps {
                push(st, &mut labels, &mut seqs);
            }
            map.insert(
                s.id,
                StageMeta {
                    name: s.name,
                    total: cells,
                    labels,
                    seqs,
                },
            );
        }
        total += 1; // the exporting tail
        self.total.store(total, Ordering::Relaxed);
        let _ = self.meta.set(Meta {
            stages: map,
            export_seq: seq + 1,
        });
        if let Backend::Tty(tty) = &self.backend {
            tty.header.set_message(self.header_msg());
        }
    }

    /// The output sink for `stage`'s guest commands: routes each chunk here (line-buffered,
    /// stage-prefixed) in tty/plain mode, or inherits stdout when disabled.
    pub fn stage_sink(self: &Arc<Self>, stage: StageId) -> OutputSink {
        if matches!(self.backend, Backend::Disabled) {
            return OutputSink::Inherit;
        }
        let me = Arc::clone(self);
        OutputSink::Routed(Arc::new(move |fd, bytes| {
            let f = if matches!(fd, Fd::Stderr) { 2 } else { 1 };
            me.emit(stage, f, bytes);
        }))
    }

    pub fn base_start(&self, stage: StageId) {
        self.start_cell(stage, 1);
    }
    pub fn base_done(&self, stage: StageId, outcome: Outcome) {
        self.done_cell(stage, 1, outcome);
    }
    pub fn step_start(&self, stage: StageId, step: usize) {
        self.start_cell(stage, step + 2);
    }
    pub fn step_done(&self, stage: StageId, step: usize, outcome: Outcome) {
        self.flush_partial(stage);
        self.done_cell(stage, step + 2, outcome);
    }

    /// The whole stage restores from its final snapshot in one shot, so collapse it to a
    /// single `[stage] CACHED` line rather than itemizing every instruction. Every step
    /// still counts toward the header's done/total — the work is accounted, just not listed.
    pub fn stage_fully_cached(&self, stage: StageId) {
        let Some(meta) = self.meta.get() else { return };
        let Some(sm) = meta.stages.get(&stage) else {
            return;
        };
        self.done.fetch_add(sm.total, Ordering::Relaxed);
        match &self.backend {
            Backend::Tty(tty) => {
                let line = self.dim(&right_align(&format!(" => [{}]", sm.name), "CACHED"));
                let _ = tty.mp.println(line);
            }
            Backend::Plain => println!("#{} CACHED [{}]", sm.seq(1), sm.name),
            Backend::Disabled => {}
        }
        self.refresh_header();
    }

    pub fn export_start(&self) {
        match &self.backend {
            Backend::Tty(tty) => {
                let pb = tty.mp.add(ProgressBar::new_spinner());
                pb.set_style(self.step_style());
                pb.set_message("exporting to image".to_string());
                pb.enable_steady_tick(Duration::from_millis(120));
                tty.bars.lock().unwrap().insert(EXPORT_KEY, pb);
            }
            Backend::Plain => {
                let seq = self.meta.get().map(|m| m.export_seq).unwrap_or(0);
                println!("#{seq} exporting to image");
            }
            Backend::Disabled => {}
        }
    }

    pub fn export_done(&self) {
        self.done.fetch_add(1, Ordering::Relaxed);
        let seq = self.meta.get().map(|m| m.export_seq).unwrap_or(0);
        match &self.backend {
            Backend::Tty(tty) => {
                let elapsed = tty
                    .bars
                    .lock()
                    .unwrap()
                    .remove(&EXPORT_KEY)
                    .map(|pb| {
                        let e = pb.elapsed();
                        pb.finish_and_clear();
                        e
                    })
                    .unwrap_or_default();
                let line = self.green(&right_align(" => exporting to image", &fmt_dur(elapsed)));
                let _ = tty.mp.println(line);
                self.refresh_header();
            }
            Backend::Plain => println!("#{seq} DONE"),
            Backend::Disabled => {}
        }
    }

    /// Stop the renderer and leave a final summary line. Any still-running step is marked
    /// failed when `!ok`.
    pub fn finish(&self, ok: bool) {
        let tag = if ok { "FINISHED" } else { "FAILED" };
        match &self.backend {
            Backend::Tty(tty) => {
                for (_, pb) in tty.bars.lock().unwrap().drain() {
                    pb.finish_and_clear();
                }
                tty.header.finish_and_clear();
                tty.sep.finish_and_clear();
                let line = format!(
                    "[+] Building {} ({}/{}) {tag}",
                    fmt_dur(self.start.elapsed()),
                    self.done.load(Ordering::Relaxed),
                    self.total.load(Ordering::Relaxed),
                );
                let styled = if ok {
                    self.paint(&line, "\x1b[1;32m")
                } else {
                    self.paint(&line, "\x1b[1;31m")
                };
                let _ = tty.mp.println(styled);
            }
            Backend::Plain => println!("#0 {tag}"),
            Backend::Disabled => {}
        }
    }

    // ---- internals -------------------------------------------------------------------

    fn start_cell(&self, stage: StageId, num: usize) {
        self.cur.lock().unwrap().insert(stage, num);
        let Some(meta) = self.meta.get() else { return };
        let Some(sm) = meta.stages.get(&stage) else {
            return;
        };
        match &self.backend {
            Backend::Tty(tty) => {
                let pb = tty.mp.add(ProgressBar::new_spinner());
                pb.set_style(self.step_style());
                pb.set_message(format!(
                    "[{} {}/{}] {}",
                    sm.name,
                    num,
                    sm.total,
                    sm.label(num)
                ));
                pb.enable_steady_tick(Duration::from_millis(120));
                tty.bars.lock().unwrap().insert((stage, num), pb);
            }
            Backend::Plain => {
                println!(
                    "#{} [{} {}/{}] {}",
                    sm.seq(num),
                    sm.name,
                    num,
                    sm.total,
                    sm.label(num)
                );
            }
            Backend::Disabled => {}
        }
    }

    fn done_cell(&self, stage: StageId, num: usize, outcome: Outcome) {
        self.done.fetch_add(1, Ordering::Relaxed);
        // reclaim the running bar's elapsed (if this cell had one — cache hits never start).
        let elapsed = if let Backend::Tty(tty) = &self.backend {
            tty.bars.lock().unwrap().remove(&(stage, num)).map(|pb| {
                let e = pb.elapsed();
                pb.finish_and_clear();
                e
            })
        } else {
            None
        };
        if let Some(meta) = self.meta.get()
            && let Some(sm) = meta.stages.get(&stage)
        {
            self.emit_cell_line(sm, num, outcome, elapsed);
        }
        self.refresh_header();
    }

    /// Print a completed/cached cell as a permanent line above the dashboard (tty) or as a
    /// `#N …` line (plain).
    fn emit_cell_line(
        &self,
        sm: &StageMeta,
        num: usize,
        outcome: Outcome,
        elapsed: Option<Duration>,
    ) {
        match &self.backend {
            Backend::Tty(tty) => {
                let head = format!(" => [{} {}/{}] {}", sm.name, num, sm.total, sm.label(num));
                let line = match outcome {
                    Outcome::Cached => self.dim(&right_align(&head, "CACHED")),
                    Outcome::Ran => {
                        self.green(&right_align(&head, &fmt_dur(elapsed.unwrap_or_default())))
                    }
                };
                let _ = tty.mp.println(line);
            }
            Backend::Plain => match outcome {
                // a ran cell already printed its `#N [stage …]` start line, so just close it;
                // a cached cell never started, so print the whole line.
                Outcome::Ran => println!(
                    "#{} DONE {}",
                    sm.seq(num),
                    fmt_dur(elapsed.unwrap_or_default())
                ),
                Outcome::Cached => println!(
                    "#{} CACHED [{} {}/{}] {}",
                    sm.seq(num),
                    sm.name,
                    num,
                    sm.total,
                    sm.label(num)
                ),
            },
            Backend::Disabled => {}
        }
    }

    fn refresh_header(&self) {
        if let Backend::Tty(tty) = &self.backend {
            tty.header.set_message(self.header_msg());
        }
    }

    fn header_msg(&self) -> String {
        format!(
            "{}/{}",
            self.done.load(Ordering::Relaxed),
            self.total.load(Ordering::Relaxed)
        )
    }

    fn step_style(&self) -> ProgressStyle {
        // {wide_msg} takes the remaining width and truncates, so a long label can't wrap (a
        // wrapped bar line would break indicatif's line accounting); the trailing {elapsed}
        // is thereby pushed to the right margin, matching the completed lines' status column.
        ProgressStyle::with_template(" => {spinner:.green} {wide_msg} {elapsed:.dim}")
            .unwrap()
            .tick_chars(SPINNER_TICKS)
    }

    // ---- guest output routing --------------------------------------------------------

    /// Accept a chunk of a stage's guest output, split it into complete lines, and print
    /// each (stage-prefixed). A trailing partial line is held until the next chunk or
    /// [`flush_partial`].
    fn emit(&self, stage: StageId, fd: u8, bytes: &[u8]) {
        if matches!(self.backend, Backend::Disabled) {
            return;
        }
        let mut lines: Vec<String> = Vec::new();
        {
            let mut buf = self.line_buf.lock().unwrap();
            let b = buf.entry((stage, fd)).or_default();
            b.extend_from_slice(bytes);
            while let Some(nl) = b.iter().position(|&c| c == b'\n') {
                let line: Vec<u8> = b.drain(..=nl).collect();
                lines.push(String::from_utf8_lossy(&line[..line.len() - 1]).into_owned());
            }
        }
        self.print_output(stage, &lines);
    }

    /// Flush a stage's held partial line (e.g. a prompt with no trailing newline) at a step
    /// boundary so it is not swallowed.
    fn flush_partial(&self, stage: StageId) {
        let mut lines: Vec<String> = Vec::new();
        {
            let mut buf = self.line_buf.lock().unwrap();
            for fd in [1u8, 2] {
                if let Some(b) = buf.get_mut(&(stage, fd))
                    && !b.is_empty()
                {
                    lines.push(String::from_utf8_lossy(&std::mem::take(b)).into_owned());
                }
            }
        }
        self.print_output(stage, &lines);
    }

    fn print_output(&self, stage: StageId, lines: &[String]) {
        if lines.is_empty() {
            return;
        }
        let seq = self.output_seq(stage);
        match &self.backend {
            Backend::Tty(tty) => {
                for l in lines {
                    let _ = tty
                        .mp
                        .println(format!("{} {l}", self.dim(&format!("#{seq}"))));
                }
            }
            Backend::Plain => {
                for l in lines {
                    println!("#{seq} {l}");
                }
            }
            Backend::Disabled => {}
        }
    }

    /// The `#N` id of the stage's currently-running cell, for prefixing its output.
    fn output_seq(&self, stage: StageId) -> usize {
        let num = self.cur.lock().unwrap().get(&stage).copied().unwrap_or(1);
        self.meta
            .get()
            .and_then(|m| m.stages.get(&stage))
            .map(|sm| sm.seq(num))
            .unwrap_or(0)
    }

    // ---- styling ---------------------------------------------------------------------

    fn dim(&self, s: &str) -> String {
        self.paint(s, "\x1b[2m")
    }
    fn green(&self, s: &str) -> String {
        self.paint(s, "\x1b[32m")
    }
    fn paint(&self, s: &str, code: &str) -> String {
        if self.color {
            format!("{code}{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
}

impl Tty {
    fn new() -> Self {
        let mp = MultiProgress::with_draw_target(ProgressDrawTarget::stdout());
        // Rule first, so it sits at the top of the pinned block, just under the log.
        let sep = mp.add(ProgressBar::new_spinner());
        sep.set_style(ProgressStyle::with_template("{msg:.dim}").unwrap());
        sep.set_message("─".repeat(term_cols()));
        let header = mp.add(ProgressBar::new_spinner());
        header.set_style(
            ProgressStyle::with_template("{prefix} {elapsed} ({msg})")
                .unwrap()
                .tick_chars(SPINNER_TICKS),
        );
        header.set_prefix("[+] Building");
        header.enable_steady_tick(Duration::from_millis(120));
        Tty {
            mp,
            sep,
            header,
            bars: Mutex::new(HashMap::new()),
        }
    }
}

/// The controlling terminal's column count (for the separator rule), or 80 if unknown.
fn term_cols() -> usize {
    #[repr(C)]
    struct WinSize {
        row: libc::c_ushort,
        col: libc::c_ushort,
        x: libc::c_ushort,
        y: libc::c_ushort,
    }
    let mut ws = WinSize {
        row: 0,
        col: 0,
        x: 0,
        y: 0,
    };
    let r = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if r == 0 && ws.col > 0 {
        ws.col as usize
    } else {
        80
    }
}

/// Elapsed as `12.3s` (buildkit style).
fn fmt_dur(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f64())
}

/// `head` with `status` pushed to the terminal's right margin: pad between them so the
/// combined visible width fills the terminal (`head` clipped with an ellipsis if it would
/// otherwise collide with `status`). Terminals defer the last-column wrap, so a full-width
/// line does not spill onto the next row.
fn right_align(head: &str, status: &str) -> String {
    right_align_to(head, status, term_cols())
}

fn right_align_to(head: &str, status: &str, width: usize) -> String {
    let sw = status.chars().count();
    // reserve room for the status plus a one-space gap.
    let head = clip(head, width.saturating_sub(sw + 1));
    let pad = width.saturating_sub(head.chars().count() + sw).max(1);
    format!("{head}{}{status}", " ".repeat(pad))
}

/// Clip `s` to at most `max` characters, marking a truncation with a trailing ellipsis.
fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_stages() -> Vec<StageInit> {
        vec![
            StageInit {
                id: 0,
                name: "base".into(),
                base_label: "FROM rust:1.75".into(),
                steps: vec![],
            },
            StageInit {
                id: 1,
                name: "build".into(),
                base_label: "FROM base".into(),
                steps: vec!["RUN cargo fetch".into(), "RUN cargo build".into()],
            },
        ]
    }

    /// A full event sequence must not panic and must account every cell (each stage's
    /// FROM + steps, plus the export tail) into `done == total`. Runs in each live mode;
    /// the Tty backend's draw target is hidden under `cargo test` (stdout not a terminal),
    /// so it exercises the state machine without emitting escape codes.
    fn drive(p: &Arc<Progress>) {
        p.init(two_stages());
        p.stage_fully_cached(0); // base: FROM (1 cell)
        p.base_start(1);
        p.base_done(1, Outcome::Ran);
        p.step_start(1, 0);
        p.emit(1, 1, b"Compiling foo\npartial-no-newline");
        p.step_done(1, 0, Outcome::Ran);
        p.step_done(1, 1, Outcome::Cached); // a cache hit: no start
        p.export_start();
        p.export_done();
        p.finish(true);
        assert_eq!(
            p.done.load(Ordering::Relaxed),
            p.total.load(Ordering::Relaxed),
            "every cell (2 stages' cells + export) should be accounted"
        );
        assert_eq!(p.total.load(Ordering::Relaxed), 1 + 3 + 1);
    }

    #[test]
    fn plain_mode_drives_without_panicking() {
        drive(&Arc::new(Progress::new_backend(Backend::Plain, false)));
    }

    #[test]
    fn tty_mode_drives_without_panicking() {
        drive(&Arc::new(Progress::new_backend(
            Backend::Tty(Tty::new()),
            false,
        )));
    }

    /// The status column sits flush at the right margin: the line fills the width, ends
    /// with the status, and a label too long to fit is clipped with an ellipsis.
    #[test]
    fn right_align_fills_width_and_clips() {
        let short = right_align_to(" => [build 2/5] RUN x", "CACHED", 40);
        assert_eq!(short.chars().count(), 40);
        assert!(short.ends_with("CACHED"));

        let long = right_align_to(&format!(" => {}", "x".repeat(100)), "2.1s", 40);
        assert_eq!(long.chars().count(), 40);
        assert!(long.ends_with("2.1s"));
        assert!(
            long.contains('…'),
            "an over-long label is clipped: {long:?}"
        );
    }

    #[test]
    fn disabled_is_inert() {
        let p = Arc::new(Progress::new_backend(Backend::Disabled, false));
        p.init(two_stages());
        p.base_start(1);
        p.base_done(1, Outcome::Ran);
        p.finish(true);
        assert!(matches!(p.stage_sink(1), OutputSink::Inherit));
    }
}
