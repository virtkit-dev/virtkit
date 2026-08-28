//! `vk build` progress reporting — a Docker/buildkit-style overview of where a build is.
//!
//! One [`Progress`] is created per interactive build and shared (an `Arc`) across the
//! parallel stage workers. It tracks every step the build will touch — one `FROM` line
//! plus one line per `RUN`/`COPY` per needed stage, and a final `exporting` line.
//!
//! Rendering is delegated to [`indicatif`], which handles the terminal quirks that a
//! hand-rolled ANSI renderer gets wrong across emulators and multiplexers (tmux/zellij) —
//! all but a terminal resize, which [`ResizeTerm`] recovers from on indicatif's behalf:
//! a header bar plus one live spinner line per in-flight step stay pinned at the bottom,
//! while completed/cached steps and each guest command's (stage-prefixed) output scroll
//! into history above them while the live block is temporarily suspended. Three modes,
//! picked once:
//! - **Tty**: the live indicatif dashboard (stdout is a terminal).
//! - **Plain**: no cursor control — each event and output line prints as a `#N …` line
//!   (buildkit `--progress=plain`). Used off-terminal (CI logs) or `VIRTKIT_PROGRESS=plain`.
//! - **Disabled**: every method is a no-op (used by `--print-plan`, which owns stdout).
//!
//! Because stages build concurrently, RUN output is routed here (via
//! [`crate::executor::OutputSink`]) rather than written straight to stdout, so it can be
//! line-buffered and stage-prefixed instead of interleaving unattributed.

use std::collections::HashMap;
use std::fmt;
use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle, TermLike};
use vk_core::messages::Fd;
use vk_core::pty::get_winsize;

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
    /// the `#N` id of each `exporting to image` tail — one per output image (a unified
    /// multi-service build exports several).
    export_seqs: Vec<usize>,
}

/// The indicatif dashboard: a rule + header bar pinned at the bottom, plus one live bar
/// per in-flight step/export. The rule divides the pinned live block from the scrolling
/// log above it.
struct Tty {
    mp: MultiProgress,
    /// a dim horizontal rule at the top of the pinned block (the visual separator).
    sep: ProgressBar,
    header: ProgressBar,
    /// running bars keyed by (stage, cell num); export uses [`export_key`].
    bars: Mutex<HashMap<(StageId, usize), ProgressBar>>,
    /// the most recently started cell's label, mirrored into the terminal title so a parallel
    /// build's title tracks the latest work item (empty until the first cell starts).
    activity: Mutex<String>,
    /// whether to emit terminal-title (OSC) updates; suppressed by `VIRTKIT_NO_TITLE`.
    title: bool,
}

/// bars-map key for the `index`-th export tail (no real stage has this id, so the
/// `usize::MAX` stage never collides with a real stage's cells).
fn export_key(index: usize) -> (StageId, usize) {
    (usize::MAX, index)
}

/// bars-map cell num for a stage's transient "restoring" spinner (real cells are 1..=total).
const RESTORE_NUM: usize = 0;

/// bars-map cell num for a stage's transient "finishing" spinner (real cells are 1..=total).
const FINISH_NUM: usize = usize::MAX;

/// bars-map cell num for a stage's transient "waiting for a concurrent build" spinner (real
/// cells are 1..=total; distinct from [`RESTORE_NUM`] and [`FINISH_NUM`]).
const WAIT_LOCK_NUM: usize = usize::MAX - 1;

/// bars-map cell num for a stage's transient live "output tail" — the current partial
/// (carriage-return-updated) guest line, shown in place until a newline commits it to the
/// scrolling log (real cells are 1..=total; distinct from the other transient sentinels).
const OUTPUT_TAIL_NUM: usize = usize::MAX - 2;

/// bars-map cell num for a stage's transient "waiting for host memory" spinner (real cells
/// are 1..=total; distinct from the other transient sentinels).
const WAIT_MEM_NUM: usize = usize::MAX - 3;

enum Backend {
    Tty(Box<Tty>),
    Plain,
    /// Plain-style `#N …` lines routed to a sink instead of stdout — the streamed
    /// on-demand build the service manager forwards to the guest that requested a
    /// service start, so its `vk service up` sees live build progress.
    Routed(super::ProgressSink),
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
    /// when each in-flight cell started, keyed by (stage, cell num). Kept here rather than
    /// read off the tty bar so a plain/routed build (a git hook, a CI log) reports real
    /// durations too — that is precisely where the numbers are read after the fact.
    cell_start: Mutex<HashMap<(StageId, usize), Instant>>,
    /// a step's command run-time, frozen at [`Progress::step_committing`] so the emitted line
    /// reports how long the RUN/COPY took — not that plus the snapshot + cache push that
    /// `cache_save` folds in after it (which would inflate a trivial step to minutes).
    cell_ran: Mutex<HashMap<(StageId, usize), Duration>>,
    /// cached cells counted per stage but not yet materialized — a cache hit resolves an
    /// instruction instantly, but its filesystem is in hand only once the stage's snapshot
    /// is restored. Held here until [`Progress::restore_done`] moves it into `done`, so the
    /// header tracks real materialization instead of racing ahead of a running restore pull.
    pending: Mutex<HashMap<StageId, usize>>,
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
            Arc::new(Progress::new_backend(
                Backend::Tty(Box::new(Tty::new())),
                color,
            ))
        } else {
            Arc::new(Progress::new_backend(Backend::Plain, false))
        }
    }

    /// A reporter that streams plain `#N …` lines to `sink` instead of stdout — used to
    /// forward an in-process build's progress to a remote consumer (the guest that asked the
    /// service manager to bring a service up). Like [`Progress::new`], [`Progress::init`]
    /// must be called before any event.
    pub fn routed(sink: super::ProgressSink) -> Arc<Self> {
        Arc::new(Progress::new_backend(Backend::Routed(sink), false))
    }

    /// Emit one already-formatted plain line to the plain/routed target — stdout for the
    /// plain backend, the sink for a routed (streamed) build. Only the `Plain`/`Routed`
    /// event arms call it; the tty/disabled backends render (or drop) their own lines.
    fn plain_line(&self, args: std::fmt::Arguments) {
        match &self.backend {
            Backend::Plain => println!("{args}"),
            Backend::Routed(sink) => sink(&std::fmt::format(args)),
            Backend::Tty(_) | Backend::Disabled => {}
        }
    }

    /// Emit one free-form line into the build's log — a note from the driver rather than a
    /// step event. Routed like every other line, because the tty backend's pinned block is
    /// drawing (and steady-ticking) from the moment the reporter exists, so a raw write would
    /// land inside it: the tty prints above that block with indicatif suspended, the plain
    /// backend writes stdout, and a routed build streams the line to its consumer.
    pub fn note(&self, line: &str) {
        match &self.backend {
            Backend::Tty(tty) => {
                let _ = tty.println(self.dim(line));
            }
            Backend::Plain | Backend::Routed(_) => self.plain_line(format_args!("{line}")),
            Backend::Disabled => {}
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
            cell_start: Mutex::new(HashMap::new()),
            cell_ran: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Populate the step metadata (in build order, assigning each cell its `#N` id) and
    /// prime the header. `exports` is the number of `exporting to image` tails (one per
    /// output image — a unified multi-service build produces several). No-op when disabled.
    pub fn init(self: &Arc<Self>, stages: Vec<StageInit>, exports: usize) {
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
        let export_seqs: Vec<usize> = (0..exports).map(|i| seq + 1 + i).collect();
        total += exports; // one exporting tail per output image
        self.total.store(total, Ordering::Relaxed);
        let _ = self.meta.set(Meta {
            stages: map,
            export_seqs,
        });
        self.refresh_header();
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
    /// The step's command has finished; its snapshot + cache push are about to run. Freeze
    /// the command's elapsed for the final line and switch the live bar to a dim "caching"
    /// state, so the dashboard keeps moving through the commit instead of appearing to stall
    /// on a step whose command is already done.
    pub fn step_committing(&self, stage: StageId, step: usize) {
        let num = step + 2;
        // Copy the Instant out so cell_start and cell_ran are never held together
        // (parallel stage workers would otherwise race the locks in opposite orders).
        let started = self.cell_start.lock().unwrap().get(&(stage, num)).copied();
        if let Some(started) = started {
            self.cell_ran
                .lock()
                .unwrap()
                .insert((stage, num), started.elapsed());
        }
        if let Backend::Tty(tty) = &self.backend
            && let Some(pb) = tty.bars.lock().unwrap().get(&(stage, num))
        {
            pb.set_style(self.commit_style());
        }
    }
    pub fn step_done(&self, stage: StageId, step: usize, outcome: Outcome) {
        self.flush_partial(stage);
        self.done_cell(stage, step + 2, outcome);
    }

    /// The step's command failed. Emit its line marked `FAILED` and drop its live bar, so
    /// the dashboard shows which instruction stopped the build instead of clearing the
    /// in-flight line (which would leave only the error text below the CACHED lines).
    pub fn step_failed(&self, stage: StageId, step: usize) {
        self.flush_partial(stage);
        let num = step + 2;
        self.cell_start.lock().unwrap().remove(&(stage, num));
        self.cell_ran.lock().unwrap().remove(&(stage, num));
        let Some(meta) = self.meta.get() else { return };
        let Some(sm) = meta.stages.get(&stage) else {
            return;
        };
        match &self.backend {
            Backend::Tty(tty) => {
                if let Some(pb) = tty.bars.lock().unwrap().remove(&(stage, num)) {
                    pb.finish_and_clear();
                }
                let head = format!(" => [{} {}/{}] {}", sm.name, num, sm.total, sm.label(num));
                let line = self.paint(&right_align(&head, "FAILED"), "\x1b[31m");
                let _ = tty.println(line);
            }
            Backend::Plain | Backend::Routed(_) => {
                self.plain_line(format_args!("#{} ERROR", sm.seq(num)))
            }
            Backend::Disabled => {}
        }
    }

    /// The whole stage restores from its final snapshot in one shot, so collapse it to a
    /// single `[stage] CACHED` line rather than itemizing every instruction. Every step
    /// still counts toward the header's done/total — the work is accounted, just not listed.
    pub fn stage_fully_cached(&self, stage: StageId) {
        let Some(meta) = self.meta.get() else { return };
        let Some(sm) = meta.stages.get(&stage) else {
            return;
        };
        // Counted into `done` only once the stage's snapshot is restored (restore_done).
        *self.pending.lock().unwrap().entry(stage).or_default() += sm.total;
        match &self.backend {
            Backend::Tty(tty) => {
                let line = self.dim(&right_align(&format!(" => [{}]", sm.name), "CACHED"));
                let _ = tty.println(line);
            }
            Backend::Plain | Backend::Routed(_) => {
                self.plain_line(format_args!("#{} CACHED [{}]", sm.seq(1), sm.name))
            }
            Backend::Disabled => {}
        }
        self.refresh_header();
    }

    /// Show a transient spinner while a stage's cached snapshot is pulled from the registry
    /// and reassembled — an otherwise silent, sometimes long gap that runs after the stage's
    /// cells are already marked CACHED (so the header advances with nothing visibly running).
    /// Cleared by [`Progress::restore_done`], or drained by [`Progress::finish`] on error.
    pub fn restore_start(&self, stage: StageId, name: &str) {
        if let Backend::Tty(tty) = &self.backend {
            let pb = tty.mp.add(ProgressBar::new_spinner());
            pb.set_style(self.step_style());
            pb.set_message(format!("[{name}] restoring cached image"));
            pb.enable_steady_tick(Duration::from_millis(120));
            tty.bars.lock().unwrap().insert((stage, RESTORE_NUM), pb);
        }
    }
    pub fn restore_done(&self, stage: StageId) {
        // The snapshot is now materialized: the stage's cached cells become done.
        let n = self.pending.lock().unwrap().remove(&stage).unwrap_or(0);
        if n > 0 {
            self.done.fetch_add(n, Ordering::Relaxed);
        }
        if let Backend::Tty(tty) = &self.backend
            && let Some(pb) = tty.bars.lock().unwrap().remove(&(stage, RESTORE_NUM))
        {
            pb.finish_and_clear();
        }
        self.refresh_header();
    }

    /// Show a transient spinner while this stage waits on a cross-runner build-once lock a peer
    /// holds — the peer is building the same stage, so we park until it releases and then restore
    /// its result rather than rebuild. `holder` names who owns the build. Cleared by
    /// [`Progress::wait_lock_done`], or drained by [`Progress::finish`] on error.
    pub fn wait_lock_start(&self, stage: StageId, name: &str, holder: &str) {
        let msg = format!("[{name}] waiting for a concurrent build (held by {holder})");
        match &self.backend {
            Backend::Tty(tty) => {
                let pb = tty.mp.add(ProgressBar::new_spinner());
                pb.set_style(self.step_style());
                pb.set_message(msg);
                pb.enable_steady_tick(Duration::from_millis(120));
                tty.bars.lock().unwrap().insert((stage, WAIT_LOCK_NUM), pb);
            }
            // Off-terminal (CI logs) the wait is exactly where a stuck build is diagnosed, so
            // emit the holder as a plain line too.
            Backend::Plain | Backend::Routed(_) => self.plain_line(format_args!("{msg}")),
            Backend::Disabled => {}
        }
    }
    pub fn wait_lock_done(&self, stage: StageId) {
        if let Backend::Tty(tty) = &self.backend
            && let Some(pb) = tty.bars.lock().unwrap().remove(&(stage, WAIT_LOCK_NUM))
        {
            pb.finish_and_clear();
        }
    }

    /// Show a transient spinner while this stage waits for the host to have room for its
    /// guest — it holds a job slot but not yet the memory, and without a line of its own the
    /// wait is indistinguishable from a guest that is slow to boot. `short` is how many MiB
    /// it is waiting on. Cleared by [`Progress::wait_mem_done`], or drained by
    /// [`Progress::finish`] on error.
    pub fn wait_mem_start(&self, stage: StageId, name: &str, short: u64) {
        let msg = format!("[{name}] waiting for host memory ({short} MiB short)");
        match &self.backend {
            Backend::Tty(tty) => {
                let pb = tty.mp.add(ProgressBar::new_spinner());
                pb.set_style(self.step_style());
                pb.set_message(msg);
                pb.enable_steady_tick(Duration::from_millis(120));
                tty.bars.lock().unwrap().insert((stage, WAIT_MEM_NUM), pb);
            }
            // Off-terminal (CI logs) a build that is waiting on memory rather than working
            // is exactly what someone reading the log needs told.
            Backend::Plain | Backend::Routed(_) => self.plain_line(format_args!("{msg}")),
            Backend::Disabled => {}
        }
    }

    /// Clear [`Progress::wait_mem_start`]'s spinner. `started` says why the wait ended: the
    /// host found room, or the build was cancelled and the stage was let through to fail its
    /// own check. Off-terminal only the first prints the other half of the pair — a log that
    /// shows every park and no resume cannot tell a two-second wait from a twenty-minute
    /// one, but a cancelled build must not claim a stage is starting.
    pub fn wait_mem_done(&self, stage: StageId, name: &str, started: bool) {
        match &self.backend {
            Backend::Tty(tty) => {
                if let Some(pb) = tty.bars.lock().unwrap().remove(&(stage, WAIT_MEM_NUM)) {
                    pb.finish_and_clear();
                }
            }
            Backend::Plain | Backend::Routed(_) if started => {
                self.plain_line(format_args!("[{name}] host memory available, starting"));
            }
            Backend::Plain | Backend::Routed(_) | Backend::Disabled => {}
        }
    }

    /// Show a transient spinner while a stage's guest shuts down at `stage_end` — after the last
    /// step's bar is cleared but before the stage counts as done, an otherwise silent gap with
    /// the header frozen and nothing visibly running. The final cache upload no longer blocks
    /// here (it drains in the background), so this covers only the guest flush + shutdown.
    /// Cleared by [`Progress::stage_finishing_done`], or drained by [`Progress::finish`] on error.
    pub fn stage_finishing_start(&self, stage: StageId, name: &str) {
        if let Backend::Tty(tty) = &self.backend {
            let pb = tty.mp.add(ProgressBar::new_spinner());
            pb.set_style(self.step_style());
            pb.set_message(format!("[{name}] flushing cache"));
            pb.enable_steady_tick(Duration::from_millis(120));
            tty.bars.lock().unwrap().insert((stage, FINISH_NUM), pb);
        }
    }
    pub fn stage_finishing_done(&self, stage: StageId) {
        if let Backend::Tty(tty) = &self.backend
            && let Some(pb) = tty.bars.lock().unwrap().remove(&(stage, FINISH_NUM))
        {
            pb.finish_and_clear();
        }
    }

    pub fn export_start(&self, index: usize) {
        match &self.backend {
            Backend::Tty(tty) => {
                let pb = tty.mp.add(ProgressBar::new_spinner());
                pb.set_style(self.step_style());
                pb.set_message("exporting to image".to_string());
                pb.enable_steady_tick(Duration::from_millis(120));
                tty.bars.lock().unwrap().insert(export_key(index), pb);
            }
            Backend::Plain | Backend::Routed(_) => {
                let seq = self.export_seq(index);
                self.plain_line(format_args!("#{seq} exporting to image"));
            }
            Backend::Disabled => {}
        }
    }

    pub fn export_done(&self, index: usize) {
        self.done.fetch_add(1, Ordering::Relaxed);
        let seq = self.export_seq(index);
        match &self.backend {
            Backend::Tty(tty) => {
                let elapsed = tty
                    .bars
                    .lock()
                    .unwrap()
                    .remove(&export_key(index))
                    .map(|pb| {
                        let e = pb.elapsed();
                        pb.finish_and_clear();
                        e
                    })
                    .unwrap_or_default();
                let line = self.green(&right_align(" => exporting to image", &fmt_dur(elapsed)));
                let _ = tty.println(line);
                self.refresh_header();
            }
            Backend::Plain | Backend::Routed(_) => self.plain_line(format_args!("#{seq} DONE")),
            Backend::Disabled => {}
        }
    }

    /// The `#N` id of the `index`-th export tail (0 if init has not run / index is out
    /// of range — plain-mode cosmetics only).
    fn export_seq(&self, index: usize) -> usize {
        self.meta
            .get()
            .and_then(|m| m.export_seqs.get(index).copied())
            .unwrap_or(0)
    }

    /// Stop the renderer and leave a final summary line. Any still-running step is marked
    /// failed when `!ok`.
    pub fn finish(&self, ok: bool) {
        let tag = if ok { "FINISHED" } else { "FAILED" };
        // A successful build restores every cached prefix, so all pending is already in
        // `done`; fold in any remainder (a build that stopped before a restore) so the final
        // count is never stuck below total.
        let leftover: usize = self.pending.lock().unwrap().drain().map(|(_, n)| n).sum();
        if leftover > 0 {
            self.done.fetch_add(leftover, Ordering::Relaxed);
        }
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
                let _ = tty.println(styled);
                tty.set_title(&format!(
                    "vk build {tag} ({}/{})",
                    self.done.load(Ordering::Relaxed),
                    self.total.load(Ordering::Relaxed),
                ));
            }
            Backend::Plain | Backend::Routed(_) => self.plain_line(format_args!("#0 {tag}")),
            Backend::Disabled => {}
        }
    }

    // ---- internals -------------------------------------------------------------------

    fn start_cell(&self, stage: StageId, num: usize) {
        self.cur.lock().unwrap().insert(stage, num);
        self.cell_start
            .lock()
            .unwrap()
            .insert((stage, num), Instant::now());
        let Some(meta) = self.meta.get() else { return };
        let Some(sm) = meta.stages.get(&stage) else {
            return;
        };
        match &self.backend {
            Backend::Tty(tty) => {
                let msg = format!("[{} {}/{}] {}", sm.name, num, sm.total, sm.label(num));
                let pb = tty.mp.add(ProgressBar::new_spinner());
                pb.set_style(self.step_style());
                pb.set_message(msg.clone());
                pb.enable_steady_tick(Duration::from_millis(120));
                tty.bars.lock().unwrap().insert((stage, num), pb);
                *tty.activity.lock().unwrap() = msg;
                self.refresh_header();
            }
            Backend::Plain | Backend::Routed(_) => {
                self.plain_line(format_args!(
                    "#{} [{} {}/{}] {}",
                    sm.seq(num),
                    sm.name,
                    num,
                    sm.total,
                    sm.label(num)
                ));
            }
            Backend::Disabled => {}
        }
    }

    fn done_cell(&self, stage: StageId, num: usize, outcome: Outcome) {
        match outcome {
            // A ran cell is materialized now; a cached cell counts only once its stage's
            // snapshot is restored (restore_done), so the header does not race a restore.
            Outcome::Ran => {
                self.done.fetch_add(1, Ordering::Relaxed);
            }
            Outcome::Cached => {
                *self.pending.lock().unwrap().entry(stage).or_default() += 1;
            }
        }
        // reclaim this cell's elapsed (None if it never started — cache hits don't).
        // A step reports its frozen command time (see `step_committing`); the base has none
        // frozen, so it falls back to the cell's full lifetime (its materialize time).
        let started = self.cell_start.lock().unwrap().remove(&(stage, num));
        let ran = self.cell_ran.lock().unwrap().remove(&(stage, num));
        let elapsed = ran.or_else(|| started.map(|t| t.elapsed()));
        if let Backend::Tty(tty) = &self.backend
            && let Some(pb) = tty.bars.lock().unwrap().remove(&(stage, num))
        {
            pb.finish_and_clear();
        }
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
                let _ = tty.println(line);
            }
            Backend::Plain | Backend::Routed(_) => match outcome {
                // a ran cell already printed its `#N [stage …]` start line, so just close it;
                // a cached cell never started, so print the whole line.
                Outcome::Ran => self.plain_line(format_args!(
                    "#{} DONE {}",
                    sm.seq(num),
                    fmt_dur(elapsed.unwrap_or_default())
                )),
                Outcome::Cached => self.plain_line(format_args!(
                    "#{} CACHED [{} {}/{}] {}",
                    sm.seq(num),
                    sm.name,
                    num,
                    sm.total,
                    sm.label(num)
                )),
            },
            Backend::Disabled => {}
        }
    }

    fn refresh_header(&self) {
        if let Backend::Tty(tty) = &self.backend {
            tty.header.set_message(self.header_msg());
            let activity = tty.activity.lock().unwrap();
            tty.set_title(&build_title(&self.header_msg(), &activity));
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

    /// The style for a step whose command has finished and is committing to the cache: a
    /// dimmed label with a `caching` marker, distinguishing the snapshot/push phase from the
    /// still-running command above it.
    fn commit_style(&self) -> ProgressStyle {
        ProgressStyle::with_template(" => {spinner:.yellow} {wide_msg:.dim} caching {elapsed:.dim}")
            .unwrap()
            .tick_chars(SPINNER_TICKS)
    }

    // ---- guest output routing --------------------------------------------------------

    /// Accept a chunk of a stage's guest output. Complete (newline-terminated) lines are
    /// printed to the scrolling log, each with its carriage-return overwrites collapsed to the
    /// final visible text. The remaining partial — including a carriage-return progress frame
    /// with no trailing newline — updates the stage's live [output tail](Self::set_output_tail)
    /// in place, so a `foo\rbar\r…` progress stream refreshes one pinned line instead of being
    /// buffered whole and dumped as an unwrapped mega-line that derails the dashboard.
    /// Progress is emitted on a single stream in practice, so the tail tracks whichever fd
    /// last carried a partial.
    fn emit(&self, stage: StageId, fd: u8, bytes: &[u8]) {
        if matches!(self.backend, Backend::Disabled) {
            return;
        }
        let (lines, tail) = {
            let mut buf = self.line_buf.lock().unwrap();
            fold_output(buf.entry((stage, fd)).or_default(), bytes)
        };
        self.print_output(stage, &lines);
        self.set_output_tail(stage, (!tail.is_empty()).then_some(tail.as_str()));
    }

    /// Commit a stage's held partial line (a prompt or a final progress frame with no trailing
    /// newline) to the scrolling log at a step boundary so it is not swallowed, and clear the
    /// live output tail (now committed above).
    fn flush_partial(&self, stage: StageId) {
        let mut lines: Vec<String> = Vec::new();
        {
            let mut buf = self.line_buf.lock().unwrap();
            for fd in [1u8, 2] {
                if let Some(b) = buf.get_mut(&(stage, fd))
                    && !b.is_empty()
                {
                    let visible = visible_tail(&std::mem::take(b));
                    if !visible.is_empty() {
                        lines.push(visible);
                    }
                }
            }
        }
        self.print_output(stage, &lines);
        self.set_output_tail(stage, None);
    }

    /// Update `stage`'s transient live output-tail cell to `text`, or clear it when `None`.
    /// Tty only: rendered as a width-truncated line ({wide_msg}) in the pinned block, so a
    /// carriage-return progress frame updates in place and never wraps — a wrapped line would
    /// break indicatif's line accounting, the very corruption this cell exists to avoid.
    /// Plain/routed backends have no in-place line, so a partial surfaces only when a newline
    /// (or [`flush_partial`](Self::flush_partial)) commits it.
    fn set_output_tail(&self, stage: StageId, text: Option<&str>) {
        let Backend::Tty(tty) = &self.backend else {
            return;
        };
        match text {
            Some(t) if !t.is_empty() => {
                let prefix = self.dim(&format!("#{}", self.output_seq(stage)));
                let msg = format!("{prefix} {t}");
                let mut bars = tty.bars.lock().unwrap();
                bars.entry((stage, OUTPUT_TAIL_NUM))
                    .or_insert_with(|| {
                        let pb = tty.mp.add(ProgressBar::new_spinner());
                        pb.set_style(ProgressStyle::with_template("{wide_msg}").unwrap());
                        pb
                    })
                    .set_message(msg);
            }
            _ => {
                if let Some(pb) = tty.bars.lock().unwrap().remove(&(stage, OUTPUT_TAIL_NUM)) {
                    pb.finish_and_clear();
                }
            }
        }
    }

    fn print_output(&self, stage: StageId, lines: &[String]) {
        if lines.is_empty() {
            return;
        }
        let seq = self.output_seq(stage);
        match &self.backend {
            Backend::Tty(tty) => {
                let prefix = self.dim(&format!("#{seq}"));
                let _ = tty.print_lines(lines.iter().map(|l| format!("{prefix} {l}")));
            }
            Backend::Plain | Backend::Routed(_) => {
                for l in lines {
                    self.plain_line(format_args!("#{seq} {l}"));
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
        // `ProgressDrawTarget::stdout` cannot be used — the resize recovery needs `ResizeTerm` as
        // the target — so its off-a-terminal check is made here instead, and it is the whole of
        // what is reproduced. `stdout` also hides on `console::is_dumb()`, which counts an *unset*
        // `TERM` as dumb where `Progress::new` counts only `TERM=dumb`: a real terminal with no
        // `TERM` used to reach a hidden target and so print nothing at all, neither dashboard nor
        // step log.
        let target = if io::stdout().is_terminal() {
            // 20 Hz, the refresh rate `ProgressDrawTarget::stdout` sets.
            ProgressDrawTarget::term_like_with_hz(Box::new(ResizeTerm::new()), 20)
        } else {
            ProgressDrawTarget::hidden()
        };
        let mp = MultiProgress::with_draw_target(target);
        // Rule first, so it sits at the top of the pinned block, just under the log.
        let sep = sep_bar(&mp);
        let header = mp.add(ProgressBar::new_spinner());
        header.set_style(
            ProgressStyle::with_template("{prefix} {elapsed} ({msg})")
                .unwrap()
                .tick_chars(SPINNER_TICKS),
        );
        header.set_prefix("[+] Building");
        header.enable_steady_tick(Duration::from_millis(120));
        let tty = Tty {
            mp,
            sep,
            header,
            bars: Mutex::new(HashMap::new()),
            activity: Mutex::new(String::new()),
            title: std::env::var_os("VIRTKIT_NO_TITLE").is_none(),
        };
        // Save the terminal's current title on the xterm title stack so it can be restored on
        // exit (paired with the `\x1b[23;2t` pop in `Drop`). Must precede any `set_title`.
        tty.write_seq("\x1b[22;2t");
        tty
    }

    /// Write a raw control sequence to the terminal, serialized against indicatif's draws by
    /// the shared stdout lock. No-op when title updates are disabled or the target is hidden.
    /// The save (`Tty::new`) and restore (`Drop`) go through the same gate, and the draw
    /// target is chosen once in `Tty::new`, so `is_hidden()` cannot change under the dashboard
    /// and the stack push/pop stay paired.
    fn write_seq(&self, seq: &str) {
        if !self.title || self.mp.is_hidden() {
            return;
        }
        let mut out = io::stdout().lock();
        let _ = out.write_all(seq.as_bytes());
        let _ = out.flush();
    }

    /// Set the terminal window title (OSC 2, BEL-terminated). No visible glyph, so it needs no
    /// indicatif suspend; the shared stdout lock keeps the sequence intact against indicatif.
    fn set_title(&self, title: &str) {
        self.write_seq(&format!("\x1b]2;{title}\x07"));
    }

    fn println(&self, line: impl AsRef<str>) -> io::Result<()> {
        self.print_lines(std::iter::once(line))
    }

    fn print_lines<I, S>(&self, lines: I) -> io::Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        if self.mp.is_hidden() {
            return Ok(());
        }
        // `MultiProgress::println` misaccounts wrapped text rows in indicatif 0.18, which
        // can leave stale pinned separator rows behind. Suspending lets stdout perform a
        // normal line write while indicatif only clears/redraws the live block.
        self.mp.suspend(|| {
            let mut out = io::stdout().lock();
            for line in lines {
                writeln!(out, "{}", line.as_ref())?;
            }
            out.flush()
        })
    }
}

impl Drop for Tty {
    /// Restore the terminal title saved in [`Tty::new`] (pop the xterm title stack), so `vk`
    /// leaves the title as it found it — on success, failure, or an early error return.
    fn drop(&mut self) {
        self.write_seq("\x1b[23;2t");
    }
}

/// The [`TermLike`] indicatif draws the pinned block through: stdout, plus the terminal-resize
/// recovery indicatif does not do itself.
struct ResizeTerm {
    state: Mutex<Frame>,
    /// the terminal's `(columns, rows)` source — [`term_size`], swapped out by the tests.
    size: Box<dyn Fn() -> (u16, u16) + Send + Sync>,
    /// where a finished frame goes — [`write_stdout`], swapped out by the tests.
    sink: Box<FrameSink>,
}

/// Where [`ResizeTerm`] writes a finished frame. A named type because the boxed signature
/// trips `clippy::type_complexity` inline.
type FrameSink = dyn Fn(&[u8]) -> io::Result<()> + Send + Sync;

impl fmt::Debug for ResizeTerm {
    /// [`TermLike`] requires it. Neither hook has a representation worth printing, so the
    /// bookkeeping is the whole of it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResizeTerm")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// [`ResizeTerm`]'s per-draw bookkeeping.
#[derive(Debug, Default)]
struct Frame {
    /// the open draw's bytes, held back until it ends and then written under one stdout
    /// lock, so a frame never reaches the terminal half-written.
    buf: Vec<u8>,
    /// the width the frame now on screen was drawn at, or `None` when the screen holds no
    /// frame: before the first draw, and after a draw that emitted no line (the erase half of
    /// `MultiProgress::suspend`).
    drawn_width: Option<u16>,
    /// the width the open draw is laying its lines out at: sampled when the draw opens and
    /// again on each of indicatif's `width` calls, the last of which is the one it lays the
    /// frame out against.
    render_width: u16,
    /// a draw is open: the first byte-emitting call opens one, `flush` closes it.
    drawing: bool,
    /// the open draw is the first at a new width, so its erase phase is suppressed.
    recovering: bool,
    /// the open draw still owes the fresh row a recovery starts on. It is opened by the
    /// draw's first line, or by `end_draw` when there is none (the erase half of
    /// `MultiProgress::suspend`) — either way it only ends the stale frame's last row, so the
    /// log lines that follow start clean and no blank row is spent.
    open_row: bool,
    /// the open draw has emitted a line, so it leaves a frame on screen.
    wrote: bool,
}

impl ResizeTerm {
    fn new() -> Self {
        Self::with(term_size, write_stdout)
    }

    fn with(
        size: impl Fn() -> (u16, u16) + Send + Sync + 'static,
        sink: impl Fn(&[u8]) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        ResizeTerm {
            state: Mutex::new(Frame::default()),
            size: Box::new(size),
            sink: Box::new(sink),
        }
    }

    /// Open a draw (a no-op once one is open) and decide whether it has to recover from a
    /// resize. Every [`TermLike`] method that appends a byte calls this first, so the decision
    /// is taken from the state the draw actually starts in whichever call indicatif leads
    /// with — today always `move_cursor_up`, but nothing in the trait promises that.
    fn begin(&self, f: &mut Frame) {
        if f.drawing {
            return;
        }
        let cols = (self.size)().0;
        f.drawing = true;
        f.wrote = false;
        f.recovering = f.drawn_width.is_some_and(|w| w != cols);
        f.open_row = f.recovering;
        // A width for `end_draw` to record even if indicatif never asks for one.
        f.render_width = cols;
    }

    /// Close the open draw and take its bytes, recording whether it left a frame on screen and
    /// at which width — the baseline the next draw's resize check compares against.
    fn end_draw(&self) -> Vec<u8> {
        let mut f = self.state.lock().unwrap();
        // A recovering draw that wrote nothing still owes the row break: without it the
        // cursor stays wherever the abandoned frame left it — mid-row, since that frame was
        // padded to the old width — and the next log line is glued onto its tail.
        if std::mem::take(&mut f.open_row) {
            f.buf.extend_from_slice(b"\r\n");
        }
        f.drawn_width = f.wrote.then_some(f.render_width);
        f.drawing = false;
        f.recovering = false;
        std::mem::take(&mut f.buf)
    }
}

impl Frame {
    /// Append `bytes` as part of a line, first opening the fresh row a resize recovery owes:
    /// the stale frame is abandoned where it lies and this draw starts under it.
    fn put(&mut self, bytes: &[u8]) {
        if std::mem::take(&mut self.open_row) {
            self.buf.extend_from_slice(b"\r\n");
        }
        self.wrote = true;
        self.buf.extend_from_slice(bytes);
    }
}

impl TermLike for ResizeTerm {
    /// Sampled fresh per call: indicatif lays every line out against it, so a widened terminal
    /// is used immediately, and [`ResizeTerm::end_draw`] records it as the drawn width.
    fn width(&self) -> u16 {
        let cols = (self.size)().0;
        self.state.lock().unwrap().render_width = cols;
        cols
    }

    fn height(&self) -> u16 {
        (self.size)().1
    }

    fn move_cursor_up(&self, n: usize) -> io::Result<()> {
        let mut f = self.state.lock().unwrap();
        self.begin(&mut f);
        if !f.recovering {
            move_cursor(&mut f.buf, n, 'A');
        }
        Ok(())
    }

    fn move_cursor_down(&self, n: usize) -> io::Result<()> {
        let mut f = self.state.lock().unwrap();
        self.begin(&mut f);
        if !f.recovering {
            move_cursor(&mut f.buf, n, 'B');
        }
        Ok(())
    }

    /// Horizontal moves are neither erase nor content, so they neither suppress under a
    /// recovery nor open its fresh row — they only reposition within the row the draw is
    /// already on. indicatif's own draws never emit one.
    fn move_cursor_right(&self, n: usize) -> io::Result<()> {
        let mut f = self.state.lock().unwrap();
        self.begin(&mut f);
        move_cursor(&mut f.buf, n, 'C');
        Ok(())
    }

    fn move_cursor_left(&self, n: usize) -> io::Result<()> {
        let mut f = self.state.lock().unwrap();
        self.begin(&mut f);
        move_cursor(&mut f.buf, n, 'D');
        Ok(())
    }

    fn write_line(&self, s: &str) -> io::Result<()> {
        let mut f = self.state.lock().unwrap();
        self.begin(&mut f);
        f.put(s.as_bytes());
        f.buf.push(b'\n');
        Ok(())
    }

    fn write_str(&self, s: &str) -> io::Result<()> {
        let mut f = self.state.lock().unwrap();
        self.begin(&mut f);
        f.put(s.as_bytes());
        Ok(())
    }

    /// Clearing a row is the erase phase, so it too is skipped while recovering.
    fn clear_line(&self) -> io::Result<()> {
        let mut f = self.state.lock().unwrap();
        self.begin(&mut f);
        if !f.recovering {
            f.buf.extend_from_slice(b"\r\x1b[2K");
        }
        Ok(())
    }

    /// indicatif ends every draw with a flush, so this is where a whole frame reaches the
    /// terminal — under one stdout lock, taken without holding the frame lock across it. A
    /// draw that emitted nothing at all skips the write rather than syscalling for zero bytes.
    fn flush(&self) -> io::Result<()> {
        let frame = self.end_draw();
        if frame.is_empty() {
            return Ok(());
        }
        (self.sink)(&frame)
    }
}

/// The rule at the top of the pinned block, added to `mp`.
///
/// It is a `wide_bar` filled to `position == len`, with `─` as both its filled and its empty
/// cluster so that any width renders as a solid rule — not a message of that many dashes,
/// because indicatif re-fits a `wide_bar` to the terminal every time it renders the bar, which
/// is what makes the rule follow a resize. That only happens when the bar itself ticks: a
/// member that does not is re-emitted from indicatif's cached lines, frozen at the width it
/// last rendered at. Hence the steady tick, matching the header's.
fn sep_bar(mp: &MultiProgress) -> ProgressBar {
    let sep = mp.add(ProgressBar::new(1));
    sep.set_style(
        ProgressStyle::with_template("{wide_bar:.dim}")
            .unwrap()
            .progress_chars("──"),
    );
    sep.set_position(1);
    sep.enable_steady_tick(Duration::from_millis(120));
    sep
}

/// [`ResizeTerm`]'s production sink: a finished frame, written and flushed under one lock,
/// so nothing else on stdout can land inside it.
fn write_stdout(frame: &[u8]) -> io::Result<()> {
    let mut out = io::stdout().lock();
    out.write_all(frame)?;
    out.flush()
}

/// Append a CSI cursor move of `n` cells in `dir` (`A` up, `B` down, `C` right, `D` left).
/// A zero-cell move emits nothing: terminals read a zero parameter as one cell.
fn move_cursor(buf: &mut Vec<u8>, n: usize, dir: char) {
    if n > 0 {
        buf.extend_from_slice(format!("\x1b[{n}{dir}").as_bytes());
    }
}

/// The controlling terminal's `(columns, rows)`, each falling back to the conventional 80x24
/// when the terminal does not report it.
fn term_size() -> (u16, u16) {
    let (rows, cols) = get_winsize(libc::STDOUT_FILENO).unwrap_or((0, 0));
    (
        if cols > 0 { cols } else { 80 },
        if rows > 0 { rows } else { 24 },
    )
}

/// The controlling terminal's column count, or 80 if unknown.
fn term_cols() -> usize {
    term_size().0 as usize
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

/// The terminal-title string for an in-progress build: the header counts, plus the current
/// activity clipped to a title-sized budget when there is one.
fn build_title(counts: &str, activity: &str) -> String {
    if activity.is_empty() {
        format!("vk build ({counts})")
    } else {
        format!("vk build ({counts}) {}", clip(activity, 72))
    }
}

/// Fold a chunk of raw guest bytes for one output stream into the complete lines it
/// terminated and the current visible "tail" (the partial after the last newline). `buf`
/// carries the unterminated remainder across chunks. Applies terminal carriage-return
/// semantics: `\r` returns to column 0 so following text overwrites, `\r\n` is a plain line
/// end, and each result is the final visible segment. `buf` is kept bounded — bytes a later
/// carriage return has already overwritten are dropped rather than accumulated.
fn fold_output(buf: &mut Vec<u8>, chunk: &[u8]) -> (Vec<String>, String) {
    buf.extend_from_slice(chunk);
    let mut lines = Vec::new();
    while let Some(nl) = buf.iter().position(|&c| c == b'\n') {
        let line: Vec<u8> = buf.drain(..=nl).collect();
        lines.push(visible_tail(&line[..line.len() - 1])); // drop the '\n', collapse '\r's
    }
    // Drop everything up to and including the last interior carriage return: it has been
    // overwritten and can never become visible. A lone trailing '\r' is kept — it may begin a
    // '\r\n' whose '\n' lands in the next chunk.
    let end = buf.len() - usize::from(buf.last() == Some(&b'\r'));
    if let Some(i) = buf[..end].iter().rposition(|&c| c == b'\r') {
        buf.drain(..=i);
    }
    (lines, visible_tail(buf))
}

/// The visible text of a (newline-stripped) line after applying carriage-return overwrites:
/// the segment following the last interior `\r`, with a lone trailing `\r` dropped.
fn visible_tail(b: &[u8]) -> String {
    let end = b.len() - usize::from(b.last() == Some(&b'\r'));
    let start = b[..end]
        .iter()
        .rposition(|&c| c == b'\r')
        .map_or(0, |i| i + 1);
    String::from_utf8_lossy(&b[start..end]).into_owned()
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
    use std::sync::atomic::AtomicU16;

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
        p.init(two_stages(), 1);
        p.stage_fully_cached(0); // base: FROM (1 cell)
        p.restore_start(0, "base");
        p.restore_done(0);
        p.base_start(1);
        p.base_done(1, Outcome::Ran);
        p.step_start(1, 0);
        p.emit(1, 1, b"Compiling foo\npartial-no-newline");
        p.step_committing(1, 0);
        p.step_done(1, 0, Outcome::Ran);
        p.step_done(1, 1, Outcome::Cached); // a cache hit: no start
        p.export_start(0);
        p.export_done(0);
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
            Backend::Tty(Box::new(Tty::new())),
            false,
        )));
    }

    /// The shared handles a [`ResizeTerm`] under test is driven through: a settable terminal
    /// width, and the bytes its `flush` wrote. Per-instance rather than in statics, so the
    /// tests stay independent of each other under cargo's parallel runner.
    struct Screen {
        cols: Arc<AtomicU16>,
        out: Arc<Mutex<Vec<u8>>>,
    }

    impl Screen {
        /// An 80x24 screen, plus the `ResizeTerm` that draws to it.
        fn new() -> (Self, ResizeTerm) {
            let screen = Screen {
                cols: Arc::new(AtomicU16::new(80)),
                out: Arc::new(Mutex::new(Vec::new())),
            };
            let (cols, out) = (Arc::clone(&screen.cols), Arc::clone(&screen.out));
            let term = ResizeTerm::with(
                move || (cols.load(Ordering::Relaxed), 24),
                move |bytes| {
                    out.lock().unwrap().extend_from_slice(bytes);
                    Ok(())
                },
            );
            (screen, term)
        }

        fn resize(&self, cols: u16) {
            self.cols.store(cols, Ordering::Relaxed);
        }

        /// Everything written since the last call, draining it.
        fn take(&self) -> String {
            String::from_utf8(std::mem::take(&mut *self.out.lock().unwrap())).unwrap()
        }
    }

    /// The erase phase indicatif opens every draw with, for `rows` previously drawn rows.
    /// Mirrors `indicatif::DrawState::draw_to_term`.
    fn erase(t: &ResizeTerm, rows: usize) {
        t.move_cursor_up(rows.saturating_sub(1)).unwrap();
        for i in 0..rows {
            t.clear_line().unwrap();
            if i + 1 != rows {
                t.move_cursor_down(1).unwrap();
            }
        }
        t.move_cursor_up(rows.saturating_sub(1)).unwrap();
        t.width(); // indicatif samples the width to lay the frame out
    }

    /// A whole draw: the erase phase, then `lines` written back to back the way indicatif
    /// writes them (its own width padding between them is not what is under test here).
    /// Returns what reached the screen.
    fn draw(t: &ResizeTerm, screen: &Screen, rows: usize, lines: &[&str]) -> String {
        erase(t, rows);
        for line in lines {
            t.write_str(line).unwrap();
        }
        t.flush().unwrap();
        screen.take()
    }

    /// A draw that writes no line — `MultiProgress::clear`, and the first half of its
    /// `suspend`, which take the block off the screen so the log can scroll under it.
    fn clear(t: &ResizeTerm, screen: &Screen, rows: usize) -> String {
        erase(t, rows);
        t.flush().unwrap();
        screen.take()
    }

    /// At a steady width the erase phase passes straight through, so indicatif's own row
    /// accounting drives the frame exactly as it would against a plain terminal.
    #[test]
    fn resize_term_passes_the_erase_through_at_a_steady_width() {
        let (screen, t) = Screen::new();
        // The very first draw has no frame to erase and no width to have changed from, so it
        // is not a recovery either — it just writes.
        assert_eq!(draw(&t, &screen, 0, &["first frame"]), "first frame");
        assert_eq!(
            draw(&t, &screen, 3, &["second frame"]),
            "\x1b[2A\r\x1b[2K\x1b[1B\r\x1b[2K\x1b[1B\r\x1b[2K\x1b[2Asecond frame"
        );
        assert_eq!(clear(&t, &screen, 1), "\r\x1b[2K");
    }

    /// The first draw at a new width abandons the frame on screen instead of erasing it: no
    /// cursor motion and no line clears, just a fresh row to draw on. The row count indicatif
    /// held for that frame described the pre-resize screen, and nothing portable can say what
    /// the emulator did with those rows.
    #[test]
    fn resize_term_skips_the_erase_after_a_resize() {
        for cols in [60, 100] {
            let (screen, t) = Screen::new();
            draw(&t, &screen, 0, &["first frame"]);
            screen.resize(cols);
            assert_eq!(draw(&t, &screen, 3, &["after resize"]), "\r\nafter resize");
            // ...and the frame that recovered is itself the new baseline, so the draw after it
            // erases normally again.
            assert!(draw(&t, &screen, 1, &["settled"]).starts_with("\r\x1b[2K"));
        }
    }

    /// The fresh row a recovery starts on is opened once, ahead of the frame, however many
    /// lines that frame turns out to have.
    #[test]
    fn resize_term_opens_one_row_for_a_multi_line_recovery() {
        let (screen, t) = Screen::new();
        draw(&t, &screen, 0, &["first frame"]);
        screen.resize(60);
        assert_eq!(draw(&t, &screen, 2, &["rule", "header"]), "\r\nruleheader");
    }

    /// A resize noticed by a draw that writes no line costs no blank row: all the recovery
    /// owes is the break off the abandoned frame's last row, so the log lines that follow land
    /// under it on a clean row and the redraw beneath them needs no recovery of its own.
    #[test]
    fn resize_term_recovery_is_free_for_a_draw_without_lines() {
        let (screen, t) = Screen::new();
        draw(&t, &screen, 0, &["first frame"]);
        screen.resize(60);
        assert_eq!(clear(&t, &screen, 3), "\r\n");
        assert_eq!(draw(&t, &screen, 0, &["redrawn"]), "redrawn");
    }

    /// The size and the horizontal moves are plain pass-throughs, and a zero-cell move emits
    /// nothing at all (terminals read a zero parameter as one cell).
    #[test]
    fn resize_term_passes_size_and_horizontal_moves_through() {
        let (screen, t) = Screen::new();
        screen.resize(120);
        assert_eq!(t.width(), 120);
        assert_eq!(t.height(), 24);
        t.move_cursor_right(3).unwrap();
        t.move_cursor_left(0).unwrap();
        t.move_cursor_left(2).unwrap();
        t.flush().unwrap();
        assert_eq!(screen.take(), "\x1b[3C\x1b[2D");
    }

    /// The separator rule follows the terminal instead of freezing at the width it was built
    /// at. Drawn through a real `MultiProgress`, because what makes it follow is indicatif
    /// re-rendering the bar — which only its own tick triggers.
    #[test]
    fn separator_rule_refits_to_the_terminal_width() {
        let (screen, term) = Screen::new();
        let mp = MultiProgress::with_draw_target(ProgressDrawTarget::term_like_with_hz(
            Box::new(term),
            20,
        ));
        let sep = sep_bar(&mp);
        assert!(
            wait_for_rule(&screen, 80),
            "the rule was never drawn at the terminal's width"
        );
        screen.resize(40);
        assert!(
            wait_for_rule(&screen, 40),
            "the rule did not follow the terminal down to 40 columns"
        );
        sep.finish_and_clear();
    }

    /// Poll the screen until the rule it last drew is `cols` glyphs wide. The steady tick
    /// redraws every 120ms, so only a rule that never re-fits runs out the deadline.
    fn wait_for_rule(screen: &Screen, cols: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let drawn = screen.take();
            if !drawn.is_empty() && rule_width(&drawn) == cols {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// The length of the last run of rule glyphs in `s`.
    fn rule_width(s: &str) -> usize {
        let mut last = 0;
        let mut run = 0;
        for c in s.chars() {
            if c == '─' {
                run += 1;
            } else {
                if run > 0 {
                    last = run;
                }
                run = 0;
            }
        }
        if run > 0 { run } else { last }
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

    /// A cached cell resolves instantly but counts toward the header only once its stage's
    /// snapshot is restored — so the count does not race ahead of a running restore pull.
    #[test]
    fn cached_cells_count_only_after_restore() {
        let p = Arc::new(Progress::new_backend(
            Backend::Tty(Box::new(Tty::new())),
            false,
        ));
        p.init(two_stages(), 1);
        p.stage_fully_cached(0); // stage 0's single cell is now cached...
        assert_eq!(
            p.done.load(Ordering::Relaxed),
            0,
            "a cached cell is pending until its snapshot is restored"
        );
        p.restore_start(0, "base");
        p.restore_done(0);
        assert_eq!(
            p.done.load(Ordering::Relaxed),
            1,
            "the restore materializes the cached cell into the header count"
        );
    }

    /// A build that stops before a cached stage's restore leaves that cell pending; `finish`
    /// folds the remainder into `done` so the final count is never stuck below what resolved.
    #[test]
    fn finish_flushes_pending_cached_cells() {
        let p = Arc::new(Progress::new_backend(
            Backend::Tty(Box::new(Tty::new())),
            false,
        ));
        p.init(two_stages(), 1);
        p.stage_fully_cached(0); // stage 0's cell resolves as a cache hit...
        assert_eq!(
            p.done.load(Ordering::Relaxed),
            0,
            "still pending — no restore ran"
        );
        p.finish(false); // build stopped before restore_done
        assert_eq!(
            p.done.load(Ordering::Relaxed),
            1,
            "finish flushes the un-restored pending cell into done"
        );
    }

    /// A failed step emits its line and finishes without panicking, in each live mode.
    #[test]
    fn step_failure_drives_without_panicking() {
        for p in [
            Arc::new(Progress::new_backend(Backend::Plain, false)),
            Arc::new(Progress::new_backend(
                Backend::Tty(Box::new(Tty::new())),
                false,
            )),
        ] {
            p.init(two_stages(), 1);
            p.base_start(1);
            p.base_done(1, Outcome::Ran);
            p.step_start(1, 0);
            p.step_failed(1, 0);
            p.finish(false);
        }
    }

    /// A restore that errors mid-way leaves its spinner without a matching `restore_done`;
    /// `finish(false)` must drain it so no steady-tick bar lingers, in each live mode.
    #[test]
    fn failed_restore_spinner_is_drained_by_finish() {
        for p in [
            Arc::new(Progress::new_backend(Backend::Plain, false)),
            Arc::new(Progress::new_backend(
                Backend::Tty(Box::new(Tty::new())),
                false,
            )),
        ] {
            p.init(two_stages(), 1);
            p.stage_fully_cached(0);
            p.restore_start(0, "base"); // no restore_done: the restore failed
            p.finish(false);
            if let Backend::Tty(tty) = &p.backend {
                assert!(
                    tty.bars.lock().unwrap().is_empty(),
                    "finish must drain the leftover restore spinner"
                );
            }
        }
    }

    /// A build that errors while parked on a peer's build-once lock leaves its wait spinner
    /// without a matching `wait_lock_done`; `finish(false)` must drain it so no steady-tick bar
    /// lingers, in each live mode.
    #[test]
    fn wait_lock_spinner_is_drained_by_finish() {
        for p in [
            Arc::new(Progress::new_backend(Backend::Plain, false)),
            Arc::new(Progress::new_backend(
                Backend::Tty(Box::new(Tty::new())),
                false,
            )),
        ] {
            p.init(two_stages(), 1);
            p.wait_lock_start(0, "base", "job 42"); // no wait_lock_done: the build failed
            p.finish(false);
            if let Backend::Tty(tty) = &p.backend {
                assert!(
                    tty.bars.lock().unwrap().is_empty(),
                    "finish must drain the leftover wait-lock spinner"
                );
            }
        }
    }

    /// The host-memory wait is the pair that repeats — a stage can park once per admission —
    /// so both halves have to hold: the spinner is cleared whether the stage was let in or
    /// cancelled, and `finish(false)` drains one left behind by a failure.
    #[test]
    fn wait_mem_spinner_is_cleared_however_the_wait_ends() {
        for started in [true, false] {
            let p = Arc::new(Progress::new_backend(
                Backend::Tty(Box::new(Tty::new())),
                false,
            ));
            p.init(two_stages(), 1);
            let Backend::Tty(tty) = &p.backend else {
                unreachable!("built with a tty backend")
            };
            p.wait_mem_start(0, "base", 2048);
            assert!(
                tty.bars.lock().unwrap().contains_key(&(0, WAIT_MEM_NUM)),
                "a parked stage shows a spinner of its own"
            );
            p.wait_mem_done(0, "base", started);
            assert!(
                !tty.bars.lock().unwrap().contains_key(&(0, WAIT_MEM_NUM)),
                "and loses it once the wait ends, admitted or cancelled"
            );
        }
        for p in [
            Arc::new(Progress::new_backend(Backend::Plain, false)),
            Arc::new(Progress::new_backend(
                Backend::Tty(Box::new(Tty::new())),
                false,
            )),
        ] {
            p.init(two_stages(), 1);
            p.wait_mem_start(0, "base", 2048); // no wait_mem_done: the build failed
            p.finish(false);
            if let Backend::Tty(tty) = &p.backend {
                assert!(
                    tty.bars.lock().unwrap().is_empty(),
                    "finish must drain the leftover wait-memory spinner"
                );
            }
        }
    }

    /// `fold_output` splits complete lines on `\n`, honours carriage-return overwrites
    /// (interior `\r` keeps only the final segment; `\r\n` is a plain line end), and returns
    /// the current partial as the live tail.
    #[test]
    fn fold_output_applies_carriage_return_semantics() {
        let mut buf = Vec::new();
        // plain newline-terminated lines, no partial left over.
        assert_eq!(
            fold_output(&mut buf, b"one\ntwo\n"),
            (vec!["one".into(), "two".into()], String::new())
        );
        assert!(buf.is_empty());
        // '\r\n' is an ordinary line end (the '\r' must not blank the line).
        assert_eq!(
            fold_output(&mut buf, b"crlf\r\n"),
            (vec!["crlf".into()], String::new())
        );
        // interior '\r' overwrites: only the segment after the last '\r' survives.
        assert_eq!(
            fold_output(&mut buf, b"a\rb\rc\n"),
            (vec!["c".into()], String::new())
        );
        // a carriage-return progress frame with no newline is returned as the live tail.
        assert_eq!(
            fold_output(&mut buf, b"Read 1%\rRead 2%\r"),
            (vec![], "Read 2%".into())
        );
        // an empty chunk commits nothing and leaves an empty tail.
        let mut buf = Vec::new();
        assert_eq!(fold_output(&mut buf, b""), (vec![], String::new()));
        assert!(buf.is_empty());
        // a lone '\r' is held (it may begin a '\r\n'), not shown as a blank tail; the '\n'
        // arriving next commits the empty line the overwrite left behind.
        assert_eq!(fold_output(&mut buf, b"\r"), (vec![], String::new()));
        assert_eq!(
            fold_output(&mut buf, b"\n"),
            (vec!["".into()], String::new())
        );
        // multibyte content survives an interior '\r' overwrite (the cut is on the ASCII
        // '\r', never inside a codepoint): "é" is 0xC3 0xA9.
        assert_eq!(
            fold_output(&mut buf, "old\rné\n".as_bytes()),
            (vec!["né".into()], String::new())
        );
    }

    /// `fold_output` keeps `buf` bounded across chunks: a long carriage-return progress stream
    /// (no newline) never accumulates the overwritten frames — `buf` holds ~one frame — and a
    /// `\r\n` split across chunks still yields the intended line.
    #[test]
    fn fold_output_bounds_the_partial_buffer() {
        let mut buf = Vec::new();
        for i in 0..1000 {
            let (lines, tail) = fold_output(&mut buf, format!("Read {i}%\r").as_bytes());
            assert!(lines.is_empty());
            assert_eq!(tail, format!("Read {i}%"));
        }
        assert!(
            buf.len() < 32,
            "overwritten frames must not accumulate, got {} bytes",
            buf.len()
        );
        // a '\r\n' whose '\n' arrives in the next chunk still ends the line cleanly.
        assert_eq!(fold_output(&mut buf, b"done\r"), (vec![], "done".into()));
        assert_eq!(
            fold_output(&mut buf, b"\n"),
            (vec!["done".into()], String::new())
        );
    }

    /// A carriage-return progress frame with no trailing newline shows in the live output-tail
    /// cell; a newline commits it and clears the cell; `finish` drains any leftover tail.
    #[test]
    fn output_tail_tracks_and_is_drained() {
        let p = Arc::new(Progress::new_backend(
            Backend::Tty(Box::new(Tty::new())),
            false,
        ));
        p.init(two_stages(), 1);
        p.base_start(1);
        p.base_done(1, Outcome::Ran);
        p.step_start(1, 0);
        let has_tail = |p: &Arc<Progress>| {
            let Backend::Tty(tty) = &p.backend else {
                unreachable!()
            };
            tty.bars.lock().unwrap().contains_key(&(1, OUTPUT_TAIL_NUM))
        };
        // a bare progress frame (no newline) is held live in the tail cell.
        p.emit(1, 1, b"Read: 5.65 GiB / 32.6 GiB ==> 1%\r");
        assert!(
            has_tail(&p),
            "a carriage-return frame must show in the tail"
        );
        // a newline commits the line and clears the tail cell.
        p.emit(1, 1, b"Read: 32.6 GiB / 32.6 GiB ==> 100%\n");
        assert!(!has_tail(&p), "a committed line must clear the tail");
        // a leftover tail (frame still pending) is drained by finish.
        p.emit(1, 1, b"trailing\r");
        assert!(has_tail(&p));
        p.finish(false);
        let Backend::Tty(tty) = &p.backend else {
            unreachable!()
        };
        assert!(
            tty.bars.lock().unwrap().is_empty(),
            "finish must drain the leftover output tail"
        );
    }

    /// `clip` keeps a string within its character budget, ellipsizing only when it must, and
    /// counts by chars (not bytes) so a multibyte label is clipped on a char boundary.
    #[test]
    fn clip_respects_char_budget() {
        assert_eq!(clip("abc", 5), "abc"); // under budget: untouched
        assert_eq!(clip("abcde", 5), "abcde"); // exact fit: no ellipsis
        assert_eq!(clip("abcdef", 5), "abcd…"); // over budget: last char is the ellipsis
        assert_eq!(clip("abc", 0), ""); // zero budget: empty
        assert_eq!(clip("abc", 1), "…"); // budget of one: just the ellipsis
        // Multibyte input clips by chars, and the result stays within the char budget.
        let clipped = clip("héllo wörld", 5);
        assert_eq!(clipped.chars().count(), 5);
        assert!(clipped.ends_with('…'));
    }

    /// The terminal title carries the counts alone until a cell starts, then appends the
    /// current activity clipped to the title budget.
    #[test]
    fn build_title_appends_clipped_activity() {
        assert_eq!(build_title("2/5", ""), "vk build (2/5)");
        assert_eq!(
            build_title("2/5", "[build 1/2] RUN cargo build"),
            "vk build (2/5) [build 1/2] RUN cargo build"
        );
        let long = build_title("2/5", &"x".repeat(100));
        assert!(long.starts_with("vk build (2/5) "));
        assert!(
            long.ends_with('…'),
            "an over-long activity is clipped: {long:?}"
        );
    }

    #[test]
    fn disabled_is_inert() {
        let p = Arc::new(Progress::new_backend(Backend::Disabled, false));
        p.init(two_stages(), 1);
        p.base_start(1);
        p.base_done(1, Outcome::Ran);
        p.finish(true);
        assert!(matches!(p.stage_sink(1), OutputSink::Inherit));
    }

    #[test]
    fn routed_mode_streams_plain_lines_to_the_sink() {
        // The routed backend must emit the same `#N …` lines the plain backend prints, but
        // to the sink instead of stdout — the transport the manager forwards to the guest.
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = {
            let lines = Arc::clone(&lines);
            Arc::new(move |l: &str| lines.lock().unwrap().push(l.to_string()))
                as Arc<dyn Fn(&str) + Send + Sync>
        };
        let p = Progress::routed(sink);
        drive(&p);
        let got = lines.lock().unwrap();
        assert!(!got.is_empty(), "routed build must stream lines");
        assert!(got.iter().all(|l| l.starts_with('#')), "plain `#N …` lines");
        assert!(got.iter().any(|l| l.contains("exporting to image")));
        assert!(got.iter().any(|l| l.contains("FINISHED")));
        // routed guest output must carry through, not inherit stdout
        assert!(matches!(p.stage_sink(1), OutputSink::Routed(_)));
    }

    #[test]
    fn note_streams_to_a_routed_builds_consumer() {
        // A note is the driver's own line rather than a step event, and it travels the same
        // transport: on a routed build the reader is the guest that asked for the build, which
        // never sees the driver's stdout.
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = {
            let lines = Arc::clone(&lines);
            Arc::new(move |l: &str| lines.lock().unwrap().push(l.to_string()))
                as Arc<dyn Fn(&str) + Send + Sync>
        };
        let p = Progress::routed(sink);
        p.note("virtkit: build: up to 4 stage(s) at once");
        assert_eq!(
            lines.lock().unwrap().as_slice(),
            ["virtkit: build: up to 4 stage(s) at once"]
        );
    }

    #[test]
    fn plain_lines_report_the_step_run_time() {
        // A non-tty build (a git hook, a CI log) is exactly where durations are read after
        // the fact, so its `#N DONE <d>` must carry the step's real run time — not the 0.0s
        // it printed while the elapsed was reclaimed off the (tty-only) progress bar.
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = {
            let lines = Arc::clone(&lines);
            Arc::new(move |l: &str| lines.lock().unwrap().push(l.to_string()))
                as Arc<dyn Fn(&str) + Send + Sync>
        };
        let p = Progress::routed(sink);
        p.init(two_stages(), 0);
        p.step_start(1, 0);
        std::thread::sleep(Duration::from_millis(150));
        p.step_committing(1, 0);
        p.step_done(1, 0, Outcome::Ran);
        let got = lines.lock().unwrap();
        let done = got
            .iter()
            .find(|l| l.contains(" DONE "))
            .expect("a ran step emits a DONE line");
        assert!(
            !done.ends_with(" 0.0s"),
            "DONE line lost the run time: {done}"
        );
    }
}
