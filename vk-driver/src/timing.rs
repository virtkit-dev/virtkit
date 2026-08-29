//! End-of-run timing breakdown — a coarse "where did the time go?" view for
//! `vk build` and `vk run`, printed once the work is done.
//!
//! One [`Timings`] is created per build/run and shared (an `Arc`) across the
//! parallel stage workers. Each phase-bounded operation records its elapsed time
//! against a [`Phase`] (and, for build phases, the stage it belongs to), and
//! [`Timings::render`] prints the rolled-up breakdown: one line per phase that
//! accrued time, plus a per-stage sub-breakdown where a phase spans several
//! stages.
//!
//! Because build stages run concurrently, the summed per-phase time ("busy") can
//! exceed the wall-clock elapsed — the header reports both, so a build dominated
//! by cache pushes reads differently from one bottlenecked on a single stage.
//!
//! Build stages also record peak guest memory ([`Timings::record_mem`]) in a separate block
//! below the phases to guide `# vk: mem=…` sizing.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A coarse category of build/run work. Ordered roughly as work happens; the
/// breakdown lists only the phases that actually accrued time.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    /// Parsing the Dockerfiles and resolving the build plan/DAG.
    Plan,
    /// Materializing a stage's base (`FROM <image>` pull + flatten, or `scratch`).
    BasePull,
    /// Restoring a cached instruction/stage snapshot from the registry.
    CachePull,
    /// Executing `RUN`/`COPY` instructions in the guest.
    Instructions,
    /// Snapshotting + pushing an instruction/stage result to the cache registry.
    CachePush,
    /// Assembling the final ext4 image.
    Export,
    /// `vk run` image boot: fetching the rootfs (registry pull / docker export).
    SourcePull,
    /// `vk run`: assembling the boot medium (ext4 rootfs / cpio initramfs).
    BootMedia,
    /// `vk run`: spawning the VMM and waiting for the guest agent to come up.
    Boot,
    /// `vk run`: executing the requested command in the guest.
    Exec,
}

impl Phase {
    fn label(self) -> &'static str {
        match self {
            Phase::Plan => "plan",
            Phase::BasePull => "base pull",
            Phase::CachePull => "cache pull",
            Phase::Instructions => "instructions",
            Phase::CachePush => "cache push",
            Phase::Export => "export",
            Phase::SourcePull => "source pull",
            Phase::BootMedia => "boot media",
            Phase::Boot => "boot",
            Phase::Exec => "exec",
        }
    }
}

/// Every phase in display order (work-flow order). A phase absent from a run is
/// skipped at render, so build-only and run-only phases share one list.
const ORDER: [Phase; 10] = [
    Phase::Plan,
    Phase::BasePull,
    Phase::CachePull,
    Phase::Instructions,
    Phase::CachePush,
    Phase::Export,
    Phase::SourcePull,
    Phase::BootMedia,
    Phase::Boot,
    Phase::Exec,
];

#[derive(Default)]
struct Inner {
    /// phase → (sub-label → accumulated). An empty sub-label means the phase has
    /// no natural subdivision (e.g. export, boot); a non-empty one is a stage name.
    rows: BTreeMap<Phase, BTreeMap<String, Duration>>,
    /// build concurrency, for the header note; 0 when unset (a serial `run`).
    jobs: usize,
    /// stage name → (maximum demand across its guests, assigned size), in bytes.
    mem: BTreeMap<String, (u64, u64)>,
    /// Fine-grained probe samples (`VIRTKIT_TIMING`), keyed by dotted label → (summed
    /// elapsed, sample count). Kept off the phase accounting so a probe that measures part
    /// of a coarse phase (e.g. `boot.spawn` within `boot`) never double-counts it; rendered
    /// as its own block after the phase breakdown.
    probes: BTreeMap<String, (Duration, usize)>,
}

/// Accumulates categorized durations across a build/run and renders the breakdown.
pub struct Timings {
    start: Instant,
    inner: Mutex<Inner>,
}

impl Timings {
    pub fn new() -> Self {
        Timings {
            start: Instant::now(),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Add `dur` to `phase`, attributed to `stage` (a stage name, or `""` for a
    /// phase with no natural subdivision).
    pub fn record(&self, phase: Phase, stage: &str, dur: Duration) {
        let mut g = self.inner.lock().unwrap();
        *g.rows
            .entry(phase)
            .or_default()
            .entry(stage.to_string())
            .or_default() += dur;
    }

    /// Record `stage`'s peak demand and assigned size in bytes, retaining the largest demand
    /// across guest reboots.
    pub fn record_mem(&self, stage: &str, peak: u64, declared: u64) {
        let mut g = self.inner.lock().unwrap();
        let e = g.mem.entry(stage.to_string()).or_insert((0, declared));
        *e = (e.0.max(peak), declared);
    }

    /// Return `stage`'s peak demand and assigned size for its completion line.
    pub fn stage_mem(&self, stage: &str) -> Option<(u64, u64)> {
        self.inner.lock().unwrap().mem.get(stage).copied()
    }

    /// Note the build's concurrency, so the header can report "busy across N jobs".
    pub fn note_jobs(&self, jobs: usize) {
        self.inner.lock().unwrap().jobs = jobs;
    }

    /// Record a fine-grained probe sample under `label` (a dotted name like `cache.push`),
    /// accumulating its elapsed and bumping its sample count. Gated behind `VIRTKIT_TIMING`
    /// (inert otherwise), so profiling adds nothing to a normal build; the samples surface
    /// in the end-of-run breakdown's probe block rather than printing mid-build (a raw print
    /// there would corrupt the live `vk build` dashboard).
    pub fn probe(&self, label: &str, dur: Duration) {
        if std::env::var_os("VIRTKIT_TIMING").is_none() {
            return;
        }
        let mut g = self.inner.lock().unwrap();
        let e = g.probes.entry(label.to_string()).or_default();
        e.0 += dur;
        e.1 += 1;
    }

    /// Print the breakdown to stdout. A no-op when nothing was recorded.
    pub fn render(&self) {
        if let Some(text) = self.inner.lock().unwrap().format(self.start.elapsed()) {
            println!("{text}");
        }
    }
}

impl Inner {
    /// Flatten the recorded phases into `(indent, label, duration)` display rows: one
    /// row per phase that accrued time, in [`ORDER`], plus an indented per-stage sub-row
    /// when a phase spans two or more named stages (a single stage would just restate the
    /// phase total). Pure over the recorded state so the phase/sub-row selection and
    /// ordering are testable without the clock.
    fn breakdown_lines(&self) -> Vec<(usize, String, Duration)> {
        let mut lines: Vec<(usize, String, Duration)> = Vec::new();
        for &p in &ORDER {
            let Some(m) = self.rows.get(&p) else { continue };
            let total: Duration = m.values().copied().sum();
            if total.is_zero() {
                continue;
            }
            lines.push((2, p.label().to_string(), total));
            let mut subs: Vec<(&String, &Duration)> =
                m.iter().filter(|(name, _)| !name.is_empty()).collect();
            if subs.len() >= 2 {
                // dominant stage first, ties broken by name for stable output.
                subs.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
                for (name, dur) in subs {
                    lines.push((4, format!("[{name}]"), *dur));
                }
            }
        }
        lines
    }

    /// Render the breakdown as a single block of text (header + one line per phase),
    /// or `None` when nothing was recorded. Pure over `wall` so the layout — the header
    /// branch and the right-aligned duration column — is testable without the clock.
    fn format(&self, wall: Duration) -> Option<String> {
        // Render when any block has data, including memory alone.
        if self.rows.is_empty() && self.mem.is_empty() && self.probes.is_empty() {
            return None;
        }
        let busy: Duration = self.rows.values().flat_map(|m| m.values()).copied().sum();
        let lines = self.breakdown_lines();

        let head = if self.jobs > 0 {
            format!(
                " Timing (wall {}, busy {} across {} jobs)",
                fmt_dur(wall),
                fmt_dur(busy),
                self.jobs
            )
        } else {
            format!(" Timing (wall {})", fmt_dur(wall))
        };

        // Right-align the duration column: labels padded to the widest label, then
        // the duration right-justified in the widest duration's width.
        let label_w = lines
            .iter()
            .map(|(indent, name, _)| indent + name.chars().count())
            .max()
            .unwrap_or(0);
        let dur_w = lines
            .iter()
            .map(|(_, _, d)| fmt_dur(*d).len())
            .max()
            .unwrap_or(0);
        let mut out = head;
        for (indent, name, dur) in &lines {
            let label = format!("{:indent$}{name}", "", indent = indent);
            let _ = write!(
                out,
                "\n{label:<label_w$}   {dur:>dur_w$}",
                dur = fmt_dur(*dur)
            );
        }

        // Memory is a stage-keyed byte count, not a timed phase.
        if !self.mem.is_empty() {
            // Sort by descending peak, then name for stable output.
            let mut stages: Vec<(&String, &(u64, u64))> = self.mem.iter().collect();
            stages.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.cmp(b.0)));
            out.push_str("\n Stage memory (peak demand / guest size)");
            let name_w = stages
                .iter()
                .map(|(name, _)| name.chars().count())
                .max()
                .unwrap_or(0);
            for (name, (peak, declared)) in stages {
                let label = format!("[{name}]");
                let _ = write!(
                    out,
                    "\n  {label:<w$}   {} of {}",
                    crate::usage::fmt_bytes(*peak),
                    crate::usage::fmt_bytes(*declared),
                    w = name_w + 2,
                );
            }
        }

        // Fine-grained probes (VIRTKIT_TIMING) as a trailing block: each dotted label with
        // its summed elapsed and sample count. Listed separately from the phases so it is
        // clear these are point measurements that may overlap a coarse phase, not additions
        // to the wall/busy accounting above.
        if !self.probes.is_empty() {
            let plabel_w = self
                .probes
                .keys()
                .map(|l| l.chars().count())
                .max()
                .unwrap_or(0);
            let pdur_w = self
                .probes
                .values()
                .map(|(d, _)| fmt_dur(*d).len())
                .max()
                .unwrap_or(0);
            out.push_str("\n probes (VIRTKIT_TIMING):");
            for (label, (dur, n)) in &self.probes {
                let _ = write!(
                    out,
                    "\n  {label:<plabel_w$}   {dur:>pdur_w$}  (×{n})",
                    dur = fmt_dur(*dur)
                );
            }
        }
        Some(out)
    }
}

/// Elapsed as `12.3s` (matching the build dashboard's format).
fn fmt_dur(d: Duration) -> String {
    format!("{:.1}s", d.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_rolls_up_without_panicking() {
        let t = Timings::new();
        t.note_jobs(4);
        t.record(Phase::Plan, "", Duration::from_millis(100));
        t.record(Phase::Instructions, "builder", Duration::from_secs(22));
        t.record(Phase::Instructions, "runtime", Duration::from_secs(8));
        t.record(Phase::CachePush, "builder", Duration::from_secs(4));
        t.record(Phase::Export, "", Duration::from_secs(1));
        // rolls up: instructions total is the sum of its two stages.
        let g = t.inner.lock().unwrap();
        let instr: Duration = g.rows[&Phase::Instructions].values().copied().sum();
        assert_eq!(instr, Duration::from_secs(30));
        drop(g);
        t.render(); // must not panic (stdout hidden under cargo test)
    }

    #[test]
    fn empty_render_is_a_noop() {
        Timings::new().render();
        // Nothing recorded → no text to print.
        assert!(
            Timings::new()
                .inner
                .lock()
                .unwrap()
                .format(Duration::ZERO)
                .is_none()
        );
    }

    /// The line selection: phases appear in `ORDER`, a phase with two named stages gets
    /// indented sub-rows sorted dominant-first, and a single-stage phase does not.
    #[test]
    fn breakdown_gates_and_sorts_sub_rows() {
        let t = Timings::new();
        t.record(Phase::Plan, "", Duration::from_millis(100));
        t.record(Phase::Instructions, "runtime", Duration::from_secs(8));
        t.record(Phase::Instructions, "builder", Duration::from_secs(22));
        t.record(Phase::CachePush, "builder", Duration::from_secs(4));
        t.record(Phase::Export, "", Duration::from_secs(1));
        let lines = t.inner.lock().unwrap().breakdown_lines();
        assert_eq!(
            lines,
            vec![
                (2, "plan".to_string(), Duration::from_millis(100)),
                (2, "instructions".to_string(), Duration::from_secs(30)),
                // spans two stages → sub-rows, dominant (builder, 22s) before runtime (8s).
                (4, "[builder]".to_string(), Duration::from_secs(22)),
                (4, "[runtime]".to_string(), Duration::from_secs(8)),
                // single stage → no sub-row, just the phase total.
                (2, "cache push".to_string(), Duration::from_secs(4)),
                (2, "export".to_string(), Duration::from_secs(1)),
            ]
        );
    }

    /// Fine-grained probes render as a trailing block — one row per dotted label with its
    /// summed elapsed and sample count — kept out of the phase list and the wall/busy header
    /// so they never double-count a coarse phase they overlap.
    #[test]
    fn probes_render_as_a_separate_block() {
        let t = Timings::new();
        t.record(Phase::Export, "", Duration::from_secs(1));
        {
            let mut g = t.inner.lock().unwrap();
            g.probes
                .insert("cache.push".into(), (Duration::from_millis(3200), 4));
            g.probes
                .insert("boot.spawn".into(), (Duration::from_millis(800), 2));
        }
        let text = t
            .inner
            .lock()
            .unwrap()
            .format(Duration::from_secs(5))
            .unwrap();
        // The phase accounting is unchanged: export is the only phase (no jobs noted, so the
        // header omits the busy/jobs note), and the probes add nothing to it.
        assert!(text.starts_with(" Timing (wall 5.0s)"));
        assert!(text.contains("\n probes (VIRTKIT_TIMING):"));
        // Alphabetical by label; each row carries the summed elapsed and the sample count.
        let probe_block = text.split("probes (VIRTKIT_TIMING):").nth(1).unwrap();
        let rows: Vec<&str> = probe_block.lines().filter(|l| !l.is_empty()).collect();
        assert!(rows[0].contains("boot.spawn") && rows[0].ends_with("0.8s  (×2)"));
        assert!(rows[1].contains("cache.push") && rows[1].ends_with("3.2s  (×4)"));
    }

    /// Render stage memory below the phases, ordered by descending peak.
    #[test]
    fn stage_memory_renders_as_its_own_block() {
        let t = Timings::new();
        t.record(Phase::Instructions, "builder", Duration::from_secs(22));
        t.record_mem("runtime", 612 * 1024 * 1024, 2 * 1024 * 1024 * 1024);
        t.record_mem("builder", 1_717_986_918, 4 * 1024 * 1024 * 1024);
        // A smaller reading after a guest reboot does not lower the stage peak.
        t.record_mem("builder", 512 * 1024 * 1024, 4 * 1024 * 1024 * 1024);
        let text = t
            .inner
            .lock()
            .unwrap()
            .format(Duration::from_secs(40))
            .unwrap();
        let block: Vec<&str> = text
            .split("Stage memory (peak demand / guest size)")
            .nth(1)
            .expect("the memory block")
            .lines()
            .filter(|l| !l.is_empty())
            .collect();
        assert!(block[0].contains("[builder]") && block[0].ends_with("1.6 GiB of 4.0 GiB"));
        assert!(block[1].contains("[runtime]") && block[1].ends_with("612 MiB of 2.0 GiB"));
        // Memory does not affect phase accounting.
        assert_eq!(text.lines().next().unwrap(), " Timing (wall 40.0s)");
    }

    /// Render memory even when no phase row exists.
    #[test]
    fn stage_memory_alone_still_renders() {
        let t = Timings::new();
        t.record_mem("builder", 1024 * 1024 * 1024, 4 * 1024 * 1024 * 1024);
        let text = t
            .inner
            .lock()
            .unwrap()
            .format(Duration::from_secs(2))
            .unwrap();
        assert!(text.contains("[builder]   1.0 GiB of 4.0 GiB"), "{text}");
    }

    /// The header reports summed busy time and jobs when a build concurrency is set, and
    /// omits both for a serial run; the duration column is right-aligned to a common width.
    #[test]
    fn format_header_branches_and_column_alignment() {
        let t = Timings::new();
        t.note_jobs(4);
        t.record(Phase::Plan, "", Duration::from_millis(100));
        t.record(Phase::Instructions, "builder", Duration::from_secs(22));
        let text = t
            .inner
            .lock()
            .unwrap()
            .format(Duration::from_secs(40))
            .unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // busy = 0.1 + 22 = 22.1s across 4 jobs.
        assert_eq!(lines[0], " Timing (wall 40.0s, busy 22.1s across 4 jobs)");
        // Both durations right-aligned to the widest ("22.0s" == 5 chars).
        assert!(lines[1].ends_with("  0.1s"), "plan row: {:?}", lines[1]);
        assert!(
            lines[2].ends_with(" 22.0s"),
            "instructions row: {:?}",
            lines[2]
        );

        // Serial run (no jobs noted): header drops the busy/jobs note.
        let s = Timings::new();
        s.record(Phase::Boot, "", Duration::from_secs(2));
        let text = s
            .inner
            .lock()
            .unwrap()
            .format(Duration::from_secs(3))
            .unwrap();
        assert_eq!(text.lines().next().unwrap(), " Timing (wall 3.0s)");
    }
}
