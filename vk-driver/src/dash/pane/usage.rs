//! The usage pane: what the selected environment is taking from **this host**.
//!
//! Not what the guest sees inside itself. A guest counts every page it has touched, its own
//! cache included, and will happily report gigabytes the host is not backing; the host is
//! backing what the VM has genuinely taken, and that is the figure a reader deciding whether
//! a machine full of environments is in trouble needs. The heading says so, because the two
//! are close enough in wording to be read as each other. The guest's own view is a panel
//! that already exists — `vk atop <state dir> --follow` — and the pane names it.
//!
//! Every meter carries its figure. A bar with no number beside it is unreadable in a
//! screenshot and meaningless without colour, so the bar is the quick read and the figure is
//! the answer.

use std::time::Duration;

use crate::dash::poll::Sample;
use crate::dash::render::{Line, Style, span, tilde};
use crate::dash::state::App;
use crate::usage::{fmt_bytes, fmt_cpu};
use crate::vms::mem_cell;

/// How wide the label column is, so the meters line up to the eye.
const LABEL: usize = 6;

/// The widest a bar gets. Past this it stops saying anything more precise and only takes
/// room from the figure beside it, which is the half that is exact.
const BAR: usize = 12;

/// How much room a meter's figure is left. Below this the bar is dropped rather than the
/// number: a reader can do without the picture and cannot do without the value.
const FIGURE: usize = 24;

/// What the selected environment costs this host, in the room the pane has.
pub(crate) fn lines(app: &App, width: usize, rows: usize) -> Vec<Line> {
    if rows == 0 {
        return Vec::new();
    }
    let Some(env) = app.selected_env() else {
        return vec![note("nothing selected")];
    };
    let mut out = vec![vec![
        span("host cost", Style::Bold),
        span("  not what the guest sees inside itself", Style::Dim),
    ]];
    let Some(vm) = &env.vm else {
        out.push(note("not running, so it is costing this host nothing"));
        return out;
    };
    let Some(latest) = &app.sample else {
        out.push(note("reading the process tree…"));
        return out;
    };

    let cpus = vm.cpus;
    let busy = app
        .previous
        .as_ref()
        .and_then(|previous| share(previous, latest, cpus));
    out.push(meter(
        "cpu",
        busy,
        match (busy, cpus) {
            (Some(share), Some(cpus)) => format!("{:.0}% of {cpus} cpus", share * 100.0),
            (Some(share), None) => format!("{:.0}% per cpu", share * 100.0),
            // The first reading is a total since boot and no rate at all; the second one,
            // an interval later, is what turns it into one.
            (None, _) => "measuring…".to_string(),
        },
        width,
    ));
    out.push(field(
        "",
        format!("{} used since it booted", fmt_cpu(latest.cpu)),
    ));

    let held = env.mem_used;
    let ceiling = configured(env.mem_configured());
    out.push(meter(
        "mem",
        held.zip(ceiling)
            .map(|(held, ceiling)| held as f64 / ceiling.max(1) as f64),
        mem_cell(held, env.mem_configured()),
        width,
    ));
    out.push(field(
        "",
        format!("{} at its highest", fmt_bytes(latest.peak_rss)),
    ));

    out.push(field(
        "disk",
        match latest.disk {
            Some((read, written)) => {
                format!("{} read · {} written", fmt_bytes(read), fmt_bytes(written))
            }
            // A host whose kernel accounts no block I/O has moved an unknown amount, which
            // is not the same fact as having moved none.
            None => "not accounted by this kernel".to_string(),
        },
    ));

    let mut facts = Vec::new();
    if let Some(vmm) = &vm.vmm {
        facts.push(vmm.clone());
    }
    facts.push(format!("pid {}", vm.pid));
    if let Some(ip) = &vm.guest_ip {
        facts.push(ip.to_string());
    }
    out.push(field("vm", facts.join("  ")));
    out.push(vec![span(
        format!("the guest's own view: vk atop {} --follow", tilde(&env.dir)),
        Style::Dim,
    )]);
    out
}

/// What share of its own vCPUs the VM used between two readings.
///
/// Divide by the full vCPU budget: one busy core in a twenty-two-vCPU guest reads 5%, not
/// 100%. Clamp to `0..=1` because sequential `/proc` reads of a changing process tree can
/// disagree slightly; a 103% meter would show sampling error. Without a recorded vCPU count,
/// report per-CPU usage, still saturating at 100%.
fn share(previous: &Sample, latest: &Sample, cpus: Option<u32>) -> Option<f64> {
    let wall = latest.at.checked_duration_since(previous.at)?.as_secs_f64();
    // Two readings at one instant are not an interval, and dividing by it is how a pane
    // reports infinity.
    if wall <= f64::EPSILON {
        return None;
    }
    let used = latest
        .cpu
        .checked_sub(previous.cpu)
        .unwrap_or(Duration::ZERO);
    let cpus = f64::from(cpus.unwrap_or(1).max(1));
    Some((used.as_secs_f64() / wall / cpus).clamp(0.0, 1.0))
}

/// The memory the VM booted with, in bytes — the `--mem` token, which is recorded as it was
/// written rather than normalized. `None` for the spellings a VMM accepts and this does not.
fn configured(token: Option<&str>) -> Option<u64> {
    crate::run::parse_mem_mib(token?)?.checked_mul(1024 * 1024)
}

/// One meter: a label, a bar where there is room for one, and the figure it stands for.
fn meter(label: &str, share: Option<f64>, figure: String, width: usize) -> Line {
    let cells = width.saturating_sub(LABEL).saturating_sub(FIGURE).min(BAR);
    let mut line = vec![span(format!("{label:<LABEL$}"), Style::Dim)];
    if let (Some(share), 4..) = (share, cells) {
        line.push(span(
            format!("{} ", crate::term::bar(share, cells)),
            Style::Plain,
        ));
    }
    line.push(span(figure, Style::Plain));
    line
}

/// One `label value` row, the label dimmed so the values are what the eye follows.
fn field(label: &str, value: impl AsRef<str>) -> Line {
    vec![
        span(format!("{label:<LABEL$}"), Style::Dim),
        span(value.as_ref().to_string(), Style::Plain),
    ]
}

/// A pane with nothing to draw says why, where the figures would have been.
fn note(said: &str) -> Line {
    vec![span(said, Style::Dim)]
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
    use std::time::Instant;

    fn sample(cpu_secs: u64, at: Instant) -> Sample {
        Sample {
            epoch: 0,
            cpu: Duration::from_secs(cpu_secs),
            peak_rss: 2_202_009_600,
            disk: Some((1_717_986_918, 883_195_904)),
            at,
        }
    }

    /// The figure is a rate over the VM's own vCPUs, and every way two readings can arrive
    /// out of order or at once answers with no figure rather than with a wrong one.
    #[test]
    fn the_processor_figure_is_a_rate_and_never_divides_by_zero() {
        let now = Instant::now();
        let earlier = now.checked_sub(Duration::from_secs(10)).unwrap();

        // Ten seconds of CPU over ten seconds of wall clock on four vCPUs: one core's worth.
        let busy = share(&sample(0, earlier), &sample(10, now), Some(4)).unwrap();
        assert!((busy - 0.25).abs() < 0.001, "{busy}");
        // The same reading with no vCPU count recorded is per-cpu, and saturates.
        assert_eq!(
            share(&sample(0, earlier), &sample(10, now), None),
            Some(1.0)
        );
        // And a guest using all of them reads full rather than over.
        assert_eq!(
            share(&sample(0, earlier), &sample(400, now), Some(4)),
            Some(1.0)
        );

        // Two readings at one instant are not an interval.
        assert_eq!(share(&sample(0, now), &sample(10, now), Some(4)), None);
        // Nor are two that arrived in the wrong order.
        assert_eq!(share(&sample(10, now), &sample(0, earlier), Some(4)), None);
        // A tree that shrank has used no CPU since, rather than a negative amount.
        assert_eq!(
            share(&sample(10, earlier), &sample(4, now), Some(4)),
            Some(0.0)
        );
    }

    /// A bar is exactly the cells it was given, whatever share it is drawing, and it gives
    /// way to the figure rather than squeezing it when the column is narrow.
    #[test]
    fn a_meter_keeps_its_figure_and_never_overruns_its_column() {
        for width in [0usize, 1, 8, 20, 30, 48, 120] {
            for share in [None, Some(0.0), Some(0.004), Some(0.5), Some(1.0)] {
                let line = meter("cpu", share, "38% of 22 cpus".to_string(), width);
                let bar = line
                    .iter()
                    .find_map(|run| run.text().strip_prefix('[').map(str::to_string));
                if let Some(bar) = bar {
                    let cells = bar.chars().take_while(|c| *c != ']').count();
                    let want = width.saturating_sub(LABEL).saturating_sub(FIGURE).min(BAR);
                    assert_eq!(cells, want, "{width} columns drew {cells} cells");
                }
                // The figure is on the line at every width; fitting it is the painter's job.
                assert!(
                    line.iter().any(|run| run.text().contains("38%")),
                    "{width} columns dropped the figure"
                );
            }
        }
    }

    /// The memory token is read as bytes so the meter has something to be a share of, and
    /// the spellings this does not know are absent rather than wrong.
    #[test]
    fn the_configured_memory_is_read_from_the_token_it_booted_with() {
        assert_eq!(configured(Some("8G")), Some(8 * 1024 * 1024 * 1024));
        assert_eq!(configured(Some("512M")), Some(512 * 1024 * 1024));
        assert_eq!(configured(None), None);
        assert_eq!(configured(Some("size=8G,hotplug=on")), None);
    }
}
