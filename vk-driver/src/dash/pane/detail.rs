//! The selected environment, in as many facts as the column has room for.
//!
//! The figures are written in virtkit's own shapes — `3h7m`, `304M/8G`, `1.6 GiB` — by the
//! same functions `vk list` and `vk dev list` write them with, so a reader moving between a
//! listing and this screen is reading one notation and not two.

use crate::dash::render::{Line, Style, span, tilde};
use crate::dash::state::App;
use crate::vms::{fmt_uptime, mem_cell};

/// How wide the label column is, so the values line up to the eye.
const LABEL: usize = 10;

/// The facts about whichever environment is selected.
pub(crate) fn lines(app: &App, width: usize) -> Vec<Line> {
    let Some(env) = app.selected_env() else {
        return vec![vec![span("nothing selected", Style::Dim)]];
    };
    let mut out = vec![vec![
        span(env.name(), Style::Bold),
        span("  ", Style::Plain),
        span(
            env.state(),
            match env.is_running() {
                true => Style::Good,
                false => Style::Dim,
            },
        ),
    ]];
    if let Some(workspace) = env.workspace() {
        out.push(field("workspace", tilde(workspace), width));
    }
    out.push(field("state", tilde(&env.dir), width));

    let Some(vm) = &env.vm else {
        // A stopped environment has no VM to describe, so the column says what is known
        // about it instead of leaving four empty rows.
        if let Some(row) = &env.row {
            let mut about = Vec::new();
            if let Some(age) = row.age_secs {
                about.push(format!("last seen {} ago", fmt_uptime(age)));
            }
            if let Some(environment) = &row.environment {
                about.push(environment.clone());
            }
            if !about.is_empty() {
                out.push(field("env", about.join("  "), width));
            }
        }
        out.push(vec![span("not running", Style::Dim)]);
        return out;
    };

    let mut facts = vec![format!("pid {}", vm.pid)];
    if let Some(vmm) = &vm.vmm {
        facts.push(vmm.clone());
    }
    if let Some(cpus) = vm.cpus {
        facts.push(format!("{cpus} cpus"));
    }
    if let Some(secs) = env.uptime_secs() {
        facts.push(fmt_uptime(secs));
    }
    if vm.nested == Some(true) {
        facts.push("nested".to_string());
    }
    out.push(field("vm", facts.join("  "), width));
    // A line of its own rather than the tail of the one above: what a VM is costing is one
    // of the two things a reader opens this column for, and on an eighty-column terminal
    // the fact list above is long enough to have truncated it away.
    out.push(field(
        "mem",
        mem_cell(env.mem_used, env.mem_configured()),
        width,
    ));
    if let Some(ip) = &vm.guest_ip {
        // The exec address is deliberately not here: a live one is a hundred characters of
        // socket path that no reader types, and it would fill this line with an ellipsis.
        out.push(field("guest", ip.to_string(), width));
    }
    out
}

/// One `label value` row, the label dimmed so the values are what the eye follows.
fn field(label: &str, value: impl AsRef<str>, width: usize) -> Line {
    let room = width.saturating_sub(LABEL);
    let value: String = value.as_ref().chars().take(room).collect();
    vec![
        span(format!("{label:<LABEL$}"), Style::Dim),
        span(value, Style::Plain),
    ]
}
