//! The screens that take the keyboard, and the whole screen with it.
//!
//! An overlay replaces the frame rather than being drawn over a cleared rectangle inside
//! it. There is no box to centre, so there is no width at which the box is wider than the
//! terminal and nothing to clip wrongly — the same house rule as the rest of the panel:
//! no borders, no popups, one line of heading and the content under it.

use crate::dash::render::{Line, Style, span};
use crate::dash::state::App;
use crate::vms::fmt_uptime;

/// Every key the dashboard has, because a keymap is otherwise something a reader keeps in
/// their head or looks for in a README they do not have open.
const KEYS: &[(&str, &str)] = &[
    ("j k ↑ ↓", "move the selection"),
    ("pgup pgdn", "move it a page at a time"),
    ("home end", "the first environment, or the last"),
    ("tab", "move between the list and the pane below it"),
    (
        "1  2",
        "the console, or what the environment costs this host",
    ),
    ("r", "re-read the environments now"),
    ("s", "total what each of them holds on disk (slow)"),
    ("?", "this"),
    ("q  esc  ctrl-c", "quit"),
];

/// The help screen: the keys, and what the dashboard is doing between them.
pub(crate) fn help(app: &App, _cols: usize) -> Vec<Line> {
    let mut lines = vec![vec![span("vk dash", Style::Bold)], Line::new()];
    for (keys, what) in KEYS {
        lines.push(vec![
            span(format!("  {keys:<16}"), Style::Bold),
            span(*what, Style::Plain),
        ]);
    }
    lines.push(Line::new());
    lines.push(vec![span(
        format!(
            "  the environment list re-reads every {}",
            fmt_uptime(app.interval.as_secs())
        ),
        Style::Dim,
    )]);
    lines.push(vec![span(
        "  the dashboard reads; it changes nothing on this host",
        Style::Dim,
    )]);
    lines.push(Line::new());
    lines.push(vec![span("  any key closes this", Style::Dim)]);
    lines
}
