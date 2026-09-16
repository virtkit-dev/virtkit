//! The left column: every environment on this host, and what they come to between them.
//!
//! The list says as little as it can get away with — a marker, a name and a state — because
//! it is the spine of the screen and everything else is read from whichever row is marked.
//! The state is a word, so a reader with no colour, or with the wrong kind of colour
//! blindness, reads exactly what everyone else does.

use crate::dash::envs::Env;
use crate::dash::render::{Line, Style, short_name, span};
use crate::dash::state::{App, Focus};
use crate::usage::fmt_bytes;

/// The heading, the rows, and the two lines of figures under them.
pub(crate) fn lines(app: &App, width: usize, rows: usize) -> Vec<Line> {
    let mut out = vec![vec![span(
        "ENVIRONMENTS",
        match app.focus == Focus::List {
            true => Style::Bold,
            false => Style::Dim,
        },
    )]];
    // The heading and the two lines of figures are the list's own; what is left is rows.
    let room = rows.saturating_sub(3);
    if app.envs.is_empty() {
        out.push(match app.read {
            true => vec![span("no dev environments on this host", Style::Dim)],
            false => vec![span("reading…", Style::Dim)],
        });
    }
    // Scroll the window rather than the selection: the marked row stays on screen however
    // long the list is, and the rows above it are the ones that go.
    let first = match app.selected >= room {
        true => app.selected.saturating_sub(room).saturating_add(1),
        false => 0,
    };
    for (i, env) in app.envs.iter().enumerate().skip(first).take(room) {
        out.push(row(app, env, i == app.selected, width));
    }
    out.truncate(rows.saturating_sub(2));
    out.resize(rows.saturating_sub(2), Line::new());
    out.extend(summary(app));
    out
}

/// One row: the marker, the name, and the state word at the right-hand edge.
fn row(app: &App, env: &Env, selected: bool, width: usize) -> Line {
    let state = env.state();
    let name = short_name(env.name());
    // Two columns for the marker, one space before the state word.
    let room = width
        .saturating_sub(state.chars().count())
        .saturating_sub(3);
    let fitted: String = name.chars().take(room).collect();
    let padding = room
        .saturating_sub(fitted.chars().count())
        .saturating_add(1);

    let mut line = vec![
        span(
            match selected {
                true => "> ",
                false => "  ",
            },
            Style::Plain,
        ),
        span(
            fitted,
            match selected {
                true => Style::Bold,
                false => Style::Plain,
            },
        ),
        span(" ".repeat(padding), Style::Plain),
        span(
            state,
            match env.is_running() {
                true => Style::Good,
                false => Style::Dim,
            },
        ),
    ];
    if let Some(bytes) = app.sizes.get(&env.dir) {
        line.push(span(format!(" {}", fmt_bytes(*bytes)), Style::Dim));
    }
    line
}

/// What the list comes to: the counts on one line, the figures on the next.
///
/// Two lines rather than one because this column is thirty cells wide, and a single line
/// carrying the counts and both totals would lose the last of them — which is the number
/// the reader came for.
fn summary(app: &App) -> Vec<Line> {
    let (total, running, used) = app.totals();
    let mut figures = Vec::new();
    // Only a running VM costs anything, so a host with nothing up says nothing about
    // memory rather than claiming a total of zero.
    if let Some(bytes) = used {
        figures.push(format!("{} in use", fmt_bytes(bytes)));
    }
    // A size costs a walk of every file in every environment, so it is absent rather than
    // wrong until it is asked for, and the line says which key asks.
    let on_disk: u64 = app.sizes.values().copied().fold(0u64, u64::saturating_add);
    figures.push(match (app.sizes_pending, app.sizes.is_empty()) {
        (true, _) => "sizing…".to_string(),
        (false, true) => "s for size".to_string(),
        (false, false) => format!("{} on disk", fmt_bytes(on_disk)),
    });
    vec![
        vec![span(format!("{total} envs · {running} up"), Style::Plain)],
        vec![span(figures.join(" · "), Style::Dim)],
    ]
}
