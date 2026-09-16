//! The console pane: a window onto the lines the dashboard is keeping for the selected
//! environment.
//!
//! Its first line is about the pane rather than about the guest — how much of the buffer is
//! showing, what is hiding the rest, and whether this is still the newest line. A reader who
//! scrolled up has to be told that lines are arriving somewhere they cannot see, and a
//! reader whose filter admits nothing has to be told which key undoes it.
//!
//! Every line carries its writer as a letter and its severity as a mark, not only as a
//! colour: the dashboard is read on terminals that have none, and in screenshots of them.
//! Nothing here makes the text safe, because nothing here needs to — the lines reach
//! [`crate::dash::render::Painter`], which gives a cell only to characters that occupy one,
//! so a guest's escape sequence arrives as the letters it is spelled with.

use crate::consolelog::{Level, Line as Classified};
use crate::dash::console;
use crate::dash::render::{Line, Style, span};
use crate::dash::state::App;

/// The gutter: a severity mark, a writer's letter, and the space between them and the text.
const GUTTER: usize = 3;

/// The console of whichever environment is selected, in the room it has.
pub(crate) fn lines(app: &App, width: usize, rows: usize) -> Vec<Line> {
    if rows == 0 {
        return Vec::new();
    }
    if app.selected_env().is_none() {
        return vec![note("nothing selected")];
    }
    if app.console.is_empty() {
        return vec![note(match app.console_missing {
            true => "no console: this environment has never booted",
            false => "waiting for the console…",
        })];
    }
    let shown: Vec<&Classified> = app.console.shown(&app.filter).collect();
    if shown.is_empty() {
        return vec![
            status(app, 0),
            note("everything is hidden — KAG show a writer, [ ] move the level"),
        ];
    }

    // The window ends `scrollback` lines back from the newest and fills what the status
    // line leaves.
    let end = shown.len().saturating_sub(app.scrollback);
    let start = end.saturating_sub(rows.saturating_sub(1));
    let mut out = vec![status(app, shown.len())];
    for line in shown.get(start..end).unwrap_or_default() {
        out.push(render(line, width));
    }
    out
}

/// What the pane is showing, out of what it holds, and under which filter.
fn status(app: &App, shown: usize) -> Line {
    let mut text = format!(
        "{shown}/{} lines · {}",
        app.console.len(),
        app.filter.summary()
    );
    let dropped = app.console.dropped();
    if dropped > 0 {
        text.push_str(&format!(" · {dropped} older forgotten"));
    }
    text.push_str(match app.following() {
        true => " · following",
        false => " · scrolled, end to follow",
    });
    vec![span(text, Style::Dim)]
}

/// One line: the marks, then what was written.
fn render(line: &Classified, width: usize) -> Line {
    let mark = match line.level {
        Some(Level::Error) => '!',
        Some(Level::Warn) => '*',
        _ => ' ',
    };
    let style = match line.level {
        Some(Level::Error) => Style::Alarm,
        Some(Level::Warn) => Style::Warn,
        _ => Style::Plain,
    };
    vec![
        span(
            format!("{mark}{} ", console::source_mark(line.source)),
            match style {
                Style::Plain => Style::Dim,
                other => other,
            },
        ),
        span(
            line.text
                .chars()
                .take(width.saturating_sub(GUTTER))
                .collect::<String>(),
            style,
        ),
    ]
}

/// A pane with nothing to draw says why, where the lines would have been.
fn note(said: &str) -> Line {
    vec![span(said, Style::Dim)]
}
