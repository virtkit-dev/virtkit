//! The screens that take the keyboard, and the whole screen with it.
//!
//! An overlay replaces the frame rather than being drawn over a cleared rectangle inside
//! it. There is no box to centre, so there is no width at which the box is wider than the
//! terminal and nothing to clip wrongly — the same house rule as the rest of the panel:
//! no borders, no popups, one line of heading and the content under it.

use crate::dash::actions::{Action, Weight};
use crate::dash::render::{Line, Style, span};
use crate::dash::state::{App, Confirm};
use crate::vms::fmt_uptime;

/// Every key the dashboard has, because a keymap is otherwise something a reader keeps in
/// their head or looks for in a README they do not have open.
const KEYS: &[(&str, &str)] = &[
    ("j k ↑ ↓", "move the selection"),
    ("pgup pgdn", "move it a page at a time"),
    ("home end", "the ends of the list, or of the pane below it"),
    ("tab", "move between the list and the pane below it"),
    (
        "1  2  3",
        "the console, what it costs this host, what its guest says",
    ),
    ("f", "follow the newest console line again"),
    (
        "K  A  G",
        "show the kernel, the agent, the guest — or stop showing one",
    ),
    ("[  ]", "show more of the console, or only what is worse"),
    ("r", "re-read the environments now"),
    ("s", "total what each of them holds on disk (slow)"),
    ("x", "what can be done to the selected environment"),
    ("a", "the guest's own view of itself, from vk atop"),
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
        "  it reads until you ask it for something, and what cannot be undone asks first",
        Style::Dim,
    )]);
    lines.push(Line::new());
    lines.push(vec![span("  any key closes this", Style::Dim)]);
    lines
}

/// The menu: what can be done to the selected environment, and for what cannot, why.
///
/// A greyed row with no reason beside it is a dashboard refusing to explain itself, so
/// every unavailable action carries its reason in words — the row is dim as well, but the
/// dimming is the second way of saying it and never the only one.
pub(crate) fn menu(app: &App, cols: usize) -> Vec<Line> {
    let Some(env) = app.selected_env() else {
        return vec![vec![span("nothing is selected", Style::Dim)]];
    };
    let mut lines = vec![
        vec![
            span(env.name(), Style::Bold),
            span(format!("  {}", env.state()), Style::Dim),
        ],
        Line::new(),
    ];
    for action in Action::ALL {
        lines.push(match app.availability(action) {
            Ok(()) => offered(action, cols),
            Err(refusal) => unavailable(action, refusal.short(), cols),
        });
    }
    lines.push(Line::new());
    for action in Action::ALL {
        if app.availability(action).is_ok() {
            lines.push(vec![
                span(format!("  {}  ", action.key()), Style::Dim),
                span(action.about(), Style::Dim),
            ]);
        }
    }
    lines
}

/// One action the reader can take.
fn offered(action: Action, cols: usize) -> Line {
    let head = format!("  {}  {}", action.key(), action.label());
    let mut line = vec![
        span(format!("  {}  ", action.key()), Style::Bold),
        span(action.label(), Style::Plain),
    ];
    // The mark is a word before it is a colour: this is the row a reader most needs to read
    // correctly on a terminal that has none.
    if action.weight() == Weight::Destructive {
        line.push(span(pad(&head, "destroys", cols), Style::Plain));
        line.push(span("destroys", Style::Alarm));
    }
    line
}

/// One it cannot take, and why.
fn unavailable(action: Action, why: &str, cols: usize) -> Line {
    let head = format!("  {}  {}", action.key(), action.label());
    vec![
        span(head.clone(), Style::Dim),
        span(pad(&head, why, cols), Style::Dim),
        span(why.to_string(), Style::Dim),
    ]
}

/// The gap that puts `tail` at the right-hand edge, and at least one space wherever the two
/// would otherwise touch or overlap.
fn pad(head: &str, tail: &str, cols: usize) -> String {
    let room = cols
        .saturating_sub(head.chars().count())
        .saturating_sub(tail.chars().count())
        .saturating_sub(2);
    " ".repeat(room.max(1))
}

/// One action that cannot be undone, waiting to be told to go ahead.
///
/// It shows the command it is about to run and what that command would take with it, both
/// read from this host rather than described — so the reader is agreeing to something
/// specific rather than to a word in a menu.
pub(crate) fn confirm(confirm: &Confirm, rows: usize) -> Vec<Line> {
    let job = &confirm.job;
    let mut lines = vec![
        vec![
            span(job.action.label(), Style::Alarm),
            span(format!("  {}", job.name), Style::Bold),
        ],
        vec![span(format!("  {}", job.action.about()), Style::Plain)],
        Line::new(),
        vec![span(format!("  {}", job.line()), Style::Dim)],
        Line::new(),
    ];
    match &confirm.removes {
        None => lines.push(vec![span("  reading what is in there…", Style::Dim)]),
        Some(removes) => {
            // The listing is as long as the directory is deep, and the answer belongs on
            // the screen whatever it says: what is left over is cut, with the count of what
            // was cut, rather than pushing the question off the bottom.
            let room = rows.saturating_sub(lines.len()).saturating_sub(2);
            let all: Vec<&str> = removes.lines().collect();
            for line in all.iter().take(room) {
                lines.push(vec![span(format!("  {line}"), Style::Plain)]);
            }
            if let Some(cut) = all.len().checked_sub(room).filter(|cut| *cut > 0) {
                lines.push(vec![span(
                    format!("  … and {cut} more line(s)"),
                    Style::Dim,
                )]);
            }
        }
    }
    lines.push(Line::new());
    lines.push(vec![
        span("  y", Style::Bold),
        span(" goes ahead", Style::Plain),
        span("  ·  any other key cancels", Style::Dim),
    ]);
    lines
}
