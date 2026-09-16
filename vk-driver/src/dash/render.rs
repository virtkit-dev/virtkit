//! The screen: one frame built as a single string, and the handful of rules that keep it
//! honest.
//!
//! A frame is exactly as many lines as the terminal has rows and every line is at most as
//! many columns as it has, whatever it was handed to draw. That is enforced in one place —
//! [`Painter`] — rather than by each pane counting for itself, and it is enforced **before**
//! anything is styled: an escape sequence must never be counted as a column, and a styled
//! line must never overrun because its colour was measured as text. Nothing else in this
//! module or in [`crate::dash::pane`] writes an escape sequence at all.
//!
//! Colour is an accent and never the only thing carrying a meaning: the showing tab is the
//! one in brackets, which half has the keys is said in words on the key bar. With colour
//! off not one escape sequence beyond the cursor controls is emitted, and the screen says
//! everything the coloured one does.

use unicode_width::UnicodeWidthChar;

use super::pane;
use super::state::{App, Focus, Mode, Pane};

/// How wide the environment list is. Enough for a name, the marker beside it and the
/// longest state word, which is what decides it.
const LIST_WIDTH: usize = 30;

/// The narrowest right-hand column worth having. Below this the list takes the whole
/// screen rather than two columns that can each hold half a word.
const MIN_RIGHT: usize = 20;

/// How much of the right-hand column the selected environment's facts get.
const DETAIL_ROWS: usize = 7;

/// How a run of text is drawn. Every one of these has a meaning the words already carry;
/// the style only makes it quicker to find.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Style {
    Plain,
    /// present, but not the point
    Dim,
    /// what the eye should land on first
    Bold,
    /// wants the reader
    Alarm,
}

impl Style {
    /// The escape sequence that sets this style, or nothing for the default one.
    fn sgr(self) -> &'static str {
        match self {
            Style::Plain => "",
            Style::Bold => "\x1b[1m",
            Style::Dim => "\x1b[2m",
            Style::Alarm => "\x1b[31m",
        }
    }
}

/// One run of text and how it is drawn.
#[derive(Debug, Clone)]
pub(crate) struct Span {
    text: String,
    style: Style,
}

/// A run of text, for a pane to build a line out of.
pub(crate) fn span(text: impl Into<String>, style: Style) -> Span {
    Span {
        text: text.into(),
        style,
    }
}

/// One line of a pane, before it is fitted to the screen.
pub(crate) type Line = Vec<Span>;

/// Builds one line of the frame, keeping count of the columns it has used.
///
/// Clipping happens per run and before styling, which is what makes the count trustworthy:
/// a style is an escape sequence, and an escape sequence occupies no columns however many
/// bytes it is. A character the terminal would not draw as a cell of its own — a control
/// byte, a combining mark — is dropped rather than passed through, so guest text cannot
/// reach the terminal as an instruction even if it arrives here unwashed.
pub(crate) struct Painter {
    out: String,
    /// columns used so far
    width: usize,
    /// columns there are
    cols: usize,
    colour: bool,
    /// whether a style is in force and still has to be turned off
    open: bool,
}

impl Painter {
    pub(crate) fn new(cols: usize, colour: bool) -> Self {
        Self {
            out: String::new(),
            width: 0,
            cols,
            colour,
            open: false,
        }
    }

    /// Draw `text` in `style`, as much of it as there is room for.
    pub(crate) fn push(&mut self, text: &str, style: Style) {
        let (fitted, used) = fit(text, self.cols.saturating_sub(self.width));
        if fitted.is_empty() {
            return;
        }
        let sgr = match self.colour {
            true => style.sgr(),
            false => "",
        };
        if sgr.is_empty() {
            if self.open {
                self.out.push_str(RESET);
                self.open = false;
            }
        } else {
            self.out.push_str(sgr);
            self.open = true;
        }
        self.out.push_str(&fitted);
        self.width = self.width.saturating_add(used);
    }

    /// Fill with spaces up to column `col`, if the line has not already passed it.
    pub(crate) fn pad_to(&mut self, col: usize) {
        let room = col.min(self.cols).saturating_sub(self.width);
        if room > 0 {
            self.push(&" ".repeat(room), Style::Plain);
        }
    }

    /// The line, with whatever style was left in force turned off.
    pub(crate) fn finish(mut self) -> String {
        if self.open {
            self.out.push_str(RESET);
        }
        self.out
    }
}

/// Back to the terminal's own colours. Emitted only where a style was.
const RESET: &str = "\x1b[0m";

/// As much of `text` as fits in `room` columns, and how many it took.
fn fit(text: &str, room: usize) -> (String, usize) {
    let mut out = String::new();
    let mut used = 0usize;
    for c in text.chars() {
        // Zero-width is every character a terminal does not give a cell to, control bytes
        // among them. Dropping them is what keeps the count and the screen in agreement.
        let Some(w) = UnicodeWidthChar::width(c).filter(|w| *w > 0) else {
            continue;
        };
        if used.saturating_add(w) > room {
            break;
        }
        used = used.saturating_add(w);
        out.push(c);
    }
    (out, used)
}

/// The frame for a screen of `rows` by `cols`: the whole screen as one string, ready to be
/// written in one call.
///
/// Lines are terminated `\r\n` — the terminal is in raw mode, where a newline alone drops a
/// row without returning to the left edge — and the last one is not terminated at all,
/// since a line break on the bottom row scrolls the screen and would creep the whole
/// dashboard upwards on every repaint.
pub(crate) fn frame(app: &App, rows: u16, cols: u16) -> String {
    let rows = (rows as usize).max(1);
    let cols = (cols as usize).max(1);
    let mut out = String::with_capacity(rows.saturating_mul(cols));
    // Home the cursor rather than clearing the screen: every frame overwrites the last, and
    // each line clears its own tail, so nothing flickers between frames.
    out.push_str("\x1b[H");

    // The keys belong on the bottom row, where a reader looks for them, so the screen is
    // filled to there whatever the rest had to say.
    let body = rows.saturating_sub(1);
    let mut lines = match app.mode {
        Mode::Help => paint_all(&pane::overlay::help(app, cols), cols, app.colour),
        Mode::Normal => dashboard(app, body, cols),
    };
    lines.truncate(body);
    lines.resize(body, String::new());
    lines.push(paint(&key_bar(app, cols), cols, app.colour));

    let last = lines.len().saturating_sub(1);
    for (i, line) in lines.iter().enumerate() {
        out.push_str(line);
        out.push_str("\x1b[K"); // clear whatever the last frame left on this row
        if i < last {
            out.push_str("\r\n");
        }
    }
    out.push_str("\x1b[J"); // and whatever it left below
    out
}

/// The dashboard itself: the list on the left, the selected environment on the right, with
/// one column of rule between them. A terminal too narrow for two columns gets the list,
/// which is the half that says what is on the host.
fn dashboard(app: &App, rows: usize, cols: usize) -> Vec<String> {
    let two = cols >= LIST_WIDTH.saturating_add(MIN_RIGHT).saturating_add(1);
    if !two {
        return paint_all(&left_column(app, cols), cols, app.colour);
    }
    let right_width = cols.saturating_sub(LIST_WIDTH).saturating_sub(2);
    let left = left_column(app, LIST_WIDTH);
    let right = right_column(app, right_width);
    (0..rows)
        .map(|i| {
            let mut painter = Painter::new(cols, app.colour);
            paint_into(&mut painter, left.get(i));
            painter.pad_to(LIST_WIDTH);
            painter.push("│", Style::Dim);
            painter.push(" ", Style::Plain);
            paint_into(&mut painter, right.get(i));
            painter.finish()
        })
        .collect()
}

/// The left-hand column: what is on this host.
fn left_column(app: &App, _width: usize) -> Vec<Line> {
    vec![
        vec![span("ENVIRONMENTS", heading(app.focus == Focus::List))],
        Line::new(),
        vec![span("nothing read yet", Style::Dim)],
    ]
}

/// The right-hand column: the selected environment's facts, then the tab strip, then
/// whichever pane it names.
fn right_column(app: &App, width: usize) -> Vec<Line> {
    let mut lines = vec![vec![span("nothing selected", Style::Dim)]];
    lines.resize(DETAIL_ROWS, Line::new());
    lines.push(tabs(app));
    lines.push(vec![span("─".repeat(width), Style::Dim)]);
    lines
}

/// How the heading of a column is drawn, given whether the movement keys belong to it.
/// Weight rather than hue, so it survives a terminal with no colour — and the key bar says
/// which in words, so it survives one with no styling at all.
fn heading(focused: bool) -> Style {
    match focused {
        true => Style::Bold,
        false => Style::Dim,
    }
}

/// The tab strip. Which tab is showing is said by the brackets as well as by the weight,
/// since there may be no colour to say it with.
fn tabs(app: &App) -> Line {
    let focused = app.focus == Focus::Lower;
    let mut line = Line::new();
    for (key, name, pane) in [('1', "console", Pane::Console), ('2', "usage", Pane::Usage)] {
        let showing = app.pane == pane;
        let label = match showing {
            true => format!("[{key}] {name}  "),
            false => format!(" {key}  {name}  "),
        };
        let style = match (showing, focused) {
            (true, true) => Style::Bold,
            (true, false) => Style::Plain,
            (false, _) => Style::Dim,
        };
        line.push(span(label, style));
    }
    line
}

/// The key bar, or whatever the dashboard has to say instead.
///
/// The hints are dropped from the right as the terminal narrows, except the last two:
/// whatever else goes, a reader must always be able to see how to get help and how to get
/// out. Clipping one fixed string would take those two first, which is exactly backwards.
fn key_bar(app: &App, cols: usize) -> Line {
    const ALWAYS: &str = "? help  q quit";
    // A complaint takes the bar for as long as it is unread: a key bar the reader already
    // knows is worth less than the reason the dashboard is not saying what they expected.
    if let Some(said) = &app.status {
        return vec![span(format!(" {said}"), Style::Alarm)];
    }
    let focus = match app.focus {
        Focus::List => "tab pane",
        Focus::Lower => "tab list",
    };
    let mut bar = String::from(" ");
    let mut used = 1usize.saturating_add(ALWAYS.chars().count());
    for hint in [focus, "1/2 pane"] {
        let cost = hint.chars().count().saturating_add(2);
        if used.saturating_add(cost) > cols {
            break;
        }
        used = used.saturating_add(cost);
        bar.push_str(hint);
        bar.push_str("  ");
    }
    bar.push_str(ALWAYS);
    vec![span(bar, Style::Dim)]
}

/// Fit one pane line to the screen.
fn paint(line: &Line, cols: usize, colour: bool) -> String {
    let mut painter = Painter::new(cols, colour);
    paint_into(&mut painter, Some(line));
    painter.finish()
}

fn paint_all(lines: &[Line], cols: usize, colour: bool) -> Vec<String> {
    lines.iter().map(|line| paint(line, cols, colour)).collect()
}

fn paint_into(painter: &mut Painter, line: Option<&Line>) {
    for run in line.into_iter().flatten() {
        painter.push(&run.text, run.style);
    }
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
    use std::time::Duration;

    /// Every size a frame might be asked for, from one that cannot hold a word to one
    /// bigger than any terminal.
    const SIZES: [(u16, u16); 9] = [
        (1, 1),
        (2, 4),
        (4, 2),
        (5, 20),
        (8, 32),
        (24, 80),
        (24, 200),
        (60, 120),
        (3, 49),
    ];

    fn app() -> App {
        App::new(Duration::from_secs(3), false)
    }

    /// The rows of a frame, as the terminal would see them: the cursor controls that
    /// separate them removed, so what is left is what is drawn.
    fn rows_of(frame: &str) -> Vec<String> {
        let body = frame
            .strip_prefix("\x1b[H")
            .and_then(|rest| rest.strip_suffix("\x1b[J"))
            .unwrap_or(frame);
        body.split("\r\n")
            .map(|line| line.replace("\x1b[K", ""))
            .collect()
    }

    /// The columns a line occupies, with every escape sequence taken out first.
    fn columns(line: &str) -> usize {
        let mut width = 0usize;
        let mut chars = line.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // every sequence this module writes is CSI, ended by a letter
                for tail in chars.by_ref() {
                    if tail.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            width = width.saturating_add(UnicodeWidthChar::width(c).unwrap_or(0));
        }
        width
    }

    /// A frame fills the screen it was given and never overruns it. A line one column too
    /// long wraps, and a wrap scrolls the dashboard a row further up on every repaint —
    /// which is why this is asserted at every size rather than at the one a terminal
    /// usually is.
    #[test]
    fn a_frame_is_exactly_the_screen_it_was_given() {
        for (rows, cols) in SIZES {
            for mode in [Mode::Normal, Mode::Help] {
                let mut app = app();
                app.mode = mode.clone();
                app.colour = true;
                let frame = frame(&app, rows, cols);
                let drawn = rows_of(&frame);
                assert_eq!(
                    drawn.len(),
                    rows as usize,
                    "{rows}x{cols} {mode:?} drew {} rows",
                    drawn.len()
                );
                for line in &drawn {
                    assert!(
                        columns(line) <= cols as usize,
                        "{rows}x{cols} {mode:?} drew {} columns: {line:?}",
                        columns(line)
                    );
                }
            }
        }
    }

    /// The frame is written in one call with the cursor homed and every line erasing its
    /// own tail — and nothing after the bottom row, which would scroll the screen.
    #[test]
    fn a_frame_homes_the_cursor_and_erases_as_it_goes() {
        let frame = frame(&app(), 24, 80);
        assert!(frame.starts_with("\x1b[H"));
        assert!(frame.ends_with("\x1b[J"));
        assert!(
            !frame.contains("\x1b[2J"),
            "the screen was cleared outright"
        );
        assert_eq!(frame.matches("\x1b[K").count(), 24);
        assert_eq!(frame.matches("\r\n").count(), 23);
    }

    /// With colour off, not one escape sequence beyond the cursor controls is written. A
    /// reader on a terminal that has no colour, or who asked for none, reads exactly what
    /// everyone else does.
    #[test]
    fn nothing_is_coloured_when_colour_is_off() {
        for mode in [Mode::Normal, Mode::Help] {
            let mut app = app();
            app.mode = mode;
            app.status = Some("something went wrong".to_string());
            let frame = frame(&app, 24, 80);
            for sequence in frame.split('\x1b').skip(1) {
                let kind = sequence.chars().take(2).collect::<String>();
                assert!(
                    matches!(kind.as_str(), "[H" | "[K" | "[J"),
                    "an escape sequence was drawn without colour: {sequence:?}"
                );
            }
        }
        // And with colour on, the styles are turned off again rather than left in force.
        let mut coloured = app();
        coloured.colour = true;
        coloured.status = Some("something went wrong".to_string());
        let frame = frame(&coloured, 24, 80);
        assert!(frame.contains("\x1b[31m"));
        assert!(frame.contains(RESET));
    }

    /// Whatever reaches the painter is text and not an instruction. A guest can write
    /// anything at all into its console, and a line of it holding `ESC [ 2 J` would
    /// otherwise clear the screen the dashboard is drawing on.
    #[test]
    fn text_cannot_drive_the_terminal() {
        let hostile = "boot\x1b[2Jtime\x07\x1b[31mred\r\ndrop";
        let mut painter = Painter::new(40, true);
        painter.push(hostile, Style::Plain);
        let drawn = painter.finish();
        assert!(!drawn.contains('\x1b'), "{drawn:?}");
        assert!(!drawn.contains('\r'), "{drawn:?}");
        assert!(!drawn.contains('\n'), "{drawn:?}");
        assert!(!drawn.contains('\x07'), "{drawn:?}");
        assert_eq!(drawn, "boot[2Jtime[31mreddrop");
    }

    /// A run is cut to the columns there are, counted as the terminal counts them, and the
    /// cut happens before the style so an escape sequence is never taken for a column.
    #[test]
    fn a_painter_never_overruns_the_width_it_was_given() {
        for cols in [0usize, 1, 3, 9, 40] {
            let mut painter = Painter::new(cols, true);
            painter.push("running", Style::Alarm);
            painter.pad_to(cols.saturating_add(20));
            painter.push("日本語のテキスト", Style::Bold);
            let drawn = painter.finish();
            assert!(columns(&drawn) <= cols, "{cols}: {drawn:?}");
        }
        // A double-width character that would take the last remaining column is dropped
        // whole rather than drawn as half of itself.
        let mut painter = Painter::new(3, false);
        painter.push("ab", Style::Plain);
        painter.push("日", Style::Plain);
        assert_eq!(painter.finish(), "ab");
    }
}
