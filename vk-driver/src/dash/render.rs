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

use std::path::Path;

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
    /// running, or otherwise fine
    Good,
    /// went wrong and was continued past
    Warn,
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
            Style::Good => "\x1b[32m",
            Style::Warn => "\x1b[33m",
        }
    }
}

/// One run of text and how it is drawn.
#[derive(Debug, Clone)]
pub(crate) struct Span {
    text: String,
    style: Style,
}

impl Span {
    /// What this run says, for a test that asserts on a line before it is painted.
    #[cfg(test)]
    pub(crate) fn text(&self) -> &str {
        &self.text
    }
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
    /// the column this line may not draw past, for as long as it stands: what keeps one
    /// column of a two-column layout out of the next
    limit: usize,
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
            limit: cols,
            colour,
            open: false,
        }
    }

    /// Draw nothing past column `col` until [`Painter::unlimit`] lifts it.
    pub(crate) fn limit(&mut self, col: usize) {
        self.limit = col.min(self.cols);
    }

    /// Give the rest of the screen back.
    pub(crate) fn unlimit(&mut self) {
        self.limit = self.cols;
    }

    /// Draw `text` in `style`, as much of it as there is room for.
    pub(crate) fn push(&mut self, text: &str, style: Style) {
        let (fitted, used) = fit(text, self.limit.saturating_sub(self.width));
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
        let room = col.min(self.limit).saturating_sub(self.width);
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
        return paint_all(&pane::list::lines(app, cols, rows), cols, app.colour);
    }
    let right_width = cols.saturating_sub(LIST_WIDTH).saturating_sub(2);
    let left = pane::list::lines(app, LIST_WIDTH, rows);
    let right = right_column(app, right_width, rows);
    (0..rows)
        .map(|i| {
            let mut painter = Painter::new(cols, app.colour);
            // The list keeps to its own column: a long name or a long total must not run
            // through the rule and into the facts on the other side of it.
            painter.limit(LIST_WIDTH);
            paint_into(&mut painter, left.get(i));
            painter.pad_to(LIST_WIDTH);
            painter.unlimit();
            painter.push("│", Style::Dim);
            painter.push(" ", Style::Plain);
            paint_into(&mut painter, right.get(i));
            painter.finish()
        })
        .collect()
}

/// The right-hand column: the selected environment's facts, then the tab strip, then
/// whichever pane it names.
fn right_column(app: &App, width: usize, rows: usize) -> Vec<Line> {
    let mut lines = pane::detail::lines(app, width);
    lines.truncate(DETAIL_ROWS);
    lines.resize(DETAIL_ROWS, Line::new());
    lines.push(tabs(app));
    lines.push(vec![span("─".repeat(width), Style::Dim)]);
    // Whatever the facts and the strip did not take belongs to the pane the strip names.
    let room = rows.saturating_sub(lines.len());
    lines.extend(match app.pane {
        Pane::Console => pane::console::lines(app, width, room),
        Pane::Usage => pane::usage::lines(app, width, room),
    });
    lines
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
    let mut hints = vec!["j/k move", focus, "1/2 pane"];
    // The console's keys before the list's: a reader looking at a guest's console wants
    // them more than the two that re-read the host, and the bar drops hints from the right.
    if app.pane == Pane::Console {
        hints.extend(["f follow", "KAG source", "[ ] level"]);
    }
    hints.extend(["s size", "r refresh"]);
    let mut bar = String::from(" ");
    let mut used = 1usize.saturating_add(ALWAYS.chars().count());
    for hint in hints {
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

/// A name with its hash cut to something a column can hold.
///
/// An environment is called `virtkit-4171942f2d70bae7`: a stem naming the checkout and
/// sixteen hex digits telling it apart from the other environment over the same one. The
/// stem is what a reader reads and the hash is what they need only enough of to tell two
/// rows apart, so the list keeps the stem whole and the first eight of the hash. The full
/// name stays the name everywhere it matters, the column beside it included.
pub(crate) fn short_name(name: &str) -> String {
    /// Enough hex to tell apart every environment on a host, and no more.
    const KEEP: usize = 8;

    let Some((stem, hash)) = name.rsplit_once('-') else {
        return name.to_string();
    };
    let hashlike = hash.len() > KEEP && hash.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !hashlike {
        return name.to_string();
    }
    let kept: String = hash.chars().take(KEEP).collect();
    format!("{stem}-{kept}")
}

/// A path with the reader's home written as `~`, which is how they think of it and how it
/// fits in a column this wide.
pub(crate) fn tilde(path: &Path) -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return path.display().to_string();
    };
    match path.strip_prefix(Path::new(&home)) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
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
    use crate::dash::poll::Event;
    use crate::term::Press;
    use std::path::PathBuf;
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

    /// A dashboard with a host's worth of environments read into it: one running, one
    /// stopped, one that answers to no environment, and a name long enough to have to be
    /// cut down to the column.
    fn read_app() -> App {
        use crate::dash::envs::fixture::{row, vm};
        use crate::dash::poll::Event;
        use crate::dev::list::Status;

        let mut app = app();
        app.on_event(Event::Envs(crate::dash::envs::join(
            vec![
                row("virtkit-4171942f2d70bae7", "/state/a", Status::Running),
                row("wab-qa-d3a92b42d7d0a15f", "/state/b", Status::Stopped),
            ],
            vec![vm("/state/a", 3928432), vm("/state/scratch", 4242)],
        )));
        app.sizes.insert(PathBuf::from("/state/a"), 63_887_450_112);
        app.on_event(Event::Log(console_batch(
            &app,
            &[
                "[    0.420000] virtio_net virtio0 eth0: renamed from enp0s1",
                "13:46:39 [INFO] vk-agent init: mounted /work",
                "13:46:41 [WARN] vk-agent init: dhclient failed, falling back",
                "[    9.120000] Out of memory: Killed process 7 (cc1plus)",
                "Started OpenBSD Secure Shell server.",
            ],
        )));
        // Two readings of the selected environment's process tree, five seconds apart: one
        // alone says what it has used since it booted, never what it is doing now.
        let now = std::time::Instant::now();
        let earlier = now.checked_sub(Duration::from_secs(5)).unwrap_or(now);
        for (cpu, at) in [(40u64, earlier), (44, now)] {
            app.on_event(Event::Sample(crate::dash::poll::Sample {
                epoch: app.console_epoch(),
                cpu: Duration::from_secs(cpu),
                peak_rss: 2_202_009_600,
                disk: Some((1_717_986_918, 883_195_904)),
                at,
            }));
        }
        app
    }

    /// Console lines, as the tail hands them over for whatever is selected now.
    fn console_batch(app: &App, raw: &[&str]) -> crate::dash::console::Batch {
        crate::dash::console::Batch {
            epoch: app.console_epoch(),
            lines: raw
                .iter()
                .map(|line| crate::consolelog::classify(line))
                .collect(),
            ..crate::dash::console::Batch::default()
        }
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
                // Before anything has been read and after, since the two draw different
                // things into the same room — and under each of the panes the room is
                // shared with.
                for mut app in [app(), read_app()] {
                    for pane in [Pane::Console, Pane::Usage] {
                        app.pane = pane;
                        app.mode = mode.clone();
                        app.colour = true;
                        let frame = frame(&app, rows, cols);
                        let drawn = rows_of(&frame);
                        assert_eq!(
                            drawn.len(),
                            rows as usize,
                            "{rows}x{cols} {mode:?} {pane:?} drew {} rows",
                            drawn.len()
                        );
                        for line in &drawn {
                            assert!(
                                columns(line) <= cols as usize,
                                "{rows}x{cols} {mode:?} {pane:?} drew {} columns: {line:?}",
                                columns(line)
                            );
                        }
                    }
                }
            }
        }
    }

    /// What the dashboard has read reaches the screen: the list marks the selected row, the
    /// state is a word, and the column beside it is about that row and not another.
    #[test]
    fn the_frame_says_what_was_read() {
        let app = read_app();
        let drawn = rows_of(&frame(&app, 24, 100)).join("\n");
        assert!(drawn.contains("> scratch"), "{drawn}");
        assert!(drawn.contains("virtkit-4171942f "), "the name was not cut");
        assert!(drawn.contains("running"), "{drawn}");
        assert!(drawn.contains("stopped"), "{drawn}");
        assert!(drawn.contains("3 envs · 2 up"), "{drawn}");
        assert!(drawn.contains("59.5 GiB on disk"), "{drawn}");
        // The right-hand column is about the marked row and no other.
        assert!(drawn.contains("pid 4242"), "{drawn}");
        assert!(drawn.contains("192.168.127.2"), "{drawn}");

        // And it follows the selection when that moves.
        let mut moved = read_app();
        moved.key(Press::Char('j'));
        let drawn = rows_of(&frame(&moved, 24, 100)).join("\n");
        assert!(drawn.contains("> virtkit-4171942f"), "{drawn}");
        assert!(drawn.contains("pid 3928432"), "{drawn}");
    }

    /// The console pane says what it is showing out of what it holds, and marks each line
    /// with who wrote it and how bad it is — in characters, so a terminal with no colour
    /// says everything a terminal with colour does.
    #[test]
    fn the_console_pane_marks_its_lines_and_says_what_is_hidden() {
        let mut app = read_app();
        let drawn = rows_of(&frame(&app, 24, 100)).join("\n");
        assert!(
            drawn.contains("5/5 lines · kernel+agent+guest · following"),
            "{drawn}"
        );
        assert!(
            drawn.contains("!k "),
            "a kernel alarm was not marked: {drawn}"
        );
        assert!(drawn.contains("*a "), "an agent warning was not marked");
        assert!(drawn.contains(" g Started OpenBSD"), "{drawn}");

        // Hiding two of the three writers changes the line that says so, and says which
        // keys bring them back.
        app.key(Press::Char('K'));
        app.key(Press::Char('G'));
        let drawn = rows_of(&frame(&app, 24, 100)).join("\n");
        assert!(drawn.contains("2/5 lines · agent · following"), "{drawn}");
        assert!(!drawn.contains("Started OpenBSD"), "{drawn}");
        assert!(drawn.contains("KAG source"), "the keys to undo it are gone");
    }

    /// The usage pane says whose figures these are. A reader who takes the host's cost for
    /// the guest's own view of itself reads every number on it backwards.
    #[test]
    fn the_usage_pane_says_it_is_the_host_that_is_paying() {
        let mut app = read_app();
        app.pane = Pane::Usage;
        let drawn = rows_of(&frame(&app, 24, 100)).join("\n");
        assert!(drawn.contains("host cost"), "{drawn}");
        assert!(drawn.contains("not what the guest sees"), "{drawn}");
        // Four seconds of processor over five of wall clock, across twenty-two vCPUs.
        assert!(drawn.contains("4% of 22 cpus"), "{drawn}");
        assert!(drawn.contains("44.0s used since it booted"), "{drawn}");
        assert!(drawn.contains("2.1 GiB at its highest"), "{drawn}");
        assert!(drawn.contains("1.6 GiB read · 842 MiB written"), "{drawn}");
        assert!(
            drawn.contains("vk atop"),
            "the guest's own panel is not named"
        );

        // Another environment is another process tree, and two readings of two of them make
        // no rate between them: the pane waits for its own rather than showing the last
        // one's figures under this one's name.
        app.key(Press::Char('j'));
        let drawn = rows_of(&frame(&app, 24, 100)).join("\n");
        assert!(drawn.contains("reading the process tree"), "{drawn}");

        // And one that is not running costs nothing, which is a fact rather than a set of
        // empty meters.
        app.key(Press::Char('j'));
        let drawn = rows_of(&frame(&app, 24, 100)).join("\n");
        assert!(drawn.contains("costing this host nothing"), "{drawn}");
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
        // Including the panes that draw bars and console lines, which is where the escape
        // sequences would come from if any pane wrote its own.
        for pane in [Pane::Console, Pane::Usage] {
            let mut app = read_app();
            app.pane = pane;
            let frame = frame(&app, 24, 100);
            for sequence in frame.split('\x1b').skip(1) {
                let kind = sequence.chars().take(2).collect::<String>();
                assert!(
                    matches!(kind.as_str(), "[H" | "[K" | "[J"),
                    "{pane:?} drew an escape sequence without colour: {sequence:?}"
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

        // And through the path a guest's text actually takes: a console line, classified,
        // kept, filtered and drawn into a whole frame. `consolelog` takes the sequence out
        // where it can; the painter refuses a cell to whatever is left.
        // Drawn without colour, so the only escape sequences a correct frame can hold are
        // the three cursor controls — which makes anything else the guest's.
        let mut app = read_app();
        app.on_event(Event::Log(console_batch(
            &app,
            &[
                "\x1b[2Jcleared the screen\x07",
                "[    1.000000] \x1b]0;retitled\x07 and \x1b[31m coloured",
            ],
        )));
        let frame = frame(&app, 24, 100);
        for sequence in frame.split('\x1b').skip(1) {
            let kind = sequence.chars().take(2).collect::<String>();
            assert!(
                matches!(kind.as_str(), "[H" | "[K" | "[J"),
                "a console line reached the terminal as an instruction: {sequence:?}"
            );
        }
        let drawn = rows_of(&frame).join("\n");
        assert!(drawn.contains("cleared the screen"), "{drawn}");
        assert!(!drawn.contains('\x07'), "{drawn}");
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

    /// A row is a stem and as much of a hash as tells two environments apart. Anything that
    /// is not a hash is left alone: a name is not the dashboard's to rewrite.
    #[test]
    fn a_name_keeps_its_stem_and_enough_of_its_hash() {
        assert_eq!(short_name("virtkit-4171942f2d70bae7"), "virtkit-4171942f");
        assert_eq!(short_name("wab-qa-d3a92b42d7d0a15f"), "wab-qa-d3a92b42");
        assert_ne!(
            short_name("virtkit-4171942f2d70bae7"),
            short_name("virtkit-9c02b11840e6c3da"),
            "two environments over one checkout became one row"
        );
        assert_eq!(short_name("virtkit"), "virtkit");
        assert_eq!(short_name("my-project-name"), "my-project-name");
        assert_eq!(short_name("deadbeef"), "deadbeef");
    }

    /// A path under the reader's home is written the way they think of it.
    #[test]
    fn a_path_under_home_is_written_with_a_tilde() {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return; // nothing to abbreviate against, and the environment is not ours to set
        };
        assert_eq!(tilde(&home.join("src/vk")), "~/src/vk");
        assert_eq!(tilde(Path::new("/srv/build")), "/srv/build");
    }
}
