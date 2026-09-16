//! What the dashboard knows, and what the keys do to it.
//!
//! Keys update plain state values, which the renderer draws. This module performs no
//! terminal, file or process I/O, so every key can be tested without a terminal.

use std::time::Duration;

use crate::term::Press;

/// Which of the lower pane's tabs is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pane {
    /// the selected environment's guest console
    Console,
    /// what the selected environment is costing this host
    Usage,
}

/// Which half of the screen the movement keys belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Focus {
    /// the environment list: the keys change the selection
    List,
    /// the lower pane: the keys scroll it
    Lower,
}

/// What has the keyboard. An overlay takes the whole screen rather than being drawn over a
/// cleared rectangle, so there is no centring arithmetic to get wrong on a small terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Mode {
    /// the dashboard itself
    Normal,
    /// every key the dashboard has, on one screen
    Help,
}

/// The dashboard.
pub(crate) struct App {
    pub(crate) pane: Pane,
    pub(crate) focus: Focus,
    pub(crate) mode: Mode,
    /// Something to say to the reader, which takes the key bar until the next key. A key
    /// pressed is an acknowledgement, so a complaint never outlives the reader's attention.
    pub(crate) status: Option<String>,
    /// Whether the frame may use colour. It is an accent and never the only thing carrying
    /// a meaning, so the screen says the same either way.
    pub(crate) colour: bool,
    /// How often the environment list is re-read, for the help screen to state.
    pub(crate) interval: Duration,
    quit: bool,
}

impl App {
    pub(crate) fn new(interval: Duration, colour: bool) -> Self {
        Self {
            pane: Pane::Console,
            focus: Focus::List,
            mode: Mode::Normal,
            status: None,
            colour,
            interval,
            quit: false,
        }
    }

    /// Whether the reader has asked to leave.
    pub(crate) fn quit(&self) -> bool {
        self.quit
    }

    /// Act on a key.
    pub(crate) fn key(&mut self, press: Press) {
        // Raw mode clears ISIG, so Ctrl-C arrives as a byte rather than as a signal. It is
        // a quit wherever it is pressed, including over an overlay that has the keyboard.
        if press == Press::Interrupt {
            self.quit = true;
            return;
        }
        // The help screen swallows the key that closes it: a reader who opened it with `?`
        // expects any key to put it away, not to put it away and do something as well.
        if self.mode == Mode::Help {
            self.mode = Mode::Normal;
            return;
        }
        self.status = None;
        match press {
            Press::Char('q') | Press::Escape => self.quit = true,
            Press::Char('?') => self.mode = Mode::Help,
            Press::Tab | Press::BackTab => {
                self.focus = match self.focus {
                    Focus::List => Focus::Lower,
                    Focus::Lower => Focus::List,
                }
            }
            Press::Char('1') => self.pane = Pane::Console,
            Press::Char('2') => self.pane = Pane::Usage,
            _ => {}
        }
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

    fn app() -> App {
        App::new(Duration::from_secs(3), false)
    }

    /// The keys are pressed before anything has been read, because a reader opens the
    /// dashboard and starts typing. None of them may act on what is not there yet.
    #[test]
    fn the_keys_are_safe_before_anything_has_been_read() {
        let mut app = app();
        for press in [
            Press::Up,
            Press::Down,
            Press::PageUp,
            Press::PageDown,
            Press::Home,
            Press::End,
            Press::Enter,
            Press::Backspace,
            Press::Left,
            Press::Right,
            Press::Char('j'),
            Press::Char('k'),
            Press::Char('r'),
            Press::Char('s'),
            Press::Char('x'),
        ] {
            app.key(press);
            assert!(!app.quit(), "{press:?} left the dashboard");
        }
    }

    /// `?` opens the help and the next key — any key — closes it, without also doing what
    /// that key would have done. A reader pressing `q` to put the help away means "close
    /// this", not "close this and quit".
    #[test]
    fn the_help_swallows_the_key_that_closes_it() {
        let mut app = app();
        app.key(Press::Char('?'));
        assert_eq!(app.mode, Mode::Help);
        app.key(Press::Char('q'));
        assert_eq!(app.mode, Mode::Normal);
        assert!(!app.quit(), "the key that closed the help also quit");

        // And the pane keys do not reach through it either.
        app.key(Press::Char('?'));
        app.key(Press::Char('2'));
        assert_eq!(app.mode, Mode::Normal);
        assert_eq!(app.pane, Pane::Console);
    }

    /// Ctrl-C is the key every terminal program answers to, and raw mode hands it over as a
    /// byte rather than as a signal. It quits from wherever the reader is.
    #[test]
    fn ctrl_c_quits_from_anywhere() {
        let mut plain = app();
        plain.key(Press::Interrupt);
        assert!(plain.quit());

        let mut helping = app();
        helping.key(Press::Char('?'));
        helping.key(Press::Interrupt);
        assert!(helping.quit(), "Ctrl-C was swallowed by the help screen");
    }

    /// Focus and the tab strip are both moved by keys, and neither is the other: `tab`
    /// says which half the movement keys belong to, `1`/`2` which pane is showing.
    #[test]
    fn tab_moves_the_focus_and_the_digits_move_the_pane() {
        let mut app = app();
        assert_eq!(app.focus, Focus::List);
        app.key(Press::Tab);
        assert_eq!(app.focus, Focus::Lower);
        app.key(Press::BackTab);
        assert_eq!(app.focus, Focus::List);

        app.key(Press::Char('2'));
        assert_eq!(app.pane, Pane::Usage);
        assert_eq!(app.focus, Focus::List, "a pane key moved the focus");
        app.key(Press::Char('1'));
        assert_eq!(app.pane, Pane::Console);
    }

    /// A complaint holds the key bar only until the reader has had a chance to read it: the
    /// next key is the acknowledgement, whatever key it was.
    #[test]
    fn a_key_clears_what_the_last_one_complained_about() {
        let mut app = app();
        app.status = Some("something went wrong".to_string());
        app.key(Press::Char('1'));
        assert_eq!(app.status, None);
    }
}
