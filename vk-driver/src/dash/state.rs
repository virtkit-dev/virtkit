//! What the dashboard knows, and what the keys do to it.
//!
//! Keys update plain state values, which the renderer draws. This module performs no
//! terminal, file or process I/O, so every key can be tested without a terminal.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use super::envs::Env;
use super::poll::Event;
use crate::term::Press;

/// How far a page key moves the selection.
const PAGE: isize = 10;

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

/// Something the loop is to do on the dashboard's behalf, because this module owns no
/// thread and no channel to do it with itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    /// re-read the environment list now
    Refresh,
    /// total what each of these state directories holds on disk
    Sizes(Vec<PathBuf>),
}

/// The dashboard.
pub(crate) struct App {
    /// Every environment on the host, running first. Empty until the first read lands,
    /// which is why the list has something to say about waiting.
    pub(crate) envs: Vec<Env>,
    /// Which row is selected, as an index into `envs`; kept in range by every path that
    /// changes either.
    pub(crate) selected: usize,
    /// On-disk sizes, by state directory. Empty until the reader asks for them, because the
    /// walk behind them is slow enough to be a key of its own.
    pub(crate) sizes: HashMap<PathBuf, u64>,
    pub(crate) sizes_pending: bool,
    /// Whether anything has been read yet, so the list can say it is waiting rather than
    /// claim this host has no environments.
    pub(crate) read: bool,
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
    request: Option<Request>,
}

impl App {
    pub(crate) fn new(interval: Duration, colour: bool) -> Self {
        Self {
            envs: Vec::new(),
            selected: 0,
            sizes: HashMap::new(),
            sizes_pending: false,
            read: false,
            pane: Pane::Console,
            focus: Focus::List,
            mode: Mode::Normal,
            status: None,
            colour,
            interval,
            quit: false,
            request: None,
        }
    }

    /// Whether the reader has asked to leave.
    pub(crate) fn quit(&self) -> bool {
        self.quit
    }

    /// What the loop is to do next on the dashboard's behalf, if anything.
    pub(crate) fn take_request(&mut self) -> Option<Request> {
        self.request.take()
    }

    /// The environment the right-hand column is about.
    pub(crate) fn selected_env(&self) -> Option<&Env> {
        self.envs.get(self.selected)
    }

    /// How many environments there are, how many are up, and what they are costing this
    /// host between them — the figures under the list.
    pub(crate) fn totals(&self) -> (usize, usize, Option<u64>) {
        let running = self.envs.iter().filter(|env| env.is_running()).count();
        let mut used = None;
        for bytes in self.envs.iter().filter_map(|env| env.mem_used) {
            used = Some(used.unwrap_or(0u64).saturating_add(bytes));
        }
        (self.envs.len(), running, used)
    }

    /// Fold in whatever a background thread noticed.
    pub(crate) fn on_event(&mut self, event: Event) {
        match event {
            Event::Key(press) => self.key(press),
            Event::Envs(envs) => self.on_envs(envs),
            Event::Sizes(sizes) => {
                self.sizes_pending = false;
                self.sizes.extend(sizes);
            }
            Event::Failed(said) => {
                self.read = true;
                self.status = Some(said);
            }
        }
    }

    /// A completed read: keep the reader looking at the environment they had selected,
    /// wherever it has moved to in the new list.
    ///
    /// By identity, not by position — a refresh reorders the list as environments start and
    /// stop, and following the index would move the selection under the reader's hand. An
    /// environment that has gone leaves the selection where it was rather than stranding it
    /// past the end.
    fn on_envs(&mut self, envs: Vec<Env>) {
        self.read = true;
        let was = self.selected_env().map(|env| env.dir.clone());
        let moved_to = was
            .as_ref()
            .and_then(|dir| envs.iter().position(|env| &env.dir == dir));
        self.envs = envs;
        self.selected = moved_to.unwrap_or(self.selected).min(self.last_index());
    }

    fn last_index(&self) -> usize {
        self.envs.len().saturating_sub(1)
    }

    /// Move the selection, staying inside the list however far the key asks for.
    fn select(&mut self, delta: isize) {
        if self.envs.is_empty() {
            return;
        }
        self.selected = self
            .selected
            .saturating_add_signed(delta)
            .min(self.last_index());
    }

    /// Up or down: the selection while the list has the keys, the pane below once it does.
    fn step(&mut self, delta: isize) {
        match self.focus {
            Focus::List => self.select(delta),
            // The pane below has nothing to scroll yet; the console gives it something.
            Focus::Lower => {}
        }
    }

    /// Total what every environment holds on disk, unless a walk is already under way.
    fn walk_sizes(&mut self) {
        if self.sizes_pending || self.envs.is_empty() {
            return;
        }
        self.sizes_pending = true;
        self.request = Some(Request::Sizes(
            self.envs.iter().map(|env| env.dir.clone()).collect(),
        ));
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
            Press::Char('r') => self.request = Some(Request::Refresh),
            Press::Char('s') => self.walk_sizes(),

            Press::Char('j') | Press::Down => self.step(1),
            Press::Char('k') | Press::Up => self.step(-1),
            Press::PageDown => self.step(PAGE),
            Press::PageUp => self.step(-PAGE),
            Press::Home => self.step(isize::MIN),
            Press::End => self.step(isize::MAX),
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
        assert_eq!(app.selected, 0);
        assert!(app.selected_env().is_none());
        assert_eq!(app.totals(), (0, 0, None));
        // There is nothing to walk, so `s` asked for no walk rather than an empty one.
        assert!(!app.sizes_pending);
    }

    /// A list of environments, as a completed read hands one over.
    fn envs(count: usize) -> Vec<Env> {
        let rows = (0..count)
            .map(|i| {
                super::super::envs::fixture::row(
                    &format!("env-{i}"),
                    &format!("/state/env-{i}"),
                    crate::dev::list::Status::Stopped,
                )
            })
            .collect();
        super::super::envs::join(rows, Vec::new())
    }

    /// The selection moves with the keys and stays inside the list however far they ask for:
    /// a page key on a list of three is the last row, not an index past the end.
    #[test]
    fn the_selection_moves_and_stays_in_range() {
        let mut app = app();
        app.on_event(Event::Envs(envs(4)));
        assert_eq!(app.selected, 0);
        app.key(Press::Char('j'));
        app.key(Press::Down);
        assert_eq!(app.selected, 2);
        app.key(Press::Char('k'));
        assert_eq!(app.selected, 1);
        app.key(Press::PageDown);
        assert_eq!(app.selected, 3, "a page ran off the end of the list");
        app.key(Press::End);
        assert_eq!(app.selected, 3);
        app.key(Press::PageUp);
        assert_eq!(app.selected, 0);
        app.key(Press::Home);
        assert_eq!(app.selected, 0);
        assert_eq!(app.selected_env().map(|env| env.name()), Some("env-0"));
    }

    /// While the pane below has the keys, the movement keys belong to it, so the selection
    /// stays where the reader left it.
    #[test]
    fn the_pane_below_takes_the_movement_keys_with_the_focus() {
        let mut app = app();
        app.on_event(Event::Envs(envs(4)));
        app.key(Press::Char('j'));
        app.key(Press::Tab);
        app.key(Press::Char('j'));
        app.key(Press::PageDown);
        assert_eq!(app.selected, 1);
        app.key(Press::Tab);
        app.key(Press::Char('j'));
        assert_eq!(app.selected, 2);
    }

    /// A read lands every few seconds and reorders the list as environments start and stop.
    /// The reader stays looking at the environment they selected, wherever it moved to.
    #[test]
    fn a_read_keeps_the_selected_environment_selected() {
        let mut app = app();
        app.on_event(Event::Envs(envs(4)));
        app.key(Press::Char('j'));
        app.key(Press::Char('j'));
        let selected = app.selected_env().map(|env| env.dir.clone());
        assert_eq!(
            selected.as_deref(),
            Some(std::path::Path::new("/state/env-2"))
        );

        // The same environments, in the other order.
        let mut shuffled = envs(4);
        shuffled.reverse();
        app.on_event(Event::Envs(shuffled));
        assert_eq!(app.selected, 1);
        assert_eq!(app.selected_env().map(|env| env.dir.clone()), selected);
    }

    /// An environment that has gone must not strand the selection past the end of the list,
    /// which would leave the whole right-hand column with nothing to be about.
    #[test]
    fn an_environment_that_disappears_does_not_strand_the_selection() {
        let mut app = app();
        app.on_event(Event::Envs(envs(4)));
        app.key(Press::End);
        assert_eq!(app.selected, 3);

        app.on_event(Event::Envs(envs(2)));
        assert_eq!(app.selected, 1);
        assert!(app.selected_env().is_some());

        app.on_event(Event::Envs(Vec::new()));
        assert_eq!(app.selected, 0);
        assert!(app.selected_env().is_none());
        assert!(app.read, "an empty host still counts as having been read");
    }

    /// The size walk is slow enough to be a key of its own, and asking twice must not start
    /// two of them. Its answer is what says it is over.
    #[test]
    fn the_size_walk_is_asked_for_once_at_a_time() {
        let mut app = app();
        app.on_event(Event::Envs(envs(2)));
        app.key(Press::Char('s'));
        assert!(app.sizes_pending);
        match app.take_request() {
            Some(Request::Sizes(dirs)) => assert_eq!(dirs.len(), 2),
            other => panic!("`s` asked for {other:?}"),
        }
        app.key(Press::Char('s'));
        assert_eq!(app.take_request(), None, "a second walk was started");

        app.on_event(Event::Sizes(vec![(PathBuf::from("/state/env-0"), 4096)]));
        assert!(!app.sizes_pending);
        assert_eq!(
            app.sizes.get(std::path::Path::new("/state/env-0")),
            Some(&4096)
        );
    }

    /// `r` asks for a read now, rather than waiting out the interval.
    #[test]
    fn r_asks_for_a_read_now() {
        let mut app = app();
        app.key(Press::Char('r'));
        assert_eq!(app.take_request(), Some(Request::Refresh));
        assert_eq!(app.take_request(), None, "and only once");
    }

    /// A read that failed is a line in the key bar, not the end of the session.
    #[test]
    fn a_read_that_fails_is_reported_rather_than_fatal() {
        let mut app = app();
        app.on_event(Event::Failed("the state base is unreadable".to_string()));
        assert!(!app.quit());
        assert_eq!(app.status.as_deref(), Some("the state base is unreadable"));
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
