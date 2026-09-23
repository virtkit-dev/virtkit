//! What the dashboard knows, and what the keys do to it.
//!
//! Keys update plain state values, which the renderer draws. This module performs no
//! terminal, file or process I/O, so every key can be tested without a terminal.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::actions::{Action, Job, Refusal, Weight};
use super::console;
use super::envs::Env;
use super::poll::{Event, Guest, GuestAddr, Sample, Selected};
use crate::consolelog::Source;
use crate::dev::list::Row;
use crate::term::Press;

/// How far a page key moves the selection, and the console window.
const PAGE: isize = 10;

/// Which of the lower pane's tabs is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pane {
    /// the selected environment's guest console
    Console,
    /// what the selected environment is costing this host
    Host,
    /// what the selected environment's guest makes of itself
    Guest,
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
    /// what can be done to the selected environment
    Menu,
    /// one action that cannot be undone, waiting to be told to go ahead
    Confirm(Confirm),
}

/// A destructive action, and what it would take with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Confirm {
    pub(crate) job: Job,
    /// What `vk dev gc` would remove, as `vk dev gc` itself lists it — read off the disk on
    /// a thread, so this is `None` for as long as that takes. A question with nothing under
    /// it yet says it is still reading rather than showing an empty list, which would read
    /// as "there is nothing in there".
    pub(crate) removes: Option<String>,
}

/// Something the loop is to do on the dashboard's behalf, because this module owns no
/// thread and no channel to do it with itself.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Request {
    /// re-read the environment list now
    Refresh,
    /// total what each of these state directories holds on disk
    Sizes(Vec<PathBuf>),
    /// point the threads that follow the selection at this environment
    Follow(Selected),
    /// read what removing these environments would take with it
    Preview { name: String, rows: Vec<Row> },
    /// run this action out of sight, and re-read the environments when it lands
    Run(Job),
    /// give this action the terminal until it is done with it
    Handover(Job),
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
    /// The selected environment's console, as much of it as is kept.
    pub(crate) console: console::Buffer,
    /// Which of those lines are shown. It changes the screen and never the buffer, so a
    /// reader who hides the kernel to find an agent complaint gets the kernel back intact.
    pub(crate) filter: console::Filter,
    /// How far back from the newest line the console pane is showing, counted in lines the
    /// filter admits. Zero is following.
    pub(crate) scrollback: usize,
    /// Whether the selected environment has no console file at all — it has never booted.
    pub(crate) console_missing: bool,
    /// The newest reading of what the selected environment costs this host, and the one
    /// before it. Two are kept because the interesting figure is a rate and `/proc` counts
    /// totals: one reading alone says what a VM has used since it booted, never what it is
    /// doing now.
    pub(crate) sample: Option<Sample>,
    pub(crate) previous: Option<Sample>,
    /// The guest's own account of itself: how far the asking has got, and the newest sample
    /// once it has got that far.
    pub(crate) guest: Option<Guest>,
    /// When that sample reached this host, on this host's clock — a guest whose own clock is
    /// wrong is exactly the guest a reader is looking at this pane about.
    pub(crate) guest_at: Option<Instant>,
    /// Which environment the console thread is working for. Bumped whenever the selection
    /// moves, so a pass that began under the last one is recognised and dropped.
    epoch: u64,
    /// The same for the sampler, which follows a process tree and not a directory: an
    /// environment restarted under the reader keeps the console of the boot that ended and
    /// is a new tree all the same, and a reading of the old one makes no rate with it. Two
    /// counters rather than one, because one would have to clear the console to say it.
    sample_epoch: u64,
    /// the environment those threads were last pointed at
    followed: Option<PathBuf>,
    /// the process tree they were last pointed at, which changes without the environment
    /// doing so every time one starts or stops
    sampled: Option<i32>,
    /// whether they were last told the guest's own figures were wanted, which changes with
    /// no selection moving at all: the pane keys alone decide it
    wanted_guest: bool,
    quit: bool,
    requests: VecDeque<Request>,
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
            console: console::Buffer::default(),
            filter: console::Filter::default(),
            scrollback: 0,
            console_missing: false,
            sample: None,
            previous: None,
            guest: None,
            guest_at: None,
            epoch: 0,
            sample_epoch: 0,
            followed: None,
            sampled: None,
            wanted_guest: false,
            quit: false,
            requests: VecDeque::new(),
        }
    }

    /// Whether the reader has asked to leave.
    pub(crate) fn quit(&self) -> bool {
        self.quit
    }

    /// What the loop is to do next on the dashboard's behalf, if anything.
    pub(crate) fn take_request(&mut self) -> Option<Request> {
        self.requests.pop_front()
    }

    /// Ask the loop for something, replacing an earlier ask of the same kind: a reader
    /// holding `j` down moves through five environments and wants the console of the one
    /// they stopped on, not of each one they passed.
    fn ask(&mut self, request: Request) {
        self.requests
            .retain(|queued| std::mem::discriminant(queued) != std::mem::discriminant(&request));
        self.requests.push_back(request);
    }

    /// Ask the loop for something that stands even if another of its kind is already
    /// queued. An action is not a request for the newest state of something: two of them
    /// are two things the reader asked for, and folding them together would drop one.
    fn demand(&mut self, request: Request) {
        self.requests.push_back(request);
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
            Event::Log(batch) => self.on_log(batch),
            Event::Sample(sample) => {
                // A reading taken for the environment the reader has left — or for the
                // process tree a restart replaced — says nothing about the one in front of
                // them.
                if sample.epoch == self.sample_epoch {
                    self.previous = self.sample.replace(sample);
                }
            }
            Event::Guest { epoch, guest } => {
                // Read for the process tree the reader has left, or for the one a restart
                // replaced: it is not about the guest in front of them.
                if epoch == self.sample_epoch {
                    if matches!(guest, Guest::Sample(_)) {
                        self.guest_at = Some(Instant::now());
                    }
                    self.guest = Some(guest);
                }
            }
            Event::Preview { name, text } => {
                // A listing read for an environment the reader has since backed out of, or
                // moved on from, describes something they are no longer being asked about.
                if let Mode::Confirm(confirm) = &mut self.mode
                    && confirm.job.name == name
                {
                    confirm.removes = Some(text);
                }
            }
            Event::Said(said) => self.status = Some(said),
            Event::Failed(said) => {
                self.read = true;
                self.status = Some(said);
            }
        }
    }

    /// One pass of the console the following thread was pointed at.
    fn on_log(&mut self, batch: console::Batch) {
        // A pass that began before the reader moved describes another environment's guest.
        if batch.epoch != self.epoch {
            return;
        }
        self.console_missing = batch.missing;
        if batch.restarted {
            // The file was truncated or replaced: what is kept is about bytes that are gone.
            self.console.clear();
            self.scrollback = 0;
        }
        for line in batch.lines {
            // A line arriving must not drag what a scrolled reader is looking at: the
            // window is measured back from the newest line, so it moves with it.
            if !self.following() && self.filter.admits(&line) {
                self.scrollback = self.scrollback.saturating_add(1);
            }
            self.console.push(line);
        }
        self.clamp_scrollback();
    }

    /// Which selection the following threads are working for, so a test can hand the
    /// dashboard a pass of the console exactly as they do.
    #[cfg(test)]
    pub(crate) fn console_epoch(&self) -> u64 {
        self.epoch
    }

    /// The same for the threads that follow the process tree, so a test can hand the
    /// dashboard a reading or a guest's sample exactly as they do.
    #[cfg(test)]
    pub(crate) fn sample_epoch(&self) -> u64 {
        self.sample_epoch
    }

    /// Whether the console pane is showing the newest line.
    pub(crate) fn following(&self) -> bool {
        self.scrollback == 0
    }

    /// How many lines the filter admits, which is as far back as scrolling goes.
    pub(crate) fn shown_lines(&self) -> usize {
        self.console.shown(&self.filter).count()
    }

    /// Scroll the console. Positive is back into history; zero is following the newest line.
    fn scroll(&mut self, back: isize) {
        let ceiling = self.shown_lines().saturating_sub(1);
        self.scrollback = self.scrollback.saturating_add_signed(back).min(ceiling);
    }

    /// Pull a scrolled reader back inside what the filter admits.
    ///
    /// Hiding two sources of three while scrolled a hundred lines back otherwise leaves the
    /// window ending before the first line that survives, and the pane goes blank — which
    /// reads as a broken dashboard rather than as a working filter.
    fn clamp_scrollback(&mut self) {
        self.scrollback = self.scrollback.min(self.shown_lines().saturating_sub(1));
    }

    /// Point the following threads at whatever is selected now.
    ///
    /// The buffer belongs to one environment, so moving the selection empties it: lines from
    /// the one being left would otherwise sit above the one being arrived at, under its name.
    fn retarget(&mut self) {
        let selected = self.selected_env();
        let dir = selected.map(|env| env.dir.clone());
        let pid = selected
            .and_then(|env| env.vm.as_ref())
            .and_then(|vm| i32::try_from(vm.pid).ok());
        let guest = selected
            .and_then(|env| env.vm.as_ref())
            .map(|vm| GuestAddr {
                exec_addr: vm.exec_addr.clone(),
                state_dir: vm.state_dir.clone(),
                own_log: vm.atop_log.clone(),
            });
        // The guest is asked for its own figures only while the pane that draws them is up,
        // so a pane key alone is reason enough to point the threads again.
        let want_guest = self.pane == Pane::Guest;
        if dir == self.followed && pid == self.sampled && want_guest == self.wanted_guest {
            return;
        }
        if dir != self.followed {
            // A VM that has stopped keeps the console of the boot that just ended, which is
            // the one a reader wanting to know why it stopped is about to read. Only moving
            // to another environment takes it away.
            self.epoch = self.epoch.wrapping_add(1);
            self.console.clear();
            self.scrollback = 0;
            self.console_missing = false;
        }
        if pid != self.sampled {
            // Two readings of two different process trees make no rate between them — and a
            // reading already under way is of the tree being left, so it is bumped past too.
            self.sample_epoch = self.sample_epoch.wrapping_add(1);
            self.sample = None;
            self.previous = None;
            self.guest = None;
            self.guest_at = None;
        }
        self.followed = dir.clone();
        self.sampled = pid;
        self.wanted_guest = want_guest;
        self.ask(Request::Follow(Selected {
            epoch: self.epoch,
            sample_epoch: self.sample_epoch,
            dir,
            pid,
            guest,
            want_guest,
        }));
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
        self.retarget();
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
        self.retarget();
    }

    /// Up or down: the selection while the list has the keys, the pane below once it does.
    fn step(&mut self, delta: isize) {
        match self.focus {
            Focus::List => self.select(delta),
            // Down is towards the newest line, which is less scrollback, so the sign turns
            // over. Saturating, because `End` reaches here as the largest step there is.
            Focus::Lower => self.scroll(delta.saturating_neg()),
        }
    }

    /// Total what every environment holds on disk, unless a walk is already under way.
    fn walk_sizes(&mut self) {
        if self.sizes_pending || self.envs.is_empty() {
            return;
        }
        self.sizes_pending = true;
        let dirs = self.envs.iter().map(|env| env.dir.clone()).collect();
        self.ask(Request::Sizes(dirs));
    }

    /// Show one of the lower pane's tabs.
    ///
    /// Not only a change of screen: the guest is asked for its own figures while that pane
    /// is up and left alone otherwise, so the threads that follow the selection are told.
    fn show_pane(&mut self, pane: Pane) {
        self.pane = pane;
        self.retarget();
    }

    /// Show a source, or stop showing it, keeping the window somewhere the pane can draw
    /// from.
    fn show(&mut self, source: Source) {
        self.filter.toggle(source);
        self.clamp_scrollback();
    }

    /// Whether an action can be offered for what is selected, for the menu to draw it as
    /// available or to say in words why it is not.
    pub(crate) fn availability(&self, action: Action) -> Result<(), Refusal> {
        match self.selected_env() {
            Some(env) => action.job(env).map(|_| ()),
            None => Err(Refusal::NotAnEnvironment),
        }
    }

    /// A key pressed while the menu is up.
    fn menu_key(&mut self, press: Press) {
        match press {
            // `x` closes what `x` opened, and `q` means "put this away" rather than "leave
            // the dashboard" for as long as an overlay is what is on screen.
            Press::Escape | Press::Char('x') | Press::Char('q') => self.mode = Mode::Normal,
            Press::Char(key) => {
                if let Some(action) = Action::ALL.iter().copied().find(|a| a.key() == key) {
                    self.act(action);
                }
            }
            _ => {}
        }
    }

    /// A key pressed while a destructive action is waiting to be confirmed.
    ///
    /// Only `y`. Not Enter, which a reader presses on the way to something else, and not
    /// any key, which is how the help closes — a keystroke that removes an environment
    /// should be one that could only have been meant.
    fn confirm_key(&mut self, confirm: Confirm, press: Press) {
        // Not before what would go is on the screen: agreeing to a question whose answer
        // is still being read is agreeing to nothing in particular, and `x d y` typed
        // quickly would otherwise remove it unseen.
        if press == Press::Char('y') && confirm.removes.is_none() {
            self.status = Some(format!(
                "{}: still reading what would go — y once it shows",
                confirm.job.action.label()
            ));
            self.mode = Mode::Confirm(confirm);
            return;
        }
        self.mode = Mode::Normal;
        match press == Press::Char('y') {
            true => self.start(confirm.job),
            false => {
                self.status = Some(format!("{}: cancelled", confirm.job.action.label()));
            }
        }
    }

    /// Do something to the selected environment, or say why it cannot be done.
    fn act(&mut self, action: Action) {
        let Some(env) = self.selected_env() else {
            self.mode = Mode::Normal;
            return;
        };
        match action.job(env) {
            // A refusal is not a reason to close the menu: the reader pressed a key that is
            // greyed out, and what they wanted was the reason, not an empty screen.
            Err(refusal) => {
                self.status = Some(format!("{}: {}", action.label(), refusal.why()));
            }
            Ok(job) => match action.weight() {
                Weight::Destructive => self.ask_first(job),
                _ => self.start(job),
            },
        }
    }

    /// Ask before doing something that cannot be undone, with `vk dev gc`'s own reading of
    /// what is inside the directory under the question.
    ///
    /// The selection is made here rather than by the command, because it is the selection
    /// that can refuse: `gc` will not remove a running environment, and finding that out
    /// after agreeing to it is finding it out too late.
    fn ask_first(&mut self, job: Job) {
        let rows: Vec<Row> = self.envs.iter().filter_map(|env| env.row.clone()).collect();
        match crate::dev::list::select_gc(rows, std::slice::from_ref(&job.name), false) {
            Err(report) => {
                self.mode = Mode::Normal;
                self.status = Some(format!("{}: {report:#}", job.action.label()));
            }
            Ok(selected) => {
                self.demand(Request::Preview {
                    name: job.name.clone(),
                    rows: selected,
                });
                self.mode = Mode::Confirm(Confirm { job, removes: None });
            }
        }
    }

    /// Set an action going: on a thread of its own, or with the terminal handed to it.
    fn start(&mut self, job: Job) {
        self.mode = Mode::Normal;
        self.status = Some(format!("{}: {}…", job.action.label(), job.name));
        match job.action.takes_the_terminal() {
            true => self.demand(Request::Handover(job)),
            false => self.demand(Request::Run(job)),
        }
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
        // A complaint is answered by the next key, whatever it was, so it never outlives the
        // reader's attention to it.
        self.status = None;
        // An overlay that can change something on this host has the keyboard to itself:
        // letting `j` through would move the selection out from under the very thing the
        // reader is being asked about.
        match &self.mode {
            Mode::Menu => return self.menu_key(press),
            Mode::Confirm(confirm) => return self.confirm_key(confirm.clone(), press),
            Mode::Normal | Mode::Help => {}
        }
        match press {
            Press::Char('q') | Press::Escape => self.quit = true,
            Press::Char('?') => self.mode = Mode::Help,
            Press::Char('x') => {
                if self.selected_env().is_some() {
                    self.mode = Mode::Menu;
                }
            }
            // The guest's own panel has a key of its own as well as a place in the menu: it
            // is the other half of the pane beside it, and a reader comparing the two should
            // not have to go through a menu to do it.
            Press::Char('a') => self.act(Action::Atop),
            Press::Tab | Press::BackTab => {
                self.focus = match self.focus {
                    Focus::List => Focus::Lower,
                    Focus::Lower => Focus::List,
                }
            }
            Press::Char('1') => self.show_pane(Pane::Console),
            Press::Char('2') => self.show_pane(Pane::Host),
            Press::Char('3') => self.show_pane(Pane::Guest),
            Press::Char('r') => self.ask(Request::Refresh),
            Press::Char('s') => self.walk_sizes(),

            // The console's own keys, which belong to it wherever the focus is: a reader
            // hiding the kernel is reading the console, not moving the list.
            Press::Char('f') => self.scrollback = 0,
            Press::Char('K') => self.show(Source::Kernel),
            Press::Char('A') => self.show(Source::Agent),
            Press::Char('G') => self.show(Source::Guest),
            Press::Char(']') => {
                self.filter.raise();
                self.clamp_scrollback();
            }
            Press::Char('[') => {
                self.filter.lower();
                self.clamp_scrollback();
            }

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
    use std::path::Path;

    fn app() -> App {
        App::new(Duration::from_secs(3), false)
    }

    /// Everything the dashboard has asked the loop for, in order.
    fn drain(app: &mut App) -> Vec<Request> {
        std::iter::from_fn(|| app.take_request()).collect()
    }

    /// A console line, classified as the tail classifies one.
    fn log(app: &mut App, raw: &str) {
        app.on_event(Event::Log(console::Batch {
            epoch: app.epoch,
            lines: vec![crate::consolelog::classify(raw)],
            ..console::Batch::default()
        }));
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

    /// The same list, with a VM behind every one of them.
    fn running(count: usize) -> Vec<Env> {
        let rows = (0..count)
            .map(|i| {
                super::super::envs::fixture::row(
                    &format!("env-{i}"),
                    &format!("/state/env-{i}"),
                    crate::dev::list::Status::Running,
                )
            })
            .collect();
        let vms = (0..count)
            .map(|i| {
                super::super::envs::fixture::vm(
                    &format!("/state/env-{i}"),
                    4000u32.saturating_add(i as u32),
                )
            })
            .collect();
        super::super::envs::join(rows, vms)
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
        drain(&mut app); // the read pointed the console at the first environment
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
        assert_eq!(app.pane, Pane::Host);
        assert_eq!(app.focus, Focus::List, "a pane key moved the focus");
        app.key(Press::Char('3'));
        assert_eq!(app.pane, Pane::Guest);
        app.key(Press::Char('1'));
        assert_eq!(app.pane, Pane::Console);
    }

    /// The console pane shows the newest line until the reader scrolls up, and `End` — or
    /// `f`, wherever the focus is — gives following back.
    #[test]
    fn the_console_follows_until_it_is_scrolled_and_end_gives_it_back() {
        let mut app = app();
        app.on_event(Event::Envs(envs(2)));
        for n in 0..50 {
            log(&mut app, &format!("line {n}"));
        }
        assert!(app.following());

        // While the list has the keys, up and down move the list and not the console.
        app.key(Press::Up);
        assert!(app.following());

        app.key(Press::Tab);
        app.key(Press::Up);
        assert!(!app.following());
        assert_eq!(app.scrollback, 1);
        app.key(Press::PageUp);
        assert_eq!(app.scrollback, 11);

        app.key(Press::End);
        assert!(app.following(), "end did not give following back");

        app.key(Press::PageUp);
        app.key(Press::Char('f'));
        assert!(app.following(), "f did not give following back");

        // Scrolling stops at the oldest line the buffer still holds.
        app.key(Press::Home);
        assert_eq!(app.scrollback, 49);
    }

    /// A line arriving while the reader is scrolled up must not drag the view: the window is
    /// measured back from the newest line, so what they are looking at stays where it is.
    #[test]
    fn a_line_arriving_does_not_move_a_scrolled_reader() {
        let mut app = app();
        app.on_event(Event::Envs(envs(1)));
        for n in 0..50 {
            log(&mut app, &format!("line {n}"));
        }
        app.key(Press::Tab);
        app.key(Press::PageUp);
        let looking_at = app.scrollback;

        log(&mut app, "one more");
        assert_eq!(app.scrollback, looking_at + 1);
    }

    /// The filters change what is shown and not what is kept, and a filter that hides most
    /// of the buffer pulls a scrolled reader back into what is left — otherwise the window
    /// ends before the first line that survives and the pane goes blank.
    #[test]
    fn a_filter_pulls_a_scrolled_reader_back_into_what_it_admits() {
        let mut app = app();
        app.on_event(Event::Envs(envs(1)));
        for n in 0..40 {
            log(&mut app, &format!("guest line {n}"));
        }
        log(&mut app, "[    1.000000] one kernel line");

        app.key(Press::Tab);
        for _ in 0..3 {
            app.key(Press::PageUp);
        }
        assert!(app.scrollback > 1);

        // Only the single kernel line survives this.
        app.key(Press::Char('G'));
        assert_eq!(app.shown_lines(), 1);
        assert_eq!(app.console.len(), 41, "the buffer was rebuilt to filter it");
        assert_eq!(
            app.scrollback, 0,
            "the window ended before the only line left"
        );

        // And the level floor is held to the same rule: it admits no unleveled line at all.
        app.key(Press::Char('G'));
        for _ in 0..3 {
            app.key(Press::PageUp);
        }
        app.key(Press::Char(']'));
        assert_eq!(app.shown_lines(), 0);
        assert_eq!(app.scrollback, 0);
        app.key(Press::Char('['));
        assert_eq!(app.shown_lines(), 41);
    }

    /// The console belongs to one environment. Moving the selection empties it and points
    /// the follower at the new one, so one guest's lines never appear under another's name.
    #[test]
    fn moving_the_selection_follows_the_new_environment() {
        let mut app = app();
        app.on_event(Event::Envs(envs(3)));
        match drain(&mut app).as_slice() {
            [Request::Follow(followed)] => {
                assert_eq!(followed.dir.as_deref(), Some(Path::new("/state/env-0")));
            }
            other => panic!("the first read asked for {other:?}"),
        }
        log(&mut app, "the first environment says something");
        assert_eq!(app.console.len(), 1);

        app.key(Press::Char('j'));
        assert!(
            app.console.is_empty(),
            "the console outlived its environment"
        );
        let asked = drain(&mut app);
        let Some(Request::Follow(followed)) = asked.first() else {
            panic!("moving the selection asked for {asked:?}");
        };
        assert_eq!(followed.dir.as_deref(), Some(Path::new("/state/env-1")));

        // A pass that began under the old selection is dropped rather than shown here.
        app.on_event(Event::Log(console::Batch {
            epoch: followed.epoch.saturating_sub(1),
            lines: vec![crate::consolelog::classify("a line from the one we left")],
            ..console::Batch::default()
        }));
        assert!(app.console.is_empty(), "a stale pass reached the buffer");

        // A read that does not move the selection does not restart the follower.
        log(&mut app, "the second environment says something");
        app.on_event(Event::Envs(envs(3)));
        assert_eq!(app.console.len(), 1, "a refresh cleared the console");
        assert!(drain(&mut app).is_empty());
    }

    /// A console that was truncated or replaced describes bytes that are gone, so what was
    /// kept goes with them rather than sitting above a new boot's first line.
    #[test]
    fn a_restarted_console_drops_what_it_held() {
        let mut app = app();
        app.on_event(Event::Envs(envs(1)));
        for n in 0..5 {
            log(&mut app, &format!("line {n}"));
        }
        app.on_event(Event::Log(console::Batch {
            epoch: app.epoch,
            lines: vec![crate::consolelog::classify("a fresh boot")],
            restarted: true,
            missing: false,
        }));
        assert_eq!(app.console.len(), 1);
        assert!(app.following());
    }

    /// Two readings make a rate; two readings of two different process trees make nothing.
    /// A reading for the environment the reader has left is dropped, and moving between them
    /// starts the pair again rather than deriving a figure across the gap.
    #[test]
    fn a_reading_belongs_to_the_process_tree_it_was_taken_from() {
        let mut app = app();
        app.on_event(Event::Envs(running(2)));
        let at = std::time::Instant::now();
        for cpu in [10u64, 12] {
            app.on_event(Event::Sample(Sample {
                epoch: app.sample_epoch,
                cpu: Duration::from_secs(cpu),
                peak_rss: 1024,
                disk: None,
                at,
            }));
        }
        assert!(app.sample.is_some() && app.previous.is_some());

        // Taken for the one before it, and arriving after the reader moved on.
        app.on_event(Event::Sample(Sample {
            epoch: app.sample_epoch.wrapping_sub(1),
            cpu: Duration::from_secs(900),
            peak_rss: 1024,
            disk: None,
            at,
        }));
        assert_eq!(app.sample.map(|s| s.cpu), Some(Duration::from_secs(12)));

        // Moving to another environment is another tree, so the pair starts again.
        app.key(Press::Char('j'));
        assert!(app.sample.is_none() && app.previous.is_none());
        match drain(&mut app).as_slice() {
            [Request::Follow(followed)] => assert_eq!(followed.pid, Some(4001)),
            other => panic!("moving the selection asked for {other:?}"),
        }
    }

    /// An environment restarted where it stood is one directory and two process trees: the
    /// console of the boot that ended is what a reader wants to see, and a reading of the
    /// tree that ended is not something to show against the new one.
    #[test]
    fn a_restart_in_place_drops_the_readings_of_the_tree_that_ended() {
        let mut app = app();
        app.on_event(Event::Envs(running(1)));
        drain(&mut app);
        log(&mut app, "the boot that just ended");
        let ended = app.sample_epoch;

        // The same environment, under the pid of a `vk dev up` that has just replaced it.
        let rows = vec![super::super::envs::fixture::row(
            "env-0",
            "/state/env-0",
            crate::dev::list::Status::Running,
        )];
        let vms = vec![super::super::envs::fixture::vm("/state/env-0", 5000)];
        app.on_event(Event::Envs(super::super::envs::join(rows, vms)));
        assert_eq!(app.console.len(), 1, "the restart took the console with it");

        app.on_event(Event::Sample(Sample {
            epoch: ended,
            cpu: Duration::from_secs(900),
            peak_rss: 1024,
            disk: None,
            at: std::time::Instant::now(),
        }));
        assert!(
            app.sample.is_none(),
            "a reading of the tree that ended stood"
        );
    }

    /// The guest is asked for its own figures only while the pane that draws them is up, so
    /// a pane key on its own points the threads again — and an answer that arrives for the
    /// process tree the reader has left is dropped, as a reading of the host's cost is.
    #[test]
    fn the_guest_is_asked_for_its_figures_only_while_its_pane_is_up() {
        let mut app = app();
        app.on_event(Event::Envs(running(2)));
        match drain(&mut app).as_slice() {
            [Request::Follow(followed)] => {
                assert!(!followed.want_guest, "a guest was asked for unprompted");
                assert_eq!(
                    followed.guest.as_ref().map(|guest| guest.state_dir.clone()),
                    Some(PathBuf::from("/state/env-0")),
                );
            }
            other => panic!("the first read asked for {other:?}"),
        }

        // Showing the pane says so, and leaving it says so too.
        app.key(Press::Char('3'));
        match drain(&mut app).as_slice() {
            [Request::Follow(followed)] => assert!(followed.want_guest),
            other => panic!("the pane key asked for {other:?}"),
        }
        app.key(Press::Char('1'));
        match drain(&mut app).as_slice() {
            [Request::Follow(followed)] => assert!(!followed.want_guest),
            other => panic!("leaving the pane asked for {other:?}"),
        }

        let sample = || {
            Guest::Sample(Box::new(super::super::pane::guest::fixture::sample(
                "sh -c make test",
            )))
        };
        app.on_event(Event::Guest {
            epoch: app.sample_epoch,
            guest: sample(),
        });
        assert!(matches!(app.guest, Some(Guest::Sample(_))));
        assert!(app.guest_at.is_some(), "the sample was not timed");

        // Read for the tree the reader has left, and arriving after they moved on.
        app.on_event(Event::Guest {
            epoch: app.sample_epoch.wrapping_sub(1),
            guest: Guest::Failed("the VM went away".to_string()),
        });
        assert!(
            matches!(app.guest, Some(Guest::Sample(_))),
            "a stale answer reached the pane"
        );

        // Another environment is another guest, so its figures start again rather than
        // sitting under the new one's name.
        app.key(Press::Char('j'));
        assert!(app.guest.is_none() && app.guest_at.is_none());
    }

    /// `x` opens the menu, and while it is up it has the keyboard: a key that would have
    /// moved the list must not move it out from under the environment the menu is about.
    #[test]
    fn the_menu_holds_the_keyboard_while_it_is_up() {
        let mut app = app();
        app.on_event(Event::Envs(running(3)));
        drain(&mut app);
        app.key(Press::Char('x'));
        assert_eq!(app.mode, Mode::Menu);

        app.key(Press::Char('j'));
        app.key(Press::Down);
        app.key(Press::PageDown);
        assert_eq!(app.selected, 0, "the list moved under an open menu");
        assert_eq!(app.mode, Mode::Menu, "a movement key closed the menu");
        assert!(drain(&mut app).is_empty(), "a movement key asked for work");

        // `q` over the menu puts the menu away rather than leaving the dashboard, and so
        // does the key that opened it.
        app.key(Press::Char('q'));
        assert_eq!(app.mode, Mode::Normal);
        assert!(!app.quit(), "q over the menu quit the dashboard");
        app.key(Press::Char('x'));
        app.key(Press::Char('x'));
        assert_eq!(app.mode, Mode::Normal);
        app.key(Press::Char('x'));
        app.key(Press::Escape);
        assert_eq!(app.mode, Mode::Normal);
        assert!(!app.quit(), "esc over the menu quit the dashboard");
    }

    /// An action that can be undone runs on the keystroke, and the one that hands the
    /// terminal over is handed to the loop rather than started here.
    #[test]
    fn an_action_the_menu_offers_is_asked_for_on_the_keystroke() {
        let mut app = app();
        app.on_event(Event::Envs(running(2)));
        drain(&mut app);

        app.key(Press::Char('x'));
        app.key(Press::Char('s'));
        assert_eq!(app.mode, Mode::Normal, "the menu stayed up over an action");
        match drain(&mut app).as_slice() {
            [Request::Run(job)] => {
                assert_eq!(job.action, Action::Stop);
                assert_eq!(job.name, "env-0");
            }
            other => panic!("stopping asked for {other:?}"),
        }
        assert!(app.status.is_some(), "the dashboard said nothing about it");

        // The guest's own panel wants the terminal, and answers to its key without the menu.
        app.key(Press::Char('a'));
        match drain(&mut app).as_slice() {
            [Request::Handover(job)] => assert_eq!(job.action, Action::Atop),
            other => panic!("the panel asked for {other:?}"),
        }

        // A refusal leaves the menu up, because the reason is what the reader wanted.
        app.key(Press::Char('x'));
        app.key(Press::Char('u'));
        assert_eq!(app.mode, Mode::Menu, "a refusal closed the menu");
        assert!(drain(&mut app).is_empty(), "a refused action was started");
        assert_eq!(
            app.status.as_deref(),
            Some("start: it is already running"),
            "the refusal did not say why"
        );
    }

    /// Removing an environment cannot be undone, so it asks — and only `y` answers. The
    /// question carries the command and what `vk dev gc` says is inside the directory.
    #[test]
    fn removing_an_environment_asks_first_and_only_y_agrees() {
        let mut app = app();
        app.on_event(Event::Envs(envs(2)));
        drain(&mut app);
        app.key(Press::Char('x'));
        app.key(Press::Char('d'));

        let Mode::Confirm(confirm) = app.mode.clone() else {
            panic!("removing asked nothing: {:?}", app.mode);
        };
        assert_eq!(confirm.job.name, "env-0");
        assert_eq!(confirm.job.line(), "vk dev gc --yes env-0");
        assert!(
            confirm.removes.is_none(),
            "the listing was read on this thread"
        );
        match drain(&mut app).as_slice() {
            [Request::Preview { name, rows }] => {
                assert_eq!(name, "env-0");
                assert_eq!(rows.len(), 1);
            }
            other => panic!("the question asked for {other:?}"),
        }

        // The listing lands under the question, and a listing read for another environment
        // does not.
        app.on_event(Event::Preview {
            name: "env-1".to_string(),
            text: "would remove 1 environment(s):".to_string(),
        });
        app.on_event(Event::Preview {
            name: "env-0".to_string(),
            text: "would remove env-0".to_string(),
        });
        let Mode::Confirm(confirm) = &app.mode else {
            panic!("the question went away");
        };
        assert_eq!(confirm.removes.as_deref(), Some("would remove env-0"));
        app.key(Press::Escape); // put that one away before asking again

        // Anything but `y` cancels, and cancelling starts nothing.
        for press in [
            Press::Enter,
            Press::Char('n'),
            Press::Escape,
            Press::Char('d'),
        ] {
            app.key(Press::Char('x'));
            app.key(Press::Char('d'));
            assert!(matches!(app.mode, Mode::Confirm(_)), "{press:?}");
            drain(&mut app);
            app.key(press);
            assert_eq!(app.mode, Mode::Normal, "{press:?}");
            assert!(drain(&mut app).is_empty(), "{press:?} removed it anyway");
            assert_eq!(app.status.as_deref(), Some("remove it: cancelled"));
        }

        // `y` agrees to nothing while what would go is still being read.
        app.key(Press::Char('x'));
        app.key(Press::Char('d'));
        drain(&mut app);
        app.key(Press::Char('y'));
        assert!(matches!(app.mode, Mode::Confirm(_)), "agreed unseen");
        assert!(drain(&mut app).is_empty(), "removed before it was shown");

        // And once it shows, `y` runs exactly what the question showed.
        app.on_event(Event::Preview {
            name: "env-0".to_string(),
            text: "would remove env-0".to_string(),
        });
        app.key(Press::Char('y'));
        assert_eq!(app.mode, Mode::Normal);
        match drain(&mut app).as_slice() {
            [Request::Run(job)] => assert_eq!(job.line(), "vk dev gc --yes env-0"),
            other => panic!("agreeing asked for {other:?}"),
        }
    }

    /// Ctrl-C is the key every terminal program answers to, and an overlay that has the
    /// keyboard does not get to keep it from the reader.
    #[test]
    fn ctrl_c_quits_from_the_menu_and_from_the_question() {
        let mut choosing = app();
        choosing.on_event(Event::Envs(envs(1)));
        choosing.key(Press::Char('x'));
        choosing.key(Press::Interrupt);
        assert!(choosing.quit(), "Ctrl-C was swallowed by the menu");

        let mut asking = app();
        asking.on_event(Event::Envs(envs(1)));
        asking.key(Press::Char('x'));
        asking.key(Press::Char('d'));
        assert!(matches!(asking.mode, Mode::Confirm(_)));
        drain(&mut asking); // the listing the question asked to be read
        asking.key(Press::Interrupt);
        assert!(asking.quit(), "Ctrl-C was swallowed by the question");
        assert!(
            drain(&mut asking).is_empty(),
            "leaving removed the environment"
        );
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
