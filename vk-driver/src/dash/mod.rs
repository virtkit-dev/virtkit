//! `vk dash`: one screen over every dev environment this host keeps state for.
//!
//! The dashboard reads until it is asked for something. It holds the terminal, draws a
//! frame, waits for a key, and draws again; `x` is where the keys that change something
//! live, and the one of those that cannot be undone asks before it happens. Everything it
//! changes it changes by re-execing this same `vk` — see [`actions`].
//!
//! The terminal is left exactly as it was found, by three paths that between them cover
//! every way out: [`crate::term::AltScreen`] and [`vk_core::pty::RawModeGuard`] restore on
//! drop, which covers a return and a panic's unwind; [`crate::term::catch_terminating_signals`]
//! covers the signals that unwind nothing; and a panic hook leaves the alternate screen
//! before the message is printed, since a message written onto a screen that is then torn
//! down underneath it is the one thing the reader never sees.
//!
//! Drawing is a full redraw of the whole screen per frame, the shape
//! [`crate::atop_view`] already proves costs nothing: the cursor is homed, every line
//! erases its own tail, and an 80×24 frame is under two kilobytes written in one call.
//! There is no cell grid and no diff. The size is read fresh at the top of every frame, so
//! a window resized between two of them is simply drawn at its new size and no SIGWINCH
//! handler is needed.
//!
//! The panic lints are denied for this module and everything under it: a panic in a
//! process holding a terminal in raw mode leaves a shell without its echo, which is a worse
//! failure than whatever was being reported. They are allowed back inside the tests, where
//! an assertion is how a failure is reported and there is no terminal to ruin.
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod actions;
mod console;
mod envs;
mod pane;
mod poll;
mod render;
mod state;

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use vk_core::pty::RawModeGuard;

use crate::term::{self, AltScreen};
use actions::Job;
use poll::{Event, Reader};
use state::{App, Request};

/// How long the loop waits for a key before drawing anyway. A window resized while nothing
/// is typed is redrawn at its new size within this, which is what stands in for a SIGWINCH
/// handler.
const IDLE: Duration = Duration::from_millis(250);

/// How `vk dash` was asked for.
pub(crate) struct Args {
    /// how often the environment list is re-read
    pub(crate) interval: Duration,
    /// whether the frame may use colour at all; it carries no meaning either way
    pub(crate) colour: bool,
}

/// Draw the dashboard until the reader leaves it.
pub(crate) fn run(args: Args) -> Result<()> {
    // A full-screen panel needs a terminal on both ends — the frame goes to stdout and raw
    // mode is set on stdin — and one that can address its own screen. Where there is none,
    // the same facts are listings.
    if !term::can_draw() {
        bail!(
            "vk dash needs a terminal on both stdin and stdout that can address its own \
             screen — `vk dev list` lists every environment on this host as text, and \
             `vk list` the VMs that are up"
        );
    }
    // Read before raw mode is entered: this is what the signal handler puts back.
    let saved = term::current_termios(libc::STDIN_FILENO);
    install_panic_hook();
    // Held in options because an action that hands the terminal to a child puts them both
    // down for as long as the child has it, and takes them back afterwards.
    let mut raw =
        Some(RawModeGuard::enable(libc::STDIN_FILENO).context("putting the terminal in raw mode")?);
    let mut screen = Some(AltScreen::enter()?);
    // A signal that ends the process unwinds nothing, so the guards above never run:
    // without this a SIGTERM or a closed terminal leaves the reader's shell in raw mode,
    // with no cursor and the alternate screen still on.
    if let Some(saved) = saved {
        term::catch_terminating_signals(saved);
    }
    // One channel carries the keys and everything the background threads notice, so the
    // loop has one thing to wait on.
    let (tx, rx) = channel();
    let stop = poll::Stop::new();
    let follow = poll::Follow::default();
    // The reader is held apart from the data threads: handing the terminal over stands *it*
    // down and starts another afterwards, and the threads that keep reading this host must
    // not be stopped along with it.
    let mut keys = poll::spawn_keys(tx.clone());
    poll::spawn_refresher(tx.clone(), args.interval, stop.clone());
    poll::spawn_console(tx.clone(), stop.clone(), follow.clone());
    poll::spawn_sampler(tx.clone(), stop.clone(), follow.clone(), args.interval);

    let mut app = App::new(args.interval, args.colour);
    while !app.quit() {
        paint(&app)?;
        match rx.recv_timeout(IDLE) {
            Ok(event) => {
                app.on_event(event);
                // Everything else already queued is folded in before the next frame: a
                // reader holding a key down should cost one redraw, not one per repeat.
                for queued in rx.try_iter() {
                    app.on_event(queued);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            // Every sender is gone, which can only mean the threads have stopped. There is
            // nothing left to draw from.
            Err(RecvTimeoutError::Disconnected) => break,
        }
        while let Some(request) = app.take_request() {
            match request {
                Request::Refresh => poll::refresh_once(tx.clone()),
                Request::Sizes(dirs) => poll::spawn_size_walk(dirs, tx.clone()),
                Request::Follow(selected) => follow.point_at(selected),
                Request::Preview { name, rows } => poll::spawn_preview(rows, name, tx.clone()),
                Request::Run(job) => actions::spawn(job, tx.clone()),
                Request::Handover(job) => {
                    let (said, reader) = hand_over(&mut raw, &mut screen, keys, &tx, &rx, &job)?;
                    keys = reader;
                    app.on_event(Event::Said(said));
                    // Whatever happened in there, it may have changed what is running.
                    poll::refresh_once(tx.clone());
                }
            }
        }
    }
    stop.raise();
    keys.raise();
    Ok(())
}

/// Give the terminal to a child, and take it back when the child is done with it.
///
/// Temporarily leave the alternate screen and raw mode so the child inherits the terminal
/// settings `vk dash` started with. The signal handler and panic hook remain installed, so
/// a kill during the child shell still restores a usable terminal.
///
/// Keep the host-reading threads running so their data stays current during long actions.
/// If restoring the dashboard fails, end the session and report the child's outcome:
/// drawing into a cooked terminal would fill scrollback with frames and echo keystrokes.
fn hand_over(
    raw: &mut Option<RawModeGuard>,
    screen: &mut Option<AltScreen>,
    keys: Reader,
    tx: &Sender<Event>,
    rx: &Receiver<Event>,
    job: &Job,
) -> Result<(String, Reader)> {
    // Waited for rather than given a moment: the reader is inside a read of this terminal,
    // and the child is about to be handed the same one.
    keys.stand_down();
    // A key it had already read is one the reader typed at the dashboard, but it arrives
    // after a screen they typed it at is gone — so it goes no further. Everything else the
    // threads noticed in the meantime is kept.
    let kept: Vec<Event> = rx
        .try_iter()
        .filter(|event| !matches!(event, Event::Key(_)))
        .collect();
    for event in kept {
        // This very function holds the receiver, so nothing here is undeliverable.
        let _ = tx.send(event);
    }
    *screen = None;
    *raw = None;

    let said = run_attached(job);

    // Back to the dashboard, whatever the child made of the terminal in between.
    let entered = RawModeGuard::enable(libc::STDIN_FILENO)
        .context("putting the terminal back in raw mode")
        .and_then(|guard| {
            *raw = Some(guard);
            AltScreen::enter()
        })
        .with_context(|| format!("{said} — and the terminal did not come back"))?;
    *screen = Some(entered);
    Ok((said, poll::spawn_keys(tx.clone())))
}

/// Run the child with this terminal, and say how it went.
fn run_attached(job: &Job) -> String {
    let (label, name) = (job.action.label(), job.name.as_str());
    let mut command = match job.command() {
        Ok(command) => command,
        Err(report) => return format!("{label}: {name}: {report:#}"),
    };
    // Printed onto the terminal the reader is about to be looking at, so that what happens
    // next is not a shell appearing out of nowhere.
    println!("vk dash: {}", job.line());
    // SAFETY: `pre_exec` runs in the forked child before `exec`; `signal` is
    // async-signal-safe.
    //
    // The child shares this terminal's foreground process group, so a Ctrl-C typed into it
    // is delivered to the dashboard too — and out of raw mode that is a default-action kill.
    // Ignoring it here and putting it back for the child is what makes Ctrl-C end the shell
    // rather than the dashboard behind it.
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            Ok(())
        });
    }
    let held = unsafe { libc::signal(libc::SIGINT, libc::SIG_IGN) };
    let outcome = command.status();
    // SAFETY: putting back exactly what was there; raw mode makes it moot either way, since
    // it delivers Ctrl-C as a byte rather than as a signal.
    unsafe { libc::signal(libc::SIGINT, held) };
    match outcome {
        Ok(status) if status.success() => format!("{label}: {name} finished"),
        Ok(status) => format!("{label}: {name} exited with {status}"),
        Err(report) => format!("{label}: {name}: {report}"),
    }
}

/// Draw one frame: the whole screen, built in one buffer and written in one call, at the
/// size the terminal reports now.
fn paint(app: &App) -> Result<()> {
    // A terminal that will not report its size is drawn at the size terminals had before
    // they could be asked.
    let (rows, cols) = vk_core::pty::get_winsize(libc::STDOUT_FILENO).unwrap_or((24, 80));
    // Floored only at what a frame needs to exist at all: a line longer than the screen
    // wraps, and a wrap scrolls the whole dashboard one row further up on every repaint.
    let frame = render::frame(app, rows.max(1), cols.max(1));
    let mut out = std::io::stdout();
    out.write_all(frame.as_bytes())
        .context("drawing the dashboard")?;
    out.flush().context("drawing the dashboard")?;
    Ok(())
}

/// Leave the alternate screen before the previous panic hook prints the message, so
/// restoring the screen cannot hide it. The raw-mode guard restores settings on unwind,
/// which happens after the hook runs.
fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let mut out = std::io::stdout();
        // Nothing to do about a write that fails here: a panic is already being reported,
        // and the hook below is about to report it wherever stderr goes.
        let _ = out.write_all(b"\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
        previous(info);
    }));
}
