//! `vk dash`: one screen over every dev environment this host keeps state for.
//!
//! The dashboard reads. It holds the terminal, draws a frame, waits for a key, and draws
//! again — nothing it does changes anything on this host, so a reader can leave it open
//! beside whatever they are actually doing.
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

mod pane;
mod render;
mod state;

use std::io::Write;
use std::sync::mpsc::RecvTimeoutError;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::term::{self, AltScreen};
use state::App;

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
    let _raw = vk_core::pty::RawModeGuard::enable(libc::STDIN_FILENO)
        .context("putting the terminal in raw mode")?;
    let _screen = AltScreen::enter()?;
    // A signal that ends the process unwinds nothing, so the guards above never run:
    // without this a SIGTERM or a closed terminal leaves the reader's shell in raw mode,
    // with no cursor and the alternate screen still on.
    if let Some(saved) = saved {
        term::catch_terminating_signals(saved);
    }
    let keys = term::key_thread();

    let mut app = App::new(args.interval, args.colour);
    loop {
        paint(&app)?;
        match keys.recv_timeout(IDLE) {
            Ok(press) => {
                app.key(press);
                // Everything else already queued is folded in before the next frame: a
                // reader holding a key down should cost one redraw, not one per repeat.
                for queued in keys.try_iter() {
                    app.key(queued);
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            // The reader is gone (stdin closed): there is nobody left to drive this.
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        if app.quit() {
            return Ok(());
        }
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
