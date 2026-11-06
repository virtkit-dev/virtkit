//! `--vga`: a VGA text console as the guest's `/dev/tty0`, with a PS/2 keyboard.
//!
//! The VMM (libkrun's `VmmBuilder::vga_console`) emulates the VGA registers over the text
//! window at 0xb8000 and boots the kernel with an 80x25 text screen declared, so Linux's
//! vgacon drives tty0 on it. The boot child serves that console on a Unix socket in the run
//! directory ([`SOCKET`], [`serve`]): it sends a [`Frame`] whenever the screen changes and
//! types the set-2 scancodes it reads on the guest's keyboard. Clients ([`attach`]) show the
//! screen on a terminal or write it to a file, and turn what is typed (or read from a file)
//! into scancodes ([`crate::vgakeys`]). One client at a time: the newest wins.
//!
//! The screen comes back as text — characters and colours — never pixels, so a script can
//! read it as well as a person.

use std::ffi::OsString;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// The console's socket, in the run directory.
pub(crate) const SOCKET: &str = "vga.sock";

/// Kernel parameters a guest with the console boots with: kernel messages on tty0 too (the
/// console given last stays `/dev/console`), and no probe for a PS/2 mouse the i8042 lacks.
pub(crate) const CMDLINE: &str = "console=tty0 i8042.noaux";

/// How often the server looks for a changed screen.
const POLL: Duration = Duration::from_millis(40);
/// The largest screen a frame may carry, in cells: a guard against a corrupt stream.
const MAX_CELLS: usize = 256 * 128;
/// Ctrl-]: leave a terminal view.
const DETACH: u8 = 0x1d;

// ---------------------------------------------------------------------------------------------
// The wire format
// ---------------------------------------------------------------------------------------------

/// One screen: what [`krun::VgaScreen`] reads, as sent on the socket.
///
/// On the wire: a little-endian u32 length, then cols, rows, the cursor's column and row
/// (`0xffff` both when it is hidden) as little-endian u16, then `cols * rows` u16 cells, each
/// the character (code page 437) in the low byte and its VGA attribute in the high byte. A
/// length of 0 says the client was replaced by a newer one ([`REPLACED`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Frame {
    pub cols: u16,
    pub rows: u16,
    pub cursor: Option<(u16, u16)>,
    pub cells: Vec<u16>,
}

impl Frame {
    fn encode(&self) -> Vec<u8> {
        let (cx, cy) = self.cursor.unwrap_or((0xffff, 0xffff));
        let mut body = Vec::with_capacity(8 + self.cells.len() * 2);
        for v in [self.cols, self.rows, cx, cy] {
            body.extend(v.to_le_bytes());
        }
        for c in &self.cells {
            body.extend(c.to_le_bytes());
        }
        let mut out = Vec::with_capacity(4 + body.len());
        // A frame is at most 8 + 2 * MAX_CELLS bytes, well inside a u32.
        out.extend((body.len() as u32).to_le_bytes());
        out.extend(body);
        out
    }

    /// The next frame from `r`; `None` at a clean end of the stream.
    fn read(r: &mut impl Read) -> std::io::Result<Option<Incoming>> {
        let mut len = [0u8; 4];
        match r.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len) as usize;
        if len == 0 {
            return Ok(Some(Incoming::Replaced));
        }
        if !(8..=8 + 2 * MAX_CELLS).contains(&len) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("VGA frame of {len} bytes"),
            ));
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body)?;
        let word = |i: usize| {
            u16::from_le_bytes([
                body.get(i * 2).copied().unwrap_or(0),
                body.get(i * 2 + 1).copied().unwrap_or(0),
            ])
        };
        let (cols, rows, cx, cy) = (word(0), word(1), word(2), word(3));
        let cells: Vec<u16> = (4..len / 2).map(word).collect();
        if cells.len() != usize::from(cols) * usize::from(rows) {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                format!("VGA frame of {cols}x{rows} with {} cells", cells.len()),
            ));
        }
        Ok(Some(Incoming::Frame(Frame {
            cols,
            rows,
            cursor: (cx != 0xffff).then_some((cx, cy)),
            cells,
        })))
    }

    /// The screen as text: one line per row, trailing blanks dropped, code page 437 as
    /// Unicode.
    pub(crate) fn text(&self) -> String {
        let mut out = String::new();
        for row in self.cells.chunks(usize::from(self.cols).max(1)) {
            let line: String = row.iter().map(|&c| cp437(c as u8)).collect();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }
}

/// What a client reads from the console.
#[derive(Debug, PartialEq, Eq)]
enum Incoming {
    Frame(Frame),
    /// A newer client took the console.
    Replaced,
}

/// What tells a client it was replaced: a frame of length 0.
const REPLACED: [u8; 4] = [0; 4];

/// Code page 437, the VGA's character set, as Unicode. Control positions show their glyphs,
/// as on the screen; NUL is a blank.
fn cp437(b: u8) -> char {
    const HIGH: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»\
                        ░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀\
                        αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{a0}";
    const LOW: &str = " ☺☻♥♦♣♠•◘○◙♂♀♪♫☼►◄↕‼¶§▬↨↑↓→←∟↔▲▼";
    match b {
        0x00..=0x1f => LOW.chars().nth(usize::from(b)).unwrap_or(' '),
        0x7f => '⌂',
        0x20..=0x7e => char::from(b),
        _ => HIGH.chars().nth(usize::from(b - 0x80)).unwrap_or('?'),
    }
}

impl From<krun::VgaScreen> for Frame {
    fn from(s: krun::VgaScreen) -> Frame {
        Frame {
            cols: s.cols,
            rows: s.rows,
            cursor: s.cursor,
            cells: s.cells,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The server, in the VMM's boot child
// ---------------------------------------------------------------------------------------------

/// Serve `console` on the socket `path` for as long as this process runs: the newest client
/// gets every change of the screen and types on the keyboard. A guest reboot starts a new boot
/// child, which binds the socket again; clients reconnect.
pub(crate) fn serve(path: &Path, console: Arc<krun::VgaConsole>) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener =
        vk_core::unixpath::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::thread::Builder::new()
        .name("vk-vga".into())
        .spawn(move || accept(&listener, &console))
        .context("spawning the VGA console server")?;
    Ok(())
}

fn accept(listener: &UnixListener, console: &Arc<krun::VgaConsole>) {
    // Which client is current: each one's threads end once a newer one has come.
    let current = Arc::new(AtomicU64::new(0));
    for (generation, client) in (1u64..).zip(listener.incoming()) {
        let Ok(client) = client else { continue };
        current.store(generation, Ordering::SeqCst);
        let Ok(input) = client.try_clone() else {
            continue;
        };
        let (c, cur) = (console.clone(), current.clone());
        let _ = std::thread::Builder::new()
            .name("vk-vga-out".into())
            .spawn(move || send_screens(client, &c, &cur, generation));
        let (c, cur) = (console.clone(), current.clone());
        let _ = std::thread::Builder::new()
            .name("vk-vga-in".into())
            .spawn(move || type_keys(input, &c, &cur, generation));
    }
}

/// Send the screen to `client` when it changes, until the client goes or a newer one comes.
fn send_screens(
    mut client: UnixStream,
    console: &krun::VgaConsole,
    current: &AtomicU64,
    generation: u64,
) {
    let mut last: Option<Frame> = None;
    while current.load(Ordering::SeqCst) == generation {
        if let Some(frame) = console.screen().map(Frame::from)
            && last.as_ref() != Some(&frame)
        {
            if client.write_all(&frame.encode()).is_err() {
                return;
            }
            last = Some(frame);
        }
        std::thread::sleep(POLL);
    }
    // Replaced: say so, so the old client does not reconnect and take the console back.
    let _ = client.write_all(&REPLACED);
    let _ = client.shutdown(std::net::Shutdown::Both);
}

/// Type the scancodes `client` sends on the guest's keyboard, waiting for room in its buffer.
fn type_keys(
    mut client: UnixStream,
    console: &krun::VgaConsole,
    current: &AtomicU64,
    generation: u64,
) {
    let mut buf = [0u8; 4096];
    while let Ok(n) = client.read(&mut buf) {
        if n == 0 || current.load(Ordering::SeqCst) != generation {
            return;
        }
        let mut rest = &buf[..n];
        let deadline = Instant::now() + Duration::from_secs(10);
        while !rest.is_empty() && Instant::now() < deadline {
            // Err: the VM is still being built, and its keyboard comes with it.
            if let Ok(taken) = console.type_scancodes(rest) {
                rest = rest.get(taken..).unwrap_or_default();
            }
            if !rest.is_empty() {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Options: where the screen goes and where keys come from
// ---------------------------------------------------------------------------------------------

/// How a run's VGA console is presented (`--vga[=MODE]`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Mode {
    // `auto`: this terminal when it is one and the guest command does not use it; otherwise
    // stdin and stdout as files when the command does not use them; otherwise a new terminal
    // window in a graphical session, or no view (attach with `vk vga`).
    /// this terminal, else stdin/stdout as files, else a window, else no view
    #[default]
    Auto,
    /// this terminal, full screen (Ctrl-] leaves the view)
    Tty,
    /// keys from stdin, a text snapshot of the screen to stdout at each change
    Stdio,
    /// a new terminal window, attached with `vk vga`
    Window,
    /// no view: `vk vga` attaches later
    Detached,
}

/// What a VM's VGA console is wanted for: the mode and the named files (`--vga-input`,
/// `--vga-output`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Options {
    pub mode: Mode,
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
}

/// Where a view's screen goes and its keys come from, the mode resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum View {
    /// This terminal (raw, full screen).
    Tty,
    /// Files: the keys from `input` (`None`: stdin, or no input with an output file named and
    /// no input file), the screen to `output` (`None`: stdout).
    Files {
        input: Option<Input>,
        output: Option<PathBuf>,
    },
    /// A new terminal window.
    Window,
    /// None.
    Detached,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Input {
    Stdin,
    File(PathBuf),
}

/// Resolve `opts` for a run whose command uses this process's stdio when `command_uses_stdio`,
/// with stdin/stdout being terminals as `stdin_tty`/`stdout_tty` say and a graphical session
/// as `graphical` says. Refuses what cannot work.
pub(crate) fn resolve(
    opts: &Options,
    command_uses_stdio: bool,
    stdin_tty: bool,
    stdout_tty: bool,
    graphical: bool,
) -> Result<View> {
    if opts.input.is_some() || opts.output.is_some() {
        if !matches!(opts.mode, Mode::Auto | Mode::Stdio) {
            bail!(
                "--vga-input/--vga-output name files: they go with --vga=stdio (or auto), not --vga={:?}",
                opts.mode
            );
        }
        // A named file for one side; the other is stdio only when the command leaves it be.
        let input = match &opts.input {
            Some(p) => Some(Input::File(p.clone())),
            None if !command_uses_stdio => Some(Input::Stdin),
            None => None,
        };
        let output = match &opts.output {
            Some(p) => Some(p.clone()),
            None if command_uses_stdio => bail!(
                "--vga-input without --vga-output would write the screen to stdout, which the \
                 command uses; name an output file"
            ),
            None => None,
        };
        return Ok(View::Files { input, output });
    }
    match opts.mode {
        Mode::Tty | Mode::Stdio if command_uses_stdio => bail!(
            "--vga={} needs this process's stdin and stdout, which the guest command uses; \
             use --vga=window, --vga-output FILE, or attach with `vk vga` (--vga=detached)",
            if opts.mode == Mode::Tty {
                "tty"
            } else {
                "stdio"
            }
        ),
        Mode::Tty if !(stdin_tty && stdout_tty) => {
            bail!("--vga=tty needs stdin and stdout to be a terminal")
        }
        Mode::Tty => Ok(View::Tty),
        Mode::Stdio => Ok(View::Files {
            input: Some(Input::Stdin),
            output: None,
        }),
        Mode::Window if !graphical => {
            bail!("--vga=window needs a graphical session (DISPLAY or WAYLAND_DISPLAY)")
        }
        Mode::Window => Ok(View::Window),
        Mode::Detached => Ok(View::Detached),
        Mode::Auto if !command_uses_stdio && stdin_tty && stdout_tty => Ok(View::Tty),
        Mode::Auto if !command_uses_stdio => Ok(View::Files {
            input: Some(Input::Stdin),
            output: None,
        }),
        Mode::Auto if graphical => Ok(View::Window),
        Mode::Auto => Ok(View::Detached),
    }
}

/// Whether this process runs in a graphical session a terminal window can open in.
pub(crate) fn graphical_session() -> bool {
    ["WAYLAND_DISPLAY", "DISPLAY"]
        .iter()
        .any(|v| std::env::var_os(v).is_some_and(|s| !s.is_empty()))
}

// ---------------------------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------------------------

/// Whether the VM is still running, asked from the client's threads.
pub(crate) type Alive = Arc<dyn Fn() -> bool + Send + Sync>;

/// Show the console served on `socket` as `view` until the VM stops (`alive` turns false), the
/// view's input ends or, on a terminal, Ctrl-] is typed. Reconnects across guest reboots.
/// `View::Window` opens a window running `vk vga` and returns; `View::Detached` returns.
pub(crate) fn attach(socket: &Path, view: &View, alive: Alive) -> Result<()> {
    match view {
        View::Detached => Ok(()),
        View::Window => open_window(socket),
        View::Tty => attach_tty(socket, alive),
        View::Files { input, output } => {
            attach_files(socket, input.as_ref(), output.as_deref(), alive)
        }
    }
}

/// A run's view of its VM's console, on a thread of its own; stopped and joined on drop, so a
/// terminal view gives the terminal back before the run ends.
pub(crate) struct RunView {
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl RunView {
    /// Start `view` of the console on `socket`. A view that fails says why and leaves the VM
    /// running: the console can still be attached with `vk vga`.
    pub(crate) fn start(socket: PathBuf, view: View) -> RunView {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut run_view = RunView { stop, thread: None };
        let attach_hint = format!("vk vga --socket {}", socket.display());
        match view {
            View::Detached => {
                eprintln!("virtkit: VGA console: attach with `{attach_hint}`");
            }
            View::Window => {
                if let Err(e) = open_window(&socket) {
                    eprintln!("virtkit: VGA console: {e:#}; attach with `{attach_hint}`");
                }
            }
            View::Tty | View::Files { .. } => {
                let stop = run_view.stop.clone();
                let alive: Alive = Arc::new(move || !stop.load(Ordering::SeqCst));
                let spawned = std::thread::Builder::new()
                    .name("vk-vga-view".into())
                    .spawn(move || {
                        if let Err(e) = attach(&socket, &view, alive) {
                            eprintln!("virtkit: VGA console: {e:#}; attach with `{attach_hint}`");
                        }
                    });
                match spawned {
                    Ok(t) => run_view.thread = Some(t),
                    Err(e) => eprintln!("virtkit: VGA console: {e}"),
                }
            }
        }
        run_view
    }
}

impl Drop for RunView {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            // A panicked view has nothing more to give back.
            let _ = t.join();
        }
    }
}

/// Connect to `socket`, waiting up to `wait` for the VMM to bind it while `alive`.
fn connect(socket: &Path, wait: Duration, alive: &dyn Fn() -> bool) -> Result<UnixStream> {
    let start = Instant::now();
    loop {
        match vk_core::unixpath::connect(socket) {
            Ok(s) => return Ok(s),
            Err(e) if start.elapsed() >= wait || !alive() => {
                return Err(e).with_context(|| format!("connecting to {}", socket.display()));
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// How long a client waits for a rebooting guest's VMM to serve the console again.
const RECONNECT_WAIT: Duration = Duration::from_secs(30);

/// What a client's frame reader delivers.
enum Event {
    Frame(Frame),
    /// No more frames, and why.
    End(&'static str),
}

/// Frames from the console, reconnecting after a guest reboot, on a thread; [`Event::End`]
/// ends them.
fn frames(socket: PathBuf, alive: Alive) -> Result<(std::sync::mpsc::Receiver<Event>, KeySender)> {
    let first = connect(&socket, RECONNECT_WAIT, &*alive)?;
    let keys = KeySender(Arc::new(std::sync::Mutex::new(first.try_clone()?)));
    let sender = keys.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("vk-vga-frames".into())
        .spawn(move || {
            let mut stream = first;
            loop {
                match Frame::read(&mut stream) {
                    Ok(Some(Incoming::Frame(f))) => {
                        if tx.send(Event::Frame(f)).is_err() {
                            return;
                        }
                    }
                    Ok(Some(Incoming::Replaced)) => {
                        let _ = tx.send(Event::End("another view attached"));
                        return;
                    }
                    // Hung up: a guest reboot (the next boot serves the console again), or the
                    // end of the VM.
                    _ => {
                        std::thread::sleep(Duration::from_millis(200));
                        match connect(&socket, RECONNECT_WAIT, &*alive) {
                            Ok(s) if alive() => {
                                if let Ok(w) = s.try_clone() {
                                    *sender.0.lock().unwrap_or_else(|e| e.into_inner()) = w;
                                }
                                stream = s;
                            }
                            _ => {
                                let _ = tx.send(Event::End("the VM stopped"));
                                return;
                            }
                        }
                    }
                }
            }
        })
        .context("spawning the VGA frame reader")?;
    Ok((rx, keys))
}

/// The console's connection, for keys; replaced on a reconnect.
#[derive(Clone)]
struct KeySender(Arc<std::sync::Mutex<UnixStream>>);

impl KeySender {
    fn send(&self, scancodes: &[u8]) {
        if scancodes.is_empty() {
            return;
        }
        // A key lost to a reconnect is lost: the guest was rebooting.
        let _ = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .write_all(scancodes);
    }
}

/// Bytes from `reader` on a thread; the channel closes at its end.
fn read_input(mut reader: Box<dyn Read + Send>) -> Result<std::sync::mpsc::Receiver<Vec<u8>>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("vk-vga-keys".into())
        .spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    return;
                }
            }
        })
        .context("spawning the VGA key reader")?;
    Ok(rx)
}

fn attach_files(
    socket: &Path,
    input: Option<&Input>,
    output: Option<&Path>,
    alive: Alive,
) -> Result<()> {
    let mut out: Box<dyn Write> = match output {
        Some(p) => Box::new(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(p)
                .with_context(|| format!("opening {}", p.display()))?,
        ),
        None => Box::new(std::io::stdout()),
    };
    let keys_in = match input {
        None => None,
        Some(Input::Stdin) => Some(read_input(Box::new(std::io::stdin()))?),
        Some(Input::File(p)) => Some(read_input(Box::new(
            std::fs::File::open(p).with_context(|| format!("opening {}", p.display()))?,
        ))?),
    };
    let (frames, keys) = frames(socket.to_path_buf(), alive.clone())?;
    let mut translator = crate::vgakeys::KeyTranslator::default();
    let mut keys_in = keys_in;
    loop {
        pump_keys(&mut keys_in, &mut translator, &keys, false);
        match frames.recv_timeout(Duration::from_millis(50)) {
            Ok(Event::Frame(frame)) => {
                // A snapshot per change, ended by a form feed line.
                out.write_all(frame.text().as_bytes())?;
                out.write_all(b"\x0c\n")?;
                out.flush()?;
            }
            Ok(Event::End(why)) => {
                eprintln!("virtkit: VGA console: {why}");
                return Ok(());
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if !alive() {
                    return Ok(());
                }
            }
        }
    }
}

/// Type what the input has delivered; flush a pending escape once it is idle.
/// Returns false when `detach_key` is set and Ctrl-] was typed: what came before it is typed,
/// the rest dropped. Without `detach_key` (files), Ctrl-] is a key like any other.
fn pump_keys(
    input: &mut Option<std::sync::mpsc::Receiver<Vec<u8>>>,
    translator: &mut crate::vgakeys::KeyTranslator,
    keys: &KeySender,
    detach_key: bool,
) -> bool {
    let Some(rx) = input else { return true };
    let mut got = false;
    loop {
        match rx.try_recv() {
            Ok(bytes) => {
                if detach_key && let Some(at) = bytes.iter().position(|&b| b == DETACH) {
                    keys.send(&translator.feed(bytes.get(..at).unwrap_or_default()));
                    return false;
                }
                keys.send(&translator.feed(&bytes));
                got = true;
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => break,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                keys.send(&translator.flush());
                *input = None;
                break;
            }
        }
    }
    if !got {
        keys.send(&translator.flush());
    }
    true
}

fn attach_tty(socket: &Path, alive: Alive) -> Result<()> {
    let saved = crate::term::current_termios(libc::STDIN_FILENO);
    let _raw = vk_core::pty::RawModeGuard::enable(libc::STDIN_FILENO).ok();
    if let Some(saved) = saved {
        crate::term::catch_terminating_signals(saved);
    }
    let mut out = std::io::stdout();
    // The alternate screen, so the terminal's own contents come back on leaving.
    let screen = AltScreen::enter(&mut out)?;
    let (frames, keys) = frames(socket.to_path_buf(), alive.clone())?;
    let mut keys_in = Some(read_input(Box::new(std::io::stdin()))?);
    let mut translator = crate::vgakeys::KeyTranslator::default();
    let mut last: Option<Frame> = None;
    let mut redraw_at = Instant::now();
    let why = loop {
        if !pump_keys(&mut keys_in, &mut translator, &keys, true) {
            break "detached";
        }
        match frames.recv_timeout(Duration::from_millis(30)) {
            Ok(Event::Frame(frame)) => {
                draw(&mut out, &frame)?;
                last = Some(frame);
            }
            Ok(Event::End(why)) => break why,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                break "the VM stopped";
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if !alive() {
                    break "the VM stopped";
                }
                // A resized terminal is drawn again, at most twice a second.
                if redraw_at.elapsed() > Duration::from_millis(500)
                    && let Some(f) = &last
                {
                    draw(&mut out, f)?;
                    redraw_at = Instant::now();
                }
            }
        }
    };
    drop(screen);
    eprintln!(
        "virtkit: VGA console: {why}; attach again with `vk vga --socket {}`",
        socket.display()
    );
    Ok(())
}

/// The terminal's alternate screen, left on drop.
struct AltScreen;

impl AltScreen {
    fn enter(out: &mut impl Write) -> Result<AltScreen> {
        out.write_all(b"\x1b[?1049h\x1b[H\x1b[2J")?;
        out.flush()?;
        Ok(AltScreen)
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        let mut out = std::io::stdout();
        let _ = out.write_all(b"\x1b[0m\x1b[?25h\x1b[?1049l");
        let _ = out.flush();
    }
}

/// VGA colour index to ANSI colour index (VGA: blue is 1 and red 4; ANSI: the reverse).
const ANSI: [u8; 8] = [0, 4, 2, 6, 1, 5, 3, 7];

/// The SGR sequence for a VGA attribute: foreground in bits 0-3, background in bits 4-6.
fn sgr(attr: u8) -> String {
    let fg = attr & 0x0f;
    let bg = (attr >> 4) & 0x07;
    let fg_code = if fg >= 8 {
        90 + ANSI[usize::from(fg - 8)]
    } else {
        30 + ANSI[usize::from(fg)]
    };
    format!("\x1b[0;{fg_code};{}m", 40 + ANSI[usize::from(bg)])
}

/// Draw `frame` on a terminal: every row from the top-left corner, then the cursor.
fn draw(out: &mut impl Write, frame: &Frame) -> Result<()> {
    out.write_all(&render(frame))?;
    out.flush()?;
    Ok(())
}

fn render(frame: &Frame) -> Vec<u8> {
    let mut s = String::from("\x1b[?25l\x1b[H");
    let mut attr: Option<u8> = None;
    for (y, row) in frame
        .cells
        .chunks(usize::from(frame.cols).max(1))
        .enumerate()
    {
        if y > 0 {
            s.push_str("\r\n");
        }
        for &cell in row {
            let a = (cell >> 8) as u8;
            if attr != Some(a) {
                s.push_str(&sgr(a));
                attr = Some(a);
            }
            s.push(cp437(cell as u8));
        }
        // Clear what is right of the screen in a wider terminal, in the default colours.
        s.push_str("\x1b[0m\x1b[K");
        attr = None;
    }
    s.push_str("\x1b[0m\x1b[J");
    if let Some((x, y)) = frame.cursor {
        s.push_str(&format!("\x1b[{};{}H\x1b[?25h", y + 1, x + 1));
    }
    s.into_bytes()
}

// ---------------------------------------------------------------------------------------------
// A new terminal window
// ---------------------------------------------------------------------------------------------

/// The terminal emulators tried, in order, after `$TERMINAL`, and how each takes a command:
/// `xdg-terminal-exec` (the freedesktop default-terminal launcher) and Debian's
/// `x-terminal-emulator` alternative first, then common terminals.
const TERMINALS: &[(&str, &[&str])] = &[
    ("xdg-terminal-exec", &[]),
    ("x-terminal-emulator", &["-e"]),
    ("gnome-terminal", &["--"]),
    ("ptyxis", &["--"]),
    ("konsole", &["-e"]),
    ("xfce4-terminal", &["-x"]),
    ("kitty", &[]),
    ("alacritty", &["-e"]),
    ("foot", &[]),
    ("wezterm", &["start", "--"]),
    ("xterm", &["-e"]),
];

/// The argv opening a terminal window that runs `command`: `$TERMINAL` (with `-e`) when set,
/// else the first of [`TERMINALS`] on `path`.
fn terminal_argv(
    terminal_env: Option<OsString>,
    path: Option<OsString>,
    command: &[OsString],
) -> Option<Vec<OsString>> {
    let found = |name: &str| {
        std::env::split_paths(path.as_deref().unwrap_or_default())
            .map(|d| d.join(name))
            .find(|p| {
                use std::os::unix::fs::PermissionsExt;
                p.metadata()
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
    };
    let (program, args): (PathBuf, &[&str]) = match terminal_env.filter(|t| !t.is_empty()) {
        Some(t) => (PathBuf::from(t), &["-e"]),
        None => TERMINALS
            .iter()
            .find_map(|(name, args)| found(name).map(|p| (p, *args)))?,
    };
    let mut argv = vec![program.into_os_string()];
    argv.extend(args.iter().map(OsString::from));
    argv.extend(command.iter().cloned());
    Some(argv)
}

/// Open a terminal window running `vk vga --socket <socket>`, detached from this process.
fn open_window(socket: &Path) -> Result<()> {
    let vk = std::env::current_exe().context("locating vk for the window")?;
    let command: Vec<OsString> = vec![
        vk.into_os_string(),
        "vga".into(),
        "--socket".into(),
        socket.as_os_str().to_owned(),
        "--mode".into(),
        "tty".into(),
    ];
    let argv = terminal_argv(
        std::env::var_os("TERMINAL"),
        std::env::var_os("PATH"),
        &command,
    )
    .context(
        "no terminal emulator found: set $TERMINAL, or install xdg-terminal-exec or another \
         terminal; or attach from a terminal with `vk vga`",
    )?;
    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // Its own session, so the window outlives a Ctrl-C to this one.
    // SAFETY: setsid is async-signal-safe, the only call between fork and exec.
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let child = cmd.spawn().with_context(|| {
        format!(
            "opening a terminal window with {}",
            argv[0].to_string_lossy()
        )
    })?;
    // Reap it whenever it ends, without holding this thread.
    std::thread::spawn(move || {
        let mut child = child;
        let _ = child.wait();
    });
    eprintln!(
        "virtkit: VGA console in a new {} window",
        Path::new(&argv[0]).file_name().map_or_else(
            || argv[0].to_string_lossy().into_owned(),
            |n| n.to_string_lossy().into_owned()
        )
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame() -> Frame {
        let mut cells = vec![0x0720u16; 80 * 25];
        for (i, b) in b"login:".iter().enumerate() {
            cells[80 + i] = 0x0700 | u16::from(*b);
        }
        cells[0] = 0x1fc9; // ╔ in white on blue
        Frame {
            cols: 80,
            rows: 25,
            cursor: Some((7, 1)),
            cells,
        }
    }

    #[test]
    fn a_frame_survives_the_wire() {
        let f = frame();
        let mut wire = f.encode();
        let hidden = Frame {
            cursor: None,
            ..f.clone()
        };
        wire.extend(hidden.encode());
        let mut r = &wire[..];
        assert_eq!(Frame::read(&mut r).unwrap(), Some(Incoming::Frame(f)));
        assert_eq!(Frame::read(&mut r).unwrap(), Some(Incoming::Frame(hidden)));
        assert_eq!(Frame::read(&mut r).unwrap(), None);
        assert_eq!(
            Frame::read(&mut &REPLACED[..]).unwrap(),
            Some(Incoming::Replaced)
        );
    }

    #[test]
    fn a_frame_with_the_wrong_cell_count_is_refused() {
        let mut wire = frame().encode();
        // Claim 81 columns.
        wire[4] = 81;
        assert!(Frame::read(&mut &wire[..]).is_err());
        let huge = (u32::MAX).to_le_bytes();
        assert!(Frame::read(&mut &huge[..]).is_err());
    }

    #[test]
    fn text_is_the_screen_in_unicode_without_trailing_blanks() {
        let text = frame().text();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 25);
        assert_eq!(lines[0], "╔");
        assert_eq!(lines[1], "login:");
        assert_eq!(lines[2], "");
    }

    #[test]
    fn code_page_437_maps_box_drawing_and_controls() {
        assert_eq!(cp437(0xc4), '─');
        assert_eq!(cp437(0xdb), '█');
        assert_eq!(cp437(0x01), '☺');
        assert_eq!(cp437(0x00), ' ');
        assert_eq!(cp437(0xff), '\u{a0}');
        assert_eq!(cp437(b'A'), 'A');
    }

    #[test]
    fn render_colours_and_places_the_cursor() {
        let out = String::from_utf8(render(&frame())).unwrap();
        // White (15, bright) on blue (1 -> ANSI 4).
        assert!(out.contains("\x1b[0;97;44m╔"), "{out:?}");
        assert!(out.contains("login:"));
        assert!(out.ends_with("\x1b[2;8H\x1b[?25h"), "{out:?}");
    }

    #[test]
    fn auto_takes_the_terminal_only_when_the_command_leaves_it() {
        let auto = Options::default();
        assert_eq!(resolve(&auto, false, true, true, false).unwrap(), View::Tty);
        assert_eq!(
            resolve(&auto, false, false, false, true).unwrap(),
            View::Files {
                input: Some(Input::Stdin),
                output: None
            }
        );
        assert_eq!(
            resolve(&auto, true, true, true, true).unwrap(),
            View::Window
        );
        assert_eq!(
            resolve(&auto, true, true, true, false).unwrap(),
            View::Detached
        );
    }

    #[test]
    fn explicit_modes_refuse_what_cannot_work() {
        let mode = |m| Options {
            mode: m,
            ..Options::default()
        };
        assert!(resolve(&mode(Mode::Tty), true, true, true, true).is_err());
        assert!(resolve(&mode(Mode::Tty), false, false, true, true).is_err());
        assert!(resolve(&mode(Mode::Stdio), true, false, false, true).is_err());
        assert!(resolve(&mode(Mode::Window), false, true, true, false).is_err());
        assert_eq!(
            resolve(&mode(Mode::Detached), true, true, true, true).unwrap(),
            View::Detached
        );
    }

    #[test]
    fn named_files_leave_stdio_to_the_command() {
        let opts = Options {
            output: Some("screen.txt".into()),
            ..Options::default()
        };
        assert_eq!(
            resolve(&opts, true, true, true, true).unwrap(),
            View::Files {
                input: None,
                output: Some("screen.txt".into())
            }
        );
        // With stdio free (`vk vga`, or a run without a command), keys come from stdin.
        assert_eq!(
            resolve(&opts, false, true, true, true).unwrap(),
            View::Files {
                input: Some(Input::Stdin),
                output: Some("screen.txt".into())
            }
        );
        let input_only = Options {
            input: Some("keys.txt".into()),
            ..Options::default()
        };
        assert!(resolve(&input_only, true, true, true, true).is_err());
        assert_eq!(
            resolve(&input_only, false, true, true, true).unwrap(),
            View::Files {
                input: Some(Input::File("keys.txt".into())),
                output: None
            }
        );
        let window_files = Options {
            mode: Mode::Window,
            output: Some("s".into()),
            ..Options::default()
        };
        assert!(resolve(&window_files, false, true, true, true).is_err());
    }

    #[test]
    fn ctrl_close_bracket_detaches_a_terminal_view_but_is_typed_from_files() {
        let typed_by = |detach_key: bool, input: &[u8]| {
            let (ours, theirs) = UnixStream::pair().unwrap();
            let keys = KeySender(Arc::new(std::sync::Mutex::new(ours)));
            let (tx, rx) = std::sync::mpsc::channel();
            tx.send(input.to_vec()).unwrap();
            drop(tx);
            let mut rx = Some(rx);
            let mut translator = crate::vgakeys::KeyTranslator::default();
            let kept = pump_keys(&mut rx, &mut translator, &keys, detach_key);
            drop(keys);
            let mut sent = Vec::new();
            (&theirs).read_to_end(&mut sent).unwrap();
            (kept, sent)
        };
        let a = crate::vgakeys::KeyTranslator::default().feed(b"a");
        let (kept, sent) = typed_by(true, b"a\x1db");
        assert!(!kept, "detached");
        assert_eq!(
            sent, a,
            "what came before Ctrl-] is typed, the rest dropped"
        );
        let (kept, sent) = typed_by(false, b"a\x1d");
        assert!(kept);
        assert_eq!(
            sent,
            crate::vgakeys::KeyTranslator::default().feed(b"a\x1d"),
            "typed as Ctrl-]"
        );
    }

    #[test]
    fn terminal_argv_prefers_terminal_then_the_first_found() {
        let dir = std::env::temp_dir().join(format!("vk-vga-term-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cmd: Vec<OsString> = vec!["vk".into(), "vga".into()];
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["konsole", "xterm"] {
                let p = dir.join(name);
                std::fs::write(&p, "").unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let path = Some(dir.clone().into_os_string());
        let argv = terminal_argv(None, path.clone(), &cmd).unwrap();
        assert_eq!(argv[0], dir.join("konsole").into_os_string());
        assert_eq!(&argv[1..], ["-e", "vk", "vga"]);
        let argv = terminal_argv(Some("myterm".into()), path, &cmd).unwrap();
        assert_eq!(argv, ["myterm", "-e", "vk", "vga"]);
        assert_eq!(terminal_argv(None, Some("/nonexistent".into()), &cmd), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
