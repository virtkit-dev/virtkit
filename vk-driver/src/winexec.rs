//! `vk exec` and `vk cp` against an agent-less (Windows) guest, through its qemu-ga
//! ([`crate::qga`]).
//!
//! qemu-ga's `guest-exec` returns a command's output only once it has exited, builds the
//! child's command line with quoting cmd.exe does not read, and opens files sharing them for
//! reading only, so it cannot read a log a running command still holds open. So `vk exec`
//! writes the command as a batch file under [`RUN_DIR`] (`guest-file-write`) and a PowerShell
//! wrapper ([`WRAPPER`]) that runs it with its output on a pipe and publishes what arrives as
//! closed, numbered segment files at least every [`POLL`]; vk starts the wrapper (plain path
//! arguments, nothing to quote), reads each segment as it appears and deletes the lot at the
//! end. The exit code is the command's, which the wrapper leaves in a file, with the number of
//! segments, once it has published all of its output. The batch file deletes itself as it
//! ends, as it holds the command's environment.

use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::qga::{AgentError, Client};

/// Where `vk exec` leaves its batch files and logs in the guest: under SYSTEM's own temp
/// directory (qemu-ga runs as SYSTEM), which other users can neither read nor write, since the
/// batch files carry the command's environment. qemu-ga takes literal paths, so this one
/// assumes Windows is installed in `C:\Windows`.
const RUN_DIR: &str = r"C:\Windows\System32\config\systemprofile\AppData\Local\Temp\vk";

/// How often a running command's log is read.
const POLL: Duration = Duration::from_millis(250);

/// The most a single `guest-file-read` or `guest-file-write` moves.
const CHUNK: usize = 48 * 1024;

/// How long to wait for the guest agent to answer a new connection: a guest still booting
/// has not started it yet.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// How many times following one command reconnects to the agent before giving up.
const MAX_RECONNECTS: u32 = 3;

/// The pause before such a reconnect.
const RECONNECT_PAUSE: Duration = if cfg!(test) {
    Duration::from_millis(10)
} else {
    Duration::from_secs(2)
};

/// `arg` quoted for `CommandLineToArgvW` / the MSVC runtime, which is how a Windows program
/// splits its command line: bare when it has no blank or quote, otherwise in quotes with each
/// quote escaped and the backslashes before a quote (or the closing one) doubled.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            c => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Escape a command line for a batch file so the program receives it verbatim: double `%`
/// to prevent batch expansion and escape cmd's operators outside quotes with `^`, which cmd
/// removes before starting the program.
pub fn batch_escape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut quoted = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                out.push(c);
            }
            '%' => out.push_str("%%"),
            '^' | '&' | '|' | '<' | '>' | '(' | ')' if !quoted => {
                out.push('^');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out
}

/// The PowerShell wrapper: runs the batch file `{bat}` with no input and its output (errors
/// folded in by the batch file) on a pipe, and every [`POLL`] — or 48 KiB — moves what arrived
/// into the next segment, `{seg}.<n>.seg`, written aside and renamed so it only ever appears
/// whole. Once the command has exited and its output is all published, writes its exit code
/// and the number of segments to `{seg}.exit`; if the wrapper fails first, it kills the
/// command rather than leave it running unread.
const WRAPPER: &str = r#"$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "$env:SystemRoot\System32\cmd.exe"
$psi.Arguments = '/d /v:off /c {bat}'
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.RedirectStandardOutput = $true
$p = [System.Diagnostics.Process]::Start($psi)
try {
  $p.StandardInput.Close()
  $s = $p.StandardOutput.BaseStream
  $b = New-Object byte[] 65536
  $pending = New-Object System.IO.MemoryStream
  $script:n = 0
  $script:last = [DateTime]::UtcNow
  function Publish {
    if ($pending.Length -gt 0) {
      $tmp = "{seg}.$($script:n).tmp"
      [System.IO.File]::WriteAllBytes($tmp, $pending.ToArray())
      [System.IO.File]::Move($tmp, "{seg}.$($script:n).seg")
      $script:n++
      $pending.SetLength(0)
    }
    $script:last = [DateTime]::UtcNow
  }
  while ($true) {
    $t = $s.ReadAsync($b, 0, $b.Length)
    while (-not $t.Wait({poll_ms})) { Publish }
    $r = $t.Result
    if ($r -eq 0) { break }
    $pending.Write($b, 0, $r)
    if ($pending.Length -ge 49152 -or ([DateTime]::UtcNow - $script:last).TotalMilliseconds -ge {poll_ms}) { Publish }
  }
  Publish
  $p.WaitForExit()
  [System.IO.File]::WriteAllText("{seg}.exit", "$($p.ExitCode) $($script:n)")
} finally {
  if (-not $p.HasExited) { taskkill.exe /T /F /PID $p.Id | Out-Null }
}
"#;

/// `script` as PowerShell's `-EncodedCommand` takes it: base64 of its UTF-16LE text.
pub fn encoded_command(script: &str) -> String {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    crate::sshagent::b64_encode(&utf16)
}

/// [`WRAPPER`] for the batch file `bat`, publishing segments named after `seg`.
pub fn wrapper(bat: &str, seg: &str) -> String {
    WRAPPER
        .replace("{bat}", bat)
        .replace("{seg}", seg)
        .replace("{poll_ms}", &POLL.as_millis().to_string())
}

/// The batch file `vk exec` runs: UTF-8 console code page, the environment, the working
/// directory, then the command, each with its errors folded into its output, which goes to
/// `log` when given (a background command) and to the wrapper's pipe otherwise. It then
/// deletes itself (`(goto)` ends the batch first, so cmd.exe reads no more of it) and exits
/// with the command's code, or 1 when `dir` does not exist. The redirections come first: an
/// argument with an odd number of quotes leaves cmd.exe reading the rest of its line as quoted.
pub fn script(
    command_line: &str,
    env: &[(String, String)],
    dir: Option<&str>,
    log: Option<&str>,
) -> String {
    let redirect = match log {
        Some(log) => format!(">\"{log}\" 2>&1"),
        None => "2>&1".to_string(),
    };
    let mut s = String::from("@echo off\r\nchcp 65001 >nul\r\n");
    for (key, value) in env {
        let (key, value) = (key.replace('%', "%%"), value.replace('%', "%%"));
        s.push_str(&format!("set \"{key}={value}\"\r\n"));
    }
    if let Some(dir) = dir {
        let dir = dir.replace('%', "%%");
        s.push_str(&format!("{redirect} cd /d \"{dir}\" && "));
    }
    s.push_str(&format!("{redirect} {}\r\n", batch_escape(command_line)));
    s.push_str("(goto) 2>nul & del \"%~f0\" & exit /b %ERRORLEVEL%\r\n");
    s
}

/// `--env` entries as pairs, refusing what a batch `set` cannot carry.
pub fn parse_env(env: &[String]) -> Result<Vec<(String, String)>> {
    env.iter()
        .map(|entry| {
            let Some((key, value)) = entry.split_once('=') else {
                bail!("invalid --env {entry:?} (expected KEY=value)");
            };
            if !valid_var(key, value) {
                bail!(
                    "--env {entry:?}: a Windows guest's variables cannot hold quotes or newlines"
                );
            }
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Whether a batch `set` can carry the variable `key=value`: a name, and no quote or newline.
pub fn valid_var(key: &str, value: &str) -> bool {
    !key.is_empty() && !key.contains(['=', '"', '\r', '\n']) && !value.contains(['"', '\r', '\n'])
}

/// Refuse a command or `--dir` a batch file cannot carry: a newline ends its line.
pub fn check_command(argv: &[String], dir: Option<&str>) -> Result<()> {
    if let Some(arg) = argv.iter().find(|a| a.contains(['\r', '\n'])) {
        bail!("{arg:?}: a Windows guest's command line cannot hold newlines");
    }
    check_dir(dir, "--dir")
}

/// Refuse a command line or working directory a batch file cannot carry.
pub(crate) fn check_line(command_line: &str, dir: Option<&str>) -> Result<()> {
    if command_line.contains(['\r', '\n']) {
        bail!("{command_line:?}: a Windows guest's command line cannot hold newlines");
    }
    check_dir(dir, "WORKDIR")
}

/// Refuse a working directory (`what`) a batch file cannot carry: a quote ends its `cd`
/// argument, a newline its line.
fn check_dir(dir: Option<&str>, what: &str) -> Result<()> {
    if let Some(dir) = dir.filter(|d| d.contains(['"', '\r', '\n'])) {
        bail!("{what} {dir:?}: a Windows guest's directory cannot hold quotes or newlines");
    }
    Ok(())
}

/// Write `bytes` to the guest file `path`, creating or truncating it.
pub(crate) fn put(ga: &mut Client, path: &str, bytes: &[u8]) -> Result<()> {
    write_from(ga, path, bytes).map(drop)
}

/// Write what `src` holds to the guest file `path`, creating or truncating it, one
/// [`CHUNK`] at a time; returns the bytes written.
pub(crate) fn write_from(ga: &mut Client, path: &str, mut src: impl Read) -> Result<u64> {
    let handle = ga
        .file_open(path, "wb")
        .with_context(|| format!("opening {path} for writing in the guest"))?;
    let mut written = 0u64;
    let mut chunk = Vec::with_capacity(CHUNK);
    let copied = loop {
        chunk.clear();
        match src.by_ref().take(CHUNK as u64).read_to_end(&mut chunk) {
            Ok(0) => break Ok(written),
            Ok(n) => {
                if let Err(e) = ga.file_write(handle, &chunk) {
                    break Err(e);
                }
                written += n as u64;
            }
            Err(e) => break Err(e.into()),
        }
    };
    ga.file_close(handle)?;
    copied.with_context(|| format!("writing {path} in the guest"))
}

/// Open the guest file `path` for reading, or `None` when the agent cannot (it is not there
/// yet, or the agent failed to open it); any other failure is an error.
fn open_if_present(ga: &mut Client, path: &str) -> Result<Option<i64>> {
    match ga.file_open(path, "rb") {
        Ok(handle) => Ok(Some(handle)),
        Err(e) if e.downcast_ref::<AgentError>().is_some() => Ok(None),
        Err(e) => Err(e),
    }
}

/// Run `cmd.exe /d /v:off /c <words>` and wait for it, for vk's own housekeeping. Each word
/// goes as its own argument and must need no quoting (qemu-ga's quoting is not cmd.exe's):
/// vk's paths under [`RUN_DIR`] have no blanks.
pub(crate) fn cmd(ga: &mut Client, words: &[&str]) -> Result<i32> {
    run_program(ga, "cmd.exe", &[&["/d", "/v:off", "/c"], words].concat())
}

/// Run the guest program `path` with `args` and wait for it; returns its exit code. qemu-ga
/// quotes each argument, so no shell sees them.
pub(crate) fn run_program(ga: &mut Client, path: &str, args: &[&str]) -> Result<i32> {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let pid = ga.exec(path, &args, false)?;
    loop {
        let status = ga.exec_status(pid)?;
        if status.exited {
            return Ok(status.exitcode.unwrap_or(-1));
        }
        std::thread::sleep(POLL);
    }
}

/// Start the command line `command_line` the way [`exec_command_line`] runs it, from a batch
/// file, but straight under cmd.exe, its output dropped: no PowerShell wrapper to wait for.
/// Returns its pid, waiting at most `timeout` for the agent to start it, and the batch file,
/// which deletes itself as it ends.
pub(crate) fn start_line(
    ga: &mut Client,
    command_line: &str,
    timeout: Duration,
) -> Result<(i64, String)> {
    check_line(command_line, None)?;
    let bat = format!(r"{RUN_DIR}\{}.cmd", crate::scratch::random_nonce()?);
    put_run_file(ga, &bat, script(command_line, &[], None, None).as_bytes())?;
    let args = ["/d", "/v:off", "/c", &bat].map(String::from);
    let pid = ga.exec_within("cmd.exe", &args, timeout)?;
    Ok((pid, bat))
}

/// Write `body` to the guest file `path` under [`RUN_DIR`], making the directory first if
/// this is the guest's first command.
fn put_run_file(ga: &mut Client, path: &str, body: &[u8]) -> Result<()> {
    if put(ga, path, body).is_err() {
        let code = cmd(ga, &["if", "not", "exist", RUN_DIR, "mkdir", RUN_DIR])?;
        if code != 0 {
            bail!("vk exec assumes Windows in C:\\Windows (mkdir {RUN_DIR} exited {code})");
        }
        put(ga, path, body)?;
    }
    Ok(())
}

/// Run PowerShell `script` through `ga` and return its exit code. On a nonzero exit, print
/// its output with each line prefixed by `what`. Write the script as a `.ps1` under [`RUN_DIR`]
/// and delete it afterward: a command line would cap it at cmd's 8191 characters. Only SYSTEM
/// and administrators can read the file; a fixed-size [`run_ps1_command_line`] runs it.
pub(crate) fn powershell(ga: &mut Client, script: &str, what: &str) -> Result<i32> {
    let path = format!(r"{RUN_DIR}\{}.ps1", crate::scratch::random_nonce()?);
    // With a BOM: without one, Windows PowerShell reads the file in the ANSI code page.
    put_run_file(ga, &path, format!("\u{feff}{script}").as_bytes())?;
    let mut out = Vec::new();
    let ran = exec_command_line(ga, &run_ps1_command_line(&path), &[], None, false, &mut out);
    // Best effort, as for a command's own files.
    let _ = cmd(ga, &["del", "/q", &path]);
    let code = ran?;
    if code != 0 {
        for line in String::from_utf8_lossy(&out).lines() {
            eprintln!("virtkit: {what}: {line}");
        }
    }
    Ok(code)
}

/// The command line running the `.ps1` at `path` as `-EncodedCommand`, the way vk's other
/// PowerShell runs: under qemu-ga a script started with `-File` never starts, and a script
/// block made from the file's text needs no execution policy. An `exit` in the script ends
/// PowerShell with its code, as at the top level of the command.
fn run_ps1_command_line(path: &str) -> String {
    let path = path.replace('\'', "''");
    let stub = format!("& ([scriptblock]::Create([IO.File]::ReadAllText('{path}')))");
    format!(
        "powershell.exe -NoProfile -NonInteractive -EncodedCommand {}",
        encoded_command(&stub)
    )
}

/// How long [`restart`] waits for the guest's agent to stop answering.
const RESTART_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// The exit code of a command that has started Windows restarting
/// (`ERROR_SUCCESS_REBOOT_INITIATED`).
pub(crate) const RESTART_INITIATED: i32 = 1641;

/// Restart the guest through `ga`, after a command that exited `code`, and wait until its agent
/// stops answering, so that the next connection reaches the agent of the restarted guest rather
/// than syncing with this one; `running` tells whether the guest is still up. After
/// [`RESTART_INITIATED`], Windows is restarting already: its agent may refuse the restart asked
/// on top, which is no failure.
pub(crate) fn restart(ga: &mut Client, code: i32, running: &mut dyn FnMut() -> bool) -> Result<()> {
    let asked = ga.exec("shutdown.exe", &["/r", "/t", "0"].map(String::from), false);
    if code != RESTART_INITIATED {
        asked?;
    }
    let deadline = Instant::now() + RESTART_TIMEOUT;
    // Gone after two missed pings in a row: a busy guest can miss one.
    let mut missed = 0;
    loop {
        missed = match ga.call("guest-ping", None, Duration::from_secs(5)) {
            Ok(_) => 0,
            Err(_) => missed + 1,
        };
        if missed == 2 {
            return Ok(());
        }
        if !running() {
            bail!("the guest powered off instead of restarting");
        }
        if Instant::now() >= deadline {
            bail!("the guest did not restart within {RESTART_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Run `argv` in the guest behind `socket`, stream its output to stdout and return its exit
/// code. With `background`, log output beside the batch file, print the log path to stderr
/// and return 0 once the command starts.
pub fn exec(
    socket: &Path,
    argv: &[String],
    env: &[(String, String)],
    dir: Option<&str>,
    background: bool,
) -> Result<i32> {
    let line = argv
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let mut ga = Client::connect(socket, CONNECT_TIMEOUT)?;
    run_line(
        &mut ga,
        &line,
        env,
        dir,
        background,
        &mut std::io::stdout().lock(),
    )
}

/// Run the Windows command line `command_line` (a program and its arguments as
/// `CreateProcess` takes them) through `ga`, its output streamed to `out`, and return its exit
/// code, or with `background`, start it and return 0 at once, its output going to a log in the
/// guest. A newline in it, or a quote or newline in the working directory `dir`, is refused: a
/// batch file cannot carry them. A shell-form line (`cmd /S /C <text>`) keeps cmd's operators
/// for the inner shell: [`batch_escape`] makes them literal to the batch file only.
pub fn exec_command_line(
    ga: &mut Client,
    command_line: &str,
    env: &[(String, String)],
    dir: Option<&str>,
    background: bool,
    out: &mut impl Write,
) -> Result<i32> {
    check_line(command_line, dir)?;
    run_line(ga, command_line, env, dir, background, out)
}

/// Run `command_line` as [`exec`] does, through `ga`, its output streamed to `out`.
fn run_line(
    ga: &mut Client,
    command_line: &str,
    env: &[(String, String)],
    dir: Option<&str>,
    background: bool,
    out: &mut impl Write,
) -> Result<i32> {
    let base = format!(r"{RUN_DIR}\{}", crate::scratch::random_nonce()?);
    let log = format!("{base}.log");
    let body = script(command_line, env, dir, background.then_some(log.as_str()));
    match run(ga, &base, body.as_bytes(), background, out) {
        Ok(None) => {
            eprintln!("virtkit: started in the background; its output goes to {log} in the guest");
            Ok(0)
        }
        ran => {
            // Its segments, exit file, and the batch file if it never ran. Best effort; a
            // leftover stays where only SYSTEM and administrators can read it.
            let _ = cmd(ga, &["del", "/q", &format!("{base}.*")]);
            ran.map(Option::unwrap_or_default)
        }
    }
}

/// Write `body` as the batch file `<base>.cmd` and run it: `None` once a background command
/// has started, otherwise the command's exit code once it has ended, its output streamed to
/// `out`.
fn run(
    ga: &mut Client,
    base: &str,
    body: &[u8],
    background: bool,
    out: &mut impl Write,
) -> Result<Option<i32>> {
    let bat = format!("{base}.cmd");
    put_run_file(ga, &bat, body)?;
    if background {
        ga.exec(
            "cmd.exe",
            &["/d", "/v:off", "/c", &bat].map(String::from),
            false,
        )?;
        return Ok(None);
    }
    // As -EncodedCommand: a script run with -File under qemu-ga never starts. Its own
    // output is only ever its errors.
    let pid = ga.exec(
        "powershell.exe",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            &encoded_command(&wrapper(&bat, base)),
        ]
        .map(String::from),
        true,
    )?;
    follow(ga, pid, base, out).map(Some)
}

/// How far [`follow`] has got, kept across reconnects.
#[derive(Default)]
struct Progress {
    /// the segment being copied
    segment: u64,
    /// how many of its bytes are already in `out`
    offset: u64,
    /// the guest file open, to close after a reconnect
    open: Option<i64>,
    /// the command's status once it has exited: qemu-ga forgets a command once it has said so
    exited: Option<crate::qga::ExecStatus>,
}

/// Copy the output of the wrapper `pid`, published as `<base>.<n>.seg`, to `out` as it
/// appears, until it exits; returns the command's exit code. Reconnect up to [`MAX_RECONNECTS`]
/// times after a lost connection, resuming at the byte reached: the relay drops clients whose
/// answers are slow to come.
fn follow(ga: &mut Client, pid: i64, base: &str, out: &mut impl Write) -> Result<i32> {
    let mut progress = Progress::default();
    let mut reconnects = 0;
    loop {
        let e = match follow_from(ga, pid, base, &mut progress, out) {
            Ok(code) => return Ok(code),
            Err(e) => e,
        };
        if e.downcast_ref::<crate::qga::Lost>().is_none() || reconnects == MAX_RECONNECTS {
            if let Some(handle) = progress.open {
                let _ = ga.file_close(handle);
            }
            return Err(e);
        }
        reconnects += 1;
        eprintln!("virtkit: {e:#}; reconnecting to follow the command");
        std::thread::sleep(RECONNECT_PAUSE);
        ga.reconnect(CONNECT_TIMEOUT)?;
        // The agent keeps its handles across connections; this one's position is unknown.
        if let Some(handle) = progress.open.take() {
            let _ = ga.file_close(handle);
        }
    }
}

/// [`follow`] from `progress` on, with one connection.
fn follow_from(
    ga: &mut Client,
    pid: i64,
    base: &str,
    progress: &mut Progress,
    out: &mut impl Write,
) -> Result<i32> {
    while progress.exited.is_none() {
        // Status first: once it reads exited, every segment is already published.
        let status = ga.exec_status(pid)?;
        copy_segments(ga, base, progress, out)?;
        out.flush()?;
        if status.exited {
            progress.exited = Some(status);
        } else {
            std::thread::sleep(POLL);
        }
    }
    let Some(handle) = open_if_present(ga, &format!("{base}.exit"))? else {
        let stderr = progress
            .exited
            .as_ref()
            .and_then(|status| status.err_data.as_deref())
            .and_then(crate::sshagent::b64_decode);
        let stderr = String::from_utf8_lossy(stderr.as_deref().unwrap_or_default());
        let stderr = stderr.trim();
        bail!(
            "vk's output wrapper failed in the guest before the command finished{}{stderr}",
            if stderr.is_empty() { "" } else { ": " }
        );
    };
    progress.open = Some(handle);
    let mut exit = Vec::new();
    drain(ga, handle, &mut exit, &mut 0)?;
    progress.open = None;
    ga.file_close(handle)?;
    let exit = String::from_utf8_lossy(&exit);
    let Some((code, published)) = exit
        .trim()
        .split_once(' ')
        .and_then(|(code, n)| Some((code.parse::<i32>().ok()?, n.parse::<u64>().ok()?)))
    else {
        bail!("the guest reported the exit {exit:?} (expected \"<code> <segments>\")");
    };
    if progress.segment != published {
        bail!(
            "read {} of the command's {published} output segments: the rest is lost",
            progress.segment
        );
    }
    Ok(code)
}

/// Copy the segments published since `progress` to `out`.
fn copy_segments(
    ga: &mut Client,
    base: &str,
    progress: &mut Progress,
    out: &mut impl Write,
) -> Result<()> {
    while let Some(handle) = open_if_present(ga, &format!("{base}.{}.seg", progress.segment))? {
        progress.open = Some(handle);
        if progress.offset > 0 {
            ga.file_seek(handle, progress.offset)?;
        }
        drain(ga, handle, out, &mut progress.offset)?;
        progress.open = None;
        ga.file_close(handle)?;
        progress.segment += 1;
        progress.offset = 0;
    }
    Ok(())
}

/// Copy the guest file behind `handle` to `out`, to its end, counting the bytes in `copied`.
fn drain(ga: &mut Client, handle: i64, out: &mut impl Write, copied: &mut u64) -> Result<()> {
    loop {
        let (bytes, eof) = ga.file_read(handle, CHUNK)?;
        out.write_all(&bytes)?;
        *copied += bytes.len() as u64;
        if eof || bytes.is_empty() {
            return Ok(());
        }
    }
}

/// Copy the host file `local` to the guest file `remote` (a full path: not a directory) in the
/// guest behind `socket`.
pub fn copy_in(socket: &Path, local: &Path, remote: &str) -> Result<u64> {
    let file =
        std::fs::File::open(local).with_context(|| format!("reading {}", local.display()))?;
    let mut ga = Client::connect(socket, CONNECT_TIMEOUT)?;
    let started = Instant::now();
    let copied = write_from(&mut ga, remote, file).with_context(|| {
        format!("copying to {remote} in the guest (the guest side must be a file's full path)")
    })?;
    log::debug!("copied {copied} bytes in {:?}", started.elapsed());
    Ok(copied)
}

/// Copy the guest file `remote` in the guest behind `socket` to the host file `local`.
pub fn copy_out(socket: &Path, remote: &str, local: &Path) -> Result<u64> {
    let mut ga = Client::connect(socket, CONNECT_TIMEOUT)?;
    let handle = ga.file_open(remote, "rb").with_context(|| {
        format!("opening {remote} in the guest (the guest side must be a file's full path)")
    })?;
    let read = std::fs::File::create(local)
        .with_context(|| format!("creating {}", local.display()))
        .and_then(|mut file| {
            let mut copied = 0;
            drain(&mut ga, handle, &mut file, &mut copied)
                .with_context(|| format!("copying {remote} from the guest"))?;
            Ok(copied)
        });
    ga.file_close(handle)?;
    read
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_quoted_the_way_a_windows_program_splits_them() {
        assert_eq!(quote_arg("plain"), "plain");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("two words"), "\"two words\"");
        assert_eq!(quote_arg(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_arg(r"C:\dir with space\"), r#""C:\dir with space\\""#);
        assert_eq!(quote_arg(r"C:\no\space"), r"C:\no\space");
        assert_eq!(quote_arg(r#"a\"b"#), r#""a\\\"b""#);
    }

    /// The batch-file line that runs `argv`.
    fn cmd_line(argv: &[String]) -> String {
        batch_escape(
            &argv
                .iter()
                .map(|a| quote_arg(a))
                .collect::<Vec<_>>()
                .join(" "),
        )
    }

    #[test]
    fn cmd_operators_stay_literal_outside_quotes_and_percent_is_doubled() {
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(cmd_line(&argv(&["echo", "a&b"])), "echo a^&b");
        assert_eq!(cmd_line(&argv(&["echo", "a & b"])), "echo \"a & b\"");
        assert_eq!(cmd_line(&argv(&["echo", "%PATH%"])), "echo %%PATH%%");
        assert_eq!(
            cmd_line(&argv(&["powershell", "-Command", "Get-Date | Out-String"])),
            "powershell -Command \"Get-Date | Out-String\""
        );
        assert_eq!(cmd_line(&argv(&["x", "(y)>z"])), "x ^(y^)^>z");
    }

    #[test]
    fn the_script_sets_the_environment_and_directory_then_logs_the_command() {
        let script = script(
            "hostname",
            &[("A%".into(), "1%".into())],
            Some(r"C:\Users"),
            Some(r"C:\log.txt"),
        );
        assert_eq!(
            script,
            "@echo off\r\nchcp 65001 >nul\r\nset \"A%%=1%%\"\r\n\
             >\"C:\\log.txt\" 2>&1 cd /d \"C:\\Users\" && >\"C:\\log.txt\" 2>&1 hostname\r\n\
             (goto) 2>nul & del \"%~f0\" & exit /b %ERRORLEVEL%\r\n"
        );
    }

    #[test]
    fn an_odd_quote_cannot_swallow_the_redirections() {
        // cmd.exe reads everything after the third quote as quoted.
        let script = script(r#"echo "5\"""#, &[], None, None);
        assert_eq!(
            script,
            "@echo off\r\nchcp 65001 >nul\r\n2>&1 echo \"5\\\"\"\r\n\
             (goto) 2>nul & del \"%~f0\" & exit /b %ERRORLEVEL%\r\n"
        );
    }

    #[test]
    fn newlines_and_quotes_a_batch_file_cannot_carry_are_refused() {
        let argv = |a: &str| vec!["echo".to_string(), a.to_string()];
        assert!(check_command(&argv("a b \"c\""), Some(r"C:\a b")).is_ok());
        assert!(check_command(&argv("a\r\nb"), None).is_err());
        assert!(check_command(&argv("a\rb"), None).is_err());
        assert!(check_command(&argv("a"), Some("C:\\x\r")).is_err());
        assert!(check_command(&argv("a"), Some("C:\\\"x")).is_err());
        assert!(check_command(&argv("a"), Some("C:\\x\n")).is_err());
    }

    #[test]
    fn a_shell_form_line_keeps_its_operators_for_the_inner_shell() {
        assert_eq!(
            batch_escape(r#"cmd /S /C echo %A% & echo "x | y" > out"#),
            r#"cmd /S /C echo %%A%% ^& echo "x | y" ^> out"#
        );
        assert!(check_line("cmd /S /C echo a & echo b", Some(r"C:\a b")).is_ok());
        assert!(check_line("cmd /S /C echo a\r\necho b", None).is_err());
        assert!(check_line("cmd /S /C echo a\nb", None).is_err());
        assert!(check_line("x", Some("C:\\\"x")).is_err());
    }

    #[test]
    fn the_wrapper_runs_the_batch_file_and_names_its_segments() {
        let ps = wrapper(r"C:\run\x.cmd", r"C:\run\x");
        assert!(ps.contains(r"$psi.Arguments = '/d /v:off /c C:\run\x.cmd'"));
        assert!(ps.contains(r#"WriteAllText("C:\run\x.exit", "$($p.ExitCode) $($script:n)")"#));
        assert!(ps.contains(r#"$tmp = "C:\run\x.$($script:n).tmp""#));
        assert!(ps.contains("$t.Wait(250)"));
        assert!(!ps.contains("{bat}") && !ps.contains("{seg}") && !ps.contains("{poll_ms}"));
    }

    /// A fake agent whose wrapper has exited, with stderr `stderr`, leaving the guest files
    /// `files`, and [`follow`]'s result against it with what it wrote.
    fn follow_with(files: &[(&str, &str)], stderr: &str) -> (Result<i32>, String) {
        use crate::qga::tests::{client, synced};
        let files: Vec<(String, String)> = files
            .iter()
            .map(|(p, b)| (p.to_string(), b.to_string()))
            .collect();
        let stderr = crate::sshagent::b64_encode(stderr.as_bytes());
        let mut ga = client(move |request| {
            let args = &request["arguments"];
            let reply = match request["execute"].as_str() {
                Some("guest-sync-delimited") => return synced(request),
                Some("guest-exec-status") => {
                    serde_json::json!({ "exited": true, "exitcode": 0, "err-data": stderr })
                }
                Some("guest-file-open") => {
                    match files.iter().position(|(p, _)| *p == args["path"]) {
                        Some(i) => serde_json::json!(i),
                        None => {
                            return b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"no\"}}\n"
                                .to_vec();
                        }
                    }
                }
                Some("guest-file-read") => {
                    let body = &files[args["handle"].as_u64().unwrap() as usize].1;
                    let b64 = crate::sshagent::b64_encode(body.as_bytes());
                    serde_json::json!({ "count": body.len(), "buf-b64": b64, "eof": true })
                }
                _ => serde_json::json!({}),
            };
            format!("{}\n", serde_json::json!({ "return": reply })).into_bytes()
        });
        let mut out = Vec::new();
        let code = follow(&mut ga, 1, "b", &mut out);
        (code, String::from_utf8(out).unwrap())
    }

    #[test]
    fn follow_copies_every_segment_then_returns_the_exit_code() {
        let (code, out) = follow_with(&[("b.0.seg", "a"), ("b.1.seg", "b"), ("b.exit", "3 2")], "");
        assert_eq!((code.unwrap(), out.as_str()), (3, "ab"));
    }

    #[test]
    fn follow_fails_on_a_segment_it_could_not_read() {
        let (code, _) = follow_with(&[("b.0.seg", "a"), ("b.exit", "0 2")], "");
        assert!(
            code.unwrap_err()
                .to_string()
                .contains("read 1 of the command's 2")
        );
    }

    #[test]
    fn a_failed_wrapper_reports_its_errors() {
        let (code, _) = follow_with(&[], "boom\r\n");
        assert!(code.unwrap_err().to_string().ends_with(": boom"));
    }

    /// A fake agent behind a socket in `dir`, whose wrapper prints "hello world" five bytes
    /// per read into `b.0.seg` and exits 7, running `hang_up` on each request first: a true
    /// closes the connection instead of answering. [`follow`]'s result against it with what
    /// it wrote, and the handles closed.
    fn follow_dropped(
        dir: &std::path::Path,
        hang_up: impl Fn(&serde_json::Value) -> bool + Send + Sync + 'static,
        out: &mut impl Write,
    ) -> (Result<i32>, Vec<i64>) {
        use crate::qga::tests::{HANG_UP, agent_socket, synced};
        use std::collections::HashMap;
        use std::sync::{Arc, Mutex};
        #[derive(Default)]
        struct Guest {
            statuses: u32,
            // handle -> (body, position)
            open: HashMap<i64, (&'static str, usize)>,
            next: i64,
            closed: Vec<i64>,
        }
        let guest = Arc::new(Mutex::new(Guest::default()));
        let state = guest.clone();
        let sock = dir.join("qga.sock");
        agent_socket(&sock, move |request| {
            let args = &request["arguments"];
            if request["execute"] == "guest-sync-delimited" {
                return synced(request);
            }
            if hang_up(request) {
                return HANG_UP.to_vec();
            }
            let mut guest = state.lock().unwrap();
            let reply = match request["execute"].as_str().unwrap() {
                "guest-exec-status" => {
                    guest.statuses += 1;
                    serde_json::json!({ "exited": guest.statuses > 1, "exitcode": 0 })
                }
                "guest-file-open" => {
                    let body = match args["path"].as_str().unwrap() {
                        "b.0.seg" => "hello world",
                        "b.exit" => "7 1",
                        _ => {
                            return b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"no\"}}\n"
                                .to_vec();
                        }
                    };
                    guest.next += 1;
                    let handle = guest.next;
                    guest.open.insert(handle, (body, 0));
                    serde_json::json!(handle)
                }
                "guest-file-seek" => {
                    let file = guest
                        .open
                        .get_mut(&args["handle"].as_i64().unwrap())
                        .unwrap();
                    file.1 = args["offset"].as_u64().unwrap() as usize;
                    serde_json::json!({ "position": file.1, "eof": false })
                }
                "guest-file-read" => {
                    let (body, at) = guest
                        .open
                        .get_mut(&args["handle"].as_i64().unwrap())
                        .unwrap();
                    let bytes = &body.as_bytes()[*at..body.len().min(*at + 5)];
                    *at += bytes.len();
                    let b64 = crate::sshagent::b64_encode(bytes);
                    serde_json::json!({ "count": bytes.len(), "buf-b64": b64, "eof": *at == body.len() })
                }
                "guest-file-close" => {
                    let handle = args["handle"].as_i64().unwrap();
                    guest.closed.push(handle);
                    serde_json::json!({})
                }
                other => panic!("unexpected {other}"),
            };
            format!("{}\n", serde_json::json!({ "return": reply })).into_bytes()
        });
        let mut ga = Client::connect(&sock, Duration::from_secs(5)).unwrap();
        let code = follow(&mut ga, 1, "b", out);
        let closed = guest.lock().unwrap().closed.clone();
        (code, closed)
    }

    #[test]
    fn follow_resumes_a_dropped_segment_where_it_was() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let dir = crate::qga::tests::TempDir::new("winexec-resume");
        // The second read, of " worl", is lost with the connection.
        let reads = AtomicU32::new(0);
        let mut out = Vec::new();
        let (code, closed) = follow_dropped(
            &dir.0,
            move |request| {
                request["execute"] == "guest-file-read" && reads.fetch_add(1, Ordering::SeqCst) == 1
            },
            &mut out,
        );
        assert_eq!((code.unwrap(), out.as_slice()), (7, &b"hello world"[..]));
        // The stale handle too.
        assert_eq!(closed, [1, 2, 3]);
    }

    #[test]
    fn follow_gives_up_after_its_reconnects() {
        let dir = crate::qga::tests::TempDir::new("winexec-give-up");
        let (code, _) = follow_dropped(&dir.0, |_| true, &mut Vec::new());
        let e = code.unwrap_err();
        assert!(e.downcast_ref::<crate::qga::Lost>().is_some(), "{e:#}");
    }

    #[test]
    fn follow_does_not_retry_a_failed_write_to_its_output() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let dir = crate::qga::tests::TempDir::new("winexec-epipe");
        let requests = Arc::new(AtomicU32::new(0));
        let counted = requests.clone();
        let (code, closed) = follow_dropped(
            &dir.0,
            move |_| {
                counted.fetch_add(1, Ordering::SeqCst);
                false
            },
            &mut Closed,
        );
        assert!(code.is_err());
        // Status, open, read, then the close of the segment: no second status.
        assert_eq!(requests.load(Ordering::SeqCst), 4);
        assert_eq!(closed, [1]);
    }

    #[test]
    fn a_restart_waits_for_the_agent_to_stop_answering() {
        use crate::qga::tests::{client, synced};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        // Answer pings according to `answers`; refuse `guest-exec` unless `exec`.
        let agent = |answers: fn(usize) -> bool, exec: bool| {
            let pings = Arc::new(AtomicUsize::new(0));
            let seen = pings.clone();
            let refused = b"{\"error\": {\"class\": \"GenericError\", \"desc\": \"gone\"}}\n";
            let ga = client(move |request| match request["execute"].as_str() {
                Some("guest-sync-delimited") => synced(request),
                Some("guest-exec") if exec => b"{\"return\": {\"pid\": 1}}\n".to_vec(),
                Some("guest-ping") if answers(seen.fetch_add(1, Ordering::SeqCst)) => {
                    b"{\"return\": {}}\n".to_vec()
                }
                _ => refused.to_vec(),
            });
            (ga, pings)
        };
        // The old agent answers twice more, then is gone: two missed pings tell.
        let (mut ga, pings) = agent(|n| n < 2, true);
        restart(&mut ga, 3010, &mut || true).unwrap();
        assert_eq!(pings.load(Ordering::SeqCst), 4);
        // One missed ping between answers is not the agent gone.
        let (mut ga, pings) = agent(|n| n != 1 && n < 3, true);
        restart(&mut ga, 3010, &mut || true).unwrap();
        assert_eq!(pings.load(Ordering::SeqCst), 5);
        // A refused restart fails, unless Windows is restarting already.
        let (mut ga, _) = agent(|_| false, false);
        assert!(restart(&mut ga, 3010, &mut || true).is_err());
        let (mut ga, _) = agent(|_| false, false);
        restart(&mut ga, RESTART_INITIATED, &mut || true).unwrap();
        // A guest that powers off instead is no restart.
        let (mut ga, _) = agent(|_| true, true);
        let err = restart(&mut ga, 3010, &mut || false).unwrap_err();
        assert!(err.to_string().contains("powered off"), "{err}");
    }

    #[test]
    fn a_ps1_runs_from_a_fixed_size_encoded_stub() {
        let line = run_ps1_command_line(r"C:\t\a'b.ps1");
        let (head, b64) = line.rsplit_once(' ').unwrap();
        assert_eq!(
            head,
            "powershell.exe -NoProfile -NonInteractive -EncodedCommand"
        );
        let utf16: Vec<u16> = crate::sshagent::b64_decode(b64)
            .unwrap()
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(
            String::from_utf16(&utf16).unwrap(),
            r"& ([scriptblock]::Create([IO.File]::ReadAllText('C:\t\a''b.ps1')))"
        );
    }

    #[test]
    fn an_encoded_command_is_base64_of_utf16le() {
        // "a" is 61 00 in UTF-16LE.
        assert_eq!(encoded_command("a"), "YQA=");
    }

    #[test]
    fn env_entries_need_a_key_and_no_quotes() {
        assert_eq!(
            parse_env(&["K=v=w".into()]).unwrap(),
            vec![("K".to_string(), "v=w".to_string())]
        );
        assert!(parse_env(&["novalue".into()]).is_err());
        assert!(parse_env(&["K=\"x\"".into()]).is_err());
    }
}
