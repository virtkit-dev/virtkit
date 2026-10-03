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

/// The batch-file line that runs `argv`: each argument quoted with [`quote_arg`], then made
/// literal for cmd.exe — `%` doubled (a batch file would expand it) and, wherever cmd sees the
/// text outside quotes, its operators escaped with `^`, which cmd removes before starting the
/// program.
pub fn cmd_line(argv: &[String]) -> String {
    let line = argv
        .iter()
        .map(|a| quote_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
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
    argv: &[String],
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
    s.push_str(&format!("{redirect} {}\r\n", cmd_line(argv)));
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
            if key.is_empty()
                || key.contains(['"', '\r', '\n'])
                || value.contains(['"', '\r', '\n'])
            {
                bail!(
                    "--env {entry:?}: a Windows guest's variables cannot hold quotes or newlines"
                );
            }
            Ok((key.to_string(), value.to_string()))
        })
        .collect()
}

/// Refuse a command or `--dir` a batch file cannot carry: a newline ends its line.
pub fn check_command(argv: &[String], dir: Option<&str>) -> Result<()> {
    if let Some(arg) = argv.iter().find(|a| a.contains(['\r', '\n'])) {
        bail!("{arg:?}: a Windows guest's command line cannot hold newlines");
    }
    if let Some(dir) = dir.filter(|d| d.contains(['"', '\r', '\n'])) {
        bail!("--dir {dir:?}: a Windows guest's directory cannot hold quotes or newlines");
    }
    Ok(())
}

/// Write `bytes` to the guest file `path`, creating or truncating it.
fn put(ga: &mut Client, path: &str, bytes: &[u8]) -> Result<()> {
    write_from(ga, path, bytes).map(drop)
}

/// Write what `src` holds to the guest file `path`, creating or truncating it, one
/// [`CHUNK`] at a time; returns the bytes written.
fn write_from(ga: &mut Client, path: &str, mut src: impl Read) -> Result<u64> {
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
fn cmd(ga: &mut Client, words: &[&str]) -> Result<i32> {
    let mut args = ["/d", "/v:off", "/c"].map(String::from).to_vec();
    args.extend(words.iter().map(|w| w.to_string()));
    let pid = ga.exec("cmd.exe", &args, false)?;
    loop {
        let status = ga.exec_status(pid)?;
        if status.exited {
            return Ok(status.exitcode.unwrap_or(-1));
        }
        std::thread::sleep(POLL);
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
    let mut ga = Client::connect(socket, CONNECT_TIMEOUT)?;
    let base = format!(r"{RUN_DIR}\{}", crate::scratch::random_nonce()?);
    let log = format!("{base}.log");
    let body = script(argv, env, dir, background.then_some(log.as_str()));
    match run(&mut ga, &base, body.as_bytes(), background) {
        Ok(None) => {
            eprintln!("virtkit: started in the background; its output goes to {log} in the guest");
            Ok(0)
        }
        ran => {
            // Its segments, exit file, and the batch file if it never ran. Best effort; a
            // leftover stays where only SYSTEM and administrators can read it.
            let _ = cmd(&mut ga, &["del", "/q", &format!("{base}.*")]);
            ran.map(Option::unwrap_or_default)
        }
    }
}

/// Write `body` as the batch file `<base>.cmd` and run it: `None` once a background command
/// has started, otherwise the command's exit code once it has ended, its output streamed to
/// stdout.
fn run(ga: &mut Client, base: &str, body: &[u8], background: bool) -> Result<Option<i32>> {
    let bat = format!("{base}.cmd");
    if put(ga, &bat, body).is_err() {
        // First command in this guest: make the directory, then try again.
        let code = cmd(ga, &["if", "not", "exist", RUN_DIR, "mkdir", RUN_DIR])?;
        if code != 0 {
            bail!("vk exec assumes Windows in C:\\Windows (mkdir {RUN_DIR} exited {code})");
        }
        put(ga, &bat, body)?;
    }
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
    follow(ga, pid, base, &mut std::io::stdout().lock()).map(Some)
}

/// Copy the output of the wrapper `pid`, published as `<base>.<n>.seg`, to `out` as it
/// appears, until it exits; returns the command's exit code.
fn follow(ga: &mut Client, pid: i64, base: &str, out: &mut impl Write) -> Result<i32> {
    let mut next = 0u64;
    let status = loop {
        // Status first: once it reads exited, every segment is already published.
        let status = ga.exec_status(pid)?;
        while let Some(handle) = open_if_present(ga, &format!("{base}.{next}.seg"))? {
            let read = drain(ga, handle, out);
            ga.file_close(handle)?;
            read?;
            next += 1;
        }
        out.flush()?;
        if status.exited {
            break status;
        }
        std::thread::sleep(POLL);
    };
    let Some(handle) = open_if_present(ga, &format!("{base}.exit"))? else {
        let stderr = status
            .err_data
            .as_deref()
            .and_then(crate::sshagent::b64_decode);
        let stderr = String::from_utf8_lossy(stderr.as_deref().unwrap_or_default());
        let stderr = stderr.trim();
        bail!(
            "vk's output wrapper failed in the guest before the command finished{}{stderr}",
            if stderr.is_empty() { "" } else { ": " }
        );
    };
    let mut exit = Vec::new();
    let read = drain(ga, handle, &mut exit);
    ga.file_close(handle)?;
    read?;
    let exit = String::from_utf8_lossy(&exit);
    let Some((code, published)) = exit
        .trim()
        .split_once(' ')
        .and_then(|(code, n)| Some((code.parse::<i32>().ok()?, n.parse::<u64>().ok()?)))
    else {
        bail!("the guest reported the exit {exit:?} (expected \"<code> <segments>\")");
    };
    if next != published {
        bail!("read {next} of the command's {published} output segments: the rest is lost");
    }
    Ok(code)
}

/// Copy the guest file behind `handle` to `out`, to its end.
fn drain(ga: &mut Client, handle: i64, out: &mut impl Write) -> Result<u64> {
    let mut copied = 0u64;
    loop {
        let (bytes, eof) = ga.file_read(handle, CHUNK)?;
        out.write_all(&bytes)?;
        copied += bytes.len() as u64;
        if eof || bytes.is_empty() {
            return Ok(copied);
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
            drain(&mut ga, handle, &mut file)
                .with_context(|| format!("copying {remote} from the guest"))
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
            &["hostname".to_string()],
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
        let script = script(&["echo".into(), "5\"".into()], &[], None, None);
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
