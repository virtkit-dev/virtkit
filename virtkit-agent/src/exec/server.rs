use crate::addr::SocketAddr;
use crate::framing::{DeSink, SerStream};
use crate::messages::{self, CmdExec, CmdResult, Message, RunMode, Status};
use crate::net::listen;
use crate::pty;
use crate::status::get_status;
use anyhow::anyhow;
use futures::{Sink, SinkExt, Stream, StreamExt};
use log::{debug, error, info};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process;
use std::process::Stdio;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::select;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio::{task, time};

#[derive(Clone)]
pub struct TaskState {
    running_tasks: i32,
    last_activity: Option<Instant>,
}

impl TaskState {
    fn new() -> TaskState {
        TaskState {
            running_tasks: 0,
            last_activity: Some(Instant::now()),
        }
    }
    fn inc(&mut self) {
        // last_activity is left as-is: inactive() already returns false while
        // running_tasks != 0, and a task that ends WITHOUT counting as activity
        // (dec(false), the status-request path) must restore the previous idle
        // timestamp — clearing it here would disable the inactivity timeout for
        // good after the first status request.
        self.running_tasks += 1;
    }

    fn dec(&mut self, update_last: bool) {
        self.running_tasks -= 1;
        if self.running_tasks == 0 && update_last {
            self.last_activity = Some(Instant::now());
        }
    }

    fn inactive(&self, duration: Duration) -> bool {
        if self.running_tasks != 0 {
            return false;
        }
        match self.last_activity {
            Some(t) => t.elapsed() > duration,
            None => false,
        }
    }
}

pub async fn run_server(
    socket: &SocketAddr,
    inactivity_timeout: Option<Duration>,
    exec_wrapper: Option<PathBuf>,
    exec_wrapper_env: Vec<String>,
) -> Result<(), anyhow::Error> {
    let status = Status::default();
    // Force every exec through this program (like SSH's ForceCommand): it receives
    // the requested command line as its arguments and decides what to run.
    // None = run requested commands directly (the default, unrestricted).
    let exec_wrapper = Arc::new(exec_wrapper.map(|path| ExecWrapper::new(path, exec_wrapper_env)));

    let listener = listen(socket)?;

    let state: Arc<Mutex<TaskState>> = Arc::new(Mutex::new(TaskState::new()));

    // The watchdog connects back to its own socket: only doable when serving a plain
    // unix socket path (under systemd the socket belongs to systemd, and a vsock
    // listener cannot connect to itself).
    if matches!(socket, SocketAddr::Unix(_)) && inactivity_timeout.is_none() {
        start_watchdog(status.clone(), socket.clone());
    }

    let inactivity_delay_check = if inactivity_timeout.is_some() {
        10
    } else {
        3600
    };

    loop {
        select! {
                () = sleep(Duration::from_secs(inactivity_delay_check)) => {
                    if let Some(inactivity_timeout) = inactivity_timeout {
                        let lock = state.lock().unwrap();
                        if lock.inactive(inactivity_timeout) {
                            info!(
                                "inactivity timeout: (pid={}, last activity={}s) exiting...",
                                std::process::id(),
                                lock.last_activity.unwrap().elapsed().as_secs()
                            );
                            process::exit(0);
                        }
                    }
                },
                result = listener.accept() => {
                    match result {
                Ok((stream, sink)) => {
                    let c_state = Arc::clone(&state);
                    let status = status.clone();
                    let exec_wrapper = Arc::clone(&exec_wrapper);
                    {
                        let mut lock = c_state.lock().unwrap();
                        lock.inc();
                    }
                    // A new task is spawned for each socket. The socket is moved to the new task and processed there.
                    tokio::spawn(async move {
                        let mut update_last = true;
                        match do_handle_conn(&status, stream, sink, (*exec_wrapper).as_ref()).await {
                            Err(e) => info!("{e}"),
                            Ok(skip_update) => {
                                if skip_update {
                                    update_last = false;
                                }
                            }
                        }
                        let mut lock = c_state.lock().unwrap();
                        lock.dec(update_last);
                        if update_last {
                            info!("task finished, current count: {}", lock.running_tasks);
                        }
                    });
                }
                Err(e) => error!("accept: {e}"),
                    }
            }
        }
    }
}

fn start_watchdog(status: Status, socket: SocketAddr) {
    let _forever = task::spawn(async move {
        info!(
            "watchdog: (pid={}) monitoring socket {}",
            std::process::id(),
            socket,
        );

        // check every 5s that we are still ok
        let mut interval = time::interval(Duration::from_millis(5000));
        loop {
            interval.tick().await;
            let current_status = get_status(&socket).await;
            match current_status {
                Ok(s) => {
                    if s == status {
                        continue;
                    }
                    info!(
                        "watchdog: (pid={}) invalid status, process has probably been replaced",
                        std::process::id()
                    );
                }
                Err(ref e) => {
                    info!(
                        "watchdog: (pid={}) error getting status: {}",
                        std::process::id(),
                        e
                    );
                }
            }
            info!("watchdog: (pid={}) exiting...", std::process::id());
            process::exit(1);
        }
    });
}

static REQUEST_ID: AtomicUsize = AtomicUsize::new(1);

/// Client-supplied env var names always allowed through to the wrapper. These are
/// locale/timezone hints with no influence on how the wrapper resolves or loads
/// code, so they are safe to honour by default. Supports shell-style globs.
const WRAPPER_ENV_ALLOW_DEFAULTS: &[&str] = &["LANG", "LANGUAGE", "LC_*", "TZ"];

/// A configured exec wrapper: the program every exec is forced through, plus the
/// allowlist of client-supplied env var names permitted to reach it.
pub(crate) struct ExecWrapper {
    path: PathBuf,
    /// Glob patterns (defaults + admin `--exec-wrapper-env`) matched against env
    /// var names; client env not matching any pattern is dropped before the
    /// wrapper runs, so it cannot be subverted (LD_PRELOAD, BASH_ENV, ...).
    env_allow: Vec<String>,
}

impl ExecWrapper {
    pub(crate) fn new(path: PathBuf, extra_env_allow: Vec<String>) -> Self {
        let mut env_allow: Vec<String> = WRAPPER_ENV_ALLOW_DEFAULTS
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        env_allow.extend(extra_env_allow);
        Self { path, env_allow }
    }

    fn env_allowed(&self, name: &str) -> bool {
        self.env_allow.iter().any(|pat| glob_match(pat, name))
    }
}

/// Minimal shell-style glob match supporting `*` (any run, incl. empty) and `?`
/// (one char), used to match env var names against the wrapper allowlist (like
/// SSH's `AcceptEnv`). No character classes — env var names don't need them.
fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let s: Vec<char> = name.chars().collect();
    let (mut pi, mut si) = (0, 0);
    // Position to backtrack to when a `*` needs to consume one more char.
    let (mut star, mut star_si) = (None, 0);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_si = si;
            pi += 1;
        } else if let Some(sp) = star {
            pi = sp + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Rewrite a request to run through the exec wrapper: the wrapper becomes the
/// command, and the originally-requested name + args become its arguments. dir,
/// user and tty are untouched, so the real command the wrapper execs runs as the
/// client asked. Client-supplied env is filtered to the wrapper's allowlist, and
/// the client cannot clear the (trusted) server env the wrapper inherits — so
/// neither path lets it tamper with how the wrapper itself runs.
fn wrap_cmd(mut cmd: CmdExec, wrapper: &ExecWrapper) -> CmdExec {
    let mut args = Vec::with_capacity(cmd.args.len() + 1);
    args.push(std::mem::take(&mut cmd.name));
    args.append(&mut cmd.args);
    cmd.name = wrapper.path.to_string_lossy().into_owned();
    cmd.args = args;
    cmd.env.retain(|e| {
        let key = e.split_once('=').map_or(e.as_str(), |(k, _)| k);
        wrapper.env_allowed(key)
    });
    cmd.clear_env = false;
    cmd
}

async fn do_handle_conn(
    status: &Status,
    mut stream: SerStream,
    mut sink: DeSink,
    exec_wrapper: Option<&ExecWrapper>,
) -> Result<bool, anyhow::Error> {
    let client_request = stream.next().await.ok_or(anyhow!("no data"))??;

    match client_request {
        Message::CmdExec(cmd) => {
            let cmd = match exec_wrapper {
                Some(w) => wrap_cmd(cmd, w),
                None => cmd,
            };
            let req_id = REQUEST_ID.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if cmd.tty.is_some() {
                srv_run_cmd_tty(req_id, stream, sink, cmd)
                    .await
                    .and(Ok(false))
            } else {
                srv_run_cmd(req_id, stream, sink, cmd).await.and(Ok(false))
            }
        }
        Message::CmdStatus => {
            let resp = sink
                .send(Message::RespStatus {
                    status: status.clone(),
                })
                .await;
            resp.map_err(std::convert::Into::into).and(Ok(true))
        }
        _ => Err(anyhow!("invalid message")),
    }
}

fn build_command(cmd: &CmdExec) -> Command {
    let mut command = Command::new(&cmd.name);
    command.args(&cmd.args);
    if cmd.clear_env {
        command.env_clear();
    }
    for e in &cmd.env {
        if let Some((k, v)) = e.split_once('=') {
            command.env(k, v);
        }
    }
    if let Some(dir) = &cmd.dir {
        command.current_dir(dir);
    }
    // Drop to the requested user (per-command override) or the guest's default
    // (the image's USER, exported as CMDRUNNER_DEFAULT_RUN_USER by the microVM
    // init). Unset/empty => keep running as the virtkit-agent user (root).
    let run_as = cmd
        .user
        .clone()
        .or_else(|| std::env::var("CMDRUNNER_DEFAULT_RUN_USER").ok())
        .filter(|u| !u.is_empty());
    if let Some(user) = run_as {
        apply_user(&mut command, cmd, &user);
    }
    command
}

pub(crate) struct ResolvedUser {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub home: Option<std::ffi::OsString>,
    // only the ssh server (feature `ssh`) needs the login shell
    #[cfg_attr(not(feature = "ssh"), allow(dead_code))]
    pub shell: Option<std::ffi::OsString>,
    pub groups: Vec<libc::gid_t>,
}

/// Look up a user in the passwd/group databases. Done in the parent — getpwnam_r
/// and getgrouplist are not async-signal-safe, so they must not run in pre_exec.
pub(crate) fn resolve_user(name: &str) -> std::io::Result<ResolvedUser> {
    use std::io::{Error, ErrorKind};
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "user name contains NUL"))?;

    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0_i8; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            c_name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 {
        return Err(Error::from_raw_os_error(rc));
    }
    if result.is_null() {
        return Err(Error::new(
            ErrorKind::NotFound,
            format!("unknown user {name:?}"),
        ));
    }
    use std::os::unix::ffi::OsStrExt;
    let home = if pwd.pw_dir.is_null() {
        None
    } else {
        Some(
            std::ffi::OsStr::from_bytes(unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }.to_bytes())
                .to_os_string(),
        )
    };
    let shell = if pwd.pw_shell.is_null() {
        None
    } else {
        let b = unsafe { std::ffi::CStr::from_ptr(pwd.pw_shell) }.to_bytes();
        if b.is_empty() {
            None
        } else {
            Some(std::ffi::OsStr::from_bytes(b).to_os_string())
        }
    };

    // Supplementary groups: size the buffer up if the first call reports more.
    let mut ngroups: libc::c_int = 32;
    let mut groups: Vec<libc::gid_t> = vec![0; ngroups as usize];
    loop {
        let rc = unsafe {
            libc::getgrouplist(
                c_name.as_ptr(),
                pwd.pw_gid,
                groups.as_mut_ptr(),
                &mut ngroups,
            )
        };
        if rc >= 0 {
            groups.truncate(ngroups as usize);
            break;
        }
        groups.resize(ngroups as usize, 0);
    }

    Ok(ResolvedUser {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home,
        shell,
        groups,
    })
}

/// Configure `command` to exec as `user`: set HOME/USER/LOGNAME (unless the
/// caller already provided them) and register a pre_exec that drops privileges.
fn apply_user(command: &mut Command, cmd: &CmdExec, user: &str) {
    let has_env = |key: &str| {
        cmd.env
            .iter()
            .any(|e| e.split_once('=').map(|(k, _)| k == key).unwrap_or(false))
    };

    match resolve_user(user) {
        Ok(ru) => {
            if !cmd.clear_env && !has_env("USER") {
                command.env("USER", user);
            }
            if !cmd.clear_env && !has_env("LOGNAME") {
                command.env("LOGNAME", user);
            }
            if let Some(home) = ru.home.as_ref().filter(|_| !has_env("HOME")) {
                command.env("HOME", home);
            }
            let (uid, gid, groups) = (ru.uid, ru.gid, ru.groups);
            // pre_exec runs after fork, before exec: only async-signal-safe
            // syscalls. setgroups before setgid before setuid, so the group
            // changes still have the privilege they require.
            unsafe {
                command.pre_exec(move || {
                    if libc::setgroups(groups.len() as libc::size_t, groups.as_ptr()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setgid(gid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::setuid(uid) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        Err(e) => {
            // Can't fail build_command's signature; surface it as a spawn error.
            let msg = format!("virtkit-agent: cannot run as user {user:?}: {e}");
            unsafe {
                command.pre_exec(move || Err(std::io::Error::other(msg.clone())));
            }
        }
    }
}

/// `exec --tty`: run the command on a pty. One output stream (the terminal, sent as
/// Fd::Stdout), stdin bytes go to the master, Resize messages drive TIOCSWINSZ.
async fn srv_run_cmd_tty(
    req_id: usize,
    mut stream: impl Stream<Item = Result<Message, std::io::Error>>
    + std::marker::Unpin
    + Send
    + 'static,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin + Send + 'static,
    cmd: CmdExec,
) -> Result<(), anyhow::Error> {
    info!("command [{}] {} (tty)", req_id, &cmd);
    let Some(tty) = &cmd.tty else { unreachable!() };
    if cmd.mode == RunMode::Background {
        let msg = "--tty is incompatible with --background".to_string();
        sink.send(Message::StartErr { msg: msg.clone() }).await?;
        return Err(anyhow!("command [{req_id}] {msg}"));
    }

    let (master, slave) = match pty::openpty(tty.rows, tty.cols) {
        Ok(pair) => pair,
        Err(e) => {
            sink.send(Message::StartErr {
                msg: format!("openpty: {e}"),
            })
            .await?;
            return Err(anyhow!("command [{req_id}] openpty: {e}"));
        }
    };

    let mut command = build_command(&cmd);
    if let Some(term) = &tty.term {
        command.env("TERM", term);
    }
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave))
        .kill_on_drop(true);
    // New session with the pty as controlling terminal: job control, SIGWINCH and
    // ^C/^Z dispatch work like on a real terminal. setsid() also makes the child a
    // process group leader, so the disconnect path can kill the whole group.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            sink.send(Message::StartErr { msg: e.to_string() }).await?;
            return Err(anyhow!("command [{req_id}] error starting process: {e}"));
        }
    };
    // the Command holds the slave Stdio fds: drop it so the master reads EIO (eof)
    // once the command and its children are gone
    drop(command);

    sink.send(Message::StartOK).await?;

    let master_fd = master.as_raw_fd();
    let (master_read, mut master_write) = tokio::io::split(master);

    let (tx, rx) = mpsc::channel(super::DATA_CHANNEL_CAPACITY);

    let writer = tokio::spawn(async move {
        writer_task(rx, sink, req_id).await;
    });

    let tx_out = tx.clone();
    let copy_out = tokio::spawn(async move {
        reader_task(req_id, crate::messages::Fd::Stdout, master_read, tx_out).await;
    });

    let child_pid = child.id();
    let client_stream_reader = tokio::spawn(async move {
        let disconnected = loop {
            match stream.next().await {
                Some(Ok(Message::Data {
                    fd: messages::Fd::Stdin,
                    msg,
                })) => {
                    if master_write.write_all(&msg).await.is_err() {
                        break false;
                    }
                }
                Some(Ok(Message::Resize { rows, cols })) => {
                    // master_write (same underlying fd) outlives this task: the fd
                    // stays valid for the ioctl
                    let _ = pty::set_winsize(master_fd, rows, cols);
                }
                // no tty equivalent of half-closing stdin: ignore Close
                Some(Ok(_)) => {}
                None | Some(Err(_)) => break true,
            }
        };
        if disconnected && let Some(pid) = child_pid {
            info!("command [{req_id}] client disconnected, killing process group (pgid={pid})");
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    });

    let status = match child.wait().await {
        Ok(it) => it,
        Err(err) => return Err(err.into()),
    };

    debug!("command [{req_id}] exit status: {status}");
    if status.signal().is_some() {
        copy_out.abort();
    } else {
        // drain the pty until EIO (all slave handles closed) so trailing output
        // is delivered before ExecDone
        copy_out.await?;
    }
    client_stream_reader.abort();
    drop(client_stream_reader);
    let _ = tx
        .send(Message::ExecDone(CmdResult {
            code: status.code(),
            signal: status.signal(),
        }))
        .await;
    drop(tx);
    writer.await?;
    info!("command [{req_id}] done ({status})");

    Ok(())
}

async fn srv_run_cmd(
    req_id: usize,
    mut stream: impl Stream<Item = Result<Message, std::io::Error>>
    + std::marker::Unpin
    + Send
    + 'static,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin + Send + 'static,
    cmd: CmdExec,
) -> Result<(), anyhow::Error> {
    info!("command [{}] {}", req_id, &cmd);
    let mut command = build_command(&cmd);

    match cmd.mode {
        RunMode::Background => {
            command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
        }
        RunMode::Interactive => {
            // own process group so that a client disconnect can kill the whole
            // process tree, not just the direct child (see client_stream_reader)
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0)
                .kill_on_drop(true);
        }
    }

    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            sink.send(Message::StartErr { msg: e.to_string() }).await?;
            return Err(anyhow!("command [{req_id}] error starting process: {e}",));
        }
    };

    sink.send(Message::StartOK).await?;

    if cmd.mode == RunMode::Background {
        info!("command [{req_id}] background task started");
        return Ok(());
    }

    let (tx, rx) = mpsc::channel(super::DATA_CHANNEL_CAPACITY);

    // async task to send messages using the unix socket
    // other tasks can use tx clones to send messages
    let writer = tokio::spawn(async move {
        writer_task(rx, sink, req_id).await;
    });

    // async task to read from stdout
    let tx_out = tx.clone();
    let stdout = child.stdout.take().unwrap();
    let copy_out = tokio::spawn(async move {
        reader_task(req_id, crate::messages::Fd::Stdout, stdout, tx_out).await;
    });

    // async task to read from stderr
    let tx_err = tx.clone();
    let stderr = child.stderr.take().unwrap();
    let copy_err = tokio::spawn(async move {
        reader_task(req_id, crate::messages::Fd::Stderr, stderr, tx_err).await;
    });

    // stdin writing thread
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(super::DATA_CHANNEL_CAPACITY);

    let mut stdin_tx = Some(stdin_tx);

    let mut stdin = child.stdin.take().unwrap();

    let write_stdin = tokio::spawn(async move {
        while let Some(data) = stdin_rx.recv().await {
            debug!("copy_stdin_task, writing {} bytes", &data.len());
            if stdin.write_all(&data).await.is_ok() {
                debug!("copy_stdin_task, wrote {} bytes", &data.len());
            } else {
                break;
            }
        }
        debug!("copy_stdin_task done");
        let _ = stdin.flush().await;
    });

    let child_pid = child.id();
    let client_stream_reader = tokio::spawn(async move {
        let disconnected = loop {
            let client_msg = match stream.next().await {
                Some(Ok(msg)) => msg,
                // EOF or framing error: the client is gone — it never closes the
                // connection while the command runs (stdin end-of-input is signaled
                // with a Close message, not by closing the socket)
                None | Some(Err(_)) => break true,
            };
            match client_msg {
                Message::Data {
                    fd: messages::Fd::Stdin,
                    msg,
                } => {
                    debug!("writing to stdin {} bytes", &msg.len());
                    if let Some(ref tx) = stdin_tx {
                        let _ = tx.send(msg).await;
                    } else {
                        error!("attempt to write to stdin after it is closed");
                        break false;
                    }
                }
                Message::Close {
                    fd: messages::Fd::Stdin,
                    error,
                } => {
                    if let Some(err) = error {
                        debug!("got close message on stdin with error {err}");
                    }
                    debug!("closing stdin from msg");
                    stdin_tx = None;
                }
                _ => {}
            }
        };
        // Nobody is listening anymore: kill the command instead of letting it run
        // unattended (Ctrl-C on the client side must stop the remote command). The
        // child is its own process group leader, so signal the whole group: a bare
        // kill(pid) would orphan grandchildren (e.g. `sh -c '...; sleep 60'`).
        if disconnected && let Some(pid) = child_pid {
            info!("client disconnected, killing child process group (pgid={pid})");
            unsafe {
                libc::kill(-(pid as i32), libc::SIGKILL);
            }
        }
    });

    let status = match child.wait().await {
        Ok(it) => it,
        Err(err) => return Err(err.into()),
    };

    debug!("command [{req_id}] exit status: {status}");
    let _ = tx
        .send(Message::Close {
            fd: crate::messages::Fd::Stdin,
            error: None,
        })
        .await;
    client_stream_reader.abort();
    drop(client_stream_reader);
    if status.signal().is_some() {
        copy_out.abort();
        copy_err.abort();
        write_stdin.abort();
    } else {
        copy_out.await?;
        copy_err.await?;
        write_stdin.await?;
    }
    let _ = tx
        .send(Message::ExecDone(CmdResult {
            code: status.code(),
            signal: status.signal(),
        }))
        .await;
    debug!("command [{req_id}] execDone sent");
    drop(tx);
    writer.await?;
    info!("command [{req_id}] done ({status})");

    Ok(())
}

async fn reader_task<T: AsyncRead + Unpin>(
    req_id: usize,
    fd_kind: crate::messages::Fd,
    mut src: T,
    tx: mpsc::Sender<Message>,
) {
    let mut read_count = 0;
    let mut buf = [0u8; 4096];
    loop {
        match src.read(&mut buf).await {
            Ok(size) => {
                // info!("stdout read {}", size);
                if size == 0 {
                    let _ = tx
                        .send(Message::Close {
                            fd: fd_kind,
                            error: None,
                        })
                        .await;
                    break;
                }
                let data = &buf[0..size];
                match tx
                    .send(Message::Data {
                        fd: fd_kind,
                        msg: data.into(),
                    })
                    .await
                {
                    Ok(()) => {
                        read_count += size;
                        continue;
                    }
                    Err(e) => {
                        // normal when the client went away (the writer dropped rx)
                        debug!("command [{req_id}] send error {e}");
                        break;
                    }
                };
            }
            Err(e) => {
                error!("command [{req_id}] {fd_kind} read error {e}");
                let _ = tx
                    .send(Message::Close {
                        fd: fd_kind,
                        error: Some(e.to_string()),
                    })
                    .await;
                break;
            }
        }
    }
    drop(tx);
    debug!("command [{req_id}] done reading from {fd_kind} ({read_count} bytes)");
}

async fn writer_task(
    mut rx: mpsc::Receiver<Message>,
    mut sink: impl Sink<Message, Error = std::io::Error> + Unpin + Send + 'static,
    req_id: usize,
) {
    let (mut written_stdout, mut written_stderr) = (0, 0);
    while let Some(msg) = rx.recv().await {
        match &msg {
            Message::Data {
                fd: crate::messages::Fd::Stdout,
                msg,
            } => written_stdout += &msg.len(),
            Message::Data {
                fd: crate::messages::Fd::Stderr,
                msg,
            } => written_stderr += &msg.len(),
            _ => (),
        }

        if let Err(e) = sink.send(msg).await {
            error!("command [{req_id}] error in network writer: {e}");
            break;
        }
    }
    debug!(
        "command [{req_id}] network writer done (stdout:{written_stdout}, stderr:{written_stderr})"
    );
}

#[cfg(test)]
mod tests {
    use super::{ExecWrapper, TaskState, glob_match, wrap_cmd};
    use crate::messages::{CmdExec, RunMode};
    use std::path::PathBuf;
    use std::time::Duration;

    fn sample_cmd() -> CmdExec {
        CmdExec {
            name: "git".into(),
            args: vec!["status".into()],
            env: vec![],
            clear_env: false,
            mode: RunMode::Interactive,
            dir: Some("./sub".into()),
            tty: None,
            user: None,
        }
    }

    fn wrapper(extra_env_allow: Vec<String>) -> ExecWrapper {
        ExecWrapper::new(PathBuf::from("/run/host-dispatch"), extra_env_allow)
    }

    #[test]
    fn wrap_cmd_prepends_original_command_as_args() {
        let wrapped = wrap_cmd(sample_cmd(), &wrapper(vec![]));
        assert_eq!(wrapped.name, "/run/host-dispatch");
        // the requested command line becomes the wrapper's argv
        assert_eq!(wrapped.args, vec!["git", "status"]);
        // dir/user are preserved so the real command runs as the client asked
        assert_eq!(wrapped.dir.as_deref(), Some("./sub"));
    }

    #[test]
    fn wrap_cmd_filters_client_env_to_the_allowlist() {
        let mut cmd = sample_cmd();
        cmd.clear_env = true;
        cmd.env = vec![
            "LD_PRELOAD=/tmp/evil.so".into(), // injection vector: must be dropped
            "BASH_ENV=/tmp/rc".into(),        // ditto
            "LANG=en_US.UTF-8".into(),        // default allowlist
            "LC_ALL=C".into(),                // default allowlist glob LC_*
            "MYAPP_TOKEN=abc".into(),         // admin-allowed below
        ];
        let wrapped = wrap_cmd(cmd, &wrapper(vec!["MYAPP_*".into()]));
        assert_eq!(
            wrapped.env,
            vec!["LANG=en_US.UTF-8", "LC_ALL=C", "MYAPP_TOKEN=abc"],
        );
        // the client cannot clear the trusted server env the wrapper inherits
        assert!(!wrapped.clear_env);
    }

    #[test]
    fn glob_match_handles_wildcards() {
        assert!(glob_match("LC_*", "LC_ALL"));
        assert!(glob_match("LC_*", "LC_")); // `*` matches empty
        assert!(!glob_match("LC_*", "LANG"));
        assert!(glob_match("LANG", "LANG"));
        assert!(!glob_match("LANG", "LANGUAGE"));
        assert!(glob_match("MYAPP_?", "MYAPP_X"));
        assert!(!glob_match("MYAPP_?", "MYAPP_XY"));
    }

    #[test]
    fn busy_then_idle() {
        let mut state = TaskState::new();
        state.inc();
        assert!(!state.inactive(Duration::ZERO));
        state.dec(true);
        std::thread::sleep(Duration::from_millis(5));
        assert!(state.inactive(Duration::from_millis(1)));
    }

    #[test]
    fn status_request_does_not_reset_the_idle_clock() {
        let mut state = TaskState::new();
        std::thread::sleep(Duration::from_millis(5));
        // a status request runs with update_last = false: the idle timestamp must
        // survive it (it used to be cleared for good, disabling the timeout)
        state.inc();
        state.dec(false);
        assert!(state.inactive(Duration::from_millis(1)));
    }
}
