//! Minimal SSH server embedded in virtkit-agent (russh), so a microVM is reachable
//! by a stock ssh client — and thus VS Code Remote-SSH — with no sshd in the
//! guest image and no guest network: it listens on vsock, and the host dials it
//! through the hybrid vsock-mux with `vk-agent connect` as the ssh ProxyCommand.
//!
//! Scope (POC): pubkey auth against an authorized_keys file, plus the two channel
//! requests an interactive editor needs — `pty`+`shell` (terminals) and `exec`
//! (the VS Code server bootstrap). sftp and port-forwarding (direct-tcpip) are
//! not handled yet. The crypto/transport is russh's; we only wire the channels
//! onto virtkit-agent's existing pty (`pty.rs`) and user-drop (`exec::server`) plumbing.

use std::collections::HashMap;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use log::{debug, info, warn};
use russh::keys::PublicKey;
use russh::server::{Auth, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};

use crate::addr::SocketAddr;
use crate::exec::server::{ResolvedUser, resolve_user};
use crate::net::raw_listen;
use crate::pty::{self, PtyMaster};

/// Accept SSH connections on `socket` (a vsock listener in the VM; tcp/unix work
/// too, for tests). Each connection is authenticated against `authorized_keys`
/// and, on success, runs shells/commands as `force_user` (or the SSH login user
/// when `force_user` is None).
pub async fn run_ssh_server(
    socket: &SocketAddr,
    authorized_keys: &[PublicKey],
    force_user: Option<String>,
) -> Result<()> {
    let keys = Arc::new(authorized_keys.to_vec());
    if keys.is_empty() {
        return Err(anyhow!("no authorized keys provided"));
    }
    // Ephemeral host key: clients reach us over a private vsock channel and pin
    // nothing (StrictHostKeyChecking=no in ssh-vsock.sh), so a fresh key per boot
    // is fine and avoids persisting secrets in the rootfs.
    let host_key =
        russh::keys::PrivateKey::random(&mut rand::rng(), russh::keys::Algorithm::Ed25519)
            .map_err(|e| anyhow!("generating host key: {e}"))?;
    let config = Arc::new(Config {
        inactivity_timeout: None, // a dev editor session may idle for hours
        auth_rejection_time: Duration::from_secs(1),
        keys: vec![host_key],
        ..Default::default()
    });

    let listener = raw_listen(socket)
        .await
        .with_context(|| format!("ssh: binding {socket}"))?;
    info!(
        "vk-agent ssh: listening on {socket} ({} authorized key(s))",
        keys.len()
    );

    loop {
        let conn = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!("ssh: accept on {socket}: {e}");
                continue;
            }
        };
        let handler = ServerHandler::new(Arc::clone(&keys), force_user.clone());
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            match russh::server::run_stream(config, conn, handler).await {
                Ok(session) => {
                    if let Err(e) = session.await {
                        debug!("ssh: session ended: {e}");
                    }
                }
                Err(e) => debug!("ssh: handshake failed: {e}"),
            }
        });
    }
}

/// Parse public key strings (OpenSSH format: `type base64 [comment]`).
pub fn parse_authorized_keys(lines: &[String]) -> Vec<PublicKey> {
    let mut keys = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match PublicKey::from_openssh(line) {
            Ok(k) => keys.push(k),
            Err(e) => warn!("ssh: skipping unparseable key: {e}"),
        }
    }
    keys
}

#[derive(Clone)]
struct PtyReq {
    term: Option<String>,
    rows: u16,
    cols: u16,
}

/// One per client connection. russh delivers channel requests on it in order;
/// session channels are stashed at open time and consumed by shell/exec.
struct ServerHandler {
    authorized: Arc<Vec<PublicKey>>,
    force_user: Option<String>,
    authed_user: Option<String>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    ptys: HashMap<ChannelId, PtyReq>,
    pty_fds: HashMap<ChannelId, std::os::fd::RawFd>,
}

impl ServerHandler {
    fn new(authorized: Arc<Vec<PublicKey>>, force_user: Option<String>) -> Self {
        ServerHandler {
            authorized,
            force_user,
            authed_user: None,
            channels: HashMap::new(),
            ptys: HashMap::new(),
            pty_fds: HashMap::new(),
        }
    }

    fn run_as(&self) -> String {
        self.authed_user
            .clone()
            .unwrap_or_else(|| "root".to_string())
    }
}

impl Handler for ServerHandler {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        // Compare the key material only: PublicKey's PartialEq also covers the
        // comment, which the authorized_keys file carries but the wire key omits.
        if self
            .authorized
            .iter()
            .any(|k| k.key_data() == key.key_data())
        {
            // Honor a forced run-as user (the VM logs VS Code in as `dev`);
            // otherwise run as whoever the client asked to be.
            self.authed_user = Some(self.force_user.clone().unwrap_or_else(|| user.to_string()));
            Ok(Auth::Accept)
        } else {
            Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            })
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        self.channels.insert(channel.id(), channel);
        Ok(true)
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.ptys.insert(
            channel,
            PtyReq {
                term: (!term.is_empty()).then(|| term.to_string()),
                rows: row_height.min(u32::from(u16::MAX)) as u16,
                cols: col_width.min(u32::from(u16::MAX)) as u16,
            },
        );
        session.channel_success(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(&fd) = self.pty_fds.get(&channel) {
            let _ = pty::set_winsize(
                fd,
                row_height.min(u32::from(u16::MAX)) as u16,
                col_width.min(u32::from(u16::MAX)) as u16,
            );
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(chan) = self.channels.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let user = self.run_as();
        // With a pty (real terminal): an interactive login shell on the pty.
        // Without one (`ssh -T`, as VS Code's server bootstrap does — it pipes a
        // script to stdin): a NON-interactive login shell with piped stdio, so no
        // prompt/PS1 noise contaminates the stdout VS Code parses.
        match self.ptys.remove(&channel) {
            Some(pty) => match spawn_shell(&user, &pty) {
                Ok((child, master)) => {
                    self.pty_fds.insert(channel, master.as_raw_fd());
                    session.channel_success(channel)?;
                    let handle = session.handle();
                    tokio::spawn(shell_bridge(chan, child, master, handle, channel));
                }
                Err(e) => {
                    warn!("ssh: shell for {user:?}: {e}");
                    session.channel_failure(channel)?;
                }
            },
            None => match spawn_shell_nopty(&user) {
                Ok(child) => {
                    session.channel_success(channel)?;
                    let handle = session.handle();
                    tokio::spawn(exec_bridge(chan, child, handle, channel));
                }
                Err(e) => {
                    warn!("ssh: shell (no pty) for {user:?}: {e}");
                    session.channel_failure(channel)?;
                }
            },
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(chan) = self.channels.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        let user = self.run_as();
        let cmdline = String::from_utf8_lossy(data).into_owned();
        match spawn_exec(&user, &cmdline) {
            Ok(child) => {
                session.channel_success(channel)?;
                let handle = session.handle();
                tokio::spawn(exec_bridge(chan, child, handle, channel));
            }
            Err(e) => {
                warn!("ssh: exec for {user:?}: {e}");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }

    /// Subsystem request — we serve `sftp` by spawning `vk-agent sftp-server` as
    /// the logged-in user (so transferred files are theirs) and splicing it to the
    /// channel. This is how scp/sftp — and VS Code's server copy — land files.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(chan) = self.channels.remove(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        if name != "sftp" {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let user = self.run_as();
        match resolve_user(&user) {
            Ok(ru) => {
                session.channel_success(channel)?;
                // russh-sftp serves the channel on its own task; when it ends,
                // send the channel's exit-status (scp/VS Code need it) and close.
                let done = crate::sftp::serve(chan.into_stream(), ru.uid, ru.gid).await;
                let handle = session.handle();
                tokio::spawn(async move {
                    let _ = done.await;
                    let _ = handle.exit_status_request(channel, 0).await;
                    let _ = handle.eof(channel).await;
                    let _ = handle.close(channel).await;
                });
            }
            Err(e) => {
                warn!("ssh: sftp for {user:?}: {e}");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }

    /// Local port forward (ssh -L / VS Code Remote-SSH reaching its server): the
    /// client asks us to open a TCP connection inside the guest and tunnel it over
    /// this channel. Connect first so the open succeeds/fails truthfully, then
    /// splice. Required for VS Code to talk to the server it bootstraps.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let port = port_to_connect.min(u32::from(u16::MAX)) as u16;
        match TcpStream::connect((host_to_connect, port)).await {
            Ok(tcp) => {
                tokio::spawn(tcpip_bridge(channel, tcp));
                Ok(true)
            }
            Err(e) => {
                warn!("ssh: direct-tcpip {host_to_connect}:{port}: {e}");
                Ok(false)
            }
        }
    }
}

/// Splice a forwarded-channel stream to an in-guest TCP connection until either
/// side closes.
async fn tcpip_bridge(channel: Channel<Msg>, mut tcp: TcpStream) {
    let mut stream = channel.into_stream();
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut tcp).await;
}

/// Register a pre_exec that drops privileges to `ru` (groups, gid, uid in that
/// order) — unless we are already that uid (setgroups needs root, and there is
/// nothing to drop to when serving as the target user, e.g. in tests).
/// Async-signal-safe only — the lookup already happened in the parent.
fn with_user_drop(command: &mut Command, ru: &ResolvedUser) {
    if ru.uid == unsafe { libc::geteuid() } {
        return;
    }
    let (uid, gid, groups) = (ru.uid, ru.gid, ru.groups.clone());
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

fn login_env(command: &mut Command, user: &str, ru: &ResolvedUser) {
    command.env("USER", user).env("LOGNAME", user);
    if let Some(home) = &ru.home {
        command.env("HOME", home).current_dir(home);
    }
}

/// Spawn the user's login shell on a fresh pty as `user`.
fn spawn_shell(user: &str, pty: &PtyReq) -> Result<(Child, PtyMaster)> {
    let ru = resolve_user(user)?;
    let (master, slave) = pty::openpty(pty.rows, pty.cols)?;
    let shell = ru
        .shell
        .clone()
        .unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"));
    let mut command = Command::new(&shell);
    command.arg("-l");
    login_env(&mut command, user, &ru);
    if let Some(term) = &pty.term {
        command.env("TERM", term);
    }
    command
        .stdin(Stdio::from(slave.try_clone()?))
        .stdout(Stdio::from(slave.try_clone()?))
        .stderr(Stdio::from(slave))
        .kill_on_drop(true);
    // Drop privileges, then new session + controlling tty (job control, SIGWINCH,
    // ^C). pre_exec closures run in registration order.
    with_user_drop(&mut command, &ru);
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
    let child = command.spawn()?;
    drop(command); // release the slave fds so the master sees EOF on shell exit
    Ok((child, master))
}

/// Spawn the user's login shell with piped stdio and no tty — for a `shell`
/// request that arrived without a pty (e.g. `ssh -T host` piping a script to
/// stdin, as VS Code's server bootstrap does). Non-interactive (stdin is a pipe,
/// not a terminal), so bash runs the piped commands without ever printing a
/// prompt — stdout stays clean for the marker parsing VS Code relies on.
fn spawn_shell_nopty(user: &str) -> Result<Child> {
    let ru = resolve_user(user)?;
    let shell = ru
        .shell
        .clone()
        .unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"));
    let mut command = Command::new(&shell);
    command.arg("-l");
    login_env(&mut command, user, &ru);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    with_user_drop(&mut command, &ru);
    Ok(command.spawn()?)
}

/// Spawn `cmdline` via the user's shell with piped stdio (no tty), own pgroup.
fn spawn_exec(user: &str, cmdline: &str) -> Result<Child> {
    let ru = resolve_user(user)?;
    let shell = ru
        .shell
        .clone()
        .unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"));
    let mut command = Command::new(&shell);
    command.arg("-c").arg(cmdline);
    login_env(&mut command, user, &ru);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    with_user_drop(&mut command, &ru);
    Ok(command.spawn()?)
}

/// Bridge a session channel to a pty shell until either side closes; report the
/// exit status and close the channel.
async fn shell_bridge(
    chan: Channel<Msg>,
    mut child: Child,
    mut master: PtyMaster,
    handle: Handle,
    id: ChannelId,
) {
    let mut stream = chan.into_stream();
    let pid = child.id();
    let mut copy = std::pin::pin!(tokio::io::copy_bidirectional(&mut stream, &mut master));
    let code: u32 = tokio::select! {
        // client gone or pty EOF (shell exited and closed the master)
        _ = &mut copy => {
            if let Some(p) = pid {
                unsafe { libc::kill(-(p as i32), libc::SIGHUP); }
            }
            wait_code(child.wait().await)
        }
        // shell exited: let the copy drain trailing output briefly
        status = child.wait() => {
            let _ = tokio::time::timeout(Duration::from_millis(300), &mut copy).await;
            wait_code(Ok(status_or_default(status)))
        }
    };
    let _ = handle.exit_status_request(id, code).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
}

/// Bridge a session channel to a piped command: client->stdin, stdout+stderr->
/// client (merged — no extended-data split yet), then report the exit status.
async fn exec_bridge(chan: Channel<Msg>, mut child: Child, handle: Handle, id: ChannelId) {
    let stream = chan.into_stream();
    let (mut reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(tokio::sync::Mutex::new(writer));

    let stdin = child.stdin.take();
    let stdin_task = tokio::spawn(async move {
        if let Some(mut si) = stdin {
            let _ = tokio::io::copy(&mut reader, &mut si).await;
            let _ = si.shutdown().await;
        }
    });
    let stdout = child.stdout.take();
    let w_out = Arc::clone(&writer);
    let out_task = tokio::spawn(async move {
        if let Some(mut o) = stdout {
            pump(&mut o, w_out).await;
        }
    });
    let stderr = child.stderr.take();
    let w_err = Arc::clone(&writer);
    let err_task = tokio::spawn(async move {
        if let Some(mut e) = stderr {
            pump(&mut e, w_err).await;
        }
    });

    let status = child.wait().await;
    let _ = out_task.await;
    let _ = err_task.await;
    stdin_task.abort();

    let _ = handle.exit_status_request(id, wait_code(status)).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
}

/// Copy a child output stream to the shared channel writer until EOF.
async fn pump<R, W>(src: &mut R, dst: Arc<tokio::sync::Mutex<W>>)
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let mut w = dst.lock().await;
                if w.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
}

fn status_or_default(
    status: std::io::Result<std::process::ExitStatus>,
) -> std::process::ExitStatus {
    status.unwrap_or_else(|_| std::process::ExitStatus::from_raw(0))
}

/// SSH carries an unsigned exit code; map a signal death to 128+signo (shell
/// convention) and a missing status to 0.
fn wait_code(status: std::io::Result<std::process::ExitStatus>) -> u32 {
    match status {
        Ok(s) => {
            if let Some(code) = s.code() {
                code as u32
            } else if let Some(sig) = s.signal() {
                128 + sig as u32
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}
