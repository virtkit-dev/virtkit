//! Minimal russh SSH server embedded in virtkit-agent. It makes a microVM
//! reachable by stock SSH clients, including VS Code Remote-SSH, without sshd
//! or connecting through guest networking. It listens on vsock, and the host
//! connects through the hybrid vsock mux with `vk connect` (or
//! `vk-agent connect`) as ProxyCommand.
//!
//! It authenticates OpenSSH public keys passed to `ssh-serve` on the kernel
//! command line; it does not read an authorized-keys file. It supports `pty` +
//! `shell` with window resizing, `shell` without a pty (VS Code pipes its
//! bootstrap script to `ssh -T`), `exec`, `signal`, `sftp` (scp and VS Code's
//! server copy), and `direct-tcpip` (VS Code's server connection and
//! `ssh -L`/`-D`).
//! Together these cover VS Code Remote-SSH.
//!
//! Russh's default handlers return `false` for remote forwarding (`ssh -R`) and
//! agent forwarding. Virtkit instead provides guest-listener-to-host-target
//! tunnels through the driver-managed `vk-agent forward` / `vk forward` pair.
//! `vk run --ssh-agent` bridges the host agent to a separate guest socket, but
//! only run stages inherit it: init starts this server before exporting
//! `SSH_AUTH_SOCK`, so SSH sessions must name
//! `/run/virtkit-ssh-agent.sock` explicitly.
//!
//! Russh's default handlers return `Ok(())` without replying to `env` or
//! `x11-req`. OpenSSH does not request replies for `env` (distro `ssh_config`
//! uses `SendEnv LANG LC_*`), but waits for an `x11-req` reply. The session
//! still starts without X11, and its locale falls back to the guest default.
//! Supporting `LANG` and `LC_*` requires a whitelist because client values
//! enter the login shell's environment.
//!
//! Russh handles crypto and transport; virtkit-agent only connects channels to
//! its existing pty (`pty.rs`) and user-drop (`exec::server`) plumbing.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::future::Future;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use log::{debug, info, warn};
use russh::keys::PublicKey;
use russh::server::{Auth, ChannelOpenHandle, Config, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelOpenFailure, Sig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, watch};

use vk_core::addr::SocketAddr;
use vk_core::exec::server::{ResolvedUser, give_tty, resolve_user};
use vk_core::net::raw_listen;
use vk_core::pty::{self, PtyMaster};

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
        let (gone_tx, gone) = ConnectionGone::pair();
        let handler = ServerHandler::new(Arc::clone(&keys), force_user.clone(), gone);
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
            // Every bridge of this connection ends now, whatever it sits parked on. Err
            // means no bridge is left listening, which is the same outcome.
            let _ = gone_tx.send(true);
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

/// Pty pairs a connection may hold before a shell or command takes them, as sshd's
/// default `MaxSessions`.
const MAX_PENDING_PTYS: usize = 10;

/// A granted pty request. The pair is opened at request time, so the agent refuses the
/// request when the guest is out of ptys and the client can go on without a terminal.
struct PtyReq {
    term: Option<String>,
    rows: u16,
    cols: u16,
    master: PtyMaster,
    slave: OwnedFd,
}

/// Fires once the client connection is gone; every task bridging one of its channels
/// selects against it. A channel writer parked on an exhausted flow-control window is
/// woken by the session's window adjustments alone, so once the session is gone it would
/// wait forever and keep its bridge, child process and fds with it.
#[derive(Clone)]
pub(crate) struct ConnectionGone(watch::Receiver<bool>);

impl ConnectionGone {
    /// The signal and its trigger: `send(true)` fires it, and so does dropping the sender.
    fn pair() -> (watch::Sender<bool>, Self) {
        let (tx, rx) = watch::channel(false);
        (tx, Self(rx))
    }

    /// Resolves once the connection is gone.
    async fn wait(&mut self) {
        // Err means the sender went with the connection's task: gone either way.
        let _ = self.0.wait_for(|gone| *gone).await;
    }

    /// Run `work` to completion, or return `None` if the connection goes first.
    pub(crate) async fn bound<F: Future>(&mut self, work: F) -> Option<F::Output> {
        tokio::select! {
            out = work => Some(out),
            _ = self.wait() => None,
        }
    }
}

/// One per client connection. russh delivers channel requests on it in order;
/// session channels are stashed at open time and consumed by shell/exec.
struct ServerHandler {
    authorized: Arc<Vec<PublicKey>>,
    force_user: Option<String>,
    authed_user: Option<String>,
    channels: HashMap<ChannelId, Channel<Msg>>,
    ptys: HashMap<ChannelId, PtyReq>,
    /// Send window changes to the bridge while it owns the pty master. Keeping a raw fd
    /// here could resize another terminal after the master closes and its fd is reused.
    /// Only the latest size matters, so bursts of changes coalesce.
    resizes: HashMap<ChannelId, watch::Sender<(u16, u16)>>,
    /// Route signals through the owning bridge, which tracks the process's lifetime.
    signals: HashMap<ChannelId, mpsc::Sender<libc::c_int>>,
    /// Handed to every bridge this connection spawns.
    gone: ConnectionGone,
}

impl ServerHandler {
    fn new(
        authorized: Arc<Vec<PublicKey>>,
        force_user: Option<String>,
        gone: ConnectionGone,
    ) -> Self {
        ServerHandler {
            authorized,
            force_user,
            authed_user: None,
            channels: HashMap::new(),
            ptys: HashMap::new(),
            resizes: HashMap::new(),
            signals: HashMap::new(),
            gone,
        }
    }

    fn run_as(&self) -> String {
        self.authed_user
            .clone()
            .unwrap_or_else(|| "root".to_string())
    }

    /// Route `channel`'s signal requests to its new bridge.
    fn signals_for(&mut self, channel: ChannelId) -> mpsc::Receiver<libc::c_int> {
        // Bound pending signals; drop excess requests if the bridge stalls.
        let (tx, rx) = mpsc::channel(8);
        // Remove closed senders so long-lived connections do not accumulate them.
        self.signals.retain(|_, tx| !tx.is_closed());
        self.signals.insert(channel, tx);
        rx
    }

    /// Bridge the user's login shell or `cmdline` through it to the channel on its pty.
    /// Initialize the resize watch with the pty's opening size; reject the request
    /// if spawning fails.
    fn start_on_pty(
        &mut self,
        chan: Channel<Msg>,
        channel: ChannelId,
        pty: PtyReq,
        cmdline: Option<&OsStr>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let user = self.run_as();
        let size = (pty.rows, pty.cols);
        match spawn_on_pty(&user, pty, cmdline) {
            Ok((child, master, uid)) => {
                let (resize_tx, resizes) = watch::channel(size);
                self.resizes.insert(channel, resize_tx);
                let signals = self.signals_for(channel);
                session.channel_success(channel)?;
                let handle = session.handle();
                tokio::spawn(pty_bridge(
                    chan,
                    child,
                    master,
                    resizes,
                    Signals { rx: signals, uid },
                    handle,
                    channel,
                    self.gone.clone(),
                ));
            }
            Err(e) => {
                let what = cmdline.map_or("shell", |_| "exec on a pty");
                warn!("ssh: {what} for {user:?}: {e}");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }
}

impl Handler for ServerHandler {
    type Error = russh::Error;

    async fn auth_publickey(&mut self, user: &str, key: &PublicKey) -> Result<Auth, Self::Error> {
        // Compare key material only: PublicKey's PartialEq includes comments,
        // which OpenSSH key lines may carry but wire keys omit.
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
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.insert(channel.id(), channel);
        reply.accept().await;
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        modes: &[(russh::Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        // Only a session channel nothing runs on yet can take a terminal, and only one: a
        // pair granted to any other would stay open, unused, until the connection goes.
        // Pending pairs are capped as sshd caps sessions, since each holds a guest pty.
        if !self.channels.contains_key(&channel)
            || self.ptys.contains_key(&channel)
            || self.ptys.len() >= MAX_PENDING_PTYS
        {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let rows = row_height.min(u32::from(u16::MAX)) as u16;
        let cols = col_width.min(u32::from(u16::MAX)) as u16;
        match pty::openpty(rows, cols) {
            Ok((master, slave)) => {
                // The terminal still works with the kernel's defaults, as under sshd.
                if let Err(e) = apply_terminal_modes(&slave, modes) {
                    warn!("ssh: terminal modes left at their defaults: {e}");
                }
                self.ptys.insert(
                    channel,
                    PtyReq {
                        term: (!term.is_empty()).then(|| term.to_string()),
                        rows,
                        cols,
                        master,
                        slave,
                    },
                );
                session.channel_success(channel)?;
            }
            Err(e) => {
                let user = self.run_as();
                warn!("ssh: pty for {user:?}: {e}");
                session.channel_failure(channel)?;
            }
        }
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
        let size = (
            row_height.min(u32::from(u16::MAX)) as u16,
            col_width.min(u32::from(u16::MAX)) as u16,
        );
        // A change before the shell or command starts resizes the pty it will get.
        if let Some(pty) = self.ptys.get_mut(&channel) {
            (pty.rows, pty.cols) = size;
            // A size the pty refuses is not worth failing the session over.
            let _ = pty::set_winsize(pty.master.as_raw_fd(), size.0, size.1);
            return Ok(());
        }
        if self
            .resizes
            .get(&channel)
            .is_some_and(|bridge| bridge.send(size).is_err())
        {
            // The bridge has ended: no later change can reach it.
            self.resizes.remove(&channel);
        }
        Ok(())
    }

    /// Deliver a client's signal to the process group of the shell or command the channel
    /// runs, as sshd does, pty or not: a job the shell moved to a group of its own is the
    /// shell's to pass it on to. It is sent with the session user's credentials, as sshd
    /// does, so a job that has since become another user, such as `sudo`, is out of its
    /// reach. Names other than RFC 4254's and OpenSSH's USR2 are refused, and so is a
    /// signal to a channel that runs nothing. A reply says the signal was queued for the
    /// bridge, not delivered: waiting here for the bridge could deadlock against a bridge
    /// waiting on the channel window, so a failed kill is only logged.
    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(signo) = signal_number(&signal) else {
            debug!("ssh: ignoring signal {signal:?}");
            session.channel_failure(channel)?;
            return Ok(());
        };
        let Some(bridge) = self.signals.get(&channel) else {
            session.channel_failure(channel)?;
            return Ok(());
        };
        match bridge.try_send(signo) {
            Ok(()) => session.channel_success(channel)?,
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!("ssh: dropping signal {signal:?}: the bridge has a backlog");
                session.channel_failure(channel)?;
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.signals.remove(&channel);
                session.channel_failure(channel)?;
            }
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
            Some(pty) => self.start_on_pty(chan, channel, pty, None, session)?,
            None => match spawn_shell_nopty(&user) {
                Ok((child, uid)) => {
                    let signals = self.signals_for(channel);
                    session.channel_success(channel)?;
                    let handle = session.handle();
                    tokio::spawn(exec_bridge(
                        chan,
                        child,
                        Signals { rx: signals, uid },
                        handle,
                        channel,
                        self.gone.clone(),
                    ));
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
        // Preserve bytes as sshd does; lossy UTF-8 decoding corrupts non-UTF-8 names.
        let cmdline = OsStr::from_bytes(data);
        // `ssh -t host cmd` asks for a pty before the command, as Zed's remote terminal
        // does: run it on one, or an interactive shell it starts gets pipes and never
        // prompts. Without a pty the channel stays a byte-exact pipe.
        if let Some(pty) = self.ptys.remove(&channel) {
            return self.start_on_pty(chan, channel, pty, Some(cmdline), session);
        }
        let user = self.run_as();
        match spawn_exec(&user, cmdline) {
            Ok((child, uid)) => {
                let signals = self.signals_for(channel);
                session.channel_success(channel)?;
                let handle = session.handle();
                tokio::spawn(exec_bridge(
                    chan,
                    child,
                    Signals { rx: signals, uid },
                    handle,
                    channel,
                    self.gone.clone(),
                ));
            }
            Err(e) => {
                warn!("ssh: exec for {user:?}: {e}");
                session.channel_failure(channel)?;
            }
        }
        Ok(())
    }

    /// The client closed a channel before anything ran on it: forget what was kept for it.
    /// A channel a bridge closed is already gone from russh by the time the client's close
    /// arrives, so it does not land here; its resize and signal senders go with the handler.
    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        self.ptys.remove(&channel);
        self.resizes.remove(&channel);
        self.signals.remove(&channel);
        Ok(())
    }

    /// Serve `sftp` in-process on the channel as the logged-in user, who owns the
    /// transferred files. Used by scp/sftp and VS Code's server copy.
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
        // sftp needs no terminal; release any pending pty.
        self.ptys.remove(&channel);
        if name != "sftp" {
            session.channel_failure(channel)?;
            return Ok(());
        }
        let user = self.run_as();
        match resolve_user(&user) {
            Ok(ru) => {
                session.channel_success(channel)?;
                // Serves until the client is done, then ends the channel with the
                // exit-status scp and VS Code need — see `sftp::serve` for the order.
                tokio::spawn(crate::sftp::serve(chan, ru.uid, ru.gid, self.gone.clone()));
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
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let port = port_to_connect.min(u32::from(u16::MAX)) as u16;
        match TcpStream::connect((host_to_connect, port)).await {
            Ok(tcp) => {
                reply.accept().await;
                tokio::spawn(tcpip_bridge(channel, tcp, self.gone.clone()));
            }
            Err(e) => {
                warn!("ssh: direct-tcpip {host_to_connect}:{port}: {e}");
                reply.reject(ChannelOpenFailure::ConnectFailed).await;
            }
        }
        Ok(())
    }
}

/// Splice a forwarded-channel stream to an in-guest TCP connection until either
/// side closes, or the connection goes.
async fn tcpip_bridge(channel: Channel<Msg>, mut tcp: TcpStream, mut gone: ConnectionGone) {
    let mut stream = channel.into_stream();
    // Either end closing is the normal way out; there is nothing to report to.
    let _ = gone
        .bound(tokio::io::copy_bidirectional(&mut stream, &mut tcp))
        .await;
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
    // sshd exports the passwd entry's shell, and scripts read it to decide what they may
    // rely on; vk-agent's own environment is PID 1's, which has no SHELL to inherit.
    command.env("SHELL", login_shell(ru));
    if let Some(home) = &ru.home {
        command.env("HOME", home).current_dir(home);
    }
    // Read here, per session, so the host can change it without a restart. This runs before
    // the user drop, which is what lets the file be root-only.
    match read_session_env(vk_core::runcfg::SESSION_ENV_PATH) {
        Ok(Some(text)) => {
            for (k, v) in parse_session_env(&text) {
                command.env(k, v);
            }
        }
        Ok(None) => {}
        Err(e) => warn!("ssh: session environment ignored: {e:#}"),
    }
}

/// The session environment file, when the host is the one that wrote it.
///
/// Anything in it lands in every later session — `LD_PRELOAD` and `PATH` included — so the
/// file is opened with `O_NOFOLLOW` and accepted only on the evidence of the descriptor
/// itself: a regular file owned by root and mode 0600. A guest process that got to the name
/// first is refused here rather than trusted. Absent is not an error; anything else is.
fn read_session_env(path: &str) -> Result<Option<String>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("opening {path}")),
    };
    let meta = file
        .metadata()
        .with_context(|| format!("inspecting {path}"))?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o777 != 0o600 {
        return Err(anyhow!(
            "{path} is not a root-owned 0600 regular file, so it is not the host's"
        ));
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut file, &mut text)
        .with_context(|| format!("reading {path}"))?;
    Ok(Some(text))
}

/// The session environment file's variables. The format is
/// [`vk_core::runcfg::SESSION_ENV_PATH`]'s: one `KEY=VALUE` per line, `KEY` matching
/// `[A-Za-z_][A-Za-z0-9_]*`, a `#` line a comment, a CRLF line ending stripped. A line that
/// is none of those is skipped with a log line rather than turned into an unusable variable
/// — a key with a NUL in it fails the whole spawn, in guest PID 1's session path. `HOME` is
/// skipped too: it is the passwd entry's here, and the session's working directory is set
/// from the same place and would not follow a different one.
fn parse_session_env(text: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            warn!("ssh: session environment: no '=' in {line:?}, skipped");
            continue;
        };
        if !env_name_ok(key) {
            warn!("ssh: session environment: {key:?} is not a variable name, skipped");
            continue;
        }
        if key == "HOME" {
            warn!("ssh: session environment: HOME is the login user's, skipped");
            continue;
        }
        if value.contains('\0') {
            warn!("ssh: session environment: {key} has a NUL in its value, skipped");
            continue;
        }
        out.push((key, value));
    }
    out
}

/// `[A-Za-z_][A-Za-z0-9_]*`, the shape a variable name has to have to be usable.
fn env_name_ok(key: &str) -> bool {
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// The user's login shell, or `/bin/sh` when the passwd entry names none.
fn login_shell(ru: &ResolvedUser) -> std::ffi::OsString {
    ru.shell
        .clone()
        .unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"))
}

/// Set the terminal modes the client sent with its pty request on the slave, the way sshd
/// does: its keys (^C, ^Z, erase…), its line discipline, echo and output processing. A
/// client that turned off, say, ICRNL or IUTF8 locally would otherwise type into a
/// terminal that disagrees with it. Modes Linux has no flag for, the line speeds, which a
/// pty does not use, and the character size and parity, which Linux fixes at CS8 without
/// parity on a pty, are skipped.
fn apply_terminal_modes(slave: &OwnedFd, modes: &[(russh::Pty, u32)]) -> std::io::Result<()> {
    use russh::Pty;
    if modes.is_empty() {
        return Ok(());
    }
    let fd = slave.as_raw_fd();
    // SAFETY: termios is plain data, valid zeroed; tcgetattr fills it through a valid
    // pointer, on the slave fd this function borrows.
    let mut tio: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut tio) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    for &(mode, value) in modes {
        let cc = match mode {
            Pty::VINTR => Some(libc::VINTR),
            Pty::VQUIT => Some(libc::VQUIT),
            Pty::VERASE => Some(libc::VERASE),
            Pty::VKILL => Some(libc::VKILL),
            Pty::VEOF => Some(libc::VEOF),
            Pty::VEOL => Some(libc::VEOL),
            Pty::VEOL2 => Some(libc::VEOL2),
            Pty::VSTART => Some(libc::VSTART),
            Pty::VSTOP => Some(libc::VSTOP),
            Pty::VSUSP => Some(libc::VSUSP),
            Pty::VREPRINT => Some(libc::VREPRINT),
            Pty::VWERASE => Some(libc::VWERASE),
            Pty::VLNEXT => Some(libc::VLNEXT),
            Pty::VDISCARD => Some(libc::VDISCARD),
            _ => None,
        };
        if let Some(i) = cc {
            // 255 means "disabled" in the protocol. Skip out-of-range characters
            // rather than truncating them.
            match libc::cc_t::try_from(value) {
                Ok(255) => tio.c_cc[i] = libc::_POSIX_VDISABLE,
                Ok(c) => tio.c_cc[i] = c,
                Err(_) => {}
            }
            continue;
        }
        let (field, bit) = match mode {
            Pty::IGNPAR => (&mut tio.c_iflag, libc::IGNPAR),
            Pty::PARMRK => (&mut tio.c_iflag, libc::PARMRK),
            Pty::INPCK => (&mut tio.c_iflag, libc::INPCK),
            Pty::ISTRIP => (&mut tio.c_iflag, libc::ISTRIP),
            Pty::INLCR => (&mut tio.c_iflag, libc::INLCR),
            Pty::IGNCR => (&mut tio.c_iflag, libc::IGNCR),
            Pty::ICRNL => (&mut tio.c_iflag, libc::ICRNL),
            Pty::IUCLC => (&mut tio.c_iflag, libc::IUCLC),
            Pty::IXON => (&mut tio.c_iflag, libc::IXON),
            Pty::IXANY => (&mut tio.c_iflag, libc::IXANY),
            Pty::IXOFF => (&mut tio.c_iflag, libc::IXOFF),
            Pty::IMAXBEL => (&mut tio.c_iflag, libc::IMAXBEL),
            Pty::IUTF8 => (&mut tio.c_iflag, libc::IUTF8),
            Pty::ISIG => (&mut tio.c_lflag, libc::ISIG),
            Pty::ICANON => (&mut tio.c_lflag, libc::ICANON),
            Pty::XCASE => (&mut tio.c_lflag, libc::XCASE),
            Pty::ECHO => (&mut tio.c_lflag, libc::ECHO),
            Pty::ECHOE => (&mut tio.c_lflag, libc::ECHOE),
            Pty::ECHOK => (&mut tio.c_lflag, libc::ECHOK),
            Pty::ECHONL => (&mut tio.c_lflag, libc::ECHONL),
            Pty::NOFLSH => (&mut tio.c_lflag, libc::NOFLSH),
            Pty::TOSTOP => (&mut tio.c_lflag, libc::TOSTOP),
            Pty::IEXTEN => (&mut tio.c_lflag, libc::IEXTEN),
            Pty::ECHOCTL => (&mut tio.c_lflag, libc::ECHOCTL),
            Pty::ECHOKE => (&mut tio.c_lflag, libc::ECHOKE),
            Pty::PENDIN => (&mut tio.c_lflag, libc::PENDIN),
            Pty::OPOST => (&mut tio.c_oflag, libc::OPOST),
            Pty::OLCUC => (&mut tio.c_oflag, libc::OLCUC),
            Pty::ONLCR => (&mut tio.c_oflag, libc::ONLCR),
            Pty::OCRNL => (&mut tio.c_oflag, libc::OCRNL),
            Pty::ONOCR => (&mut tio.c_oflag, libc::ONOCR),
            Pty::ONLRET => (&mut tio.c_oflag, libc::ONLRET),
            _ => continue,
        };
        if value != 0 {
            *field |= bit;
        } else {
            *field &= !bit;
        }
    }
    // SAFETY: tcsetattr only reads the termios, on the slave fd this function borrows.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &tio) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Spawn the user's login shell on the requested pty as `user`, or `cmdline` through
/// that shell when given, and return the uid it runs as.
fn spawn_on_pty(
    user: &str,
    pty: PtyReq,
    cmdline: Option<&OsStr>,
) -> Result<(Child, PtyMaster, libc::uid_t)> {
    let ru = resolve_user(user)?;
    let PtyReq {
        term,
        master,
        slave,
        ..
    } = pty;
    // A pty left owned by root still works through the fds the shell inherits.
    if let Err(e) = give_tty(&slave, ru.uid, ru.gid) {
        warn!("ssh: pty owner for {user:?}: {e}");
    }
    let shell = login_shell(&ru);
    let mut command = Command::new(&shell);
    match cmdline {
        Some(cmdline) => command.arg("-c").arg(cmdline),
        None => command.arg("-l"),
    };
    login_env(&mut command, user, &ru);
    if let Some(term) = &term {
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
    Ok((child, master, ru.uid))
}

/// Spawn the user's login shell with piped stdio and no tty — for a `shell`
/// request that arrived without a pty (e.g. `ssh -T host` piping a script to
/// stdin, as VS Code's server bootstrap does). Non-interactive (stdin is a pipe,
/// not a terminal), so bash runs the piped commands without ever printing a
/// prompt — stdout stays clean for the marker parsing VS Code relies on.
fn spawn_shell_nopty(user: &str) -> Result<(Child, libc::uid_t)> {
    let ru = resolve_user(user)?;
    let shell = login_shell(&ru);
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
    Ok((command.spawn()?, ru.uid))
}

/// Spawn `cmdline` via the user's shell with piped stdio (no tty), own pgroup.
fn spawn_exec(user: &str, cmdline: &OsStr) -> Result<(Child, libc::uid_t)> {
    let ru = resolve_user(user)?;
    let shell = login_shell(&ru);
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
    Ok((command.spawn()?, ru.uid))
}

/// The extended-data type SSH reserves for stderr (RFC 4254 §5.2). A client hands data
/// that arrives under it to its own stderr and leaves the channel's data stream untouched.
const SSH_EXTENDED_DATA_STDERR: u32 = 1;

/// How long a hung-up process group gets to leave before it is killed outright.
const HANGUP_GRACE: Duration = Duration::from_secs(5);

/// The pid of `child` while it is unreaped: it leads its own process group (and, on a
/// pty, its session), so the number stays its group's until the bridge reaps it.
fn leader_pid(child: &Child) -> Option<libc::pid_t> {
    child.id().and_then(|p| libc::pid_t::try_from(p).ok())
}

/// Send `signal` to the whole process group `child` leads.
fn signal_group(child: &Child, signal: libc::c_int) {
    if let Some(pid) = leader_pid(child) {
        // SAFETY: a plain syscall; the unreaped leader keeps the group id ours, and ESRCH
        // (the group already gone) is fine to ignore.
        unsafe { libc::kill(-pid, signal) };
    }
}

/// The client's signal requests for one channel, and the uid they are sent as.
struct Signals {
    rx: mpsc::Receiver<libc::c_int>,
    uid: libc::uid_t,
}

impl Signals {
    /// Send `signal` to process group `pgid` with the session user's credentials.
    fn deliver(&self, pgid: libc::pid_t, signal: libc::c_int) {
        if let Err(e) = kill_group_as(self.uid, pgid, signal) {
            debug!("ssh: signal {signal} to group {pgid}: {e}");
        }
    }
}

/// `kill(-pgid, signal)` as `uid`, so the kernel's permission check is the one that user
/// would get: the agent's root reaches any process, and a job whose real and saved uids
/// are another user's, such as one run through `sudo`, is not the session user's to
/// signal. The switch happens on a fresh thread, through the raw syscall: Linux
/// credentials are per thread, libc's setresuid would change every thread of the agent,
/// and a pooled thread (`spawn_blocking`) would keep the dropped uid. The thread ends
/// with the credentials it took. The one process-wide trace is the agent becoming
/// non-dumpable, which changes nothing for a root process. Spawning and joining the
/// thread from an async task costs microseconds, once per signal.
#[cfg(not(target_pointer_width = "64"))]
compile_error!("kill_group_as needs setresuid32 on a 32-bit target");
fn kill_group_as(uid: libc::uid_t, pgid: libc::pid_t, signal: libc::c_int) -> std::io::Result<()> {
    // Never 1 or below: kill(-1) signals every process, and 0 the agent's own group.
    if pgid <= 1 {
        return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
    }
    let kill = move || {
        // SAFETY: a plain syscall; ESRCH or EPERM comes back as the error.
        if unsafe { libc::kill(-pgid, signal) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    };
    if uid == unsafe { libc::geteuid() } {
        return kill();
    }
    std::thread::Builder::new()
        .name("ssh-signal".into())
        .spawn(move || {
            // SAFETY: the raw setresuid changes this thread's credentials only, and the
            // thread does nothing after the kill. It takes 32-bit uids on the 64-bit
            // targets the agent builds for; 32-bit ones would need setresuid32.
            if unsafe { libc::syscall(libc::SYS_setresuid, uid, uid, uid) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            kill()
        })?
        .join()
        .map_err(|_| std::io::Error::other("the signal thread panicked"))?
}

/// The signal number for a name a client may send: RFC 4254's list, plus the USR2
/// OpenSSH accepts too.
fn signal_number(signal: &Sig) -> Option<libc::c_int> {
    Some(match signal {
        Sig::ABRT => libc::SIGABRT,
        Sig::ALRM => libc::SIGALRM,
        Sig::FPE => libc::SIGFPE,
        Sig::HUP => libc::SIGHUP,
        Sig::ILL => libc::SIGILL,
        Sig::INT => libc::SIGINT,
        Sig::KILL => libc::SIGKILL,
        Sig::PIPE => libc::SIGPIPE,
        Sig::QUIT => libc::SIGQUIT,
        Sig::SEGV => libc::SIGSEGV,
        Sig::TERM => libc::SIGTERM,
        Sig::USR1 => libc::SIGUSR1,
        Sig::Custom(name) if name == "USR2" => libc::SIGUSR2,
        Sig::Custom(_) => return None,
    })
}

/// Hang up on `child`'s process group, as sshd does when its client leaves, and reap it.
/// A group still there when the grace period ends is killed: its client is gone, so
/// nothing it runs is still wanted, and a bridge must not wait forever on a process that
/// ignores the hang-up.
async fn hangup_and_reap(child: &mut Child) -> u32 {
    signal_group(child, libc::SIGHUP);
    match tokio::time::timeout(HANGUP_GRACE, child.wait()).await {
        Ok(status) => wait_code(status),
        Err(_) => {
            signal_group(child, libc::SIGKILL);
            wait_code(child.wait().await)
        }
    }
}

/// Bridge a session channel to a login shell or command on a pty, applying window changes
/// until either side closes or the connection ends. Report the exit status and close the
/// channel. If the client leaves, hang up as a terminal would: close the pty master,
/// signal the process group, then kill it if it remains.
#[allow(clippy::too_many_arguments)]
async fn pty_bridge(
    chan: Channel<Msg>,
    mut child: Child,
    mut master: PtyMaster,
    mut resizes: watch::Receiver<(u16, u16)>,
    mut signals: Signals,
    handle: Handle,
    id: ChannelId,
    mut gone: ConnectionGone,
) {
    // The stream outlives the trailer below: dropping it closes the channel.
    let mut stream = chan.into_stream();
    // The shell's exit status if it exited on its own; the copy's borrow of the master
    // ends with this block, so the master can be closed before the shell is hung up on.
    let exited = {
        // The ioctl wants the number; the master itself is the copy's for the duration.
        let master_fd = master.as_raw_fd();
        let mut copy = std::pin::pin!(tokio::io::copy_bidirectional(&mut stream, &mut master));
        loop {
            tokio::select! {
                // client gone or pty EOF (shell exited and closed the master)
                _ = &mut copy => break None,
                // shell exited: let the copy drain trailing output briefly
                status = child.wait() => {
                    // Whatever did not drain in time is going to a client that is not reading.
                    let _ = tokio::time::timeout(Duration::from_millis(300), &mut copy).await;
                    break Some(status_or_default(status));
                }
                // connection gone while the copy sat parked on the channel window
                _ = gone.wait() => break None,
                // the client's terminal changed size; the master is open for as long as
                // this loop runs, so the number still names it
                Ok(()) = resizes.changed() => {
                    let (rows, cols) = *resizes.borrow_and_update();
                    // A size the pty refuses is not worth ending the session over.
                    let _ = pty::set_winsize(master_fd, rows, cols);
                }
                Some(signo) = signals.rx.recv() => {
                    if let Some(pgid) = leader_pid(&child) {
                        signals.deliver(pgid, signo);
                    }
                }
            }
        }
    };
    let code: u32 = match exited {
        Some(status) => wait_code(Ok(status)),
        None => {
            // Closing the master is the hang-up a shell cannot ignore: the kernel HUPs the
            // session and ends its tty (reads see EOF, writes EIO), so even a shell that
            // traps SIGHUP comes off the pty. The signals are for whatever stays anyway.
            drop(master);
            hangup_and_reap(&mut child).await
        }
    };
    let _ = handle.exit_status_request(id, code).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
}

/// Bridge client input to stdin, stdout to channel data, and stderr to extended data,
/// then report the exit status. On disconnect, hang up the command's process group
/// and kill it if it stays.
///
/// Keeping the two output streams apart is what makes the channel a binary-transparent
/// pipe, which is the whole contract a command without a tty is run under. A client that
/// speaks a framed protocol over `ssh -T` — Zed's remote server, say — reads its length
/// prefixes straight off stdout, so a single diagnostic line folded in from stderr is not
/// noise it can skip: the next field it reads is a fragment of that line, and the stream
/// never resynchronizes. Text commands never notice, which is why `uname` and `cat` probes
/// pass over a channel a protocol cannot survive.
async fn exec_bridge(
    chan: Channel<Msg>,
    mut child: Child,
    mut signals: Signals,
    handle: Handle,
    id: ChannelId,
    mut gone: ConnectionGone,
) {
    // Split for separate stdout/stderr writers without `into_stream`'s close-on-drop,
    // which could close the channel before the exit status. Both writers share the
    // channel's window and stay within the client's allowance.
    let (mut read_half, write_half) = chan.split();

    let stdin = child.stdin.take();
    let stdin_task = tokio::spawn(async move {
        if let Some(mut si) = stdin {
            let mut from_client = read_half.make_reader();
            let _ = tokio::io::copy(&mut from_client, &mut si).await;
            let _ = si.shutdown().await;
        }
    });
    let stdout = child.stdout.take();
    let to_client = write_half.make_writer();
    let mut out_task = tokio::spawn(async move {
        if let Some(mut o) = stdout {
            pump(&mut o, to_client).await;
        }
    });
    let stderr = child.stderr.take();
    let to_client_err = write_half.make_writer_ext(Some(SSH_EXTENDED_DATA_STDERR));
    let mut err_task = tokio::spawn(async move {
        if let Some(mut e) = stderr {
            pump(&mut e, to_client_err).await;
        }
    });

    // The client's signals go to the command's process group, the one a hang-up reaches.
    let waited = gone.bound(async {
        loop {
            tokio::select! {
                status = child.wait() => break status,
                Some(signo) = signals.rx.recv() => {
                    if let Some(pgid) = leader_pid(&child) {
                        signals.deliver(pgid, signo);
                    }
                }
            }
        }
    });
    let Some(status) = waited.await else {
        // Connection gone: no one to report to, and a pump may sit parked on the window.
        stdin_task.abort();
        out_task.abort();
        err_task.abort();
        // The status has no one to go to.
        hangup_and_reap(&mut child).await;
        return;
    };
    // Let the pumps drain the command's last output, unless the connection goes first.
    let drained = gone
        .bound(async {
            // Only a panic or an abort surfaces here, and neither has anyone to tell.
            let _ = (&mut out_task).await;
            let _ = (&mut err_task).await;
        })
        .await;
    if drained.is_none() {
        out_task.abort();
        err_task.abort();
    }
    stdin_task.abort();

    // The client may already be gone; there is no one left to tell.
    let _ = handle.exit_status_request(id, wait_code(status)).await;
    let _ = handle.eof(id).await;
    let _ = handle.close(id).await;
}

/// Copy a child output stream to its own channel writer until EOF.
async fn pump<R, W>(src: &mut R, mut dst: W)
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buf = [0u8; 8192];
    loop {
        match src.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).await.is_err() {
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

#[cfg(test)]
mod tests {
    use super::{ConnectionGone, Duration, parse_session_env, read_session_env, run_ssh_server};

    /// Data, stderr extended data, and exit status returned by an exec channel.
    struct ExecOutput {
        data: Vec<u8>,
        stderr: Vec<u8>,
        status: Option<u32>,
    }

    /// The server key is fresh per boot and pinned by nobody; the tests are about the
    /// channels, not about trust.
    struct AcceptAnyHostKey;

    impl russh::client::Handler for AcceptAnyHostKey {
        type Error = russh::Error;

        async fn check_server_key(
            &mut self,
            _key: &russh::keys::PublicKeyOrCertificate,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }

    /// A test SSH server with its own socket and an authenticated client session.
    /// Dropping it stops the server.
    struct TestSession {
        server: tokio::task::JoinHandle<anyhow::Result<()>>,
        path: std::path::PathBuf,
        session: russh::client::Handle<AcceptAnyHostKey>,
    }

    impl Drop for TestSession {
        fn drop(&mut self) {
            self.server.abort();
            let _ = std::fs::remove_file(&self.path);
        }
    }

    async fn test_session() -> TestSession {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        use russh::client;
        use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg};

        use vk_core::addr::SocketAddr;

        let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap();
        let authorized = vec![key.public_key().to_openssh().unwrap()];

        // Tests run in parallel in one process: the pid alone would share the socket.
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "vk-agent-ssh-exec-{}-{}.sock",
            unsafe { libc::getpid() },
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let addr = SocketAddr::Unix(path.clone());
        let keys = super::parse_authorized_keys(&authorized);
        let server = tokio::spawn(async move { run_ssh_server(&addr, &keys, None).await });

        // The listener is bound inside the task; wait for the socket to answer.
        let stream = loop {
            match tokio::net::UnixStream::connect(&path).await {
                Ok(s) => break s,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };

        // Use the test's uid: `with_user_drop` skips same-uid drops, and numeric users
        // resolve with or without a passwd entry.
        let user = unsafe { libc::geteuid() }.to_string();
        let mut session = client::connect_stream(
            Arc::new(client::Config::default()),
            stream,
            AcceptAnyHostKey,
        )
        .await
        .unwrap();
        assert!(
            session
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), None))
                .await
                .unwrap()
                .success()
        );
        TestSession {
            server,
            path,
            session,
        }
    }

    /// Run `cmdline` against a test SSH server, on an 80x24 pty when `pty` says so, and
    /// collect what the channel sends until it closes. `resize` is sent as a window
    /// change right after the exec.
    async fn exec_over_ssh(
        cmdline: impl Into<Vec<u8>>,
        pty: bool,
        resize: Option<(u32, u32)>,
    ) -> ExecOutput {
        exec_over_ssh_with(cmdline, pty.then_some(&[][..]), resize, None).await
    }

    /// [`exec_over_ssh`], sending `modes` with the pty request when there is one, and
    /// `signal` once the command's output first says `ready`.
    async fn exec_over_ssh_with(
        cmdline: impl Into<Vec<u8>>,
        modes: Option<&[(russh::Pty, u32)]>,
        resize: Option<(u32, u32)>,
        signal: Option<russh::Sig>,
    ) -> ExecOutput {
        let test = test_session().await;
        let mut channel = test.session.channel_open_session().await.unwrap();
        if let Some(modes) = modes {
            channel
                .request_pty(true, "xterm", 80, 24, 0, 0, modes)
                .await
                .unwrap();
        }
        channel.exec(true, cmdline).await.unwrap();
        if let Some((cols, rows)) = resize {
            channel.window_change(cols, rows, 0, 0).await.unwrap();
        }
        let mut signal = signal;
        let mut out = ExecOutput {
            data: Vec::new(),
            stderr: Vec::new(),
            status: None,
        };
        // Read to Close, not Eof: on a pty the data stream ends before the exit status.
        let collect = async {
            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data } => {
                        out.data.extend_from_slice(&data);
                        if out.data.windows(5).any(|w| w == b"ready")
                            && let Some(sig) = signal.take()
                        {
                            channel.signal(sig).await.unwrap();
                        }
                    }
                    russh::ChannelMsg::ExtendedData { data, ext } => {
                        assert_eq!(ext, super::SSH_EXTENDED_DATA_STDERR);
                        out.stderr.extend_from_slice(&data);
                    }
                    russh::ChannelMsg::ExitStatus { exit_status } => out.status = Some(exit_status),
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(30), collect)
            .await
            .expect("the exec channel closes");
        out
    }

    /// The exec channel has to be the binary-transparent pipe a client without a tty is
    /// promised: a framed protocol (Zed's remote server) reads its length prefixes straight
    /// off the data stream, so nothing the command did not write to stdout may reach it.
    /// Two things otherwise would: whatever it wrote to stderr, and the carriage returns a
    /// pty inserts before newlines. Six bytes come back, or the channel is not a pipe.
    #[tokio::test]
    async fn exec_keeps_stderr_and_newlines_off_the_data_stream() {
        let out = exec_over_ssh(
            r"printf 'AB\nCD\n'; printf 'a warning\n' >&2; exit 3",
            false,
            None,
        )
        .await;
        assert_eq!(out.data, b"AB\nCD\n");
        assert_eq!(out.stderr, b"a warning\n");
        assert_eq!(out.status, Some(3));
    }

    /// The command line reaches the shell byte for byte, a non-UTF-8 name included, with
    /// or without a pty.
    #[tokio::test]
    async fn exec_passes_the_command_line_through_as_bytes() {
        for pty in [false, true] {
            let out = exec_over_ssh(&b"printf '%s' '\xff\xfe'"[..], pty, None).await;
            assert_eq!(out.data, b"\xff\xfe", "pty: {pty}");
            assert_eq!(out.status, Some(0), "pty: {pty}");
        }
    }

    /// `ssh -t host cmd` runs the command on the pty it asked for, as the controlling
    /// terminal of its own session, so an interactive shell it starts can prompt and take
    /// job control. Both streams arrive merged on the data stream, as from sshd.
    #[tokio::test]
    async fn exec_after_a_pty_request_runs_on_the_pty() {
        let out = exec_over_ssh(
            r"test -t 0 && test -t 1 && echo $TERM && stty size && echo err >&2 && : </dev/tty && tty && exit 3",
            true,
            None,
        )
        .await;
        let data = String::from_utf8(out.data).unwrap();
        let lines: Vec<&str> = data.split("\r\n").collect();
        assert!(lines.len() >= 4, "{data:?}");
        assert_eq!(lines[..3], ["xterm", "24 80", "err"], "{data:?}");
        assert!(lines[3].starts_with("/dev/pts/"), "{data:?}");
        assert!(out.stderr.is_empty(), "{:?}", out.stderr);
        assert_eq!(out.status, Some(3));
    }

    /// Requested modes move interrupt from ^C to ^B and disable erase, echo,
    /// CR-to-NL translation and output processing. An out-of-range control character,
    /// line speed and character size are ignored without failing the request.
    #[tokio::test]
    async fn a_pty_takes_the_terminal_modes_the_client_sent() {
        use russh::Pty;
        let modes = [
            (Pty::VINTR, 2),
            (Pty::VERASE, 255),
            (Pty::VQUIT, 0x1_0000),
            (Pty::ECHO, 0),
            (Pty::ICRNL, 0),
            (Pty::IUTF8, 1),
            (Pty::OPOST, 0),
            (Pty::CS7, 1),
            (Pty::TTY_OP_ISPEED, 9600),
        ];
        let out = exec_over_ssh_with("stty -a", Some(&modes), None, None).await;
        let stty = String::from_utf8_lossy(&out.data);
        for want in [
            "intr = ^B;",
            "erase = <undef>;",
            "quit = ^\\;",
            "speed 38400 baud",
        ] {
            assert!(stty.contains(want), "no {want:?} in {stty}");
        }
        let words: Vec<&str> = stty.split_whitespace().collect();
        for want in ["-echo", "-icrnl", "iutf8", "-opost", "cs8"] {
            assert!(words.contains(&want), "no {want:?} in {stty}");
        }
        assert_eq!(out.status, Some(0));
    }

    /// A window change reaches a command run on a pty, as it does a shell. The loop runs
    /// under `sh` whatever the test user's shell, and gives up after five seconds.
    #[tokio::test]
    async fn exec_on_a_pty_follows_window_changes() {
        let out = exec_over_ssh(
            r#"sh -c 'i=0; while [ "$(stty size)" = "24 80" ] && [ $i -lt 100 ]; do sleep 0.05; i=$((i+1)); done; stty size'"#,
            true,
            Some((100, 30)),
        )
        .await;
        assert_eq!(String::from_utf8_lossy(&out.data), "30 100\r\n");
        assert_eq!(out.status, Some(0));
    }

    /// A window change between the pty request and the command resizes the pty the
    /// command then starts on.
    #[tokio::test]
    async fn a_window_change_before_exec_sizes_the_pty() {
        let test = test_session().await;
        let mut channel = test.session.channel_open_session().await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.window_change(100, 30, 0, 0).await.unwrap();
        channel.exec(true, "stty size").await.unwrap();
        let mut data = Vec::new();
        let collect = async {
            while let Some(msg) = channel.wait().await {
                match msg {
                    russh::ChannelMsg::Data { data: d } => data.extend_from_slice(&d),
                    russh::ChannelMsg::Close => break,
                    _ => {}
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), collect)
            .await
            .expect("the exec channel closes");
        assert_eq!(String::from_utf8_lossy(&data), "30 100\r\n");
    }

    /// A pty request on a channel that already runs something is refused: nothing would
    /// take the pair, which would stay open until the connection goes.
    #[tokio::test]
    async fn a_pty_request_after_exec_is_refused() {
        let test = test_session().await;
        let mut channel = test.session.channel_open_session().await.unwrap();
        channel.exec(true, "sleep 5").await.unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        let replies = async {
            let mut replies = Vec::new();
            while replies.len() < 2 {
                match channel.wait().await {
                    Some(russh::ChannelMsg::Success) => replies.push(true),
                    Some(russh::ChannelMsg::Failure) => replies.push(false),
                    Some(_) => {}
                    None => break,
                }
            }
            replies
        };
        let replies = tokio::time::timeout(Duration::from_secs(10), replies)
            .await
            .expect("both requests get a reply");
        assert_eq!(replies, [true, false]);
    }

    /// Signals reach a non-pty command's process group. Use `sh` regardless of the
    /// test user's shell.
    #[tokio::test]
    async fn a_signal_reaches_a_command() {
        let out = exec_over_ssh_with(
            r#"exec sh -c 'trap "echo got-term; exit 7" TERM; echo ready; while :; do sleep 0.05; done'"#,
            None,
            None,
            Some(russh::Sig::TERM),
        )
        .await;
        assert_eq!(out.data, b"ready\ngot-term\n");
        assert_eq!(out.status, Some(7));
    }

    /// Signals on a pty reach the shell's own group, as under sshd, not the job it put in
    /// the foreground. The script starts a watcher in its own group, then, with job
    /// control on, a foreground job in a group of its own that waits for the watcher to
    /// see the signal. Each says if the signal reached it; no step waits on a clock.
    #[tokio::test]
    async fn a_signal_on_a_pty_reaches_the_shells_group() {
        let dir = std::env::temp_dir().join(format!("vk-agent-ssh-sig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (seen, script) = (dir.join("seen"), dir.join("script"));
        let _ = std::fs::remove_file(&seen);
        // The shell traps USR1 rather than die of it; a trap, unlike an ignore, is not
        // inherited, so the watcher and the job can set their own.
        std::fs::write(
            &script,
            format!(
                r#"trap : USR1
sh -c 'trap "echo group-got; touch {seen}; exit" USR1; echo ready; while :; do sleep 0.05; done' &
set -m
sh -c 'trap "echo job-got; exit" USR1; while [ ! -e {seen} ]; do sleep 0.05; done'
kill $! 2>/dev/null
echo end
"#,
                seen = seen.display()
            ),
        )
        .unwrap();
        let out = exec_over_ssh_with(
            format!("exec sh {}", script.display()),
            Some(&[]),
            None,
            Some(russh::Sig::USR1),
        )
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        let data = String::from_utf8_lossy(&out.data);
        assert!(data.contains("group-got"), "{data:?}");
        assert!(!data.contains("job-got"), "{data:?}");
        assert!(data.contains("end"), "{data:?}");
        assert_eq!(out.status, Some(0));
    }

    /// A signal is sent with the session user's credentials: it reaches that user's
    /// processes and not root's, which the agent itself could signal. Root only.
    #[test]
    fn a_signal_is_sent_as_the_session_user() {
        use std::os::unix::process::CommandExt;
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("skipped: needs root");
            return;
        }
        let spawn = |uid: libc::uid_t| {
            let mut command = std::process::Command::new("sleep");
            command.arg("30").process_group(0);
            if uid != 0 {
                command.uid(uid).gid(uid);
            }
            command.spawn().unwrap()
        };
        let pgid = |c: &std::process::Child| libc::pid_t::try_from(c.id()).unwrap();

        let mut roots = spawn(0);
        let e = super::kill_group_as(65534, pgid(&roots), libc::SIGTERM).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EPERM), "{e}");
        assert!(
            roots.try_wait().unwrap().is_none(),
            "root's process was signalled"
        );

        let mut users = spawn(65534);
        super::kill_group_as(65534, pgid(&users), libc::SIGTERM).unwrap();
        let status = users.wait().unwrap();
        assert_eq!(
            std::os::unix::process::ExitStatusExt::signal(&status),
            Some(libc::SIGTERM)
        );

        // The agent's own credentials are untouched.
        assert_eq!(unsafe { libc::geteuid() }, 0);
        super::kill_group_as(0, pgid(&roots), libc::SIGKILL).unwrap();
        roots.wait().unwrap();
    }

    #[tokio::test]
    async fn bound_work_ends_when_its_connection_goes() {
        let (tx, mut gone) = ConnectionGone::pair();
        // Work that finishes while the connection is up comes back as is.
        assert_eq!(gone.bound(async { 7 }).await, Some(7));

        // Work that would never finish ends when the connection goes.
        let mut parked = gone.clone();
        let bridge = tokio::spawn(async move { parked.bound(std::future::pending::<()>()).await });
        tx.send(true).unwrap();
        assert_eq!(bridge.await.unwrap(), None);

        // A connection task that is simply gone, sender and all, counts too.
        let (tx, mut gone) = ConnectionGone::pair();
        drop(tx);
        assert_eq!(gone.bound(std::future::pending::<()>()).await, None);
    }

    #[test]
    fn session_env_takes_key_value_lines_and_skips_the_rest() {
        let text = "TOKEN=glpat-x=y\n\nnot a pair\n=novalue\nEMPTY=\nURL=https://a.b/c\n";
        assert_eq!(
            parse_session_env(text),
            [
                ("TOKEN", "glpat-x=y"),
                ("EMPTY", ""),
                ("URL", "https://a.b/c")
            ]
        );
    }

    #[test]
    fn only_usable_variable_names_survive_and_home_is_the_login_users() {
        // CRLF is stripped, comments and blank lines are not variables, and a name that a
        // shell could not spell is skipped rather than exported unusable.
        let text = "# a comment\r\n  # indented\nA B=c\n1ST=x\nWITH-DASH=x\nHOME=/evil\n\
                    PATH=/usr/bin\r\nOK_1=v\n";
        assert_eq!(
            parse_session_env(text),
            [("PATH", "/usr/bin"), ("OK_1", "v")]
        );
        assert_eq!(parse_session_env("K=a\0b\n"), []);
    }

    #[test]
    fn a_session_env_file_that_is_not_the_hosts_is_refused() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!("vk-sshenv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let at = |name: &str| dir.join(name).to_string_lossy().into_owned();
        let write = |name: &str, mode: u32| {
            let path = dir.join(name);
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(mode)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut f, b"K=v\n").unwrap();
            path
        };

        // Absent is the ordinary case: the host has not written it yet.
        assert!(read_session_env(&at("nothing")).unwrap().is_none());
        // Group- or world-readable is not what the host writes, whoever owns it.
        write("loose", 0o644);
        assert!(read_session_env(&at("loose")).is_err());
        // A symlink planted at the name does not resolve, however tight its target.
        let target = write("target", 0o600);
        std::os::unix::fs::symlink(&target, dir.join("link")).unwrap();
        assert!(read_session_env(&at("link")).is_err());
        // A directory is not a file to read variables out of.
        std::fs::create_dir(dir.join("adir")).unwrap();
        assert!(read_session_env(&at("adir")).is_err());
        // Owned by whoever runs the tests: only root's own file is the host's.
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } != 0 {
            assert!(read_session_env(&at("target")).is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
