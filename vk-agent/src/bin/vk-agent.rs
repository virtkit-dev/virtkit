#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use clap::{Parser, Subcommand};
use log::{LevelFilter, error, info};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode, WriteLogger};
use std::fs::File;
use std::path::PathBuf;
use std::time::Duration;
use vk_core::addr::SocketAddr;
use vk_core::exec::client::{Stdin, client_run_cmd, client_run_tty};
use vk_core::exec::server::{VkRoute, run_server_routed};
use vk_core::messages::RunMode;
use vk_core::messages::{CmdExec, CmdResult, Tty};
use vk_core::net::connect;
use vk_core::status::get_status;

/// Talk to, or be, the virtkit guest agent — exec, forward, network, PID 1
#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "vk-agent", version)]
struct Cli {
    /// Socket address: a unix socket path, or a systemd://, vsock*:// or tcp:// URL
    ///
    /// systemd:// is socket activation (serve only); vsock://[cid:]port; vsock-auto://path:port
    /// is a VMM's per-port socket for a guest port (connect only). tcp://host:port carries raw
    /// bytes only — a forward end, `connect` or `ssh-serve` — and the agent protocol refuses it.
    /// Required, except by `exec --service`, which defaults to the host command channel.
    #[arg(short, long, value_name = "ADDR")]
    socket: Option<SocketAddr>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run a command on the agent at --socket, or in a compose service with --service
    #[command(arg_required_else_help = true)]
    Exec {
        /// Log this client's protocol activity to this file
        #[arg(long, value_name = "PATH")]
        debug_log: Option<PathBuf>,

        /// Run it in this compose service of the VM, through its host
        ///
        /// The VM's host runs it with `vk exec --service NAME`, over the host command channel
        /// (--socket, default /run/vk/host.sock), into this VM's own services only: a CI job
        /// VM's, a `vk run --compose` primary's, a `vk dev` environment's.
        #[arg(long, value_name = "NAME", conflicts_with = "debug_log")]
        service: Option<String>,

        /// Background mode: no stdio, do not wait for the command to exit
        #[arg(short, long)]
        background: bool,

        /// Start the remote process with an empty environment
        #[arg(long)]
        clear_env: bool,

        /// Add an environment variable, syntax KEY=value (repeatable)
        #[arg(long, value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Working directory for the remote process (default: the agent's own)
        #[arg(long)]
        dir: Option<String>,

        /// Allocate a pty on the remote side and run interactively
        ///
        /// Requires the local stdin/stdout to be a terminal; incompatible with --background.
        #[arg(short = 't', long)]
        tty: bool,

        /// Run the remote process as this Unix user (drops uid/gid/groups)
        #[arg(long, value_name = "NAME")]
        user: Option<String>,

        /// Command to run
        cmd: String,

        /// Arguments for the command
        args: Vec<String>,
    },
    /// Serve the exec channel on --socket
    Serve {
        /// Log at debug level instead of info
        #[arg(short, long)]
        debug: bool,
        /// Exit after this long without an exec; 0 = never
        ///
        /// The window runs from the last exec that finished, or from startup when none has.
        /// A status probe does not reset it, and an exec still running holds it open.
        #[arg(short, long, value_name = "SECS")]
        inactivity_timeout: Option<u64>,
        /// Force every exec through this program (like SSH's ForceCommand)
        ///
        /// It receives the requested command line as its arguments and decides what to run. Use
        /// it to enforce an allowlist. It runs as serve's own user, in serve's working
        /// directory, whatever the client asks; the client's --dir reaches it as $VK_EXEC_DIR
        /// (empty when none), for it to check before entering it. Omitted = run commands
        /// directly.
        #[arg(long, value_name = "PROGRAM")]
        exec_wrapper: Option<PathBuf>,
        /// Allow these client-supplied environment variables through to --exec-wrapper
        ///
        /// Repeatable; shell-style `*`/`?` globs, e.g. `LC_*`. LANG, LANGUAGE, LC_*, TZ are
        /// always allowed; everything else the client sends is dropped so it cannot subvert the
        /// wrapper (e.g. LD_PRELOAD).
        #[arg(long, requires = "exec_wrapper", value_name = "GLOB")]
        exec_wrapper_env: Vec<String>,
        /// Give --exec-wrapper this argument first, before the requested command line
        ///
        /// Repeatable, in order. Nothing the client sends comes before these.
        #[arg(
            long,
            requires = "exec_wrapper",
            value_name = "ARG",
            allow_hyphen_values = true
        )]
        exec_wrapper_arg: Vec<String>,
        /// Force a command named exactly `vk` through this program instead of --exec-wrapper
        ///
        /// It gets the default client environment allowlist only, never --exec-wrapper-env,
        /// and runs in the foreground only. Every other command still goes through
        /// --exec-wrapper; --max-concurrent counts both together.
        #[arg(long, requires = "exec_wrapper", value_name = "PROGRAM")]
        vk_wrapper: Option<PathBuf>,
        /// Give --vk-wrapper this argument first, before the requested command line
        ///
        /// Repeatable, in order. Nothing the client sends comes before these; the requested
        /// command line follows them, `vk` included.
        #[arg(
            long,
            requires = "vk_wrapper",
            value_name = "ARG",
            allow_hyphen_values = true
        )]
        vk_wrapper_arg: Vec<String>,
        /// Run at most this many --vk-wrapper commands at once, within --max-concurrent
        ///
        /// One more is refused, not queued. Omitted = no cap of its own.
        #[arg(long, requires = "vk_wrapper", value_name = "N")]
        vk_wrapper_max_concurrent: Option<std::num::NonZeroUsize>,
        /// Run at most this many commands at once; one more is refused, not queued
        ///
        /// A background command counts until it exits. Status probes are never refused.
        /// Omitted = no cap.
        #[arg(long, value_name = "N")]
        max_concurrent: Option<std::num::NonZeroUsize>,
        /// Refuse background commands: each runs only as long as its session
        #[arg(long)]
        no_background: bool,
    },
    /// Probe the agent at --socket and print its status reply
    Status,
    /// Forward a local listener to the --socket target, splicing raw bytes
    ///
    /// Opaque — no virtkit-agent protocol. E.g. expose a guest-local TCP port that tunnels over
    /// vsock to a host-mediated service.
    Forward {
        /// Local address to listen on: tcp://host:port, a unix path, or vsock://[cid:]port
        #[arg(long, value_name = "ADDR")]
        listen: SocketAddr,
        /// For a unix `--listen`, give the bound socket to this `user[:group]`
        ///
        /// A numeric id or a guest passwd/group name, so a non-root client can open it. Ignored
        /// for tcp/vsock listeners.
        #[arg(long, value_name = "USER[:GROUP]")]
        chown: Option<String>,
    },
    /// Splice stdin/stdout to the --socket target, raw bytes — an SSH `ProxyCommand`
    ///
    /// The stdio sibling of `forward`, with no virtkit-agent protocol. Tunnels ssh to a guest
    /// sshd reached over the VMM's per-port vsock socket, so VS Code Remote-SSH attaches to the
    /// microVM with no guest network: `ProxyCommand vk-agent -s vsock-auto://…/vsock.sock:2222
    /// connect`.
    Connect,
    /// Run an SSH server (russh) on --socket, so the image needs no sshd
    ///
    /// Pubkey auth, pty/shell + exec, so a stock ssh client (hence VS Code Remote-SSH) reaches
    /// the guest over vsock. Pair with `connect` as the host ProxyCommand.
    #[cfg(feature = "ssh")]
    SshServe {
        /// public key to accept (OpenSSH format: type base64 [comment]), repeatable
        #[arg(long = "authorized-key", value_name = "PUBKEY")]
        authorized_keys: Vec<String>,

        /// run sessions as this Unix user (default: the SSH login username)
        #[arg(long, value_name = "NAME")]
        user: Option<String>,
    },
    /// PID 1 for systemd-less guests
    ///
    /// Sets up the rootfs (API mounts, hostname, DNS) then forks and supervises a `serve` agent
    /// on --socket. The guest's IP/route comes from the kernel `ip=` cmdline param, not here.
    Init {
        /// Idle seconds before the serve agent (hence the VM) exits; 0 = never
        #[arg(short, long, value_name = "SECS")]
        inactivity_timeout: Option<u64>,
    },
}

fn main() {
    // The compose control filesystem (no --socket: it dials the manager over
    // vsock itself); handled before clap since init forks it with plain args.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("ctlfs") {
        let mountpoint = args
            .get(2)
            .cloned()
            .unwrap_or_else(|| "/run/vk/services".into());
        // uid:gid to attribute the nodes to, as init resolved them from the image's USER.
        // Absent (both) means root — init always passes both, and a hand-run `ctlfs
        // <mountpoint>` wants root. Anything else — unparsable, or only one of the pair —
        // is a caller bug: defaulting it to root would hand back the very control plane
        // the run cannot write.
        let ids = match (args.get(3), args.get(4)) {
            (None, None) => (0, 0),
            (Some(uid), Some(gid)) => {
                let parse = |s: &str| {
                    s.parse::<u32>().unwrap_or_else(|_| {
                        eprintln!("vk-agent ctlfs: {s:?} is not a uid/gid");
                        std::process::exit(1);
                    })
                };
                (parse(uid), parse(gid))
            }
            _ => {
                eprintln!("vk-agent ctlfs: uid and gid must both be given, or neither");
                std::process::exit(1);
            }
        };
        if let Err(e) = vk_agent::ctlfs::run(std::path::Path::new(&mountpoint), ids) {
            eprintln!("vk-agent ctlfs: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    // Local fs freeze/thaw, no socket: the host runs `vk-agent fsfreeze -f|-u
    // <mountpoint>` in the guest over the exec channel to quiesce the root fs for a
    // consistent snapshot. Built in (vs util-linux) so it works on any guest; handled
    // before clap since it takes no --socket.
    let mut argv = std::env::args();
    if argv.nth(1).as_deref() == Some("fsfreeze") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::fsfreeze::main(&rest));
    }
    // Clean shutdown / reboot (no socket): the host runs `vk-agent poweroff` (or `reboot`) in
    // the guest before it would otherwise kill the VMM, so the filesystems reach disk intact.
    if let Some(action) = match std::env::args().nth(1).as_deref() {
        Some("poweroff") => Some(vk_agent::poweroff::Action::PowerOff),
        Some("reboot") => Some(vk_agent::poweroff::Action::Reboot),
        _ => None,
    } {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::poweroff::main(action, &rest));
    }
    // Local free-block discard (no socket): the host runs `vk-agent fstrim <mountpoint>` in
    // the guest before a checkpoint so the snapshot's allocation map lists only live data.
    if std::env::args().nth(1).as_deref() == Some("fstrim") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::fsfreeze::trim_main(&rest));
    }
    // The writable layer's high-water mark (no socket): the host runs `vk-agent fsmark` in the
    // guest at the end of a job to read how full the overlay tmpfs its writes land on ever got
    // — guest RAM, which no host counter sees.
    if std::env::args().nth(1).as_deref() == Some("fsmark") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::fsmark::main(&rest));
    }
    // A CI job's caches and artifacts (no socket): the host runs `vk-agent archive` to stream a
    // tar of what they select out of the job's tree, and `vk-agent extract` to unpack one in.
    match std::env::args().nth(1).as_deref() {
        Some("archive") => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            std::process::exit(vk_agent::archive::archive_main(&rest));
        }
        Some("extract") => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            std::process::exit(vk_agent::archive::extract_main(&rest));
        }
        _ => {}
    }
    // Peak guest memory without a socket, read by the host before stage teardown.
    if std::env::args().nth(1).as_deref() == Some("memmark") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::memmark::main(&rest));
    }
    // Expose recorded OOM kills to the host without opening a socket.
    if std::env::args().nth(1).as_deref() == Some("oomkills") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::oomkills::main(&rest));
    }
    // The idle page-cache trimmer (no socket): init forks `vk-agent reclaim <spec>` at boot
    // when the cmdline asks for it, and it gives file cache this guest stopped using back to
    // the host whenever the guest is not under memory pressure.
    if std::env::args().nth(1).as_deref() == Some("reclaim") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        install_console_logger(LevelFilter::Info); // its reports land beside init's own lines
        std::process::exit(vk_agent::reclaim::main(&rest));
    }
    // Report why the CI tools share left this guest without gitlab-runner, for the job trace.
    if std::env::args().nth(1).as_deref() == Some("tools") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::tools::main(&rest));
    }
    // The compose services of a `vk run --compose` primary or a `vk dev` environment (no
    // socket): `vk-agent service up|down|reboot|status [NAME]`, answered by the service manager.
    if std::env::args().nth(1).as_deref() == Some("service") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(guest_service(&rest));
    }
    // The run's environment (no socket), for login shells and anything else the agent did not
    // start: `vk-agent env --export|--print0|--exec`.
    if std::env::args().nth(1).as_deref() == Some("env") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::runenv::main(&rest));
    }
    // The guest statistics sampler (no socket): init forks `vk-agent atop <dir>
    // <interval_secs>` at boot when the cmdline asks for it, and it appends atop-parseable
    // samples of this guest's /proc to the host archive share until SIGUSR2.
    if std::env::args().nth(1).as_deref() == Some("atop") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(vk_agent::atop::main(&rest));
    }
    // Local block-device mount/unmount (no socket): the host attaches a source stage's
    // ext4 read-only and runs `vk-agent mount|umount …` in the guest to read it.
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("mount") | Some("umount") | Some("copy") | Some("cleanup") | Some("cleanup-pending")
    ) {
        let rest: Vec<String> = std::env::args().skip(1).collect();
        std::process::exit(vk_agent::diskmount::main(&rest));
    }
    // PID 1: the guest was booted `init=/usr/local/bin/vk-agent` (a systemd-less
    // image). The kernel/initramfs passes no usable argv, so bypass clap entirely
    // and derive the vsock socket from the kernel cmdline. Equivalent to the
    // explicit `init` subcommand below, minus the argument plumbing.
    if std::process::id() == 1 {
        init_main(vk_agent::init::socket_from_cmdline(), None);
        return;
    }
    let cli_args = Cli::parse();
    if let Some((argv, tty)) = service_exec_request(&cli_args.command) {
        std::process::exit(service_exec(cli_args.socket, argv, tty));
    }
    let Some(socket) = cli_args.socket else {
        <Cli as clap::CommandFactory>::command()
            .error(
                clap::error::ErrorKind::MissingRequiredArgument,
                "--socket is required",
            )
            .exit()
    };
    // PID 1 init is synchronous (it forks + reaps): handle it before any tokio
    // runtime exists. Every other subcommand runs on a runtime.
    if let Commands::Init { inactivity_timeout } = cli_args.command {
        init_main(socket, inactivity_timeout);
        return;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("building the tokio runtime")
        .block_on(async_main(socket, cli_args.command));
}

/// The host command channel a guest reaches its host through.
const HOST_SOCK: &str = "/run/vk/host.sock";

/// Build the host request for `vk-agent exec --service` and its pty flag. The channel accepts
/// only `vk exec --service NAME … -- CMD…`; the host routes on the leading `vk`.
/// Return `None` for any other command.
fn service_exec_request(command: &Commands) -> Option<(Vec<String>, bool)> {
    let Commands::Exec {
        service: Some(service),
        background,
        clear_env,
        env,
        dir,
        tty,
        user,
        cmd,
        args,
        debug_log: _,
    } = command
    else {
        return None;
    };
    let mut argv = ["vk", "exec", "--service", service]
        .map(String::from)
        .to_vec();
    for (set, flag) in [
        (*background, "--background"),
        (*tty, "--tty"),
        (*clear_env, "--clear-env"),
    ] {
        if set {
            argv.push(flag.to_string());
        }
    }
    for (flag, value) in [("--user", user), ("--dir", dir)] {
        if let Some(value) = value {
            argv.extend([flag.to_string(), value.clone()]);
        }
    }
    for e in env {
        argv.extend(["--env".to_string(), e.clone()]);
    }
    argv.push("--".to_string());
    argv.push(cmd.clone());
    argv.extend(args.iter().cloned());
    Some((argv, *tty))
}

/// Why `vk-agent exec --service` without --socket cannot reach the host command channel.
const NO_HOST_CHANNEL: &str = "this VM has no host command channel: `exec --service` is for CI \
                               jobs, `vk run --compose` primaries and `vk dev` environments \
                               with compose services";

/// Why a guest whose kernel command line is `cmdline` (`None`: unreadable) cannot reach its
/// services over the default host command channel, or `None` when it can: a guest without
/// service exec is told why, one that is not a vk guest that it has no channel.
fn no_default_service_exec(cmdline: Option<&str>) -> Option<&'static str> {
    match cmdline.and_then(vk_core::service_exec::from_cmdline) {
        Some(true) => None,
        Some(false) => Some(vk_core::service_exec::NO_SERVICE_EXEC),
        None => Some(NO_HOST_CHANNEL),
    }
}

/// `vk-agent exec --service`: `argv` run by the VM's host over its host command channel at
/// `socket`, by default [`HOST_SOCK`] once the kernel command line says the host serves it.
/// Its exit status, or 1 when the host cannot be reached.
fn service_exec(socket: Option<SocketAddr>, argv: Vec<String>, tty: bool) -> i32 {
    let default = socket.is_none();
    if default
        && let Some(why) =
            no_default_service_exec(std::fs::read_to_string("/proc/cmdline").ok().as_deref())
    {
        eprintln!("vk-agent: {why}");
        return 1;
    }
    // Service exec on, yet no socket: the init's forward to the host never started.
    if default && std::fs::symlink_metadata(HOST_SOCK).is_err() {
        eprintln!(
            "vk-agent: the host command channel {HOST_SOCK} is missing: its forward did not \
             start (see the boot log)"
        );
        return 1;
    }
    let socket = socket.unwrap_or_else(|| SocketAddr::Unix(HOST_SOCK.into()));
    let mut argv = argv.into_iter();
    let name = argv.next().unwrap_or_default();
    // A pty only when asked for (it merges stderr into stdout), and only on a terminal.
    // SAFETY: isatty on the inherited stdio fds.
    let tty = (tty && unsafe { libc::isatty(0) } == 1 && unsafe { libc::isatty(1) } == 1)
        .then(Tty::local);
    let ran = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("building the tokio runtime")
        .block_on(execute(
            socket,
            name,
            argv.collect(),
            false,
            Vec::new(),
            RunMode::Interactive,
            None,
            tty,
            None,
        ));
    match ran {
        Ok(result) => {
            if let Some(code) = result.code {
                return code;
            }
            if let Some(signal) = result.signal {
                // SAFETY: re-raise the command's terminating signal on this process.
                unsafe { libc::kill(std::process::id() as i32, signal) };
                return 128 + signal;
            }
            0
        }
        Err(e) => {
            eprintln!("vk-agent: {e:#}");
            1
        }
    }
}

/// `vk-agent service OP [NAME]`: the service manager's answer to `args`.
fn guest_service(args: &[String]) -> i32 {
    use vk_core::fleetctl::{Client, NoManager, SERVICE_USAGE, ServiceOp};
    let Some(op) = ServiceOp::parse(args) else {
        eprintln!("{SERVICE_USAGE}");
        return 2;
    };
    let reply = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("building the tokio runtime")
        .block_on(op.run(&mut Client::new()));
    match reply {
        Ok(reply) => {
            reply.print();
            if reply.ok { 0 } else { 1 }
        }
        Err(e) if e.downcast_ref::<NoManager>().is_some() => {
            eprintln!(
                "vk-agent: {e:#}\nvk-agent: `service` needs a service manager, which a `vk run \
                 --compose` primary has; a CI job's services are fixed for the job"
            );
            1
        }
        Err(e) => {
            eprintln!("vk-agent: {e:#}");
            1
        }
    }
}

/// Configure logging for PID 1 and the long-running `serve`, `forward` and `ssh-serve`
/// subcommands. They write to stdout: the guest console is captured in the host's
/// `console.log`, while the host-side `--host-exec` server writes to a dedicated log.
///
/// The default format starts with `HH:MM:SS [LEVEL] ` in UTC. Debug records then add the
/// thread ID and module. Force uncoloured output because the guest console is a terminal but
/// its output is consumed as a file. Keep this prefix stable for `console.log` consumers.
fn install_console_logger(level: LevelFilter) {
    // Initialization fails only if another logger is already registered. Each process calls
    // this once; PID 1 should keep running if that invariant breaks.
    TermLogger::init(
        level,
        Config::default(),
        TerminalMode::Stdout,
        ColorChoice::Never,
    )
    .ok();
}

fn init_main(socket: SocketAddr, inactivity_timeout: Option<u64>) {
    install_console_logger(LevelFilter::Info);
    // Zero (no watchdog) is resolved inside run_init, together with the kernel-cmdline
    // fallback it takes precedence over: filtering it here would instead let the cmdline win.
    if let Err(e) = vk_agent::init::run_init(&socket, inactivity_timeout) {
        error!("init: {e:#}");
        std::process::exit(1);
    }
}

async fn async_main(socket: SocketAddr, command: Commands) {
    match command {
        Commands::Exec {
            debug_log,
            service: _,
            cmd,
            args,
            clear_env,
            env,
            background,
            dir,
            tty,
            user,
        } => {
            if let Some(log_path) = debug_log {
                let _ = WriteLogger::init(
                    LevelFilter::Debug,
                    Config::default(),
                    File::create(log_path).unwrap(),
                );
            }
            // the server silently skips entries without '=': reject them up front
            if let Some(bad) = env.iter().find(|e| !e.contains('=')) {
                eprintln!("error: invalid --env '{bad}' (expected KEY=value)");
                std::process::exit(2);
            }
            let mode = if background {
                RunMode::Background
            } else {
                RunMode::Interactive
            };
            let tty = if tty {
                if background {
                    eprintln!("error: --tty is incompatible with --background");
                    std::process::exit(2);
                }
                if unsafe { libc::isatty(0) } != 1 || unsafe { libc::isatty(1) } != 1 {
                    eprintln!("error: --tty requires stdin and stdout to be a terminal");
                    std::process::exit(2);
                }
                Some(Tty::local())
            } else {
                None
            };
            match execute(socket, cmd, args, clear_env, env, mode, dir, tty, user).await {
                Ok(p) => {
                    if let Some(code) = p.code {
                        std::process::exit(code)
                    }
                    if let Some(signal) = p.signal {
                        info!("killing self with signal {signal}");
                        unsafe {
                            libc::kill(std::process::id() as i32, signal);
                        };
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
        }
        Commands::Status => {
            match get_status(&socket).await {
                Ok(status) => println!("got status: {status}"),
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1)
                }
            };
        }
        Commands::Serve {
            debug,
            inactivity_timeout,
            exec_wrapper,
            exec_wrapper_env,
            exec_wrapper_arg,
            vk_wrapper,
            vk_wrapper_arg,
            vk_wrapper_max_concurrent,
            max_concurrent,
            no_background,
        } => {
            let log_level = if debug {
                LevelFilter::Debug
            } else {
                LevelFilter::Info
            };
            install_console_logger(log_level);
            // run_server_routed reads a zero timeout as no timeout, so it needs no filtering here.
            let duration = inactivity_timeout.map(Duration::from_secs);
            if let Err(e) = run_server_routed(
                &socket,
                duration,
                exec_wrapper,
                exec_wrapper_env,
                exec_wrapper_arg,
                vk_wrapper.map(|path| VkRoute {
                    path,
                    args: vk_wrapper_arg,
                    max_concurrent: vk_wrapper_max_concurrent,
                }),
                vk_core::exec::server::Limits {
                    max_concurrent,
                    background: !no_background,
                    ..Default::default()
                },
            )
            .await
            {
                error!("run_server_routed: {e}");
                std::process::exit(1)
            };
        }
        Commands::Forward { listen, chown } => {
            install_console_logger(LevelFilter::Info);
            let chown = match chown.as_deref().map(vk_agent::diskmount::parse_chown) {
                Some(Ok(ids)) => Some(ids),
                Some(Err(e)) => {
                    error!("forward: --chown: {e:#}");
                    std::process::exit(1)
                }
                None => None,
            };
            if let Err(e) = vk_core::forward::run_forward(&listen, &socket, chown, None).await {
                error!("forward: {e:#}");
                std::process::exit(1)
            }
        }
        Commands::Connect => {
            // stdout carries the raw SSH byte stream — never init a logger on it.
            // Errors go to stderr, which ssh surfaces to the user as ProxyCommand
            // output.
            if let Err(e) = vk_core::forward::run_connect(&socket).await {
                eprintln!("connect: {e:#}");
                std::process::exit(1)
            }
        }
        #[cfg(feature = "ssh")]
        Commands::SshServe {
            authorized_keys,
            user,
        } => {
            install_console_logger(LevelFilter::Info);
            let keys = vk_agent::ssh::parse_authorized_keys(authorized_keys.as_slice());
            if let Err(e) = vk_agent::ssh::run_ssh_server(&socket, &keys, user).await {
                error!("ssh-serve: {e:#}");
                std::process::exit(1)
            }
        }
        // handled synchronously in main(), before the runtime is built
        Commands::Init { .. } => unreachable!(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn execute(
    socket: SocketAddr,
    cmd: String,
    args: Vec<String>,
    clear_env: bool,
    env: Vec<String>,
    mode: RunMode,
    dir: Option<String>,
    tty: Option<Tty>,
    user: Option<String>,
) -> Result<CmdResult, anyhow::Error> {
    let (stream, sink) = connect(&socket).await?;

    info!("Connected to {socket}");

    let exec = CmdExec {
        name: cmd,
        args,
        clear_env,
        env,
        mode,
        dir,
        tty,
        user,
    };
    if exec.tty.is_some() {
        client_run_tty(stream, sink, exec).await
    } else {
        client_run_cmd(stream, sink, exec, Stdin::Forward).await
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, NO_HOST_CHANNEL, no_default_service_exec, service_exec_request};

    /// `exec --service` asks the host for the service exec form, `vk exec --service`, `vk`
    /// first, its flags before the `--` and the command after it, a `-t` in the command
    /// left there; a plain exec asks nothing of it.
    #[test]
    fn exec_service_asks_the_host_for_the_service_exec_form() {
        use clap::Parser;
        let asked = |a: &[&str]| {
            let cli = Cli::try_parse_from(a).unwrap();
            service_exec_request(&cli.command).map(|(argv, tty)| (argv, tty, cli.socket.is_none()))
        };
        let (argv, tty, default_socket) = asked(&[
            "vk-agent",
            "exec",
            "--service",
            "db",
            "-t",
            "--user",
            "pg",
            "--env",
            "A=1",
            "--",
            "ls",
            "-t",
        ])
        .unwrap();
        assert_eq!(
            argv,
            [
                "vk",
                "exec",
                "--service",
                "db",
                "--tty",
                "--user",
                "pg",
                "--env",
                "A=1",
                "--",
                "ls",
                "-t"
            ]
        );
        assert!(tty);
        assert!(default_socket);
        let (argv, tty, _) = asked(&["vk-agent", "exec", "--service", "db", "--", "-x"]).unwrap();
        assert_eq!(argv, ["vk", "exec", "--service", "db", "--", "-x"]);
        assert!(!tty);
        let (_, _, default_socket) = asked(&[
            "vk-agent",
            "-s",
            "/tmp/h.sock",
            "exec",
            "--service",
            "db",
            "--",
            "true",
        ])
        .unwrap();
        assert!(!default_socket);
        assert_eq!(
            asked(&["vk-agent", "-s", "/tmp/a.sock", "exec", "true"]),
            None
        );
        // --debug-log is not taken with --service.
        assert!(
            Cli::try_parse_from([
                "vk-agent",
                "exec",
                "--service",
                "db",
                "--debug-log",
                "/tmp/log",
                "--",
                "true",
            ])
            .is_err()
        );
    }

    /// Without --socket, `exec --service` dials the host command channel only when the kernel
    /// command line says the host serves this VM's services, `VIRTKIT_SERVICE_EXEC=1`; a vk
    /// guest without it is told why, anything else that it has no channel.
    #[test]
    fn exec_service_needs_service_exec_on_the_cmdline() {
        assert_eq!(
            no_default_service_exec(Some("VIRTKIT_VSOCK_PORT=4444 VIRTKIT_SERVICE_EXEC=1")),
            None
        );
        assert_eq!(
            no_default_service_exec(Some("VIRTKIT_VSOCK_PORT=4444 VIRTKIT_HOST_EXEC_PORT=1100")),
            Some(vk_core::service_exec::NO_SERVICE_EXEC)
        );
        assert_eq!(
            no_default_service_exec(Some("VIRTKIT_SERVICE_EXEC=0")),
            Some(vk_core::service_exec::NO_SERVICE_EXEC)
        );
        assert_eq!(
            no_default_service_exec(Some("root=/dev/sda1 quiet")),
            Some(NO_HOST_CHANNEL)
        );
        assert_eq!(no_default_service_exec(None), Some(NO_HOST_CHANNEL));
    }

    // `-h` is a summary: a short line per command, per flag and per possible value, with
    // the detail in the doc comment's second paragraph (which clap shows as `--help`). A
    // one-paragraph doc comment is both, so it lands in `-h` in full — this is what
    // catches that. It also catches the opposite slip, an entry with no help at all.
    // Short is not the same as one rendered line: clap appends `[default: …]` and
    // `[possible values: …]`, and lays wide groups out on a second line regardless.
    // Mirrors `vk-driver`'s test of the same name.
    #[test]
    fn help_summaries_stay_short() {
        // The same budget as `vk`'s copy of this test: an 80-column terminal plus a
        // little slack (the longest entry here is 79).
        const LIMIT: usize = 84;

        // Every `-h` entry of `cmd` and, recursively, of its subcommands: the command's
        // own about, each argument's help, and each possible value's help.
        fn collect(path: &str, cmd: &clap::Command, out: &mut Vec<(String, Option<usize>)>) {
            out.push((format!("{path} about"), summary_len(cmd.get_about())));
            for arg in cmd.get_arguments() {
                let name = match arg.get_long() {
                    Some(long) => format!("--{long}"),
                    None => format!("<{}>", arg.get_id()),
                };
                out.push((format!("{path} {name}"), summary_len(arg.get_help())));
                // A bool flag carries synthetic true/false values clap never prints;
                // only an arg that takes a value gets a `[possible values: …]` line.
                let is_bool_flag = matches!(
                    arg.get_action(),
                    clap::ArgAction::SetTrue | clap::ArgAction::SetFalse
                );
                if !is_bool_flag {
                    for value in arg.get_possible_values() {
                        let what = format!("{path} {name}={}", value.get_name());
                        out.push((what, summary_len(value.get_help())));
                    }
                }
            }
            for sub in cmd.get_subcommands() {
                collect(&format!("{path} {}", sub.get_name()), sub, out);
            }
        }
        fn summary_len(text: Option<&clap::builder::StyledStr>) -> Option<usize> {
            Some(text?.to_string().chars().count())
        }

        let mut entries = Vec::new();
        collect(
            "vk-agent",
            &<Cli as clap::CommandFactory>::command(),
            &mut entries,
        );
        let bad: Vec<_> = entries
            .into_iter()
            .filter_map(|(what, len)| match len {
                Some(len) if len > LIMIT => Some(format!("{what}: {len} chars")),
                None => Some(format!("{what}: no help")),
                Some(_) => None,
            })
            .collect();
        assert!(
            bad.is_empty(),
            "help entries over {LIMIT} chars or missing:\n  {}",
            bad.join("\n  ")
        );
    }
}
