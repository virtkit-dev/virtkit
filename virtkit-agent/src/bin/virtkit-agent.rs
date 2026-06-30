#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

use clap::{Parser, Subcommand};
use log::{LevelFilter, error, info};
use simplelog::{ColorChoice, Config, TermLogger, TerminalMode, WriteLogger};
use std::fs::File;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::time::Duration;
use virtkit_agent::addr::SocketAddr;
use virtkit_agent::exec::client::{client_run_cmd, client_run_tty};
use virtkit_agent::exec::server::run_server;
use virtkit_agent::messages::RunMode;
use virtkit_agent::messages::{CmdExec, CmdResult, Tty};
use virtkit_agent::net::connect;
use virtkit_agent::status::get_status;

#[derive(Debug, Parser)] // requires `derive` feature
#[command(name = "virtkit-agent", version)]
#[command(about = "send / execute commands through unix or vsock sockets", long_about = None)]
struct Cli {
    /// Socket address: a unix socket path, systemd:// (socket activation, serve
    /// only), vsock://[cid:]port, or vsock-mux://path:port (hybrid vsock unix
    /// socket of a Cloud Hypervisor / Firecracker VMM, connect only)
    #[arg(short, long)]
    socket: SocketAddr,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Execute command
    #[command(arg_required_else_help = true)]
    Exec {
        /// Optional debug log
        #[arg(long)]
        debug_log: Option<PathBuf>,

        /// Backgound mode (no stdin/stdout/stderr, do not wait process end)
        #[arg(short, long)]
        background: bool,

        /// Start remote process with an empty environment
        #[arg(long)]
        clear_env: bool,

        /// Add environment variable, syntax KEY=value (can be used multiple times)
        #[arg(long)]
        env: Vec<String>,

        /// Working directory
        /// If not set, the working directory is the same as the server
        #[arg(long)]
        dir: Option<String>,

        /// Allocate a pty on the remote side and run interactively (requires the
        /// local stdin/stdout to be a terminal; incompatible with --background)
        #[arg(short = 't', long)]
        tty: bool,

        /// Run the remote process as this Unix user (drops uid/gid/groups)
        #[arg(long)]
        user: Option<String>,

        /// Command to run
        cmd: String,

        /// Arguments
        args: Vec<String>,
    },
    Serve {
        #[arg(short, long)]
        debug: bool,
        #[arg(short, long)]
        inactivity_timeout: Option<u64>,
        /// Force every exec through this program (like SSH's ForceCommand): it
        /// receives the requested command line as its arguments and decides what to
        /// run. Use it to enforce an allowlist. Omitted = run commands directly.
        #[arg(long)]
        exec_wrapper: Option<PathBuf>,
        /// Allow these client-supplied environment variables through to the
        /// --exec-wrapper (repeatable; shell-style `*`/`?` globs, e.g. `LC_*`).
        /// LANG, LANGUAGE, LC_*, TZ are always allowed; everything else the client
        /// sends is dropped so it cannot subvert the wrapper (e.g. LD_PRELOAD).
        #[arg(long, requires = "exec_wrapper")]
        exec_wrapper_env: Vec<String>,
    },
    Status,
    /// Forward a local listener to the --socket target, splicing raw bytes
    /// (opaque — no virtkit-agent protocol). E.g. expose a guest-local TCP port that
    /// tunnels over vsock to a host-mediated service.
    Forward {
        /// Local address to listen on: tcp://host:port, a unix socket path, or
        /// vsock://[cid:]port
        #[arg(long)]
        listen: SocketAddr,
    },
    /// Splice stdin/stdout to the --socket target, raw bytes (no virtkit-agent
    /// protocol) — the stdio sibling of `forward`, meant to be an SSH
    /// `ProxyCommand`. Tunnels ssh to a guest sshd reached over the hybrid
    /// vsock-mux so VS Code Remote-SSH attaches to the microVM with no guest
    /// network:
    ///   ProxyCommand virtkit-agent -s vsock-mux://…/vsock.sock:2222 connect
    Connect,
    /// Bridge a guest tap NIC to a host network backend (gvproxy) over --socket,
    /// using the qemu vhost framing (BE32 length + ethernet frame). The guest
    /// gets a real L2 interface on the shared fleet LAN with no host privileges:
    /// the backend runs unprivileged on the host and egresses via host sockets.
    /// Addressing (IP/route/DNS) is configured separately. E.g.:
    ///   virtkit-agent -s vsock://1024 net --iface eth0
    Net {
        /// tap interface to create and bring up
        #[arg(long, default_value = "eth0")]
        iface: String,
    },
    /// Run an SSH server (russh) on --socket — pubkey auth, pty/shell + exec — so
    /// a stock ssh client (hence VS Code Remote-SSH) reaches the guest over vsock
    /// with no sshd in the image. Pair with `connect` as the host ProxyCommand.
    #[cfg(feature = "ssh")]
    SshServe {
        /// public key to accept (OpenSSH format: type base64 [comment]), repeatable
        #[arg(long = "authorized-key", value_name = "PUBKEY")]
        authorized_keys: Vec<String>,

        /// run sessions as this Unix user (default: the SSH login username)
        #[arg(long)]
        user: Option<String>,
    },
    /// PID 1 for systemd-less guests: set up the rootfs (API mounts, hostname,
    /// DNS) then fork and supervise a `serve` agent on --socket. The guest's
    /// IP/route comes from the kernel `ip=` cmdline param, not here.
    Init {
        /// Idle seconds before the serve agent (hence the VM) exits; 0 = never.
        #[arg(short, long)]
        inactivity_timeout: Option<u64>,
    },
}

fn main() {
    // Multi-call binary: invoked through the `virtctl` symlink, it is the fleet
    // control client (talks to the manager over vsock) — no --socket, its own args.
    let argv0 = std::env::args().next().unwrap_or_default();
    if std::path::Path::new(&argv0)
        .file_name()
        .and_then(|s| s.to_str())
        == Some("virtctl")
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("building the tokio runtime");
        if let Err(e) = rt.block_on(virtkit_agent::fleetctl::run_client(&args)) {
            eprintln!("virtctl: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    // Local fs freeze/thaw, no socket: the host runs `virtkit-agent fsfreeze -f|-u
    // <mountpoint>` in the guest over the exec channel to quiesce the root fs for a
    // consistent snapshot. Built in (vs util-linux) so it works on any guest; handled
    // before clap since it takes no --socket.
    let mut argv = std::env::args();
    if argv.nth(1).as_deref() == Some("fsfreeze") {
        let rest: Vec<String> = std::env::args().skip(2).collect();
        std::process::exit(virtkit_agent::fsfreeze::main(&rest));
    }
    // Local block-device mount/unmount (no socket): the host attaches a source stage's
    // ext4 read-only and runs `virtkit-agent mount|umount …` in the guest to read it.
    if matches!(
        std::env::args().nth(1).as_deref(),
        Some("mount") | Some("umount") | Some("copy") | Some("cleanup")
    ) {
        let rest: Vec<String> = std::env::args().skip(1).collect();
        std::process::exit(virtkit_agent::diskmount::main(&rest));
    }
    // PID 1: the guest was booted `init=/usr/local/bin/virtkit-agent` (a systemd-less
    // image). The kernel/initramfs passes no usable argv, so bypass clap entirely
    // and derive the vsock socket from the kernel cmdline. Equivalent to the
    // explicit `init` subcommand below, minus the argument plumbing.
    if std::process::id() == 1 {
        init_main(virtkit_agent::init::socket_from_cmdline(), None);
        return;
    }
    let cli_args = Cli::parse();
    let socket = cli_args.socket;
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

fn init_main(socket: SocketAddr, inactivity_timeout: Option<u64>) {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Stdout,
        if std::io::stdout().is_terminal() {
            ColorChoice::Auto
        } else {
            ColorChoice::Never
        },
    )
    .ok();
    let timeout = inactivity_timeout.filter(|t| *t > 0);
    if let Err(e) = virtkit_agent::init::run_init(&socket, timeout) {
        error!("init: {e:#}");
        std::process::exit(1);
    }
}

async fn async_main(socket: SocketAddr, command: Commands) {
    match command {
        Commands::Exec {
            debug_log,
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
                // (0, 0) = terminal that does not report a size: pick a sane default
                let (rows, cols) = match virtkit_agent::pty::get_winsize(0) {
                    Ok((0, 0)) | Err(_) => (24, 80),
                    Ok(size) => size,
                };
                Some(Tty {
                    term: std::env::var("TERM").ok(),
                    rows,
                    cols,
                })
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
        } => {
            let log_level = if debug {
                LevelFilter::Debug
            } else {
                LevelFilter::Info
            };
            TermLogger::init(
                log_level,
                Config::default(),
                TerminalMode::Stdout,
                if std::io::stdout().is_terminal() {
                    ColorChoice::Auto
                } else {
                    ColorChoice::Never
                },
            )
            .unwrap();
            let duration: Option<Duration> = if let Some(timeout) = inactivity_timeout {
                if timeout > 0 {
                    Some(Duration::from_secs(timeout))
                } else {
                    None
                }
            } else {
                None
            };
            if let Err(e) = run_server(&socket, duration, exec_wrapper, exec_wrapper_env).await {
                error!("run_server: {e}");
                std::process::exit(1)
            };
        }
        Commands::Forward { listen } => {
            TermLogger::init(
                LevelFilter::Info,
                Config::default(),
                TerminalMode::Stdout,
                if std::io::stdout().is_terminal() {
                    ColorChoice::Auto
                } else {
                    ColorChoice::Never
                },
            )
            .unwrap();
            if let Err(e) = virtkit_agent::forward::run_forward(&listen, &socket).await {
                error!("forward: {e:#}");
                std::process::exit(1)
            }
        }
        Commands::Connect => {
            // stdout carries the raw SSH byte stream — never init a logger on it.
            // Errors go to stderr, which ssh surfaces to the user as ProxyCommand
            // output.
            if let Err(e) = virtkit_agent::forward::run_connect(&socket).await {
                eprintln!("connect: {e:#}");
                std::process::exit(1)
            }
        }
        Commands::Net { iface } => {
            TermLogger::init(
                LevelFilter::Info,
                Config::default(),
                TerminalMode::Stdout,
                if std::io::stdout().is_terminal() {
                    ColorChoice::Auto
                } else {
                    ColorChoice::Never
                },
            )
            .unwrap();
            if let Err(e) = virtkit_agent::tap::run_net(&socket, &iface).await {
                error!("net: {e:#}");
                std::process::exit(1)
            }
        }
        #[cfg(feature = "ssh")]
        Commands::SshServe {
            authorized_keys,
            user,
        } => {
            TermLogger::init(
                LevelFilter::Info,
                Config::default(),
                TerminalMode::Stdout,
                if std::io::stdout().is_terminal() {
                    ColorChoice::Auto
                } else {
                    ColorChoice::Never
                },
            )
            .unwrap();
            let keys = virtkit_agent::ssh::parse_authorized_keys(authorized_keys.as_slice());
            if let Err(e) = virtkit_agent::ssh::run_ssh_server(&socket, &keys, user).await {
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
        client_run_cmd(stream, sink, exec).await
    }
}
