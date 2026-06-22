//! gitlab-runner custom executor running each CI job in a throwaway Cloud Hypervisor
//! microVM.
//!
//! Wire-up in /etc/gitlab-runner/config.toml:
//!   [runners.custom]
//!     config_exec   = "/usr/local/bin/virtkit"
//!     config_args   = ["gitlab", "config"]
//!     prepare_exec  = "/usr/local/bin/virtkit"
//!     prepare_args  = ["gitlab", "prepare"]
//!     run_exec      = "/usr/local/bin/virtkit"
//!     run_args      = ["gitlab", "run"]
//!     cleanup_exec  = "/usr/local/bin/virtkit"
//!     cleanup_args  = ["gitlab", "cleanup"]

#[cfg(target_env = "musl")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

mod config;
mod convert;
mod cpio;
mod dockerhash;
mod ensure;
mod ext4;
mod fleet;
mod image;
mod initramfs;
mod jobctx;
mod launch;
mod net;
mod oci;
mod run;
mod services;
mod source;
mod switch;
#[cfg(feature = "virtiofsd")]
mod virtiofsd;
mod vm;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use virtkit_agent::addr::SocketAddr;

use crate::config::Config;
use crate::jobctx::JobCtx;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum GitlabCmd {
    /// config_exec: describe the driver to gitlab-runner (JSON on stdout)
    Config,
    /// prepare_exec: boot the job's microVM, wait for the in-guest agent
    Prepare,
    /// run_exec: run one stage script inside the VM
    Run {
        script: PathBuf,
        /// Stage name (prepare_script, get_sources, build_script, ...), unused
        stage: Option<String>,
    },
    /// cleanup_exec: stop the VM and remove the job state (idempotent)
    Cleanup,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// GitLab custom-executor lifecycle (config / prepare / run / cleanup)
    Gitlab {
        #[command(subcommand)]
        cmd: GitlabCmd,
    },
    /// Host side of a forward (companion of `virtkit-agent forward`): accept on
    /// `--listen` and splice each connection to `--to`, opaque to the protocol.
    /// Long-running, spawned detached per job — e.g. the VMM's per-port vsock
    /// unix socket -> a host-local service the guest must not reach directly.
    Forward {
        /// Local address to listen on (a unix socket path, tcp://host:port, ...)
        #[arg(long)]
        listen: SocketAddr,
        /// Target each accepted connection is spliced to
        #[arg(long)]
        to: SocketAddr,
    },
    /// Userspace L2 network gateway for microVM(s) — the fleet switch. Accepts the
    /// qemu vhost transport on each VM's hybrid-vsock guest-port socket, answers
    /// ARP + serves DHCP, and proxies guest TCP/UDP out through the host's own
    /// sockets — no host privileges, multi-VM on one LAN. Replaces gvproxy.
    Switch {
        /// VM qemu socket(s) to accept on (Cloud Hypervisor's <vsock.sock>_<port>);
        /// repeatable — one per VM on the shared LAN.
        #[arg(long = "listen", required = true)]
        listen: Vec<PathBuf>,
        /// Gateway IPv4 — also the DHCP server and DNS address.
        #[arg(long, default_value = "192.168.127.1")]
        gateway: std::net::Ipv4Addr,
        /// Subnet prefix length.
        #[arg(long, default_value_t = 24)]
        prefix: u8,
        /// fleet name the gateway resolver answers locally: name=ip (repeatable)
        #[arg(long = "host")]
        host: Vec<String>,
    },
    /// Orchestrate a fleet of microVMs on one shared LAN: ensure each ext4 is current,
    /// run the switch in-process, and boot the service VMs (init=service-vm-init,
    /// static *.lan addresses) plus the builder (--builder; init=builder-vm-init,
    /// DHCP, virtiofs /workdir + git worktree). --listen adds any extra VM's vsock.
    Fleet {
        #[arg(long, default_value = "192.168.127.1")]
        gateway: std::net::Ipv4Addr,
        #[arg(long, default_value_t = 24)]
        prefix: u8,
        #[arg(long, default_value_t = 1024)]
        net_port: u32,
        /// fleet host map for /etc/hosts (name=ip,...), passed to the guests
        #[arg(long)]
        hosts: Option<String>,
        #[arg(long, default_value = "/usr/local/lib/virtkit/vmlinux")]
        kernel: PathBuf,
        #[arg(long, default_value = "cloud-hypervisor")]
        cloud_hypervisor: PathBuf,
        /// extra vsock socket(s) the switch should also listen on (e.g. the builder's)
        #[arg(long = "listen")]
        listen: Vec<PathBuf>,
        /// service VM to boot: name:ext4:ip/cidr:cid (repeatable)
        #[arg(long = "service")]
        service: Vec<String>,
        /// build-service-image.sh to (re)build a stale/missing service ext4
        #[arg(long)]
        service_build: Option<PathBuf>,
        /// docker image a service ext4 is built from: name=ref (repeatable)
        #[arg(long = "service-image")]
        service_image: Vec<String>,
        /// the agent binary baked into the images as PID 1 — part of each ext4's
        /// build fingerprint (required when --builder-build/--service-build is used)
        #[arg(long)]
        agent: Option<PathBuf>,
        /// ensure the ext4 images are current (build the stale ones) and exit, without
        /// starting the switch or booting any VM
        #[arg(long)]
        ensure_only: bool,
        /// builder ext4 to boot in-process (omit to boot the builder separately)
        #[arg(long)]
        builder: Option<PathBuf>,
        /// build-builder-image.sh to (re)build a stale/missing builder ext4
        #[arg(long)]
        builder_build: Option<PathBuf>,
        /// builder hostname
        #[arg(long, default_value = "builder")]
        builder_name: String,
        /// host dir shared rw as /workdir in the builder [current dir]
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// builder's git dir to share at the same guest path (worktree); derived from
        /// the workdir when omitted
        #[arg(long)]
        git_dir: Option<PathBuf>,
        /// builder vsock CID
        #[arg(long, default_value_t = 3)]
        builder_cid: u32,
        /// builder vCPUs
        #[arg(long, default_value_t = 4)]
        builder_cpus: u32,
        /// builder RAM
        #[arg(long, default_value = "8G")]
        builder_mem: String,
    },
    /// Dev: boot a (generic, kernel-less) docker image as a microVM — cpio
    /// initramfs in RAM, virtkit-agent as PID 1, vsock — with no gitlab-runner and
    /// no assembly tools. Only docker (rootfs/kernel source) + cloud-hypervisor.
    Launch {
        /// Image to boot (docker ref, or OCI reference with --oci), e.g. alpine:3.20
        image: String,
        /// Pinned guest kernel (the pinned vmlinux: virtio + ext4 built in)
        #[arg(long, default_value = "/usr/local/lib/virtkit/vmlinux")]
        kernel: PathBuf,
        /// Pull the rootfs from a registry (no docker daemon)
        #[arg(long)]
        oci: bool,
        /// PEM CA bundle the registry TLS cert chains to (with --oci)
        #[arg(long)]
        ca: Option<PathBuf>,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        /// plain HTTP registry (with --oci)
        #[arg(long)]
        insecure: bool,
        /// Static (musl) virtkit-agent injected as PID 1
        #[arg(long = "agent", default_value = "/usr/local/lib/virtkit/virtkit-agent")]
        agent: PathBuf,
        /// cloud-hypervisor binary
        #[arg(long, default_value = "cloud-hypervisor")]
        cloud_hypervisor: PathBuf,
        #[arg(long, default_value_t = 2)]
        cpus: u32,
        #[arg(long, default_value = "1G")]
        mem: String,
        #[arg(long, default_value_t = 120)]
        boot_timeout: u64,
        /// Boot from a native ext4 disk instead of a cpio initramfs
        #[arg(long)]
        disk: bool,
        /// Drop into an interactive shell in the guest (requires a terminal);
        /// ignores any trailing command
        #[arg(long)]
        shell: bool,
        /// Command to run in the guest (default: a boot-info probe)
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// Compute the content hash of Dockerfile stages (so a stage resolves to the
    /// image tag an external build pipeline produced). Prints `stage:hash` lines.
    /// Multiple -f flags are merged; cross-file stage deps fold transitively.
    DockerHash {
        /// Dockerfile(s) to analyze (repeatable; default: Dockerfile)
        #[arg(short = 'f', long = "file", default_value = "Dockerfile")]
        dockerfile: Vec<PathBuf>,
        /// Build arg affecting the hash (KEY=VAL), repeatable
        #[arg(long = "build-arg")]
        build_arg: Vec<String>,
        /// Regex of stages to exclude from analysis, repeatable
        #[arg(long)]
        blacklist: Vec<String>,
        /// Stages to print (default: all, in definition order)
        stages: Vec<String>,
    },
    /// Dev: build an ext4 image from a directory tree (native, no mke2fs).
    Mkext { src: PathBuf, out: PathBuf },
    /// Build an ext4 image from a rootfs tar (e.g. `docker export`), injecting
    /// host files at guest paths. Native, no mke2fs, no root.
    MkextTar {
        /// rootfs tar (ownership/mode from its headers), or "-" to STREAM stdin
        /// (e.g. `docker export | … -`) — single pass, no intermediate tar
        tar: PathBuf,
        /// output ext4 image
        out: PathBuf,
        /// inject a host file at a guest path, HOST:GUEST:OCTAL_MODE (repeatable)
        #[arg(long = "inject", value_name = "HOST:GUEST:MODE")]
        inject: Vec<String>,
        /// spare free space (GiB) left in the filesystem for the guest to write
        #[arg(long, default_value_t = 0)]
        free_gib: u64,
        /// streaming only (tar = "-"): upper-bound rootfs size in GiB (the image is
        /// sparse, so over-estimating is free); required when streaming
        #[arg(long, default_value_t = 0)]
        size_gib: u64,
        /// streaming only: inode budget override (default: ~1 per 16 KiB)
        #[arg(long)]
        inodes: Option<u64>,
        /// filesystem UUID to stamp (32 hex digits, dashes optional) — set it to a
        /// content fingerprint to make the image's identity == what it was built from
        #[arg(long)]
        uuid: Option<String>,
        /// filesystem label to stamp (≤16 bytes; for blkid/lsblk)
        #[arg(long)]
        label: Option<String>,
    },
    /// Dev: pull an OCI image from a registry (no docker) and flatten it to a
    /// rootfs tar.
    OciPull {
        reference: String,
        out: PathBuf,
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        password: Option<String>,
        /// PEM CA bundle the registry's TLS cert chains to
        #[arg(long)]
        ca: Option<PathBuf>,
        /// plain HTTP (a local/insecure registry)
        #[arg(long)]
        insecure: bool,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    // `virtkit virtiofsd …` — the bundled vhost-user virtio-fs daemon. Dispatched
    // before the clap CLI / config load (it takes virtiofsd's own flags and needs no
    // executor config); the spawned daemon blocks until the VMM disconnects.
    #[cfg(feature = "virtiofsd")]
    {
        let args: Vec<String> = std::env::args().collect();
        if args.get(1).map(String::as_str) == Some("virtiofsd") {
            return match virtiofsd::run(args[1..].to_vec()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            };
        }
    }

    let cli = Cli::parse();
    let cfg = match Config::load() {
        Ok(cfg) => cfg,
        Err(e) => return fail(&e, 2),
    };
    // `launch` is a standalone dev path: no JobCtx (no CUSTOM_ENV_* job context).
    if let Cmd::Launch {
        image,
        kernel,
        oci,
        ca,
        username,
        password,
        insecure,
        agent,
        cloud_hypervisor,
        cpus,
        mem,
        boot_timeout,
        disk,
        shell,
        command,
    } = &cli.cmd
    {
        let args = launch::LaunchArgs {
            image: image.clone(),
            kernel: kernel.clone(),
            agent: agent.clone(),
            cloud_hypervisor: cloud_hypervisor.clone(),
            oci: *oci,
            ca: ca.clone(),
            username: username.clone(),
            password: password.clone(),
            insecure: *insecure,
            cpus: *cpus,
            mem: mem.clone(),
            boot_timeout_secs: *boot_timeout,
            disk: *disk,
            shell: *shell,
            command: command.clone(),
        };
        return match launch::run(&args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::DockerHash {
        dockerfile,
        build_arg,
        blacklist,
        stages,
    } = &cli.cmd
    {
        let mut args = std::collections::BTreeMap::new();
        for a in build_arg {
            let (k, v) = a.split_once('=').unwrap_or((a.as_str(), ""));
            args.insert(k.to_string(), v.to_string());
        }
        return match dockerhash::run(dockerfile.as_slice(), &args, blacklist, stages) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Mkext { src, out } = &cli.cmd {
        return match ext4::build_from_dir(src, out) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::MkextTar {
        tar,
        out,
        inject,
        free_gib,
        size_gib,
        inodes,
        uuid,
        label,
    } = &cli.cmd
    {
        let fsid = {
            let uuid = match uuid {
                Some(s) => match parse_uuid(s) {
                    Some(u) => Some(u),
                    None => {
                        return fail(&anyhow::anyhow!("bad --uuid {s:?} (want 32 hex digits)"), 2);
                    }
                },
                None => None,
            };
            ext4::FsId {
                uuid,
                label: label.clone(),
                with_journal: true,
            }
        };
        // each spec is HOST:GUEST:OCTAL_MODE; the guest path is normalized to the
        // image-relative form (no leading slash) the writer expects.
        let mut parsed: Vec<(String, PathBuf, u16)> = Vec::new();
        for spec in inject {
            let p: Vec<&str> = spec.splitn(3, ':').collect();
            if p.len() != 3 {
                return fail(
                    &anyhow::anyhow!("--inject must be HOST:GUEST:MODE, got {spec:?}"),
                    2,
                );
            }
            let mode = match u16::from_str_radix(p[2], 8) {
                Ok(m) => m,
                Err(_) => return fail(&anyhow::anyhow!("bad octal mode in {spec:?}"), 2),
            };
            parsed.push((
                p[1].trim_start_matches('/').to_string(),
                PathBuf::from(p[0]),
                mode,
            ));
        }
        let injects: Vec<(&str, &std::path::Path, u16)> = parsed
            .iter()
            .map(|(g, h, m)| (g.as_str(), h.as_path(), *m))
            .collect();
        let extra_free = free_gib * (1024 * 1024 * 1024 / 4096); // GiB -> 4 KiB blocks
        let r = if tar.as_os_str() == "-" {
            if *size_gib == 0 {
                return fail(
                    &anyhow::anyhow!("--size-gib is required when streaming (tar = -)"),
                    2,
                );
            }
            let reader = ProgressReader::new(std::io::BufReader::with_capacity(
                1 << 20,
                std::io::stdin().lock(),
            ));
            let res = ext4::build_from_tar_stream(
                reader,
                &injects,
                size_gib * (1 << 30),
                extra_free,
                *inodes,
                &fsid,
                out,
            );
            eprintln!(); // terminate the progress line
            res
        } else {
            ext4::build_from_tar_injecting(tar, &injects, extra_free, &fsid, out)
        };
        return match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::OciPull {
        reference,
        out,
        username,
        password,
        ca,
        insecure,
    } = &cli.cmd
    {
        let ca_pem = match ca {
            Some(p) => match std::fs::read(p) {
                Ok(b) => Some(b),
                Err(e) => return fail(&anyhow::anyhow!("reading {}: {e}", p.display()), 1),
            },
            None => None,
        };
        return match oci::pull_flatten(
            reference,
            username.as_deref(),
            password.as_deref(),
            ca_pem,
            *insecure,
            out,
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Switch {
        listen,
        gateway,
        prefix,
        host,
    } = &cli.cmd
    {
        let mut hosts = std::collections::HashMap::new();
        for h in host {
            match h.split_once('=').and_then(|(n, ip)| {
                ip.parse::<std::net::Ipv4Addr>()
                    .ok()
                    .map(|ip| (n.to_ascii_lowercase(), ip))
            }) {
                Some((name, ip)) => {
                    hosts.insert(name, ip);
                }
                None => return fail(&anyhow::anyhow!("bad --host {h:?} (want name=ip)"), 2),
            }
        }
        return match switch::run(listen, *gateway, *prefix, hosts).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    if let Cmd::Fleet {
        gateway,
        prefix,
        net_port,
        hosts,
        kernel,
        cloud_hypervisor,
        listen,
        service,
        service_build,
        service_image,
        agent,
        ensure_only,
        builder,
        builder_build,
        builder_name,
        workdir,
        git_dir,
        builder_cid,
        builder_cpus,
        builder_mem,
    } = &cli.cmd
    {
        let builder_opts = builder.as_ref().map(|ext4| fleet::BuilderOpts {
            ext4: ext4.clone(),
            name: builder_name.clone(),
            workdir: workdir.clone().unwrap_or_else(|| PathBuf::from(".")),
            git_dir: git_dir.clone(),
            cid: *builder_cid,
            cpus: *builder_cpus,
            mem: builder_mem.clone(),
            build_script: builder_build.clone(),
        });
        return match fleet::run(
            *gateway,
            *prefix,
            *net_port,
            hosts.clone(),
            kernel.clone(),
            cloud_hypervisor.clone(),
            listen.clone(),
            service.clone(),
            builder_opts,
            service_build.clone(),
            service_image.clone(),
            agent.clone(),
            *ensure_only,
        )
        .await
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => fail(&e, 1),
        };
    }
    let ctx = match JobCtx::new(cfg) {
        Ok(ctx) => ctx,
        Err(e) => return fail(&e, 2),
    };

    match cli.cmd {
        Cmd::Gitlab { cmd } => match cmd {
            GitlabCmd::Config => {
                let info = serde_json::json!({
                    "driver": {
                        "name": "virtkit",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "builds_dir": ctx.cfg.guest.builds_dir,
                    "cache_dir": ctx.cfg.guest.cache_dir,
                    "builds_dir_is_shared": false,
                });
                println!("{info}");
                ExitCode::SUCCESS
            }
            GitlabCmd::Prepare => match vm::prepare(&ctx).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, ctx.system_failure),
            },
            GitlabCmd::Run { script, stage: _ } => match run::run_stage(&ctx, &script).await {
                Ok(result) => match (result.code, result.signal) {
                    (Some(0), _) => ExitCode::SUCCESS,
                    // non-zero exit: the script already reported its error
                    (Some(_), _) => exit_code(ctx.build_failure),
                    (None, signal) => {
                        eprintln!("virtkit: stage script killed by signal {signal:?}");
                        exit_code(ctx.build_failure)
                    }
                },
                // can't reach/drive the VM: environment problem, job is retryable
                Err(e) => fail(&e, ctx.system_failure),
            },
            GitlabCmd::Cleanup => match vm::cleanup(&ctx) {
                Ok(()) => ExitCode::SUCCESS,
                // gitlab-runner only logs cleanup failures; report and don't mask
                Err(e) => fail(&e, 1),
            },
        },
        // run_forward only returns on a bind error; otherwise it serves until the
        // process is killed (cleanup tears the detached child down).
        Cmd::Forward { listen, to } => {
            match virtkit_agent::forward::run_forward(&listen, &to).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&e, 1),
            }
        }
        // handled above, before JobCtx
        Cmd::Switch { .. }
        | Cmd::Fleet { .. }
        | Cmd::Launch { .. }
        | Cmd::Mkext { .. }
        | Cmd::MkextTar { .. }
        | Cmd::OciPull { .. }
        | Cmd::DockerHash { .. } => {
            unreachable!()
        }
    }
}

fn fail(e: &anyhow::Error, code: i32) -> ExitCode {
    eprintln!("virtkit: error: {e:#}");
    exit_code(code)
}

/// Parse a UUID (32 hex digits, dashes optional) into 16 bytes.
fn parse_uuid(s: &str) -> Option<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn exit_code(code: i32) -> ExitCode {
    ExitCode::from(code.clamp(1, 255) as u8)
}

/// Wraps a reader to print a bytes-streamed indicator to stderr (so streaming a
/// `docker export` shows progress without depending on `pv`).
struct ProgressReader<R> {
    inner: R,
    bytes: u64,
    next_report: u64,
}

impl<R> ProgressReader<R> {
    fn new(inner: R) -> Self {
        ProgressReader {
            inner,
            bytes: 0,
            next_report: 0,
        }
    }
}

impl<R: std::io::Read> std::io::Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes += n as u64;
        if self.bytes >= self.next_report {
            use std::io::Write;
            eprint!(
                "\r   streaming rootfs: {:.1} GiB",
                self.bytes as f64 / (1u64 << 30) as f64
            );
            let _ = std::io::stderr().flush();
            self.next_report = self.bytes + (512 << 20); // report every 512 MiB
        }
        Ok(n)
    }
}
