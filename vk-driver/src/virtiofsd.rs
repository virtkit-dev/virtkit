//! Bundled vhost-user virtio-fs daemon — the `vk virtiofsd …` subcommand, so
//! virtkit ships its own virtio-fs backend instead of a separate virtiofsd binary
//! (the fleet and the executor spawn `current_exe virtiofsd …`).
//!
//! This is a slim wrapper over the `virtiofsd` library exposing only the flags the
//! fleet/executor pass (`--shared-dir`, `--socket-path`, `--cache`, `--sandbox`,
//! `--readonly`, `--tag`). The daemon setup mirrors virtiofsd's own `main.rs`
//! (Sandbox → Listener → PassthroughFs → VhostUserDaemon); it deliberately omits
//! capability-dropping — the shares are mounted `--sandbox=none` and Cloud Hypervisor
//! already confines the guest. RLIMIT_NOFILE and seccomp are applied like upstream.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use clap::Parser;

use vhost::vhost_user::Listener;
use vhost_user_backend::VhostUserDaemon;
use virtiofsd::filesystem::{FileSystem, SerializableFileSystem};
use virtiofsd::limits;
use virtiofsd::passthrough::read_only::PassthroughFsRo;
use virtiofsd::passthrough::{self, CachePolicy, PassthroughFs};
use virtiofsd::sandbox::{Sandbox, SandboxMode};
use virtiofsd::seccomp::{SeccompAction, enable_seccomp};
use virtiofsd::soft_idmap::cmdline::IdMap;
use virtiofsd::vhost_user::VhostUserFsBackendBuilder;
use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};

#[derive(Parser)]
#[command(name = "vk virtiofsd", about = "bundled vhost-user virtio-fs daemon")]
struct Opt {
    /// shared directory exported to the guest
    #[arg(long = "shared-dir")]
    shared_dir: String,
    /// vhost-user unix socket to listen on
    #[arg(long = "socket-path")]
    socket_path: String,
    /// cache policy: never | metadata | auto | always
    #[arg(long, default_value = "auto")]
    cache: String,
    /// sandbox mode: none | chroot | namespace
    #[arg(long, default_value = "none")]
    sandbox: String,
    /// export the share read-only
    #[arg(long)]
    readonly: bool,
    /// seccomp filter action: kill | log | trap | none
    #[arg(long, default_value = "kill")]
    seccomp: String,
    /// virtio-fs tag (optional)
    #[arg(long)]
    tag: Option<String>,
    /// worker thread pool size (0 = synchronous)
    #[arg(long = "thread-pool-size", default_value_t = 0)]
    thread_pool_size: usize,
    /// UID translation rule for the guest↔host boundary (repeatable);
    /// format: `type:from:to[:count]` where type is one of:
    /// `map` (bidirectional), `guest`, `host`, `squash-guest`, `squash-host`, `forbid-guest`
    #[arg(long = "uid-map")]
    uid_map: Vec<IdMap>,
    /// GID translation rule (same format as --uid-map, repeatable)
    #[arg(long = "gid-map")]
    gid_map: Vec<IdMap>,
}

/// Run the daemon. `argv` starts with the program name (e.g. ["virtiofsd", "--shared-dir", …]).
pub fn run(argv: Vec<String>) -> Result<()> {
    let opt = Opt::parse_from(argv);

    // Raise RLIMIT_NOFILE to 1_000_000 (virtiofsd default) so large shared directories
    // with many open files don't hit the shell default of ~1024.
    limits::setup_rlimit_nofile(None).map_err(|e| anyhow!("raising RLIMIT_NOFILE: {e}"))?;

    let cache = CachePolicy::from_str(&opt.cache)
        .map_err(|_| anyhow!("invalid --cache {:?}", opt.cache))?;
    let sandbox_mode = SandboxMode::from_str(&opt.sandbox)
        .map_err(|_| anyhow!("invalid --sandbox {:?}", opt.sandbox))?;

    // Cache timeouts as virtiofsd's main.rs derives them from the policy.
    let timeout = match cache {
        CachePolicy::Never => Duration::from_secs(0),
        CachePolicy::Auto => Duration::from_secs(1),
        CachePolicy::Metadata | CachePolicy::Always => Duration::from_secs(86400),
    };

    let listener = Listener::new(&opt.socket_path, true)
        .map_err(|e| anyhow!("creating vhost-user listener at {}: {e:?}", opt.socket_path))?;

    let mut sandbox = Sandbox::new(opt.shared_dir.clone(), sandbox_mode, Vec::new(), Vec::new())
        .context("creating sandbox")?;
    let listener = sandbox
        .enter(listener)
        .map_err(|e| anyhow!("entering sandbox: {e:?}"))?;

    let fs_cfg = passthrough::Config {
        root_dir: sandbox.get_root_dir(),
        entry_timeout: timeout,
        attr_timeout: timeout,
        cache_policy: cache,
        uid_map: if opt.uid_map.is_empty() {
            None
        } else {
            Some(opt.uid_map)
        },
        gid_map: if opt.gid_map.is_empty() {
            None
        } else {
            Some(opt.gid_map)
        },
        ..Default::default()
    };

    // Restrict the daemon's syscalls (defense in depth, like upstream). Must run
    // before the worker thread pool starts; --seccomp=none disables it.
    let seccomp = match opt.seccomp.as_str() {
        "none" => SeccompAction::Allow,
        "kill" => SeccompAction::Kill,
        "log" => SeccompAction::Log,
        "trap" => SeccompAction::Trap,
        other => anyhow::bail!("invalid --seccomp {other:?} (kill|log|trap|none)"),
    };
    if !matches!(seccomp, SeccompAction::Allow) {
        enable_seccomp(seccomp, false).map_err(|e| anyhow!("enabling seccomp: {e:?}"))?;
    }

    if opt.readonly {
        let fs = PassthroughFsRo::new(fs_cfg).map_err(|e| anyhow!("creating read-only fs: {e}"))?;
        serve(fs, listener, opt.thread_pool_size, opt.tag)
    } else {
        let fs = PassthroughFs::new(fs_cfg).map_err(|e| anyhow!("creating fs: {e}"))?;
        serve(fs, listener, opt.thread_pool_size, opt.tag)
    }
}

fn serve<F: FileSystem + SerializableFileSystem + Send + Sync + 'static>(
    fs: F,
    listener: Listener,
    thread_pool_size: usize,
    tag: Option<String>,
) -> Result<()> {
    let backend = Arc::new(
        VhostUserFsBackendBuilder::default()
            .set_thread_pool_size(thread_pool_size)
            .set_tag(tag)
            .build(fs)
            .map_err(|e| anyhow!("creating vhost-user backend: {e}"))?,
    );
    let mut daemon = VhostUserDaemon::new(
        String::from("virtkit-virtiofsd"),
        backend,
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .map_err(|e| anyhow!("creating daemon: {e}"))?;
    daemon
        .start(listener)
        .map_err(|e| anyhow!("starting daemon: {e:?}"))?;
    daemon
        .wait()
        .map_err(|e| anyhow!("daemon exited with error: {e:?}"))?;
    Ok(())
}
