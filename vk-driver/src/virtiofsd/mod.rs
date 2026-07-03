//! Bundled vhost-user virtio-fs daemon — the `vk virtiofsd …` subcommand, so
//! virtkit ships its own virtio-fs backend instead of a separate virtiofsd binary
//! (the run/units paths and the executor spawn `current_exe virtiofsd …`).
//!
//! FUSE requests are served by the vendored libkrun fs engine
//! (`Server<PassthroughFs>` — the same code the libkrun backend uses in-process),
//! carried over the vhost-user transport cloud-hypervisor speaks. The bridge:
//! vhost-user delivers descriptor chains as virtio-queue chains over vm-memory
//! 0.16; libkrun's `Reader`/`Writer` take vm-memory 0.17 `VolatileSlice`s. Both are
//! (ptr, len) views over the same mmap'd guest memory, so each slice is re-wrapped
//! by pointer (see `collect_slices`).
//!
//! Hardening mirrors what virtkit used from upstream virtiofsd: RLIMIT_NOFILE
//! raised, an optional chroot sandbox, and a seccomp syscall allowlist (pure-Rust
//! `seccompiler` — no libseccomp), kill-on-violation by default. `--readonly` uses
//! libkrun's fail-closed read-only wrapper; `--uid-map`/`--gid-map` are served by
//! [`idmap::IdMapFs`] (virtiofsd-compatible soft id mapping).

mod idmap;
mod seccomp;

use std::collections::VecDeque;
use std::io;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, RwLock};

use anyhow::{Context as _, Result, anyhow};
use clap::Parser;
use devices::virtio::descriptor_utils::{Reader as KrunReader, Writer as KrunWriter};
use devices::virtio::fs::filesystem::FileSystem;
use devices::virtio::fs::passthrough::{CachePolicy, Config as FsConfig, PassthroughFs};
use devices::virtio::fs::read_only::PassthroughFsRo;
use devices::virtio::fs::{InodeAllocator, Server};
use futures::executor::{ThreadPool, ThreadPoolBuilder};
use vhost::vhost_user::Listener;
use vhost::vhost_user::message::{VhostUserProtocolFeatures, VhostUserVirtioFeatures};
use vhost_user_backend::{VhostUserBackend, VhostUserDaemon, VringMutex, VringState, VringT};
use virtio_bindings::bindings::virtio_config::VIRTIO_F_VERSION_1;
use virtio_bindings::bindings::virtio_ring::{
    VIRTIO_RING_F_EVENT_IDX, VIRTIO_RING_F_INDIRECT_DESC,
};
use virtio_queue::{DescriptorChain, QueueOwnedT};
use vm_memory::{
    GuestAddressSpace, GuestMemory, GuestMemoryAtomic, GuestMemoryLoadGuard, GuestMemoryMmap,
    GuestMemoryRegion, VolatileMemory,
};
use vm_memory_krun::VolatileSlice as KrunVolatileSlice;
use vmm_sys_util::epoll::EventSet;
use vmm_sys_util::eventfd::EventFd;

use idmap::{IdMap, IdMapFs, IdTable};

type Mem = GuestMemoryAtomic<GuestMemoryMmap>;
type Chain = DescriptorChain<GuestMemoryLoadGuard<GuestMemoryMmap>>;

const QUEUE_SIZE: usize = 1024;
// hiprio + one request queue (VIRTIO_FS_F_NOTIFICATION is not advertised).
const NUM_QUEUES: usize = 2;
// virtio-fs config space: char tag[36]; le32 num_request_queues.
const TAG_LEN: usize = 36;

#[derive(Parser)]
#[command(name = "vk virtiofsd", about = "bundled vhost-user virtio-fs daemon")]
struct Opt {
    /// shared directory exported to the guest
    #[arg(long = "shared-dir")]
    shared_dir: String,
    /// vhost-user unix socket to listen on
    #[arg(long = "socket-path")]
    socket_path: String,
    /// cache policy: never | auto | always (metadata is treated as auto)
    #[arg(long, default_value = "auto")]
    cache: String,
    /// sandbox mode: none | chroot
    #[arg(long, default_value = "none")]
    sandbox: String,
    /// export the share read-only
    #[arg(long)]
    readonly: bool,
    /// seccomp filter action: kill | log | trap | none
    #[arg(long, default_value = "kill")]
    seccomp: seccomp::Action,
    /// virtio-fs tag (optional; normally the VMM provides it)
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

    // Raise RLIMIT_NOFILE to 1M (virtiofsd's default) so large shared directories
    // with many open files don't hit the shell default of ~1024.
    raise_nofile_limit(1_000_000)?;

    let cache_policy = match opt.cache.as_str() {
        // upstream virtiofsd's `metadata` sits between never and auto; this engine
        // has no equivalent, and virtkit only ever passes auto.
        "metadata" => CachePolicy::Auto,
        s => CachePolicy::from_str(s).map_err(|_| anyhow!("invalid --cache {s:?}"))?,
    };

    // The listener must exist before a chroot (the socket path is outside the share);
    // CH connects as the client.
    let listener = Listener::new(&opt.socket_path, true)
        .with_context(|| format!("binding the vhost-user socket {}", opt.socket_path))?;

    // Sandbox, then resolve the served root. chroot confines path resolution to the
    // share even if the daemon is subverted; `none` matches how virtkit spawns its
    // shares today (unprivileged, CH already confines the guest).
    let root_dir = match opt.sandbox.as_str() {
        "none" => opt.shared_dir.clone(),
        "chroot" => {
            let dir = std::ffi::CString::new(opt.shared_dir.as_str())
                .context("shared dir path contains a NUL byte")?;
            // SAFETY: dir is a valid C string; chroot/chdir have no memory effects.
            let rc = unsafe { libc::chroot(dir.as_ptr()) };
            if rc != 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("chroot({}) — needs CAP_SYS_CHROOT", opt.shared_dir));
            }
            std::env::set_current_dir("/").context("chdir into the chroot")?;
            "/".to_string()
        }
        other => {
            return Err(anyhow!(
                "--sandbox {other:?} is not supported by the bundled daemon (use none or chroot)"
            ));
        }
    };

    let fs_cfg = FsConfig {
        root_dir,
        cache_policy,
        ..Default::default()
    };
    let uid = IdTable::new(&opt.uid_map);
    let gid = IdTable::new(&opt.gid_map);
    let opts = DaemonOpts {
        listener,
        tag: opt.tag,
        thread_pool_size: opt.thread_pool_size,
        seccomp: opt.seccomp,
    };

    // Monomorphize the four filesystem stacks (ro and idmap wrap the passthrough).
    let alloc = Arc::new(InodeAllocator::new());
    match (opt.readonly, uid.is_empty() && gid.is_empty()) {
        (false, true) => serve(PassthroughFs::new(fs_cfg, alloc)?, opts),
        (true, true) => serve(PassthroughFsRo::new(fs_cfg, alloc)?, opts),
        (false, false) => serve(
            IdMapFs::new(PassthroughFs::new(fs_cfg, alloc)?, uid, gid),
            opts,
        ),
        (true, false) => serve(
            IdMapFs::new(PassthroughFsRo::new(fs_cfg, alloc)?, uid, gid),
            opts,
        ),
    }
}

struct DaemonOpts {
    listener: Listener,
    tag: Option<String>,
    thread_pool_size: usize,
    seccomp: seccomp::Action,
}

fn serve<F>(fs: F, opts: DaemonOpts) -> Result<()>
where
    F: FileSystem<Inode = u64, Handle = u64> + Send + Sync + 'static,
{
    let tag = match &opts.tag {
        Some(t) if t.len() > TAG_LEN => return Err(anyhow!("--tag longer than {TAG_LEN} bytes")),
        Some(t) => Some(t.clone()),
        None => None,
    };
    let pool = if opts.thread_pool_size > 0 {
        Some(
            ThreadPoolBuilder::new()
                .pool_size(opts.thread_pool_size)
                .create()
                .context("creating the request thread pool")?,
        )
    } else {
        None
    };
    let backend = Arc::new(Backend {
        server: Arc::new(Server::new(fs)),
        mem: RwLock::new(None),
        event_idx: AtomicBool::new(false),
        exit_event: EventFd::new(libc::EFD_NONBLOCK).context("creating the exit eventfd")?,
        exit_code: Arc::new(AtomicI32::new(0)),
        tag,
        pool,
    });
    let mut daemon = VhostUserDaemon::new(
        "vk-virtiofsd".to_string(),
        backend,
        GuestMemoryAtomic::new(GuestMemoryMmap::new()),
    )
    .map_err(|e| anyhow!("creating the vhost-user daemon: {e:?}"))?;

    // Confine before serving guest requests. Filters propagate to the daemon's
    // worker threads (TSYNC + inheritance on spawn).
    seccomp::enable(opts.seccomp)?;

    daemon
        .start(opts.listener)
        .map_err(|e| anyhow!("starting the vhost-user daemon: {e:?}"))?;
    daemon
        .wait()
        .map_err(|e| anyhow!("serving vhost-user requests: {e:?}"))
}

fn raise_nofile_limit(target: u64) -> Result<()> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit write/read only the struct we pass.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(io::Error::last_os_error()).context("getrlimit(RLIMIT_NOFILE)");
    }
    let want = target.min(lim.rlim_max);
    if lim.rlim_cur < want {
        lim.rlim_cur = want;
        // SAFETY: as above.
        if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } != 0 {
            return Err(io::Error::last_os_error()).context("setrlimit(RLIMIT_NOFILE)");
        }
    }
    Ok(())
}

fn other_err<E: std::fmt::Debug>(e: E) -> io::Error {
    io::Error::other(format!("{e:?}"))
}

/// Collect a chain's readable or writable descriptors as libkrun (vm-memory 0.17)
/// VolatileSlices over the vhost-user-mapped guest memory.
///
/// SAFETY contract for the rewrap: each 0.16 slice is a validated (ptr, len) view of
/// a guest memory region mapped in this process; the returned 0.17 slices are the
/// same bytes with the same lifetime 'a (the memory guard held by the caller across
/// the whole request). The vhost-user protocol quiesces queues before the memory
/// table changes, so the mapping outlives in-flight requests.
fn collect_slices<'a>(
    mem: &'a GuestMemoryLoadGuard<GuestMemoryMmap>,
    chain: Chain,
    writable: bool,
) -> io::Result<VecDeque<KrunVolatileSlice<'a>>> {
    let descs: Vec<_> = if writable {
        chain.writable().collect()
    } else {
        chain.readable().collect()
    };
    let mut out = VecDeque::with_capacity(descs.len());
    let mut total: usize = 0;
    for d in descs {
        total = total
            .checked_add(d.len() as usize)
            .ok_or_else(|| io::Error::other("descriptor chain length overflow"))?;
        let region = mem
            .find_region(d.addr())
            .ok_or_else(|| io::Error::other("descriptor outside guest memory"))?;
        let offset = d.addr().0 - region.start_addr().0;
        let slice = region
            .deref()
            .get_slice(offset as usize, d.len() as usize)
            .map_err(other_err)?;
        // SAFETY: see function doc — same mapped bytes, lifetime tied to `mem`.
        out.push_back(unsafe {
            KrunVolatileSlice::new(slice.ptr_guard_mut().as_ptr(), slice.len())
        });
    }
    Ok(out)
}

struct Backend<F: FileSystem<Inode = u64, Handle = u64> + Send + Sync + 'static> {
    server: Arc<Server<F>>,
    mem: RwLock<Option<Mem>>,
    event_idx: AtomicBool,
    exit_event: EventFd,
    /// libkrun's guest-exit ioctl channel — meaningless for a CH share, never read.
    exit_code: Arc<AtomicI32>,
    tag: Option<String>,
    pool: Option<ThreadPool>,
}

/// Process one chain through the FUSE server and retire its descriptor.
fn handle_chain<F>(
    server: &Server<F>,
    exit_code: &Arc<AtomicI32>,
    mem: &GuestMemoryLoadGuard<GuestMemoryMmap>,
    chain: Chain,
    vring: &mut VringState<Mem>,
    event_idx: bool,
) -> io::Result<()>
where
    F: FileSystem<Inode = u64, Handle = u64> + Send + Sync + 'static,
{
    let head = chain.head_index();
    // A failed request (malformed FUSE message — guest-controlled input) must not
    // take the share down or leave the descriptor in flight: retire it with a
    // 0-length reply and keep serving. Only vring-level errors stay fatal.
    let len = (|| -> io::Result<usize> {
        let reader = KrunReader::from_volatile_slices(collect_slices(mem, chain.clone(), false)?);
        let writer = KrunWriter::from_volatile_slices(collect_slices(mem, chain, true)?);
        server
            .handle_message(reader, writer, &None, exit_code)
            .map_err(other_err)
    })()
    .unwrap_or_else(|e| {
        log::error!("vk virtiofsd: request failed: {e}");
        0
    });
    vring.add_used(head, len as u32).map_err(other_err)?;
    if !event_idx || vring.needs_notification().unwrap_or(true) {
        vring.signal_used_queue().map_err(other_err)?;
    }
    Ok(())
}

impl<F: FileSystem<Inode = u64, Handle = u64> + Send + Sync + 'static> Backend<F> {
    fn process_queue_serial(&self, vring: &mut VringState<Mem>) -> io::Result<()> {
        let mem = self
            .mem
            .read()
            .unwrap()
            .as_ref()
            .ok_or_else(|| io::Error::other("no guest memory configured"))?
            .memory();
        let chains: Vec<Chain> = vring
            .get_queue_mut()
            .iter(mem.clone())
            .map_err(other_err)?
            .collect();
        let event_idx = self.event_idx.load(Ordering::Relaxed);
        for chain in chains {
            handle_chain(&self.server, &self.exit_code, &mem, chain, vring, event_idx)?;
        }
        Ok(())
    }

    fn process_queue_pool(&self, pool: &ThreadPool, vring: &VringMutex<Mem>) -> io::Result<()> {
        let atomic_mem = self
            .mem
            .read()
            .unwrap()
            .as_ref()
            .ok_or_else(|| io::Error::other("no guest memory configured"))?
            .clone();
        loop {
            let chain = {
                let mut state = vring.get_mut();
                let mem = atomic_mem.memory();
                state.get_queue_mut().iter(mem).map_err(other_err)?.next()
            };
            let Some(chain) = chain else { break };
            let server = self.server.clone();
            let exit_code = self.exit_code.clone();
            let event_idx = self.event_idx.load(Ordering::Relaxed);
            let atomic_mem = atomic_mem.clone();
            let vring = vring.clone();
            pool.spawn_ok(async move {
                let mem = atomic_mem.memory();
                if let Err(e) = handle_chain(
                    &server,
                    &exit_code,
                    &mem,
                    chain,
                    &mut vring.get_mut(),
                    event_idx,
                ) {
                    log::error!("vk virtiofsd: retiring descriptor failed: {e}");
                }
            });
        }
        Ok(())
    }
}

impl<F: FileSystem<Inode = u64, Handle = u64> + Send + Sync + 'static> VhostUserBackend
    for Backend<F>
{
    type Bitmap = ();
    type Vring = VringMutex<Mem>;

    fn num_queues(&self) -> usize {
        NUM_QUEUES
    }

    fn max_queue_size(&self) -> usize {
        QUEUE_SIZE
    }

    fn features(&self) -> u64 {
        (1 << VIRTIO_F_VERSION_1)
            | (1 << VIRTIO_RING_F_INDIRECT_DESC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits()
    }

    fn protocol_features(&self) -> VhostUserProtocolFeatures {
        // No DAX (BACKEND_REQ) and no live migration (LOG_*/DEVICE_STATE); CONFIG
        // only when a tag was given (the VMM normally provides it on its own side).
        let mut features = VhostUserProtocolFeatures::MQ
            | VhostUserProtocolFeatures::REPLY_ACK
            | VhostUserProtocolFeatures::CONFIGURE_MEM_SLOTS;
        if self.tag.is_some() {
            features |= VhostUserProtocolFeatures::CONFIG;
        }
        features
    }

    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
        // struct virtio_fs_config { char tag[36]; le32 num_request_queues; }
        let mut config = [0u8; TAG_LEN + 4];
        if let Some(tag) = &self.tag {
            config[..tag.len()].copy_from_slice(tag.as_bytes());
        }
        config[TAG_LEN..].copy_from_slice(&1u32.to_le_bytes());
        let offset = offset as usize;
        let end = offset.saturating_add(size as usize).min(config.len());
        config.get(offset..end).unwrap_or(&[]).to_vec()
    }

    fn set_event_idx(&self, enabled: bool) {
        self.event_idx.store(enabled, Ordering::Relaxed);
    }

    fn update_memory(&self, mem: Mem) -> io::Result<()> {
        *self.mem.write().unwrap() = Some(mem);
        Ok(())
    }

    fn handle_event(
        &self,
        device_event: u16,
        evset: EventSet,
        vrings: &[VringMutex<Mem>],
        _thread_id: usize,
    ) -> io::Result<()> {
        if evset != EventSet::IN {
            return Err(io::Error::other("unexpected event set"));
        }
        let vring = vrings
            .get(device_event as usize)
            .ok_or_else(|| io::Error::other(format!("unexpected device event {device_event}")))?;
        if let Some(pool) = &self.pool {
            self.process_queue_pool(pool, vring)
        } else if self.event_idx.load(Ordering::Relaxed) {
            loop {
                vring.disable_notification().map_err(other_err)?;
                self.process_queue_serial(&mut vring.get_mut())?;
                if !vring.enable_notification().map_err(other_err)? {
                    break;
                }
            }
            Ok(())
        } else {
            self.process_queue_serial(&mut vring.get_mut())
        }
    }

    fn exit_event(&self, _thread_index: usize) -> Option<EventFd> {
        self.exit_event.try_clone().ok()
    }
}
