//! Service-unit provisioning and boot — the machinery shared by every consumer of
//! compose-declared service microVMs: `vk run --compose` (foreground owner)
//! and the GitLab executor's job supervisor (ephemeral, one detached owner per job).
//!
//! A unit is a byte-clean image (built from its `build:` stage or pulled from its
//! `image:` ref — see `ensure.rs`) plus its merged runtime config. Booting one is a
//! throwaway CoW overlay over the ext4, the agent + config riding a per-boot
//! initramfs (`rdinit=/init VIRTKIT_PIVOT=/dev/vda VIRTKIT_MODE=service`), attached
//! to the owner's switch over vsock. All children are spawned *tied* (PDEATHSIG):
//! whichever process owns a unit takes it down by dying, however rudely.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

use anyhow::{Context, Result, bail};
use vk_core::runcfg::RunConfig;

/// One service unit, ready to boot: its ensured clean image, its address on the
/// owner's LAN, and the merged runtime config rendered into the boot initramfs on
/// every start.
pub struct Provisioned {
    pub name: String,
    pub hostname: String,
    pub ext4: PathBuf,
    /// static address, `ip/prefix`
    pub ip: String,
    pub cid: u32,
    pub config: RunConfig,
    pub volumes: Vec<crate::compose::Volume>,
    /// Who runs as PID 1 in this unit's guest (its compose `x-virtkit.init`): the
    /// vk-agent (`Default`, today's service medium) or the image's own `/sbin/init`
    /// (`Image`, the preinit handoff). Uniform with the primary path.
    pub init: crate::run::InitSource,
    /// Which kernel this unit boots on (its compose `x-virtkit.kernel`): the pinned
    /// kernel (`Default`), the image's own kernel + modules (`Image`), or an explicit
    /// file (`Path`). Uniform with the primary path.
    pub kernel: crate::run::KernelSource,
}

/// The builder wiring for `build:` units, shared across a consumer's units (each
/// unit brings its own Dockerfiles/args on top). All paths are resolved — the agent
/// in particular may be a held memfd path.
pub struct BuildOpts {
    /// ARG overrides applied to every `build:` unit (compose `args:` add per unit)
    pub build_args: Vec<(String, String)>,
    pub kernel: PathBuf,
    pub cloud_hypervisor: PathBuf,
    pub agent: PathBuf,
    pub cache_registry: Option<String>,
    pub cache_insecure: bool,
}

/// Ensure a unit's clean image at `ext4` (skipping when its content fingerprint
/// already matches — see `ensure.rs`) and return its merged runtime config: the
/// image's sidecar defaults layered with the unit's compose overrides.
pub async fn ensure_unit(
    unit: &crate::compose::Unit,
    ext4: &Path,
    build: &BuildOpts,
) -> Result<RunConfig> {
    match &unit.source {
        crate::compose::Source::Build { .. } => {
            // No streaming here (the CI/eager paths): the on-demand manager start uses
            // ensure_unit_build_sync with a sink.
            return materialize_build_unit(unit, ext4, build, None);
        }
        crate::compose::Source::Image(image) => {
            crate::ensure::ensure_unit_pull(image, ext4).await?;
        }
    }
    read_merged_config(unit, ext4)
}

/// Ensure a `build:` unit's clean image synchronously — the microVM build path never
/// awaits — streaming its build progress to `sink` when set, and return its merged runtime
/// config. This is the on-demand start path (the service manager builds a profiled-down
/// `build:` service the first time it is brought up). Errors for an `image:` unit: those
/// need the async pull and are materialized up front, not on demand.
pub fn ensure_unit_build_sync(
    unit: &crate::compose::Unit,
    ext4: &Path,
    build: &BuildOpts,
    sink: Option<crate::build::ProgressSink>,
) -> Result<RunConfig> {
    match &unit.source {
        crate::compose::Source::Build { .. } => {
            // The build writes the image in place at `ext4` (a non-atomic flatten), and the
            // manager releases the units lock across it — so two concurrent first-starts of
            // the same service would corrupt each other's write. A blocking flock beside the
            // image serializes them: the first builds, the rest block then find it fresh (the
            // fingerprint short-circuit in `ensure_unit_build`), mirroring `ensure_unit_store`.
            let _lock = lock_exclusive(&build_lock_path(ext4))?;
            materialize_build_unit(unit, ext4, build, sink)
        }
        crate::compose::Source::Image(_) => anyhow::bail!(
            "on-demand start of the image: service {:?} is not supported — \
             image services are materialized up front",
            unit.name
        ),
    }
}

/// Build a `build:` unit's ext4 (skipping when its fingerprint already matches), streaming
/// to `sink` if set, then return its merged runtime config. Panics if `unit.source` is not
/// `Build` — callers dispatch on the source first.
fn materialize_build_unit(
    unit: &crate::compose::Unit,
    ext4: &Path,
    build: &BuildOpts,
    sink: Option<crate::build::ProgressSink>,
) -> Result<RunConfig> {
    let crate::compose::Source::Build {
        dockerfiles,
        context,
        target,
        args,
    } = &unit.source
    else {
        unreachable!("materialize_build_unit requires a build: source")
    };
    let mut build_args = build.build_args.clone();
    build_args.extend(args.iter().cloned());
    // compose semantics: one context for all the service's files.
    let contexts = vec![context.clone(); dockerfiles.len()];
    let key =
        crate::build::target_stage_key(dockerfiles, &contexts, &build_args, target.as_deref())?;
    let recipe = crate::ensure::BuildRecipe {
        dockerfiles: dockerfiles.clone(),
        contexts,
        build_args,
        kernel: Some(build.kernel.clone()),
        cloud_hypervisor: Some(build.cloud_hypervisor.clone()),
        agent: Some(build.agent.clone()),
        cache_registry: build.cache_registry.clone(),
        cache_insecure: build.cache_insecure,
    };
    crate::ensure::ensure_unit_build(&recipe, target.as_deref(), &key, ext4, sink)?;
    read_merged_config(unit, ext4)
}

/// The unit's boot config: the image's own defaults (its sidecar, written by the build /
/// pull) layered with the unit's compose overrides.
fn read_merged_config(unit: &crate::compose::Unit, ext4: &Path) -> Result<RunConfig> {
    let sidecar = crate::build::config_sidecar(ext4);
    let image_cfg = RunConfig::from_json(
        &std::fs::read_to_string(&sidecar)
            .with_context(|| format!("reading {}", sidecar.display()))?,
    )
    .with_context(|| format!("parsing {}", sidecar.display()))?;
    Ok(crate::compose::merged_config(&image_cfg, unit))
}

/// A unit's content fingerprint — the canonical-UUID identity `ensure` stamps as the
/// image's ext4 UUID: `fingerprint(manifest digest)` for `image:` units,
/// `fingerprint(stage key)` for `build:` ones. Resolved over the network, exactly as
/// the ensure itself will.
pub async fn unit_fingerprint(unit: &crate::compose::Unit, build: &BuildOpts) -> Result<String> {
    match &unit.source {
        crate::compose::Source::Build {
            dockerfiles,
            context,
            target,
            args,
        } => {
            let mut build_args = build.build_args.clone();
            build_args.extend(args.iter().cloned());
            let contexts = vec![context.clone(); dockerfiles.len()];
            let key = crate::build::target_stage_key(
                dockerfiles,
                &contexts,
                &build_args,
                target.as_deref(),
            )?;
            Ok(crate::ensure::fingerprint(&[&key]))
        }
        crate::compose::Source::Image(image) => {
            let digest = crate::oci::resolve_digest(image)
                .await
                .with_context(|| format!("resolving {image}"))?;
            Ok(crate::ensure::fingerprint(&[&digest]))
        }
    }
}

/// Ensure a unit's image in the shared content-addressed `store` and return its
/// image path + merged runtime config. The store key is the unit's fingerprint, so
/// every consumer wanting the same content shares one image: concurrent ensures
/// serialize on a per-fingerprint `flock` — the first pays the pull/build, the rest
/// find it fresh (the UUID check inside the lock). Each ensure bumps a per-entry
/// `.used` marker so a later GC can sweep by idle age — a cache hit never rebuilds
/// the image, so its ext4 mtime is not a usage signal on its own. Nothing here
/// removes store entries; GC (which must also sweep the sibling `<fp>.lock` files) is
/// a follow-up, like the instruction cache's.
pub async fn ensure_unit_store(
    unit: &crate::compose::Unit,
    store: &Path,
    build: &BuildOpts,
) -> Result<(PathBuf, RunConfig)> {
    let fp = unit_fingerprint(unit, build).await?;
    let dir = store.join(&fp);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let ext4 = dir.join("image.ext4");
    // The flock blocks until granted — potentially for a whole concurrent pull/build —
    // so acquire it on a blocking thread rather than parking an async worker, and hold
    // the guard across the ensure below.
    let lock_path = store.join(format!("{fp}.lock"));
    let _lock = tokio::task::spawn_blocking(move || lock_exclusive(&lock_path))
        .await
        .context("unit store lock task")??;
    let config = ensure_unit(unit, &ext4, build).await?;
    // GC readiness: record last use on every ensure (hit or miss), best-effort.
    let _ = std::fs::File::create(dir.join(".used"));
    Ok((ext4, config))
}

/// The lock file guarding an on-demand build of the image at `ext4` (a sibling `.build.lock`),
/// so concurrent first-starts of the same service serialize instead of racing the in-place write.
fn build_lock_path(ext4: &Path) -> PathBuf {
    let mut p = ext4.as_os_str().to_os_string();
    p.push(".build.lock");
    PathBuf::from(p)
}

/// A held image lock; released when dropped (flock releases on the last close).
struct LockGuard {
    _file: std::fs::File,
}

/// Blocking exclusive `flock` on `path` (created if absent). Advisory and
/// filesystem-local — fine for a runner state dir; a store on NFS is unsupported.
fn lock_exclusive(path: &Path) -> Result<LockGuard> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
    // SAFETY: the fd is owned by `f`, which the guard keeps alive; flock returns
    // 0 or -1/errno and blocks until the lock is granted.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("locking {}", path.display()));
    }
    Ok(LockGuard { _file: f })
}

/// The `n`th static service address, counted from the TOP of the subnet down
/// (`n = 0` → broadcast - 1). DHCP leases (a dev VM, a CI job VM) grow from the
/// bottom (.2 up), so the two never collide in practice.
pub fn nth_static_ip(gateway: Ipv4Addr, prefix: u8, n: u32) -> Result<Ipv4Addr> {
    // Reject prefixes with no usable static/DHCP host range: /31 and /32 have no
    // (or one) host, and the `- 2` below would underflow at /32.
    if !(2..=30).contains(&prefix) {
        bail!("invalid subnet prefix /{prefix}");
    }
    let hosts = 2u64.pow(32 - u32::from(prefix)) - 2; // minus network + broadcast
    let mask = u32::MAX << (32 - prefix);
    let network = u32::from(gateway) & mask;
    // keep clear of the gateway and leave the low half to the DHCP pool.
    if u64::from(n) >= hosts / 2 {
        bail!("too many services for a /{prefix} subnet");
    }
    Ok(Ipv4Addr::from(network | (hosts as u32 - n)))
}

/// A stable, locally-administered unicast MAC for a sibling from its run-assigned
/// IPv4: `52:54:00:<octet2>:<octet3>:<octet4>`. The `52:54:00` prefix is the
/// QEMU-style locally-administered unicast OUI; the last three octets carry the
/// low three IPv4 octets, so every host on a /24 (up to a /8) LAN gets a distinct
/// MAC. The switch keys a DHCP reservation on this MAC to hand the sibling its
/// svc.ip (== the address the resolver advertises for its name), instead of a pool
/// lease.
pub fn mac_for_ip(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("52:54:00:{:02x}:{:02x}:{:02x}", o[1], o[2], o[3])
}

/// First vsock CID handed to services — clear of the reserved CIDs (0-2) and the
/// primary VM's default (3).
pub const FIRST_SERVICE_CID: u32 = 100;

/// vsock port the reparented `vk-agent serve` listens on in an image-init sibling
/// (the preinit boot's `VIRTKIT_VSOCK_PORT`). Siblings are reached over the LAN, not
/// vsock exec, so nothing on the host dials this — it just gives the serve a port
/// (the agent's own default is the same value). Mirrors the primary path's port.
const VSOCK_PORT: u32 = 4444;

/// Boot one unit in `dir` (its runtime state: overlay, sockets, console, boot
/// initramfs — distinct from where the image lives): a throwaway CoW overlay over
/// its clean ext4, booted through the agent initramfs which also carries the unit's
/// merged runtime config — VIRTKIT_MODE=service then forks its argv. Static address,
/// attached to the owner's switch over vsock; compose volumes are virtiofs bind
/// mounts. Returns the VMM child plus any virtiofsd children — all tied to the
/// calling process.
pub fn boot_unit(
    svc: &Provisioned,
    dir: &Path,
    kernel: &Path,
    cloud_hypervisor: &Path,
    agent: &Path,
    net_port: u32,
    gateway: Ipv4Addr,
) -> Result<(Child, Vec<Child>)> {
    let overlay = dir.join(format!("{}-overlay.qcow2", svc.name));
    let vsock = dir.join("vsock.sock");
    let console = dir.join("console.log");

    let _ = std::fs::remove_file(&overlay);
    create_overlay(&svc.ext4, &overlay)?;
    let _ = std::fs::remove_file(&vsock);

    // The init/kernel axes are a uniform per-unit property (from the unit's compose
    // `x-virtkit` marker), applied identically here for a sibling and in the primary
    // path (`run::build_and_boot`). A non-default axis boots via the preinit
    // initramfs — the image's own init needs the agent-as-/init handoff, and a
    // modular image kernel needs the module initramfs — exactly like the primary.
    let image_boot =
        svc.init == crate::run::InitSource::Image || svc.kernel == crate::run::KernelSource::Image;
    // The boot medium + boot kernel. Default/Default: the agent-service medium (agent
    // + the unit's config as VIRTKIT_MODE=service). Otherwise: the preinit medium,
    // reading the unit's clean ext4 (the overlay's ro backing) to extract the image
    // kernel/modules and build the agent-as-/init initramfs.
    let cpio = dir.join("initramfs.cpio");
    let boot_kernel;
    let handoff_frag;
    if image_boot {
        let boot = crate::fullvm::prepare(
            &svc.ext4,
            agent,
            &dir.join("vmlinuz"),
            &cpio,
            Some(&svc.config),
            &svc.kernel,
            kernel,
        )?;
        boot_kernel = boot.kernel;
        // Per-axis handoff tokens, mirroring the primary path: keep ttyS0 for a
        // modular image kernel (no early hvc0), hand PID 1 to /sbin/init for image init.
        let mut frag = String::new();
        if svc.kernel == crate::run::KernelSource::Image {
            frag.push_str(" VIRTKIT_KERNEL=image");
        }
        if svc.init == crate::run::InitSource::Image {
            frag.push_str(" VIRTKIT_INIT=image VIRTKIT_HANDOFF=/sbin/init");
        }
        handoff_frag = frag;
    } else {
        // The boot medium: agent + the unit's merged config, rebuilt on every start so
        // it always reflects the owner's current view.
        crate::initramfs::build_agent_initramfs_with_config(agent, Some(&svc.config), &cpio)?;
        boot_kernel = kernel.to_path_buf();
        handoff_frag = String::new();
    }

    // compose volumes: each bind mount is its own virtiofs share.
    let mut aux: Vec<Child> = Vec::new();
    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    let mut virtiofs = String::new();
    for (i, vol) in svc.volumes.iter().enumerate() {
        let tag = format!("vol{i}");
        let sock = dir.join(format!("vfsd-{tag}.sock"));
        if !crate::vmm::libkrun_selected() {
            aux.push(crate::spawn::spawn_virtiofsd(
                &sock,
                &vol.host,
                vol.read_only,
                &[],
                &[],
            )?);
        }
        if !virtiofs.is_empty() {
            virtiofs.push(',');
        }
        virtiofs.push_str(&format!("{tag}:{}", vol.guest));
        shares.push(crate::vmm::FsShare {
            tag,
            socket: sock,
            host_dir: vol.host.clone(),
            read_only: vol.read_only,
        });
    }
    let shared_mem = !shares.is_empty();

    // The sibling's deterministic MAC, derived from its run-assigned IP. Passed on
    // the cmdline so the agent sets the tap's hardware address to it, letting the
    // switch honor its per-MAC DHCP reservation and hand back this exact IP (== the
    // address the resolver advertises for the sibling's name). Harmless for the
    // static path (it sets its address directly); required for the image-init path,
    // whose own systemd DHCPs eth0.
    let mac = svc
        .ip
        .split('/')
        .next()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .map(mac_for_ip);

    // Build and spawn the VMM. On any failure, kill the virtiofsd children already
    // spawned above before returning — Child's Drop does not kill, so a soft error
    // return would otherwise orphan them for the owner's lifetime.
    let spawn_vmm = move || -> Result<Child> {
        // Two boot shapes, one per axis state. Both keep the same LAN wiring — the
        // switch bridge port, the static address, the gateway resolver — and the
        // virtiofs shares, so networking and volumes work identically; only who takes
        // PID 1 and which kernel/initramfs boots differ.
        let mut cmdline = if image_boot {
            // Preinit boot, mirroring the primary path (`run::build_and_boot`): the
            // agent rides the initramfs as /init, pivots, then either stays PID 1
            // (kernel=image only) or execs /sbin/init (init=image). VIRTKIT_VSOCK_PORT
            // gives the reparented `vk-agent serve` its port; the handoff tokens
            // (VIRTKIT_KERNEL/VIRTKIT_INIT) were computed above.
            format!(
                "console=ttyS0 pci=conf1 VIRTKIT_PIVOT=/dev/vda \
                 VIRTKIT_VSOCK_PORT={VSOCK_PORT} VIRTKIT_HOSTNAME={} \
                 VIRTKIT_NET_PORT={net_port} VIRTKIT_VM_IP={} VIRTKIT_VM_DNS={gateway}{handoff_frag}",
                svc.hostname, svc.ip
            )
        } else {
            // Default agent-service boot: the agent stays PID 1 and forks the unit's
            // entrypoint (VIRTKIT_MODE=service). Static address + the gateway as
            // resolver (its DNS answers the service names and forwards the rest), so
            // the unit resolves siblings without /etc/hosts.
            format!(
                "console=ttyS0 rdinit=/init VIRTKIT_PIVOT=/dev/vda VIRTKIT_MODE=service \
                 VIRTKIT_HOSTNAME={} VIRTKIT_NET_PORT={net_port} \
                 VIRTKIT_VM_IP={} VIRTKIT_VM_DNS={gateway}",
                svc.hostname, svc.ip
            )
        };
        if let Some(mac) = &mac {
            cmdline.push_str(&format!(" VIRTKIT_VM_MAC={mac}"));
        }
        if !virtiofs.is_empty() {
            cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS={virtiofs}"));
        }

        // units are reached over the switch network, not vsock exec; only the
        // guest→host switch bridge needs mapping.
        let vsock_ports = vec![crate::vmm::VsockPort::bridge(&vsock, net_port)];
        let spec = crate::vmm::VmSpec {
            kernel: boot_kernel,
            cmdline,
            disks: vec![crate::vmm::Disk::overlay(overlay)],
            initramfs: Some(cpio),
            shares,
            vsock_cid: svc.cid,
            vsock_socket: vsock,
            vsock_ports,
            cpus: 2,
            mem: "1G".into(),
            shared_mem,
            net: crate::vmm::Net::None,
            balloon: false,
            serial_log: console.clone(),
            api_socket: None,
            pass_fds: Vec::new(),
            proc_name: crate::vmm::resolve_proc_name(&svc.name),
        };
        let log = std::fs::File::create(&console)?;
        let vmm = crate::vmm::selected(cloud_hypervisor);
        // Tied (PDEATHSIG) like the virtiofsd aux children: a service VMM dies with
        // its owner — the run or the CI job supervisor — rather than leaking
        // on a hard kill that skips the explicit teardown.
        let mut cmd = vmm.command(&spec);
        cmd.stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log);
        crate::spawn::spawn_tied(cmd).with_context(|| format!("spawning {}", vmm.name()))
    };
    match spawn_vmm() {
        Ok(child) => Ok((child, aux)),
        Err(e) => {
            for c in &mut aux {
                let _ = c.kill();
            }
            Err(e)
        }
    }
}

/// Create a CoW qcow2 `overlay` over the ro raw `ext4` base. The backing reference is
/// stored verbatim, so canonicalize the base to an absolute path — a relative one would
/// be resolved against the overlay's directory and break.
fn create_overlay(ext4: &Path, overlay: &Path) -> Result<()> {
    let base =
        std::fs::canonicalize(ext4).with_context(|| format!("locating {}", ext4.display()))?;
    crate::qcow2::create_overlay(overlay, &base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn build_unit_fingerprints_key_the_store() {
        // scratch-only builds resolve offline; the fingerprint follows the content.
        let tmp = std::env::temp_dir().join(format!("vk-unitfp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let write = |name: &str, content: &str| -> crate::compose::Unit {
            let dir = tmp.join(name);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("Dockerfile"), content).unwrap();
            crate::compose::parse(
                &format!("services:\n  {name}:\n    build: ./{name}\n"),
                &tmp,
                &|_| None,
            )
            .unwrap()
            .pop()
            .unwrap()
        };
        let a = write("aa", "FROM scratch\nENV X=1\n");
        let b = write("bb", "FROM scratch\nENV X=2\n");
        let c = write("cc", "FROM scratch\nENV X=1\n"); // same content as aa
        let opts = BuildOpts {
            build_args: vec![],
            kernel: "/nonexistent".into(),
            cloud_hypervisor: "/nonexistent".into(),
            agent: "/nonexistent".into(),
            cache_registry: Some("none".into()),
            cache_insecure: false,
        };
        let fp = |u: &crate::compose::Unit| block_on(unit_fingerprint(u, &opts)).unwrap();
        assert_ne!(fp(&a), fp(&b)); // different content -> different store entries
        assert_eq!(fp(&a), fp(&c)); // same content -> one shared entry
        assert!(crate::ensure::parse_uuid(&fp(&a)).is_some()); // canonical UUID form
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn store_lock_serializes_holders() {
        let tmp = std::env::temp_dir().join(format!("vk-unitlock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let path = tmp.join("x.lock");
        let guard = lock_exclusive(&path).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let p2 = path.clone();
        let t = std::thread::spawn(move || {
            let _g = lock_exclusive(&p2).unwrap(); // blocks until the first drops
            tx.send(()).unwrap();
        });
        // the second locker must still be waiting …
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "second flock holder did not block"
        );
        drop(guard);
        // … and proceeds once released.
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("second flock holder never acquired");
        t.join().unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn on_demand_build_rejects_an_image_service() {
        // `image:` services need the async pull and are materialized up front; the sync
        // on-demand start path must refuse one rather than silently do nothing.
        let unit = crate::compose::parse(
            "services:\n  redis:\n    image: redis:7\n",
            Path::new("."),
            &|_| None,
        )
        .unwrap()
        .pop()
        .unwrap();
        let opts = BuildOpts {
            build_args: vec![],
            kernel: "/nonexistent".into(),
            cloud_hypervisor: "/nonexistent".into(),
            agent: "/nonexistent".into(),
            cache_registry: Some("none".into()),
            cache_insecure: false,
        };
        let err = ensure_unit_build_sync(&unit, Path::new("/nonexistent/image.ext4"), &opts, None)
            .unwrap_err();
        assert!(
            err.to_string().contains("materialized up front"),
            "expected an image-service rejection, got: {err:#}"
        );
    }

    #[test]
    fn static_ips_grow_from_the_subnet_top() {
        let gw: Ipv4Addr = "192.168.127.1".parse().unwrap();
        // /24: broadcast .255, so services get .254, .253, … — clear of the DHCP
        // pool growing from .2.
        assert_eq!(
            nth_static_ip(gw, 24, 0).unwrap(),
            "192.168.127.254".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            nth_static_ip(gw, 24, 3).unwrap(),
            "192.168.127.251".parse::<Ipv4Addr>().unwrap()
        );
        // half the subnet stays reserved for DHCP.
        assert!(nth_static_ip(gw, 24, 127).is_err());
        assert!(nth_static_ip(gw, 30, 1).is_err()); // /30 has one host, at most
        // out-of-range / degenerate prefixes are rejected, not left to overflow the
        // shift (/33, /0) or underflow the host count (/32, /31).
        assert!(nth_static_ip(gw, 0, 0).is_err());
        assert!(nth_static_ip(gw, 33, 0).is_err());
        assert!(nth_static_ip(gw, 32, 0).is_err());
        assert!(nth_static_ip(gw, 31, 0).is_err());
    }
}
