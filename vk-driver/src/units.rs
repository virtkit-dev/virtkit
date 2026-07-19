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
use std::process::Child;

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

/// The build recipe + target + stage key for a `build:` unit, shared by the ext4-path
/// helper and the materialize path so both agree on the stage identity. Errors for an
/// `image:` unit (callers dispatch on the source first).
fn build_recipe(
    unit: &crate::compose::Unit,
    global_build_args: &[(String, String)],
    build: Option<&BuildOpts>,
) -> Result<(crate::ensure::BuildRecipe, Option<String>, String)> {
    let crate::compose::Source::Build {
        dockerfiles,
        context,
        target,
        args,
    } = &unit.source
    else {
        bail!("service {:?} is not a build: unit", unit.name)
    };
    let mut build_args = global_build_args.to_vec();
    build_args.extend(args.iter().cloned());
    // compose semantics: one context for all the service's files.
    let contexts = vec![context.clone(); dockerfiles.len()];
    let key =
        crate::build::target_stage_key(dockerfiles, &contexts, &build_args, target.as_deref())?;
    let recipe = crate::ensure::BuildRecipe {
        dockerfiles: dockerfiles.clone(),
        contexts,
        build_args,
        kernel: build.map(|b| b.kernel.clone()),
        cloud_hypervisor: build.map(|b| b.cloud_hypervisor.clone()),
        agent: build.map(|b| b.agent.clone()),
        cache_registry: build.and_then(|b| b.cache_registry.clone()),
        cache_insecure: build.is_some_and(|b| b.cache_insecure),
    };
    Ok((recipe, target.clone(), key))
}

/// The shared build-tier ext4 path a `build:` unit resolves to, without building it: a pure
/// function of the stage fingerprint, so provisioning can address a unit before (or without)
/// materializing it. `global_build_args` are the run-wide `--build-arg`s the manager also
/// applies. Errors for an `image:` unit.
pub fn build_unit_ext4(
    state_dir: &Path,
    global_build_args: &[(String, String)],
    unit: &crate::compose::Unit,
) -> Result<PathBuf> {
    let (_recipe, _target, key) = build_recipe(unit, global_build_args, None)?;
    Ok(crate::ensure::build_tier_dir(state_dir, &key).join("runner.ext4"))
}

/// Ensure a `build:` unit is materialized in the shared build tier synchronously — the
/// microVM build path never awaits — streaming its build progress to `sink` when set, and
/// return its merged runtime config. This is the on-demand start path (the service manager
/// builds a profiled-down `build:` service the first time it is brought up). Concurrent
/// first-starts of the same stage serialize inside `ensure_build_tier` (a per-stage pull
/// lock), and share the one tier entry. Errors for an `image:` unit: those need the async
/// pull and are materialized up front, not on demand.
pub fn ensure_unit_build_sync(
    unit: &crate::compose::Unit,
    state_dir: &Path,
    idle: std::time::Duration,
    build: &BuildOpts,
    sink: Option<crate::build::ProgressSink>,
) -> Result<RunConfig> {
    if let crate::compose::Source::Image(_) = &unit.source {
        anyhow::bail!(
            "on-demand start of the image: service {:?} is not supported — \
             image services are materialized up front",
            unit.name
        );
    }
    let (recipe, target, key) = build_recipe(unit, &build.build_args, Some(build))?;
    let dir =
        crate::ensure::ensure_build_tier(state_dir, idle, &recipe, target.as_deref(), &key, sink)?;
    read_merged_config(unit, &dir.join("runner.ext4"))
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
        let vmm = crate::vmm::selected(cloud_hypervisor);
        // The one VMM spawn shared with `vk run`/`vk build`/the job VM: tied (PDEATHSIG)
        // so a service VMM dies with its owner, and clears CLOEXEC on the embedded-kernel
        // and pass-fds so they survive the exec into the VMM subprocess.
        crate::run::spawn_vmm(&*vmm, &spec).with_context(|| format!("spawning {}", vmm.name()))
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
        let err = ensure_unit_build_sync(
            &unit,
            Path::new("/nonexistent/state"),
            std::time::Duration::from_secs(1800),
            &opts,
            None,
        )
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
