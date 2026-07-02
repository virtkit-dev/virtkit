//! microVM lifecycle: prepare (overlay + cloud-hypervisor + wait for the in-guest
//! agent) and cleanup (ACPI poweroff, escalation, state removal). One VM per job.

use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use vk_core::addr::SocketAddr;

use crate::image::ResolvedImage;
use crate::jobctx::JobCtx;
use crate::vmm::Vmm;

/// A job VM's boot medium: a copy-on-write ext4 disk (with an optional initrd —
/// a self-booting image ships one; a generic guest on the all-built-in pinned
/// kernel needs none) or a cpio initramfs held in RAM.
enum Media {
    Disk {
        rootfs: PathBuf,
        initrd: Option<PathBuf>,
    },
    Initramfs {
        cpio: PathBuf,
    },
}

impl Media {
    fn files(&self) -> Vec<&Path> {
        match self {
            Media::Disk { rootfs, initrd } => {
                let mut v = vec![rootfs.as_path()];
                v.extend(initrd.as_deref());
                v
            }
            Media::Initramfs { cpio } => vec![cpio.as_path()],
        }
    }
}

pub async fn prepare(ctx: &JobCtx) -> Result<()> {
    let cfg = &ctx.cfg;
    // MICROVM_IMAGE selects the guest image (prefix-based); unset = local/default.
    let (kernel, media, generic) = match crate::image::resolve(ctx)? {
        ResolvedImage::Disk {
            rootfs,
            kernel,
            initrd,
            generic,
        } => (kernel, Media::Disk { rootfs, initrd }, generic),
        ResolvedImage::Initramfs { kernel, initramfs } => {
            (kernel, Media::Initramfs { cpio: initramfs }, true)
        }
    };
    // generic guests (cpio, or ext4 on the pinned guest kernel) boot virtkit-agent as PID 1;
    // self-booting images boot their own init off a disk.
    for p in media
        .files()
        .into_iter()
        .chain(std::iter::once(kernel.as_path()))
    {
        if !p.is_file() {
            bail!("image file missing: {}", p.display());
        }
    }
    if unsafe { libc::access(c"/dev/kvm".as_ptr(), libc::R_OK | libc::W_OK) } != 0 {
        bail!("no rw access to /dev/kvm (is the runner user in the kvm group?)");
    }
    let (cpus, mem) = vm_size(ctx)?;

    // A leftover job dir (failed cleanup, retried job id) must not leak a VM
    // or keep its tap leased.
    stop_vm(ctx);
    crate::net::release(ctx);
    if ctx.job_dir.exists() {
        std::fs::remove_dir_all(&ctx.job_dir)
            .with_context(|| format!("removing stale {}", ctx.job_dir.display()))?;
    }
    std::fs::create_dir_all(&ctx.job_dir)
        .with_context(|| format!("creating {}", ctx.job_dir.display()))?;
    // record the boot flavour for the run stage (a separate process) to pick the
    // guest shell: a cpio/OCI guest (alpine/distroless in RAM) has no bash.
    let _ = std::fs::write(
        ctx.job_dir.join("boot.kind"),
        match (generic, &media) {
            (true, Media::Disk { .. }) => "generic-disk",
            (true, Media::Initramfs { .. }) => "generic-cpio",
            (false, _) => "systemd",
        },
    );

    // Disk guests get a throwaway CoW overlay over the ro base; initramfs guests
    // have no disk at all (the rootfs is the cpio, in RAM).
    let overlay = ctx.overlay();
    if let Media::Disk { rootfs, .. } = &media {
        crate::qcow2::create_overlay(&overlay, rootfs)?;
    }

    let mut cmdline = match (generic, &media) {
        // generic disk guest (the default bundle): virtkit-agent is PID 1 on the ext4
        // root (virtio-blk + ext4 built into the pinned kernel) and serves the exec
        // channel directly — no systemd.
        (true, Media::Disk { .. }) => format!(
            "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/vk-agent \
             VIRTKIT_HOSTNAME={} VIRTKIT_VSOCK_PORT={}",
            cfg.vm.hostname, cfg.vm.vsock_port
        ),
        // generic cpio guest: virtkit-agent is PID 1 in the initramfs (no disk root)
        // and serves directly.
        (true, Media::Initramfs { .. }) => format!(
            "console=ttyS0 rdinit=/usr/local/bin/vk-agent VIRTKIT_HOSTNAME={} \
             VIRTKIT_VSOCK_PORT={}",
            cfg.vm.hostname, cfg.vm.vsock_port
        ),
        // self-booting image: virtkit-agent is PID 1, execs the image's captured
        // entrypoint (VIRTKIT_MODE=service) which brings up systemd; the in-guest
        // serve agent then runs as a systemd unit.
        (false, _) => format!(
            "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/vk-agent \
             VIRTKIT_MODE=service VIRTKIT_HOSTNAME={}",
            cfg.vm.hostname
        ),
    };

    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    if let Some(share) = &cfg.share {
        let vfsd_sock = ctx.vfsd_sock();
        let mut vfsd = cfg.virtiofsd_command(); // bundled `vk virtiofsd` unless configured
        vfsd.arg(format!("--socket-path={}", vfsd_sock.display()))
            .arg(format!("--shared-dir={}", share.dir.display()))
            .args(["--cache=auto", "--sandbox=none"]);
        if share.readonly {
            vfsd.arg("--readonly");
        }
        let child = spawn_detached(vfsd, &ctx.vfsd_log()).context("spawning virtiofsd")?;
        std::fs::write(ctx.vfsd_pidfile(), child.id().to_string())?;
        wait_for_socket(&vfsd_sock, Duration::from_secs(5))
            .context("virtiofsd did not create its socket")?;
        shares.push(crate::vmm::FsShare {
            tag: "workdir".into(),
            socket: vfsd_sock,
        });
    }

    // GitLab CI tools ([gitlab] dir): a second, read-only virtio-fs share. The
    // in-guest agent links the tools the job image lacks onto its PATH — dynamic,
    // so nothing is baked into the bundle and a host update needs no re-conversion.
    if let Some(gl) = &cfg.gitlab
        && let Some(dir) = &gl.dir
    {
        let sock = ctx.tools_vfsd_sock();
        let mut vfsd = cfg.virtiofsd_command();
        vfsd.arg(format!("--socket-path={}", sock.display()))
            .arg(format!("--shared-dir={}", dir.display()))
            .args(["--cache=auto", "--sandbox=none", "--readonly"]);
        let child =
            spawn_detached(vfsd, &ctx.tools_vfsd_log()).context("spawning the tools virtiofsd")?;
        std::fs::write(ctx.tools_vfsd_pidfile(), child.id().to_string())?;
        wait_for_socket(&sock, Duration::from_secs(5))
            .context("the tools virtiofsd did not create its socket")?;
        shares.push(crate::vmm::FsShare {
            tag: "vktools".into(),
            socket: sock,
        });
        cmdline.push_str(" VIRTKIT_TOOLS=vktools:/run/virtkit-tools");
    }

    let mut net = crate::vmm::Net::None;
    // (ip, prefix, gw, dns) once a tap is wired, rendered onto the cmdline below
    // in the form the chosen init understands.
    let mut net_info: Option<(String, u32, String, String)> = None;
    match cfg.net.mode.as_str() {
        "none" => {}
        "tap" => {
            if cfg.net.tap.is_empty() {
                bail!("net.mode = \"tap\" requires net.tap");
            }
            net = crate::vmm::Net::Tap {
                tap: cfg.net.tap.clone(),
                mac: cfg.net.mac.clone(),
            };
            if !cfg.net.ip.is_empty() {
                let (ip, prefix) = split_cidr(&cfg.net.ip)?;
                net_info = Some((ip, prefix, cfg.net.gw.clone(), cfg.net.dns.clone()));
            }
        }
        "pool" => {
            let lease = crate::net::allocate(ctx)?;
            net = crate::vmm::Net::Tap {
                tap: lease.tap.clone(),
                mac: lease.mac.clone(),
            };
            net_info = Some((lease.ip, lease.prefix.into(), lease.gw, lease.dns));
        }
        "switch" => {
            // Per-job userspace switch: no virtio-net device and no kernel `ip=`
            // (eth0 does not exist at kernel init) — the in-guest agent forks a
            // tap bridged to the switch over vsock, then sets a static address.
            // Spawn the switch (with the egress allowlist) so it is listening
            // before the guest dials it; then point the agent at it. The same
            // shared LAN/egress core the dev `fleet` uses.
            let (gateway, prefix, guest_ip) = crate::net::switch_addrs(&cfg.net.subnet)?;
            spawn_switch(ctx, gateway, prefix)?;
            cmdline.push_str(&format!(
                " VIRTKIT_NET_PORT={} VIRTKIT_VM_IP={guest_ip}/{prefix} \
                 VIRTKIT_VM_GW={gateway} VIRTKIT_VM_DNS={gateway}",
                cfg.net.net_port
            ));
        }
        other => bail!("unsupported net.mode {other:?} (none|tap|pool|switch)"),
    }
    if let Some((ip, prefix, gw, dns)) = net_info {
        // Both flavours bring eth0 up from the kernel `ip=` autoconfig param
        // (CONFIG_IP_PNP) at boot — earlier and more reliable than configuring it
        // from a userspace init. Format:
        // <client>:<server>:<gw>:<netmask>:<host>:<device>:<autoconf>.
        // The agent writes resolv.conf from VIRTKIT_VM_DNS.
        cmdline.push_str(" net.ifnames=0 biosdevname=0");
        cmdline.push_str(&format!(
            " ip={ip}::{gw}:{}::eth0:off",
            prefix_to_netmask(prefix)
        ));
        if !dns.is_empty() {
            cmdline.push_str(&format!(" VIRTKIT_VM_DNS={dns}"));
        }
    }

    // RAM scratch mounts (e.g. CI /builds): the agent mounts these (VIRTKIT_TMPFS)
    // before handing off to the payload, in any mode.
    if !cfg.guest.tmpfs.is_empty() {
        // lands on the kernel cmdline: a space or comma in an entry would split
        // or corrupt the VIRTKIT_TMPFS list the agent parses
        for entry in &cfg.guest.tmpfs {
            if !entry.starts_with('/')
                || !entry.contains(':')
                || entry.contains(|c: char| c.is_whitespace() || c == ',')
            {
                bail!("invalid guest.tmpfs entry {entry:?} (want \"/path:size\")");
            }
        }
        cmdline.push_str(&format!(" VIRTKIT_TMPFS={}", cfg.guest.tmpfs.join(",")));
    }

    // SSH-agent forwarding ([auth] ssh_agent): tell the guest agent to present
    // SSH_AUTH_SOCK and relay it over a vsock port to the host side (start_ssh_agent_forward
    // below). A no-op if the runner has no agent — warn so a misconfig is visible.
    if ssh_agent_forwarding(cfg) {
        cmdline.push_str(&format!(
            " VIRTKIT_SSH_AGENT_PORT={}",
            crate::run::SSH_AGENT_VSOCK_PORT
        ));
    } else if cfg.auth.ssh_agent {
        eprintln!("virtkit: [auth] ssh_agent set but SSH_AUTH_SOCK is unset — not forwarding");
    }

    if !cfg.vm.cmdline_extra.is_empty() {
        cmdline.push(' ');
        cmdline.push_str(&cfg.vm.cmdline_extra);
    }

    // kernel is common; the boot medium is either a CoW disk overlay (+ a
    // self-booting image's initrd) or a single cpio initramfs (the rootfs in RAM).
    // A generic guest on the pinned kernel ships no initrd (virtio-blk + ext4 built in).
    let (disks, initramfs) = match &media {
        Media::Disk { initrd, .. } => (
            vec![crate::vmm::Disk::overlay(overlay.clone())],
            initrd.clone(),
        ),
        Media::Initramfs { cpio } => (Vec::new(), Some(cpio.clone())),
    };

    // shared=on (set via shared_mem): required by virtio-fs, harmless without.
    let spec = crate::vmm::VmSpec {
        kernel,
        cmdline,
        disks,
        initramfs,
        shares,
        vsock_cid: 3,
        vsock_socket: ctx.vsock_sock(),
        cpus,
        mem: mem.clone(),
        shared_mem: true,
        net,
        balloon: cfg.vm.balloon,
        serial_log: ctx.console_log(),
        api_socket: Some(ctx.api_sock()),
    };
    let ch_command = crate::vmm::CloudHypervisor {
        bin: cfg.cloud_hypervisor().to_path_buf(),
    }
    .command(&spec);
    let mut ch_child = spawn_detached(ch_command, &ctx.ch_log())
        .with_context(|| format!("spawning {}", cfg.cloud_hypervisor().display()))?;
    std::fs::write(ctx.ch_pidfile(), ch_child.id().to_string())?;

    println!(
        "virtkit: booting microVM (cpus={cpus}, mem={mem}, {})",
        match &media {
            Media::Disk { .. } => "disk",
            Media::Initramfs { .. } => "cpio initramfs",
        }
    );

    // Ready = the in-guest virtkit-agent answers on vsock (systemd is up, the agent
    // socket is active). Each status attempt has its own internal timeout.
    let addr = SocketAddr::VsockMux {
        path: ctx.vsock_sock(),
        port: cfg.vm.vsock_port,
    };
    let start = Instant::now();
    let deadline = start + Duration::from_secs(cfg.vm.boot_timeout_secs);
    loop {
        // try_wait on the held Child: exact (no /proc parsing, no pid-reuse race)
        if let Some(status) = ch_child.try_wait()? {
            log_tail(&ctx.console_log(), 30);
            bail!(
                "cloud-hypervisor exited during boot ({status}, see {})",
                ctx.ch_log().display()
            );
        }
        match vk_core::status::get_status(&addr).await {
            Ok(status) => {
                // Fail fast on a wire-protocol skew (the guest bundle's virtkit-agent
                // predates this virtkit, or vice versa): rmp_serde structs are
                // fixed-length arrays, so a mismatched virtkit-agent cannot decode our
                // commands and would otherwise drop the connection mid-command with
                // an opaque "connection to the VM lost". A pre-versioning virtkit-agent
                // reports protocol 0.
                let want = vk_core::messages::PROTOCOL_VERSION;
                if status.protocol() != want {
                    bail!(
                        "guest vk-agent wire protocol v{} != vk v{want} — the guest \
                         bundle and the host are out of sync; rebuild/republish the guest \
                         bundle with a matching vk-agent",
                        status.protocol(),
                    );
                }
                println!(
                    "vk: VM ready in {:.1}s (vk-agent {status})",
                    start.elapsed().as_secs_f32()
                );
                start_ssh_agent_forward(ctx)?;
                start_services(ctx).await?;
                return Ok(());
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    log_tail(&ctx.console_log(), 30);
                    bail!(
                        "VM not ready after {}s ({e}) — console tail above, logs in {}",
                        cfg.vm.boot_timeout_secs,
                        ctx.job_dir.display()
                    );
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// SSH-agent forwarding is on when `[auth] ssh_agent` is set AND the runner actually has an
/// agent (`$SSH_AUTH_SOCK`). The guest side is driven by the cmdline var; the host side is
/// the forward started below.
fn ssh_agent_forwarding(cfg: &crate::config::Config) -> bool {
    cfg.auth.ssh_agent && std::env::var_os("SSH_AUTH_SOCK").is_some()
}

/// Host side of the SSH-agent forward ([auth] ssh_agent): the guest dials vsock port
/// SSH_AGENT_VSOCK_PORT, surfaced by cloud-hypervisor as `<vsock.sock>_<port>`; a detached
/// `vk forward` binds it and splices to the runner's `$SSH_AUTH_SOCK`. Only agent
/// protocol bytes cross — the keys never enter the guest. Torn down in cleanup via its pidfile.
fn start_ssh_agent_forward(ctx: &JobCtx) -> Result<()> {
    if !ssh_agent_forwarding(&ctx.cfg) {
        return Ok(());
    }
    let host_sock = std::env::var_os("SSH_AUTH_SOCK").expect("checked by ssh_agent_forwarding");
    let mut listen = ctx.vsock_sock().into_os_string();
    listen.push(format!("_{}", crate::run::SSH_AGENT_VSOCK_PORT));
    let listen = std::path::PathBuf::from(listen);

    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let mut fwd = Command::new(exe);
    fwd.arg("forward")
        .arg("--listen")
        .arg(&listen)
        .arg("--to")
        .arg(&host_sock);
    let child = spawn_detached(fwd, &ctx.ssh_agent_forward_log())
        .context("spawning the ssh-agent forward")?;
    std::fs::write(ctx.ssh_agent_forward_pidfile(), child.id().to_string())?;
    wait_for_socket(&listen, Duration::from_secs(5))
        .context("ssh-agent forward did not bind its socket")?;
    Ok(())
}

/// Bring up the job's CI `services:` once the VM is ready (no-op without any).
/// A host-side forward bridges the VMM's per-port vsock socket to the registry
/// proxy; then a root script in the guest starts the guest-side forward and each
/// service container (see services.rs). The registry credential lives only on
/// the host proxy — it never reaches the guest or the job.
async fn start_services(ctx: &JobCtx) -> Result<()> {
    let services = crate::services::from_env()?;
    if services.is_empty() {
        return Ok(());
    }
    let scfg = ctx.cfg.services.as_ref().ok_or_else(|| {
        anyhow!(
            "job declares services: but virtkit has no [services] config — \
             cannot satisfy them (configure the registry proxy)"
        )
    })?;

    // Host side of the registry forward. A guest connection to host vsock port
    // <port> is surfaced by Cloud Hypervisor as the unix socket
    // <vsock.sock>_<port>; our forward binds it and splices to the proxy.
    let mut listen = ctx.vsock_sock().into_os_string();
    listen.push(format!("_{}", scfg.port));
    let listen = std::path::PathBuf::from(listen);

    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let mut fwd = Command::new(exe);
    fwd.arg("forward")
        .arg("--listen")
        .arg(&listen)
        .arg("--to")
        .arg(format!("tcp://{}", scfg.registry_proxy));
    let child =
        spawn_detached(fwd, &ctx.svc_forward_log()).context("spawning the services forward")?;
    std::fs::write(ctx.svc_forward_pidfile(), child.id().to_string())?;
    // the guest's first pull must not race the host listener coming up
    wait_for_socket(&listen, Duration::from_secs(5))
        .context("services forward did not bind its socket")?;

    println!("virtkit: bringing up {} service(s)", services.len());
    let script = crate::services::setup_script(scfg, &services);
    // services are a systemd-guest feature (in-VM dockerd); use the configured shell
    let result = crate::executor::exec_script(
        &crate::executor::vsock_addr(ctx),
        &ctx.cfg.guest.run_command,
        script.into_bytes(),
        Some("root".into()),
    )
    .await
    .context("running the services setup in the guest")?;
    match (result.code, result.signal) {
        (Some(0), _) => Ok(()),
        (Some(c), _) => bail!("services setup failed in the guest (exit {c})"),
        (None, sig) => bail!("services setup killed in the guest (signal {sig:?})"),
    }
}

/// Spawn the per-job userspace switch (net.mode = "switch") as a detached child,
/// listening on the guest's vsock-bridge socket (`<vsock.sock>_<net_port>`) with
/// the `[egress]` allowlist, and wait for it to bind before the guest dials it.
/// Long-lived (it serves the VM's whole life); torn down in cleanup via its
/// pidfile. The switch is this same `virtkit` binary's `switch` subcommand.
fn spawn_switch(ctx: &JobCtx, gateway: Ipv4Addr, prefix: u8) -> Result<()> {
    let cfg = &ctx.cfg;
    let listen = ctx.net_vsock_sock(cfg.net.net_port);
    let _ = std::fs::remove_file(&listen);
    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let mut cmd = Command::new(exe);
    cmd.arg("switch")
        .arg("--listen")
        .arg(&listen)
        .arg("--gateway")
        .arg(gateway.to_string())
        .arg("--prefix")
        .arg(prefix.to_string());
    // allow_ip stays host-controlled; allow_name is the host cap by default, or a
    // job-narrowed subset of it (MICROVM_EGRESS_ALLOW_NAME).
    for cidr in &cfg.egress.allow_ip {
        cmd.arg("--allow-ip").arg(cidr);
    }
    for name in effective_allow_names(cfg, ctx)? {
        cmd.arg("--allow-name").arg(name);
    }
    let child = spawn_detached(cmd, &ctx.switch_log()).context("spawning the per-job switch")?;
    std::fs::write(ctx.switch_pidfile(), child.id().to_string())?;
    wait_for_socket(&listen, Duration::from_secs(5))
        .context("the per-job switch did not bind its socket")?;
    Ok(())
}

/// The switch `--allow-name` list for this job: the host `[egress]` cap by default,
/// or the job's `MICROVM_EGRESS_ALLOW_NAME` subset of it. The cap is host-only, so a
/// job can restrict its own egress (least privilege) but never widen it.
fn effective_allow_names(cfg: &crate::config::Config, ctx: &JobCtx) -> Result<Vec<String>> {
    match &ctx.egress_allow_name_req {
        None => Ok(cfg.egress.allow_name.clone()),
        Some(req) => narrow_allow_names(&cfg.egress.allow_ip, &cfg.egress.allow_name, req),
    }
}

/// Parse a space/comma separated `MICROVM_EGRESS_ALLOW_NAME` request and check each
/// name falls within the host `[egress]` cap, using the switch's own suffix
/// semantics. A name outside the cap is an error — the job cannot widen its egress.
///
/// The check is against the *full* host policy `Egress::new(allow_ip, allow_name)`,
/// not `allow_name` alone: the host egress is unrestricted only when both lists are
/// empty (`Egress::AllowAll`). An empty `allow_name` with a non-empty `allow_ip`
/// denies all names, so the job cannot add any — otherwise a job could append a name
/// to an IP-only cap and widen its egress.
fn narrow_allow_names(allow_ip: &[String], cap: &[String], req: &str) -> Result<Vec<String>> {
    let requested: Vec<String> = req
        .split([',', ' ', '\t', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let policy = crate::switch::Egress::new(allow_ip, cap)?;
    for name in &requested {
        if !policy.allows_host(name) {
            bail!(
                "MICROVM_EGRESS_ALLOW_NAME {name:?} is not within the host [egress] allow_name cap"
            );
        }
    }
    Ok(requested)
}

/// Effective vCPU count and memory size: the job's MICROVM_CPUS/MICROVM_MEM
/// requests, silently clamped to the host ceilings (vm.max_cpus/max_mem,
/// defaulting to the base values — config opt-in for any elevation).
fn vm_size(ctx: &JobCtx) -> Result<(u32, String)> {
    let vm = &ctx.cfg.vm;
    let cpus = match &ctx.cpus_req {
        None => vm.cpus,
        Some(s) => {
            let n: u32 = s
                .parse()
                .ok()
                .filter(|n| *n > 0)
                .with_context(|| format!("invalid MICROVM_CPUS {s:?}"))?;
            n.min(vm.max_cpus.unwrap_or(vm.cpus))
        }
    };
    let mem = match &ctx.mem_req {
        None => vm.mem.clone(),
        Some(s) => {
            let req = parse_gib(s).with_context(|| format!("invalid MICROVM_MEM {s:?}"))?;
            let max = match &vm.max_mem {
                Some(m) => parse_gib(m).context("invalid vm.max_mem")?,
                None => parse_gib(&vm.mem).context("invalid vm.mem")?,
            };
            format!("{}G", req.min(max))
        }
    };
    Ok((cpus, mem))
}

/// "<n>G" (GiB) — the only size format the sizing variables accept
fn parse_gib(s: &str) -> Result<u64> {
    let n = s
        .strip_suffix('G')
        .ok_or_else(|| anyhow!("expected <n>G"))?
        .parse::<u64>()?;
    if n == 0 {
        bail!("expected a non-zero size");
    }
    Ok(n)
}

/// Split "a.b.c.d/prefix" into (ip, prefix).
fn split_cidr(cidr: &str) -> Result<(String, u32)> {
    let (ip, p) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow!("net.ip {cidr:?} is not CIDR (a.b.c.d/prefix)"))?;
    let prefix: u32 = p
        .parse()
        .ok()
        .filter(|p| *p <= 32)
        .with_context(|| format!("invalid prefix in {cidr:?}"))?;
    Ok((ip.to_string(), prefix))
}

/// IPv4 prefix length → dotted netmask, for the kernel `ip=` autoconf param.
fn prefix_to_netmask(prefix: u32) -> String {
    let bits: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32))
    };
    format!(
        "{}.{}.{}.{}",
        (bits >> 24) & 0xff,
        (bits >> 16) & 0xff,
        (bits >> 8) & 0xff,
        bits & 0xff
    )
}

/// Stop the job's VM (and virtiofsd) if running: graceful ACPI power-button,
/// then forced VMM shutdown, then SIGKILL. Idempotent — every step tolerates an
/// already-gone process or a partial prepare.
pub fn stop_vm(ctx: &JobCtx) {
    if let Some(pid) = read_pidfile(&ctx.ch_pidfile()) {
        let tag = ctx.job_dir.to_string_lossy().into_owned();
        if pid_running(pid, &tag) {
            let api = ctx.api_sock();
            let _ = ch_api_put(&api, "vm.power-button");
            if !wait_gone(
                pid,
                &tag,
                Duration::from_secs(ctx.cfg.vm.shutdown_timeout_secs),
            ) {
                let _ = ch_api_put(&api, "vm.shutdown");
                if !wait_gone(pid, &tag, Duration::from_secs(5)) {
                    unsafe { libc::kill(pid, libc::SIGTERM) };
                    if !wait_gone(pid, &tag, Duration::from_secs(3)) {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                        wait_gone(pid, &tag, Duration::from_secs(3));
                    }
                }
            }
        }
    }
    for pidfile in [
        ctx.vfsd_pidfile(),
        ctx.tools_vfsd_pidfile(),
        ctx.switch_pidfile(),
    ] {
        if let Some(pid) = read_pidfile(&pidfile)
            && pid_running(pid, &ctx.job_dir.to_string_lossy())
        {
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }
    // the detached vk forward children (services registry proxy, ssh-agent) if started
    for pidfile in [ctx.svc_forward_pidfile(), ctx.ssh_agent_forward_pidfile()] {
        if let Some(pid) = read_pidfile(&pidfile)
            && pid_running(pid, &ctx.job_dir.to_string_lossy())
        {
            unsafe { libc::kill(pid, libc::SIGTERM) };
        }
    }
}

pub fn cleanup(ctx: &JobCtx) -> Result<()> {
    stop_vm(ctx);
    crate::net::release(ctx);
    match std::fs::remove_dir_all(&ctx.job_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", ctx.job_dir.display())),
    }
}

/// Spawn a long-lived child in its own process group (it must survive this
/// short-lived executor stage and never receive its signals), stdout+stderr
/// appended to a log file. The returned Child is never killed on drop; later
/// stages find the process again through its pidfile.
fn spawn_detached(mut cmd: Command, log: &Path) -> Result<std::process::Child> {
    let logfile = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening {}", log.display()))?;
    Ok(cmd
        .stdin(Stdio::null())
        .stdout(logfile.try_clone()?)
        .stderr(logfile)
        .process_group(0)
        .spawn()?)
}

fn wait_for_socket(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while !path.exists() {
        if Instant::now() >= deadline {
            bail!("{} did not appear within {timeout:?}", path.display());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(())
}

fn read_pidfile(path: &Path) -> Option<i32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// A recorded pid counts as ours only while its cmdline still references the job
/// dir — guards the kill/wait logic against pid reuse after a crash.
fn pid_running(pid: i32, expect_in_cmdline: &str) -> bool {
    let Ok(cmdline) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
        return false;
    };
    String::from_utf8_lossy(&cmdline)
        .replace('\0', " ")
        .contains(expect_in_cmdline)
}

fn wait_gone(pid: i32, expect_in_cmdline: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while pid_running(pid, expect_in_cmdline) {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    true
}

/// Minimal HTTP PUT on the Cloud Hypervisor API socket (same calls as
/// shutdown.sh's `curl --unix-socket`); not worth an HTTP client dependency.
fn ch_api_put(sock: &Path, endpoint: &str) -> Result<()> {
    let mut stream = UnixStream::connect(sock)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    write!(
        stream,
        "PUT /api/v1/{endpoint} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
    )?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf)?;
    let resp = String::from_utf8_lossy(&buf[..n]);
    if resp.starts_with("HTTP/1.1 2") {
        Ok(())
    } else {
        Err(anyhow!(
            "{endpoint}: {}",
            resp.lines().next().unwrap_or("no response")
        ))
    }
}

/// Dump the end of the serial console to stderr — the only useful trace when the
/// guest never brings virtkit-agent up.
fn log_tail(path: &Path, lines: usize) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return;
    };
    let all: Vec<&str> = text.lines().collect();
    let tail = &all[all.len().saturating_sub(lines)..];
    if !tail.is_empty() {
        eprintln!("--- console tail ({}) ---", path.display());
        for line in tail {
            eprintln!("{line}");
        }
        eprintln!("--- end console tail ---");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::jobctx::JobCtx;

    fn ctx(cpus_req: Option<&str>, mem_req: Option<&str>) -> JobCtx {
        let mut cfg = Config::default();
        cfg.vm.cpus = 4;
        cfg.vm.mem = "8G".into();
        cfg.vm.max_cpus = Some(16);
        cfg.vm.max_mem = Some("64G".into());
        let mut ctx = JobCtx::new_for_job(cfg, "42".into()).unwrap();
        ctx.cpus_req = cpus_req.map(String::from);
        ctx.mem_req = mem_req.map(String::from);
        ctx
    }

    #[test]
    fn sizing() {
        assert_eq!(vm_size(&ctx(None, None)).unwrap(), (4, "8G".into()));
        assert_eq!(
            vm_size(&ctx(Some("12"), Some("32G"))).unwrap(),
            (12, "32G".into())
        );
        // clamped to the ceilings
        assert_eq!(
            vm_size(&ctx(Some("64"), Some("256G"))).unwrap(),
            (16, "64G".into())
        );
        // garbage rejected
        assert!(vm_size(&ctx(Some("zero"), None)).is_err());
        assert!(vm_size(&ctx(Some("0"), None)).is_err());
        assert!(vm_size(&ctx(None, Some("64"))).is_err());
        assert!(vm_size(&ctx(None, Some("4096M"))).is_err());
    }

    #[test]
    fn per_job_allow_name_narrows_within_cap() {
        let cap = vec!["corp.example.com".to_string(), "github.com".to_string()];
        // a subset (exact + under a suffix) is accepted, returned as the job's set
        assert_eq!(
            narrow_allow_names(&[], &cap, "gitlab.corp.example.com, github.com").unwrap(),
            vec![
                "gitlab.corp.example.com".to_string(),
                "github.com".to_string()
            ]
        );
        // a name outside the cap fails the job (no widening)
        assert!(narrow_allow_names(&[], &cap, "pypi.org").is_err());
        assert!(narrow_allow_names(&[], &cap, "gitlab.corp.example.com pypi.org").is_err());
        // both caps empty = unrestricted host egress (AllowAll), so any name is within it
        assert_eq!(
            narrow_allow_names(&[], &[], "anything.example").unwrap(),
            vec!["anything.example".to_string()]
        );
        // an IP-only cap (allow_ip set, allow_name empty) allows NO names: the host
        // permits no name egress, so a job cannot add one and widen past the cap.
        let ip_cap = vec!["10.0.0.0/8".to_string()];
        assert!(narrow_allow_names(&ip_cap, &[], "evil.example").is_err());
    }

    #[test]
    fn cidr_and_netmask() {
        assert_eq!(
            split_cidr("192.168.231.16/24").unwrap(),
            ("192.168.231.16".into(), 24)
        );
        assert_eq!(split_cidr("10.0.0.1/8").unwrap(), ("10.0.0.1".into(), 8));
        assert!(split_cidr("10.0.0.1").is_err());
        assert!(split_cidr("10.0.0.1/33").is_err());
        assert_eq!(prefix_to_netmask(24), "255.255.255.0");
        assert_eq!(prefix_to_netmask(16), "255.255.0.0");
        assert_eq!(prefix_to_netmask(8), "255.0.0.0");
        assert_eq!(prefix_to_netmask(0), "0.0.0.0");
        assert_eq!(prefix_to_netmask(32), "255.255.255.255");
    }
}
