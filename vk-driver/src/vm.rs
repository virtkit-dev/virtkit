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

use crate::image::ResolvedImage;
use crate::jobctx::JobCtx;

/// The boot medium: a read-only base rootfs (booted through a CoW overlay) plus a
/// self-booting image's own initrd, if it shipped one.
struct Media {
    rootfs: PathBuf,
    initrd: Option<PathBuf>,
}

impl Media {
    fn files(&self) -> Vec<&Path> {
        let mut v = vec![self.rootfs.as_path()];
        v.extend(self.initrd.as_deref());
        v
    }
}

pub async fn prepare(ctx: &JobCtx) -> Result<()> {
    let cfg = &ctx.cfg;
    // Fail-fast preflight in the runner-visible process (crisp errors beat a
    // supervisor log pointer); the supervisor re-resolves from the same env.
    let (kernel, media, _generic) = resolve_media(ctx)?;
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

    // A leftover job (failed cleanup, retried job id) must not leak: signal its
    // supervisor — everything it owns cascades by PDEATHSIG — and drop the state.
    stop_supervisor(ctx);
    crate::net::release(ctx);
    if ctx.job_dir.exists() {
        std::fs::remove_dir_all(&ctx.job_dir)
            .with_context(|| format!("removing stale {}", ctx.job_dir.display()))?;
    }
    std::fs::create_dir_all(&ctx.job_dir)
        .with_context(|| format!("creating {}", ctx.job_dir.display()))?;

    // ONE detached process owns the job from here (the runner protocol requires
    // this stage to exit — ready is signaled by exiting 0): the supervisor spawns
    // the switch/virtiofsds/forwards/VMM as tied children, supervises them, and
    // tears everything down on SIGTERM (cleanup) or by dying. The job dir on its
    // cmdline is the pid-reuse guard for the later signal.
    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let mut sup_cmd = Command::new(exe);
    sup_cmd.args(["gitlab", "supervise"]).arg(&ctx.job_dir);
    let mut sup =
        spawn_detached(sup_cmd, &ctx.supervisor_log()).context("spawning the job supervisor")?;

    println!("virtkit: booting microVM (cpus={cpus}, mem={mem})");

    // Ready = the in-guest virtkit-agent answers on vsock. The supervisor exiting
    // during boot (the VMM died, a helper failed to start) fails the poll fast.
    let addr = crate::vmm::exec_addr(&ctx.vsock_sock(), cfg.vm.vsock_port);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(cfg.vm.boot_timeout_secs);
    loop {
        if let Some(status) = sup.try_wait()? {
            log_tail(&ctx.supervisor_log(), 15);
            log_tail(&ctx.console_log(), 30);
            bail!(
                "the job supervisor exited during boot ({status}, see {})",
                ctx.supervisor_log().display()
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
                probe_guest_shell(ctx, &addr).await;
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

/// Resolve MICROVM_IMAGE to the boot files (kernel + rootfs + optional initrd).
fn resolve_media(ctx: &JobCtx) -> Result<(PathBuf, Media, bool)> {
    match crate::image::resolve(ctx)? {
        ResolvedImage::Disk {
            rootfs,
            kernel,
            initrd,
            generic,
        } => Ok((kernel, Media { rootfs, initrd }, generic)),
    }
}

/// The detached job supervisor (`vk gitlab supervise <job_dir>`, spawned by
/// prepare): assembles and boots everything the job needs — switch, virtiofsds,
/// forwards, the VMM — as tied children (PDEATHSIG), then supervises. SIGTERM
/// (cleanup, or the stale-state sweep) shuts the guest down gracefully and exits;
/// the children cascade. Readiness is prepare's business (it polls the agent).
pub async fn supervise(ctx: &JobCtx, job_dir_arg: &Path) -> Result<()> {
    if job_dir_arg != ctx.job_dir {
        bail!(
            "supervise arg {} != the job dir the environment derives ({}) — refusing",
            job_dir_arg.display(),
            ctx.job_dir.display()
        );
    }
    // The pidfile is written by this process (not prepare): it exists from the
    // first moment there is something to signal, whatever happens to prepare.
    std::fs::write(ctx.supervisor_pidfile(), std::process::id().to_string())
        .with_context(|| format!("writing {}", ctx.supervisor_pidfile().display()))?;

    let cfg = &ctx.cfg;
    let (kernel, media, generic) = resolve_media(ctx)?;
    let (cpus, mem) = vm_size(ctx)?;
    // The agent backs each service boot (it rides the boot initramfs) and any
    // service build; an embedded copy lives in a memfd whose path is valid only
    // while this handle is open — supervise runs for the job's whole life.
    // `[build] agent` overrides, as everywhere else.
    let agent = crate::embed::resolve(crate::embed::Asset::Agent, cfg.build.agent.as_deref())?;
    let mut children: Vec<std::process::Child> = Vec::new();
    // Every guest gets a throwaway CoW overlay over the ro base rootfs.
    let overlay = ctx.overlay();
    crate::qcow2::create_overlay(&overlay, &media.rootfs)?;

    let mut cmdline = if generic {
        // generic guest (the default bundle): virtkit-agent is PID 1 on the ext4
        // root (virtio-blk + ext4 built into the pinned kernel) and serves the exec
        // channel directly — no systemd.
        format!(
            "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/vk-agent \
             VIRTKIT_HOSTNAME={} VIRTKIT_VSOCK_PORT={}",
            cfg.vm.hostname, cfg.vm.vsock_port
        )
    } else {
        // self-booting image: virtkit-agent is PID 1, execs the image's captured
        // entrypoint (VIRTKIT_MODE=service) which brings up systemd; the in-guest
        // serve agent then runs as a systemd unit.
        format!(
            "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/vk-agent \
             VIRTKIT_MODE=service VIRTKIT_HOSTNAME={}",
            cfg.vm.hostname
        )
    };

    let mut shares: Vec<crate::vmm::FsShare> = Vec::new();
    if let Some(share) = &cfg.share {
        let vfsd_sock = ctx.vfsd_sock();
        // libkrun mounts the host dir directly (built-in virtio-fs); only
        // cloud-hypervisor needs an external virtiofsd on the socket.
        if !crate::vmm::libkrun_selected() {
            let mut vfsd = cfg.virtiofsd_command(); // bundled `vk virtiofsd` unless configured
            vfsd.arg(format!("--socket-path={}", vfsd_sock.display()))
                .arg(format!("--shared-dir={}", share.dir.display()))
                .args(["--cache=auto", "--sandbox=none"]);
            if share.readonly {
                vfsd.arg("--readonly");
            }
            children.push(spawn_tied_logged(vfsd, &ctx.vfsd_log()).context("spawning virtiofsd")?);
            wait_for_socket(&vfsd_sock, Duration::from_secs(5))
                .context("virtiofsd did not create its socket")?;
        }
        shares.push(crate::vmm::FsShare {
            tag: "workdir".into(),
            socket: vfsd_sock,
            host_dir: share.dir.clone(),
            read_only: share.readonly,
        });
    }

    // GitLab CI tools ([gitlab] dir): a second, read-only virtio-fs share. The
    // in-guest agent links the tools the job image lacks onto its PATH — dynamic,
    // so nothing is baked into the bundle and a host update needs no re-conversion.
    if let Some(gl) = &cfg.gitlab
        && let Some(dir) = &gl.dir
    {
        let sock = ctx.tools_vfsd_sock();
        if !crate::vmm::libkrun_selected() {
            let mut vfsd = cfg.virtiofsd_command();
            vfsd.arg(format!("--socket-path={}", sock.display()))
                .arg(format!("--shared-dir={}", dir.display()))
                .args(["--cache=auto", "--sandbox=none", "--readonly"]);
            children.push(
                spawn_tied_logged(vfsd, &ctx.tools_vfsd_log())
                    .context("spawning the tools virtiofsd")?,
            );
            wait_for_socket(&sock, Duration::from_secs(5))
                .context("the tools virtiofsd did not create its socket")?;
        }
        shares.push(crate::vmm::FsShare {
            tag: "vktools".into(),
            socket: sock,
            host_dir: dir.clone(),
            read_only: true,
        });
        cmdline.push_str(" VIRTKIT_TOOLS=vktools:/run/virtkit-tools");
    }

    let mut net = crate::vmm::Net::None;
    // services: need the per-job LAN — they are sibling VMs on the switch.
    if cfg.net.mode != "switch" && !crate::services::from_env()?.is_empty() {
        bail!(
            "the job declares services:, which boot as sibling VMs on the per-job \
             switch — set [net] mode = \"switch\" (got {:?})",
            cfg.net.mode
        );
    }
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
            // shared LAN/egress core `run --compose` uses.
            let (gateway, prefix, guest_ip) = crate::net::switch_addrs(&cfg.net.subnet)?;
            let services = plan_services(ctx, gateway, prefix, &agent.path).await?;
            // the switch binds each service's vsock socket at startup: the
            // runtime dirs must exist before it spawns.
            for svc in &services {
                std::fs::create_dir_all(ctx.job_dir.join(format!("svc-{}", svc.name)))
                    .with_context(|| format!("creating service dir for {}", svc.name))?;
            }
            children.push(spawn_switch(ctx, gateway, prefix, &services)?);
            for svc in &services {
                let dir = ctx.job_dir.join(format!("svc-{}", svc.name));
                let (child, aux) = crate::units::boot_unit(
                    svc,
                    &dir,
                    &cfg.local.generic_kernel,
                    cfg.cloud_hypervisor(),
                    &agent.path,
                    cfg.net.net_port,
                    gateway,
                )
                .with_context(|| format!("booting service {}", svc.name))?;
                println!("virtkit: service {} booting ({})", svc.name, svc.ip);
                children.push(child);
                children.extend(aux);
            }
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
    // SSH_AUTH_SOCK and relay it over a vsock port to the host side (the forward from
    // ssh_agent_forward_command, started by the supervisor). A no-op if the runner has
    // no agent — warn so a misconfig is visible.
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

    // kernel is common; the boot medium is the CoW disk overlay plus a
    // self-booting image's initrd. A generic guest on the pinned kernel ships
    // no initrd (virtio-blk + ext4 built in).
    let disks = vec![crate::vmm::Disk::overlay(overlay.clone())];
    let initramfs = media.initrd;

    // shared=on (set via shared_mem): required by virtio-fs, harmless without.
    // vsock ports the guest uses: the exec channel always, plus the switch bridge in
    // `switch` net mode (guest egress over the userspace switch) and the ssh-agent
    // bridge when agent forwarding is on. Tap/pool networking uses a virtio-net device,
    // not vsock. Only the libkrun backend consumes this; cloud-hypervisor derives it.
    let mut vsock_ports = vec![crate::vmm::VsockPort::exec(
        &ctx.vsock_sock(),
        cfg.vm.vsock_port,
    )];
    if cfg.net.mode == "switch" {
        vsock_ports.push(crate::vmm::VsockPort::bridge(
            &ctx.vsock_sock(),
            cfg.net.net_port,
        ));
    }
    if ssh_agent_forwarding(cfg) {
        vsock_ports.push(crate::vmm::VsockPort::bridge(
            &ctx.vsock_sock(),
            crate::run::SSH_AGENT_VSOCK_PORT,
        ));
    }

    let spec = crate::vmm::VmSpec {
        kernel,
        cmdline,
        disks,
        initramfs,
        shares,
        vsock_cid: 3,
        vsock_socket: ctx.vsock_sock(),
        vsock_ports,
        cpus,
        mem: mem.clone(),
        shared_mem: true,
        net,
        balloon: cfg.vm.balloon,
        serial_log: ctx.console_log(),
        // libkrun has no API socket (it is driven as a subprocess); cloud-hypervisor
        // uses one for graceful shutdown in graceful_vmm_stop.
        api_socket: (!crate::vmm::libkrun_selected()).then(|| ctx.api_sock()),
        pass_fds: Vec::new(),
    };
    // passive listeners the guest dials once up: safe (and simplest) to start before
    // the VMM, and intentionally not bind-waited — they bind long before the guest
    // boots far enough to dial them. Both are plain `vk forward` children.
    if let Some(fwd) = ssh_agent_forward_command(ctx)? {
        children.push(
            spawn_tied_logged(fwd, &ctx.ssh_agent_forward_log())
                .context("spawning the ssh-agent forward")?,
        );
    }
    let vmm = crate::vmm::selected(cfg.cloud_hypervisor());
    let ch_command = vmm.command(&spec);
    let mut vmm_child = spawn_tied_logged(ch_command, &ctx.ch_log())
        .with_context(|| format!("spawning the {} VMM", vmm.name()))?;

    // Own the job until told to stop (SIGTERM: cleanup or a stale-state sweep) or
    // the guest dies on its own. Tied children die with this process either way;
    // the explicit kills below just make teardown prompt instead of lazy.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing the SIGTERM handler")?;
    loop {
        tokio::select! {
            _ = term.recv() => {
                graceful_vmm_stop(ctx, &mut vmm_child);
                for mut c in children {
                    let _ = c.kill();
                    let _ = c.wait();
                }
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                if let Some(status) = vmm_child.try_wait()? {
                    for mut c in children {
                        let _ = c.kill();
                        let _ = c.wait();
                    }
                    bail!("{} exited ({status})", vmm.name());
                }
                // any owned helper dying (the switch, a service VM, a virtiofsd,
                // a forward) leaves a broken job: fail loudly rather than limp.
                for c in &mut children {
                    if let Some(status) = c.try_wait()? {
                        graceful_vmm_stop(ctx, &mut vmm_child);
                        for mut c in children {
                            let _ = c.kill();
                            let _ = c.wait();
                        }
                        bail!("a supervised helper exited ({status}) — job torn down");
                    }
                }
            }
        }
    }
}

/// SSH-agent forwarding is on when `[auth] ssh_agent` is set AND the runner actually has an
/// agent (`$SSH_AUTH_SOCK`). The guest side is driven by the cmdline var; the host side is
/// the forward started below.
fn ssh_agent_forwarding(cfg: &crate::config::Config) -> bool {
    cfg.auth.ssh_agent && std::env::var_os("SSH_AUTH_SOCK").is_some()
}

/// Host side of the SSH-agent forward ([auth] ssh_agent): the guest dials vsock
/// port SSH_AGENT_VSOCK_PORT, surfaced by the VMM as `<vsock.sock>_<port>`; a
/// `vk forward` binds it and splices to the runner's `$SSH_AUTH_SOCK`. Only agent
/// protocol bytes cross — the keys never enter the guest. `None` when forwarding
/// is off. A passive listener: started before the guest, no readiness to wait for.
fn ssh_agent_forward_command(ctx: &JobCtx) -> Result<Option<Command>> {
    if !ssh_agent_forwarding(&ctx.cfg) {
        return Ok(None);
    }
    let host_sock = std::env::var_os("SSH_AUTH_SOCK").expect("checked by ssh_agent_forwarding");
    let mut listen = ctx.vsock_sock().into_os_string();
    listen.push(format!("_{}", crate::run::SSH_AGENT_VSOCK_PORT));

    let exe = std::env::current_exe().context("locating the virtkit binary")?;
    let mut fwd = Command::new(exe);
    fwd.arg("forward")
        .arg("--listen")
        .arg(&listen)
        .arg("--to")
        .arg(&host_sock);
    Ok(Some(fwd))
}

/// Probe the booted guest for bash and record the result for the run stage (a
/// separate process): the configured run_command (bash) serves most images, but a
/// bash-less OCI guest (alpine, distroless) needs the POSIX-sh fallback. Probing
/// the actual guest replaces the old medium-based guess (cpio => sh), which broke
/// bash-less images once generic bundles became ext4 disks. Best-effort: an
/// unreadable marker falls back to the configured command.
async fn probe_guest_shell(ctx: &JobCtx, addr: &vk_core::addr::SocketAddr) {
    let has_bash = matches!(
        crate::executor::exec_script(
            addr,
            &["sh".to_string()],
            b"command -v bash >/dev/null 2>&1".to_vec(),
            None,
        )
        .await,
        Ok(res) if res.code == Some(0)
    );
    let _ = std::fs::write(
        ctx.job_dir.join("guest.shell"),
        if has_bash { "configured" } else { "sh" },
    );
}

/// Map the job's `services:` onto provisioned units: parse + alias-map, ensure
/// each clean image in the shared content-addressed store (first job pays the
/// pull, concurrent jobs flock and share), assign static addresses from the top
/// of the job subnet and CIDs from the service range, and merge each unit's boot
/// config (image defaults + service `variables:`/entrypoint/command overrides).
async fn plan_services(
    ctx: &JobCtx,
    gateway: Ipv4Addr,
    prefix: u8,
    agent: &Path,
) -> Result<Vec<crate::units::Provisioned>> {
    let units = crate::services::to_units(crate::services::from_env()?);
    if units.is_empty() {
        return Ok(Vec::new());
    }
    let build = crate::units::BuildOpts {
        build_args: Vec::new(),
        kernel: ctx.cfg.local.generic_kernel.clone(),
        cloud_hypervisor: ctx.cfg.cloud_hypervisor().to_path_buf(),
        agent: agent.to_path_buf(),
        cache_registry: None,
        cache_insecure: false,
    };
    let store = ctx.cfg.services_store();
    std::fs::create_dir_all(&store).with_context(|| format!("creating {}", store.display()))?;
    let mut out = Vec::new();
    for (slot, unit) in units.into_iter().enumerate() {
        let (ext4, config) = crate::units::ensure_unit_store(&unit, &store, &build)
            .await
            .with_context(|| format!("service {}", unit.name))?;
        let ip = crate::units::nth_static_ip(gateway, prefix, slot as u32)?;
        out.push(crate::units::Provisioned {
            name: unit.name,
            hostname: unit.hostname,
            ext4,
            ip: format!("{ip}/{prefix}"),
            cid: crate::units::FIRST_SERVICE_CID + slot as u32,
            config,
            volumes: Vec::new(),
        });
    }
    Ok(out)
}

/// The per-job userspace switch (net.mode = "switch"): a tied supervisor child
/// listening on the guest's vsock-bridge socket (`<vsock.sock>_<net_port>`) with
/// the `[egress]` allowlist, awaited until it binds before the guest dials it.
/// The switch is this same `virtkit` binary's `switch` subcommand.
fn spawn_switch(
    ctx: &JobCtx,
    gateway: Ipv4Addr,
    prefix: u8,
    services: &[crate::units::Provisioned],
) -> Result<std::process::Child> {
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
    // each service VM's vsock bridge socket, plus its alias in the gateway
    // resolver — the job (and the services themselves) resolve plain aliases.
    for svc in services {
        let sock = ctx
            .job_dir
            .join(format!("svc-{}", svc.name))
            .join(format!("vsock.sock_{}", cfg.net.net_port));
        cmd.arg("--listen").arg(sock);
        let ip = svc.ip.split('/').next().unwrap_or_default();
        cmd.arg("--host").arg(format!("{}={ip}", svc.hostname));
    }
    // allow_ip stays host-controlled; allow_name is the host cap by default, or a
    // job-narrowed subset of it (MICROVM_EGRESS_ALLOW_NAME).
    for cidr in &cfg.egress.allow_ip {
        cmd.arg("--allow-ip").arg(cidr);
    }
    for name in effective_allow_names(cfg, ctx)? {
        cmd.arg("--allow-name").arg(name);
    }
    let child = spawn_tied_logged(cmd, &ctx.switch_log()).context("spawning the per-job switch")?;
    wait_for_socket(&listen, Duration::from_secs(5))
        .context("the per-job switch did not bind its socket")?;
    Ok(child)
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

/// Signal the job's supervisor and wait for it to go — everything it owns (the
/// switch, virtiofsds, forwards, the VMM after its graceful guest shutdown)
/// follows, by its TERM handler or by PDEATHSIG. Idempotent: tolerates a missing
/// or stale pidfile (the job-dir cmdline tag guards against pid reuse).
pub fn stop_supervisor(ctx: &JobCtx) {
    let Some(pid) = read_pidfile(&ctx.supervisor_pidfile()) else {
        return;
    };
    let tag = ctx.job_dir.to_string_lossy().into_owned();
    if !pid_running(pid, &tag) {
        return;
    }
    unsafe { libc::kill(pid, libc::SIGTERM) };
    // the supervisor's own teardown runs the graceful guest shutdown; give it
    // that budget plus margin before the hammer.
    let grace = Duration::from_secs(ctx.cfg.vm.shutdown_timeout_secs + 15);
    if !wait_gone(pid, &tag, grace) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        wait_gone(pid, &tag, Duration::from_secs(3));
    }
}

/// Gracefully stop the supervisor's own VMM child: ACPI power-button over the API
/// socket, then vm.shutdown, then SIGTERM/SIGKILL — each step only if the previous
/// one did not end the process. libkrun has no API socket: TERM then KILL.
fn graceful_vmm_stop(ctx: &JobCtx, child: &mut std::process::Child) {
    let timeout = Duration::from_secs(ctx.cfg.vm.shutdown_timeout_secs);
    if crate::vmm::libkrun_selected() {
        unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        if !wait_child_gone(child, timeout) {
            let _ = child.kill();
            let _ = child.wait();
        }
        return;
    }
    let api = ctx.api_sock();
    let _ = ch_api_put(&api, "vm.power-button");
    if !wait_child_gone(child, timeout) {
        let _ = ch_api_put(&api, "vm.shutdown");
        if !wait_child_gone(child, Duration::from_secs(5)) {
            unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
            if !wait_child_gone(child, Duration::from_secs(3)) {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

/// Poll the held child (exact — no /proc parsing, no pid-reuse race) until it
/// exits or `timeout` passes.
fn wait_child_gone(child: &mut std::process::Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn cleanup(ctx: &JobCtx) -> Result<()> {
    stop_supervisor(ctx);
    crate::net::release(ctx);
    match std::fs::remove_dir_all(&ctx.job_dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", ctx.job_dir.display())),
    }
}

/// Spawn a tied child (PDEATHSIG — it dies with this process, see
/// `spawn::spawn_tied`) with stdout+stderr appended to a log file. The
/// supervisor's spawn primitive: children need no pidfiles, killing the
/// supervisor cascades.
fn spawn_tied_logged(mut cmd: Command, log: &Path) -> Result<std::process::Child> {
    let logfile = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log)
        .with_context(|| format!("opening {}", log.display()))?;
    cmd.stdin(Stdio::null())
        .stdout(logfile.try_clone()?)
        .stderr(logfile);
    crate::spawn::spawn_tied(cmd).map_err(Into::into)
}

/// Spawn a long-lived child in its own process group (it must survive this
/// short-lived executor stage and never receive its signals), stdout+stderr
/// appended to a log file. The returned Child is never killed on drop; later
/// stages find the process again through its pidfile. Only the job supervisor is
/// spawned this way — everything else is its tied child.
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
