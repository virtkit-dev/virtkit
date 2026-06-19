//! `virtkit fleet` — orchestrate a fleet of microVMs on one shared LAN, in
//! Rust: run the userspace switch in-process (no subprocess) and boot the VMs
//! natively (the Rust successor of the former launch-{service,builder}.sh). The builder
//! (`--builder`) shares /workdir + the git worktree over virtiofs and DHCPs an
//! address; declared services (`--service`) get static *.lan addresses.
//!
//! Both boot init=/usr/local/bin/virtkit-agent (the agent's init modes). Each
//! service: a throwaway CoW overlay over its ext4, the agent execs the image's
//! captured entrypoint (VIRTKIT_MODE=service) on a static *.lan address. The
//! builder: a CoW overlay (keyed on the base fs UUID), the agent serves vsock +
//! ssh with two virtiofs shares (workdir + gitdir) and DHCP.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use virtkit_agent::fleetctl::{Reply, Request, UnitStatus};

/// One fleet VM unit: `name:ext4:ip/cidr:cid[:workdir]`. The agent (PID 1) always
/// execs the image's captured entrypoint (VIRTKIT_MODE=service). The optional
/// `workdir` flag also shares the live repo READ-ONLY into the unit (for an image
/// whose entrypoint assembles itself from /workdir and then execs systemd) —
/// otherwise it is a plain service (redis, mysql) that just runs its image.
struct Service {
    name: String,
    ext4: PathBuf,
    ip: String,
    cid: u32,
    /// share the live repo (workdir + git dir) read-only into the unit
    workdir: bool,
}

impl Service {
    fn parse(spec: &str) -> Result<Self> {
        let parts: Vec<&str> = spec.split(':').collect();
        let (name, ext4, ip, cid, workdir) = match parts.as_slice() {
            [name, ext4, ip, cid] => (*name, *ext4, *ip, *cid, false),
            [name, ext4, ip, cid, "workdir"] => (*name, *ext4, *ip, *cid, true),
            [_, _, _, _, flag] => bail!("bad --service flag {flag:?} (want `workdir`)"),
            _ => bail!("bad --service {spec:?} (want name:ext4:ip/cidr:cid[:workdir])"),
        };
        Ok(Service {
            name: name.to_string(),
            ext4: PathBuf::from(ext4),
            ip: ip.to_string(),
            cid: cid.parse().with_context(|| format!("cid in {spec:?}"))?,
            workdir,
        })
    }

    /// State dir for this VM (where its sockets/overlay/console live).
    fn dir(&self) -> &Path {
        self.ext4.parent().unwrap_or(Path::new("."))
    }
}

/// The builder VM: shares /workdir (+ the git worktree) over virtiofs and DHCPs an
/// address on the shared LAN. Booted in-process when `--builder` is given.
pub struct BuilderOpts {
    pub ext4: PathBuf,
    pub name: String,
    /// host dir shared rw as /workdir
    pub workdir: PathBuf,
    /// the main repo's git dir to share at the same guest path (worktree); derived
    /// from `workdir` when None
    pub git_dir: Option<PathBuf>,
    pub cid: u32,
    pub cpus: u32,
    pub mem: String,
    /// build-builder-image.sh to (re)build the ext4 when stale; None skips the check
    pub build_script: Option<PathBuf>,
}

impl BuilderOpts {
    fn dir(&self) -> &Path {
        self.ext4.parent().unwrap_or(Path::new("."))
    }
}

/// Parse the fleet host map (`name=ip,name=ip`) into name -> IPv4 for the gateway
/// resolver. Names are lowercased to match DNS query names. None/empty -> empty map.
fn parse_hosts(hosts: Option<&str>) -> Result<HashMap<String, Ipv4Addr>> {
    let mut map = HashMap::new();
    let Some(s) = hosts else { return Ok(map) };
    for entry in s.split(',').filter(|e| !e.is_empty()) {
        let (name, ip) = entry
            .split_once('=')
            .with_context(|| format!("bad host entry {entry:?} (want name=ip)"))?;
        let ip: Ipv4Addr = ip
            .parse()
            .with_context(|| format!("ip in host entry {entry:?}"))?;
        map.insert(name.to_ascii_lowercase(), ip);
    }
    Ok(map)
}

/// Parse `--service-image name=ref` pairs (the ref may contain ':', so split on the
/// first '=' only) into a name -> image map.
fn parse_service_images(items: &[String]) -> Result<HashMap<&str, &str>> {
    items
        .iter()
        .map(|s| {
            s.split_once('=')
                .with_context(|| format!("bad --service-image {s:?} (want name=ref)"))
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    gateway: Ipv4Addr,
    prefix: u8,
    net_port: u32,
    hosts: Option<String>,
    kernel: PathBuf,
    cloud_hypervisor: PathBuf,
    extra_listen: Vec<PathBuf>,
    services: Vec<String>,
    builder: Option<BuilderOpts>,
    service_build: Option<PathBuf>,
    service_images: Vec<String>,
    agent: Option<PathBuf>,
    ensure_only: bool,
) -> Result<()> {
    let services: Vec<Service> = services
        .iter()
        .map(|s| Service::parse(s))
        .collect::<Result<_>>()?;

    // Ensure each VM's ext4 is current before boot: the staleness check compares the
    // image's UUID to a fingerprint of its build inputs (which include the agent
    // binary baked in as PID 1); the build itself stays the shell script.
    if let Some(b) = &builder
        && let Some(script) = &b.build_script
    {
        let agent = agent
            .as_deref()
            .context("--agent is required with --builder-build")?;
        crate::ensure::ensure_builder(&b.ext4, script, agent)?;
    }
    if let Some(script) = &service_build {
        let agent = agent
            .as_deref()
            .context("--agent is required with --service-build")?;
        let images = parse_service_images(&service_images)?;
        for svc in &services {
            let image = images
                .get(svc.name.as_str())
                .with_context(|| format!("no --service-image for service {}", svc.name))?;
            crate::ensure::ensure_service(&svc.name, image, &svc.ext4, script, agent)?;
        }
    }
    if ensure_only {
        return Ok(());
    }

    if !kernel.is_file() {
        bail!("guest kernel not found at {}", kernel.display());
    }

    // The switch listens on every VM's hybrid-vsock guest-port socket: the services
    // we boot, the builder (if any), and anything extra passed via --listen.
    let mut listen = extra_listen;
    for svc in &services {
        listen.push(svc.dir().join(format!("vsock.sock_{net_port}")));
    }
    if let Some(b) = &builder {
        listen.push(b.dir().join(format!("vsock.sock_{net_port}")));
    }
    // The fleet name map (name=ip,...) is served by the switch's gateway resolver, so
    // the guests resolve *.lan over DNS (no /etc/hosts injection).
    let host_map = parse_hosts(hosts.as_deref())?;
    let switch_listen = listen.clone();
    tokio::spawn(async move {
        if let Err(e) = crate::switch::run(&switch_listen, gateway, prefix, host_map).await {
            eprintln!("fleet: switch exited: {e:#}");
        }
    });
    // Give the switch a moment to bind before the guests dial it.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Boot the builder eagerly (you drive the fleet from it); the services are
    // declared and started on demand via `virtctl` (the control server below).
    let mut builder_ch: Option<Child> = None;
    let mut aux: Vec<Child> = Vec::new();
    if let Some(b) = &builder {
        let (ch, virtiofsds) = boot_builder(b, &kernel, &cloud_hypervisor, net_port)
            .with_context(|| format!("booting builder {}", b.name))?;
        println!("fleet: {} (DHCP) booting", b.name);
        builder_ch = Some(ch);
        aux.extend(virtiofsds);
    }

    // The manager owns the declared service units; the control server starts/stops
    // them on request. The switch already pre-listens on every unit's socket, so an
    // on-demand boot just dials a listening socket — no dynamic switch changes. A
    // `workdir` unit (the runner) shares the live repo read-only, reusing the builder's
    // workdir + derived git dir (virtiofsd itself is the bundled `virtkit virtiofsd`).
    let (share_workdir, share_git) = match &builder {
        Some(b) => (
            Some(b.workdir.clone()),
            git_share_for(&b.workdir, b.git_dir.as_deref()),
        ),
        None => (None, None),
    };
    let mgr = Arc::new(Manager {
        kernel,
        cloud_hypervisor,
        net_port,
        gateway,
        workdir: share_workdir,
        git_share: share_git,
        units: Mutex::new(
            services
                .into_iter()
                .map(|s| {
                    (
                        s.name.clone(),
                        UnitState {
                            svc: s,
                            child: None,
                            aux: Vec::new(),
                        },
                    )
                })
                .collect(),
        ),
    });
    let declared = mgr.units.lock().unwrap().len();

    // Control server on the builder's hybrid-vsock control socket — only the builder
    // can reach it, so the control plane is scoped to the dev VM by construction.
    if let Some(b) = &builder {
        let ctrl = b.dir().join(format!(
            "vsock.sock_{}",
            virtkit_agent::fleetctl::CONTROL_PORT
        ));
        let mgr = mgr.clone();
        tokio::spawn(async move {
            if let Err(e) = control_server(&ctrl, mgr).await {
                eprintln!("fleet: control server exited: {e:#}");
            }
        });
    }

    println!(
        "fleet: switch{} up on {gateway}/{prefix}; {declared} service(s) declared — start with virtctl",
        if builder.is_some() { " + builder" } else { "" }
    );
    // Run until interrupted, then stop everything (the switch task dies with us).
    tokio::signal::ctrl_c().await.ok();
    println!("fleet: stopping ...");
    for st in mgr.units.lock().unwrap().values_mut() {
        if let Some(mut child) = st.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        for mut a in st.aux.drain(..) {
            let _ = a.kill();
            let _ = a.wait();
        }
    }
    if let Some(mut ch) = builder_ch {
        let _ = ch.kill();
        let _ = ch.wait();
    }
    for mut child in aux {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

/// A declared service unit, its running cloud-hypervisor child (if started), and the
/// virtiofsd children backing its repo share (workdir units only).
struct UnitState {
    svc: Service,
    child: Option<Child>,
    aux: Vec<Child>,
}

/// The fleet manager: declared service units, started/stopped on demand over the
/// control protocol. boot_service is sync, so the lock is held only around the sync
/// boot/kill — never across an await.
struct Manager {
    kernel: PathBuf,
    cloud_hypervisor: PathBuf,
    net_port: u32,
    gateway: Ipv4Addr,
    /// repo share for `workdir` units (host /workdir + derived git dir) — taken from
    /// the builder; None when the fleet has no builder.
    workdir: Option<PathBuf>,
    git_share: Option<PathBuf>,
    units: Mutex<HashMap<String, UnitState>>,
}

impl Manager {
    fn handle(&self, req: Request) -> Reply {
        match req {
            Request::List => self.list(),
            Request::Status { unit } => self.status(&unit),
            Request::Start { unit } => self.start(&unit),
            Request::Stop { unit } => self.stop(&unit),
            Request::Restart { unit } => {
                let _ = self.stop(&unit);
                self.start(&unit)
            }
            Request::Logs { unit, lines } => self.logs(&unit, lines),
        }
    }

    fn list(&self) -> Reply {
        let mut u = self.units.lock().unwrap();
        let mut names: Vec<String> = u.keys().cloned().collect();
        names.sort();
        let units = names
            .iter()
            .map(|n| {
                let st = u.get_mut(n).unwrap();
                UnitStatus {
                    name: n.clone(),
                    state: state_of(st).into(),
                    ip: st.svc.ip.clone(),
                }
            })
            .collect();
        Reply::list(units)
    }

    fn status(&self, name: &str) -> Reply {
        let mut u = self.units.lock().unwrap();
        match u.get_mut(name) {
            Some(st) => Reply::list(vec![UnitStatus {
                name: name.into(),
                state: state_of(st).into(),
                ip: st.svc.ip.clone(),
            }]),
            None => Reply::err(format!("no such unit {name:?}")),
        }
    }

    fn start(&self, name: &str) -> Reply {
        let mut u = self.units.lock().unwrap();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        if state_of(st) == "running" {
            return Reply::ok(format!("{name} already running ({})", st.svc.ip));
        }
        match boot_service(
            &st.svc,
            &self.kernel,
            &self.cloud_hypervisor,
            self.net_port,
            self.gateway,
            self.workdir.as_deref(),
            self.git_share.as_deref(),
        ) {
            Ok((child, aux)) => {
                let ip = st.svc.ip.clone();
                st.child = Some(child);
                st.aux = aux;
                Reply::ok(format!("started {name} ({ip})"))
            }
            Err(e) => Reply::err(format!("starting {name}: {e:#}")),
        }
    }

    fn stop(&self, name: &str) -> Reply {
        let mut u = self.units.lock().unwrap();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        let was_running = st.child.is_some();
        if let Some(mut child) = st.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // tear down the unit's virtiofsd backers (workdir units), if any
        for mut a in st.aux.drain(..) {
            let _ = a.kill();
            let _ = a.wait();
        }
        Reply::ok(if was_running {
            format!("stopped {name}")
        } else {
            format!("{name} not running")
        })
    }

    fn logs(&self, name: &str, lines: usize) -> Reply {
        let u = self.units.lock().unwrap();
        let Some(st) = u.get(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        let console = st.svc.dir().join("console.log");
        match std::fs::read_to_string(&console) {
            Ok(text) => {
                let mut tail: Vec<&str> = text.lines().rev().take(lines).collect();
                tail.reverse();
                Reply::ok(tail.join("\n"))
            }
            Err(e) => Reply::err(format!("reading {}: {e}", console.display())),
        }
    }
}

/// "running" if the unit's child is alive, else "stopped". Reaps a child that has
/// exited (e.g. the service crashed) so the reported state reflects reality.
fn state_of(st: &mut UnitState) -> &'static str {
    match st.child.as_mut().map(Child::try_wait) {
        Some(Ok(None)) | Some(Err(_)) => "running",
        Some(Ok(Some(_))) => {
            st.child = None;
            "stopped"
        }
        None => "stopped",
    }
}

/// Accept control connections on the builder's hybrid-vsock control socket and serve
/// the virtctl protocol (one request, one reply per connection).
async fn control_server(listen: &Path, mgr: Arc<Manager>) -> Result<()> {
    let _ = std::fs::remove_file(listen);
    let listener = tokio::net::UnixListener::bind(listen)
        .with_context(|| format!("control: bind {}", listen.display()))?;
    loop {
        let (conn, _) = listener.accept().await?;
        let mgr = mgr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_control(conn, mgr).await {
                eprintln!("fleet: control request: {e:#}");
            }
        });
    }
}

async fn handle_control(conn: tokio::net::UnixStream, mgr: Arc<Manager>) -> Result<()> {
    let (rd, mut wr) = conn.into_split();
    let mut rd = tokio::io::BufReader::new(rd);
    let req: Request = virtkit_agent::fleetctl::read_msg(&mut rd).await?;
    let reply = mgr.handle(req); // sync; the unit lock is never held across an await
    virtkit_agent::fleetctl::write_msg(&mut wr, &reply).await?;
    Ok(())
}

/// Boot one fleet unit: a throwaway CoW overlay over its ext4, init=virtkit-agent
/// (VIRTKIT_MODE=service — exec the image's captured entrypoint), a static fleet
/// address, attached to the shared switch over vsock. A `workdir` unit (the runner)
/// additionally gets the live repo (workdir + git dir) over virtiofs, READ-ONLY: its
/// entrypoint assembles the appliance from /workdir and execs systemd. Returns the
/// cloud-hypervisor child plus any virtiofsd children (so the caller can stop them).
#[allow(clippy::too_many_arguments)]
fn boot_service(
    svc: &Service,
    kernel: &Path,
    cloud_hypervisor: &Path,
    net_port: u32,
    gateway: Ipv4Addr,
    workdir: Option<&Path>,
    git_share: Option<&Path>,
) -> Result<(Child, Vec<Child>)> {
    let dir = svc.dir();
    let overlay = dir.join(format!("{}-overlay.qcow2", svc.name));
    let vsock = dir.join("vsock.sock");
    let console = dir.join("console.log");

    let _ = std::fs::remove_file(&overlay);
    create_overlay(&svc.ext4, &overlay)?;
    let _ = std::fs::remove_file(&vsock);

    // A `workdir` unit shares the live repo READ-ONLY (own virtiofsd), like the builder
    // but never writable: the runner's assembly hardens permissions by following
    // symlinks into the repo, so RO makes those chmod no-ops and protects the host tree.
    // Plain services get no share and the default small VM.
    let mut aux: Vec<Child> = Vec::new();
    let mut fs_args: Vec<String> = Vec::new();
    let mut virtiofs = String::new();
    let (mut cpus, mut mem) = ("boot=2".to_string(), "size=1G".to_string());
    if svc.workdir {
        let workdir = workdir
            .context("a `workdir` unit needs the repo share, but the fleet has no builder")?;
        let workdir_sock = dir.join("vfsd-workdir.sock");
        aux.push(spawn_virtiofsd(&workdir_sock, workdir, true)?);
        fs_args.push(format!("tag=workdir,socket={}", workdir_sock.display()));
        virtiofs.push_str("workdir:/workdir");
        // git worktree: share the main repo's git dir at the SAME guest path so the
        // worktree's .git -> commondir chain resolves (the assembly reads git).
        if let Some(gs) = git_share {
            let git_sock = dir.join("vfsd-git.sock");
            aux.push(spawn_virtiofsd(&git_sock, gs, true)?);
            fs_args.push(format!("tag=gitdir,socket={}", git_sock.display()));
            virtiofs.push_str(&format!(",gitdir:{}", gs.display()));
        }
        (cpus, mem) = ("boot=4".to_string(), "size=4G,shared=on".to_string());
    }

    // Static address + the gateway as resolver (its DNS answers *.lan and forwards
    // the rest), so the unit resolves fleet names without an /etc/hosts injection.
    let mut cmdline = format!(
        "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/virtkit-agent \
         VIRTKIT_MODE=service VIRTKIT_HOSTNAME={} VIRTKIT_NET_PORT={net_port} \
         VIRTKIT_VM_IP={} VIRTKIT_VM_DNS={gateway}",
        svc.name, svc.ip
    );
    if !virtiofs.is_empty() {
        cmdline.push_str(&format!(" VIRTKIT_VIRTIOFS={virtiofs}"));
    }

    let log = std::fs::File::create(&console)?;
    let mut cmd = Command::new(cloud_hypervisor);
    cmd.arg("--kernel").arg(kernel).arg("--disk").arg(format!(
        "path={},readonly=off,backing_files=on,image_type=qcow2",
        overlay.display()
    ));
    for fa in &fs_args {
        cmd.arg("--fs").arg(fa);
    }
    let ch = cmd
        .arg("--vsock")
        .arg(format!("cid={},socket={}", svc.cid, vsock.display()))
        .arg("--cpus")
        .arg(&cpus)
        .arg("--memory")
        .arg(&mem)
        .arg("--serial")
        .arg(format!("file={}", console.display()))
        .arg("--console")
        .arg("off")
        .arg("--cmdline")
        .arg(&cmdline)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .with_context(|| format!("spawning {}", cloud_hypervisor.display()))?;
    Ok((ch, aux))
}

/// Boot the builder VM (the former launch-builder.sh NET=lan, in Rust): two virtiofs shares
/// (workdir + the git worktree), a CoW overlay keyed on the base fs UUID, and
/// init=/sbin/builder-vm-init with DHCP networking. Returns the cloud-hypervisor
/// child plus the virtiofsd children (so the caller can stop them on shutdown).
fn boot_builder(
    b: &BuilderOpts,
    kernel: &Path,
    cloud_hypervisor: &Path,
    net_port: u32,
) -> Result<(Child, Vec<Child>)> {
    if !b.ext4.is_file() {
        bail!("builder ext4 not found at {}", b.ext4.display());
    }
    let dir = b.dir();
    let mut aux: Vec<Child> = Vec::new();

    // virtiofsd on /workdir — READ-WRITE (no --readonly): live editing both ways.
    let workdir_sock = dir.join("vfsd-workdir.sock");
    aux.push(spawn_virtiofsd(&workdir_sock, &b.workdir, false)?);
    let mut fs_args: Vec<String> = vec![format!("tag=workdir,socket={}", workdir_sock.display())];

    // git worktree: share the main repo's git dir at the SAME guest path so the
    // worktree's .git -> commondir chain resolves.
    let git_share = git_share_for(&b.workdir, b.git_dir.as_deref());
    if let Some(gs) = &git_share {
        let git_sock = dir.join("vfsd-git.sock");
        aux.push(spawn_virtiofsd(&git_sock, gs, false)?);
        fs_args.push(format!("tag=gitdir,socket={}", git_sock.display()));
    }

    // Copy-on-write overlay tied to the base fs UUID via its NAME: a rebuilt base
    // (new UUID) maps to a different filename, so a stale overlay is never reused.
    let uuid = fs_uuid(&b.ext4);
    let overlay = match &uuid {
        Some(u) => dir.join(format!("builder-overlay-{u}.qcow2")),
        None => dir.join("builder-overlay.qcow2"),
    };
    prune_builder_overlays(dir, &overlay);
    if !overlay.exists() {
        create_overlay(&b.ext4, &overlay)?;
    }

    let vsock = dir.join("vsock.sock");
    let _ = std::fs::remove_file(&vsock);
    let console = dir.join("console.log");

    // The agent (PID 1) mounts the virtiofs shares, DHCPs, and serves vsock + ssh
    // (VIRTKIT_SSH for VS Code Remote-SSH). The git worktree share, when present, is
    // mounted at the same guest path so the worktree resolves. DNS comes from DHCP
    // (the gateway resolver), so no /etc/hosts injection.
    let mut virtiofs = String::from("workdir:/workdir");
    if let Some(gs) = &git_share {
        virtiofs.push_str(&format!(",gitdir:{}", gs.display()));
    }
    let cmdline = format!(
        "console=ttyS0 root=/dev/vda rw rootfstype=ext4 init=/usr/local/bin/virtkit-agent \
         VIRTKIT_HOSTNAME={} VIRTKIT_NET_PORT={net_port} VIRTKIT_NET_DHCP=1 \
         VIRTKIT_VIRTIOFS={virtiofs} VIRTKIT_SSH=1",
        b.name
    );

    let log = std::fs::File::create(&console)?;
    let mut cmd = Command::new(cloud_hypervisor);
    cmd.arg("--kernel").arg(kernel).arg("--disk").arg(format!(
        "path={},readonly=off,backing_files=on,image_type=qcow2",
        overlay.display()
    ));
    for fa in &fs_args {
        cmd.arg("--fs").arg(fa);
    }
    // shared=on is REQUIRED for virtiofs (the workdir/gitdir shares).
    let ch = cmd
        .arg("--vsock")
        .arg(format!("cid={},socket={}", b.cid, vsock.display()))
        .arg("--cpus")
        .arg(format!("boot={}", b.cpus))
        .arg("--memory")
        .arg(format!("size={},shared=on", b.mem))
        .arg("--serial")
        .arg(format!("file={}", console.display()))
        .arg("--console")
        .arg("off")
        .arg("--cmdline")
        .arg(&cmdline)
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()
        .with_context(|| format!("spawning {}", cloud_hypervisor.display()))?;
    Ok((ch, aux))
}

/// Create a CoW qcow2 `overlay` over the ro raw `ext4` base. qemu-img stores the
/// backing path RELATIVE to the overlay's directory, so a relative base path would be
/// resolved twice (overlay dir + base path) and break; canonicalize it to an absolute
/// path so the backing reference is unambiguous.
fn create_overlay(ext4: &Path, overlay: &Path) -> Result<()> {
    let base =
        std::fs::canonicalize(ext4).with_context(|| format!("locating {}", ext4.display()))?;
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
        .arg(&base)
        .arg(overlay)
        .status()
        .context("running qemu-img")?;
    if !st.success() {
        bail!("qemu-img create failed ({st})");
    }
    Ok(())
}

/// Start the bundled virtiofsd (this executable's `virtkit virtiofsd` subcommand) on
/// `shared_dir` (optionally read-only) and wait for its socket to appear. RO shares
/// (the runner's repo) are a host-side guarantee the guest can never write back to the
/// repo, even via the assembly's symlink chmod hardening.
fn spawn_virtiofsd(sock: &Path, shared_dir: &Path, readonly: bool) -> Result<Child> {
    let _ = std::fs::remove_file(sock);
    let exe = std::env::current_exe().context("locating the virtkit binary for virtiofsd")?;
    let mut cmd = Command::new(exe);
    cmd.arg("virtiofsd")
        .arg(format!("--socket-path={}", sock.display()))
        .arg(format!("--shared-dir={}", shared_dir.display()))
        .arg("--cache=auto")
        .arg("--sandbox=none");
    if readonly {
        cmd.arg("--readonly");
    }
    let child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawning the bundled virtiofsd (virtkit virtiofsd)")?;
    for _ in 0..50 {
        if sock.exists() {
            return Ok(child);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("virtiofsd socket {} never appeared", sock.display());
}

/// Decide whether a separate git-dir share is needed for `workdir` (i.e. it is a linked
/// git worktree whose git dir lives outside the share). Returns the host path to share
/// at the same guest path, or None when no separate share is needed. Shared by the
/// builder and any workdir unit (both mount the live repo).
fn git_share_for(workdir: &Path, git_dir: Option<&Path>) -> Option<PathBuf> {
    let host_git_dir = match git_dir {
        Some(g) => g.to_path_buf(),
        None => derive_host_git_dir(workdir)?,
    };
    let workdir = std::fs::canonicalize(workdir).unwrap_or_else(|_| workdir.to_path_buf());
    let g = std::fs::canonicalize(&host_git_dir).ok()?;
    // Already visible under /workdir, or not a directory -> no separate share.
    if g == workdir || g.starts_with(&workdir) || !g.is_dir() {
        return None;
    }
    Some(g)
}

/// Derive the main repo's git dir from a worktree (as the former launch-builder.sh did):
/// `git -C <workdir> rev-parse --git-dir`, then if it has a `commondir`, resolve it
/// and take its parent (the main repo root).
fn derive_host_git_dir(workdir: &Path) -> Option<PathBuf> {
    let out = Command::new("git")
        .arg("-C")
        .arg(workdir)
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let gd = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if gd.is_empty() {
        return None;
    }
    // rev-parse --git-dir may be relative to the workdir.
    let git_dir = {
        let p = PathBuf::from(&gd);
        if p.is_absolute() { p } else { workdir.join(p) }
    };
    let commondir = git_dir.join("commondir");
    if !commondir.is_file() {
        return None;
    }
    let common_rel = std::fs::read_to_string(&commondir).ok()?;
    let common = std::fs::canonicalize(git_dir.join(common_rel.trim())).ok()?;
    std::fs::canonicalize(common.parent()?).ok()
}

/// The base ext4's filesystem UUID (blkid, fallback dumpe2fs), used to name the
/// overlay so a rebuilt base never reuses a stale overlay, and (via ensure) as the
/// content fingerprint that decides a rebuild.
pub(crate) fn fs_uuid(ext4: &Path) -> Option<String> {
    if let Ok(out) = Command::new("blkid")
        .args(["-o", "value", "-s", "UUID"])
        .arg(ext4)
        .output()
        && out.status.success()
    {
        let u = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !u.is_empty() {
            return Some(u);
        }
    }
    let out = Command::new("dumpe2fs").arg("-h").arg(ext4).output().ok()?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(rest) = line.strip_prefix("Filesystem UUID:") {
            let u = rest.trim().to_string();
            if !u.is_empty() {
                return Some(u);
            }
        }
    }
    None
}

/// Remove builder overlays bound to other (old) base UUIDs.
fn prune_builder_overlays(dir: &Path, keep: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("builder-overlay-") && name.ends_with(".qcow2") && entry.path() != keep
        {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_parse_plain() {
        let s = Service::parse("redis:/out/redis.ext4:192.168.127.3/24:4").unwrap();
        assert_eq!(s.name, "redis");
        assert_eq!(s.ext4, PathBuf::from("/out/redis.ext4"));
        assert_eq!(s.ip, "192.168.127.3/24");
        assert_eq!(s.cid, 4);
        assert!(!s.workdir);
    }

    #[test]
    fn service_parse_workdir_flag() {
        let s = Service::parse("runner:/out/runner.ext4:192.168.127.5/24:6:workdir").unwrap();
        assert_eq!(s.name, "runner");
        assert_eq!(s.cid, 6);
        assert!(
            s.workdir,
            "the `workdir` flag shares the live repo read-only"
        );
    }

    #[test]
    fn service_parse_rejects_unknown_flag() {
        assert!(Service::parse("runner:/out/r.ext4:192.168.127.5/24:6:systemd").is_err());
    }

    #[test]
    fn service_parse_rejects_malformed() {
        assert!(Service::parse("too:few:fields").is_err());
        assert!(Service::parse("a:b:c:notanumber").is_err());
    }
}
