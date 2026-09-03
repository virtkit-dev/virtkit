//! The service manager: a set of declared compose units, started/stopped on
//! demand over the virtctl control protocol (`vk_core::fleetctl`). The owner
//! (`run`) declares every unit up front — image materialized, address and
//! CID assigned — and the manager boots/kills them; the control server answers
//! one request per connection on a hybrid-vsock control socket, so only VMs on
//! the owner's LAN can reach the control plane.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use vk_core::addr::SocketAddr;
use vk_core::fleetctl::{Frame, Reply, Request, UnitStatus};

/// A declared service unit, its runtime dir (sockets/overlay/console), its running
/// VMM child (if started), and the virtiofsd children backing its volume shares.
struct UnitState {
    svc: crate::units::Provisioned,
    dir: PathBuf,
    /// The compose unit behind this service — its build recipe + overrides, so a
    /// profiled-down service can be built on demand the first time it is started.
    unit: crate::compose::Unit,
    child: Option<Child>,
    aux: Vec<Child>,
    /// Reference on the shared-cache base this unit overlays (image tier or build tier),
    /// held while the unit runs so the idle GC never evicts a base under a live overlay.
    /// Acquired at boot, dropped on stop.
    guard: Option<crate::cachelock::Guard>,
}

/// The two roots a [`Manager`] works from, named rather than positional: passing them the wrong
/// way round would file a run's registry corrections under a cache root, which reads the same
/// either way at the call site.
pub struct ManagerDirs {
    /// the shared cache root a `build:` unit materializes into
    pub cache: PathBuf,
    /// the run's own directory, the key its VM-registry entry is filed under — so a service
    /// this manager builds on demand can correct the image that entry names (`vms`). `None`
    /// for a run that files no entry: an unpinned run, or a services-only compose run.
    pub run: Option<PathBuf>,
}

/// The manager owns the declared service units. Because `units::boot_unit` is synchronous,
/// the lock is held only during synchronous boot and stop operations, never across an await.
/// A stop can hold it for `shutdown::STOP_GRACE`, so requests run outside the runtime threads.
pub struct Manager {
    kernel: PathBuf,
    cloud_hypervisor: PathBuf,
    net_port: u32,
    gateway: Ipv4Addr,
    /// the vk-agent every service boot's initramfs carries (the owner holds the
    /// embedded-asset handle this path stays valid through)
    agent: PathBuf,
    /// the builder wiring (cache, build args, embedded kernel/agent) for building a
    /// profiled-down `build:` service on demand at its first start
    build: crate::units::BuildOpts,
    /// the roots this manager works from
    dirs: ManagerDirs,
    /// how long a base may sit idle before the on-demand build path's GC evicts it
    idle: std::time::Duration,
    units: Mutex<HashMap<String, UnitState>>,
}

impl Manager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kernel: PathBuf,
        cloud_hypervisor: PathBuf,
        net_port: u32,
        gateway: Ipv4Addr,
        agent: PathBuf,
        build: crate::units::BuildOpts,
        dirs: ManagerDirs,
        idle: std::time::Duration,
        units: impl IntoIterator<Item = (crate::units::Provisioned, PathBuf, crate::compose::Unit)>,
    ) -> Manager {
        Manager {
            kernel,
            cloud_hypervisor,
            net_port,
            gateway,
            agent,
            build,
            dirs,
            idle,
            units: Mutex::new(
                units
                    .into_iter()
                    .map(|(svc, dir, unit)| {
                        (
                            svc.name.clone(),
                            UnitState {
                                svc,
                                dir,
                                unit,
                                child: None,
                                aux: Vec::new(),
                                guard: None,
                            },
                        )
                    })
                    .collect(),
            ),
        }
    }

    /// Number of declared units.
    pub fn declared(&self) -> usize {
        self.units.lock().unwrap().len()
    }

    /// Dispatch a request to a single (non-streaming) reply. `handle_control` intercepts
    /// `Start`/`Restart` to stream build progress (see `stream_start`); the `Start`/`Restart`
    /// arms here are the non-streaming fallback (a null progress sink) for any other caller.
    pub fn handle(&self, req: Request) -> Reply {
        match req {
            Request::List => self.list(),
            Request::Status { unit } => self.status(&unit),
            Request::Start { unit } => self.start(&unit),
            Request::Stop { unit } => self.stop(&unit),
            Request::Restart { unit } => {
                let _ = self.stop(&unit);
                self.start(&unit)
            }
            Request::Reboot { unit } => self.reboot(&unit),
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

    pub fn start(&self, name: &str) -> Reply {
        self.start_streamed(name, None)
    }

    /// Start a service, building its image first if it is not already materialized (a
    /// profiled-down `build:` service, brought up on demand) — streaming that build's
    /// progress to `sink` when set. The image build is long and runs WITHOUT the units lock
    /// held (only `list`/`status` would otherwise stall behind it); the lock is re-taken for
    /// the quick boot. A fresh image skips the build, so an already-materialized service
    /// (every eager start) just boots, exactly as before. Concurrent first-starts of the same
    /// `build:` stage are serialized inside `ensure_unit_build_sync` (the shared build tier's
    /// per-stage pull lock), not by the units lock — so they cannot race the tier write, and
    /// share the one tier entry. An `image:` unit was resolved/pulled at provisioning, so it
    /// skips the build and just boots.
    pub fn start_streamed(&self, name: &str, sink: Option<crate::build::ProgressSink>) -> Reply {
        // Snapshot the unit under the lock, then release it for the (possibly long) build.
        let unit = {
            let mut u = self.units.lock().unwrap();
            let Some(st) = u.get_mut(name) else {
                return Reply::err(format!("no such unit {name:?}"));
            };
            if state_of(st) == "running" {
                return Reply::ok(format!("{name} already running ({})", st.svc.ip));
            }
            st.unit.clone()
        };

        // A `build:` unit materializes into the shared build tier (lock released for the
        // build) — a fresh stage returns instantly; an `image:` unit was already pulled.
        let built_image = if matches!(unit.source, crate::compose::Source::Build { .. }) {
            match crate::units::ensure_unit_build_sync(
                &unit,
                &self.dirs.cache,
                self.idle,
                &self.build,
                sink,
            ) {
                Ok(built) => Some(built),
                Err(e) => return Reply::err(format!("building {name}: {e:#}")),
            }
        } else {
            None
        };
        // Still outside the units lock: the registry write fsyncs, and the whole point of
        // releasing that lock for the build is that `list`/`status` never wait on file I/O.
        // Recording the address before the boot adopts it is safe either way: the entry this
        // build settled on is the one a boot of this unit uses from here on.
        if let (Some((ext4, _, _)), Some(run)) = (&built_image, &self.dirs.run) {
            crate::vms::note_service_image(run, name, ext4);
        }

        // Re-take the lock for the boot; re-check running in case a concurrent start won.
        let mut u = self.units.lock().unwrap();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        if state_of(st) == "running" {
            // A concurrent start won: dropping `built_image` here releases the reference this
            // one took, which is right — the winner holds its own on the same entry.
            return Reply::ok(format!("{name} already running ({})", st.svc.ip));
        }
        // Reference the shared-cache base for the unit's running lifetime, so the idle GC
        // never evicts a base under this live overlay. A `build:` unit carries its guard
        // straight from the build that just promoted its entry (see `ensure_unit_build_sync`)
        // — there is no gap, between that promotion and here, in which the entry sat
        // unreferenced. An `image:` unit (never built here) takes its reference fresh; `None`
        // for a rootfs outside the managed tiers (nothing to reference-count there). That
        // acquisition blocks behind a reclaim of the same entry, which is the one way this
        // path can hold the units lock across file I/O — bounded by that sweep's `remove`.
        let guard = if let Some((ext4, config, guard)) = built_image {
            // Boot the entry the build reports, with the config it carries: both are known
            // only after the build, and the address provisioning predicted can key elsewhere
            // (see `ensure_unit_build_sync`).
            st.svc.ext4 = ext4;
            st.svc.config = config;
            Some(guard)
        } else {
            match crate::image::acquire_use_lock_for(&self.dirs.cache, &st.svc.ext4) {
                Ok(guard) => guard,
                Err(e) => return Reply::err(format!("referencing {name} image: {e:#}")),
            }
        };
        match crate::units::boot_unit(
            &st.svc,
            &st.dir,
            &self.kernel,
            &self.cloud_hypervisor,
            &self.agent,
            self.net_port,
            self.gateway,
        ) {
            Ok((child, aux)) => {
                let ip = st.svc.ip.clone();
                st.child = Some(child);
                st.aux = aux;
                st.guard = guard;
                Reply::ok(format!("started {name} ({ip})"))
            }
            Err(e) => Reply::err(format!("starting {name}: {e:#}")),
        }
    }

    /// Point each recorded service at the image it booted. The registry entry is filed after
    /// the run's eager starts, and every `build:` sibling materializes at its first start
    /// (`build_compose_images` builds only the primary) — so those adoptions happen before
    /// there is an entry for [`crate::vms::note_service_image`] to correct, and are folded in
    /// here instead. Later, control-plane starts go through that function.
    pub fn refresh_service_images(&self, entries: &mut [crate::vms::ServiceEntry]) {
        let units = self.units.lock().unwrap();
        for e in entries {
            if let Some(st) = units.get(&e.name)
                && let Some(recipe) = e.stale_recipe.as_mut()
            {
                recipe.root_ext4 = st.svc.ext4.clone();
            }
        }
    }

    /// Power off a unit's guest, then kill and reap its VMM and helpers. Hold the units lock
    /// for up to `shutdown::STOP_GRACE` so another start cannot race the stopping guest for its
    /// overlay and sockets.
    pub fn stop(&self, name: &str) -> Reply {
        let mut u = self.units.lock().unwrap();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        let was_running = state_of(st) == "running";
        let mut killed = Vec::new();
        if let Some(mut child) = st.child.take() {
            killed = crate::shutdown::power_off_then_kill(&mut [(
                name,
                &unit_addr(&st.dir),
                &mut child,
            )]);
        }
        // tear down the unit's virtiofsd backers (workdir units), if any
        for mut a in st.aux.drain(..) {
            let _ = a.kill();
            let _ = a.wait();
        }
        // release the shared-cache base reference now the overlay is gone
        st.guard = None;
        Reply::ok(match (was_running, killed.is_empty()) {
            (false, _) => format!("{name} not running"),
            (true, true) => format!("stopped {name}"),
            (true, false) => format!("stopped {name} (killed: the guest did not power off)"),
        })
    }

    /// Reboot a unit's guest in place: ask its agent to reboot (over vsock), else hard-reset
    /// through the VMM keeper (SIGUSR1). The VM process — and so the unit's pid — stays put;
    /// the guest comes back on the same disks. Unlike `Restart`, no image rebuild.
    fn reboot(&self, name: &str) -> Reply {
        let mut u = self.units.lock().unwrap();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        if state_of(st) != "running" {
            return Reply::err(format!("{name} not running"));
        }
        let Some(child) = st.child.as_ref() else {
            return Reply::err(format!("{name} not running"));
        };
        if crate::shutdown::request_reboot(&unit_addr(&st.dir)) {
            Reply::ok(format!("rebooting {name}"))
        } else {
            crate::shutdown::hard_reset(child);
            Reply::ok(format!("hard-resetting {name} (agent unreachable)"))
        }
    }

    /// Power off all guests concurrently within one `shutdown::STOP_GRACE`, then kill and reap their
    /// VMMs and helpers.
    pub fn stop_all(&self) {
        let mut units = self.units.lock().unwrap();
        // Compute addresses while borrowing the map immutably. It is unchanged before `iter_mut`,
        // so both iterators have the same order and `zip` aligns.
        let addrs: Vec<_> = units.values().map(|st| unit_addr(&st.dir)).collect();
        let mut vmms: Vec<(&str, &SocketAddr, &mut Child)> = units
            .iter_mut()
            .zip(&addrs)
            .filter_map(|((name, st), addr)| st.child.as_mut().map(|c| (name.as_str(), addr, c)))
            .collect();
        for name in crate::shutdown::power_off_then_kill(&mut vmms) {
            eprintln!(
                "virtkit: service {name}: did not power off within {} s — killed",
                crate::shutdown::STOP_GRACE.as_secs()
            );
        }
        for st in units.values_mut() {
            st.child = None; // killed and reaped above
            for mut a in st.aux.drain(..) {
                let _ = a.kill();
                let _ = a.wait();
            }
            st.guard = None;
        }
    }

    fn logs(&self, name: &str, lines: usize) -> Reply {
        let u = self.units.lock().unwrap();
        let Some(st) = u.get(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        let console = st.dir.join("console.log");
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

/// Build a unit's agent exec address from its runtime directory.
fn unit_addr(dir: &Path) -> SocketAddr {
    crate::vmm::exec_addr(&dir.join("vsock.sock"), crate::units::VSOCK_PORT)
}

/// "running" if the unit's child is alive, else "stopped". Reaps a child that has
/// exited (e.g. the service crashed) so the reported state reflects reality; a child
/// whose status can't be read is conservatively reported "running" (and left for a
/// later poll to reap).
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

/// Accept control connections on a VM's hybrid-vsock control socket and serve
/// the control protocol (a session of request/reply pairs per connection —
/// the guest's /run/vk/services bridge keeps one connection open across operations).
pub async fn control_server(listen: &Path, mgr: Arc<Manager>) -> Result<()> {
    let _ = std::fs::remove_file(listen);
    let listener = tokio::net::UnixListener::bind(listen)
        .with_context(|| format!("control: bind {}", listen.display()))?;
    loop {
        let (conn, _) = listener.accept().await?;
        let mgr = mgr.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_control(conn, mgr).await {
                eprintln!("virtkit: control request: {e:#}");
            }
        });
    }
}

async fn handle_control(conn: tokio::net::UnixStream, mgr: Arc<Manager>) -> Result<()> {
    let (rd, mut wr) = conn.into_split();
    let mut rd = tokio::io::BufReader::new(rd);
    loop {
        // the peer hanging up between requests is the normal end of a session
        let Ok(req) = vk_core::fleetctl::read_msg::<_, Request>(&mut rd).await else {
            return Ok(());
        };
        match req {
            // Start/Restart may build the image on demand — a long, blocking op whose
            // progress streams back as Progress frames, then a terminal Done.
            Request::Start { unit } => stream_start(&mut wr, &mgr, unit, false).await?,
            Request::Restart { unit } => stream_start(&mut wr, &mgr, unit, true).await?,
            // Stop holds the units lock while the guest powers off. Run every other request
            // outside the runtime too, so a status waiting on that lock does not occupy a
            // runtime worker for the grace period.
            other => {
                let mgr = Arc::clone(&mgr);
                let reply = tokio::task::spawn_blocking(move || mgr.handle(other))
                    .await
                    .unwrap_or_else(|e| Reply::err(format!("request task failed: {e}")));
                vk_core::fleetctl::write_msg(&mut wr, &Frame::Done(reply)).await?;
            }
        }
    }
}

/// Handle a Start/Restart by running the (possibly image-building) start on a blocking
/// thread and forwarding its build progress to the peer as `Progress` frames, then the
/// terminal `Done`. The build sink pushes lines onto an unbounded channel this drains until
/// the blocking task finishes and drops it; a write error (peer gone) abandons the stream
/// while the detached build runs to completion.
async fn stream_start(
    wr: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    mgr: &Arc<Manager>,
    unit: String,
    restart: bool,
) -> Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let sink: crate::build::ProgressSink = Arc::new(move |line: &str| {
        let _ = tx.send(line.to_string());
    });
    let mgr = Arc::clone(mgr);
    let task = tokio::task::spawn_blocking(move || {
        if restart {
            let _ = mgr.stop(&unit);
        }
        mgr.start_streamed(&unit, Some(sink))
    });
    // Drain build progress until the task drops its sink (build + boot done). A write error
    // here (peer gone) returns via `?`, dropping the receiver and detaching the build — it
    // runs to completion, warming the store for the next start; its outcome (or a panic) is
    // then unobserved. Only the drained path below surfaces a task panic as a `Reply::err`.
    while let Some(line) = rx.recv().await {
        vk_core::fleetctl::write_msg(wr, &Frame::Progress(line)).await?;
    }
    let reply = task
        .await
        .unwrap_or_else(|e| Reply::err(format!("start task failed: {e}")));
    vk_core::fleetctl::write_msg(wr, &Frame::Done(reply)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manager over one `build:` unit and one `image:` unit, provisioned as `plan_services`
    /// would leave them: each addressed, neither built.
    fn manager_over_two_units() -> Manager {
        let compose = "services:\n  db:\n    build: ./db\n  cache:\n    image: redis:7\n";
        let units = crate::compose::parse(compose, Path::new("/proj"), &|_| None, None).unwrap();
        let gw: Ipv4Addr = "192.168.127.1".parse().unwrap();
        let provisioned: Vec<_> = units
            .iter()
            .enumerate()
            .map(|(slot, unit)| {
                let svc = crate::units::provisioned(
                    unit,
                    PathBuf::from(format!("/tier/predicted-{}/runner.ext4", unit.name)),
                    Default::default(),
                    crate::units::Siting {
                        gateway: gw,
                        prefix: 24,
                        slot: slot as u32,
                        extra_ips: Vec::new(),
                    },
                )
                .unwrap();
                (svc, PathBuf::from("/run/svc"), unit.clone())
            })
            .collect();
        Manager::new(
            "/nonexistent".into(),
            "/nonexistent".into(),
            1024,
            gw,
            "/nonexistent".into(),
            crate::units::BuildOpts {
                build_args: vec![],
                kernel: "/nonexistent".into(),
                cloud_hypervisor: "/nonexistent".into(),
                agent: "/nonexistent".into(),
                cache_registry: None,
                cache_insecure: false,
                cache_auth: Default::default(),
                net: crate::build::BuildNet::All,
                audit: false,
            },
            ManagerDirs {
                cache: PathBuf::from("/cache"),
                run: Some(PathBuf::from("/run/vm")),
            },
            std::time::Duration::from_secs(1800),
            provisioned,
        )
    }

    fn entry(name: &str, recipe: bool) -> crate::vms::ServiceEntry {
        crate::vms::ServiceEntry {
            name: name.to_string(),
            exec_addr: format!("vsock-auto:///run/{name}/vsock.sock:4444"),
            stale_recipe: recipe.then(|| crate::vms::StaleRecipe {
                dockerfiles: vec![PathBuf::from("/proj/db/Dockerfile")],
                contexts: vec![PathBuf::from("/proj/db")],
                build_contexts: Vec::new(),
                build_args: Vec::new(),
                target: None,
                root_ext4: PathBuf::from("/tier/predicted-db/runner.ext4"),
            }),
        }
    }

    #[test]
    fn refreshing_records_the_entry_an_eager_start_adopted() {
        // A run's eager starts happen before it files its registry entry, so the adoption in
        // `start_streamed` has nothing to correct and this is what carries it instead. Without
        // it the entry keeps the address provisioning predicted for the run's whole life, and
        // `vk list --stale` weighs an image the service never booted.
        let mgr = manager_over_two_units();
        // What an eager start does once its build reports where it landed.
        let adopted = PathBuf::from("/tier/built-db/runner.ext4");
        mgr.units.lock().unwrap().get_mut("db").unwrap().svc.ext4 = adopted.clone();

        let mut entries = vec![entry("db", true), entry("cache", false)];
        mgr.refresh_service_images(&mut entries);

        assert_eq!(
            entries[0].stale_recipe.as_ref().unwrap().root_ext4,
            adopted,
            "the recorded image must follow the entry the build settled on"
        );
        // An `image:` service carries no recipe, and an unknown name must not panic.
        assert!(entries[1].stale_recipe.is_none());
        mgr.refresh_service_images(&mut [entry("absent", true)]);
    }
}
