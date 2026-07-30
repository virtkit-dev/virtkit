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

/// The manager owns the declared service units. units::boot_unit is sync, so the
/// lock is held only around the sync boot/kill — never across an await.
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
    /// the shared cache root a `build:` unit materializes into, and how long a base may sit
    /// idle before the on-demand build path's GC evicts it
    state_dir: PathBuf,
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
        state_dir: PathBuf,
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
            state_dir,
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
        let built_config = if matches!(unit.source, crate::compose::Source::Build { .. }) {
            match crate::units::ensure_unit_build_sync(
                &unit,
                &self.state_dir,
                self.idle,
                &self.build,
                sink,
            ) {
                Ok(config) => Some(config),
                Err(e) => return Reply::err(format!("building {name}: {e:#}")),
            }
        } else {
            None
        };

        // Re-take the lock for the boot; re-check running in case a concurrent start won.
        let mut u = self.units.lock().unwrap();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        if state_of(st) == "running" {
            return Reply::ok(format!("{name} already running ({})", st.svc.ip));
        }
        // A freshly-built image's own config (env/user/entrypoint) is known only after the
        // build, so adopt it before booting — a profiled-down service had no config yet.
        if let Some(config) = built_config {
            st.svc.config = config;
        }
        // Reference the shared-cache base for the unit's running lifetime, so the idle GC
        // never evicts a base under this live overlay. `None` for a rootfs outside the
        // managed tiers (nothing to reference-count there).
        let guard = match crate::image::acquire_use_lock_for(&self.state_dir, &st.svc.ext4) {
            Ok(guard) => guard,
            Err(e) => return Reply::err(format!("referencing {name} image: {e:#}")),
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

    pub fn stop(&self, name: &str) -> Reply {
        let mut u = self.units.lock().unwrap();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        let was_running = state_of(st) == "running";
        if let Some(mut child) = st.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        // tear down the unit's virtiofsd backers (workdir units), if any
        for mut a in st.aux.drain(..) {
            let _ = a.kill();
            let _ = a.wait();
        }
        // release the shared-cache base reference now the overlay is gone
        st.guard = None;
        Reply::ok(if was_running {
            format!("stopped {name}")
        } else {
            format!("{name} not running")
        })
    }

    /// Kill every running unit and its helpers (owner teardown).
    pub fn stop_all(&self) {
        for st in self.units.lock().unwrap().values_mut() {
            if let Some(mut child) = st.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
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
            other => {
                let reply = mgr.handle(other); // sync; the unit lock is never held across an await
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
