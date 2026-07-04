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
use vk_core::fleetctl::{Reply, Request, UnitStatus};

/// A declared service unit, its runtime dir (sockets/overlay/console), its running
/// VMM child (if started), and the virtiofsd children backing its volume shares.
struct UnitState {
    svc: crate::units::Provisioned,
    dir: PathBuf,
    child: Option<Child>,
    aux: Vec<Child>,
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
    units: Mutex<HashMap<String, UnitState>>,
}

impl Manager {
    pub fn new(
        kernel: PathBuf,
        cloud_hypervisor: PathBuf,
        net_port: u32,
        gateway: Ipv4Addr,
        agent: PathBuf,
        units: impl IntoIterator<Item = (crate::units::Provisioned, PathBuf)>,
    ) -> Manager {
        Manager {
            kernel,
            cloud_hypervisor,
            net_port,
            gateway,
            agent,
            units: Mutex::new(
                units
                    .into_iter()
                    .map(|(svc, dir)| {
                        (
                            svc.name.clone(),
                            UnitState {
                                svc,
                                dir,
                                child: None,
                                aux: Vec::new(),
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
        let mut u = self.units.lock().unwrap();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        if state_of(st) == "running" {
            return Reply::ok(format!("{name} already running ({})", st.svc.ip));
        }
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
        let reply = mgr.handle(req); // sync; the unit lock is never held across an await
        vk_core::fleetctl::write_msg(&mut wr, &reply).await?;
    }
}
