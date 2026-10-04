//! The service manager: a set of declared compose units, started/stopped on
//! demand over the virtctl control protocol (`vk_core::fleetctl`). The owner
//! (`run`) declares every unit up front — image materialized, address
//! assigned — and the manager boots/kills them; the control server answers
//! requests on the owner's per-port control socket, so only its guest reaches
//! the control plane, and on a host-only socket beside it for `vk` itself.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use vk_core::addr::SocketAddr;
use vk_core::fleetctl::{Frame, Reply, Request, UnitStatus};

/// A declared service unit, its runtime dir (sockets/overlay/console), its running
/// VMM child (if started), and the socket-forward children backing its socket volumes.
struct UnitState {
    svc: crate::units::Provisioned,
    dir: PathBuf,
    /// The compose unit behind this service — its build recipe + overrides, so a
    /// profiled-down service can be built on demand the first time it is started.
    unit: crate::compose::Unit,
    child: Option<Child>,
    /// How the last VMM exited, once reaped; cleared by the next start.
    exited: Option<std::process::ExitStatus>,
    aux: Vec<Child>,
    /// Reference on the shared-cache base this unit overlays (image tier or build tier),
    /// held while the unit runs so the idle GC never evicts a base under a live overlay.
    /// Acquired at boot, dropped on stop.
    guard: Option<crate::cachelock::Guard>,
    /// The UEFI firmware a Windows unit's VMM boots, held while it runs (an embedded copy is
    /// a memfd).
    firmware: Option<crate::embed::Resolved>,
    /// Windows boot count: provisioning runs without the units lock and must not drive
    /// a guest replaced by a later start.
    boots: u64,
    /// Its healthcheck has passed since it started: a later dependent does not probe again.
    healthy: bool,
    /// How many times it was asked to stop: a start waiting on its dependencies gives up once
    /// this changes.
    stops: u64,
}

type UnitsGuard<'a> = std::sync::MutexGuard<'a, HashMap<String, UnitState>>;

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
/// A stop can hold it for `shutdown::STOP_GRACE` (`winsvc::STOP_GRACE` for a Windows unit), so
/// requests run outside the runtime threads.
pub struct Manager {
    kernel: PathBuf,
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
    /// how long a control-plane start waits for the service's agent to answer
    boot_timeout: std::time::Duration,
    units: Mutex<HashMap<String, UnitState>>,
}

impl Manager {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kernel: PathBuf,
        net_port: u32,
        gateway: Ipv4Addr,
        agent: PathBuf,
        build: crate::units::BuildOpts,
        dirs: ManagerDirs,
        idle: std::time::Duration,
        boot_timeout: std::time::Duration,
        units: impl IntoIterator<Item = (crate::units::Provisioned, PathBuf, crate::compose::Unit)>,
    ) -> Manager {
        Manager {
            kernel,
            net_port,
            gateway,
            agent,
            build,
            dirs,
            idle,
            boot_timeout,
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
                                exited: None,
                                aux: Vec::new(),
                                guard: None,
                                firmware: None,
                                boots: 0,
                                healthy: false,
                                stops: 0,
                            },
                        )
                    })
                    .collect(),
            ),
        }
    }

    /// Lock the units map, recovering the guard even when a previous holder panicked. Every
    /// request already runs on its own task whose panic is caught into a `Reply::err`, but a
    /// panic under this lock would otherwise poison it and turn every *later* request into a
    /// failure until the whole run restarts. The map is a set of independent unit entries, so
    /// serving on from the recovered state beats bricking the control plane.
    fn units_guard(&self) -> UnitsGuard<'_> {
        self.units.lock().unwrap_or_else(|e| self.recover(e))
    }

    /// [`Self::units_guard`] without blocking: `None` while another request holds the lock.
    fn try_units_guard(&self) -> Option<UnitsGuard<'_>> {
        match self.units.try_lock() {
            Ok(u) => Some(u),
            Err(std::sync::TryLockError::WouldBlock) => None,
            Err(std::sync::TryLockError::Poisoned(e)) => Some(self.recover(e)),
        }
    }

    fn recover<'a>(&self, e: std::sync::PoisonError<UnitsGuard<'a>>) -> UnitsGuard<'a> {
        // Report recovery once and clear the poison so later requests lock normally.
        eprintln!("virtkit: recovered the units lock a panicking request had poisoned");
        self.units.clear_poison();
        e.into_inner()
    }

    /// Number of declared units.
    pub fn declared(&self) -> usize {
        self.units_guard().len()
    }

    /// Return a single reply. `Start`/`Restart` discard build progress and reply after spawning
    /// the VMM, without waiting for the agent. `handle_control` routes them to `stream_start`
    /// instead, which streams build progress and waits for the agent.
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
        let mut u = self.units_guard();
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
        let mut u = self.units_guard();
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
        let (unit, stops) = {
            let mut u = self.units_guard();
            let Some(st) = u.get_mut(name) else {
                return Reply::err(format!("no such unit {name:?}"));
            };
            if state_of(st) == "running" {
                return Reply::ok(format!("{name} already running ({})", st.svc.ip));
            }
            (st.unit.clone(), st.stops)
        };
        // Wait for dependency health or completion without the lock so `list`/`status`
        // can answer meanwhile.
        if let Err(e) = self.wait_dependencies(&unit, stops) {
            return Reply::err(format!("starting {name}: {e:#}"));
        }

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
        let mut u = self.units_guard();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        if state_of(st) == "running" {
            // A concurrent start won: dropping `built_image` here releases the reference this
            // one took, which is right — the winner holds its own on the same entry.
            return Reply::ok(format!("{name} already running ({})", st.svc.ip));
        }
        if let crate::compose::Source::Bundle { .. } = &st.unit.source {
            // Booted under the lock, provisioned without it: minutes, during which
            // `list`/`status` must still answer.
            let ip = st.svc.ip.clone();
            let booted = self.boot_windows(st);
            drop(u);
            return match booted {
                Ok((provisioning, boot)) => self.provision_windows(name, &ip, &provisioning, boot),
                Err(e) => Reply::err(format!("starting {name}: {e:#}")),
            };
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
            &self.agent,
            self.net_port,
            self.gateway,
        ) {
            Ok((child, aux)) => {
                let ip = st.svc.ip.clone();
                st.child = Some(child);
                st.exited = None;
                st.healthy = false;
                st.aux = aux;
                st.guard = guard;
                Reply::ok(format!("started {name} ({ip})"))
            }
            Err(e) => Reply::err(format!("starting {name}: {e:#}")),
        }
    }

    /// Boot the Windows unit `st` and return its provisioning, with the boot it is for.
    fn boot_windows(&self, st: &mut UnitState) -> Result<(crate::winsvc::Provisioning, u64)> {
        let provisioning =
            crate::winsvc::Provisioning::of(&st.svc, &st.unit, &st.dir, self.gateway)?;
        let (child, firmware) = crate::winsvc::boot(&st.svc, &st.dir, self.net_port, self.gateway)?;
        st.child = Some(child);
        st.exited = None;
        st.firmware = Some(firmware);
        st.healthy = false;
        st.boots += 1;
        Ok((provisioning, st.boots))
    }

    /// Provision Windows unit `name`'s boot `boot`, then reply. Failure leaves the guest
    /// running, as for a Linux unit whose agent never answers.
    fn provision_windows(
        &self,
        name: &str,
        ip: &str,
        provisioning: &crate::winsvc::Provisioning,
        boot: u64,
    ) -> Reply {
        match provisioning.run(&mut || self.boot_running(name, boot)) {
            Ok(()) => Reply::ok(format!("started {name} ({ip})")),
            Err(e) => Reply::err(format!("starting {name}: {e:#}")),
        }
    }

    /// Whether Windows unit `name`'s boot `boot` still runs. Provisioning must not drive
    /// a replacement guest from a later stop and start.
    fn boot_running(&self, name: &str, boot: u64) -> bool {
        // As in `still_running`: a busy lock's holder is the one changing the state. So while a
        // stop or restart holds it (a stop, up to its grace), this boot still reads as running
        // and the provisioning keeps waiting on a guest that is going; the first check after
        // the lock frees sees it gone.
        let Some(mut u) = self.try_units_guard() else {
            return true;
        };
        u.get_mut(name)
            .is_some_and(|st| st.boots == boot && state_of(st) == "running")
    }

    /// Point each recorded service at the image it booted. The registry entry is filed after
    /// the run's eager starts, and every `build:` sibling materializes at its first start
    /// (`build_compose_images` builds only the primary) — so those adoptions happen before
    /// there is an entry for [`crate::vms::note_service_image`] to correct, and are folded in
    /// here instead. Later, control-plane starts go through that function.
    pub fn refresh_service_images(&self, entries: &mut [crate::vms::ServiceEntry]) {
        let units = self.units_guard();
        for e in entries {
            if let Some(st) = units.get(&e.name)
                && let Some(recipe) = e.stale_recipe.as_mut()
            {
                recipe.root_ext4 = st.svc.ext4.clone();
            }
        }
    }

    /// Wait for the unit's agent to answer on its exec channel at `dir`. The VMM binds the
    /// socket only once guest vsock is up; replying earlier lets `exec` race its creation.
    /// Images with `EXPOSE`d ports delay the channel until those ports accept connections,
    /// which the CI executor also relies on when waiting for services.
    async fn wait_ready(&self, name: &str, dir: &Path) -> Result<()> {
        // A Windows unit's start already waited for its provisioning; it runs no vk-agent.
        if self.is_windows(name) {
            return Ok(());
        }
        let console = dir.join(crate::run::CONSOLE_LOG);
        let still_up = || std::future::ready(self.still_running(name, &console));
        match crate::vms::await_agent(&unit_addr(dir), self.boot_timeout, still_up).await? {
            // A service that runs to completion powers its guest off, possibly before the
            // agent answers a probe; the start did what was asked.
            crate::vms::AgentWait::Answered | crate::vms::AgentWait::Ended => Ok(()),
            // Leave the unit running: a slow guest may still come up.
            crate::vms::AgentWait::TimedOut(e) => anyhow::bail!(
                "{name} not ready after {}s ({e}); it is still running\n{}",
                self.boot_timeout.as_secs(),
                crate::run::tail(&console, 20)
            ),
        }
    }

    /// Wait for what `unit` waits on in its dependencies (`depends_on` conditions): their
    /// healthcheck passing, or their run to complete successfully. Gives up once `unit` is
    /// stopped meanwhile (`vk service stop`, compose down), as `stops` then changes.
    fn wait_dependencies(&self, unit: &crate::compose::Unit, stops: u64) -> Result<()> {
        let cancelled = || {
            self.units_guard()
                .get(&unit.name)
                .is_none_or(|st| st.stops != stops)
        };
        for (dependency, condition) in &unit.wait_for {
            match condition {
                crate::compose::Condition::Healthy => {
                    println!(
                        "virtkit: service {}: waiting for {dependency} to be healthy",
                        unit.name
                    );
                    self.wait_healthy(dependency, &cancelled)?;
                }
                crate::compose::Condition::CompletedSuccessfully => {
                    println!(
                        "virtkit: service {}: waiting for {dependency} to complete",
                        unit.name
                    );
                    self.wait_completed(dependency, &cancelled)?;
                }
            }
        }
        Ok(())
    }

    /// Probe `name`'s healthcheck until it passes, or fails `retries` times in a row past its
    /// start period, which runs from now: vk does not know when the service itself is ready to
    /// be checked, and a dependent waits only once its dependency has started.
    fn wait_healthy(&self, name: &str, cancelled: &dyn Fn() -> bool) -> Result<()> {
        let (check, target, console) = {
            let mut u = self.units_guard();
            let st = u
                .get_mut(name)
                .with_context(|| format!("no such unit {name:?}"))?;
            match state_of(st) {
                "running" if st.healthy => return Ok(()),
                "running" => {}
                _ if st.exited.is_none() => anyhow::bail!("{name} was not started"),
                _ => anyhow::bail!("{name} ended before it was healthy"),
            }
            let check = st
                .unit
                .healthcheck
                .clone()
                .with_context(|| format!("{name} declares no healthcheck to be healthy by"))?;
            let target = match st.unit.source {
                crate::compose::Source::Bundle { .. } => {
                    crate::health::Target::GuestAgent(st.dir.join(crate::uefi::GUEST_AGENT_SOCKET))
                }
                _ => crate::health::Target::Agent {
                    addr: unit_addr(&st.dir),
                    user: st.unit.user.clone(),
                },
            };
            (check, target, st.dir.join(crate::run::CONSOLE_LOG))
        };
        let started = std::time::Instant::now();
        let mut failures = 0;
        loop {
            if !self.still_running(name, &console)? {
                anyhow::bail!("{name} ended before it was healthy");
            }
            let failure = match crate::health::probe(&target, &check.test, check.timeout) {
                Ok(0) => {
                    if let Some(st) = self.units_guard().get_mut(name) {
                        st.healthy = true;
                    }
                    return Ok(());
                }
                Ok(code) => format!("exit code {code}"),
                Err(e) => format!("{e:#}"),
            };
            failures = crate::health::count_failure(&check, failures, started.elapsed())
                .with_context(|| {
                    format!(
                        "{name} is unhealthy: {} failed checks in a row, the last: {failure}",
                        check.retries
                    )
                })?;
            pause(check.interval, cancelled)?;
        }
    }

    /// Wait until `name`'s guest has ended, successfully: a job service's run. A Linux guest
    /// powers off the same way whatever its service returned, so its success is the exit code
    /// its agent logged.
    fn wait_completed(&self, name: &str, cancelled: &dyn Fn() -> bool) -> Result<()> {
        loop {
            {
                let mut u = self.units_guard();
                let st = u
                    .get_mut(name)
                    .with_context(|| format!("no such unit {name:?}"))?;
                if state_of(st) != "running" {
                    let windows = matches!(st.unit.source, crate::compose::Source::Bundle { .. });
                    let console = st.dir.join(crate::run::CONSOLE_LOG);
                    return match st.exited {
                        Some(status) if status.success() && windows => Ok(()),
                        Some(status) if status.success() => match service_exit_code(&console) {
                            Some(0) => Ok(()),
                            Some(code) => anyhow::bail!("{name} exited with code {code}"),
                            None => anyhow::bail!("{name} ended with no exit code logged"),
                        },
                        Some(status) => anyhow::bail!("{name} ended with {status}"),
                        None => anyhow::bail!("{name} was not started"),
                    };
                }
            }
            pause(std::time::Duration::from_millis(500), cancelled)?;
        }
    }

    /// Whether `name` is a Windows unit (a bundle `image:`).
    fn is_windows(&self, name: &str) -> bool {
        self.units_guard()
            .get(name)
            .is_some_and(|st| matches!(st.unit.source, crate::compose::Source::Bundle { .. }))
    }

    /// [`Self::wait_ready`]'s check between probes: `Ok(false)` once `name`'s VMM has exited
    /// cleanly (its guest powered off), an error once it stopped any other way.
    fn still_running(&self, name: &str, console: &Path) -> Result<bool> {
        // Never block on the lock: a stop holds it for up to `shutdown::STOP_GRACE`, which
        // must not stall a runtime worker. A busy lock skips this round's state check; its
        // holder is the one changing the state.
        let Some(mut u) = self.try_units_guard() else {
            return Ok(true);
        };
        let st = u
            .get_mut(name)
            .with_context(|| format!("no such unit {name:?}"))?;
        if state_of(st) == "running" {
            return Ok(true);
        }
        if st.exited.is_some_and(|status| status.success()) {
            return Ok(false);
        }
        anyhow::bail!(
            "{name} stopped before its agent answered\n{}",
            crate::run::tail(console, 20)
        )
    }

    /// Power off a unit's guest, then kill and reap its VMM and helpers. Hold the units lock
    /// for up to `shutdown::STOP_GRACE` (`winsvc::STOP_GRACE` for a Windows unit) so another
    /// start cannot race the stopping guest for its overlay and sockets.
    pub fn stop(&self, name: &str) -> Reply {
        let mut u = self.units_guard();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        let was_running = state_of(st) == "running";
        st.stops += 1;
        let mut killed = Vec::new();
        if let Some(mut child) = st.child.take() {
            if let crate::compose::Source::Bundle { .. } = &st.unit.source {
                if !crate::winsvc::stop(name, &mut child, &st.dir) {
                    killed.push(name.to_string());
                }
            } else {
                killed = crate::shutdown::power_off_then_kill(&mut [(
                    name,
                    &unit_addr(&st.dir),
                    &mut child,
                )]);
            }
        }
        // tear down the unit's socket forwards, if any
        for mut a in st.aux.drain(..) {
            let _ = a.kill();
            let _ = a.wait();
        }
        // release the shared-cache base reference now the overlay is gone
        st.guard = None;
        st.firmware = None;
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
        let mut u = self.units_guard();
        let Some(st) = u.get_mut(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        if state_of(st) != "running" {
            return Reply::err(format!("{name} not running"));
        }
        let Some(child) = st.child.as_ref() else {
            return Reply::err(format!("{name} not running"));
        };
        let asked = match st.unit.source {
            crate::compose::Source::Bundle { .. } => crate::winsvc::reboot(&st.dir),
            _ => crate::shutdown::request_reboot(&unit_addr(&st.dir)),
        };
        if asked {
            Reply::ok(format!("rebooting {name}"))
        } else {
            crate::shutdown::hard_reset(child);
            Reply::ok(format!("hard-resetting {name} (agent unreachable)"))
        }
    }

    /// Power off all guests concurrently within one `shutdown::STOP_GRACE` (`winsvc::STOP_GRACE`
    /// for the Windows units), then kill and reap their VMMs and helpers.
    pub fn stop_all(&self) {
        let mut units = self.units_guard();
        // A start still waiting on its dependencies gives up.
        for st in units.values_mut() {
            st.stops += 1;
        }
        // Compute addresses while borrowing the map immutably. It is unchanged before `iter_mut`,
        // so both iterators have the same order and `zip` aligns.
        let addrs: Vec<_> = units.values().map(|st| unit_addr(&st.dir)).collect();
        let mut vmms: Vec<(&str, &SocketAddr, &mut Child)> = Vec::new();
        // Windows units answer the power button, not the agent's poweroff: each is stopped on
        // a thread of its own, alongside the others.
        let mut windows: Vec<(&str, &Path, &mut Child)> = Vec::new();
        for ((name, st), addr) in units.iter_mut().zip(&addrs) {
            let Some(child) = st.child.as_mut() else {
                continue;
            };
            if let crate::compose::Source::Bundle { .. } = st.unit.source {
                windows.push((name.as_str(), st.dir.as_path(), child));
            } else {
                vmms.push((name.as_str(), addr, child));
            }
        }
        std::thread::scope(|scope| {
            for (name, dir, child) in windows {
                scope.spawn(move || {
                    if !crate::winsvc::stop(name, child, dir) {
                        eprintln!(
                            "virtkit: {name}: killed (the guest did not power off within {}s)",
                            crate::winsvc::STOP_GRACE.as_secs()
                        );
                    }
                });
            }
            // Report each kill and its reason immediately.
            crate::shutdown::power_off_then_kill(&mut vmms);
        });
        for st in units.values_mut() {
            st.child = None; // killed and reaped above
            for mut a in st.aux.drain(..) {
                let _ = a.kill();
                let _ = a.wait();
            }
            st.guard = None;
            st.firmware = None;
        }
    }

    fn logs(&self, name: &str, lines: usize) -> Reply {
        let u = self.units_guard();
        let Some(st) = u.get(name) else {
            return Reply::err(format!("no such unit {name:?}"));
        };
        let console = st.dir.join(crate::run::CONSOLE_LOG);
        match console_tail(&console, MAX_LOGS_TAIL) {
            Ok(text) => {
                let mut tail: Vec<&str> = text.lines().rev().take(lines).collect();
                tail.reverse();
                Reply::ok(tail.join("\n"))
            }
            Err(e) => Reply::err(format!("reading {}: {e}", console.display())),
        }
    }
}

/// Control connections a guest may hold open at once. The host's own clients (`vk list`,
/// `vk dev`) dial [`host_control_socket`] instead, so a guest at this bound locks out only
/// itself.
const MAX_CONTROL_CONNECTIONS: usize = 16;

/// How long a control connection may sit between requests before the manager drops it. A
/// request in progress (a `Start` building on demand) is not idle; the guest's client
/// reconnects on its next request.
const CONTROL_IDLE: std::time::Duration = std::time::Duration::from_secs(60);

/// The most of a unit's console `logs` reads: the end of it, which is where its last lines
/// are. The console grows without bound and the guest writes it, so reading it whole would
/// let a guest asking for its own logs make the host hold all of it.
///
/// An eighth of a control message: lossy decoding turns each invalid byte into three and JSON
/// escapes a control character into six, so the reply carrying the tail still fits.
const MAX_LOGS_TAIL: u64 = vk_core::fleetctl::MAX_MSG / 8;

/// The whole lines in the last `max` bytes of `path`, as text — lossy, since the guest writes
/// it. A line the cut lands inside is dropped rather than shown from its middle.
fn console_tail(path: &Path, max: u64) -> std::io::Result<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let len = f.metadata()?.len();
    if len <= max {
        // Still bounded: the guest may be writing past `len` meanwhile.
        let mut bytes = Vec::new();
        f.take(max).read_to_end(&mut bytes)?;
        return Ok(String::from_utf8_lossy(&bytes).into_owned());
    }
    // From one byte before the cut, so a cut right after a newline keeps the line it starts.
    f.seek(SeekFrom::Start(len - max - 1))?;
    let mut bytes = Vec::new();
    f.take(max + 1).read_to_end(&mut bytes)?;
    let whole = bytes
        .iter()
        .position(|&b| b == b'\n')
        .map_or(&[][..], |nl| &bytes[nl + 1..]);
    Ok(String::from_utf8_lossy(whole).into_owned())
}

/// Sleep for `duration`, giving up once `cancelled`.
fn pause(duration: std::time::Duration, cancelled: &dyn Fn() -> bool) -> Result<()> {
    let until = std::time::Instant::now() + duration;
    loop {
        if cancelled() {
            anyhow::bail!("stopped while waiting for its dependencies");
        }
        let left = until.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        std::thread::sleep(left.min(std::time::Duration::from_millis(250)));
    }
}

/// The exit code a Linux guest's agent logged for its service in `console` (the last one: a
/// service is started once per boot), if any.
fn service_exit_code(console: &Path) -> Option<i32> {
    const MARK: &str = "vk-agent init: service exited (code ";
    let text = std::fs::read_to_string(console).ok()?;
    let line = text.lines().rev().find(|l| l.contains(MARK))?;
    let rest = &line[line.find(MARK)? + MARK.len()..];
    rest[..rest.find(')')?].parse().ok()
}

/// Build a unit's agent exec address from its runtime directory.
fn unit_addr(dir: &Path) -> SocketAddr {
    crate::vmm::exec_addr(
        &dir.join(crate::units::VSOCK_SOCKET),
        crate::units::VSOCK_PORT,
    )
}

/// "running" if the unit's child is alive, else "stopped". Reaps a child that has
/// exited (e.g. the service crashed) so the reported state reflects reality; a child
/// whose status can't be read is conservatively reported "running" (and left for a
/// later poll to reap).
fn state_of(st: &mut UnitState) -> &'static str {
    match st.child.as_mut().map(Child::try_wait) {
        Some(Ok(None)) | Some(Err(_)) => "running",
        Some(Ok(Some(status))) => {
            st.child = None;
            st.exited = Some(status);
            "stopped"
        }
        None => "stopped",
    }
}

/// The host-only control socket of a run whose guest-facing one is the per-port socket of
/// base `vsock`. The VMM forwards guest connections to `<vsock>_<CONTROL_PORT>` only, so a guest
/// cannot reach this one, nor fill its connections.
pub fn host_control_socket(vsock: &Path) -> PathBuf {
    let mut socket =
        vk_core::net::hybrid_socket(vsock, vk_core::fleetctl::CONTROL_PORT).into_os_string();
    socket.push(".host");
    socket.into()
}

/// Serve the control protocol (a session of request/reply pairs per connection — the guest's
/// /run/vk/services bridge keeps one connection open across operations) on both of a VM's
/// control sockets: the guest's, the per-port socket of base `vsock`, holding at most
/// [`MAX_CONTROL_CONNECTIONS`]; and the host's own, [`host_control_socket`].
pub async fn control_server(vsock: &Path, mgr: Arc<Manager>) -> Result<()> {
    let guest = bind_control(&vk_core::net::hybrid_socket(
        vsock,
        vk_core::fleetctl::CONTROL_PORT,
    ))?;
    let host = bind_control(&host_control_socket(vsock))?;
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONTROL_CONNECTIONS));
    tokio::try_join!(
        serve_control(guest, Some(slots), mgr.clone()),
        serve_control(host, None, mgr),
    )?;
    Ok(())
}

fn bind_control(listen: &Path) -> Result<tokio::net::UnixListener> {
    let _ = std::fs::remove_file(listen);
    vk_core::unixpath::bind_tokio(listen)
        .with_context(|| format!("control: bind {}", listen.display()))
}

/// Accept on `listener`, holding a slot per connection when `slots` is given.
/// When all slots are held, wait for a connection to close before accepting another.
async fn serve_control(
    listener: tokio::net::UnixListener,
    slots: Option<Arc<tokio::sync::Semaphore>>,
    mgr: Arc<Manager>,
) -> Result<()> {
    loop {
        let slot = match &slots {
            Some(slots) => Some(slots.clone().acquire_owned().await?),
            None => None,
        };
        let (conn, _) = listener.accept().await?;
        let mgr = mgr.clone();
        tokio::spawn(async move {
            let _slot = slot;
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
        // The peer hanging up or idling between requests is the normal end of a session. A
        // request is a unit name and an operation: bounded to that, not to a reply's size.
        let read = vk_core::fleetctl::read_msg_capped::<_, Request>(
            &mut rd,
            vk_core::fleetctl::MAX_REQUEST,
        );
        let Ok(Ok(req)) = tokio::time::timeout(CONTROL_IDLE, read).await else {
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
/// while the detached build runs to completion. A successful start sends its `Done` only once
/// the unit's agent answers (`Manager::wait_ready`), within the boot timeout.
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
    let task = tokio::task::spawn_blocking({
        let (mgr, unit) = (Arc::clone(mgr), unit.clone());
        move || {
            if restart {
                let _ = mgr.stop(&unit);
            }
            let reply = mgr.start_streamed(&unit, Some(sink));
            let dir = mgr.units_guard().get(&unit).map(|st| st.dir.clone());
            (reply, dir)
        }
    });
    // Drain build progress until the task drops its sink (build + boot done). A write error
    // here (peer gone) returns via `?`, dropping the receiver and detaching the build — it
    // runs to completion, warming the store for the next start; its outcome (or a panic) is
    // then unobserved. Only the drained path below surfaces a task panic as a `Reply::err`.
    while let Some(line) = rx.recv().await {
        vk_core::fleetctl::write_msg(wr, &Frame::Progress(line)).await?;
    }
    let (mut reply, dir) = task
        .await
        .unwrap_or_else(|e| (Reply::err(format!("start task failed: {e}")), None));
    if reply.ok
        && let Some(dir) = dir
        && let Err(e) = mgr.wait_ready(&unit, &dir).await
    {
        reply = Reply::err(format!("{e:#}"));
    }
    vk_core::fleetctl::write_msg(wr, &Frame::Done(reply)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory for one test, under a name no other run computes.
    fn scratch_dir(name: &str) -> PathBuf {
        let nonce = crate::scratch::random_nonce().unwrap();
        let dir = std::env::temp_dir().join(format!("vk-manager-{name}-{nonce}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Only the end of a long console is read, and only its whole lines.
    #[test]
    fn a_console_is_read_from_its_end_in_whole_lines() {
        let dir = scratch_dir("console-tail");
        let path = dir.join("console.log");
        std::fs::write(&path, b"first line\nsecond\nthird\n").unwrap();
        assert_eq!(
            console_tail(&path, 1 << 20).unwrap(),
            "first line\nsecond\nthird\n"
        );
        // A cut inside "second" drops what is left of it.
        assert_eq!(console_tail(&path, 9).unwrap(), "third\n");
        // A cut right after a newline keeps the whole line it starts.
        assert_eq!(console_tail(&path, 13).unwrap(), "second\nthird\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The guest's and host's control clients of a test server on `vsock`, once it listens.
    async fn control_sockets(vsock: &Path) -> (PathBuf, PathBuf) {
        let guest = vk_core::net::hybrid_socket(vsock, vk_core::fleetctl::CONTROL_PORT);
        let host = host_control_socket(vsock);
        while !host.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        (guest, host)
    }

    /// A list request over a fresh connection to `socket`, and its reply.
    async fn list_over(socket: &Path) -> Reply {
        let (rd, mut wr) = tokio::net::UnixStream::connect(socket)
            .await
            .unwrap()
            .into_split();
        let mut rd = tokio::io::BufReader::new(rd);
        vk_core::fleetctl::write_msg(&mut wr, &Request::List)
            .await
            .unwrap();
        let Frame::Done(reply) = vk_core::fleetctl::read_msg(&mut rd).await.unwrap() else {
            panic!("a list answers with Done");
        };
        reply
    }

    /// A guest holding every connection it may leaves the host's clients served on their own
    /// socket while its own next connection waits, until one of its connections closes. No
    /// connection here reaches the idle bound, so nothing frees a slot but the guest.
    #[tokio::test]
    async fn a_guest_at_its_connection_bound_leaves_the_host_served() {
        use tokio::net::UnixStream;
        let dir = scratch_dir("control");
        let vsock = dir.join("vsock.sock");
        let mgr = Arc::new(manager_over_two_units());
        tokio::spawn({
            let vsock = vsock.clone();
            async move { control_server(&vsock, mgr).await }
        });
        let (guest, host) = control_sockets(&vsock).await;
        let mut held = Vec::new();
        for _ in 0..MAX_CONTROL_CONNECTIONS {
            held.push(UnixStream::connect(&guest).await.unwrap());
        }

        // Not served in a while; a short wait, since a slow server only lets this pass.
        let mut over = std::pin::pin!(list_over(&guest));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), &mut over)
                .await
                .is_err(),
            "a guest connection past the bound was served"
        );
        // Bounded well inside the idle bound, which would free the slots.
        let reply = tokio::time::timeout(CONTROL_IDLE / 2, list_over(&host))
            .await
            .expect("the host waited for a slot");
        assert!(reply.ok, "{}", reply.message);

        held.pop();
        assert!(over.await.ok);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A guest connection is dropped after [`CONTROL_IDLE`], not before. With the clock paused,
    /// the idle wait is the only timer, so advancing to it elapses the bound.
    #[tokio::test(start_paused = true)]
    async fn an_idle_guest_connection_is_dropped_at_the_idle_bound() {
        use tokio::io::AsyncReadExt;
        let dir = scratch_dir("control-idle");
        let vsock = dir.join("vsock.sock");
        let mgr = Arc::new(manager_over_two_units());
        tokio::spawn({
            let vsock = vsock.clone();
            async move { control_server(&vsock, mgr).await }
        });
        let (guest, _) = control_sockets(&vsock).await;
        let opened = tokio::time::Instant::now();
        let mut idle = tokio::net::UnixStream::connect(&guest).await.unwrap();
        assert_eq!(idle.read(&mut [0u8; 1]).await.unwrap(), 0);
        assert!(
            opened.elapsed() >= CONTROL_IDLE,
            "an idle connection closed early"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_linux_services_exit_code_is_the_last_one_its_agent_logged() {
        let dir = scratch_dir("exit-code");
        let console = dir.join("console.log");
        assert_eq!(service_exit_code(&console), None, "no console yet");
        std::fs::write(
            &console,
            "06:31:22 [INFO] vk-agent init: service pid 56\n\
             07:30:30 [INFO] vk-agent init: service exited (code 0)\n\
             boot again\n\
             07:31:02 [INFO] vk-agent init: service exited (code 1)\n",
        )
        .unwrap();
        assert_eq!(service_exit_code(&console), Some(1));
        std::fs::write(&console, "vk-agent init: service exited (code -15)\n").unwrap();
        assert_eq!(service_exit_code(&console), Some(-15));
        std::fs::write(&console, "a guest that never ran a service\n").unwrap();
        assert_eq!(service_exit_code(&console), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wait_on_a_dependency_never_started_fails_and_a_stop_ends_a_wait() {
        let mgr = manager_over_two_units();
        let never = || false;
        for err in [
            mgr.wait_healthy("cache", &never).unwrap_err(),
            mgr.wait_completed("cache", &never).unwrap_err(),
        ] {
            assert!(format!("{err:#}").contains("was not started"), "{err:#}");
        }
        let stops = |mgr: &Manager| mgr.units_guard()["cache"].stops;
        let before = stops(&mgr);
        assert!(mgr.stop("cache").ok);
        mgr.stop_all();
        assert_eq!(stops(&mgr), before + 2);
        let started = std::time::Instant::now();
        let err = pause(std::time::Duration::from_secs(60), &|| true).unwrap_err();
        assert!(
            format!("{err:#}").contains("stopped while waiting"),
            "{err:#}"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// A manager over one `build:` unit and one `image:` unit, provisioned as `plan_services`
    /// would leave them: each addressed, neither built.
    fn manager_over_two_units() -> Manager {
        manager_over_two_units_within(std::time::Duration::from_secs(120))
    }

    /// [`manager_over_two_units`] with a control-plane start waiting up to `boot_timeout`.
    fn manager_over_two_units_within(boot_timeout: std::time::Duration) -> Manager {
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
            1024,
            gw,
            "/nonexistent".into(),
            crate::units::BuildOpts {
                build_args: vec![],
                kernel: "/nonexistent".into(),
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
            boot_timeout,
            provisioned,
        )
    }

    /// The panic hook is process-wide, so the test that swaps it takes its turn rather than
    /// swallowing another test's panic message. Guards `()`, so a poisoning carries nothing.
    static HOOK_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn a_poisoned_units_lock_is_recovered_not_fatal() {
        let _serial = HOOK_SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mgr = manager_over_two_units();
        // Poison the lock by unwinding while holding its guard.
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {})); // keep the expected panic out of the test log
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _g = mgr.units.lock().unwrap();
            panic!("boom while holding the units lock");
        }));
        std::panic::set_hook(prev);
        assert!(r.is_err(), "the closure must panic to poison the lock");
        assert!(
            mgr.units.is_poisoned(),
            "the lock is poisoned after the panic"
        );
        // Recovered, not fatal: the manager keeps answering over the poisoned lock instead of
        // failing every later request until the run restarts — on both a read-only guard and a
        // mutating one — and the first recovery clears the poison so later requests take the
        // normal path.
        assert_eq!(mgr.declared(), 2);
        assert!(
            mgr.status("db").ok,
            "a mutating-guard request also recovers"
        );
        assert!(!mgr.units.is_poisoned(), "recovery clears the poison flag");
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

    #[tokio::test]
    async fn waiting_on_a_unit_that_is_not_running_fails_at_once() {
        let mgr = manager_over_two_units();
        let dir = mgr.units_guard()["cache"].dir.clone();
        let err = mgr.wait_ready("cache", &dir).await.unwrap_err().to_string();
        assert!(
            err.contains("cache stopped before its agent answered"),
            "{err}"
        );
        let err = mgr
            .wait_ready("absent", &dir)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no such unit"), "{err}");
    }

    /// Point `cache` at a VMM stand-in that exits with `code` right away, as a guest that
    /// powers off does; `wait_ready` keeps probing until it has.
    fn exiting_unit(mgr: &Manager, code: i32) -> PathBuf {
        let child = std::process::Command::new("sh")
            .args(["-c", &format!("exit {code}")])
            .spawn()
            .unwrap();
        let mut u = mgr.units_guard();
        let st = u.get_mut("cache").unwrap();
        st.child = Some(child);
        st.dir.clone()
    }

    #[tokio::test]
    async fn a_unit_whose_guest_powered_off_cleanly_is_ready() {
        // A one-shot service (`command: cp …`) powers its guest off as soon as it finishes,
        // possibly before a probe reaches its agent: the start succeeded.
        let mgr = manager_over_two_units_within(std::time::Duration::from_secs(10));
        let dir = exiting_unit(&mgr, 0);
        mgr.wait_ready("cache", &dir).await.unwrap();
    }

    #[tokio::test]
    async fn a_unit_whose_vmm_failed_before_its_agent_answered_is_an_error() {
        let mgr = manager_over_two_units_within(std::time::Duration::from_secs(10));
        let dir = exiting_unit(&mgr, 1);
        let err = mgr.wait_ready("cache", &dir).await.unwrap_err().to_string();
        assert!(
            err.contains("cache stopped before its agent answered"),
            "{err}"
        );
    }

    /// Provisioning drives only its own boot's guest, never a stopped or replacement guest.
    #[test]
    fn a_provisioning_drives_only_the_boot_it_is_for() {
        let mgr = manager_over_two_units();
        let set = |child: Option<std::process::Child>, boots: u64| {
            let mut u = mgr.units_guard();
            let st = u.get_mut("cache").unwrap();
            if let Some(mut old) = std::mem::replace(&mut st.child, child) {
                let _ = old.kill();
                let _ = old.wait();
            }
            st.boots = boots;
        };
        let sleeper = || {
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap()
        };
        set(Some(sleeper()), 1);
        assert!(mgr.boot_running("cache", 1));
        // Stopped: its guest is gone.
        set(None, 1);
        assert!(!mgr.boot_running("cache", 1));
        // Started again: the guest up is the next boot's.
        set(Some(sleeper()), 2);
        assert!(!mgr.boot_running("cache", 1));
        assert!(mgr.boot_running("cache", 2));
        set(None, 2);
    }

    #[tokio::test]
    async fn a_unit_whose_agent_never_answers_times_out_and_is_left_running() {
        let mgr = manager_over_two_units_within(std::time::Duration::ZERO);
        // A live child stands in for the VMM; the unit's dir holds no exec socket.
        let dir = {
            let mut u = mgr.units_guard();
            let st = u.get_mut("cache").unwrap();
            st.child = Some(
                std::process::Command::new("sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            );
            st.dir.clone()
        };
        let err = mgr.wait_ready("cache", &dir).await.unwrap_err().to_string();
        let mut child = mgr
            .units_guard()
            .get_mut("cache")
            .unwrap()
            .child
            .take()
            .unwrap();
        let _ = child.kill();
        let _ = child.wait();
        assert!(err.contains("cache not ready after 0s"), "{err}");
        assert!(err.contains("still running"), "{err}");
    }

    #[tokio::test]
    async fn a_unit_whose_agent_answers_is_ready() {
        let mgr = manager_over_two_units_within(std::time::Duration::from_secs(10));
        // A live child stands in for the VMM; an exec server bound late stands in for the
        // agent, at the per-port socket the unit's `vsock-auto` address resolves to first.
        let dir = std::env::temp_dir().join(format!("vk-mgr-ready-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let SocketAddr::VsockAuto { path, port } = unit_addr(&dir) else {
            panic!("a unit's exec address is vsock-auto");
        };
        let agent = SocketAddr::Unix(vk_core::net::hybrid_socket(&path, port));
        mgr.units_guard().get_mut("cache").unwrap().child = Some(
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            vk_core::exec::server::run_server(
                &agent,
                Some(std::time::Duration::from_secs(60)),
                None,
                vec![],
            )
            .await
            .unwrap();
        });
        let res = mgr.wait_ready("cache", &dir).await;
        let mut child = mgr
            .units_guard()
            .get_mut("cache")
            .unwrap()
            .child
            .take()
            .unwrap();
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        res.unwrap();
    }
}
