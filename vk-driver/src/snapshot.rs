//! `vk snapshot`: a running UEFI VM (or every Windows service of a compose run) saved as a
//! bundle a later `vk run` starts from instead of booting.
//!
//! A snapshot bundle is a [`crate::uefi`] bundle whose `vm.json` carries `"snapshot"`: beside its
//! disks it holds the VM's `state.json` and the memory image it names, written by libkrun
//! through the VM's control socket ([`crate::vmmctl`]). Taking one ends the VM: its disk
//! overlays are linked into the bundle before the snapshot, so its last flush lands in them
//! too, then unlinked from the run once it has ended, so nothing writes them again. A run from
//! it gives the guest a new VM generation ID ([`crate::uefi::guest_spec`]).
//!
//! The overlays keep their backing files' paths: a snapshot needs the bundle its VM ran (and
//! any snapshot that one was taken from) to stay where it is, unchanged.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// How long a VM has to end after its snapshot's quit request.
const END_TIMEOUT: Duration = Duration::from_secs(60);

/// What a snapshot bundle's `vm.json` says beside its disks.
pub struct Machine {
    pub cpus: Option<u32>,
    pub mem: Option<String>,
    /// The VM's address on its run's network; None: it had none.
    pub addr: Option<Ipv4Addr>,
}

/// Snapshot the VM behind the control socket `control`, whose run directory holds its disk
/// overlays, into the new bundle `out`, and end it; `ended` says when it has. A failure removes
/// `out` and, before the VM is asked to end, resumes it; `if_paused` tells the user what to do
/// should it stay paused.
pub fn snapshot_vm(
    control: &Path,
    out: &Path,
    machine: impl FnOnce(&Path) -> Result<Machine>,
    ended: impl Fn() -> bool,
    if_paused: &str,
) -> Result<()> {
    let work = control.parent().context("the VM's run directory")?;
    let disks: Vec<PathBuf> = (0..)
        .map(|i| work.join(format!("disk{i}.qcow2")))
        .take_while(|p| p.exists())
        .collect();
    if disks.is_empty() {
        bail!("the VM's disks are not in {}", work.display());
    }
    create_private_dir(out)?;
    let result = save(control, &disks, out, machine, ended, if_paused);
    if result.is_err() {
        let _ = std::fs::remove_dir_all(out);
    }
    result
}

/// [`snapshot_vm`] into the directory `out` it created.
fn save(
    control: &Path,
    disks: &[PathBuf],
    out: &Path,
    machine: impl FnOnce(&Path) -> Result<Machine>,
    ended: impl Fn() -> bool,
    if_paused: &str,
) -> Result<()> {
    let manifest = out.join(crate::uefi::MANIFEST);
    let manifest_tmp = manifest.with_extension("tmp");
    let prepare = || -> Result<()> {
        let out = std::fs::canonicalize(out)?;
        // Linked first: an `out` on another filesystem fails before the VM is touched.
        let mut names = Vec::new();
        for (i, disk) in disks.iter().enumerate() {
            let name = format!("disk{i}.qcow2");
            std::fs::hard_link(disk, out.join(&name)).with_context(|| {
                format!(
                    "linking {} into the snapshot (it must be on the run's filesystem)",
                    disk.display()
                )
            })?;
            names.push(name);
        }
        crate::vmmctl::snapshot(control, &out)?;
        let machine = machine(&out)?;
        let manifest = serde_json::json!({
            "firmware": "uefi",
            "cpus": machine.cpus,
            "mem": machine.mem,
            "disks": names,
            "snapshot": crate::uefi::SnapshotInfo { addr: machine.addr },
        });
        std::fs::write(&manifest_tmp, serde_json::to_string_pretty(&manifest)?)
            .with_context(|| format!("writing {}", manifest_tmp.display()))?;
        crate::vmmctl::quit(control)
    };
    if let Err(e) = prepare() {
        return Err(match crate::vmmctl::request(control, "resume") {
            Ok(()) => e,
            Err(re) => anyhow::anyhow!(
                "{e:#}; resuming the VM failed too ({re:#}), so it is left paused: {if_paused}"
            ),
        });
    }
    let deadline = Instant::now() + END_TIMEOUT;
    while !ended() {
        if Instant::now() > deadline {
            bail!(
                "the VM did not end within {}s of its snapshot, which is dropped",
                END_TIMEOUT.as_secs()
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    for disk in disks {
        std::fs::remove_file(disk)
            .with_context(|| format!("unlinking {} from the run", disk.display()))?;
    }
    // Last: a bundle with its `vm.json` is whole.
    std::fs::rename(&manifest_tmp, &manifest)
        .with_context(|| format!("writing {}", manifest.display()))
}

/// Create the new directory `dir`, and its missing parents, readable by its owner only: a
/// snapshot holds the guest's RAM. An existing `dir` is refused.
fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// Read a compose service's vCPU count and RAM (the sum of its RAM regions) from `snapshot`,
/// and its address from runtime dir `dir` ([`crate::winsvc::ADDRESS`]).
fn service_machine(snapshot: &Path, dir: &Path) -> Result<Machine> {
    let path = snapshot.join("state.json");
    let state: serde_json::Value = serde_json::from_reader(std::io::BufReader::new(
        std::fs::File::open(&path).with_context(|| format!("reading {}", path.display()))?,
    ))
    .with_context(|| format!("parsing {}", path.display()))?;
    let cpus = state["cpu"]["vcpus"].as_array().map(|v| v.len() as u32);
    let bytes: u64 = state["memory"]
        .as_array()
        .context("the snapshot records no memory")?
        .iter()
        .filter_map(|region| region["len"].as_u64())
        .sum();
    let path = dir.join(crate::winsvc::ADDRESS);
    let addr = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;
    Ok(Machine {
        cpus,
        mem: Some(format!("{}M", bytes >> 20)),
        addr: Some(addr),
    })
}

/// The Windows services of the compose run whose state directory is `run_dir`: each service's
/// name and control socket, in name order.
fn run_services(run_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut services = Vec::new();
    for entry in std::fs::read_dir(run_dir).with_context(|| format!("{}", run_dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(service) = name.strip_prefix("svc-") else {
            continue;
        };
        let control = entry.path().join(crate::uefi::CONTROL_SOCKET);
        if control.exists() {
            services.push((service.to_string(), control));
        }
    }
    services.sort();
    Ok(services)
}

/// Whether a VM still listens on the control socket `control`.
fn listening(control: &Path) -> bool {
    vk_core::unixpath::connect(control).is_ok()
}

/// Snapshot every running Windows service of the compose run in `run_dir` into
/// `out/<service>`, ending them. Every one is paused before any is saved, so the lab's machines
/// stop at one moment. The run's Linux services are not saved: a run from the snapshot boots
/// them. A failure resumes the services not saved yet and says which ones ended.
pub fn snapshot_run(run_dir: &Path, out: &Path) -> Result<String> {
    // A stopped service leaves its socket behind.
    let services: Vec<_> = run_services(run_dir)?
        .into_iter()
        .filter(|(_, control)| listening(control))
        .collect();
    if services.is_empty() {
        bail!("{} runs no Windows service", run_dir.display());
    }
    create_private_dir(out)?;
    let mut ended = Vec::new();
    let Err(e) = snapshot_services(&services, out, &mut ended) else {
        return Ok(ended
            .iter()
            .map(|name| format!("snapshotted {name} into {}\n", out.join(name).display()))
            .collect());
    };
    let paused: Vec<&str> = services[ended.len()..]
        .iter()
        .filter(|(_, control)| crate::vmmctl::request(control, "resume").is_err())
        .map(|(name, _)| name.as_str())
        .collect();
    let mut msg = format!("{e:#}");
    if ended.is_empty() {
        let _ = std::fs::remove_dir_all(out);
    } else {
        msg += &format!(
            "; {} ended, snapshotted into {}",
            ended.join(", "),
            out.display()
        );
    }
    if !paused.is_empty() {
        msg += &format!(
            "; {} could not be resumed: stopping the run ends them",
            paused.join(", ")
        );
    }
    bail!("{msg}")
}

/// [`snapshot_run`]'s `services` into `out`, each pushed onto `ended` once saved.
fn snapshot_services(
    services: &[(String, PathBuf)],
    out: &Path,
    ended: &mut Vec<String>,
) -> Result<()> {
    for (name, control) in services {
        crate::vmmctl::request(control, "pause").with_context(|| format!("pausing {name}"))?;
    }
    for (name, control) in services {
        let dir = control.parent().context("the service's runtime dir")?;
        snapshot_vm(
            control,
            &out.join(name),
            |snapshot| service_machine(snapshot, dir),
            || !listening(control),
            "stopping the run ends it",
        )
        .with_context(|| format!("snapshotting {name}"))?;
        ended.push(name.clone());
    }
    Ok(())
}

/// The snapshot of the compose service `service` in the fleet snapshot `dir`, if it has one.
pub fn service_snapshot(dir: &Path, service: &str) -> Option<PathBuf> {
    let bundle = dir.join(service);
    bundle
        .join(crate::uefi::MANIFEST)
        .is_file()
        .then(|| std::fs::canonicalize(&bundle).unwrap_or(bundle))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Record VM control requests and check snapshots have linked overlays and no `vm.json`
    /// yet; with `fail`, fail the snapshot.
    struct Fake {
        asked: Arc<Mutex<Vec<&'static str>>>,
        fail: bool,
    }

    impl crate::vmmctl::Control for Fake {
        fn pause(&self) -> Result<()> {
            self.asked.lock().unwrap().push("pause");
            Ok(())
        }

        fn resume(&self) -> Result<()> {
            self.asked.lock().unwrap().push("resume");
            Ok(())
        }

        fn snapshot(&self, dir: &Path) -> Result<()> {
            self.asked.lock().unwrap().push("snapshot");
            assert_eq!(std::fs::read(dir.join("disk0.qcow2")).unwrap(), b"0");
            assert_eq!(std::fs::read(dir.join("disk1.qcow2")).unwrap(), b"1");
            assert!(!dir.join(crate::uefi::MANIFEST).exists());
            if self.fail {
                bail!("no space left");
            }
            Ok(())
        }

        fn quit(&self) -> Result<()> {
            self.asked.lock().unwrap().push("quit");
            Ok(())
        }
    }

    /// A run directory with two overlays and a [`Fake`] VM on its control socket.
    struct Run {
        dir: PathBuf,
        control: PathBuf,
        asked: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Run {
        fn new(name: &str, fail: bool) -> Run {
            let dir = std::env::temp_dir().join(format!("vk-snap-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let work = dir.join("run");
            std::fs::create_dir_all(&work).unwrap();
            std::fs::write(work.join("disk0.qcow2"), "0").unwrap();
            std::fs::write(work.join("disk1.qcow2"), "1").unwrap();
            let control = work.join(crate::uefi::CONTROL_SOCKET);
            let asked = Arc::new(Mutex::new(Vec::new()));
            let fake = Fake {
                asked: asked.clone(),
                fail,
            };
            crate::vmmctl::serve(&control, fake).unwrap();
            Run {
                dir,
                control,
                asked,
            }
        }

        fn snapshot(&self, out: &Path) -> Result<()> {
            let machine = |_: &Path| {
                Ok(Machine {
                    cpus: Some(2),
                    mem: Some("4G".into()),
                    addr: Some(Ipv4Addr::new(192, 168, 127, 2)),
                })
            };
            let ended = || self.asked.lock().unwrap().contains(&"quit");
            snapshot_vm(&self.control, out, machine, ended, "resume it")
        }

        fn asked(&self) -> Vec<&'static str> {
            self.asked.lock().unwrap().clone()
        }

        fn has_disks(&self) -> bool {
            let work = self.dir.join("run");
            work.join("disk0.qcow2").exists() && work.join("disk1.qcow2").exists()
        }
    }

    impl Drop for Run {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_snapshot_takes_the_vms_overlays_and_ends_it() {
        let run = Run::new("ok", false);
        let out = run.dir.join("snaps/one");
        run.snapshot(&out).unwrap();
        assert_eq!(run.asked(), ["snapshot", "quit"]);
        assert!(!run.has_disks());
        assert_eq!(std::fs::read(out.join("disk1.qcow2")).unwrap(), b"1");
        assert!(!out.join("vm.tmp").exists());
        let bundle = crate::uefi::Bundle::open(&out).unwrap();
        assert_eq!(bundle.manifest.cpus, Some(2));
        assert_eq!(bundle.manifest.mem.as_deref(), Some("4G"));
        assert_eq!(
            bundle.manifest.snapshot,
            Some(crate::uefi::SnapshotInfo {
                addr: Some(Ipv4Addr::new(192, 168, 127, 2))
            })
        );
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&out).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn an_existing_out_is_refused_before_the_vm_is_asked_anything() {
        let run = Run::new("exists", false);
        let out = run.dir.join("out");
        std::fs::create_dir(&out).unwrap();
        let err = run.snapshot(&out).unwrap_err();
        assert!(format!("{err:#}").contains("exists"), "{err:#}");
        assert!(run.asked().is_empty());
        assert!(out.is_dir());
        assert!(run.has_disks());
    }

    #[test]
    fn a_failed_snapshot_resumes_the_vm_and_leaves_nothing_behind() {
        let run = Run::new("fail", true);
        let out = run.dir.join("out");
        let err = run.snapshot(&out).unwrap_err();
        assert!(format!("{err:#}").contains("no space left"), "{err:#}");
        assert_eq!(run.asked(), ["snapshot", "resume"]);
        assert!(!out.exists());
        assert!(run.has_disks());
    }

    #[test]
    fn a_service_snapshot_records_its_vcpus_ram_and_address() {
        let dir = std::env::temp_dir().join(format!("vk-snapshot-machine-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("state.json"),
            r#"{"version":1,"cpu":{"vm":{},"vcpus":[{},{}]},"memory":[
                {"guest_addr":0,"len":3221225472},{"guest_addr":4294967296,"len":0}]}"#,
        )
        .unwrap();
        assert!(service_machine(&dir, &dir).is_err());
        std::fs::write(dir.join(crate::winsvc::ADDRESS), "192.168.127.3").unwrap();
        let machine = service_machine(&dir, &dir).unwrap();
        assert_eq!(machine.cpus, Some(2));
        assert_eq!(machine.mem.as_deref(), Some("3072M"));
        assert_eq!(machine.addr, Some(Ipv4Addr::new(192, 168, 127, 3)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_services_with_a_control_socket_are_a_runs_windows_services() {
        let dir = std::env::temp_dir().join(format!("vk-snapshot-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for svc in ["svc-dc", "svc-member1", "svc-web", "other"] {
            std::fs::create_dir_all(dir.join(svc)).unwrap();
        }
        for svc in ["svc-member1", "svc-dc"] {
            std::fs::write(dir.join(svc).join(crate::uefi::CONTROL_SOCKET), "").unwrap();
        }
        let names: Vec<String> = run_services(&dir)
            .unwrap()
            .into_iter()
            .map(|s| s.0)
            .collect();
        assert_eq!(names, ["dc", "member1"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
