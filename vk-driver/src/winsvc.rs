//! Windows compose services: a unit whose `image:` is a bundle directory — what `vk build`
//! makes of a Windows Dockerfile — boots as a UEFI guest on the run's LAN instead of a Linux
//! microVM.
//!
//! Every start boots fresh overlays over the bundle's disks, with a new VM generation ID: a
//! restart is a new machine, as a Linux service's throwaway root is. The NIC's MAC derives from
//! the unit's address, so the switch's DHCP reservation hands Windows that address, with the
//! gateway as its resolver (which answers the other services' names).
//!
//! The service is up once its provisioning has run: the compose `command:`, else the image's
//! `CMD` (kept in the bundle's `layer.json`), run through qemu-ga as SYSTEM with `VK_HOSTNAME`,
//! `VK_IP`, `VK_PREFIX` and `VK_GATEWAY` ahead of the service's environment. It runs at every
//! start, so it must be safe to run again; its exit code 3010 or 1641 restarts Windows and runs
//! it once more, up to [`MAX_RESTARTS`] times.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::uefi::{Bundle, GUEST_AGENT_SOCKET};

/// How long Windows has to come up — a generalized image's first boot runs specialize and
/// OOBE — at the start and after each restart its provisioning asks for.
pub(crate) const START_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How long a Windows service has to power off before it is killed: a domain controller can
/// take minutes to shut down.
pub(crate) const STOP_GRACE: Duration = Duration::from_secs(3 * 60);

/// How many restarts one start's provisioning may ask for.
const MAX_RESTARTS: u32 = 4;

/// The provisioning's output, in the unit's runtime dir.
pub(crate) const PROVISION_LOG: &str = "provision.log";

/// What a bundle unit boots with when neither its compose `x-virtkit` nor its `vm.json` sizes it.
const DEFAULT_CPUS: u32 = 2;
const DEFAULT_MEM: &str = "4G";

/// Boot the bundle unit `svc` in its runtime dir `dir`, on the switch port `net_port`. Returns
/// the VMM and the firmware it boots, which must stay held while it runs.
pub(crate) fn boot(
    svc: &crate::units::Provisioned,
    dir: &Path,
    net_port: u32,
    gateway: Ipv4Addr,
) -> Result<(Child, crate::embed::Resolved)> {
    let bundle = Bundle::open(&svc.ext4)?;
    let disks = bundle.disks()?;
    // A new machine every start: drop the last start's overlays and generation ID.
    let stale = (0..disks.len())
        .map(|i| format!("disk{i}.qcow2"))
        .chain([crate::uefi::GENERATION_ID.to_string()]);
    for name in stale {
        let path = dir.join(name);
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e).with_context(|| format!("removing {}", path.display()));
            }
            _ => {}
        }
    }
    let disks = crate::uefi::overlays(&disks, dir)?;
    let cpus = svc.cpus.or(bundle.manifest.cpus).unwrap_or(DEFAULT_CPUS);
    let mem = svc
        .mem
        .clone()
        .or_else(|| bundle.manifest.mem.clone())
        .unwrap_or_else(|| DEFAULT_MEM.to_string());
    let firmware = crate::uefi::firmware()?;
    let mut spec = crate::uefi::guest_spec(&firmware.path, dir, &svc.name, disks, cpus, &mem)?;
    spec.nics = crate::vmm::switch_attach(
        &dir.join(crate::units::VSOCK_SOCKET),
        net_port,
        &[svc.addr],
        svc.prefix,
        gateway,
    )
    .nics;
    let vmm = crate::vmm::selected();
    let child = crate::run::spawn_vmm(vmm.as_ref(), &spec, crate::prio::Prio::Normal)?;
    Ok((child, firmware))
}

/// What one start's provisioning runs, gathered so it can run without the units lock.
pub(crate) struct Provisioning {
    pub name: String,
    pub dir: PathBuf,
    /// the compose `command:`, else the image's `CMD`; `None`: nothing to run
    pub command: Option<String>,
    pub workdir: Option<String>,
    pub env: Vec<(String, String)>,
}

impl Provisioning {
    /// The provisioning of the bundle unit `svc`, whose compose unit is `unit` and runtime dir
    /// `dir`, on the LAN whose gateway is `gateway`.
    pub(crate) fn of(
        svc: &crate::units::Provisioned,
        unit: &crate::compose::Unit,
        dir: &Path,
        gateway: Ipv4Addr,
    ) -> Result<Provisioning> {
        let record = crate::winbuild::provisioning(&svc.ext4)?;
        let command = match &unit.source {
            crate::compose::Source::Bundle {
                command: Some(line),
                ..
            } => Some(line.clone()),
            _ => record.provision,
        };
        let mut env = vec![
            ("VK_HOSTNAME".to_string(), svc.hostname.clone()),
            ("VK_IP".to_string(), svc.addr.to_string()),
            ("VK_PREFIX".to_string(), svc.prefix.to_string()),
            ("VK_GATEWAY".to_string(), gateway.to_string()),
        ];
        env.extend(svc.config.env.iter().cloned());
        // The provisioning runs from a batch file, as `vk exec --env` does. Its variables and
        // command line are checked here, so a start that cannot run them fails before booting.
        if let Some((k, v)) = env.iter().find(|(k, v)| !crate::winexec::valid_var(k, v)) {
            bail!(
                "service {}: environment {k}={v:?}: a Windows guest's variables cannot hold \
                 quotes or newlines",
                svc.name
            );
        }
        if let Some(line) = &command {
            crate::winexec::check_line(line, record.workdir.as_deref())?;
        }
        Ok(Provisioning {
            name: svc.name.clone(),
            dir: dir.to_path_buf(),
            command,
            workdir: record.workdir,
            env,
        })
    }

    /// Wait for Windows to come up, then run the provisioning, restarting Windows as often as
    /// it asks. `running` says whether the guest is still up.
    pub(crate) fn run(&self, running: &mut dyn FnMut() -> bool) -> Result<()> {
        let socket = self.dir.join(GUEST_AGENT_SOCKET);
        let console = self.dir.join(crate::run::CONSOLE_LOG);
        let log_path = self.dir.join(PROVISION_LOG);
        let mut log = std::fs::File::create(&log_path)
            .with_context(|| format!("creating {}", log_path.display()))?;
        println!(
            "virtkit: service {}: waiting for Windows, then its provisioning (log {})",
            self.name,
            log_path.display()
        );
        let mut ga = crate::uefi::wait_started(&socket, &console, START_TIMEOUT, running)?;
        let Some(command) = &self.command else {
            return Ok(());
        };
        let mut restarts = 0;
        loop {
            let code = crate::winexec::exec_command_line(
                &mut ga,
                command,
                &self.env,
                self.workdir.as_deref(),
                false,
                &mut log,
            )?;
            match code {
                0 => return Ok(()),
                3010 | crate::winexec::RESTART_INITIATED if restarts < MAX_RESTARTS => {
                    restarts += 1;
                    writeln!(log, "virtkit: exit {code}: restarting Windows")?;
                    crate::winexec::restart(&mut ga, code, running)?;
                    ga = crate::uefi::wait_started(&socket, &console, START_TIMEOUT, running)
                        .context("Windows did not come back after the restart")?;
                }
                3010 | crate::winexec::RESTART_INITIATED => bail!(
                    "service {}: its provisioning still asks for a restart after {MAX_RESTARTS}",
                    self.name
                ),
                code => bail!(
                    "service {}: its provisioning exited {code}\n{}",
                    self.name,
                    crate::run::tail(&log_path, 20)
                ),
            }
        }
    }
}

/// Stop the Windows service `name` whose VMM is `child` and runtime dir `dir` as `vk stop` stops a
/// UEFI guest, killing it past [`STOP_GRACE`], and reap it; `false` if it had to be killed.
pub(crate) fn stop(name: &str, child: &mut Child, dir: &Path) -> bool {
    let off = match crate::uefi::power_off_blocking(child, dir, STOP_GRACE) {
        Ok(off) => off.is_some(),
        Err(e) => {
            eprintln!("virtkit: stopping {name}: {e:#}");
            false
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    off
}

/// Restart the Windows guest behind the qemu-ga socket in `dir` in place; `false` when its
/// agent does not answer.
pub(crate) fn reboot(dir: &Path) -> bool {
    crate::qga::Client::connect(&dir.join(GUEST_AGENT_SOCKET), Duration::from_secs(5))
        .and_then(|mut ga| ga.exec("shutdown.exe", &["/r", "/t", "0"].map(String::from), false))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The provisioning of the service `dc` that `compose` declares over a bundle whose image's
    /// `CMD` is `cmd /c image.cmd`.
    fn provisioning_of(compose: &str) -> Result<Provisioning> {
        let base = std::env::temp_dir().join(format!("vk-winsvc-{}", std::process::id()));
        let bundle = base.join(format!("win-{}", crate::scratch::random_nonce().unwrap()));
        std::fs::create_dir_all(&bundle).unwrap();
        std::fs::write(bundle.join(crate::uefi::MANIFEST), "{}").unwrap();
        let record = serde_json::json!({
            "version": 1,
            "key": "c".repeat(64),
            "shell": [],
            "env": [],
            "workdir": r"C:\vk",
            "provision": "cmd /c image.cmd",
        });
        std::fs::write(bundle.join("layer.json"), record.to_string()).unwrap();
        let yaml = format!(
            "services:\n  dc:\n    image: ./{}\n{compose}",
            bundle.file_name().unwrap().to_str().unwrap()
        );
        let parsed = crate::compose::parse(&yaml, &base, &|_| None, None);
        let provisioning = parsed.and_then(|units| {
            let unit = &units[0];
            let svc = crate::units::provisioned(
                unit,
                bundle.clone(),
                crate::compose::merged_config(&Default::default(), unit),
                crate::units::Siting {
                    gateway: Ipv4Addr::new(192, 168, 127, 1),
                    prefix: 24,
                    slot: 0,
                    extra_ips: Vec::new(),
                },
            )?;
            Provisioning::of(
                &svc,
                unit,
                Path::new("/run/dc"),
                Ipv4Addr::new(192, 168, 127, 1),
            )
        });
        let _ = std::fs::remove_dir_all(&bundle);
        provisioning
    }

    #[test]
    fn a_provisioning_runs_the_image_cmd_with_the_vk_variables_first() {
        let p = provisioning_of("    environment:\n      DOMAIN: corp\n").unwrap();
        assert_eq!(p.command.as_deref(), Some("cmd /c image.cmd"));
        assert_eq!(p.workdir.as_deref(), Some(r"C:\vk"));
        let names: Vec<_> = p.env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            ["VK_HOSTNAME", "VK_IP", "VK_PREFIX", "VK_GATEWAY", "DOMAIN"]
        );
        assert_eq!(p.env[0].1, "dc");
        assert_eq!(p.env[3].1, "192.168.127.1");
    }

    #[test]
    fn the_service_environment_comes_after_the_vk_variables_and_its_command_replaces_cmd() {
        let p = provisioning_of(
            "    command: powershell -File C:\\vk\\dc.ps1\n    environment:\n      VK_HOSTNAME: other\n",
        )
        .unwrap();
        assert_eq!(p.command.as_deref(), Some(r"powershell -File C:\vk\dc.ps1"));
        // The batch file sets them in order: the service's value wins.
        let hostnames: Vec<_> = p
            .env
            .iter()
            .filter(|(k, _)| k == "VK_HOSTNAME")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(hostnames, ["dc", "other"]);
    }

    #[test]
    fn a_variable_a_batch_file_cannot_carry_is_refused_before_booting() {
        let Err(err) = provisioning_of("    environment:\n      PASS: 'a\"b'\n") else {
            panic!("a quote in a variable is refused");
        };
        assert!(format!("{err:#}").contains("cannot hold quotes"), "{err:#}");
    }
}
