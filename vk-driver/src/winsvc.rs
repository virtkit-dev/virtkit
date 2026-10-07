//! Windows compose services: a unit whose `image:` is a bundle directory — what `vk build`
//! makes of a Windows Dockerfile — boots as a UEFI guest on the run's LAN instead of a Linux
//! microVM.
//!
//! Every start boots fresh overlays over the bundle's disks, with a new VM generation ID: a
//! restart is a new machine, as a Linux service's throwaway root is. The NIC's MAC derives from
//! the unit's address, so the switch's DHCP reservation hands Windows that address, with the
//! gateway as its resolver (which answers the other services' names). A service on a tap
//! (`x-virtkit.tap`) has it as its first NIC instead, the switch port leased without a route;
//! its static address, if any, and the run's names in its hosts file are set over qemu-ga
//! before its provisioning ([`crate::wintap`]).
//!
//! The service is up once its provisioning has run: the compose `command:`, else the image's
//! `CMD` (kept in the bundle's `layer.json`), run through qemu-ga as SYSTEM with `VK_HOSTNAME`,
//! `VK_IP`, `VK_PREFIX` and `VK_GATEWAY` ahead of the service's environment. It runs at every
//! start, so it must be safe to run again; its exit code 3010 or 1641 restarts Windows and runs
//! it once more, up to [`MAX_RESTARTS`] times.
//!
//! A service started from its snapshot (`vk run --compose --from-snapshot`) resumes instead of
//! booting, provisioned already: it is up once its qemu-ga answers, and its clock is then set.

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::uefi::{Bundle, GUEST_AGENT_SOCKET};

/// How long Windows has to come up — a generalized image's first boot runs specialize and
/// OOBE — at the start and after each restart its provisioning asks for. Generous: on a
/// loaded host a nested Windows 11 can take most of 15 minutes per boot, and a guest that
/// powers off is noticed within half a minute anyway.
pub(crate) const START_TIMEOUT: Duration = Duration::from_secs(45 * 60);

/// How long a guest restored from its snapshot has for its agent to answer: it resumes
/// where it was rather than boots.
const RESUME_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How long a Windows service has to power off before it is killed: a domain controller can
/// take minutes to shut down.
pub(crate) const STOP_GRACE: Duration = Duration::from_secs(3 * 60);

/// How many restarts one start's provisioning may ask for.
const MAX_RESTARTS: u32 = 4;

/// Where a Windows service reads its compose secrets, as Docker puts them on Windows.
pub(crate) const SECRETS_DIR: &str = r"C:\ProgramData\Docker\secrets";

/// The provisioning's output, in the unit's runtime dir.
pub(crate) const PROVISION_LOG: &str = "provision.log";

/// The unit's address on its run's LAN, in its runtime dir: what `vk snapshot --run-dir`
/// records, so a restore can check it gets the same one.
pub(crate) const ADDRESS: &str = "address";

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
    // Every start, restarts included: the tap may have gone or been taken since the last.
    if let Some(tap) = &svc.tap {
        crate::net::probe_tap(&tap.tap).with_context(|| format!("service {}", svc.name))?;
    }
    let disks = new_machine(dir, &bundle)?;
    let cpus = svc.cpus.or(bundle.manifest.cpus).unwrap_or(DEFAULT_CPUS);
    let mem = svc
        .mem
        .clone()
        .or_else(|| bundle.manifest.mem.clone())
        .unwrap_or_else(|| DEFAULT_MEM.to_string());
    crate::uefi::check_restore(
        &bundle.manifest,
        svc.cpus,
        svc.mem.as_deref(),
        Some(svc.addr),
        svc.tap.as_ref(),
    )
    .with_context(|| format!("service {}", svc.name))?;
    crate::uefi::record_tap(dir, svc.tap.as_ref())?;
    let address = dir.join(ADDRESS);
    std::fs::write(&address, svc.addr.to_string())
        .with_context(|| format!("writing {}", address.display()))?;
    let firmware = crate::uefi::firmware()?;
    // A snapshot (`vk run --compose --from-snapshot`) resumes instead of booting.
    let restore = bundle
        .manifest
        .snapshot
        .as_ref()
        .map(|_| bundle.dir.as_path());
    let mut spec =
        crate::uefi::guest_spec(&firmware.path, dir, &svc.name, disks, cpus, &mem, restore)?;
    spec.tpm_state = crate::uefi::tpm_state(dir, &bundle.manifest);
    // A tap is the first NIC, the switch port the next, which the switch leases without a route.
    spec.net = crate::uefi::tap_net(svc.tap.as_ref());
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

/// Start a new machine every start: remove the previous overlays, generation ID, UUID, UEFI
/// variables and TPM state from `dir`, then recreate the overlays and variable store from
/// `bundle`.
fn new_machine(dir: &Path, bundle: &Bundle) -> Result<Vec<crate::vmm::Disk>> {
    crate::uefi::remove_files(dir, [crate::uefi::GENERATION_ID, crate::uefi::SYSTEM_UUID])?;
    crate::uefi::machine_files(dir, bundle, true)
}

/// What one start's provisioning runs, gathered so it can run without the units lock.
pub(crate) struct Provisioning {
    pub name: String,
    pub dir: PathBuf,
    /// the compose `command:`, else the image's `CMD`; `None`: nothing to run
    pub command: Option<String>,
    pub workdir: Option<String>,
    pub env: Vec<(String, String)>,
    /// copied into [`SECRETS_DIR`] before the provisioning runs
    pub secrets: Vec<crate::compose::Secret>,
    /// The service resumes from a snapshot, provisioned already: only its clock is set.
    pub restored: bool,
    /// Its first NIC's tap, configured before provisioning ([`crate::wintap`]), and the
    /// run's names (name, ip) pinned in its hosts file because the tap LAN's resolver
    /// does not know them.
    pub tap: Option<crate::net::TapNet>,
    pub tap_hosts: Vec<(String, String)>,
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
        crate::winbuild::warn_evaluation(&svc.ext4, &format!("service {}", svc.name));
        let restored = matches!(
            unit.source,
            crate::compose::Source::Bundle { snapshot: true, .. }
        );
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
            secrets: unit.secrets.clone(),
            restored,
            tap: svc.tap.clone(),
            tap_hosts: svc.tap_hosts.clone(),
        })
    }

    /// Wait for Windows to come up, then run the provisioning, restarting Windows as often as
    /// it asks. `running` says whether the guest is still up.
    pub(crate) fn run(&self, running: &mut dyn FnMut() -> bool) -> Result<()> {
        let socket = self.dir.join(GUEST_AGENT_SOCKET);
        let console = self.dir.join(crate::run::CONSOLE_LOG);
        let log_path = self.dir.join(PROVISION_LOG);
        let label = format!("service {}", self.name);
        let mut log = std::fs::File::create(&log_path)
            .with_context(|| format!("creating {}", log_path.display()))?;
        if self.restored {
            println!("virtkit: service {}: resuming from its snapshot", self.name);
            // Its setup finished before the snapshot: its agent answering is enough.
            let mut ga =
                crate::qga::Client::connect_while(&socket, RESUME_TIMEOUT, &label, running)
                    .context("the restored guest's agent did not answer")?;
            // It resumes at the time its snapshot was taken.
            if let Err(e) = crate::uefi::set_clock(&mut ga) {
                eprintln!(
                    "virtkit: service {}: warning: its clock is not set, so Kerberos may fail \
                     until it is: {e:#}",
                    self.name
                );
            }
            return Ok(());
        }
        println!(
            "virtkit: service {}: waiting for Windows, then its provisioning (log {})",
            self.name,
            log_path.display()
        );
        let mut ga = crate::uefi::wait_started(&socket, &console, START_TIMEOUT, &label, running)?;
        if let Some(tap) = &self.tap {
            crate::wintap::configure(&mut ga, tap, &self.tap_hosts)
                .with_context(|| format!("service {}", self.name))?;
        }
        self.put_secrets(&mut ga)?;
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
                    ga = crate::uefi::wait_started(
                        &socket,
                        &console,
                        START_TIMEOUT,
                        &label,
                        running,
                    )
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

    /// Copy the service's secrets into a fresh [`SECRETS_DIR`] that only SYSTEM and
    /// administrators can read or own. `C:\ProgramData` lets every user create in it and read
    /// what it holds, so whatever stands at that path (a directory a user made, or a junction
    /// to one) is removed first, and the new directory drops its inherited entries before any
    /// secret goes in; the files inherit the rest. Any step failing fails the start.
    fn put_secrets(&self, ga: &mut crate::qga::Client) -> Result<()> {
        use crate::winexec::{cmd, run_program};
        if self.secrets.is_empty() {
            return Ok(());
        }
        // `rd` may exit 0 having removed nothing; `mkdir` then fails on what is left.
        let code = cmd(
            ga,
            &["if", "exist", SECRETS_DIR, "rd", "/s", "/q", SECRETS_DIR],
        )?;
        if code != 0 {
            bail!("removing the old {SECRETS_DIR}: rd exited {code}");
        }
        let code = cmd(ga, &["mkdir", SECRETS_DIR])?;
        if code != 0 {
            bail!("mkdir {SECRETS_DIR} exited {code}");
        }
        // SIDs, not names, which Windows translates. `/setowner` is a form of its own.
        let restrict: [&[&str]; 2] = [
            &[
                SECRETS_DIR,
                "/inheritance:r",
                "/grant:r",
                "*S-1-5-18:(OI)(CI)F",
                "*S-1-5-32-544:(OI)(CI)F",
                "/Q",
            ],
            &[SECRETS_DIR, "/setowner", "*S-1-5-32-544", "/Q"],
        ];
        for args in restrict {
            let code = run_program(ga, "icacls.exe", args)?;
            if code != 0 {
                bail!(
                    "restricting {SECRETS_DIR} to SYSTEM and administrators: icacls exited {code}"
                );
            }
        }
        for secret in &self.secrets {
            let file = std::fs::File::open(&secret.file)
                .with_context(|| format!("reading {}", secret.file.display()))?;
            crate::winexec::write_from(ga, &format!(r"{SECRETS_DIR}\{}", secret.target), file)
                .with_context(|| format!("copying the secret {} in", secret.target))?;
        }
        Ok(())
    }
}

/// Stop the Windows service `name` whose VMM is `child` and runtime dir `dir` as `vk stop` stops a
/// UEFI guest, ending it past [`STOP_GRACE`] ([`crate::uefi::force_off`]), and reap it; `false`
/// if it had to be ended.
pub(crate) fn stop(name: &str, child: &mut Child, dir: &Path) -> bool {
    let off = match crate::uefi::power_off_blocking(child, dir, STOP_GRACE) {
        Ok(off) => off.is_some(),
        Err(e) => {
            eprintln!("virtkit: stopping {name}: {e:#}");
            false
        }
    };
    crate::uefi::force_off_blocking(child, dir);
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
    fn a_service_on_a_tap_takes_it_to_its_provisioning() {
        let p = provisioning_of(
            "    x-virtkit:\n      tap: { name: vktap0, mac: '52:54:00:00:00:01', \
             ip: 192.168.77.10/24, gw: 192.168.77.1, dns: [192.168.77.1] }\n",
        )
        .unwrap();
        let tap = p.tap.unwrap();
        assert_eq!(
            (tap.tap.as_str(), tap.mac.as_str()),
            ("vktap0", "52:54:00:00:00:01")
        );
        assert_eq!(
            tap.addr.unwrap().0,
            Ipv4Addr::new(192, 168, 77, 10),
            "its static address"
        );
        assert!(provisioning_of("").unwrap().tap.is_none());
    }

    #[test]
    fn a_variable_a_batch_file_cannot_carry_is_refused_before_booting() {
        let Err(err) = provisioning_of("    environment:\n      PASS: 'a\"b'\n") else {
            panic!("a quote in a variable is refused");
        };
        assert!(format!("{err:#}").contains("cannot hold quotes"), "{err:#}");
    }

    #[test]
    fn a_secret_reaches_the_provisioning_of_a_windows_service() {
        let base = std::env::temp_dir().join(format!("vk-winsvc-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::write(base.join("pw.txt"), "s3cret").unwrap();
        let p =
            provisioning_of("    secrets: [pw]\nsecrets:\n  pw:\n    file: ./pw.txt\n").unwrap();
        assert_eq!(
            p.secrets,
            [crate::compose::Secret {
                target: "pw".into(),
                file: base.join("./pw.txt"),
            }]
        );
    }

    /// Run [`Provisioning::put_secrets`] against an agent whose program exit codes come from
    /// `exit(command_line)`; return the result, command lines run and guest files opened.
    fn put_secrets_with(
        exit: impl Fn(&str) -> i32 + Send + 'static,
    ) -> (Result<()>, Vec<String>, Vec<String>) {
        use crate::qga::tests::{client, synced};
        use std::sync::{Arc, Mutex};
        let dir = std::env::temp_dir().join(format!(
            "vk-winsvc-put-{}",
            crate::scratch::random_nonce().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("pw.txt"), "s3cret").unwrap();
        let runs = Arc::new(Mutex::new(Vec::new()));
        let opened = Arc::new(Mutex::new(Vec::new()));
        let (seen_runs, seen_opened) = (runs.clone(), opened.clone());
        let mut ga = client(move |request| {
            let args = &request["arguments"];
            let reply = match request["execute"].as_str() {
                Some("guest-sync-delimited") => return synced(request),
                Some("guest-exec") => {
                    let mut line = vec![args["path"].as_str().unwrap().to_string()];
                    line.extend(
                        args["arg"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|a| a.as_str().unwrap().to_string()),
                    );
                    let mut runs = seen_runs.lock().unwrap();
                    runs.push(line.join(" "));
                    serde_json::json!({ "pid": runs.len() })
                }
                Some("guest-exec-status") => {
                    let line =
                        &seen_runs.lock().unwrap()[args["pid"].as_u64().unwrap() as usize - 1];
                    serde_json::json!({ "exited": true, "exitcode": exit(line) })
                }
                Some("guest-file-open") => {
                    let path = args["path"].as_str().unwrap().to_string();
                    seen_opened.lock().unwrap().push(path);
                    serde_json::json!(1)
                }
                Some("guest-file-write") => serde_json::json!({ "count": 6, "eof": false }),
                _ => serde_json::json!({}),
            };
            format!("{}\n", serde_json::json!({ "return": reply })).into_bytes()
        });
        let p = Provisioning {
            name: "dc".into(),
            dir: dir.clone(),
            command: None,
            workdir: None,
            env: Vec::new(),
            secrets: vec![crate::compose::Secret {
                target: "join".into(),
                file: dir.join("pw.txt"),
            }],
            restored: false,
            tap: None,
            tap_hosts: Vec::new(),
        };
        let result = p.put_secrets(&mut ga);
        let _ = std::fs::remove_dir_all(&dir);
        let runs = runs.lock().unwrap().clone();
        let opened = opened.lock().unwrap().clone();
        (result, runs, opened)
    }

    #[test]
    fn secrets_go_into_a_fresh_directory_only_system_and_administrators_can_read() {
        let (result, runs, opened) = put_secrets_with(|_| 0);
        result.unwrap();
        let dir = SECRETS_DIR;
        assert_eq!(
            runs,
            [
                format!("cmd.exe /d /v:off /c if exist {dir} rd /s /q {dir}"),
                format!("cmd.exe /d /v:off /c mkdir {dir}"),
                format!(
                    "icacls.exe {dir} /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F \
                     *S-1-5-32-544:(OI)(CI)F /Q"
                ),
                format!("icacls.exe {dir} /setowner *S-1-5-32-544 /Q"),
            ]
        );
        assert_eq!(opened, [format!(r"{dir}\join")]);
    }

    #[test]
    fn no_secret_is_copied_unless_every_step_succeeds() {
        for failing in [" rd ", "mkdir", "/grant:r", "/setowner"] {
            let fail = move |line: &str| i32::from(line.contains(failing));
            let (result, _, opened) = put_secrets_with(fail);
            assert!(result.is_err(), "{failing}");
            assert!(opened.is_empty(), "{failing}");
        }
    }

    #[test]
    fn a_new_start_drops_the_last_machines_variable_store_and_ids() {
        let base = std::env::temp_dir().join(format!(
            "vk-winsvc-new-{}",
            crate::scratch::random_nonce().unwrap()
        ));
        let (img, dir) = (base.join("img"), base.join("run"));
        std::fs::create_dir_all(&img).unwrap();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            img.join(crate::uefi::MANIFEST),
            r#"{"firmware": "uefi", "disks": ["d"]}"#,
        )
        .unwrap();
        std::fs::write(img.join("d"), vec![0u8; 1 << 20]).unwrap();
        for kept in [
            crate::uefi::UEFI_VARS,
            crate::uefi::GENERATION_ID,
            crate::uefi::SYSTEM_UUID,
        ] {
            std::fs::write(dir.join(kept), "last start's").unwrap();
        }
        let disks = new_machine(&dir, &Bundle::open(&img).unwrap()).unwrap();
        assert_eq!(disks.len(), 1);
        // The bundle has no store of its own: the boot makes one from the empty template.
        assert!(!dir.join(crate::uefi::UEFI_VARS).exists());
        assert!(!dir.join(crate::uefi::GENERATION_ID).exists());
        assert!(!dir.join(crate::uefi::SYSTEM_UUID).exists());
        let _ = std::fs::remove_dir_all(base);
    }
}
