//! `vk run <bundle>`: boot a UEFI guest — an installed Windows disk — from a local bundle
//! directory instead of an OCI image.
//!
//! A bundle is a directory holding `vm.json` and the disks it names:
//!
//! ```json
//! {"firmware": "uefi", "cpus": 2, "mem": "4G", "disks": ["disk.qcow2"]}
//! ```
//!
//! The guest runs no vk-agent: the firmware is the boot payload (an ELF with a PVH entry,
//! which libkrun hands the memory map and ACPI tables), each disk is attached as a qcow2
//! overlay in the run's work dir so the bundle itself is never written, and `--net` puts the
//! guest on the run's switch, whose DHCP reserves the run address for the NIC's MAC. The run
//! lasts until the guest powers off; a stop presses the ACPI power button.

use std::path::{Path, PathBuf};
use std::process::Child;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::run::RunArgs;
use crate::vmm::{Disk, Net, VmSpec};

/// The bundle's machine description.
pub(crate) const MANIFEST: &str = "vm.json";

/// Overrides the UEFI firmware vk embeds: an edk2 OvmfPkg/CloudHv build (`CLOUDHV.fd`, an ELF
/// with a PVH entry point).
pub(crate) const FIRMWARE_ENV: &str = "VIRTKIT_UEFI_FIRMWARE";

/// The run directory's qemu-ga socket ([`crate::qga`]).
pub(crate) const GUEST_AGENT_SOCKET: &str = "qga.sock";

/// The run directory's VM generation ID, beside the disk overlays it belongs to.
const GENERATION_ID: &str = "vmgenid";

/// A VMM that exits within this long of its spawn failed to boot; past it, the guest is up
/// as far as a detached run's parent cares (Windows has no agent to answer earlier).
const BOOT_SETTLE: Duration = Duration::from_secs(3);

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Firmware {
    Uefi,
}

/// `vm.json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    pub firmware: Firmware,
    pub cpus: Option<u32>,
    pub mem: Option<String>,
    /// Disk images in attach order, relative to the bundle directory.
    pub disks: Vec<PathBuf>,
}

/// A bundle directory and its parsed manifest.
#[derive(Debug)]
pub(crate) struct Bundle {
    pub dir: PathBuf,
    pub manifest: Manifest,
}

impl Bundle {
    /// The bundle `image` names, if it is a directory holding a `vm.json`; `None` for
    /// anything else (an image reference goes on to the OCI path).
    pub fn detect(image: &str) -> Result<Option<Bundle>> {
        let dir = Path::new(image);
        let manifest = dir.join(MANIFEST);
        if !dir.is_dir() || !manifest.is_file() {
            return Ok(None);
        }
        let dir = std::fs::canonicalize(dir).with_context(|| format!("bundle {image}"))?;
        Ok(Some(Bundle {
            manifest: Self::parse(&manifest)?,
            dir,
        }))
    }

    fn parse(path: &Path) -> Result<Manifest> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let manifest: Manifest =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if manifest.disks.is_empty() {
            bail!(
                "{}: `disks` is empty; a UEFI guest boots from a disk",
                path.display()
            );
        }
        Ok(manifest)
    }

    /// The bundle's disks as absolute paths, each checked to exist.
    fn disks(&self) -> Result<Vec<PathBuf>> {
        self.manifest
            .disks
            .iter()
            .map(|disk| {
                let path = self.dir.join(disk);
                if !path.is_file() {
                    bail!("bundle disk {} not found", path.display());
                }
                Ok(path)
            })
            .collect()
    }

    /// The name the VM goes by: the bundle directory's.
    fn name(&self) -> String {
        self.dir
            .file_name()
            .map_or_else(|| "uefi".to_string(), |n| n.to_string_lossy().into_owned())
    }
}

/// The firmware image to boot: [`FIRMWARE_ENV`], else the copy embedded in `vk` (a memfd the
/// VMM inherits, held open by the returned [`crate::embed::Resolved`]), else the on-disk
/// default.
fn firmware() -> Result<crate::embed::Resolved> {
    let explicit = std::env::var_os(FIRMWARE_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    let firmware = crate::embed::resolve(crate::embed::Asset::Firmware, explicit.as_deref())?;
    if !firmware.is_embedded() && !firmware.path.is_file() {
        bail!(
            "UEFI firmware not found at {} (set {FIRMWARE_ENV}, or use a `vk` with it embedded)",
            firmware.path.display()
        );
    }
    Ok(firmware)
}

/// One overlay per bundle disk in `work`, reused when it is already there (a `--state-dir`
/// run picks up the guest's disk where the last one left it) and over the same disk.
fn overlays(disks: &[PathBuf], work: &Path) -> Result<Vec<Disk>> {
    disks
        .iter()
        .enumerate()
        .map(|(i, base)| {
            let overlay = work.join(format!("disk{i}.qcow2"));
            if overlay.exists() {
                let kept = crate::qcow2::Qcow2::open(&overlay)
                    .with_context(|| format!("opening {}", overlay.display()))?;
                if kept.backing_path() != Some(base.as_path()) {
                    bail!(
                        "{} is an overlay over {}, not {}: this run directory holds another \
                         bundle's disks",
                        overlay.display(),
                        kept.backing_path()
                            .unwrap_or(Path::new("nothing"))
                            .display(),
                        base.display()
                    );
                }
            } else {
                // Whole or not at all: a torn overlay would otherwise be reused for good.
                let tmp = overlay.with_extension("qcow2.tmp");
                crate::qcow2::create_overlay(&tmp, base)
                    .with_context(|| format!("creating an overlay over {}", base.display()))?;
                std::fs::rename(&tmp, &overlay)
                    .with_context(|| format!("renaming into {}", overlay.display()))?;
            }
            Ok(Disk::overlay(overlay))
        })
        .collect()
}

/// The `vk run` flags a bundle run cannot honour: its guest runs no vk-agent, so nothing
/// takes a command, a share, an environment or an SSH server into it, and the bundle path
/// wires no egress audit, registry proxy or inactivity watch.
fn refuse_unsupported(args: &RunArgs) -> Result<()> {
    let unsupported = [
        (!args.command.is_empty(), "a command"),
        (!args.dockerfiles.is_empty(), "--file"),
        (args.compose.is_some(), "--compose"),
        (args.workdir.is_some(), "--workdir"),
        (!args.volumes.is_empty(), "--volume"),
        (!args.symlinks.is_empty(), "--symlink"),
        (!args.extra_disks.is_empty(), "--disk"),
        (!args.env.is_empty(), "--env/--env-file"),
        (args.shell, "--shell"),
        (args.tty, "--tty"),
        (args.ssh, "--ssh"),
        (args.ssh_agent, "--ssh-agent"),
        (args.host_exec, "--host-exec"),
        (args.atop.is_some(), "--atop"),
        (args.nics.is_some(), "--nics"),
        (args.audit_egress, "--audit-egress"),
        (args.registry_proxy.is_some(), "--registry-proxy"),
        (
            args.inactivity_timeout_secs.is_some(),
            "--inactivity-timeout",
        ),
    ];
    let set: Vec<&str> = unsupported
        .iter()
        .filter(|(set, _)| *set)
        .map(|(_, flag)| *flag)
        .collect();
    if !set.is_empty() {
        bail!("a UEFI bundle run cannot honour {}", set.join(", "));
    }
    Ok(())
}

/// The VM generation ID for the disks in `work`: created on first boot, kept across boots,
/// new for fresh overlays (a copy of the bundle's disk). Only a missing ID is created;
/// an unreadable or malformed ID is an error, since a silently changed ID makes a
/// Windows domain controller reset its invocation ID and RID pool.
fn generation_id(work: &Path) -> Result<[u8; 16]> {
    use std::io::Read;

    let path = work.join(GENERATION_ID);
    match std::fs::read(&path) {
        Ok(bytes) => {
            return <[u8; 16]>::try_from(bytes.as_slice())
                .map_err(|_| anyhow::anyhow!("{}: {} bytes, not 16", path.display(), bytes.len()));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    }
    let mut id = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut id))
        .context("reading /dev/urandom")?;
    // Whole or not at all: a torn file would be replaced, changing the ID.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, id).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming into {}", path.display()))?;
    Ok(id)
}

/// Boot `bundle` and hold it until the guest powers off or the run is stopped.
pub(crate) async fn run(args: &RunArgs, work: &Path, bundle: Bundle) -> Result<()> {
    refuse_unsupported(args)?;
    let firmware = match bundle.manifest.firmware {
        Firmware::Uefi => firmware()?,
    };
    let disks = overlays(&bundle.disks()?, work)?;
    let name = bundle.name();
    let cpus = args.cpus.or(bundle.manifest.cpus).unwrap_or(2);
    let mem = args
        .mem
        .clone()
        .or_else(|| bundle.manifest.mem.clone())
        .unwrap_or_else(|| "4G".to_string());
    let console = work.join(crate::run::CONSOLE_LOG);
    let vsock = work.join("vsock.sock");

    // The run answers the terminal's Ctrl-C with the power button ([`hold`]), so its VMM and
    // switch must not take the same SIGINT and die first.
    crate::spawn::isolate_helpers();
    let mut switch = None;
    let mut nics = Vec::new();
    let mut guest_ip = None;
    if args.net {
        let (child, attach) = crate::run::spawn_vm_switch(
            &vsock,
            work,
            crate::run::NET_VSOCK_PORT,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
            None,
            Some(work.join(crate::run::NET_BYTES)),
            false,
            None,
            crate::prio::Prio::Normal,
        )
        .await?;
        switch = Some(child);
        nics = attach.nics;
        guest_ip = Some(crate::net::switch_addrs(crate::run::RUN_SUBNET)?.2);
    }

    let spec = VmSpec {
        kernel: firmware.path.clone(),
        cmdline: String::new(),
        disks,
        initramfs: None,
        shares: Vec::new(),
        vsock_ports: Vec::new(),
        cpus,
        mem: mem.clone(),
        net: Net::None,
        nics,
        // Windows has no balloon driver unless the image installs one.
        balloon: false,
        serial_log: console.clone(),
        // The firmware and Windows' EMS console write COM1.
        console_serial: true,
        pmu: false,
        nested: false,
        pass_fds: Vec::new(),
        proc_name: crate::vmm::resolve_proc_name(&name),
        reboot: true,
        numa: args.numa.clone(),
        guest_agent: Some(work.join(GUEST_AGENT_SOCKET)),
        hyperv: true,
        vm_generation_id: Some(generation_id(work)?),
    };
    let vmm = crate::vmm::selected();
    let mut ch = match crate::run::spawn_vmm(vmm.as_ref(), &spec, crate::prio::Prio::Normal) {
        Ok(ch) => ch,
        Err(e) => {
            if let Some(child) = switch.take() {
                crate::run::stop_switch(child);
            }
            return Err(e);
        }
    };
    // `vk reboot` hard-resets the guest: there is no agent to ask.
    crate::run::forward_hard_resets(&ch);
    println!(
        "virtkit: {name}: UEFI guest booting ({cpus} vCPU, {mem}{}); console {}",
        guest_ip.map_or(String::new(), |ip| format!(", {ip}")),
        console.display()
    );

    let _registration = args.state_dir.as_ref().map(|_| {
        crate::vms::register(crate::vms::VmEntry {
            state_dir: crate::run::registry_key(work),
            project_dir: crate::run::project_dir(args),
            pid: std::process::id(),
            pid_start_ticks: crate::vms::own_start_ticks(),
            label: name.clone(),
            // No agent: nothing answers on an exec channel, so `vk reboot` hard-resets.
            exec_addr: String::new(),
            ssh_addr: None,
            atop_log: None,
            created_secs: crate::vms::unix_now(),
            vmm: Some(vmm.name().to_string()),
            vmm_pid: Some(ch.id()),
            cpus: Some(cpus),
            mem: Some(mem.clone()),
            nested: Some(false),
            guest_ip,
            stale_recipe: None,
            services: Vec::new(),
        })
    });

    let result = hold(&mut ch, &console, args.detach_log.as_deref()).await;
    if ch.try_wait().ok().flatten().is_none() {
        // Stopped: press the power button, then kill when the grace expires or on a second
        // Ctrl-C.
        let pressed = Instant::now();
        crate::shutdown::press_power_button(&ch);
        let deadline = pressed + crate::shutdown::STOP_GRACE;
        let powered_off = async {
            loop {
                // An unreadable status is taken as alive: the deadline bounds the wait.
                if ch.try_wait().ok().flatten().is_some() {
                    return true;
                }
                if Instant::now() >= deadline {
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        };
        tokio::select! {
            off = powered_off => match off {
                true => println!(
                    "virtkit: guest powered off ({:.0?} after the power button)",
                    pressed.elapsed()
                ),
                false => eprintln!(
                    "virtkit: guest still up {}s after the power button; killed",
                    crate::shutdown::STOP_GRACE.as_secs()
                ),
            },
            _ = tokio::signal::ctrl_c() => eprintln!("virtkit: Ctrl-C again; guest killed"),
        }
        let _ = ch.kill();
    }
    let _ = ch.wait();
    if let Some(child) = switch.take() {
        crate::run::stop_switch(child);
    }
    result
}

/// Wait for the VMM to exit or the run to be stopped. A VMM gone within [`BOOT_SETTLE`] is a
/// failed boot; past it, a detached run hands the terminal back.
async fn hold(ch: &mut Child, console: &Path, detach_log: Option<&Path>) -> Result<()> {
    let spawned = Instant::now();
    let mut ready = false;
    // Handle foreground Ctrl-C too: isolated helpers leave it to this process alone.
    // The default would end the run immediately, skipping the wait for power-off.
    let stop = async {
        tokio::select! {
            _ = crate::shutdown::terminate_signal() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    tokio::pin!(stop);
    loop {
        if let Some(status) = ch.try_wait().context("waiting for the VMM")? {
            if !ready {
                bail!("{}", crate::run::boot_failure(console, status));
            }
            if !status.success() {
                bail!("the VMM exited with {status}");
            }
            println!("virtkit: guest powered off");
            return Ok(());
        }
        if !ready && spawned.elapsed() >= BOOT_SETTLE {
            ready = true;
            crate::detach::signal_ready(detach_log);
        }
        tokio::select! {
            () = &mut stop => {
                println!("virtkit: stopping ... (ACPI power button)");
                return Ok(());
            }
            () = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh scratch directory for one test, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Scratch {
            let dir = std::env::temp_dir().join(format!("vk-uefi-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_directory_with_vm_json_is_a_bundle_and_anything_else_is_not() {
        let tmp = Scratch::new("detect");
        let dir = tmp.path().join("ws2025");
        std::fs::create_dir(&dir).unwrap();
        assert!(Bundle::detect(dir.to_str().unwrap()).unwrap().is_none());
        assert!(Bundle::detect("alpine:3.20").unwrap().is_none());
        assert!(Bundle::detect("").unwrap().is_none());

        std::fs::write(
            dir.join(MANIFEST),
            r#"{"firmware": "uefi", "cpus": 4, "mem": "6G", "disks": ["disk.qcow2"]}"#,
        )
        .unwrap();
        let bundle = Bundle::detect(dir.to_str().unwrap()).unwrap().unwrap();
        assert_eq!(bundle.manifest.firmware, Firmware::Uefi);
        assert_eq!(bundle.manifest.cpus, Some(4));
        assert_eq!(bundle.manifest.mem.as_deref(), Some("6G"));
        assert_eq!(bundle.name(), "ws2025");
        assert!(bundle.disks().is_err(), "the named disk does not exist");
        std::fs::write(dir.join("disk.qcow2"), b"").unwrap();
        assert_eq!(bundle.disks().unwrap(), vec![bundle.dir.join("disk.qcow2")]);
    }

    #[test]
    fn a_manifest_without_disks_or_with_another_firmware_is_refused() {
        let tmp = Scratch::new("refuse");
        for (body, why) in [
            (r#"{"firmware": "uefi", "disks": []}"#, "empty"),
            (r#"{"firmware": "bios", "disks": ["d"]}"#, "unknown variant"),
            (
                r#"{"firmware": "uefi", "disks": ["d"], "gpu": true}"#,
                "unknown field",
            ),
        ] {
            std::fs::write(tmp.path().join(MANIFEST), body).unwrap();
            let err = Bundle::detect(tmp.path().to_str().unwrap()).unwrap_err();
            assert!(format!("{err:#}").contains(why), "{body}: {err:#}");
        }
    }

    #[test]
    fn a_bundle_run_refuses_the_flags_it_cannot_honour() {
        assert!(refuse_unsupported(&RunArgs::default()).is_ok());
        let args = RunArgs {
            command: vec!["true".into()],
            ssh: true,
            audit_egress: true,
            registry_proxy: Some("10.0.2.2:5000".into()),
            inactivity_timeout_secs: Some(60),
            ..Default::default()
        };
        let err = refuse_unsupported(&args).unwrap_err().to_string();
        assert!(
            err.contains(
                "honour a command, --ssh, --audit-egress, --registry-proxy, --inactivity-timeout"
            ),
            "{err}"
        );
    }

    #[test]
    fn the_generation_id_is_made_once_per_run_directory() {
        let a = Scratch::new("genid-a");
        let b = Scratch::new("genid-b");
        let first = generation_id(a.path()).unwrap();
        assert_eq!(generation_id(a.path()).unwrap(), first);
        assert_ne!(generation_id(b.path()).unwrap(), first);
    }

    #[test]
    fn a_malformed_generation_id_is_an_error_not_replaced() {
        let work = Scratch::new("genid-bad");
        let path = work.path().join(GENERATION_ID);
        std::fs::write(&path, [0u8; 15]).unwrap();
        let err = generation_id(work.path()).unwrap_err();
        assert!(err.to_string().contains("15 bytes"), "{err:#}");
        assert_eq!(std::fs::read(&path).unwrap(), [0u8; 15]);
    }

    #[test]
    fn overlays_are_made_once_and_reused_over_the_same_disk_only() {
        use std::io::Write;
        let tmp = Scratch::new("overlays");
        let base = tmp.path().join("base.raw");
        std::fs::write(&base, vec![0u8; 1 << 20]).unwrap();
        let work = tmp.path().join("work");
        std::fs::create_dir(&work).unwrap();
        let disks = overlays(std::slice::from_ref(&base), &work).unwrap();
        assert_eq!(disks.len(), 1);
        assert_eq!(disks[0].path, work.join("disk0.qcow2"));
        assert!(!work.join("disk0.qcow2.tmp").exists());
        // A marker past the overlay's metadata stands for the guest's writes: a second run
        // over the same work dir keeps them.
        let marker = b"guest wrote this";
        std::fs::OpenOptions::new()
            .append(true)
            .open(&disks[0].path)
            .unwrap()
            .write_all(marker)
            .unwrap();
        overlays(std::slice::from_ref(&base), &work).unwrap();
        assert!(std::fs::read(&disks[0].path).unwrap().ends_with(marker));

        // Another bundle's disk is refused rather than booted from this one's overlay.
        let other = tmp.path().join("other.raw");
        std::fs::write(&other, vec![0u8; 1 << 20]).unwrap();
        let Err(err) = overlays(std::slice::from_ref(&other), &work) else {
            panic!("an overlay over another disk was reused");
        };
        assert!(format!("{err:#}").contains("another bundle"), "{err:#}");
    }
}
