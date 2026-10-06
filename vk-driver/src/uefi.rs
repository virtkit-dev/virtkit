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

use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};
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

/// The run directory's socket for COM1's input (`vk console`).
pub(crate) const CONSOLE_SOCKET: &str = "console.sock";

/// The run directory's socket for VM control (pause, resume): [`crate::vmmctl`].
pub(crate) const CONTROL_SOCKET: &str = "vmm.sock";

/// The run directory's VM generation ID, beside the disk overlays it belongs to.
pub(crate) const GENERATION_ID: &str = "vmgenid";
/// The SMBIOS system UUID of a run directory's disks, kept as the generation ID is.
pub(crate) const SYSTEM_UUID: &str = "system-uuid";
/// The UEFI variable store of a run directory's disks (the firmware's flash), kept with them.
pub(crate) const UEFI_VARS: &str = "uefi-vars.fd";
/// The firmware's variable store flash length. Every store vk boots, including templates and
/// bundle stores, must match this length for the firmware's flash layout.
const UEFI_VARS_LEN: u64 = 0x84000;
/// The machine's permanent TPM state, kept in its run directory beside its disks.
pub(crate) const TPM_STATE: &str = "tpm-state";

/// How long a guest has to answer the ACPI power button before vk asks its qemu-ga to shut it
/// down instead (a Windows guest can be set to ignore the button).
const BUTTON_GRACE: Duration = Duration::from_secs(20);

/// How long a build guest has to power off before it is killed.
const BUILD_STOP_GRACE: Duration = Duration::from_secs(10 * 60);

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
    /// The machine's UEFI variable store (boot entries, Secure Boot keys), relative to the
    /// bundle directory; a run starts from a copy. None: the firmware's empty store.
    #[serde(default)]
    pub uefi_vars: Option<PathBuf>,
    /// The machine starts with Microsoft's Secure Boot keys enrolled (when the bundle has no
    /// variable store of its own).
    #[serde(default)]
    pub secure_boot: bool,
    /// The machine's TPM 2.0 (`# vk: tpm=on`), with state in the run directory
    /// ([`TPM_STATE`]). Each machine gets a new TPM; snapshot restore uses the saved state,
    /// which libkrun writes there.
    #[serde(default)]
    pub tpm: bool,
    /// Set for a snapshot (`vk snapshot`): the bundle also holds the VM's state and memory,
    /// which a run starts from instead of booting.
    #[serde(default)]
    pub snapshot: Option<SnapshotInfo>,
}

/// What a snapshot bundle's run must match: the VM it was taken of.
#[derive(Debug, Clone, Copy, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotInfo {
    /// The VM's address on its run's network, which its NIC's MAC derives from and the guest
    /// keeps using; None: it had no network.
    pub addr: Option<Ipv4Addr>,
}

/// Refuse to restore the snapshot `manifest` describes (if it is one) with other vCPUs `cpus`,
/// memory `mem` or address `addr` than it was taken with: its saved CPU, memory and NIC state
/// fit only those. `cpus` and `mem` are overrides (None: the manifest's); `addr` is the
/// guest's address on its run's network (None: no network).
pub(crate) fn check_restore(
    manifest: &Manifest,
    cpus: Option<u32>,
    mem: Option<&str>,
    addr: Option<Ipv4Addr>,
) -> Result<()> {
    let Some(snapshot) = manifest.snapshot else {
        return Ok(());
    };
    match (snapshot.addr, addr) {
        (Some(_), None) => bail!("this snapshot was taken on a network: run it with --net"),
        (None, Some(_)) => bail!("this snapshot was taken without a network: run it without --net"),
        (Some(taken), Some(addr)) if taken != addr => {
            bail!("this snapshot was taken at {taken}, not {addr}")
        }
        _ => {}
    }
    let mib = |mem: &str| crate::run::parse_mem_mib(mem);
    if cpus.is_some_and(|c| Some(c) != manifest.cpus)
        || mem.is_some_and(|m| mib(m) != manifest.mem.as_deref().and_then(mib))
    {
        bail!(
            "this snapshot runs only with the {} vCPUs and {} of memory it was taken with",
            manifest.cpus.map_or("?".to_string(), |c| c.to_string()),
            manifest.mem.as_deref().unwrap_or("?")
        );
    }
    Ok(())
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
        if !dir.is_dir() || !dir.join(MANIFEST).is_file() {
            return Ok(None);
        }
        Self::open(dir).map(Some)
    }

    /// The bundle at `dir`, a directory holding a `vm.json`.
    pub(crate) fn open(dir: &Path) -> Result<Bundle> {
        Ok(Bundle {
            manifest: Self::parse(&dir.join(MANIFEST))?,
            dir: std::fs::canonicalize(dir).with_context(|| format!("bundle {}", dir.display()))?,
        })
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

    /// The file `vm.json` names `relative`, in the bundle directory: a relative path without
    /// `..`, so a manifest names only files of its bundle.
    fn file(&self, relative: &Path) -> Result<PathBuf> {
        let inside = relative
            .components()
            .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
        if !inside || relative.as_os_str().is_empty() {
            bail!(
                "{}: {} is not a path inside the bundle",
                self.dir.join(MANIFEST).display(),
                relative.display()
            );
        }
        Ok(self.dir.join(relative))
    }

    /// The bundle's disks as absolute paths, each checked to exist.
    pub(crate) fn disks(&self) -> Result<Vec<PathBuf>> {
        self.manifest
            .disks
            .iter()
            .map(|disk| {
                let path = self.file(disk)?;
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
pub(crate) fn firmware() -> Result<crate::embed::Resolved> {
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
pub(crate) fn overlays(disks: &[PathBuf], work: &Path) -> Result<Vec<Disk>> {
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
        (args.tap.is_some(), "--tap"),
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

/// Prepare `bundle`'s disk overlays ([`overlays`]) and variable store ([`seed_uefi_vars`]) in
/// `work`. `fresh` first removes the previous overlays, store and TPM state to start from the
/// bundle (a TPM then starts new, or on a snapshot's state).
pub(crate) fn machine_files(work: &Path, bundle: &Bundle, fresh: bool) -> Result<Vec<Disk>> {
    let bundle_disks = bundle.disks()?;
    if fresh {
        let kept = (0..bundle_disks.len()).map(|i| format!("disk{i}.qcow2"));
        remove_files(
            work,
            kept.chain([UEFI_VARS.to_string(), TPM_STATE.to_string()]),
        )?;
    }
    let disks = overlays(&bundle_disks, work)?;
    seed_uefi_vars(work, bundle)?;
    Ok(disks)
}

/// Remove the files `names` from `dir`, ignoring missing files.
pub(crate) fn remove_files<N: AsRef<Path>>(
    dir: &Path,
    names: impl IntoIterator<Item = N>,
) -> Result<()> {
    for name in names {
        let path = dir.join(name);
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e).with_context(|| format!("removing {}", path.display()));
            }
            _ => {}
        }
    }
    Ok(())
}

/// The UEFI variable store of the disks in `work`, made on their first boot from the firmware's
/// empty template unless [`seed_uefi_vars`] gave them one, and kept with them. None when vk has
/// no template (built without one): the firmware then keeps its variables in RAM.
fn uefi_vars(work: &Path) -> Result<Option<PathBuf>> {
    let path = work.join(UEFI_VARS);
    if !path.exists() {
        let Some(template) = vars_template(crate::embed::Asset::UefiVars)? else {
            return Ok(None);
        };
        write_vars(&path, &template)?;
    }
    Ok(Some(path))
}

/// Seed the disks in `work` with `bundle`'s variable store unless they already have one. Copy
/// the bundle's store so it stays unchanged for the next machine; otherwise use Microsoft's
/// keys for a Secure Boot bundle.
pub(crate) fn seed_uefi_vars(work: &Path, bundle: &Bundle) -> Result<()> {
    let path = work.join(UEFI_VARS);
    if path.exists() {
        return Ok(());
    }
    if let Some(vars) = &bundle.manifest.uefi_vars {
        let from = bundle.file(vars)?;
        let bytes = std::fs::read(&from).with_context(|| format!("reading {}", from.display()))?;
        return write_vars(&path, &bytes).with_context(|| format!("copying {}", from.display()));
    }
    if bundle.manifest.secure_boot {
        seed_secure_boot(work)?;
    }
    Ok(())
}

/// Start the disks in `work` with Secure Boot on, unless they have a variable store already:
/// the store with Microsoft's keys (KEK, db) enrolled, so Windows and the drivers Microsoft
/// signs boot and anything else is refused. Experimental: an authenticated variable write at
/// the guest's run time (Windows' Secure Boot update task writing db or dbx) is known to
/// bug-check 0x1E in the firmware's runtime services. And without SMM it guards only the boot
/// chain below the guest's kernel: that kernel can rewrite the variable store directly,
/// replacing PK, KEK, db or dbx or turning Secure Boot off for good.
pub(crate) fn seed_secure_boot(work: &Path) -> Result<()> {
    let path = work.join(UEFI_VARS);
    if path.exists() {
        return Ok(());
    }
    let Some(template) = vars_template(crate::embed::Asset::UefiVarsSecureBoot)? else {
        bail!("this vk has no Secure Boot variable store (build-firmware.sh makes one)");
    };
    write_vars(&path, &template)
}

/// A variable store template's bytes: embedded in `vk`, else installed beside the firmware's
/// default path; None when neither is there.
fn vars_template(asset: crate::embed::Asset) -> Result<Option<Vec<u8>>> {
    if let Some(bytes) = asset.embedded() {
        return Ok(Some(bytes.to_vec()));
    }
    match std::fs::read(asset.default_path()) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", asset.default_path())),
    }
}

/// Write the variable store `bytes` as the new file `path`, whole or not at all.
fn write_vars(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 != UEFI_VARS_LEN {
        bail!(
            "a UEFI variable store of {} bytes, not {UEFI_VARS_LEN}",
            bytes.len()
        );
    }
    write_atomic(path, bytes)
}

/// Write `bytes` to `path` atomically and durably, readable only by its owner.
/// Sync the directory after renaming the file.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    vk_fs::write_atomic(path, bytes, 0o600)?;
    let dir = path.parent().context("a file in a directory")?;
    std::fs::File::open(dir)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("syncing {}", dir.display()))
}

/// Refuse the variable store `path` unless it is [`UEFI_VARS_LEN`] long.
fn check_vars_len(path: &Path) -> Result<()> {
    let len = std::fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .len();
    if len != UEFI_VARS_LEN {
        bail!(
            "{} is a UEFI variable store of {len} bytes, not {UEFI_VARS_LEN}",
            path.display()
        );
    }
    Ok(())
}

/// The VM generation ID for the disks in `work`: created on first boot, kept across boots,
/// new for fresh overlays (a copy of the bundle's disk). Only a missing ID is created;
/// an unreadable or malformed ID is an error, since a silently changed ID makes a
/// Windows domain controller reset its invocation ID and RID pool.
fn generation_id(work: &Path) -> Result<[u8; 16]> {
    read_or_create(&work.join(GENERATION_ID), random_id)
}

/// The SMBIOS system UUID of the disks in `work`, a random UUID kept as the generation ID is.
fn system_uuid(work: &Path) -> Result<[u8; 16]> {
    read_or_create(&work.join(SYSTEM_UUID), random_uuid_v4)
}

/// The system UUID in `snapshot`, kept by the restored guest and saved in `work` so later
/// snapshots keep it too.
fn restored_uuid(snapshot: &Path, work: &Path) -> Result<[u8; 16]> {
    let path = snapshot.join(SYSTEM_UUID);
    let uuid = read_id(&path)?.with_context(|| {
        format!(
            "{} is missing: the snapshot predates system UUIDs; take it again",
            path.display()
        )
    })?;
    write_id(&work.join(SYSTEM_UUID), &uuid)?;
    Ok(uuid)
}

/// The 16 bytes in `path`, or `fresh()` written there if it is missing. Only a missing file is
/// created: an unreadable or malformed one is an error.
fn read_or_create(path: &Path, fresh: impl FnOnce() -> Result<[u8; 16]>) -> Result<[u8; 16]> {
    if let Some(id) = read_id(path)? {
        return Ok(id);
    }
    let id = fresh()?;
    write_id(path, &id)?;
    Ok(id)
}

/// The 16 bytes in `path`; None if it is missing. An unreadable or malformed file is an error.
fn read_id(path: &Path) -> Result<Option<[u8; 16]>> {
    match std::fs::read(path) {
        Ok(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
            .map(Some)
            .map_err(|_| anyhow::anyhow!("{}: {} bytes, not 16", path.display(), bytes.len())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write `id` to `path` through a temporary file and a rename, so a crash never leaves a torn
/// ID, which would fail every later boot.
fn write_id(path: &Path, id: &[u8; 16]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, id).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming into {}", path.display()))
}

/// 16 random bytes.
fn random_id() -> Result<[u8; 16]> {
    use std::io::Read;

    let mut id = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut id))
        .context("reading /dev/urandom")?;
    Ok(id)
}

/// A random (version 4) UUID, in RFC 4122 byte order.
fn random_uuid_v4() -> Result<[u8; 16]> {
    let mut uuid = random_id()?;
    uuid[6] = uuid[6] & 0x0f | 0x40;
    uuid[8] = uuid[8] & 0x3f | 0x80;
    Ok(uuid)
}

/// The TPM state file in `work` for `manifest`, if the machine has a TPM.
/// Otherwise its [`guest_spec`] has none.
pub(crate) fn tpm_state(work: &Path, manifest: &Manifest) -> Option<PathBuf> {
    manifest.tpm.then(|| work.join(TPM_STATE))
}

/// The spec of a UEFI guest named `name` booting `firmware` on `disks`, its console log, qemu-ga
/// and COM1 input sockets and VM generation ID in `work`; no network. With `restore`, the guest
/// starts from the snapshot in that directory instead of booting, under a new VM generation ID
/// that `work` does not keep: it is a copy of the snapshotted guest, which it must not pass
/// for (a domain controller then resets its invocation ID and RID pool), and libkrun refuses
/// to restore a guest that had one without a new one. It keeps the snapshot's system UUID, and
/// the caller gives `work` the snapshot's variable store ([`seed_uefi_vars`]).
pub(crate) fn guest_spec(
    firmware: &Path,
    work: &Path,
    name: &str,
    disks: Vec<Disk>,
    cpus: u32,
    mem: &str,
    restore: Option<&Path>,
) -> Result<VmSpec> {
    let (vm_generation_id, system_uuid) = match restore {
        Some(snapshot) => (random_id()?, restored_uuid(snapshot, work)?),
        None => (generation_id(work)?, system_uuid(work)?),
    };
    // A restored guest has a variable store only if its snapshot's machine had one (which
    // [`seed_uefi_vars`] copied in place of `work`'s), as libkrun requires.
    let uefi_vars = match restore {
        Some(_) => Some(work.join(UEFI_VARS)).filter(|p| p.exists()),
        None => uefi_vars(work)?,
    };
    if let Some(vars) = &uefi_vars {
        check_vars_len(vars)?;
    }
    Ok(VmSpec {
        kernel: firmware.to_path_buf(),
        cmdline: String::new(),
        disks,
        initramfs: None,
        shares: Vec::new(),
        vsock_ports: Vec::new(),
        cpus,
        mem: mem.to_string(),
        net: Net::None,
        nics: Vec::new(),
        // Windows has no balloon driver unless the image installs one.
        balloon: false,
        serial_log: work.join(crate::run::CONSOLE_LOG),
        // The firmware and Windows' EMS console write COM1.
        console_serial: true,
        pmu: false,
        nested: false,
        pass_fds: Vec::new(),
        proc_name: crate::vmm::resolve_proc_name(name),
        reboot: true,
        numa: crate::numa::Numa::Auto,
        guest_agent: Some(work.join(GUEST_AGENT_SOCKET)),
        hyperv: true,
        vm_generation_id: Some(vm_generation_id),
        system_uuid: Some(system_uuid),
        uefi_vars,
        // A TPM only for a machine that asks for one ([`tpm_state`]).
        tpm_state: None,
        serial_input: Some(work.join(CONSOLE_SOCKET)),
        control: Some(work.join(CONTROL_SOCKET)),
        restore_from: restore.map(Path::to_path_buf),
    })
}

/// Stop the guest behind `ch`, with run directory `work`: press the ACPI power button, then
/// request qemu-ga shutdown after [`BUTTON_GRACE`]. Return the elapsed time since the button,
/// or `None` after `grace` if still running; the caller then kills it.
async fn power_off(ch: &mut Child, work: &Path, grace: Duration) -> Option<Duration> {
    let pressed = Instant::now();
    let deadline = pressed + grace;
    let socket = work.join(GUEST_AGENT_SOCKET);
    let button = crate::shutdown::press_power_button(ch);
    if button && exited_by(ch, pressed + BUTTON_GRACE).await {
        return Some(pressed.elapsed());
    }
    // Off the runtime: the agent's sync blocks for up to its timeout. That sync waits its turn
    // behind other clients' requests (see `relay::serve_agent_socket`): when they hold the agent
    // longer, the request is not made and the kill at the end of `grace` stops the guest.
    let asked = tokio::task::spawn_blocking(move || {
        crate::qga::Client::connect(&socket, Duration::from_secs(5))?.shutdown()
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|r| r);
    match asked {
        Ok(()) if button => eprintln!(
            "virtkit: guest still up {}s after the power button; asked qemu-ga to shut down",
            BUTTON_GRACE.as_secs()
        ),
        Ok(()) => eprintln!("virtkit: no power button to press; asked qemu-ga to shut down"),
        Err(e) => eprintln!("virtkit: qemu-ga shutdown: {e:#}"),
    }
    exited_by(ch, deadline).await.then(|| pressed.elapsed())
}

/// [`power_off`] from synchronous code, on a thread of its own (so it can block whether or not
/// the caller is inside a runtime). A guest already off counts as off at once. Each call costs
/// a thread and a runtime: `Manager::stop_all` makes one per Windows unit, a handful at most.
pub(crate) fn power_off_blocking(
    ch: &mut Child,
    work: &Path,
    grace: Duration,
) -> Result<Option<Duration>> {
    if ch.try_wait().ok().flatten().is_some() {
        return Ok(Some(Duration::ZERO));
    }
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                Ok(tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("starting a runtime to stop the guest")?
                    .block_on(power_off(ch, work, grace)))
            })
            .join()
            .map_err(|_| anyhow::anyhow!("stopping the guest panicked"))?
    })
}

/// Wait until the Windows guest behind the qemu-ga `socket` has finished starting — on the
/// first boot of a generalized image, specialize and OOBE restart it once its agent is already
/// up — and return a connection to its qemu-ga. `running` says whether the guest is still up;
/// `console` is its serial log, for the error; `label` names the guest in progress lines.
pub(crate) fn wait_started(
    socket: &Path,
    console: &Path,
    timeout: Duration,
    label: &str,
    running: &mut dyn FnMut() -> bool,
) -> Result<crate::qga::Client> {
    const STATE: &str =
        r#"reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" /v ImageState"#;
    let deadline = Instant::now() + timeout;
    let mut progress = crate::qga::Progress::new(label);
    loop {
        progress.tick();
        if !running() {
            bail!(
                "the guest powered off while starting; see {}",
                console.display()
            );
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            bail!(
                "Windows did not finish starting within {}s; see {}",
                timeout.as_secs(),
                console.display()
            );
        }
        // In short slices, so a guest that dies is noticed.
        let Ok(mut ga) = crate::qga::Client::connect(socket, left.min(Duration::from_secs(30)))
        else {
            std::thread::sleep(Duration::from_secs(1));
            continue;
        };
        let mut out = Vec::new();
        match crate::winexec::exec_command_line(&mut ga, STATE, &[], None, false, &mut out) {
            // Setup done, or no such key (reg exits 1): an image past its first boot. Anything
            // else, an empty answer included, is a guest still on its way, whose restart out
            // of OOBE would kill the caller's command.
            Ok(0) if String::from_utf8_lossy(&out).contains("IMAGE_STATE_COMPLETE") => {
                return Ok(ga);
            }
            Ok(1) => return Ok(ga),
            // Still in specialize or OOBE, or restarting out of them.
            Ok(_) | Err(_) => std::thread::sleep(Duration::from_secs(5)),
        }
    }
}

/// A UEFI guest a build boots: no registry entry, and a network only through `nics`, in a run
/// directory of its own. Dropping it kills a guest still running.
pub(crate) struct Guest {
    ch: Child,
    work: PathBuf,
    /// Holds an embedded firmware's memfd open for the VMM.
    _firmware: crate::embed::Resolved,
}

impl Guest {
    /// Boot `disks` as the guest `name`, with `work` as its run directory and `nics` on a
    /// switch (none: no network). No TPM: a build's guests run without one.
    pub(crate) fn boot(
        work: &Path,
        name: &str,
        disks: Vec<Disk>,
        cpus: u32,
        mem: &str,
        nics: Vec<crate::vmm::Nic>,
    ) -> Result<Guest> {
        let firmware = firmware()?;
        let mut spec = guest_spec(&firmware.path, work, name, disks, cpus, mem, None)?;
        spec.nics = nics;
        let vmm = crate::vmm::selected();
        let ch = crate::run::spawn_vmm(vmm.as_ref(), &spec, crate::prio::Prio::Normal)?;
        Ok(Guest {
            ch,
            work: work.to_path_buf(),
            _firmware: firmware,
        })
    }

    /// The guest's qemu-ga socket.
    pub(crate) fn agent_socket(&self) -> PathBuf {
        self.work.join(GUEST_AGENT_SOCKET)
    }

    /// The guest's serial console log.
    pub(crate) fn console(&self) -> PathBuf {
        self.work.join(crate::run::CONSOLE_LOG)
    }

    /// Whether the guest is still running.
    pub(crate) fn running(&mut self) -> bool {
        self.ch.try_wait().ok().flatten().is_none()
    }

    /// Wait up to `timeout` for the guest to power off by itself (a reboot does not end it):
    /// `true` once it has, `false` if it is still running. A VMM that fails is an error.
    pub(crate) fn wait_poweroff(&mut self, timeout: Duration) -> Result<bool> {
        let end = Instant::now() + timeout;
        loop {
            if let Some(status) = self.ch.try_wait().context("waiting for the VMM")? {
                if status.success() {
                    return Ok(true);
                }
                bail!("{}", crate::run::boot_failure(&self.console(), status));
            }
            if Instant::now() >= end {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Stop the guest as `vk stop` does, with [`BUILD_STOP_GRACE`] before the kill (a build
    /// layer must close cleanly, and a Windows that has just changed roles takes its time).
    /// Return an error if killed: its disk may hold a torn write. Blocks; call outside async
    /// tasks (builds run on a blocking thread).
    pub(crate) fn shutdown(mut self) -> Result<Duration> {
        if !self.running() {
            return Ok(Duration::ZERO);
        }
        match power_off_blocking(&mut self.ch, &self.work, BUILD_STOP_GRACE)? {
            Some(after) => Ok(after),
            None => bail!(
                "the guest did not power off within {}s and was killed",
                BUILD_STOP_GRACE.as_secs()
            ),
        }
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        if self.running() {
            let _ = self.ch.kill();
        }
        let _ = self.ch.wait();
    }
}

/// Boot `bundle` and hold it until the guest powers off or the run is stopped.
pub(crate) async fn run(args: &RunArgs, work: &Path, bundle: Bundle) -> Result<()> {
    refuse_unsupported(args)?;
    crate::winbuild::warn_evaluation(&bundle.dir, &bundle.dir.display().to_string());
    let firmware = match bundle.manifest.firmware {
        Firmware::Uefi => firmware()?,
    };
    let restore = bundle.manifest.snapshot.is_some();
    let guest_ip = if args.net {
        Some(crate::net::switch_addrs(crate::run::RUN_SUBNET)?.2)
    } else {
        None
    };
    check_restore(&bundle.manifest, args.cpus, args.mem.as_deref(), guest_ip)?;
    // A snapshot's memory goes with its disks, variable store and TPM state as they were:
    // never with a previous run's.
    let disks = machine_files(work, &bundle, restore)?;
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
    }

    let restore_from = restore.then_some(bundle.dir.as_path());
    let mut spec = guest_spec(&firmware.path, work, &name, disks, cpus, &mem, restore_from)?;
    spec.nics = nics;
    spec.numa = args.numa.clone();
    spec.tpm_state = tpm_state(work, &bundle.manifest);
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
        "virtkit: {name}: UEFI guest {} ({cpus} vCPU, {mem}{}); console {}",
        if restore {
            "restored from its snapshot"
        } else {
            "booting"
        },
        guest_ip.map_or(String::new(), |ip| format!(", {ip}")),
        console.display()
    );
    if restore {
        set_clock_when_up(work.join(GUEST_AGENT_SOCKET));
    }

    let _registration = crate::vms::register(crate::vms::VmEntry {
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
        guest_agent: Some(work.join(GUEST_AGENT_SOCKET)),
        control: Some(work.join(CONTROL_SOCKET)),
    });

    let result = hold(&mut ch, &console, args.detach_log.as_deref()).await;
    if ch.try_wait().ok().flatten().is_none() {
        // Stopped: the power button, then qemu-ga's shutdown; the kill once STOP_GRACE runs
        // out or on a second Ctrl-C.
        tokio::select! {
            off = power_off(&mut ch, work, crate::shutdown::STOP_GRACE) => match off {
                Some(after) => {
                    println!("virtkit: guest powered off ({after:.0?} after the power button)")
                }
                None => eprintln!(
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

/// Whether the VMM `ch` exits by `deadline`. An unreadable status is taken as alive: the
/// deadline bounds the wait.
async fn exited_by(ch: &mut Child, deadline: Instant) -> bool {
    loop {
        if ch.try_wait().ok().flatten().is_some() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Set the guest's clock through qemu-ga `socket` to the host's once its agent answers, on a
/// separate thread: a restored guest resumes at the time its snapshot was taken.
fn set_clock_when_up(socket: PathBuf) {
    let set = move || -> Result<()> {
        set_clock(&mut crate::qga::Client::connect(
            &socket,
            Duration::from_secs(60),
        )?)
    };
    let _ = std::thread::Builder::new()
        .name("vk-set-clock".into())
        .spawn(move || match set() {
            Ok(()) => println!("virtkit: guest clock set to the host's"),
            Err(e) => eprintln!(
                "virtkit: warning: the restored guest's clock is not set, so Kerberos may fail \
                 until it is: {e:#}"
            ),
        });
}

/// Set the clock of the guest behind `ga` to the host's.
pub(crate) fn set_clock(ga: &mut crate::qga::Client) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos() as u64;
    ga.call(
        "guest-set-time",
        Some(serde_json::json!({ "time": now })),
        crate::qga::DEFAULT_TIMEOUT,
    )?;
    Ok(())
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

    fn manifest(json: &str) -> serde_json::Result<Manifest> {
        serde_json::from_str(json)
    }

    #[test]
    fn a_snapshot_manifest_records_the_address_and_refuses_unknown_fields() {
        let m = manifest(
            r#"{"firmware": "uefi", "disks": ["d"], "snapshot": {"addr": "192.168.127.2"}}"#,
        )
        .unwrap();
        assert_eq!(
            m.snapshot,
            Some(SnapshotInfo {
                addr: Some(Ipv4Addr::new(192, 168, 127, 2))
            })
        );
        let m = manifest(r#"{"firmware": "uefi", "disks": ["d"], "snapshot": {"addr": null}}"#)
            .unwrap();
        assert_eq!(m.snapshot, Some(SnapshotInfo { addr: None }));
        assert!(
            manifest(r#"{"firmware": "uefi", "disks": ["d"]}"#)
                .unwrap()
                .snapshot
                .is_none()
        );
        assert!(
            manifest(
                r#"{"firmware": "uefi", "disks": ["d"], "snapshot": {"addr": null, "net": true}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn a_snapshot_restores_only_on_the_network_vcpus_and_memory_it_was_taken_with() {
        let ip = |last| Some(Ipv4Addr::new(192, 168, 127, last));
        let m = manifest(
            r#"{"firmware": "uefi", "cpus": 2, "mem": "4G", "disks": ["d"],
                "snapshot": {"addr": "192.168.127.2"}}"#,
        )
        .unwrap();
        check_restore(&m, None, None, ip(2)).unwrap();
        check_restore(&m, Some(2), Some("4096M"), ip(2)).unwrap();
        check_restore(&m, Some(2), Some("4096"), ip(2)).unwrap();
        let err =
            |cpus, mem, addr| format!("{:#}", check_restore(&m, cpus, mem, addr).unwrap_err());
        assert!(err(None, None, None).contains("with --net"));
        assert!(err(None, None, ip(3)).contains("taken at 192.168.127.2, not 192.168.127.3"));
        let resized = "runs only with the 2 vCPUs and 4G of memory";
        assert!(err(Some(4), None, ip(2)).contains(resized));
        assert!(err(None, Some("2G"), ip(2)).contains(resized));
        let offline = manifest(
            r#"{"firmware": "uefi", "cpus": 2, "mem": "4G", "disks": ["d"],
                "snapshot": {"addr": null}}"#,
        )
        .unwrap();
        check_restore(&offline, None, None, None).unwrap();
        let err = check_restore(&offline, None, None, ip(2)).unwrap_err();
        assert!(format!("{err:#}").contains("without --net"));
        // A bundle that is not a snapshot boots with anything.
        let boot = manifest(r#"{"firmware": "uefi", "disks": ["d"]}"#).unwrap();
        check_restore(&boot, Some(8), Some("1G"), None).unwrap();
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

    /// A variable store of the right length, every byte `b`.
    fn store(b: u8) -> Vec<u8> {
        vec![b; UEFI_VARS_LEN as usize]
    }

    /// A bundle in `tmp/img` of the manifest `json`, with a 1 MiB disk `d` and the variable
    /// store `vars.fd` of `b`s.
    fn vars_bundle(tmp: &Scratch, json: &str) -> Bundle {
        let dir = tmp.path().join("img");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(tmp.path().join("run")).unwrap();
        std::fs::write(dir.join(MANIFEST), json).unwrap();
        std::fs::write(dir.join("d"), vec![0u8; 1 << 20]).unwrap();
        std::fs::write(dir.join("vars.fd"), store(b'b')).unwrap();
        Bundle::detect(dir.to_str().unwrap()).unwrap().unwrap()
    }

    #[test]
    fn a_machine_starts_from_a_copy_of_its_bundles_variable_store_and_keeps_its_own() {
        let tmp = Scratch::new("vars");
        let bundle = vars_bundle(
            &tmp,
            r#"{"firmware": "uefi", "disks": ["d"], "uefi_vars": "vars.fd"}"#,
        );
        let work = tmp.path().join("run");
        assert!(!bundle.manifest.secure_boot);
        seed_uefi_vars(&work, &bundle).unwrap();
        assert_eq!(std::fs::read(work.join(UEFI_VARS)).unwrap(), store(b'b'));
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(work.join(UEFI_VARS))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // The machine's own store, once it has one, is never replaced; the bundle's is never
        // written.
        std::fs::write(work.join(UEFI_VARS), store(b'm')).unwrap();
        seed_uefi_vars(&work, &bundle).unwrap();
        seed_secure_boot(&work).unwrap();
        assert_eq!(std::fs::read(work.join(UEFI_VARS)).unwrap(), store(b'm'));
        assert_eq!(
            std::fs::read(bundle.dir.join("vars.fd")).unwrap(),
            store(b'b')
        );
    }

    #[test]
    fn a_fresh_machine_replaces_the_variable_store_its_run_kept() {
        // As a snapshot's restore does: its memory goes with the snapshot's store only.
        let tmp = Scratch::new("vars-fresh");
        let bundle = vars_bundle(
            &tmp,
            r#"{"firmware": "uefi", "disks": ["d"], "uefi_vars": "vars.fd"}"#,
        );
        let work = tmp.path().join("run");
        std::fs::write(work.join(UEFI_VARS), store(b's')).unwrap();
        std::fs::write(work.join(TPM_STATE), "tpm").unwrap();
        machine_files(&work, &bundle, false).unwrap();
        assert_eq!(std::fs::read(work.join(UEFI_VARS)).unwrap(), store(b's'));
        assert!(work.join(TPM_STATE).exists());
        machine_files(&work, &bundle, true).unwrap();
        assert_eq!(std::fs::read(work.join(UEFI_VARS)).unwrap(), store(b'b'));
        // Nor with the run's TPM: a new one, or the snapshot's, which libkrun writes there.
        assert!(!work.join(TPM_STATE).exists());
    }

    #[test]
    fn only_a_machine_whose_manifest_asks_for_a_tpm_gets_one() {
        let work = Path::new("/run/x");
        let plain = manifest(r#"{"firmware": "uefi", "disks": ["d"]}"#).unwrap();
        assert_eq!(tpm_state(work, &plain), None);
        let tpm = manifest(r#"{"firmware": "uefi", "disks": ["d"], "tpm": true}"#).unwrap();
        assert_eq!(tpm_state(work, &tpm), Some(work.join(TPM_STATE)));
    }

    #[test]
    fn a_secure_boot_bundle_without_a_store_starts_from_microsofts_keys() {
        let tmp = Scratch::new("vars-secboot");
        let bundle = vars_bundle(
            &tmp,
            r#"{"firmware": "uefi", "disks": ["d"], "secure_boot": true}"#,
        );
        let work = tmp.path().join("run");
        let seeded = seed_uefi_vars(&work, &bundle);
        // The template is vk's own: embedded or installed in a release, absent in a dev build.
        match vars_template(crate::embed::Asset::UefiVarsSecureBoot).unwrap() {
            Some(template) => {
                seeded.unwrap();
                assert_eq!(std::fs::read(work.join(UEFI_VARS)).unwrap(), template);
            }
            None => {
                let err = seeded.unwrap_err();
                assert!(format!("{err:#}").contains("no Secure Boot"), "{err:#}");
                assert!(!work.join(UEFI_VARS).exists());
            }
        }
    }

    #[test]
    fn a_variable_store_of_another_length_is_refused() {
        let tmp = Scratch::new("vars-len");
        let bundle = vars_bundle(
            &tmp,
            r#"{"firmware": "uefi", "disks": ["d"], "uefi_vars": "vars.fd"}"#,
        );
        let work = tmp.path().join("run");
        std::fs::write(bundle.dir.join("vars.fd"), b"short").unwrap();
        let err = seed_uefi_vars(&work, &bundle).unwrap_err();
        assert!(format!("{err:#}").contains("of 5 bytes"), "{err:#}");
        assert!(!work.join(UEFI_VARS).exists());
        std::fs::write(work.join(UEFI_VARS), b"short").unwrap();
        assert!(check_vars_len(&work.join(UEFI_VARS)).is_err());
        std::fs::write(work.join(UEFI_VARS), store(0)).unwrap();
        check_vars_len(&work.join(UEFI_VARS)).unwrap();
    }

    #[test]
    fn a_manifest_names_only_files_inside_its_bundle() {
        let tmp = Scratch::new("vars-paths");
        let outside = tmp.path().join("outside");
        std::fs::write(&outside, store(0)).unwrap();
        let work = tmp.path().join("run");
        for (json, what) in [
            (
                r#"{"firmware": "uefi", "disks": ["../outside"]}"#,
                "../outside",
            ),
            (
                &format!(
                    r#"{{"firmware": "uefi", "disks": ["{}"]}}"#,
                    outside.display()
                ),
                outside.to_str().unwrap(),
            ),
            (r#"{"firmware": "uefi", "disks": [""]}"#, ""),
        ] {
            let bundle = vars_bundle(&tmp, json);
            let err = bundle.disks().unwrap_err();
            assert!(
                err.to_string().contains("not a path inside the bundle"),
                "{what}: {err}"
            );
        }
        let bundle = vars_bundle(
            &tmp,
            r#"{"firmware": "uefi", "disks": ["./d"], "uefi_vars": "../outside"}"#,
        );
        assert_eq!(bundle.disks().unwrap(), vec![bundle.dir.join("d")]);
        let err = seed_uefi_vars(&work, &bundle).unwrap_err();
        assert!(
            err.to_string().contains("not a path inside the bundle"),
            "{err}"
        );
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
            tap: Some(crate::net::TapNet {
                tap: "vkdev0".into(),
                mac: "02:00:00:00:00:01".into(),
                addr: None,
            }),
            audit_egress: true,
            registry_proxy: Some("10.0.2.2:5000".into()),
            inactivity_timeout_secs: Some(60),
            ..Default::default()
        };
        let err = refuse_unsupported(&args).unwrap_err().to_string();
        assert!(
            err.contains(
                "honour a command, --ssh, --tap, --audit-egress, --registry-proxy, --inactivity-timeout"
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
    fn the_system_uuid_is_a_version_4_uuid_made_once_per_run_directory() {
        let a = Scratch::new("uuid-a");
        let uuid = system_uuid(a.path()).unwrap();
        assert_eq!(system_uuid(a.path()).unwrap(), uuid);
        assert_ne!(uuid, generation_id(a.path()).unwrap());
        assert_eq!(uuid[6] >> 4, 4);
        assert_eq!(uuid[8] >> 6, 0b10);
    }

    #[test]
    fn a_restore_keeps_the_snapshots_system_uuid_in_its_run_directory() {
        let snapshot = Scratch::new("uuid-snap");
        let work = Scratch::new("uuid-work");
        let err = restored_uuid(snapshot.path(), work.path()).unwrap_err();
        assert!(err.to_string().contains("predates system UUIDs"), "{err:#}");
        std::fs::write(snapshot.path().join(SYSTEM_UUID), [7u8; 16]).unwrap();
        system_uuid(work.path()).unwrap();
        assert_eq!(
            restored_uuid(snapshot.path(), work.path()).unwrap(),
            [7u8; 16]
        );
        assert_eq!(system_uuid(work.path()).unwrap(), [7u8; 16]);
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
