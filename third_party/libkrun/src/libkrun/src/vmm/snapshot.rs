// Copyright 2026 The virtkit Authors.
// SPDX-License-Identifier: Apache-2.0
//
// VM snapshots (local patch, see VENDOR.md): a paused VM's state, written to a directory, and
// a fresh VM built on the same configuration brought back to it before its vCPUs first run.
//
// A snapshot directory holds `state.json` ([`VmSnapshot`]: the vCPUs' and in-kernel devices'
// state, the legacy devices', each virtio-pci transport's) and the memory image it names, the
// guest's RAM regions one after the other in a sparse file. The disks are not in it: the VM's
// disk images, frozen once the VM ends, are the snapshot's disks.
//
// A snapshot restores only on the host CPU model and the build it was taken with: the CPU
// state holds the host's CPUID and MSRs, and its layout is kvm-bindings'.

use std::arch::x86_64::CpuidResult;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use devices::legacy::{AcpiPm, AcpiPmState, Cmos, CmosState, I8042Device, I8042State};
use devices::legacy::{Serial, SerialState};
use devices::virtio::{PciTransportState, VirtioPciTransport};
use vm_memory::{GuestMemoryBackend, GuestMemoryMmap, GuestMemoryRegion};

use super::CpuState;

/// The snapshot's state file in its directory, the last thing a snapshot writes.
pub const STATE_FILE: &str = "state.json";
/// The prefix of the memory images' names in the directory.
const MEMORY_PREFIX: &str = "memory-";

/// The layout version of [`VmSnapshot`]; a restore refuses another.
const VERSION: u32 = 1;

/// The kvm-bindings release whose structures' serialized form the CPU state is: a restore
/// refuses another (a test checks it against `Cargo.lock`).
const KVM_BINDINGS: &str = "0.14.1";

/// Guest pages are dumped in this unit: an all-zero one stays a hole in the image.
const PAGE: usize = 4096;

/// What `state.json` holds.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct VmSnapshot {
    #[serde(flatten)]
    pub origin: Origin,
    /// The memory image's name in the directory.
    pub memory_file: String,
    /// Whether the VM declared a VM generation ID, which a restore must then change.
    pub vm_generation_id: bool,
    pub cpu: CpuState,
    pub legacy: LegacyState,
    /// Each virtio-pci transport's state, in registration order.
    pub pci: Vec<PciTransportState>,
    /// The RAM regions the memory image holds, in order.
    pub memory: Vec<MemoryRegion>,
}

/// What a snapshot was taken with, which a restore must have too.
#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Origin {
    pub version: u32,
    /// Defaulted, like `host_cpu`, so that another version's state reads as that.
    #[serde(default)]
    pub kvm_bindings: String,
    #[serde(default)]
    pub host_cpu: HostCpu,
}

impl Origin {
    fn this() -> Self {
        Origin {
            version: VERSION,
            kvm_bindings: KVM_BINDINGS.to_string(),
            host_cpu: HostCpu::this(),
        }
    }

    /// Why a snapshot taken with `self` does not restore here, if it does not.
    fn check(&self) -> io::Result<()> {
        let here = Origin::this();
        let refused = if self.version != here.version {
            format!(
                "snapshot version {} (this build reads {VERSION})",
                self.version
            )
        } else if self.kvm_bindings != here.kvm_bindings {
            format!(
                "a snapshot of kvm-bindings {} (this build has {KVM_BINDINGS})",
                self.kvm_bindings
            )
        } else if (&self.host_cpu.vendor, self.host_cpu.signature)
            != (&here.host_cpu.vendor, here.host_cpu.signature)
        {
            format!(
                "a snapshot taken on another CPU model ({}, this host {})",
                self.host_cpu, here.host_cpu
            )
        } else if self.host_cpu.features != here.host_cpu.features {
            format!(
                "a snapshot taken on a CPU with other features ({})",
                feature_differences(&self.host_cpu.features, &here.host_cpu.features)
            )
        } else {
            return Ok(());
        };
        Err(io::Error::other(refused))
    }
}

/// The host CPU's model and features, as CPUID reports them: a snapshot holds the CPUID and
/// MSRs its vCPUs had on it, which only the same CPU model takes back.
///
/// The features are the ISA's only: a microcode update or a kernel setting changes leaf 7 EDX
/// (MD_CLEAR, IBRS/IBPB, STIBP, SSBD, L1D_FLUSH, ARCH_CAPABILITIES, TSX_FORCE_ABORT, ...) and
/// HLE and RTM in leaf 7 EBX (TSX disabled) on the same CPU, which still takes the snapshot.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostCpu {
    /// Leaf 0's vendor string.
    pub vendor: String,
    /// Leaf 1 EAX: family, model and stepping.
    pub signature: u32,
    /// The words [`FEATURE_WORDS`] names.
    pub features: [u32; 7],
}

/// What each word of [`HostCpu::features`] is.
const FEATURE_WORDS: [&str; 7] = [
    "leaf 1 ECX",
    "leaf 1 EDX",
    "leaf 7 EBX",
    "leaf 7 ECX",
    "leaf 0xd EAX",
    "leaf 0x8000_0001 ECX",
    "leaf 0x8000_0001 EDX",
];

/// HLE (bit 4) and RTM (bit 11) in leaf 7 EBX, which TSX being disabled clears.
const LEAF7_EBX_TSX: u32 = 1 << 4 | 1 << 11;

/// The features of a CPU whose CPUID leaves 1, 7.0, 0xd.0 and 0x8000_0001 are these, `None`
/// where the CPU has no such leaf.
fn features(
    leaf1: CpuidResult,
    leaf7: Option<CpuidResult>,
    leaf_d: Option<CpuidResult>,
    ext1: Option<CpuidResult>,
) -> [u32; 7] {
    [
        leaf1.ecx,
        leaf1.edx,
        leaf7.map_or(0, |r| r.ebx & !LEAF7_EBX_TSX),
        leaf7.map_or(0, |r| r.ecx),
        leaf_d.map_or(0, |r| r.eax),
        ext1.map_or(0, |r| r.ecx),
        ext1.map_or(0, |r| r.edx),
    ]
}

/// The words of `saved` that differ from `here`'s, with the bits that do.
fn feature_differences(saved: &[u32; 7], here: &[u32; 7]) -> String {
    let words = FEATURE_WORDS.iter().zip(saved.iter().zip(here));
    words
        .filter(|(_, (saved, here))| saved != here)
        .map(|(name, (saved, here))| {
            let bits: Vec<String> = (0..32)
                .filter(|bit| (saved ^ here) >> bit & 1 != 0)
                .map(|bit| bit.to_string())
                .collect();
            format!(
                "{name} {saved:#010x}, this host {here:#010x}: bits {}",
                bits.join(", ")
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

impl HostCpu {
    pub fn this() -> Self {
        use std::arch::x86_64::{__cpuid, __cpuid_count};
        let leaf0 = __cpuid(0);
        let vendor = [leaf0.ebx, leaf0.edx, leaf0.ecx]
            .iter()
            .flat_map(|r| r.to_le_bytes())
            .map(char::from)
            .collect();
        let leaf = |leaf, max| (leaf <= max).then(|| __cpuid_count(leaf, 0));
        let ext_max = __cpuid(0x8000_0000).eax;
        let leaf1 = __cpuid(1);
        let leaf7 = leaf(7, leaf0.eax);
        let leaf_d = leaf(0xd, leaf0.eax);
        let ext1 = leaf(0x8000_0001, ext_max);
        HostCpu {
            vendor,
            signature: leaf1.eax,
            features: features(leaf1, leaf7, leaf_d, ext1),
        }
    }
}

impl std::fmt::Display for HostCpu {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{} signature {:#x}", self.vendor, self.signature)
    }
}

/// A guest RAM region in the memory image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MemoryRegion {
    pub guest_addr: u64,
    pub len: u64,
}

/// The legacy (port I/O) devices a snapshot keeps.
#[derive(Clone)]
pub struct LegacyDevices {
    pub cmos: Arc<Mutex<Cmos>>,
    pub serials: Vec<Arc<Mutex<Serial>>>,
    pub i8042: Arc<Mutex<I8042Device>>,
    pub acpi_pm: Arc<Mutex<AcpiPm>>,
}

#[derive(serde::Serialize, serde::Deserialize)]
#[cfg_attr(test, derive(Default))]
pub struct LegacyState {
    pub cmos: CmosState,
    pub serials: Vec<SerialState>,
    pub i8042: I8042State,
    pub acpi_pm: AcpiPmState,
}

impl LegacyDevices {
    pub fn save(&self) -> LegacyState {
        LegacyState {
            cmos: self.cmos.lock().unwrap().save_state(),
            serials: self
                .serials
                .iter()
                .map(|serial| serial.lock().unwrap().save_state())
                .collect(),
            i8042: self.i8042.lock().unwrap().save_state(),
            acpi_pm: self.acpi_pm.lock().unwrap().save_state(),
        }
    }

    /// Put back `state`, of a VM with as many serial ports.
    pub fn restore(&self, state: &LegacyState) -> io::Result<()> {
        if state.serials.len() != self.serials.len() {
            return Err(io::Error::other(format!(
                "the snapshot has {} serial ports, the VM {}",
                state.serials.len(),
                self.serials.len()
            )));
        }
        self.cmos.lock().unwrap().restore_state(&state.cmos);
        for (serial, saved) in self.serials.iter().zip(&state.serials) {
            serial.lock().unwrap().restore_state(saved);
        }
        self.i8042.lock().unwrap().restore_state(&state.i8042);
        self.acpi_pm.lock().unwrap().restore_state(&state.acpi_pm);
        Ok(())
    }
}

/// The RAM regions of `memory`: every region below `shm_start` (a virtio-fs DAX window above
/// it maps host files, which a snapshot does not keep).
pub fn ram_regions(memory: &GuestMemoryMmap, shm_start: u64) -> Vec<MemoryRegion> {
    memory
        .iter()
        .filter(|region| shm_start == 0 || region.start_addr().0 < shm_start)
        .map(|region| MemoryRegion {
            guest_addr: region.start_addr().0,
            len: region.len(),
        })
        .collect()
}

/// A snapshot of the given parts, taken here.
pub fn new_snapshot(
    cpu: CpuState,
    legacy: LegacyState,
    pci: Vec<PciTransportState>,
    memory: Vec<MemoryRegion>,
    vm_generation_id: bool,
) -> VmSnapshot {
    VmSnapshot {
        origin: Origin::this(),
        memory_file: String::new(),
        vm_generation_id,
        cpu,
        legacy,
        pci,
        memory,
    }
}

/// Write `snapshot`, with its regions of `memory`, as the snapshot in `dir`, replacing the one
/// there only once complete: a new memory image beside the old one, then `state.json`, which
/// names it, renamed over the old one, the commit point; then the old image goes. A snapshot
/// that fails leaves the previous one whole.
///
/// Once the rename is done the snapshot is taken, and this returns `Ok`: a failure to sync the
/// directory (the new snapshot may not survive a host crash, the previous one then does) or to
/// remove an old image (the next snapshot removes it) is only logged.
pub fn write(dir: &Path, memory: &GuestMemoryMmap, snapshot: &mut VmSnapshot) -> io::Result<()> {
    snapshot.memory_file = new_image_name()?;
    let image = dir.join(&snapshot.memory_file);
    // Created here, so that a failure below removes only an image this snapshot created.
    let image_file = create_private(&image)?;
    let tmp = dir.join(format!("{STATE_FILE}.tmp"));
    let committed = write_memory(&image_file, memory, &snapshot.memory)
        .and_then(|()| write_state(&tmp, snapshot))
        .and_then(|()| std::fs::rename(&tmp, dir.join(STATE_FILE)));
    if let Err(e) = committed {
        // Best effort: neither is named by the state file, and the next snapshot removes a
        // stray image.
        let _ = std::fs::remove_file(&tmp);
        let _ = std::fs::remove_file(&image);
        return Err(e);
    }
    if let Err(e) = File::open(dir).and_then(|dir| dir.sync_all()) {
        log::warn!("snapshot {}: syncing the directory: {e}", dir.display());
    }
    if let Err(e) = remove_old_images(dir, &snapshot.memory_file) {
        log::warn!(
            "snapshot {}: removing old memory images: {e}",
            dir.display()
        );
    }
    Ok(())
}

/// A new memory image name: the time, and a random part that no other snapshot's has.
fn new_image_name() -> io::Result<String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut random = [0u8; 8];
    // SAFETY: getrandom writes at most `random.len()` bytes into it.
    let got = unsafe { libc::getrandom(random.as_mut_ptr().cast(), random.len(), 0) };
    if got != random.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(format!(
        "{MEMORY_PREFIX}{nanos:x}-{:016x}",
        u64::from_ne_bytes(random)
    ))
}

/// Remove the memory images in `dir` but `keep`: the previous snapshot's, and any a failed one
/// left behind.
fn remove_old_images(dir: &Path, keep: &str) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with(MEMORY_PREFIX) && name != keep)
        {
            std::fs::remove_file(dir.join(name))?;
        }
    }
    Ok(())
}

/// Write `regions` of `memory` one after the other into `file`, new and empty, leaving
/// all-zero pages as holes.
fn write_memory(file: &File, memory: &GuestMemoryMmap, regions: &[MemoryRegion]) -> io::Result<()> {
    let total: u64 = regions.iter().map(|r| r.len).sum();
    file.set_len(total)?;
    let mut file_offset = 0u64;
    for region in regions {
        let host = host_slice(memory, region)?;
        // Runs of non-zero pages, each written at once.
        let mut run_start = None;
        for (i, page) in host.chunks(PAGE).enumerate() {
            match (is_zero(page), run_start) {
                (false, None) => run_start = Some(i * PAGE),
                (true, Some(start)) => {
                    file.write_all_at(&host[start..i * PAGE], file_offset + start as u64)?;
                    run_start = None;
                }
                _ => {}
            }
        }
        if let Some(start) = run_start {
            file.write_all_at(&host[start..], file_offset + start as u64)?;
        }
        file_offset += region.len;
    }
    file.sync_all()
}

/// A new file at `path` that only its owner can read, failing if one is there.
fn create_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Read the image at `path` back into `regions` of `memory`, which must be the regions it was
/// dumped from. Its data extents are read; a hole is a zero page, which the fresh VM's memory
/// mostly is already (reading an untouched page allocates nothing), but not where its build
/// loaded the firmware and wrote its tables, which are cleared.
pub fn load_memory(
    memory: &GuestMemoryMmap,
    regions: &[MemoryRegion],
    path: &Path,
) -> io::Result<()> {
    let file = File::open(path)?;
    let mut file_offset = 0u64;
    for region in regions {
        let host = host_slice(memory, region)?;
        let end = file_offset + region.len;
        let mut at = file_offset;
        while at < end {
            let data = seek(&file, at, libc::SEEK_DATA)?.unwrap_or(end).min(end);
            clear(&mut host[(at - file_offset) as usize..(data - file_offset) as usize]);
            if data == end {
                break;
            }
            let hole = seek(&file, data, libc::SEEK_HOLE)?.unwrap_or(end).min(end);
            let from = (data - file_offset) as usize;
            let to = (hole - file_offset) as usize;
            file.read_exact_at(&mut host[from..to], data)?;
            at = hole;
        }
        file_offset = end;
    }
    Ok(())
}

/// `lseek(fd, offset, whence)`; `None` past the last data (`ENXIO`).
fn seek(file: &File, offset: u64, whence: libc::c_int) -> io::Result<Option<u64>> {
    // SAFETY: lseek on an owned, open descriptor.
    let at = unsafe { libc::lseek(file.as_raw_fd(), offset as libc::off_t, whence) };
    if at < 0 {
        let err = io::Error::last_os_error();
        return if err.raw_os_error() == Some(libc::ENXIO) {
            Ok(None)
        } else {
            Err(err)
        };
    }
    Ok(Some(at as u64))
}

/// The host mapping of `region` in `memory`.
#[allow(clippy::mut_from_ref)]
fn host_slice<'a>(memory: &'a GuestMemoryMmap, region: &MemoryRegion) -> io::Result<&'a mut [u8]> {
    let mapped = memory
        .iter()
        .find(|r| r.start_addr().0 == region.guest_addr && r.len() == region.len)
        .ok_or_else(|| {
            io::Error::other(format!(
                "no guest RAM region of {:#x} bytes at {:#x}",
                region.len, region.guest_addr
            ))
        })?;
    // SAFETY: the region's mapping is `len` bytes long and lives as long as `memory`; the
    // vCPUs are paused or not started, and the devices quiet, while a snapshot reads or a
    // restore writes it.
    Ok(unsafe { std::slice::from_raw_parts_mut(mapped.as_ptr(), mapped.len() as usize) })
}

/// Zero the pages of `bytes` that are not zero already, leaving untouched ones untouched.
fn clear(bytes: &mut [u8]) {
    for page in bytes.chunks_mut(PAGE) {
        if !is_zero(page) {
            page.fill(0);
        }
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Write `snapshot` as a new file at `path`.
fn write_state(path: &Path, snapshot: &VmSnapshot) -> io::Result<()> {
    // A state file a failed snapshot left behind.
    match std::fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let file = create_private(path)?;
    let mut out = io::BufWriter::new(&file);
    serde_json::to_writer(&mut out, snapshot).map_err(io::Error::other)?;
    io::Write::flush(&mut out)?;
    drop(out);
    file.sync_all()
}

/// The snapshot in `dir`, if it was taken with this build on this host's CPU model.
pub fn read_state(dir: &Path) -> io::Result<VmSnapshot> {
    let json = std::fs::read(dir.join(STATE_FILE))?;
    // What it was taken with first: another version's layout would not parse.
    let origin: Origin = serde_json::from_slice(&json).map_err(io::Error::other)?;
    origin.check()?;
    serde_json::from_slice(&json).map_err(io::Error::other)
}

/// The memory image `snapshot` names in `dir`.
pub fn memory_image(dir: &Path, snapshot: &VmSnapshot) -> io::Result<PathBuf> {
    let name = &snapshot.memory_file;
    if !name.starts_with(MEMORY_PREFIX) || name.contains('/') {
        return Err(io::Error::other(format!("no memory image named {name:?}")));
    }
    Ok(dir.join(name))
}

/// Restore every transport of `transports` from `states`, in order: the same device list.
pub fn restore_transports(
    transports: &[Arc<Mutex<VirtioPciTransport>>],
    states: &[PciTransportState],
) -> io::Result<()> {
    if transports.len() != states.len() {
        return Err(io::Error::other(format!(
            "the snapshot has {} PCI devices, the VM {}",
            states.len(),
            transports.len()
        )));
    }
    for (index, (transport, state)) in transports.iter().zip(states).enumerate() {
        transport
            .lock()
            .unwrap()
            .restore_state(state)
            .map_err(|e| io::Error::other(format!("PCI device {index}: {e}")))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use vm_memory::{Bytes, GuestAddress};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("krun-snap-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const RANGES: [(GuestAddress, usize); 2] = [
        (GuestAddress(0), 0x40000),
        (GuestAddress(0x100000), 0x20000),
    ];

    fn test_snapshot(memory: &GuestMemoryMmap) -> VmSnapshot {
        new_snapshot(
            CpuState::default(),
            LegacyState::default(),
            Vec::new(),
            ram_regions(memory, 0),
            false,
        )
    }

    #[test]
    fn a_memory_image_keeps_data_in_place_and_zeros_as_holes() {
        let dir = temp_dir("mem");
        let live = GuestMemoryMmap::from_ranges(&RANGES).unwrap();
        live.write_obj(0xdead_beefu32, GuestAddress(0x1234))
            .unwrap();
        // A run of two pages, and one that ends its region.
        live.write_obj(0x55u8, GuestAddress(0x8000)).unwrap();
        live.write_obj(0x66u8, GuestAddress(0x9fff)).unwrap();
        live.write_obj(0x1122_3344_5566_7788u64, GuestAddress(0x11fff8))
            .unwrap();
        let regions = ram_regions(&live, 0);
        let image = dir.join("memory-test");
        write_memory(&create_private(&image).unwrap(), &live, &regions).unwrap();
        // Four pages of data in 384 KiB of RAM, readable by its owner only.
        let meta = std::fs::metadata(&image).unwrap();
        assert_eq!(meta.len(), 0x60000);
        assert!(std::os::unix::fs::MetadataExt::blocks(&meta) * 512 <= 8 * PAGE as u64);
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);

        let fresh = GuestMemoryMmap::from_ranges(&RANGES).unwrap();
        fresh.write_obj(0xffu8, GuestAddress(0x2000)).unwrap();
        load_memory(&fresh, &regions, &image).unwrap();
        assert_eq!(
            fresh.read_obj::<u32>(GuestAddress(0x1234)).unwrap(),
            0xdead_beef
        );
        assert_eq!(fresh.read_obj::<u8>(GuestAddress(0x8000)).unwrap(), 0x55);
        assert_eq!(fresh.read_obj::<u8>(GuestAddress(0x9fff)).unwrap(), 0x66);
        assert_eq!(
            fresh.read_obj::<u64>(GuestAddress(0x11fff8)).unwrap(),
            0x1122_3344_5566_7788
        );
        // What the fresh VM had where the snapshot has zeros is gone.
        assert_eq!(fresh.read_obj::<u8>(GuestAddress(0x2000)).unwrap(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_snapshot_replaces_the_previous_one_only_once_complete() {
        let dir = temp_dir("commit");
        let live = GuestMemoryMmap::from_ranges(&RANGES).unwrap();
        live.write_obj(1u8, GuestAddress(0)).unwrap();
        let mut first = test_snapshot(&live);
        write(&dir, &live, &mut first).unwrap();
        let state = dir.join(STATE_FILE);
        assert_eq!(
            std::fs::metadata(&state).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let first_image = memory_image(&dir, &read_state(&dir).unwrap()).unwrap();
        assert_eq!(first_image, dir.join(&first.memory_file));

        // A snapshot that cannot complete (its regions are not this memory's) leaves the
        // previous one as it was, and nothing of its own.
        let other = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        assert!(write(&dir, &other, &mut test_snapshot(&live)).is_err());
        let names = |dir: &Path| {
            let mut names: Vec<String> = std::fs::read_dir(dir)
                .unwrap()
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect();
            names.sort();
            names
        };
        assert_eq!(names(&dir), [first.memory_file.clone(), STATE_FILE.into()]);
        assert_eq!(read_state(&dir).unwrap().memory_file, first.memory_file);

        // One that completes takes its place, and the old image goes.
        let mut second = test_snapshot(&live);
        write(&dir, &live, &mut second).unwrap();
        assert_ne!(second.memory_file, first.memory_file);
        assert_eq!(names(&dir), [second.memory_file.clone(), STATE_FILE.into()]);
        assert_eq!(read_state(&dir).unwrap().memory_file, second.memory_file);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_restore_refuses_a_snapshot_of_another_version_build_or_cpu_model() {
        let dir = temp_dir("origin");
        let live = GuestMemoryMmap::from_ranges(&RANGES).unwrap();
        write(&dir, &live, &mut test_snapshot(&live)).unwrap();
        let state = dir.join(STATE_FILE);
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        let refusal = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut json = saved.clone();
            change(&mut json);
            std::fs::write(&state, json.to_string()).unwrap();
            read_state(&dir).err().map(|e| e.to_string())
        };
        assert_eq!(refusal(&|_| {}), None);
        // Another version's layout need not even parse as this one's.
        let refused = refusal(&|json| *json = serde_json::json!({ "version": VERSION + 1 }));
        assert!(refused.unwrap().contains("snapshot version"));
        let refused = refusal(&|json| json["kvm_bindings"] = "0.1.0".into());
        assert!(refused.unwrap().contains("kvm-bindings 0.1.0"));
        let refused = refusal(&|json| {
            let signature = json["host_cpu"]["signature"].as_u64().unwrap();
            json["host_cpu"]["signature"] = (signature ^ 1).into();
        });
        assert!(refused.unwrap().contains("another CPU model"));
        let refused = refusal(&|json| {
            let word = json["host_cpu"]["features"][2].as_u64().unwrap();
            json["host_cpu"]["features"][2] = (word ^ 0x22).into();
        });
        let refused = refused.unwrap();
        assert!(refused.contains("a CPU with other features (leaf 7 EBX 0x"));
        assert!(refused.ends_with(": bits 1, 5)"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cpu_features_leave_out_what_microcode_and_kernel_settings_change() {
        let leaf = |ebx, edx| CpuidResult {
            eax: 0,
            ebx,
            ecx: 0,
            edx,
        };
        let leaf1 = leaf(0, 0);
        let host = |leaf7| features(leaf1, Some(leaf7), None, None);
        let avx2 = 1 << 5;
        let base = host(leaf(avx2 | LEAF7_EBX_TSX, 0));
        // TSX disabled, and leaf 7 EDX's MD_CLEAR (10) and ARCH_CAPABILITIES (29).
        assert_eq!(host(leaf(avx2, 1 << 10 | 1 << 29)), base);
        // An ISA feature is kept.
        assert_ne!(host(leaf(LEAF7_EBX_TSX, 0)), base);
        assert_eq!(features(leaf1, None, None, None), [0; 7]);
    }

    #[test]
    fn the_kvm_bindings_a_snapshot_records_are_the_ones_built_with() {
        let manifest = include_str!("../../Cargo.toml");
        assert!(
            manifest.contains(&format!("kvm-bindings = {{ version = \"{KVM_BINDINGS}\"")),
            "update KVM_BINDINGS with the kvm-bindings dependency"
        );
        let lock = include_str!("../../../../Cargo.lock");
        assert!(lock.contains(&format!(
            "name = \"kvm-bindings\"\nversion = \"{KVM_BINDINGS}\"\n"
        )));
    }

    #[test]
    fn legacy_devices_restore_only_with_as_many_serial_ports() {
        use devices::legacy::{AcpiPm, Cmos, I8042Device, Serial};
        use std::sync::atomic::AtomicBool;
        use utils::eventfd::{EFD_NONBLOCK, EventFd};

        let evt = || EventFd::new(EFD_NONBLOCK).unwrap();
        fn shared<T>(device: T) -> Arc<Mutex<T>> {
            Arc::new(Mutex::new(device))
        }
        let devices = |serials: usize| LegacyDevices {
            cmos: shared(Cmos::new(1 << 30, 0)),
            serials: (0..serials)
                .map(|_| shared(Serial::new_sink(evt())))
                .collect(),
            i8042: shared(I8042Device::new(evt(), Arc::default(), evt())),
            acpi_pm: shared(AcpiPm::new(
                evt(),
                Arc::new(AtomicBool::new(false)),
                evt(),
                None,
            )),
        };
        let saved = devices(2).save();
        devices(2).restore(&saved).unwrap();
        let refused = devices(1).restore(&saved).unwrap_err();
        assert!(refused.to_string().contains("2 serial ports, the VM 1"));
    }

    #[test]
    fn a_restore_refuses_another_device_list() {
        use devices::virtio::Rng;

        struct NoLine;
        impl devices::pci::PciIntxLine for NoLine {
            fn set_level(&self, _asserted: bool) -> io::Result<()> {
                Ok(())
            }
        }
        let memory = GuestMemoryMmap::from_ranges(&RANGES).unwrap();
        let transport = || {
            let rng = Arc::new(Mutex::new(Rng::new().unwrap()));
            let transport =
                VirtioPciTransport::new(memory.clone(), rng, None, Arc::new(NoLine), 0xc000_0000)
                    .unwrap();
            Arc::new(Mutex::new(transport))
        };
        let transports = [transport()];
        let saved = transports[0].lock().unwrap().save_state();
        restore_transports(&[transport()], std::slice::from_ref(&saved)).unwrap();

        let refused = restore_transports(&transports, &[saved.clone(), saved.clone()]);
        assert!(refused.unwrap_err().to_string().contains("2 PCI devices"));
        let mut other = saved;
        other.device_type += 1;
        let refused = restore_transports(&[transport()], &[other]);
        assert!(refused.unwrap_err().to_string().contains("type"));
    }
}
