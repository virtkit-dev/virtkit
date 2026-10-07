// The UEFI variable service's device (local patch, see VENDOR.md): the register interface of
// edk2's OvmfPkg/Include/IndustryStandard/QemuUefiVars.h, which the firmware's
// VirtMmCommunicationDxe drives, in front of virtkit's vk-uefi-vars, which keeps the machine's
// variables in its store file and checks their authenticated writes on the host.
//
// The firmware gives the device the guest-physical address of its 64 KiB communication buffer
// once; each DMA_MM command then reads the MM message there, has the service answer it in
// place and writes it back, all before the command's status reads back. A command that changed
// a non-volatile variable has the store file replaced (written whole, then renamed over it)
// before it completes.

use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use log::{error, info};
use vk_uefi_vars::{MmError, Service};
use vm_memory::{Bytes, GuestAddress, GuestMemoryMmap};

use crate::bus::BusDevice;

const REG_MAGIC: u64 = 0x00;
const REG_CMD_STS: u64 = 0x02;
const REG_BUFFER_SIZE: u64 = 0x04;
const REG_DMA_BUFFER_ADDR_LO: u64 = 0x08;
const REG_DMA_BUFFER_ADDR_HI: u64 = 0x0c;
const REG_FLAGS: u64 = 0x1c;

const MAGIC_VALUE: u16 = 0xef1;

const CMD_RESET: u16 = 0x01;
const CMD_DMA_MM: u16 = 0x02;

const STS_SUCCESS: u16 = 0x00;
const STS_ERR_UNKNOWN: u16 = 0x10;
const STS_ERR_NOT_SUPPORTED: u16 = 0x11;
const STS_ERR_BAD_BUFFER_SIZE: u16 = 0x12;

/// The firmware's communication buffer (VirtMmCommunication.h's MAX_BUFFER_SIZE).
const MAX_BUFFER_SIZE: u32 = 64 * 1024;

/// The device's MMIO window: a page, as the firmware maps it for run time.
pub const UEFI_VARS_SIZE: u64 = 0x1000;

/// The device's state besides the store file, for a snapshot.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub struct UefiVarsState {
    pub status: u16,
    pub buffer_size: u32,
    pub dma: u64,
    /// The service's phase, volatile variables, policies and locks.
    pub transient: Vec<u8>,
}

pub struct UefiVars {
    service: Service,
    path: PathBuf,
    mem: GuestMemoryMmap,
    status: u16,
    buffer_size: u32,
    dma: u64,
}

impl UefiVars {
    /// The service over the store file at `path`, with `saved`'s state for a snapshot's restore.
    pub fn new(
        path: &Path,
        mem: GuestMemoryMmap,
        saved: Option<&UefiVarsState>,
    ) -> io::Result<UefiVars> {
        let bytes = std::fs::read(path)
            .map_err(|e| io::Error::new(e.kind(), format!("reading {}: {e}", path.display())))?;
        let mut service = Service::new(bytes)
            .map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
        let (status, buffer_size, dma) = match saved {
            Some(saved) => {
                service
                    .restore_transient(&saved.transient)
                    .map_err(|e| io::Error::other(format!("the snapshot's UEFI variables: {e}")))?;
                (saved.status, saved.buffer_size, saved.dma)
            }
            None => (STS_SUCCESS, 0, 0),
        };
        info!("uefi-vars: {}: {}", path.display(), service.summary());
        Ok(UefiVars {
            service,
            path: path.to_path_buf(),
            mem,
            status,
            buffer_size,
            dma,
        })
    }

    pub fn save_state(&self) -> UefiVarsState {
        UefiVarsState {
            status: self.status,
            buffer_size: self.buffer_size,
            dma: self.dma,
            transient: self.service.save_transient(),
        }
    }

    fn command(&mut self, command: u16) -> u16 {
        match command {
            // The transfer state only, as QEMU's soft reset: the firmware resets the device as it
            // starts, but so could the guest's kernel at run time, which must not take the
            // service back before the end of DXE. A new boot is a new VMM, with a new service.
            CMD_RESET => {
                self.buffer_size = 0;
                self.dma = 0;
                STS_SUCCESS
            }
            CMD_DMA_MM => self.dma_mm(),
            // PIO transfers: the firmware uses them only when FLAGS asks, which it never does.
            _ => STS_ERR_NOT_SUPPORTED,
        }
    }

    fn dma_mm(&mut self) -> u16 {
        if self.buffer_size == 0 || self.buffer_size > MAX_BUFFER_SIZE {
            return STS_ERR_BAD_BUFFER_SIZE;
        }
        let mut buf = vec![0u8; self.buffer_size as usize];
        if let Err(e) = self.mem.read_slice(&mut buf, GuestAddress(self.dma)) {
            error!(
                "uefi-vars: reading the communication buffer at {:#x}: {e}",
                self.dma
            );
            return STS_ERR_UNKNOWN;
        }
        let changes = self.service.nv_changes();
        let status = match self.service.communicate(&mut buf) {
            Ok(()) => STS_SUCCESS,
            Err(MmError::Malformed) => return STS_ERR_BAD_BUFFER_SIZE,
            Err(MmError::Unsupported) => return STS_ERR_NOT_SUPPORTED,
        };
        if let Err(e) = self.mem.write_slice(&buf, GuestAddress(self.dma)) {
            error!(
                "uefi-vars: writing the communication buffer at {:#x}: {e}",
                self.dma
            );
            return STS_ERR_UNKNOWN;
        }
        if let Err(e) = self.persist() {
            // The change went into the service; the file keeps the last store written, and the
            // next command tries again. Only the command that made the change fails for it: one
            // that merely retried an earlier write answers as it would have.
            error!("uefi-vars: writing {}: {e}", self.path.display());
            if self.service.nv_changes() != changes {
                return STS_ERR_UNKNOWN;
            }
        }
        status
    }

    /// Replace the store file with the service's store, if a non-volatile variable changed.
    fn persist(&mut self) -> io::Result<()> {
        let Some(bytes) = self.service.take_image().map_err(io::Error::other)? else {
            return Ok(());
        };
        write_atomic(&self.path, bytes)?;
        self.service.mark_written();
        Ok(())
    }
}

/// Write `bytes` to `path` through a temporary file in the same directory, synced, renamed over
/// it: a crash leaves the old store or the new one, never a torn one.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        // Created anew, private: never a leftover (or planted) file or link at that name.
        match std::fs::remove_file(&tmp) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()
}

impl BusDevice for UefiVars {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let value: u64 = match offset {
            REG_MAGIC => u64::from(MAGIC_VALUE),
            REG_CMD_STS => u64::from(self.status),
            REG_BUFFER_SIZE => u64::from(self.buffer_size),
            REG_DMA_BUFFER_ADDR_LO => self.dma & 0xffff_ffff,
            REG_DMA_BUFFER_ADDR_HI => self.dma >> 32,
            REG_FLAGS => 0,
            _ => 0,
        };
        let bytes = value.to_le_bytes();
        for (i, b) in data.iter_mut().enumerate() {
            *b = bytes.get(i).copied().unwrap_or(0);
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        let mut bytes = [0u8; 8];
        for (b, d) in bytes.iter_mut().zip(data) {
            *b = *d;
        }
        let value = u64::from_le_bytes(bytes);
        match offset {
            REG_CMD_STS => self.status = self.command(value as u16),
            REG_BUFFER_SIZE => self.buffer_size = value as u32,
            REG_DMA_BUFFER_ADDR_LO => self.dma = (self.dma & !0xffff_ffff) | (value & 0xffff_ffff),
            REG_DMA_BUFFER_ADDR_HI => {
                self.dma = (self.dma & 0xffff_ffff) | ((value & 0xffff_ffff) << 32)
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_uefi_vars::Guid;

    const SMM_VARIABLE_PROTOCOL: Guid = Guid::new(
        0xed32d533,
        0x99e6,
        0x4209,
        [0x9c, 0xc0, 0x2d, 0x72, 0xcd, 0xd9, 0x98, 0xa7],
    );
    const SYSTEM_NV_DATA_FV: Guid = Guid::new(
        0xfff12b8d,
        0x7696,
        0x4c8b,
        [0xa9, 0x85, 0x27, 0x47, 0x07, 0x5b, 0x4f, 0x50],
    );
    const AUTHENTICATED_VARIABLE: Guid = Guid::new(
        0xaaf32c78,
        0x947b,
        0x439a,
        [0xa1, 0x80, 0x2e, 0x14, 0x4e, 0xc3, 0x77, 0x92],
    );
    /// The communication buffer's guest address.
    const DMA: u64 = 0x1000;

    /// An empty 528 KiB store: firmware volume header, authenticated store header, erased.
    fn image() -> Vec<u8> {
        let total: usize = 0x84000;
        let mut b = vec![0xffu8; total];
        b[..16].fill(0);
        b[16..32].copy_from_slice(&SYSTEM_NV_DATA_FV.0);
        b[32..40].copy_from_slice(&(total as u64).to_le_bytes());
        b[40..44].copy_from_slice(&0x4856_465fu32.to_le_bytes());
        b[44..48].copy_from_slice(&0u32.to_le_bytes());
        b[48..50].copy_from_slice(&0x48u16.to_le_bytes());
        let st = 0x48;
        b[st..st + 16].copy_from_slice(&AUTHENTICATED_VARIABLE.0);
        b[st + 16..st + 20].copy_from_slice(&(0x40000u32 - 0x48).to_le_bytes());
        b[st + 20] = 0x5a;
        b[st + 21] = 0xfe;
        b[st + 22..st + 28].fill(0);
        b
    }

    fn write(dev: &mut UefiVars, offset: u64, value: u32) {
        dev.write(0, offset, &value.to_le_bytes());
    }

    /// A device over an empty store in a directory of its own, and the guest memory it reads.
    fn device(test: &str) -> (UefiVars, GuestMemoryMmap, PathBuf) {
        let dir = std::env::temp_dir().join(format!("vk-uefi-vars-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vars.fd");
        std::fs::write(&path, image()).unwrap();
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let dev = UefiVars::new(&path, mem.clone(), None).unwrap();
        (dev, mem, dir)
    }

    /// Send a variable protocol message (function, then its payload); the command's status.
    fn send(dev: &mut UefiVars, mem: &GuestMemoryMmap, function: u64, payload: &[u8]) -> u16 {
        let mut msg = SMM_VARIABLE_PROTOCOL.0.to_vec();
        msg.extend_from_slice(&(16 + payload.len() as u64).to_le_bytes());
        msg.extend_from_slice(&function.to_le_bytes());
        msg.extend_from_slice(&0u64.to_le_bytes());
        msg.extend_from_slice(payload);
        mem.write_slice(&msg, GuestAddress(DMA)).unwrap();
        write(dev, REG_BUFFER_SIZE, msg.len() as u32);
        write(dev, REG_DMA_BUFFER_ADDR_LO, DMA as u32);
        write(dev, REG_CMD_STS, u32::from(CMD_DMA_MM));
        dev.status
    }

    /// SMM_VARIABLE_COMMUNICATE_ACCESS_VARIABLE for `name` with `data` (empty for a get).
    fn access(name: &str, attributes: u32, data: &[u8], room: usize) -> Vec<u8> {
        let name: Vec<u8> = name
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        let mut out = SYSTEM_NV_DATA_FV.0.to_vec();
        out.extend_from_slice(&(data.len().max(room) as u64).to_le_bytes());
        out.extend_from_slice(&(name.len() as u64).to_le_bytes());
        out.extend_from_slice(&attributes.to_le_bytes());
        out.extend_from_slice(&name);
        out.extend_from_slice(data);
        out.resize(out.len() + room, 0);
        out
    }

    /// A RESET at run time, which the guest's kernel can write too, leaves the service past
    /// ExitBootServices: only the transfer state goes.
    #[test]
    fn a_reset_clears_the_transfer_and_leaves_the_service() {
        let (mut dev, mem, dir) = device("reset");
        let fresh = dev.save_state().transient;
        // EXIT_BOOT_SERVICE.
        assert_eq!(send(&mut dev, &mem, 6, &[]), STS_SUCCESS);
        let runtime = dev.save_state().transient;
        assert_ne!(runtime, fresh);

        write(&mut dev, REG_CMD_STS, u32::from(CMD_RESET));
        let state = dev.save_state();
        assert_eq!(
            (state.status, state.buffer_size, state.dma),
            (STS_SUCCESS, 0, 0)
        );
        assert_eq!(state.transient, runtime, "the service is still at run time");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A store file that cannot be written fails the command that changed a variable, not the
    /// ones after it, which try the write again until it goes.
    #[test]
    fn only_the_change_fails_for_an_unwritable_store() {
        use std::os::unix::fs::PermissionsExt;
        const NV_BS_RT: u32 = 0x7;
        let (mut dev, mem, dir) = device("unwritable");
        let set =
            |dev: &mut UefiVars, value: &[u8]| send(dev, &mem, 3, &access("V", NV_BS_RT, value, 0));
        assert_eq!(set(&mut dev, b"one"), STS_SUCCESS);
        let written = std::fs::read(dir.join("vars.fd")).unwrap();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        if std::fs::write(dir.join("probe"), b"").is_ok() {
            // Root ignores the mode: nothing here can fail.
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        assert_eq!(set(&mut dev, b"two"), STS_ERR_UNKNOWN);
        assert_eq!(
            send(&mut dev, &mem, 1, &access("V", 0, &[], 16)),
            STS_SUCCESS,
            "a get only retries the write"
        );
        assert_eq!(std::fs::read(dir.join("vars.fd")).unwrap(), written);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            send(&mut dev, &mem, 1, &access("V", 0, &[], 16)),
            STS_SUCCESS
        );
        assert_ne!(
            std::fs::read(dir.join("vars.fd")).unwrap(),
            written,
            "the retry wrote it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
