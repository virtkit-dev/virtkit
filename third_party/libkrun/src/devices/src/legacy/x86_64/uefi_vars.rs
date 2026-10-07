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
            CMD_RESET => {
                self.service.reset();
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
            // The guest's write went into the service; the file keeps the last store written,
            // and the next change tries again.
            error!("uefi-vars: writing {}: {e}", self.path.display());
            return STS_ERR_UNKNOWN;
        }
        status
    }

    /// Replace the store file with the service's store, if a non-volatile variable changed.
    fn persist(&mut self) -> io::Result<()> {
        let Some(bytes) = self.service.take_image().map_err(io::Error::other)? else {
            return Ok(());
        };
        write_atomic(&self.path, bytes)
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
        let mut file = std::fs::File::create(&tmp)?;
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
