// The UEFI variable store flash (local patch, see VENDOR.md): a CFI flash device with the
// subset of Intel's command set that edk2's QEMU flash driver (OvmfPkg/QemuFlashFvbServices-
// RuntimeDxe) uses, over a file the VMM keeps per machine. The firmware finds its variable
// store there and keeps its UEFI variables (boot entries, Secure Boot keys) across boots.
//
// Every access traps: the store is read once at boot, then the variable driver works from its
// own cache, and a write is a byte-program command, so nothing here is on a hot path. Programs
// and erases reach the file at once, and are synced when the firmware ends them with the read
// array command: once per variable write, not per byte.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;

use log::error;

use crate::bus::BusDevice;

const WRITE_BYTE: u8 = 0x10;
const WRITE_BYTE_ALT: u8 = 0x40;
const BLOCK_ERASE: u8 = 0x20;
const CLEAR_STATUS: u8 = 0x50;
const READ_STATUS: u8 = 0x70;
const READ_ID: u8 = 0x90;
const CFI_QUERY: u8 = 0x98;
const ERASE_CONFIRM: u8 = 0xd0;
const READ_ARRAY: u8 = 0xff;

/// Status register: the device is ready.
const STATUS_READY: u8 = 0x80;
/// Status register: an erase failed (a bad command sequence).
const STATUS_ERASE_ERROR: u8 = 0x20;

/// What a read returns, and what the next write means.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub enum FlashMode {
    /// Reads return the array.
    #[default]
    ReadArray,
    /// Reads return the status register.
    ReadStatus,
    /// The next write is a byte to program.
    Program,
    /// The next write confirms (0xd0) the erase of its block.
    EraseSetup,
}

/// The device's state besides its contents, which live in its file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "snapshot", derive(serde::Serialize, serde::Deserialize))]
pub struct FlashState {
    pub mode: FlashMode,
    pub status: u8,
}

pub struct Flash {
    file: File,
    contents: Vec<u8>,
    block_size: usize,
    state: FlashState,
    /// Written since the last sync.
    dirty: bool,
}

impl Flash {
    /// A flash device of `file`'s contents, erased by blocks of `block_size` bytes; the file's
    /// length must be a multiple of it.
    pub fn new(file: File, block_size: usize) -> io::Result<Self> {
        let len = file.metadata()?.len() as usize;
        if len == 0 || block_size == 0 || !len.is_multiple_of(block_size) {
            return Err(io::Error::other(format!(
                "a flash image of {len} bytes is not a whole number of {block_size}-byte blocks"
            )));
        }
        let mut contents = vec![0u8; len];
        file.read_exact_at(&mut contents, 0)?;
        Ok(Flash {
            file,
            contents,
            block_size,
            state: FlashState::default(),
            dirty: false,
        })
    }

    pub fn len(&self) -> u64 {
        self.contents.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    pub fn save_state(&self) -> FlashState {
        self.state
    }

    pub fn restore_state(&mut self, state: &FlashState) {
        self.state = *state;
    }

    /// Store `contents[from..to]` in the file. A failure is logged: the guest goes on with what
    /// it wrote, and loses it at the next boot.
    fn persist(&mut self, from: usize, to: usize) {
        if let Err(e) = self
            .file
            .write_all_at(&self.contents[from..to], from as u64)
        {
            error!("UEFI variable flash: writing its file: {e}");
        }
        self.dirty = true;
    }

    /// Sync what the programs and erases since the last sync wrote. A failure is logged, as
    /// [`Self::persist`]'s is.
    fn sync(&mut self) {
        if !self.dirty {
            return;
        }
        self.dirty = false;
        if let Err(e) = self.file.sync_data() {
            error!("UEFI variable flash: syncing its file: {e}");
        }
    }

    fn program(&mut self, offset: usize, data: &[u8]) {
        let end = (offset + data.len()).min(self.contents.len());
        if offset >= end {
            return;
        }
        self.contents[offset..end].copy_from_slice(&data[..end - offset]);
        self.persist(offset, end);
        self.state.status |= STATUS_READY;
    }

    fn erase(&mut self, offset: usize) {
        let start = offset - offset % self.block_size;
        let end = start + self.block_size;
        self.contents[start..end].fill(0xff);
        self.persist(start, end);
        self.state.status |= STATUS_READY;
    }
}

impl BusDevice for Flash {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        let offset = offset as usize;
        match self.state.mode {
            FlashMode::ReadArray => {
                for (i, b) in data.iter_mut().enumerate() {
                    *b = self.contents.get(offset + i).copied().unwrap_or(0xff);
                }
            }
            // The status register answers on every byte lane, as on a device in byte mode.
            _ => data.fill(self.state.status),
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        let offset = offset as usize;
        if offset >= self.contents.len() {
            return;
        }
        match self.state.mode {
            FlashMode::Program => {
                self.program(offset, data);
                self.state.mode = FlashMode::ReadStatus;
                return;
            }
            FlashMode::EraseSetup => {
                if data.first() == Some(&ERASE_CONFIRM) {
                    self.erase(offset);
                } else {
                    self.state.status |= STATUS_ERASE_ERROR | STATUS_READY;
                }
                self.state.mode = FlashMode::ReadStatus;
                return;
            }
            FlashMode::ReadArray | FlashMode::ReadStatus => {}
        }
        let Some(&command) = data.first() else {
            return;
        };
        self.state.mode = match command {
            WRITE_BYTE | WRITE_BYTE_ALT => FlashMode::Program,
            BLOCK_ERASE => FlashMode::EraseSetup,
            CLEAR_STATUS => {
                self.state.status = 0;
                FlashMode::ReadArray
            }
            READ_STATUS => FlashMode::ReadStatus,
            READ_ARRAY => {
                self.sync();
                FlashMode::ReadArray
            }
            // No identification or query data: nothing that probes this device asks for it.
            READ_ID | CFI_QUERY => FlashMode::ReadArray,
            _ => self.state.mode,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: usize = 0x1000;

    fn flash(blocks: usize) -> (Flash, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "krun-flash-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, vec![0x5au8; blocks * BLOCK]).unwrap();
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (Flash::new(file, BLOCK).unwrap(), path)
    }

    fn read_byte(flash: &mut Flash, offset: u64) -> u8 {
        let mut b = [0u8];
        flash.read(0, offset, &mut b);
        b[0]
    }

    #[test]
    fn edk2_detects_a_writable_flash() {
        // QemuFlashDetected's sequence on a byte that is none of 0x00, 0x50, 0x70.
        let (mut flash, path) = flash(2);
        let original = read_byte(&mut flash, 0);
        flash.write(0, 0, &[CLEAR_STATUS]);
        let probe = read_byte(&mut flash, 0);
        assert!(original != CLEAR_STATUS && probe != CLEAR_STATUS);
        flash.write(0, 0, &[READ_STATUS]);
        assert_eq!(read_byte(&mut flash, 0), 0x00, "a cleared status");
        flash.write(0, 0, &[WRITE_BYTE]);
        flash.write(0, 0, &[original]);
        flash.write(0, 0, &[READ_STATUS]);
        let status = read_byte(&mut flash, 0);
        flash.write(0, 0, &[READ_ARRAY]);
        assert_eq!(status & 0x10, 0, "no programming error");
        assert_eq!(read_byte(&mut flash, 0), original);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn programs_and_erases_reach_the_file() {
        let (mut flash, path) = flash(2);
        for (i, b) in [0x11u8, 0x22, 0x33].iter().enumerate() {
            flash.write(0, BLOCK as u64 + 8 + i as u64, &[WRITE_BYTE]);
            flash.write(0, BLOCK as u64 + 8 + i as u64, &[*b]);
        }
        flash.write(0, BLOCK as u64 + 10, &[READ_ARRAY]);
        let mut back = [0u8; 4];
        flash.read(0, BLOCK as u64 + 8, &mut back);
        assert_eq!(back, [0x11, 0x22, 0x33, 0x5a]);
        // Erase the first block through an address inside it.
        flash.write(0, 0x123, &[BLOCK_ERASE]);
        flash.write(0, 0x123, &[ERASE_CONFIRM]);
        assert!(flash.dirty);
        // The firmware's read array command ends it, and syncs the file.
        flash.write(0, 0, &[READ_ARRAY]);
        assert!(!flash.dirty);
        drop(flash);
        let file = std::fs::read(&path).unwrap();
        assert!(file[..BLOCK].iter().all(|&b| b == 0xff));
        assert_eq!(&file[BLOCK + 8..BLOCK + 12], &[0x11, 0x22, 0x33, 0x5a]);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_bad_erase_sequence_is_reported_and_erases_nothing() {
        let (mut flash, path) = flash(1);
        flash.write(0, 0, &[BLOCK_ERASE]);
        flash.write(0, 0, &[READ_ARRAY]);
        assert_ne!(read_byte(&mut flash, 0) & STATUS_ERASE_ERROR, 0);
        flash.write(0, 0, &[READ_ARRAY]);
        assert_eq!(read_byte(&mut flash, 0), 0x5a);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn an_image_of_partial_blocks_is_refused() {
        let path = std::env::temp_dir().join(format!("krun-flash-odd-{}", std::process::id()));
        std::fs::write(&path, vec![0u8; BLOCK + 1]).unwrap();
        assert!(Flash::new(File::open(&path).unwrap(), BLOCK).is_err());
        let _ = std::fs::remove_file(path);
    }
}
