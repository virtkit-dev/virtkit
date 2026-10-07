// QEMU's firmware configuration interface, the traditional I/O port form only (local patch, see
// VENDOR.md): a selector at 0x510 and a data byte at 0x511, the signature, the interface ID
// (no DMA), the file directory and the files the VMM gives. edk2's VirtMmCommunicationDxe reads
// one, "etc/hardware-info", to find the UEFI variable service's device.

use crate::bus::BusDevice;

/// The I/O ports the interface takes: the selector (16 bits) and the data port.
pub const FW_CFG_PORT: u64 = 0x510;
pub const FW_CFG_PORT_LEN: u64 = 2;

const SIGNATURE: u16 = 0x0000;
const ID: u16 = 0x0001;
const FILE_DIR: u16 = 0x0019;
const FILE_FIRST: u16 = 0x0020;
/// The interface ID: the traditional interface, no DMA.
const ID_TRADITIONAL: u32 = 1;
/// A file's name, NUL-padded, in a directory entry.
const NAME_LEN: usize = 56;

pub struct FwCfg {
    items: Vec<(u16, Vec<u8>)>,
    selected: Option<usize>,
    offset: usize,
}

impl FwCfg {
    /// The interface with `files`, each (name, contents).
    pub fn new(files: Vec<(String, Vec<u8>)>) -> FwCfg {
        let mut dir = Vec::new();
        dir.extend_from_slice(&(files.len() as u32).to_be_bytes());
        let mut items = vec![
            (SIGNATURE, b"QEMU".to_vec()),
            (ID, ID_TRADITIONAL.to_le_bytes().to_vec()),
        ];
        for (i, (name, data)) in files.into_iter().enumerate() {
            let select = FILE_FIRST + i as u16;
            dir.extend_from_slice(&(data.len() as u32).to_be_bytes());
            dir.extend_from_slice(&select.to_be_bytes());
            dir.extend_from_slice(&0u16.to_be_bytes());
            let mut padded = [0u8; NAME_LEN];
            for (p, c) in padded.iter_mut().zip(name.bytes().take(NAME_LEN - 1)) {
                *p = c;
            }
            dir.extend_from_slice(&padded);
            items.push((select, data));
        }
        items.push((FILE_DIR, dir));
        FwCfg {
            items,
            selected: None,
            offset: 0,
        }
    }
}

impl BusDevice for FwCfg {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        if offset != 1 {
            data.fill(0);
            return;
        }
        let item = self.selected.and_then(|i| self.items.get(i));
        for b in data.iter_mut() {
            *b = item
                .and_then(|(_, contents)| contents.get(self.offset))
                .copied()
                .unwrap_or(0);
            self.offset = self.offset.saturating_add(1);
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        if offset != 0 || data.len() < 2 {
            return;
        }
        let key = u16::from_le_bytes([data[0], data[1]]);
        self.selected = self.items.iter().position(|(k, _)| *k == key);
        self.offset = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_item(cfg: &mut FwCfg, key: u16, len: usize) -> Vec<u8> {
        cfg.write(0, 0, &key.to_le_bytes());
        let mut out = vec![0u8; len];
        for b in out.iter_mut() {
            let mut one = [0u8];
            cfg.read(0, 1, &mut one);
            *b = one[0];
        }
        out
    }

    #[test]
    fn a_file_is_found_through_the_directory() {
        let mut cfg = FwCfg::new(vec![("etc/hardware-info".into(), vec![1, 2, 3])]);
        assert_eq!(read_item(&mut cfg, SIGNATURE, 4), b"QEMU");
        let dir = read_item(&mut cfg, FILE_DIR, 4 + 64);
        assert_eq!(u32::from_be_bytes(dir[0..4].try_into().unwrap()), 1);
        assert_eq!(u32::from_be_bytes(dir[4..8].try_into().unwrap()), 3);
        let select = u16::from_be_bytes([dir[8], dir[9]]);
        assert_eq!(&dir[12..12 + 17], b"etc/hardware-info");
        assert_eq!(read_item(&mut cfg, select, 3), [1, 2, 3]);
    }
}
