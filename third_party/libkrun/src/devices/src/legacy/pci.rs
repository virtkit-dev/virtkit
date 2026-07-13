// Copyright 2024 The virtkit Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Minimal legacy PCI support: a type-1 (0xCF8/0xCFC) configuration mechanism
// exposing a single host bridge at 00:00.0, so the guest can enumerate a PCI
// bus. No BARs, capabilities, MSI, or ACPI. Semantics follow cloud-hypervisor's
// `pci::PciConfigIo` / `parse_io_config_address`, adapted to libkrun's
// `BusDevice` trait (which has no `Barrier` return).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::bus::BusDevice;

/// Number of 32-bit registers exposed per function in legacy config space.
/// Type-0 header is 16 dwords (64 bytes); the type-1 mechanism can address 64
/// dwords (256 bytes) per function.
const NUM_CONFIG_REGISTERS: usize = 64;

/// A single PCI function's configuration space, addressed as 32-bit registers.
pub struct PciDevice {
    /// 32-bit configuration registers (dword-indexed).
    registers: [u32; NUM_CONFIG_REGISTERS],
}

impl PciDevice {
    /// Build a minimal host-bridge config space.
    ///
    /// `vendor_id`/`device_id` identify the bridge; class code is set to
    /// "bridge device / host bridge" (0x06 / 0x00), prog-if 0, revision 0,
    /// header type 0. Everything else reads back as 0.
    pub fn new_host_bridge(vendor_id: u16, device_id: u16) -> Self {
        let mut registers = [0u32; NUM_CONFIG_REGISTERS];

        // Register 0x00: device id (upper 16) | vendor id (lower 16).
        registers[0] = (u32::from(device_id) << 16) | u32::from(vendor_id);

        // Register 0x02: class code (upper 8) | subclass (bits 16-23) |
        // prog-if (bits 8-15) | revision id (bits 0-7).
        // Class 0x06 (bridge), subclass 0x00 (host bridge), prog-if 0, rev 0.
        registers[2] = 0x0600_0000;

        // Register 0x03: BIST | header type | latency timer | cache line size.
        // Header type 0x00 (single-function endpoint-style header).
        registers[3] = 0x0000_0000;

        PciDevice { registers }
    }

    /// Read a 32-bit configuration register by dword index.
    fn read_config_register(&self, register: usize) -> u32 {
        self.registers.get(register).copied().unwrap_or(0)
    }

    /// Write a (possibly partial) 32-bit configuration register.
    ///
    /// For A1 the host bridge has no writable state (no BARs), so writes are
    /// accepted and dropped. Kept for symmetry with the read path and to make
    /// the intent explicit.
    fn write_config_register(&mut self, _register: usize, _offset: u64, _data: &[u8]) {
        // Host bridge: no writable registers in A1. Ignore.
    }
}

/// A PCI bus holding functions keyed by device number. Device 0 is the host
/// bridge.
pub struct PciBus {
    devices: HashMap<u8, Arc<Mutex<PciDevice>>>,
}

impl PciBus {
    pub fn new() -> Self {
        PciBus {
            devices: HashMap::new(),
        }
    }

    pub fn add_device(&mut self, device_number: u8, device: Arc<Mutex<PciDevice>>) {
        self.devices.insert(device_number, device);
    }
}

impl Default for PciBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Legacy type-1 configuration access via I/O ports 0xCF8 (address) and 0xCFC
/// (data). Registered on the PIO bus at base 0xCF8, length 8: offsets 0..=3 are
/// the CONFIG_ADDRESS latch, offsets 4..=7 are the CONFIG_DATA window.
pub struct PciConfigIo {
    /// CONFIG_ADDRESS latch. Bit 31 = enable.
    config_address: u32,
    pci_bus: Arc<Mutex<PciBus>>,
}

impl PciConfigIo {
    pub fn new(pci_bus: Arc<Mutex<PciBus>>) -> Self {
        PciConfigIo {
            config_address: 0,
            pci_bus,
        }
    }

    fn config_space_read(&self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (bus, device, function, register) =
            parse_io_config_address(self.config_address & !0x8000_0000);

        // Only bus 0, function 0 exist in A1.
        if bus != 0 || function > 0 {
            return 0xffff_ffff;
        }

        self.pci_bus
            .lock()
            .unwrap()
            .devices
            .get(&(device as u8))
            .map_or(0xffff_ffff, |d| {
                d.lock().unwrap().read_config_register(register)
            })
    }

    fn config_space_write(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }

        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return;
        }

        let (bus, device, function, register) =
            parse_io_config_address(self.config_address & !0x8000_0000);

        if bus != 0 || function > 0 {
            return;
        }

        if let Some(d) = self.pci_bus.lock().unwrap().devices.get(&(device as u8)) {
            d.lock()
                .unwrap()
                .write_config_register(register, offset, data);
        }
    }

    fn set_config_address(&mut self, offset: u64, data: &[u8]) {
        if offset as usize + data.len() > 4 {
            return;
        }
        let (mask, value): (u32, u32) = match data.len() {
            1 => (
                0x0000_00ff << (offset * 8),
                u32::from(data[0]) << (offset * 8),
            ),
            2 => (
                0x0000_ffff << (offset * 8),
                ((u32::from(data[1]) << 8) | u32::from(data[0])) << (offset * 8),
            ),
            4 => (
                0xffff_ffff,
                u32::from(data[0])
                    | (u32::from(data[1]) << 8)
                    | (u32::from(data[2]) << 16)
                    | (u32::from(data[3]) << 24),
            ),
            _ => return,
        };
        self.config_address = (self.config_address & !mask) | value;
    }
}

impl BusDevice for PciConfigIo {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        // `offset` is relative to 0xcf8.
        let value = match offset {
            0..=3 => self.config_address,
            4..=7 => self.config_space_read(),
            _ => 0xffff_ffff,
        };

        // Only allow reads within a single 32-bit register.
        let start = offset as usize % 4;
        let end = start + data.len();
        if end <= 4 {
            for i in start..end {
                data[i - start] = (value >> (i * 8)) as u8;
            }
        } else {
            for d in data.iter_mut() {
                *d = 0xff;
            }
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        // `offset` is relative to 0xcf8.
        match offset {
            o @ 0..=3 => self.set_config_address(o, data),
            o @ 4..=7 => self.config_space_write(o - 4, data),
            _ => {}
        }
    }
}

/// Parse the CONFIG_ADDRESS register into a (bus, device, function, register)
/// tuple. `register` is a dword index (0..=63).
fn parse_io_config_address(config_address: u32) -> (usize, usize, usize, usize) {
    const BUS_NUMBER_OFFSET: usize = 16;
    const BUS_NUMBER_MASK: u32 = 0x00ff;
    const DEVICE_NUMBER_OFFSET: usize = 11;
    const DEVICE_NUMBER_MASK: u32 = 0x1f;
    const FUNCTION_NUMBER_OFFSET: usize = 8;
    const FUNCTION_NUMBER_MASK: u32 = 0x07;
    const REGISTER_NUMBER_OFFSET: usize = 2;
    const REGISTER_NUMBER_MASK: u32 = 0x3f;

    let shift_and_mask = |offset: usize, mask: u32| ((config_address >> offset) & mask) as usize;

    (
        shift_and_mask(BUS_NUMBER_OFFSET, BUS_NUMBER_MASK),
        shift_and_mask(DEVICE_NUMBER_OFFSET, DEVICE_NUMBER_MASK),
        shift_and_mask(FUNCTION_NUMBER_OFFSET, FUNCTION_NUMBER_MASK),
        shift_and_mask(REGISTER_NUMBER_OFFSET, REGISTER_NUMBER_MASK),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bus_with_host_bridge() -> Arc<Mutex<PciBus>> {
        let mut bus = PciBus::new();
        bus.add_device(
            0,
            Arc::new(Mutex::new(PciDevice::new_host_bridge(0x1b36, 0x0008))),
        );
        Arc::new(Mutex::new(bus))
    }

    fn read_reg(cfg: &mut PciConfigIo, device: u32, register: u32) -> u32 {
        let addr = 0x8000_0000 | (device << 11) | (register << 2);
        cfg.write(0, 0, &addr.to_le_bytes());
        let mut data = [0u8; 4];
        cfg.read(0, 4, &mut data);
        u32::from_le_bytes(data)
    }

    #[test]
    fn host_bridge_vendor_device() {
        let mut cfg = PciConfigIo::new(bus_with_host_bridge());
        assert_eq!(read_reg(&mut cfg, 0, 0), (0x0008 << 16) | 0x1b36);
    }

    #[test]
    fn host_bridge_class_code() {
        let mut cfg = PciConfigIo::new(bus_with_host_bridge());
        let reg2 = read_reg(&mut cfg, 0, 2);
        assert_eq!(reg2 >> 24, 0x06); // class: bridge
        assert_eq!((reg2 >> 16) & 0xff, 0x00); // subclass: host bridge
    }

    #[test]
    fn empty_slot_reads_all_ones() {
        let mut cfg = PciConfigIo::new(bus_with_host_bridge());
        assert_eq!(read_reg(&mut cfg, 1, 0), 0xffff_ffff);
    }

    #[test]
    fn disabled_address_reads_all_ones() {
        let mut cfg = PciConfigIo::new(bus_with_host_bridge());
        // No enable bit set.
        cfg.write(0, 0, &0u32.to_le_bytes());
        let mut data = [0u8; 4];
        cfg.read(0, 4, &mut data);
        assert_eq!(u32::from_le_bytes(data), 0xffff_ffff);
    }

    #[test]
    fn partial_config_data_byte_reads() {
        // Byte-granular reads of CONFIG_DATA must slice the addressed register by
        // `offset % 4` (the type-1 mechanism lets a guest read any sub-word).
        let mut cfg = PciConfigIo::new(bus_with_host_bridge());
        cfg.write(0, 0, &0x8000_0000u32.to_le_bytes()); // enable, dev 0, register 0
        let byte = |cfg: &mut PciConfigIo, off: u64| {
            let mut b = [0u8; 1];
            cfg.read(0, off, &mut b);
            b[0]
        };
        // Register 0 = device (0x0008) << 16 | vendor (0x1b36), little-endian bytes.
        assert_eq!(byte(&mut cfg, 4), 0x36); // vendor low
        assert_eq!(byte(&mut cfg, 5), 0x1b); // vendor high
        assert_eq!(byte(&mut cfg, 6), 0x08); // device low
        assert_eq!(byte(&mut cfg, 7), 0x00); // device high
    }

    #[test]
    fn partial_config_address_word_write() {
        // A 2-byte write to the high half of CONFIG_ADDRESS (port 0xcfa, byte offset 2)
        // must land in bits 16..=31 — it used to shift by offset*16 (= <<32), which
        // panics under overflow-checks and silently corrupts the register in release.
        let mut cfg = PciConfigIo::new(bus_with_host_bridge());
        // Assemble CONFIG_ADDRESS = 0x8000_0000 from two word writes: low half (dev 0,
        // register 0) then high half (0x8000, the enable bit). The high-half write is the
        // one that exercised the buggy shift.
        cfg.write(0, 0, &[0x00, 0x00]);
        cfg.write(0, 2, &[0x00, 0x80]);
        // CONFIG_DATA now reads the host bridge's register 0 (vendor/device).
        let mut data = [0u8; 4];
        cfg.read(0, 4, &mut data);
        assert_eq!(u32::from_le_bytes(data), (0x0008 << 16) | 0x1b36);
    }
}
