// Copyright 2024 The virtkit Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Minimal legacy PCI support: a type-1 (0xCF8/0xCFC) configuration mechanism
// exposing a host bridge at 00:00.0 plus general endpoint functions, so the
// guest can enumerate a PCI bus and drive a virtio-pci device over INTx.
// Semantics follow cloud-hypervisor's `pci::PciConfigIo` /
// `parse_io_config_address` and `pci::PciConfiguration`, adapted to libkrun's
// `BusDevice` trait (which has no `Barrier` return). MSI/MSI-X and ACPI are
// deliberately out of scope here.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::bus::BusDevice;

/// Number of 32-bit registers exposed per function in legacy config space.
/// Type-0 header is 16 dwords (64 bytes); the type-1 mechanism can address 64
/// dwords (256 bytes) per function, which is where the capability list lives.
const NUM_CONFIG_REGISTERS: usize = 64;

/// First dword index available for the PCI capability list (0x40). The 64-byte
/// header occupies dwords 0..16; capabilities are placed from 0x40 onwards.
const FIRST_CAPABILITY_OFFSET: usize = 0x40;

/// Dword index of the first BAR (BAR0) in a type-0 header.
const BAR0_REGISTER: usize = 4;

/// A single PCI function's configuration space, addressed as 32-bit registers.
///
/// Besides the raw register array this tracks, per BAR, whether the low bits
/// encode the region size (so a driver probing BAR size by writing all-ones and
/// reading back gets the size mask, and the assigned base otherwise).
pub struct PciDevice {
    /// 32-bit configuration registers (dword-indexed).
    registers: [u32; NUM_CONFIG_REGISTERS],
    /// Writable-bit mask per register (1 = driver may change the bit). Used to
    /// keep read-only fields (ids, class, caps) stable while letting the command
    /// register and BAR bases be written.
    writable_bits: [u32; NUM_CONFIG_REGISTERS],
    /// For each BAR dword, `Some(size)` if it is a memory BAR whose size is
    /// `size`. Sizing (write 0xffff_ffff, read back the size mask) is handled
    /// for the low dword; the high dword of a 64-bit BAR returns its size mask.
    bar_sizes: [Option<u64>; NUM_CONFIG_REGISTERS],
    /// Next free dword index for appending a capability.
    next_capability_offset: usize,
    /// Byte offset (within config space) of the last capability's `next` pointer,
    /// so a freshly added capability can be linked into the list.
    last_capability_next_ptr: Option<usize>,
}

impl PciDevice {
    fn empty() -> Self {
        PciDevice {
            registers: [0u32; NUM_CONFIG_REGISTERS],
            writable_bits: [0u32; NUM_CONFIG_REGISTERS],
            bar_sizes: [None; NUM_CONFIG_REGISTERS],
            next_capability_offset: FIRST_CAPABILITY_OFFSET,
            last_capability_next_ptr: None,
        }
    }

    /// Build a minimal host-bridge config space.
    ///
    /// `vendor_id`/`device_id` identify the bridge; class code is set to
    /// "bridge device / host bridge" (0x06 / 0x00), prog-if 0, revision 0,
    /// header type 0. Everything else reads back as 0.
    pub fn new_host_bridge(vendor_id: u16, device_id: u16) -> Self {
        let mut dev = Self::empty();

        // Register 0x00: device id (upper 16) | vendor id (lower 16).
        dev.registers[0] = (u32::from(device_id) << 16) | u32::from(vendor_id);

        // Register 0x02: class code (upper 8) | subclass (bits 16-23) |
        // prog-if (bits 8-15) | revision id (bits 0-7).
        // Class 0x06 (bridge), subclass 0x00 (host bridge), prog-if 0, rev 0.
        dev.registers[2] = 0x06 << 24;

        // Register 0x03: header type 0x00.
        dev.registers[3] = 0x0000_0000;

        dev
    }

    /// Build the config space of a PCI endpoint (header type 0).
    ///
    /// `class`/`subclass`/`prog_if` set register 0x02; `interrupt_pin` /
    /// `interrupt_line` set the low two bytes of register 0x0f. The command
    /// register (0x01, low 16 bits) is made writable so the driver can enable
    /// memory-space decoding. `status` advertises the presence of a capability
    /// list (bit 4).
    #[allow(clippy::too_many_arguments)]
    pub fn new_endpoint(
        vendor_id: u16,
        device_id: u16,
        class: u8,
        subclass: u8,
        prog_if: u8,
        interrupt_pin: u8,
        interrupt_line: u8,
    ) -> Self {
        let mut dev = Self::empty();

        dev.registers[0] = (u32::from(device_id) << 16) | u32::from(vendor_id);

        // Command register (low 16) is writable; status register (high 16)
        // advertises a capability list at bit 4.
        dev.registers[1] = 0x0010 << 16;
        dev.writable_bits[1] = 0x0000_ffff;

        dev.registers[2] =
            (u32::from(class) << 24) | (u32::from(subclass) << 16) | (u32::from(prog_if) << 8);

        // Header type 0x00, single function.
        dev.registers[3] = 0x0000_0000;

        // Register 0x0d (byte 0x34): capabilities pointer -> first cap offset.
        dev.registers[0x0d] = FIRST_CAPABILITY_OFFSET as u32;

        // Register 0x0f: interrupt pin (byte 1) | interrupt line (byte 0).
        dev.registers[0x0f] = (u32::from(interrupt_pin) << 8) | u32::from(interrupt_line);
        // interrupt_line (byte 0) is conventionally writable by firmware/driver.
        dev.writable_bits[0x0f] = 0x0000_00ff;

        dev
    }

    /// Program a 64-bit memory BAR at `bar_index` (0 => BAR0/BAR1 pair).
    ///
    /// `base` is the assigned guest-physical base; `size` the region size (power
    /// of two). The low dword carries the memory-type bits (64-bit, non-prefetch)
    /// and lets the driver read back the size mask while probing; both dwords are
    /// writable so a standard BAR write-then-restore leaves the assigned base.
    pub fn set_memory_bar_64(&mut self, bar_index: usize, base: u64, size: u64) {
        let lo = BAR0_REGISTER + bar_index * 2;
        let hi = lo + 1;

        // Low dword: base bits | 0b100 (64-bit memory, non-prefetchable).
        self.registers[lo] = ((base & 0xffff_fff0) as u32) | 0b100;
        self.registers[hi] = (base >> 32) as u32;

        // The address bits are writable; the low 4 type bits are fixed.
        self.writable_bits[lo] = 0xffff_fff0;
        self.writable_bits[hi] = 0xffff_ffff;

        self.bar_sizes[lo] = Some(size);
        self.bar_sizes[hi] = Some(size);
    }

    /// Append a vendor-specific (virtio) capability to the capability list,
    /// returning the byte offset at which it was placed. `body` is the capability
    /// payload following the 1-byte id and 1-byte next-pointer (i.e. it starts at
    /// the virtio `cap_len` field). The capability is dword-padded.
    pub fn add_vendor_capability(&mut self, body: &[u8]) -> usize {
        let cap_offset = self.next_capability_offset;

        // Assemble the full capability bytes: id (0x09 = vendor specific), next
        // pointer (patched to 0 for now; linked below), then the body.
        let mut bytes = Vec::with_capacity(2 + body.len());
        bytes.push(0x09u8); // PCI_CAP_ID_VNDR
        bytes.push(0x00u8); // next pointer, terminates the list for now
        bytes.extend_from_slice(body);
        // Pad to a dword boundary.
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }

        // Write the capability bytes into the register array.
        for (i, chunk) in bytes.chunks(4).enumerate() {
            let mut word = 0u32;
            for (b, byte) in chunk.iter().enumerate() {
                word |= u32::from(*byte) << (b * 8);
            }
            self.registers[cap_offset / 4 + i] = word;
        }

        // Link the previous capability's next pointer to this one.
        if let Some(prev_next) = self.last_capability_next_ptr {
            let reg = prev_next / 4;
            let shift = (prev_next % 4) * 8;
            self.registers[reg] =
                (self.registers[reg] & !(0xffu32 << shift)) | ((cap_offset as u32) << shift);
        }

        // This capability's next pointer is its second byte.
        self.last_capability_next_ptr = Some(cap_offset + 1);
        self.next_capability_offset = cap_offset + bytes.len();
        cap_offset
    }

    /// Read a 32-bit configuration register by dword index.
    fn read_config_register(&self, register: usize) -> u32 {
        self.registers.get(register).copied().unwrap_or(0)
    }

    /// Write a (possibly partial) 32-bit configuration register, honouring the
    /// per-register writable-bit mask and BAR-sizing semantics.
    fn write_config_register(&mut self, register: usize, offset: u64, data: &[u8]) {
        if register >= NUM_CONFIG_REGISTERS {
            return;
        }
        if offset as usize + data.len() > 4 {
            return;
        }

        // Assemble the incoming bytes into a value/mask aligned to the register.
        let mut value = 0u32;
        let mut mask = 0u32;
        for (i, byte) in data.iter().enumerate() {
            let shift = (offset as usize + i) * 8;
            value |= u32::from(*byte) << shift;
            mask |= 0xffu32 << shift;
        }

        // BAR sizing: a driver probes the region size by writing an all-ones
        // dword and reading back the size mask. Only a full 32-bit write (all
        // four bytes) is a size probe; a partial write is a normal base update,
        // so require `mask == 0xffff_ffff` before entering the size branch.
        if mask == 0xffff_ffff {
            if let Some(size) = self.bar_sizes[register] {
                let writable = self.writable_bits[register] & mask;
                let incoming = value & writable;
                if incoming == writable && writable != 0 {
                    // Driver probing size: report ~(size-1) over the address bits.
                    let size_mask = !(size.wrapping_sub(1));
                    let dword = if (register - BAR0_REGISTER) % 2 == 0 {
                        // Low dword keeps its type bits.
                        (size_mask as u32 & 0xffff_fff0) | (self.registers[register] & 0x0000_000f)
                    } else {
                        (size_mask >> 32) as u32
                    };
                    self.registers[register] =
                        (self.registers[register] & !writable) | (dword & writable);
                    return;
                }
            }
        }

        let writable = self.writable_bits[register] & mask;
        self.registers[register] = (self.registers[register] & !writable) | (value & writable);
    }
}

/// A PCI bus holding functions keyed by device number. Device 0 is the host
/// bridge; endpoints (e.g. the virtio-pci block device) live at higher slots.
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

    /// Attach an endpoint function at `device_number` (00:`device_number`.0).
    pub fn add_pci_device(&self, device_number: u8, device: Arc<Mutex<PciDevice>>) {
        self.pci_bus
            .lock()
            .unwrap()
            .add_device(device_number, device);
    }

    fn config_space_read(&self) -> u32 {
        let enabled = (self.config_address & 0x8000_0000) != 0;
        if !enabled {
            return 0xffff_ffff;
        }

        let (bus, device, function, register) =
            parse_io_config_address(self.config_address & !0x8000_0000);

        // Only bus 0, function 0 exist.
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

    fn write_reg(cfg: &mut PciConfigIo, device: u32, register: u32, value: u32) {
        let addr = 0x8000_0000 | (device << 11) | (register << 2);
        cfg.write(0, 0, &addr.to_le_bytes());
        cfg.write(0, 4, &value.to_le_bytes());
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

    #[test]
    fn endpoint_ids_and_class() {
        let ep = PciDevice::new_endpoint(0x1af4, 0x1042, 0x01, 0x00, 0x00, 1, 11);
        let mut bus = PciBus::new();
        bus.add_device(
            0,
            Arc::new(Mutex::new(PciDevice::new_host_bridge(0x1b36, 0x0008))),
        );
        bus.add_device(1, Arc::new(Mutex::new(ep)));
        let mut cfg = PciConfigIo::new(Arc::new(Mutex::new(bus)));

        assert_eq!(read_reg(&mut cfg, 1, 0), (0x1042 << 16) | 0x1af4);
        let reg2 = read_reg(&mut cfg, 1, 2);
        assert_eq!(reg2 >> 24, 0x01); // mass storage
                                      // capabilities pointer present
        assert_eq!(
            read_reg(&mut cfg, 1, 0x0d) & 0xff,
            FIRST_CAPABILITY_OFFSET as u32
        );
        // interrupt line/pin
        let reg_f = read_reg(&mut cfg, 1, 0x0f);
        assert_eq!(reg_f & 0xff, 11);
        assert_eq!((reg_f >> 8) & 0xff, 1);
    }

    #[test]
    fn bar_sizing_reports_size_mask_then_base() {
        let mut ep = PciDevice::new_endpoint(0x1af4, 0x1042, 0x01, 0x00, 0x00, 1, 11);
        ep.set_memory_bar_64(0, 0xd000_0000, 0x8_0000);
        let mut bus = PciBus::new();
        bus.add_device(1, Arc::new(Mutex::new(ep)));
        let mut cfg = PciConfigIo::new(Arc::new(Mutex::new(bus)));

        // Initial base with 64-bit memory type bits (0b100).
        assert_eq!(read_reg(&mut cfg, 1, 4), 0xd000_0000 | 0b100);
        // Probe size: write all ones, read back size mask (keeping type bits).
        write_reg(&mut cfg, 1, 4, 0xffff_ffff);
        let sized = read_reg(&mut cfg, 1, 4);
        assert_eq!(
            sized & 0xffff_fff0,
            (!(0x8_0000u64 - 1)) as u32 & 0xffff_fff0
        );
        // Restore base.
        write_reg(&mut cfg, 1, 4, 0xd000_0000);
        assert_eq!(read_reg(&mut cfg, 1, 4) & 0xffff_fff0, 0xd000_0000);
    }

    #[test]
    fn vendor_capability_is_linked() {
        let mut ep = PciDevice::new_endpoint(0x1af4, 0x1042, 0x01, 0x00, 0x00, 1, 11);
        let off0 = ep.add_vendor_capability(&[0, 1, 2, 3]);
        let off1 = ep.add_vendor_capability(&[4, 5, 6, 7]);
        assert_eq!(off0, FIRST_CAPABILITY_OFFSET);
        // First cap's next pointer should point at the second cap.
        let reg = off0 / 4;
        let next = (ep.registers[reg] >> 8) & 0xff;
        assert_eq!(next as usize, off1);
    }
}
