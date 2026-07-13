// Copyright 2024 The virtkit Authors.
// SPDX-License-Identifier: Apache-2.0
//
// MSI-X table / PBA state and interrupt delivery for the virtio-pci transport.
// Semantics (table/PBA read-write, message-control, PBA pending injection) are
// adapted from cloud-hypervisor's `pci::msix`, but self-contained: interrupts
// are delivered by writing a per-vector eventfd that the VMM has registered as
// a `KVM_IRQFD` against a KVM MSI GSI, and routing updates go through the shared
// `GsiRoutes` manager rather than a `vm-device` abstraction.
//
// Two vectors are used: vector 0 for config-change interrupts and vector 1
// shared by all virtqueues. When the guest has not enabled MSI-X, `signal()`
// reports that so the caller falls back to legacy INTx.

use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::Mutex;

use utils::eventfd::{EventFd, EFD_NONBLOCK};

#[cfg(target_os = "linux")]
use crate::legacy::GsiRoutes;

/// Bytes per MSI-X table entry (addr_lo, addr_hi, data, vector_ctl).
pub const MSIX_TABLE_ENTRY_SIZE: u64 = 16;

/// Number of MSI-X vectors: vector 0 = config change, vector 1 = shared by all
/// virtqueues.
pub const NUM_VECTORS: u16 = 2;

const MSIX_TABLE_ENTRIES_MODULO: u64 = 16;
const MSIX_PBA_ENTRIES_MODULO: u64 = 8;
const BITS_PER_PBA_ENTRY: usize = 64;
const FUNCTION_MASK_BIT: u8 = 14;
const MSIX_ENABLE_BIT: u8 = 15;

/// A single MSI-X table entry. Defaults masked (vector_ctl bit 0 set) per spec.
#[derive(Clone, Copy)]
pub struct MsixTableEntry {
    msg_addr_lo: u32,
    msg_addr_hi: u32,
    msg_data: u32,
    vector_ctl: u32,
}

impl MsixTableEntry {
    fn masked(&self) -> bool {
        self.vector_ctl & 0x1 == 0x1
    }

    fn addr(&self) -> u64 {
        (u64::from(self.msg_addr_hi) << 32) | u64::from(self.msg_addr_lo)
    }
}

impl Default for MsixTableEntry {
    fn default() -> Self {
        MsixTableEntry {
            msg_addr_lo: 0,
            msg_addr_hi: 0,
            msg_data: 0,
            vector_ctl: 0x1,
        }
    }
}

/// A single MSI-X vector: its table entry, the assigned KVM MSI GSI (0 until the
/// device manager assigns one), and the eventfd the VMM registers as its irqfd.
struct MsixVector {
    entry: MsixTableEntry,
    gsi: u32,
    irqfd: Arc<EventFd>,
}

/// MSI-X configuration and delivery state for one virtio-pci device.
pub struct MsixConfig {
    vectors: Vec<MsixVector>,
    pba: Vec<u64>,
    /// Message-control enable bit (bit 15).
    enabled: bool,
    /// Message-control function-mask bit (bit 14).
    function_masked: bool,
    /// Shared KVM GSI routing manager, set at device registration.
    #[cfg(target_os = "linux")]
    routes: Option<Arc<Mutex<GsiRoutes>>>,
}

impl MsixConfig {
    pub fn new() -> Self {
        let mut vectors = Vec::with_capacity(NUM_VECTORS as usize);
        for _ in 0..NUM_VECTORS {
            let irqfd = Arc::new(
                EventFd::new(EFD_NONBLOCK).expect("failed to create MSI-X vector eventfd"),
            );
            vectors.push(MsixVector {
                entry: MsixTableEntry::default(),
                gsi: 0,
                irqfd,
            });
        }
        let num_pba_entries = (NUM_VECTORS as usize / BITS_PER_PBA_ENTRY) + 1;
        MsixConfig {
            vectors,
            pba: vec![0; num_pba_entries],
            enabled: false,
            function_masked: false,
            #[cfg(target_os = "linux")]
            routes: None,
        }
    }

    /// The per-vector eventfds, in vector order, for the VMM to register as
    /// `KVM_IRQFD`s against the assigned MSI GSIs.
    pub fn vector_irqfds(&self) -> Vec<Arc<EventFd>> {
        self.vectors.iter().map(|v| v.irqfd.clone()).collect()
    }

    /// Assign the KVM MSI GSI for a vector (called by the device manager after
    /// allocating GSIs).
    pub fn set_gsi(&mut self, index: usize, gsi: u32) {
        if let Some(v) = self.vectors.get_mut(index) {
            v.gsi = gsi;
        }
    }

    /// Attach the shared KVM GSI routing manager.
    #[cfg(target_os = "linux")]
    pub fn set_routes(&mut self, routes: Arc<Mutex<GsiRoutes>>) {
        self.routes = Some(routes);
    }

    /// Number of MSI-X table entries advertised in the capability.
    pub fn table_size() -> u16 {
        NUM_VECTORS
    }

    /// True if the driver has enabled MSI-X (message-control enable bit).
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Apply a write to the message-control register (enable / function-mask
    /// bits). Updates routes on enable and, when unmasking the function, injects
    /// any pending vectors from the PBA.
    pub fn set_msg_ctl(&mut self, reg: u16) {
        let old_enabled = self.enabled;
        let old_masked = self.function_masked;

        self.function_masked = ((reg >> FUNCTION_MASK_BIT) & 1) == 1;
        self.enabled = ((reg >> MSIX_ENABLE_BIT) & 1) == 1;

        if old_enabled != self.enabled || old_masked != self.function_masked {
            if self.enabled && !self.function_masked {
                for idx in 0..self.vectors.len() {
                    if !self.vectors[idx].entry.masked() {
                        self.update_route(idx);
                    }
                }
            } else if old_enabled {
                // MSI-X was disabled: drop all installed routes.
                self.clear_all_routes();
            }
        }

        // Function-mask cleared: inject any pending, unmasked vectors.
        if old_masked && !self.function_masked && self.enabled {
            for idx in 0..self.vectors.len() {
                if !self.vectors[idx].entry.masked() && self.get_pba_bit(idx) == 1 {
                    self.inject_and_clear_pba(idx);
                }
            }
        }
    }

    /// Read from the MSI-X table (4- or 8-byte accesses).
    pub fn read_table(&self, offset: u64, data: &mut [u8]) {
        let index = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo = offset % MSIX_TABLE_ENTRIES_MODULO;
        let Some(v) = self.vectors.get(index) else {
            data.copy_from_slice(&[0xff; 8][..data.len()]);
            return;
        };
        let e = &v.entry;
        match data.len() {
            4 => {
                let value = match modulo {
                    0x0 => e.msg_addr_lo,
                    0x4 => e.msg_addr_hi,
                    0x8 => e.msg_data,
                    0xc => e.vector_ctl,
                    _ => 0,
                };
                data.copy_from_slice(&value.to_le_bytes());
            }
            8 => {
                let value = match modulo {
                    0x0 => (u64::from(e.msg_addr_hi) << 32) | u64::from(e.msg_addr_lo),
                    0x8 => (u64::from(e.vector_ctl) << 32) | u64::from(e.msg_data),
                    _ => 0,
                };
                data.copy_from_slice(&value.to_le_bytes());
            }
            _ => warn!("msix: invalid table read len {}", data.len()),
        }
    }

    /// Write to the MSI-X table (4- or 8-byte accesses), updating routes and
    /// injecting pending vectors on a mask->unmask transition as needed.
    pub fn write_table(&mut self, offset: u64, data: &[u8]) {
        let index = (offset / MSIX_TABLE_ENTRIES_MODULO) as usize;
        let modulo = offset % MSIX_TABLE_ENTRIES_MODULO;
        if index >= self.vectors.len() {
            warn!("msix: invalid table write index {index}");
            return;
        }
        let old_entry = self.vectors[index].entry;

        let e = &mut self.vectors[index].entry;
        match data.len() {
            4 => {
                let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                match modulo {
                    0x0 => e.msg_addr_lo = value,
                    0x4 => e.msg_addr_hi = value,
                    0x8 => e.msg_data = value,
                    0xc => e.vector_ctl = value,
                    _ => warn!("msix: invalid table write offset {modulo}"),
                }
            }
            8 => {
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                match modulo {
                    0x0 => {
                        e.msg_addr_lo = value as u32;
                        e.msg_addr_hi = (value >> 32) as u32;
                    }
                    0x8 => {
                        e.msg_data = value as u32;
                        e.vector_ctl = (value >> 32) as u32;
                    }
                    _ => warn!("msix: invalid table write offset {modulo}"),
                }
            }
            _ => {
                warn!("msix: invalid table write len {}", data.len());
                return;
            }
        }

        let new_entry = self.vectors[index].entry;
        // Update the route if the entry changed and is live.
        if self.enabled && !self.function_masked && !new_entry.masked() {
            self.update_route(index);
        }
        // Vector unmasked with a pending PBA bit: inject and clear it.
        if self.enabled
            && !self.function_masked
            && old_entry.masked()
            && !new_entry.masked()
            && self.get_pba_bit(index) == 1
        {
            self.inject_and_clear_pba(index);
        }
    }

    /// Read from the MSI-X PBA (4- or 8-byte accesses).
    pub fn read_pba(&self, offset: u64, data: &mut [u8]) {
        let index = (offset / MSIX_PBA_ENTRIES_MODULO) as usize;
        let modulo = offset % MSIX_PBA_ENTRIES_MODULO;
        let Some(&entry) = self.pba.get(index) else {
            data.copy_from_slice(&[0xff; 8][..data.len()]);
            return;
        };
        match data.len() {
            4 => {
                let value = match modulo {
                    0x0 => entry as u32,
                    0x4 => (entry >> 32) as u32,
                    _ => 0,
                };
                data.copy_from_slice(&value.to_le_bytes());
            }
            8 => data.copy_from_slice(&entry.to_le_bytes()),
            _ => warn!("msix: invalid pba read len {}", data.len()),
        }
    }

    /// The PBA is read-only from the driver's view.
    pub fn write_pba(&mut self, _offset: u64, _data: &[u8]) {
        warn!("msix: PBA is read-only");
    }

    /// Deliver an interrupt for `index`. Returns true if the interrupt was (or
    /// will be, when pending) delivered via MSI-X, so the caller must NOT fall
    /// back to INTx; returns false only when MSI-X is disabled.
    pub fn signal(&mut self, index: usize) -> bool {
        if !self.enabled {
            return false;
        }
        let Some(v) = self.vectors.get(index) else {
            return false;
        };
        if self.function_masked || v.entry.masked() {
            // Record the pending interrupt; it is injected when unmasked.
            self.set_pba_pending(index);
            return true;
        }
        if let Err(e) = v.irqfd.write(1) {
            warn!("msix: failed to signal vector {index}: {e:?}");
        }
        true
    }

    // --- routing / pba helpers ----------------------------------------------

    #[cfg(target_os = "linux")]
    fn update_route(&mut self, index: usize) {
        let Some(v) = self.vectors.get(index) else {
            return;
        };
        if v.gsi == 0 {
            return;
        }
        let (gsi, addr, data) = (v.gsi, v.entry.addr(), v.entry.msg_data);
        if let Some(routes) = &self.routes {
            routes.lock().unwrap().set_msi_route(gsi, addr, data);
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn update_route(&mut self, _index: usize) {}

    #[cfg(target_os = "linux")]
    fn clear_all_routes(&mut self) {
        if let Some(routes) = self.routes.clone() {
            let mut routes = routes.lock().unwrap();
            for v in &self.vectors {
                if v.gsi != 0 {
                    routes.clear_msi_route(v.gsi);
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn clear_all_routes(&mut self) {}

    fn inject_and_clear_pba(&mut self, index: usize) {
        if let Some(v) = self.vectors.get(index) {
            if let Err(e) = v.irqfd.write(1) {
                warn!("msix: failed to inject pending vector {index}: {e:?}");
            }
        }
        self.clear_pba_pending(index);
    }

    /// Mark `vector` pending in the PBA (an interrupt arrived while masked).
    fn set_pba_pending(&mut self, vector: usize) {
        let index = vector / BITS_PER_PBA_ENTRY;
        let shift = vector % BITS_PER_PBA_ENTRY;
        if let Some(entry) = self.pba.get_mut(index) {
            *entry |= 1u64 << shift;
        }
    }

    /// Clear `vector`'s pending bit in the PBA (its pending interrupt was injected).
    fn clear_pba_pending(&mut self, vector: usize) {
        let index = vector / BITS_PER_PBA_ENTRY;
        let shift = vector % BITS_PER_PBA_ENTRY;
        if let Some(entry) = self.pba.get_mut(index) {
            *entry &= !(1u64 << shift);
        }
    }

    fn get_pba_bit(&self, vector: usize) -> u8 {
        let index = vector / BITS_PER_PBA_ENTRY;
        let shift = vector % BITS_PER_PBA_ENTRY;
        self.pba
            .get(index)
            .map_or(0, |e| ((e >> shift) & 0x1) as u8)
    }
}

impl Default for MsixConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_write_u32(cfg: &mut MsixConfig, offset: u64, value: u32) {
        cfg.write_table(offset, &value.to_le_bytes());
    }

    fn table_read_u32(cfg: &MsixConfig, offset: u64) -> u32 {
        let mut data = [0u8; 4];
        cfg.read_table(offset, &mut data);
        u32::from_le_bytes(data)
    }

    #[test]
    fn table_round_trip() {
        let mut cfg = MsixConfig::new();
        // Vector 1 (offset 0x10): addr_lo, addr_hi, data, vector_ctl.
        table_write_u32(&mut cfg, 0x10, 0xdead_beef);
        table_write_u32(&mut cfg, 0x14, 0x0000_00fe);
        table_write_u32(&mut cfg, 0x18, 0x0000_1234);
        table_write_u32(&mut cfg, 0x1c, 0x0000_0000); // unmask
        assert_eq!(table_read_u32(&cfg, 0x10), 0xdead_beef);
        assert_eq!(table_read_u32(&cfg, 0x14), 0x0000_00fe);
        assert_eq!(table_read_u32(&cfg, 0x18), 0x0000_1234);
        assert_eq!(table_read_u32(&cfg, 0x1c), 0x0000_0000);
    }

    #[test]
    fn msg_ctl_toggle() {
        let mut cfg = MsixConfig::new();
        assert!(!cfg.enabled());
        cfg.set_msg_ctl(1 << MSIX_ENABLE_BIT);
        assert!(cfg.enabled());
        assert!(!cfg.function_masked);
        cfg.set_msg_ctl(0);
        assert!(!cfg.enabled());
    }

    #[test]
    fn signal_disabled_falls_back_to_intx() {
        let mut cfg = MsixConfig::new();
        // Not enabled: signal must return false so the caller uses INTx.
        assert!(!cfg.signal(1));
    }

    #[test]
    fn signal_masked_sets_pba_not_intx() {
        let mut cfg = MsixConfig::new();
        cfg.set_msg_ctl(1 << MSIX_ENABLE_BIT);
        // Vector 1 starts masked (default vector_ctl bit 0 set).
        assert!(cfg.signal(1));
        assert_eq!(cfg.get_pba_bit(1), 1);
    }

    #[test]
    fn signal_unmasked_drains_eventfd() {
        let mut cfg = MsixConfig::new();
        cfg.set_msg_ctl(1 << MSIX_ENABLE_BIT);
        // Unmask vector 1.
        table_write_u32(&mut cfg, 0x1c, 0);
        let evt = cfg.vector_irqfds()[1].clone();
        assert!(cfg.signal(1));
        // The eventfd was written: it should read back a count.
        assert_eq!(evt.read().unwrap(), 1);
    }

    #[test]
    fn masked_then_unmasked_injects_pending() {
        let mut cfg = MsixConfig::new();
        cfg.set_msg_ctl(1 << MSIX_ENABLE_BIT);
        // Vector 1 masked by default: signal sets the PBA bit.
        assert!(cfg.signal(1));
        assert_eq!(cfg.get_pba_bit(1), 1);
        let evt = cfg.vector_irqfds()[1].clone();
        // Unmask vector 1 via a table write: the pending bit is injected+cleared.
        table_write_u32(&mut cfg, 0x1c, 0);
        assert_eq!(cfg.get_pba_bit(1), 0);
        assert_eq!(evt.read().unwrap(), 1);
    }
}
