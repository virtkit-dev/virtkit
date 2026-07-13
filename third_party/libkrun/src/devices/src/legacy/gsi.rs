// Copyright 2024 The virtkit Authors.
// SPDX-License-Identifier: Apache-2.0
//
// KVM GSI routing manager for the in-kernel irqchip. `KVM_SET_GSI_ROUTING`
// replaces the entire routing table, so every commit re-supplies the default
// x86 IOAPIC + PIC entries (pins 0..=23) that KVM installs by default and then
// appends one MSI route per configured MSI-X vector. Without re-supplying the
// defaults, adding an MSI route would silently break legacy INTx / serial /
// i8042 delivery.

use std::collections::BTreeMap;
use std::sync::Arc;

use kvm_bindings::{
    kvm_irq_routing_entry, kvm_irq_routing_entry__bindgen_ty_1, kvm_irq_routing_irqchip,
    kvm_irq_routing_msi, KvmIrqRouting, KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER,
    KVM_IRQCHIP_PIC_SLAVE, KVM_IRQ_ROUTING_IRQCHIP, KVM_IRQ_ROUTING_MSI,
};
use kvm_ioctls::VmFd;

/// Number of IOAPIC pins mirrored in the default routing (matches the x86 KVM
/// `default_routing[]` in arch/x86/kvm/irq_comm.c).
const IOAPIC_NUM_PINS: u32 = 24;

/// Manages KVM MSI GSI routes for the virtio-pci MSI-X transports, keyed by GSI.
/// Every route change re-commits the full table (defaults + MSI entries).
pub struct GsiRoutes {
    vmfd: Arc<VmFd>,
    /// gsi -> (message address, message data).
    msi: BTreeMap<u32, (u64, u32)>,
}

impl GsiRoutes {
    pub fn new(vmfd: Arc<VmFd>) -> Self {
        GsiRoutes {
            vmfd,
            msi: BTreeMap::new(),
        }
    }

    /// The default x86 KVM routing entries for pins 0..=23. Pins 0..=15 get two
    /// entries (IOAPIC and the corresponding PIC master/slave pin); pins 16..=23
    /// get a single IOAPIC entry.
    fn default_entries() -> Vec<kvm_irq_routing_entry> {
        let mut entries = Vec::with_capacity(40);
        for gsi in 0..IOAPIC_NUM_PINS {
            entries.push(irqchip_entry(gsi, KVM_IRQCHIP_IOAPIC, gsi));
            if gsi < 16 {
                let (chip, pin) = if gsi < 8 {
                    (KVM_IRQCHIP_PIC_MASTER, gsi)
                } else {
                    (KVM_IRQCHIP_PIC_SLAVE, gsi % 8)
                };
                entries.push(irqchip_entry(gsi, chip, pin));
            }
        }
        entries
    }

    /// Insert or update the MSI route for `gsi` and re-commit the table.
    pub fn set_msi_route(&mut self, gsi: u32, addr: u64, data: u32) {
        self.msi.insert(gsi, (addr, data));
        self.commit();
    }

    /// Remove the MSI route for `gsi` (if any) and re-commit the table.
    pub fn clear_msi_route(&mut self, gsi: u32) {
        if self.msi.remove(&gsi).is_some() {
            self.commit();
        }
    }

    /// Rebuild the full GSI routing table (defaults + MSI entries) and push it
    /// to KVM. `KVM_SET_GSI_ROUTING` replaces the whole table, so the defaults
    /// must always be present.
    fn commit(&self) {
        let mut entries = Self::default_entries();
        for (&gsi, &(addr, data)) in &self.msi {
            entries.push(msi_entry(gsi, addr, data));
        }

        let mut routing = match KvmIrqRouting::new(entries.len()) {
            Ok(r) => r,
            Err(e) => {
                error!("gsi: failed to allocate irq routing table: {e:?}");
                return;
            }
        };
        routing.as_mut_slice().copy_from_slice(&entries);
        if let Err(e) = self.vmfd.set_gsi_routing(&routing) {
            error!("gsi: KVM_SET_GSI_ROUTING failed: {e:?}");
        }
    }
}

fn irqchip_entry(gsi: u32, irqchip: u32, pin: u32) -> kvm_irq_routing_entry {
    kvm_irq_routing_entry {
        gsi,
        type_: KVM_IRQ_ROUTING_IRQCHIP,
        flags: 0,
        u: kvm_irq_routing_entry__bindgen_ty_1 {
            irqchip: kvm_irq_routing_irqchip { irqchip, pin },
        },
        ..Default::default()
    }
}

fn msi_entry(gsi: u32, addr: u64, data: u32) -> kvm_irq_routing_entry {
    kvm_irq_routing_entry {
        gsi,
        type_: KVM_IRQ_ROUTING_MSI,
        flags: 0,
        u: kvm_irq_routing_entry__bindgen_ty_1 {
            msi: kvm_irq_routing_msi {
                address_lo: addr as u32,
                address_hi: (addr >> 32) as u32,
                data,
                ..Default::default()
            },
        },
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_entries_layout() {
        let entries = GsiRoutes::default_entries();
        // 24 IOAPIC entries (pins 0..=23) + 16 PIC entries (pins 0..=15).
        assert_eq!(entries.len(), 40);

        let ioapic = entries
            .iter()
            .filter(|e| e.type_ == KVM_IRQ_ROUTING_IRQCHIP)
            .filter(|e| unsafe { e.u.irqchip.irqchip } == KVM_IRQCHIP_IOAPIC)
            .count();
        assert_eq!(ioapic, 24);

        let pic = entries
            .iter()
            .filter(|e| e.type_ == KVM_IRQ_ROUTING_IRQCHIP)
            .filter(|e| {
                let chip = unsafe { e.u.irqchip.irqchip };
                chip == KVM_IRQCHIP_PIC_MASTER || chip == KVM_IRQCHIP_PIC_SLAVE
            })
            .count();
        assert_eq!(pic, 16);
    }
}
