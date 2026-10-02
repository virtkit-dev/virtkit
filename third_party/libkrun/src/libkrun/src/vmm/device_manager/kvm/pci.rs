// Copyright 2026 The libkrun Authors.
// SPDX-License-Identifier: Apache-2.0

//! PCI root and virtio-pci registration for the x86_64 KVM backend.

use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};

use devices::Bus;
use devices::legacy::GsiRoutes;
use devices::pci::{
    BarWindow, ConfigMechanism1, Ecam, PciAddress, PciFunction, PciIntxLine, PciRootError,
};
use devices::virtio::{
    CreatePciTransportError, VIRTIO_PCI_BAR0_SIZE, VirtioDevice, VirtioPciTransport,
};
use kvm_ioctls::{IoEventAddress, NoDatamatch, VmFd};
use vm_memory::GuestMemoryMmap;

const PCI_BUS0: u8 = 0;
/// The most GSI routes KVM accepts (`KVM_MAX_IRQ_ROUTES` on x86).
const KVM_MAX_IRQ_ROUTES: u32 = 4096;
/// The routing table's default entries besides the IOAPIC pins' own: the PIC aliases of
/// pins 0-15, which `GsiRoutes` commits alongside the MSI routes.
const PIC_ALIAS_ROUTES: u32 = 16;
/// GSIs below this are the IOAPIC's pins (and their PIC aliases).
const IOAPIC_NUM_PINS: u32 = arch::x86_64::layout::IRQ_MAX + 1;

#[derive(Debug)]
pub enum Error {
    Bus(devices::BusError),
    CreateTransport(CreatePciTransportError),
    /// No device slot or BAR0 space left on bus 0.
    BusFull,
    /// More MSI-X vectors than KVM can route.
    MsiGsisExhausted,
    PciRoot(PciRootError),
    RegisterIoEvent(kvm_ioctls::Error),
    RegisterIrqFd(kvm_ioctls::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bus(err) => write!(f, "failed to register PCI bus device: {err}"),
            Self::CreateTransport(err) => write!(f, "failed to create virtio-pci transport: {err}"),
            Self::BusFull => write!(f, "no PCI device slot or BAR space is left on bus 0"),
            Self::MsiGsisExhausted => write!(f, "no more KVM GSIs are available for MSI-X"),
            Self::PciRoot(err) => write!(f, "failed to register PCI function: {err}"),
            Self::RegisterIoEvent(err) => write!(f, "failed to register queue ioeventfd: {err}"),
            Self::RegisterIrqFd(err) => write!(f, "failed to register MSI-X irqfd: {err}"),
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// Owns the bus-0 PCI functions and their guest address windows.
pub struct PciHostManager {
    root: devices::pci::SharedPciRoot,
    next_device: u8,
    irq: u32,
    functions: Vec<arch::x86_64::PciFunctionInfo>,
    /// The next KVM GSI for an MSI-X vector: above the IOAPIC's pins, which keep their
    /// default routes (local patch, see VENDOR.md).
    next_msi_gsi: u32,
    /// The VM's GSI routing table, shared by every transport's MSI-X state. Created with the
    /// first device, when the VM fd is known.
    msi_routes: Option<Arc<Mutex<GsiRoutes>>>,
}

struct KvmPciIntxLine {
    vm: Arc<VmFd>,
    /// `None` for a device past the INTx GSIs, which interrupts over MSI-X only.
    gsi: Option<u32>,
}

impl PciIntxLine for KvmPciIntxLine {
    fn set_level(&self, asserted: bool) -> std::io::Result<()> {
        let Some(gsi) = self.gsi else {
            return Ok(());
        };
        self.vm
            .set_irq_line(gsi, asserted)
            .map_err(|err| std::io::Error::from_raw_os_error(err.errno()))
    }
}

impl PciHostManager {
    pub fn new() -> Self {
        let root = devices::pci::PciRoot::shared();
        root.lock()
            .expect("Poisoned PCI root lock")
            .insert(
                PciAddress::new(PCI_BUS0, 0, 0),
                Arc::new(Mutex::new(devices::pci::PciHostBridge::new())),
            )
            .expect("an empty PCI root has a free 00:00.0");
        Self {
            root,
            next_device: 1,
            irq: arch::x86_64::layout::IRQ_BASE,
            functions: Vec::new(),
            next_msi_gsi: IOAPIC_NUM_PINS,
            msi_routes: None,
        }
    }

    pub fn register_config_io(&self, bus: &mut Bus) -> Result<()> {
        bus.insert(
            Arc::new(Mutex::new(ConfigMechanism1::new(self.root.clone()))),
            devices::pci::CONFIG_MECHANISM_1_ADDRESS,
            devices::pci::CONFIG_MECHANISM_1_SIZE,
        )
        .map_err(Error::Bus)
    }

    pub fn register_mmio(&self, bus: &mut Bus) -> Result<()> {
        bus.insert(
            Arc::new(Mutex::new(Ecam::new(self.root.clone()))),
            arch::x86_64::layout::PCI_ECAM_START,
            arch::x86_64::layout::PCI_ECAM_SIZE,
        )
        .map_err(Error::Bus)?;
        bus.insert(
            Arc::new(Mutex::new(BarWindow::new(
                self.root.clone(),
                arch::x86_64::layout::PCI_BAR_START,
            ))),
            arch::x86_64::layout::PCI_BAR_START,
            arch::x86_64::layout::PCI_BAR_END - arch::x86_64::layout::PCI_BAR_START,
        )
        .map_err(Error::Bus)?;
        // UEFI firmware reassigns BARs from the bottom of the 32-bit hole (local patch).
        bus.insert(
            Arc::new(Mutex::new(BarWindow::new(
                self.root.clone(),
                arch::x86_64::layout::PCI_MMIO32_LOW_START,
            ))),
            arch::x86_64::layout::PCI_MMIO32_LOW_START,
            arch::x86_64::layout::PCI_MMIO32_LOW_END - arch::x86_64::layout::PCI_MMIO32_LOW_START,
        )
        .map_err(Error::Bus)
    }

    pub fn register_virtio_device(
        &mut self,
        vm: Arc<VmFd>,
        guest_memory: GuestMemoryMmap,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<Option<arch::x86_64::PciFunctionInfo>> {
        // Bus 0 has 31 device slots. The IOAPIC's GSIs run out sooner, so a device past them
        // gets no INTx and interrupts over MSI-X alone, which every virtio-pci driver uses
        // when offered (local patch, see VENDOR.md).
        if self.next_device > 31 {
            return Err(Error::BusFull);
        }

        let intx_gsi = (self.irq <= arch::x86_64::layout::IRQ_MAX).then_some(self.irq);
        let address = PciAddress::new(PCI_BUS0, self.next_device, 0);
        let bar_base = arch::x86_64::layout::PCI_BAR_START
            + u64::from(self.next_device - 1) * VIRTIO_PCI_BAR0_SIZE;
        if bar_base + VIRTIO_PCI_BAR0_SIZE > arch::x86_64::layout::PCI_BAR_END {
            return Err(Error::BusFull);
        }
        let intx_line = Arc::new(KvmPciIntxLine {
            vm: vm.clone(),
            gsi: intx_gsi,
        });
        let mut transport = VirtioPciTransport::new(
            guest_memory,
            device,
            intx_gsi.map(|gsi| gsi as u8),
            intx_line,
            bar_base as u32,
        )
        .map_err(Error::CreateTransport)?;

        // MSI-X: one MSI GSI per vector, raised by its irqfd; the transport programs the
        // GSI's route when the driver writes the vector's message. Queue notifications go
        // straight to the device's queue eventfds through ioeventfds instead of trapping.
        let routes = self
            .msi_routes
            .get_or_insert_with(|| Arc::new(Mutex::new(GsiRoutes::new(vm.clone()))))
            .clone();
        let mut gsis = Vec::new();
        for irqfd in transport.msix_irqfds() {
            let gsi = self.next_msi_gsi;
            // The table holds the IOAPIC pins, their PIC aliases and one route per MSI GSI.
            if gsi + PIC_ALIAS_ROUTES >= KVM_MAX_IRQ_ROUTES {
                return Err(Error::MsiGsisExhausted);
            }
            vm.register_irqfd(&irqfd, gsi)
                .map_err(Error::RegisterIrqFd)?;
            gsis.push(gsi);
            self.next_msi_gsi += 1;
        }
        transport.set_msix_gsis(&gsis, routes);
        // Registered at BAR0's current base, and moved with it when the guest relocates
        // BAR0, so a stale one never swallows writes to whatever lands at the old address.
        let ioevents = transport.queue_notify_ioevents();
        let base = u64::from(transport.bar0_base());
        if base != 0 {
            for (offset, event) in &ioevents {
                vm.register_ioevent(event, &IoEventAddress::Mmio(base + offset), NoDatamatch)
                    .map_err(Error::RegisterIoEvent)?;
            }
        }
        let moved_vm = vm.clone();
        transport.on_bar0_moved(Box::new(move |old, new| {
            for (offset, event) in &ioevents {
                if old != 0
                    && let Err(e) = moved_vm.unregister_ioevent(
                        event,
                        &IoEventAddress::Mmio(u64::from(old) + offset),
                        NoDatamatch,
                    )
                {
                    log::warn!("virtio-pci: moving a queue ioeventfd off 0x{old:x}: {e}");
                }
                if new != 0
                    && let Err(e) = moved_vm.register_ioevent(
                        event,
                        &IoEventAddress::Mmio(u64::from(new) + offset),
                        NoDatamatch,
                    )
                {
                    log::warn!("virtio-pci: moving a queue ioeventfd to 0x{new:x}: {e}");
                }
            }
        }));

        let function: Arc<Mutex<dyn PciFunction>> = Arc::new(Mutex::new(transport));
        self.root
            .lock()
            .expect("Poisoned PCI root lock")
            .insert(address, function)
            .map_err(Error::PciRoot)?;

        self.next_device += 1;
        // Only a device with INTx has a routing entry (the DSDT's _PRT) and uses up a GSI.
        let Some(gsi) = intx_gsi else {
            return Ok(None);
        };
        let info = arch::x86_64::PciFunctionInfo {
            device: address.device,
            function: address.function,
            gsi,
        };
        self.functions.push(info);
        self.irq += 1;
        // GSI 9 carries the ACPI SCI (local patch, see VENDOR.md).
        if self.irq == arch::x86_64::layout::SCI_GSI {
            self.irq += 1;
        }
        Ok(Some(info))
    }

    /// The host bridge as the ACPI tables describe it; `shm_window` declares the
    /// shared-memory span as one of its windows.
    pub fn acpi_info(&self, shm_window: bool) -> arch::x86_64::PciHostInfo {
        arch::x86_64::PciHostInfo {
            ecam_base: arch::x86_64::layout::PCI_ECAM_START,
            bar_start: arch::x86_64::layout::PCI_BAR_START,
            bar_size: arch::x86_64::layout::PCI_BAR_END - arch::x86_64::layout::PCI_BAR_START,
            functions: self.functions.clone(),
            shm_window,
        }
    }
}
