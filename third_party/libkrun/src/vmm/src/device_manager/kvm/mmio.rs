// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::{fmt, io};

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use devices::fdt::DeviceInfoForFDT;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
use devices::legacy::IrqChip;
use devices::{BusDevice, DeviceType};
use kernel::cmdline as kernel_cmdline;
use kvm_ioctls::{IoEventAddress, VmFd};
#[cfg(target_arch = "aarch64")]
use utils::eventfd::EventFd;

/// Errors for MMIO device manager.
#[allow(clippy::enum_variant_names)]
#[derive(Debug)]
pub enum Error {
    /// Failed to create MmioTransport
    CreateMmioTransport(devices::virtio::CreateMmioTransportError),
    /// Failed to perform an operation on the bus.
    BusError(devices::BusError),
    /// Appending to kernel command line failed.
    Cmdline(kernel_cmdline::Error),
    /// Failure in creating or cloning an event fd.
    EventFd(io::Error),
    /// No more IRQs are available.
    IrqsExhausted,
    /// No more PCI bus-0 slots are available.
    #[cfg(target_arch = "x86_64")]
    PciSlotsExhausted,
    /// Registering an IO Event failed.
    RegisterIoEvent(kvm_ioctls::Error),
    /// Registering an IRQ FD failed.
    RegisterIrqFd(kvm_ioctls::Error),
    /// The device couldn't be found
    DeviceNotFound,
    /// Failed to update the mmio device.
    UpdateFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::CreateMmioTransport(ref e) => {
                write!(f, "failed to create mmio transport for the device {e}")
            }
            Error::BusError(ref e) => write!(f, "failed to perform bus operation: {e}"),
            Error::Cmdline(ref e) => {
                write!(f, "unable to add device to kernel command line: {e}")
            }
            Error::EventFd(ref e) => write!(f, "failed to create or clone event descriptor: {e}"),
            Error::IrqsExhausted => write!(f, "no more IRQs are available"),
            #[cfg(target_arch = "x86_64")]
            Error::PciSlotsExhausted => write!(f, "no more PCI slots are available"),
            Error::RegisterIoEvent(ref e) => write!(f, "failed to register IO event: {e}"),
            Error::RegisterIrqFd(ref e) => write!(f, "failed to register irqfd: {e}"),
            Error::DeviceNotFound => write!(f, "the device couldn't be found"),
            Error::UpdateFailed => write!(f, "failed to update the mmio device"),
        }
    }
}

impl From<devices::virtio::CreateMmioTransportError> for Error {
    fn from(e: devices::virtio::CreateMmioTransportError) -> Self {
        Self::CreateMmioTransport(e)
    }
}

type Result<T> = ::std::result::Result<T, Error>;

/// This represents the size of the mmio device specified to the kernel as a cmdline option
/// It has to be larger than 0x100 (the offset where the configuration space starts from
/// the beginning of the memory mapped device registers) + the size of the configuration space
/// Currently hardcoded to 4K.
const MMIO_LEN: u64 = 0x1000;

/// Base for virtio-pci BAR windows, placed high in the 32-bit MMIO gap so it
/// never overlaps the low-growing virtio-mmio transport allocations (which
/// start at `arch::MMIO_MEM_START` == 0xd000_0000 and grow upward). Each BAR is
/// `CAPABILITY_BAR_SIZE` and 512KiB-aligned; the gap runs up to 4GiB.
#[cfg(target_arch = "x86_64")]
const PCI_MMIO_BASE: u64 = 0xe000_0000;

/// Upper bound (exclusive) on KVM MSI GSIs used for MSI-X vectors. KVM allows up
/// to 4095 routes; cap well below that to leave head-room for the default
/// IOAPIC/PIC entries and any future use.
#[cfg(target_arch = "x86_64")]
const MSI_GSI_MAX: u32 = 1024;

/// Manages the complexities of registering a MMIO device.
pub struct MMIODeviceManager {
    pub bus: devices::Bus,
    mmio_base: u64,
    irq: u32,
    last_irq: u32,
    id_to_dev_info: HashMap<(DeviceType, String), MMIODeviceInfo>,
    /// Next free base for a virtio-pci BAR window.
    #[cfg(target_arch = "x86_64")]
    pci_mmio_base: u64,
    /// Next free PCI device (slot) number on bus 0. Slot 0 is the host bridge;
    /// virtio-pci endpoints are handed 00:01.0, 00:02.0, … as they register.
    #[cfg(target_arch = "x86_64")]
    next_pci_device_number: u8,
    /// PCI INTx routes as (device number, interrupt pin 1-based, GSI), so the
    /// MP table can emit matching PCI-bus interrupt-source entries.
    #[cfg(target_arch = "x86_64")]
    pci_irqs: Vec<(u8, u8, u32)>,
    /// Shared INTx GSI for all virtio-pci devices. PCI INTx is level-triggered
    /// and shareable, so a single scarce IOAPIC GSI serves every device (KVM
    /// allows multiple irqfds on one GSI). Allocated lazily on the first device.
    #[cfg(target_arch = "x86_64")]
    pci_intx_gsi: Option<u32>,
    /// Next free KVM MSI GSI for MSI-X vectors. Starts at the IOAPIC pin count
    /// (24); MSI GSIs live above the IOAPIC pins and are plentiful (~1000).
    #[cfg(target_arch = "x86_64")]
    next_msi_gsi: u32,
    /// Shared KVM GSI routing manager for MSI-X routes, set by the builder
    /// before any virtio-pci device is registered.
    #[cfg(target_arch = "x86_64")]
    pci_gsi_routes: Option<Arc<Mutex<devices::legacy::GsiRoutes>>>,
}

impl MMIODeviceManager {
    /// Create a new DeviceManager handling mmio devices (virtio net, block).
    pub fn new(mmio_base: &mut u64, irq_interval: (u32, u32)) -> MMIODeviceManager {
        if cfg!(any(target_arch = "aarch64", target_arch = "riscv64")) {
            *mmio_base += MMIO_LEN;
        }
        MMIODeviceManager {
            mmio_base: *mmio_base,
            irq: irq_interval.0,
            last_irq: irq_interval.1,
            bus: devices::Bus::new(),
            id_to_dev_info: HashMap::new(),
            #[cfg(target_arch = "x86_64")]
            pci_mmio_base: PCI_MMIO_BASE,
            #[cfg(target_arch = "x86_64")]
            next_pci_device_number: 1,
            #[cfg(target_arch = "x86_64")]
            pci_irqs: Vec::new(),
            #[cfg(target_arch = "x86_64")]
            pci_intx_gsi: None,
            #[cfg(target_arch = "x86_64")]
            next_msi_gsi: arch::x86_64::layout::IOAPIC_NUM_PINS,
            #[cfg(target_arch = "x86_64")]
            pci_gsi_routes: None,
        }
    }

    /// Advance the IOAPIC-pin cursor, skipping the pin reserved for the ACPI SCI
    /// (x86_64 only).
    fn advance_irq(&mut self) {
        self.irq += 1;
        #[cfg(target_arch = "x86_64")]
        if self.irq == arch::x86_64::layout::SCI_GSI {
            self.irq += 1;
        }
    }

    /// PCI INTx routing table collected during device registration, as
    /// (device number, interrupt pin, GSI). Consumed when building the MP table.
    #[cfg(target_arch = "x86_64")]
    pub fn pci_irqs(&self) -> &[(u8, u8, u32)] {
        &self.pci_irqs
    }

    /// Register a MMIO IOAPIC device.
    #[cfg(target_arch = "x86_64")]
    pub fn register_mmio_ioapic(
        &mut self,
        intc: Option<Arc<Mutex<devices::legacy::IrqChipDevice>>>,
    ) -> Result<()> {
        if let Some(intc) = intc {
            let (addr, size) = {
                let intc = intc.lock().unwrap();
                (intc.get_mmio_addr(), intc.get_mmio_size())
            };
            self.bus.insert(intc, addr, size).map_err(Error::BusError)?;
        }

        Ok(())
    }

    /// Register an already created MMIO device to be used via MMIO transport.
    pub fn register_mmio_device(
        &mut self,
        vm: &VmFd,
        mut mmio_device: devices::virtio::MmioTransport,
        type_id: u32,
        device_id: String,
    ) -> Result<(u64, u32)> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        for (i, queue_evt) in mmio_device.queue_evts().iter().enumerate() {
            let io_addr = IoEventAddress::Mmio(
                self.mmio_base + u64::from(devices::virtio::NOTIFY_REG_OFFSET),
            );

            vm.register_ioevent(queue_evt, &io_addr, i as u32)
                .map_err(Error::RegisterIoEvent)?;
        }

        vm.register_irqfd(mmio_device.interrupt_evt(), self.irq)
            .map_err(Error::RegisterIrqFd)?;

        mmio_device.set_irq_line(self.irq);

        self.bus
            .insert(Arc::new(Mutex::new(mmio_device)), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;
        let ret = (self.mmio_base, self.irq);
        self.id_to_dev_info.insert(
            (DeviceType::Virtio(type_id), device_id),
            MMIODeviceInfo {
                addr: self.mmio_base,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );
        self.mmio_base += MMIO_LEN;
        self.advance_irq();

        Ok(ret)
    }

    /// Attach the shared KVM GSI routing manager, used to install MSI-X routes.
    /// Must be called by the builder before any virtio-pci device is registered.
    #[cfg(target_arch = "x86_64")]
    pub fn set_pci_gsi_routes(&mut self, routes: Arc<Mutex<devices::legacy::GsiRoutes>>) {
        self.pci_gsi_routes = Some(routes);
    }

    /// Register a virtio-pci device: allocate a bus-0 slot, wire the device's
    /// INTx eventfd to the shared INTx GSI, allocate MSI-X GSIs and register the
    /// per-vector irqfds, register the per-queue notify ioeventfds inside the
    /// device's BAR0 window, place the BAR0 MMIO region on the bus, and return
    /// the assigned (device_number, bar_base, intx_gsi). The caller adds the
    /// returned config space to the `PciBus` at `device_number`.
    ///
    /// All virtio-pci devices share one level-triggered, shareable INTx GSI (KVM
    /// allows multiple irqfds per GSI), so bus-0 slots (max 31), not GSIs, are
    /// the limiting resource. MSI-X vectors draw from the plentiful KVM MSI GSI
    /// pool above the IOAPIC pins.
    #[cfg(target_arch = "x86_64")]
    pub fn register_virtio_pci_device(
        &mut self,
        vm: &VmFd,
        device: devices::virtio::VirtioPciDevice,
        type_id: u32,
        device_id: String,
    ) -> Result<(u8, u64, u32, Arc<Mutex<devices::virtio::VirtioPciDevice>>)> {
        use devices::virtio::CAPABILITY_BAR_SIZE;

        // Bus 0 has 32 slots; slot 0 is the host bridge, so endpoints occupy
        // 1..=31. Slots, not GSIs, are the limiting resource now.
        if self.next_pci_device_number > 31 {
            return Err(Error::PciSlotsExhausted);
        }
        let device_number = self.next_pci_device_number;
        let bar_base = self.pci_mmio_base;

        let mut device = device;

        // INTx: allocate the shared GSI once (from the scarce IOAPIC pool) and
        // reuse it for every virtio-pci device. PCI INTx is shareable.
        let intx_gsi = match self.pci_intx_gsi {
            Some(gsi) => gsi,
            None => {
                if self.irq > self.last_irq {
                    return Err(Error::IrqsExhausted);
                }
                let gsi = self.irq;
                self.advance_irq();
                self.pci_intx_gsi = Some(gsi);
                gsi
            }
        };
        device.set_irq_line(intx_gsi);

        // MSI-X: allocate one KVM MSI GSI per vector and register its irqfd.
        let vector_irqfds = device.vector_irqfds();
        let num_vectors = vector_irqfds.len() as u32;
        if self.next_msi_gsi + num_vectors > MSI_GSI_MAX {
            return Err(Error::IrqsExhausted);
        }
        let mut msi_gsis = Vec::with_capacity(vector_irqfds.len());
        for (i, evt) in vector_irqfds.iter().enumerate() {
            let gsi = self.next_msi_gsi + i as u32;
            vm.register_irqfd(evt, gsi).map_err(Error::RegisterIrqFd)?;
            msi_gsis.push(gsi);
        }
        self.next_msi_gsi += num_vectors;
        device.set_msix_gsis(&msi_gsis);
        if let Some(routes) = &self.pci_gsi_routes {
            device.set_msix_routes(routes.clone());
        }

        // Per-queue notify: each queue's eventfd fires on a write to its own
        // address inside the notify region (address-based, no datamatch).
        for (i, queue_evt) in device.queue_evts().iter().enumerate() {
            let notify_addr = bar_base + devices::virtio::VirtioPciDevice::queue_notify_offset(i);
            let io_addr = IoEventAddress::Mmio(notify_addr);
            vm.register_ioevent(queue_evt, &io_addr, kvm_ioctls::NoDatamatch)
                .map_err(Error::RegisterIoEvent)?;
        }

        // INTx: the device asserts the shared GSI by writing this eventfd.
        vm.register_irqfd(device.interrupt_evt(), intx_gsi)
            .map_err(Error::RegisterIrqFd)?;

        let device = Arc::new(Mutex::new(device));
        self.bus
            .insert(device.clone(), bar_base, CAPABILITY_BAR_SIZE)
            .map_err(Error::BusError)?;

        self.id_to_dev_info.insert(
            (DeviceType::Virtio(type_id), device_id),
            MMIODeviceInfo {
                addr: bar_base,
                _len: CAPABILITY_BAR_SIZE,
                _irq: intx_gsi,
            },
        );

        // Record the shared INTx route (interrupt pin A == 1) for the MP table.
        self.pci_irqs.push((device_number, 1, intx_gsi));

        self.pci_mmio_base += CAPABILITY_BAR_SIZE;
        self.next_pci_device_number += 1;

        Ok((device_number, bar_base, intx_gsi, device))
    }

    /// Append a registered MMIO device to the kernel cmdline.
    #[cfg(target_arch = "x86_64")]
    pub fn add_device_to_cmdline(
        &mut self,
        cmdline: &mut kernel_cmdline::Cmdline,
        mmio_base: u64,
        irq: u32,
    ) -> Result<()> {
        // as per doc, [virtio_mmio.]device=<size>@<baseaddr>:<irq> needs to be appended
        // to kernel commandline for virtio mmio devices to get recognized
        // the size parameter has to be transformed to KiB, so dividing hexadecimal value in
        // bytes to 1024; further, the '{}' formatting rust construct will automatically
        // transform it to decimal
        cmdline
            .insert(
                "virtio_mmio.device",
                &format!("{}K@0x{:08x}:{}", MMIO_LEN / 1024, mmio_base, irq),
            )
            .map_err(Error::Cmdline)
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Register an early console at some MMIO address.
    pub fn register_mmio_serial(
        &mut self,
        vm: &VmFd,
        cmdline: &mut kernel_cmdline::Cmdline,
        intc: IrqChip,
        serial: Arc<Mutex<devices::legacy::Serial>>,
    ) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        vm.register_irqfd(serial.lock().unwrap().interrupt_evt(), self.irq)
            .map_err(Error::RegisterIrqFd)?;

        {
            let mut serial = serial.lock().unwrap();
            serial.set_intc(intc);
            serial.set_irq_line(self.irq);
        }

        self.bus
            .insert(serial, self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        cmdline
            .insert(
                "earlycon",
                #[cfg(target_arch = "aarch64")]
                &format!("pl011,mmio32,0x{:08x}", self.mmio_base),
                #[cfg(target_arch = "riscv64")]
                &format!("uart,mmio,0x{:08x}", self.mmio_base),
            )
            .map_err(Error::Cmdline)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::Serial, DeviceType::Serial.to_string()),
            MMIODeviceInfo {
                addr: ret,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.advance_irq();

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    /// Register a MMIO RTC device.
    pub fn register_mmio_rtc(&mut self, vm: &VmFd) -> Result<()> {
        if self.irq > self.last_irq {
            return Err(Error::IrqsExhausted);
        }

        // Attaching the RTC device.
        let rtc_evt = EventFd::new(utils::eventfd::EFD_NONBLOCK).map_err(Error::EventFd)?;
        let device = devices::legacy::RTC::new(rtc_evt.try_clone().map_err(Error::EventFd)?);
        vm.register_irqfd(&rtc_evt, self.irq)
            .map_err(Error::RegisterIrqFd)?;

        self.bus
            .insert(Arc::new(Mutex::new(device)), self.mmio_base, MMIO_LEN)
            .map_err(Error::BusError)?;

        let ret = self.mmio_base;
        self.id_to_dev_info.insert(
            (DeviceType::RTC, "rtc".to_string()),
            MMIODeviceInfo {
                addr: ret,
                _len: MMIO_LEN,
                _irq: self.irq,
            },
        );

        self.mmio_base += MMIO_LEN;
        self.advance_irq();

        Ok(())
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
    /// Gets the information of the devices registered up to some point in time.
    pub fn get_device_info(&self) -> &HashMap<(DeviceType, String), MMIODeviceInfo> {
        &self.id_to_dev_info
    }

    /// Gets the the specified device.
    pub fn get_device(
        &self,
        device_type: DeviceType,
        device_id: &str,
    ) -> Option<&Mutex<dyn BusDevice>> {
        if let Some(dev_info) = self
            .id_to_dev_info
            .get(&(device_type, device_id.to_string()))
        {
            if let Some((_, device)) = self.bus.get_device(dev_info.addr) {
                return Some(device);
            }
        }
        None
    }
}

/// Private structure for storing information about the MMIO device registered at some address on the bus.
#[derive(Clone, Debug)]
pub struct MMIODeviceInfo {
    addr: u64,
    _irq: u32,
    _len: u64,
}

#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
impl DeviceInfoForFDT for MMIODeviceInfo {
    fn addr(&self) -> u64 {
        self.addr
    }
    fn irq(&self) -> u32 {
        self._irq
    }
    fn length(&self) -> u64 {
        self._len
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::super::builder;
    use super::*;
    use arch;
    use devices::legacy::DummyIrqChip;
    #[cfg(target_arch = "aarch64")]
    use devices::legacy::KvmGicV3;
    #[cfg(target_arch = "x86_64")]
    use devices::legacy::KvmIoapic;
    use devices::virtio::{
        ActivateResult, DeviceQueue, InterruptTransport, QueueConfig, VirtioDevice,
    };
    use std::sync::Arc;
    use utils::errno;
    use vm_memory::{GuestAddress, GuestMemoryMmap};

    const QUEUE_CONFIG: &[QueueConfig] = &[QueueConfig::new(64)];

    impl MMIODeviceManager {
        fn register_virtio_device(
            &mut self,
            vm: &VmFd,
            guest_mem: GuestMemoryMmap,
            device: Arc<Mutex<dyn devices::virtio::VirtioDevice>>,
            _cmdline: &mut kernel_cmdline::Cmdline,
            type_id: u32,
            device_id: &str,
        ) -> Result<u64> {
            let mmio_device =
                devices::virtio::MmioTransport::new(guest_mem, DummyIrqChip::new().into(), device)
                    .unwrap();
            let (mmio_base, _irq) =
                self.register_mmio_device(vm, mmio_device, type_id, device_id.to_string())?;
            #[cfg(target_arch = "x86_64")]
            self.add_device_to_cmdline(_cmdline, mmio_base, _irq)?;
            Ok(mmio_base)
        }
    }

    #[allow(dead_code)]
    struct DummyDevice {
        dummy: u32,
    }

    impl DummyDevice {
        pub fn new() -> Self {
            DummyDevice { dummy: 0 }
        }
    }

    impl devices::virtio::VirtioDevice for DummyDevice {
        fn avail_features(&self) -> u64 {
            0
        }

        fn acked_features(&self) -> u64 {
            0
        }

        fn set_acked_features(&mut self, _: u64) {}

        fn device_type(&self) -> u32 {
            0
        }

        fn device_name(&self) -> &str {
            "dummy"
        }

        fn queue_config(&self) -> &[QueueConfig] {
            &QUEUE_CONFIG
        }

        fn read_config(&self, offset: u64, data: &mut [u8]) {
            let _ = offset;
            let _ = data;
        }

        fn write_config(&mut self, offset: u64, data: &[u8]) {
            let _ = offset;
            let _ = data;
        }

        fn activate(
            &mut self,
            _mem: GuestMemoryMmap,
            _intc: InterruptTransport,
            _queues: Vec<DeviceQueue>,
        ) -> ActivateResult {
            Ok(())
        }

        fn is_activated(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_register_virtio_device() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        assert!(device_manager
            .register_virtio_device(vm.fd(), guest_mem, dummy, &mut cmdline, 0, "dummy")
            .is_ok());
    }

    #[test]
    fn test_register_too_many_devices() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        #[cfg(target_arch = "x86_64")]
        let _kvmioapic = KvmIoapic::new(vm.fd()).unwrap();
        #[cfg(target_arch = "aarch64")]
        let _gic = KvmGicV3::new(vm.fd(), 1).unwrap();

        let mut cmdline = kernel_cmdline::Cmdline::new(4096);

        // x86_64 reserves one IOAPIC pin for the ACPI SCI (see advance_irq), so one
        // fewer virtio IRQ is allocatable than the raw IRQ_BASE..=IRQ_MAX span.
        let available = arch::IRQ_MAX - arch::IRQ_BASE + 1;
        #[cfg(target_arch = "x86_64")]
        let available = available - 1;

        for _i in 0..available {
            device_manager
                .register_virtio_device(
                    vm.fd(),
                    guest_mem.clone(),
                    Arc::new(Mutex::new(DummyDevice::new())),
                    &mut cmdline,
                    0,
                    "dummy1",
                )
                .unwrap();
        }
        assert_eq!(
            format!(
                "{}",
                device_manager
                    .register_virtio_device(
                        vm.fd(),
                        guest_mem,
                        Arc::new(Mutex::new(DummyDevice::new())),
                        &mut cmdline,
                        0,
                        "dummy2"
                    )
                    .unwrap_err()
            ),
            "no more IRQs are available".to_string()
        );
    }

    #[test]
    fn test_dummy_device() {
        let dummy = DummyDevice::new();
        assert_eq!(dummy.device_type(), 0);
        assert_eq!(dummy.queue_config().len(), QUEUE_CONFIG.len());
    }

    #[test]
    fn test_error_messages() {
        let device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let e = Error::Cmdline(
            cmdline
                .insert(
                    "virtio_mmio=device",
                    &format!(
                        "{}K@0x{:08x}:{}",
                        MMIO_LEN / 1024,
                        device_manager.mmio_base,
                        device_manager.irq
                    ),
                )
                .unwrap_err(),
        );
        assert_eq!(
            format!("{e}"),
            format!(
                "unable to add device to kernel command line: {}",
                kernel_cmdline::Error::HasEquals
            ),
        );
        assert_eq!(
            format!("{}", Error::UpdateFailed),
            "failed to update the mmio device"
        );
        assert_eq!(
            format!("{}", Error::BusError(devices::BusError::Overlap)),
            format!(
                "failed to perform bus operation: {}",
                devices::BusError::Overlap
            )
        );
        assert_eq!(
            format!("{}", Error::IrqsExhausted),
            "no more IRQs are available"
        );
        assert_eq!(
            format!("{}", Error::RegisterIoEvent(errno::Error::new(0))),
            format!("failed to register IO event: {}", errno::Error::new(0))
        );
        assert_eq!(
            format!("{}", Error::RegisterIrqFd(errno::Error::new(0))),
            format!("failed to register irqfd: {}", errno::Error::new(0))
        );
    }

    #[test]
    fn test_device_info() {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let guest_mem =
            GuestMemoryMmap::from_ranges(&[(start_addr1, 0x1000), (start_addr2, 0x1000)]).unwrap();
        let vm = builder::setup_vm(&guest_mem, false).unwrap();
        let mut device_manager =
            MMIODeviceManager::new(&mut 0xd000_0000, (arch::IRQ_BASE, arch::IRQ_MAX));
        let mut cmdline = kernel_cmdline::Cmdline::new(4096);
        let dummy = Arc::new(Mutex::new(DummyDevice::new()));

        let type_id = 0;
        let id = String::from("foo");
        if let Ok(addr) = device_manager.register_virtio_device(
            vm.fd(),
            guest_mem,
            dummy,
            &mut cmdline,
            type_id,
            &id,
        ) {
            assert!(device_manager
                .get_device(DeviceType::Virtio(type_id), &id)
                .is_some());
            assert_eq!(
                addr,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())].addr
            );
            assert_eq!(
                arch::IRQ_BASE,
                device_manager.id_to_dev_info[&(DeviceType::Virtio(type_id), id.clone())]._irq
            );
        }
        let id = "bar";
        assert!(device_manager
            .get_device(DeviceType::Virtio(type_id), id)
            .is_none());
    }
}
