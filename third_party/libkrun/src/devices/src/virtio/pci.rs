// Copyright 2024 The virtkit Authors.
// SPDX-License-Identifier: Apache-2.0
//
// Modern virtio-pci transport over legacy INTx. Wraps a `VirtioDevice` (the
// same trait `MmioTransport` wraps) and serves the modern virtio-pci register
// layout out of a single 64-bit memory BAR (BAR0):
//
//   common config @ 0x0000   (VirtioPciCommonConfig, adapted from cloud-hypervisor)
//   ISR           @ 0x2000   (read -> return + clear the pending bits)
//   device config @ 0x4000   (delegated to VirtioDevice::read_config/write_config)
//   notify        @ 0x6000   (write kicks the selected queue's eventfd)
//
// A device that exposes a shared-memory region (virtio-fs's DAX window) also
// gets a second 64-bit memory BAR (BAR2) covering it, advertised by a
// `virtio_pci_cap64` shared-memory capability.
//
// Interrupts are delivered over the device's INTx line: on a used-queue the ISR
// bit 0 is set and the INTx GSI asserted (reusing `InterruptTransport`, which
// already sets the status word and pokes the irqchip via an eventfd registered
// against the GSI with `register_irqfd`). A guest that enables MSI-X instead gets
// per-vector delivery; INTx is the fallback when it does not.
//
// The companion legacy PCI config space (header, BARs, capabilities pointing
// into this BAR) is built by `pci_config_space()` and lives on the `PciBus`.

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use utils::byte_order;
use utils::eventfd::{EventFd, EFD_NONBLOCK};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{GuestAddress, GuestMemoryMmap};

use super::device::{DeviceQueue, QueueConfig, VirtioDevice};
use super::mmio::{CreateMmioTransportError, InterruptTransport};
use super::msix::{MsixConfig, MSIX_TABLE_ENTRY_SIZE, NUM_VECTORS};
use super::queue::Queue;
use super::{device_status, TYPE_BLOCK, TYPE_NET};
use crate::bus::BusDevice;
#[cfg(target_os = "linux")]
use crate::legacy::GsiRoutes;
use crate::legacy::{IrqChip, PciDevice};

/// virtio PCI vendor id.
const VIRTIO_PCI_VENDOR_ID: u16 = 0x1af4;
/// Modern virtio device id base; add the virtio device type to get the id.
const VIRTIO_PCI_DEVICE_ID_BASE: u16 = 0x1040;

/// BAR0 layout offsets and sizes (8KiB-aligned, mirroring cloud-hypervisor).
const COMMON_CONFIG_BAR_OFFSET: u64 = 0x0000;
const COMMON_CONFIG_SIZE: u64 = 56;
const ISR_CONFIG_BAR_OFFSET: u64 = 0x2000;
const ISR_CONFIG_SIZE: u64 = 1;
const DEVICE_CONFIG_BAR_OFFSET: u64 = 0x4000;
const DEVICE_CONFIG_SIZE: u64 = 0x1000;
const NOTIFICATION_BAR_OFFSET: u64 = 0x6000;
const NOTIFICATION_SIZE: u64 = 0x1000;
/// MSI-X table and PBA regions inside BAR0 (both within CAPABILITY_BAR_SIZE).
const MSIX_TABLE_BAR_OFFSET: u64 = 0x8000;
const MSIX_PBA_BAR_OFFSET: u64 = 0x4_8000;
/// The BAR size must be a power of two large enough to cover all regions.
pub const CAPABILITY_BAR_SIZE: u64 = 0x8_0000;

/// A dword per notification address (queue index i notifies at
/// NOTIFICATION_BAR_OFFSET + i * NOTIFY_OFF_MULTIPLIER).
const NOTIFY_OFF_MULTIPLIER: u32 = 4;

/// virtio PCI capability `cfg_type` values (virtio spec 4.1.4).
const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
const VIRTIO_PCI_CAP_SHARED_MEMORY_CFG: u8 = 8;

/// BAR number holding a device's shared-memory region (a 64-bit pair, so BAR2 + BAR3).
/// BAR0/BAR1 are the capability window.
const SHM_BAR: usize = 2;
/// virtio-fs shared-memory id of the DAX window (virtio spec 5.11.2). The only
/// shared-memory region any device here exposes.
const VIRTIO_FS_SHMCAP_ID_CACHE: u8 = 0;

/// Modern virtio-pci common configuration negotiation state (virtio spec
/// 4.1.4.3). Semantics adapted from cloud-hypervisor's `VirtioPciCommonConfig`,
/// mapped onto libkrun's `Queue`/`VirtioDevice`.
struct CommonConfig {
    device_feature_select: u32,
    driver_feature_select: u32,
    driver_status: u8,
    queue_select: u16,
    /// MSI-X vector selected for config-change interrupts (common-config 0x10).
    /// 0xffff (`VIRTIO_MSI_NO_VECTOR`) until the driver assigns one. Recorded for
    /// driver compatibility but not consulted for delivery: this transport uses a
    /// fixed two-vector model (vector 0 config, vector 1 shared by all queues).
    msix_config: u16,
    /// MSI-X vector selected per virtqueue (common-config 0x1a, indexed by the
    /// selected queue). 0xffff until the driver assigns one. Like `msix_config`,
    /// recorded but not consulted — every queue shares the one queue vector.
    queue_msix_vector: Vec<u16>,
}

impl CommonConfig {
    fn new(num_queues: usize) -> Self {
        CommonConfig {
            device_feature_select: 0,
            driver_feature_select: 0,
            driver_status: 0,
            queue_select: 0,
            msix_config: 0xffff,
            queue_msix_vector: vec![0xffff; num_queues],
        }
    }
}

/// A snapshot of a virtqueue's programmed registers (max/selected size, ready
/// flag, ring addresses). The transport hands the live `Queue`s to the device on
/// activation (which then owns them), so it keeps this per-queue snapshot
/// resident to answer post-`DRIVER_OK` reads of the common-config queue fields
/// (0x18/0x1c/0x20-0x34) coherently. Mirrors the intent of cloud-hypervisor's
/// resident `queues` on the transport.
#[derive(Clone, Copy)]
struct QueueState {
    max_size: u16,
    size: u16,
    ready: bool,
    desc_table: GuestAddress,
    avail_ring: GuestAddress,
    used_ring: GuestAddress,
}

impl QueueState {
    fn new(max_size: u16) -> Self {
        QueueState {
            max_size,
            size: 0,
            ready: false,
            desc_table: GuestAddress(0),
            avail_ring: GuestAddress(0),
            used_ring: GuestAddress(0),
        }
    }
}

/// Modern virtio-pci transport for a wrapped virtio device, over INTx.
pub struct VirtioPciDevice {
    device: Arc<Mutex<dyn VirtioDevice>>,
    mem: GuestMemoryMmap,

    common_config: CommonConfig,

    // Live queues owned by the transport during negotiation; moved to the device
    // on activation (`None` afterwards). `queue_state` mirrors their programmed
    // registers and stays resident so common-config reads remain coherent once
    // the queues have been handed off.
    queues: Option<Vec<Queue>>,
    queue_state: Vec<QueueState>,
    queue_evts: Vec<Arc<EventFd>>,
    queue_config: Vec<QueueConfig>,

    interrupt: InterruptTransport,
    device_activated: bool,

    /// MSI-X table / PBA state, shared with the `InterruptTransport` (for
    /// delivery) and with the PCI config space (for message-control writes).
    msix: Arc<Mutex<MsixConfig>>,
}

impl VirtioPciDevice {
    /// Construct a virtio-pci transport. The interrupt is delivered over the
    /// INTx line whose eventfd/GSI wiring is set up by the caller (via
    /// `interrupt_evt()` + `set_irq_line()`).
    pub fn new(
        mem: GuestMemoryMmap,
        intc: IrqChip,
        device: Arc<Mutex<dyn VirtioDevice>>,
    ) -> Result<Self, CreateMmioTransportError> {
        let locked = device
            .try_lock()
            .expect("Mutex of VirtioDevice should not be locked when calling VirtioPciDevice::new");
        let log_target = format!("virtio-pci[{}]", locked.device_name());
        let queue_config: Vec<QueueConfig> = locked.queue_config().to_vec();
        drop(locked);

        let queues: Vec<Queue> = queue_config.iter().map(|c| Queue::new(c.size)).collect();
        let queue_state = queues
            .iter()
            .map(|q| QueueState::new(q.get_max_size()))
            .collect();
        let mut queue_evts = Vec::with_capacity(queue_config.len());
        for _ in &queue_config {
            queue_evts.push(Arc::new(
                EventFd::new(EFD_NONBLOCK)
                    .map_err(CreateMmioTransportError::CreateInterruptEventFd)?,
            ));
        }

        let interrupt = InterruptTransport::new(intc, log_target)?;
        let msix = Arc::new(Mutex::new(MsixConfig::new()));
        interrupt.set_msix(msix.clone());

        Ok(VirtioPciDevice {
            device,
            mem,
            common_config: CommonConfig::new(queue_config.len()),
            queues: Some(queues),
            queue_state,
            queue_evts,
            queue_config,
            interrupt,
            device_activated: false,
            msix,
        })
    }

    /// The wrapped virtio device type (used as the device-manager info key).
    pub fn device_type_id(&self) -> u32 {
        self.device.lock().unwrap().device_type()
    }

    /// The eventfd asserted to raise the device's INTx line. The caller must
    /// register it against the INTx GSI with `KVM_IRQFD`.
    pub fn interrupt_evt(&self) -> &EventFd {
        self.interrupt.event()
    }

    /// Bind the device's INTx GSI (the `interrupt_line` also advertised in the
    /// PCI config space). Must be called before activation.
    pub fn set_irq_line(&mut self, irq: u32) {
        self.interrupt.set_irq_line(irq);
    }

    /// The queue notification eventfds, in queue order, for ioeventfd
    /// registration. Notifying queue `i` writes `queue_evts()[i]`.
    pub fn queue_evts(&self) -> &[Arc<EventFd>] {
        &self.queue_evts
    }

    /// Offset within BAR0 at which queue `i` is notified.
    pub fn queue_notify_offset(i: usize) -> u64 {
        NOTIFICATION_BAR_OFFSET + i as u64 * u64::from(NOTIFY_OFF_MULTIPLIER)
    }

    /// The per-vector MSI-X eventfds, in vector order, for the device manager to
    /// register as `KVM_IRQFD`s against the assigned MSI GSIs.
    pub fn vector_irqfds(&self) -> Vec<Arc<EventFd>> {
        self.msix.lock().unwrap().vector_irqfds()
    }

    /// Assign the KVM MSI GSIs for the MSI-X vectors (vector order).
    pub fn set_msix_gsis(&self, gsis: &[u32]) {
        let mut msix = self.msix.lock().unwrap();
        for (i, &gsi) in gsis.iter().enumerate() {
            msix.set_gsi(i, gsi);
        }
    }

    /// Attach the shared KVM GSI routing manager to the MSI-X config.
    #[cfg(target_os = "linux")]
    pub fn set_msix_routes(&self, routes: Arc<Mutex<GsiRoutes>>) {
        self.msix.lock().unwrap().set_routes(routes);
    }

    /// Build the legacy PCI config space (header + BARs + virtio capabilities)
    /// describing this transport. `bar_base` is the assigned BAR0 guest-physical
    /// base; `interrupt_line` the INTx GSI the guest wires to the IOAPIC. A
    /// device with a shared-memory region also gets BAR2 pinned at that region.
    pub fn pci_config_space(&self, bar_base: u64, interrupt_line: u8) -> PciDevice {
        let device_type = self.device.lock().unwrap().device_type();
        let device_id = VIRTIO_PCI_DEVICE_ID_BASE + device_type as u16;

        // Class/subclass per device type (virtio spec / PCI class codes).
        let (class, subclass) = match device_type {
            TYPE_BLOCK => (0x01, 0x00), // mass storage / SCSI-ish
            TYPE_NET => (0x02, 0x00),   // network / ethernet
            _ => (0xff, 0x00),          // other
        };

        let mut dev = PciDevice::new_endpoint(
            VIRTIO_PCI_VENDOR_ID,
            device_id,
            class,
            subclass,
            0x00,
            1, // interrupt pin A
            interrupt_line,
        );
        dev.set_memory_bar_64(0, bar_base, CAPABILITY_BAR_SIZE);

        // The four modern virtio-pci capabilities pointing into BAR0. Each body
        // is the `struct virtio_pci_cap` from `cap_len` onwards (the id + next
        // bytes are prepended by `add_vendor_capability`).
        dev.add_vendor_capability(&virtio_pci_cap(
            VIRTIO_PCI_CAP_COMMON_CFG,
            COMMON_CONFIG_BAR_OFFSET as u32,
            COMMON_CONFIG_SIZE as u32,
        ));
        dev.add_vendor_capability(&virtio_pci_cap(
            VIRTIO_PCI_CAP_ISR_CFG,
            ISR_CONFIG_BAR_OFFSET as u32,
            ISR_CONFIG_SIZE as u32,
        ));
        dev.add_vendor_capability(&virtio_pci_cap(
            VIRTIO_PCI_CAP_DEVICE_CFG,
            DEVICE_CONFIG_BAR_OFFSET as u32,
            DEVICE_CONFIG_SIZE as u32,
        ));
        dev.add_vendor_capability(&virtio_pci_notify_cap(
            NOTIFICATION_BAR_OFFSET as u32,
            NOTIFICATION_SIZE as u32,
            NOTIFY_OFF_MULTIPLIER,
        ));

        // MSI-X capability: table and PBA both in BAR0 (BIR 0). Attach the shared
        // `MsixConfig` so config-space message-control writes reach it.
        dev.add_msix_capability(
            MSIX_TABLE_BAR_OFFSET as u32,
            MSIX_PBA_BAR_OFFSET as u32,
            NUM_VECTORS,
            self.msix.clone(),
        );

        // Shared-memory region (virtio-fs's DAX window), if the device has one:
        // a second 64-bit memory BAR covering it plus the capability pointing
        // there. The BAR carries the guest-physical address the region was
        // registered with KVM at, and the guest is expected to leave it there —
        // the window is guest memory, not an emulated MMIO range, so a BAR write
        // that moved it would hand the fuse driver an address with no memslot
        // behind it. Nothing enforces that; the DSDT declaring the span as a
        // host-bridge window is what keeps Linux from reassigning it, and
        // `ShmManager` sizes and aligns the region so it is a valid BAR (power
        // of two, naturally aligned).
        if let Some(shm) = self.device.lock().unwrap().shm_region() {
            let size = shm.size as u64;
            dev.set_memory_bar_64(SHM_BAR, shm.guest_addr, size);
            dev.add_vendor_capability(&virtio_pci_cap64(
                VIRTIO_PCI_CAP_SHARED_MEMORY_CFG,
                SHM_BAR as u8,
                VIRTIO_FS_SHMCAP_ID_CACHE,
                0,
                size,
            ));
        }

        dev
    }

    fn locked_device(&self) -> std::sync::MutexGuard<'_, dyn VirtioDevice + 'static> {
        self.device.lock().expect("Poisoned device lock")
    }

    /// Read the selected queue's snapshot (resident across activation).
    fn with_queue<U, F: FnOnce(&QueueState) -> U>(&self, d: U, f: F) -> U {
        self.queue_state
            .get(self.common_config.queue_select as usize)
            .map_or(d, f)
    }

    /// Mutate the selected queue: update the resident snapshot and, while the
    /// live queues are still owned by the transport (pre-activation), the queue
    /// itself. `f` receives the live `Queue` when available so the same closure
    /// programs both.
    fn with_queue_mut<F: FnOnce(&mut Queue)>(&mut self, f: F) {
        let idx = self.common_config.queue_select as usize;
        if let Some(q) = self.queues.as_mut().and_then(|qs| qs.get_mut(idx)) {
            f(q);
            if let Some(state) = self.queue_state.get_mut(idx) {
                state.size = q.size;
                state.ready = q.ready;
                state.desc_table = q.desc_table;
                state.avail_ring = q.avail_ring;
                state.used_ring = q.used_ring;
            }
        }
    }

    fn activate(&mut self) {
        if self.device_activated {
            return;
        }
        let Some(queues) = self.queues.take() else {
            return;
        };
        let mut device_queues: Vec<DeviceQueue> = queues
            .into_iter()
            .zip(self.queue_evts.iter().cloned())
            .map(|(queue, event)| DeviceQueue::new(queue, event))
            .collect();

        // Propagate the negotiated VIRTIO_F_RING_EVENT_IDX to each queue, so the
        // device and driver agree on used/avail-ring notification suppression
        // (mirrors MmioTransport::activate). Without this the guest can miss
        // completions after the first request.
        let event_idx_enabled =
            (self.locked_device().acked_features() & (1 << VIRTIO_RING_F_EVENT_IDX)) != 0;
        for dq in &mut device_queues {
            dq.queue.set_event_idx(event_idx_enabled);
        }

        let result =
            self.locked_device()
                .activate(self.mem.clone(), self.interrupt.clone(), device_queues);
        match result {
            Ok(()) => self.device_activated = true,
            Err(_) => error!("virtio-pci: failed to activate device"),
        }
    }

    fn set_driver_status(&mut self, status: u8) {
        self.common_config.driver_status = status;
        let ready = (device_status::ACKNOWLEDGE
            | device_status::DRIVER
            | device_status::FEATURES_OK
            | device_status::DRIVER_OK) as u8;
        if status & (device_status::FAILED as u8) == 0 && status == ready && !self.device_activated
        {
            self.activate();
        }
        if status == device_status::INIT as u8 {
            // Reset requested by the driver: recreate queues for a fresh cycle.
            if self.device_activated {
                self.locked_device().reset();
            }
            self.device_activated = false;
            let queues: Vec<Queue> = self
                .queue_config
                .iter()
                .map(|c| Queue::new(c.size))
                .collect();
            self.queue_state = queues
                .iter()
                .map(|q| QueueState::new(q.get_max_size()))
                .collect();
            self.queues = Some(queues);
            self.common_config = CommonConfig::new(self.queue_config.len());
        }
    }

    // --- BAR0 region handlers ------------------------------------------------

    fn read_common_config(&self, offset: u64, data: &mut [u8]) {
        let v: u64 = match (offset, data.len()) {
            (0x00, 4) => self.common_config.device_feature_select as u64,
            (0x04, 4) => {
                // The PCI transport is modern-only and each device already
                // advertises VIRTIO_F_VERSION_1 in its feature bits, so the page
                // is returned as-is (no extra OR).
                let features = self.locked_device().avail_features();
                let sel = self.common_config.device_feature_select;
                if sel < 2 {
                    (features >> (sel * 32)) as u32 as u64
                } else {
                    0
                }
            }
            (0x08, 4) => self.common_config.driver_feature_select as u64,
            (0x0c, 4) => 0, // driver_feature is write-only from the driver's view
            (0x10, 2) => u64::from(self.common_config.msix_config),
            (0x12, 2) => self.queue_state.len() as u64,
            (0x14, 1) => self.common_config.driver_status as u64,
            (0x15, 1) => u64::from(self.interrupt.config_generation()),
            (0x16, 2) => self.common_config.queue_select as u64,
            // queue_size: advertise the device max until the driver selects a
            // smaller size (a fresh queue has size 0, max_size = the device max).
            (0x18, 2) => {
                self.with_queue(0, |q| if q.size == 0 { q.max_size } else { q.size }) as u64
            }
            (0x1a, 2) => u64::from(
                self.common_config
                    .queue_msix_vector
                    .get(self.common_config.queue_select as usize)
                    .copied()
                    .unwrap_or(0xffff),
            ),
            (0x1c, 2) => u64::from(self.with_queue(false, |q| q.ready)),
            (0x1e, 2) => self.common_config.queue_select as u64, // queue_notify_off
            (0x20, 4) => self.with_queue(0, |q| q.desc_table.0 & 0xffff_ffff),
            (0x24, 4) => self.with_queue(0, |q| q.desc_table.0 >> 32),
            (0x28, 4) => self.with_queue(0, |q| q.avail_ring.0 & 0xffff_ffff),
            (0x2c, 4) => self.with_queue(0, |q| q.avail_ring.0 >> 32),
            (0x30, 4) => self.with_queue(0, |q| q.used_ring.0 & 0xffff_ffff),
            (0x34, 4) => self.with_queue(0, |q| q.used_ring.0 >> 32),
            _ => {
                warn!(
                    "virtio-pci: invalid common cfg read 0x{offset:x} len {}",
                    data.len()
                );
                0
            }
        };
        write_value(data, v);
    }

    fn write_common_config(&mut self, offset: u64, data: &[u8]) {
        let v = read_value(data);
        match (offset, data.len()) {
            (0x00, 4) => self.common_config.device_feature_select = v as u32,
            (0x08, 4) => self.common_config.driver_feature_select = v as u32,
            (0x0c, 4) => {
                let sel = self.common_config.driver_feature_select;
                if sel < 2 {
                    self.locked_device().ack_features_by_page(sel, v as u32);
                }
            }
            (0x14, 1) => self.set_driver_status(v as u8),
            (0x16, 2) => self.common_config.queue_select = v as u16,
            (0x18, 2) => self.with_queue_mut(|q| q.size = v as u16),
            (0x1c, 2) => self.with_queue_mut(|q| q.ready = v == 1),
            (0x20, 4) => self.with_queue_mut(|q| set_lo(&mut q.desc_table, v as u32)),
            (0x24, 4) => self.with_queue_mut(|q| set_hi(&mut q.desc_table, v as u32)),
            (0x28, 4) => self.with_queue_mut(|q| set_lo(&mut q.avail_ring, v as u32)),
            (0x2c, 4) => self.with_queue_mut(|q| set_hi(&mut q.avail_ring, v as u32)),
            (0x30, 4) => self.with_queue_mut(|q| set_lo(&mut q.used_ring, v as u32)),
            (0x34, 4) => self.with_queue_mut(|q| set_hi(&mut q.used_ring, v as u32)),
            // msix_config: the driver's selected config-change vector.
            (0x10, 2) => self.common_config.msix_config = v as u16,
            // queue_msix_vector: the driver's selected vector for the currently
            // selected queue.
            (0x1a, 2) => {
                let idx = self.common_config.queue_select as usize;
                if let Some(slot) = self.common_config.queue_msix_vector.get_mut(idx) {
                    *slot = v as u16;
                }
            }
            _ => warn!(
                "virtio-pci: invalid common cfg write 0x{offset:x} len {}",
                data.len()
            ),
        }
    }
}

impl BusDevice for VirtioPciDevice {
    fn read(&mut self, _vcpuid: u64, offset: u64, data: &mut [u8]) {
        match offset {
            o if o < COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE => {
                self.read_common_config(o - COMMON_CONFIG_BAR_OFFSET, data)
            }
            o if (ISR_CONFIG_BAR_OFFSET..ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE).contains(&o) => {
                // Reading the ISR returns the pending bits and clears them.
                if let Some(v) = data.get_mut(0) {
                    *v = self.interrupt.status().swap(0, Ordering::AcqRel) as u8;
                }
            }
            o if (DEVICE_CONFIG_BAR_OFFSET..DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE)
                .contains(&o) =>
            {
                self.locked_device()
                    .read_config(o - DEVICE_CONFIG_BAR_OFFSET, data);
            }
            o if (NOTIFICATION_BAR_OFFSET..NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE)
                .contains(&o) => {}
            o if msix_table_region().contains(&o) => {
                self.msix
                    .lock()
                    .unwrap()
                    .read_table(o - MSIX_TABLE_BAR_OFFSET, data);
            }
            o if o >= MSIX_PBA_BAR_OFFSET => {
                self.msix
                    .lock()
                    .unwrap()
                    .read_pba(o - MSIX_PBA_BAR_OFFSET, data);
            }
            _ => {}
        }
    }

    fn write(&mut self, _vcpuid: u64, offset: u64, data: &[u8]) {
        match offset {
            o if o < COMMON_CONFIG_BAR_OFFSET + COMMON_CONFIG_SIZE => {
                self.write_common_config(o - COMMON_CONFIG_BAR_OFFSET, data)
            }
            o if (ISR_CONFIG_BAR_OFFSET..ISR_CONFIG_BAR_OFFSET + ISR_CONFIG_SIZE).contains(&o) => {}
            o if (DEVICE_CONFIG_BAR_OFFSET..DEVICE_CONFIG_BAR_OFFSET + DEVICE_CONFIG_SIZE)
                .contains(&o) =>
            {
                self.locked_device()
                    .write_config(o - DEVICE_CONFIG_BAR_OFFSET, data);
            }
            o if (NOTIFICATION_BAR_OFFSET..NOTIFICATION_BAR_OFFSET + NOTIFICATION_SIZE)
                .contains(&o) =>
            {
                // The kernel writes the queue index at the notify offset. As a
                // fallback for hosts without ioeventfd, kick the queue directly.
                let idx = (o - NOTIFICATION_BAR_OFFSET) / u64::from(NOTIFY_OFF_MULTIPLIER);
                if let Some(evt) = self.queue_evts.get(idx as usize) {
                    let _ = evt.write(1);
                } else {
                    warn!("virtio-pci: notify to unknown queue {idx}");
                }
            }
            o if msix_table_region().contains(&o) => {
                self.msix
                    .lock()
                    .unwrap()
                    .write_table(o - MSIX_TABLE_BAR_OFFSET, data);
            }
            o if o >= MSIX_PBA_BAR_OFFSET => {
                self.msix
                    .lock()
                    .unwrap()
                    .write_pba(o - MSIX_PBA_BAR_OFFSET, data);
            }
            _ => {}
        }
    }
}

/// The BAR0 byte range covered by the MSI-X table (NUM_VECTORS entries).
fn msix_table_region() -> std::ops::Range<u64> {
    MSIX_TABLE_BAR_OFFSET..MSIX_TABLE_BAR_OFFSET + u64::from(NUM_VECTORS) * MSIX_TABLE_ENTRY_SIZE
}

// --- helpers -----------------------------------------------------------------

fn set_lo(addr: &mut GuestAddress, v: u32) {
    *addr = GuestAddress((addr.0 & !0xffff_ffff) | u64::from(v));
}

fn set_hi(addr: &mut GuestAddress, v: u32) {
    *addr = GuestAddress((addr.0 & 0xffff_ffff) | (u64::from(v) << 32));
}

fn read_value(data: &[u8]) -> u64 {
    match data.len() {
        1 => u64::from(data[0]),
        2 => u64::from(byte_order::read_le_u16(data)),
        4 => u64::from(byte_order::read_le_u32(data)),
        8 => byte_order::read_le_u64(data),
        _ => 0,
    }
}

fn write_value(data: &mut [u8], v: u64) {
    match data.len() {
        1 => data[0] = v as u8,
        2 => byte_order::write_le_u16(data, v as u16),
        4 => byte_order::write_le_u32(data, v as u32),
        8 => byte_order::write_le_u64(data, v),
        _ => {}
    }
}

/// Serialise a `struct virtio_pci_cap` body (from `cap_len` onwards): the 14 bytes
/// cap_len, cfg_type, bar, id, padding[2], offset (le32), length (le32).
/// `add_vendor_capability` prepends the id + next bytes, making the capability 16
/// bytes, which is what `cap_len` reports.
fn virtio_pci_cap_body(cfg_type: u8, bar: u8, id: u8, offset: u32, length: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(14);
    b.push(16); // cap_len
    b.push(cfg_type);
    b.push(bar);
    b.push(id);
    b.extend_from_slice(&[0, 0]); // padding
    b.extend_from_slice(&offset.to_le_bytes());
    b.extend_from_slice(&length.to_le_bytes());
    b
}

/// Serialise a `struct virtio_pci_cap` body for a region in BAR0.
fn virtio_pci_cap(cfg_type: u8, offset: u32, length: u32) -> Vec<u8> {
    virtio_pci_cap_body(cfg_type, 0, 0, offset, length)
}

/// Serialise a `struct virtio_pci_notify_cap` body (the common cap fields plus a
/// trailing le32 `notify_off_multiplier`).
fn virtio_pci_notify_cap(offset: u32, length: u32, multiplier: u32) -> Vec<u8> {
    let mut b = virtio_pci_cap(VIRTIO_PCI_CAP_NOTIFY_CFG, offset, length);
    b[0] = 20; // cap_len
    b.extend_from_slice(&multiplier.to_le_bytes());
    b
}

/// Serialise a `struct virtio_pci_cap64` body: the common cap fields (whose
/// `offset`/`length` carry the low 32 bits) followed by le32 `offset_hi` and
/// `length_hi`. Used for the shared-memory capability, whose region can exceed
/// 4 GiB.
fn virtio_pci_cap64(cfg_type: u8, bar: u8, id: u8, offset: u64, length: u64) -> Vec<u8> {
    let mut b = virtio_pci_cap_body(cfg_type, bar, id, offset as u32, length as u32);
    b[0] = 24; // cap_len
    b.extend_from_slice(&((offset >> 32) as u32).to_le_bytes());
    b.extend_from_slice(&((length >> 32) as u32).to_le_bytes());
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `struct virtio_pci_cap` body, as the spec lays it out from `cap_len`.
    #[test]
    fn cap_body_layout() {
        let b = virtio_pci_cap(VIRTIO_PCI_CAP_COMMON_CFG, 0x1234, 56);
        assert_eq!(b.len(), 14);
        assert_eq!(b[0], 16); // cap_len, counting the id+next bytes
        assert_eq!(b[1], VIRTIO_PCI_CAP_COMMON_CFG);
        assert_eq!(b[2], 0); // BAR0
        assert_eq!(&b[6..10], &0x1234u32.to_le_bytes());
        assert_eq!(&b[10..14], &56u32.to_le_bytes());
    }

    /// The notify capability appends `notify_off_multiplier` and grows `cap_len`.
    #[test]
    fn notify_cap_appends_multiplier() {
        let b = virtio_pci_notify_cap(NOTIFICATION_BAR_OFFSET as u32, 0x1000, 4);
        assert_eq!(b.len(), 18);
        assert_eq!(b[0], 20);
        assert_eq!(b[1], VIRTIO_PCI_CAP_NOTIFY_CFG);
        assert_eq!(&b[14..18], &4u32.to_le_bytes());
    }

    /// The shared-memory capability is a `virtio_pci_cap64`: the high halves of
    /// offset and length follow the common fields, so a window larger than 4 GiB
    /// is described exactly.
    #[test]
    fn shm_cap64_carries_high_halves() {
        let size: u64 = 8 << 30;
        let b = virtio_pci_cap64(
            VIRTIO_PCI_CAP_SHARED_MEMORY_CFG,
            SHM_BAR as u8,
            VIRTIO_FS_SHMCAP_ID_CACHE,
            0,
            size,
        );
        assert_eq!(b.len(), 22);
        assert_eq!(b[0], 24); // cap_len
        assert_eq!(b[1], VIRTIO_PCI_CAP_SHARED_MEMORY_CFG);
        assert_eq!(b[2], 2); // BAR2
        assert_eq!(b[3], VIRTIO_FS_SHMCAP_ID_CACHE);
        assert_eq!(&b[6..10], &0u32.to_le_bytes()); // offset lo
        assert_eq!(&b[10..14], &(size as u32).to_le_bytes()); // length lo
        assert_eq!(&b[14..18], &0u32.to_le_bytes()); // offset hi
        assert_eq!(&b[18..22], &((size >> 32) as u32).to_le_bytes()); // length hi
    }
}
