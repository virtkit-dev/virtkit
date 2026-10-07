// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::Error as DeviceError;
use crate::virtio::net::Result;
use crate::virtio::net::{NUM_QUEUES, QUEUE_CONFIG};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    TYPE_NET, VirtioDevice,
};

use super::backend::{ReadError, WriteError};
#[cfg(unix)]
use super::worker::Backend;
use super::worker::NetWorker;

#[cfg(unix)]
use std::os::fd::RawFd;
#[cfg(windows)]
use std::os::windows::io::RawSocket;

use std::cmp;
use std::io::Write;
use std::mem::size_of;
use std::path::PathBuf;
#[cfg(unix)]
use std::thread::JoinHandle;
#[cfg(unix)]
use utils::eventfd::{EFD_NONBLOCK, EventFd};
use virtio_bindings::virtio_net::{VIRTIO_NET_F_MAC, VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_MTU};
use virtio_bindings::virtio_ring::VIRTIO_RING_F_EVENT_IDX;
use vm_memory::{ByteValued, GuestMemoryError, GuestMemoryMmap};

const VIRTIO_F_VERSION_1: u32 = 32;

#[derive(Debug)]
pub enum FrontendError {
    DescriptorChainTooSmall,
    EmptyQueue,
    GuestMemory(GuestMemoryError),
    QueueError(QueueError),
    ReadOnlyDescriptor,
}

#[derive(Debug)]
pub enum RxError {
    Backend(ReadError),
    DeviceError(DeviceError),
}

#[derive(Debug)]
pub enum TxError {
    Backend(WriteError),
    DeviceError(DeviceError),
    QueueError(QueueError),
}

/// The device config space, in the layout the virtio spec fixes for virtio-net. `mtu` is
/// only meaningful to a driver that negotiated `VIRTIO_NET_F_MTU`; it reads it at offset 10.
#[derive(Copy, Clone, Debug, Default)]
#[repr(C, packed)]
struct VirtioNetConfig {
    mac: [u8; 6],
    status: u16,
    max_virtqueue_pairs: u16,
    mtu: u16,
}

// Safe because it only has data and has no implicit padding.
unsafe impl ByteValued for VirtioNetConfig {}

#[derive(Clone)]
pub enum VirtioNetBackend {
    #[cfg(unix)]
    UnixstreamFd(RawFd),
    #[cfg(windows)]
    UnixstreamFd(RawSocket),
    UnixstreamPath(PathBuf),
    #[cfg(unix)]
    UnixgramFd(RawFd),
    #[cfg(unix)]
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
    #[cfg(target_os = "linux")]
    TapFd(std::sync::Arc<std::os::fd::OwnedFd>),
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,

    /// The running worker, which hands its backend back when `worker_stopfd` stops it.
    #[cfg(unix)]
    worker: Option<JoinHandle<Backend>>,
    #[cfg(unix)]
    worker_stopfd: EventFd,
    /// The backend between a reset and the next activation. Opened once: an `*Fd` backend
    /// owns its descriptor, which a second open would take from a closed (or reused) number.
    #[cfg(unix)]
    backend: Option<Backend>,
    /// Whether the backend has been opened; one lost since (its worker panicked) is not
    /// opened again, for that reason.
    #[cfg(unix)]
    backend_opened: bool,
}

/// The features an MTU brings: the MTU itself, and on Unix hosts mergeable receive buffers. The
/// Windows worker never writes `num_buffers`, so it must not offer them.
fn mtu_features() -> u64 {
    let features = 1 << VIRTIO_NET_F_MTU;
    #[cfg(unix)]
    let features = features | (1 << VIRTIO_NET_F_MRG_RXBUF);
    features
}

impl Net {
    /// Create a new virtio network device using the backend.
    ///
    /// `mtu` is the link MTU the driver should adopt (`MIN_MTU..=MAX_MTU`, validated by the
    /// caller), and on Unix hosts brings mergeable receive buffers with it. `None` leaves both features
    /// unadvertised, so the driver keeps its own default of 1500 and one buffer per frame.
    pub fn new(
        id: String,
        cfg_backend: VirtioNetBackend,
        mac: [u8; 6],
        features: u32,
        mtu: Option<u16>,
    ) -> Result<Self> {
        let mut avail_features = features as u64
            | (1 << VIRTIO_NET_F_MAC)
            | (1 << VIRTIO_RING_F_EVENT_IDX)
            | (1 << VIRTIO_F_VERSION_1);
        if mtu.is_some() {
            // Mergeable receive buffers come with the MTU: on a link wide enough to be worth
            // setting, a driver that has to size every posted buffer for the largest frame
            // spends nearly all of them on packets nowhere near it.
            avail_features |= mtu_features();
        }

        let config = VirtioNetConfig {
            mac,
            status: 0,
            max_virtqueue_pairs: 0,
            mtu: mtu.unwrap_or(0),
        };

        Ok(Net {
            id,
            cfg_backend,

            avail_features,
            acked_features: 0u64,

            device_state: DeviceState::Inactive,
            config,

            #[cfg(unix)]
            worker: None,
            #[cfg(unix)]
            worker_stopfd: EventFd::new(EFD_NONBLOCK).map_err(super::Error::EventFd)?,
            #[cfg(unix)]
            backend: None,
            #[cfg(unix)]
            backend_opened: false,
        })
    }

    /// Set or clear the advertised link MTU before activation, as `new`'s `mtu` does.
    pub fn set_mtu(&mut self, mtu: Option<u16>) {
        let bits = mtu_features();
        if mtu.is_some() {
            self.avail_features |= bits;
        } else {
            self.avail_features &= !bits;
        }
        self.config.mtu = mtu.unwrap_or(0);
    }

    /// Provides the ID of this net device.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Provides the virtio-net backend of this net device.
    pub fn backend(&self) -> &VirtioNetBackend {
        &self.cfg_backend
    }
}

impl VirtioDevice for Net {
    fn avail_features(&self) -> u64 {
        self.avail_features
    }

    fn acked_features(&self) -> u64 {
        self.acked_features
    }

    fn set_acked_features(&mut self, acked_features: u64) {
        self.acked_features = acked_features;
    }

    fn device_type(&self) -> u32 {
        TYPE_NET
    }

    fn device_name(&self) -> &str {
        "net"
    }

    fn queue_config(&self) -> &[QueueConfig] {
        &QUEUE_CONFIG
    }

    fn config_len(&self) -> Option<u32> {
        Some(size_of::<VirtioNetConfig>() as u32)
    }

    fn read_config(&self, offset: u64, mut data: &mut [u8]) {
        let config_slice = self.config.as_slice();
        let config_len = config_slice.len() as u64;
        if offset >= config_len {
            error!("Failed to read config space");
            return;
        }
        if let Some(end) = offset.checked_add(data.len() as u64) {
            // This write can't fail, offset and end are checked against config_len.
            data.write_all(&config_slice[offset as usize..cmp::min(end, config_len) as usize])
                .unwrap();
        }
    }

    fn write_config(&mut self, offset: u64, data: &[u8]) {
        log::warn!(
            "Net: guest driver attempted to write device config (offset={:x}, len={:x})",
            offset,
            data.len()
        );
    }

    fn activate(
        &mut self,
        mem: GuestMemoryMmap,
        interrupt: InterruptTransport,
        queues: Vec<DeviceQueue>,
    ) -> ActivateResult {
        let [rx_q, tx_q]: [_; NUM_QUEUES] = queues.try_into().map_err(|_| {
            error!("Cannot perform activate. Expected {} queue(s)", NUM_QUEUES);
            ActivateError::BadActivate
        })?;

        // Before the backend leaves the device: a worker that cannot be stopped must not get it.
        #[cfg(unix)]
        let stop = self.worker_stopfd.try_clone().map_err(|err| {
            error!(
                "virtio-net ({}): cannot clone its stop eventfd: {err}",
                self.id
            );
            ActivateError::BadActivate
        })?;
        #[cfg(unix)]
        let worker = self.open_backend().map(|backend| {
            NetWorker::with_backend(
                rx_q,
                tx_q,
                interrupt.clone(),
                mem.clone(),
                self.acked_features,
                backend,
            )
        });
        #[cfg(windows)]
        let worker = NetWorker::new(
            rx_q,
            tx_q,
            interrupt.clone(),
            mem.clone(),
            self.acked_features,
            self.cfg_backend.clone(),
        );
        match worker {
            Ok(worker) => {
                #[cfg(unix)]
                {
                    self.worker = Some(worker.run(stop));
                }
                #[cfg(windows)]
                worker.run();
                self.device_state = DeviceState::Activated(mem, interrupt);
                Ok(())
            }
            Err(err) => {
                error!(
                    "Error activating virtio-net ({}) backend: {err:?}",
                    self.id()
                );
                Err(ActivateError::BadActivate)
            }
        }
    }

    fn is_activated(&self) -> bool {
        self.device_state.is_activated()
    }

    /// Stop the worker and keep its backend for the next activation (local patch). Windows'
    /// virtio-net driver resets the device as it starts, and again when another virtio
    /// function makes it start over; a device that cannot reset leaves it failed.
    #[cfg(unix)]
    fn reset(&mut self) -> bool {
        if let Some(worker) = self.worker.take() {
            let _ = self.worker_stopfd.write(1);
            match worker.join() {
                Ok(backend) => self.backend = Some(backend),
                Err(err) => error!("virtio-net ({}) worker panicked: {err:?}", self.id),
            }
        }
        self.device_state = DeviceState::Inactive;
        true
    }
}

#[cfg(unix)]
impl Net {
    /// The backend for an activation: the one a reset kept, set to the features this
    /// driver negotiated, or on the first activation a newly opened one.
    fn open_backend(&mut self) -> std::result::Result<Backend, super::backend::ConnectError> {
        if let Some(mut backend) = self.backend.take() {
            backend.set_vnet_features(self.acked_features)?;
            return Ok(backend);
        }
        if self.backend_opened {
            return Err(super::backend::ConnectError::BackendLost);
        }
        self.backend_opened = true;
        NetWorker::connect(self.cfg_backend.clone(), self.acked_features)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    fn net(mtu: Option<u16>) -> Net {
        Net::new(
            "eth0".into(),
            VirtioNetBackend::UnixstreamFd(-1),
            MAC,
            0,
            mtu,
        )
        .unwrap()
    }

    /// The driver reads the MTU at offset 10 of the config space, after mac[6], status and
    /// max_virtqueue_pairs, as a little-endian u16.
    #[test]
    fn mtu_sits_at_config_offset_10() {
        let dev = net(Some(65500));
        let mut cfg = [0u8; 12];
        dev.read_config(0, &mut cfg);
        assert_eq!(&cfg[..6], &MAC);
        assert_eq!(u16::from_le_bytes([cfg[10], cfg[11]]), 65500);

        let mut field = [0u8; 2];
        dev.read_config(10, &mut field);
        assert_eq!(u16::from_le_bytes(field), 65500);
    }

    struct NoIrq;

    impl crate::virtio::device::InterruptHandler for NoIrq {
        fn try_signal(
            &self,
            _interrupt: crate::virtio::device::InterruptType,
        ) -> std::result::Result<(), crate::Error> {
            Ok(())
        }
    }

    /// A reset stops the worker and keeps its backend, which the next activation carries on
    /// with: the socket stays open, owned once, until the device goes.
    #[test]
    fn a_reset_keeps_the_backend_for_the_next_activation() {
        use crate::virtio::queue::Queue;
        use std::io::{ErrorKind, Read};
        use std::os::fd::IntoRawFd;
        use std::sync::Arc;
        use utils::eventfd::EventFd;
        use vm_memory::GuestAddress;

        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x10000)]).unwrap();
        let (socket, mut peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut dev = Net::new(
            "eth0".into(),
            VirtioNetBackend::UnixstreamFd(socket.into_raw_fd()),
            MAC,
            0,
            None,
        )
        .unwrap();
        let queues = || {
            (0..NUM_QUEUES)
                .map(|_| DeviceQueue::new(Queue::new(16), Arc::new(EventFd::new(0).unwrap())))
                .collect::<Vec<_>>()
        };
        let interrupt = || InterruptTransport::from_handler(Arc::new(NoIrq));
        peer.set_nonblocking(true).unwrap();
        let still_open = |peer: &mut std::os::unix::net::UnixStream| {
            peer.read(&mut [0u8; 1]).unwrap_err().kind() == ErrorKind::WouldBlock
        };

        for _ in 0..3 {
            dev.activate(mem.clone(), interrupt(), queues()).unwrap();
            assert!(dev.is_activated());
            assert!(dev.reset());
            assert!(!dev.is_activated());
            assert!(dev.backend.is_some(), "the worker handed its backend back");
            assert!(still_open(&mut peer));
        }
        drop(dev);
        assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0, "the device closed it");
    }

    /// VIRTIO_NET_F_MTU and the mergeable receive buffers that come with it are offered only
    /// when an MTU was configured; without one the field stays zero and no driver is
    /// entitled to read it.
    #[test]
    fn mtu_features_are_offered_only_with_an_mtu() {
        let bits = (1u64 << VIRTIO_NET_F_MTU) | (1u64 << VIRTIO_NET_F_MRG_RXBUF);
        assert_eq!(net(Some(1500)).avail_features() & bits, bits);
        assert_eq!(net(None).avail_features() & bits, 0);

        let mut field = [0xffu8; 2];
        net(None).read_config(10, &mut field);
        assert_eq!(u16::from_le_bytes(field), 0);
    }
}
