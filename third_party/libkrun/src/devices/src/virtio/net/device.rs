// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.
use crate::virtio::net::Result;
use crate::virtio::net::{NUM_QUEUES, QUEUE_CONFIG};
use crate::virtio::queue::Error as QueueError;
use crate::virtio::{
    ActivateError, ActivateResult, DeviceQueue, DeviceState, InterruptTransport, QueueConfig,
    VirtioDevice, TYPE_NET,
};
use crate::Error as DeviceError;

use super::backend::{ReadError, WriteError};
use super::worker::NetWorker;

use std::cmp;
use std::io::Write;
use std::os::fd::RawFd;
use std::path::PathBuf;
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
    UnixstreamFd(RawFd),
    UnixstreamPath(PathBuf),
    UnixgramFd(RawFd),
    UnixgramPath(PathBuf, bool),
    #[cfg(target_os = "linux")]
    Tap(String),
}

pub struct Net {
    id: String,
    pub cfg_backend: VirtioNetBackend,

    avail_features: u64,
    acked_features: u64,

    pub(crate) device_state: DeviceState,

    config: VirtioNetConfig,
}

impl Net {
    /// Create a new virtio network device using the backend.
    ///
    /// `mtu` is the link MTU the driver should adopt (`MIN_MTU..=MAX_MTU`, validated by the
    /// caller), and brings mergeable receive buffers with it. `None` leaves both features
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
            avail_features |= (1 << VIRTIO_NET_F_MTU) | (1 << VIRTIO_NET_F_MRG_RXBUF);
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
        })
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

        match NetWorker::new(
            rx_q,
            tx_q,
            interrupt.clone(),
            mem.clone(),
            self.acked_features,
            self.cfg_backend.clone(),
        ) {
            Ok(worker) => {
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
}

#[cfg(test)]
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
