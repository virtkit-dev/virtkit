// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Implements virtio devices, queues, and transport mechanisms.
use std;
use std::any::Any;
use std::io::Error as IOError;
use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard, TryLockError};
use std::time::{Duration, Instant};

use virtio_bindings::virtio_ids;

#[cfg(not(feature = "tee"))]
pub mod balloon;
#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub mod bindings;
pub mod block;
pub mod console;
pub mod descriptor_utils;
pub mod device;
pub mod file_traits;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub mod fs;
#[cfg(feature = "gpu")]
pub mod gpu;
#[cfg(feature = "input")]
pub mod input;
pub mod linux_errno;
mod mmio;
// MSI-X table, PBA and delivery for the virtio-pci transport (local patch, see VENDOR.md).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod msix;
#[cfg(feature = "net")]
pub mod net;
// The virtio-pci transport: only the Linux x86_64 VMM attaches it, and its MSI-X state is
// KVM-only (local patch, see VENDOR.md).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod pci;
mod queue;
#[cfg(not(feature = "tee"))]
pub mod rng;
#[cfg(feature = "vhost-user")]
pub mod vhost_user;
pub mod vsock;

#[cfg(not(feature = "tee"))]
pub use self::balloon::*;
#[cfg(feature = "blk")]
pub use self::block::{Block, CacheType};
pub use self::console::*;
pub use self::device::*;
#[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
pub use self::fs::*;
#[cfg(feature = "gpu")]
pub use self::gpu::*;
pub use self::mmio::*;
#[cfg(feature = "net")]
pub use self::net::Net;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use self::pci::*;
pub use self::queue::{Descriptor, DescriptorChain, Queue};
#[cfg(not(feature = "tee"))]
pub use self::rng::*;
#[cfg(feature = "vhost-user")]
pub use self::vhost_user::VhostUserDevice;
pub use self::vsock::*;

/// Held shared by a virtio device's threads while they write guest memory (a disk batch, a
/// received frame, console input) and exclusively by a VM snapshot while it reads the devices'
/// state and the guest's memory, so neither changes under it (local patch). One VM per
/// process, so one gate.
///
/// A thread must not take [`device_writes`] while it already holds it: whether a waiting
/// writer holds off new readers is up to the platform's `RwLock`, and where it does, the
/// nested read waits for the snapshot that waits for the outer one.
static GUEST_MEMORY_GATE: RwLock<()> = RwLock::new(());

/// The device types the gate covers: those whose threads take [`device_writes`] (block, net,
/// console) and those that run on the VMM's event loop, which a snapshot itself occupies
/// (rng, balloon). A snapshot refuses a VM with any other.
pub const QUIESCED_DEVICE_TYPES: [u32; 5] = [
    virtio_ids::VIRTIO_ID_BLOCK,
    virtio_ids::VIRTIO_ID_NET,
    virtio_ids::VIRTIO_ID_CONSOLE,
    virtio_ids::VIRTIO_ID_RNG,
    virtio_ids::VIRTIO_ID_BALLOON,
];

/// Taken by a device thread around its writes to guest memory.
pub fn device_writes() -> RwLockReadGuard<'static, ()> {
    GUEST_MEMORY_GATE
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Taken by a snapshot: returns once no device thread is writing guest memory, and keeps them
/// from starting until it is dropped; `None` if they still are after `timeout`.
pub fn quiesce_devices(timeout: Duration) -> Option<RwLockWriteGuard<'static, ()>> {
    let deadline = Instant::now() + timeout;
    loop {
        match GUEST_MEMORY_GATE.try_write() {
            Ok(gate) => return Some(gate),
            Err(TryLockError::Poisoned(e)) => return Some(e.into_inner()),
            Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(TryLockError::WouldBlock) => return None,
        }
    }
}

/// When the driver initializes the device, it lets the device know about the
/// completed stages using the Device Status Field.
///
/// These following consts are defined in the order in which the bits would
/// typically be set by the driver. INIT -> ACKNOWLEDGE -> DRIVER and so on.
///
/// This module is a 1:1 mapping for the Device Status Field in the virtio 1.0
/// specification, section 2.1.
mod device_status {
    pub const INIT: u32 = 0;
    pub const ACKNOWLEDGE: u32 = 1;
    pub const DRIVER: u32 = 2;
    pub const FAILED: u32 = 128;
    pub const FEATURES_OK: u32 = 8;
    pub const DRIVER_OK: u32 = 4;
}

/// Types taken from linux/virtio_ids.h.
/// Type 0 is not used by virtio. Use it as wildcard for non-virtio devices
pub const TYPE_NET: u32 = 1;
pub const TYPE_BLOCK: u32 = 2;

/// Interrupt flags (re: interrupt status & acknowledge registers).
/// See linux/virtio_mmio.h.
pub const VIRTIO_MMIO_INT_VRING: u32 = 0x01;
pub const VIRTIO_MMIO_INT_CONFIG: u32 = 0x02;

/// Offset from the base MMIO address of a virtio device used by the guest to notify the device of
/// queue events.
pub const NOTIFY_REG_OFFSET: u32 = 0x50;

#[derive(Debug)]
pub enum ActivateError {
    EpollCtl(IOError),
    BadActivate,
}

pub type ActivateResult = std::result::Result<(), ActivateError>;

/// Trait that helps in upcasting an object to Any
pub trait AsAny {
    fn as_any(&self) -> &dyn Any;

    fn as_mut_any(&mut self) -> &mut dyn Any;
}
impl<T: Any> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    #[test]
    fn a_snapshot_waits_for_a_device_write_up_to_a_timeout_and_holds_off_the_next() {
        let (writing, started) = mpsc::channel();
        let (finish, finished) = mpsc::channel::<()>();
        let writer = std::thread::spawn(move || {
            let _writing = super::device_writes();
            writing.send(()).unwrap();
            finished.recv().unwrap();
        });
        started.recv().unwrap();
        // A write that outlasts the timeout fails the snapshot rather than stalling it.
        assert!(super::quiesce_devices(Duration::from_millis(50)).is_none());

        let quiet = Arc::new(AtomicBool::new(false));
        let snapshot = std::thread::spawn({
            let quiet = quiet.clone();
            move || {
                let gate = super::quiesce_devices(Duration::from_secs(10)).unwrap();
                quiet.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(100));
                drop(gate);
            }
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !quiet.load(Ordering::SeqCst),
            "the snapshot waited for the write"
        );
        finish.send(()).unwrap();
        writer.join().unwrap();
        while !quiet.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        // While the snapshot holds the gate, a device write waits for it.
        let next = std::thread::spawn(move || {
            let _writing = super::device_writes();
        });
        snapshot.join().unwrap();
        next.join().unwrap();
    }
}
