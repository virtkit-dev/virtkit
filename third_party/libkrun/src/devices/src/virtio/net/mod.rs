// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::{io, mem, result};
use virtio_bindings::virtio_net::virtio_net_hdr_v1;

use super::QueueConfig;

pub const MAX_BUFFER_SIZE: usize = 65562;
const QUEUE_SIZE: u16 = 1024;
const ETH_HDR_LEN: usize = 14;
/// Smallest link MTU a caller may configure (`VIRTIO_NET_F_MTU`), matching the floor the
/// virtio-net spec and the Linux driver (`ETH_MIN_MTU`) enforce.
pub const MIN_MTU: u16 = 68;
/// Largest link MTU a caller may configure. The config field is a `u16`, and the frame it
/// describes plus the virtio-net header has to fit [`MAX_BUFFER_SIZE`] — the assertion below
/// ties the two together so a buffer-size change cannot silently outgrow the frame buffers.
pub const MAX_MTU: u16 = u16::MAX;
const _: () = assert!(MAX_BUFFER_SIZE >= VNET_HDR_LEN + ETH_HDR_LEN + MAX_MTU as usize);
pub const NUM_QUEUES: usize = 2;
pub static QUEUE_CONFIG: [QueueConfig; NUM_QUEUES] = [QueueConfig::new(QUEUE_SIZE); NUM_QUEUES];

mod backend;
pub mod device;
#[cfg(target_os = "linux")]
mod tap;
mod unixgram;
mod unixstream;
mod worker;

// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2050006
const VNET_HDR_LEN: usize = mem::size_of::<virtio_net_hdr_v1>();

// This initializes to all 0 the virtio_net_hdr part of a buf and return the length of the header
fn write_virtio_net_hdr(buf: &mut [u8]) -> usize {
    buf[0..VNET_HDR_LEN].fill(0);
    VNET_HDR_LEN
}

pub use self::device::Net;
#[derive(Debug)]
pub enum Error {
    /// EventFd error.
    EventFd(io::Error),
}

pub type Result<T> = result::Result<T, Error>;
