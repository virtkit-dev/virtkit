// Copyright 2020, Red Hat Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "tee")]
use std::fmt::{Display, Formatter, Result};

/// Data structure holding the attributes read from the `libkrunfw` kernel config.
#[derive(Debug, Default)]
pub struct KernelBundle {
    pub host_addr: u64,
    pub guest_addr: u64,
    #[cfg_attr(all(feature = "amd-sev", not(feature = "tdx")), allow(dead_code))]
    pub entry_addr: u64,
    pub size: usize,
}

/// Data structure holding the attributes read from the `libkrunfw` qboot config.
#[cfg(feature = "tee")]
#[derive(Debug, Default)]
pub struct QbootBundle {
    pub host_addr: u64,
    pub size: usize,
}

/// Structure used to specify the parameters for the `libkrunfw` qboot bundle.
#[cfg(feature = "tee")]
#[derive(Debug)]
pub enum QbootBundleError {
    /// Qboot binary is not 64K long.
    InvalidSize,
}

#[cfg(feature = "tee")]
impl Display for QbootBundleError {
    fn fmt(&self, f: &mut Formatter) -> Result {
        use self::QbootBundleError::*;
        match *self {
            InvalidSize => write!(f, "qboot binary is not 64K long."),
        }
    }
}

/// Data structure holding the attributes read from the `libkrunfw` initrd config.
#[cfg(feature = "tee")]
#[derive(Debug, Default)]
pub struct InitrdBundle {
    pub host_addr: u64,
    pub size: usize,
}
