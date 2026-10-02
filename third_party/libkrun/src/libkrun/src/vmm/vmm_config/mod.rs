// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/// Wrapper for configuring an external kernel to be loaded in the microVM.
pub mod external_kernel;

/// Wrapper for configuring the firmware.
pub mod firmware;

/// Wrapper for configuring the kernel bundle to be loaded in the microVM.
pub mod kernel_bundle;

/// Wrapper for configuring the kernel command line.
pub mod kernel_cmdline;

/// Wrapper for configuring the memory and CPU of the microVM.
pub mod machine_config;
