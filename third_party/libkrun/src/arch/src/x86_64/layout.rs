// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Portions Copyright 2017 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the THIRD-PARTY file.

//! Magic addresses externally used to lay out x86_64 VMs.

/// Initial stack for the boot CPU.
pub const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// Kernel command line start address.
pub const CMDLINE_START: u64 = 0x20000;
/// Kernel command line start address maximum size.
pub const CMDLINE_MAX_SIZE: usize = 0x10000;
/// Kernel command line static size on SEV.
pub const CMDLINE_SEV_SIZE: usize = 0x200;
/// Initrd start address on SEV.
pub const INITRD_SEV_START: u64 = 0xa00000;

/// Start of the high memory.
pub const HIMEM_START: u64 = 0x0010_0000; //1 MB.

/// Number of interrupt pins on the guest's single IOAPIC. Must match the
/// emulated IOAPIC (devices/legacy/ioapic.rs) and the pins the MPTABLE routes
/// (mptable.rs): the guest can only use an IRQ that all three agree exists.
pub const IOAPIC_NUM_PINS: u32 = 24;

/// First usable IRQ ID for virtio device interrupts on x86_64. Pins 0-4 are
/// reserved for legacy devices (timer, keyboard, PIC cascade, the serial ports),
/// so virtio devices start at pin 5.
pub const IRQ_BASE: u32 = 5;
/// Last usable IRQ ID for virtio device interrupts on x86_64. Legacy virtio-mmio
/// has one interrupt line per device (no MSI multiplexing), so each device claims
/// one IOAPIC pin and the ceiling is the single IOAPIC's last pin (pin 23).
pub const IRQ_MAX: u32 = IOAPIC_NUM_PINS - 1;

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

/// Where the ACPI tables (RSDP, XSDT, FADT, FACS, MADT, DSDT) are written. This
/// sits in the legacy 0xA0000-0xFFFFF segment: backed by guest RAM region 0 but
/// outside the E820 RAM map, the conventional home for firmware tables. The RSDP
/// is both pointed to by `boot_params.acpi_rsdp_addr` and findable by the legacy
/// 0xE0000-0xFFFFF scan.
pub const ACPI_TABLES_START: u64 = 0xe0000;
/// Highest address available to the ACPI tables (end of the 1 MiB segment).
pub const ACPI_TABLES_END: u64 = 0x100000;

/// Base of the ACPI PM1 register block (PM1a_EVT at +0, PM1a_CNT at +4) and the
/// ACPI reset register (+0xC), served by the `AcpiPm` PIO device.
pub const ACPI_PM_BASE: u16 = 0x600;
/// Length of the `AcpiPm` PIO window.
pub const ACPI_PM_LEN: u64 = 0x10;
/// ACPI reset register, as an offset from `ACPI_PM_BASE` and as an absolute port.
pub const ACPI_RESET_REG: u16 = ACPI_PM_BASE + 0x0c;
/// Value the guest writes to `ACPI_RESET_REG` to request a reset.
pub const ACPI_RESET_VALUE: u8 = 1;
/// IOAPIC GSI carrying the ACPI SCI (power-button events). Fixed; skipped by
/// the virtio IRQ allocator.
pub const SCI_GSI: u32 = 9;

/// The 'zero page', a.k.a linux kernel bootparams.
pub const ZERO_PAGE_START: u64 = 0x7000;

/// SNP: space for the initial LIDT
pub const SNP_LIDT_START: u64 = 0x0;
/// SNP: Secrets page.
pub const SNP_SECRETS_START: u64 = 0x5000;
/// SNP: CPUID page
pub const SNP_CPUID_START: u64 = 0x6000;
/// SNP: FW stack and initial page tables
pub const SNP_FWDATA_START: u64 = 0x8000;
pub const SNP_FWDATA_SIZE: usize = 0x7000;

// Where BIOS/VGA magic would live on a real PC.
pub const EBDA_START: u64 = 0x9fc00;

/// Where the PC register will point after a reset.
#[cfg(not(feature = "tdx"))]
pub const RESET_VECTOR: u64 = 0xfff0;
#[cfg(feature = "tdx")]
pub const RESET_VECTOR: u64 = 0xffff_fff0;
pub const RESET_VECTOR_SEV_AP: u64 = 0xfff3;

/// The address to load the firmware, if present.
pub const FIRMWARE_START: u64 = 0xffff_0000;

/// The size of the firmware.
pub const FIRMWARE_SIZE: u64 = 65536;

/// Base of the guest-physical span virtio-fs DAX windows are carved from, and its size.
///
/// Fixed, and far above any guest's RAM, so the DSDT can declare exactly this span as a
/// 64-bit PCI host-bridge memory window: the virtio-pci transport exposes each window as a
/// memory BAR, and Linux keeps a BAR only where a bridge window covers it. It ends at
/// 128 GiB, so reaching it needs 37 physical address bits — libkrun passes the host's
/// MAXPHYADDR through unmodified, so that is what the guest has to have.
/// (Local patch — see ../../../VENDOR.md.)
pub const SHM_MEM_START: u64 = 64 << 30;
pub const SHM_MEM_SIZE: u64 = 64 << 30;

/// The start of the memory area reserved for MMIO devices.
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
pub const MEM_32BIT_GAP_SIZE: u64 = 768 << 20;
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
