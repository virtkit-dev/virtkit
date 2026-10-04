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

// The I/O APIC has 24 pins (0-23). ISA IRQs 0-4 are reserved for
// legacy devices, leaving GSIs 5-23 for virtio-mmio devices.
/// First usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_BASE: u32 = 5;
/// Last usable IRQ ID for virtio device interrupts on x86_64.
pub const IRQ_MAX: u32 = 23;

/// Address for the TSS setup.
pub const KVM_TSS_ADDRESS: u64 = 0xfffb_d000;

/// Base of the guest-physical span shared-memory regions (virtio-fs DAX windows) are carved
/// from when the devices are on virtio-pci, and its size. Fixed, so the DSDT can declare
/// exactly this span as a 64-bit PCI host-bridge window (for a guest whose RAM stays below
/// it): the transport exposes each region as a memory BAR, and Linux keeps a BAR only where
/// a bridge window covers it. It ends at 128 GiB, so reaching it needs 37 physical address
/// bits, which the guest gets from the host's CPUID leaf 0x80000008 as KVM reports it.
pub const SHM_MEM_START: u64 = 64 << 30;
pub const SHM_MEM_SIZE: u64 = 64 << 30;

/// Whether a guest whose RAM ends at `ram_last_addr` can have the span above: its RAM must
/// stay below `SHM_MEM_START`.
pub fn shm_span_usable(ram_last_addr: u64) -> bool {
    ram_last_addr <= SHM_MEM_START
}

/// Base of the ACPI PM1 register block (PM1a_EVT at +0, PM1a_CNT at +4), the ACPI reset
/// register (+0xC) and the GPE0 block (+0x10), served by the `AcpiPm` PIO device (local
/// patch, see VENDOR.md).
pub const ACPI_PM_BASE: u16 = 0x600;
/// Length of the `AcpiPm` PIO window.
pub const ACPI_PM_LEN: u64 = 0x14;
/// The GPE0 block: GPE0_STS, then GPE0_EN, each `ACPI_GPE0_BLK_LEN / 2` bytes.
pub const ACPI_GPE0_BLK: u16 = ACPI_PM_BASE + 0x10;
pub const ACPI_GPE0_BLK_LEN: u8 = 4;
/// The GPE that notifies the guest of a new VM generation ID (`\_GPE._E05`), QEMU's.
pub const VMGENID_GPE: u8 = 5;
/// ACPI reset register, as an absolute port.
pub const ACPI_RESET_REG: u16 = ACPI_PM_BASE + 0x0c;
/// Value the guest writes to `ACPI_RESET_REG` to request a reset.
pub const ACPI_RESET_VALUE: u8 = 1;
/// IOAPIC GSI carrying the ACPI SCI (power-button events). Fixed; skipped by the virtio IRQ
/// allocators.
pub const SCI_GSI: u32 = 9;

/// Address of the hvm_start_info struct used in PVH boot.
/// Mutually exclusive with SNP_CPUID_START (TEE only).
pub const PVH_INFO_START: u64 = 0x6000;

/// Starting address of array of modules of hvm_modlist_entry type.
/// Used to enable initrd support using the PVH boot ABI.
pub const MODLIST_START: u64 = 0x6040;

/// Address of memory map table used in PVH boot. Can overlap
/// with the zero page address since they are mutually exclusive.
pub const MEMMAP_START: u64 = 0x7000;

/// Location of RSDP pointer in x86 machines.
pub const RSDP_ADDR: u64 = 0x000e_0000;

/// The pvpanic device's I/O port, QEMU's (local patch).
pub const PVPANIC_PORT: u16 = 0x505;

/// The 16-byte VM generation ID the DSDT's VGEN device points at: the last page of the
/// reserved window below 1 MiB, past the ACPI tables (local patch).
pub const VMGENID_ADDR: u64 = 0x000f_f000;

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

/// The start of the memory area reserved for MMIO devices: the 32-bit hole below 4 GiB, which
/// guest RAM skips. 1 GiB, from 3 GiB, as cloud-hypervisor lays it out: UEFI firmware built for
/// it (OVMF's CloudHv) assigns PCI BARs from 3 GiB up, so RAM must end there (local patch, see
/// VENDOR.md).
pub const FIRST_ADDR_PAST_32BITS: u64 = 1 << 32;
pub const MEM_32BIT_GAP_SIZE: u64 = 1 << 30;
pub const MMIO_MEM_START: u64 = FIRST_ADDR_PAST_32BITS - MEM_32BIT_GAP_SIZE;
/// The low part of the hole, where firmware moves PCI BARs; the BAR window covers it too.
pub const PCI_MMIO32_LOW_START: u64 = MMIO_MEM_START;
pub const PCI_MMIO32_LOW_END: u64 = 0xd000_0000;
/// Where virtio-mmio devices are placed, above the firmware's BARs.
pub const MMIO_DEVICES_START: u64 = PCI_MMIO32_LOW_END;

/// Start of the PCI Express ECAM window for bus 0.
pub const PCI_ECAM_START: u64 = 0xe000_0000;
/// ECAM exposes 4 KiB of configuration space for each of 256 PCI buses.
/// This VM exposes bus 0 only.
pub const PCI_ECAM_SIZE: u64 = 1 << 20;
/// Start of the PCI memory BAR allocation window.
pub const PCI_BAR_START: u64 = PCI_ECAM_START + PCI_ECAM_SIZE;
/// Exclusive end of the PCI memory BAR allocation window, below the IOAPIC.
pub const PCI_BAR_END: u64 = 0xfec0_0000;
