// Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::result;

use acpi_tables::aml::{
    AddressSpace, AddressSpaceCacheable, Device, EISAName, IO, Interrupt, Memory32Fixed, Name,
    Package, PackageBuilder, Path, ResourceTemplate, Scope, ZERO,
};
use acpi_tables::facs::FACS;
use acpi_tables::fadt::{FADTBuilder, Flags};
use acpi_tables::gas::{AccessSize, AddressSpace as GasSpace, GAS};
use acpi_tables::madt::{
    EnabledStatus, IoApic, LocalInterruptController, MADT, ProcessorLocalApic,
};
use acpi_tables::mcfg::MCFG;
use acpi_tables::rsdp::Rsdp;
use acpi_tables::sdt::Sdt;
use acpi_tables::xsdt::XSDT;
use acpi_tables::{Aml, AmlSink};
use vm_memory::Bytes;
use vm_memory::{GuestAddress, GuestMemory, GuestMemoryMmap, Permissions};
use zerocopy::byteorder::{LE, U16, U32};
use zerocopy::{Immutable, IntoBytes};

use crate::x86_64::layout::{
    ACPI_PM_BASE, ACPI_RESET_REG, ACPI_RESET_VALUE, HIMEM_START, RSDP_ADDR, SCI_GSI,
};

/// Standard local APIC physical base address.
const LOCAL_APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000;
/// Standard I/O APIC physical base address.
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000;
/// With APIC/xAPIC, there are only 255 APIC IDs available, and the I/O APIC
/// occupies one, so at most 254 CPUs can be represented in the MADT.
const MAX_SUPPORTED_CPUS: u32 = 254;
/// IAPC_BOOT_ARCH bit 1: 8042 present on ports 0x60/0x64 (`ACPI_FADT_8042`).
const IAPC_BOOT_ARCH_8042: u16 = 1 << 1;

/// PM1 event block (status + enable) and control block lengths, in bytes.
const PM1_EVT_LEN: u8 = 4;
const PM1_CNT_LEN: u8 = 2;
const PM1A_CNT_PORT: u16 = ACPI_PM_BASE + 0x04;

/// MADT Interrupt Source Override (type 2, ACPI 6.x § 5.2.12.5): ISA IRQ `source` arrives on
/// `gsi` with `flags` polarity/trigger. `acpi_tables` has no such structure.
#[repr(C, packed)]
#[derive(Clone, Copy, IntoBytes, Immutable)]
struct InterruptSourceOverride {
    r#type: u8,
    length: u8,
    bus: u8,
    source: u8,
    gsi: U32<LE>,
    flags: U16<LE>,
}

impl InterruptSourceOverride {
    fn new(source: u8, gsi: u32, flags: u16) -> Self {
        Self {
            r#type: 2,
            length: std::mem::size_of::<Self>() as u8,
            bus: 0,
            source,
            gsi: gsi.into(),
            flags: flags.into(),
        }
    }
}

impl Aml for InterruptSourceOverride {
    fn to_aml_bytes(&self, sink: &mut dyn AmlSink) {
        sink.vec(self.as_bytes());
    }
}

/// MPS INTI flags: polarity 01 (active high), trigger 01 (edge). The SCI is delivered by a
/// one-shot KVM irqfd with no resample fd, so it is programmed edge/high.
const MADT_INT_EDGE_HIGH: u16 = 0b0101;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciFunctionInfo {
    pub device: u8,
    pub function: u8,
    pub gsi: u32,
}

#[derive(Clone, Debug)]
pub struct PciHostInfo {
    pub ecam_base: u64,
    pub bar_start: u64,
    pub bar_size: u64,
    pub functions: Vec<PciFunctionInfo>,
}

/// Builds a 36-byte ACPI 2.0+ RSDP pointing at the given XSDT address.
fn build_rsdp(xsdt_addr: u64) -> Vec<u8> {
    Rsdp::new(*b"LIBKRN", xsdt_addr).as_bytes().to_vec()
}

fn build_dsdt(virtio_mmio_devices: &[(u64, u32)], pci_host: Option<&PciHostInfo>) -> Vec<u8> {
    let mut aml_body = Vec::new();

    // (io_base, irq, acpi_device_name) — PC/AT standard COM port assignments
    const COM_PORTS: [(u16, u32, &str); 4] = [
        (0x3F8, 4, "COM1"),
        (0x2F8, 3, "COM2"),
        (0x3E8, 4, "COM3"),
        (0x2E8, 3, "COM4"),
    ];
    for (i, &(io_base, irq, name)) in COM_PORTS.iter().enumerate() {
        let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0501"));
        let uid = Name::new(Path::new("_UID"), &(i as u32));
        let io_res = IO::new(io_base, io_base, 0x08, 0x08);
        let irq_res = Interrupt::new(true, true, false, true, irq);
        let crs = Name::new(
            Path::new("_CRS"),
            &ResourceTemplate::new(vec![&io_res, &irq_res]),
        );
        Device::new(Path::new(name), vec![&hid, &uid, &crs]).to_aml_bytes(&mut aml_body);
    }

    {
        let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0303"));
        let uid = Name::new(Path::new("_UID"), &0u32);
        let io_data = IO::new(0x0060, 0x0060, 0x01, 0x01);
        let io_cmd = IO::new(0x0064, 0x0064, 0x01, 0x01);
        let irq_res = Interrupt::new(true, true, false, false, 1);
        let crs = Name::new(
            Path::new("_CRS"),
            &ResourceTemplate::new(vec![&io_data, &io_cmd, &irq_res]),
        );
        Device::new(Path::new("KBD0"), vec![&hid, &uid, &crs]).to_aml_bytes(&mut aml_body);
    }

    for (i, &(mmio_base, irq)) in virtio_mmio_devices.iter().enumerate() {
        let name = format!("VR{i:02X}");
        let hid = Name::new(Path::new("_HID"), &"LNRO0005");
        let uid = Name::new(Path::new("_UID"), &(i as u32));
        let mem = Memory32Fixed::new(true, mmio_base as u32, 0x1000);
        let irq_res = Interrupt::new(true, false, false, false, irq);
        let crs = Name::new(
            Path::new("_CRS"),
            &ResourceTemplate::new(vec![&mem, &irq_res]),
        );
        Device::new(Path::new(&name), vec![&hid, &uid, &crs]).to_aml_bytes(&mut aml_body);
    }

    if let Some(pci_host) = pci_host {
        let hid = Name::new(Path::new("_HID"), &EISAName::new("PNP0A08"));
        let cid = Name::new(Path::new("_CID"), &EISAName::new("PNP0A03"));
        let seg = Name::new(Path::new("_SEG"), &0u32);
        let bbn = Name::new(Path::new("_BBN"), &0u32);
        let uid = Name::new(Path::new("_UID"), &0u32);
        let buses = AddressSpace::new_bus_number(0u16, 0u16);
        let memory = AddressSpace::new_memory(
            AddressSpaceCacheable::NotCacheable,
            true,
            pci_host.bar_start,
            pci_host.bar_start + pci_host.bar_size - 1,
            None,
        );
        let crs = Name::new(
            Path::new("_CRS"),
            &ResourceTemplate::new(vec![&buses, &memory]),
        );

        let mut prt = PackageBuilder::new();
        for function in &pci_host.functions {
            let mut route = PackageBuilder::new();
            let address = (u32::from(function.device) << 16) | u32::from(function.function);
            let pin = 0u32;
            let gsi = function.gsi;
            route.add_element(&address);
            route.add_element(&pin);
            route.add_element(&ZERO);
            route.add_element(&gsi);
            prt.add_element(&route);
        }
        let prt_name = Name::new(Path::new("_PRT"), &prt);
        Device::new(
            Path::new("PCI0"),
            vec![&hid, &cid, &seg, &bbn, &uid, &crs, &prt_name],
        )
        .to_aml_bytes(&mut aml_body);
    }

    let scope_bytes = Scope::raw(Path::new("\\_SB_"), aml_body);

    // \_S5: the SLP_TYP values (PM1a, PM1b) Linux writes to PM1a_CNT for a power-off, served
    // by the `AcpiPm` device (local patch).
    let mut s5 = Vec::new();
    Name::new(
        Path::new("\\_S5_"),
        &Package::new(vec![&5u8, &0u8, &0u8, &0u8]),
    )
    .to_aml_bytes(&mut s5);

    let mut dsdt = Sdt::new(*b"DSDT", 36, 2, *b"LIBKRN", *b"KRUNDSDT", 1);
    dsdt.append_slice(&s5);
    dsdt.append_slice(&scope_bytes);
    dsdt.as_slice().to_vec()
}

/// Builds an ACPI 6.x FADT pointing at the given FACS and DSDT addresses.
/// It describes the fixed hardware the `AcpiPm` device serves (local patch, see VENDOR.md)
/// instead of a HW-reduced platform: the PM1 event and control blocks at `ACPI_PM_BASE`, the
/// SCI on `SCI_GSI`, and the reset register, so a guest can power off through `\_S5`, take a
/// fixed-feature power button, and reset. There is no PM timer, no GPE block and no SMI
/// command port (the platform is always in ACPI mode). IAPC_BOOT_ARCH advertises the emulated
/// i8042; Linux treats a clear `ACPI_FADT_8042` bit on FADT revision >= 2 as firmware-absent.
fn build_fadt(facs_addr: u64, dsdt_addr: u64) -> Vec<u8> {
    let io = |port: u16, len: u8, access: AccessSize| {
        GAS::new(GasSpace::SystemIo, len * 8, 0, access, u64::from(port))
    };
    let mut builder = FADTBuilder::new(*b"LIBKRN", *b"KRUNFADT", 1)
        .firmware_ctrl_64(facs_addr)
        .dsdt_64(dsdt_addr)
        .flag(Flags::Wbinvd)
        .flag(Flags::SlpButton)
        .flag(Flags::ResetRegSup)
        .flag(Flags::Headless);
    builder.iapc_boot_arch = IAPC_BOOT_ARCH_8042.into();
    builder.sci_int = (SCI_GSI as u16).into();
    builder.pm1a_evt_blk = u32::from(ACPI_PM_BASE).into();
    builder.pm1a_cnt_blk = u32::from(PM1A_CNT_PORT).into();
    builder.pm1_evt_len = PM1_EVT_LEN;
    builder.pm1_cnt_len = PM1_CNT_LEN;
    builder.x_pm1a_evt_blk = io(ACPI_PM_BASE, PM1_EVT_LEN, AccessSize::WordAccess);
    builder.x_pm1a_cnt_blk = io(PM1A_CNT_PORT, PM1_CNT_LEN, AccessSize::WordAccess);
    builder.reset_reg = io(ACPI_RESET_REG, 1, AccessSize::ByteAccess);
    builder.reset_value = ACPI_RESET_VALUE;
    let fadt = builder.finalize();
    let mut bytes = Vec::new();
    fadt.to_aml_bytes(&mut bytes);
    bytes
}

/// Builds an ACPI 6.x MADT with one Processor Local APIC entry per vCPU
/// and one I/O APIC entry.
fn build_madt(num_cpus: u8) -> Vec<u8> {
    let mut madt = MADT::new(
        *b"LIBKRN",
        *b"KRUNAPIC",
        1,
        LocalInterruptController::Address(LOCAL_APIC_DEFAULT_PHYS_BASE),
    );

    for cpu_id in 0..num_cpus {
        madt.add_structure(ProcessorLocalApic::new(
            cpu_id,
            cpu_id,
            EnabledStatus::Enabled,
        ));
    }

    madt.add_structure(IoApic::new(num_cpus + 1, IO_APIC_DEFAULT_PHYS_BASE, 0));
    // The SCI's polarity and trigger, which otherwise default to level/low for ISA IRQ 9.
    madt.add_structure(InterruptSourceOverride::new(
        SCI_GSI as u8,
        SCI_GSI,
        MADT_INT_EDGE_HIGH,
    ));

    let mut bytes = Vec::new();
    madt.to_aml_bytes(&mut bytes);

    bytes
}

/// Builds an ACPI 2.0+ XSDT with entries for the given 64-bit table addresses.
fn build_xsdt(entry_addrs: &[u64]) -> Vec<u8> {
    let mut xsdt = XSDT::new(*b"LIBKRN", *b"KRUNXSDT", 1);
    for addr in entry_addrs {
        xsdt.add_entry(*addr);
    }
    let mut bytes = Vec::new();
    xsdt.to_aml_bytes(&mut bytes);
    bytes
}

fn build_mcfg(pci_host: &PciHostInfo) -> Vec<u8> {
    let mut mcfg = MCFG::new(*b"LIBKRN", *b"KRUNMCFG", 1);
    mcfg.add_ecam(pci_host.ecam_base, 0, 0, 0);
    let mut bytes = Vec::new();
    mcfg.to_aml_bytes(&mut bytes);
    bytes
}

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// The reserved ACPI window (RSDP_ADDR..HIMEM_START) is too small to
    /// hold the generated tables.
    NotEnoughMemory,
    /// Failed to write a table into guest memory.
    WriteFailed,
    /// `num_cpus` exceeds what a single MADT I/O APIC entry ID (`num_cpus + 1`, a u8) can represent.
    TooManyCpus,
}

pub type Result<T> = result::Result<T, Error>;

/// Builds and writes RSDP, XSDT, FADT, DSDT, MCFG (if PCI is enabled) and MADT into guest memory
/// starting at `RSDP_ADDR`.
pub fn setup_acpi(
    mem: &GuestMemoryMmap,
    num_cpus: u8,
    virtio_mmio_devices: &[(u64, u32)],
    pci_host: Option<&PciHostInfo>,
) -> Result<()> {
    if u32::from(num_cpus) > MAX_SUPPORTED_CPUS {
        return Err(Error::TooManyCpus);
    }

    let dsdt = build_dsdt(virtio_mmio_devices, pci_host);
    let madt = build_madt(num_cpus);
    let mcfg = pci_host.map(build_mcfg);

    const RSDP_SIZE: u64 = 36;
    let xsdt_entries = 2 + if mcfg.is_some() { 1 } else { 0 };
    let xsdt_size = 36 + xsdt_entries * 8;
    let fadt_size_placeholder = build_fadt(0, 0).len() as u64;
    let facs = {
        let mut bytes = Vec::new();
        FACS::new().to_aml_bytes(&mut bytes);
        bytes
    };

    let rsdp_addr = RSDP_ADDR;
    let xsdt_addr = rsdp_addr + RSDP_SIZE;
    let fadt_addr = xsdt_addr + xsdt_size as u64;
    // The FACS must sit on a 64-byte boundary (ACPI 6.x § 5.2.10).
    let facs_addr = (fadt_addr + fadt_size_placeholder).next_multiple_of(64);
    let dsdt_addr = facs_addr + facs.len() as u64;
    let madt_addr = dsdt_addr + dsdt.len() as u64;
    let mcfg_addr = madt_addr + madt.len() as u64;

    let fadt = build_fadt(facs_addr, dsdt_addr);
    let mut xsdt_entries = vec![fadt_addr, madt_addr];
    if mcfg.is_some() {
        xsdt_entries.push(mcfg_addr);
    }
    let xsdt = build_xsdt(&xsdt_entries);
    let rsdp = build_rsdp(xsdt_addr);

    let total_size = mcfg_addr + mcfg.as_ref().map_or(0, |table| table.len() as u64) - rsdp_addr;
    if rsdp_addr + total_size > HIMEM_START
        || !mem.check_range(
            GuestAddress(rsdp_addr),
            total_size as usize,
            Permissions::Write,
        )
    {
        return Err(Error::NotEnoughMemory);
    }

    mem.write_slice(&rsdp, GuestAddress(rsdp_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&xsdt, GuestAddress(xsdt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&fadt, GuestAddress(fadt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&facs, GuestAddress(facs_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&dsdt, GuestAddress(dsdt_addr))
        .map_err(|_| Error::WriteFailed)?;
    mem.write_slice(&madt, GuestAddress(madt_addr))
        .map_err(|_| Error::WriteFailed)?;
    if let Some(mcfg) = mcfg {
        mem.write_slice(&mcfg, GuestAddress(mcfg_addr))
            .map_err(|_| Error::WriteFailed)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn madt_has_one_lapic_entry_per_cpu() {
        let num_cpus = 4u8;
        let bytes = build_madt(num_cpus);
        assert_eq!(&bytes[0..4], b"APIC");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        // Fixed MADT header is 44 bytes (36-byte SDT header + 4 + 4), per ACPI 6.x.
        let mut offset = 44usize;
        let mut lapic_count = 0;
        let mut ioapic_count = 0;
        let mut override_count = 0;
        while offset < bytes.len() {
            let entry_type = bytes[offset];
            let entry_len = bytes[offset + 1] as usize;
            match entry_type {
                0 => lapic_count += 1,
                1 => ioapic_count += 1,
                2 => override_count += 1,
                t => panic!("unexpected MADT entry type {t}"),
            }
            offset += entry_len;
        }
        assert_eq!(lapic_count, num_cpus as usize);
        assert_eq!(ioapic_count, 1);
        assert_eq!(override_count, 1, "the SCI override");
    }

    #[test]
    fn rsdp_checksums_are_valid() {
        let bytes = build_rsdp(crate::x86_64::layout::RSDP_ADDR);
        assert_eq!(bytes.len(), 36);

        // First 20 bytes (ACPI 1.0-compatible region) must sum to 0.
        let sum1: u8 = bytes[0..20].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum1, 0);

        // Full 36-byte structure must also sum to 0.
        let sum2: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum2, 0);

        assert_eq!(&bytes[0..8], b"RSD PTR ");
    }

    #[test]
    fn dsdt_contains_device_nodes() {
        let devices = vec![(0xd000_0000u64, 5u32), (0xd000_1000, 6)];
        let bytes = build_dsdt(&devices, None);

        assert_eq!(&bytes[..4], b"DSDT");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert!(length > 36);

        assert!(bytes.len() > 100);
    }

    #[test]
    fn dsdt_empty_devices() {
        let bytes = build_dsdt(&[], None);

        assert_eq!(&bytes[..4], b"DSDT");
        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        // Even with no virtio devices, ISA devices are still present
        let length = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert!(length > 36);
    }

    #[test]
    fn pci_dsdt_contains_root_bridge_and_interrupt_routes() {
        let pci_host = PciHostInfo {
            ecam_base: 0xe000_0000,
            bar_start: 0xe010_0000,
            bar_size: 0x1eb0_0000,
            functions: vec![PciFunctionInfo {
                device: 1,
                function: 0,
                gsi: 5,
            }],
        };
        let bytes = build_dsdt(&[], Some(&pci_host));

        assert!(bytes.windows(4).any(|part| part == b"PCI0"));
        assert!(bytes.windows(4).any(|part| part == b"_PRT"));
        assert_eq!(
            bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
    }

    #[test]
    fn mcfg_contains_bus_zero_ecam_and_valid_checksum() {
        let pci_host = PciHostInfo {
            ecam_base: 0xe000_0000,
            bar_start: 0xe010_0000,
            bar_size: 0x1eb0_0000,
            functions: Vec::new(),
        };
        let bytes = build_mcfg(&pci_host);

        assert_eq!(&bytes[..4], b"MCFG");
        assert_eq!(
            bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte)),
            0
        );
        assert_eq!(
            u64::from_le_bytes(bytes[44..52].try_into().unwrap()),
            pci_host.ecam_base
        );
        assert_eq!(u16::from_le_bytes(bytes[52..54].try_into().unwrap()), 0);
        assert_eq!(bytes[54], 0);
        assert_eq!(bytes[55], 0);
    }

    #[test]
    fn fadt_describes_the_pm1_block_sci_and_reset_register() {
        let bytes = build_fadt(0x000e_1000, 0x000e_1100);
        let u16_at = |o: usize| u16::from_le_bytes(bytes[o..o + 2].try_into().unwrap());
        let u32_at = |o: usize| u32::from_le_bytes(bytes[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());

        // Offsets per the ACPI 6.x FADT layout.
        let flags = u32_at(112);
        assert_eq!(flags & (1 << 20), 0, "not a HW-reduced platform");
        assert_ne!(flags & (1 << 10), 0, "RESET_REG_SUP");
        assert_eq!(flags & (1 << 4), 0, "fixed-feature power button");
        assert_eq!(u16_at(46), SCI_GSI as u16, "SCI_INT");
        assert_eq!(u32_at(48), 0, "no SMI_CMD: always in ACPI mode");
        assert_eq!(u32_at(56), u32::from(ACPI_PM_BASE), "PM1a_EVT_BLK");
        assert_eq!(u32_at(64), u32::from(ACPI_PM_BASE) + 4, "PM1a_CNT_BLK");
        assert_eq!((bytes[88], bytes[89]), (PM1_EVT_LEN, PM1_CNT_LEN));
        assert_eq!(bytes[116], 1, "reset register in system I/O space");
        assert_eq!(u64_at(120), u64::from(ACPI_RESET_REG));
        assert_eq!(bytes[128], ACPI_RESET_VALUE);
        assert_eq!(u64_at(132), 0x000e_1000, "X_FIRMWARE_CTRL (FACS)");
        assert_eq!(u64_at(152), u64::from(ACPI_PM_BASE), "X_PM1a_EVT_BLK");
        assert_eq!(u64_at(176), u64::from(ACPI_PM_BASE) + 4, "X_PM1a_CNT_BLK");
    }

    #[test]
    fn dsdt_declares_s5() {
        let bytes = build_dsdt(&[], None);
        assert!(bytes.windows(4).any(|w| w == b"_S5_"));
    }

    #[test]
    fn madt_overrides_the_sci_to_edge_high() {
        let bytes = build_madt(1);
        let expected = InterruptSourceOverride::new(SCI_GSI as u8, SCI_GSI, MADT_INT_EDGE_HIGH);
        assert!(bytes.windows(10).any(|w| w == expected.as_bytes()));
        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);
    }

    #[test]
    fn fadt_layout_and_checksum() {
        let bytes = build_fadt(0x000e_1000, 0x000e_1100);
        assert_eq!(&bytes[0..4], b"FACP");
        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        // x_dsdt field is at byte offset 140, little-endian u64 (ACPI 6.x FADT layout).
        let x_dsdt = u64::from_le_bytes(bytes[140..148].try_into().unwrap());
        assert_eq!(x_dsdt, 0x000e_1100);
    }

    #[test]
    fn xsdt_lists_all_entry_addresses() {
        let entries = [0x000e_2000u64, 0x000e_3000u64];
        let bytes = build_xsdt(&entries);
        assert_eq!(&bytes[0..4], b"XSDT");

        let sum: u8 = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        assert_eq!(sum, 0);

        let header_size = 36; // fixed ACPI SDT header size
        for (i, expected) in entries.iter().enumerate() {
            let off = header_size + i * 8;
            let got = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap());
            assert_eq!(got, *expected);
        }
    }

    #[test]
    fn setup_acpi_fits_in_reserved_window() {
        let window_size = (HIMEM_START - RSDP_ADDR) as usize;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), window_size)]).unwrap();

        setup_acpi(&mem, 4, &[], None).unwrap();

        let rsdp: [u8; 8] = {
            let mut buf = [0u8; 8];
            mem.read_slice(&mut buf, GuestAddress(RSDP_ADDR)).unwrap();
            buf
        };
        assert_eq!(&rsdp, b"RSD PTR ");
    }

    #[test]
    fn setup_acpi_places_an_aligned_facs() {
        let window_size = (HIMEM_START - RSDP_ADDR) as usize;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), window_size)]).unwrap();
        setup_acpi(&mem, 2, &[], None).unwrap();

        let read_u64 = |addr: u64| {
            let mut buf = [0u8; 8];
            mem.read_slice(&mut buf, GuestAddress(addr)).unwrap();
            u64::from_le_bytes(buf)
        };
        // RSDP -> XSDT (offset 24) -> first entry, the FADT -> X_FIRMWARE_CTRL (offset 132).
        let xsdt = read_u64(RSDP_ADDR + 24);
        let fadt = read_u64(xsdt + 36);
        let facs = read_u64(fadt + 132);
        assert_eq!(facs % 64, 0, "FACS at {facs:#x} must be 64-byte aligned");
        let mut sig = [0u8; 4];
        mem.read_slice(&mut sig, GuestAddress(facs)).unwrap();
        assert_eq!(&sig, b"FACS");
    }

    #[test]
    fn setup_acpi_adds_mcfg_to_xsdt() {
        let window_size = (HIMEM_START - RSDP_ADDR) as usize;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), window_size)]).unwrap();
        let pci_host = PciHostInfo {
            ecam_base: 0xe000_0000,
            bar_start: 0xe010_0000,
            bar_size: 0x1eb0_0000,
            functions: Vec::new(),
        };

        setup_acpi(&mem, 1, &[], Some(&pci_host)).unwrap();

        let mut rsdp = [0; 36];
        mem.read_slice(&mut rsdp, GuestAddress(RSDP_ADDR)).unwrap();
        let xsdt_addr = u64::from_le_bytes(rsdp[24..32].try_into().unwrap());
        let mut xsdt_header = [0; 36];
        mem.read_slice(&mut xsdt_header, GuestAddress(xsdt_addr))
            .unwrap();
        let xsdt_len = u32::from_le_bytes(xsdt_header[4..8].try_into().unwrap()) as usize;
        assert_eq!((xsdt_len - 36) / 8, 3);

        let mut entries = [0; 24];
        mem.read_slice(&mut entries, GuestAddress(xsdt_addr + 36))
            .unwrap();
        let mcfg_addr = u64::from_le_bytes(entries[16..24].try_into().unwrap());
        let mut signature = [0; 4];
        mem.read_slice(&mut signature, GuestAddress(mcfg_addr))
            .unwrap();
        assert_eq!(&signature, b"MCFG");
    }

    #[test]
    fn setup_acpi_fails_if_window_too_small() {
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), 8)]).unwrap();
        assert!(setup_acpi(&mem, 4, &[], None).is_err());
    }

    #[test]
    fn setup_acpi_fails_if_too_many_cpus() {
        let window_size = (HIMEM_START - RSDP_ADDR) as usize;
        let mem = GuestMemoryMmap::from_ranges(&[(GuestAddress(RSDP_ADDR), window_size)]).unwrap();

        assert_eq!(setup_acpi(&mem, 255, &[], None), Err(Error::TooManyCpus));
    }
}
