// SPDX-License-Identifier: Apache-2.0
//
// Minimal ACPI table set for x86_64 guests. Enough for a Linux guest to find an
// RSDP, enumerate CPUs and the IOAPIC from the MADT, drive an ACPI power-off
// (\_S5 + the PM1a control block), take a fixed-feature power button over the
// SCI, and reset through the FADT reset register. No PM timer, no GPE blocks, no
// control methods beyond the DSDT's \_S5 and PCI0 root bridge.
//
// Tables are assembled into one byte buffer and written to guest RAM at
// `ACPI_TABLES_START`; every internal pointer is that base plus an offset. The
// DSDT is a precompiled AML blob (see dsdt.asl / DSDT_AML).

use std::mem::size_of;

use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryMmap};

use crate::x86_64::layout::{
    ACPI_PM_BASE, ACPI_RESET_REG, ACPI_RESET_VALUE, ACPI_TABLES_END, ACPI_TABLES_START, SCI_GSI,
};

/// Precompiled DSDT AML. Source: dsdt.asl (this directory), compiled with iasl
/// (ACPICA). Regenerate with `iasl -tc dsdt.asl` and copy the byte array. Holds
/// only \_S5 (ACPI power-off) and the \_SB.PCI0 root bridge, whose _CRS declares the
/// 32-bit window the virtio BAR0s sit in and the 64-bit window (`layout::SHM_MEM_START`,
/// `SHM_MEM_SIZE`) the virtio-fs DAX windows do.
#[rustfmt::skip]
const DSDT_AML: [u8; 236] = [
    0x44, 0x53, 0x44, 0x54, 0xec, 0x00, 0x00, 0x00, 0x02, 0xb3, 0x4b, 0x52,
    0x55, 0x4e, 0x20, 0x20, 0x4b, 0x52, 0x55, 0x4e, 0x56, 0x4b, 0x49, 0x54,
    0x01, 0x00, 0x00, 0x00, 0x49, 0x4e, 0x54, 0x4c, 0x12, 0x12, 0x25, 0x20,
    0x08, 0x5f, 0x53, 0x35, 0x5f, 0x12, 0x07, 0x04, 0x0a, 0x05, 0x00, 0x00,
    0x00, 0x10, 0x4a, 0x0b, 0x5f, 0x53, 0x42, 0x5f, 0x5b, 0x82, 0x42, 0x0b,
    0x50, 0x43, 0x49, 0x30, 0x08, 0x5f, 0x48, 0x49, 0x44, 0x0c, 0x41, 0xd0,
    0x0a, 0x03, 0x08, 0x5f, 0x55, 0x49, 0x44, 0x00, 0x08, 0x5f, 0x42, 0x42,
    0x4e, 0x00, 0x14, 0x09, 0x5f, 0x53, 0x54, 0x41, 0x00, 0xa4, 0x0a, 0x0f,
    0x08, 0x5f, 0x43, 0x52, 0x53, 0x11, 0x46, 0x08, 0x0a, 0x82, 0x88, 0x0d,
    0x00, 0x02, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x47, 0x01, 0xf8, 0x0c, 0xf8, 0x0c, 0x01, 0x08, 0x88, 0x0d,
    0x00, 0x01, 0x0c, 0x03, 0x00, 0x00, 0x00, 0x00, 0xf7, 0x0c, 0x00, 0x00,
    0xf8, 0x0c, 0x88, 0x0d, 0x00, 0x01, 0x0c, 0x03, 0x00, 0x00, 0x00, 0x0d,
    0xff, 0xff, 0x00, 0x00, 0x00, 0xf3, 0x87, 0x17, 0x00, 0x00, 0x0c, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xbf, 0xfe,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x1e, 0x8a, 0x2b, 0x00, 0x00,
    0x0c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x79, 0x00,
];

const APIC_DEFAULT_PHYS_BASE: u32 = 0xfee0_0000;
const IO_APIC_DEFAULT_PHYS_BASE: u32 = 0xfec0_0000;

const OEM_ID: [u8; 6] = *b"KRUN  ";
const OEM_TABLE_ID: [u8; 8] = *b"KRUNVKIT";
const OEM_REVISION: u32 = 1;
const CREATOR_ID: [u8; 4] = *b"KRUN";
const CREATOR_REVISION: u32 = 1;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    /// The tables do not fit in the reserved region.
    NotEnoughSpace,
    /// Failed to write the tables to guest memory.
    Write,
}

pub type Result<T> = std::result::Result<T, Error>;

/// ACPI Generic Address Structure.
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct GenericAddress {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
}
unsafe impl ByteValued for GenericAddress {}

const SPACE_SYSTEM_IO: u8 = 1;
const ACCESS_BYTE: u8 = 1;
const ACCESS_WORD: u8 = 2;

impl GenericAddress {
    fn io(port: u16, bit_width: u8, access_size: u8) -> Self {
        GenericAddress {
            address_space_id: SPACE_SYSTEM_IO,
            register_bit_width: bit_width,
            register_bit_offset: 0,
            access_size,
            address: u64::from(port),
        }
    }
}

/// The common System Description Table header (RSDT/XSDT/FADT/MADT/DSDT...).
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: [u8; 4],
    creator_revision: u32,
}
unsafe impl ByteValued for SdtHeader {}

impl SdtHeader {
    fn new(signature: &[u8; 4], length: u32, revision: u8) -> Self {
        SdtHeader {
            signature: *signature,
            length,
            revision,
            checksum: 0,
            oem_id: OEM_ID,
            oem_table_id: OEM_TABLE_ID,
            oem_revision: OEM_REVISION,
            creator_id: CREATOR_ID,
            creator_revision: CREATOR_REVISION,
        }
    }
}

/// Root System Description Pointer (ACPI 2.0+, 36 bytes).
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    length: u32,
    xsdt_address: u64,
    extended_checksum: u8,
    reserved: [u8; 3],
}
unsafe impl ByteValued for Rsdp {}

/// Fixed ACPI Description Table (revision 6).
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct Fadt {
    header: SdtHeader,
    firmware_ctrl: u32,
    dsdt: u32,
    reserved0: u8,
    preferred_pm_profile: u8,
    sci_int: u16,
    smi_cmd: u32,
    acpi_enable: u8,
    acpi_disable: u8,
    s4bios_req: u8,
    pstate_cnt: u8,
    pm1a_evt_blk: u32,
    pm1b_evt_blk: u32,
    pm1a_cnt_blk: u32,
    pm1b_cnt_blk: u32,
    pm2_cnt_blk: u32,
    pm_tmr_blk: u32,
    gpe0_blk: u32,
    gpe1_blk: u32,
    pm1_evt_len: u8,
    pm1_cnt_len: u8,
    pm2_cnt_len: u8,
    pm_tmr_len: u8,
    gpe0_blk_len: u8,
    gpe1_blk_len: u8,
    gpe1_base: u8,
    cst_cnt: u8,
    p_lvl2_lat: u16,
    p_lvl3_lat: u16,
    flush_size: u16,
    flush_stride: u16,
    duty_offset: u8,
    duty_width: u8,
    day_alrm: u8,
    mon_alrm: u8,
    century: u8,
    iapc_boot_arch: u16,
    reserved1: u8,
    flags: u32,
    reset_reg: GenericAddress,
    reset_value: u8,
    arm_boot_arch: u16,
    minor_version: u8,
    x_firmware_ctrl: u64,
    x_dsdt: u64,
    x_pm1a_evt_blk: GenericAddress,
    x_pm1b_evt_blk: GenericAddress,
    x_pm1a_cnt_blk: GenericAddress,
    x_pm1b_cnt_blk: GenericAddress,
    x_pm2_cnt_blk: GenericAddress,
    x_pm_tmr_blk: GenericAddress,
    x_gpe0_blk: GenericAddress,
    x_gpe1_blk: GenericAddress,
    sleep_control_reg: GenericAddress,
    sleep_status_reg: GenericAddress,
    hypervisor_vendor_id: u64,
}
unsafe impl ByteValued for Fadt {}

// FADT feature flags.
const FADT_WBINVD: u32 = 1 << 0;
const FADT_SLP_BUTTON: u32 = 1 << 5; // no fixed sleep button
const FADT_RESET_REG_SUP: u32 = 1 << 10;
const FADT_HEADLESS: u32 = 1 << 12;
// IAPC boot architecture flags.
const IAPC_8042: u16 = 1 << 1;
const IAPC_VGA_NOT_PRESENT: u16 = 1 << 2;
// PM block widths (bytes) and register offsets from ACPI_PM_BASE (see AcpiPm).
const PM1_EVT_LEN: u8 = 4;
const PM1_CNT_LEN: u8 = 2;
const PM1A_CNT_PORT: u16 = ACPI_PM_BASE + 0x04;

/// Firmware ACPI Control Structure (64 bytes, no checksum).
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct Facs {
    signature: [u8; 4],
    length: u32,
    hardware_signature: u32,
    firmware_waking_vector: u32,
    global_lock: u32,
    flags: u32,
    x_firmware_waking_vector: u64,
    version: u8,
    reserved0: [u8; 3],
    ospm_flags: u32,
    reserved1: [u8; 24],
}
unsafe impl ByteValued for Facs {}

/// MADT header body (after the common SDT header).
#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct MadtHeader {
    header: SdtHeader,
    local_apic_address: u32,
    flags: u32,
}
unsafe impl ByteValued for MadtHeader {}

const MADT_PCAT_COMPAT: u32 = 1;

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct MadtLocalApic {
    type_: u8,
    length: u8,
    processor_uid: u8,
    apic_id: u8,
    flags: u32,
}
unsafe impl ByteValued for MadtLocalApic {}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct MadtIoApic {
    type_: u8,
    length: u8,
    ioapic_id: u8,
    reserved: u8,
    address: u32,
    gsi_base: u32,
}
unsafe impl ByteValued for MadtIoApic {}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct MadtIntOverride {
    type_: u8,
    length: u8,
    bus: u8,
    source: u8,
    gsi: u32,
    flags: u16,
}
unsafe impl ByteValued for MadtIntOverride {}

#[repr(C, packed)]
#[derive(Copy, Clone, Default)]
struct MadtLocalApicNmi {
    type_: u8,
    length: u8,
    processor_uid: u8,
    flags: u16,
    lint: u8,
}
unsafe impl ByteValued for MadtLocalApicNmi {}

const MADT_TYPE_LOCAL_APIC: u8 = 0;
const MADT_TYPE_IO_APIC: u8 = 1;
const MADT_TYPE_INT_OVERRIDE: u8 = 2;
const MADT_TYPE_LOCAL_APIC_NMI: u8 = 4;
const MADT_LAPIC_ENABLED: u32 = 1;
// Interrupt flags: polarity 01 (active high), trigger 01 (edge). The SCI is
// delivered by a one-shot KVM_IRQFD with no resample fd, so it is programmed
// edge/high — the same reason the MP table uses edge/high for PCI INTx.
const MADT_INT_EDGE_HIGH: u16 = 0b0101;

/// Wrapping one's-complement checksum: the byte that makes the sum of the range zero.
fn checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    sum.wrapping_neg()
}

/// Append `obj`'s bytes to `buf`, returning the offset it was written at.
fn push<T: ByteValued>(buf: &mut Vec<u8>, obj: &T) -> usize {
    let offset = buf.len();
    buf.extend_from_slice(obj.as_slice());
    offset
}

/// Pad `buf` up to an 8-byte boundary so the next table starts aligned.
fn align(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(8) {
        buf.push(0);
    }
}

/// Build the tables and write them to guest memory. Returns the guest address of
/// the RSDP, to be handed to the guest via `boot_params.acpi_rsdp_addr`.
pub fn setup_acpi(mem: &GuestMemoryMmap, num_cpus: u8) -> Result<u64> {
    let base = ACPI_TABLES_START;
    let mut buf: Vec<u8> = Vec::new();

    // Reserve the RSDP slot; filled in last (it points at the XSDT).
    let rsdp_off = buf.len();
    buf.extend_from_slice(&[0u8; size_of::<Rsdp>()]);
    align(&mut buf);

    // XSDT: header + pointers to FADT and MADT (addresses computed below).
    let xsdt_off = buf.len();
    let xsdt_len = size_of::<SdtHeader>() + 2 * size_of::<u64>();
    buf.resize(buf.len() + xsdt_len, 0);
    align(&mut buf);

    // FADT.
    let fadt_off = buf.len();
    // FACS and DSDT addresses are known once we place them after the FADT.
    buf.extend_from_slice(&[0u8; size_of::<Fadt>()]);
    align(&mut buf);

    // FACS (no checksum).
    let facs_off = buf.len();
    let facs = Facs {
        signature: *b"FACS",
        length: size_of::<Facs>() as u32,
        version: 2,
        ..Default::default()
    };
    push(&mut buf, &facs);
    align(&mut buf);

    // MADT.
    let madt_off = buf.len();
    build_madt(&mut buf, num_cpus);
    align(&mut buf);

    // DSDT (precompiled AML).
    let dsdt_off = buf.len();
    buf.extend_from_slice(&DSDT_AML);
    align(&mut buf);

    let addr = |off: usize| base + off as u64;

    // Now fill in the FADT, which points at FACS and DSDT.
    let fadt = build_fadt(addr(facs_off), addr(dsdt_off));
    buf[fadt_off..fadt_off + size_of::<Fadt>()].copy_from_slice(fadt.as_slice());
    let fadt_bytes = &mut buf[fadt_off..fadt_off + size_of::<Fadt>()];
    fadt_bytes[9] = checksum(fadt_bytes);

    // XSDT: header then the two entries (FADT, MADT).
    let xsdt_hdr = SdtHeader::new(b"XSDT", xsdt_len as u32, 1);
    buf[xsdt_off..xsdt_off + size_of::<SdtHeader>()].copy_from_slice(xsdt_hdr.as_slice());
    let e0 = xsdt_off + size_of::<SdtHeader>();
    buf[e0..e0 + 8].copy_from_slice(&addr(fadt_off).to_le_bytes());
    buf[e0 + 8..e0 + 16].copy_from_slice(&addr(madt_off).to_le_bytes());
    let xsdt_bytes = &mut buf[xsdt_off..xsdt_off + xsdt_len];
    xsdt_bytes[9] = checksum(xsdt_bytes);

    // RSDP last.
    let mut rsdp = Rsdp {
        signature: *b"RSD PTR ",
        checksum: 0,
        oem_id: OEM_ID,
        revision: 2,
        rsdt_address: 0,
        length: size_of::<Rsdp>() as u32,
        xsdt_address: addr(xsdt_off),
        extended_checksum: 0,
        reserved: [0; 3],
    };
    // First checksum covers the ACPI 1.0 part (first 20 bytes); the extended one
    // covers all 36.
    rsdp.checksum = checksum(&rsdp.as_slice()[..20]);
    rsdp.extended_checksum = checksum(rsdp.as_slice());
    buf[rsdp_off..rsdp_off + size_of::<Rsdp>()].copy_from_slice(rsdp.as_slice());

    let end = base + buf.len() as u64;
    if end > ACPI_TABLES_END {
        return Err(Error::NotEnoughSpace);
    }
    if !mem.address_in_range(GuestAddress(end - 1)) {
        return Err(Error::NotEnoughSpace);
    }
    mem.write_slice(&buf, GuestAddress(base))
        .map_err(|_| Error::Write)?;

    Ok(addr(rsdp_off))
}

fn build_fadt(facs_addr: u64, dsdt_addr: u64) -> Fadt {
    // Checksum is computed over the serialised bytes, not the struct.
    Fadt {
        header: SdtHeader::new(b"FACP", size_of::<Fadt>() as u32, 6),
        firmware_ctrl: facs_addr as u32,
        dsdt: dsdt_addr as u32,
        sci_int: SCI_GSI as u16,
        smi_cmd: 0,
        pm1a_evt_blk: u32::from(ACPI_PM_BASE),
        pm1a_cnt_blk: u32::from(PM1A_CNT_PORT),
        pm1_evt_len: PM1_EVT_LEN,
        pm1_cnt_len: PM1_CNT_LEN,
        // An i8042 keyboard controller is emulated (i8042.rs), so advertise it.
        iapc_boot_arch: IAPC_8042 | IAPC_VGA_NOT_PRESENT,
        flags: FADT_WBINVD | FADT_SLP_BUTTON | FADT_RESET_REG_SUP | FADT_HEADLESS,
        reset_reg: GenericAddress::io(ACPI_RESET_REG, 8, ACCESS_BYTE),
        reset_value: ACPI_RESET_VALUE,
        minor_version: 0,
        x_firmware_ctrl: facs_addr,
        x_dsdt: dsdt_addr,
        x_pm1a_evt_blk: GenericAddress::io(ACPI_PM_BASE, PM1_EVT_LEN * 8, ACCESS_WORD),
        x_pm1a_cnt_blk: GenericAddress::io(PM1A_CNT_PORT, PM1_CNT_LEN * 8, ACCESS_WORD),
        ..Default::default()
    }
}

fn build_madt(buf: &mut Vec<u8>, num_cpus: u8) {
    let start = buf.len();
    // Header body, patched with the final length afterwards.
    let hdr = MadtHeader {
        header: SdtHeader::new(b"APIC", 0, 5),
        local_apic_address: APIC_DEFAULT_PHYS_BASE,
        flags: MADT_PCAT_COMPAT,
    };
    push(buf, &hdr);

    for cpu in 0..num_cpus {
        push(
            buf,
            &MadtLocalApic {
                type_: MADT_TYPE_LOCAL_APIC,
                length: size_of::<MadtLocalApic>() as u8,
                processor_uid: cpu,
                apic_id: cpu,
                flags: MADT_LAPIC_ENABLED,
            },
        );
    }

    push(
        buf,
        &MadtIoApic {
            type_: MADT_TYPE_IO_APIC,
            length: size_of::<MadtIoApic>() as u8,
            ioapic_id: num_cpus.wrapping_add(1),
            reserved: 0,
            address: IO_APIC_DEFAULT_PHYS_BASE,
            gsi_base: 0,
        },
    );

    // The SCI (IRQ == GSI == SCI_GSI) is edge/high, not the ISA default.
    push(
        buf,
        &MadtIntOverride {
            type_: MADT_TYPE_INT_OVERRIDE,
            length: size_of::<MadtIntOverride>() as u8,
            bus: 0,
            source: SCI_GSI as u8,
            gsi: SCI_GSI,
            flags: MADT_INT_EDGE_HIGH,
        },
    );

    push(
        buf,
        &MadtLocalApicNmi {
            type_: MADT_TYPE_LOCAL_APIC_NMI,
            length: size_of::<MadtLocalApicNmi>() as u8,
            processor_uid: 0xff,
            flags: 0,
            lint: 1,
        },
    );

    let len = (buf.len() - start) as u32;
    buf[start + 4..start + 8].copy_from_slice(&len.to_le_bytes());
    let madt_bytes = &mut buf[start..start + len as usize];
    madt_bytes[9] = checksum(madt_bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x86_64::layout::{SHM_MEM_SIZE, SHM_MEM_START};

    fn read_table(buf: &[u8], sig: &[u8; 4]) -> Option<(usize, usize)> {
        // Find a table by signature by scanning (tests only).
        let mut i = 0;
        while i + 8 <= buf.len() {
            if &buf[i..i + 4] == sig {
                let len =
                    u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]) as usize;
                if len >= 8 && i + len <= buf.len() {
                    return Some((i, len));
                }
            }
            i += 1;
        }
        None
    }

    fn build(num_cpus: u8) -> (Vec<u8>, u64) {
        let mem =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), ACPI_TABLES_END as usize + 0x1000)])
                .unwrap();
        let rsdp = setup_acpi(&mem, num_cpus).unwrap();
        let mut buf = vec![0u8; (ACPI_TABLES_END - ACPI_TABLES_START) as usize];
        mem.read_slice(&mut buf, GuestAddress(ACPI_TABLES_START))
            .unwrap();
        (buf, rsdp)
    }

    #[test]
    fn sizes_are_canonical() {
        assert_eq!(size_of::<GenericAddress>(), 12);
        assert_eq!(size_of::<SdtHeader>(), 36);
        assert_eq!(size_of::<Rsdp>(), 36);
        assert_eq!(size_of::<Fadt>(), 276);
        assert_eq!(size_of::<Facs>(), 64);
    }

    #[test]
    fn rsdp_points_to_valid_tables() {
        let (buf, rsdp) = build(2);
        assert_eq!(rsdp, ACPI_TABLES_START);
        let r = &buf[0..36];
        assert_eq!(&r[0..8], b"RSD PTR ");
        assert_eq!(checksum(&r[..20]), 0);
        assert_eq!(checksum(r), 0);
    }

    #[test]
    fn table_checksums_zero() {
        let (buf, _) = build(4);
        for sig in [b"XSDT", b"FACP", b"APIC", b"DSDT"] {
            let (off, len) = read_table(&buf, sig).unwrap_or_else(|| panic!("missing table"));
            assert_eq!(
                checksum(&buf[off..off + len]),
                0,
                "bad checksum for a table"
            );
        }
    }

    #[test]
    fn madt_has_one_lapic_per_cpu() {
        for cpus in [1u8, 4, 16] {
            let (buf, _) = build(cpus);
            let (off, len) = read_table(&buf, b"APIC").unwrap();
            let mut i = off + size_of::<MadtHeader>();
            let end = off + len;
            let mut lapics = 0u8;
            while i + 2 <= end {
                let type_ = buf[i];
                let elen = buf[i + 1] as usize;
                assert!(elen >= 2 && i + elen <= end);
                if type_ == MADT_TYPE_LOCAL_APIC {
                    lapics += 1;
                }
                i += elen;
            }
            assert_eq!(lapics, cpus);
        }
    }

    /// The DSDT is a hand-pasted AML blob and the checksum tests pass whatever it holds, so
    /// nothing else ties the host-bridge window it declares to the span the DAX BARs are
    /// carved from. Let them drift and every guest silently loses its DAX windows.
    /// (Local patch — see ../../../../VENDOR.md.)
    #[test]
    fn dsdt_declares_the_shm_host_bridge_window() {
        // ACPI QWord Address Space Descriptor: tag 0x8a, a le16 body length of 0x2b, then
        // three flag bytes followed by granularity, min, max, translation offset and length
        // as little-endian u64s.
        let start = DSDT_AML
            .windows(3)
            .position(|w| w == [0x8a, 0x2b, 0x00])
            .expect("no QWordMemory descriptor in the DSDT");
        let field = |n: usize| {
            let off = start + 6 + n * 8;
            u64::from_le_bytes(DSDT_AML[off..off + 8].try_into().unwrap())
        };
        let (min, max, len) = (field(1), field(2), field(4));

        assert_eq!(min, SHM_MEM_START);
        assert_eq!(len, SHM_MEM_SIZE);
        assert_eq!(max, min + len - 1);
    }

    #[test]
    fn fadt_reset_and_pm_fields() {
        let (buf, _) = build(1);
        let (off, _) = read_table(&buf, b"FACP").unwrap();
        let fadt = &buf[off..off + size_of::<Fadt>()];
        // sci_int at offset 46.
        assert_eq!(u16::from_le_bytes([fadt[46], fadt[47]]), SCI_GSI as u16);
        // reset_value at 128.
        assert_eq!(fadt[128], ACPI_RESET_VALUE);
        // reset_reg address (GAS at 116, address u64 at 116+4).
        let raddr = u64::from_le_bytes(fadt[120..128].try_into().unwrap());
        assert_eq!(raddr, u64::from(ACPI_RESET_REG));
    }
}
