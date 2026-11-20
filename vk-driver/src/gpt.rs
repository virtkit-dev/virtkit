//! Read partition types, unique GUIDs, names and byte ranges from a disk image's primary GPT.
//! Check the protective MBR, header revision, reserved field, table layout, header and array
//! CRCs, and partition bounds. An invalid primary is an error. The backup table is never read.

use anyhow::{Context, Result, bail};

use crate::diskimg::DiskImage;

/// The sector size vk's disks are attached with.
pub const SECTOR: u64 = 512;
/// Maximum entry count. Partitioners typically write 128 entries.
const MAX_ENTRIES: u32 = 1024;
/// Linux ignores a GPT whose entries are not 128 bytes.
const ENTRY_SIZE: u32 = 128;
/// UEFI reserves at least 16 KiB for each entry array.
const MIN_ARRAY_SECTORS: u64 = 16384 / SECTOR;

// GUID comparisons use the uppercase text returned by read.

/// `Linux extended boot` (XBOOTLDR): the `/boot` a boot loader reads the kernel from.
pub const TYPE_XBOOTLDR: &str = "BC13C2FF-59E6-4262-A352-B275FD6F7172";
/// `Linux root (x86-64)`.
pub const TYPE_ROOT_X86_64: &str = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    /// 1-based, as Linux numbers it (`/dev/vda<index>`).
    pub index: u32,
    pub type_guid: String,
    pub unique_guid: String,
    /// A label only, decoded lossily: the guest writes it.
    pub name: String,
    /// Byte offset and length on the disk.
    pub offset: u64,
    pub len: u64,
}

/// The partitions of the GPT on `disk`, in table order, unused entries left out.
pub fn read(disk: &DiskImage) -> Result<Vec<Partition>> {
    let mut mbr = [0u8; SECTOR as usize];
    disk.read_exact_at(&mut mbr, 0)
        .context("reading the protective MBR")?;
    // By default, Linux requires a protective entry of type 0xEE starting at LBA 1.
    if mbr[510..512] != [0x55, 0xAA]
        || !mbr[446..510]
            .as_chunks::<16>()
            .0
            .iter()
            .any(|e| e[4] == 0xEE && rd32(e, 8) == 1)
    {
        bail!("no protective MBR at LBA 0");
    }
    let mut hdr = [0u8; SECTOR as usize];
    disk.read_exact_at(&mut hdr, SECTOR)
        .context("reading the GPT header")?;
    if &hdr[0..8] != b"EFI PART" {
        bail!("no GPT header at LBA 1");
    }
    let hdr_size = rd32(&hdr, 12) as usize;
    if !(92..=SECTOR as usize).contains(&hdr_size) {
        bail!("GPT header size {hdr_size} outside 92..=512");
    }
    let mut crc_input = hdr[..hdr_size].to_vec();
    crc_input[16..20].fill(0);
    if crc32(&crc_input) != rd32(&hdr, 16) {
        bail!("GPT header CRC mismatch");
    }
    if rd32(&hdr, 8) != 0x0001_0000 {
        bail!("GPT header revision {:#x} unsupported", rd32(&hdr, 8));
    }
    if rd32(&hdr, 20) != 0 {
        bail!("GPT header reserved field nonzero");
    }
    let sectors = disk.len() / SECTOR;
    let (my_lba, alternate) = (rd64(&hdr, 24), rd64(&hdr, 32));
    let first_usable = rd64(&hdr, 40);
    let last_usable = rd64(&hdr, 48);
    let entries_lba = rd64(&hdr, 72);
    let count = rd32(&hdr, 80);
    let entry_size = rd32(&hdr, 84);
    if count == 0 || count > MAX_ENTRIES || entry_size != ENTRY_SIZE {
        bail!("GPT entry array of {count} entries of {entry_size} bytes");
    }
    let array_len = u64::from(count) * u64::from(entry_size);
    // Each array needs whole sectors and at least the UEFI minimum. The primary array
    // fits before the first usable LBA. Leave room for the backup array immediately
    // before its header, which may precede the end of a grown disk.
    let array_sectors = array_len.div_ceil(SECTOR).max(MIN_ARRAY_SECTORS);
    // Reject overflow in layout sums computed from guest header fields.
    let fits = |a: u64, b: u64, limit: u64| a.checked_add(b).is_some_and(|end| end <= limit);
    if my_lba != 1
        || entries_lba < 2
        || !fits(entries_lba, array_sectors, first_usable)
        || first_usable > last_usable
        || alternate >= sectors
        || !fits(last_usable, array_sectors, alternate.saturating_sub(1))
    {
        bail!(
            "GPT layout inconsistent: header at LBA {my_lba}, backup at {alternate}, entries at \
             {entries_lba} ({array_sectors} sectors), usable {first_usable}..={last_usable}, \
             {sectors} sectors"
        );
    }
    let mut array = vec![0u8; array_len as usize];
    let array_at = entries_lba
        .checked_mul(SECTOR)
        .context("GPT entry array offset overflows")?;
    disk.read_exact_at(&mut array, array_at)
        .context("reading the GPT entry array")?;
    if crc32(&array) != rd32(&hdr, 88) {
        bail!("GPT entry array CRC mismatch");
    }

    let mut parts: Vec<Partition> = Vec::new();
    for (i, e) in array.chunks_exact(entry_size as usize).enumerate() {
        if e[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        let (first, last) = (rd64(e, 32), rd64(e, 40));
        if first < first_usable || last > last_usable || first > last {
            bail!(
                "GPT partition {} spans LBA {first}..={last}, outside the usable range",
                i + 1
            );
        }
        if let Some(p) = parts.iter().find(|p| {
            let (pf, pl) = (p.offset / SECTOR, (p.offset + p.len) / SECTOR - 1);
            first <= pl && pf <= last
        }) {
            bail!("GPT partitions {} and {} overlap", p.index, i + 1);
        }
        let unique_guid = guid(&e[16..32]);
        if let Some(p) = parts.iter().find(|p| p.unique_guid == unique_guid) {
            bail!(
                "GPT partitions {} and {} share GUID {unique_guid}",
                p.index,
                i + 1
            );
        }
        let name: Vec<u16> = e[56..128]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .take_while(|&c| c != 0)
            .collect();
        parts.push(Partition {
            index: i as u32 + 1,
            type_guid: guid(&e[0..16]),
            unique_guid,
            name: String::from_utf16_lossy(&name),
            offset: first * SECTOR,
            len: (last - first + 1) * SECTOR,
        });
    }
    Ok(parts)
}

/// The one partition of type `type_guid`; none or several is an error.
pub fn only_of_type<'a>(parts: &'a [Partition], type_guid: &str) -> Result<&'a Partition> {
    let mut it = parts.iter().filter(|p| p.type_guid == type_guid);
    match (it.next(), it.next()) {
        (Some(p), None) => Ok(p),
        (None, _) => bail!("no GPT partition of type {type_guid}"),
        (Some(a), Some(b)) => bail!(
            "GPT partitions {} and {} are both of type {type_guid}",
            a.index,
            b.index
        ),
    }
}

/// A GUID in its text form: the first three fields are little-endian on disk.
fn guid(b: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{}",
        rd32(b, 0),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10..16]
            .iter()
            .map(|x| format!("{x:02X}"))
            .collect::<String>()
    )
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

fn rd64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

/// CRC-32 (IEEE 802.3, reflected), as the GPT checksums are.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (crc & 1).wrapping_neg());
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guid_bytes(s: &str) -> [u8; 16] {
        let h: Vec<u8> = (0..32)
            .step_by(2)
            .map(|i| {
                let hex: String = s.chars().filter(|c| *c != '-').collect();
                u8::from_str_radix(&hex[i..i + 2], 16).unwrap()
            })
            .collect();
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&[h[3], h[2], h[1], h[0]]);
        b[4..6].copy_from_slice(&[h[5], h[4]]);
        b[6..8].copy_from_slice(&[h[7], h[6]]);
        b[8..16].copy_from_slice(&h[8..16]);
        b
    }

    /// A 1 MiB GPT disk. Each tuple supplies the type, first and last LBA, and name.
    /// An empty type marks an unused entry. The header points to an unwritten backup
    /// at the last LBA.
    fn disk(parts: &[(&str, u64, u64, &str)]) -> Vec<u8> {
        let sectors = 2048u64;
        let mut d = vec![0u8; (sectors * SECTOR) as usize];
        let mut array = vec![0u8; 128 * 128];
        for (i, (ty, first, last, name)) in parts.iter().enumerate() {
            if ty.is_empty() {
                continue;
            }
            let e = &mut array[i * 128..(i + 1) * 128];
            e[0..16].copy_from_slice(&guid_bytes(ty));
            e[16..32].copy_from_slice(&[i as u8 + 1; 16]);
            e[32..40].copy_from_slice(&first.to_le_bytes());
            e[40..48].copy_from_slice(&last.to_le_bytes());
            for (j, c) in name.encode_utf16().enumerate() {
                e[56 + 2 * j..58 + 2 * j].copy_from_slice(&c.to_le_bytes());
            }
        }
        d[446 + 4] = 0xEE;
        d[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
        d[510..512].copy_from_slice(&[0x55, 0xAA]);
        let h = &mut d[512..1024];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&1u64.to_le_bytes());
        h[32..40].copy_from_slice(&(sectors - 1).to_le_bytes());
        h[40..48].copy_from_slice(&34u64.to_le_bytes());
        h[48..56].copy_from_slice(&(sectors - 34).to_le_bytes());
        h[72..80].copy_from_slice(&2u64.to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&crc32(&array).to_le_bytes());
        let c = crc32(&h[..92]);
        h[16..20].copy_from_slice(&c.to_le_bytes());
        d[1024..1024 + array.len()].copy_from_slice(&array);
        d
    }

    fn read_bytes(d: &[u8]) -> Result<Vec<Partition>> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("vk-gpt-{}-{seq}", std::process::id()));
        vk_fs::write_new(&p, d, 0o600).unwrap();
        let img = DiskImage::open(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        read(&img)
    }

    /// `disk` with header field `off` set to `v`, its CRC recomputed.
    fn with(d: &[u8], off: usize, v: &[u8]) -> Vec<u8> {
        let mut d = d.to_vec();
        d[512 + off..512 + off + v.len()].copy_from_slice(v);
        d[512 + 16..512 + 20].fill(0);
        let c = crc32(&d[512..512 + 92]);
        d[512 + 16..512 + 20].copy_from_slice(&c.to_le_bytes());
        d
    }

    #[test]
    fn crc32_is_ieee() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    /// Unused entries count toward Linux partition numbers. A name can fill its field
    /// without a terminating NUL.
    #[test]
    fn partitions_keep_their_table_numbers() {
        let long = "n".repeat(36);
        let parts = read_bytes(&disk(&[
            (TYPE_XBOOTLDR, 100, 199, "a"),
            ("", 0, 0, ""),
            (TYPE_ROOT_X86_64, 200, 299, &long),
        ]))
        .unwrap();
        let got: Vec<(u32, &str)> = parts.iter().map(|p| (p.index, p.name.as_str())).collect();
        assert_eq!(got, [(1, "a"), (3, long.as_str())]);
    }

    #[test]
    fn reads_partitions_and_finds_one_by_type() {
        let d = disk(&[
            (TYPE_XBOOTLDR, 2048 - 1000, 2048 - 600, "boot"),
            (TYPE_ROOT_X86_64, 100, 199, "root"),
        ]);
        let parts = read_bytes(&d).unwrap();
        assert_eq!(parts.len(), 2);
        let boot = only_of_type(&parts, TYPE_XBOOTLDR).unwrap();
        assert_eq!(boot.index, 1);
        assert_eq!(boot.name, "boot");
        assert_eq!(boot.offset, 1048 * SECTOR);
        assert_eq!(boot.len, 401 * SECTOR);
        assert_eq!(
            only_of_type(&parts, TYPE_ROOT_X86_64).unwrap().unique_guid,
            "02020202-0202-0202-0202-020202020202"
        );
    }

    #[test]
    fn refuses_a_damaged_or_inconsistent_table() {
        let good = disk(&[(TYPE_XBOOTLDR, 100, 199, "boot")]);
        let mut bad_hdr = good.clone();
        bad_hdr[512 + 40] ^= 1;
        let mut bad_array = good.clone();
        bad_array[1024 + 60] ^= 1;
        let mut no_mbr = good.clone();
        no_mbr[510] = 0;
        let mut mbr_at_0 = good.clone();
        mbr_at_0[446 + 8] = 0;
        for (d, want) in [
            (no_mbr, "protective MBR"),
            (mbr_at_0, "protective MBR"),
            // Both array bounds can overflow u64.
            (
                with(&good, 72, &(u64::MAX - 1).to_le_bytes()),
                "inconsistent",
            ),
            (
                with(&good, 48, &(u64::MAX - 1).to_le_bytes()),
                "inconsistent",
            ),
            (with(&good, 84, &256u32.to_le_bytes()), "entry array"),
            (with(&good, 8, &0x0002_0000u32.to_le_bytes()), "revision"),
            (with(&good, 20, &1u32.to_le_bytes()), "reserved"),
            // Backup header off disk or at LBA 0. Primary array before LBA 2 or one
            // sector into the usable range. Last usable LBA one sector into the backup array.
            (with(&good, 32, &2048u64.to_le_bytes()), "inconsistent"),
            (with(&good, 32, &0u64.to_le_bytes()), "inconsistent"),
            (with(&good, 72, &1u64.to_le_bytes()), "inconsistent"),
            (with(&good, 72, &0u64.to_le_bytes()), "inconsistent"),
            (with(&good, 72, &3u64.to_le_bytes()), "inconsistent"),
            (with(&good, 48, &2015u64.to_le_bytes()), "inconsistent"),
            // A short table still reserves UEFI's 32 sectors before the first usable LBA.
            (
                with(
                    &with(&good, 80, &4u32.to_le_bytes()),
                    40,
                    &10u64.to_le_bytes(),
                ),
                "inconsistent",
            ),
            // The primary header reports its own location as LBA 5.
            (with(&good, 24, &5u64.to_le_bytes()), "inconsistent"),
            // Entries running into the first usable LBA, and a backup header inside the
            // usable range.
            (with(&good, 72, &10u64.to_le_bytes()), "inconsistent"),
            (with(&good, 32, &1500u64.to_le_bytes()), "inconsistent"),
            (with(&good, 84, &136u32.to_le_bytes()), "entry array"),
            (with(&good, 80, &0u32.to_le_bytes()), "entry array"),
            (bad_hdr, "header CRC"),
            (bad_array, "array CRC"),
            (with(&good, 12, &91u32.to_le_bytes()), "header size"),
            (with(&good, 12, &513u32.to_le_bytes()), "header size"),
            (with(&good, 80, &2000u32.to_le_bytes()), "entry array"),
            // The array starts past the first usable LBA and extends beyond the disk.
            (with(&good, 72, &2047u64.to_le_bytes()), "inconsistent"),
            (
                disk(&[(TYPE_XBOOTLDR, 199, 100, "x")]),
                "outside the usable",
            ),
            (
                disk(&[(TYPE_XBOOTLDR, 100, 2040, "x")]),
                "outside the usable",
            ),
            (
                disk(&[
                    (TYPE_XBOOTLDR, 100, 199, "a"),
                    (TYPE_XBOOTLDR, 150, 250, "b"),
                ]),
                "overlap",
            ),
        ] {
            let err = format!("{:#}", read_bytes(&d).unwrap_err());
            assert!(err.contains(want), "{want}: {err}");
        }
        let two = read_bytes(&disk(&[
            (TYPE_XBOOTLDR, 100, 199, "a"),
            (TYPE_XBOOTLDR, 200, 299, "b"),
        ]))
        .unwrap();
        assert!(only_of_type(&two, TYPE_XBOOTLDR).is_err());
        assert!(only_of_type(&two, TYPE_ROOT_X86_64).is_err());
        let mut no_header = good.clone();
        no_header[512] = 0;
        let err = format!("{:#}", read_bytes(&no_header).unwrap_err());
        assert!(err.contains("no GPT header"), "{err}");
        // Two entries with one unique GUID.
        let mut dup = disk(&[
            (TYPE_XBOOTLDR, 100, 199, "a"),
            (TYPE_ROOT_X86_64, 200, 299, "b"),
        ]);
        dup.copy_within(1024 + 16..1024 + 32, 1024 + 128 + 16);
        let array_crc = crc32(&dup[1024..1024 + 128 * 128]);
        dup[512 + 88..512 + 92].copy_from_slice(&array_crc.to_le_bytes());
        dup[512 + 16..512 + 20].fill(0);
        let c = crc32(&dup[512..512 + 92]);
        dup[512 + 16..512 + 20].copy_from_slice(&c.to_le_bytes());
        let err = format!("{:#}", read_bytes(&dup).unwrap_err());
        assert!(err.contains("share GUID"), "{err}");
    }

    /// Growing a disk can leave its backup header before the last LBA.
    /// Any MBR slot can hold the protective entry.
    #[test]
    fn accepts_a_grown_disk_and_any_mbr_slot() {
        let good = disk(&[(TYPE_XBOOTLDR, 100, 199, "boot")]);
        let grown = with(
            &with(&good, 32, &1500u64.to_le_bytes()),
            48,
            &1467u64.to_le_bytes(),
        );
        assert_eq!(read_bytes(&grown).unwrap().len(), 1);
        let mut slot3 = good.clone();
        slot3.copy_within(446..462, 446 + 32);
        slot3[446..462].fill(0);
        assert_eq!(read_bytes(&slot3).unwrap().len(), 1);
    }
}
