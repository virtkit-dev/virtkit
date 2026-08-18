//! OVA packaging — wrap a disk exported by [`crate::vmdk`] in the OVF envelope
//! vSphere imports: the descriptor XML declaring the appliance's virtual
//! hardware, a SHA256 manifest, and the two of them tarred with the disk in a
//! spec-permitted order (descriptor first, manifest last), so ESXi and vCenter
//! can import the file as a stream.
//!
//! The hardware written into the descriptor is the modern VMware trio the wab
//! appliances already deploy with: a VirtualSCSI (pvscsi) controller, a VMXNET3
//! NIC on "VM Network", and BIOS or EFI firmware.

use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use sha2::Digest;

/// Firmware the appliance boots with. `Bios` matches a grub-pc/MBR disk (the
/// runner image); `Efi` is for a disk carrying an ESP + grub-efi.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Firmware {
    /// a grub-pc/MBR disk, as the runner image is
    Bios,
    /// a disk carrying an ESP + grub-efi
    Efi,
}

/// The appliance the OVF descriptor declares around the disk.
pub struct OvaSpec {
    /// VM name; also the file stem of every member inside the OVA
    pub name: String,
    pub cpus: u32,
    pub mem_mib: u64,
    /// VMware guest-OS identifier (`vmw:osType`), e.g. `debian11_64Guest`
    pub guest_os: String,
    pub firmware: Firmware,
}

/// Package the raw disk image `disk` as an OVA at `out`. The disk is first
/// converted to a streamOptimized VMDK in a sibling temp file (the tar header
/// needs its size up front, and a multi-GiB spool does not belong in RAM), which
/// is removed on every path out of here.
pub fn write_ova(disk: &Path, out: &Path, spec: &OvaSpec) -> Result<crate::vmdk::VmdkInfo> {
    validate_name(&spec.name)?;
    if spec.cpus == 0 || spec.mem_mib == 0 {
        bail!("an appliance needs at least 1 vCPU and some memory");
    }
    validate_name(&spec.guest_os).context("--guest-os")?;

    // The VMDK spool, cleaned up however this function leaves.
    let vmdk_path = out.with_extension("vmdk.tmp");
    // By identity, like main.rs's out==disk check: an input named like the spool would
    // otherwise be truncated while still being read, then removed with the spool.
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a), Ok(b)) = (std::fs::metadata(disk), std::fs::metadata(&vmdk_path))
            && a.dev() == b.dev()
            && a.ino() == b.ino()
        {
            bail!(
                "the VMDK spool {} would overwrite the input disk — pass another output path",
                vmdk_path.display()
            );
        }
    }
    struct Cleanup<'a>(&'a Path);
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.0);
        }
    }
    let _cleanup = Cleanup(&vmdk_path);
    let info = crate::vmdk::write_stream_optimized(disk, &vmdk_path)?;

    let ovf_name = format!("{}.ovf", spec.name);
    let vmdk_name = format!("{}-disk1.vmdk", spec.name);
    let mf_name = format!("{}.mf", spec.name);

    let ovf = descriptor(spec, &vmdk_name, info.written, info.capacity);

    // Manifest: SHA256 of the descriptor (in memory) and of the spooled VMDK.
    let mut vmdk_file =
        std::fs::File::open(&vmdk_path).with_context(|| format!("reopening {vmdk_name}"))?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = vmdk_file.read(&mut buf).context("hashing the VMDK")?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let manifest = format!(
        "SHA256({ovf_name})= {}\nSHA256({vmdk_name})= {}\n",
        hex(&sha2::Sha256::digest(ovf.as_bytes())),
        hex(&hasher.finalize()),
    );

    // The OVA proper: a plain ustar, descriptor first, then the disk, then the
    // manifest — the member order the OVF spec fixes so imports can stream.
    let ova = std::fs::File::create(out).with_context(|| format!("creating {}", out.display()))?;
    let mut tar = tar::Builder::new(std::io::BufWriter::new(ova));
    append(&mut tar, &ovf_name, ovf.len() as u64, ovf.as_bytes())?;
    vmdk_file
        .seek(SeekFrom::Start(0))
        .context("rewinding the VMDK")?;
    append(&mut tar, &vmdk_name, info.written, &mut vmdk_file)?;
    append(
        &mut tar,
        &mf_name,
        manifest.len() as u64,
        manifest.as_bytes(),
    )?;
    let mut inner = tar.into_inner().context("finishing the OVA tar")?;
    inner.flush().context("flushing the OVA")?;
    Ok(info)
}

fn hex(digest: &[u8]) -> String {
    use std::fmt::Write;
    digest.iter().fold(String::with_capacity(64), |mut s, b| {
        write!(s, "{b:02x}").unwrap();
        s
    })
}

/// One tar member with neutral metadata (root-owned, 0644, epoch mtime), so the
/// archive is reproducible and carries nothing about the building host.
fn append<W: Write>(
    tar: &mut tar::Builder<W>,
    name: &str,
    size: u64,
    data: impl Read,
) -> Result<()> {
    let mut h = tar::Header::new_ustar();
    // Spelled out even where new_ustar's zeroed defaults would be read the same way, so
    // the headers are strictly POSIX ustar for a validator that checks conformance.
    h.set_entry_type(tar::EntryType::Regular);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mode(0o644);
    h.set_size(size);
    h.set_mtime(0);
    tar.append_data(&mut h, name, data)
        .with_context(|| format!("adding {name} to the OVA"))
}

/// Member and VM names land in tar headers, XML attributes and the manifest:
/// keep them to characters that cannot break out of any of the three.
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 80
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("name {name:?} must be 1-80 chars of [A-Za-z0-9._-]");
    }
    Ok(())
}

/// The OVF descriptor. Element order inside an Item follows the CIM RASD schema
/// (alphabetical), which strict importers validate. The `OperatingSystemSection`'s
/// CIM id is deliberately pinned at 100 ("Linux 2.6.x 64-Bit") whatever `--guest-os` says:
/// VMware importers key on `vmw:osType` and ignore the CIM id.
fn descriptor(spec: &OvaSpec, vmdk_name: &str, vmdk_bytes: u64, capacity: u64) -> String {
    let name = &spec.name;
    let cpus = spec.cpus;
    let mem = spec.mem_mib;
    let guest_os = &spec.guest_os;
    // BIOS is VMware's default; only EFI needs saying.
    let firmware = match spec.firmware {
        Firmware::Bios => String::new(),
        Firmware::Efi => {
            "\n      <vmw:Config ovf:required=\"false\" vmw:key=\"firmware\" vmw:value=\"efi\"/>"
                .to_string()
        }
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References>
    <File ovf:href="{vmdk_name}" ovf:id="file1" ovf:size="{vmdk_bytes}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="{capacity}" ovf:capacityAllocationUnits="byte" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The list of logical networks</Info>
    <Network ovf:name="VM Network">
      <Description>The VM Network network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="{name}">
    <Info>A virtual machine</Info>
    <Name>{name}</Name>
    <OperatingSystemSection ovf:id="100" vmw:osType="{guest_os}">
      <Info>The kind of installed guest operating system</Info>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemType>vmx-13</vssd:VirtualSystemType>
      </System>
      <Item>
        <rasd:AllocationUnits>hertz * 10^6</rasd:AllocationUnits>
        <rasd:Description>Number of Virtual CPUs</rasd:Description>
        <rasd:ElementName>{cpus} virtual CPU(s)</rasd:ElementName>
        <rasd:InstanceID>1</rasd:InstanceID>
        <rasd:ResourceType>3</rasd:ResourceType>
        <rasd:VirtualQuantity>{cpus}</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits>
        <rasd:Description>Memory Size</rasd:Description>
        <rasd:ElementName>{mem}MB of memory</rasd:ElementName>
        <rasd:InstanceID>2</rasd:InstanceID>
        <rasd:ResourceType>4</rasd:ResourceType>
        <rasd:VirtualQuantity>{mem}</rasd:VirtualQuantity>
      </Item>
      <Item>
        <rasd:Address>0</rasd:Address>
        <rasd:Description>SCSI Controller</rasd:Description>
        <rasd:ElementName>SCSI Controller 0</rasd:ElementName>
        <rasd:InstanceID>3</rasd:InstanceID>
        <rasd:ResourceSubType>VirtualSCSI</rasd:ResourceSubType>
        <rasd:ResourceType>6</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>0</rasd:AddressOnParent>
        <rasd:ElementName>Hard Disk 1</rasd:ElementName>
        <rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource>
        <rasd:InstanceID>4</rasd:InstanceID>
        <rasd:Parent>3</rasd:Parent>
        <rasd:ResourceType>17</rasd:ResourceType>
      </Item>
      <Item>
        <rasd:AddressOnParent>7</rasd:AddressOnParent>
        <rasd:AutomaticAllocation>true</rasd:AutomaticAllocation>
        <rasd:Connection>VM Network</rasd:Connection>
        <rasd:Description>VMXNET3 ethernet adapter on &quot;VM Network&quot;</rasd:Description>
        <rasd:ElementName>Network adapter 1</rasd:ElementName>
        <rasd:InstanceID>5</rasd:InstanceID>
        <rasd:ResourceSubType>VMXNET3</rasd:ResourceSubType>
        <rasd:ResourceType>10</rasd:ResourceType>
      </Item>{firmware}
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TmpDir(std::path::PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> TmpDir {
            let dir = std::env::temp_dir().join(format!("vk-ova-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TmpDir(dir)
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn spec() -> OvaSpec {
        OvaSpec {
            name: "appliance".into(),
            cpus: 4,
            mem_mib: 8192,
            guest_os: "debian11_64Guest".into(),
            firmware: Firmware::Bios,
        }
    }

    #[test]
    fn ova_members_are_ordered_and_manifested() {
        let dir = TmpDir::new("pack");
        let raw = dir.0.join("d.raw");
        std::fs::write(&raw, vec![0xEEu8; 128 * 1024]).unwrap();
        let out = dir.0.join("d.ova");
        write_ova(&raw, &out, &spec()).unwrap();

        // Member order is the spec's: descriptor, disk, manifest — and the spool
        // is gone.
        let mut ar = tar::Archive::new(std::fs::File::open(&out).unwrap());
        let mut members = Vec::new();
        let mut by_name = std::collections::HashMap::new();
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            let name = e.path().unwrap().to_string_lossy().into_owned();
            let mut data = Vec::new();
            e.read_to_end(&mut data).unwrap();
            members.push(name.clone());
            by_name.insert(name, data);
        }
        assert_eq!(
            members,
            ["appliance.ovf", "appliance-disk1.vmdk", "appliance.mf"]
        );
        assert!(!out.with_extension("vmdk.tmp").exists(), "spool removed");

        // The manifest's hashes match the members it names.
        let mf = String::from_utf8(by_name["appliance.mf"].clone()).unwrap();
        for line in mf.lines() {
            let (head, hash) = line.split_once(")= ").unwrap();
            let file = head.strip_prefix("SHA256(").unwrap();
            let got = hex(&sha2::Sha256::digest(&by_name[file]));
            assert_eq!(got, hash, "{file} hash");
        }

        // The descriptor declares the disk by reference and size, and the
        // hardware the spec asked for.
        let ovf = String::from_utf8(by_name["appliance.ovf"].clone()).unwrap();
        assert!(ovf.contains(r#"ovf:href="appliance-disk1.vmdk""#));
        assert!(ovf.contains(&format!(
            r#"ovf:size="{}""#,
            by_name["appliance-disk1.vmdk"].len()
        )));
        assert!(ovf.contains(r#"ovf:capacity="131072""#));
        assert!(ovf.contains("<rasd:VirtualQuantity>4</rasd:VirtualQuantity>"));
        assert!(ovf.contains("<rasd:VirtualQuantity>8192</rasd:VirtualQuantity>"));
        assert!(ovf.contains("VirtualSCSI") && ovf.contains("VMXNET3"));
        assert!(ovf.contains(r#"vmw:osType="debian11_64Guest""#));
        // BIOS is the default: no firmware override is written.
        assert!(!ovf.contains("vmw:key=\"firmware\""));

        // The embedded VMDK is the streamOptimized export of the raw input.
        assert_eq!(
            &by_name["appliance-disk1.vmdk"][..4],
            &0x564d_444bu32.to_le_bytes()
        );
    }

    #[test]
    fn efi_firmware_is_declared_and_bad_names_are_refused() {
        let dir = TmpDir::new("efi");
        let raw = dir.0.join("d.raw");
        std::fs::write(&raw, vec![1u8; 4096]).unwrap();
        let out = dir.0.join("d.ova");
        let mut s = spec();
        s.firmware = Firmware::Efi;
        write_ova(&raw, &out, &s).unwrap();
        let mut ar = tar::Archive::new(std::fs::File::open(&out).unwrap());
        let mut ovf = String::new();
        ar.entries()
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .read_to_string(&mut ovf)
            .unwrap();
        assert!(
            ovf.contains(r#"vmw:key="firmware" vmw:value="efi""#),
            "{ovf}"
        );

        // Names ride tar headers, XML attributes and the manifest: nothing that
        // could break out of any of them is accepted.
        for bad in ["", "a b", "x\"y", "a/b", "<vm>", &"n".repeat(81)] {
            let mut s = spec();
            s.name = bad.to_string();
            let err = write_ova(&raw, &dir.0.join("bad.ova"), &s).unwrap_err();
            assert!(format!("{err:#}").contains("must be"), "{bad:?}: {err:#}");
        }
    }
}
