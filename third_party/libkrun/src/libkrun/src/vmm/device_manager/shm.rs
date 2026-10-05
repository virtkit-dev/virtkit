use std::collections::BTreeMap;

use arch::ArchMemoryInfo;
use vm_memory::GuestAddress;
use vmm_sys_util::align_upwards;

#[allow(unused)]
#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "gpu")]
    DuplicatedGpuRegion,
    OutOfSpace,
}

#[derive(Clone)]
pub struct ShmRegion {
    pub guest_addr: GuestAddress,
    pub size: usize,
}

pub struct ShmManager {
    #[allow(unused)]
    next_guest_addr: u64,
    /// One past the last address regions may occupy: the end of the span the DSDT declares
    /// as a PCI host-bridge window when devices are on virtio-pci; unbounded otherwise.
    #[allow(unused)]
    end_guest_addr: u64,
    /// Whether regions must be describable by a PCI BAR (a power of two, aligned to it).
    #[allow(unused)]
    pci: bool,
    #[allow(unused)]
    page_size: usize,
    fs_regions: BTreeMap<usize, ShmRegion>,
    gpu_region: Option<ShmRegion>,
    #[cfg(feature = "vhost-user")]
    vhost_user_regions: BTreeMap<usize, ShmRegion>,
}

impl ShmManager {
    /// Regions start above the guest's RAM, as upstream, unless the devices are on virtio-pci
    /// (`pci`, x86_64): then they live in the fixed span at `SHM_MEM_START` that the DSDT
    /// declares as a host-bridge window, and a guest whose RAM reaches into it has no span
    /// at all (local patch, see VENDOR.md).
    pub fn new(info: &ArchMemoryInfo, pci: bool) -> ShmManager {
        #[cfg(target_arch = "x86_64")]
        let (start, end) = if pci {
            use arch::x86_64::layout::{SHM_MEM_SIZE, SHM_MEM_START, shm_span_usable};
            if shm_span_usable(info.ram_last_addr) {
                (SHM_MEM_START, SHM_MEM_START + SHM_MEM_SIZE)
            } else {
                (0, 0)
            }
        } else {
            (info.shm_start_addr, u64::MAX)
        };
        #[cfg(not(target_arch = "x86_64"))]
        let (start, end) = {
            let _ = pci;
            (info.shm_start_addr, u64::MAX)
        };
        Self {
            next_guest_addr: start,
            end_guest_addr: end,
            pci,
            page_size: info.page_size,
            fs_regions: BTreeMap::new(),
            gpu_region: None,
            #[cfg(feature = "vhost-user")]
            vhost_user_regions: BTreeMap::new(),
        }
    }

    pub fn regions(&self) -> Vec<(GuestAddress, usize)> {
        let mut regions: Vec<(GuestAddress, usize)> = Vec::new();

        for region in self.fs_regions.iter() {
            regions.push((region.1.guest_addr, region.1.size));
        }

        if let Some(region) = &self.gpu_region {
            regions.push((region.guest_addr, region.size));
        }

        #[cfg(feature = "vhost-user")]
        for region in self.vhost_user_regions.values() {
            regions.push((region.guest_addr, region.size));
        }

        regions
    }

    #[cfg(not(any(feature = "tee", feature = "aws-nitro")))]
    pub fn fs_region(&self, index: usize) -> Option<&ShmRegion> {
        self.fs_regions.get(&index)
    }

    #[cfg(feature = "gpu")]
    pub fn gpu_region(&self) -> Option<&ShmRegion> {
        self.gpu_region.as_ref()
    }

    #[allow(unused)]
    fn create_region(&mut self, size: usize) -> Result<ShmRegion, Error> {
        self.create_region_at(align_upwards!(size, self.page_size), self.next_guest_addr)
    }

    /// Reserve `size` bytes at `base` (at or after `next_guest_addr`) within the span.
    #[allow(unused)]
    fn create_region_at(&mut self, size: usize, base: u64) -> Result<ShmRegion, Error> {
        // A start address of 0 is the "this guest has no span" sentinel (a PCI guest whose RAM
        // reaches the span), not a usable base: a region there would land on the guest's RAM.
        if self.next_guest_addr == 0 {
            return Err(Error::OutOfSpace);
        }
        match base.checked_add(size as u64) {
            Some(end) if base >= self.next_guest_addr && end <= self.end_guest_addr => {
                self.next_guest_addr = end;
                Ok(ShmRegion {
                    guest_addr: GuestAddress(base),
                    size,
                })
            }
            _ => Err(Error::OutOfSpace),
        }
    }

    /// Size and place a virtio-fs window so the transport can describe it. virtio-pci
    /// exposes it as a memory BAR, which a driver sizes by probing an address mask: the size
    /// must be a power of two and the base aligned to it, and the guest maps it in 2 MiB
    /// subsections, so a smaller one is unusable. virtio-mmio carries base and length in
    /// registers, so it keeps upstream's page-aligned placement (local patch, see VENDOR.md).
    #[cfg(not(feature = "tee"))]
    fn place_fs_region(&self, size: usize) -> Result<(usize, u64), Error> {
        const MIN_SIZE: usize = 2 << 20;
        if !self.pci {
            return Ok((align_upwards!(size, self.page_size), self.next_guest_addr));
        }
        let size = size
            .checked_next_power_of_two()
            .ok_or(Error::OutOfSpace)?
            .max(MIN_SIZE);
        let base = self
            .next_guest_addr
            .checked_next_multiple_of(size as u64)
            .ok_or(Error::OutOfSpace)?;
        Ok((size, base))
    }

    #[cfg(feature = "gpu")]
    pub fn create_gpu_region(&mut self, size: usize) -> Result<(), Error> {
        if self.gpu_region.is_some() {
            Err(Error::DuplicatedGpuRegion)
        } else {
            self.gpu_region = Some(self.create_region(size)?);
            Ok(())
        }
    }

    #[cfg(not(feature = "tee"))]
    pub fn create_fs_region(&mut self, index: usize, size: usize) -> Result<(), Error> {
        let (size, base) = self.place_fs_region(size)?;
        let region = self.create_region_at(size, base)?;
        self.fs_regions.insert(index, region);
        Ok(())
    }

    #[cfg(feature = "vhost-user")]
    pub fn create_vhost_user_region(&mut self, index: usize, size: usize) -> Result<(), Error> {
        let region = self.create_region(size)?;
        self.vhost_user_regions.insert(index, region);
        Ok(())
    }

    #[cfg(feature = "vhost-user")]
    pub fn vhost_user_region(&self, index: usize) -> Option<&ShmRegion> {
        self.vhost_user_regions.get(&index)
    }
}

#[cfg(all(test, target_arch = "x86_64", not(feature = "tee")))]
mod tests {
    use super::*;
    use arch::x86_64::layout::{SHM_MEM_SIZE, SHM_MEM_START};

    fn info(ram_last_addr: u64, shm_start_addr: u64) -> ArchMemoryInfo {
        ArchMemoryInfo {
            ram_below_gap: 0,
            ram_above_gap: 0,
            ram_last_addr,
            shm_start_addr,
            guest_last_addr: 0,
            page_size: 4096,
            initrd_addr: 0,
            firmware_addr: 0,
        }
    }

    #[test]
    fn pci_windows_are_aligned_powers_of_two_in_the_span() {
        let mut shm = ShmManager::new(&info(8 << 30, 9 << 30), true);
        shm.create_fs_region(0, 3 << 20).unwrap();
        shm.create_fs_region(1, 1 << 20).unwrap();
        let a = shm.fs_region(0).unwrap().clone();
        let b = shm.fs_region(1).unwrap().clone();
        assert_eq!((a.guest_addr.0, a.size), (SHM_MEM_START, 4 << 20));
        // Rounded up to the 2 MiB floor, aligned past the first window.
        assert_eq!(
            (b.guest_addr.0, b.size),
            (SHM_MEM_START + (4 << 20), 2 << 20)
        );
        // The span is bounded.
        assert!(matches!(
            shm.create_fs_region(2, SHM_MEM_SIZE as usize),
            Err(Error::OutOfSpace)
        ));
    }

    #[test]
    fn a_pci_guest_whose_ram_reaches_the_span_gets_no_window() {
        let mut shm = ShmManager::new(&info(SHM_MEM_START + 1, SHM_MEM_START + (1 << 30)), true);
        assert!(matches!(
            shm.create_fs_region(0, 2 << 20),
            Err(Error::OutOfSpace)
        ));
    }

    #[test]
    fn mmio_windows_sit_above_ram_page_aligned_and_unbounded() {
        let start = 128u64 << 30;
        let mut shm = ShmManager::new(&info(127 << 30, start), false);
        shm.create_fs_region(0, (3 << 20) + 1).unwrap();
        shm.create_fs_region(1, SHM_MEM_SIZE as usize).unwrap();
        let a = shm.fs_region(0).unwrap().clone();
        let b = shm.fs_region(1).unwrap().clone();
        assert_eq!((a.guest_addr.0, a.size), (start, (3 << 20) + 4096));
        assert_eq!(b.guest_addr.0, start + (3 << 20) + 4096);
    }
}
