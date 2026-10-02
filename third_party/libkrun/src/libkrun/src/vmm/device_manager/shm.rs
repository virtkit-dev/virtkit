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
    /// One past the last address regions may occupy: on x86_64 the end of the span the DSDT
    /// declares as a PCI host-bridge window; unbounded elsewhere. A `shm_start_addr` of 0
    /// means the guest has no span at all (local patch, see VENDOR.md).
    #[allow(unused)]
    end_guest_addr: u64,
    #[allow(unused)]
    page_size: usize,
    fs_regions: BTreeMap<usize, ShmRegion>,
    gpu_region: Option<ShmRegion>,
    #[cfg(feature = "vhost-user")]
    vhost_user_regions: BTreeMap<usize, ShmRegion>,
}

/// How much guest-physical space shared-memory regions may occupy, from `shm_start_addr`.
#[cfg(target_arch = "x86_64")]
const SHM_SPAN: u64 = arch::x86_64::layout::SHM_MEM_SIZE;
#[cfg(not(target_arch = "x86_64"))]
const SHM_SPAN: u64 = u64::MAX;

impl ShmManager {
    pub fn new(info: &ArchMemoryInfo) -> ShmManager {
        Self {
            next_guest_addr: info.shm_start_addr,
            end_guest_addr: info.shm_start_addr.saturating_add(SHM_SPAN),
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
        // A start address of 0 is the "this guest has no span" sentinel, not a usable base:
        // carving a region there would land it on the guest's own RAM.
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
    /// registers and is happy with either (local patch, see VENDOR.md).
    #[cfg(not(feature = "tee"))]
    fn place_fs_region(&self, size: usize) -> Result<(usize, u64), Error> {
        const MIN_SIZE: usize = 2 << 20;
        if !cfg!(target_arch = "x86_64") {
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
