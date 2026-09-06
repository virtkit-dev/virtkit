use std::collections::BTreeMap;

use arch::ArchMemoryInfo;
use vm_memory::GuestAddress;
use vmm_sys_util::align_upwards;

#[derive(Debug)]
pub enum Error {
    DuplicatedGpuRegion,
    OutOfSpace,
}

#[derive(Clone)]
pub struct ShmRegion {
    pub guest_addr: GuestAddress,
    pub size: usize,
}

pub struct ShmManager {
    next_guest_addr: u64,
    /// One past the last address regions may occupy: on x86_64 the end of the span the DSDT
    /// declares as a PCI host-bridge window, which is what makes a region's BAR one the guest
    /// keeps; unbounded elsewhere. `shm_start_addr` of 0 means the guest has no span at all.
    /// (Local patch — see ../../../VENDOR.md.)
    end_guest_addr: u64,
    page_size: usize,
    fs_regions: BTreeMap<usize, ShmRegion>,
    gpu_region: Option<ShmRegion>,
}

/// How much guest-physical space shared-memory regions may occupy in total, counted from
/// `shm_start_addr`. On x86_64 that is the span the DSDT declares as a PCI host-bridge
/// window; the other transports read a region's base and length out of device registers,
/// so nothing bounds them. (Local patch — see ../../../VENDOR.md.)
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

    fn create_region(&mut self, size: usize) -> Result<ShmRegion, Error> {
        // A start address of 0 is the "this guest has no shm span" sentinel, not a usable
        // base — carving a region there would land it on the guest's own RAM.
        // (Local patch — see ../../../VENDOR.md.)
        if self.next_guest_addr == 0 {
            return Err(Error::OutOfSpace);
        }

        let size = align_upwards!(size, self.page_size);

        let region = ShmRegion {
            guest_addr: GuestAddress(self.next_guest_addr),
            size,
        };

        match self.next_guest_addr.checked_add(size as u64) {
            Some(addr) if addr <= self.end_guest_addr => {
                self.next_guest_addr = addr;
                Ok(region)
            }
            _ => Err(Error::OutOfSpace),
        }
    }

    pub fn create_gpu_region(&mut self, size: usize) -> Result<(), Error> {
        if self.gpu_region.is_some() {
            Err(Error::DuplicatedGpuRegion)
        } else {
            self.gpu_region = Some(self.create_region(size)?);
            Ok(())
        }
    }

    /// Size and place the window so the transport can describe it.
    ///
    /// virtio-pci exposes it as a PCI memory BAR, which a driver sizes by probing an address
    /// mask: the size must be a power of two and the base aligned to it, or the guest
    /// mis-decodes the window. The guest also maps it in 2 MiB subsections, so a smaller one
    /// is unusable. (Local patch — see ../../../VENDOR.md.)
    #[cfg(all(not(feature = "tee"), target_arch = "x86_64"))]
    fn place_fs_region(&self, size: usize) -> Result<(usize, u64), Error> {
        const MIN_SIZE: usize = 2 << 20;

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

    /// virtio-mmio carries a region's base and length in device registers, so it needs
    /// neither a power-of-two size nor an aligned base. (Local patch — see ../../../VENDOR.md.)
    #[cfg(all(not(feature = "tee"), not(target_arch = "x86_64")))]
    fn place_fs_region(&self, size: usize) -> Result<(usize, u64), Error> {
        Ok((size, self.next_guest_addr))
    }

    /// Reserve the shared-memory (DAX) window of virtio-fs device `index`.
    #[cfg(not(feature = "tee"))]
    pub fn create_fs_region(&mut self, index: usize, size: usize) -> Result<(), Error> {
        let (size, base) = self.place_fs_region(size)?;
        // All or nothing: an alignment that cannot be followed by the region itself must not
        // leave the next caller starting from a bumped address.
        let saved = std::mem::replace(&mut self.next_guest_addr, base);
        match self.create_region(size) {
            Ok(region) => {
                self.fs_regions.insert(index, region);
                Ok(())
            }
            Err(e) => {
                self.next_guest_addr = saved;
                Err(e)
            }
        }
    }
}

// Local patch — see ../../../VENDOR.md.
#[cfg(test)]
mod tests {
    use super::*;

    fn manager(shm_start_addr: u64) -> ShmManager {
        ShmManager::new(&ArchMemoryInfo {
            shm_start_addr,
            page_size: 4096,
            ..Default::default()
        })
    }

    #[test]
    fn a_zero_start_address_yields_no_region() {
        let mut mgr = manager(0);
        assert!(matches!(
            mgr.create_gpu_region(8 << 20),
            Err(Error::OutOfSpace)
        ));
        #[cfg(not(feature = "tee"))]
        assert!(matches!(
            mgr.create_fs_region(0, 8 << 20),
            Err(Error::OutOfSpace)
        ));
    }

    /// The span is what the DSDT declares as a host-bridge window, so a region reaching past
    /// it is one the guest would discard: refuse it, and leave the cursor for the next caller.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_region_past_the_span_is_refused_and_leaves_the_cursor_put() {
        let start = arch::x86_64::layout::SHM_MEM_START;
        let mut mgr = manager(start);
        assert!(matches!(
            mgr.create_gpu_region(SHM_SPAN as usize + 4096),
            Err(Error::OutOfSpace)
        ));
        assert_eq!(mgr.next_guest_addr, start);
    }

    /// The BAR a virtio-pci guest programs describes a power-of-two region at a naturally
    /// aligned base, so `create_fs_region` has to hand out exactly that.
    #[cfg(all(
        not(any(feature = "tee", feature = "aws-nitro")),
        target_arch = "x86_64"
    ))]
    #[test]
    fn fs_regions_are_power_of_two_sized_and_naturally_aligned() {
        let start = arch::x86_64::layout::SHM_MEM_START;
        let mut mgr = manager(start);

        // Rounded up to 2 MiB, the smallest window the guest can map.
        mgr.create_fs_region(0, 4096).unwrap();
        let first = mgr.fs_region(0).unwrap();
        assert_eq!(first.size, 2 << 20);
        assert_eq!(first.guest_addr.0, start);

        // Rounded up to 8 GiB, and pushed to the next 8 GiB boundary to reach it.
        mgr.create_fs_region(1, 6 << 30).unwrap();
        let second = mgr.fs_region(1).unwrap();
        assert_eq!(second.size, 8 << 30);
        assert_eq!(second.guest_addr.0, start + (8 << 30));
    }

    /// A share whose window does not fit costs that share its DAX, not every later one.
    #[cfg(all(
        not(any(feature = "tee", feature = "aws-nitro")),
        target_arch = "x86_64"
    ))]
    #[test]
    fn an_oversized_fs_region_leaves_the_next_one_placeable() {
        let start = arch::x86_64::layout::SHM_MEM_START;
        let mut mgr = manager(start);

        assert!(matches!(
            mgr.create_fs_region(0, SHM_SPAN as usize + 1),
            Err(Error::OutOfSpace)
        ));
        mgr.create_fs_region(1, 2 << 20).unwrap();
        assert_eq!(mgr.fs_region(1).unwrap().guest_addr.0, start);
    }
}
