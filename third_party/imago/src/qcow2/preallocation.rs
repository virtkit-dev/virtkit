//! Implementation for preallocation.
//!
//! Preallocation is used for new images or when growing images.

use super::*;
use crate::storage::ext::write_full_zeroes;

#[maybe_async]
impl<S: Storage + 'static, F: WrappedFormat<S> + 'static> Qcow2<S, F> {
    /// Make the given range zero.
    ///
    /// Bypasses disk bound checking, i.e. can and will write beyond the image end.
    pub(super) async fn preallocate_zero(&self, mut offset: u64, length: u64) -> io::Result<()> {
        let max_offset = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Preallocate range overflow")
        })?;

        // It does not matter what happens after the virtual disk end, so we may align up to the
        // next full cluster (this prevents needless COW at the image end)
        let max_offset = max_offset.next_multiple_of(self.header.cluster_size() as u64);

        while offset < max_offset {
            let (zofs, zlen) = self
                .ensure_fixed_mapping(
                    GuestOffset(offset),
                    max_offset - offset,
                    FixedMapping::ZeroRetainAllocation,
                )
                .await?;
            let zofs = zofs.0;
            if zofs > offset {
                self.preallocate(offset, zofs - offset, storage::PreallocateMode::Zero)
                    .await?;
            }
            offset = zofs + zlen;
            if zlen == 0 && offset < max_offset {
                self.preallocate(offset, max_offset - offset, storage::PreallocateMode::Zero)
                    .await?;
                break;
            }
        }

        Ok(())
    }

    /// Preallocate the given range as data clusters.
    ///
    /// Does not write data beyond trying to ensure `storage_prealloc_mode` for the underlying
    /// clusters.
    ///
    /// Bypasses disk bound checking, i.e. can and will write beyond the image end.
    pub(super) async fn preallocate(
        &self,
        mut offset: u64,
        length: u64,
        storage_prealloc_mode: storage::PreallocateMode,
    ) -> io::Result<()> {
        let max_offset = offset.checked_add(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "Preallocate range overflow")
        })?;

        // External data file: Resize with preallocation to exact size
        if let Some(data_file) = self.storage.as_ref() {
            data_file.resize(max_offset, storage_prealloc_mode).await?;
        }

        while offset < max_offset {
            let (file, fofs, flen) = self
                .do_ensure_data_mapping(GuestOffset(offset), max_offset - offset, true, true)
                .await?;

            // Data in metadata file: Allocate data areas as we go
            if self.storage.is_none() {
                match storage_prealloc_mode {
                    storage::PreallocateMode::None => (), // handled below
                    storage::PreallocateMode::Zero => {
                        file.write_zeroes(fofs, flen).await?;
                    }
                    storage::PreallocateMode::Allocate => {
                        file.write_allocated_zeroes(fofs, flen).await?;
                    }
                    storage::PreallocateMode::WriteData => {
                        write_full_zeroes(file, fofs, flen).await?;
                    }
                }
            }

            offset += flen;
        }

        Ok(())
    }
}
