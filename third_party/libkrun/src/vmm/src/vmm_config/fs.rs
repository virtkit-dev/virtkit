#[cfg(not(feature = "aws-nitro"))]
use devices::virtio::fs::virtual_entry::VirtualDirEntry;

#[derive(Clone, Debug)]
pub struct FsDeviceConfig {
    pub fs_id: String,
    /// Host directory to pass through. None means a virtual-only filesystem
    /// (NullFs + AugmentFs, no host directory).
    pub shared_dir: Option<String>,
    pub shm_size: Option<usize>,
    pub read_only: bool,
    /// virtiofsd-style UID id-map spec strings (`type:from:to[:count]`); empty = identity.
    pub uid_map: Vec<String>,
    /// virtiofsd-style GID id-map spec strings (same format as `uid_map`); empty = identity.
    pub gid_map: Vec<String>,
    #[cfg(not(feature = "aws-nitro"))]
    pub virtual_entries: Vec<VirtualDirEntry>,
    /// How long (ms) the guest may cache a failed (ENOENT) lookup. `0` = no caching
    /// (the previous behavior: every miss round-trips).
    pub negative_timeout_ms: u32,
}
