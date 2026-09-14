use devices::virtio::fs::passthrough::CachePolicy;
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
    /// What the guest may cache of this share's data: `Auto` (the default) is close-to-open
    /// consistency, `Always` keeps whatever it cached — for a tree the host never changes
    /// while it is shared — and `Never` caches nothing.
    pub cache_policy: CachePolicy,
    /// How long (ms) the guest may reuse a directory entry it looked up without asking again.
    pub entry_timeout_ms: u32,
    /// How long (ms) the guest may reuse the attributes it fetched for an inode.
    pub attr_timeout_ms: u32,
    /// How long (ms) the guest may cache a failed (ENOENT) lookup. `0` = no caching
    /// (the previous behavior: every miss round-trips).
    pub negative_timeout_ms: u32,
    /// Whether the share serves extended attributes. `false` answers every xattr request
    /// `ENOSYS`, which is what makes the guest stop sending them for the life of the mount.
    pub xattr: bool,
    /// Per-inode DAX: regular files at least this many bytes are marked for DAX
    /// (`ATTR_DAX`), for a guest that mounts the share `dax=inode`. `None` = the mount
    /// option alone decides.
    pub dax_inode_min: Option<u64>,
}
