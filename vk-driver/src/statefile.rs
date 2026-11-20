//! Permissions for run recipes, state directories and the name index directory. A state
//! directory holds control sockets with root access to the guest. A recipe can contain
//! passwords from the command line. Both are private to the owner.

use std::path::Path;

use anyhow::{Context, Result};

/// The mode of a record `vk` writes about a VM: its owner's alone.
pub const FILE_MODE: u32 = 0o600;

/// The mode of a directory that holds a VM's state, or the names of VMs: its owner's alone.
pub const DIR_MODE: u32 = 0o700;

/// Atomically replace the record with a new file. Its mode is [`FILE_MODE`] subject
/// to the process umask, regardless of the previous file's permissions.
pub fn write(path: &Path, contents: &[u8]) -> Result<()> {
    vk_fs::write_atomic(path, contents, FILE_MODE)
}

/// Create `dir` and missing parents with [`DIR_MODE`] subject to the umask. Callers
/// that need to restrict an existing directory must set its permissions separately.
pub fn create_dir_all(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
}

/// Create `dir` with [`DIR_MODE`] subject to the umask. An existing entry yields
/// `AlreadyExists`, so success means this call created the directory.
pub fn create_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(DIR_MODE).create(dir)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A record is its owner's alone, even over a file that was readable by others.
    #[test]
    fn records_and_directories_are_their_owners_alone() {
        let dir = std::env::temp_dir().join(format!("vk-statefile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let nested = dir.join("a/b");
        create_dir_all(&nested).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&nested), DIR_MODE);
        let file = nested.join("record.json");
        std::fs::write(&file, "old").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        write(&file, b"new").unwrap();
        assert_eq!(mode(&file), FILE_MODE);
        assert_eq!(std::fs::read(&file).unwrap(), b"new");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
