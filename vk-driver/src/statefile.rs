//! Who may read what `vk` keeps about a VM: the one place that says so.
//!
//! A VM's state dir holds its control sockets — the exec channel is a root shell in the
//! guest — so it is its owner's alone, and the records `vk` writes about a VM (the recipe
//! with its full command line, its last registry entry, the name index)
//! follow the same rule. Every such write goes through here, so opening them to the owner's
//! group later is a change to [`FILE_MODE`] and [`DIR_MODE`], not a hunt for literals.

use std::path::Path;

use anyhow::{Context, Result};

/// The mode of a record `vk` writes about a VM: its owner's alone.
pub const FILE_MODE: u32 = 0o600;

/// The mode of a directory that holds a VM's state, or the names of VMs: its owner's alone.
pub const DIR_MODE: u32 = 0o700;

/// Write a record whole or not at all, at [`FILE_MODE`] whatever the umask and whatever
/// mode a file already there has.
pub fn write(path: &Path, contents: &[u8]) -> Result<()> {
    vk_fs::write_atomic(path, contents, FILE_MODE)
}

/// Create `dir` and its missing parents at [`DIR_MODE`]. One already there keeps the mode
/// it has: a caller that must narrow a directory it did not make says so itself.
pub fn create_dir_all(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(dir)
        .with_context(|| format!("creating {}", dir.display()))
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
