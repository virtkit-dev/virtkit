//! `vk-agent drop-caches dentries|all`: drop the guest kernel's dentry and inode caches, and
//! with `all` its page cache.
//!
//! The host's virtio-fs server holds a descriptor for each shared inode until the guest
//! forgets it. Without memory pressure, cached inodes can accumulate until the VMM reaches
//! its descriptor limit and further opens fail.
//!
//! `dentries` reclaims unused dentries and inodes across all filesystems; later lookups
//! repopulate them. Cached pages can keep inodes resident, so `all` also drops the page cache
//! when `dentries` does not free enough. It first syncs all guest filesystems and waits for
//! dirty data to be written. The kernel logs successful drops unless logging was disabled.

use std::io::{self, Write};

const DROP_CACHES: &str = "/proc/sys/vm/drop_caches";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum What {
    Dentries,
    All,
}

impl What {
    fn parse(arg: &str) -> Option<Self> {
        match arg {
            "dentries" => Some(What::Dentries),
            "all" => Some(What::All),
            _ => None,
        }
    }

    /// Kernel `drop_caches` values: 2 reclaims slab objects (including dentries and inodes);
    /// 3 also drops the page cache.
    fn level(self) -> &'static str {
        match self {
            What::Dentries => "2",
            What::All => "3",
        }
    }
}

fn drop_caches(what: What) -> io::Result<()> {
    // Open before syncing so an open failure avoids the sync.
    let mut file = std::fs::OpenOptions::new().write(true).open(DROP_CACHES)?;
    if what == What::All {
        // Dirty pages cannot be dropped and can keep their inodes cached.
        // SAFETY: sync takes no arguments and cannot fail.
        unsafe { libc::sync() };
    }
    file.write_all(what.level().as_bytes())
}

/// CLI entry for `vk-agent drop-caches dentries|all`.
pub fn main(args: &[String]) -> i32 {
    let what = match args {
        [arg] => What::parse(arg),
        _ => None,
    };
    let Some(what) = what else {
        eprintln!("usage: vk-agent drop-caches dentries|all");
        return 2;
    };
    match drop_caches(what) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("drop-caches: writing {DROP_CACHES}: {e}");
            1
        }
    }
}

// A live drop test would reclaim the test machine's caches.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_are_the_kernels() {
        assert_eq!(What::parse("dentries").map(What::level), Some("2"));
        assert_eq!(What::parse("all").map(What::level), Some("3"));
    }

    #[test]
    fn bad_arguments_are_a_usage_error() {
        let run = |args: &[&str]| main(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>());
        assert_eq!(run(&[]), 2);
        assert_eq!(run(&["pages"]), 2);
        assert_eq!(run(&["3"]), 2);
        assert_eq!(run(&["all", "x"]), 2);
    }
}
