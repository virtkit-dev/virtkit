//! The guest kernel and vk-agent, optionally embedded into the `vk` binary.
//!
//! The shipped `vk` is self-contained: build.sh compiles it with the `embed`
//! feature and points build.rs at a freshly built vk-agent and the pinned vmlinux.
//! At runtime an asset is resolved in this order: an explicit --kernel/--agent
//! path, else the embedded copy (served from an anonymous memfd), else the
//! on-disk default under /usr/local/lib/vk. A plain dev `cargo build` embeds
//! nothing, so it just uses the flags or the on-disk defaults.
//!
//! The blobs are embedded with the linker (`.incbin` in a `global_asm!` section),
//! not `include_bytes!`: the linker splices each file straight into `.rodata`, so
//! rustc/LLVM never materialise the ~24M kernel + ~7M agent as constants — which
//! otherwise cost significant compile time and peak memory. build.rs supplies the
//! paths via VK_EMBED_{KERNEL,AGENT}_PATH (an empty placeholder when nothing is
//! provided, giving a zero-length blob that resolves to "not embedded").
//!
//! An embedded asset is materialised into an anonymous (CLOEXEC) memfd rather than a
//! temp file, so nothing touches disk. The kernel is handed to the spawned VMM by
//! clearing CLOEXEC on its fd for that one spawn (`run::spawn_vmm`), which then opens
//! `/proc/self/fd/<n>`; the agent is only ever reopened in this process by the packer.
use std::fs::File;
use std::io::Write;
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

#[derive(Clone, Copy)]
pub enum Asset {
    Kernel,
    Agent,
}

impl Asset {
    /// Name given to the memfd backing the embedded copy.
    fn filename(self) -> &'static str {
        match self {
            Asset::Kernel => "vmlinux",
            Asset::Agent => "vk-agent",
        }
    }

    /// On-disk fallback when nothing is embedded and no flag is given.
    fn default_path(self) -> &'static str {
        match self {
            Asset::Kernel => "/usr/local/lib/vk/vmlinux",
            Asset::Agent => "/usr/local/lib/vk/vk-agent",
        }
    }

    fn embedded(self) -> Option<&'static [u8]> {
        match self {
            Asset::Kernel => kernel(),
            Asset::Agent => agent(),
        }
    }
}

// The two blobs, spliced into `.rodata` by the linker. Each `.incbin` is bracketed
// by start/end symbols so the runtime can recover the byte range; an empty placeholder
// file (the no-asset dev build) makes start == end, i.e. a zero-length blob.
#[cfg(feature = "embed")]
mod blob {
    use std::arch::global_asm;

    global_asm!(concat!(
        ".section .rodata.vk_embed_kernel,\"a\",@progbits\n",
        ".globl VK_EMBED_KERNEL_START\n",
        "VK_EMBED_KERNEL_START:\n",
        ".incbin \"",
        env!("VK_EMBED_KERNEL_PATH"),
        "\"\n",
        ".globl VK_EMBED_KERNEL_END\n",
        "VK_EMBED_KERNEL_END:\n",
        ".section .rodata.vk_embed_agent,\"a\",@progbits\n",
        ".globl VK_EMBED_AGENT_START\n",
        "VK_EMBED_AGENT_START:\n",
        ".incbin \"",
        env!("VK_EMBED_AGENT_PATH"),
        "\"\n",
        ".globl VK_EMBED_AGENT_END\n",
        "VK_EMBED_AGENT_END:\n",
    ));

    unsafe extern "C" {
        pub static VK_EMBED_KERNEL_START: u8;
        pub static VK_EMBED_KERNEL_END: u8;
        pub static VK_EMBED_AGENT_START: u8;
        pub static VK_EMBED_AGENT_END: u8;
    }

    /// The bytes between two linker symbols (`None` if empty). The symbols bound a
    /// contiguous `.incbin` blob in `.rodata`, so the range is a single static object.
    fn between(start: *const u8, end: *const u8) -> Option<&'static [u8]> {
        let len = end as usize - start as usize;
        // SAFETY: start..end is the linker-placed .incbin blob, valid for the whole
        // program and never mutated.
        (len != 0).then(|| unsafe { std::slice::from_raw_parts(start, len) })
    }

    pub fn kernel() -> Option<&'static [u8]> {
        between(
            &raw const VK_EMBED_KERNEL_START,
            &raw const VK_EMBED_KERNEL_END,
        )
    }

    pub fn agent() -> Option<&'static [u8]> {
        between(
            &raw const VK_EMBED_AGENT_START,
            &raw const VK_EMBED_AGENT_END,
        )
    }
}

#[cfg(feature = "embed")]
fn kernel() -> Option<&'static [u8]> {
    blob::kernel()
}

#[cfg(feature = "embed")]
fn agent() -> Option<&'static [u8]> {
    blob::agent()
}

#[cfg(not(feature = "embed"))]
fn kernel() -> Option<&'static [u8]> {
    None
}

#[cfg(not(feature = "embed"))]
fn agent() -> Option<&'static [u8]> {
    None
}

/// A resolved asset: the path to hand a consumer, plus the memfd backing it when the
/// asset is embedded.
pub struct Resolved {
    pub path: PathBuf,
    /// The open (CLOEXEC) memfd for an embedded asset, held so its `/proc/self/fd/<n>`
    /// path stays valid — the VMM opens the kernel (its spawn clears CLOEXEC on this fd)
    /// and the in-process packer reopens the agent. `None` for an explicit --flag path or
    /// the on-disk default.
    fd: Option<File>,
}

impl Resolved {
    /// Whether this resolved to the embedded copy (a memfd) rather than a real path.
    pub fn is_embedded(&self) -> bool {
        self.fd.is_some()
    }
}

/// Resolve an asset. An explicit override wins; otherwise the embedded copy is placed
/// in an anonymous memfd — no disk copy — and addressed as `/proc/self/fd/<n>`, which a
/// spawned VMM inherits and opens (and the in-process packer reopens); otherwise the
/// on-disk default is used. The agent's mode is set by the initramfs/ext4 packers, so
/// the backing file need not be executable.
pub fn resolve(asset: Asset, explicit: Option<&Path>) -> Result<Resolved> {
    if let Some(p) = explicit {
        return Ok(Resolved {
            path: p.to_path_buf(),
            fd: None,
        });
    }
    if let Some(bytes) = asset.embedded() {
        let (file, path) = memfd(asset.filename(), bytes)?;
        return Ok(Resolved {
            path,
            fd: Some(file),
        });
    }
    Ok(Resolved {
        path: PathBuf::from(asset.default_path()),
        fd: None,
    })
}

/// Back `bytes` with an anonymous in-memory file and return it with its
/// `/proc/self/fd/<n>` path. The fd is `CLOEXEC`, so idle helper children never inherit
/// it; the kernel is handed to the VMM by clearing `CLOEXEC` on its fd only in that
/// spawn (see `run::spawn_vmm`), and the agent is only ever reopened in-process. The
/// caller holds the returned `File` to keep the fd open.
fn memfd(name: &str, bytes: &[u8]) -> Result<(File, PathBuf)> {
    let cname = std::ffi::CString::new(name).expect("asset name has no interior nul");
    // SAFETY: `cname` is a valid C string; memfd_create returns an owned fd or -1/errno.
    let fd = unsafe { libc::memfd_create(cname.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("memfd_create");
    }
    // SAFETY: `fd` was just created and is owned by us.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .with_context(|| format!("writing embedded {name} to a memfd"))?;
    Ok((file, PathBuf::from(format!("/proc/self/fd/{fd}"))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_flag_wins() {
        // resolve() never touches an explicit path (existence is the caller's check).
        let p = Path::new("/nonexistent/vmlinux");
        let r = resolve(Asset::Kernel, Some(p)).unwrap();
        assert_eq!(r.path, p);
        assert!(!r.is_embedded());
    }

    #[test]
    fn no_flag_uses_embedded_else_default() {
        for asset in [Asset::Kernel, Asset::Agent] {
            let r = resolve(asset, None).unwrap();
            if asset.embedded().is_some() {
                assert!(r.is_embedded());
                assert!(r.path.starts_with("/proc/self/fd"));
            } else {
                assert!(!r.is_embedded());
                assert_eq!(r.path, Path::new(asset.default_path()));
            }
        }
    }

    #[test]
    fn memfd_round_trips_through_its_proc_path() {
        let (_file, path) = memfd("blob", b"embedded bytes").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"embedded bytes");
    }
}
