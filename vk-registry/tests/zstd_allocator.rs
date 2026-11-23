//! zstd allocates its contexts with Rust's global allocator.
//!
//! The workspace enables `with-rust-allocator` so jemalloc handles zstd workspaces
//! on musl. Without it, zstd calls C malloc and bypasses this test's counter.
//!
//! Keep this test in its own binary. The counter includes allocations from every test.

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Bytes requested from the global allocator since the process started.
static REQUESTED: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: `alloc` and `dealloc` forward unchanged to `System`; the other methods keep
// their defaults, built on these two.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        REQUESTED.fetch_add(layout.size(), Ordering::Relaxed);
        // SAFETY: the caller upholds `GlobalAlloc::alloc`'s contract.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller passes a `ptr` that `alloc` above obtained from `System` with
        // this layout.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

#[test]
fn zstd_contexts_use_the_global_allocator() {
    let raw = vec![0x5a_u8; 1 << 20];

    let before = REQUESTED.load(Ordering::Relaxed);
    let mut enc = zstd::stream::write::Encoder::new(std::io::sink(), 1).unwrap();
    enc.write_all(&raw).unwrap();
    enc.finish().unwrap();
    let compress = REQUESTED.load(Ordering::Relaxed) - before;
    // The compressor's tables and window alone exceed this.
    assert!(
        compress >= 512 << 10,
        "compression requested {compress} bytes"
    );

    let frame = zstd::encode_all(&raw[..], 1).unwrap();
    let before = REQUESTED.load(Ordering::Relaxed);
    let mut dec = zstd::stream::read::Decoder::new(&frame[..]).unwrap();
    std::io::copy(&mut dec, &mut std::io::sink()).unwrap();
    let decompress = REQUESTED.load(Ordering::Relaxed) - before;
    // The decoder buffers this frame's 512 KiB window plus space for block decoding.
    assert!(
        decompress >= 512 << 10,
        "decompression requested {decompress} bytes"
    );
}
