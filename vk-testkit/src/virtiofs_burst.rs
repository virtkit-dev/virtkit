//! `vk-testkit virtiofs-burst <merged root> <share> <threads> <seconds>`: a guest stress
//! probe for a virtio-fs request stranded behind a full virtqueue
//! (`tests/virtiofs-full-ring-e2e.sh`).
//!
//! `<merged root>` is an overlayfs whose lower layer is the virtio-fs share `<share>`, with
//! directories `d0`, `d1`, … present in both layers, so each is merged. Listing a merged
//! directory reads the lower one with an unbounded count, which FUSE turns into a READDIR
//! with a 1 MiB buffer of single pages: 259 of the request ring's 1024 descriptors (the
//! device offers no indirect descriptors). Each burst, every thread opens and lists its
//! own directory, so four overlapping submissions need more descriptors than the ring
//! holds; after the burst the share is quiet. This is the shape of the original hang:
//! a parallel tree walker over a checkout seeded into an overlay upper.
//!
//! The opt-in VMM hook delays large replies and pauses the submitting vCPU after an
//! enqueue returns -ENOSPC. Listing threads avoid the virtio-fs interrupt CPUs.
//! Completions can then finish before the old caller queues the refused request.
//! The patched enqueue has already queued it under the ring lock.
//!
//! A watchdog declares a burst that has made no progress for [`STALL`] stranded, then looks
//! up a name on the share from another thread (any completion resends queued requests) and
//! checks that the burst ends. Exits 0 when no request stranded in `<seconds>`,
//! [`STRANDED`] when one did and the lookup freed it, [`STRANDED_FOR_GOOD`] when it did not.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// How long a burst may make no progress before its pending request counts as stranded.
pub const STALL: Duration = Duration::from_secs(10);
/// Exit status: a request stranded, and another request on the share freed it.
pub const STRANDED: u8 = 10;
/// Exit status: a request stranded, and another request on the share did not free it.
pub const STRANDED_FOR_GOOD: u8 = 11;

struct Shared {
    start: Barrier,
    done: Barrier,
    epoch: Instant,
    /// Listings of the current burst not yet finished.
    busy: AtomicUsize,
    /// Microseconds since `epoch` of the burst's last finished listing.
    progress_us: AtomicU64,
    bursts: AtomicU64,
    stopping: AtomicBool,
}

impl Shared {
    fn now_us(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_micros()).unwrap_or(u64::MAX)
    }
}

/// Runs the probe; returns the exit status.
pub fn run(merged: &Path, share: &Path, threads: usize, seconds: u64) -> Result<u8> {
    if !(4..=32).contains(&threads) || seconds == 0 || seconds > 3600 {
        bail!("need 4..32 threads and 1..3600 seconds");
    }
    // Keep the interrupt/completion CPU out of the listing threads' affinity masks.
    let cpus = listing_cpus(threads + 1)?;
    println!(
        "listing CPUs {:?}, watchdog CPU {}",
        &cpus[..threads],
        cpus[threads]
    );
    pin_cpu(cpus[threads])?;
    let dirs: Vec<PathBuf> = (0..threads).map(|i| merged.join(format!("d{i}"))).collect();
    for dir in &dirs {
        std::fs::read_dir(dir).with_context(|| format!("listing {}", dir.display()))?;
    }
    let shared = Arc::new(Shared {
        start: Barrier::new(threads + 1),
        done: Barrier::new(threads + 1),
        epoch: Instant::now(),
        busy: AtomicUsize::new(0),
        progress_us: AtomicU64::new(0),
        bursts: AtomicU64::new(0),
        stopping: AtomicBool::new(false),
    });
    for (i, dir) in dirs.into_iter().enumerate() {
        let shared = Arc::clone(&shared);
        let cpu = cpus[i];
        std::thread::spawn(move || {
            if let Err(e) = pin_cpu(cpu) {
                fail(&format!("pinning listing thread: {e:#}"));
            }
            lister(&dir, &shared);
        });
    }
    {
        let (share, shared) = (share.to_path_buf(), Arc::clone(&shared));
        std::thread::spawn(move || watchdog(&share, &shared));
    }

    let end = Instant::now() + Duration::from_secs(seconds);
    let mut slowest = Duration::ZERO;
    while Instant::now() < end {
        shared.busy.store(threads, Ordering::SeqCst);
        shared.progress_us.store(shared.now_us(), Ordering::SeqCst);
        shared.bursts.fetch_add(1, Ordering::SeqCst);
        let t = Instant::now();
        shared.start.wait();
        shared.done.wait();
        slowest = slowest.max(t.elapsed());
        // Preserve busy == 0 for the watchdog's rescue check instead of starting a
        // new burst before it gets to observe completion of the stranded one.
        while shared.stopping.load(Ordering::SeqCst) {
            std::thread::park();
        }
    }
    println!(
        "{} bursts of {threads} concurrent listings in {seconds}s, none stranded (slowest \
         burst {} ms)",
        shared.bursts.load(Ordering::SeqCst),
        slowest.as_millis()
    );
    Ok(0)
}

fn lister(dir: &Path, shared: &Shared) {
    loop {
        shared.start.wait();
        // A fresh open each burst: overlayfs keeps a merged listing only while the directory
        // is open, so every burst reads the lower directory again.
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries {
                    if let Err(e) = entry {
                        fail(&format!("listing {}: {e}", dir.display()));
                    }
                }
            }
            Err(e) => fail(&format!("opening {}: {e}", dir.display())),
        }
        shared.busy.fetch_sub(1, Ordering::SeqCst);
        shared.progress_us.store(shared.now_us(), Ordering::SeqCst);
        shared.done.wait();
    }
}

fn watchdog(share: &Path, shared: &Shared) {
    let stall_us = u64::try_from(STALL.as_micros()).unwrap_or(u64::MAX);
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let busy = shared.busy.load(Ordering::SeqCst);
        let idle = shared
            .now_us()
            .saturating_sub(shared.progress_us.load(Ordering::SeqCst));
        if busy == 0 || idle < stall_us {
            continue;
        }
        shared.stopping.store(true, Ordering::SeqCst);
        println!(
            "stranded: burst {} has {busy} listing(s) unfinished {}s after its last progress",
            shared.bursts.load(Ordering::SeqCst),
            STALL.as_secs()
        );
        // Any request on the share: its completion resends the queued ones. From its own
        // thread, so a lookup stuck behind the stranded request cannot hold the watchdog.
        let rescue = share.join("rescue");
        std::thread::spawn(move || {
            // The lookup's own result (most likely ENOENT) does not matter.
            let _ = std::fs::symlink_metadata(rescue);
        });
        let t = Instant::now();
        while shared.busy.load(Ordering::SeqCst) != 0 && t.elapsed() < STALL {
            std::thread::sleep(Duration::from_millis(10));
        }
        if shared.busy.load(Ordering::SeqCst) != 0 {
            println!("still stranded {}s after another request", STALL.as_secs());
            std::process::exit(STRANDED_FOR_GOOD.into());
        }
        println!(
            "freed by another request on the share after {} ms",
            t.elapsed().as_millis()
        );
        std::process::exit(STRANDED.into());
    }
}

fn listing_cpus(count: usize) -> Result<Vec<usize>> {
    // Managed MSI-X vectors reject writes to smp_affinity_list. Reserve their
    // effective CPUs instead; a parked submitter must not park the completion CPU.
    let interrupts = std::fs::read_to_string("/proc/interrupts")?;
    let mut reserved = Vec::new();
    for line in interrupts
        .lines()
        .filter(|s| s.contains("virtio") && s.contains("req."))
    {
        let irq = line
            .split_once(':')
            .context("IRQ line has no colon")?
            .0
            .trim();
        let irq: usize = irq.parse()?;
        let mask = std::fs::read_to_string(format!("/proc/irq/{irq}/effective_affinity_list"))?;
        for range in mask.trim().split(',') {
            let (first, last) = range.split_once('-').unwrap_or((range, range));
            let first: usize = first.parse()?;
            let last: usize = last.parse()?;
            if first > last || last >= libc::CPU_SETSIZE as usize {
                bail!("invalid IRQ CPU range: {range}");
            }
            reserved.extend(first..=last);
        }
    }
    if reserved.is_empty() {
        bail!("no virtio-fs request IRQ found");
    }
    // SAFETY: the kernel writes a cpu_set_t of the supplied size to live storage.
    let mut allowed: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    if unsafe { libc::sched_getaffinity(0, std::mem::size_of_val(&allowed), &mut allowed) } != 0 {
        return Err(std::io::Error::last_os_error()).context("reading CPU affinity");
    }
    let cpus: Vec<_> = (0..libc::CPU_SETSIZE as usize)
        // SAFETY: cpu is bounded by CPU_SETSIZE and allowed is initialized.
        .filter(|&cpu| unsafe { libc::CPU_ISSET(cpu, &allowed) } && !reserved.contains(&cpu))
        .take(count)
        .collect();
    if cpus.len() != count {
        bail!("need {count} CPUs apart from virtio-fs IRQ CPUs {reserved:?}");
    }
    println!("virtio-fs IRQ CPUs {reserved:?}");
    Ok(cpus)
}

fn pin_cpu(cpu: usize) -> Result<()> {
    // SAFETY: zero is a valid empty cpu_set_t.
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    // SAFETY: cpu is below CPU_SETSIZE and set is a live cpu_set_t. pid 0 selects
    // only this calling thread; the kernel copies the mask during the call.
    let result = unsafe {
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of_val(&set), &set)
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("setting CPU affinity");
    }
    Ok(())
}

/// Ends the process: a worker that returned instead would leave the others at a barrier.
fn fail(msg: &str) -> ! {
    eprintln!("vk-testkit virtiofs-burst: {msg}");
    std::process::exit(2);
}
