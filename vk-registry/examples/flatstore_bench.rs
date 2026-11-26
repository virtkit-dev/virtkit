//! Build this `vk_registry::flatstore` benchmark with `--release` and run it on the target
//! filesystem. Compare dentry counts with the tag-per-file store for new puts, misses and hits.
//!
//! ```text
//! flatstore_bench populate <area> <count> <threads>    objects of sccache-like sizes, sparse
//! flatstore_bench load <area> <count>                  lazy load per shard, RSS, watches
//! flatstore_bench tput <area> <threads> <secs> <procs> put, get, miss and contains throughput
//! flatstore_bench lag <area> <secs> <loaders>          put-to-visibility: secs × 500 puts
//! flatstore_bench dentries <dir> <ops>                 dentry-state deltas per batch
//! flatstore_bench evict <area> <over> <evict_to>       one pass, byte cap = floor(usage / (1 + <over>))
//! ```
//!
//! `dentries` creates a fresh directory under `<dir>`. With `FLATSTORE_DURABLE=1`, `tput`
//! syncs each object's data before publication ([`Options::durable`]).

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: jemallocator::Jemalloc = jemallocator::Jemalloc;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsFd as _, AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use vk_registry::flatstore::{FlatStore, Options};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a = |i: usize| -> Result<&str> {
        args.get(i)
            .map(String::as_str)
            .with_context(|| format!("argument {i} missing; see the source's header"))
    };
    let n = |i: usize| -> Result<u64> { Ok(a(i)?.parse()?) };
    let pos = |i: usize| -> Result<u64> {
        let v = n(i)?;
        ensure!(v > 0, "argument {i} must be positive");
        Ok(v)
    };
    match a(0)? {
        "populate" => populate(Path::new(a(1)?), n(2)?, pos(3)?),
        "load" => load(Path::new(a(1)?), n(2)?),
        "tput" => tput(Path::new(a(1)?), pos(2)?, pos(3)?, pos(4)?),
        "tput-child" => tput_child(Path::new(a(1)?), a(2)?, pos(3)?, pos(4)?, a(5)?),
        "lag" => lag(Path::new(a(1)?), pos(2)?, n(3)?),
        "lag-writer" => lag_writer(Path::new(a(1)?), a(2)?, pos(3)?),
        "dentries" => dentries(Path::new(a(1)?), pos(2)?),
        "evict" => evict(Path::new(a(1)?), a(2)?.parse()?, a(3)?.parse()?),
        other => bail!("unknown command {other}"),
    }
}

/// splitmix64: a deterministic stream, seeded per thread.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    /// Model sccache sizes with a lognormal draw (median 136 KB, mean 470 KB, p99 ≈ 5 MB).
    /// Cap samples at 64 MiB.
    fn size(&mut self) -> u64 {
        let (u1, u2) = (self.unit().max(1e-12), self.unit());
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        let (mu, sigma) = (136_000f64.ln(), (2.0 * (470.0f64 / 136.0).ln()).sqrt());
        ((mu + sigma * z).exp() as u64).clamp(1, 64 << 20)
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn mono_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: a valid timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// A per-run name derived from the PID and monotonic clock.
fn unique() -> String {
    format!("{}-{}", std::process::id(), mono_ns())
}

fn status(field: &str) -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(field))
                .map(|l| l[field.len()..].trim().to_string())
        })
        .unwrap_or_else(|| "unavailable".into())
}

/// Count watches in readable procfs fdinfo files. Directory iteration errors return `None`.
fn inotify_watches() -> Option<usize> {
    let mut n = 0;
    for e in std::fs::read_dir("/proc/self/fdinfo").ok()? {
        if let Ok(s) = std::fs::read_to_string(e.ok()?.path()) {
            n += s.lines().filter(|l| l.starts_with("inotify wd:")).count();
        }
    }
    Some(n)
}

fn hash_name(key: &[u8]) -> (u8, String) {
    let h: [u8; 32] = Sha256::digest(key).into();
    (h[0], h.iter().map(|b| format!("{b:02x}")).collect())
}

/// Fixed-size, mergeable latency histograms in nanoseconds. Sixteen buckets per power of
/// two bound the error at 6.25%. The maximum is exact.
#[derive(Clone)]
struct Hist(Vec<u64>, u64);

impl Hist {
    fn new() -> Hist {
        Hist(vec![0; 64 * 16], 0)
    }
    fn bucket(ns: u64) -> usize {
        if ns < 16 {
            return ns as usize;
        }
        let e = 63 - ns.leading_zeros() as usize;
        (e - 3) * 16 + ((ns >> (e - 4)) & 15) as usize
    }
    fn value(b: usize) -> u64 {
        if b < 16 {
            return b as u64;
        }
        (16 + (b % 16) as u64) << (b / 16 + 3 - 4)
    }
    fn record(&mut self, ns: u64) {
        self.0[Self::bucket(ns)] += 1;
        self.1 = self.1.max(ns);
    }
    fn merge(&mut self, o: &Hist) {
        for (a, b) in self.0.iter_mut().zip(&o.0) {
            *a += b;
        }
        self.1 = self.1.max(o.1);
    }
    /// The `p` quantile, a bucket's lower bound; the largest sample itself for 1.
    fn pct(&self, p: f64) -> u64 {
        let total: u64 = self.0.iter().sum();
        if total == 0 {
            return 0;
        }
        if p >= 1.0 {
            return self.1;
        }
        let rank = ((total as f64 * p).ceil() as u64).max(1);
        let mut seen = 0;
        for (b, c) in self.0.iter().enumerate() {
            seen += c;
            if seen >= rank {
                return Self::value(b);
            }
        }
        Self::value(self.0.len() - 1)
    }
    /// `max;bucket:count,...` for the nonzero buckets.
    fn encode(&self) -> String {
        let parts: Vec<String> = (self.0.iter().enumerate())
            .filter(|(_, c)| **c > 0)
            .map(|(b, c)| format!("{b}:{c}"))
            .collect();
        format!("{};{}", self.1, parts.join(","))
    }
    fn decode(s: &str) -> Result<Hist> {
        let mut h = Hist::new();
        let (max, s) = s.split_once(';').context("histogram maximum")?;
        h.1 = max.parse()?;
        if !s.is_empty() {
            for part in s.split(',') {
                let (b, c) = part.split_once(':').context("histogram entry")?;
                let b: usize = b.parse()?;
                ensure!(b < h.0.len(), "histogram bucket {b}");
                h.0[b] += c.parse::<u64>()?;
            }
        }
        Ok(h)
    }
}

/// On drop, try to kill and reap children still held by the guard.
struct Children(Vec<Child>);

impl Children {
    /// Require every child to exit successfully. On failure the guard retains all children,
    /// including those whose exit status is already cached.
    fn finish(mut self) -> Result<()> {
        for c in &mut self.0 {
            let st = c.wait()?;
            ensure!(st.success(), "a child process failed: {st}");
        }
        self.0.clear();
        Ok(())
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// Area commands require this marker to keep the store from reaping unrelated directories.
const MARKER: &str = ".flatstore-bench";

/// Pin the benchmark area so the returned path survives renames while the descriptor is open.
/// With `init`, create a missing area or mark an empty one.
fn pin(area: &Path, init: bool) -> Result<(OwnedFd, PathBuf)> {
    pin_as(area, init, false)
}

/// Child commands also accept `fd:<n>` from [`inheritable`] so every process opens the same area.
fn pin_child(area: &Path) -> Result<(OwnedFd, PathBuf)> {
    pin_as(area, false, true)
}

fn pin_as(area: &Path, init: bool, child: bool) -> Result<(OwnedFd, PathBuf)> {
    let inherited = (area.to_str())
        .and_then(|a| a.strip_prefix("fd:"))
        .filter(|_| child);
    let dir = match inherited {
        Some(n) => {
            let n: libc::c_int = n.parse()?;
            // SAFETY: no pointers; the result is checked.
            let fd = unsafe { libc::fcntl(n, libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error()).context("the inherited area");
            }
            // SAFETY: fresh descriptor.
            unsafe { OwnedFd::from_raw_fd(fd) }
        }
        None => {
            if init {
                std::fs::create_dir_all(area)?;
            }
            vk_fs::open_dir_nofollow(area)?
        }
    };
    // O_PATH inspects the marker without blocking on a FIFO.
    let marked = open_in(&dir, MARKER, libc::O_PATH)
        .is_ok_and(|f| std::fs::File::from(f).metadata().is_ok_and(|m| m.is_file()));
    if !marked {
        ensure!(
            init && vk_fs::dir_names(dir.as_fd())?.is_empty(),
            "{} has no usable {MARKER}: not a benchmark area",
            area.display()
        );
        drop(open_in(
            &dir,
            MARKER,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        )?);
    }
    let path = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
    Ok((dir, path))
}

/// A duplicate of `dir` that children inherit, and the `fd:<n>` argument naming it.
fn inheritable(dir: &OwnedFd) -> Result<(OwnedFd, String)> {
    // SAFETY: no pointers; the result is checked. F_DUPFD leaves close-on-exec clear.
    let fd = unsafe { libc::fcntl(dir.as_raw_fd(), libc::F_DUPFD, 3) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("duplicating the area");
    }
    Ok((
        // SAFETY: fresh descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) },
        format!("fd:{fd}"),
    ))
}

fn open_in(dir: &OwnedFd, name: &str, flags: libc::c_int) -> Result<OwnedFd> {
    let c = std::ffi::CString::new(name)?;
    // SAFETY: the descriptor is live and the name NUL-terminated.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("opening {name}"));
    }
    // SAFETY: fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn rename_in(from: &OwnedFd, old: &str, to: &OwnedFd, new: &str) -> Result<()> {
    let (o, n) = (std::ffi::CString::new(old)?, std::ffi::CString::new(new)?);
    // SAFETY: live descriptors and NUL-terminated names.
    if unsafe { libc::renameat(from.as_raw_fd(), o.as_ptr(), to.as_raw_fd(), n.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("renaming {old}"));
    }
    Ok(())
}

/// Create `count` sparse `k-<i>` objects with sampled sizes and mtimes in the past 30 days.
/// Size files in a reapable run, then rename them over previous objects through pinned
/// staging and shard descriptors. Creating and removing the run resolve `runs` again.
fn populate(area: &Path, count: u64, threads: u64) -> Result<()> {
    let (_pin, area) = pin(area, true)?;
    let area = area.as_path();
    drop(FlatStore::open(area, Options::default())?); // makes the layout
    let objects = vk_fs::open_dir_nofollow(&area.join("objects"))?;
    let shards: Vec<OwnedFd> = (0..=u8::MAX)
        .map(|s| {
            open_in(
                &objects,
                &format!("{s:02x}"),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )
        })
        .collect::<Result<_>>()?;
    // A new dot-prefixed run has a grace period to acquire its lock before publication.
    let runs = vk_fs::open_dir_nofollow(&area.join("runs"))?;
    // The reaper recognizes the store's run-name format.
    let name = format!("{}-{:016x}", std::process::id(), mono_ns());
    std::fs::create_dir(area.join("runs").join(format!(".{name}")))?;
    let staging = open_in(
        &runs,
        &format!(".{name}"),
        libc::O_RDONLY | libc::O_DIRECTORY,
    )?;
    // SAFETY: plain flock on a live descriptor.
    ensure!(unsafe { libc::flock(staging.as_raw_fd(), libc::LOCK_EX) } == 0);
    rename_in(&runs, &format!(".{name}"), &runs, &name)?;
    let start = Instant::now();
    let total = AtomicU64::new(0);
    std::thread::scope(|s| -> Result<()> {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let (shards, staging, total) = (&shards, &staging, &total);
                s.spawn(move || -> Result<()> {
                    let mut rng = Rng(t);
                    let base = now() - 30 * 86400;
                    for i in (t..count).step_by(threads as usize) {
                        let size = rng.size();
                        let mtime = base + rng.next() % (30 * 86400);
                        let (shard, hex) = hash_name(format!("k-{i}").as_bytes());
                        let tmp = format!("s-{i}");
                        let f = std::fs::File::from(open_in(
                            staging,
                            &tmp,
                            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                        )?);
                        f.set_len(size)?;
                        f.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(mtime))?;
                        drop(f);
                        rename_in(staging, &tmp, &shards[usize::from(shard)], &hex)?;
                        total.fetch_add(size, Ordering::Relaxed);
                    }
                    Ok(())
                })
            })
            .collect();
        for h in handles {
            h.join().expect("populate thread panicked")?;
        }
        Ok(())
    })?;
    std::fs::remove_dir(area.join("runs").join(&name))?;
    println!(
        "populated {count} objects, {:.1} GB logical (sparse), in {:.1?}",
        total.load(Ordering::Relaxed) as f64 / 1e9,
        start.elapsed()
    );
    Ok(())
}

fn load(area: &Path, count: u64) -> Result<()> {
    let (_pin, area) = pin(area, true)?;
    let area = area.as_path();
    let rss0 = status("VmRSS:");
    let t0 = Instant::now();
    let store = FlatStore::open(area, Options::default())?;
    let open = t0.elapsed();
    // Probe one population key per represented shard.
    let mut probe: BTreeMap<u8, String> = BTreeMap::new();
    for i in 0..count {
        let k = format!("k-{i}");
        probe.entry(Sha256::digest(k.as_bytes())[0]).or_insert(k);
        if probe.len() == 256 {
            break;
        }
    }
    let mut per = Hist::new();
    let t1 = Instant::now();
    for k in probe.values() {
        let t = Instant::now();
        store.contains(k.as_bytes())?;
        per.record(t.elapsed().as_nanos() as u64);
    }
    let all = t1.elapsed();
    // Sample after first touches, before `usage` loads unvisited shards and fills missing stats.
    let (rss1, watches, loaded) = (status("VmRSS:"), inotify_watches(), store.loaded_shards());
    let attempts = 100_000.min(count);
    let t = Instant::now();
    let mut found = 0;
    for i in 0..attempts {
        found += store.contains(format!("k-{i}").as_bytes())? as u64;
    }
    let lookup = t.elapsed();
    let t = Instant::now();
    let u = store.usage()?;
    let usage = t.elapsed();
    if probe.is_empty() {
        println!("open {open:.1?}; shard first touch: no samples");
    } else {
        println!(
            "open {open:.1?}; shard first touch p50 {:.0} us p99 {:.0} us max {:.0} us; {} shards {all:.2?}",
            per.pct(0.5) as f64 / 1e3,
            per.pct(0.99) as f64 / 1e3,
            per.pct(1.0) as f64 / 1e3,
            probe.len()
        );
    }
    println!(
        "{loaded} shards loaded: RSS before {rss0}, after {rss1}; inotify watches {}",
        watches.map_or("unavailable".into(), |n| n.to_string()),
    );
    if attempts == 0 {
        println!("contains: no samples");
    } else {
        println!(
            "contains of {attempts} keys ({found} present): {:.0} ns each",
            lookup.as_nanos() as f64 / attempts as f64
        );
    }
    println!(
        "usage (every shard loaded, every object stat'ed) in {usage:.2?}: {} objects {:.1} GB; RSS {}, peak {}",
        u.objects,
        u.bytes as f64 / 1e9,
        status("VmRSS:"),
        status("VmHWM:"),
    );
    Ok(())
}

const PHASES: [&str; 4] = ["put", "get", "miss", "contains"];

/// Throughput worker process, also used for lag load. Each phase starts worker threads,
/// prints `ready` once they are waiting and releases them on `go` from stdin.
/// Each result is `phase ops bytes start_ns end_ns histogram`. The timestamps span release
/// to last completion on CLOCK_MONOTONIC. Latencies are in nanoseconds.
/// `barrier` runs all phases once. `loop` repeats until EOF between phases.
fn tput_child(area: &Path, prefix: &str, threads: u64, secs: u64, mode: &str) -> Result<()> {
    ensure!(matches!(mode, "barrier" | "loop"), "unknown mode {mode}");
    let (_pin, area) = pin_child(area)?;
    let opts = Options {
        durable: std::env::var_os("FLATSTORE_DURABLE").is_some_and(|v| v == "1"),
        ..Options::default()
    };
    let store = FlatStore::open(&area, opts)?;
    store.usage()?; // every shard loaded: measure steady state, not first touches
    let mut data = vec![0u8; 64 << 20];
    let mut rng = Rng(0xfeed);
    for c in data.chunks_mut(8) {
        c.copy_from_slice(&rng.next().to_le_bytes()[..c.len()]);
    }
    let data = &data;
    let written: Vec<AtomicU64> = (0..threads).map(|_| AtomicU64::new(0)).collect();
    let mut stdin = std::io::stdin().lock();
    let rounds = if mode == "loop" { usize::MAX } else { 1 };
    for phase in PHASES
        .iter()
        .cycle()
        .take(PHASES.len().saturating_mul(rounds))
    {
        let phase = *phase;
        let (stop, go, ready) = (
            AtomicBool::new(false),
            AtomicBool::new(false),
            AtomicU64::new(0),
        );
        let merged = Mutex::new((0u64, 0u64, Hist::new(), 0u64));
        let start = AtomicU64::new(0);
        let ended = std::thread::scope(|s| -> Result<bool> {
            let mut handles = Vec::new();
            // Whatever ends the phase early, the workers stop and are joined.
            let run = (|| -> Result<bool> {
                for t in 0..threads {
                    let (store, stop, go, ready, written, merged) =
                        (&store, &stop, &go, &ready, &written, &merged);
                    let worker = move || -> Result<()> {
                        let mut rng = Rng(t * 7919 + 1);
                        // A key some worker put, this one's own if it put any.
                        let hit_key = |rng: &mut Rng| -> Result<String> {
                            let owner = (0..threads)
                                .map(|d| (t + d) % threads)
                                .find(|&w| written[w as usize].load(Ordering::Relaxed) > 0)
                                .context("no worker put anything")?;
                            let n = written[owner as usize].load(Ordering::Relaxed);
                            Ok(format!("{prefix}-{owner}-{}", rng.next() % n))
                        };
                        let (mut ops, mut bytes, mut lat) = (0u64, 0u64, Hist::new());
                        let mut last = 0;
                        let mut buf = vec![0u8; 1 << 20];
                        ready.fetch_add(1, Ordering::Relaxed);
                        while !go.load(Ordering::Acquire) {
                            if stop.load(Ordering::Relaxed) {
                                return Ok(());
                            }
                            std::thread::sleep(Duration::from_micros(50));
                        }
                        while !stop.load(Ordering::Relaxed) {
                            let t0 = Instant::now();
                            match phase {
                                "put" => {
                                    let size = rng.size().min(data.len() as u64) as usize;
                                    let off = (rng.next() as usize) % (data.len() - size + 1);
                                    let i = written[t as usize].load(Ordering::Relaxed);
                                    let key = format!("{prefix}-{t}-{i}");
                                    store.put(key.as_bytes(), &mut &data[off..off + size])?;
                                    written[t as usize].store(i + 1, Ordering::Relaxed);
                                    bytes += size as u64;
                                }
                                "get" => {
                                    let key = hit_key(&mut rng)?;
                                    let mut obj =
                                        store.get(key.as_bytes())?.context("a put key missing")?;
                                    loop {
                                        let r = obj.file.read(&mut buf)?;
                                        if r == 0 {
                                            break;
                                        }
                                        bytes += r as u64;
                                    }
                                }
                                "miss" => {
                                    let key = format!("absent-{prefix}-{t}-{}", rng.next());
                                    ensure!(store.get(key.as_bytes())?.is_none());
                                }
                                _ => {
                                    let key = hit_key(&mut rng)?;
                                    ensure!(store.contains(key.as_bytes())?);
                                }
                            }
                            lat.record(t0.elapsed().as_nanos() as u64);
                            ops += 1;
                            last = mono_ns();
                        }
                        let mut m = merged.lock().unwrap();
                        m.0 += ops;
                        m.1 += bytes;
                        m.2.merge(&lat);
                        if ops > 0 {
                            m.3 = m.3.max(last);
                        }
                        Ok(())
                    };
                    handles.push(
                        std::thread::Builder::new()
                            .spawn_scoped(s, worker)
                            .context("starting a worker thread")?,
                    );
                }
                while ready.load(Ordering::Relaxed) < threads {
                    std::thread::sleep(Duration::from_micros(50));
                }
                // Propagate pipe errors so workers waiting for release can stop.
                let mut out = std::io::stdout().lock();
                writeln!(out, "ready")?;
                out.flush()?;
                drop(out);
                let mut line = String::new();
                if stdin.read_line(&mut line)? == 0 && mode == "loop" {
                    return Ok(true);
                }
                ensure!(line.trim() == "go", "expected go, got {line:?}");
                start.store(mono_ns(), Ordering::Relaxed);
                go.store(true, Ordering::Release);
                // The parent sends nothing during a phase. Any stdin event breaks the protocol.
                let deadline = Instant::now() + Duration::from_secs(secs);
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        break;
                    }
                    let mut fd = libc::pollfd {
                        fd: 0,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let ms = left.as_millis().clamp(1, 1000) as libc::c_int;
                    // SAFETY: one valid pollfd.
                    if unsafe { libc::poll(&mut fd, 1, ms) } > 0 {
                        bail!("unexpected event on parent stdin mid-phase");
                    }
                }
                Ok(false)
            })();
            stop.store(true, Ordering::Relaxed);
            for h in handles {
                h.join().expect("tput thread panicked")?;
            }
            run
        })?;
        if ended {
            return Ok(());
        }
        let (ops, bytes, lat, end) = merged.into_inner().unwrap();
        let start = start.into_inner();
        println!("{phase} {ops} {bytes} {start} {end} {}", lat.encode());
        std::io::stdout().flush()?;
    }
    Ok(())
}

/// Spawn a `tput-child`, its stdin and stdout piped, into `children`.
fn spawn_child(
    children: &mut Children,
    area: &Path,
    prefix: &str,
    threads: u64,
    secs: u64,
    mode: &str,
) -> Result<(ChildStdin, BufReader<ChildStdout>)> {
    let mut c = Command::new(std::env::current_exe()?)
        .args(["tput-child", &area.display().to_string(), prefix])
        .args([threads.to_string(), secs.to_string(), mode.into()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let (i, o) = (c.stdin.take(), c.stdout.take());
    children.0.push(c);
    Ok((i.context("stdin")?, BufReader::new(o.context("stdout")?)))
}

fn read_line(o: &mut BufReader<ChildStdout>) -> Result<String> {
    let mut l = String::new();
    ensure!(o.read_line(&mut l)? > 0, "child stdout closed early");
    Ok(l.trim_end().to_string())
}

/// Release each phase once every process has its workers ready.
fn tput(area: &Path, threads: u64, secs: u64, procs: u64) -> Result<()> {
    let (pinned, _) = pin(area, true)?;
    let (_inherited, arg) = inheritable(&pinned)?;
    let area = Path::new(&arg);
    let prefix = unique();
    let mut children = Children(Vec::new());
    let mut pipes = Vec::new();
    for p in 0..procs {
        let prefix = format!("{prefix}-p{p}");
        pipes.push(spawn_child(
            &mut children,
            area,
            &prefix,
            threads,
            secs,
            "barrier",
        )?);
    }
    for phase in PHASES {
        for (_, o) in &mut pipes {
            ensure!(read_line(o)? == "ready", "a child is not ready for {phase}");
        }
        for (i, _) in &mut pipes {
            i.write_all(b"go\n")?;
            i.flush()?;
        }
        let (mut ops, mut bytes, mut lat) = (0u64, 0u64, Hist::new());
        let (mut first, mut last) = (u64::MAX, 0u64);
        for (_, o) in &mut pipes {
            let l = read_line(o)?;
            let f: Vec<&str> = l.split(' ').collect();
            ensure!(
                f.len() == 6 && f[0] == phase,
                "bad record for {phase}: {l:?}"
            );
            ops += f[1].parse::<u64>()?;
            bytes += f[2].parse::<u64>()?;
            first = first.min(f[3].parse()?);
            last = last.max(f[4].parse()?);
            lat.merge(&Hist::decode(f[5])?);
        }
        // Measure from the earliest release to the latest completion across all processes.
        let wall = last.saturating_sub(first).max(1) as f64 / 1e9;
        println!(
            "{procs} proc x {threads} thr {phase:>8}: {:>9.0} op/s {:>7.0} MB/s  p50 {:>7.1} us  p99 {:>8.1} us",
            ops as f64 / wall,
            bytes as f64 / wall / 1e6,
            lat.pct(0.5) as f64 / 1e3,
            lat.pct(0.99) as f64 / 1e3
        );
    }
    drop(pipes);
    children.finish()
}

/// Put `secs × 500` keys named `<prefix>-<i>`. After each put, report `i put_done_ns`
/// and sleep 2 ms. A closed output pipe ends the writer on its next report.
fn lag_writer(area: &Path, prefix: &str, secs: u64) -> Result<()> {
    let (_pin, area) = pin_child(area)?;
    let store = FlatStore::open(&area, Options::default())?;
    let n = secs * 500;
    std::thread::sleep(Duration::from_millis(500)); // let the reader settle
    let mut out = std::io::stdout().lock();
    for i in 0..n {
        store.put(format!("{prefix}-{i}").as_bytes(), &mut &b"lag"[..])?;
        writeln!(out, "{i} {}", mono_ns())?;
        out.flush()?;
        std::thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

/// Put-to-visibility lag, under load from `loaders` processes that are running before the
/// writer starts and keep running until the last key is seen.
fn lag(area: &Path, secs: u64, loaders: u64) -> Result<()> {
    let (pinned, root) = pin(area, true)?;
    let (_inherited, arg) = inheritable(&pinned)?;
    let area = Path::new(&arg);
    let prefix = format!("lag-{}", unique());
    let reader = FlatStore::open(&root, Options::default())?;
    reader.usage()?;
    let mut children = Children(Vec::new());
    let stop = AtomicBool::new(false);
    let (n, lags) = std::thread::scope(|s| -> Result<(u64, Hist)> {
        let mut feeders = Vec::new();
        // Whatever ends the run, the feeders are told to stop before they are joined.
        let run = (|| -> Result<(u64, Hist)> {
            for p in 0..loaders {
                let phase = (secs / 4).max(1);
                let load = format!("{prefix}-load{p}");
                let (mut i, mut o) = spawn_child(&mut children, area, &load, 8, phase, "loop")?;
                ensure!(read_line(&mut o)? == "ready", "a loader is not ready");
                i.write_all(b"go\n")?;
                let stop = &stop;
                // Release each phase. On stop, close the loader's stdin at the next phase boundary.
                let feeder = move || -> Result<()> {
                    loop {
                        match read_line(&mut o) {
                            Ok(l) if l == "ready" => {
                                if stop.load(Ordering::Relaxed) {
                                    return Ok(());
                                }
                                i.write_all(b"go\n")?;
                            }
                            Ok(_) => {}
                            Err(_) if stop.load(Ordering::Relaxed) => return Ok(()),
                            Err(e) => return Err(e.context("reading the next loader phase")),
                        }
                    }
                };
                feeders.push(
                    std::thread::Builder::new()
                        .spawn_scoped(s, feeder)
                        .context("starting a feeder thread")?,
                );
            }
            observe_lag(area, &prefix, secs, &reader, &mut children)
        })();
        stop.store(true, Ordering::Relaxed);
        for f in feeders {
            f.join().expect("feeder panicked")?;
        }
        run
    })?;
    children.finish()?;
    println!(
        "{n} puts, {loaders} loader procs (8 thr put/get/miss/contains): lag p50 {:.1} us p99 {:.1} us max {:.1} us",
        lags.pct(0.5) as f64 / 1e3,
        lags.pct(0.99) as f64 / 1e3,
        lags.pct(1.0) as f64 / 1e3
    );
    Ok(())
}

/// Run the writer and time when `reader` sees each of its keys.
fn observe_lag(
    area: &Path,
    prefix: &str,
    secs: u64,
    reader: &FlatStore,
    children: &mut Children,
) -> Result<(u64, Hist)> {
    let mut writer = Command::new(std::env::current_exe()?)
        .args(["lag-writer", &area.display().to_string(), prefix])
        .arg(secs.to_string())
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = writer.stdout.take().context("writer stdout")?;
    children.0.push(writer);
    let n = secs * 500;
    // Start each key's timeout when this reader processes its report.
    // Early EOF fails the measurement if reports are missing.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let report = (|| -> Result<(usize, u64)> {
                let line = line?;
                let (i, t) = line.split_once(' ').context("writer line")?;
                Ok((i.parse()?, t.parse()?))
            })();
            if tx.send(report).is_err() {
                return;
            }
        }
    });
    // Poll unseen keys independently, including the next LOOKAHEAD unreported keys.
    // An earlier miss or a late report within that window need not delay the first sighting.
    const LOOKAHEAD: usize = 64;
    let n = n as usize;
    let mut put_ns = vec![0u64; n];
    let mut reported_at = Vec::with_capacity(n);
    let mut seen = vec![0u64; n];
    let mut unseen = std::collections::BTreeSet::new();
    let mut polled_to = 0;
    loop {
        loop {
            match rx.try_recv() {
                Ok(report) => {
                    let (i, t) = report?;
                    ensure!(
                        i == reported_at.len(),
                        "writer line {} is for key {i}",
                        reported_at.len()
                    );
                    ensure!(i < n, "the writer reported more than {n} puts");
                    put_ns[i] = t;
                    reported_at.push(Instant::now());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    ensure!(
                        reported_at.len() == n,
                        "the writer reported {} puts of {n} before closing its output",
                        reported_at.len()
                    );
                    break;
                }
            }
        }
        let to = n.min(reported_at.len() + LOOKAHEAD);
        unseen.extend(polled_to..to);
        polled_to = to;
        let mut found = Vec::new();
        for &i in &unseen {
            if reader.contains(format!("{prefix}-{i}").as_bytes())? {
                seen[i] = mono_ns();
                found.push(i);
            }
        }
        for i in found {
            unseen.remove(&i);
        }
        if let Some(&i) = unseen.first()
            && i < reported_at.len()
            && reported_at[i].elapsed() > Duration::from_secs(30)
        {
            bail!("timed out waiting for {prefix}-{i} to become visible");
        }
        if reported_at.len() == n && unseen.is_empty() {
            break;
        }
    }
    let mut lags = Hist::new();
    for (seen, put) in seen.iter().zip(&put_ns) {
        // Observation can precede the writer's post-put timestamp. Record zero in that case.
        lags.record(seen.saturating_sub(*put));
    }
    Ok((n as u64, lags))
}

/// (nr_dentry, nr_negative)
fn dentry_state() -> Result<(i64, i64)> {
    let path = "/proc/sys/fs/dentry-state";
    let s = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
    let f: Vec<i64> = s
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .with_context(|| format!("parsing {path}: {s:?}"))?;
    ensure!(f.len() >= 5, "{path} has {} fields: {s:?}", f.len());
    Ok((f[0], f[4]))
}

fn measure(label: &str, ops: u64, f: impl FnOnce() -> Result<()>) -> Result<()> {
    let (d0, n0) = dentry_state()?;
    let t = Instant::now();
    f()?;
    let el = t.elapsed();
    let (d1, n1) = dentry_state()?;
    println!(
        "{label:<44} {ops:>7} ops {:>7.2}s  dentries {:>+9}  negative {:>+9}",
        el.as_secs_f64(),
        d1 - d0,
        n1 - n0
    );
    Ok(())
}

/// Try to remove this run's scratch tree on drop. Cleanup walks the pinned directory
/// and checks that `name` in `parent` still identifies it before the walk and final removal.
struct RemoveOnDrop {
    parent: OwnedFd,
    name: String,
    dir: OwnedFd,
    done: bool,
}

impl RemoveOnDrop {
    fn remove(&mut self) -> Result<()> {
        self.done = true;
        let r = vk_fs::remove_tree_in(self.parent.as_fd(), self.name.as_ref(), self.dir.as_fd())?;
        ensure!(r.skipped.is_empty(), "left behind: {:?}", r.skipped);
        Ok(())
    }
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.remove();
        }
    }
}

fn dentries(parent: &Path, ops: u64) -> Result<()> {
    std::fs::create_dir_all(parent)?;
    // A fresh, pinned directory isolates the files each run touches. The counters are system-wide.
    let name = format!("flatstore-bench-{}", unique());
    let parent_fd = vk_fs::open_dir_nofollow(parent)?;
    let c = std::ffi::CString::new(name.as_str())?;
    // SAFETY: the descriptor is live and the name NUL-terminated.
    if unsafe { libc::mkdirat(parent_fd.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("creating {}", parent.join(&name).display()));
    }
    let dir_fd = open_in(&parent_fd, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
    // Restore owner permissions masked by umask while keeping the directory private.
    // SAFETY: plain call on a live descriptor.
    if unsafe { libc::fchmod(dir_fd.as_raw_fd(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error()).context("the scratch directory's mode");
    }
    let dir = PathBuf::from(format!("/proc/self/fd/{}", dir_fd.as_raw_fd()));
    println!("in {}", parent.join(&name).display());
    let mut cleanup = RemoveOnDrop {
        parent: parent_fd,
        name,
        dir: dir_fd,
        done: false,
    };
    measure("idle 5 s (noise)", 0, || {
        std::thread::sleep(Duration::from_secs(5));
        Ok(())
    })?;

    // flatstore
    let clock = Arc::new(AtomicU64::new(now()));
    let c = Arc::clone(&clock);
    let opts = Options {
        refresh: Duration::ZERO,
        clock: Some(Arc::new(move || c.load(Ordering::Relaxed))),
        ..Options::default()
    };
    let area = dir.join("flat");
    let store = FlatStore::open(&area, opts.clone())?;
    store.usage()?;
    measure("flat: GET miss", ops, || {
        for i in 0..ops {
            ensure!(store.get(format!("absent-{i}").as_bytes())?.is_none());
        }
        Ok(())
    })?;
    let body = [7u8; 1024];
    measure("flat: PUT new", ops, || {
        for i in 0..ops {
            store.put(format!("k-{i}").as_bytes(), &mut &body[..])?;
        }
        Ok(())
    })?;
    measure("flat: PUT overwrite", ops, || {
        for i in 0..ops {
            store.put(format!("k-{i}").as_bytes(), &mut &body[..])?;
        }
        Ok(())
    })?;
    clock.fetch_add(1, Ordering::Relaxed);
    measure("flat: GET hit + recency touch", ops, || {
        for i in 0..ops {
            store.get(format!("k-{i}").as_bytes())?.context("hit")?;
        }
        Ok(())
    })?;
    measure("flat: GET hit (no touch)", ops, || {
        for i in 0..ops {
            store.get(format!("k-{i}").as_bytes())?.context("hit")?;
        }
        Ok(())
    })?;
    measure("flat: DELETE", ops / 2, || {
        for i in 0..ops / 2 {
            ensure!(store.delete(format!("k-{i}").as_bytes())?);
        }
        Ok(())
    })?;
    drop(store);
    let capped = FlatStore::open(
        &area,
        Options {
            cap: Some(1),
            evict_to: 0.0,
            evict_interval: Duration::from_secs(3600),
            ..opts
        },
    )?;
    let left = ops - ops / 2;
    measure("flat: evict all", left, || {
        let r = capped.evict()?.context("evictor")?;
        ensure!(r.evicted == left, "{r:?}");
        Ok(())
    })?;
    drop(capped);

    // Model the S3 view's single raw-file tag. PUT /files/ also writes a digest tag.
    let store = vk_registry::Store::new(dir.join("store"))?;
    let src = dir.join("src");
    // sccache's key layout: `a/b/c/<hash>`, so a repository per three-hex prefix
    let key = |i: u64| {
        let (_, h) = hash_name(format!("k-{i}").as_bytes());
        (
            format!("files/sccache/{}/{}/{}", &h[0..1], &h[1..2], &h[2..3]),
            h,
        )
    };
    measure("store: PUT new (put_file)", ops, || {
        let mut f = std::fs::File::create_new(&src)?;
        for i in 0..ops {
            let mut b = body;
            b[..8].copy_from_slice(&i.to_le_bytes());
            use std::io::Seek;
            f.seek(std::io::SeekFrom::Start(0))?;
            f.write_all(&b)?;
            let sha: String = Sha256::digest(b)
                .iter()
                .map(|x| format!("{x:02x}"))
                .collect();
            let (repo, tag) = key(i);
            store.put_file(&[(&repo, &tag)], &src, &sha, None, &Default::default())?;
        }
        Ok(())
    })?;
    measure("store: GET miss (open_file, absent tag)", ops, || {
        for i in 0..ops {
            // Use an existing repository so the miss reaches the tag name.
            let ((repo, _), (_, tag)) = (key(i), key(ops + i));
            ensure!(store.open_file(&repo, &tag)?.is_none());
        }
        Ok(())
    })?;
    measure("store: GET hit (open_file)", ops, || {
        for i in 0..ops {
            let (repo, tag) = key(i);
            store.open_file(&repo, &tag)?.context("hit")?;
        }
        Ok(())
    })?;
    drop(store);
    cleanup
        .remove()
        .context("removing the benchmark's directory")
}

fn evict(area: &Path, over: f64, evict_to: f64) -> Result<()> {
    ensure!(
        over.is_finite() && over > 0.0,
        "<over> must be a positive fraction"
    );
    ensure!(
        (0.0..=1.0).contains(&evict_to),
        "<evict_to> must be within 0..=1"
    );
    let (_pin, area) = pin(area, true)?;
    let area = area.as_path();
    let probe = FlatStore::open(area, Options::default())?;
    let u = probe.usage()?;
    drop(probe);
    let cap = (u.bytes as f64 / (1.0 + over)) as u64;
    let store = FlatStore::open(
        area,
        Options {
            cap: Some(cap),
            evict_to,
            evict_interval: Duration::from_secs(3600),
            ..Options::default()
        },
    )?;
    // Preload the index to time a steady-state evictor. Inotify tracks later changes.
    let t = Instant::now();
    store.usage()?;
    let load = t.elapsed();
    let (d0, n0) = dentry_state()?;
    let r = store.evict()?.context("not the evictor")?;
    let (d1, n1) = dentry_state()?;
    println!(
        "{} objects {:.1} GB, cap {:.1} GB, evict_to {evict_to}: index load + stat {load:.2?}; evicted {} ({:.1} GB), raced {}, listing {:.2?}, select {:.2?}, pass {:.2?}; RSS peak {}; dentries {:+} negative {:+}",
        u.objects,
        u.bytes as f64 / 1e9,
        cap as f64 / 1e9,
        r.evicted,
        r.freed as f64 / 1e9,
        r.raced,
        r.listed,
        r.select.saturating_sub(r.listed),
        r.total,
        status("VmHWM:"),
        d1 - d0,
        n1 - n0
    );
    Ok(())
}
