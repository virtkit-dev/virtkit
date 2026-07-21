//! Per-op virtio-fs microbenchmark. Isolates each metadata/data op so we can see which
//! one carries the round-trip cost. Usage: fsbench <dir> <N>.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Time `op` over `n` iterations and print the per-op cost. The body should be a single
/// filesystem operation (plus the path formatting the C-library equivalent would also
/// pay), so the printed figure isolates that op's round-trip.
fn bench(label: &str, n: u64, mut op: impl FnMut(u64)) {
    let start = Instant::now();
    for i in 0..n {
        op(i);
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "  {label:<16} {:8.1} us/op  ({n} ops, {secs:.2} s)",
        secs / n as f64 * 1e6
    );
}

/// open(O_CREAT|O_WRONLY, 0644): create the file without truncating an existing one.
fn create(path: &Path) -> fs::File {
    fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o644)
        .open(path)
        .unwrap_or_else(|e| panic!("creating {}: {e}", path.display()))
}

fn main() {
    let mut args = std::env::args();
    let prog = args.next().unwrap_or_else(|| "fsbench".into());
    let (Some(dir), Some(n)) = (
        args.next(),
        args.next()
            .and_then(|s| s.parse::<u64>().ok().filter(|&n| n > 0)),
    ) else {
        eprintln!("usage: {prog} <dir> <N>");
        std::process::exit(2);
    };
    let base = PathBuf::from(dir).join("fsb");
    fs::create_dir_all(&base).expect("creating the bench dir");
    let buf = [b'x'; 4096];

    // create: O_CREAT|O_WRONLY then close, empty file
    bench("create", n, |i| drop(create(&base.join(format!("c{i}")))));
    // stat: on the just-created files
    bench("stat", n, |i| {
        fs::metadata(base.join(format!("c{i}"))).expect("stat");
    });
    // write4k: create + one 4KB write + close
    bench("write4k", n, |i| {
        create(&base.join(format!("w{i}")))
            .write_all(&buf)
            .expect("write");
    });
    // fsync: create + 4KB write + fsync + close
    bench("write4k_fsync", n, |i| {
        let mut f = create(&base.join(format!("f{i}")));
        f.write_all(&buf).expect("write");
        f.sync_all().expect("fsync");
    });
    // unlink: the create/ files, then cleanup of the write4k/fsync files
    bench("unlink", n, |i| {
        fs::remove_file(base.join(format!("c{i}"))).expect("unlink");
    });
    bench("unlink_w", n, |i| {
        fs::remove_file(base.join(format!("w{i}"))).expect("unlink");
    });
    bench("unlink_f", n, |i| {
        fs::remove_file(base.join(format!("f{i}"))).expect("unlink");
    });
    fs::remove_dir(&base).expect("removing the bench dir");
}
