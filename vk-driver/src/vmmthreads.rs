//! What a job's VMM threads were doing when its supervisor stopped it.
//!
//! A guest request the host never answers leaves nothing behind: the job runs into its
//! timeout and the VMM is killed with the evidence. So the supervisor, before it stops the
//! VMM, records each thread's name, state, wait channel, the syscall it is blocked in with
//! the file its first argument names when that is an fd, and its kernel stack, which the
//! kernel shows only to root — to the job dir, which the guest cannot reach. `cleanup` then
//! copies the record next to the job's guest statistics, which outlive the job; the guest
//! shares that directory, so the record goes there only once the guest is gone.

use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::jobctx::JobCtx;

/// The record's name, in the job dir and then in its archive directory.
pub const FILE_NAME: &str = "vmm-threads.txt";

/// Record the job's VMM threads (`pid`) only if the job has an archive directory.
/// Best effort: failure loses the record, never blocks teardown. When prepare tears down
/// a leftover job, its record is deleted with its job directory.
pub fn record(ctx: &JobCtx, pid: u32) {
    if crate::atop::job_archive_dir(ctx).is_none() {
        return;
    }
    if let Err(e) = vk_fs::write_atomic_unsynced(&ctx.vmm_threads_file(), &snapshot(pid), 0o600) {
        eprintln!("virtkit: warning: {e:#}");
    }
}

/// Copy the record into the job's archive directory, once the guest that shares that directory
/// is gone: `cleanup`, after the supervisor stops. Best effort, like the statistics it joins.
pub fn archive(ctx: &JobCtx) {
    let Some(dir) = crate::atop::job_archive_dir_after_vm(ctx) else {
        return;
    };
    if let Err(e) = copy_into(&ctx.vmm_threads_file(), &dir) {
        eprintln!("virtkit: warning: {e:#}");
    }
}

/// Copy `record`, if there is one, into `dir` under [`FILE_NAME`]. The guest had `dir`, so the
/// copy is renamed into place: a symlink it planted under that name is replaced, not followed,
/// and a directory there fails the copy.
fn copy_into(record: &Path, dir: &Path) -> Result<()> {
    let data = match std::fs::read(record) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", record.display())),
    };
    vk_fs::write_atomic_unsynced(&dir.join(FILE_NAME), &data, 0o600)
}

/// One line per thread of `pid`, by thread id, each followed by its kernel stack where
/// readable.
fn snapshot(pid: u32) -> Vec<u8> {
    let proc = PathBuf::from(format!("/proc/{pid}"));
    let mut out = format!("# threads of VMM pid {pid} as its supervisor stopped it\n").into_bytes();
    let tasks = match std::fs::read_dir(proc.join("task")) {
        Ok(tasks) => tasks,
        Err(e) => {
            out.extend_from_slice(format!("# no thread list: {e}\n").as_bytes());
            return out;
        }
    };
    // A thread that exits while the list is read, or before its line is written, is not in it.
    let mut tids: Vec<u32> = tasks
        .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
        .collect();
    tids.sort_unstable();
    for tid in tids {
        thread(&proc, tid, &mut out);
    }
    out
}

/// Append the line of thread `tid` of the process at `proc`, unless its `stat` shows it has
/// exited. A file the kernel will not show (`stack` without root, any of a thread exiting
/// after that) leaves its field out.
fn thread(proc: &Path, tid: u32, out: &mut Vec<u8>) {
    let task = proc.join("task").join(tid.to_string());
    let read = |name: &str| {
        std::fs::read(task.join(name)).map(|mut bytes| {
            while bytes.last() == Some(&b'\n') {
                bytes.pop();
            }
            bytes
        })
    };
    let stat = match read("stat") {
        Ok(stat) => Some(stat),
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                || e.raw_os_error() == Some(libc::ESRCH) =>
        {
            return;
        }
        Err(_) => None,
    };
    out.extend_from_slice(format!("{tid} ").as_bytes());
    out.extend(read("comm").unwrap_or_default().escape_ascii());
    let state = stat.and_then(|stat| stat_state(&stat));
    out.extend_from_slice(format!(" state={}", state.map_or('?', char::from)).as_bytes());
    if let Ok(wchan) = read("wchan") {
        out.extend_from_slice(b" wchan=");
        out.extend_from_slice(&wchan);
    }
    if let Ok(syscall) = read("syscall") {
        out.push(b' ');
        out.extend_from_slice(&describe_syscall(&syscall, &task.join("fd")));
    }
    out.push(b'\n');
    if let Ok(stack) = read("stack") {
        for frame in stack.split(|&b| b == b'\n') {
            out.extend_from_slice(b"    ");
            out.extend_from_slice(frame);
            out.push(b'\n');
        }
    }
}

/// The state letter of a `stat` line: the field after the command, whose parentheses may
/// themselves hold a `)`.
fn stat_state(stat: &[u8]) -> Option<u8> {
    let end = stat.iter().rposition(|&b| b == b')')?;
    stat.get(end.checked_add(2)?).copied()
}

/// A task's `syscall` file in words: `running`, `none` for a thread blocked outside any
/// syscall, or the syscall's name and raw arguments — and, for one whose first argument is an
/// fd, the file that fd names in `fd_dir`. The thread may close that fd and open another
/// between the two reads, so the file named is the one the fd held when it was resolved.
fn describe_syscall(raw: &[u8], fd_dir: &Path) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(raw) else {
        return b"syscall="
            .iter()
            .copied()
            .chain(raw.escape_ascii())
            .collect();
    };
    let mut fields = text.split_ascii_whitespace();
    let Some(nr) = fields.next().and_then(|f| f.parse::<libc::c_long>().ok()) else {
        return format!("syscall={text}").into_bytes();
    };
    if nr < 0 {
        return b"syscall=none".to_vec();
    }
    // Six arguments, then the stack and instruction pointers.
    let args: Vec<&str> = fields.take(6).collect();
    let known = SYSCALLS.iter().find(|&&(n, ..)| n == nr);
    let mut out = match known {
        Some((_, name, _)) => format!("syscall={name}"),
        None => format!("syscall={nr}"),
    };
    out.push_str(&format!("({})", args.join(", ")));
    let mut out = out.into_bytes();
    let fd = args
        .first()
        .and_then(|arg| u64::from_str_radix(arg.trim_start_matches("0x"), 16).ok())
        // AT_FDCWD and other negative values do not fit, and name no fd.
        .and_then(|arg| i32::try_from(arg).ok());
    if let (Some((_, _, true)), Some(fd)) = (known, fd)
        && let Ok(target) = std::fs::read_link(fd_dir.join(fd.to_string()))
    {
        out.extend_from_slice(format!(" fd {fd} -> ").as_bytes());
        // Escaped: the guest names the files in its shares, and a newline in one would forge
        // a thread line.
        out.extend(target.as_os_str().as_bytes().escape_ascii());
    }
    out
}

/// The syscalls a blocked VMM thread is likely found in, by number: their names, and whether
/// the first argument is an fd (or a directory fd) worth resolving.
const SYSCALLS: &[(libc::c_long, &str, bool)] = &[
    (libc::SYS_read, "read", true),
    (libc::SYS_write, "write", true),
    (libc::SYS_pread64, "pread64", true),
    (libc::SYS_pwrite64, "pwrite64", true),
    (libc::SYS_readv, "readv", true),
    (libc::SYS_writev, "writev", true),
    (libc::SYS_preadv, "preadv", true),
    (libc::SYS_pwritev, "pwritev", true),
    (libc::SYS_preadv2, "preadv2", true),
    (libc::SYS_pwritev2, "pwritev2", true),
    (libc::SYS_getdents64, "getdents64", true),
    (libc::SYS_ioctl, "ioctl", true),
    (libc::SYS_fsync, "fsync", true),
    (libc::SYS_fdatasync, "fdatasync", true),
    (libc::SYS_fallocate, "fallocate", true),
    (libc::SYS_ftruncate, "ftruncate", true),
    (libc::SYS_lseek, "lseek", true),
    (libc::SYS_fcntl, "fcntl", true),
    (libc::SYS_flock, "flock", true),
    (libc::SYS_fstat, "fstat", true),
    (libc::SYS_fstatfs, "fstatfs", true),
    (libc::SYS_close, "close", true),
    (libc::SYS_fchmod, "fchmod", true),
    (libc::SYS_openat, "openat", true),
    (libc::SYS_newfstatat, "newfstatat", true),
    (libc::SYS_statx, "statx", true),
    (libc::SYS_readlinkat, "readlinkat", true),
    (libc::SYS_unlinkat, "unlinkat", true),
    (libc::SYS_mkdirat, "mkdirat", true),
    (libc::SYS_mknodat, "mknodat", true),
    (libc::SYS_linkat, "linkat", true),
    (libc::SYS_renameat2, "renameat2", true),
    (libc::SYS_fchmodat, "fchmodat", true),
    (libc::SYS_fchownat, "fchownat", true),
    (libc::SYS_utimensat, "utimensat", true),
    (libc::SYS_fgetxattr, "fgetxattr", true),
    (libc::SYS_fsetxattr, "fsetxattr", true),
    (libc::SYS_flistxattr, "flistxattr", true),
    (libc::SYS_fremovexattr, "fremovexattr", true),
    (libc::SYS_copy_file_range, "copy_file_range", true),
    (libc::SYS_epoll_wait, "epoll_wait", true),
    (libc::SYS_epoll_pwait, "epoll_pwait", true),
    (libc::SYS_recvfrom, "recvfrom", true),
    (libc::SYS_recvmsg, "recvmsg", true),
    (libc::SYS_sendto, "sendto", true),
    (libc::SYS_sendmsg, "sendmsg", true),
    (libc::SYS_accept4, "accept4", true),
    (libc::SYS_connect, "connect", true),
    (libc::SYS_io_uring_enter, "io_uring_enter", true),
    (libc::SYS_futex, "futex", false),
    (libc::SYS_poll, "poll", false),
    (libc::SYS_ppoll, "ppoll", false),
    (libc::SYS_nanosleep, "nanosleep", false),
    (libc::SYS_clock_nanosleep, "clock_nanosleep", false),
    (libc::SYS_wait4, "wait4", false),
    (libc::SYS_rt_sigtimedwait, "rt_sigtimedwait", false),
    (libc::SYS_restart_syscall, "restart_syscall", false),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-vmmthreads-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_thread_blocked_reading_a_pipe_shows_the_syscall_and_the_pipe() {
        let (reader, writer) = std::io::pipe().unwrap();
        let fd = reader.as_raw_fd();
        let (tx, rx) = std::sync::mpsc::channel();
        let blocked = std::thread::Builder::new()
            .name("vmmthreads-rd".into())
            .spawn(move || {
                // SAFETY: gettid has no preconditions.
                tx.send(unsafe { libc::gettid() } as u32).unwrap();
                let mut byte = [0u8];
                let mut reader = reader;
                std::io::Read::read(&mut reader, &mut byte).unwrap();
            })
            .unwrap();
        let tid = rx.recv().unwrap();
        let wanted = format!("syscall=read(0x{fd:x}");
        let line = (0..200)
            .find_map(|_| {
                let snapshot = String::from_utf8(snapshot(std::process::id())).unwrap();
                let line = snapshot
                    .lines()
                    .find(|l| l.starts_with(&format!("{tid} ")))
                    .map(str::to_owned);
                if line.as_deref().is_some_and(|l| l.contains(&wanted)) {
                    return line;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
                None
            })
            .expect("the reader never showed blocked in read");
        drop(writer);
        blocked.join().unwrap();
        assert!(
            line.starts_with(&format!("{tid} vmmthreads-rd state=S ")),
            "{line}"
        );
        assert!(line.contains(&format!(" fd {fd} -> pipe:[")), "{line}");
    }

    #[test]
    fn a_syscall_file_reads_as_words() {
        let fd_dir = Path::new("/nonexistent");
        assert_eq!(describe_syscall(b"running", fd_dir), b"syscall=running");
        assert_eq!(
            describe_syscall(b"-1 0x7ffc 0x7f00", fd_dir),
            b"syscall=none"
        );
        let futex = format!(
            "{} 0x7f18c07ff990 0x109 0x0 0x0 0x0 0x0 0x7ffc 0x7f00",
            libc::SYS_futex
        );
        assert_eq!(
            describe_syscall(futex.as_bytes(), fd_dir),
            b"syscall=futex(0x7f18c07ff990, 0x109, 0x0, 0x0, 0x0, 0x0)"
        );
        assert_eq!(
            describe_syscall(b"9999 0x1 0x2 0x3 0x4 0x5 0x6 0x7 0x8", fd_dir),
            b"syscall=9999(0x1, 0x2, 0x3, 0x4, 0x5, 0x6)"
        );
    }

    #[test]
    fn at_fdcwd_names_no_fd() {
        let fd_dir = scratch("fdcwd");
        std::os::unix::fs::symlink("/somewhere", fd_dir.join("0")).unwrap();
        let openat = format!(
            "{} 0xffffffffffffff9c 0x55 0x0 0x0 0x0 0x0 0x7ffc 0x7f00",
            libc::SYS_openat
        );
        let described = describe_syscall(openat.as_bytes(), &fd_dir);
        std::fs::remove_dir_all(&fd_dir).unwrap();
        assert!(!described.windows(4).any(|w| w == b" fd "), "{described:?}");
    }

    #[test]
    fn an_fd_argument_names_its_file_escaped() {
        let fd_dir = scratch("fdname");
        std::os::unix::fs::symlink("/builds/a\nb", fd_dir.join("6")).unwrap();
        let getdents = format!(
            "{} 0x6 0x7f18 0x8000 0x0 0x0 0x0 0x7ffc 0x7f00",
            libc::SYS_getdents64
        );
        let described = describe_syscall(getdents.as_bytes(), &fd_dir);
        std::fs::remove_dir_all(&fd_dir).unwrap();
        assert_eq!(
            String::from_utf8(described).unwrap(),
            "syscall=getdents64(0x6, 0x7f18, 0x8000, 0x0, 0x0, 0x0) fd 6 -> /builds/a\\nb"
        );
    }

    #[test]
    fn an_argument_of_a_syscall_taking_no_fd_is_not_resolved() {
        let fd_dir = scratch("nofd");
        std::os::unix::fs::symlink("/somewhere", fd_dir.join("6")).unwrap();
        let futex = format!("{} 0x6 0x80 0x0 0x0 0x0 0x0 0x7ffc 0x7f00", libc::SYS_futex);
        let described = describe_syscall(futex.as_bytes(), &fd_dir);
        std::fs::remove_dir_all(&fd_dir).unwrap();
        assert_eq!(described, b"syscall=futex(0x6, 0x80, 0x0, 0x0, 0x0, 0x0)");
    }

    #[test]
    fn a_syscall_file_that_is_not_utf8_is_escaped() {
        assert_eq!(
            describe_syscall(b"0 \xff\n", Path::new("/nonexistent")),
            b"syscall=0 \\xff\\n"
        );
    }

    #[test]
    fn a_process_that_is_gone_has_no_thread_list() {
        let snapshot = String::from_utf8(snapshot(u32::MAX)).unwrap();
        let mut lines = snapshot.lines();
        assert_eq!(
            lines.next(),
            Some(
                format!(
                    "# threads of VMM pid {} as its supervisor stopped it",
                    u32::MAX
                )
                .as_str()
            )
        );
        assert!(
            lines.next().unwrap().starts_with("# no thread list: "),
            "{snapshot}"
        );
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn a_stat_line_s_state_follows_the_last_parenthesis() {
        assert_eq!(stat_state(b"247 (fs worker) S 1 2"), Some(b'S'));
        assert_eq!(stat_state(b"247 (a) b) D 1 2"), Some(b'D'));
        assert_eq!(stat_state(b"247 (cut"), None);
        assert_eq!(stat_state(b"247 (cut)"), None);
        assert_eq!(stat_state(b""), None);
        assert_eq!(stat_state(b")"), None);
    }

    #[test]
    fn the_archived_copy_replaces_a_planted_symlink_without_following_it() {
        let dir = scratch("archive");
        let record = dir.join("record");
        let archive = dir.join("archive");
        std::fs::create_dir(&archive).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, archive.join(FILE_NAME)).unwrap();
        std::fs::write(&record, b"threads").unwrap();
        copy_into(&record, &archive).unwrap();
        let copied = archive.join(FILE_NAME);
        let meta = std::fs::symlink_metadata(&copied).unwrap();
        let (kind, mode) = (
            meta.file_type(),
            std::os::unix::fs::PermissionsExt::mode(&meta.permissions()),
        );
        let (copy, victim) = (
            std::fs::read(&copied).unwrap(),
            std::fs::read(&victim).unwrap(),
        );
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(kind.is_file());
        assert_eq!(copy, b"threads");
        assert_eq!(victim, b"untouched");
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_directory_planted_at_the_name_fails_the_copy_and_stays() {
        let dir = scratch("planted-dir");
        let record = dir.join("record");
        std::fs::write(&record, b"threads").unwrap();
        let archive = dir.join("archive");
        std::fs::create_dir_all(archive.join(FILE_NAME).join("inner")).unwrap();
        let copied = copy_into(&record, &archive);
        let kept = archive.join(FILE_NAME).join("inner").is_dir();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(copied.is_err());
        assert!(kept);
    }

    /// A job context under a scratch state dir, its job dir created.
    fn job(name: &str) -> (PathBuf, JobCtx) {
        let root = scratch(name);
        let cfg = crate::config::Config {
            state_dir: Some(root.clone()),
            ..Default::default()
        };
        let ctx = JobCtx::new_for_job(cfg, "job1".into()).unwrap();
        std::fs::create_dir_all(&ctx.job_dir).unwrap();
        (root, ctx)
    }

    #[test]
    fn a_job_without_an_archive_directory_records_nothing() {
        let (root, ctx) = job("unrecorded");
        record(&ctx, std::process::id());
        let recorded = ctx.vmm_threads_file().exists();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!recorded);
    }

    #[test]
    fn the_record_is_archived_only_once_the_supervisor_is_gone() {
        let (root, ctx) = job("archived");
        let dir = root.join("archive");
        std::fs::create_dir(&dir).unwrap();
        crate::atop::record_archive_dir(&ctx, &dir).unwrap();
        record(&ctx, std::process::id());
        // A stand-in supervisor: a live process whose command line names the job dir. Not a
        // lone `sleep`, which a shell may exec in its own place, dropping the argument.
        let mut supervisor = std::process::Command::new("sh")
            .args(["-c", "sleep 30; :", "sh"])
            .arg(&ctx.job_dir)
            .spawn()
            .unwrap();
        std::fs::write(
            JobCtx::supervisor_pidfile_in(&ctx.job_dir),
            supervisor.id().to_string(),
        )
        .unwrap();
        // /proc/<pid>/cmdline reads empty until the new image's argv is set up.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while crate::vm::live_supervisor_pid(&ctx).is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "the stand-in never came up"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        archive(&ctx);
        let while_alive = dir.join(FILE_NAME).exists();
        supervisor.kill().unwrap();
        supervisor.wait().unwrap();
        archive(&ctx);
        let archived = std::fs::read(dir.join(FILE_NAME)).unwrap_or_default();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(!while_alive);
        assert!(
            archived
                .starts_with(format!("# threads of VMM pid {} ", std::process::id()).as_bytes()),
            "{}",
            archived.escape_ascii()
        );
    }

    #[test]
    fn no_record_archives_nothing() {
        let dir = scratch("none");
        copy_into(&dir.join("record"), &dir).unwrap();
        let created = dir.join(FILE_NAME).exists();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!created);
    }
}
