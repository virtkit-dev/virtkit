//! Seccomp sandbox for the bundled virtio-fs daemon.
//!
//! The daemon services untrusted-guest FUSE requests against a real host directory,
//! so it confines itself to the syscalls that work needs. The allowlist is ported
//! from upstream virtiofsd 1.13 (its libseccomp filter), rebuilt on `seccompiler`
//! (pure Rust, BPF compiled in-process) so no C library is linked. Anything off the
//! list triggers the configured action (kill by default).

use std::collections::BTreeMap;
use std::str::FromStr;

use anyhow::{Context as _, Result, anyhow};
use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};

/// What a filtered (non-allowlisted) syscall does to the daemon.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Action {
    /// No filter installed at all.
    None,
    /// Kill the whole process (the production default, like upstream virtiofsd).
    Kill,
    /// Log the syscall and continue (debugging).
    Log,
    /// Deliver SIGSYS (debugging with a handler / core inspection).
    Trap,
}

impl FromStr for Action {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "none" => Ok(Action::None),
            "kill" => Ok(Action::Kill),
            "log" => Ok(Action::Log),
            "trap" => Ok(Action::Trap),
            other => Err(format!(
                "invalid seccomp action {other:?} (want none|kill|log|trap)"
            )),
        }
    }
}

/// The syscalls a virtio-fs passthrough daemon performs: upstream virtiofsd's
/// allowlist (x86_64 set), minus the entries for architectures we do not build.
const ALLOWLIST: &[libc::c_long] = &[
    libc::SYS_accept4,
    libc::SYS_brk,
    libc::SYS_capget, // for CAP_FSETID
    libc::SYS_capset,
    libc::SYS_clock_gettime,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_close,
    libc::SYS_copy_file_range,
    libc::SYS_dup,
    // legacy syscalls that only exist on x86_64 (aarch64 has only the *at/newer forms)
    #[cfg(target_arch = "x86_64")]
    libc::SYS_epoll_create,
    libc::SYS_epoll_create1,
    libc::SYS_epoll_ctl,
    libc::SYS_epoll_pwait,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_epoll_wait,
    libc::SYS_eventfd2,
    libc::SYS_exit,
    libc::SYS_exit_group,
    libc::SYS_fallocate,
    libc::SYS_fchdir,
    libc::SYS_fchmod,
    libc::SYS_fchmodat,
    libc::SYS_fchownat,
    libc::SYS_fcntl,
    libc::SYS_fdatasync,
    libc::SYS_fgetxattr,
    libc::SYS_flistxattr,
    libc::SYS_flock,
    libc::SYS_fremovexattr,
    libc::SYS_fsetxattr,
    libc::SYS_fstat,
    libc::SYS_fstatfs,
    libc::SYS_fsync,
    libc::SYS_ftruncate,
    libc::SYS_futex,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_getdents,
    libc::SYS_getdents64,
    libc::SYS_getegid,
    libc::SYS_geteuid,
    libc::SYS_getpid,
    libc::SYS_getrandom,
    libc::SYS_gettid,
    libc::SYS_gettimeofday,
    libc::SYS_getxattr,
    libc::SYS_linkat,
    libc::SYS_listxattr,
    libc::SYS_lseek,
    libc::SYS_madvise,
    libc::SYS_membarrier,
    libc::SYS_mkdirat,
    libc::SYS_mknodat,
    libc::SYS_mmap,
    libc::SYS_mprotect,
    libc::SYS_mremap,
    libc::SYS_munmap,
    libc::SYS_name_to_handle_at,
    libc::SYS_newfstatat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_open,
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_open_by_handle_at,
    libc::SYS_prctl,
    libc::SYS_pread64,
    libc::SYS_preadv,
    libc::SYS_preadv2,
    libc::SYS_pwrite64,
    libc::SYS_pwritev,
    libc::SYS_pwritev2,
    libc::SYS_read,
    libc::SYS_readlinkat,
    libc::SYS_readv,
    libc::SYS_recvmsg,
    libc::SYS_removexattr,
    libc::SYS_renameat,
    libc::SYS_renameat2,
    libc::SYS_rseq,
    libc::SYS_rt_sigaction,
    libc::SYS_rt_sigprocmask,
    libc::SYS_rt_sigreturn,
    libc::SYS_sched_getaffinity,
    libc::SYS_sched_yield,
    libc::SYS_sendmsg,
    libc::SYS_sendto,
    libc::SYS_setgroups,
    libc::SYS_setresgid,
    libc::SYS_setresuid,
    libc::SYS_set_robust_list,
    libc::SYS_setxattr,
    libc::SYS_sigaltstack,
    libc::SYS_statx,
    libc::SYS_symlinkat,
    libc::SYS_syncfs,
    libc::SYS_tgkill,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_time,
    libc::SYS_tkill,
    libc::SYS_umask,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_unlink,
    libc::SYS_unlinkat,
    libc::SYS_unshare,
    libc::SYS_utimensat,
    libc::SYS_write,
    libc::SYS_writev,
];

/// Install the allowlist filter on the calling thread and all threads it spawns
/// (seccomp filters are inherited across clone). Call before serving requests.
pub fn enable(action: Action) -> Result<()> {
    let mismatch = match action {
        Action::None => return Ok(()),
        Action::Kill => SeccompAction::KillProcess,
        Action::Log => SeccompAction::Log,
        Action::Trap => SeccompAction::Trap,
    };
    // no arg rules: each listed syscall is allowed unconditionally. The cast is a
    // no-op on 64-bit targets but keeps c_long portable.
    #[allow(clippy::unnecessary_cast)]
    let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = ALLOWLIST
        .iter()
        .map(|&nr| (nr as i64, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        mismatch,
        SeccompAction::Allow,
        std::env::consts::ARCH
            .try_into()
            .map_err(|e| anyhow!("unsupported seccomp arch: {e:?}"))?,
    )
    .map_err(|e| anyhow!("building the seccomp filter: {e}"))?;
    let prog: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| anyhow!("compiling the seccomp filter: {e}"))?;
    seccompiler::apply_filter_all_threads(&prog).context("applying the seccomp filter")
}
