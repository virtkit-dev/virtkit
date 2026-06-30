//! `virtkit-agent init` — PID 1 for guest images that ship no systemd. It brings
//! the rootfs and (optionally) the fleet LAN up, then either supervises a `serve`
//! agent you drive over vsock (the default — a managed VM), or `exec`s the image's
//! own entrypoint (`VIRTKIT_MODE=service`).
//!
//! Configuration comes from the kernel cmdline (the executor passes it; a guest
//! booted `init=/usr/local/bin/virtkit-agent` gets no usable argv) and from capture
//! files written at image-build time:
//!   /etc/virtkit/env    image ENV (KEY=VALUE per line; lost by `docker export`)
//!   /etc/virtkit/user   image USER: exported as VIRTKIT_DEFAULT_RUN_USER so served
//!                       stages drop to it (serve mode), and dropped to in service mode
//!   /etc/virtkit/cmd    Entrypoint+Cmd, one argv element per line (service mode)
//!
//! Cmdline params (all VIRTKIT_*):
//!   VIRTKIT_VSOCK_PORT   serve agent's vsock port (default 4444)
//!   VIRTKIT_HOSTNAME     hostname (+ a 127.0.1.1 self-entry in /etc/hosts)
//!   VIRTKIT_NET_PORT     bring eth0 up: a tap bridged to the host switch over this
//!                        vsock port; then DHCP (VIRTKIT_NET_DHCP=1) or a static
//!                        VIRTKIT_VM_IP / VIRTKIT_VM_GW / VIRTKIT_VM_DNS
//!   VIRTKIT_VIRTIOFS     tag:path[,tag:path] virtiofs shares to mount
//!   VIRTKIT_SYMLINKS     src:dest[,src:dest] — after virtiofs mounts, create each
//!                        `dest` as a symlink pointing to `src`. Entries where `src`
//!                        does not exist are silently skipped.
//!   VIRTKIT_TOOLS        tag:mountpoint — mount this virtio-fs share (read-only)
//!                        and link the CI tools it carries (git/git-lfs/…) onto
//!                        the PATH, skipping any the image already provides
//!   VIRTKIT_TMPFS        /path:size[,/path:size] RAM scratch dirs (e.g. CI /builds)
//!   VIRTKIT_SSH=1        also run ssh-serve (vsock 2222); keys VIRTKIT_SSH_KEYS
//!                        (comma-separated `type:base64` entries, no spaces),
//!                        user VIRTKIT_SSH_USER (default dev)
//!   VIRTKIT_SSH_AGENT_PORT  forward the host SSH agent: run a guest-side forwarder that
//!                        presents SSH_AUTH_SOCK and relays it over this vsock port to the
//!                        host (which splices to the host's real agent). Only agent
//!                        protocol bytes cross — private keys never enter the guest.
//!   VIRTKIT_MODE=service fork the captured entrypoint; the agent stays as PID 1 and
//!                        reaps orphans. A systemd image hands off via its entrypoint.
//!   VIRTKIT_SERVE=1      (service) also start the vsock exec server (port 4444) for
//!                        live debugging: `virtkit-agent -s vsock-mux://<vsock.sock>:4444 exec`
//!   VIRTKIT_DEBUG=1      (service) fork+wait the entrypoint, then hold the VM on exit
//!                        for post-mortem inspection (overrides VIRTKIT_SERVE)
//!
//! The whole module is sync: no tokio in PID 1.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::{info, warn};

use crate::addr::SocketAddr;

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SSH_VSOCK_PORT: u32 = 2222;
/// Guest-side SSH_AUTH_SOCK the forwarder binds (on the /run tmpfs, never in the image).
const SSH_AGENT_SOCK: &str = "/run/virtkit-ssh-agent.sock";

/// Entry point for `… init`. Sets the guest up, then serves (default) or execs the
/// image entrypoint (VIRTKIT_MODE=service).
pub fn run_init(socket: &SocketAddr, inactivity_timeout: Option<u64>) -> Result<()> {
    info!("virtkit-agent init: PID {} ({socket})", std::process::id());
    // SAFETY: single-threaded here (no tokio, no serve fork yet).
    unsafe { std::env::set_var("PATH", DEFAULT_PATH) };

    // If booted from the agent-only initramfs (`VIRTKIT_PIVOT=<root dev>`), mount the
    // real image ext4 and switch into it — keeping this process as PID 1 — so the agent
    // never lives inside the image. A no-op on the legacy in-rootfs `init=` boot.
    let pivoted = pivot_to_real_root().unwrap_or_else(|e| {
        warn!("virtkit-agent init: pivot to real root failed: {e:#} — continuing in place");
        false
    });

    mount_api_filesystems();
    apply_sysctls(); // honor /etc/sysctl.d/*.conf — there is no systemd-sysctl here
    let cmdline = read_cmdline();
    bring_up_loopback();
    set_hostname(&cmdline);
    write_self_hosts(&cmdline);
    load_image_env(); // so served/exec'd commands inherit the image PATH etc.
    export_default_run_user(); // so served stages drop to the image's USER
    // /usr/local/bin/virtctl -> the agent (fleet control client). Skipped when pivoted
    // into a built image (dfbuild): the agent isn't in the rootfs, so the symlink would
    // dangle and pollute the artifact.
    if !pivoted {
        ensure_virtctl_symlink();
    }
    mount_virtiofs(&cmdline);
    apply_symlinks(&cmdline);
    link_ci_tools(&cmdline); // host CI tools (git/git-lfs/…) onto PATH, if the image lacks them
    configure_network(&cmdline);
    write_resolv_conf(&cmdline); // DNS for every net mode (kernel `ip=` pool + static bridge)
    apply_tmpfs(&cmdline); // RAM scratch dirs (e.g. CI /builds) before the payload starts
    // orphans reparent to PID 1 (this process): reap them.
    set_child_subreaper();

    // VIRTKIT_MODE=service: fork the image's captured entrypoint and supervise it as
    // PID 1 (reaps orphans). A systemd image uses this too — its entrypoint execs
    // /sbin/init, handing off to systemd which then takes over process supervision.
    if cmdline.get("VIRTKIT_MODE").map(String::as_str) == Some("service") {
        return run_service(&cmdline);
    }

    maybe_ssh_serve(&cmdline);
    maybe_ssh_agent(&cmdline);
    let serve = spawn_serve(socket, inactivity_timeout)?;
    install_term_handler();
    supervise(serve)
}

/// When booted from the agent-only initramfs, mount the real root (an ext4 named by
/// `VIRTKIT_PIVOT` on the kernel cmdline, e.g. `/dev/vda`) and switch into it while
/// staying PID 1. Returns `Ok(false)` (a no-op) on the legacy boot where the agent was
/// `init=`'d from inside the rootfs and `VIRTKIT_PIVOT` is absent.
///
/// This is the initramfs→real-root `switch_root` dance: the new root is mounted, moved
/// onto `/`, and `chroot`'d into. The initramfs (carrying our `/init`) is left hidden
/// underneath; this process keeps running and its binary stays reachable via
/// `/proc/self/exe` even though the path is gone — which is how the host re-invokes the
/// agent's `copy`/`mount`/`fsfreeze` subcommands without it being present in the image.
fn pivot_to_real_root() -> Result<bool> {
    // /proc to read the cmdline, /dev for the root block-device node.
    let _ = std::fs::create_dir_all("/proc");
    let _ = mount("proc", "/proc", "proc", 0);
    let cmdline = read_cmdline();
    let Some(dev) = cmdline.get("VIRTKIT_PIVOT").cloned() else {
        return Ok(false);
    };
    let _ = std::fs::create_dir_all("/dev");
    let _ = mount("devtmpfs", "/dev", "devtmpfs", 0);
    std::fs::create_dir_all("/newroot")?;
    mount(&dev, "/newroot", "ext4", 0).with_context(|| format!("mounting real root {dev}"))?;
    std::env::set_current_dir("/newroot").context("chdir /newroot")?;
    mount(".", "/", "", libc::MS_MOVE).context("mount --move /newroot /")?;
    let rc = unsafe { libc::chroot(c".".as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("chroot into the new root");
    }
    std::env::set_current_dir("/").context("chdir / after chroot")?;
    info!("virtkit-agent init: pivoted into real root {dev}");
    Ok(true)
}

/// Mount the kernel API filesystems a from-scratch rootfs lacks. Best effort:
/// each may already be mounted (the initrd/kernel set some up) — tolerate it.
fn mount_api_filesystems() {
    // Mountpoint dirs we create here (that the base lacked, e.g. a FROM scratch image) are
    // recorded so `cleanup` can drop them before commit — otherwise an empty /proc, /sys,
    // /dev, /run, /tmp would litter the built image. Recorded after /run is mounted (the
    // registry lives on it). Pre-existing dirs (a normal debian/alpine base ships them) are
    // left untouched and kept.
    let mut created: Vec<&str> = Vec::new();
    // (source, target, fstype, flags)
    let mounts: &[(&str, &str, &str, libc::c_ulong)] = &[
        ("proc", "/proc", "proc", 0),
        ("sysfs", "/sys", "sysfs", 0),
        ("devtmpfs", "/dev", "devtmpfs", 0),
        ("devpts", "/dev/pts", "devpts", 0),
    ];
    for (src, target, fstype, flags) in mounts {
        if !std::path::Path::new(target).exists() {
            created.push(target);
        }
        let _ = std::fs::create_dir_all(target);
        if let Err(e) = mount(src, target, fstype, *flags)
            && e.raw_os_error() != Some(libc::EBUSY)
        // EBUSY = already mounted (the common case for /proc /sys /dev)
        {
            warn!("virtkit-agent init: mount {fstype} on {target} failed: {e}");
        }
    }
    // The standard /dev file-descriptor symlinks. devtmpfs does not create these (a
    // container runtime/udev normally would), but shells rely on them: bash process
    // substitution `<(…)` opens /dev/fd/<n>, and scripts read /dev/stdin et al.
    for (link, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ] {
        if !std::path::Path::new(link).exists()
            && let Err(e) = std::os::unix::fs::symlink(target, link)
        {
            warn!("virtkit-agent init: symlink {link} -> {target} failed: {e}");
        }
    }
    // /run and /tmp as fresh tmpfs, but recreate the image's baked top-level dirs so
    // a service's runtime dir survives — e.g. /run/redis (owned by redis) that redis
    // binds its unix socket into. systemd-tmpfiles would recreate these; we have no
    // systemd, and a bare tmpfs mount would hide them.
    for target in ["/run", "/tmp"] {
        if !std::path::Path::new(target).exists() {
            created.push(target);
        }
        let _ = std::fs::create_dir_all(target);
        if let Err(e) = mount_tmpfs_keep_dirs(target, libc::MS_NOSUID | libc::MS_NODEV)
            && e.raw_os_error() != Some(libc::EBUSY)
        {
            warn!("virtkit-agent init: tmpfs on {target} failed: {e}");
        }
    }
    // Now that /run (the registry's tmpfs) is mounted, record the mountpoints we created
    // so the pre-commit cleanup can remove them from a FROM scratch image.
    for target in created {
        crate::diskmount::note_created(std::path::Path::new(target));
    }
}

/// Mount a fresh tmpfs on `target`, first snapshotting its underlying top-level
/// directories (name, mode, uid, gid) and recreating them on the new tmpfs — so a
/// service's baked runtime dir (e.g. /run/redis owned by redis) isn't hidden.
fn mount_tmpfs_keep_dirs(target: &str, flags: libc::c_ulong) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut dirs: Vec<(std::ffi::OsString, u32, u32, u32)> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(target) {
        for e in rd.flatten() {
            if let Ok(md) = e.metadata()
                && md.is_dir()
            {
                dirs.push((e.file_name(), md.mode(), md.uid(), md.gid()));
            }
        }
    }
    mount("tmpfs", target, "tmpfs", flags)?;
    for (name, mode, uid, gid) in dirs {
        let path = std::path::Path::new(target).join(&name);
        if std::fs::create_dir(&path).is_ok() {
            let _ = std::fs::set_permissions(&path, PermissionsExt::from_mode(mode & 0o7777));
            if let Some(p) = path.to_str() {
                unsafe { libc::chown(cstr(p).as_ptr(), uid, gid) };
            }
        }
    }
    Ok(())
}

/// `mount(2)` wrapper (source/target/fstype, no data).
fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong) -> io::Result<()> {
    let (c_src, c_tgt, c_fs) = (cstr(src), cstr(target), cstr(fstype));
    let rc = unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_tgt.as_ptr(),
            c_fs.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// `mount(2)` with a filesystem-specific data string (e.g. tmpfs "size=64G,mode=0755").
fn mount_data(
    src: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
) -> io::Result<()> {
    let (c_src, c_tgt, c_fs, c_data) = (cstr(src), cstr(target), cstr(fstype), cstr(data));
    let rc = unsafe {
        libc::mount(
            c_src.as_ptr(),
            c_tgt.as_ptr(),
            c_fs.as_ptr(),
            flags,
            c_data.as_ptr().cast(),
        )
    };
    if rc != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Mount the RAM scratch dirs named on the cmdline (VIRTKIT_TMPFS=/path:size[,/path:size],
/// e.g. /builds:64G). For job scratch (CI clones into /builds): guest memory is allocated
/// on demand and returned to the host when the VM is torn down, so an over-sized cap is
/// free. Each dir is chowned to the captured run-user (the image USER) so a job stage
/// running as that user can write into it. Runs before the payload (service/systemd) so
/// the mounts are already in place.
fn apply_tmpfs(cmdline: &HashMap<String, String>) {
    let Some(spec) = cmdline.get("VIRTKIT_TMPFS") else {
        return;
    };
    let user = std::fs::read_to_string("/etc/virtkit/user")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    for entry in spec.split(',').filter(|e| !e.is_empty()) {
        let Some((path, size)) = parse_tmpfs_entry(entry) else {
            warn!("virtkit-agent init: bad VIRTKIT_TMPFS entry {entry:?} (want /path:size)");
            continue;
        };
        let _ = std::fs::create_dir_all(path);
        let data = format!("size={size},mode=0755");
        let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOATIME;
        if let Err(e) = mount_data("tmpfs", path, "tmpfs", flags, &data) {
            warn!("virtkit-agent init: tmpfs {path} (size={size}) failed: {e}");
            continue;
        }
        if !user.is_empty() && user != "root" {
            let owner = format!("{user}:{user}");
            let _ = run_cmd("chown", &[owner.as_str(), path]);
        }
        info!("virtkit-agent init: tmpfs {path} (size={size})");
    }
}

/// Validate one VIRTKIT_TMPFS entry "/path:size" → (path, size); None if malformed
/// (no ':', empty field, or a non-absolute path).
fn parse_tmpfs_entry(entry: &str) -> Option<(&str, &str)> {
    let (path, size) = entry.split_once(':')?;
    if path.is_empty() || size.is_empty() || !path.starts_with('/') {
        return None;
    }
    Some((path, size))
}

/// Apply sysctl settings from the standard config files (the systemd-sysctl job a
/// generic-boot guest has no systemd to run), so the rootfs's /etc/sysctl.d/*.conf
/// still takes effect in the VM — e.g. kernel.perf_event_paranoid for in-VM perf,
/// or a service's vm.overcommit_memory. Best effort: a key the guest kernel lacks or
/// won't accept is warned and skipped. Requires /proc mounted (call after the API
/// mounts). The guest has its own kernel, so these touch only the VM.
fn apply_sysctls() {
    // Lowest precedence first so a later (higher-precedence) write wins; an exact
    // systemd cross-directory same-name shadow is not reproduced (not needed here).
    let mut files: Vec<std::path::PathBuf> = Vec::new();
    for dir in ["/usr/lib/sysctl.d", "/etc/sysctl.d", "/run/sysctl.d"] {
        if let Ok(rd) = std::fs::read_dir(dir) {
            let mut confs: Vec<_> = rd
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "conf"))
                .collect();
            confs.sort();
            files.append(&mut confs);
        }
    }
    files.push(std::path::PathBuf::from("/etc/sysctl.conf"));

    for f in &files {
        let Ok(text) = std::fs::read_to_string(f) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let (path, value) = (sysctl_path(key), value.trim());
            if let Err(e) = std::fs::write(&path, value) {
                warn!(
                    "virtkit-agent init: sysctl {}={value} failed: {e}",
                    key.trim()
                );
            }
        }
    }
}

/// Map a sysctl key to its /proc/sys path: '.' separators become '/', a leading '-'
/// (the "ignore errors" marker) is stripped, and a key already written with '/' is
/// taken as-is.
fn sysctl_path(key: &str) -> String {
    let key = key.trim().trim_start_matches('-').trim();
    let rel = if key.contains('/') {
        key.to_string()
    } else {
        key.replace('.', "/")
    };
    format!("/proc/sys/{rel}")
}

/// Parse /proc/cmdline into KEY=VALUE pairs (bare flags are ignored).
fn read_cmdline() -> HashMap<String, String> {
    let raw = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    raw.split_whitespace()
        .filter_map(|tok| tok.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Derive the serve agent's vsock listen socket from the kernel cmdline
/// (`VIRTKIT_VSOCK_PORT`, default 4444). A guest booted `init=…` gets no usable
/// argv, so the executor passes the port on the cmdline instead.
pub fn socket_from_cmdline() -> SocketAddr {
    const DEFAULT_VSOCK_PORT: u32 = 4444;
    let port = read_cmdline()
        .get("VIRTKIT_VSOCK_PORT")
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_VSOCK_PORT);
    SocketAddr::Vsock { cid: None, port }
}

/// Bring loopback up (the VS Code server and many tools bind 127.0.0.1, and glibc's
/// resolver needs it for source-address selection). Via ioctl so it works on guests
/// without iproute2/net-tools (minimal glibc images). Best effort.
fn bring_up_loopback() {
    if let Err(e) = crate::netcfg::set_up("lo") {
        warn!("virtkit-agent init: could not bring up loopback: {e:#}");
    }
}

fn set_hostname(cmdline: &HashMap<String, String>) {
    let Some(name) = cmdline.get("VIRTKIT_HOSTNAME") else {
        return;
    };
    let rc = unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) };
    if rc != 0 {
        warn!(
            "virtkit-agent init: sethostname({name}) failed: {}",
            io::Error::last_os_error()
        );
    }
}

/// Make this VM's own name resolvable offline (sudo etc. look it up before/without
/// the network), via the standard 127.0.1.1 entry. Only the bare name — a *.lan name
/// stays a DNS answer (its real LAN IP), never shadowed by a loopback entry.
fn write_self_hosts(cmdline: &HashMap<String, String>) {
    let mut hosts = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
    if !hosts
        .lines()
        .any(|l| l.split_whitespace().next() == Some("127.0.0.1"))
    {
        hosts.push_str("127.0.0.1\tlocalhost\n");
    }
    if let Some(host) = cmdline.get("VIRTKIT_HOSTNAME")
        && !hosts
            .lines()
            .any(|l| l.split_whitespace().any(|w| w == host))
    {
        hosts.push_str(&format!("127.0.1.1\t{host}\n"));
    }
    if let Err(e) = std::fs::write("/etc/hosts", hosts) {
        warn!("virtkit-agent init: writing /etc/hosts failed: {e}");
    }
}

/// Expose the agent under the `virtctl` name (the fleet control client): a symlink
/// next to it, so `virtctl start mysql` works from the VM's PATH. Best effort;
/// the rootfs is writable (CoW), and it's recreated each boot if missing.
fn ensure_virtctl_symlink() {
    let link = "/usr/local/bin/virtctl";
    if !std::path::Path::new(link).exists() {
        let _ = std::os::unix::fs::symlink("virtkit-agent", link);
    }
}

/// Load the image's ENV from /etc/virtkit/env (one KEY=VALUE per line) into our own
/// environment, so the serve agent and any exec'd command inherit it (PATH, etc.).
fn load_image_env() {
    let Ok(text) = std::fs::read_to_string("/etc/virtkit/env") else {
        return;
    };
    for line in text.lines() {
        if let Some((k, v)) = line.split_once('=') {
            // SAFETY: still single-threaded (before any fork).
            unsafe { std::env::set_var(k, v) };
        }
    }
}

/// Export the image's USER (captured into /etc/virtkit/user) as
/// VIRTKIT_DEFAULT_RUN_USER, so the serve agent's exec server drops each stage to it
/// — a generic guest then runs like `docker run` would. Empty/root is left unset (the
/// agent already runs as root). The serve child inherits this env across the fork.
fn export_default_run_user() {
    let user = std::fs::read_to_string("/etc/virtkit/user")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    if !user.is_empty() && user != "root" {
        // SAFETY: still single-threaded init, before any serve/service fork.
        unsafe { std::env::set_var("VIRTKIT_DEFAULT_RUN_USER", &user) };
        info!("virtkit-agent init: VIRTKIT_DEFAULT_RUN_USER={user}");
    }
}

/// Mount the virtiofs shares named on the cmdline (VIRTKIT_VIRTIOFS=tag:path,...).
fn mount_virtiofs(cmdline: &HashMap<String, String>) {
    let Some(spec) = cmdline.get("VIRTKIT_VIRTIOFS") else {
        return;
    };
    let _ = run_cmd("modprobe", &["virtiofs"]); // built-in on our kernel; harmless
    for entry in spec.split(',').filter(|e| !e.is_empty()) {
        let Some((tag, path)) = entry.split_once(':') else {
            warn!("virtkit-agent init: bad VIRTKIT_VIRTIOFS entry {entry:?} (want tag:path)");
            continue;
        };
        let _ = std::fs::create_dir_all(path);
        if let Err(e) = mount(tag, path, "virtiofs", 0) {
            warn!("virtkit-agent init: mount virtiofs {tag} at {path} failed: {e}");
        }
    }
}

/// Create symlinks declared in VIRTKIT_SYMLINKS=src:dest[,src:dest,...].
/// Called after virtiofs mounts so the sources are accessible. Entries whose
/// source path does not exist are silently skipped (e.g. optional host files).
fn apply_symlinks(cmdline: &HashMap<String, String>) {
    let Some(spec) = cmdline.get("VIRTKIT_SYMLINKS") else {
        return;
    };
    for entry in spec.split(',').filter(|e| !e.is_empty()) {
        let Some((src, dest)) = entry.split_once(':') else {
            warn!("virtkit-agent init: bad VIRTKIT_SYMLINKS entry {entry:?} (want src:dest)");
            continue;
        };
        if !Path::new(src).exists() {
            continue;
        }
        if let Some(parent) = Path::new(dest).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(dest);
        if let Err(e) = std::os::unix::fs::symlink(src, dest) {
            warn!("virtkit-agent init: symlink {src} -> {dest}: {e}");
        }
    }
}

/// Mount the host CI-tools virtio-fs share (VIRTKIT_TOOLS=tag:mountpoint, set by the
/// GitLab executor) read-only, then link each tool it carries onto the guest PATH
/// (/usr/local/bin) — but only when the job image does not already provide that
/// command (per-image opt-out, checked here in-guest where PATH is accurate). The
/// host keeps the binaries; nothing is copied into the guest or baked into a bundle.
fn link_ci_tools(cmdline: &HashMap<String, String>) {
    let Some(spec) = cmdline.get("VIRTKIT_TOOLS") else {
        return;
    };
    let Some((tag, mnt)) = spec.split_once(':') else {
        warn!("virtkit-agent init: bad VIRTKIT_TOOLS {spec:?} (want tag:mountpoint)");
        return;
    };
    let _ = run_cmd("modprobe", &["virtiofs"]); // built-in on our kernel; harmless
    let _ = std::fs::create_dir_all(mnt);
    if let Err(e) = mount(tag, mnt, "virtiofs", 0) {
        warn!("virtkit-agent init: mount CI tools {tag} at {mnt} failed: {e}");
        return;
    }
    let Ok(entries) = std::fs::read_dir(mnt) else {
        return;
    };
    let _ = std::fs::create_dir_all("/usr/local/bin");
    // `git` ships with its `git-remote-http(s)` helpers (https is not a builtin); the
    // family is all-or-nothing, governed by whether the image already has git, so we
    // never mix our helpers with the image's git. Captured before we link anything.
    let image_has_git = which("git");
    let mut linked_git = false;
    for entry in entries.flatten() {
        let src = entry.path();
        let Some(name) = src.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !src.is_file() {
            continue; // is_file follows the symlink (git-remote-https -> git-remote-http)
        }
        // per-image opt-out: leave a tool to the image when it already provides it
        let skip = if name == "git" || name.starts_with("git-remote") {
            image_has_git
        } else {
            which(name)
        };
        if skip {
            continue;
        }
        let link = format!("/usr/local/bin/{name}");
        let _ = std::fs::remove_file(&link);
        match std::os::unix::fs::symlink(&src, &link) {
            Ok(()) => {
                info!("virtkit-agent init: CI tool {name} -> {link}");
                if name == "git" {
                    linked_git = true;
                }
            }
            Err(e) => warn!("virtkit-agent init: link {} -> {link}: {e}", src.display()),
        }
    }
    // The injected static git's compiled-in CA bundle is Alpine's /etc/ssl/cert.pem,
    // absent in most job images. Point it at the image's own CA store so https clones
    // work; only when we linked our git and the job has not set its own.
    if linked_git && std::env::var_os("GIT_SSL_CAINFO").is_none() {
        const CA_CANDIDATES: &[&str] = &[
            "/etc/ssl/certs/ca-certificates.crt", // debian/ubuntu/alpine
            "/etc/pki/tls/certs/ca-bundle.crt",   // rhel/fedora
            "/etc/ssl/ca-bundle.pem",             // suse
            "/etc/ssl/cert.pem",                  // alpine/busybox default
        ];
        if let Some(ca) = CA_CANDIDATES.iter().find(|p| Path::new(p).exists()) {
            // SAFETY: still single-threaded init, before any serve/service fork.
            unsafe { std::env::set_var("GIT_SSL_CAINFO", ca) };
            info!("virtkit-agent init: GIT_SSL_CAINFO={ca}");
        }
    }
}

/// Bring eth0 up on the shared fleet LAN: fork the tap bridge (`net`) to the host
/// switch over VIRTKIT_NET_PORT, then DHCP or a static address.
fn configure_network(cmdline: &HashMap<String, String>) {
    let Some(port) = cmdline.get("VIRTKIT_NET_PORT") else {
        return;
    };
    // The bridge is long-running (reaped by supervise; inherited by the service on
    // exec). It carries ethernet frames over vsock with no host privileges.
    if let Err(e) = fork_agent(&[
        "--socket".into(),
        format!("vsock://{port}"),
        "net".into(),
        "--iface".into(),
        "eth0".into(),
    ]) {
        warn!("virtkit-agent init: net bridge failed to start: {e}");
        return;
    }
    if !wait_for_iface("eth0", 50) {
        warn!("virtkit-agent init: eth0 did not come up");
        return;
    }
    if cmdline.get("VIRTKIT_NET_DHCP").map(String::as_str) == Some("1") {
        // -1: one attempt; the gateway's DHCP also hands out the resolver.
        if !run_cmd("timeout", &["20", "dhclient", "-1", "eth0"]) {
            warn!("virtkit-agent init: dhclient failed");
        }
    } else if let Some(ip) = cmdline.get("VIRTKIT_VM_IP") {
        let gw = cmdline
            .get("VIRTKIT_VM_GW")
            .map_or("192.168.127.1", String::as_str);
        // ioctls, not `ip`: minimal glibc images (debian:*-slim) ship no iproute2, so
        // shelling out left them with no address/route and a broken resolver.
        if let Err(e) = set_static_network(ip, gw) {
            warn!("virtkit-agent init: configuring eth0 {ip} via {gw} failed: {e:#}");
        }
    }
    // DNS is written separately (write_resolv_conf) so it applies to the kernel `ip=`
    // pool net too, not just this vsock-bridge static path.
}

/// Apply a static `VIRTKIT_VM_IP` (`a.b.c.d/prefix`) + `VIRTKIT_VM_GW` to eth0 via
/// ioctls (address, netmask, default route).
fn set_static_network(ip_cidr: &str, gw: &str) -> Result<()> {
    let (ip_str, prefix) = match ip_cidr.split_once('/') {
        Some((ip, p)) => (ip, p.parse::<u32>().context("parsing the IP prefix")?),
        None => (ip_cidr, 24),
    };
    let ip: std::net::Ipv4Addr = ip_str.parse().context("parsing VIRTKIT_VM_IP")?;
    let gw: std::net::Ipv4Addr = gw.parse().context("parsing VIRTKIT_VM_GW")?;
    crate::netcfg::set_addr("eth0", ip, prefix)?;
    crate::netcfg::add_default_route(gw)?;
    Ok(())
}

/// Write /etc/resolv.conf from VIRTKIT_VM_DNS (comma-separated nameservers), set by
/// the executor for both the kernel `ip=` pool net and the static vsock bridge — the
/// kernel `ip=` autoconf brings the interface up but carries no resolver, and a
/// generic guest has no initramfs/userland to write one. DHCP guests get their
/// resolver from dhclient (no VIRTKIT_VM_DNS), so this is a no-op there.
fn write_resolv_conf(cmdline: &HashMap<String, String>) {
    let Some(dns) = cmdline.get("VIRTKIT_VM_DNS") else {
        return;
    };
    let conf = resolv_conf(dns);
    if conf.is_empty() {
        return;
    }
    match std::fs::write("/etc/resolv.conf", &conf) {
        Ok(()) => info!("virtkit-agent init: resolv.conf nameservers {dns}"),
        Err(e) => warn!("virtkit-agent init: writing /etc/resolv.conf failed: {e}"),
    }
}

/// Render a resolv.conf body from a `VIRTKIT_VM_DNS` value: one `nameserver` line
/// per comma-separated entry (the cmdline allows `1.1.1.1,8.8.8.8`). Empty in, empty out.
fn resolv_conf(dns: &str) -> String {
    dns.split(',')
        .filter(|s| !s.is_empty())
        .map(|ns| format!("nameserver {ns}\n"))
        .collect()
}

/// Wait up to `tries` × 100 ms for a network interface to appear.
fn wait_for_iface(name: &str, tries: u32) -> bool {
    let path = format!("/sys/class/net/{name}");
    for _ in 0..tries {
        if Path::new(&path).exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Optionally run the embedded SSH server (VS Code Remote-SSH) on vsock 2222.
fn maybe_ssh_serve(cmdline: &HashMap<String, String>) {
    if cmdline.get("VIRTKIT_SSH").map(String::as_str) != Some("1") {
        return;
    }
    // VIRTKIT_SSH_KEYS: comma-separated public keys encoded as `type:base64`
    // (spaces stripped so they fit on the kernel cmdline).
    let keys_raw = cmdline
        .get("VIRTKIT_SSH_KEYS")
        .map(String::as_str)
        .unwrap_or("");
    let keys: Vec<String> = keys_raw
        .split(',')
        .filter(|s| !s.is_empty())
        .filter_map(|entry| match entry.split_once(':') {
            Some((t, b)) => Some(format!("{t} {b}")),
            None => {
                warn!("virtkit-agent init: skipping malformed VIRTKIT_SSH_KEYS entry (no `:`)");
                None
            }
        })
        .collect();
    if keys.is_empty() {
        warn!("virtkit-agent init: VIRTKIT_SSH_KEYS empty — ssh server disabled");
        return;
    }
    let user = cmdline
        .get("VIRTKIT_SSH_USER")
        .cloned()
        .unwrap_or_else(|| "dev".into());
    let mut args = vec![
        "--socket".into(),
        format!("vsock://{SSH_VSOCK_PORT}"),
        "ssh-serve".into(),
    ];
    for key in &keys {
        args.push("--authorized-key".into());
        args.push(key.clone());
    }
    args.push("--user".into());
    args.push(user);
    if let Err(e) = fork_agent(&args) {
        warn!("virtkit-agent init: ssh server failed to start: {e}");
    }
}

/// Argv for the guest-side SSH-agent forwarder: listen on the guest SSH_AUTH_SOCK and
/// relay to the host over `port` (the host splices it to its real `$SSH_AUTH_SOCK`).
fn ssh_agent_forward_args(port: &str) -> Vec<String> {
    vec![
        "--socket".into(),
        format!("vsock://{port}"),
        "forward".into(),
        "--listen".into(),
        SSH_AGENT_SOCK.into(),
    ]
}

/// Optionally forward the host's SSH agent (`VIRTKIT_SSH_AGENT_PORT`): start the guest-side
/// forwarder presenting a unix socket, then point `SSH_AUTH_SOCK` at it so served/exec'd
/// commands (ssh, git) find it. Only agent protocol bytes cross the vsock — keys stay host-side.
fn maybe_ssh_agent(cmdline: &HashMap<String, String>) {
    let Some(port) = cmdline.get("VIRTKIT_SSH_AGENT_PORT") else {
        return;
    };
    match fork_agent(&ssh_agent_forward_args(port)) {
        // Set it before spawn_serve so the served stages inherit it (single-threaded here).
        // SAFETY: PID 1, no other threads yet (serve/net not forked).
        Ok(_) => unsafe { std::env::set_var("SSH_AUTH_SOCK", SSH_AGENT_SOCK) },
        Err(e) => warn!("virtkit-agent init: ssh-agent forward failed to start: {e}"),
    }
}

/// `VIRTKIT_MODE=service`: run the image's captured entrypoint as its user. Normally
/// `exec` (the service becomes PID 1, like the container); under VIRTKIT_DEBUG it is
/// run then held so a crash doesn't panic PID 1 and the console keeps the error.
fn run_service(cmdline: &HashMap<String, String>) -> Result<()> {
    let mut argv = read_argv_file("/etc/virtkit/cmd");
    if argv.is_empty() {
        // No captured entrypoint: a self-booting image (systemd) has its init at
        // /sbin/init — hand off to it; otherwise drop to a shell.
        if Path::new("/sbin/init").exists() {
            warn!("virtkit-agent init: no captured command — forking /sbin/init");
            argv = vec!["/sbin/init".into()];
        } else {
            warn!("virtkit-agent init: no captured command (/etc/virtkit/cmd) — forking /bin/sh");
            argv = vec!["/bin/sh".into()];
        }
    }
    let user = std::fs::read_to_string("/etc/virtkit/user")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let argv = wrap_user(argv, &user);
    info!(
        "virtkit-agent init: service as {}: {:?}",
        if user.is_empty() { "root" } else { &user },
        argv
    );

    // VIRTKIT_DEBUG=1: fork+wait, then hold for post-mortem inspection.
    if cmdline.get("VIRTKIT_DEBUG").map(String::as_str) == Some("1") {
        match fork_exec_wait(&argv) {
            Ok(code) => {
                warn!("virtkit-agent init: service exited rc={code} — holding (VIRTKIT_DEBUG)")
            }
            Err(e) => warn!("virtkit-agent init: service failed: {e} — holding (VIRTKIT_DEBUG)"),
        }
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // Fork the service as a child — the agent (PID 1) stays to reap orphans.
    let service_pid = fork_exec(&argv)?;
    info!("virtkit-agent init: service pid {service_pid}");

    // VIRTKIT_SERVE=1: optionally start the vsock exec server for live debugging.
    // Connect with: virtkit-agent -s vsock-mux://<vsock.sock>:4444 exec -- <cmd>
    let serve_pid = if cmdline.get("VIRTKIT_SERVE").map(String::as_str) == Some("1") {
        let socket = socket_from_cmdline();
        match spawn_serve(&socket, None) {
            Ok(pid) => {
                info!("virtkit-agent init: exec server up on {socket} (pid {pid})");
                Some(pid)
            }
            Err(e) => {
                warn!("virtkit-agent init: exec server failed to start: {e}");
                None
            }
        }
    } else {
        None
    };

    install_term_handler();
    supervise_service(service_pid, serve_pid)
}

/// Reap orphaned processes as PID 1; power off when the service child exits.
/// If the optional exec server exits, log it and continue (service is the primary).
fn supervise_service(service_pid: libc::pid_t, serve_pid: Option<libc::pid_t>) -> Result<()> {
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                _ => break, // ECHILD: nothing left to wait on
            }
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -libc::WTERMSIG(status)
        };
        if pid == service_pid {
            info!("virtkit-agent init: service exited (code {code}); powering off");
            break;
        }
        if Some(pid) == serve_pid {
            info!("virtkit-agent init: exec server exited (code {code})");
            continue; // service is still running; keep supervising
        }
        // an orphan was reaped — keep supervising
    }
    poweroff();
}

/// Wrap argv to drop to `user` via setpriv (when non-root and setpriv is present).
fn wrap_user(argv: Vec<String>, user: &str) -> Vec<String> {
    if !user.is_empty() && user != "root" && which("setpriv") {
        let mut v: Vec<String> = [
            "setpriv",
            "--reuid",
            user,
            "--regid",
            user,
            "--init-groups",
            "--",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        v.extend(argv);
        v
    } else {
        argv
    }
}

/// execvp(argv) — replaces this process (PATH-searched). Never returns on success.
fn exec_argv(argv: &[String]) -> ! {
    let c_argv: Vec<CString> = argv.iter().map(|a| cstr(a)).collect();
    let mut ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe { libc::execvp(c_argv[0].as_ptr(), ptrs.as_ptr()) };
    eprintln!(
        "virtkit-agent init: exec {:?} failed: {}",
        argv.first(),
        io::Error::last_os_error()
    );
    unsafe { libc::_exit(127) };
}

fn set_child_subreaper() {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
        warn!(
            "virtkit-agent init: PR_SET_CHILD_SUBREAPER failed: {}",
            io::Error::last_os_error()
        );
    }
}

/// fork() + exec the serve agent (`… --socket <socket> serve [--inactivity-timeout]`).
fn spawn_serve(socket: &SocketAddr, inactivity_timeout: Option<u64>) -> Result<libc::pid_t> {
    let mut args = vec![
        "--socket".to_string(),
        socket.to_string(),
        "serve".to_string(),
    ];
    if let Some(t) = inactivity_timeout {
        args.push("--inactivity-timeout".to_string());
        args.push(t.to_string());
    }
    let pid = fork_agent(&args)?;
    info!("virtkit-agent init: serve started (pid {pid})");
    Ok(pid)
}

/// fork() and exec this agent binary (/proc/self/exe) with `args`; return the child
/// pid in the parent. For the long-running children init supervises (serve/net/ssh).
fn fork_agent(args: &[String]) -> Result<libc::pid_t> {
    // Exec the magic `/proc/self/exe` path directly rather than its readlink target:
    // after an initramfs pivot the agent's on-disk path (the initramfs `/init`) is gone,
    // but `/proc/self/exe` still execs the running binary in the forked child.
    let mut argv_owned = vec![cstr("/proc/self/exe")];
    argv_owned.extend(args.iter().map(|a| cstr(a)));
    let mut argv: Vec<*const libc::c_char> = argv_owned.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: fork in a sync, single-threaded PID 1 (no tokio runtime here); the
    // child only calls execv before touching anything else.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork failed: {}", io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe { libc::execv(argv_owned[0].as_ptr(), argv.as_ptr()) };
        unsafe { libc::_exit(127) };
    }
    Ok(pid)
}

/// fork() + exec `argv`; return the child pid in the parent without waiting.
fn fork_exec(argv: &[String]) -> Result<libc::pid_t> {
    // SAFETY: fork in a sync, single-threaded PID 1 (no tokio runtime here); the
    // child only calls exec_argv before touching anything else.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork failed: {}", io::Error::last_os_error());
    }
    if pid == 0 {
        exec_argv(argv); // never returns
    }
    Ok(pid)
}

/// fork + exec `argv`, wait for it, return its exit code (service debug path).
fn fork_exec_wait(argv: &[String]) -> Result<i32> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork failed: {}", io::Error::last_os_error());
    }
    if pid == 0 {
        exec_argv(argv);
    }
    loop {
        let mut status: libc::c_int = 0;
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return Ok(if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -1
            });
        }
        if r < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            bail!("waitpid failed: {}", io::Error::last_os_error());
        }
    }
}

/// On SIGTERM/SIGINT (e.g. a forwarded shutdown), power the VM off.
fn install_term_handler() {
    // SAFETY: poweroff() is async-signal-safe enough for our purpose (sync +
    // reboot syscalls); we never return from it.
    unsafe {
        libc::signal(
            libc::SIGTERM,
            handle_term as *const () as libc::sighandler_t,
        );
        libc::signal(libc::SIGINT, handle_term as *const () as libc::sighandler_t);
    }
}

extern "C" fn handle_term(_sig: libc::c_int) {
    poweroff();
}

/// Reap reparented orphans; when the serve child exits, power off.
fn supervise(serve_pid: libc::pid_t) -> Result<()> {
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, 0) };
        if pid < 0 {
            let e = io::Error::last_os_error();
            match e.raw_os_error() {
                Some(libc::EINTR) => continue,
                _ => break, // ECHILD: nothing left to wait on
            }
        }
        if pid == serve_pid {
            info!("virtkit-agent init: serve exited (status {status}); powering off");
            break;
        }
        // an orphan (or the net/ssh child) was reaped — keep supervising
    }
    poweroff();
}

/// Flush and power the VM off (the executor's cleanup also force-stops the VMM,
/// but a clean poweroff on serve exit is tidier). Never returns.
fn poweroff() -> ! {
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    // reboot() should not return for PID 1; if it does, exit so the kernel panics
    // visibly rather than hanging.
    std::process::exit(0);
}

/// Run a helper command, output discarded; true on exit 0. Used for the few
/// userspace tools the guest images provide (ip, dhclient, modprobe, ...).
fn run_cmd(prog: &str, args: &[&str]) -> bool {
    Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// True if `cmd` is found in any PATH directory.
fn which(cmd: &str) -> bool {
    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .any(|d| !d.is_empty() && Path::new(d).join(cmd).is_file())
}

/// Read a file as an argv list (one element per line; blank lines skipped — docker
/// inspect appends a trailing newline that would otherwise be a stray empty arg).
fn read_argv_file(path: &str) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn cstr(s: &str) -> CString {
    CString::new(s).expect("cmdline/path contains an interior NUL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_parses_key_values() {
        let raw = "console=ttyS0 VIRTKIT_HOSTNAME=runner VIRTKIT_VM_DNS=1.1.1.1,8.8.8.8 ro init=/x";
        let m: HashMap<String, String> = raw
            .split_whitespace()
            .filter_map(|t| t.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(m.get("VIRTKIT_HOSTNAME").unwrap(), "runner");
        assert_eq!(m.get("VIRTKIT_VM_DNS").unwrap(), "1.1.1.1,8.8.8.8");
        assert!(!m.contains_key("ro"));
    }

    #[test]
    fn ssh_agent_forward_args_relay_to_host_port() {
        assert_eq!(
            ssh_agent_forward_args("2223"),
            vec![
                "--socket",
                "vsock://2223",
                "forward",
                "--listen",
                SSH_AGENT_SOCK,
            ]
        );
    }

    #[test]
    fn resolv_conf_one_line_per_nameserver() {
        assert_eq!(resolv_conf("192.168.231.1"), "nameserver 192.168.231.1\n");
        assert_eq!(
            resolv_conf("1.1.1.1,8.8.8.8"),
            "nameserver 1.1.1.1\nnameserver 8.8.8.8\n"
        );
        assert_eq!(resolv_conf(""), "");
    }

    #[test]
    fn tmpfs_entry_parse() {
        assert_eq!(parse_tmpfs_entry("/builds:64G"), Some(("/builds", "64G")));
        assert_eq!(parse_tmpfs_entry("/rd:16G"), Some(("/rd", "16G")));
        assert_eq!(parse_tmpfs_entry("builds:64G"), None); // not absolute
        assert_eq!(parse_tmpfs_entry("/builds"), None); // no size
        assert_eq!(parse_tmpfs_entry("/builds:"), None); // empty size
        assert_eq!(parse_tmpfs_entry(":64G"), None); // empty path
    }

    #[test]
    fn sysctl_key_to_path() {
        assert_eq!(
            sysctl_path("kernel.perf_event_paranoid"),
            "/proc/sys/kernel/perf_event_paranoid"
        );
        assert_eq!(
            sysctl_path("  kernel.kptr_restrict "),
            "/proc/sys/kernel/kptr_restrict"
        );
        assert_eq!(
            sysctl_path("-net.ipv4.ip_forward"),
            "/proc/sys/net/ipv4/ip_forward"
        ); // '-' marker
        assert_eq!(
            sysctl_path("net/ipv4/ip_forward"),
            "/proc/sys/net/ipv4/ip_forward"
        ); // slash form
    }

    #[test]
    fn service_user_wrapping() {
        // root / empty -> argv unchanged
        assert_eq!(
            wrap_user(vec!["redis-server".into()], "root"),
            vec!["redis-server".to_string()]
        );
        assert_eq!(wrap_user(vec!["x".into()], ""), vec!["x".to_string()]);
    }

    #[test]
    fn argv_file_skips_blanks() {
        // (read_argv_file reads a real path; just exercise the line filter shape)
        let v: Vec<String> = "redis-server\n\n/etc/redis.conf\n"
            .lines()
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect();
        assert_eq!(
            v,
            vec!["redis-server".to_string(), "/etc/redis.conf".to_string()]
        );
    }
}
