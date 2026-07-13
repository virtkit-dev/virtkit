//! `vk-agent init` — PID 1 for guest images that ship no systemd. It brings
//! the rootfs and (optionally) the shared LAN up, then either supervises a `serve`
//! agent you drive over vsock (the default — a managed VM), or `exec`s the image's
//! own entrypoint (`VIRTKIT_MODE=service`).
//!
//! Configuration comes from the kernel cmdline (the executor passes it; a guest
//! booted `init=/usr/local/bin/vk-agent` gets no usable argv), from the boot
//! initramfs, and from capture files written at image-conversion time:
//!   /virtkit-service.json  (initramfs) the service's runtime config — env, user,
//!                       workdir, entrypoint+cmd — merged by the host (image defaults
//!                       + per-service overrides) and read *before* the pivot hides
//!                       the initramfs. The image itself stays byte-clean.
//!   /etc/virtkit/env    image ENV (KEY=VALUE per line; lost by `docker export`)
//!   /etc/virtkit/user   image USER: exported as VIRTKIT_DEFAULT_RUN_USER so served
//!                       stages drop to it (serve mode)
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
//!   VIRTKIT_CTL=1        mount the compose control fs at /run/vk/services (a FUSE
//!                        bridge to the host service manager over vsock)
//!   VIRTKIT_HOST_EXEC_PORT  host command channel: present /run/vk/host.sock and
//!                        relay it over this vsock port to the host's `vk-agent
//!                        serve` (whose --exec-wrapper enforces the allowlist)
//!   VIRTKIT_SSH=1        also run ssh-serve (vsock 2222); keys VIRTKIT_SSH_KEYS
//!                        (comma-separated `type:base64` entries, no spaces),
//!                        user VIRTKIT_SSH_USER (default root)
//!   VIRTKIT_SSH_AGENT_PORT  forward the host SSH agent: run a guest-side forwarder that
//!                        presents SSH_AUTH_SOCK and relays it over this vsock port to the
//!                        host (which splices to the host's real agent). Only agent
//!                        protocol bytes cross — private keys never enter the guest.
//!   VIRTKIT_MODE=service fork the boot config's entrypoint; the agent stays as PID 1
//!                        and reaps orphans. A systemd image hands off via its entrypoint.
//!   VIRTKIT_SERVE=1      (service) also start the vsock exec server (port 4444) for
//!                        live debugging: `vk-agent -s vsock-mux://<vsock.sock>:4444 exec`
//!   VIRTKIT_DEBUG=1      (service) fork+wait the entrypoint, then hold the VM on exit
//!                        for post-mortem inspection (overrides VIRTKIT_SERVE)
//!
//! The whole module is sync: no tokio in PID 1.

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::{info, warn};

use vk_core::addr::SocketAddr;
use vk_core::runcfg::RunConfig;

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const SSH_VSOCK_PORT: u32 = 2222;
/// Guest-side SSH_AUTH_SOCK the forwarder binds (on the /run tmpfs, never in the image).
const SSH_AGENT_SOCK: &str = "/run/virtkit-ssh-agent.sock";
const HOST_EXEC_AGENT_SOURCE: &str = "/proc/1/exe";
const HOST_EXEC_AGENT_BIN: &str = "/run/vk/bin/vk-agent";

/// Entry point for `… init`. Sets the guest up, then serves (default) or execs the
/// image entrypoint (VIRTKIT_MODE=service).
pub fn run_init(socket: &SocketAddr, inactivity_timeout: Option<u64>) -> Result<()> {
    info!("vk-agent init: PID {} ({socket})", std::process::id());
    // SAFETY: single-threaded here (no tokio, no serve fork yet).
    unsafe { std::env::set_var("PATH", DEFAULT_PATH) };

    // The boot config rides the initramfs, which the pivot below hides — read it first.
    let boot_config = read_boot_config();

    // Mount /proc up front so the kernel cmdline is readable now — every path below
    // is cmdline-driven, and the module load / init check run before the pivot that
    // would otherwise be the first to mount it. Harmless if already mounted.
    let _ = std::fs::create_dir_all("/proc");
    let _ = mount("proc", "/proc", "proc", 0);

    let cmdline = read_cmdline();

    // A modular image kernel (`--kernel image`) ships its boot-critical modules on the
    // preinit initramfs with a `/virtkit-modules` load list — insmod them before any
    // path mounts /dev/vda, in BOTH init modes. Absent (pinned kernel, or a plain run)
    // there is no list, so this is a no-op.
    if std::path::Path::new("/virtkit-modules").exists() {
        load_preinit_modules();
    }

    // Image init (`vk run --init image`): the image runs its OWN init/systemd. Handled
    // entirely by run_full_vm — pivot into the real root, fork a reparented serve, then
    // exec the image's init so systemd (not this agent) becomes PID 1. Gated on the
    // cmdline token so every default-init boot path stays unchanged.
    if cmdline.get("VIRTKIT_INIT").map(String::as_str) == Some("image") {
        return run_full_vm(socket, &cmdline, boot_config.as_ref());
    }

    // If booted from the agent-only initramfs (`VIRTKIT_PIVOT=<root dev>`), mount the
    // real image ext4 and switch into it — keeping this process as PID 1 — so the agent
    // never lives inside the image. A no-op on the legacy in-rootfs `init=` boot.
    if let Err(e) = pivot_to_real_root() {
        warn!("vk-agent init: pivot to real root failed: {e:#} — continuing in place");
    }

    mount_api_filesystems()?;
    apply_sysctls(); // honor /etc/sysctl.d/*.conf — there is no systemd-sysctl here
    bring_up_loopback();
    set_hostname(&cmdline);
    write_self_hosts(&cmdline);
    load_image_env(); // so served/exec'd commands inherit the image PATH etc.
    export_default_run_user(); // so served stages drop to the image's USER
    apply_boot_config(boot_config.as_ref()); // the boot config wins over any capture
    materialize_env(boot_config.as_ref()); // persist the merged env for login shells
    mount_virtiofs(&cmdline);
    apply_symlinks(&cmdline);
    link_ci_tools(&cmdline); // host CI tools (git/git-lfs/…) onto PATH, if the image lacks them
    configure_network(&cmdline);
    write_resolv_conf(&cmdline); // DNS for every net mode (kernel `ip=` pool + static bridge)
    apply_tmpfs(&cmdline); // RAM scratch dirs (e.g. CI /builds) before the payload starts
    // orphans reparent to PID 1 (this process): reap them.
    set_child_subreaper();

    // VIRTKIT_MODE=service: fork the boot config's entrypoint and supervise it as
    // PID 1 (reaps orphans). A systemd image uses this too — its entrypoint execs
    // /sbin/init, handing off to systemd which then takes over process supervision.
    if cmdline.get("VIRTKIT_MODE").map(String::as_str) == Some("service") {
        return run_service(&cmdline, boot_config.as_ref());
    }

    maybe_ssh_serve(&cmdline);
    maybe_ctlfs(&cmdline);
    maybe_host_exec(&cmdline);
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
    info!("vk-agent init: pivoted into real root {dev}");
    Ok(true)
}

/// Image-init handoff (`vk run --init image`): pivot into the real root, apply the
/// virtkit-provided setup the image's init won't do itself (host volume mounts,
/// symlinks, the ssh and exec serves, image env), fork a reparented `vk-agent serve`,
/// then exec the image's own init (systemd) so it becomes PID 1.
///
/// Any modular image kernel's boot-critical modules are already loaded by the caller
/// (`run_init`) before this runs — they must precede the pivot, which mounts the ext4
/// rootfs at `/dev/vda`. The serves are forked just before the exec; once the exec
/// makes systemd PID 1, they reparent to it and keep carrying the run's `-- <cmd>` /
/// ssh over vsock. Only setup the image's init does not own is applied here —
/// networking is left to the image (deferred).
fn run_full_vm(
    socket: &SocketAddr,
    cmdline: &HashMap<String, String>,
    cfg: Option<&RunConfig>,
) -> Result<()> {
    // The pivot is mandatory here: the whole point is to hand off to the image's own
    // /sbin/init, which only exists in the real root. Unlike the serve-mode path (which
    // can keep serving in place), continuing without the pivot would just exec the
    // initramfs's own tree — so fail loudly instead.
    pivot_to_real_root().context("vk-agent image-init: pivot to real root")?;
    // Re-mount /proc and /dev in the pivoted root before the setup below: the
    // pivot's MS_MOVE hid the initramfs mounts, so the new root has neither. /proc
    // is needed because `spawn_serve` execs `/proc/self/exe` (else exit 127); /dev
    // (devtmpfs) is needed for device nodes the setup opens, e.g. /dev/net/tun for
    // the eth0 bridge. systemd re-mounts both after the handoff (already-mounted is
    // fine).
    let _ = std::fs::create_dir_all("/proc");
    let _ = mount("proc", "/proc", "proc", 0);
    let _ = std::fs::create_dir_all("/dev");
    let _ = mount("devtmpfs", "/dev", "devtmpfs", 0);

    // Apply only the virtkit-provided setup the image's own init won't do: host
    // volume mounts (`--volume`/`--workdir`), symlinks, an eth0 bridge to the vk
    // switch, and the run's env (so the served command and ssh sessions inherit it).
    // Each is a no-op unless its cmdline param is set.
    load_image_env();
    apply_boot_config(cfg);
    materialize_env(cfg);
    mount_virtiofs(cmdline);
    apply_symlinks(cmdline);
    configure_network_fullvm(cmdline);

    // The vsock services the run exposes, forked before the exec so they reparent to
    // systemd and keep serving: ssh-serve (`--ssh`), the host-agent forwarder
    // (`--ssh-agent`), and the exec channel that carries `-- <cmd>`. The first two are
    // gated on their cmdline params.
    maybe_ssh_serve(cmdline);
    maybe_ssh_agent(cmdline);
    let _serve = spawn_serve(socket, None)?;

    let handoff = cmdline
        .get("VIRTKIT_HANDOFF")
        .cloned()
        .unwrap_or_else(|| "/sbin/init".to_string());
    info!("vk-agent image-init: exec {handoff} (systemd takes PID 1)");
    exec_argv(&[handoff]); // never returns; this process becomes the image's init
}

/// Load the boot-critical modules listed (one absolute `.ko` path per line) in the
/// preinit's `/virtkit-modules`, in order. Runs while the initramfs is still the
/// root, so both the list and the `.ko` files are present. A single module failing
/// (or already loaded) never aborts the boot.
fn load_preinit_modules() {
    let list = match std::fs::read_to_string("/virtkit-modules") {
        Ok(list) => list,
        Err(e) => {
            warn!("vk-agent preinit: no /virtkit-modules ({e}) — loading no modules");
            return;
        }
    };
    let mods: Vec<&str> = list
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let mut loaded = 0;
    for path in &mods {
        if insmod(path) {
            loaded += 1;
        }
    }
    info!(
        "vk-agent preinit: loaded {loaded}/{} preinit modules",
        mods.len()
    );
}

/// `insmod` one module via `finit_module(2)` (load straight from the open fd, no
/// params). `EEXIST`/`EBUSY` mean it is already loaded — fine. Any other error is
/// logged and skipped: a missing optional module must not stall the boot.
fn insmod(path: &str) -> bool {
    use std::os::unix::io::AsRawFd;
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => {
            warn!("vk-agent preinit: opening module {path} failed: {e}");
            return false;
        }
    };
    let params = c"";
    // SAFETY: `file` outlives the call, so the fd is valid; params is a valid C string.
    let rc = unsafe { libc::syscall(libc::SYS_finit_module, file.as_raw_fd(), params.as_ptr(), 0) };
    if rc == 0 {
        return true;
    }
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::EEXIST) | Some(libc::EBUSY) => true, // already loaded — fine
        _ => {
            warn!("vk-agent preinit: loading module {path} failed: {e}");
            false
        }
    }
}

/// Mount the kernel API filesystems a from-scratch rootfs lacks. Best effort:
/// each may already be mounted (the initrd/kernel set some up) — tolerate it.
fn mount_api_filesystems() -> Result<()> {
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
            warn!("vk-agent init: mount {fstype} on {target} failed: {e}");
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
            warn!("vk-agent init: symlink {link} -> {target} failed: {e}");
        }
    }
    // /run and /tmp as fresh tmpfs, but recreate the image's baked top-level dirs so
    // a service's runtime dir survives — e.g. /run/redis (owned by redis) that redis
    // binds its unix socket into. systemd-tmpfiles would recreate these; we have no
    // systemd, and a bare tmpfs mount would hide them.
    //
    // /tmp is the exception when a build hands us a disk-backed scratch device
    // (VIRTKIT_TMP_DEV): a build's RUN steps write bulk transient data (tar extractions,
    // ./configure) to /tmp, and a RAM tmpfs caps that at ½·guest-RAM. The device is a
    // separate, sparse ext4 disk — not RAM-bound, and never part of the stage snapshot — so
    // it stays a fresh mount that leaks nothing into the image.
    let tmp_dev = tmp_dev_from_cmdline();
    for target in ["/run", "/tmp"] {
        if !std::path::Path::new(target).exists() {
            created.push(target);
        }
        let _ = std::fs::create_dir_all(target);
        let res = if target == "/tmp"
            && let Some(dev) = &tmp_dev
        {
            crate::diskmount::mount_rw(
                dev,
                std::path::Path::new(target),
                libc::MS_NOSUID | libc::MS_NODEV,
            )
            .and_then(|()| {
                // A freshly-made ext4's root is mode 0755 owned by root, but a kernel tmpfs
                // /tmp is 1777 (world-writable + sticky). Restore that so unprivileged RUN
                // steps (apt dropping to _apt, ./configure) can create temp files there.
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(
                    std::path::Path::new(target),
                    std::fs::Permissions::from_mode(0o1777),
                )
            })
        } else {
            mount_tmpfs_keep_dirs(target, libc::MS_NOSUID | libc::MS_NODEV)
        };
        if let Err(e) = res
            && e.raw_os_error() != Some(libc::EBUSY)
        {
            // A build explicitly provisioned the disk-backed /tmp scratch (VIRTKIT_TMP_DEV):
            // if it will not mount, /tmp would silently stay on the (small, lineage-shared)
            // rootfs overlay and a bulk RUN write would later ENOSPC with no hint why. Fail
            // the boot instead — the build surfaces this as a boot failure with the console
            // tail, so the cause is visible rather than a mystery out-of-space mid-RUN.
            if target == "/tmp"
                && let Some(dev) = &tmp_dev
            {
                bail!(
                    "mounting the disk-backed /tmp scratch device {dev} failed: {e} — \
                     refusing to fall back to an on-rootfs /tmp (a bulk write would then \
                     exhaust the rootfs). Check that {dev} is a valid ext4 scratch disk."
                );
            }
            warn!("vk-agent init: mounting {target} failed: {e}");
        }
    }
    // Now that /run (the registry's tmpfs) is mounted, record the mountpoints we created
    // so the pre-commit cleanup can remove them from a FROM scratch image.
    for target in created {
        crate::diskmount::note_created(std::path::Path::new(target));
    }
    Ok(())
}

/// The disk-backed `/tmp` scratch device a build's `boot_session` passes as
/// `VIRTKIT_TMP_DEV=/dev/vdN`, or `None` for a plain run (tmpfs `/tmp`). Read straight from
/// `/proc/cmdline` because `/tmp` is mounted before the general cmdline parse.
fn tmp_dev_from_cmdline() -> Option<String> {
    std::fs::read_to_string("/proc/cmdline")
        .ok()?
        .split_whitespace()
        .find_map(|t| t.strip_prefix("VIRTKIT_TMP_DEV=").map(str::to_string))
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
            warn!("vk-agent init: bad VIRTKIT_TMPFS entry {entry:?} (want /path:size)");
            continue;
        };
        let _ = std::fs::create_dir_all(path);
        let data = format!("size={size},mode=0755");
        let flags = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOATIME;
        if let Err(e) = mount_data("tmpfs", path, "tmpfs", flags, &data) {
            warn!("vk-agent init: tmpfs {path} (size={size}) failed: {e}");
            continue;
        }
        if !user.is_empty() && user != "root" {
            let owner = format!("{user}:{user}");
            let _ = run_cmd("chown", &[owner.as_str(), path]);
        }
        info!("vk-agent init: tmpfs {path} (size={size})");
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
                warn!("vk-agent init: sysctl {}={value} failed: {e}", key.trim());
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
        warn!("vk-agent init: could not bring up loopback: {e:#}");
    }
}

fn set_hostname(cmdline: &HashMap<String, String>) {
    let Some(name) = cmdline.get("VIRTKIT_HOSTNAME") else {
        return;
    };
    let rc = unsafe { libc::sethostname(name.as_ptr().cast(), name.len()) };
    if rc != 0 {
        warn!(
            "vk-agent init: sethostname({name}) failed: {}",
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
        warn!("vk-agent init: writing /etc/hosts failed: {e}");
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
        info!("vk-agent init: VIRTKIT_DEFAULT_RUN_USER={user}");
    }
}

/// The boot-time service config carried in the agent initramfs — `None` when the
/// initramfs carries none (a plain `vk run`/builder boot) or it fails to parse.
/// Must run before the pivot: the initramfs is hidden underneath afterwards.
fn read_boot_config() -> Option<RunConfig> {
    let path = format!("/{}", vk_core::runcfg::INITRAMFS_PATH);
    let text = std::fs::read_to_string(&path).ok()?;
    match RunConfig::from_json(&text) {
        Ok(c) => Some(c),
        Err(e) => {
            warn!("vk-agent init: unparsable {path}: {e}");
            None
        }
    }
}

/// Apply the boot config's environment and user the way the `/etc/virtkit` capture
/// does for converted images — the config wins over any baked capture (a clean image
/// has none). The entrypoint/workdir parts are consumed by `run_service`.
fn apply_boot_config(cfg: Option<&RunConfig>) {
    let Some(cfg) = cfg else { return };
    for (k, v) in &cfg.env {
        // SAFETY: still single-threaded init, before any serve/service fork.
        unsafe { std::env::set_var(k, v) };
    }
    if !cfg.user.is_empty() && cfg.user != "root" {
        // SAFETY: as above.
        unsafe { std::env::set_var("VIRTKIT_DEFAULT_RUN_USER", &cfg.user) };
        info!("vk-agent init: VIRTKIT_DEFAULT_RUN_USER={}", cfg.user);
    }
}

/// Persist the boot config's environment to /etc/virtkit/env, upserted over any
/// baked capture (config wins, order preserved). The runtime env is already
/// applied by `apply_boot_config`; this write is for *login* shells, whose
/// /etc/profile resets PATH — a profile.d snippet can re-apply the effective env
/// from the file, and on a clean-image boot (`run -f`) the file would otherwise
/// not exist at all. Best effort: a read-only rootfs just keeps the in-process env.
fn materialize_env(cfg: Option<&RunConfig>) {
    let Some(cfg) = cfg else { return };
    if cfg.env.is_empty() {
        return;
    }
    let mut merged: Vec<(String, String)> = std::fs::read_to_string("/etc/virtkit/env")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.into(), v.into())))
        .collect();
    for (k, v) in &cfg.env {
        match merged.iter_mut().find(|(ek, _)| ek == k) {
            Some(e) => e.1 = v.clone(),
            None => merged.push((k.clone(), v.clone())),
        }
    }
    // one entry per line — a key/value with an embedded newline can't fit the format
    let text: String = merged
        .iter()
        .filter(|(k, v)| !k.contains('\n') && !v.contains('\n'))
        .map(|(k, v)| format!("{k}={v}\n"))
        .collect();
    let _ = std::fs::create_dir_all("/etc/virtkit");
    if let Err(e) = std::fs::write("/etc/virtkit/env", text) {
        warn!("vk-agent init: writing /etc/virtkit/env failed: {e}");
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
            warn!("vk-agent init: bad VIRTKIT_VIRTIOFS entry {entry:?} (want tag:path)");
            continue;
        };
        let mountpoint = Path::new(path);
        let created_parents = match create_mountpoint(mountpoint) {
            Ok(created) => created,
            Err(e) => {
                warn!(
                    "vk-agent init: creating virtiofs mountpoint {} failed: {e}",
                    mountpoint.display()
                );
                continue;
            }
        };
        if let Err(e) = mount(tag, path, "virtiofs", 0) {
            warn!(
                "vk-agent init: mount virtiofs {tag} at {} failed: {e}",
                mountpoint.display()
            );
        } else {
            chown_created_mount_parents(mountpoint, &created_parents);
        }
    }
}

/// Create a mountpoint without losing which parent directories were synthesized.
///
/// The mountpoint itself is excluded from the returned list: after the mount it is the
/// shared host directory, so chowning it would alter host ownership.
fn create_mountpoint(path: &Path) -> io::Result<Vec<PathBuf>> {
    let mut created = Vec::new();
    if let Some(parent) = path.parent() {
        let mut parents: Vec<&Path> = parent.ancestors().collect();
        parents.reverse();
        for dir in parents {
            if dir.as_os_str().is_empty() || dir.exists() {
                continue;
            }
            match std::fs::create_dir(dir) {
                Ok(()) => created.push(dir.to_path_buf()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
    }
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    Ok(created)
}

fn chown_created_mount_parents(mountpoint: &Path, created_parents: &[PathBuf]) {
    if created_parents.is_empty() {
        return;
    }
    use std::os::unix::fs::MetadataExt;

    let meta = match std::fs::metadata(mountpoint) {
        Ok(meta) => meta,
        Err(e) => {
            warn!(
                "vk-agent init: stat mount {} to chown its synthesized parents failed: {e}",
                mountpoint.display()
            );
            return;
        }
    };
    for dir in created_parents {
        if let Err(e) = std::os::unix::fs::chown(dir, Some(meta.uid()), Some(meta.gid())) {
            warn!(
                "vk-agent init: chown synthesized mount parent {} to {}:{} failed: {e}",
                dir.display(),
                meta.uid(),
                meta.gid()
            );
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
            warn!("vk-agent init: bad VIRTKIT_SYMLINKS entry {entry:?} (want src:dest)");
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
            warn!("vk-agent init: symlink {src} -> {dest}: {e}");
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
        warn!("vk-agent init: bad VIRTKIT_TOOLS {spec:?} (want tag:mountpoint)");
        return;
    };
    let _ = run_cmd("modprobe", &["virtiofs"]); // built-in on our kernel; harmless
    let _ = std::fs::create_dir_all(mnt);
    if let Err(e) = mount(tag, mnt, "virtiofs", 0) {
        warn!("vk-agent init: mount CI tools {tag} at {mnt} failed: {e}");
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
                info!("vk-agent init: CI tool {name} -> {link}");
                if name == "git" {
                    linked_git = true;
                }
            }
            Err(e) => warn!("vk-agent init: link {} -> {link}: {e}", src.display()),
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
            info!("vk-agent init: GIT_SSL_CAINFO={ca}");
        }
    }
}

/// Bring eth0 up on the shared LAN: fork the tap bridge (`net`) to the host
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
        warn!("vk-agent init: net bridge failed to start: {e}");
        return;
    }
    if !wait_for_iface("eth0", 50) {
        warn!("vk-agent init: eth0 did not come up");
        return;
    }
    if cmdline.get("VIRTKIT_NET_DHCP").map(String::as_str) == Some("1") {
        // -1: one attempt; the gateway's DHCP also hands out the resolver.
        if !run_cmd("timeout", &["20", "dhclient", "-1", "eth0"]) {
            warn!("vk-agent init: dhclient failed");
        }
    } else if let Some(ip) = cmdline.get("VIRTKIT_VM_IP") {
        let gw = cmdline
            .get("VIRTKIT_VM_GW")
            .map_or("192.168.127.1", String::as_str);
        // ioctls, not `ip`: minimal glibc images (debian:*-slim) ship no iproute2, so
        // shelling out left them with no address/route and a broken resolver.
        if let Err(e) = set_static_network(ip, gw) {
            warn!("vk-agent init: configuring eth0 {ip} via {gw} failed: {e:#}");
        }
    }
    // DNS is written separately (write_resolv_conf) so it applies to the kernel `ip=`
    // pool net too, not just this vsock-bridge static path.
}

/// Full-VM networking: create the eth0 tap bridged to the vk switch over vsock and
/// bring its link up, but leave *addressing* to the image's own DHCP client — so an
/// image already set to DHCP eth0 needs no change. As a fallback for images not
/// configured to DHCP, fork a child that waits a grace period and, if eth0 still has
/// no address, runs `dhclient` itself. The bridge and the fallback child reparent to
/// the image's init after the exec.
fn configure_network_fullvm(cmdline: &HashMap<String, String>) {
    let Some(port) = cmdline.get("VIRTKIT_NET_PORT") else {
        return;
    };
    if let Err(e) = fork_agent(&[
        "--socket".into(),
        format!("vsock://{port}"),
        "net".into(),
        "--iface".into(),
        "eth0".into(),
    ]) {
        warn!("vk-agent image-init: net bridge failed to start: {e}");
        return;
    }
    // Fork a watcher rather than blocking here: the tap can take a moment to appear,
    // and the image's own DHCP client races us. The watcher waits for eth0, gives the
    // image a grace period to configure it, then falls back to dhclient. It reparents
    // to the image's init after the exec below.
    // SAFETY: single-threaded preinit (no tokio); the child only waits and runs a
    // helper before _exit.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        if !wait_for_iface("eth0", 150) {
            warn!("vk-agent image-init: eth0 never appeared");
            unsafe { libc::_exit(0) };
        }
        // Give the image's own DHCP client a head start; only step in if it didn't.
        std::thread::sleep(Duration::from_secs(8));
        if iface_configured("eth0") {
            info!("vk-agent image-init: eth0 configured by the image");
        } else {
            info!("vk-agent image-init: image did not configure eth0 — running dhclient");
            if !run_cmd("dhclient", &["-1", "eth0"]) {
                warn!("vk-agent image-init: dhclient fallback failed (no dhcp client in image?)");
            }
        }
        unsafe { libc::_exit(0) };
    }
    // Seed /etc/resolv.conf with the switch's resolver so name resolution works even
    // on images that DHCP an address but don't wire up DNS (no systemd-resolved).
    write_resolv_conf(cmdline);
}

/// Whether `iface` has an address/route yet — proxied by an entry in
/// `/proc/net/route` (a freshly link-up-only interface has none; a DHCP'd or
/// statically-configured one does). Avoids depending on iproute2 in the image.
fn iface_configured(iface: &str) -> bool {
    std::fs::read_to_string("/proc/net/route")
        .map(|s| {
            s.lines()
                .skip(1)
                .any(|l| l.split_whitespace().next() == Some(iface))
        })
        .unwrap_or(false)
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
        Ok(()) => info!("vk-agent init: resolv.conf nameservers {dns}"),
        Err(e) => warn!("vk-agent init: writing /etc/resolv.conf failed: {e}"),
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

/// VIRTKIT_CTL=1: fork the agent's `ctlfs` — the compose control plane mounted
/// at /run/vk/services (each operation bridges to the host manager over vsock).
/// Mounted one level down so /run/vk stays a plain directory with room for the
/// run's other endpoints.
fn maybe_ctlfs(cmdline: &HashMap<String, String>) {
    if cmdline.get("VIRTKIT_CTL").map(String::as_str) != Some("1") {
        return;
    }
    if let Err(e) = fork_agent(&["ctlfs".into(), "/run/vk/services".into()]) {
        warn!("vk-agent init: control fs failed to start: {e}");
    }
}

/// Guest vsock port + socket of the host-exec channel (`VIRTKIT_HOST_EXEC_PORT`):
/// the guest-side forwarder presents `/run/vk/host.sock`, relaying each connection
/// to the host's `vk-agent serve` (which enforces its own command allowlist).
const HOST_EXEC_SOCK: &str = "/run/vk/host.sock";

/// Argv for the guest-side host-exec forwarder: listen on [`HOST_EXEC_SOCK`] and
/// relay to the host over `port` — the exact shape of the SSH-agent forward. When
/// a non-root run user is given, the socket is chowned to it so a job stage running
/// as that user can reach the host channel (`vk-agent -s /run/vk/host.sock exec …`).
fn host_exec_forward_args(port: &str, run_user: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--socket".into(),
        format!("vsock://{port}"),
        "forward".into(),
        "--listen".into(),
        HOST_EXEC_SOCK.into(),
    ];
    if let Some(user) = run_user {
        args.push("--chown".into());
        args.push(user.into());
    }
    args
}

/// Optionally expose the host command channel (`VIRTKIT_HOST_EXEC_PORT`): a
/// guest-side forwarder presents [`HOST_EXEC_SOCK`], so guest tooling reaches the
/// host's `vk-agent serve` at a discoverable path with no transport knowledge
/// (`vk-agent -s /run/vk/host.sock exec …`). Only protocol bytes cross the vsock;
/// what may actually run is decided host-side (`serve --exec-wrapper`).
fn maybe_host_exec(cmdline: &HashMap<String, String>) {
    let Some(port) = cmdline.get("VIRTKIT_HOST_EXEC_PORT") else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all("/run/vk") {
        warn!("vk-agent init: creating /run/vk failed: {e}");
        return;
    }
    if let Err(e) = install_host_exec_agent(HOST_EXEC_AGENT_SOURCE, HOST_EXEC_AGENT_BIN) {
        warn!("vk-agent init: mounting {HOST_EXEC_AGENT_BIN} failed: {e:#}");
    }
    // Give the socket to the run user (VIRTKIT_DEFAULT_RUN_USER, set above by
    // export_default_run_user/apply_boot_config; unset when the stage runs as root)
    // so a non-root job stage can reach the host channel.
    let run_user = std::env::var("VIRTKIT_DEFAULT_RUN_USER").ok();
    if let Err(e) = fork_agent(&host_exec_forward_args(port, run_user.as_deref())) {
        warn!("vk-agent init: host-exec forward failed to start: {e}");
    }
}

fn install_host_exec_agent(src: &str, dest: &str) -> Result<()> {
    let dest_path = Path::new(dest);
    let parent = dest_path
        .parent()
        .with_context(|| format!("{dest} has no parent directory"))?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    let _ = std::fs::remove_file(dest_path);
    // Bind-mount the running agent rather than copying it: the client always matches the
    // live binary and the image needn't ship it. The bind needs an existing dest inode,
    // hence the empty placeholder file created just above.
    std::fs::File::create(dest_path).with_context(|| format!("creating {dest}"))?;
    if let Err(e) = mount(src, dest, "", libc::MS_BIND) {
        let _ = std::fs::remove_file(dest_path);
        return Err(e).with_context(|| format!("mounting {src} on {dest}"));
    }
    Ok(())
}

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
                warn!("vk-agent init: skipping malformed VIRTKIT_SSH_KEYS entry (no `:`)");
                None
            }
        })
        .collect();
    if keys.is_empty() {
        warn!("vk-agent init: VIRTKIT_SSH_KEYS empty — ssh server disabled");
        return;
    }
    let user = cmdline
        .get("VIRTKIT_SSH_USER")
        .cloned()
        .unwrap_or_else(|| "root".into());
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
        warn!("vk-agent init: ssh server failed to start: {e}");
    }
}

/// Argv for the guest-side SSH-agent forwarder: listen on the guest SSH_AUTH_SOCK and
/// relay to the host over `port` (the host splices it to its real `$SSH_AUTH_SOCK`).
/// When a non-root run user is given, the socket is chowned to it so that user's
/// ssh/git (a served/exec'd stage) can open it.
fn ssh_agent_forward_args(port: &str, run_user: Option<&str>) -> Vec<String> {
    let mut args = vec![
        "--socket".into(),
        format!("vsock://{port}"),
        "forward".into(),
        "--listen".into(),
        SSH_AGENT_SOCK.into(),
    ];
    if let Some(user) = run_user {
        args.push("--chown".into());
        args.push(user.into());
    }
    args
}

/// Optionally forward the host's SSH agent (`VIRTKIT_SSH_AGENT_PORT`): start the guest-side
/// forwarder presenting a unix socket, then point `SSH_AUTH_SOCK` at it so served/exec'd
/// commands (ssh, git) find it. Only agent protocol bytes cross the vsock — keys stay host-side.
fn maybe_ssh_agent(cmdline: &HashMap<String, String>) {
    let Some(port) = cmdline.get("VIRTKIT_SSH_AGENT_PORT") else {
        return;
    };
    // Give the socket to the run user (VIRTKIT_DEFAULT_RUN_USER, set earlier in init;
    // unset when stages run as root) so that user's ssh/git can open it.
    let run_user = std::env::var("VIRTKIT_DEFAULT_RUN_USER").ok();
    match fork_agent(&ssh_agent_forward_args(port, run_user.as_deref())) {
        // Set it before spawn_serve so the served stages inherit it (single-threaded here).
        // SAFETY: PID 1, no other threads yet (serve/net not forked).
        Ok(_) => unsafe { std::env::set_var("SSH_AUTH_SOCK", SSH_AGENT_SOCK) },
        Err(e) => warn!("vk-agent init: ssh-agent forward failed to start: {e}"),
    }
}

/// `VIRTKIT_MODE=service`: run the boot config's entrypoint as its user, in its
/// workdir. Normally forked (the agent stays PID 1 and reaps orphans); under
/// VIRTKIT_DEBUG it is run then held so a crash doesn't panic PID 1 and the console
/// keeps the error.
fn run_service(cmdline: &HashMap<String, String>, config: Option<&RunConfig>) -> Result<()> {
    let cfg = config.cloned().unwrap_or_default();
    let argv = service_argv(&cfg, Path::new("/sbin/init").exists());
    let argv = wrap_user(argv, &cfg.user);
    if !cfg.workdir.is_empty() && cfg.workdir != "/" {
        // children (the service, a VIRTKIT_SERVE exec server) inherit PID 1's cwd,
        // so the service starts in its image WORKDIR like `docker run` would.
        if let Err(e) = std::env::set_current_dir(&cfg.workdir) {
            warn!("vk-agent init: chdir {} failed: {e}", cfg.workdir);
        }
    }
    info!(
        "vk-agent init: service as {}: {:?}",
        if cfg.user.is_empty() {
            "root"
        } else {
            &cfg.user
        },
        argv
    );

    // VIRTKIT_DEBUG=1: fork+wait, then hold for post-mortem inspection.
    if cmdline.get("VIRTKIT_DEBUG").map(String::as_str) == Some("1") {
        match fork_exec_wait(&argv) {
            Ok(code) => {
                warn!("vk-agent init: service exited rc={code} — holding (VIRTKIT_DEBUG)")
            }
            Err(e) => warn!("vk-agent init: service failed: {e} — holding (VIRTKIT_DEBUG)"),
        }
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // Fork the service as a child — the agent (PID 1) stays to reap orphans.
    let service_pid = fork_exec(&argv)?;
    info!("vk-agent init: service pid {service_pid}");

    // VIRTKIT_SERVE=1: optionally start the vsock exec server for live debugging.
    // Connect with: vk-agent -s vsock-mux://<vsock.sock>:4444 exec -- <cmd>
    let serve_pid = if cmdline.get("VIRTKIT_SERVE").map(String::as_str) == Some("1") {
        let socket = socket_from_cmdline();
        match spawn_serve(&socket, None) {
            Ok(pid) => {
                info!("vk-agent init: exec server up on {socket} (pid {pid})");
                Some(pid)
            }
            Err(e) => {
                warn!("vk-agent init: exec server failed to start: {e}");
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
            info!("vk-agent init: service exited (code {code}); powering off");
            break;
        }
        if Some(pid) == serve_pid {
            info!("vk-agent init: exec server exited (code {code})");
            continue; // service is still running; keep supervising
        }
        // an orphan was reaped — keep supervising
    }
    poweroff();
}

/// The argv a service boots: the config's entrypoint+cmd; with none, a self-booting
/// image (systemd) hands off to /sbin/init, else a shell (debuggable, never a panic).
fn service_argv(cfg: &RunConfig, have_sbin_init: bool) -> Vec<String> {
    let argv = cfg.argv();
    if !argv.is_empty() {
        return argv;
    }
    if have_sbin_init {
        warn!("vk-agent init: no service command in the boot config — forking /sbin/init");
        vec!["/sbin/init".into()]
    } else {
        warn!("vk-agent init: no service command in the boot config — forking /bin/sh");
        vec!["/bin/sh".into()]
    }
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
        "vk-agent init: exec {:?} failed: {}",
        argv.first(),
        io::Error::last_os_error()
    );
    unsafe { libc::_exit(127) };
}

fn set_child_subreaper() {
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0 {
        warn!(
            "vk-agent init: PR_SET_CHILD_SUBREAPER failed: {}",
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
    info!("vk-agent init: serve started (pid {pid})");
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
            info!("vk-agent init: serve exited (status {status}); powering off");
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
            ssh_agent_forward_args("2223", None),
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
    fn ssh_agent_forward_args_chowns_socket_to_run_user() {
        assert_eq!(
            ssh_agent_forward_args("2223", Some("build")),
            vec![
                "--socket",
                "vsock://2223",
                "forward",
                "--listen",
                SSH_AGENT_SOCK,
                "--chown",
                "build",
            ]
        );
    }

    #[test]
    fn host_exec_forward_args_relay_to_host_port() {
        assert_eq!(
            host_exec_forward_args("1100", None),
            vec![
                "--socket",
                "vsock://1100",
                "forward",
                "--listen",
                HOST_EXEC_SOCK,
            ]
        );
    }

    /// Removes its directory on drop so a panicking assertion never leaks the temp tree.
    struct TempTree(PathBuf);
    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn host_exec_forward_args_chowns_socket_to_run_user() {
        assert_eq!(
            host_exec_forward_args("1100", Some("build")),
            vec![
                "--socket",
                "vsock://1100",
                "forward",
                "--listen",
                HOST_EXEC_SOCK,
                "--chown",
                "build",
            ]
        );
    }

    #[test]
    fn create_mountpoint_tracks_only_created_parents() {
        let root = std::env::temp_dir().join(format!(
            "virtkit-init-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let root = TempTree(root);
        let root = &root.0;
        let target = root.join("home/vince/bastion/wab/.git");

        let created = create_mountpoint(&target).unwrap();

        assert_eq!(
            created,
            vec![
                root.join("home"),
                root.join("home/vince"),
                root.join("home/vince/bastion"),
                root.join("home/vince/bastion/wab"),
            ]
        );
        assert!(target.is_dir());
        assert!(!created.contains(&target));

        // Re-run: nothing new to create, including no re-report of existing parents.
        let created_again = create_mountpoint(&target).unwrap();
        assert!(created_again.is_empty());

        // Partial prefix already present: only the missing tail is reported.
        let other = root.join("home/vince/bastion/other/.git");
        let created_partial = create_mountpoint(&other).unwrap();
        assert_eq!(
            created_partial,
            vec![root.join("home/vince/bastion/other"),]
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
    fn service_argv_prefers_config_then_init_then_shell() {
        let cfg = RunConfig {
            entrypoint: vec!["redis-server".into()],
            cmd: vec!["--appendonly".into(), "yes".into()],
            ..Default::default()
        };
        assert_eq!(
            service_argv(&cfg, true),
            vec!["redis-server", "--appendonly", "yes"]
        );
        // no configured command: a systemd image hands off, else a shell.
        assert_eq!(
            service_argv(&RunConfig::default(), true),
            vec!["/sbin/init"]
        );
        assert_eq!(service_argv(&RunConfig::default(), false), vec!["/bin/sh"]);
    }

    #[test]
    fn boot_config_parses_the_runcfg_json() {
        let cfg = RunConfig {
            env: vec![("PORT".into(), "6379".into())],
            user: "redis".into(),
            workdir: "/data".into(),
            entrypoint: vec!["redis-server".into()],
            cmd: vec![],
        };
        assert_eq!(RunConfig::from_json(&cfg.to_json()).unwrap(), cfg);
    }
}
