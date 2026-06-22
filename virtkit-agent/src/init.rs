//! `virtkit-agent init` — PID 1 for guest images that ship no systemd. It brings
//! the rootfs and (optionally) the fleet LAN up, then either supervises a `serve`
//! agent you drive over vsock (the default — a managed VM), or `exec`s the image's
//! own entrypoint (`VIRTKIT_MODE=service`).
//!
//! Configuration comes from the kernel cmdline (the executor passes it; a guest
//! booted `init=/usr/local/bin/virtkit-agent` gets no usable argv) and from capture
//! files written at image-build time:
//!   /etc/virtkit/env    image ENV (KEY=VALUE per line; lost by `docker export`)
//!   /etc/virtkit/user   image USER to drop to (service mode)
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
//!   VIRTKIT_TMPFS        /path:size[,/path:size] RAM scratch dirs (e.g. CI /builds)
//!   VIRTKIT_SSH=1        also run ssh-serve (vsock 2222); keys VIRTKIT_SSH_KEYS
//!                        (default /workdir/docker/runner/authorized_keys), user
//!                        VIRTKIT_SSH_USER (default dev)
//!   VIRTKIT_MODE=service exec the captured entrypoint instead of serving (a systemd
//!                        image uses this: its entrypoint execs /sbin/init)
//!   VIRTKIT_DEBUG=1      (service) don't exec — run, report, hold a shell
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

/// Entry point for `… init`. Sets the guest up, then serves (default) or execs the
/// image entrypoint (VIRTKIT_MODE=service).
pub fn run_init(socket: &SocketAddr, inactivity_timeout: Option<u64>) -> Result<()> {
    info!("virtkit-agent init: PID {} ({socket})", std::process::id());
    // SAFETY: single-threaded here (no tokio, no serve fork yet).
    unsafe { std::env::set_var("PATH", DEFAULT_PATH) };

    mount_api_filesystems();
    apply_sysctls(); // honor /etc/sysctl.d/*.conf — there is no systemd-sysctl here
    let cmdline = read_cmdline();
    bring_up_loopback();
    set_hostname(&cmdline);
    write_self_hosts(&cmdline);
    load_image_env(); // so served/exec'd commands inherit the image PATH etc.
    ensure_virtctl_symlink(); // /usr/local/bin/virtctl -> the agent (fleet control client)
    mount_virtiofs(&cmdline);
    apply_symlinks(&cmdline);
    configure_network(&cmdline);
    apply_tmpfs(&cmdline); // RAM scratch dirs (e.g. CI /builds) before the payload starts
    // orphans reparent to PID 1 (this process): reap them.
    set_child_subreaper();

    // VIRTKIT_MODE=service: exec the image's captured entrypoint instead of serving.
    // A systemd image uses this too — its entrypoint execs /sbin/init (or a wrapper
    // that does), so the agent needs no dedicated "systemd" mode: handing off to the
    // image entrypoint is handing off to systemd.
    if cmdline.get("VIRTKIT_MODE").map(String::as_str) == Some("service") {
        return run_service(&cmdline);
    }

    maybe_ssh_serve(&cmdline);
    let serve = spawn_serve(socket, inactivity_timeout)?;
    install_term_handler();
    supervise(serve)
}

/// Mount the kernel API filesystems a from-scratch rootfs lacks. Best effort:
/// each may already be mounted (the initrd/kernel set some up) — tolerate it.
fn mount_api_filesystems() {
    // (source, target, fstype, flags)
    let mounts: &[(&str, &str, &str, libc::c_ulong)] = &[
        ("proc", "/proc", "proc", 0),
        ("sysfs", "/sys", "sysfs", 0),
        ("devtmpfs", "/dev", "devtmpfs", 0),
        ("devpts", "/dev/pts", "devpts", 0),
    ];
    for (src, target, fstype, flags) in mounts {
        let _ = std::fs::create_dir_all(target);
        if let Err(e) = mount(src, target, fstype, *flags)
            && e.raw_os_error() != Some(libc::EBUSY)
        // EBUSY = already mounted (the common case for /proc /sys /dev)
        {
            warn!("virtkit-agent init: mount {fstype} on {target} failed: {e}");
        }
    }
    // /run and /tmp as fresh tmpfs, but recreate the image's baked top-level dirs so
    // a service's runtime dir survives — e.g. /run/redis (owned by redis) that redis
    // binds its unix socket into. systemd-tmpfiles would recreate these; we have no
    // systemd, and a bare tmpfs mount would hide them.
    for target in ["/run", "/tmp"] {
        let _ = std::fs::create_dir_all(target);
        if let Err(e) = mount_tmpfs_keep_dirs(target, libc::MS_NOSUID | libc::MS_NODEV)
            && e.raw_os_error() != Some(libc::EBUSY)
        {
            warn!("virtkit-agent init: tmpfs on {target} failed: {e}");
        }
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

/// Bring loopback up (the VS Code server and many tools bind 127.0.0.1). Best effort.
fn bring_up_loopback() {
    if !run_cmd("ip", &["link", "set", "dev", "lo", "up"]) && !run_cmd("ifconfig", &["lo", "up"]) {
        warn!("virtkit-agent init: could not bring up loopback");
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
/// next to it, so `virtctl start mysql` works from the builder's PATH. Best effort;
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
        let _ = run_cmd("ip", &["addr", "add", ip, "dev", "eth0"]);
        let _ = run_cmd("ip", &["route", "add", "default", "via", gw]);
        if let Some(dns) = cmdline.get("VIRTKIT_VM_DNS") {
            let _ = std::fs::write("/etc/resolv.conf", format!("nameserver {dns}\n"));
        }
    }
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
    let keys = cmdline
        .get("VIRTKIT_SSH_KEYS")
        .cloned()
        .unwrap_or_else(|| "/workdir/docker/runner/authorized_keys".into());
    let user = cmdline
        .get("VIRTKIT_SSH_USER")
        .cloned()
        .unwrap_or_else(|| "dev".into());
    if !Path::new(&keys).exists() {
        warn!("virtkit-agent init: {keys} missing — ssh server disabled");
        return;
    }
    if let Err(e) = fork_agent(&[
        "--socket".into(),
        format!("vsock://{SSH_VSOCK_PORT}"),
        "ssh-serve".into(),
        "--authorized-keys".into(),
        keys,
        "--user".into(),
        user,
    ]) {
        warn!("virtkit-agent init: ssh server failed to start: {e}");
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
            warn!("virtkit-agent init: no captured command — exec /sbin/init");
            argv = vec!["/sbin/init".into()];
        } else {
            warn!("virtkit-agent init: no captured command (/etc/virtkit/cmd) — exec /bin/sh");
            argv = vec!["/bin/sh".into()];
        }
    }
    let user = std::fs::read_to_string("/etc/virtkit/user")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let argv = wrap_user(argv, &user);
    info!(
        "virtkit-agent init: service exec as {}: {:?}",
        if user.is_empty() { "root" } else { &user },
        argv
    );

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
    exec_argv(&argv); // never returns
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
    let exe = std::fs::read_link("/proc/self/exe").context("reading /proc/self/exe")?;
    let mut argv_owned = vec![cstr(&exe.to_string_lossy())];
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
