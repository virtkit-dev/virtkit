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
//!   VIRTKIT_VIRTIOFS_OVERLAY  tag[,tag] — mount these shares as the read-only lower
//!                        layer of a tmpfs-backed overlayfs at their path, so every
//!                        write under the mountpoint runs at guest-native speed. A
//!                        listed share that fails to overlay-mount fails the boot (no
//!                        silent fallback to the far slower direct mount)
//!   VIRTKIT_VIRTIOFS_OVERLAY_SIZE  how much of this VM's memory each overlay layer
//!                        above may take, as a tmpfs size= (e.g. 80%, 12G). Unset
//!                        leaves the kernel's own tmpfs default (half the RAM)
//!   VIRTKIT_DISKS        /dev/vdX:path[,/dev/vdX:path] — mount each already-formatted ext4
//!                        raw disk (a compose/`-v` `disk` volume) read-write at path, creating
//!                        it. Unlike a virtiofs share, this is a real block device: full POSIX
//!                        semantics (arbitrary chown, mknod, sockets), and content that
//!                        persists in the backing file across boots
//!   VIRTKIT_SYMLINKS     src:dest[,src:dest] — after virtiofs mounts, create each
//!                        `dest` as a symlink pointing to `src`. Entries where `src`
//!                        does not exist are silently skipped.
//!   VIRTKIT_TOOLS        tag:mountpoint — mount this virtio-fs share (read-only)
//!                        and link the CI tools it carries (git/git-lfs/…) onto
//!                        the PATH, skipping any the image already provides
//!   VIRTKIT_TMPFS        /path:size[,/path:size] RAM scratch dirs (e.g. CI /builds)
//!   VIRTKIT_ATOP         tag:mountpoint:interval_secs — mount this virtio-fs share
//!                        read-write and fork the guest statistics sampler on it: one
//!                        atop-parseable sample of this guest's /proc per interval,
//!                        appended to <mountpoint>/atop.log (see the `atop` module)
//!   VIRTKIT_CTL=1        mount the compose control fs at /run/vk/services (a FUSE
//!                        bridge to the host service manager over vsock). Honored on
//!                        the full-VM path too, which claims /run as a tmpfs first so
//!                        the image's own init does not mount over the bridge
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
//!   VIRTKIT_INACTIVITY_TIMEOUT  power off after this many seconds without an active
//!                        exec command (status probes do not reset the clock). Honored in
//!                        the default mode only: the service and full-VM paths arm no
//!                        watchdog, and their exec server is not what powers the VM off.
//!   VIRTKIT_INIT         the image takes PID 1 through the preinit handoff, and this
//!                        names what it becomes: `image` (the image's own init) or
//!                        `entrypoint` (the boot config's entrypoint+cmd). Absent: the
//!                        agent keeps PID 1 (the default and service modes below)
//!   VIRTKIT_HANDOFF      which init `VIRTKIT_INIT=image` execs (default /sbin/init)
//!   VIRTKIT_MODE=service fork the boot config's entrypoint; the agent stays as PID 1
//!                        and reaps orphans. A systemd image hands off via its entrypoint.
//!   VIRTKIT_SERVE=1      (service) also start the vsock exec server (port 4444) for
//!                        live debugging: `vk-agent -s vsock-mux://<vsock.sock>:4444 exec`
//!   VIRTKIT_DEBUG=1      (service) fork+wait the entrypoint, then hold the VM on exit
//!                        for post-mortem inspection (overrides VIRTKIT_SERVE)
//!
//! The whole module is sync: no tokio in PID 1.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use log::{info, warn};

use vk_core::addr::SocketAddr;
use vk_core::runcfg::{ImageInit, RunConfig};

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
    let inactivity_timeout = resolve_inactivity_timeout(inactivity_timeout, &cmdline);

    // A modular image kernel (`--kernel image`) ships its boot-critical modules on the
    // preinit initramfs with a `/virtkit-modules` load list — insmod them before any
    // path mounts /dev/vda, in BOTH init modes. Absent (pinned kernel, or a plain run)
    // there is no list, so this is a no-op.
    if std::path::Path::new("/virtkit-modules").exists() {
        load_preinit_modules();
    }

    // Image init (`vk run --init image|entrypoint`): the IMAGE takes PID 1. Handled
    // entirely by run_full_vm — pivot into the real root, fork a reparented serve, then
    // exec what the axis names (the image's init, or its entrypoint) so that, not this
    // agent, becomes PID 1. Gated on the cmdline token so every default-init boot path
    // stays unchanged.
    if let Some(axis) = cmdline.get("VIRTKIT_INIT") {
        match ImageInit::from_token(axis) {
            Some(axis) => return run_full_vm(socket, &cmdline, boot_config.as_ref(), axis),
            // Only this driver writes the token, so a value it does not name means the
            // two have drifted apart: say so instead of quietly keeping PID 1 and
            // serving a guest that never ran what the axis asked for.
            None => warn!("vk-agent init: unknown VIRTKIT_INIT={axis} — keeping PID 1"),
        }
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
    mount_virtiofs(&cmdline)?;
    mount_disks(&cmdline)?;
    apply_symlinks(&cmdline);
    link_ci_tools(&cmdline); // host CI tools (git/git-lfs/…) onto PATH, if the image lacks them
    maybe_atop(&cmdline); // record this guest's own stats, before anything else runs in it
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
    // After the last fork: the sampler is a thread, and forking with one running would leave a
    // child holding a lock it can only drop by exec'ing. Nothing has run in the guest yet — the
    // serve above only now begins accepting commands — so no writes go unwatched.
    crate::fsmark::watch();
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
    // devtmpfs alone leaves /dev/fd and friends absent, and the entrypoint this path
    // hands PID 1 to is a shell script as often as not: a `<(…)` in it would fail on
    // /dev/fd/<n> until the image's own init got around to creating the links.
    link_dev_std_fds();
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

/// Image-init handoff (`vk run --init image|entrypoint`): pivot into the real root,
/// apply the virtkit-provided setup the image's init won't do itself (the guest's name,
/// host volume mounts, symlinks, the ssh and exec serves, image env), fork a reparented
/// `vk-agent serve`, then exec what `axis` names — the image's own init (systemd), or its
/// entrypoint — so that becomes PID 1.
///
/// What is applied is that list and nothing more — whatever takes PID 1 next brings the
/// rest of the machine up itself (/dev/pts, /run, loopback, tmpfs scratch), the way an init
/// does. An entrypoint that needs those *without* exec'ing an init belongs in
/// `VIRTKIT_MODE=service`, which sets them up and forks it. /run is the one exception, and
/// only under `--compose`: the control fs mounted in it has to outlive the handoff, so
/// [`claim_run_tmpfs`] gets there first.
///
/// Any modular image kernel's boot-critical modules are already loaded by the caller
/// (`run_init`) before this runs — they must precede the pivot, which mounts the ext4
/// rootfs at `/dev/vda`. The serves are forked just before the exec; once the exec hands
/// PID 1 over, they reparent to the new PID 1 and keep carrying the run's `-- <cmd>` /
/// ssh over vsock. The guest's assigned address is applied before the handoff (see
/// `configure_network_fullvm`); everything else about the network stays the image's.
fn run_full_vm(
    socket: &SocketAddr,
    cmdline: &HashMap<String, String>,
    cfg: Option<&RunConfig>,
    axis: ImageInit,
) -> Result<()> {
    // The pivot is mandatory here: the whole point is to hand off to something in the
    // image — its own /sbin/init, or its entrypoint — and neither exists anywhere but the
    // real root. Unlike the serve-mode path (which can keep serving in place), continuing
    // without the pivot would just exec the initramfs's own tree — so fail loudly instead.
    pivot_to_real_root().context("vk-agent image-init: pivot to real root")?;
    // Re-mount /proc and /dev in the pivoted root before the setup below: the
    // pivot's MS_MOVE hid the initramfs mounts, so the new root has neither. /proc
    // is needed because `spawn_serve` execs `/proc/self/exe` (else exit 127); /dev
    // (devtmpfs) is needed for device nodes the setup opens, e.g. /dev/net/tun for
    // the eth0 bridge. systemd re-mounts these after the handoff (already-mounted is
    // fine).
    let _ = std::fs::create_dir_all("/proc");
    let _ = mount("proc", "/proc", "proc", 0);
    let _ = std::fs::create_dir_all("/dev");
    let _ = mount("devtmpfs", "/dev", "devtmpfs", 0);
    // Re-create the /dev/fd links directly rather than relying on the pre-pivot
    // devtmpfs (which carries them across this remount only because devtmpfs is a
    // single kernel-global instance, not a fresh tree per mount) — idempotent, and
    // keeps this call site correct even if that pivot ever changes.
    link_dev_std_fds();
    // /sys too: the interface state the setup below reads lives there
    // (/sys/class/net/<iface>), so without it the agent cannot see even the tap it
    // creates itself — it would look absent until the image's init mounted sysfs, long
    // after the handoff. Worth a warning, unlike the two above: the only symptom of a
    // missing /sys is an eth0 that never appears.
    let _ = std::fs::create_dir_all("/sys");
    if let Err(e) = mount("sysfs", "/sys", "sysfs", 0)
        && e.raw_os_error() != Some(libc::EBUSY)
    {
        warn!("vk-agent image-init: mounting /sys failed: {e} — eth0 will look absent");
    }

    // Apply only the virtkit-provided setup the image's own init won't do: the guest's name
    // (until the image's own init sets one), host volume mounts (`--volume`/`--workdir`),
    // symlinks, an eth0 bridge to the vk switch, and the run's env (so the served command
    // and ssh sessions inherit it). Each is a no-op unless its cmdline param is set.
    //
    // The name first, because what runs next reads it: an entrypoint that prepares the
    // machine (an appliance assembling itself) asks for the hostname long before any init
    // would set one, and without this it reads the kernel default `(none)` — which is not
    // a valid hostname to pass on. An image that ships /etc/hostname renames the host once
    // its own init applies that, leaving the /etc/hosts self-entry under the name set here —
    // harmless (it never shadows a *.lan DNS answer), and what the default path already does.
    set_hostname(cmdline);
    write_self_hosts(cmdline);
    load_image_env();
    apply_boot_config(cfg);
    materialize_env(cfg);
    claim_run_tmpfs(cmdline); // before the shares: a volume under /run must land on that tmpfs
    mount_virtiofs(cmdline)?;
    mount_disks(cmdline)?;
    apply_symlinks(cmdline);
    configure_network_fullvm(cmdline);

    // The vsock services the run exposes, forked before the exec so they reparent to
    // systemd and keep serving: ssh-serve (`--ssh`), the host-agent forwarder
    // (`--ssh-agent`), the compose control fs at /run/vk/services (`--compose`), and the
    // exec channel that carries `-- <cmd>`. All but the last are gated on their cmdline
    // params.
    maybe_ssh_serve(cmdline);
    maybe_ssh_agent(cmdline);
    maybe_ctlfs(cmdline);
    let _serve = spawn_serve(socket, None)?;

    // Only the entrypoint axis chdirs: /sbin/init neither has nor wants a workdir. It
    // precedes the exec so a relative entrypoint (`./prepare.sh`) resolves there.
    if let (ImageInit::Entrypoint, Some(cfg)) = (axis, cfg) {
        chdir_workdir(cfg);
    }
    let drop_ids = (axis == ImageInit::Entrypoint)
        .then(|| drop_ids_for_user(cfg.map_or("", |c| c.user.as_str())))
        .flatten();
    exec_first(&image_init_candidates(axis, cmdline, cfg, drop_ids)) // never returns
}

/// Become the first candidate that execs. `execvp` returns only when it failed, leaving
/// this process untouched, so it is what decides whether the image can actually become a
/// candidate — a probe here would have to predict PATH lookup, the execute bit, and a
/// shebang's interpreter, and be wrong about all three between the check and the exec.
/// Never returns: PID 1 exiting is a kernel panic, so the last candidate's failure is
/// terminal and [`exec_argv`] reports it.
fn exec_first(candidates: &[Vec<String>]) -> ! {
    let (last, rest) = candidates
        .split_last()
        .expect("image_init_candidates always offers the image's init");
    for argv in rest {
        info!("vk-agent image-init: exec {argv:?} (it takes PID 1)");
        let e = try_exec_argv(argv);
        warn!("vk-agent image-init: exec {argv:?} failed: {e} — trying the next candidate");
    }
    info!("vk-agent image-init: exec {last:?} (it takes PID 1)");
    exec_argv(last)
}

/// What PID 1 becomes after the handoff, as [`ImageInit`] names it — in preference order,
/// since only the exec itself can tell whether the image really carries a candidate.
///
/// [`ImageInit::Init`] offers the image's own init alone: `VIRTKIT_HANDOFF` if the host
/// named one, else `/sbin/init`. An image booted for its own init and missing it is broken,
/// and looks it — the boot ends the way it did before any of this.
///
/// [`ImageInit::Entrypoint`] leads with the image's ENTRYPOINT+CMD (merged host-side with
/// any compose override), exec'd — NOT forked as `VIRTKIT_MODE=service` does — so an
/// entrypoint that sets the machine up and then execs systemd hands PID 1 straight on.
/// Service mode cannot do that: systemd refuses to run anywhere but PID 1, which the agent
/// holds there. It runs as the image's `USER`, as service mode's `wrap_user` does, so one
/// image does not change hands between the two boot axes. An entrypoint that execs an init
/// still needs root, and an image declaring otherwise is broken under `docker run` too. A
/// host share carries no id map, so a non-root uid cannot create files in one.
///
/// The image's init and then a shell follow it, so an image with no entrypoint to exec — or
/// one PID 1 cannot exec — reaches a debuggable guest rather than exiting 127 from PID 1 and
/// panicking the kernel, the same ladder [`service_argv`] climbs. A drop spends that ladder:
/// PID 1 becomes `setpriv`, which execs and only then reports, so anything it finds wrong is
/// terminal. That is why [`drop_ids_for_user`] settles the drop before the exec and hands
/// over ids it has already resolved.
fn image_init_candidates(
    axis: ImageInit,
    cmdline: &HashMap<String, String>,
    cfg: Option<&RunConfig>,
    drop_ids: Option<(u32, u32)>,
) -> Vec<Vec<String>> {
    let init = vec![
        cmdline
            .get("VIRTKIT_HANDOFF")
            .cloned()
            .unwrap_or_else(|| "/sbin/init".to_string()),
    ];
    if axis == ImageInit::Init {
        return vec![init];
    }
    let mut candidates = Vec::new();
    // ENTRYPOINT+CMD and the USER that owns them come from the same config.
    if let Some((entrypoint, user)) = cfg
        .map(|c| (c.argv(), c.user.as_str()))
        .filter(|(argv, _)| !argv.is_empty())
    {
        // Only this candidate is dropped to the USER: the init below it must be root, and so
        // must the debug shell that follows, or a mis-declared image would land somewhere it
        // cannot work at all.
        candidates.push(if let Some((uid, gid)) = drop_ids {
            info!(
                "vk-agent image-init: entrypoint runs as the image's USER {user} ({uid}:{gid}), \
                 as `docker run` does — an entrypoint that execs an init needs root (declare \
                 `user: root` to keep it)"
            );
            setpriv_wrap(entrypoint, &uid.to_string(), &gid.to_string())
        } else {
            entrypoint
        });
    } else {
        warn!("vk-agent image-init: no entrypoint in the boot config — falling back to the init");
    }
    candidates.push(init);
    candidates.push(vec!["/bin/sh".to_string()]);
    candidates
}

/// The ids to hand the entrypoint over as, or `None` to keep root. Settled before the exec
/// rather than discovered by it, because PID 1 becomes `setpriv`, which execs fine and only
/// then reports that it cannot become the user — and PID 1 exiting panics the kernel, so
/// [`exec_first`]'s ladder never gets its turn.
///
/// The USER has to have a passwd entry in the image: the ids come out of that entry, because
/// `setpriv --init-groups` looks the uid up itself and fails on a `USER 1000` no passwd knows,
/// and `--regid` given a name needs a group of that name, which a user's own primary group
/// need not have. Handing over `pw_uid`/`pw_gid` asks neither question. The image also has to
/// carry a `setpriv` that can make the drop, which is a question only the drop itself answers
/// — busybox provides the name without `--reuid`. Any miss keeps the entrypoint at root, with
/// the reason on the console.
fn drop_ids_for_user(user: &str) -> Option<(u32, u32)> {
    if user.is_empty() || user == "root" {
        return None;
    }
    let (uid, gid) = match passwd_ids(user) {
        // `USER 0` is root under another name; nothing to drop, and setpriv would be noise.
        Some((0, _)) => return None,
        Some(ids) => ids,
        None => {
            warn!(
                "vk-agent image-init: USER {user} has no passwd entry in the image — keeping root"
            );
            return None;
        }
    };
    if !setpriv_can_drop("setpriv", uid, gid) {
        warn!(
            "vk-agent image-init: no setpriv in the image that can drop to USER {user} \
             ({uid}:{gid}) — keeping root"
        );
        return None;
    }
    Some((uid, gid))
}

/// Whether `prog` can actually drop to `uid`/`gid`, asked by making the drop in a child that
/// does nothing but print a version. PID 1 cannot ask: it *becomes* `setpriv`, and a busybox
/// one — the name without the flags — execs fine and then exits, which panics the kernel.
/// Unlike the exec-time discovery [`exec_first`] relies on, a wrong answer here is safe: it
/// only keeps the entrypoint at root.
fn setpriv_can_drop(prog: &str, uid: u32, gid: u32) -> bool {
    let (uid, gid) = (uid.to_string(), gid.to_string());
    run_cmd(
        prog,
        &[
            "--reuid",
            &uid,
            "--regid",
            &gid,
            "--init-groups",
            "--",
            "/proc/self/exe",
            "--version",
        ],
    )
}

/// The image's own passwd entry for `user` — a name via `getpwnam`, a number via `getpwuid` —
/// as (uid, gid). `None` when the image's passwd does not have it.
fn passwd_ids(user: &str) -> Option<(u32, u32)> {
    // SAFETY: getpwnam/getpwuid return a pointer into a static buffer (single-threaded,
    // short-lived process); we read two fields before any further call.
    unsafe {
        let p = match user.parse::<u32>() {
            Ok(uid) => libc::getpwuid(uid),
            Err(_) => libc::getpwnam(CString::new(user).ok()?.as_ptr()),
        };
        if p.is_null() {
            return None;
        }
        Some(((*p).pw_uid, (*p).pw_gid))
    }
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

/// The standard /dev file-descriptor symlinks. devtmpfs does not create these (a
/// container runtime/udev normally would), but shells rely on them: bash process
/// substitution `<(…)` opens /dev/fd/<n>, and scripts read /dev/stdin et al. Both init
/// paths need them — the image-init one before it hands PID 1 to a script that may use
/// either, since the init that would create them has not run yet.
fn link_dev_std_fds() {
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
    // What an earlier boot of this image already claimed, read once for the whole table.
    let noted = crate::diskmount::ephemeral_registry();
    // (source, target, fstype, flags)
    let mounts: &[(&str, &str, &str, libc::c_ulong)] = &[
        ("proc", "/proc", "proc", 0),
        ("sysfs", "/sys", "sysfs", 0),
        ("devtmpfs", "/dev", "devtmpfs", 0),
        ("devpts", "/dev/pts", "devpts", 0),
        // POSIX shared memory: devtmpfs does not provide /dev/shm, but Python's
        // multiprocessing (shared_memory, semaphores) and other libs need it — without
        // it they fail with ENOENT on /dev/shm. tmpfs defaults to mode 1777 (like /tmp),
        // so an unprivileged process can create segments. Mounted after /dev exists.
        (
            "tmpfs",
            "/dev/shm",
            "tmpfs",
            libc::MS_NOSUID | libc::MS_NODEV,
        ),
    ];
    for (src, target, fstype, flags) in mounts {
        if is_ephemeral_mountpoint(&noted, target) {
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
    link_dev_std_fds();
    // /dev/kvm, when nested virtualization gave this guest one: devtmpfs creates it
    // root-only and there is no udev here to widen it, so an unprivileged in-guest
    // process (a `vk exec --user` shell, a CI job) could not boot a microVM of its own.
    // Absent on a guest whose CPUID carries no VMX/SVM — its kvm module then registers
    // no node, which is the NotFound below. Present even unasked on cloud-hypervisor,
    // which cannot mask the host's bit; harmless, because the isolation boundary is the
    // VM around this and no host access is handed out here.
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions("/dev/kvm", std::fs::Permissions::from_mode(0o666))
            && e.kind() != io::ErrorKind::NotFound
        {
            warn!("vk-agent init: chmod /dev/kvm failed: {e}");
        }
    }
    // /run and /tmp as fresh tmpfs, but recreate the image's baked top-level dirs so
    // a service's runtime dir survives — e.g. /run/redis (owned by redis) that redis
    // binds its unix socket into. systemd-tmpfiles would recreate these; we have no
    // systemd, and a bare tmpfs mount would hide them.
    //
    // /run gets the mount an init would have given it (RUN_TMPFS_FLAGS/RUN_TMPFS_DATA)
    // rather than the kernel tmpfs default: root's, as it is on any real system, and
    // bounded. /tmp keeps that default, where 1777 is what it should be.
    //
    // /tmp is the exception when a build hands us a disk-backed scratch device
    // (VIRTKIT_TMP_DEV): a build's RUN steps write bulk transient data (tar extractions,
    // ./configure) to /tmp, and a RAM tmpfs caps that at ½·guest-RAM. The device is a
    // separate, sparse ext4 disk — not RAM-bound, and never part of the stage snapshot — so
    // it stays a fresh mount that leaks nothing into the image.
    let tmp_dev = tmp_dev_from_cmdline();
    for target in ["/run", "/tmp"] {
        if is_ephemeral_mountpoint(&noted, target) {
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
        } else if target == "/run" {
            mount_tmpfs_keep_dirs(target, RUN_TMPFS_FLAGS, RUN_TMPFS_DATA)
        } else {
            mount_tmpfs_keep_dirs(target, libc::MS_NOSUID | libc::MS_NODEV, "")
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
    // so the pre-commit cleanup can remove them from a FROM scratch image. A mountpoint that
    // is itself image content is recorded in the image as well as on tmpfs, so a build that
    // restores a mid-stage snapshot still knows the directory is the agent's and not the
    // base's. /dev/pts and /dev/shm are not: their entries live on the devtmpfs mounted over
    // /dev, so they never reach the image, and the next boot finds them missing again anyway.
    // Recording them there would put the registry file into every image built — even on a base
    // that ships every API mountpoint — and cost the host a re-push to take it back out.
    for target in created {
        let p = std::path::Path::new(target);
        if p.parent() == Some(std::path::Path::new("/")) {
            crate::diskmount::note_ephemeral(p);
        } else {
            crate::diskmount::note_created(p);
        }
    }
    Ok(())
}

/// Whether `target` is a mountpoint the agent owns rather than one the base image ships:
/// either it is not there yet, or an earlier boot of this image already recorded it as ours
/// in `noted` (the in-image registry) and a snapshot carried it here.
fn is_ephemeral_mountpoint(noted: &str, target: &str) -> bool {
    let p = std::path::Path::new(target);
    !p.exists() || crate::diskmount::noted_ephemeral_in(noted, p)
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

/// Mount a fresh tmpfs on `target` with `data` as its tmpfs options (empty for the
/// kernel defaults), first snapshotting its underlying top-level directories (name, mode,
/// uid, gid) and recreating them on the new tmpfs — so a service's baked runtime dir
/// (e.g. /run/redis owned by redis) isn't hidden.
fn mount_tmpfs_keep_dirs(target: &str, flags: libc::c_ulong, data: &str) -> io::Result<()> {
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
    mount_data("tmpfs", target, "tmpfs", flags, data)?;
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

/// An explicit `vk-agent init` argument wins; PID 1 normally has no usable argv, so
/// `vk run` carries the same value on the kernel cmdline. Zero means no watchdog.
fn resolve_inactivity_timeout(
    explicit: Option<u64>,
    cmdline: &HashMap<String, String>,
) -> Option<u64> {
    explicit
        .or_else(|| {
            cmdline
                .get("VIRTKIT_INACTIVITY_TIMEOUT")
                .and_then(|value| value.parse().ok())
        })
        .filter(|timeout| *timeout > 0)
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
///
/// Tags listed in VIRTKIT_VIRTIOFS_OVERLAY are not mounted at their path directly: the
/// share becomes the read-only lower layer of an overlayfs whose upper/work live on a
/// guest tmpfs, so writes under the path never cross virtio-fs (each synchronous
/// create/write/unlink round-trip costs 50–90µs vs ~2µs on tmpfs). An overlay share
/// that fails to mount fails the boot: falling back to the direct mount would silently
/// run the workload 15–50× slower.
fn mount_virtiofs(cmdline: &HashMap<String, String>) -> Result<()> {
    let mut overlay = overlay_tags(cmdline)?;
    let size = overlay_size(cmdline)?;
    let Some(spec) = cmdline.get("VIRTKIT_VIRTIOFS") else {
        if !overlay.is_empty() {
            bail!(
                "VIRTKIT_VIRTIOFS_OVERLAY names {} but VIRTKIT_VIRTIOFS declares no shares",
                sorted_join(&overlay)
            );
        }
        return Ok(());
    };
    let _ = run_cmd("modprobe", &["virtiofs"]); // built-in on our kernel; harmless
    let mut overlaid: HashSet<String> = HashSet::new();
    for entry in spec.split(',').filter(|e| !e.is_empty()) {
        let Some((tag, path)) = entry.split_once(':') else {
            warn!("vk-agent init: bad VIRTKIT_VIRTIOFS entry {entry:?} (want tag:path)");
            continue;
        };
        if overlay.remove(tag) {
            mount_share_overlay(tag, path, size)
                .with_context(|| format!("overlay-mounting virtiofs share {tag} at {path}"))?;
            overlaid.insert(tag.to_string());
            continue;
        }
        // A duplicated overlay tag must not fall through here: the plain mount would
        // silently shadow the overlay and restore the very slowdown it exists to avoid.
        if overlaid.contains(tag) {
            bail!("VIRTKIT_VIRTIOFS lists overlay share {tag} more than once");
        }
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
    if !overlay.is_empty() {
        bail!(
            "VIRTKIT_VIRTIOFS_OVERLAY names {} but VIRTKIT_VIRTIOFS declares no such share",
            sorted_join(&overlay)
        );
    }
    Ok(())
}

/// Mount each `VIRTKIT_DISKS=/dev/vdX:path[,/dev/vdX:path]` entry — a compose/`-v` `disk`
/// volume's already-formatted ext4 raw disk — read-write at path, creating it. Unlike a
/// virtiofs share, this is a real block device: no host-side ownership mapping, so the guest
/// gets full POSIX semantics (arbitrary chown, mknod, sockets), and — being the host's own
/// file, not a tmpfs layer — its content persists across boots. A disk that fails to mount
/// fails the boot: the volume is why the service exists, so silently starting without it is
/// worse than not starting.
fn mount_disks(cmdline: &HashMap<String, String>) -> Result<()> {
    let Some(spec) = cmdline.get("VIRTKIT_DISKS") else {
        return Ok(());
    };
    for entry in spec.split(',').filter(|e| !e.is_empty()) {
        let Some((device, path)) = entry.split_once(':') else {
            bail!("bad VIRTKIT_DISKS entry {entry:?} (want /dev/vdX:path)");
        };
        let target = Path::new(path);
        let created_parents = create_mountpoint(target)
            .with_context(|| format!("creating disk mountpoint {}", target.display()))?;
        mount(device, path, "ext4", libc::MS_NOSUID | libc::MS_NODEV)
            .with_context(|| format!("mounting disk {device} at {}", target.display()))?;
        chown_created_mount_parents(target, &created_parents);
    }
    Ok(())
}

/// Root under which overlay-backed shares keep their private lower/upper/work mounts.
pub(crate) const OVERLAY_ROOT: &str = "/run/virtkit-overlay";

/// The tmpfs holding one overlay's upper+work, under its private directory. Named here rather
/// than spelled twice because [`crate::fsmark`] measures that layer from the outside and must
/// not drift from where [`overlay_dirs`] mounts it.
pub(crate) const OVERLAY_RW: &str = "rw";

/// The share tags VIRTKIT_VIRTIOFS_OVERLAY marks for an in-guest overlay.
///
/// A tag becomes a path component under OVERLAY_ROOT, so anything that would escape it
/// (`/`, `.`, `..`) is rejected rather than resolved outside the private root.
fn overlay_tags(cmdline: &HashMap<String, String>) -> Result<HashSet<String>> {
    let Some(spec) = cmdline.get("VIRTKIT_VIRTIOFS_OVERLAY") else {
        return Ok(HashSet::new());
    };
    let mut tags = HashSet::new();
    for tag in spec.split(',').filter(|t| !t.is_empty()) {
        if tag.contains('/') || tag == "." || tag == ".." {
            bail!("VIRTKIT_VIRTIOFS_OVERLAY tag {tag:?} is not a valid share tag");
        }
        tags.insert(tag.to_string());
    }
    Ok(tags)
}

/// How much of this VM's memory an overlay layer may take, from
/// VIRTKIT_VIRTIOFS_OVERLAY_SIZE: a tmpfs `size=` value, either a percentage of the RAM
/// (`80%`) or an absolute size (`12G`). `None` where the host named none, which leaves the
/// kernel's own tmpfs default of half the RAM.
///
/// Validated here as well as host-side, because the value ends up inside a mount option list:
/// a token carrying a comma would mount the layer with options nobody asked for, and one
/// carrying nonsense would fail the mount long after the cause is visible. A boot with a size
/// this agent cannot make sense of is refused rather than quietly given a different layer.
fn overlay_size(cmdline: &HashMap<String, String>) -> Result<Option<&str>> {
    let Some(spec) = cmdline.get("VIRTKIT_VIRTIOFS_OVERLAY_SIZE") else {
        return Ok(None);
    };
    let split = spec
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(spec.len());
    let (digits, unit) = spec.split_at(split);
    if digits.is_empty() || !matches!(unit, "" | "%" | "k" | "K" | "m" | "M" | "g" | "G") {
        bail!("VIRTKIT_VIRTIOFS_OVERLAY_SIZE {spec:?} is not a tmpfs size (e.g. 80%, 12G)");
    }
    Ok(Some(spec))
}

/// The tags of a set, sorted and comma-joined for a stable error message.
fn sorted_join(tags: &HashSet<String>) -> String {
    let mut tags: Vec<&str> = tags.iter().map(String::as_str).collect();
    tags.sort_unstable();
    tags.join(", ")
}

/// The private paths backing one overlay share.
struct OverlayDirs {
    /// The read-only virtiofs mount serving as the overlay's lower layer.
    lower: String,
    /// The tmpfs mountpoint holding upper+work.
    rw: String,
    upper: String,
    work: String,
}

fn overlay_dirs(tag: &str) -> OverlayDirs {
    let base = format!("{OVERLAY_ROOT}/{tag}");
    let rw = format!("{base}/{OVERLAY_RW}");
    OverlayDirs {
        lower: format!("{base}/lower"),
        upper: format!("{rw}/upper"),
        work: format!("{rw}/work"),
        rw,
    }
}

/// The overlay mount data string. `redirect_dir=on`: builds rename directories, and
/// without it rename(2) of a lower dir fails with EXDEV. `metacopy=on`: chmod/chown of
/// a lower file copies up its metadata only, not the data. `index=off`: the index
/// feature needs exportfs (file-handle) support the virtiofs lower lacks; the cost is
/// only that a lower hardlink copies up as independent files.
fn overlay_data(lower: &str, upper: &str, work: &str) -> String {
    format!(
        "lowerdir={lower},upperdir={upper},workdir={work},redirect_dir=on,metacopy=on,index=off"
    )
}

/// The overlay upper tmpfs's mount options. Without a `size=` the kernel caps it at half the
/// RAM, which is its default for a general-purpose machine rather than a choice made here.
fn overlay_tmpfs_data(size: Option<&str>) -> String {
    match size {
        Some(size) => format!("mode=0755,size={size}"),
        None => "mode=0755".to_string(),
    }
}

/// Mount the virtiofs share `tag` at `path` behind an overlayfs: the share is the
/// read-only lower layer, upper/work live on a dedicated guest tmpfs of `size` (`None` =
/// the kernel's own default). Only first-touch reads of lower files cross virtio-fs (and
/// then stay in the guest page cache); the host never sees guest writes.
fn mount_share_overlay(tag: &str, path: &str, size: Option<&str>) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let OverlayDirs {
        lower,
        rw,
        upper,
        work,
    } = overlay_dirs(tag);
    std::fs::create_dir_all(&lower).with_context(|| format!("creating {lower}"))?;
    mount(tag, &lower, "virtiofs", libc::MS_RDONLY)
        .with_context(|| format!("mounting virtiofs {tag} (lower layer) at {lower}"))?;
    // A dedicated tmpfs (not the shared /run) keeps bulk build writes away from the
    // agent's runtime dirs. Its size is what a build tree has to fit under, so the host
    // states it (`[gitlab] checkout_overlay_size`); told nothing, the kernel's own tmpfs
    // default of half the RAM applies, and the VM memory size is the lever either way.
    std::fs::create_dir_all(&rw).with_context(|| format!("creating {rw}"))?;
    mount_data(
        "tmpfs",
        &rw,
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOATIME,
        &overlay_tmpfs_data(size),
    )
    .with_context(|| format!("mounting the overlay upper tmpfs at {rw}"))?;
    std::fs::create_dir(&upper).with_context(|| format!("creating {upper}"))?;
    std::fs::create_dir(&work).with_context(|| format!("creating {work}"))?;
    // A dir present in both layers takes its merged metadata from the UPPER one: the
    // upper root must replicate the lower root's ownership/mode, or the merged tree
    // would appear root-owned 0755 and the mapped job user could not create files in it.
    let meta = std::fs::metadata(&lower).with_context(|| format!("stat {lower}"))?;
    std::os::unix::fs::chown(&upper, Some(meta.uid()), Some(meta.gid()))
        .with_context(|| format!("chown {upper} to the share owner"))?;
    std::fs::set_permissions(
        &upper,
        std::fs::Permissions::from_mode(meta.mode() & 0o7777),
    )
    .with_context(|| format!("chmod {upper} to the share mode"))?;
    let mountpoint = Path::new(path);
    let created_parents = create_mountpoint(mountpoint)
        .with_context(|| format!("creating overlay mountpoint {path}"))?;
    mount_data(
        "overlay",
        path,
        "overlay",
        0,
        &overlay_data(&lower, &upper, &work),
    )
    .with_context(|| format!("mounting the overlay at {path}"))?;
    chown_created_mount_parents(mountpoint, &created_parents);
    Ok(())
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

/// `VIRTKIT_ATOP=tag:mountpoint:interval_secs`: mount the host's per-job statistics
/// archive read-write and fork the sampler onto it, so the guest records what the job
/// running in it does — every tick, page and byte belongs to that one job (see the
/// `atop` module for the format). The sampler's pid is left in
/// [`vk_core::atop::PID_FILE`] for the host to signal at the end of the job.
///
/// Best effort throughout: a job whose stats cannot be recorded still runs.
fn maybe_atop(cmdline: &HashMap<String, String>) {
    let Some(spec) = cmdline.get("VIRTKIT_ATOP") else {
        return;
    };
    let Some((tag, mnt, interval)) = vk_core::atop::parse_knob(spec) else {
        warn!("vk-agent init: bad VIRTKIT_ATOP {spec:?} (want tag:mountpoint:interval_secs)");
        return;
    };
    // The same mountpoint handling as every other share (see mount_virtiofs): virtiofs
    // itself is built into the pinned guest kernel, so there is nothing to load first.
    if let Err(e) = create_mountpoint(Path::new(mnt)) {
        warn!("vk-agent init: creating stats mountpoint {mnt} failed: {e}");
        return;
    }
    if let Err(e) = mount(tag, mnt, "virtiofs", 0) {
        warn!("vk-agent init: mount stats archive {tag} at {mnt} failed: {e}");
        return;
    }
    // Written here rather than by the sampler: the pid is known the moment the fork
    // returns, so the host never races a child that has not got round to it.
    match fork_agent(&["atop".into(), mnt.into(), interval.to_string()]) {
        Ok(pid) => {
            if let Err(e) = std::fs::write(vk_core::atop::PID_FILE, pid.to_string()) {
                warn!("vk-agent init: writing {}: {e}", vk_core::atop::PID_FILE);
            }
            info!("vk-agent init: stats sampler on {mnt} every {interval}s (pid {pid})");
        }
        Err(e) => warn!("vk-agent init: stats sampler failed to start: {e}"),
    }
}

/// Bring eth0 up on the shared LAN: fork the tap bridge (`net`) to the host
/// switch over VIRTKIT_NET_PORT, then DHCP or a static address.
/// Argv for the `vk-agent net` tap bridge: the vsock backend + eth0, plus the
/// run-assigned `--mac` when `VIRTKIT_VM_MAC` is set (so an image-init sibling that
/// DHCPs eth0 matches the switch's per-MAC reservation and lands on its advertised
/// IP). Absent the var, the tap keeps a kernel-random MAC — today's behavior.
fn net_args(port: &str, cmdline: &HashMap<String, String>) -> Vec<String> {
    let mut args = vec![
        "--socket".into(),
        format!("vsock://{port}"),
        "net".into(),
        "--iface".into(),
        "eth0".into(),
    ];
    if let Some(mac) = cmdline.get("VIRTKIT_VM_MAC") {
        args.push("--mac".into());
        args.push(mac.clone());
    }
    args
}

/// The gateway to use when the run assigned an address but no `VIRTKIT_VM_GW` — the vk
/// switch's own address in the default subnet. Every producer sets the param; this is the
/// fallback both network paths share.
const DEFAULT_GATEWAY: &str = "192.168.127.1";

/// How long to wait for the switch to answer ARP for the gateway, in 100 ms tries. The ioctl
/// sets the address instantly, but the forked bridge still has to dial the host switch before
/// frames flow: a first DNS query dropped into a not-yet-forwarding bridge fails name
/// resolution outright (getaddrinfo exhausts its retries). The switch itself answers ARP for
/// the gateway, so the probe works under any egress policy.
const GATEWAY_TRIES: u32 = 100;

fn configure_network(cmdline: &HashMap<String, String>) {
    let Some(port) = cmdline.get("VIRTKIT_NET_PORT") else {
        return;
    };
    // The bridge is long-running (reaped by supervise; inherited by the service on
    // exec). It carries ethernet frames over vsock with no host privileges.
    if let Err(e) = fork_agent(&net_args(port, cmdline)) {
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
            .map_or(DEFAULT_GATEWAY, String::as_str);
        // ioctls, not `ip`: minimal glibc images (debian:*-slim) ship no iproute2, so
        // shelling out left them with no address/route and a broken resolver. The gateway
        // wait is skipped when addressing failed — there is nothing to wait for.
        if let Err(e) = set_static_network(ip, gw) {
            warn!("vk-agent init: configuring eth0 {ip} via {gw} failed: {e:#}");
        } else if !wait_for_gateway(gw, GATEWAY_TRIES) {
            warn!(
                "vk-agent init: gateway {gw} unreachable after {}s; continuing anyway",
                GATEWAY_TRIES / 10
            );
        }
    }
    // DNS is written separately (write_resolv_conf) so it applies to the kernel `ip=`
    // pool net too, not just this vsock-bridge static path.
}

/// Full-VM networking: create the eth0 tap bridged to the vk switch over vsock, bring
/// its link up, and give it the address the run assigned this guest
/// (`VIRTKIT_VM_IP`/`VIRTKIT_VM_GW`) — the same one the switch's DHCP would hand back,
/// so applying it directly settles the address instead of waiting to see whether the
/// image does. A run without an assigned address keeps the old behaviour: give the
/// image's own client a grace period, then fall back to `dhclient`.
///
/// The assigned address is applied before the exec; only the DHCP fallback waits in a forked
/// child, which reparents to the image's init after the exec — as the bridge itself does.
fn configure_network_fullvm(cmdline: &HashMap<String, String>) {
    // How long to wait for eth0 to appear, in 100 ms tries. The interface is the tap the
    // agent creates itself, visible in /sys the moment the bridge helper makes it, so this
    // is a guard against that helper failing to start — not a race to lose. The inline wait
    // is paid before PID 1 is handed over, so it is the shorter of the two; the fallback
    // child blocks nothing and keeps the 15 s it always waited.
    const IFACE_TRIES: u32 = 100;
    const IFACE_TRIES_FALLBACK: u32 = 150;
    let Some(port) = cmdline.get("VIRTKIT_NET_PORT") else {
        return;
    };
    if let Err(e) = fork_agent(&net_args(port, cmdline)) {
        warn!("vk-agent image-init: net bridge failed to start: {e}");
        return;
    }
    if let Some(ip) = cmdline.get("VIRTKIT_VM_IP") {
        let gw = cmdline
            .get("VIRTKIT_VM_GW")
            .map_or(DEFAULT_GATEWAY, String::as_str);
        // Addressed here, before PID 1 is handed over: whatever runs next may need the
        // network in its first seconds — an appliance that configures itself from the
        // running interface does — and a child racing it cannot promise that. The tap is
        // ours, so it appears as soon as the bridge helper above creates it.
        //
        // ioctls, not `ip`: minimal images ship no iproute2. An image client that DHCPs
        // later lands on this same address — the switch's first pool lease is this guest's
        // own index, and a sibling holds a per-MAC reservation — so this cannot disagree
        // with what the image believes.
        if !wait_for_iface("eth0", IFACE_TRIES) {
            warn!("vk-agent image-init: eth0 never appeared — leaving it to the image");
        } else if let Err(e) = set_static_network(ip, gw) {
            warn!("vk-agent image-init: configuring eth0 {ip} via {gw} failed: {e:#}");
        } else {
            info!("vk-agent image-init: eth0 {ip} via {gw}");
            // Wait for the gateway as the default path does: the address is instant, the
            // forked bridge's dial to the switch is not, and what takes PID 1 next should
            // not lose its first DNS query into a bridge that is not forwarding yet.
            if !wait_for_gateway(gw, GATEWAY_TRIES) {
                warn!(
                    "vk-agent image-init: gateway {gw} unreachable after {}s; continuing anyway",
                    GATEWAY_TRIES / 10
                );
            }
        }
    } else {
        // No address assigned to this guest, so the image's own client owns addressing.
        // Wait for it in a child (it may take a while, and nothing here should block the
        // handoff on it), then step in with dhclient only if it did nothing.
        // SAFETY: single-threaded preinit (no tokio); the child only waits and runs a
        // helper before _exit.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            warn!(
                "vk-agent image-init: fork for the dhclient fallback failed: {} — eth0 is \
                 the image's alone",
                io::Error::last_os_error()
            );
        } else if pid == 0 {
            if !wait_for_iface("eth0", IFACE_TRIES_FALLBACK) {
                warn!("vk-agent image-init: eth0 never appeared");
                unsafe { libc::_exit(0) };
            }
            // Head start for the image's own client; step in only if it did nothing.
            std::thread::sleep(Duration::from_secs(8));
            if iface_configured("eth0") {
                info!("vk-agent image-init: eth0 configured by the image");
            } else {
                info!("vk-agent image-init: image did not configure eth0 — running dhclient");
                if !run_cmd("dhclient", &["-1", "eth0"]) {
                    warn!(
                        "vk-agent image-init: dhclient fallback failed (no dhcp client in image?)"
                    );
                }
            }
            unsafe { libc::_exit(0) };
        }
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

/// Wait up to `tries` × 100 ms for the default gateway to become reachable. A poke
/// datagram makes the kernel ARP for the gateway (payload irrelevant — a drop while the
/// bridge is still connecting just re-ARPs next poll); a completed `/proc/net/arp` entry
/// means the switch answered, i.e. the bridge is forwarding. The switch itself answers
/// ARP for the gateway, so the probe works under any egress policy.
fn wait_for_gateway(gw: &str, tries: u32) -> bool {
    for _ in 0..tries {
        if let Ok(sock) = std::net::UdpSocket::bind("0.0.0.0:0") {
            let _ = sock.send_to(&[0], (gw, 53));
        }
        if gateway_reachable(gw) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// True when `/proc/net/arp` lists `gw` with a resolved hardware address (ATF_COM set).
fn gateway_reachable(gw: &str) -> bool {
    std::fs::read_to_string("/proc/net/arp")
        .map(|text| arp_has_resolved_entry(&text, gw))
        .unwrap_or(false)
}

/// True when an `/proc/net/arp` dump lists `gw` with the ATF_COM flag set — a resolved
/// hardware address. Columns: IP address, HW type, Flags, HW address, Mask, Device.
fn arp_has_resolved_entry(text: &str, gw: &str) -> bool {
    /// `/proc/net/arp` flag for a completed (resolved) entry — `ATF_COM`.
    const ATF_COM: u32 = 0x2;
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3
            && cols[0] == gw
            && let Ok(flags) = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16)
        {
            return flags & ATF_COM != 0;
        }
    }
    false
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

/// Whether the run manages compose services (`VIRTKIT_CTL=1`) — the one gate
/// `claim_run_tmpfs` and `maybe_ctlfs` must agree on, since a claim without the control fs
/// is a pointless tmpfs and a control fs without the claim is the mount an image's init
/// hides.
fn ctl_enabled(cmdline: &HashMap<String, String>) -> bool {
    cmdline.get("VIRTKIT_CTL").map(String::as_str) == Some("1")
}

/// VIRTKIT_CTL=1: fork the agent's `ctlfs` — the compose control plane mounted
/// at /run/vk/services (each operation bridges to the host manager over vsock).
/// Mounted one level down so /run/vk stays a plain directory with room for the
/// run's other endpoints. Its nodes are attributed to the run's own user, so a
/// primary that runs as the image's `USER` can drive its siblings — off the same
/// `VIRTKIT_DEFAULT_RUN_USER` the exec server drops served commands by. The variable, not a
/// `RunConfig`: the default path has none to read (a plain `vk run` carries no boot config),
/// where only the `/etc/virtkit/user` capture names the user, and the run's other endpoints
/// read it the same way.
fn maybe_ctlfs(cmdline: &HashMap<String, String>) {
    if !ctl_enabled(cmdline) {
        return;
    }
    let (uid, gid) = ctl_owner_ids(&std::env::var("VIRTKIT_DEFAULT_RUN_USER").unwrap_or_default());
    if let Err(e) = fork_agent(&[
        "ctlfs".into(),
        "/run/vk/services".into(),
        uid.to_string(),
        gid.to_string(),
    ]) {
        warn!("vk-agent init: control fs failed to start: {e}");
    }
}

/// The ids the control fs attributes its nodes to. The run's own user owns them — writing a
/// `ctl` file is the run's business, and a primary the image declares a `USER` for is not root
/// once it drops (`--init entrypoint`) or once a served command does.
///
/// Resolved by the same [`vk_core::exec::server::resolve_user`] the served commands are dropped
/// with, off the same `VIRTKIT_DEFAULT_RUN_USER` the exec server reads, so the owner is the uid
/// those processes actually get: a `USER` the image's passwd does not list still resolves — as a
/// bare uid with gid 0, the way `docker run --user <uid>` does — and a `user:group` spec takes
/// its gid from the group half. `drop_ids_for_user` cannot share this: `setpriv --init-groups`
/// needs a real passwd entry, where the kernel checking this mount needs only the number. So
/// the two can disagree — an image with no usable `setpriv` keeps a root entrypoint while these
/// nodes are the USER's; root writes them anyway (`CAP_DAC_OVERRIDE`), so the mismatch costs
/// nothing and is not worth reconciling.
///
/// Root when the image declares no user, and when the spec does not resolve at all.
fn ctl_owner_ids(user: &str) -> (u32, u32) {
    if user.is_empty() || user == "root" {
        return (0, 0);
    }
    match vk_core::exec::server::resolve_user(user) {
        Ok(ru) => (ru.uid, ru.gid),
        Err(e) => {
            warn!(
                "vk-agent init: USER {user} does not resolve ({e}) — the control fs stays root's"
            );
            (0, 0)
        }
    }
}

// The flags and tmpfs options systemd's own `mount_setup` mounts /run with (`mode=0755` +
// `TMPFS_LIMITS_RUN`, systemd v257) — not the kernel tmpfs default, which is 1777 and capped
// only at ½·guest-RAM. Both init paths mount /run this way: `mount_api_filesystems` for the
// guest the agent keeps, `claim_run_tmpfs` for the one it hands to the image — which then
// finds the /run it would have mounted itself, options and all.
const RUN_TMPFS_FLAGS: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_STRICTATIME;
const RUN_TMPFS_DATA: &str = "mode=0755,size=20%,nr_inodes=800k";

/// VIRTKIT_CTL=1 in the full-VM path: claim /run as a tmpfs before the control fs is
/// mounted under it. An init that finds nothing mounted on /run mounts its own tmpfs
/// there — which would hide the FUSE mount underneath it, leaving /run/vk/services in
/// /proc/self/mounts and unreachable — while one that finds /run already a mount point
/// leaves it alone (systemd checks exactly that, in `mount_one`, for every API mount
/// point it sets up). The image's baked /run dirs are recreated on the new tmpfs, so a
/// service's runtime dir (e.g. /run/redis) survives the claim.
///
/// Should an init ever mount over a claimed /run anyway, the control fs goes back to being
/// unreachable — what the full-VM path did before it was mounted at all — and nothing else
/// about the boot changes.
///
/// The default path needs none of this: `mount_api_filesystems` already put /run on a
/// tmpfs and no image init follows it.
fn claim_run_tmpfs(cmdline: &HashMap<String, String>) {
    if !ctl_enabled(cmdline) {
        return;
    }
    // As `mount_api_filesystems` does: an image that ships no /run (FROM scratch) has
    // nothing to mount on otherwise.
    let _ = std::fs::create_dir_all("/run");
    if let Err(e) = mount_tmpfs_keep_dirs("/run", RUN_TMPFS_FLAGS, RUN_TMPFS_DATA) {
        // Mount the control fs anyway: an image whose init leaves /run alone still gets a
        // working one, and one that does not is no worse off than before.
        warn!(
            "vk-agent image-init: mounting /run failed: {e} — the control fs may not \
             survive the image's own init"
        );
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
    chdir_workdir(&cfg);
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

    // Power off on a forwarded shutdown even while the readiness gate below is still waiting.
    install_term_handler();

    // Gate readiness on the image's EXPOSEd ports before advertising the guest as up: the host
    // (prepare) polls the exec server started just below, so holding it back until the ports
    // accept connections keeps a CI job from racing a still-initializing service.
    wait_for_exposed_ports(cmdline, &cfg, service_pid);

    // VIRTKIT_SERVE=1: start the vsock exec server — the readiness signal prepare polls, also a
    // live-debugging channel: vk-agent -s vsock-mux://<vsock.sock>:4444 exec -- <cmd>
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

    supervise_service(service_pid, serve_pid)
}

/// Hold guest readiness until every EXPOSEd TCP port accepts connections. The host observes
/// readiness through the exec server the caller starts *after* this returns, so blocking here
/// delays "ready" until the service truly listens — a CI job then never connects before, say,
/// the database is up. Probes the guest's own LAN address, not loopback: a listener bound only
/// to 127.0.0.1 (as some DB init phases briefly are) must not count as ready, since a peer over
/// the LAN could not reach it. Orphans are reaped meanwhile; if the service process itself exits
/// before its ports open, the VM powers off (as supervise_service would), which the host reads
/// as the service failing to come up. No ports — or no known address — returns at once, leaving
/// readiness at "the guest booted".
fn wait_for_exposed_ports(
    cmdline: &HashMap<String, String>,
    cfg: &RunConfig,
    service_pid: libc::pid_t,
) {
    if cfg.exposed_ports.is_empty() {
        return;
    }
    let Some(ip) = guest_ip_from_cmdline(cmdline) else {
        warn!("vk-agent init: no VIRTKIT_VM_IP — skipping the exposed-port readiness gate");
        return;
    };
    for &port in &cfg.exposed_ports {
        let target = std::net::SocketAddr::from((ip, port));
        loop {
            reap_orphans_or_poweroff(service_pid);
            if std::net::TcpStream::connect_timeout(&target, Duration::from_secs(1)).is_ok() {
                info!("vk-agent init: service port {port} ready");
                break;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// The guest's own LAN address from `VIRTKIT_VM_IP` (`a.b.c.d/prefix`), dropping the prefix.
/// `None` when the key is absent (e.g. a DHCP boot) or unparseable, which leaves readiness at
/// the boot-level gate.
fn guest_ip_from_cmdline(cmdline: &HashMap<String, String>) -> Option<std::net::Ipv4Addr> {
    cmdline
        .get("VIRTKIT_VM_IP")
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
}

/// Non-blocking reap of exited children while gating on readiness. If the reaped child is the
/// service itself, power off — mirroring supervise_service's rule that the service exiting ends
/// the guest, so a crash during init surfaces to the host as the service never becoming ready.
fn reap_orphans_or_poweroff(service_pid: libc::pid_t) {
    loop {
        let mut status: libc::c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if pid <= 0 {
            break; // 0 = no child has exited; <0 = EINTR/ECHILD
        }
        if pid == service_pid {
            let code = if libc::WIFEXITED(status) {
                libc::WEXITSTATUS(status)
            } else {
                -libc::WTERMSIG(status)
            };
            info!(
                "vk-agent init: service exited (code {code}) before its ports opened; powering off"
            );
            poweroff();
        }
    }
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

/// chdir into the config's WORKDIR, like `docker run` — so a relative argv resolves there,
/// and so anything PID 1 goes on to start inherits it. Best effort: a directory the image
/// does not have warns and leaves the cwd alone. `/` (or none) is already the cwd.
fn chdir_workdir(cfg: &RunConfig) {
    if cfg.workdir.is_empty() || cfg.workdir == "/" {
        return;
    }
    if let Err(e) = std::env::set_current_dir(&cfg.workdir) {
        warn!("vk-agent init: chdir {} failed: {e}", cfg.workdir);
    }
}

/// Wrap argv to drop to `user` via setpriv (when non-root and setpriv is present).
fn wrap_user(argv: Vec<String>, user: &str) -> Vec<String> {
    if !user.is_empty() && user != "root" && which("setpriv") {
        setpriv_wrap(argv, user, user)
    } else {
        argv
    }
}

/// `argv` under `setpriv`, dropping to `reuid`/`regid` — the drop service mode and the
/// entrypoint axis share. Either may be a name or a number, as `setpriv` takes both; the
/// caller decides whether the drop is possible at all.
fn setpriv_wrap(argv: Vec<String>, reuid: &str, regid: &str) -> Vec<String> {
    let mut v: Vec<String> = [
        "setpriv",
        "--reuid",
        reuid,
        "--regid",
        regid,
        "--init-groups",
        "--",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    v.extend(argv);
    v
}

/// execvp(argv) — replaces this process (PATH-searched). Never returns on success.
fn exec_argv(argv: &[String]) -> ! {
    let e = try_exec_argv(argv);
    eprintln!("vk-agent init: exec {:?} failed: {e}", argv.first());
    unsafe { libc::_exit(127) };
}

/// Try to become `argv`, handing back the error if that failed: `execvp` returns only on
/// failure, and leaves this process able to try something else.
fn try_exec_argv(argv: &[String]) -> io::Error {
    let c_argv: Vec<CString> = argv.iter().map(|a| cstr(a)).collect();
    let mut ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|c| c.as_ptr()).collect();
    ptrs.push(std::ptr::null());
    unsafe { libc::execvp(c_argv[0].as_ptr(), ptrs.as_ptr()) };
    io::Error::last_os_error()
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
    // FIFREEZE via raw open/ioctl + reboot syscalls); we never return from it.
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
    // SAFETY: async-signal-safe syscall (poweroff also runs from the SIGTERM handler).
    unsafe {
        libc::sync();
    }
    // Freeze the root fs before power-off so its ext4 journal is checkpointed and the next
    // mount runs no journal recovery; see `fsfreeze::freeze_for_poweroff`. `sync()` alone
    // flushes dirty pages but leaves the journal open. Best-effort and no thaw: we are
    // powering off.
    crate::fsfreeze::freeze_for_poweroff(c"/");
    // SAFETY: async-signal-safe syscall.
    unsafe {
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
    fn inactivity_timeout_comes_from_explicit_arg_or_cmdline() {
        let cmdline =
            HashMap::from([("VIRTKIT_INACTIVITY_TIMEOUT".to_string(), "1800".to_string())]);
        assert_eq!(resolve_inactivity_timeout(None, &cmdline), Some(1800));
        assert_eq!(resolve_inactivity_timeout(Some(60), &cmdline), Some(60));
        assert_eq!(resolve_inactivity_timeout(Some(0), &cmdline), None);

        let invalid = HashMap::from([(
            "VIRTKIT_INACTIVITY_TIMEOUT".to_string(),
            "invalid".to_string(),
        )]);
        assert_eq!(resolve_inactivity_timeout(None, &invalid), None);

        // Zero disables the watchdog whichever side carries it.
        let zero = HashMap::from([("VIRTKIT_INACTIVITY_TIMEOUT".to_string(), "0".to_string())]);
        assert_eq!(resolve_inactivity_timeout(None, &zero), None);
    }

    #[test]
    fn overlay_tags_absent_is_empty() {
        assert!(overlay_tags(&HashMap::new()).unwrap().is_empty());
    }

    #[test]
    fn overlay_tags_splits_commas() {
        let m = HashMap::from([(
            "VIRTKIT_VIRTIOFS_OVERLAY".to_string(),
            "cibuild,b".to_string(),
        )]);
        let tags = overlay_tags(&m).unwrap();
        assert_eq!(
            tags,
            HashSet::from(["cibuild".to_string(), "b".to_string()])
        );
    }

    #[test]
    fn overlay_tags_reject_path_escapes() {
        for bad in ["a/b", "/abs", ".", ".."] {
            let m = HashMap::from([("VIRTKIT_VIRTIOFS_OVERLAY".to_string(), bad.to_string())]);
            let err = overlay_tags(&m).unwrap_err().to_string();
            assert!(err.contains(&format!("{bad:?}")), "{bad}: {err}");
        }
    }

    #[test]
    fn mount_virtiofs_rejects_overlay_tags_without_shares() {
        let m = HashMap::from([(
            "VIRTKIT_VIRTIOFS_OVERLAY".to_string(),
            "cibuild,extra".to_string(),
        )]);
        let err = mount_virtiofs(&m).unwrap_err().to_string();
        assert!(err.contains("cibuild, extra"), "{err}");
    }

    #[test]
    fn mount_disks_is_a_noop_without_the_cmdline_key() {
        mount_disks(&HashMap::new()).unwrap();
    }

    #[test]
    fn mount_disks_rejects_a_malformed_entry() {
        let m = HashMap::from([("VIRTKIT_DISKS".to_string(), "no-colon-here".to_string())]);
        let err = mount_disks(&m).unwrap_err().to_string();
        assert!(err.contains("no-colon-here"), "{err}");
    }

    #[test]
    fn the_overlay_layer_is_sized_by_the_host_or_left_to_the_kernel() {
        // Told nothing, the layer keeps the kernel's own default (half the RAM) rather than a
        // size this agent invents — the policy belongs to the host that knows the workload.
        assert_eq!(overlay_tmpfs_data(None), "mode=0755");
        assert_eq!(overlay_tmpfs_data(Some("80%")), "mode=0755,size=80%");
        assert_eq!(overlay_size(&HashMap::new()).unwrap(), None);
        let sized =
            |v: &str| HashMap::from([("VIRTKIT_VIRTIOFS_OVERLAY_SIZE".to_string(), v.to_string())]);
        assert_eq!(overlay_size(&sized("80%")).unwrap(), Some("80%"));
        assert_eq!(overlay_size(&sized("12G")).unwrap(), Some("12G"));
        // Checked again on this side of the cmdline: the value lands in a mount option list, so
        // one carrying a separator would mount the layer with options nobody asked for. A boot
        // is refused rather than given a silently different writable layer.
        for bad in ["", "80%,mode=0777", "eighty", "80 %", "12GB"] {
            assert!(overlay_size(&sized(bad)).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn overlay_dirs_live_under_the_private_root() {
        let dirs = overlay_dirs("cibuild");
        assert_eq!(dirs.lower, "/run/virtkit-overlay/cibuild/lower");
        assert_eq!(dirs.rw, "/run/virtkit-overlay/cibuild/rw");
        assert_eq!(dirs.upper, "/run/virtkit-overlay/cibuild/rw/upper");
        assert_eq!(dirs.work, "/run/virtkit-overlay/cibuild/rw/work");
    }

    #[test]
    fn the_control_fs_belongs_to_the_run_s_own_user() {
        // The run's user owns the control nodes, so a primary that is not root — an entrypoint
        // that dropped to the image's USER, or a served stage that did — can still write `ctl`.
        // An image that declares no USER leaves them root's, as does a *name* that resolves to
        // nothing. A bare uid needs no passwd entry: the kernel compares the attributed number
        // to the caller's fsuid (`default_permissions`).
        assert_eq!(ctl_owner_ids(""), (0, 0));
        assert_eq!(ctl_owner_ids("root"), (0, 0));
        assert_eq!(ctl_owner_ids("0"), (0, 0));
        // Only a spec that does not resolve at all falls back to root — an unknown *name*. A
        // number always resolves, which is the point of the case below.
        assert_eq!(ctl_owner_ids("nosuchuser-virtkit"), (0, 0));
        // A uid the passwd does not list still owns them, as a bare uid with gid 0 — what the
        // exec server drops such a `USER` to, and a distroless image's usual shape. Attributing
        // the number is the whole job: the kernel checks this mount against it, not against a
        // passwd entry.
        assert_eq!(ctl_owner_ids("65532"), (65532, 0));
        // A `user:group` spec takes its gid from the group half, as the drop does.
        assert_eq!(ctl_owner_ids("65532:1500"), (65532, 1500));
        // A name the image's passwd does have resolves to that entry's own ids.
        if let Some((uid, gid)) = passwd_ids("daemon")
            && uid != 0
        {
            assert_eq!(ctl_owner_ids("daemon"), (uid, gid));
        }
    }

    #[test]
    fn run_is_mounted_with_an_init_s_own_options() {
        // systemd's `mount_setup` row for /run, so an image's init finds the mount it would
        // have made itself — and the guest the agent keeps gets the same bounded, root-owned
        // /run rather than the kernel's 1777, half-the-RAM default.
        assert_eq!(RUN_TMPFS_DATA, "mode=0755,size=20%,nr_inodes=800k");
        assert_eq!(
            RUN_TMPFS_FLAGS,
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_STRICTATIME
        );
    }

    #[test]
    fn overlay_data_pins_the_mount_options() {
        assert_eq!(
            overlay_data("/l", "/u", "/w"),
            "lowerdir=/l,upperdir=/u,workdir=/w,redirect_dir=on,metacopy=on,index=off"
        );
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
    fn arp_resolved_entry_detected() {
        let header =
            "IP address       HW type     Flags       HW address            Mask     Device\n";
        let resolved = format!(
            "{header}192.168.127.1    0x1         0x2         52:54:00:12:34:56     *        eth0\n"
        );
        assert!(arp_has_resolved_entry(&resolved, "192.168.127.1"));
        // Entry present but ATF_COM (0x2) not set — still resolving, not reachable.
        let pending = format!(
            "{header}192.168.127.1    0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        );
        assert!(!arp_has_resolved_entry(&pending, "192.168.127.1"));
        // Gateway not listed.
        assert!(!arp_has_resolved_entry(&resolved, "10.0.0.1"));
        // Header only / empty input.
        assert!(!arp_has_resolved_entry(header, "192.168.127.1"));
        assert!(!arp_has_resolved_entry("", "192.168.127.1"));
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
    fn image_init_candidates_lead_with_the_entrypoint_only_for_the_entrypoint_axis() {
        let cfg = RunConfig {
            entrypoint: vec!["/prepare-machine.sh".into()],
            cmd: vec!["--log-level=info".into()],
            ..Default::default()
        };
        let empty = HashMap::new();
        let handoff = HashMap::from([(
            "VIRTKIT_HANDOFF".to_string(),
            "/lib/systemd/systemd".to_string(),
        )]);

        // the init axis offers the init and nothing else, exactly as it did before the
        // entrypoint axis existed — the host's handoff where it named one
        assert_eq!(
            image_init_candidates(ImageInit::Init, &empty, Some(&cfg), None),
            [["/sbin/init"]]
        );
        assert_eq!(
            image_init_candidates(ImageInit::Init, &handoff, Some(&cfg), None),
            [["/lib/systemd/systemd"]]
        );

        // the entrypoint axis leads with the config's entrypoint+cmd, verbatim: a bare name
        // is left for execvp's PATH lookup rather than resolved here
        assert_eq!(
            image_init_candidates(ImageInit::Entrypoint, &empty, Some(&cfg), None),
            [
                vec!["/prepare-machine.sh", "--log-level=info"],
                vec!["/sbin/init"],
                vec!["/bin/sh"]
            ]
        );
        let bare = RunConfig {
            entrypoint: vec!["prepare-machine.sh".into()],
            ..Default::default()
        };
        assert_eq!(
            image_init_candidates(ImageInit::Entrypoint, &empty, Some(&bare), None)[0],
            ["prepare-machine.sh"]
        );
        // A guest that can drop to the image's USER hands the entrypoint over under setpriv, by
        // the ids the image's passwd gave — a name would make setpriv resolve it again, and a
        // group of that name need not exist. Only the entrypoint is dropped: the init below it
        // and the debug shell below that stay root, for a guest that could not start the
        // entrypoint at all.
        let as_app = RunConfig {
            entrypoint: vec!["/prepare-machine.sh".into()],
            user: "app".into(),
            ..Default::default()
        };
        assert_eq!(
            image_init_candidates(
                ImageInit::Entrypoint,
                &empty,
                Some(&as_app),
                Some((1000, 100))
            ),
            [
                vec![
                    "setpriv",
                    "--reuid",
                    "1000",
                    "--regid",
                    "100",
                    "--init-groups",
                    "--",
                    "/prepare-machine.sh"
                ],
                vec!["/sbin/init"],
                vec!["/bin/sh"]
            ]
        );
        // A guest that cannot (no setpriv, or a USER the image's passwd does not know) keeps
        // root rather than exec'ing a setpriv that would exit from PID 1 and panic the kernel.
        assert_eq!(
            image_init_candidates(ImageInit::Entrypoint, &empty, Some(&as_app), None)[0],
            ["/prepare-machine.sh"]
        );
        // Neither a missing USER nor an explicit root is ever a drop — nor is `USER 0`, which
        // is root by number and needs no setpriv to become.
        assert_eq!(drop_ids_for_user(""), None);
        assert_eq!(drop_ids_for_user("root"), None);
        assert_eq!(drop_ids_for_user("0"), None);
        // The ids come out of the passwd entry, so a USER with none is not a drop.
        assert_eq!(passwd_ids("nosuchuser-virtkit"), None);
        assert_eq!(passwd_ids("4294967294"), None);
        assert_eq!(passwd_ids("root"), Some((0, 0)));
        assert_eq!(passwd_ids("0"), Some((0, 0)));

        // nothing to exec: straight to the init, then a shell — PID 1 always has a next
        // candidate, since exiting from it panics the kernel
        assert_eq!(
            image_init_candidates(ImageInit::Entrypoint, &handoff, None, None),
            [vec!["/lib/systemd/systemd"], vec!["/bin/sh"]]
        );
    }

    #[test]
    fn a_setpriv_that_cannot_make_the_drop_is_not_one() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("vk-setpriv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = |name: &str, code: u8| {
            let p = dir.join(name);
            std::fs::write(&p, format!("#!/bin/sh\nexit {code}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p.to_string_lossy().into_owned()
        };
        // util-linux: takes the flags and makes the drop.
        assert!(setpriv_can_drop(&fake("setpriv-ok", 0), 1000, 100));
        // busybox: has the name, rejects --reuid — the case PID 1 must not discover by exec'ing
        // it, since a setpriv that exits from PID 1 panics the kernel.
        assert!(!setpriv_can_drop(&fake("setpriv-busybox", 1), 1000, 100));
        // no setpriv at all.
        assert!(!setpriv_can_drop(
            &dir.join("setpriv-absent").to_string_lossy(),
            1000,
            100
        ));
        std::fs::remove_dir_all(&dir).ok();
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
            exposed_ports: vec![6379],
        };
        assert_eq!(RunConfig::from_json(&cfg.to_json()).unwrap(), cfg);
    }

    #[test]
    fn guest_ip_drops_the_prefix() {
        let m: HashMap<String, String> =
            [("VIRTKIT_VM_IP".to_string(), "10.0.2.15/24".to_string())]
                .into_iter()
                .collect();
        assert_eq!(
            guest_ip_from_cmdline(&m),
            Some("10.0.2.15".parse().unwrap())
        );
    }

    #[test]
    fn guest_ip_absent_or_unparseable_is_none() {
        assert_eq!(guest_ip_from_cmdline(&HashMap::new()), None);
        let m: HashMap<String, String> =
            [("VIRTKIT_VM_IP".to_string(), "not-an-ip/24".to_string())]
                .into_iter()
                .collect();
        assert_eq!(guest_ip_from_cmdline(&m), None);
    }
}
