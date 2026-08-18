//! `vk check`: host preflight. Verifies the current user can actually boot
//! microVMs (/dev/kvm access, the selected VMM backend, a guest kernel + agent)
//! and that each feature the config enables has its host side in place (net.mode
//! taps, [docker] credentials, [registry] store/credentials, ...). Some features
//! are checked only when named with `--feature`: the CI-executor ones (gitlab,
//! services), and the capability probes a script asks this build about (entrypoint).
//! Prints one line per check; the caller turns "any check failed" into the exit code.

use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::embed::Asset;

#[derive(Clone, Copy, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Feature {
    /// rw access to /dev/kvm (KVM API sanity-checked)
    Kvm,
    /// the selected VMM backend can run (built-in libkrun, or cloud-hypervisor)
    Vmm,
    /// a guest kernel and vk-agent are available (embedded or on disk)
    Kernel,
    /// the configured net.mode's host side (/dev/net/tun + taps where needed)
    Net,
    /// [docker]: the OCI image registry credentials/CA are readable
    Docker,
    /// [registry]: local store writable, or remote credential files readable
    Registry,
    /// gitlab executor: per-job state dir writable, [gitlab] tools dir readable
    Gitlab,
    /// [share]: shared dir readable, a virtiofsd available when needed
    Share,
    /// [services]: the shared image cache CI services pull into is writable
    Services,
    /// the kernel accounts what jobs use, so their traces can report it
    Usage,
    /// this build can hand PID 1 to the image's own entrypoint (`--init entrypoint`)
    Entrypoint,
}

impl Feature {
    /// Features the default sweep leaves out, each for its own reason. The CI-executor
    /// ones (the gitlab runner and its sibling service VMs) probe state dirs under a
    /// root-owned default path, so sweeping them would fail every host that just boots
    /// VMs without running CI. `Entrypoint` answers a question about this build rather
    /// than about the host, so it belongs where a script asks for it and nowhere else.
    fn on_request_only(self) -> bool {
        matches!(
            self,
            Feature::Gitlab | Feature::Services | Feature::Entrypoint
        )
    }

    fn name(self) -> &'static str {
        match self {
            Feature::Kvm => "kvm",
            Feature::Vmm => "vmm",
            Feature::Kernel => "kernel",
            Feature::Net => "net",
            Feature::Docker => "docker",
            Feature::Registry => "registry",
            Feature::Gitlab => "gitlab",
            Feature::Share => "share",
            Feature::Services => "services",
            Feature::Usage => "usage",
            Feature::Entrypoint => "entrypoint",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Status {
    Ok,
    /// the feature is not enabled here, so there is nothing to verify
    Skip,
    Fail,
}

struct Outcome {
    status: Status,
    detail: String,
}

fn ok(detail: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::Ok,
        detail: detail.into(),
    }
}
fn skip(detail: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::Skip,
        detail: detail.into(),
    }
}
fn fail(detail: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::Fail,
        detail: detail.into(),
    }
}

/// Run the checks and print one line each; returns whether every check passed.
/// No `--feature` = the default sweep (every feature except the CI-executor
/// ones), where a feature the config leaves unconfigured is skipped; naming
/// features checks exactly those, and one that turns out unconfigured fails
/// (the caller asserted it should be usable).
pub fn run(cfg: &Config, requested: &[Feature]) -> bool {
    let explicit = !requested.is_empty();
    let features: Vec<Feature> = if explicit {
        let mut v = Vec::new();
        for f in requested {
            if !v.contains(f) {
                v.push(*f);
            }
        }
        v
    } else {
        default_sweep()
    };

    // Lead with the config file in use (informational — does not affect all_ok), so a
    // surprising check result can be traced to the wrong or missing file at a glance.
    match &cfg.source {
        Some(p) => println!("{:<4} {:<8} {}", "ok", "config", p.display()),
        None => println!(
            "{:<4} {:<8} no config file (built-in defaults)",
            "skip", "config"
        ),
    }

    let mut all_ok = true;
    for f in features {
        let mut outcome = evaluate(cfg, f);
        if explicit && outcome.status == Status::Skip {
            outcome = fail(format!("{} — requested but not enabled", outcome.detail));
        }
        let label = match outcome.status {
            Status::Ok => "ok",
            Status::Skip => "skip",
            Status::Fail => "FAIL",
        };
        println!("{:<4} {:<8} {}", label, f.name(), outcome.detail);
        all_ok &= outcome.status != Status::Fail;
    }
    all_ok
}

/// The features checked when none are named.
fn default_sweep() -> Vec<Feature> {
    <Feature as clap::ValueEnum>::value_variants()
        .iter()
        .copied()
        .filter(|f| !f.on_request_only())
        .collect()
}

fn evaluate(cfg: &Config, feature: Feature) -> Outcome {
    match feature {
        Feature::Kvm => kvm(),
        Feature::Vmm => vmm(cfg),
        Feature::Kernel => kernel(),
        Feature::Net => net(cfg),
        Feature::Docker => docker(cfg),
        Feature::Registry => registry(cfg),
        Feature::Gitlab => gitlab(cfg),
        Feature::Share => share(cfg),
        Feature::Services => services(cfg),
        Feature::Usage => usage(),
        Feature::Entrypoint => entrypoint(),
    }
}

/// Whether this `vk` can hand PID 1 to an image's own entrypoint (`--init entrypoint`, or a
/// compose `x-virtkit: { init: entrypoint }`). Asked for by name and never swept, because it
/// is a property of the binary: what it adds over reading `--init`'s help is an exit code, so
/// a script asks this `vk` whether the axis is there instead of parsing prose — and a `vk`
/// too old to have it rejects the feature name outright.
///
/// The host side is the agent. It rides the preinit initramfs as `/init` and is the thing
/// that execs the image's ENTRYPOINT+CMD, so a `vk` with no agent to embed or find cannot do
/// this whichever axis the operator names.
fn entrypoint() -> Outcome {
    use clap::ValueEnum;
    let axes = <crate::run::InitSource as ValueEnum>::value_variants()
        .iter()
        .filter_map(|axis| axis.to_possible_value())
        .map(|v| v.get_name().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    match asset_source(Asset::Agent) {
        Some(src) => ok(format!("--init {axes}; agent {src} execs it as PID 1")),
        None => fail(format!(
            "--init {axes}, but no agent to exec it: nothing embedded and {} missing",
            Asset::Agent.default_path()
        )),
    }
}

/// Whether this host can measure what its jobs use. Not a reason a job cannot run — which is
/// why an unaccounted kernel skips rather than fails, and only fails when an operator names
/// the feature and is told it does not hold. Reported because the alternative is a blank in
/// every job trace with nothing to say why: a phase whose disk was never measurable and one
/// that touched no disk print the same nothing.
fn usage() -> Outcome {
    let tree = match crate::usage::kernel_lists_children() {
        true => "process tree from the kernel's child lists",
        false => "process tree from a scan of every process (no CONFIG_PROC_CHILDREN)",
    };
    match crate::usage::io_accounted() {
        true => ok(format!("block I/O accounted, {tree}")),
        false => skip(format!(
            "no block I/O accounting in this kernel (CONFIG_TASK_IO_ACCOUNTING) — a job's \
             disk figures are reported as unmeasured; {tree}"
        )),
    }
}

fn kvm() -> Outcome {
    let dev = Path::new("/dev/kvm");
    if !dev.exists() {
        return fail("/dev/kvm missing (is KVM enabled — kvm_intel/kvm_amd loaded?)");
    }
    if !access_ok(dev, libc::R_OK | libc::W_OK) {
        return fail("no rw access to /dev/kvm (is the user in the kvm group?)");
    }
    let file = match std::fs::OpenOptions::new().read(true).write(true).open(dev) {
        Ok(f) => f,
        Err(e) => return fail(format!("opening /dev/kvm: {e}")),
    };
    // KVM_GET_API_VERSION (_IO(0xAE, 0x00)); the stable KVM API is pinned at 12.
    // KVM insists the unused ioctl argument is 0 (EINVAL otherwise), so pass it
    // explicitly rather than leaving the variadic slot to garbage.
    let version = unsafe { libc::ioctl(file.as_raw_fd(), 0xAE00 as _, 0) };
    if version < 0 {
        return fail(format!(
            "KVM_GET_API_VERSION on /dev/kvm failed: {} (a sandbox/seccomp profile blocking KVM ioctls?)",
            std::io::Error::last_os_error()
        ));
    }
    if version != 12 {
        return fail(format!("unexpected KVM API version {version} (want 12)"));
    }
    ok("rw access to /dev/kvm, KVM API v12")
}

fn vmm(cfg: &Config) -> Outcome {
    if crate::vmm::libkrun_selected() {
        return ok("libkrun (built into vk)");
    }
    match resolve_bin(cfg.cloud_hypervisor()) {
        Some(p) => ok(format!("cloud-hypervisor: {}", p.display())),
        None => fail(format!(
            "cloud-hypervisor not runnable: {} (install it, or set `cloud_hypervisor` in the config)",
            cfg.cloud_hypervisor().display()
        )),
    }
}

/// Where an asset comes from — `embedded`, or the path it was found at — or `None` when it is
/// neither embedded nor on disk.
fn asset_source(asset: Asset) -> Option<String> {
    if asset.embedded().is_some() {
        return Some("embedded".to_string());
    }
    let p = Path::new(asset.default_path());
    p.is_file().then(|| p.display().to_string())
}

fn kernel() -> Outcome {
    let mut have = Vec::new();
    let mut missing = Vec::new();
    for (name, asset) in [("kernel", Asset::Kernel), ("agent", Asset::Agent)] {
        match asset_source(asset) {
            Some(src) => have.push(format!("{name} {src}")),
            None => missing.push(format!(
                "{name}: nothing embedded and {} missing",
                asset.default_path()
            )),
        }
    }
    if missing.is_empty() {
        ok(have.join(", "))
    } else {
        fail(missing.join("; "))
    }
}

fn net(cfg: &Config) -> Outcome {
    let net = &cfg.net;
    let sys = Path::new("/sys/class/net");
    match net.mode.as_str() {
        "none" => ok("mode none (no guest networking)"),
        "switch" => ok("mode switch (userspace, no host privileges needed)"),
        "tap" => {
            if net.tap.is_empty() {
                return fail("net.mode = \"tap\" needs net.tap set");
            }
            if !sys.join(&net.tap).exists() {
                return fail(format!("tap {} not found", net.tap));
            }
            if !access_ok(Path::new("/dev/net/tun"), libc::R_OK | libc::W_OK) {
                return fail("no rw access to /dev/net/tun");
            }
            ok(format!("mode tap: {} present, /dev/net/tun rw", net.tap))
        }
        "pool" => {
            let present = (0..net.count)
                .filter(|i| sys.join(format!("{}{i}", net.tap_prefix)).exists())
                .count();
            if present == 0 {
                return fail(format!(
                    "tap pool missing ({}0..{} not found — is microvm-taps.service up?)",
                    net.tap_prefix, net.count
                ));
            }
            if !access_ok(Path::new("/dev/net/tun"), libc::R_OK | libc::W_OK) {
                return fail("no rw access to /dev/net/tun");
            }
            ok(format!(
                "mode pool: {present}/{} taps present, /dev/net/tun rw",
                net.count
            ))
        }
        other => fail(format!("unknown net.mode {other:?}")),
    }
}

fn docker(cfg: &Config) -> Outcome {
    let Some(d) = &cfg.docker else {
        return skip("[docker] not configured");
    };
    // The image is pulled with the native OCI client and booted on the embedded kernel +
    // agent, so the only host inputs are the registry credential files — check they are
    // readable, like [registry] does.
    let mut problems = Vec::new();
    if let Some(ca) = &d.ca_file
        && !access_ok(ca, libc::R_OK)
    {
        problems.push(format!("ca_file unreadable: {}", ca.display()));
    }
    if !d.username.is_empty() {
        match &d.password_file {
            Some(p) if !access_ok(p, libc::R_OK) => {
                problems.push(format!("password_file unreadable: {}", p.display()));
            }
            Some(_) => {}
            None => problems.push("username set but no password_file".into()),
        }
    }
    if let Some(m) = &d.mirror {
        if let Some(ca) = &m.ca_file
            && !access_ok(ca, libc::R_OK)
        {
            problems.push(format!("mirror ca_file unreadable: {}", ca.display()));
        }
        if !m.username.is_empty() {
            match &m.password_file {
                Some(p) if !access_ok(p, libc::R_OK) => {
                    problems.push(format!("mirror password_file unreadable: {}", p.display()));
                }
                Some(_) => {}
                None => problems.push("mirror username set but no password_file".into()),
            }
        }
    }
    if !problems.is_empty() {
        return fail(problems.join("; "));
    }
    let repo = d.repo.as_deref().unwrap_or("(none)");
    match &d.mirror {
        Some(m) => ok(format!(
            "OCI image registry {repo} + Docker Hub mirror {} reachable-by-config",
            m.repo
        )),
        None => ok(format!("OCI image registry {repo} reachable-by-config")),
    }
}

fn registry(cfg: &Config) -> Outcome {
    let Some(r) = &cfg.registry else {
        return skip("[registry] not configured");
    };
    if let Some(root) = r.local_root() {
        return match dir_writable(&root) {
            Ok(()) => ok(format!("local store {} writable", root.display())),
            Err(e) => fail(e),
        };
    }
    let mut problems = Vec::new();
    if let Some(ca) = &r.ca_file
        && !access_ok(ca, libc::R_OK)
    {
        problems.push(format!("ca_file unreadable: {}", ca.display()));
    }
    if !r.username.is_empty() {
        match &r.password_file {
            Some(p) if !access_ok(p, libc::R_OK) => {
                problems.push(format!("password_file unreadable: {}", p.display()));
            }
            Some(_) => {}
            None => problems.push("username set but no password_file".into()),
        }
    }
    if problems.is_empty() {
        ok(format!(
            "remote {} (credential files readable; not probed over the network)",
            r.repo
        ))
    } else {
        fail(problems.join("; "))
    }
}

fn gitlab(cfg: &Config) -> Outcome {
    // Without a config file this host runs no executor — return a skip that
    // run() escalates to a "requested but not enabled" failure (this check only
    // runs when named with --feature) rather than a confusing permission error
    // on the default root-owned state dir.
    if cfg.source.is_none() {
        return skip("no config file (gitlab executor not set up on this host)");
    }
    let jobs = cfg.state_dir().join("jobs");
    if let Err(e) = dir_writable(&jobs) {
        return fail(format!("{e} (per-job state lives there; see state_dir)"));
    }
    if let Some(gl) = &cfg.gitlab
        && let Some(dir) = &gl.dir
        && let Err(e) = std::fs::read_dir(dir)
    {
        return fail(format!(
            "[gitlab] tools dir {} unreadable: {e}",
            dir.display()
        ));
    }
    // Guest statistics recording: whether jobs are recorded, and whether the archive they
    // are recorded into can actually be written. A misconfigured interval fails the check
    // rather than each job it would stop.
    let stats = if crate::atop::enabled(cfg) {
        let root = crate::atop::archive_root(cfg);
        match crate::atop::interval_secs(cfg) {
            Err(e) => return fail(format!("{e:#}")),
            Ok(secs) => match dir_writable(&root) {
                Err(e) => return fail(format!("{e} (guest stats are archived there)")),
                Ok(()) => format!(
                    "guest stats every {secs}s, {} -> {}",
                    crate::atop::retention_note(cfg),
                    root.display()
                ),
            },
        }
    } else {
        "guest stats off (`[gitlab] atop`)".to_string()
    };
    ok(format!("jobs dir {} writable, {stats}", jobs.display()))
}

fn share(cfg: &Config) -> Outcome {
    let Some(s) = &cfg.share else {
        return skip("[share] not configured");
    };
    if let Err(e) = std::fs::read_dir(&s.dir) {
        return fail(format!("share dir {} unreadable: {e}", s.dir.display()));
    }
    let served = if crate::vmm::libkrun_selected() {
        "virtio-fs built into libkrun".to_string()
    } else if let Some(p) = &cfg.virtiofsd {
        match resolve_bin(p) {
            Some(p) => format!("virtiofsd: {}", p.display()),
            None => return fail(format!("virtiofsd not runnable: {}", p.display())),
        }
    } else if cfg!(feature = "virtiofsd") {
        "bundled virtiofsd".to_string()
    } else {
        return fail("no virtiofsd: vk built without the virtiofsd feature and none configured");
    };
    ok(format!("dir {} readable, {served}", s.dir.display()))
}

fn services(cfg: &Config) -> Outcome {
    // CI services boot as sibling microVMs from the same digest-keyed image cache the
    // job's own image uses (`<state_dir>/registry`); the check is that that cache is
    // (creatable and) writable by this user.
    let store = cfg.state_dir().join("registry");
    if let Err(e) = std::fs::create_dir_all(&store) {
        return fail(format!(
            "image cache {} not creatable: {e}",
            store.display()
        ));
    }
    let probe = store.join(".check");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            ok(format!("service image cache {} writable", store.display()))
        }
        Err(e) => fail(format!(
            "service image cache {} not writable: {e}",
            store.display()
        )),
    }
}

/// Whether the current user's real IDs pass an access(2) check on `path`.
fn access_ok(path: &Path, mode: libc::c_int) -> bool {
    let Ok(c) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path.
    unsafe { libc::access(c.as_ptr(), mode) == 0 }
}

/// Resolve a binary the way spawning it would: a path with a separator is used
/// as-is, a bare name is searched through PATH; `None` if not executable.
fn resolve_bin(bin: &Path) -> Option<PathBuf> {
    if bin.components().count() > 1 {
        return access_ok(bin, libc::X_OK).then(|| bin.to_path_buf());
    }
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(bin))
        .find(|p| access_ok(p, libc::X_OK))
}

/// Whether the current user can create files in `dir` (created if missing),
/// proven by writing and removing an empty probe file.
fn dir_writable(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let probe = dir.join(format!(".vk-check-{}", std::process::id()));
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|e| format!("writing in {}: {e}", dir.display()))?;
    // best-effort: the probe is empty, ours, and pid-named
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Gitlab;

    // A feature the default config leaves unconfigured is a skip, so the default
    // sweep passes on hosts that don't use it; run() escalates it to a failure
    // only when named explicitly.
    #[test]
    fn unconfigured_feature_skips() {
        let cfg = Config::default();
        for f in [Feature::Docker, Feature::Registry] {
            assert_eq!(evaluate(&cfg, f).status, Status::Skip);
        }
    }

    // Named-only features run just when asked for: the CI-executor ones probe root-owned
    // default state dirs, and `entrypoint` answers for the build, not the host. The default
    // sweep covers everything else.
    #[test]
    fn default_sweep_omits_the_named_only_features() {
        let sweep = default_sweep();
        assert!(!sweep.contains(&Feature::Gitlab));
        assert!(!sweep.contains(&Feature::Services));
        assert!(!sweep.contains(&Feature::Entrypoint));
        for f in <Feature as clap::ValueEnum>::value_variants() {
            assert_eq!(sweep.contains(f), !f.on_request_only());
        }
    }

    // The capability probe names every axis this build has, which is the answer a script
    // came for. Whether it then passes depends on the host having an agent to exec the
    // entrypoint — a `cargo test` binary embeds none — but it never skips: a probe that
    // declined to answer would be escalated to a failure by `run`, saying the opposite of
    // what it means. A vk without the axis never reaches this: clap rejects the feature name
    // first, which is the signal a script reads.
    #[test]
    fn the_entrypoint_probe_names_the_axes_this_build_supports() {
        let outcome = evaluate(&Config::default(), Feature::Entrypoint);
        assert!(
            outcome.detail.contains("--init default, image, entrypoint"),
            "{}",
            outcome.detail
        );
        assert_ne!(outcome.status, Status::Skip);
    }

    // The default net.mode ("none") and "switch" need nothing from the host.
    #[test]
    fn userspace_net_modes_pass() {
        let mut cfg = Config::default();
        assert_eq!(evaluate(&cfg, Feature::Net).status, Status::Ok);
        cfg.net.mode = "switch".into();
        assert_eq!(evaluate(&cfg, Feature::Net).status, Status::Ok);
        cfg.net.mode = "bridge".into();
        assert_eq!(evaluate(&cfg, Feature::Net).status, Status::Fail);
    }

    // resolve_bin: bare names go through PATH, paths with a separator are taken
    // as-is; both report an unrunnable target as None.
    #[test]
    fn resolve_bin_searches_path() {
        assert!(resolve_bin(Path::new("sh")).is_some());
        assert!(resolve_bin(Path::new("/bin/sh")).is_some());
        assert!(resolve_bin(Path::new("vk-no-such-binary")).is_none());
        assert!(resolve_bin(Path::new("./vk-no-such-binary")).is_none());
    }

    /// The executor check reports what the host will record and whether it can: a setting
    /// that would stop every job on this host fails here, once, instead of there, each time.
    #[test]
    fn the_gitlab_check_reports_the_guest_statistics_archive() {
        let root = std::env::temp_dir().join(format!("vk-check-atop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let with = |gl: Gitlab| Config {
            source: Some(root.join("config.toml")),
            state_dir: Some(root.clone()),
            gitlab: Some(gl),
            ..Default::default()
        };

        // On by default: the interval and where the days of recordings go.
        let out = gitlab(&with(Gitlab::default()));
        assert_eq!(out.status, Status::Ok, "{}", out.detail);
        assert!(
            out.detail.contains("guest stats every 10s"),
            "{}",
            out.detail
        );
        // and how long what it records survives
        assert!(out.detail.contains("kept 14 days back"), "{}", out.detail);
        assert!(
            out.detail
                .contains(&root.join("atop").display().to_string()),
            "{}",
            out.detail
        );
        // The archive is created by the probe, so an operator sees the path that will fill.
        assert!(root.join("atop").is_dir());

        // Turned off, the check says so rather than going quiet about it.
        let out = gitlab(&with(Gitlab {
            atop: false,
            ..Default::default()
        }));
        assert_eq!(out.status, Status::Ok, "{}", out.detail);
        assert!(out.detail.contains("guest stats off"), "{}", out.detail);

        // An interval no job could sample at fails the check, naming the setting.
        let out = gitlab(&with(Gitlab {
            atop_interval_secs: 0,
            ..Default::default()
        }));
        assert_eq!(out.status, Status::Fail);
        assert!(out.detail.contains("atop_interval_secs"), "{}", out.detail);

        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn dir_writable_probes_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("vk-check-test-{}", std::process::id()));
        dir_writable(&dir).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir(&dir).unwrap();
    }
}
