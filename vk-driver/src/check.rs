//! `vk check`: host preflight. Verifies the current user can actually boot
//! microVMs (/dev/kvm access, the selected VMM backend, a guest kernel + agent)
//! and that each feature the config enables has its host side in place (net.mode
//! taps, [docker] credentials, [registry] store/credentials, ...). Some features
//! are checked only when named with `--feature`: the CI-executor ones (gitlab,
//! services), and the capability probes a script asks this build about (entrypoint,
//! publish).
//! `--min-version` lets scripts gate on this binary's release instead of a feature name.
//! Prints one line per check; the caller turns "any check failed" into the exit code.
//! Failed checks print suggested repairs; `--fix` offers to apply the automated steps.

use std::fmt;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

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
    /// gitlab executor: state and tools dirs usable, guest stats and nesting supported
    Gitlab,
    /// [share]: shared dir readable, a virtiofsd available when needed
    Share,
    /// [services]: the shared image cache CI services pull into is writable
    Services,
    /// the kernel accounts what jobs use, so their traces can report it
    Usage,
    /// this build can hand PID 1 to the image's own entrypoint (`--init entrypoint`)
    Entrypoint,
    /// this build can relay a local connection into a guest's network (`vk publish`)
    Publish,
    /// this build can give a guest more than one NIC (`vk run --nics`, `x-virtkit.nics`)
    Nics,
}

impl Feature {
    /// Features the default sweep leaves out, each for its own reason. The CI-executor
    /// ones (the gitlab runner and its sibling service VMs) probe state dirs under a
    /// root-owned default path, so sweeping them would fail every host that just boots
    /// VMs without running CI. `Entrypoint`, `Publish` and `Nics` answer a question about
    /// this build rather than about the host, so they belong where a script asks for them
    /// and nowhere else.
    fn on_request_only(self) -> bool {
        matches!(
            self,
            Feature::Gitlab
                | Feature::Services
                | Feature::Entrypoint
                | Feature::Publish
                | Feature::Nics
        )
    }

    /// Parse a feature name as spelled by `--feature`.
    pub fn from_name(name: &str) -> Option<Feature> {
        <Feature as clap::ValueEnum>::from_str(name, false).ok()
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
            Feature::Publish => "publish",
            Feature::Nics => "nics",
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
    /// Steps to resolve a diagnosed failure; empty for other outcomes.
    remedy: Vec<Step>,
}

fn ok(detail: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::Ok,
        detail: detail.into(),
        remedy: Vec::new(),
    }
}
fn skip(detail: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::Skip,
        detail: detail.into(),
        remedy: Vec::new(),
    }
}
fn fail(detail: impl Into<String>) -> Outcome {
    Outcome {
        status: Status::Fail,
        detail: detail.into(),
        remedy: Vec::new(),
    }
}

/// An ordered remedy step, printed as a command or edit the user can copy from the report.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Step {
    /// a command to run, `sudo` where it needs root
    Run { argv: Vec<String>, sudo: bool },
    /// `nestedVirtualization=true` in the named `%USERPROFILE%\.wslconfig`
    EditWslconfig { path: String },
    /// a `[boot] command` in `/etc/wsl.conf`, which is what makes a distro-side fix last
    EditWslConf { command: String },
    /// something only the user can do — on the Windows side, or in a new login
    Manual(String),
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Run { argv, sudo } => {
                if *sudo {
                    f.write_str("sudo ")?;
                }
                f.write_str(&argv.join(" "))
            }
            Step::EditWslconfig { path } => {
                write!(f, "write `[wsl2] nestedVirtualization=true` to {path}")
            }
            Step::EditWslConf { command } => write!(
                f,
                "write `[boot] command = {command}` to {} (needs root) — without it the module \
                 and the {KVM_DEV} mode are gone after the next `wsl --shutdown`",
                crate::wsl::WSL_CONF
            ),
            Step::Manual(what) => f.write_str(what),
        }
    }
}

/// A step run as root, which every distro-side one here is.
fn sudo(argv: &[&str]) -> Step {
    Step::Run {
        argv: argv.iter().map(|a| a.to_string()).collect(),
        sudo: true,
    }
}

/// A release number, optionally prefixed with the `v` used in git tags, compared field by
/// field. Missing fields are zero, so `0.45` means `0.45.0`. `vk-selfupdate` deliberately
/// does not zero-fill because an update must distinguish the `0.45` and `0.45.0` tags;
/// a command-line version floor need not.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Version([u64; 3]);

impl FromStr for Version {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // clap prints the rejected value, so these errors say only what is wrong with it.
        let stripped = s.strip_prefix('v').unwrap_or(s);
        if stripped.is_empty() {
            return Err("expected a release number such as 0.45.0".to_string());
        }
        let mut fields = [0u64; 3];
        let max = fields.len();
        for (n, part) in stripped.split('.').enumerate() {
            // Accept only digits: `u64::from_str` accepts signs such as `+45`. Report an
            // oversized numeric field differently from a non-number. Validate the field
            // before the count so `1.2.3.` reports its trailing empty field, not a fourth.
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("`{part}` is not a release-number field"));
            }
            let Some(field) = fields.get_mut(n) else {
                return Err(format!("more than {max} fields"));
            };
            *field = part.parse().map_err(|_| format!("`{part}` is too large"))?;
        }
        Ok(Version(fields))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.0[0], self.0[1], self.0[2])
    }
}

impl Version {
    /// The release number `vk --version` prints before the git hash.
    /// `the_build_version_parses` enforces the crate version's shape, so releases should
    /// not reach the error. A suffix has no defined ordering and is rejected.
    pub fn own() -> Result<Version, String> {
        let raw = env!("CARGO_PKG_VERSION");
        raw.parse()
            .map_err(|_| format!("this build's version `{raw}` is not a release number"))
    }
}

/// Whether this `vk` meets the requested release floor. This generalizes capability checks
/// such as `entrypoint` and `publish` and covers behavior changes without feature names.
/// A `vk` too old to support `--min-version` rejects the flag.
fn min_version(have: Version, min: Version) -> Outcome {
    if have >= min {
        ok(format!("vk {have} (at least {min} required)"))
    } else {
        fail(format!("vk {have} is older than the {min} required"))
    }
}

/// Check an explicitly requested feature. A check skipped by the default sweep fails here
/// because the caller requires it. `Err` carries the report detail.
pub fn probe(cfg: &Config, feature: Feature) -> Result<(), String> {
    let outcome = evaluate(cfg, feature);
    match outcome.status {
        Status::Ok => Ok(()),
        Status::Skip => Err(format!("{} — requested but not enabled", outcome.detail)),
        Status::Fail => Err(outcome.detail),
    }
}

/// Run only `--min-version`, without loading a [`Config`]. An unreadable host config must
/// not look like an old `vk`. `Err` means the build cannot identify its release, distinct
/// from a version-floor failure and its exit code.
pub fn min_version_only(min: Version) -> Result<bool, String> {
    Ok(report("version", &min_version(Version::own()?, min)))
}

/// Run the checks and print one line each; returns whether every check passed.
/// No `--feature` = the default sweep (every feature except the CI-executor
/// ones), where a feature the config leaves unconfigured is skipped; naming
/// features checks exactly those, and one that turns out unconfigured fails
/// (the caller asserted it should be usable). `--min-version` adds a version line, and
/// on its own asserts only that.
pub fn run(
    cfg: &Config,
    requested: &[Feature],
    min: Option<Version>,
    fix: bool,
) -> Result<bool, String> {
    let explicit = !requested.is_empty();
    let features = selected(requested, min);

    // Lead with the config file in use (informational — does not affect all_ok), so a
    // surprising check result can be traced to the wrong or missing file at a glance.
    match &cfg.source {
        Some(p) => line("ok", "config", p.display()),
        None => line("skip", "config", "no config file (built-in defaults)"),
    }

    let mut all_ok = true;
    if let Some(min) = min {
        all_ok &= report("version", &min_version(Version::own()?, min));
    }
    let mut offered = Vec::new();
    let mut remedy = Vec::new();
    for f in features {
        let mut outcome = evaluate(cfg, f);
        if explicit && outcome.status == Status::Skip {
            outcome = fail(format!("{} — requested but not enabled", outcome.detail));
        }
        let passed = report(f.name(), &outcome);
        if fix && !outcome.remedy.is_empty() {
            offered.push(f);
            remedy.append(&mut outcome.remedy);
        } else {
            all_ok &= passed;
        }
    }
    // Recheck after applying repairs to report remaining steps, usually a WSL restart
    // or a new login. Declining keeps the original failure.
    if !remedy.is_empty() {
        if apply(&remedy)? {
            for f in offered {
                all_ok &= report(f.name(), &evaluate(cfg, f));
            }
        } else {
            all_ok = false;
        }
    }
    Ok(all_ok)
}

/// Show the repair plan, ask for confirmation, and apply it. Declining returns false,
/// not an error. Stop at the first failed step and name it in the error.
fn apply(remedy: &[Step]) -> Result<bool, String> {
    // Gather the steps printed under individual checks into one plan for confirmation.
    println!();
    println!("to apply:");
    for step in remedy {
        println!("  {step}");
    }
    if !crate::dev::on_terminal() {
        return Err("refusing to apply without a terminal — run the steps above".to_string());
    }
    if !crate::dev::ask_on_terminal("apply?").map_err(|e| format!("{e:#}"))? {
        return Ok(false);
    }
    let mut manual = Vec::new();
    for step in remedy {
        match step {
            Step::Manual(what) => manual.push(what),
            _ => perform(step).map_err(|e| format!("{step}: {e:#}"))?,
        }
    }
    for what in manual {
        println!("  still yours to do: {what}");
    }
    Ok(true)
}

/// Carry out one step. A command inherits this process's streams, so `sudo` prompts on the
/// terminal [`apply`] has already insisted on.
fn perform(step: &Step) -> anyhow::Result<()> {
    use anyhow::Context;
    match step {
        Step::Run { argv, sudo } => {
            let argv = sudo_argv(argv, *sudo);
            let (prog, args) = argv.split_first().context("a step with no command")?;
            let status = std::process::Command::new(prog)
                .args(args)
                .status()
                .with_context(|| format!("running {prog}"))?;
            anyhow::ensure!(status.success(), "{prog} exited {status}");
            Ok(())
        }
        Step::EditWslconfig { .. } => {
            let path = crate::wsl::wslconfig_set_nested(&crate::wsl::Interop)?;
            println!("  wrote {}", path.display());
            Ok(())
        }
        Step::EditWslConf { command } => write_as_root(
            crate::wsl::WSL_CONF,
            &crate::wsl::wsl_conf_with_boot_command(command)?,
        ),
        // Collected by the caller and printed at the end instead.
        Step::Manual(_) => Ok(()),
    }
}

/// A step's argv to spawn, with `sudo` in front when the step needs root.
fn sudo_argv(argv: &[String], sudo: bool) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::with_capacity(argv.len() + usize::from(sudo));
    if sudo {
        out.push("sudo");
    }
    out.extend(argv.iter().map(String::as_str));
    out
}

/// The `sudo sh -c` script that writes `path` atomically: a sibling is written, mode-set, and
/// renamed over it, so a crash mid-write cannot leave the original truncated.
///
/// `path` is interpolated into the shell script unescaped, so it must be a trusted constant —
/// never a caller-supplied path. Today only [`crate::wsl::WSL_CONF`] reaches here.
fn write_as_root_script(path: &str) -> String {
    format!("cat > {path}.vk-new && chmod 644 {path}.vk-new && mv {path}.vk-new {path}")
}

/// Write `contents` to a file only root can write, feeding the bytes on stdin so no value of
/// ours reaches the shell and the file lands 0644, the mode WSL's own configuration has.
/// [`write_as_root_script`] does the atomic sibling-and-rename.
fn write_as_root(path: &str, contents: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;
    use std::io::Write;

    let script = write_as_root_script(path);
    let mut child = std::process::Command::new("sudo")
        .args(["sh", "-c", &script])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("running sudo sh to write {path}"))?;
    child
        .stdin
        .take()
        .context("sudo sh has no stdin")?
        .write_all(contents)
        .with_context(|| format!("writing {path}"))?;
    let status = child.wait().context("waiting for sudo sh")?;
    anyhow::ensure!(status.success(), "sudo sh exited {status}");
    Ok(())
}

/// Select deduplicated named features or the default sweep. A version-only request selects
/// none because it asks nothing about the host. `main` normally routes that case through
/// [`min_version_only`]; this remains a backstop.
fn selected(requested: &[Feature], min: Option<Version>) -> Vec<Feature> {
    if !requested.is_empty() {
        let mut v = Vec::new();
        for f in requested {
            if !v.contains(f) {
                v.push(*f);
            }
        }
        v
    } else if min.is_some() {
        Vec::new()
    } else {
        default_sweep()
    }
}

/// Print one check's line, and under it the steps that would make it pass; returns whether
/// it passed.
fn report(name: &str, outcome: &Outcome) -> bool {
    let label = match outcome.status {
        Status::Ok => "ok",
        Status::Skip => "skip",
        Status::Fail => "FAIL",
    };
    line(label, name, &outcome.detail);
    if !outcome.remedy.is_empty() {
        println!("     fix:");
        for step in &outcome.remedy {
            println!("       {step}");
        }
    }
    outcome.status != Status::Fail
}

/// Keep config and check line columns aligned.
fn line(label: &str, name: &str, detail: impl fmt::Display) {
    println!("{label:<4} {name:<8} {detail}");
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
        Feature::Publish => publish(),
        Feature::Nics => nics(),
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

/// Whether this `vk` can run `vk publish`. Asked for by name and never swept, for the
/// same reason as `entrypoint`: it is a property of the binary, not the host, and a
/// `vk` too old to have the command rejects the feature name outright rather than
/// reaching here.
///
/// The host side is the same agent asset `entrypoint`/`kernel` check for: `CmdConnect`
/// rides the agent's own control channel, so a `vk` with no agent to embed or find has
/// nothing to ask to dial out from a guest.
fn publish() -> Outcome {
    match asset_source(Asset::Agent) {
        Some(src) => ok(format!("agent {src} understands `vk publish` (CmdConnect)")),
        None => fail(format!(
            "no agent to ask: nothing embedded and {} missing",
            Asset::Agent.default_path()
        )),
    }
}

/// Whether this `vk` can give a guest more than one NIC (`vk run --nics`, or a compose
/// `x-virtkit: { nics: N }`). Asked for by name and never swept, for the same reason as
/// `entrypoint`/`publish`: it is a property of the binary, and a `vk` too old to have the
/// axis rejects the feature name outright rather than reaching here.
///
/// Extra NICs still require the agent. The VMM creates them under libkrun; the agent creates
/// taps under cloud-hypervisor. In both cases the agent addresses them from
/// `VIRTKIT_NET_EXTRA_IPS`, so `vk` cannot bring them up without an embedded or external
/// agent.
fn nics() -> Outcome {
    match asset_source(Asset::Agent) {
        Some(src) => ok(format!(
            "up to {} NICs per guest; agent {src} addresses them",
            crate::units::MAX_NICS
        )),
        None => fail(format!(
            "no agent to bring the extra NICs up: nothing embedded and {} missing",
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
    let Err(why) = kvm_ready(Path::new(KVM_DEV)) else {
        return ok(format!("rw access to {KVM_DEV}, KVM API v12"));
    };
    // A fresh WSL2 distro cannot host KVM in three ways the generic reason above does not
    // name, each with steps of its own. Anything else fails there as it does anywhere.
    match crate::wsl::is_wsl2()
        .then(wsl2_facts)
        .and_then(|facts| wsl2_kvm_remedy(&facts))
    {
        Some((detail, remedy)) => Outcome {
            status: Status::Fail,
            detail,
            remedy,
        },
        None => fail(why),
    }
}

const KVM_DEV: &str = "/dev/kvm";

/// Host facts gathered before the pure WSL2 KVM diagnosis runs.
struct Wsl2 {
    /// the CPU's virtualization extension, absent until nested virtualization takes effect
    virt: Option<crate::wsl::Virt>,
    /// whether `/dev/kvm` is there at all, and whether this process can use it
    kvm_present: bool,
    kvm_rw: bool,
    /// whether it is already `root:kvm` with the mode that lets the group use it
    kvm_mode_ok: bool,
    /// `%USERPROFILE%\.wslconfig` as Windows spells it, and its `nestedVirtualization`
    wslconfig: String,
    nested: Option<bool>,
    /// whether a `kvm` group exists, and whether this session's credentials include it
    kvm_group: bool,
    in_kvm_group: bool,
    /// the login name `usermod` takes
    user: String,
    /// what `/etc/wsl.conf` already runs at boot
    boot: Boot,
}

/// `/etc/wsl.conf`'s `[boot] command`, seen from the question of adding one.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Boot {
    /// none yet, so `vk` can write the one the fix needs
    None,
    /// one already there, printed for the user to extend — `vk` never rewrites it
    Other(String),
    /// unreadable, so what it runs cannot be judged
    Unreadable(String),
}

/// Read the facts. An interop failure is not an error here: the diagnosis is a report, and a
/// `.wslconfig` this distro cannot reach only leaves that step naming `%USERPROFILE%` itself.
fn wsl2_facts() -> Wsl2 {
    let dev = Path::new(KVM_DEV);
    let interop = crate::wsl::Interop;
    let kvm_gid = group_gid("kvm");
    Wsl2 {
        virt: crate::wsl::cpu_virt(),
        kvm_present: dev.exists(),
        kvm_rw: access_ok(dev, libc::R_OK | libc::W_OK),
        kvm_mode_ok: kvm_gid.is_some_and(|gid| owned_by(dev, gid)),
        wslconfig: crate::wsl::wslconfig_win_path(&interop),
        nested: crate::wsl::wslconfig_nested(&interop).ok().flatten(),
        kvm_group: kvm_gid.is_some(),
        in_kvm_group: kvm_gid.is_some_and(in_group),
        user: login_name(),
        boot: match crate::wsl::wsl_conf_boot_command() {
            Ok(None) => Boot::None,
            Ok(Some(command)) => Boot::Other(command),
            Err(e) => Boot::Unreadable(format!("{e:#}")),
        },
    }
}

/// The WSL2 diagnosis for a host [`kvm_ready`] refused, and the steps that would fix it.
/// `None` when none of these explains the refusal, leaving the generic reason to stand.
fn wsl2_kvm_remedy(facts: &Wsl2) -> Option<(String, Vec<Step>)> {
    let Some(virt) = facts.virt else {
        // Nesting is a Windows-side setting, and the distro sees it only as CPU flags that
        // are not there. Nothing distro-side is worth suggesting until it is on.
        return Some((
            "nested virtualization is off in WSL2 — no vmx/svm in /proc/cpuinfo (it needs \
             Windows 11, or the Store WSL on a recent Windows 10)"
                .to_string(),
            nesting_steps(facts),
        ));
    };
    let detail = if !facts.kvm_present {
        format!(
            "{KVM_DEV} missing in WSL2 — {} is not loaded",
            virt.module()
        )
    } else if !facts.kvm_rw {
        format!("no rw access to {KVM_DEV} — WSL2 creates it root:root 0600")
    } else {
        return None;
    };
    Some((detail, distro_steps(facts, virt)))
}

/// Turning nesting on: the `.wslconfig` key, and the WSL restart that applies it. Only the
/// user can ask for that restart — it ends every distro, this process included.
fn nesting_steps(facts: &Wsl2) -> Vec<Step> {
    let restart = "run `wsl --shutdown` in Windows, then reopen the distro";
    match facts.nested {
        Some(true) => vec![Step::Manual(format!(
            "nestedVirtualization=true is already set in {}; {restart}",
            facts.wslconfig
        ))],
        _ => vec![
            Step::EditWslconfig {
                path: facts.wslconfig.clone(),
            },
            Step::Manual(restart.to_string()),
        ],
    }
}

/// Loading the module and opening the device up to the `kvm` group, then what makes both
/// survive the next `wsl --shutdown` — a WSL2 distro boots without either.
fn distro_steps(facts: &Wsl2, virt: crate::wsl::Virt) -> Vec<Step> {
    let module = virt.module();
    let mut steps = Vec::new();
    if !facts.kvm_present {
        steps.push(sudo(&["modprobe", module]));
    }
    if !facts.kvm_group {
        steps.push(sudo(&["groupadd", "kvm"]));
    }
    let mut usermod = false;
    if !facts.in_kvm_group {
        match facts.user.is_empty() {
            false => {
                steps.push(sudo(&["usermod", "-aG", "kvm", &facts.user]));
                usermod = true;
            }
            // No passwd entry and no $USER: the name is the user's to supply.
            true => steps.push(Step::Manual(
                "add this login to the kvm group: sudo usermod -aG kvm <user>".to_string(),
            )),
        }
    }
    if !facts.kvm_mode_ok {
        steps.push(sudo(&["chown", "root:kvm", KVM_DEV]));
        steps.push(sudo(&["chmod", "660", KVM_DEV]));
    }
    if !steps.is_empty() {
        let command = format!("modprobe {module}; chown root:kvm {KVM_DEV}; chmod 660 {KVM_DEV}");
        steps.push(match &facts.boot {
            Boot::None => Step::EditWslConf { command },
            Boot::Other(existing) => Step::Manual(format!(
                "add to the existing `[boot] command` in {} (`{existing}`): `{command}` — \
                 without it the module and the {KVM_DEV} mode are gone after the next \
                 `wsl --shutdown`",
                crate::wsl::WSL_CONF
            )),
            Boot::Unreadable(why) => Step::Manual(format!(
                "{why} — put `{command}` in its `[boot] command`, or the module and the \
                 {KVM_DEV} mode are gone after the next `wsl --shutdown`"
            )),
        });
    }
    if usermod {
        steps.push(Step::Manual(
            "then log in again (or `wsl --shutdown`) so the group membership applies".to_string(),
        ));
    }
    steps
}

/// A group's gid, or `None` when this host has no such group.
fn group_gid(name: &str) -> Option<libc::gid_t> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: `c` is a valid NUL-terminated name. `getgrnam` returns a pointer into static
    // storage or null, and the gid is copied out before anything else can call it again.
    unsafe { libc::getgrnam(c.as_ptr()).as_ref().map(|g| g.gr_gid) }
}

/// Check current session credentials for `gid`, so pending `usermod` changes still prompt
/// the user to log in again.
fn in_group(gid: libc::gid_t) -> bool {
    // SAFETY: a size of 0 asks for the count and writes nothing; the second call fills a
    // buffer of exactly the length it is given. `getegid` cannot fail.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups = vec![0; usize::try_from(count).unwrap_or(0)];
    let len = libc::c_int::try_from(groups.len()).unwrap_or(0);
    let filled = unsafe { libc::getgroups(len, groups.as_mut_ptr()) };
    let egid = unsafe { libc::getegid() };
    egid == gid
        || groups
            .iter()
            .take(usize::try_from(filled).unwrap_or(0))
            .any(|g| *g == gid)
}

/// Check root:`gid` ownership and group access so redundant `chown`/`chmod` steps are omitted.
fn owned_by(dev: &Path, gid: libc::gid_t) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(dev)
        .is_ok_and(|md| md.uid() == 0 && md.gid() == gid && md.mode() & 0o777 == 0o660)
}

/// The login name `usermod` takes. `$USER` stands in for a uid with no passwd entry, as
/// `vk dev`'s WSL bridge does.
fn login_name() -> String {
    login_name_from(
        // SAFETY: getuid reads a thread-safe global and cannot fail.
        unsafe { libc::getuid() },
        std::env::var("SUDO_USER").ok(),
        crate::hostpolicy::self_passwd().ok().map(|(name, _)| name),
        std::env::var("USER").ok(),
    )
}

/// Resolve the login from explicit inputs so tests need no uid or environment changes.
/// Under `sudo`, use the invoker's `$SUDO_USER` instead of the root passwd entry. A root
/// login without `$SUDO_USER` returns an empty name, leaving the user to complete the
/// step instead of emitting `usermod … root`.
fn login_name_from(
    uid: libc::uid_t,
    sudo_user: Option<String>,
    passwd: Option<String>,
    user_env: Option<String>,
) -> String {
    if uid == 0 {
        return sudo_user
            .filter(|name| !name.is_empty())
            .unwrap_or_default();
    }
    passwd
        .filter(|name| !name.is_empty())
        .or(user_env)
        .unwrap_or_default()
}

/// Refuse to boot a microVM on a host this process cannot use KVM on, with the diagnosis
/// `vk check` gives. `vk run` and the executor's `prepare` call this before pulling or
/// building an image: without it a missing `/dev/kvm` surfaces only as the VMM aborting
/// mid-boot ("Error creating the Kvm object: Error(2)"), after the pull.
pub(crate) fn require_kvm() -> anyhow::Result<()> {
    kvm_ready(Path::new(KVM_DEV)).map_err(|why| anyhow::anyhow!("{why} — see `vk check`"))
}

/// Whether `dev` (normally `/dev/kvm`) is a usable KVM device for this process: present,
/// readable and writable, and answering KVM_GET_API_VERSION with the stable API. `Err` is
/// the user-facing reason it is not.
fn kvm_ready(dev: &Path) -> Result<(), String> {
    let name = dev.display();
    if !dev.exists() {
        return Err(format!(
            "{name} missing (is KVM enabled — kvm_intel/kvm_amd loaded?)"
        ));
    }
    if !access_ok(dev, libc::R_OK | libc::W_OK) {
        return Err(format!(
            "no rw access to {name} (is the user in the kvm group?)"
        ));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev)
        .map_err(|e| format!("opening {name}: {e}"))?;
    // KVM_GET_API_VERSION (_IO(0xAE, 0x00)); the stable KVM API is pinned at 12.
    // KVM insists the unused ioctl argument is 0 (EINVAL otherwise), so pass it
    // explicitly rather than leaving the variadic slot to garbage.
    let version = unsafe { libc::ioctl(file.as_raw_fd(), 0xAE00 as _, 0) };
    if version < 0 {
        return Err(format!(
            "KVM_GET_API_VERSION on {name} failed: {} (a sandbox/seccomp profile blocking KVM ioctls?)",
            std::io::Error::last_os_error()
        ));
    }
    if version != 12 {
        return Err(format!("unexpected KVM API version {version} (want 12)"));
    }
    Ok(())
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

/// What is wrong with a `token_file`, if anything: unreadable, or holding nothing once trimmed. The
/// empty case is worth its own report — `Creds::from_files` refuses it rather than sending an empty
/// `Bearer `, so a provisioning script that created the file but never wrote to it fails the first
/// pull, which is exactly what `vk check` is for. `what` prefixes the problem so
/// `[docker.mirror]`'s reads "mirror token_file …".
fn token_problem(token_file: &Path, what: &str) -> Option<String> {
    match std::fs::read_to_string(token_file) {
        Err(e) => Some(format!(
            "{what}token_file unreadable: {} ({e})",
            token_file.display()
        )),
        Ok(t) if t.trim().is_empty() => {
            Some(format!("{what}token_file empty: {}", token_file.display()))
        }
        Ok(_) => None,
    }
}

/// What is wrong with a section's Basic pair, if anything. Nothing when a `token_file`
/// supersedes it: every resolver — `Creds::from_files`, `registry::cred`, and through the
/// former the guest credential proxy — returns on the token and never opens the password.
/// `what` prefixes the problem, as it does for [`token_problem`].
fn basic_problem(
    username: &str,
    password_file: Option<&Path>,
    token_file: Option<&Path>,
    what: &str,
) -> Option<String> {
    if username.is_empty() || token_file.is_some() {
        return None;
    }
    match password_file {
        Some(p) if !access_ok(p, libc::R_OK) => {
            Some(format!("{what}password_file unreadable: {}", p.display()))
        }
        Some(_) => None,
        None => Some(format!("{what}username set but no password_file")),
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
    if let Some(t) = &d.token_file {
        problems.extend(token_problem(t, ""));
    }
    problems.extend(basic_problem(
        &d.username,
        d.password_file.as_deref(),
        d.token_file.as_deref(),
        "",
    ));
    if let Some(m) = &d.mirror {
        if let Some(ca) = &m.ca_file
            && !access_ok(ca, libc::R_OK)
        {
            problems.push(format!("mirror ca_file unreadable: {}", ca.display()));
        }
        if let Some(t) = &m.token_file {
            problems.extend(token_problem(t, "mirror "));
        }
        problems.extend(basic_problem(
            &m.username,
            m.password_file.as_deref(),
            m.token_file.as_deref(),
            "mirror ",
        ));
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
    if let Some(t) = &r.token_file {
        problems.extend(token_problem(t, ""));
    }
    problems.extend(basic_problem(
        &r.username,
        r.password_file.as_deref(),
        r.token_file.as_deref(),
        "",
    ));
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
    // `[vm] nested` needs host KVM loaded with nested=1. vm::prepare refuses each job it
    // would boot; failing here too catches the runner before any of them, as the atop
    // interval below does.
    if let Err(e) =
        crate::vm::refuse_unsupported_nesting(cfg.vm.nested, crate::vmm::host_nesting_enabled())
    {
        return fail(format!("{e:#}"));
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
    let nesting = if cfg.vm.nested {
        "job VMs may nest (`[vm] nested`)"
    } else {
        "no nesting"
    };
    ok(format!(
        "jobs dir {} writable, {stats}, {nesting}",
        jobs.display()
    ))
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

    /// The pre-boot refusal names what is wrong with the device: absent, or not KVM at all
    /// (a regular file opens rw but has no KVM ioctls — ENOTTY).
    #[test]
    fn kvm_readiness_says_why_a_device_is_unusable() {
        let dir = std::env::temp_dir().join(format!("vk-kvm-ready-{}", std::process::id()));
        // Remove leftovers from an aborted run with the same pid so the first
        // assertion sees a missing device.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dev = dir.join("kvm");
        assert!(kvm_ready(&dev).unwrap_err().contains("missing"));
        std::fs::write(&dev, b"").unwrap();
        assert!(kvm_ready(&dev).unwrap_err().contains("KVM_GET_API_VERSION"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Keep the crate version compatible with `Version::own`.
    #[test]
    fn the_build_version_parses() {
        let raw = env!("CARGO_PKG_VERSION");
        assert_eq!(
            raw.parse::<Version>().map(|v| v.to_string()),
            Ok(raw.to_string())
        );
        assert_eq!(Version::own().map(|v| v.to_string()), Ok(raw.to_string()));
    }

    /// Accept the tag's `v` prefix and zero-fill missing fields.
    #[test]
    fn versions_parse_and_order_field_by_field() {
        let v = |s: &str| s.parse::<Version>().unwrap();
        assert_eq!(v("0.45.0"), v("v0.45.0"));
        assert_eq!(v("0.45"), v("0.45.0"));
        assert_eq!(v("1"), v("1.0.0"));
        // Field by field, not lexicographically: 0.9 is behind 0.10, and 0.45.1 behind 0.46.
        assert!(v("0.10.0") > v("0.9.0"));
        assert!(v("0.45.1") < v("0.46.0"));
        assert!(v("0.45.0") >= v("0.45"));
    }

    /// Reject suffixes (as `vk-selfupdate` does), signs, whitespace, and oversized fields.
    #[test]
    fn versions_refuse_what_they_cannot_order() {
        let bad = [
            "",
            "v",
            "V0.45",
            "0.x",
            "1.2.3.4",
            "0..1",
            "-1",
            "+1",
            "0.+45",
            "0.45.0-rc1",
            "0.45.0-dev",
            "0.45.0+build",
            " 0.45",
            "0.45 ",
            "99999999999999999999",
        ];
        for s in bad {
            assert!(s.parse::<Version>().is_err(), "{s} parsed");
        }
    }

    /// Pass floors through the current version and fail above it, naming both versions.
    #[test]
    fn min_version_reports_both_versions_either_way() {
        let have = Version([0, 45, 0]);
        let names_both = |o: &Outcome, min: Version| {
            o.detail.contains(&have.to_string()) && o.detail.contains(&min.to_string())
        };

        for min in [Version([0, 0, 0]), Version([0, 45, 0])] {
            let outcome = min_version(have, min);
            assert_eq!(outcome.status, Status::Ok, "{}", outcome.detail);
            assert!(names_both(&outcome, min), "{}", outcome.detail);
        }

        // A patch field the caller left off is zero, so 0.45 is met and 0.45.1 is not.
        let min = Version([0, 45, 1]);
        let outcome = min_version(have, min);
        assert_eq!(outcome.status, Status::Fail);
        assert!(outcome.detail.contains("older than"), "{}", outcome.detail);
        assert!(names_both(&outcome, min), "{}", outcome.detail);
    }

    /// A version-only check answers without config or feature evaluation.
    #[test]
    fn a_minimum_version_alone_answers_without_a_config() {
        let Version([major, ..]) = Version::own().unwrap();
        assert_eq!(min_version_only(Version([0, 0, 0])), Ok(true));
        assert_eq!(min_version_only(Version([major + 1, 0, 0])), Ok(false));
    }

    /// A version floor never widens the selected feature set and alone empties it.
    #[test]
    fn a_minimum_version_never_widens_the_feature_set() {
        let min = Some(Version([0, 45, 0]));
        assert_eq!(selected(&[], None), default_sweep());
        assert!(selected(&[], min).is_empty());
        assert_eq!(selected(&[Feature::Gitlab], min), vec![Feature::Gitlab]);
        assert_eq!(selected(&[Feature::Gitlab], None), vec![Feature::Gitlab]);
        // Named twice is checked once, whether or not a version came with it.
        assert_eq!(
            selected(&[Feature::Gitlab, Feature::Gitlab], min),
            vec![Feature::Gitlab]
        );
    }

    /// `[registry]` follows the same precedence as `[docker]`, because `registry::cred`
    /// does: a readable `token_file` settles the credential, so the `password_file` it
    /// never opens is not a problem — but an empty token file is, since `cred` refuses it.
    #[test]
    fn the_registry_check_follows_the_token_precedence() {
        let dir = std::env::temp_dir().join(format!("vk-check-registry-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let token = dir.join("token");
        let section = |token_file: Option<PathBuf>| Config {
            registry: Some(crate::config::Registry::for_share(
                "registry.example.com/team".to_string(),
                false,
                None,
                "ci".to_string(),
                // Deliberately absent: what the Basic path would fail on.
                Some(dir.join("absent")),
                token_file,
                None,
            )),
            ..Config::default()
        };

        std::fs::write(&token, "vkr_x\n").unwrap();
        assert_eq!(registry(&section(Some(token.clone()))).status, Status::Ok);

        std::fs::write(&token, "  \n").unwrap();
        let out = registry(&section(Some(token)));
        assert_eq!(out.status, Status::Fail);
        assert!(out.detail.contains("token_file empty"), "{}", out.detail);

        // With no token to supersede it, the unreadable password_file is reported again.
        let out = registry(&section(None));
        assert_eq!(out.status, Status::Fail);
        assert!(
            out.detail.contains("password_file unreadable"),
            "{}",
            out.detail
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A `[docker]` whose `token_file` supersedes the Basic pair: the superseded
    /// `password_file` is never read by `Creds::from_files`, so an unreadable one is not a
    /// problem to report — but an empty token file is, since the pull refuses it.
    #[test]
    fn the_docker_check_follows_the_token_precedence() {
        let dir = std::env::temp_dir().join(format!("vk-check-docker-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let token = dir.join("token");
        let section = |token_file: Option<PathBuf>| Config {
            docker: Some(crate::config::Docker {
                repo: Some("registry.example.com/team".to_string()),
                ca_file: None,
                username: "ci".to_string(),
                // Deliberately absent: what the Basic path would fail on.
                password_file: Some(dir.join("absent")),
                token_file,
                insecure: false,
                mirror: None,
            }),
            ..Config::default()
        };

        std::fs::write(&token, "vkr_x\n").unwrap();
        assert_eq!(docker(&section(Some(token.clone()))).status, Status::Ok);

        std::fs::write(&token, "  \n").unwrap();
        let out = docker(&section(Some(token)));
        assert_eq!(out.status, Status::Fail);
        assert!(out.detail.contains("token_file empty"), "{}", out.detail);

        // With no token to supersede it, the unreadable password_file is reported again.
        let out = docker(&section(None));
        assert_eq!(out.status, Status::Fail);
        assert!(
            out.detail.contains("password_file unreadable"),
            "{}",
            out.detail
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
    // default state dirs, and `entrypoint`/`publish` answer for the build, not the host.
    // The default sweep covers everything else.
    #[test]
    fn default_sweep_omits_the_named_only_features() {
        let sweep = default_sweep();
        assert!(!sweep.contains(&Feature::Gitlab));
        assert!(!sweep.contains(&Feature::Services));
        assert!(!sweep.contains(&Feature::Entrypoint));
        assert!(!sweep.contains(&Feature::Publish));
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

    // Same shape as the entrypoint probe: never skips (a `cargo test` binary embeds no
    // agent, so this fails rather than declining to answer), and a `vk` without the
    // command never reaches this — clap rejects the feature name first.
    #[test]
    fn the_publish_probe_never_skips() {
        let outcome = evaluate(&Config::default(), Feature::Publish);
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
        // The default config grants no nesting, and the check says so rather than leaving
        // an operator to guess whether the grant took.
        assert!(out.detail.contains("no nesting"), "{}", out.detail);

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

    /// A distro with everything still to do, which is what a fresh WSL2 install is.
    fn wsl2() -> Wsl2 {
        Wsl2 {
            virt: Some(crate::wsl::Virt::Intel),
            kvm_present: false,
            kvm_rw: false,
            kvm_mode_ok: false,
            wslconfig: r"C:\Users\dev\.wslconfig".to_string(),
            nested: None,
            kvm_group: false,
            in_kvm_group: false,
            user: "dev".to_string(),
            boot: Boot::None,
        }
    }

    /// Every step as the report prints it.
    fn steps(remedy: &[Step]) -> Vec<String> {
        remedy.iter().map(Step::to_string).collect()
    }

    /// `usermod` has to name the invoking user, never the root `sudo vk check --fix` runs as:
    /// under sudo that is `$SUDO_USER`, and a bare root login (no `$SUDO_USER`) names no one.
    #[test]
    fn the_login_to_add_is_the_invoker_not_root() {
        // Not root: the passwd entry answers, and $USER only stands in for a uid without one.
        assert_eq!(
            login_name_from(1000, None, Some("dev".into()), Some("shell".into())),
            "dev"
        );
        assert_eq!(
            login_name_from(1000, None, Some(String::new()), Some("shell".into())),
            "shell"
        );
        assert_eq!(login_name_from(1000, None, None, None), "");
        // Root via sudo: the invoker, not the root the process now runs as.
        assert_eq!(
            login_name_from(
                0,
                Some("dev".into()),
                Some("root".into()),
                Some("root".into())
            ),
            "dev"
        );
        // A real root login has no invoker to name, so the step is left for the user.
        assert_eq!(
            login_name_from(0, None, Some("root".into()), Some("root".into())),
            ""
        );
        assert_eq!(login_name_from(0, Some(String::new()), None, None), "");
    }

    /// An unknown invoker (root with no `$SUDO_USER`) gets the `<user>` step to complete by
    /// hand, never a `usermod` that would add root to the group instead.
    #[test]
    fn an_unknown_login_leaves_the_group_step_manual() {
        let remedy = distro_steps(
            &Wsl2 {
                user: String::new(),
                ..wsl2()
            },
            crate::wsl::Virt::Intel,
        );
        assert!(
            steps(&remedy)
                .iter()
                .any(|s| s.contains("usermod -aG kvm <user>")),
            "{:?}",
            steps(&remedy)
        );
        assert!(
            !steps(&remedy)
                .iter()
                .any(|s| s.contains("usermod -aG kvm root")),
            "never adds root: {:?}",
            steps(&remedy)
        );
    }

    /// `sudo` goes in front only when the step needs root; the program stays first otherwise.
    #[test]
    fn sudo_prefixes_only_privileged_steps() {
        let argv = [
            "usermod".to_string(),
            "-aG".to_string(),
            "kvm".to_string(),
            "dev".to_string(),
        ];
        assert_eq!(
            sudo_argv(&argv, true),
            ["sudo", "usermod", "-aG", "kvm", "dev"]
        );
        assert_eq!(sudo_argv(&argv, false), ["usermod", "-aG", "kvm", "dev"]);
        assert_eq!(sudo_argv(&[], false), Vec::<&str>::new());
    }

    /// The atomic-write script stages a sibling and renames it over the target, never
    /// truncating the original in place.
    #[test]
    fn the_root_write_script_renames_a_sibling_into_place() {
        assert_eq!(
            write_as_root_script("/etc/wsl.conf"),
            "cat > /etc/wsl.conf.vk-new && chmod 644 /etc/wsl.conf.vk-new && \
             mv /etc/wsl.conf.vk-new /etc/wsl.conf"
        );
    }

    /// No vmx/svm is the Windows side's problem: the `.wslconfig` key, and the WSL restart
    /// that applies it. Nothing distro-side is suggested — none of it can work yet.
    #[test]
    fn a_distro_without_nesting_is_pointed_at_the_wslconfig() {
        let (detail, remedy) = wsl2_kvm_remedy(&Wsl2 {
            virt: None,
            ..wsl2()
        })
        .expect("a diagnosis");
        assert!(detail.contains("nested virtualization is off"), "{detail}");
        assert!(detail.contains("no vmx/svm"), "{detail}");
        assert_eq!(
            steps(&remedy),
            [
                r"write `[wsl2] nestedVirtualization=true` to C:\Users\dev\.wslconfig",
                "run `wsl --shutdown` in Windows, then reopen the distro",
            ]
        );

        // Already set: only WSL restarting can apply it, so that is the whole remedy.
        let (_, remedy) = wsl2_kvm_remedy(&Wsl2 {
            virt: None,
            nested: Some(true),
            ..wsl2()
        })
        .expect("a diagnosis");
        assert_eq!(
            steps(&remedy),
            [concat!(
                r"nestedVirtualization=true is already set in C:\Users\dev\.wslconfig; ",
                "run `wsl --shutdown` in Windows, then reopen the distro"
            )]
        );
    }

    /// Nesting on but no device: the module, the group, the mode, what keeps all three across
    /// a `wsl --shutdown`, and the new login the group membership needs.
    #[test]
    fn a_distro_without_the_module_is_given_every_step_in_order() {
        let (detail, remedy) = wsl2_kvm_remedy(&wsl2()).expect("a diagnosis");
        assert!(detail.contains("/dev/kvm missing in WSL2"), "{detail}");
        assert!(detail.contains("kvm_intel is not loaded"), "{detail}");
        assert_eq!(
            steps(&remedy)[..5],
            [
                "sudo modprobe kvm_intel",
                "sudo groupadd kvm",
                "sudo usermod -aG kvm dev",
                "sudo chown root:kvm /dev/kvm",
                "sudo chmod 660 /dev/kvm",
            ]
        );
        assert_eq!(
            remedy[5],
            Step::EditWslConf {
                command: "modprobe kvm_intel; chown root:kvm /dev/kvm; chmod 660 /dev/kvm"
                    .to_string(),
            }
        );
        assert!(steps(&remedy)[5].contains("gone after the next `wsl --shutdown`"));
        assert!(steps(&remedy)[6].contains("log in again"));

        // The module named is the one this CPU needs.
        let (detail, remedy) = wsl2_kvm_remedy(&Wsl2 {
            virt: Some(crate::wsl::Virt::Amd),
            ..wsl2()
        })
        .expect("a diagnosis");
        assert!(detail.contains("kvm_amd is not loaded"), "{detail}");
        assert_eq!(steps(&remedy)[0], "sudo modprobe kvm_amd");
    }

    /// A device that is there but not usable: only what is actually missing is asked for, and
    /// a `[boot] command` that is already something else is never rewritten.
    #[test]
    fn a_device_without_access_is_given_only_the_steps_it_needs() {
        let facts = Wsl2 {
            kvm_present: true,
            kvm_group: true,
            boot: Boot::Other("mount -t drvfs C: /mnt/c".to_string()),
            ..wsl2()
        };
        let (detail, remedy) = wsl2_kvm_remedy(&facts).expect("a diagnosis");
        assert!(detail.contains("no rw access to /dev/kvm"), "{detail}");
        assert_eq!(
            steps(&remedy)[..3],
            [
                "sudo usermod -aG kvm dev",
                "sudo chown root:kvm /dev/kvm",
                "sudo chmod 660 /dev/kvm",
            ]
        );
        let boot = &steps(&remedy)[3];
        assert!(
            boot.starts_with("add to the existing `[boot] command`"),
            "{boot}"
        );
        assert!(boot.contains("mount -t drvfs C: /mnt/c"), "{boot}");
        assert!(!remedy.iter().any(|s| matches!(s, Step::EditWslConf { .. })));

        // A device already root:kvm 0660, with this session in the group: the mode and the
        // membership steps drop out, leaving only what has to be redone after a restart.
        let (_, remedy) = wsl2_kvm_remedy(&Wsl2 {
            kvm_mode_ok: true,
            in_kvm_group: true,
            boot: Boot::None,
            ..facts
        })
        .expect("a diagnosis");
        assert!(steps(&remedy).is_empty(), "{:?}", steps(&remedy));
    }

    /// A step reads as the command to run or the edit to make, so the report is worth
    /// pasting into a shell whether or not `--fix` is used.
    #[test]
    fn a_step_reads_as_what_it_does() {
        assert_eq!(
            sudo(&["chmod", "660", KVM_DEV]).to_string(),
            "sudo chmod 660 /dev/kvm"
        );
        assert_eq!(
            Step::Run {
                argv: vec!["modprobe".to_string(), "kvm_intel".to_string()],
                sudo: false,
            }
            .to_string(),
            "modprobe kvm_intel"
        );
        assert_eq!(
            Step::EditWslconfig {
                path: r"C:\Users\dev\.wslconfig".to_string(),
            }
            .to_string(),
            r"write `[wsl2] nestedVirtualization=true` to C:\Users\dev\.wslconfig"
        );
        let boot = Step::EditWslConf {
            command: "modprobe kvm_amd".to_string(),
        }
        .to_string();
        assert!(
            boot.contains("`[boot] command = modprobe kvm_amd`"),
            "{boot}"
        );
        assert!(boot.contains("/etc/wsl.conf"), "{boot}");
        assert_eq!(
            Step::Manual("reopen the distro".to_string()).to_string(),
            "reopen the distro"
        );
    }

    /// A refusal none of these cases explains — a device that opens but answers no KVM ioctl
    /// — keeps the generic reason rather than being given steps that would not help.
    #[test]
    fn a_usable_device_that_still_fails_gets_no_wsl_steps() {
        assert_eq!(
            wsl2_kvm_remedy(&Wsl2 {
                kvm_present: true,
                kvm_rw: true,
                ..wsl2()
            }),
            None
        );
    }

    #[test]
    fn dir_writable_probes_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("vk-check-test-{}", std::process::id()));
        dir_writable(&dir).unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir(&dir).unwrap();
    }
}
