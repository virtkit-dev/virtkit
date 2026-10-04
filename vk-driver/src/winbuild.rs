//! `vk build` of a Windows Dockerfile: a stage starts from `FROM winiso:` ([`crate::winiso`]), an
//! earlier stage or a bundle an earlier build wrote, and each `RUN` or `COPY` is a layer — a
//! qcow2 overlay over the one before, cached by its parent and the instruction — made by booting
//! the guest on it, acting through qemu-ga ([`crate::winexec`]) and powering it off cleanly.
//! `ENV`, `WORKDIR` and `SHELL` shape the `RUN` steps after them. `# vk: disk=` sizes a
//! `winiso:` stage's install, `# vk: generalize=on` ends the stage with sysprep, and
//! `# vk: firmware=uefi-secboot` (experimental) enrolls Microsoft's Secure Boot keys. The result
//! is a bundle `vk run` boots, which records its layer so another Dockerfile can build `FROM` it
//! against the same build cache: the record names the layer, and only the cache that made it
//! holds its disk.
//!
//! As Docker does on Windows, a shell-form `RUN` is the program line `<SHELL> <text>` (by
//! default `cmd /S /C <text>`), and runs as qemu-ga does, as SYSTEM. Its exit code 3010 or 1641
//! asks for a restart (`--reboot=auto`); `--reboot=always|never` overrides. A step has no
//! network unless its `RUN` says `--network=default`. `CMD` is the image's provisioning, which
//! the bundle records; `ENTRYPOINT` is refused.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::build::hex;
use crate::build::parser::{self, Cmdline, Instruction};
use crate::qga::Client;
use crate::vmm::Disk;
use crate::winiso::flag;

/// The shell of a shell-form `RUN`, as Docker's on Windows.
const DEFAULT_SHELL: [&str; 3] = ["cmd", "/S", "/C"];

/// The disk a `FROM winiso:` stage installs onto.
const DEFAULT_DISK: u64 = 40 << 30;

/// How long a booting guest has for its qemu-ga to answer.
const AGENT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// How long sysprep has to generalize the image and power the guest off.
const SYSPREP_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// A bundle's record of the layer it boots.
const LAYER_RECORD: &str = "layer.json";

/// The version of the [`LAYER_RECORD`] format this build writes and reads.
const LAYER_RECORD_VERSION: u64 = 1;

/// Whether `text` is a Dockerfile for Windows: one of its stages installs from `winiso:`,
/// names the Windows platform, or starts from a bundle a Windows build wrote (relative to
/// `context`).
pub(crate) fn is_windows(text: &str, context: &Path) -> Result<bool> {
    Ok(parser::parse(text)?.instructions.iter().any(|i| match i {
        Instruction::From(f) => {
            f.image.starts_with(crate::winiso::SCHEME)
                || f.platform
                    .as_deref()
                    .is_some_and(|p| p.starts_with("windows"))
                || layer_record(&context.join(&f.image)).is_some()
        }
        _ => false,
    }))
}

/// What to build.
pub(crate) struct Options {
    pub dockerfile: PathBuf,
    pub context: PathBuf,
    pub target: Option<String>,
    /// The bundle directory to write.
    pub out: PathBuf,
    pub cpus: u32,
    pub mem: String,
    /// `--build-net none`: refuse `RUN --network=default`.
    pub no_network: bool,
}

/// A stage as it builds: its current layer and what its later `RUN`s inherit. A bundle
/// records it (`layer.json`) so another Dockerfile can build `FROM` the bundle: its key, shell,
/// `ENV`, `WORKDIR` and `CMD`; the disk is the cache's for that key, and the password is the
/// bundle's `admin-password`. The bundle builds only against the cache that made it.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct Layer {
    #[serde(skip)]
    disk: PathBuf,
    key: String,
    #[serde(skip)]
    password: String,
    shell: Vec<String>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    /// The image's `CMD`, as the Windows command line a service runs at each start (its
    /// provisioning: hostname, address, domain join).
    #[serde(default)]
    provision: Option<String>,
    /// `# vk: firmware=uefi-secboot` (experimental): the image's machines, and the build's
    /// guests, start with Microsoft's Secure Boot keys enrolled. Inherited by a stage built on
    /// this one. The image does not carry the build guest's variables: each machine starts from
    /// the template. Without SMM this guards only the boot chain below the guest's kernel, which
    /// can rewrite the variable store directly (PK, KEK, db, dbx, or Secure Boot off, for good).
    /// A variable write Windows authenticates at run time (its Secure Boot update task writing
    /// db or dbx) is known to bug-check 0x1E in the firmware's runtime services.
    #[serde(default)]
    secure_boot: bool,
    /// `# vk: tpm=on`: the image's machines have a TPM 2.0, each its own. The build's guests
    /// have none: Windows could seal something to a TPM that ends with its step (Windows 11's
    /// automatic device encryption does, leaving an image no machine can boot). Inherited by a
    /// stage built on this one.
    #[serde(default)]
    tpm: bool,
    /// Variables set by `ENV` since the last step, still to be made machine-wide.
    #[serde(skip)]
    unsaved_env: Vec<(String, String)>,
    /// `WORKDIR` changed since the last step: the directory is still to be created.
    #[serde(skip)]
    unmade_workdir: bool,
    /// Sysprep made this layer: its next step deletes the answer file the generalize step left.
    #[serde(default)]
    generalized: bool,
}

struct Stage {
    from: parser::From,
    body: Vec<Instruction>,
}

impl Stage {
    fn label(&self, index: usize) -> String {
        self.from
            .as_name
            .clone()
            .unwrap_or_else(|| index.to_string())
    }

    /// The value of the `# vk:` Windows directive `name` above the stage's `FROM`.
    fn directive(&self, name: &str) -> Option<&str> {
        self.from
            .guest
            .windows
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

fn stages(df: parser::Dockerfile) -> Result<Vec<Stage>> {
    let mut stages: Vec<Stage> = Vec::new();
    for instruction in df.instructions {
        match (instruction, stages.last_mut()) {
            (Instruction::From(from), _) => stages.push(Stage {
                from,
                body: Vec::new(),
            }),
            (other, Some(stage)) => stage.body.push(other),
            (other, None) => bail!("{} before the first FROM", parser::keyword_of(&other)),
        }
    }
    Ok(stages)
}

/// The stage `target` names (its `AS` name or index), or the last one.
fn target_index(stages: &[Stage], target: Option<&str>) -> Result<usize> {
    match target {
        Some(t) => stages
            .iter()
            .position(|s| s.from.as_name.as_deref() == Some(t))
            .or_else(|| t.parse::<usize>().ok().filter(|i| *i < stages.len()))
            .with_context(|| format!("no stage {t:?}")),
        None => stages.len().checked_sub(1).context("no FROM"),
    }
}

/// The vCPUs and memory of a stage's guests: its `# vk:` line's, else the build's.
fn guest_size(stage: &Stage, opts: &Options) -> (u32, String) {
    let guest = &stage.from.guest;
    (
        guest.cpus.unwrap_or(opts.cpus),
        guest.mem.clone().unwrap_or_else(|| opts.mem.clone()),
    )
}

/// Build `opts` and write its bundle.
pub(crate) fn build(opts: &Options) -> Result<()> {
    let text = std::fs::read_to_string(&opts.dockerfile)
        .with_context(|| format!("reading {}", opts.dockerfile.display()))?;
    let stages =
        stages(parser::parse(&text)?).with_context(|| format!("{}", opts.dockerfile.display()))?;
    let target = target_index(&stages, opts.target.as_deref())
        .with_context(|| format!("{}", opts.dockerfile.display()))?;
    let cache = crate::run::default_data_base()?.join("windows");
    let started = Instant::now();
    let mut built: HashMap<usize, Layer> = HashMap::new();
    let layer = build_stage(&stages, target, opts, &cache, &mut built)?;
    let (cpus, mem) = guest_size(&stages[target], opts);
    write_bundle(&layer, cpus, &mem, &opts.out)?;
    eprintln!(
        "virtkit: built {} in {}s",
        opts.out.display(),
        started.elapsed().as_secs()
    );
    Ok(())
}

/// Refuse what `stage` asks for that a Windows build does not do, before anything boots.
fn check_stage(stage: &Stage, context: &Path, no_network: bool) -> Result<()> {
    let from = &stage.from;
    let winiso =
        crate::winiso::Source::of_stage(&from.image, &from.extra_flags, context)?.is_some();
    for (key, value) in &from.guest.windows {
        match key.as_str() {
            "disk" if !winiso => bail!("`# vk: disk` sizes a winiso: stage's install only"),
            "disk" => {
                disk_size(value)?;
            }
            "generalize" if !matches!(value.as_str(), "on" | "off") => {
                bail!("`# vk: generalize={value}`: expected on or off")
            }
            "generalize" => {}
            "firmware" if !matches!(value.as_str(), "uefi" | "uefi-secboot") => {
                bail!("`# vk: firmware={value}`: expected uefi or uefi-secboot")
            }
            "firmware" => {}
            "tpm" if !matches!(value.as_str(), "on" | "off") => {
                bail!("`# vk: tpm={value}`: expected on or off")
            }
            "tpm" => {}
            // Parsed for the Windows build, which does not act on them yet.
            _ => bail!("`# vk: {key}` is not supported yet"),
        }
    }
    if !winiso && let Some((name, _)) = from.extra_flags.first() {
        bail!(
            "FROM {}: --{name} applies to a winiso: stage only",
            from.image
        );
    }
    for instruction in &stage.body {
        match instruction {
            Instruction::Run(run) => {
                reboot_mode(run)?;
                if network_mode(run)? && no_network {
                    bail!("RUN --network=default: --build-net none forbids it");
                }
            }
            Instruction::Copy(copy) => {
                if copy.from.is_some() {
                    bail!("COPY --from is not supported in a Windows build yet");
                }
                if copy.chown.is_some() || copy.chmod.is_some() || copy.link {
                    bail!("COPY --chown, --chmod and --link do not apply to a Windows build");
                }
                for path in copy.sources.iter().chain([&copy.dest]) {
                    no_substitution("COPY", path)?;
                }
            }
            Instruction::Env(pairs) => {
                for (key, value) in pairs {
                    no_substitution(&format!("ENV {key}"), value)?;
                }
            }
            Instruction::Workdir(dir) => no_substitution("WORKDIR", dir)?,
            Instruction::Other { name, args } if name == "SHELL" => {
                shell(args)?;
            }
            Instruction::Other { name, .. } if matches!(name.as_str(), "ADD" | "ONBUILD") => {
                bail!("{name} is not supported in a Windows build")
            }
            Instruction::Arg { name, .. } => {
                bail!("ARG {name}: a Windows build takes no build arguments")
            }
            Instruction::User(user) => {
                bail!("USER {user}: a Windows build runs every step as SYSTEM, through qemu-ga")
            }
            Instruction::Entrypoint(_) => {
                bail!("ENTRYPOINT: a Windows image provisions with CMD alone")
            }
            _ => {}
        }
    }
    Ok(())
}

/// The install disk `# vk: disk=<size>` asks for, in bytes: 20G or more.
fn disk_size(size: &str) -> Result<u64> {
    crate::run::parse_mem_mib(size)
        .filter(|&mib| mib >= 20 << 10)
        .and_then(|mib| mib.checked_mul(1 << 20))
        .with_context(|| format!("`# vk: disk={size}`: expected a size of at least 20G"))
}

/// Refuse a `$` variable reference in `text`, which Docker would substitute and a Windows
/// build does not.
fn no_substitution(what: &str, text: &str) -> Result<()> {
    let refers = text
        .split('$')
        .skip(1)
        .any(|rest| rest.starts_with(|c: char| c == '{' || c == '_' || c.is_ascii_alphabetic()));
    if refers {
        bail!("{what} {text}: variable substitution is not supported in a Windows build");
    }
    Ok(())
}

/// The `SHELL` instruction's arguments as the shell's argv.
fn shell(args: &str) -> Result<Vec<String>> {
    match serde_json::from_str::<Vec<String>>(args.trim()) {
        Ok(argv) if !argv.is_empty() => Ok(argv),
        _ => bail!("SHELL {args}: expected a non-empty JSON array"),
    }
}

/// A `RUN`'s `--reboot` (`auto` by default), refusing the flags a Windows build does not take.
fn reboot_mode(run: &parser::Run) -> Result<&str> {
    if !run.mounts.is_empty() || run.security.is_some() {
        bail!("RUN --mount and --security do not apply to a Windows build");
    }
    if let Some((name, _)) = run.extra_flags.iter().find(|(k, _)| k != "reboot") {
        bail!("RUN --{name}: a Windows build takes --reboot only");
    }
    if run.extra_flags.len() > 1 {
        bail!("RUN --reboot given twice");
    }
    match flag(&run.extra_flags, "reboot").unwrap_or("auto") {
        reboot @ ("auto" | "always" | "never") => Ok(reboot),
        reboot => bail!("RUN --reboot={reboot}: expected auto, always or never"),
    }
}

/// Whether a `RUN` has a network: none unless it says `--network=default`.
fn network_mode(run: &parser::Run) -> Result<bool> {
    match run.network.as_deref() {
        None | Some("none") => Ok(false),
        Some("default") => Ok(true),
        Some(other) => bail!("RUN --network={other}: expected default or none"),
    }
}

/// Whether a `RUN` that exited `code` restarts the guest, under its `--reboot`; `None` when it
/// failed.
fn wants_restart(reboot: &str, code: i32) -> Option<bool> {
    match (reboot, code) {
        ("always", 0) | ("auto", 3010 | 1641) => Some(true),
        (_, 0) => Some(false),
        _ => None,
    }
}

fn build_stage(
    stages: &[Stage],
    index: usize,
    opts: &Options,
    cache: &Path,
    built: &mut HashMap<usize, Layer>,
) -> Result<Layer> {
    if let Some(layer) = built.get(&index) {
        return Ok(layer.clone());
    }
    let stage = &stages[index];
    let label = stage.label(index);
    check_stage(stage, &opts.context, opts.no_network).with_context(|| format!("stage {label}"))?;
    let (cpus, mem) = guest_size(stage, opts);
    let bundle = opts.context.join(&stage.from.image);
    let mut layer = if let Some(source) =
        crate::winiso::Source::of_stage(&stage.from.image, &stage.from.extra_flags, &opts.context)?
    {
        let disk = match stage.directive("disk") {
            Some(size) => disk_size(size)?,
            None => DEFAULT_DISK,
        };
        let base = crate::winiso::base(&source, disk, cpus, &mem, &cache.join("winiso"))?;
        Layer {
            disk: base.disk,
            key: base.key,
            password: base.password,
            shell: DEFAULT_SHELL.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(),
            workdir: None,
            provision: None,
            secure_boot: false,
            tpm: false,
            unsaved_env: Vec::new(),
            unmade_workdir: false,
            generalized: false,
        }
    } else if let Some(parent) = stages[..index]
        .iter()
        .position(|s| s.from.as_name.as_deref() == Some(stage.from.image.as_str()))
    {
        build_stage(stages, parent, opts, cache, built)?
    } else if layer_record(&bundle).is_some() {
        bundle_layer(&bundle, cache).with_context(|| format!("FROM {}", stage.from.image))?
    } else {
        bail!(
            "FROM {}: a Windows stage starts from winiso:, an earlier stage or a bundle a \
             Windows build wrote",
            stage.from.image
        );
    };
    machine_directives(stage, &mut layer);
    let steps = Steps {
        cpus,
        mem: &mem,
        cache,
    };
    for (n, instruction) in stage.body.iter().enumerate() {
        let what = format!("[{label} {}/{}]", n + 1, stage.body.len());
        match instruction {
            Instruction::Env(pairs) => {
                for (k, v) in pairs {
                    layer.env.retain(|(name, _)| !name.eq_ignore_ascii_case(k));
                    layer.env.push((k.clone(), v.clone()));
                    layer.unsaved_env.push((k.clone(), v.clone()));
                }
            }
            Instruction::Workdir(dir) => {
                layer.workdir = Some(absolute(dir, layer.workdir.as_deref()));
                layer.unmade_workdir = true;
            }
            Instruction::Other { name, args } if name == "SHELL" => layer.shell = shell(args)?,
            Instruction::Run(run) => run_step(&mut layer, run, &what, &steps)?,
            Instruction::Copy(copy) => copy_step(&mut layer, copy, &what, &opts.context, &steps)?,
            Instruction::Cmd(cmd) => layer.provision = provision(&layer.shell, cmd),
            // Recorded by the image's run config in a later step; nothing to build.
            _ => {}
        }
    }
    if stage.directive("generalize") == Some("on") {
        // Its step also makes the stage's last ENV and WORKDIR. Generalizing an image built
        // FROM a generalized one runs sysprep again, which Windows allows a limited number of
        // times (its rearm count).
        eprintln!("virtkit: [{label}] generalize (sysprep)");
        // The key includes the answer and password: each bundle supplies its own password,
        // so different passwords produce different layers.
        let answer = generalize_answer(&layer.password);
        step(
            &mut layer,
            &format!("GENERALIZE\0{answer}"),
            &steps,
            false,
            |ga, _, vm| generalize(ga, &answer, vm),
        )?;
        layer.generalized = true;
    } else if !layer.unsaved_env.is_empty() || layer.unmade_workdir {
        // As Docker keeps a stage's last ENV and WORKDIR in its image.
        eprintln!("virtkit: [{label}] saving ENV and WORKDIR");
        step(&mut layer, "SAVE", &steps, false, |_, _, _| Ok(()))?;
    }
    built.insert(index, layer.clone());
    Ok(layer)
}

/// The layer the bundle `dir` records ([`LAYER_RECORD`]), its disk found in `cache` by its key:
/// the record names a layer, not a file, so a bundle cannot have the build back its layers
/// with a disk the cache did not make.
fn bundle_layer(dir: &Path, cache: &Path) -> Result<Layer> {
    let mut layer = read_layer(dir)?;
    let step = cache.join("layers").join(&layer.key);
    layer.disk = if step.join("complete").exists() {
        step.join("disk.qcow2")
    } else if let Some(disk) = crate::winiso::cached_base(&cache.join("winiso"), &layer.key) {
        disk
    } else {
        bail!(
            "its layer {} is gone from the build cache; build it again",
            &layer.key[..12]
        );
    };
    let password = dir.join("admin-password");
    layer.password = std::fs::read_to_string(&password)
        .with_context(|| format!("reading {}", password.display()))?
        .trim()
        .to_string();
    Ok(layer)
}

/// The layer the bundle `dir` records ([`LAYER_RECORD`]), checked but without its disk or
/// password.
fn read_layer(dir: &Path) -> Result<Layer> {
    let record = dir.join(LAYER_RECORD);
    let value = layer_record(dir).with_context(|| format!("{}: no layer", record.display()))?;
    if value["version"].as_u64() != Some(LAYER_RECORD_VERSION) {
        bail!(
            "{}: version {} is not one this vk reads",
            record.display(),
            value["version"]
        );
    }
    let layer: Layer =
        serde_json::from_value(value).with_context(|| format!("{}", record.display()))?;
    if layer.key.len() != 64
        || !layer
            .key
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("{}: not a layer key: {:?}", record.display(), layer.key);
    }
    // Steps pass ENV to batch files, as `vk exec --env` does.
    if let Some((k, v)) = layer
        .env
        .iter()
        .find(|(k, v)| !crate::winexec::valid_var(k, v))
    {
        bail!(
            "{}: ENV {k}={v:?}: a Windows guest's variables cannot hold quotes or newlines",
            record.display()
        );
    }
    Ok(layer)
}

/// What a service needs from a bundle's layer record: the image's provisioning and the
/// directory it runs in.
#[derive(Debug, Default)]
pub(crate) struct Provisioning {
    pub provision: Option<String>,
    pub workdir: Option<String>,
}

/// The provisioning the bundle at `dir` records; none for a bundle without a layer record (one
/// not made by `vk build`).
pub(crate) fn provisioning(dir: &Path) -> Result<Provisioning> {
    let path = dir.join(LAYER_RECORD);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Provisioning::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        Ok(_) => {}
    }
    let layer = read_layer(dir)?;
    Ok(Provisioning {
        provision: layer.provision,
        workdir: layer.workdir,
    })
}

/// Apply `stage`'s machine directives (`firmware`, `tpm`) to `layer`.
/// Stages built on this layer inherit them.
fn machine_directives(stage: &Stage, layer: &mut Layer) {
    if let Some(firmware) = stage.directive("firmware") {
        layer.secure_boot = firmware == "uefi-secboot";
    }
    if let Some(tpm) = stage.directive("tpm") {
        layer.tpm = tpm == "on";
    }
}

/// Read [`LAYER_RECORD`] from bundle `dir` only if it has a `version`, so a stray
/// `layer.json` does not make a Dockerfile a Windows one.
fn layer_record(dir: &Path) -> Option<serde_json::Value> {
    let text = std::fs::read_to_string(dir.join(LAYER_RECORD)).ok()?;
    serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .filter(|record| record.get("version").is_some())
}

/// Where a generalize step writes its answer file, as [`SYSPREP`] names it. The next step on the
/// generalized layer deletes it (see [`make_step`]), as it holds the Administrator password; a
/// bundle of the generalized layer itself still has it.
const GENERALIZE_ANSWER: &str = r"C:\vk\generalize.xml";

/// Generalize the image and power off; its next boot runs [`GENERALIZE_XML`].
const SYSPREP: &str = r"C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown /quiet /unattend:C:\vk\generalize.xml";

/// [`GENERALIZE_XML`] with the Administrator password `password`.
fn generalize_answer(password: &str) -> String {
    GENERALIZE_XML.replace("@PASSWORD@", &crate::winiso::xml_escape(password))
}

/// Write the answer file `answer` through `ga`, start sysprep and wait for it to power `vm` off.
fn generalize(ga: &mut Client, answer: &str, vm: &mut crate::uefi::Guest) -> Result<()> {
    crate::winexec::put(ga, GENERALIZE_ANSWER, answer.as_bytes())?;
    // Sysprep powers the guest off when it is done; nothing to wait for but that.
    crate::winexec::exec_command_line(ga, SYSPREP, &[], None, true, &mut std::io::sink())?;
    if !vm.wait_poweroff(SYSPREP_TIMEOUT)? {
        bail!(
            "sysprep did not power the guest off within {}s",
            SYSPREP_TIMEOUT.as_secs()
        );
    }
    Ok(())
}

/// The answer file a generalized image's first boot runs: a fresh computer name, no OOBE
/// pages, the image's Administrator password (`@PASSWORD@`).
const GENERALIZE_XML: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>*</ComputerName>
      <TimeZone>UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale><UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts>
        <AdministratorPassword><Value>@PASSWORD@</Value><PlainText>true</PlainText></AdministratorPassword>
      </UserAccounts>
      <OOBE><HideEULAPage>true</HideEULAPage><ProtectYourPC>3</ProtectYourPC><SkipMachineOOBE>true</SkipMachineOOBE></OOBE>
    </component>
  </settings>
</unattend>
"#;

/// What a stage's steps boot: its guests' size and the layer cache.
struct Steps<'a> {
    cpus: u32,
    mem: &'a str,
    cache: &'a Path,
}

fn run_step(layer: &mut Layer, run: &parser::Run, what: &str, steps: &Steps) -> Result<()> {
    let reboot = reboot_mode(run)?;
    let network = network_mode(run)?;
    let line = command_line(&layer.shell, &run.cmd);
    eprintln!("virtkit: {what} RUN {}", first_line(&line));
    let material = run_material(layer, &line, reboot, network);
    step(layer, &material, steps, network, |ga, l, vm| {
        let code = crate::winexec::exec_command_line(
            ga,
            &line,
            &l.env,
            l.workdir.as_deref(),
            false,
            &mut std::io::stderr().lock(),
        )?;
        let Some(restart) = wants_restart(reboot, code) else {
            bail!("RUN {} exited {code}", first_line(&line));
        };
        if restart {
            eprintln!("virtkit: {what} restarting the guest");
            restart_guest(ga, code, vm)?;
        }
        Ok(())
    })
}

/// A `RUN` step's material: its command line, flags, and the `ENV` and `WORKDIR` it runs with.
fn run_material(layer: &Layer, line: &str, reboot: &str, network: bool) -> String {
    format!(
        "RUN\0{line}\0{reboot}\0{network}\0{:?}\0{:?}",
        layer.env, layer.workdir
    )
}

fn copy_step(
    layer: &mut Layer,
    copy: &parser::Copy,
    what: &str,
    context: &Path,
    steps: &Steps,
) -> Result<()> {
    let (targets, material) = copy_plan(copy, context, layer.workdir.as_deref())?;
    eprintln!(
        "virtkit: {what} COPY {} -> {}",
        copy.sources.join(" "),
        copy.dest
    );
    step(layer, &material, steps, false, |ga, _, _| {
        make_dirs(ga, targets.iter().map(|(t, _)| t.as_str()))?;
        for (target, path) in &targets {
            let file =
                std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
            crate::winexec::write_from(ga, target, file)?;
        }
        Ok(())
    })
}

/// The Windows command line `cmd` is: a shell form after `shell`, as Docker runs it on
/// Windows, or the exec form's arguments quoted.
pub(crate) fn command_line(shell: &[String], cmd: &Cmdline) -> String {
    let quoted = |args: &[String]| {
        args.iter()
            .map(|a| crate::winexec::quote_arg(a))
            .collect::<Vec<_>>()
            .join(" ")
    };
    match cmd {
        Cmdline::Shell(text) => format!("{} {text}", quoted(shell)),
        Cmdline::Exec(argv) => quoted(argv),
    }
}

/// The provisioning a `CMD` records: its command line, or none for `CMD []`, which clears it
/// as in Docker.
fn provision(shell: &[String], cmd: &Cmdline) -> Option<String> {
    Some(command_line(shell, cmd)).filter(|line| !line.is_empty())
}

fn first_line(s: &str) -> &str {
    s.lines().next().unwrap_or("")
}

/// `path` made absolute against the stage's `WORKDIR` (or `C:\`): one with a drive or a UNC
/// path stays, one with a leading `\` or `/` is rooted at `C:`.
fn absolute(path: &str, workdir: Option<&str>) -> String {
    let path = path.replace('/', "\\");
    if path.as_bytes().get(1) == Some(&b':') || path.starts_with("\\\\") {
        path
    } else if path.starts_with('\\') {
        format!("C:{path}")
    } else {
        format!("{}\\{path}", workdir.unwrap_or("C:").trim_end_matches('\\'))
    }
}

/// Whether a `COPY` destination names a directory: a trailing separator, or `.` or `..`.
fn names_dir(dest: &str) -> bool {
    dest.ends_with('\\') || matches!(dest.rsplit('\\').next(), Some("." | ".."))
}

/// What a `COPY` writes: each source file's guest path and host path, and the step's material,
/// which names every target and digest, as the files are hashed a piece at a time.
fn copy_plan(
    copy: &parser::Copy,
    context: &Path,
    workdir: Option<&str>,
) -> Result<(Vec<(String, PathBuf)>, String)> {
    let (files, has_dir) = copy_sources(context, &copy.sources)?;
    let dest = copy.dest.replace('/', "\\");
    let into_dir = names_dir(&dest) || files.len() > 1 || has_dir;
    let base = absolute(&dest, workdir);
    let mut material = format!("COPY\0{base}\0{into_dir}");
    let mut targets = Vec::new();
    for (rel, path) in files {
        let target = copy_target(&base, &rel, into_dir);
        let digest = crate::winiso::sha256_file(&path)?;
        material.push_str(&format!("\0{target}\0{digest}"));
        targets.push((target, path));
    }
    Ok((targets, material))
}

/// Where the file `rel` of a `COPY` to the absolute `base` lands, `.` and `..` resolved.
fn copy_target(base: &str, rel: &str, into_dir: bool) -> String {
    let path = if into_dir {
        format!("{base}\\{}", rel.replace('/', "\\"))
    } else {
        base.to_string()
    };
    // The root, `C:` or `\\server\share`, stays; `..` goes no higher.
    let parts: Vec<&str> = path.split('\\').collect();
    let root_len = if path.starts_with("\\\\") { 4 } else { 1 };
    let (root, rest) = parts.split_at(root_len.min(parts.len()));
    let mut out: Vec<&str> = Vec::new();
    for part in rest {
        match *part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            part => out.push(part),
        }
    }
    format!("{}\\{}", root.join("\\"), out.join("\\"))
}

/// The files `sources` (context-relative, files or directories) name: (relative name, path),
/// sorted, and whether a source is a directory. Nothing outside `context` is read: a source
/// or a symlink leading out of it is refused, as is a symlink to a directory.
fn copy_sources(context: &Path, sources: &[String]) -> Result<(Vec<(String, PathBuf)>, bool)> {
    let context = context
        .canonicalize()
        .with_context(|| format!("build context {}", context.display()))?;
    let mut files = Vec::new();
    let mut has_dir = false;
    for source in sources {
        let relative = Path::new(source);
        if relative.is_absolute() || relative.components().any(|c| c == Component::ParentDir) {
            bail!("COPY {source}: a source is a path inside the build context");
        }
        let path = context.join(relative);
        if std::fs::symlink_metadata(&path).is_err() {
            bail!("COPY {source}: not found in the build context");
        }
        let real = inside(&context, &path).with_context(|| format!("COPY {source}"))?;
        if real.is_dir() {
            has_dir = true;
            walk(&context, &real, &mut files).with_context(|| format!("COPY {source}"))?;
        } else {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .with_context(|| format!("COPY {source}: not a UTF-8 file name"))?;
            files.push((name.to_string(), real));
        }
    }
    files.sort();
    Ok((files, has_dir))
}

/// `path` past any symlink, refused unless it stays inside `context` (canonical).
fn inside(context: &Path, path: &Path) -> Result<PathBuf> {
    let real = path
        .canonicalize()
        .with_context(|| format!("resolving {}", path.display()))?;
    if !real.starts_with(context) {
        bail!("{} leads outside the build context", path.display());
    }
    Ok(real)
}

/// Add the files under the directory `root` to `files`, named relative to it. A symlink to a
/// file is followed if it stays inside `context`; one to a directory is refused, so the walk
/// cannot loop.
fn walk(context: &Path, root: &Path, files: &mut Vec<(String, PathBuf)>) -> Result<()> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).with_context(|| format!("{}", dir.display()))? {
            let entry = entry?;
            let path = entry.path();
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(path);
                continue;
            }
            let rel = path
                .strip_prefix(root)?
                .to_str()
                .with_context(|| format!("{}: not a UTF-8 file name", path.display()))?
                .to_string();
            if kind.is_file() {
                files.push((rel, path));
            } else if kind.is_symlink() {
                let real = inside(context, &path)?;
                if real.is_dir() {
                    bail!("{rel}: a symlink to a directory, which a Windows build does not follow");
                }
                files.push((rel, real));
            } else {
                bail!("{rel}: not a regular file");
            }
        }
    }
    Ok(())
}

/// `s` as a PowerShell single-quoted string; PowerShell takes the typographic single quotes
/// for quotes too.
fn ps_quote(s: &str) -> String {
    let mut out = String::from("'");
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201a}' | '\u{201b}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// A PowerShell line creating the directory `dir`, as `mkdir -p` would.
fn mkdir_line(dir: &str) -> String {
    format!(
        "New-Item -ItemType Directory -Force -Path {} | Out-Null",
        ps_quote(dir)
    )
}

/// Create the directories `files` go into, in one command.
fn make_dirs<'a>(ga: &mut Client, files: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut dirs: Vec<&str> = files
        .filter_map(|f| f.rsplit_once('\\').map(|(d, _)| d))
        .collect();
    dirs.sort();
    dirs.dedup();
    if dirs.is_empty() {
        return Ok(());
    }
    let mut script = String::from("$ErrorActionPreference = 'Stop'\n");
    for dir in &dirs {
        script.push_str(&mkdir_line(dir));
        script.push('\n');
    }
    match crate::winexec::powershell(ga, &script, "COPY")? {
        0 => Ok(()),
        code => bail!("creating {} in the guest failed ({code})", dirs.join(", ")),
    }
}

/// Restart the guest in place, after a step that exited `code`, and wait for its agent.
fn restart_guest(ga: &mut Client, code: i32, guest: &mut crate::uefi::Guest) -> Result<()> {
    crate::winexec::restart(ga, code, &mut || guest.running())?;
    *ga = Client::connect(&guest.agent_socket(), AGENT_TIMEOUT)
        .context("qemu-ga did not come back after the restart")?;
    Ok(())
}

/// The cache key of the step `material` on `layer`: its parent, the instruction, and what
/// `ENV` and `WORKDIR` left for the step to make.
fn step_key(layer: &Layer, material: &str) -> String {
    let workdir = layer.workdir.as_deref().filter(|_| layer.unmade_workdir);
    // Include Secure Boot in the key because a step's drivers may not load under it.
    // Keys without Secure Boot retain the existing cache format. The TPM is not in it: steps
    // run without one.
    let firmware = if layer.secure_boot {
        "\0uefi-secboot"
    } else {
        ""
    };
    hex(&Sha256::digest(
        format!(
            "winbuild-step-v1\0{}\0{material}\0{:?}\0{workdir:?}{firmware}",
            layer.key, layer.unsaved_env
        )
        .as_bytes(),
    ))
}

/// Make the layer `material` names on top of `layer`, or take it from the cache: boot the guest
/// on an overlay, with a `network` or none, make the variables `ENV` set and the directory
/// `WORKDIR` named since the last step, apply `act`, and power off.
fn step(
    layer: &mut Layer,
    material: &str,
    steps: &Steps,
    network: bool,
    act: impl FnOnce(&mut Client, &Layer, &mut crate::uefi::Guest) -> Result<()>,
) -> Result<()> {
    let key = step_key(layer, material);
    let dir = steps.cache.join("layers").join(&key);
    if dir.join("complete").exists() {
        eprintln!("virtkit:   CACHED {}", &key[..12]);
    } else {
        clear_attempts(&steps.cache.join("layers"), &key);
        let tmp = crate::winiso::scratch_beside(&dir)?;
        let work = tmp.join("run");
        std::fs::create_dir_all(&work)?;
        let disk = tmp.join("disk.qcow2");
        crate::qcow2::create_overlay(&disk, &layer.disk)?;
        let started = Instant::now();
        if let Err(e) = make_step(layer, &work, &disk, steps, network, act) {
            // The step's logs stay for whoever reads the error; its disk is no use to them.
            let _ = std::fs::remove_file(&disk);
            return Err(e.context(format!("the step's logs are in {}", work.display())));
        }
        let _ = std::fs::remove_dir_all(&work);
        std::fs::write(tmp.join("complete"), "")?;
        crate::winiso::publish(&tmp, &dir)?;
        eprintln!("virtkit:   done in {}s", started.elapsed().as_secs());
    }
    layer.disk = dir.join("disk.qcow2");
    layer.key = key;
    layer.unsaved_env.clear();
    layer.unmade_workdir = false;
    layer.generalized = false;
    Ok(())
}

/// Remove what earlier attempts at the layer `key` left in `layers`: a failed step keeps its
/// logs (see [`step`]), and a killed build its whole directory. An attempt whose process is
/// still running is left alone.
fn clear_attempts(layers: &Path, key: &str) {
    let Ok(entries) = std::fs::read_dir(layers) else {
        return;
    };
    let prefix = format!("{key}.tmp-");
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.strip_prefix(&prefix)) else {
            continue;
        };
        if !Path::new("/proc").join(pid).exists() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// [`step`]'s guest: boot `disk` with `work` as its run directory and, given `network`, on a
/// switch of its own as `vk run --net` has; make the variables `ENV` set and the directory
/// `WORKDIR` named since the last step, apply `act`, and power off.
fn make_step(
    layer: &Layer,
    work: &Path,
    disk: &Path,
    steps: &Steps,
    network: bool,
    act: impl FnOnce(&mut Client, &Layer, &mut crate::uefi::Guest) -> Result<()>,
) -> Result<()> {
    // Declared before the guest, so it outlives it.
    let mut switch = SwitchGuard(None);
    let mut nics = Vec::new();
    if network {
        let vsock = work.join("vsock.sock");
        let spawn = crate::run::spawn_vm_switch(
            &vsock,
            work,
            crate::run::NET_VSOCK_PORT,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            None,
            None,
            None,
            false,
            None,
            crate::prio::Prio::Normal,
        );
        let (child, attach) = match tokio::runtime::Handle::try_current() {
            Ok(rt) => rt.block_on(spawn),
            Err(_) => tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("starting a runtime to spawn the step's switch")?
                .block_on(spawn),
        }?;
        switch.0 = Some(child);
        nics = attach.nics;
    }
    if layer.secure_boot {
        crate::uefi::seed_secure_boot(work)?;
    }
    let mut vm = crate::uefi::Guest::boot(
        work,
        "vk-build",
        vec![Disk::overlay(disk.to_path_buf())],
        steps.cpus,
        steps.mem,
        nics,
    )?;
    let mut ga = setup_complete(&mut vm)?;
    if layer.generalized {
        // Best effort: the answer file only matters for the password it holds.
        let _ = crate::winexec::cmd(&mut ga, &["del", "/f", "/q", GENERALIZE_ANSWER]);
    }
    let workdir = layer.workdir.as_deref().filter(|_| layer.unmade_workdir);
    if let Some(script) = prepare_script(&layer.unsaved_env, workdir) {
        match crate::winexec::powershell(&mut ga, &script, "ENV/WORKDIR")? {
            0 => {}
            code => bail!("saving ENV and WORKDIR failed ({code})"),
        }
    }
    act(&mut ga, layer, &mut vm)?;
    drop(ga);
    vm.shutdown()?;
    Ok(())
}

/// [`crate::uefi::wait_started`] for a step's guest `vm`, within [`AGENT_TIMEOUT`].
fn setup_complete(vm: &mut crate::uefi::Guest) -> Result<Client> {
    let (socket, console) = (vm.agent_socket(), vm.console());
    crate::uefi::wait_started(&socket, &console, AGENT_TIMEOUT, &mut || vm.running())
}

/// A step's switch, stopped however the step ends.
struct SwitchGuard(Option<std::process::Child>);

impl Drop for SwitchGuard {
    fn drop(&mut self) {
        if let Some(child) = self.0.take() {
            crate::run::stop_switch(child);
        }
    }
}

/// The PowerShell making `vars` machine-wide environment variables, as Docker persists `ENV` in
/// the image, and creating `workdir`, as Docker does a `WORKDIR`; `None` when there is neither.
fn prepare_script(vars: &[(String, String)], workdir: Option<&str>) -> Option<String> {
    if vars.is_empty() && workdir.is_none() {
        return None;
    }
    let mut script = String::from("$ErrorActionPreference = 'Stop'\n");
    for (k, v) in vars {
        script.push_str(&format!(
            "[Environment]::SetEnvironmentVariable({}, {}, 'Machine')\n",
            ps_quote(k),
            ps_quote(v)
        ));
    }
    if let Some(dir) = workdir {
        script.push_str(&mkdir_line(dir));
        script.push('\n');
    }
    Some(script)
}

/// Write the bundle `vk run` boots into `out`: `vm.json` (`cpus` and `mem`), an overlay over
/// the built layer, the Administrator password and, last, its record ([`LAYER_RECORD`]).
fn write_bundle(layer: &Layer, cpus: u32, mem: &str, out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
    // Gone until the rest is written, so a bundle half rewritten names no layer.
    let record = out.join(LAYER_RECORD);
    let _ = std::fs::remove_file(&record);
    let disk = out.join("disk.qcow2");
    let _ = std::fs::remove_file(&disk);
    crate::qcow2::create_overlay(&disk, &layer.disk)?;
    std::fs::write(
        out.join(crate::uefi::MANIFEST),
        serde_json::to_string_pretty(&serde_json::json!({
            "firmware": "uefi",
            "cpus": cpus,
            "mem": mem,
            "disks": ["disk.qcow2"],
            "secure_boot": layer.secure_boot,
            "tpm": layer.tpm,
        }))?,
    )?;
    let password = out.join("admin-password");
    let _ = std::fs::remove_file(&password);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&password)?;
    writeln!(file, "{}", layer.password)?;
    let mut value = serde_json::to_value(layer)?;
    value["version"] = LAYER_RECORD_VERSION.into();
    let tmp = out.join(format!("{LAYER_RECORD}.tmp"));
    std::fs::write(&tmp, serde_json::to_string_pretty(&value)?)?;
    std::fs::rename(&tmp, &record)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(text: &str) -> Vec<Stage> {
        stages(parser::parse(text).unwrap()).unwrap()
    }

    /// The error checking the one stage of `text` gives.
    fn refusal(text: &str) -> String {
        let stages = parsed(text);
        format!(
            "{:#}",
            check_stage(&stages[0], Path::new("/ctx"), false).unwrap_err()
        )
    }

    const WINISO: &str = "FROM winiso:ws.iso@sha256:7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51 \
         --drivers=v.iso@sha256:7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51 AS base\n";

    fn layer() -> Layer {
        Layer {
            disk: PathBuf::from("/c/disk.qcow2"),
            key: "parent".into(),
            password: "p".into(),
            shell: DEFAULT_SHELL.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(),
            workdir: None,
            provision: None,
            secure_boot: false,
            tpm: false,
            unsaved_env: Vec::new(),
            unmade_workdir: false,
            generalized: false,
        }
    }

    #[test]
    fn sysprep_reads_the_answer_file_a_generalize_step_writes() {
        assert!(SYSPREP.ends_with(&format!("/unattend:{GENERALIZE_ANSWER}")));
    }

    #[test]
    fn a_dockerfile_is_windows_when_a_stage_installs_or_targets_windows() {
        let ctx = scratch("is-windows");
        let windows = |text: &str| is_windows(text, &ctx);
        assert!(
            windows("FROM winiso:ws.iso@sha256:aa --drivers=v.iso@sha256:bb AS base\nRUN x\n")
                .unwrap()
        );
        assert!(windows("FROM --platform=windows/amd64 base\n").unwrap());
        assert!(!windows("FROM alpine:3.20\nRUN apk add curl\n").unwrap());
        assert!(windows("FROM\n").is_err());
        std::fs::create_dir_all(ctx.join("base-out")).unwrap();
        assert!(!windows("FROM base-out\n").unwrap());
        // A stray layer.json, without the record's version, leaves the build a Linux one.
        std::fs::write(ctx.join("base-out").join(LAYER_RECORD), "{}").unwrap();
        assert!(!windows("FROM base-out\n").unwrap());
        std::fs::write(ctx.join("base-out").join(LAYER_RECORD), r#"{"version":1}"#).unwrap();
        assert!(windows("FROM base-out\n").unwrap());
        let _ = std::fs::remove_dir_all(&ctx);
    }

    #[test]
    fn the_target_is_named_numbered_or_the_last_stage() {
        let stages = parsed("FROM a AS one\nFROM b\nFROM c AS three\n");
        assert_eq!(target_index(&stages, None).unwrap(), 2);
        assert_eq!(target_index(&stages, Some("one")).unwrap(), 0);
        assert_eq!(target_index(&stages, Some("1")).unwrap(), 1);
        assert!(target_index(&stages, Some("3")).is_err());
        assert!(target_index(&stages, Some("two")).is_err());
        assert!(target_index(&[], None).is_err());
        let err = super::stages(parser::parse("ARG V=1\nFROM a\n").unwrap())
            .err()
            .unwrap();
        assert!(
            err.to_string().contains("ARG before the first FROM"),
            "{err}"
        );
    }

    #[test]
    fn run_takes_reboot_and_network_only() {
        let reboot = |text: &str| {
            let stages = parsed(&format!("FROM x\n{text}\n"));
            let Instruction::Run(run) = &stages[0].body[0] else {
                unreachable!()
            };
            reboot_mode(run).map(str::to_string)
        };
        assert_eq!(reboot("RUN a").unwrap(), "auto");
        assert_eq!(reboot("RUN --reboot=never a").unwrap(), "never");
        assert!(reboot("RUN --reboot=sometimes a").is_err());
        assert!(reboot("RUN --reboot=never --reboot=always a").is_err());
        assert!(reboot("RUN --timeout=5m a").is_err());
        assert!(reboot("RUN --mount=type=cache,target=/c a").is_err());
        assert!(reboot("RUN --security=insecure a").is_err());
        let network = |text: &str| {
            let stages = parsed(&format!("FROM x\n{text}\n"));
            let Instruction::Run(run) = &stages[0].body[0] else {
                unreachable!()
            };
            network_mode(run)
        };
        assert!(!network("RUN a").unwrap());
        assert!(!network("RUN --network=none a").unwrap());
        assert!(network("RUN --network=default --reboot=never a").unwrap());
        assert!(network("RUN --network=host a").is_err());
    }

    #[test]
    fn a_run_restarts_on_its_exit_code_as_reboot_says() {
        assert_eq!(wants_restart("auto", 0), Some(false));
        assert_eq!(wants_restart("auto", 3010), Some(true));
        assert_eq!(wants_restart("auto", 1641), Some(true));
        assert_eq!(wants_restart("always", 0), Some(true));
        assert_eq!(wants_restart("never", 0), Some(false));
        assert_eq!(wants_restart("never", 3010), None);
        assert_eq!(wants_restart("always", 3010), None);
        assert_eq!(wants_restart("auto", 1), None);
    }

    #[test]
    fn what_a_windows_build_does_not_do_is_refused_before_it_boots() {
        let refused = [
            ("USER admin\n", "runs every step as SYSTEM"),
            ("ARG V\n", "takes no build arguments"),
            ("ADD a.zip C:/\n", "ADD is not supported"),
            ("COPY --from=other a C:/\n", "COPY --from"),
            ("COPY --chown=a a C:/\n", "--chown"),
            ("COPY ${SRC} C:/\n", "variable substitution"),
            ("ENV P=$PATH\n", "variable substitution"),
            ("WORKDIR $HOME\n", "variable substitution"),
            ("SHELL []\n", "non-empty JSON array"),
            ("RUN --network=host a\n", "--network=host"),
            ("ENTRYPOINT [\"a\"]\n", "provisions with CMD alone"),
        ];
        for (body, want) in refused {
            let err = refusal(&format!("{WINISO}{body}"));
            assert!(err.contains(want), "{body}: {err}");
        }
        let directives = [
            ("hyperv=on", "`# vk: hyperv` is not supported yet"),
            ("tpm=yes", "expected on or off"),
            ("generalize=yes", "expected on or off"),
            ("firmware=bios", "expected uefi or uefi-secboot"),
            ("disk=10G", "at least 20G"),
            ("disk=lots", "at least 20G"),
        ];
        for (line, want) in directives {
            let err = refusal(&format!("# vk: {line}\n{WINISO}"));
            assert!(err.contains(want), "{line}: {err}");
        }
        let err = refusal("# vk: disk=60G\nFROM base\n");
        assert!(err.contains("a winiso: stage's install only"), "{err}");
        let sized = parsed(&format!("# vk: disk=60G generalize=on\n{WINISO}"));
        check_stage(&sized[0], Path::new("/ctx"), false).unwrap();
        for firmware in ["uefi", "uefi-secboot"] {
            let stage = parsed(&format!("# vk: firmware={firmware}\n{WINISO}"));
            check_stage(&stage[0], Path::new("/ctx"), false).unwrap();
        }
        // A TPM is the image's machines', kept by the stages built on it until one says off.
        let mut built = layer();
        for (directives, tpm) in [
            ("# vk: tpm=on\n", true),
            ("", true),
            ("# vk: tpm=off\n", false),
        ] {
            let stage = parsed(&format!("{directives}{WINISO}"));
            check_stage(&stage[0], Path::new("/ctx"), false).unwrap();
            machine_directives(&stage[0], &mut built);
            assert_eq!(built.tpm, tpm, "{directives}");
        }
        assert_eq!(disk_size("60G").unwrap(), 60 << 30);
        let err = refusal("FROM base --drivers=x\n");
        assert!(
            err.contains("--drivers applies to a winiso: stage only"),
            "{err}"
        );
        let ok = parsed(&format!(
            "{WINISO}ENV A=1 B=cost$\nWORKDIR C:/app\nSHELL [\"powershell\", \"-Command\"]\n\
             RUN --reboot=always a\nCOPY a b C:/app/\nLABEL x=y\n"
        ));
        check_stage(&ok[0], Path::new("/ctx"), false).unwrap();
        // --build-net none leaves a step no network to ask for.
        let networked = parsed(&format!("{WINISO}RUN --network=default a\n"));
        check_stage(&networked[0], Path::new("/ctx"), false).unwrap();
        let err = check_stage(&networked[0], Path::new("/ctx"), true).unwrap_err();
        assert!(
            format!("{err:#}").contains("--build-net none forbids it"),
            "{err:#}"
        );
        let offline = parsed(&format!("{WINISO}RUN --network=none a\nRUN a\n"));
        check_stage(&offline[0], Path::new("/ctx"), true).unwrap();
    }

    #[test]
    fn a_command_line_is_the_shell_and_its_text_or_the_arguments_quoted() {
        let shell: Vec<String> = DEFAULT_SHELL.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            command_line(&shell, &Cmdline::Shell("echo a & echo b".into())),
            "cmd /S /C echo a & echo b"
        );
        assert_eq!(
            command_line(&shell, &Cmdline::Exec(vec!["a b".into(), "c".into()])),
            "\"a b\" c"
        );
    }

    #[test]
    fn cmd_is_recorded_as_a_command_line_and_cmd_empty_clears_it() {
        let cmd = |text: &str| {
            let stages = parsed(&format!("FROM x\n{text}\n"));
            let Instruction::Cmd(cmd) = &stages[0].body[0] else {
                unreachable!()
            };
            cmd.clone()
        };
        let powershell = vec!["powershell".to_string(), "-Command".to_string()];
        assert_eq!(
            provision(&powershell, &cmd("CMD a b")).as_deref(),
            Some("powershell -Command a b")
        );
        // MSVCRT quoting: a blank quotes the argument, a quote is escaped.
        assert_eq!(
            provision(&powershell, &cmd(r#"CMD ["setup.cmd", "a \"b\" c"]"#)).as_deref(),
            Some(r#"setup.cmd "a \"b\" c""#)
        );
        assert_eq!(provision(&powershell, &cmd("CMD []")), None);
    }

    #[test]
    fn a_service_reads_its_provisioning_from_the_layer_record() {
        let dir = scratch("prov");
        let none = provisioning(&dir).unwrap();
        assert_eq!((none.provision, none.workdir), (None, None));
        let mut record = serde_json::to_value(Layer {
            key: "c".repeat(64),
            workdir: Some(r"C:\vk".into()),
            provision: Some(command_line(
                &["powershell".into(), "-Command".into()],
                &Cmdline::Shell(r"C:\vk\join.ps1".into()),
            )),
            ..layer()
        })
        .unwrap();
        record["version"] = LAYER_RECORD_VERSION.into();
        std::fs::write(dir.join(LAYER_RECORD), record.to_string()).unwrap();
        let read = provisioning(&dir).unwrap();
        assert_eq!(
            read.provision.as_deref(),
            Some(r"powershell -Command C:\vk\join.ps1")
        );
        assert_eq!(read.workdir.as_deref(), Some(r"C:\vk"));
        // A record this vk does not read is an error, not an image without provisioning.
        std::fs::write(dir.join(LAYER_RECORD), "{}").unwrap();
        assert!(provisioning(&dir).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_paths_land_under_the_workdir() {
        assert_eq!(absolute("C:\\vk\\a", Some("D:\\x")), "C:\\vk\\a");
        assert_eq!(absolute("a.txt", Some("C:\\app\\")), "C:\\app\\a.txt");
        assert_eq!(absolute("a.txt", None), "C:\\a.txt");
        assert_eq!(absolute("/app/a.txt", Some("D:\\x")), "C:\\app\\a.txt");
        assert_eq!(absolute("\\app", None), "C:\\app");
        assert_eq!(absolute("sub/dir", Some("C:\\app")), "C:\\app\\sub\\dir");
        assert_eq!(absolute("\\\\srv\\share", None), "\\\\srv\\share");
    }

    #[test]
    fn a_copy_lands_in_a_directory_or_on_its_destination() {
        assert!(names_dir("C:\\app\\") && names_dir(".") && names_dir("x\\.."));
        assert!(!names_dir("C:\\app\\a.txt"));
        assert_eq!(
            copy_target("C:\\app\\", "sub/b.ps1", true),
            "C:\\app\\sub\\b.ps1"
        );
        assert_eq!(
            copy_target("C:\\app\\a.ps1", "x.ps1", false),
            "C:\\app\\a.ps1"
        );
        assert_eq!(copy_target("C:\\work\\..\\..", "a.txt", true), "C:\\a.txt");
        assert_eq!(
            copy_target("\\\\srv\\share\\.\\x\\..", "a.txt", true),
            "\\\\srv\\share\\a.txt"
        );
    }

    #[test]
    fn a_new_attempt_at_a_layer_clears_the_dead_attempts_before_it() {
        let layers = std::env::temp_dir().join(format!("vk-winbuild-tmp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&layers);
        let live = format!("k.tmp-{}", std::process::id());
        for dir in ["k.tmp-999999999", live.as_str(), "other.tmp-999999999", "k"] {
            std::fs::create_dir_all(layers.join(dir).join("run")).unwrap();
        }
        clear_attempts(&layers, "k");
        let mut left: Vec<String> = std::fs::read_dir(&layers)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        let mut want = vec!["k".to_string(), live, "other.tmp-999999999".to_string()];
        want.sort();
        assert_eq!(left, want);
        let _ = std::fs::remove_dir_all(&layers);
    }

    #[test]
    fn a_step_key_covers_secure_boot_and_is_unchanged_without_it() {
        let base = layer();
        // Without Secure Boot, the key the cache always had for this step.
        let v1 = format!("winbuild-step-v1\0{}\0COPY\0x\0[]\0None", base.key);
        assert_eq!(
            step_key(&base, "COPY\0x"),
            hex(&Sha256::digest(v1.as_bytes()))
        );
        let mut secure_boot = layer();
        secure_boot.secure_boot = true;
        assert_ne!(
            step_key(&base, "COPY\0x"),
            step_key(&secure_boot, "COPY\0x")
        );
    }

    #[test]
    fn a_step_key_covers_what_env_and_workdir_left_it_to_make() {
        let base = layer();
        let key = step_key(&base, "COPY\0x");
        assert_eq!(key, step_key(&base, "COPY\0x"));
        assert_ne!(key, step_key(&base, "COPY\0y"));
        let mut env = layer();
        env.unsaved_env.push(("A".into(), "1".into()));
        assert_ne!(key, step_key(&env, "COPY\0x"));
        let mut workdir = layer();
        workdir.workdir = Some("C:\\app".into());
        // A workdir made by an earlier step is in the material of the steps that use it.
        assert_eq!(key, step_key(&workdir, "COPY\0x"));
        workdir.unmade_workdir = true;
        assert_ne!(key, step_key(&workdir, "COPY\0x"));
        // Network access changes the step's cache material.
        assert_ne!(
            run_material(&base, "a", "auto", true),
            run_material(&base, "a", "auto", false)
        );
    }

    #[test]
    fn env_and_workdir_are_made_with_their_quotes_doubled() {
        assert_eq!(prepare_script(&[], None), None);
        let script = prepare_script(&[("A".into(), "it's".into())], Some("C:\\a'b")).unwrap();
        assert_eq!(
            script,
            "$ErrorActionPreference = 'Stop'\n\
             [Environment]::SetEnvironmentVariable('A', 'it''s', 'Machine')\n\
             New-Item -ItemType Directory -Force -Path 'C:\\a''b' | Out-Null\n"
        );
        assert_eq!(ps_quote("a\u{2019}b"), "'a\u{2019}\u{2019}b'");
    }

    /// A fresh directory for one test.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-winbuild-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    #[test]
    fn copy_sources_walk_directories_relative_to_the_context() {
        let ctx = scratch("walk");
        std::fs::create_dir_all(ctx.join("scripts/sub")).unwrap();
        std::fs::write(ctx.join("one.ps1"), "1").unwrap();
        std::fs::write(ctx.join("scripts/a.ps1"), "a").unwrap();
        std::fs::write(ctx.join("scripts/sub/b.ps1"), "b").unwrap();
        std::os::unix::fs::symlink(ctx.join("one.ps1"), ctx.join("scripts/link.ps1")).unwrap();
        let (files, has_dir) = copy_sources(&ctx, &["one.ps1".into()]).unwrap();
        assert_eq!(files, vec![("one.ps1".to_string(), ctx.join("one.ps1"))]);
        assert!(!has_dir);
        let (files, has_dir) = copy_sources(&ctx, &["scripts".into()]).unwrap();
        let names: Vec<&str> = files.iter().map(|(rel, _)| rel.as_str()).collect();
        assert_eq!(names, vec!["a.ps1", "link.ps1", "sub/b.ps1"]);
        assert_eq!(files[1].1, ctx.join("one.ps1"));
        assert!(has_dir);
        assert!(copy_sources(&ctx, &["missing".into()]).is_err());
        let _ = std::fs::remove_dir_all(&ctx);
    }

    #[test]
    fn copy_sources_stay_inside_the_context() {
        let root = scratch("escape");
        let ctx = root.join("ctx");
        std::fs::create_dir_all(ctx.join("dir")).unwrap();
        std::fs::write(root.join("secret"), "s").unwrap();
        std::fs::write(ctx.join("ok"), "o").unwrap();
        let refused = |sources: &[&str]| {
            let sources: Vec<String> = sources.iter().map(|s| s.to_string()).collect();
            copy_sources(&ctx, &sources).is_err()
        };
        assert!(refused(&["../secret"]));
        assert!(refused(&["dir/../../secret"]));
        assert!(refused(&[root.join("secret").to_str().unwrap()]));
        std::os::unix::fs::symlink(root.join("secret"), ctx.join("out")).unwrap();
        assert!(refused(&["out"]));
        std::os::unix::fs::symlink(root.join("secret"), ctx.join("dir/out")).unwrap();
        assert!(refused(&["dir"]));
        std::fs::remove_file(ctx.join("dir/out")).unwrap();
        // A symlinked directory, here a loop, is not followed.
        std::os::unix::fs::symlink(&ctx, ctx.join("dir/loop")).unwrap();
        assert!(refused(&["dir"]));
        assert!(!refused(&["ok"]));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_copy_key_covers_where_each_file_lands() {
        let ctx = scratch("copykey");
        std::fs::write(ctx.join("a.txt"), "a").unwrap();
        let plan = |dest: &str, workdir: Option<&str>| {
            let copy = parser::Copy {
                sources: vec!["a.txt".into()],
                dest: dest.into(),
                from: None,
                chown: None,
                chmod: None,
                link: false,
            };
            let (targets, material) = copy_plan(&copy, &ctx, workdir).unwrap();
            let targets: Vec<String> = targets.into_iter().map(|(t, _)| t).collect();
            (targets, material)
        };
        // `C:/app` and `C:/app/` make different layers: a file `app`, or `app\a.txt`.
        let (file, file_key) = plan("C:/app", None);
        let (dir, dir_key) = plan("C:/app/", None);
        assert_eq!(file, vec!["C:\\app"]);
        assert_eq!(dir, vec!["C:\\app\\a.txt"]);
        assert_ne!(file_key, dir_key);
        let (here, here_key) = plan(".", Some("C:\\work"));
        assert_eq!(here, vec!["C:\\work\\a.txt"]);
        assert_ne!(here_key, plan(".", Some("C:\\other")).1);
        std::fs::write(ctx.join("a.txt"), "b").unwrap();
        assert_ne!(dir_key, plan("C:/app/", None).1);
        let _ = std::fs::remove_dir_all(&ctx);
    }

    #[test]
    fn a_bundle_names_its_layer_and_the_cache_supplies_the_disk() {
        let root = scratch("bundle");
        let (bundle, cache) = (root.join("out"), root.join("cache"));
        let key = "a".repeat(64);
        let mut built = layer();
        built.key = key.clone();
        built.disk = cache.join("layers").join(&key).join("disk.qcow2");
        built.password = "secret".into();
        built.env = vec![("A".into(), "1".into())];
        built.workdir = Some("C:\\app".into());
        built.generalized = true;
        built.provision = Some("cmd /S /C setup.cmd".into());
        built.tpm = true;
        std::fs::create_dir_all(cache.join("layers").join(&key)).unwrap();
        std::fs::write(&built.disk, vec![0; 1 << 20]).unwrap();
        write_bundle(&built, 2, "4G", &bundle).unwrap();
        let manifest = crate::uefi::Bundle::open(&bundle).unwrap().manifest;
        assert!(manifest.tpm, "the image's machines have a TPM");
        let record = std::fs::read_to_string(bundle.join(LAYER_RECORD)).unwrap();
        assert!(
            !record.contains("secret") && !record.contains("disk.qcow2"),
            "{record}"
        );
        assert!(!bundle.join(format!("{LAYER_RECORD}.tmp")).exists());
        let err = format!("{:#}", bundle_layer(&bundle, &cache).unwrap_err());
        assert!(err.contains("gone from the build cache"), "{err}");
        let step = cache.join("layers").join(&key);
        std::fs::write(step.join("complete"), "").unwrap();
        let loaded = bundle_layer(&bundle, &cache).unwrap();
        assert_eq!(loaded.disk, step.join("disk.qcow2"));
        assert_eq!(loaded.password, "secret");
        assert!(loaded.generalized);
        assert_eq!(loaded.provision, built.provision);
        // A step on it keys as one on the layer the bundle recorded.
        assert_eq!(step_key(&loaded, "RUN\0x"), step_key(&built, "RUN\0x"));
        assert_eq!((loaded.env, loaded.workdir), (built.env, built.workdir));
        let refused = [
            (record.replace(&key, "../../etc"), "not a layer key"),
            (
                record.replace("\"version\": 1", "\"version\": 2"),
                "version 2",
            ),
            (record.replace("\"1\"", "\"a\\\"b\""), "cannot hold quotes"),
            (
                record.replace("\"1\"", "\"a\\r\\nb\""),
                "cannot hold quotes",
            ),
        ];
        for (forged, want) in refused {
            assert_ne!(forged, record, "{want}");
            std::fs::write(bundle.join(LAYER_RECORD), forged).unwrap();
            let err = format!("{:#}", bundle_layer(&bundle, &cache).unwrap_err());
            assert!(err.contains(want), "{want}: {err}");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_bundle_on_the_installed_base_finds_its_disk_in_the_winiso_cache() {
        let root = scratch("bundle-base");
        let (bundle, cache) = (root.join("out"), root.join("cache"));
        let key = "b".repeat(64);
        let settled = cache.join("winiso").join("settled").join(&key);
        std::fs::create_dir_all(&settled).unwrap();
        std::fs::write(settled.join("base.json"), "{}").unwrap();
        std::fs::create_dir_all(&bundle).unwrap();
        let mut record = serde_json::to_value(layer()).unwrap();
        record["key"] = key.into();
        record["version"] = LAYER_RECORD_VERSION.into();
        std::fs::write(bundle.join(LAYER_RECORD), record.to_string()).unwrap();
        std::fs::write(bundle.join("admin-password"), "pw\n").unwrap();
        let loaded = bundle_layer(&bundle, &cache).unwrap();
        assert_eq!(loaded.disk, settled.join("disk.qcow2"));
        assert_eq!(loaded.password, "pw");
        // Records predating CMD have no provisioning.
        record.as_object_mut().unwrap().remove("provision");
        std::fs::write(bundle.join(LAYER_RECORD), record.to_string()).unwrap();
        assert_eq!(bundle_layer(&bundle, &cache).unwrap().provision, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_generalize_answer_carries_the_password_escaped_and_keys_the_step() {
        let answer = generalize_answer("a&<b");
        assert!(answer.contains("<Value>a&amp;&lt;b</Value>"), "{answer}");
        let key = |password: &str| {
            step_key(
                &layer(),
                &format!("GENERALIZE\0{}", generalize_answer(password)),
            )
        };
        assert_ne!(key("one"), key("two"));
        assert_eq!(key("one"), key("one"));
    }
}
