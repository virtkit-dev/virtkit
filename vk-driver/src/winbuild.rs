//! `vk build` of a Windows Dockerfile: a stage starts from `FROM winiso:` ([`crate::winiso`]) or
//! an earlier stage, and each `RUN` or `COPY` is a layer — a qcow2 overlay over the one before,
//! cached by its parent and the instruction — made by booting the guest on it, acting through
//! qemu-ga ([`crate::winexec`]) and powering it off cleanly. `ENV`, `WORKDIR` and `SHELL` shape
//! the `RUN` steps after them. The result is a bundle `vk run` boots.
//!
//! As Docker does on Windows, a shell-form `RUN` is the program line `<SHELL> <text>` (by
//! default `cmd /S /C <text>`), and runs as qemu-ga does, as SYSTEM. Its exit code 3010 or 1641
//! asks for a restart (`--reboot=auto`); `--reboot=always|never` overrides.

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

/// Whether `text` is a Dockerfile for Windows: one of its stages installs from `winiso:` or
/// names the Windows platform.
pub(crate) fn is_windows(text: &str) -> Result<bool> {
    Ok(parser::parse(text)?.instructions.iter().any(|i| match i {
        Instruction::From(f) => {
            f.image.starts_with(crate::winiso::SCHEME)
                || f.platform
                    .as_deref()
                    .is_some_and(|p| p.starts_with("windows"))
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
}

/// A stage as it builds: its current layer and what its later `RUN`s inherit.
#[derive(Clone, Debug)]
struct Layer {
    disk: PathBuf,
    key: String,
    password: String,
    shell: Vec<String>,
    env: Vec<(String, String)>,
    workdir: Option<String>,
    /// Variables set by `ENV` since the last step, still to be made machine-wide.
    unsaved_env: Vec<(String, String)>,
    /// `WORKDIR` changed since the last step: the directory is still to be created.
    unmade_workdir: bool,
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
fn check_stage(stage: &Stage, context: &Path) -> Result<()> {
    let from = &stage.from;
    // Parsed for the Windows build, which does not act on them yet.
    if let Some((key, _)) = from.guest.windows.first() {
        bail!("`# vk: {key}` is not supported yet");
    }
    if crate::winiso::Source::of_stage(&from.image, &from.extra_flags, context)?.is_none()
        && let Some((name, _)) = from.extra_flags.first()
    {
        bail!(
            "FROM {}: --{name} applies to a winiso: stage only",
            from.image
        );
    }
    for instruction in &stage.body {
        match instruction {
            Instruction::Run(run) => {
                reboot_mode(run)?;
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
            _ => {}
        }
    }
    Ok(())
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
    if !run.mounts.is_empty() || run.network.is_some() || run.security.is_some() {
        bail!("RUN --mount, --network and --security do not apply to a Windows build");
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
    check_stage(stage, &opts.context).with_context(|| format!("stage {label}"))?;
    let (cpus, mem) = guest_size(stage, opts);
    let mut layer = if let Some(source) =
        crate::winiso::Source::of_stage(&stage.from.image, &stage.from.extra_flags, &opts.context)?
    {
        let base = crate::winiso::base(&source, DEFAULT_DISK, cpus, &mem, &cache.join("winiso"))?;
        Layer {
            disk: base.disk,
            key: base.key,
            password: base.password,
            shell: DEFAULT_SHELL.iter().map(|s| s.to_string()).collect(),
            env: Vec::new(),
            workdir: None,
            unsaved_env: Vec::new(),
            unmade_workdir: false,
        }
    } else if let Some(parent) = stages[..index]
        .iter()
        .position(|s| s.from.as_name.as_deref() == Some(stage.from.image.as_str()))
    {
        build_stage(stages, parent, opts, cache, built)?
    } else {
        bail!(
            "FROM {}: a Windows stage starts from winiso: or an earlier stage",
            stage.from.image
        );
    };
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
            // Recorded by the image's run config in a later step; nothing to build.
            _ => {}
        }
    }
    // As Docker keeps a stage's last ENV and WORKDIR in its image.
    if !layer.unsaved_env.is_empty() || layer.unmade_workdir {
        eprintln!("virtkit: [{label}] saving ENV and WORKDIR");
        step(&mut layer, "SAVE", &steps, |_, _, _| Ok(()))?;
    }
    built.insert(index, layer.clone());
    Ok(layer)
}

/// What a stage's steps boot: its guests' size and the layer cache.
struct Steps<'a> {
    cpus: u32,
    mem: &'a str,
    cache: &'a Path,
}

fn run_step(layer: &mut Layer, run: &parser::Run, what: &str, steps: &Steps) -> Result<()> {
    let reboot = reboot_mode(run)?;
    let line = command_line(&layer.shell, &run.cmd);
    eprintln!("virtkit: {what} RUN {}", first_line(&line));
    let material = format!(
        "RUN\0{line}\0{reboot}\0{:?}\0{:?}",
        layer.env, layer.workdir
    );
    step(layer, &material, steps, |ga, l, vm| {
        let code = crate::winexec::exec_command_line(
            ga,
            &line,
            &l.env,
            l.workdir.as_deref(),
            &mut std::io::stderr().lock(),
        )?;
        let Some(restart) = wants_restart(reboot, code) else {
            bail!("RUN {} exited {code}", first_line(&line));
        };
        if restart {
            eprintln!("virtkit: {what} restarting the guest");
            restart_guest(ga, vm)?;
        }
        Ok(())
    })
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
    step(layer, &material, steps, |ga, _, _| {
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

/// Restart the guest in place and wait for its agent.
fn restart_guest(ga: &mut Client, guest: &mut crate::uefi::Guest) -> Result<()> {
    crate::winexec::restart(ga, &mut || guest.running())?;
    *ga = Client::connect(&guest.agent_socket(), AGENT_TIMEOUT)
        .context("qemu-ga did not come back after the restart")?;
    Ok(())
}

/// The cache key of the step `material` on `layer`: its parent, the instruction, and what
/// `ENV` and `WORKDIR` left for the step to make.
fn step_key(layer: &Layer, material: &str) -> String {
    let workdir = layer.workdir.as_deref().filter(|_| layer.unmade_workdir);
    hex(&Sha256::digest(
        format!(
            "winbuild-step-v1\0{}\0{material}\0{:?}\0{workdir:?}",
            layer.key, layer.unsaved_env
        )
        .as_bytes(),
    ))
}

/// Make the layer `material` names on top of `layer`, or take it from the cache: boot the guest
/// on an overlay, make the variables `ENV` set and the directory `WORKDIR` named since the last
/// step, apply `act`, and power off.
fn step(
    layer: &mut Layer,
    material: &str,
    steps: &Steps,
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
        if let Err(e) = make_step(layer, &work, &disk, steps, act) {
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

/// [`step`]'s guest: boot `disk` with `work` as its run directory, make the variables `ENV`
/// set and the directory `WORKDIR` named since the last step, apply `act`, and power off.
fn make_step(
    layer: &Layer,
    work: &Path,
    disk: &Path,
    steps: &Steps,
    act: impl FnOnce(&mut Client, &Layer, &mut crate::uefi::Guest) -> Result<()>,
) -> Result<()> {
    let mut vm = crate::uefi::Guest::boot(
        work,
        "vk-build",
        vec![Disk::overlay(disk.to_path_buf())],
        steps.cpus,
        steps.mem,
    )?;
    let mut ga = Client::connect(&vm.agent_socket(), AGENT_TIMEOUT)
        .with_context(|| format!("qemu-ga did not answer; see {}", vm.console().display()))?;
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
/// the built layer, and the Administrator password.
fn write_bundle(layer: &Layer, cpus: u32, mem: &str, out: &Path) -> Result<()> {
    std::fs::create_dir_all(out)?;
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
            check_stage(&stages[0], Path::new("/ctx")).unwrap_err()
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
            unsaved_env: Vec::new(),
            unmade_workdir: false,
        }
    }

    #[test]
    fn a_dockerfile_is_windows_when_a_stage_installs_or_targets_windows() {
        assert!(
            is_windows("FROM winiso:ws.iso@sha256:aa --drivers=v.iso@sha256:bb AS base\nRUN x\n")
                .unwrap()
        );
        assert!(is_windows("FROM --platform=windows/amd64 base\n").unwrap());
        assert!(!is_windows("FROM alpine:3.20\nRUN apk add curl\n").unwrap());
        assert!(is_windows("FROM\n").is_err());
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
    fn run_takes_reboot_only() {
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
        assert!(reboot("RUN --network=none a").is_err());
        assert!(reboot("RUN --security=insecure a").is_err());
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
            ("RUN --network=host a\n", "--network"),
        ];
        for (body, want) in refused {
            let err = refusal(&format!("{WINISO}{body}"));
            assert!(err.contains(want), "{body}: {err}");
        }
        let err = refusal(&format!("# vk: generalize=on\n{WINISO}"));
        assert!(
            err.contains("`# vk: generalize` is not supported yet"),
            "{err}"
        );
        let err = refusal("FROM base --drivers=x\n");
        assert!(
            err.contains("--drivers applies to a winiso: stage only"),
            "{err}"
        );
        let ok = parsed(&format!(
            "{WINISO}ENV A=1 B=cost$\nWORKDIR C:/app\nSHELL [\"powershell\", \"-Command\"]\n\
             RUN --reboot=always a\nCOPY a b C:/app/\nLABEL x=y\n"
        ));
        check_stage(&ok[0], Path::new("/ctx")).unwrap();
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
}
