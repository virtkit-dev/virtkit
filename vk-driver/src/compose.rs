//! The docker-compose subset `vk run --compose` consumes — the service
//! declaration, kept isomorphic to compose so a compose file (or a GitLab CI
//! `services:` block, which is a subset of it) migrates mechanically.
//!
//! Supported per service: `image` xor `build.{context, dockerfile (string or list —
//! a vk extension merging the files into one stage namespace), target, args,
//! additional_contexts (directories only)}`,
//! `environment`, `command`, `entrypoint`, `user`, `hostname`, `depends_on`
//! (start-ordering only), `volumes` (bind mounts) and `profiles` (a profiled
//! service stays down at start-up unless activated or depended on). **Any other
//! key is a hard error** — silently ignoring a compose key would silently change
//! behavior.
//!
//! ```yaml
//! services:
//!   redis:
//!     image: redis:7-alpine       # pulled; fingerprint = manifest digest
//!   db:
//!     build: ./db                 # shorthand: context ./db, ./db/Dockerfile
//!   app:
//!     build:
//!       context: .                # shared by all the service's dockerfiles
//!       dockerfile: [base.Dockerfile, app.Dockerfile]  # merged stage namespace
//!       target: app               # any stage across the merged files
//!       additional_contexts:      # extra dirs, read via COPY --from=<name>
//!         shared: ../shared       #   (also the `- shared=../shared` list form)
//!     depends_on: [db, redis]
//! ```
//!
//! Values interpolate `$VAR`, `${VAR}` and `${VAR:-default}` from the environment over a
//! sibling `.env` ([`load`]). Local runs also supply reserved `${VK_*}` values
//! ([`Builtins`]), keeping host paths and ids out of committed files.
//!
//! Runtime config follows the compose model: the image (its config sidecar / OCI
//! config) carries the defaults, the service entries are start-time overrides —
//! merged by [`merged_config`] and handed to the guest at boot. Changing an
//! override never rebuilds an image.

use std::collections::BTreeMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use vk_core::runcfg::RunConfig;

/// One declared service, mapped from a compose `services.<name>` entry.
#[derive(Debug, Clone)]
pub struct Unit {
    pub name: String,
    /// guest hostname (compose `hostname`, default: the service name)
    pub hostname: String,
    pub source: Source,
    /// start-time overrides, layered over the image's runtime config
    pub environment: Vec<(String, String)>,
    pub entrypoint: Option<Vec<String>>,
    pub command: Option<Vec<String>>,
    pub user: Option<String>,
    /// services that must be started before this one (ordering only)
    pub depends_on: Vec<String>,
    pub volumes: Vec<Volume>,
    /// compose profiles: a service with any profile assigned is declared but NOT
    /// started at start-up unless one of its profiles is activated (`--profile`)
    /// or an enabled service depends on it — `virtctl start` works regardless
    pub profiles: Vec<String>,
    /// Who runs as PID 1 in this unit's guest (compose `x-virtkit.init`), applied
    /// identically whether the unit boots as the primary (`--primary`) or a sibling.
    /// `Default` = vk-agent; `Image` = the image's own `/sbin/init`; `Entrypoint` =
    /// the image's own ENTRYPOINT+CMD.
    pub init: crate::run::InitSource,
    /// Which kernel this unit's guest boots on (compose `x-virtkit.kernel`), applied
    /// identically primary or sibling. `Default` = the pinned kernel; `Image` = the
    /// image's own kernel + modules; `Path` = an explicit kernel file.
    pub kernel: crate::run::KernelSource,
    /// This unit's guest vCPU count (compose `x-virtkit.cpus`), applied identically
    /// primary or sibling; `None` = the consumer's default.
    pub cpus: Option<u32>,
    /// This unit's guest RAM (compose `x-virtkit.mem`, `<n>G`/`<n>M`/MiB), applied
    /// identically primary or sibling; `None` = the consumer's default.
    pub mem: Option<String>,
    /// Whether this unit's guest runs microVMs of its own (compose `x-virtkit.nested`),
    /// applied identically primary or sibling — a service that is itself a hypervisor
    /// (a vk builder, a nested test runner). `false` = no nesting, the default.
    pub nested: bool,
}

/// Where a unit's image comes from.
#[derive(Debug, Clone)]
pub enum Source {
    /// pulled from a registry (fingerprint: the manifest digest)
    Image(String),
    /// built in-process from Dockerfile stage(s) (fingerprint: the stage key)
    Build {
        /// the service's Dockerfile(s); several merge into one stage namespace
        dockerfiles: Vec<PathBuf>,
        /// the build context, shared by all the service's files (compose semantics)
        context: PathBuf,
        /// `build.additional_contexts`: extra named contexts this service's stages may read
        /// with `COPY --from=<name>`, each already resolved against the compose file's dir.
        build_contexts: Vec<(String, PathBuf)>,
        target: Option<String>,
        args: Vec<(String, String)>,
    },
}

/// A bind mount (`host:guest[:ro|:rw|:overlay|:disk[,size=SIZE]]`); named volumes are not
/// supported.
#[derive(Debug, Clone)]
pub struct Volume {
    pub host: PathBuf,
    pub guest: String,
    pub read_only: bool,
    /// Mount the share as the read-only lower layer of a tmpfs-backed overlayfs at `guest`,
    /// instead of mounting it directly: the guest reads the host tree but every write lands in
    /// guest RAM and never crosses back. Implies `read_only` for the share itself. Directory
    /// binds only (a single-file bind has nothing to overlay).
    pub overlay: bool,
    /// The host path is a regular file (not a directory): a single-file bind. Virtio-fs shares
    /// a directory, so this is served by a single-file fs (root = just this file) and linked
    /// into place in the guest, rather than mounted at `guest` directly.
    pub is_file: bool,
    /// The host path is a whole ext4 filesystem in a file, attached as a raw virtio-blk device
    /// and mounted at `guest` — not virtiofs-shared at all. Gives the guest full POSIX
    /// semantics (arbitrary chown, mknod, sockets) that a virtiofs share's host-side ownership
    /// mapping does not allow, and — unlike `overlay` — real persistence: the file, not a
    /// tmpfs layer, so its content survives across boots. Created and formatted on first use
    /// (the file does not exist yet); an existing file is trusted as-is, whatever a previous
    /// boot left in it. Mutually exclusive with `overlay`/`is_file`.
    pub disk: bool,
    /// Formatted capacity for a freshly created `disk` volume, from its `size=` suffix.
    /// Ignored once the backing file already exists — its own capacity applies, since this ext4
    /// writer has no resize. `None` uses a generous built-in default.
    pub disk_size_mib: Option<u64>,
}

/// The service's start-time config layered over the image's defaults, compose
/// semantics: environment upserts; `entrypoint:` replaces the entrypoint AND drops
/// the image's cmd (`command:`, when also given, replaces it); `command:` alone
/// replaces only the cmd; `user:` replaces the user. The image keeps its workdir.
pub fn merged_config(image: &RunConfig, unit: &Unit) -> RunConfig {
    let mut env = image.env.clone();
    for (k, v) in &unit.environment {
        match env.iter_mut().find(|(ek, _)| ek == k) {
            Some(e) => e.1 = v.clone(),
            None => env.push((k.clone(), v.clone())),
        }
    }
    let (entrypoint, cmd) = match (&unit.entrypoint, &unit.command) {
        (Some(e), Some(c)) => (e.clone(), c.clone()),
        (Some(e), None) => (e.clone(), Vec::new()),
        (None, Some(c)) => (image.entrypoint.clone(), c.clone()),
        (None, None) => (image.entrypoint.clone(), image.cmd.clone()),
    };
    RunConfig {
        env,
        user: unit.user.clone().unwrap_or_else(|| image.user.clone()),
        workdir: image.workdir.clone(),
        entrypoint,
        cmd,
        // The readiness port gate is an image property; compose overrides never change it.
        exposed_ports: image.exposed_ports.clone(),
    }
}

/// Start order over the units: dependencies first (DFS), unknown names and cycles
/// are errors. Returns indices into `units`.
pub fn boot_order(units: &[Unit]) -> Result<Vec<usize>> {
    let by_name: BTreeMap<&str, usize> = units
        .iter()
        .enumerate()
        .map(|(i, u)| (u.name.as_str(), i))
        .collect();
    let mut order = Vec::new();
    let mut state = vec![0u8; units.len()]; // 0 unvisited, 1 visiting, 2 done
    fn visit(
        i: usize,
        units: &[Unit],
        by_name: &BTreeMap<&str, usize>,
        state: &mut [u8],
        order: &mut Vec<usize>,
    ) -> Result<()> {
        match state[i] {
            2 => return Ok(()),
            1 => bail!("depends_on cycle through service {:?}", units[i].name),
            _ => {}
        }
        state[i] = 1;
        for dep in &units[i].depends_on {
            let &d = by_name.get(dep.as_str()).with_context(|| {
                format!("service {:?} depends_on unknown {dep:?}", units[i].name)
            })?;
            visit(d, units, by_name, state, order)?;
        }
        state[i] = 2;
        order.push(i);
        Ok(())
    }
    for i in 0..units.len() {
        visit(i, units, &by_name, &mut state, &mut order)?;
    }
    Ok(order)
}

/// Which units start eagerly, given the activated profiles — compose semantics:
/// a unit with no profiles always starts; a profiled unit starts when one of its
/// profiles is active, or when an enabled unit (transitively) depends on it. The
/// rest stay declared-but-down, for `virtctl start`.
pub fn enabled(units: &[Unit], active_profiles: &[String]) -> Vec<bool> {
    let by_name: BTreeMap<&str, usize> = units
        .iter()
        .enumerate()
        .map(|(i, u)| (u.name.as_str(), i))
        .collect();
    let mut on = vec![false; units.len()];
    let mut stack: Vec<usize> = units
        .iter()
        .enumerate()
        .filter(|(_, u)| {
            u.profiles.is_empty() || u.profiles.iter().any(|p| active_profiles.contains(p))
        })
        .map(|(i, _)| i)
        .collect();
    while let Some(i) = stack.pop() {
        if std::mem::replace(&mut on[i], true) {
            continue;
        }
        for dep in &units[i].depends_on {
            // unknown deps are boot_order's error to report; skip here.
            if let Some(&d) = by_name.get(dep.as_str()) {
                stack.push(d);
            }
        }
    }
    on
}

/// The transitive `depends_on` closure of one unit, excluding the unit itself —
/// `docker compose run` semantics: running a service starts its dependencies
/// (profiled or not) and nothing else. Unknown names are `boot_order`'s error to
/// report; they are skipped here.
pub fn dependency_closure(units: &[Unit], root: usize) -> Vec<bool> {
    let by_name: BTreeMap<&str, usize> = units
        .iter()
        .enumerate()
        .map(|(i, u)| (u.name.as_str(), i))
        .collect();
    let mut on = vec![false; units.len()];
    let mut stack = vec![root];
    while let Some(i) = stack.pop() {
        for dep in &units[i].depends_on {
            if let Some(&d) = by_name.get(dep.as_str())
                && !std::mem::replace(&mut on[d], true)
            {
                stack.push(d);
            }
        }
    }
    on[root] = false;
    on
}

/// Reserved `${VK_*}` interpolation values for a local run.
///
/// They expose the workspace, state directory, running `vk`, and effective uid/gid without
/// a generated `.env`. The GitLab executor passes `None` for untrusted job-authored compose
/// files, making every `${VK_*}` reference an error.
#[derive(Debug, Clone)]
pub struct Builtins {
    /// `${VK_WORKSPACE}` — the run's workspace root (`--workspace`, else the launch cwd)
    pub workspace: PathBuf,
    /// `${VK_STATE_DIR}` — the run's state directory (`--state-dir`, else per-pid launch
    /// scratch removed when the run ends). `None` for `vk build --compose` without
    /// `--state-dir`; referencing it then fails instead of inventing a directory.
    pub state_dir: Option<PathBuf>,
    /// `${VK_SELF}` — the running `vk`, for the bind that hands a guest its own copy
    pub vk_self: PathBuf,
    /// `${VK_UID}` — the effective host uid, for a build arg that keeps a shared tree's
    /// ownership coherent
    pub uid: u32,
    /// `${VK_GID}` — the effective host gid, as `uid`
    pub gid: u32,
}

/// Every name [`Builtins`] answers. References reserve the entire `VK_` prefix so typos do
/// not fall through to the environment. Definitions reserve only these five names, and only
/// when builtins are supplied (see [`load_with_env`]).
const BUILTIN_NAMES: [&str; 5] = [
    "VK_WORKSPACE",
    "VK_STATE_DIR",
    "VK_SELF",
    "VK_UID",
    "VK_GID",
];

impl Builtins {
    /// Resolve the builtins for this process: `workspace` (or the cwd) and `state_dir` as
    /// absolute paths, the running executable, and the effective uid/gid.
    pub fn resolve(workspace: Option<&Path>, state_dir: Option<&Path>) -> Result<Self> {
        let workspace = match workspace {
            // Check before `parse_volume` treats a missing source as a directory share and
            // turns a flag typo into a later mount error.
            Some(w) if !w.is_dir() => bail!("--workspace {} is not a directory", w.display()),
            Some(w) => absolute(w)?,
            None => std::env::current_dir().context("resolving the workspace (the cwd)")?,
        };
        Ok(Self {
            workspace,
            state_dir: state_dir.map(absolute).transpose()?,
            vk_self: std::env::current_exe().context("resolving this vk executable")?,
            // SAFETY: geteuid/getegid always succeed and touch no memory.
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        })
    }

    /// The value of one reserved name. An unknown `VK_` name is an error naming the
    /// supported set — the prefix never falls back to the environment.
    fn value(&self, name: &str) -> Result<String> {
        match name {
            "VK_WORKSPACE" => path_value(name, &self.workspace),
            "VK_STATE_DIR" => match &self.state_dir {
                Some(dir) => path_value(name, dir),
                None => bail!(
                    "compose references ${{{name}}}, but this command has no run state dir — \
                     pass `vk build --state-dir` to name the one the boot will use"
                ),
            },
            // After replacement, `current_exe` can return a `… (deleted)` path that no longer
            // opens. Refuse it instead of binding nothing into the guest.
            "VK_SELF" if !self.vk_self.is_file() => bail!(
                "compose references ${{{name}}}, but {} is gone — the running vk was \
                 replaced or removed since it started",
                self.vk_self.display()
            ),
            "VK_SELF" => path_value(name, &self.vk_self),
            "VK_UID" => Ok(self.uid.to_string()),
            "VK_GID" => Ok(self.gid.to_string()),
            _ => bail!(
                "compose references ${{{name}}}, but the VK_ namespace is reserved for the \
                 builtins ({})",
                BUILTIN_NAMES.join(", ")
            ),
        }
    }
}

/// Validate a builtin path for interpolation. The short volume syntax reparses `:` as a
/// field separator and newlines as additional binds, so paths containing either are unsafe.
///
/// The splitter also trims leading and trailing whitespace, which could change the bound
/// path. Interior whitespace survives volume parsing, but references in `command:` or
/// `entrypoint:` strings still need shell-style quoting.
fn path_value(name: &str, p: &Path) -> Result<String> {
    let s = p
        .to_str()
        .with_context(|| format!("${{{name}}} is {} — not valid UTF-8", p.display()))?;
    if let Some(bad) = s.chars().find(|c| *c == ':' || *c == '\n') {
        bail!(
            "${{{name}}} is {s:?}: a {bad:?} in it cannot survive the `host:guest[:mode]` \
             volume syntax — give the run a path without one"
        );
    }
    if s != s.trim() {
        bail!(
            "${{{name}}} is {s:?}: the space around it is stripped when a volume entry is \
             split, so the bind would name a different directory — give the run a path \
             without one"
        );
    }
    Ok(s.to_string())
}

/// Resolve `p` consistently before and after it exists by canonicalizing its deepest
/// existing ancestor and appending missing components. A missing component later created
/// as a symlink resolves to its target once present.
///
/// This keeps `${VK_STATE_DIR}` identical for `vk build`, which creates nothing, and
/// `vk run`, which creates the directory first, so prebuild cache keys match the boot.
fn absolute(p: &Path) -> Result<PathBuf> {
    let joined = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .with_context(|| format!("resolving {} against the cwd", p.display()))?
            .join(p)
    };
    // Normalize `.` and `..` lexically before canonicalizing the existing prefix; otherwise
    // the result depends on how much of the path exists. A `..` after a symlink therefore
    // names the lexical parent rather than the symlink target's parent.
    let mut head = PathBuf::new();
    for part in joined.components() {
        match part {
            std::path::Component::ParentDir if head.parent().is_some() => {
                head.pop();
            }
            other => head.push(other),
        }
    }
    let mut missing = Vec::new();
    loop {
        match std::fs::canonicalize(&head) {
            Ok(mut abs) => {
                abs.extend(missing.iter().rev());
                return Ok(abs);
            }
            // Anything but "not there yet" — a denied traversal, a symlink loop, a
            // non-directory component — is a real failure, not a path to keep trimming.
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(e).with_context(|| format!("resolving {}", head.display()));
            }
            Err(_) => {
                let Some(name) = head.file_name().map(|n| n.to_os_string()) else {
                    // Trimmed all the way to `/` (or to a `..` above it) and it still does
                    // not resolve: there is nothing left to strip.
                    return Ok(head);
                };
                missing.push(name);
                head.pop();
            }
        }
    }
}

/// Load + map a compose file. `base` (the file's directory) anchors every relative
/// path: build contexts, Dockerfiles, and bind-mount sources. Variable references
/// (`$VAR`, `${VAR}`, `${VAR:-default}`) are interpolated first, docker-compose
/// style — from the process environment layered over a sibling `.env` (the process
/// env wins) — so machine-specific values (a repo path, a uid) stay out of the
/// committed file. `builtins` additionally answers the reserved `${VK_*}` names (see
/// [`Builtins`]); `None` makes any reference to one an error.
pub fn load(path: &Path, builtins: Option<&Builtins>) -> Result<Vec<Unit>> {
    load_with_env(path, &|name| std::env::var(name).ok(), builtins)
}

/// Like `load`, but the caller supplies how a `${VAR}` name resolves against the *ambient*
/// environment (the sibling `.env` is still layered underneath, ambient winning per docker
/// precedence). The GitLab executor passes a resolver restricted to job (`CUSTOM_ENV_*`)
/// variables, so an untrusted committed compose file cannot interpolate runner-level secrets
/// out of the executor's process environment.
pub fn load_with_env(
    path: &Path,
    ambient: &dyn Fn(&str) -> Option<String>,
    builtins: Option<&Builtins>,
) -> Result<Vec<Unit>> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let dotenv = load_dotenv(base)?;
    // Reject collisions instead of silently ignoring the user's value or letting it redirect
    // a vk-owned mount. When builtins are withheld, references already fail, so definitions
    // remain harmless. Reserve only the five names: unrelated `VK_` variables such as
    // `VK_DEV_CPUS` and `VK_CACHE` may legitimately appear in a sibling `.env`.
    if builtins.is_some() {
        for name in BUILTIN_NAMES {
            if ambient(name).is_some() {
                bail!("{name} is reserved for vk's own value — unset it in the environment");
            }
            if dotenv.iter().any(|(k, _)| k == name) {
                bail!(
                    "{name} is reserved for vk's own value — remove it from {}",
                    base.join(".env").display()
                );
            }
        }
    }
    let resolve = |name: &str| {
        // ambient environment first (docker precedence), then the sibling .env. A
        // set-but-empty ambient value wins over a .env value — and, being empty, is
        // then treated as unset by `interpolate` (so it takes a default or errors).
        ambient(name).or_else(|| {
            dotenv
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    };
    parse(&raw, base, &resolve, builtins).with_context(|| format!("in {}", path.display()))
}

/// Load `KEY=VALUE` pairs from a `.env` beside the compose file — docker-compose's
/// interpolation source. A missing file is not an error (no vars). Blank lines and
/// `#` comments are skipped; the value is taken raw (same convention as
/// `--env-file`) past one matching pair of quotes stripped by
/// `crate::strip_env_quotes` — no escape sequences, no `$VAR` expansion.
fn load_dotenv(dir: &Path) -> Result<Vec<(String, String)>> {
    let path = dir.join(".env");
    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut vars = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        match line.split_once('=') {
            Some((k, v)) => vars.push((
                k.trim().to_string(),
                crate::strip_env_quotes(v).into_owned(),
            )),
            None => bail!(
                "{}:{}: expected KEY=VALUE, got {line:?}",
                path.display(),
                n + 1
            ),
        }
    }
    Ok(vars)
}

/// Interpolate `$VAR`, `${VAR}` and `${VAR:-default}` in `text`, docker-compose
/// style; `$$` is a literal `$`. An unset (or empty) variable uses its `:-default`
/// when given, otherwise it is a **hard error** — unlike docker's silent empty
/// substitution, since an empty image tag or bind-mount path is always a bug that
/// should fail the boot loudly rather than mount/pull the wrong thing.
///
/// `:-default` is the only supported modifier: docker's `:?`, `:+` and the
/// colon-less `${VAR-default}` forms are rejected as a bad reference. A default is
/// taken literally (no nested references), so `${A:-${B}}` yields `${B}` verbatim.
///
/// A `VK_`-prefixed name is answered by `builtins` alone (see [`Builtins`]) — never by
/// `resolve`, and never by a `:-default`, since a builtin is either supplied or refused.
fn interpolate(
    text: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
    builtins: Option<&Builtins>,
) -> Result<String> {
    // set-and-non-empty; treated as unset otherwise so `:-default` and the
    // unset-error path both fire on an empty value.
    let value = |name: &str| resolve(name).filter(|v| !v.is_empty());
    // Resolve the reserved namespace before consulting the environment. Withheld builtins
    // must fail rather than pick up a runner variable with the same name.
    let reserved = |name: &str| -> Result<String> {
        match builtins {
            Some(b) => b.value(name),
            None => bail!(
                "compose references ${{{name}}}: the VK_ builtins are supplied only to a local \
                 `vk run --compose` / `vk build --compose`"
            ),
        }
    };
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '_';

    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek().copied() {
            Some('$') => {
                chars.next();
                out.push('$');
            }
            Some('{') => {
                chars.next(); // consume '{'
                let mut name = String::new();
                let mut default: Option<String> = None;
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(':') if chars.peek() == Some(&'-') => {
                            chars.next(); // consume '-'
                            let mut d = String::new();
                            loop {
                                match chars.next() {
                                    Some('}') => break,
                                    Some(dc) => d.push(dc),
                                    None => bail!("unterminated ${{{name}...}} (missing '}}')"),
                                }
                            }
                            default = Some(d);
                            break;
                        }
                        Some(nc) if is_name(nc) => name.push(nc),
                        Some(other) => {
                            bail!("bad character {other:?} in ${{{name}...}} variable reference")
                        }
                        None => bail!("unterminated ${{{name}...}} (missing '}}')"),
                    }
                }
                if name.is_empty() {
                    bail!("empty variable reference ${{}}");
                }
                if name.starts_with("VK_") {
                    if default.is_some() {
                        bail!(
                            "${{{name}}} is a vk builtin and takes no `:-default`: it is \
                             either supplied or refused, so a default could never be used"
                        );
                    }
                    out.push_str(&reserved(&name)?);
                    continue;
                }
                match value(&name).or(default) {
                    Some(v) => out.push_str(&v),
                    None => bail!(
                        "compose references ${{{name}}} but it is unset — define it in the \
                         environment or a sibling .env, or give it a ${{{name}:-default}}"
                    ),
                }
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                let mut name = String::new();
                while let Some(&nc) = chars.peek() {
                    if is_name(nc) {
                        name.push(nc);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if name.starts_with("VK_") {
                    out.push_str(&reserved(&name)?);
                    continue;
                }
                match value(&name) {
                    Some(v) => out.push_str(&v),
                    None => bail!(
                        "compose references ${name} but it is unset — define it in the \
                         environment or a sibling .env"
                    ),
                }
            }
            // a lone '$' not starting a reference (e.g. trailing, or before a space)
            _ => out.push('$'),
        }
    }
    Ok(out)
}

/// Parse + validate the compose subset (see the module docs for what is accepted).
pub fn parse(
    yaml: &str,
    base: &Path,
    resolve: &dyn Fn(&str) -> Option<String>,
    builtins: Option<&Builtins>,
) -> Result<Vec<Unit>> {
    // Interpolate on the parsed YAML *values* (never keys), then deserialize: a
    // value may expand to embedded newlines (a volume-list variable) without
    // disturbing the document structure, and `deny_unknown_fields` still runs.
    let mut doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml)?;
    interpolate_values(&mut doc, resolve, builtins)?;
    let file: ComposeFile = serde_yaml_ng::from_value(doc)?;
    if file.services.is_empty() {
        bail!("no services declared");
    }
    let mut units = Vec::new();
    for (name, svc) in file.services {
        units.push(map_service(&name, svc, base).with_context(|| format!("service {name:?}"))?);
    }
    Ok(units)
}

/// Interpolate every string *value* in a parsed YAML document (mapping keys are
/// left untouched, matching docker-compose — only values carry `${VAR}`). Applied
/// before deserializing so it covers every field uniformly.
fn interpolate_values(
    v: &mut serde_yaml_ng::Value,
    resolve: &dyn Fn(&str) -> Option<String>,
    builtins: Option<&Builtins>,
) -> Result<()> {
    use serde_yaml_ng::Value;
    match v {
        Value::String(s) => *s = interpolate(s, resolve, builtins)?,
        Value::Sequence(seq) => {
            for e in seq {
                interpolate_values(e, resolve, builtins)?;
            }
        }
        Value::Mapping(m) => {
            for (_k, val) in m.iter_mut() {
                interpolate_values(val, resolve, builtins)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// A service name becomes a LAN hostname, so it must be a valid RFC-1123 DNS
/// label: 1–63 chars of `[a-z0-9-]` with no leading or trailing hyphen.
fn is_dns_label(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

fn map_service(name: &str, svc: ComposeService, base: &Path) -> Result<Unit> {
    if !is_dns_label(name) {
        bail!(
            "service name {name:?} must be a DNS label \
             ([a-z0-9-], no leading/trailing hyphen, ≤63 chars) — it becomes a LAN hostname"
        );
    }
    let source = match (svc.image, svc.build) {
        (Some(image), None) => Source::Image(image),
        (None, Some(build)) => map_build(build, base)?,
        (Some(_), Some(_)) => bail!("give either image: or build:, not both"),
        (None, None) => bail!("needs image: or build:"),
    };
    // Each entry may hold several specs separated by newlines: interpolation can
    // expand one `${LIST}` entry into N binds (an empty/whitespace value → none),
    // so a host-built volume list — including conditional mounts — is injected
    // through a single variable.
    let volumes = svc
        .volumes
        .iter()
        .flat_map(|entry| entry.lines())
        .map(str::trim)
        .filter(|spec| !spec.is_empty())
        .map(|spec| parse_volume(spec, base))
        .collect::<Result<_>>()?;
    let depends_on = match svc.depends_on {
        Some(d) => {
            d.validate()?;
            d.into_names()
        }
        None => Vec::new(),
    };
    // The hostname lands unquoted in the switch's `--host <name>=<ip>` and the guest
    // cmdline, so it gets the same DNS-label gate as the service name.
    let hostname = match svc.hostname {
        Some(h) if !is_dns_label(&h) => bail!(
            "service {name:?} hostname {h:?} must be a DNS label \
             ([a-z0-9-], no leading/trailing hyphen, ≤63 chars)"
        ),
        Some(h) => h,
        None => name.to_string(),
    };
    // The per-service axes (compose `x-virtkit`): absent key/subkey = the defaults,
    // so an unmarked service keeps today's agent-as-PID1 pinned-kernel 2-vCPU/1G boot.
    let (init, kernel, cpus, mem, nested) = match svc.x_virtkit {
        Some(x) => (x.init()?, x.kernel()?, x.cpus()?, x.mem()?, x.nested()?),
        None => (
            crate::run::InitSource::Default,
            crate::run::KernelSource::Default,
            None,
            None,
            false,
        ),
    };
    Ok(Unit {
        name: name.to_string(),
        hostname,
        source,
        environment: svc.environment.map(Env::into_pairs).unwrap_or_default(),
        entrypoint: svc.entrypoint.map(Cmd::into_argv).transpose()?,
        command: svc.command.map(Cmd::into_argv).transpose()?,
        user: svc.user,
        depends_on,
        volumes,
        profiles: svc.profiles,
        init,
        kernel,
        cpus,
        mem,
        nested,
    })
}

fn map_build(build: serde_yaml_ng::Value, base: &Path) -> Result<Source> {
    let spec = match build {
        // `build: <dir>` is the compose shorthand for a context dir. The mapping
        // form is dispatched explicitly (not via an untagged enum) so an unknown
        // build key errors naming that key, like every other unsupported key.
        serde_yaml_ng::Value::String(dir) => BuildSpec {
            context: Some(dir.into()),
            ..Default::default()
        },
        other => serde_yaml_ng::from_value(other).context("build:")?,
    };
    let context = base.join(spec.context.as_deref().unwrap_or(Path::new(".")));
    let dockerfiles: Vec<PathBuf> = match spec.dockerfile {
        None => vec![context.join("Dockerfile")],
        Some(OneOrMany::One(f)) => vec![context.join(f)],
        Some(OneOrMany::Many(fs)) => {
            if fs.is_empty() {
                bail!("build.dockerfile: empty list");
            }
            fs.into_iter().map(|f| context.join(f)).collect()
        }
    };
    let build_contexts = spec
        .additional_contexts
        .map(Env::into_pairs)
        .unwrap_or_default()
        .into_iter()
        .map(|(name, value)| {
            // A nameless context is unreachable — no `COPY --from=` can spell it — so the
            // `COPY` it was meant for would resolve as an image ref and fail inside the build.
            if name.is_empty() {
                bail!("build.additional_contexts: an entry needs a name ({value:?})");
            }
            // Only a directory is a context here: compose's remote forms would silently be
            // taken for a relative path and fail deep inside the build instead.
            if value.contains("://")
                || ["service:", "target:", "docker-image:", "oci-layout:"]
                    .iter()
                    .any(|p| value.starts_with(p))
            {
                bail!(
                    "build.additional_contexts {name}: only a directory is supported, got {value:?}"
                );
            }
            if value.is_empty() {
                bail!("build.additional_contexts {name}: empty directory");
            }
            Ok((name, base.join(value)))
        })
        .collect::<Result<Vec<_>>>()?;
    // The list form can name one context twice, where the map form cannot. Caught here so it
    // reports in compose's own vocabulary rather than as a bare build-context clash later.
    for (i, (name, _)) in build_contexts.iter().enumerate() {
        if build_contexts[..i].iter().any(|(seen, _)| seen == name) {
            bail!("build.additional_contexts {name}: declared more than once");
        }
    }
    Ok(Source::Build {
        dockerfiles,
        context,
        build_contexts,
        target: spec.target,
        args: spec.args.map(Env::into_pairs).unwrap_or_default(),
    })
}

/// A bind-mount `host:guest[:ro|rw|overlay|disk[,size=SIZE]]`. A source that is not a path (a
/// compose named volume) is rejected — there is no volume manager here. Public: `run -v/--volume`
/// parses the same syntax, anchored at the caller's cwd instead of the compose
/// file's directory.
pub fn parse_volume(spec: &str, base: &Path) -> Result<Volume> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (host, guest, mode_field) = match parts.as_slice() {
        [h, g] => (*h, *g, "rw"),
        [h, g, m] => (*h, *g, *m),
        _ => bail!("bad volume {spec:?} (want host:guest[:ro|:rw|:overlay|:disk[,size=SIZE]])"),
    };
    if !(host.starts_with('/') || host.starts_with('.') || host.starts_with('~')) {
        bail!("volume {spec:?}: named volumes are not supported (bind-mount a path)");
    }
    if host.starts_with('~') {
        bail!("volume {spec:?}: ~ expansion is not supported (use an absolute path)");
    }
    // The mode field is a keyword plus optional comma `key=value` refinements — mirroring
    // `docker run --mount`'s style for the one case (disk's `size=`) where a bare flag isn't
    // enough. `overlay` exports the share read-only and mounts it as an overlayfs lower layer
    // guest-side (writes go to a guest tmpfs, never back to the host tree). `disk` skips
    // virtiofs entirely — see [`Volume::disk`].
    let mut mode_parts = mode_field.split(',');
    let mode = mode_parts.next().unwrap_or("rw");
    let (read_only, overlay, disk) = match mode {
        "ro" => (true, false, false),
        "rw" => (false, false, false),
        "overlay" => (true, true, false),
        // No `disk,ro` yet — a disk volume is always attached read-write.
        "disk" => (false, false, true),
        other => {
            bail!("volume {spec:?}: unsupported mode {other:?} (want ro, rw, overlay or disk)")
        }
    };
    let mut disk_size_mib = None;
    for opt in mode_parts {
        if !disk {
            bail!("volume {spec:?}: {opt:?} is only valid with disk mode");
        }
        let size = opt.strip_prefix("size=").with_context(|| {
            format!("volume {spec:?}: unknown disk option {opt:?} (want size=SIZE)")
        })?;
        if disk_size_mib.is_some() {
            bail!("volume {spec:?}: size= given more than once");
        }
        disk_size_mib = Some(crate::run::parse_mem_mib(size).with_context(|| {
            format!("volume {spec:?}: bad disk size {size:?} (want e.g. 10G, 512M)")
        })?);
    }
    if !guest.starts_with('/') {
        bail!("volume {spec:?}: the guest path must be absolute");
    }
    let host = base.join(host);
    // A single-file bind when the source resolves to a regular file (a missing/dir source
    // stays a directory share, the prior behavior). A disk volume's host path is its own
    // backing file, not a single-file bind — never virtiofs-shared, so this stays false even
    // once a previous boot's file is sitting there.
    let is_file = !disk
        && std::fs::metadata(&host)
            .map(|m| m.is_file())
            .unwrap_or(false);
    if overlay && is_file {
        bail!("volume {spec:?}: overlay mode needs a directory source, not a single file");
    }
    if disk && std::fs::metadata(&host).is_ok_and(|m| m.is_dir()) {
        bail!("volume {spec:?}: disk mode needs a file source (or none yet), not a directory");
    }
    Ok(Volume {
        host,
        guest: guest.to_string(),
        read_only,
        overlay,
        is_file,
        disk,
        disk_size_mib,
    })
}

/// Formatted capacity for a fresh `disk` volume with no explicit `size=` — generous because it
/// is sparse (real host disk cost is only what gets written): double
/// `run::SCRATCH_DISK_FREE_BLOCKS`'s 32 GiB, since a `disk` volume's content is meant to
/// survive indefinitely rather than get discarded after one build.
const DEFAULT_DISK_VOLUME_MIB: u64 = 65536; // 64 GiB

/// Resolve a `disk` volume's backing file, creating and formatting it if this is the first
/// use. An existing file is trusted as-is — whatever ext4 a previous boot left there — so the
/// volume's content survives across runs; only a missing file gets sized (from
/// `disk_size_mib`, else [`DEFAULT_DISK_VOLUME_MIB`]) and formatted. No-op, and no-ops safely,
/// on a non-`disk` volume.
///
/// Built into a same-directory temp file first, then published with a hard link — which
/// fails with `AlreadyExists` rather than silently overwriting a file a racing boot already
/// published — instead of writing `vol.host` directly, so a crash mid-format can never leave
/// a half-written file behind for a later boot to wrongly trust as-is. The temp file is opened
/// `0600` at creation (`create_new`, so it also can't follow a pre-planted symlink at the temp
/// path) rather than chmod'd after the fact, since the volume may end up holding whatever a
/// service stores in it (e.g. a database's data directory); `ext4::build_empty`'s own
/// `File::create` on that same path only truncates and rewrites it, leaving the mode as-is.
pub fn ensure_disk_backing(vol: &Volume) -> Result<()> {
    if !vol.disk || vol.host.exists() {
        return Ok(());
    }
    let parent = vol
        .host
        .parent()
        .with_context(|| format!("disk volume {}: no parent directory", vol.host.display()))?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let mib = vol.disk_size_mib.unwrap_or(DEFAULT_DISK_VOLUME_MIB);
    // ext4.rs's writer works in fixed 4 KiB blocks.
    let free_blocks = mib
        .checked_mul(1024 * 1024 / 4096)
        .with_context(|| format!("disk volume {}: size={mib}M overflows", vol.host.display()))?;

    let file_name = vol
        .host
        .file_name()
        .and_then(|n| n.to_str())
        .with_context(|| format!("disk volume {}: bad file name", vol.host.display()))?;
    let tmp = parent.join(format!(".{file_name}.vk-disk-tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let publish = (|| -> Result<()> {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        crate::ext4::build_empty(&tmp, free_blocks)
            .with_context(|| format!("formatting disk volume {}", vol.host.display()))?;
        match std::fs::hard_link(&tmp, &vol.host) {
            Ok(()) => Ok(()),
            // A racing boot published it first; its file is as good as ours would have been.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => {
                Err(e).with_context(|| format!("publishing disk volume {}", vol.host.display()))
            }
        }
    })();
    let _ = std::fs::remove_file(&tmp);
    publish
}

/// Parse a `--symlink SRC:DST` spec: two absolute guest paths, split at the first
/// colon (matching the agent's VIRTKIT_SYMLINKS parser, so a `:` in DST is fine).
/// The spec rides the kernel cmdline, where ',' and whitespace are separators —
/// paths containing them are rejected rather than silently corrupting the format.
pub fn parse_symlink(spec: &str) -> Result<(String, String)> {
    match spec.split_once(':') {
        Some((src, dst))
            if src.starts_with('/')
                && dst.starts_with('/')
                && !spec.contains(',')
                && !spec.chars().any(char::is_whitespace) =>
        {
            Ok((src.to_string(), dst.to_string()))
        }
        _ => bail!(
            "bad --symlink {spec:?} (want absolute SRC:DST guest paths; \
             ',' and whitespace are cmdline separators)"
        ),
    }
}

/// Split a compose string-form command into argv, shell-words style (like compose,
/// without running a shell): single/double quotes group words, and a backslash
/// escapes the next character — except inside single quotes, where it is literal.
fn shell_words(s: &str) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    let mut escaped = false;
    for c in s.chars() {
        if escaped {
            cur.push(c);
            started = true;
            escaped = false;
            continue;
        }
        match (quote, c) {
            // backslash escapes the next char outside quotes and inside double
            // quotes; single quotes keep it literal (handled by the arm below).
            (None, '\\') | (Some('"'), '\\') => {
                escaped = true;
                started = true;
            }
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            (None, c) => {
                cur.push(c);
                started = true;
            }
        }
    }
    if quote.is_some() {
        bail!("unterminated quote in {s:?}");
    }
    if escaped {
        bail!("dangling backslash in {s:?}");
    }
    if started {
        out.push(cur);
    }
    Ok(out)
}

// ---- raw compose shapes (serde; unknown keys are hard errors) ----

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeFile {
    /// accepted and ignored: the compose spec deprecates it
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<String>,
    #[serde(default)]
    services: BTreeMap<String, ComposeService>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ComposeService {
    image: Option<String>,
    build: Option<serde_yaml_ng::Value>,
    environment: Option<Env>,
    command: Option<Cmd>,
    entrypoint: Option<Cmd>,
    user: Option<String>,
    hostname: Option<String>,
    depends_on: Option<DependsOn>,
    #[serde(default)]
    volumes: Vec<String>,
    #[serde(default)]
    profiles: Vec<String>,
    /// vk extension: per-service init/kernel axes (compose `x-*` extension key).
    /// Only `x-virtkit` is recognized; any other `x-*` key still errors like any
    /// unsupported key (deny_unknown_fields), matching the strict-parse contract.
    #[serde(rename = "x-virtkit", default)]
    x_virtkit: Option<XVirtkit>,
}

/// The `x-virtkit` per-service marker: the init/kernel axes as compose strings,
/// parsed into [`crate::run::InitSource`] / [`crate::run::KernelSource`], plus the
/// guest sizing (`cpus`/`mem`) and nested virtualization (`nested`). An absent
/// subkey defaults to `Default`/unset/off.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct XVirtkit {
    #[serde(default)]
    init: Option<String>,
    #[serde(default)]
    kernel: Option<String>,
    /// scalar, not u32: a `${VAR}` reference interpolates into a YAML string
    #[serde(default)]
    cpus: Option<Scalar>,
    #[serde(default)]
    mem: Option<Scalar>,
    /// scalar, not bool: `nested: true` is a YAML bool but `${VAR}` interpolates
    /// into a string, and both spellings must reach the same parse
    #[serde(default)]
    nested: Option<Scalar>,
}

impl XVirtkit {
    /// `init: default|image|entrypoint` → [`crate::run::InitSource`] (absent = Default).
    fn init(&self) -> Result<crate::run::InitSource> {
        match self.init.as_deref() {
            None | Some("default") => Ok(crate::run::InitSource::Default),
            Some("image") => Ok(crate::run::InitSource::Image),
            Some("entrypoint") => Ok(crate::run::InitSource::Entrypoint),
            Some(other) => {
                bail!(
                    "x-virtkit.init: expected \"default\", \"image\" or \"entrypoint\", \
                     got {other:?}"
                )
            }
        }
    }

    /// `kernel: default|image|<path>` → [`crate::run::KernelSource`] (absent =
    /// Default; a non-keyword string is a kernel file path).
    fn kernel(&self) -> Result<crate::run::KernelSource> {
        Ok(match self.kernel.as_deref() {
            None => crate::run::KernelSource::Default,
            // Infallible parser: "default"/"image" map to those variants, else a Path.
            Some(s) => crate::run::KernelSource::parse(s).unwrap(),
        })
    }

    /// `cpus: <n>` → the guest vCPU count (absent = the consumer's default).
    fn cpus(&self) -> Result<Option<u32>> {
        self.cpus
            .clone()
            .map(|c| {
                let s = c.into_string();
                s.parse::<u32>().ok().filter(|n| *n > 0).with_context(|| {
                    format!("x-virtkit.cpus: expected a positive count, got {s:?}")
                })
            })
            .transpose()
    }

    /// `mem: <n>G|<n>M|<MiB>` → the guest RAM size (absent = the consumer's default).
    /// Validated here so a typo fails the compose load, not a later boot.
    fn mem(&self) -> Result<Option<String>> {
        self.mem
            .clone()
            .map(|m| {
                let s = m.into_string();
                crate::run::parse_mem_mib(&s)
                    .filter(|mib| *mib > 0)
                    .with_context(|| {
                        format!("x-virtkit.mem: expected a non-zero <n>G, <n>M or MiB, got {s:?}")
                    })?;
                Ok(s)
            })
            .transpose()
    }

    /// `nested: true|false` → whether the guest can run microVMs of its own
    /// (absent = off). The host must allow nesting; that is checked at boot, where
    /// the same failure reaches a `vk run --nested` guest.
    fn nested(&self) -> Result<bool> {
        match self.nested.clone().map(Scalar::into_string) {
            None => Ok(false),
            // `True`/`TRUE` are YAML bools that already normalise to "true" on the literal
            // path, so fold case for the `${VAR}` and quoted spellings to accept the same
            // set. `yes`, `on` and `1` stay rejected: YAML 1.2 reads none of them as bools.
            Some(s) => match s.to_ascii_lowercase().as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => bail!("x-virtkit.nested: expected true or false, got {s:?}"),
            },
        }
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BuildSpec {
    context: Option<PathBuf>,
    dockerfile: Option<OneOrMany>,
    target: Option<String>,
    args: Option<Env>,
    /// compose `additional_contexts`: `name: dir` map or `name=dir` list. Only directories
    /// are supported (not compose's `docker-image://` / `oci-layout://` / `service:` forms).
    additional_contexts: Option<Env>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(PathBuf),
    Many(Vec<PathBuf>),
}

/// compose environment/args: a `KEY: value` map or a `KEY=value` list; scalar
/// values (numbers, bools) stringify like compose does.
#[derive(Deserialize)]
#[serde(untagged)]
enum Env {
    Map(BTreeMap<String, Scalar>),
    List(Vec<String>),
}

impl Env {
    fn into_pairs(self) -> Vec<(String, String)> {
        match self {
            Env::Map(m) => m.into_iter().map(|(k, v)| (k, v.into_string())).collect(),
            Env::List(l) => l
                .into_iter()
                .map(|e| match e.split_once('=') {
                    Some((k, v)) => (k.to_string(), v.to_string()),
                    None => (e, String::new()),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(untagged)]
enum Scalar {
    Str(String),
    Num(serde_yaml_ng::Number),
    Bool(bool),
    Null,
}

impl Scalar {
    fn into_string(self) -> String {
        match self {
            Scalar::Str(s) => s,
            Scalar::Num(n) => n.to_string(),
            Scalar::Bool(b) => b.to_string(),
            // compose reads a null-valued key (`KEY:`) from the host environment;
            // a hermetic guest has no host env to inherit, so it maps to empty.
            Scalar::Null => String::new(),
        }
    }
}

/// compose command/entrypoint: an argv list, or a string split shell-words style.
#[derive(Deserialize)]
#[serde(untagged)]
enum Cmd {
    List(Vec<String>),
    Str(String),
}

impl Cmd {
    fn into_argv(self) -> Result<Vec<String>> {
        match self {
            Cmd::List(v) => Ok(v),
            Cmd::Str(s) => shell_words(&s),
        }
    }
}

/// compose depends_on: a name list, or a map with per-dependency conditions —
/// only start-ordering is supported, so `service_started` (the default) passes
/// and anything else (e.g. `service_healthy`) errors.
#[derive(Deserialize)]
#[serde(untagged)]
enum DependsOn {
    List(Vec<String>),
    Map(BTreeMap<String, DependsCondition>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DependsCondition {
    condition: Option<String>,
}

impl DependsOn {
    fn into_names(self) -> Vec<String> {
        match self {
            DependsOn::List(l) => l,
            DependsOn::Map(m) => m.into_keys().collect(),
        }
    }

    fn validate(&self) -> Result<()> {
        if let DependsOn::Map(m) = self {
            for (name, c) in m {
                match c.condition.as_deref() {
                    None | Some("service_started") => {}
                    Some(other) => bail!(
                        "depends_on {name:?}: condition {other:?} is not supported \
                         (start ordering only)"
                    ),
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    // Most tests need no interpolation: shadow `parse` with a no-vars variant so
    // the call sites stay two-arg. Tests exercising `${VAR}` call `super::parse`
    // with a real resolver.
    fn parse(yaml: &str, base: &Path) -> Result<Vec<Unit>> {
        super::parse(yaml, base, &|_| None, None)
    }

    // As `parse`: the builtin-less form, so only the tests that exercise `${VK_*}` name
    // a `Builtins`.
    fn interpolate(text: &str, resolve: &dyn Fn(&str) -> Option<String>) -> Result<String> {
        super::interpolate(text, resolve, None)
    }

    fn one(yaml: &str) -> Unit {
        parse(yaml, Path::new("/base")).unwrap().pop().unwrap()
    }

    #[test]
    fn image_service_with_overrides() {
        let u = one(
            "services:\n  redis:\n    image: redis:7\n    environment:\n      PORT: 6380\n\
             \x20     FLAG: true\n    command: redis-server --port 6380\n    user: redis\n",
        );
        assert!(matches!(&u.source, Source::Image(i) if i == "redis:7"));
        assert_eq!(u.hostname, "redis");
        assert_eq!(
            u.environment,
            [
                ("FLAG".to_string(), "true".to_string()),
                ("PORT".to_string(), "6380".to_string())
            ]
        );
        assert_eq!(
            u.command.as_deref().unwrap(),
            ["redis-server", "--port", "6380"]
        );
        assert_eq!(u.user.as_deref(), Some("redis"));
    }

    #[test]
    fn build_service_paths_anchor_on_the_compose_dir() {
        // shorthand: build: <dir>
        let u = one("services:\n  app:\n    build: ./app\n");
        match &u.source {
            Source::Build {
                dockerfiles,
                context,
                target,
                ..
            } => {
                assert_eq!(context, &PathBuf::from("/base/./app"));
                assert_eq!(dockerfiles, &[PathBuf::from("/base/./app/Dockerfile")]);
                assert!(target.is_none());
            }
            _ => panic!("expected a build source"),
        }
        // mapping form with the vk list extension + target + args
        let u = one(
            "services:\n  app:\n    build:\n      context: .\n      dockerfile:\n\
             \x20       - base.Dockerfile\n        - app.Dockerfile\n      target: app\n\
             \x20     args:\n        ver: 9\n",
        );
        match &u.source {
            Source::Build {
                dockerfiles,
                target,
                args,
                ..
            } => {
                assert_eq!(dockerfiles.len(), 2);
                assert_eq!(dockerfiles[1], PathBuf::from("/base/./app.Dockerfile"));
                assert_eq!(target.as_deref(), Some("app"));
                assert_eq!(args, &[("ver".to_string(), "9".to_string())]);
            }
            _ => panic!("expected a build source"),
        }
    }

    #[test]
    fn additional_contexts_parse_in_both_forms_and_anchor_on_the_compose_dir() {
        let contexts_of = |yaml: &str| match &one(yaml).source {
            Source::Build { build_contexts, .. } => build_contexts.clone(),
            _ => panic!("expected a build source"),
        };
        // map form (`name: dir`), the compose spelling
        assert_eq!(
            contexts_of(
                "services:\n  app:\n    build:\n      context: docker/dev\n\
                 \x20     additional_contexts:\n        shared: shared\n"
            ),
            vec![("shared".to_string(), PathBuf::from("/base/shared"))]
        );
        // list form (`name=dir`), like build args
        assert_eq!(
            contexts_of(
                "services:\n  app:\n    build:\n      context: .\n\
                 \x20     additional_contexts:\n        - shared=shared\n        - tools=ci/tools\n"
            ),
            vec![
                ("shared".to_string(), PathBuf::from("/base/shared")),
                ("tools".to_string(), PathBuf::from("/base/ci/tools")),
            ]
        );
        // absent = none
        assert!(contexts_of("services:\n  app:\n    build: .\n").is_empty());
        // compose's remote forms are refused rather than taken for a relative directory
        for value in [
            "docker-image://alpine",
            "oci-layout:///l",
            "service:other",
            "target:other",
        ] {
            let err = parse(
                &format!(
                    "services:\n  app:\n    build:\n      context: .\n\
                     \x20     additional_contexts:\n        x: {value}\n"
                ),
                Path::new("/base"),
            )
            .unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains("only a directory is supported"), "{msg}");
        }
        // A half-written entry names no directory, or nothing at all — both would otherwise
        // register a context that no `COPY --from=` could ever reach.
        for (entry, want) in [
            ("        x:\n", "empty directory"),
            ("        - shared\n", "empty directory"),
            ("        - =shared\n", "needs a name"),
            ("        - x=a\n        - x=b\n", "declared more than once"),
        ] {
            let err = parse(
                &format!(
                    "services:\n  app:\n    build:\n      context: .\n\
                     \x20     additional_contexts:\n{entry}"
                ),
                Path::new("/base"),
            )
            .unwrap_err();
            let msg = format!("{err:#}");
            assert!(msg.contains(want), "{entry:?} -> {msg}");
        }
    }

    #[test]
    fn unsupported_keys_error_naming_the_key() {
        let err = parse(
            "services:\n  web:\n    image: x\n    restart: always\n",
            Path::new("/b"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("restart"), "{err:#}");
        let err = parse(
            "services:\n  web:\n    build:\n      context: .\n      cache_from: [a]\n",
            Path::new("/b"),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("cache_from"), "{err:#}");
    }

    #[test]
    fn source_is_image_xor_build() {
        let both = "services:\n  x:\n    image: a\n    build: .\n";
        assert!(parse(both, Path::new("/b")).is_err());
        let neither = "services:\n  x:\n    user: root\n";
        assert!(parse(neither, Path::new("/b")).is_err());
    }

    #[test]
    fn volumes_are_bind_mounts_only() {
        let u = one("services:\n  s:\n    image: x\n    volumes:\n      - ./data:/data:ro\n");
        assert_eq!(u.volumes[0].host, PathBuf::from("/base/./data"));
        assert_eq!(u.volumes[0].guest, "/data");
        assert!(u.volumes[0].read_only);
        let named = "services:\n  s:\n    image: x\n    volumes:\n      - dbdata:/var/lib\n";
        let err = parse(named, Path::new("/b")).unwrap_err();
        assert!(format!("{err:#}").contains("named volumes"), "{err:#}");
    }

    #[test]
    fn volume_modes_ro_rw_overlay() {
        let rw = parse_volume("/src:/dst", Path::new("/b")).unwrap();
        assert!(!rw.read_only && !rw.overlay);
        let ro = parse_volume("/src:/dst:ro", Path::new("/b")).unwrap();
        assert!(ro.read_only && !ro.overlay);
        // overlay implies a read-only share plus the guest-side overlay flag.
        let ov = parse_volume("/src:/dst:overlay", Path::new("/b")).unwrap();
        assert!(ov.read_only && ov.overlay);
        let bad = parse_volume("/src:/dst:rox", Path::new("/b")).unwrap_err();
        assert!(format!("{bad:#}").contains("unsupported mode"), "{bad:#}");
    }

    #[test]
    fn volume_mode_disk() {
        // A bare `disk`: read-write, no overlay/is_file, no explicit size.
        let d = parse_volume("/data.ext4:/var/wab:disk", Path::new("/b")).unwrap();
        assert!(d.disk && !d.read_only && !d.overlay && !d.is_file);
        assert_eq!(d.disk_size_mib, None);

        // `size=` is a comma refinement of the mode, parsed the same way `--mem` is.
        let sized = parse_volume("/data.ext4:/var/wab:disk,size=10G", Path::new("/b")).unwrap();
        assert!(sized.disk);
        assert_eq!(sized.disk_size_mib, Some(10 * 1024));

        // `size=` only makes sense alongside `disk`.
        let err = parse_volume("/src:/dst:ro,size=10G", Path::new("/b")).unwrap_err();
        assert!(
            format!("{err:#}").contains("only valid with disk mode"),
            "{err:#}"
        );

        // An unrecognized disk option is rejected rather than silently ignored.
        let err = parse_volume("/data.ext4:/var/wab:disk,bogus=1", Path::new("/b")).unwrap_err();
        assert!(
            format!("{err:#}").contains("unknown disk option"),
            "{err:#}"
        );

        // A repeated `size=` is rejected rather than letting the last one silently win.
        let err =
            parse_volume("/data.ext4:/var/wab:disk,size=1G,size=2G", Path::new("/b")).unwrap_err();
        assert!(
            format!("{err:#}").contains("size= given more than once"),
            "{err:#}"
        );

        // A directory source makes no sense for a disk's backing file.
        let tmp = std::env::temp_dir().join(format!("vk-compose-diskdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let err =
            parse_volume(&format!("{}:/var/wab:disk", tmp.display()), Path::new("/b")).unwrap_err();
        assert!(format!("{err:#}").contains("not a directory"), "{err:#}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn ensure_disk_backing_creates_once_and_reuses() {
        let dir = std::env::temp_dir().join(format!("vk-compose-diskfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let host = dir.join("nested/data.ext4");

        let vol = parse_volume(
            &format!("{}:/var/wab:disk", host.display()),
            Path::new("/b"),
        )
        .unwrap();
        assert!(!vol.host.exists(), "backing file must not exist yet");
        ensure_disk_backing(&vol).unwrap();
        assert!(vol.host.is_file(), "first call creates the backing file");
        let created_len = std::fs::metadata(&vol.host).unwrap().len();
        assert_eq!(
            std::fs::metadata(&vol.host).unwrap().permissions().mode() & 0o777,
            0o600,
            "a fresh backing file must not be group/other accessible"
        );
        assert!(
            std::fs::read_dir(dir.join("nested"))
                .unwrap()
                .filter_map(|e| e.ok())
                .all(|e| !e.file_name().to_string_lossy().contains("vk-disk-tmp")),
            "the publish temp file must not be left behind"
        );

        // A second call (a later boot) must not reformat: write a marker byte and confirm it
        // survives, which a reformat would wipe.
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .open(&vol.host)
                .unwrap();
            f.write_all(b"\xAB").unwrap();
        }
        ensure_disk_backing(&vol).unwrap();
        let mut marker = [0u8; 1];
        {
            use std::io::Read;
            std::fs::File::open(&vol.host)
                .unwrap()
                .read_exact(&mut marker)
                .unwrap();
        }
        assert_eq!(
            marker[0], 0xAB,
            "an existing backing file must be reused as-is"
        );
        assert_eq!(
            std::fs::metadata(&vol.host).unwrap().len(),
            created_len,
            "reusing must not resize"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_specs_are_absolute_and_cmdline_safe() {
        // happy path
        assert_eq!(
            parse_symlink("/host/file:/etc/creds").unwrap(),
            ("/host/file".to_string(), "/etc/creds".to_string())
        );
        // a DST containing ':' round-trips via the first-colon split
        assert_eq!(
            parse_symlink("/a:/weird:name").unwrap(),
            ("/a".to_string(), "/weird:name".to_string())
        );
        // relative SRC, missing colon, and cmdline separators are rejected
        assert!(parse_symlink("rel:/dst").is_err());
        assert!(parse_symlink("/no-colon").is_err());
        assert!(parse_symlink("/a,b:/c").is_err());
        assert!(parse_symlink("/a b:/c").is_err());
    }

    #[test]
    fn depends_on_orders_and_rejects_health_conditions() {
        let units = parse(
            "services:\n  a:\n    image: x\n    depends_on: [b]\n  b:\n    image: y\n",
            Path::new("/b"),
        )
        .unwrap();
        let order = boot_order(&units).unwrap();
        let pos = |n: &str| order.iter().position(|&i| units[i].name == n).unwrap();
        assert!(pos("b") < pos("a"));
        // unknown dep + cycle
        let unknown = parse(
            "services:\n  a:\n    image: x\n    depends_on: [nope]\n",
            Path::new("/b"),
        )
        .unwrap();
        assert!(boot_order(&unknown).is_err());
        let cycle = parse(
            "services:\n  a:\n    image: x\n    depends_on: [b]\n  b:\n    image: y\n    depends_on: [a]\n",
            Path::new("/b"),
        )
        .unwrap();
        assert!(boot_order(&cycle).is_err());
        // condition map: started ok, healthy rejected
        let healthy = "services:\n  a:\n    image: x\n    depends_on:\n      b:\n        condition: service_healthy\n  b:\n    image: y\n";
        let err = parse(healthy, Path::new("/b")).unwrap_err();
        assert!(format!("{err:#}").contains("service_healthy"), "{err:#}");
    }

    #[test]
    fn profiles_gate_the_start_set() {
        let units = parse(
            "services:\n\
             \x20 web:\n    image: w\n    depends_on: [db]\n\
             \x20 db:\n    image: d\n    profiles: [full]\n\
             \x20 debug:\n    image: g\n    profiles: [debug]\n",
            Path::new("/b"),
        )
        .unwrap();
        let by = |name: &str| units.iter().position(|u| u.name == name).unwrap();
        // no profile active: web starts, and pulls in db (an enabled service depends
        // on it — compose implicitly enables dependencies); debug stays down.
        let on = enabled(&units, &[]);
        assert!(on[by("web")] && on[by("db")]);
        assert!(!on[by("debug")]);
        // activating the profile brings debug up too.
        let on = enabled(&units, &["debug".to_string()]);
        assert!(on[by("debug")]);
        // a profiled unit nothing depends on and no active profile: everything down.
        let solo = parse(
            "services:\n  x:\n    image: i\n    profiles: [a, b]\n",
            Path::new("/b"),
        )
        .unwrap();
        assert_eq!(enabled(&solo, &[]), [false]);
        assert_eq!(enabled(&solo, &["b".to_string()]), [true]);
    }

    #[test]
    fn dependency_closure_is_transitive_and_excludes_the_root() {
        let units = parse(
            "services:\n\
             \x20 a:\n    image: i\n    depends_on: [b]\n\
             \x20 b:\n    image: i\n    depends_on: [c]\n\
             \x20 c:\n    image: i\n    profiles: [x]\n\
             \x20 d:\n    image: i\n",
            Path::new("/b"),
        )
        .unwrap();
        let by = |n: &str| units.iter().position(|u| u.name == n).unwrap();
        let on = dependency_closure(&units, by("a"));
        // b and c (transitively, despite c's profile) — never a itself, never d.
        assert!(on[by("b")] && on[by("c")]);
        assert!(!on[by("a")] && !on[by("d")]);
        // a leaf has an empty closure.
        assert!(dependency_closure(&units, by("d")).iter().all(|x| !x));
    }

    #[test]
    fn merged_config_layers_compose_overrides() {
        let image = RunConfig {
            env: vec![("PATH".into(), "/bin".into()), ("PORT".into(), "1".into())],
            user: "svc".into(),
            workdir: "/srv".into(),
            entrypoint: vec!["/bin/app".into()],
            cmd: vec!["--serve".into()],
            exposed_ports: vec![5432],
        };
        let mut unit = one("services:\n  s:\n    image: x\n    environment: [PORT=2]\n");
        // env upserts; everything else keeps the image defaults
        let m = merged_config(&image, &unit);
        // the readiness port gate is an image property preserved across the merge
        assert_eq!(m.exposed_ports, [5432]);
        assert_eq!(
            m.env,
            [
                ("PATH".to_string(), "/bin".to_string()),
                ("PORT".to_string(), "2".to_string())
            ]
        );
        assert_eq!(m.argv(), ["/bin/app", "--serve"]);
        assert_eq!((m.user.as_str(), m.workdir.as_str()), ("svc", "/srv"));
        // command alone replaces cmd, keeps entrypoint
        unit.command = Some(vec!["--other".into()]);
        assert_eq!(merged_config(&image, &unit).argv(), ["/bin/app", "--other"]);
        // entrypoint alone replaces entrypoint AND drops the image cmd
        unit.command = None;
        unit.entrypoint = Some(vec!["/bin/sh".into()]);
        assert_eq!(merged_config(&image, &unit).argv(), ["/bin/sh"]);
        // user override
        unit.user = Some("root".into());
        assert_eq!(merged_config(&image, &unit).user, "root");
    }

    #[test]
    fn an_entrypoint_unit_boots_its_compose_override_as_pid_1() {
        // `init: entrypoint` execs the unit's merged argv as PID 1 (see vk-agent's
        // `image_init_candidates`), so a compose override has to reach that argv — the
        // image's own ENTRYPOINT+CMD is only the default underneath it.
        let unit = one(
            "services:\n  s:\n    image: x\n    command: [--config, /etc/app.toml]\n\
             \x20   x-virtkit: { init: entrypoint }\n",
        );
        assert_eq!(unit.init, crate::run::InitSource::Entrypoint);
        let image = RunConfig {
            entrypoint: vec!["/prepare-machine.sh".into()],
            cmd: vec!["/sbin/init".into()],
            workdir: "/srv".into(),
            ..Default::default()
        };
        let cfg = merged_config(&image, &unit);
        assert_eq!(
            cfg.argv(),
            ["/prepare-machine.sh", "--config", "/etc/app.toml"]
        );
        // the entrypoint's cwd, which the agent chdirs to before the exec
        assert_eq!(cfg.workdir, "/srv");
    }

    #[test]
    fn x_virtkit_marker_sets_the_init_kernel_axes() {
        use crate::run::{InitSource, KernelSource};
        // no marker → Default/Default (today's behavior)
        let u = one("services:\n  s:\n    image: x\n");
        assert_eq!(u.init, InitSource::Default);
        assert_eq!(u.kernel, KernelSource::Default);
        // both axes set to image
        let u =
            one("services:\n  s:\n    image: x\n    x-virtkit: { init: image, kernel: image }\n");
        assert_eq!(u.init, InitSource::Image);
        assert_eq!(u.kernel, KernelSource::Image);
        // partial: only init
        let u = one("services:\n  s:\n    image: x\n    x-virtkit: { init: image }\n");
        assert_eq!(u.init, InitSource::Image);
        assert_eq!(u.kernel, KernelSource::Default);
        // partial: only kernel, and a path value → Path
        let u = one("services:\n  s:\n    image: x\n    x-virtkit: { kernel: /boot/vmlinux }\n");
        assert_eq!(u.init, InitSource::Default);
        assert_eq!(u.kernel, KernelSource::Path("/boot/vmlinux".into()));
        // entrypoint: PID 1 is the image's ENTRYPOINT, which may exec the real init
        let u = one("services:\n  s:\n    image: x\n    x-virtkit: { init: entrypoint }\n");
        assert_eq!(u.init, InitSource::Entrypoint);
        assert!(u.init.is_image()); // boots through the preinit handoff, like image
        // explicit "default" is the same as absent
        let u = one(
            "services:\n  s:\n    image: x\n    x-virtkit: { init: default, kernel: default }\n",
        );
        assert_eq!(u.init, InitSource::Default);
        assert_eq!(u.kernel, KernelSource::Default);
        // a bad init value errors naming it; an unknown x-virtkit subkey errors
        assert!(
            parse(
                "services:\n  s:\n    image: x\n    x-virtkit: { init: systemd }\n",
                Path::new("/b")
            )
            .is_err()
        );
        assert!(
            parse(
                "services:\n  s:\n    image: x\n    x-virtkit: { foo: bar }\n",
                Path::new("/b")
            )
            .is_err()
        );
        // an unrelated x-* key is still a hard error (only x-virtkit is recognized)
        assert!(
            parse(
                "services:\n  s:\n    image: x\n    x-bake: {}\n",
                Path::new("/b")
            )
            .is_err()
        );
    }

    #[test]
    fn x_virtkit_sizing_parses_and_validates() {
        // absent = None: the consumer's default sizing applies
        let u = one("services:\n  s:\n    image: x\n");
        assert_eq!((u.cpus, u.mem), (None, None));
        // number and string scalars both work; mem takes G/M/MiB forms
        let u = one("services:\n  s:\n    image: x\n    x-virtkit: { cpus: 4, mem: 512M }\n");
        assert_eq!(u.cpus, Some(4));
        assert_eq!(u.mem.as_deref(), Some("512M"));
        let u = one("services:\n  s:\n    image: x\n    x-virtkit: { cpus: \"8\", mem: 2G }\n");
        assert_eq!((u.cpus, u.mem.as_deref()), (Some(8), Some("2G")));
        // sizing composes with the other axes under one marker
        let u = one("services:\n  s:\n    image: x\n    x-virtkit: { init: image, mem: 2G }\n");
        assert_eq!(u.init, crate::run::InitSource::Image);
        assert_eq!((u.cpus, u.mem.as_deref()), (None, Some("2G")));
        // a ${VAR} reference sizes a service from the environment
        let u = super::parse(
            "services:\n  s:\n    image: x\n    x-virtkit:\n      cpus: ${N}\n      mem: ${M}\n",
            Path::new("/b"),
            &vars(&[("N", "6"), ("M", "3G")]),
            None,
        )
        .unwrap()
        .pop()
        .unwrap();
        assert_eq!((u.cpus, u.mem.as_deref()), (Some(6), Some("3G")));
        // zero and garbage fail the load, not a later boot
        for marker in ["{ cpus: 0 }", "{ cpus: two }", "{ mem: 0 }", "{ mem: big }"] {
            assert!(
                parse(
                    &format!("services:\n  s:\n    image: x\n    x-virtkit: {marker}\n"),
                    Path::new("/b")
                )
                .is_err(),
                "{marker} should be rejected"
            );
        }
    }

    #[test]
    fn x_virtkit_nested_opts_one_service_in() {
        // absent = off: an unmarked service keeps VMX/SVM masked
        assert!(!one("services:\n  s:\n    image: x\n").nested);
        assert!(!one("services:\n  s:\n    image: x\n    x-virtkit: { cpus: 2 }\n").nested);
        // the YAML bool and the ${VAR} string spelling reach the same parse
        assert!(one("services:\n  s:\n    image: x\n    x-virtkit: { nested: true }\n").nested);
        assert!(!one("services:\n  s:\n    image: x\n    x-virtkit: { nested: false }\n").nested);
        // every spelling YAML itself reads as a bool, plus the quoted string form
        assert!(one("services:\n  s:\n    image: x\n    x-virtkit: { nested: True }\n").nested);
        assert!(one("services:\n  s:\n    image: x\n    x-virtkit: { nested: TRUE }\n").nested);
        assert!(one("services:\n  s:\n    image: x\n    x-virtkit: { nested: \"true\" }\n").nested);
        // ${VAR} arrives as a string, so it must accept the same spellings
        for value in ["true", "True"] {
            let u = super::parse(
                "services:\n  s:\n    image: x\n    x-virtkit:\n      nested: ${N}\n",
                Path::new("/b"),
                &vars(&[("N", value)]),
                None,
            )
            .unwrap()
            .pop()
            .unwrap();
            assert!(u.nested, "${{N}}={value:?} should read as nested");
        }
        // a null value is an unset key, not a bad one: `Option` reads it as absent
        assert!(!one("services:\n  s:\n    image: x\n    x-virtkit: { nested: }\n").nested);
        // anything else fails the load, not a later boot
        for marker in ["{ nested: yes }", "{ nested: 1 }", "{ nested: maybe }"] {
            assert!(
                parse(
                    &format!("services:\n  s:\n    image: x\n    x-virtkit: {marker}\n"),
                    Path::new("/b")
                )
                .is_err(),
                "{marker} should be rejected"
            );
        }
    }

    #[test]
    fn shell_words_honors_quotes() {
        assert_eq!(
            shell_words("redis-server '/etc/my conf' --x \"a b\"").unwrap(),
            ["redis-server", "/etc/my conf", "--x", "a b"]
        );
        assert!(shell_words("broken 'quote").is_err());
        assert_eq!(shell_words("  ").unwrap(), Vec::<String>::new());
        // backslash escapes a space outside quotes and a quote inside double quotes;
        // it is literal inside single quotes; a dangling backslash errors.
        assert_eq!(
            shell_words(r#"a\ b "c\"d" 'e\f'"#).unwrap(),
            ["a b", "c\"d", "e\\f"]
        );
        assert!(shell_words(r"trailing\").is_err());
    }

    #[test]
    fn service_names_must_be_dns_safe() {
        assert!(parse("services:\n  My_Svc:\n    image: x\n", Path::new("/b")).is_err());
        // leading/trailing hyphens and over-long names are rejected
        assert!(parse("services:\n  -svc:\n    image: x\n", Path::new("/b")).is_err());
        assert!(parse("services:\n  svc-:\n    image: x\n", Path::new("/b")).is_err());
        assert!(!is_dns_label(&"a".repeat(64)));
        assert!(is_dns_label("web-1"));
    }

    #[test]
    fn hostname_override_must_be_dns_safe() {
        // a valid override is taken verbatim
        assert_eq!(
            one("services:\n  db:\n    image: x\n    hostname: primary-db\n").hostname,
            "primary-db"
        );
        // one that could break out of `--host <name>=<ip>` / the guest cmdline is rejected
        assert!(
            parse(
                "services:\n  db:\n    image: x\n    hostname: bad=host\n",
                Path::new("/b")
            )
            .is_err()
        );
    }

    // A resolver over a fixed set of vars, for the interpolation tests.
    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |name: &str| map.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone())
    }

    #[test]
    fn interpolation_forms() {
        let r = vars(&[("HOST", "/home/x"), ("EMPTY", "")]);
        // braced, bare, and default (used when unset OR empty), plus $$ escape.
        assert_eq!(interpolate("${HOST}/repo", &r).unwrap(), "/home/x/repo");
        assert_eq!(interpolate("$HOST:/g", &r).unwrap(), "/home/x:/g");
        assert_eq!(interpolate("${MISSING:-def}", &r).unwrap(), "def");
        assert_eq!(interpolate("${EMPTY:-def}", &r).unwrap(), "def");
        assert_eq!(interpolate("${HOST:-def}", &r).unwrap(), "/home/x");
        assert_eq!(interpolate("price is $$5", &r).unwrap(), "price is $5");
        // a lone '$' not starting a reference is kept verbatim.
        assert_eq!(interpolate("a $ b", &r).unwrap(), "a $ b");
    }

    #[test]
    fn interpolation_unset_is_hard_error() {
        let r = vars(&[("SET", "1"), ("EMPTY", "")]);
        assert!(interpolate("${MISSING}", &r).is_err());
        assert!(interpolate("$MISSING", &r).is_err());
        // set-but-empty is treated as unset (no default => error)
        assert!(interpolate("${EMPTY}", &r).is_err());
        assert!(interpolate("${UNTERMINATED", &r).is_err());
        // a set var still resolves
        assert_eq!(interpolate("${SET}", &r).unwrap(), "1");
        // unsupported docker modifiers are a bad reference, not silently accepted
        assert!(interpolate("${SET:?err}", &r).is_err());
        assert!(interpolate("${SET:+alt}", &r).is_err());
        assert!(interpolate("${SET-def}", &r).is_err());
    }

    #[test]
    fn interpolation_default_is_literal_not_nested() {
        // a `:-default` is taken verbatim: the inner `${B}` is not re-interpolated,
        // so it ends at the first `}` and the trailing `}` is kept literally.
        let r = vars(&[]);
        assert_eq!(interpolate("${A:-${B}}", &r).unwrap(), "${B}");
    }

    // Use the existing test binary because `${VK_SELF}` refuses missing files.
    fn builtins(workspace: &str, state_dir: Option<&str>) -> Builtins {
        Builtins {
            workspace: PathBuf::from(workspace),
            state_dir: state_dir.map(PathBuf::from),
            vk_self: std::env::current_exe().unwrap(),
            uid: 1000,
            gid: 1001,
        }
    }

    #[test]
    fn builtins_answer_the_reserved_names() {
        let b = builtins("/repo", Some("/state/repo"));
        let r = vars(&[]);
        let go = |t: &str| super::interpolate(t, &r, Some(&b)).unwrap();
        assert_eq!(go("${VK_WORKSPACE}:/workdir"), "/repo:/workdir");
        assert_eq!(go("$VK_STATE_DIR/vscode"), "/state/repo/vscode");
        let me = b.vk_self.to_str().unwrap();
        assert_eq!(
            go("${VK_SELF}:/usr/local/bin/vk:ro"),
            format!("{me}:/usr/local/bin/vk:ro")
        );
        assert_eq!(go("${VK_UID}:${VK_GID}"), "1000:1001");
    }

    #[test]
    fn a_vk_that_is_no_longer_there_is_refused() {
        // A self-update can leave `current_exe` pointing at a path that no longer opens.
        let mut b = builtins("/repo", None);
        b.vk_self = PathBuf::from("/nonexistent/vk (deleted)");
        let err = super::interpolate("${VK_SELF}", &vars(&[]), Some(&b))
            .unwrap_err()
            .to_string();
        assert!(err.contains("was replaced or removed"), "{err}");
    }

    #[test]
    fn the_vk_namespace_never_falls_back_to_the_environment() {
        // Withheld builtins never fall through to a resolver that could expose runner paths.
        let r = vars(&[("VK_WORKSPACE", "/runner/secrets")]);
        assert!(super::interpolate("${VK_WORKSPACE}", &r, None).is_err());
        assert!(super::interpolate("$VK_WORKSPACE", &r, None).is_err());
        // Supplied: the builtin wins over the same name in the environment.
        let b = builtins("/repo", None);
        assert_eq!(
            super::interpolate("${VK_WORKSPACE}", &r, Some(&b)).unwrap(),
            "/repo"
        );
        // Only an exact `VK_` prefix is reserved; the lowercase spelling is an ordinary
        // variable and still comes from the resolver.
        let lower = vars(&[("vk_workspace", "/elsewhere")]);
        assert_eq!(
            super::interpolate("${vk_workspace}", &lower, Some(&b)).unwrap(),
            "/elsewhere"
        );
    }

    #[test]
    fn a_builtin_takes_no_default() {
        // A builtin is supplied or rejected, so a default can never apply.
        let b = builtins("/repo", Some("/state"));
        let r = vars(&[]);
        for text in ["${VK_WORKSPACE:-/fallback}", "${VK_STATE_DIR:-/tmp/x}"] {
            let err = super::interpolate(text, &r, Some(&b))
                .unwrap_err()
                .to_string();
            assert!(err.contains("takes no `:-default`"), "{text}: {err}");
        }
        // The colon-less form is a bad reference wherever it appears, builtin or not.
        assert!(super::interpolate("${VK_WORKSPACE-/x}", &r, Some(&b)).is_err());
    }

    #[test]
    fn the_reserved_prefix_survives_the_lexer_edges() {
        let b = builtins("/repo", Some("/state"));
        let r = vars(&[]);
        let go = |t: &str| super::interpolate(t, &r, Some(&b));
        // `$$` escapes before any name is read, so this is a literal, not a reference.
        assert_eq!(go("$$VK_WORKSPACE").unwrap(), "$VK_WORKSPACE");
        // Unbraced numeric builtins, and one immediately followed by a non-name character.
        assert_eq!(go("$VK_UID:$VK_GID").unwrap(), "1000:1001");
        // A bare prefix is an unknown reserved name, not an empty reference.
        assert!(go("${VK_}").is_err());
        assert!(go("${}").is_err());
        assert!(go("${VK_WORKSPACE").is_err());
    }

    #[test]
    fn an_unknown_reserved_name_is_reported_against_the_builtins() {
        let b = builtins("/repo", Some("/state"));
        let err = super::interpolate("${VK_WORKSPCE}", &vars(&[]), Some(&b))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("VK_WORKSPACE"),
            "should list the builtins: {err}"
        );
    }

    #[test]
    fn a_builtin_path_that_breaks_the_volume_syntax_is_refused() {
        // Volume parsing treats a colon as a field separator and a newline as another bind.
        let r = vars(&[]);
        for bad in ["/re:po", "/re\npo", " /repo", "/repo "] {
            let b = builtins(bad, None);
            assert!(
                super::interpolate("${VK_WORKSPACE}:/workdir", &r, Some(&b)).is_err(),
                "{bad:?} should be refused"
            );
        }
        // Interior whitespace survives a volume entry intact, so it stays allowed.
        let b = builtins("/re po", None);
        assert_eq!(
            super::interpolate("${VK_WORKSPACE}:/workdir", &r, Some(&b)).unwrap(),
            "/re po:/workdir"
        );
    }

    #[test]
    fn a_state_dir_reference_needs_a_run_to_have_one() {
        // A prebuild without --state-dir must not invent a path that differs from the boot.
        let b = builtins("/repo", None);
        let err = super::interpolate("${VK_STATE_DIR}", &vars(&[]), Some(&b))
            .unwrap_err()
            .to_string();
        assert!(err.contains("--state-dir"), "should name the flag: {err}");
    }

    // Removes its directory on drop, so a panicking assertion cannot leak it.
    struct TmpDir(PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    #[test]
    fn dotenv_parsing() {
        let dir = std::env::temp_dir().join(format!("vk-dotenv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _guard = TmpDir(dir.clone());
        std::fs::write(
            dir.join(".env"),
            "# a comment\n\nexport A=1\nB = two words\nC=\nD='quoted'\n",
        )
        .unwrap();
        let v = load_dotenv(&dir).unwrap();
        assert_eq!(v.iter().find(|(k, _)| k == "A").unwrap().1, "1");
        // value is taken raw after the first '='; key is trimmed, `export ` stripped
        assert_eq!(v.iter().find(|(k, _)| k == "B").unwrap().1, " two words");
        assert_eq!(v.iter().find(|(k, _)| k == "C").unwrap().1, "");
        // one matching pair of quotes is stripped (crate::strip_env_quotes)
        assert_eq!(v.iter().find(|(k, _)| k == "D").unwrap().1, "quoted");
        // a missing .env is empty, not an error
        assert!(load_dotenv(Path::new("/no/such/dir")).unwrap().is_empty());
    }

    #[test]
    fn interpolation_covers_all_fields() {
        let r = vars(&[
            ("IMG", "redis:7"),
            ("H", "srv"),
            ("WHO", "redis"),
            ("PORT", "6390"),
        ]);
        let u = super::parse(
            "services:\n  redis:\n    image: ${IMG}\n    hostname: ${H}\n    user: ${WHO}\n\
             \x20   environment:\n      PORT: ${PORT}\n    command: redis-server --port ${PORT}\n",
            Path::new("/base"),
            &r,
            None,
        )
        .unwrap()
        .pop()
        .unwrap();
        assert!(matches!(&u.source, Source::Image(i) if i == "redis:7"));
        assert_eq!(u.hostname, "srv");
        assert_eq!(u.user.as_deref(), Some("redis"));
        assert_eq!(u.environment, [("PORT".to_string(), "6390".to_string())]);
        assert_eq!(u.command.unwrap(), ["redis-server", "--port", "6390"]);
    }

    #[test]
    fn volume_list_injected_from_one_variable() {
        let yaml = "services:\n  dev:\n    image: x\n    volumes:\n\
                    \x20     - ${WABDIR}:/workdir\n      - ${EXTRA:-}\n";
        // EXTRA expands to two newline-separated specs → one entry becomes two binds.
        let r = vars(&[("WABDIR", "/repo"), ("EXTRA", "/a:/x\n/b:/y:ro")]);
        let u = super::parse(yaml, Path::new("/base"), &r, None)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(u.volumes.len(), 3);
        assert_eq!(u.volumes[0].guest, "/workdir");
        assert_eq!(u.volumes[1].host, Path::new("/a"));
        assert_eq!(u.volumes[2].guest, "/y");
        assert!(u.volumes[2].read_only);

        // an unset list variable (via :-) contributes zero binds, not an error.
        let r2 = vars(&[("WABDIR", "/repo")]);
        let u2 = super::parse(yaml, Path::new("/base"), &r2, None)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(u2.volumes.len(), 1);
    }

    #[test]
    fn load_with_env_uses_the_supplied_resolver_over_dotenv() {
        // The executor passes a resolver restricted to job variables; `load_with_env` must
        // interpolate from it (layered over the sibling `.env`, ambient winning) rather than
        // the process environment.
        let dir = std::env::temp_dir().join(format!("vk-loadenv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("compose.yml"),
            "services:\n  app:\n    image: ${AMBIENT}/img:${FROM_DOTENV}\n",
        )
        .unwrap();
        std::fs::write(dir.join(".env"), "FROM_DOTENV=v1\nAMBIENT=dotenv-loses\n").unwrap();

        let ambient = |name: &str| (name == "AMBIENT").then(|| "reg".to_string());
        let units = load_with_env(&dir.join("compose.yml"), &ambient, None).unwrap();
        match &units[0].source {
            // AMBIENT came from the resolver (winning over .env), FROM_DOTENV from .env.
            Source::Image(img) => assert_eq!(img, "reg/img:v1"),
            other => panic!("expected an image source, got {other:?}"),
        }

        // A variable the resolver does not provide and `.env` lacks is a hard error — it is
        // NOT silently pulled from the process environment.
        std::fs::write(
            dir.join("compose.yml"),
            "services:\n  app:\n    image: img:${PATH}\n",
        )
        .unwrap();
        assert!(load_with_env(&dir.join("compose.yml"), &|_| None, None).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_reserved_name_defined_outside_is_refused() {
        let dir = std::env::temp_dir().join(format!("vk-reserved-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _guard = TmpDir(dir.clone());
        let file = dir.join("compose.yml");
        std::fs::write(
            &file,
            "services:\n  app:\n    image: x\n    volumes:\n      - ${VK_WORKSPACE}:/workdir\n",
        )
        .unwrap();
        let b = builtins("/repo", None);

        // Baseline: the builtin alone resolves the file.
        let units = load_with_env(&file, &|_| None, Some(&b)).unwrap();
        assert_eq!(units[0].volumes[0].host, Path::new("/repo"));

        // Where the builtins are supplied, defining the same name outside is a hard error
        // rather than one of the two values silently winning: from the environment …
        let ambient = |name: &str| (name == "VK_WORKSPACE").then(|| "/elsewhere".to_string());
        assert!(load_with_env(&file, &ambient, Some(&b)).is_err());

        // … and from the sibling .env.
        std::fs::write(dir.join(".env"), "VK_STATE_DIR=/elsewhere\n").unwrap();
        let err = load_with_env(&file, &|_| None, Some(&b))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(".env"),
            "should name where it came from: {err}"
        );

        // Withheld builtins cannot collide, so an unused definition remains valid.
        let plain = dir.join("plain.yml");
        std::fs::write(&plain, "services:\n  app:\n    image: x\n").unwrap();
        assert!(load_with_env(&plain, &ambient, None).is_ok());

        // Definitions reserve only builtin names, not the entire `VK_` prefix.
        std::fs::write(dir.join(".env"), "VK_DEV_CPUS=4\n").unwrap();
        assert!(load_with_env(&plain, &|_| None, Some(&b)).is_ok());
    }

    #[test]
    fn resolve_rejects_a_workspace_that_is_not_a_directory() {
        let err = Builtins::resolve(Some(Path::new("/nonexistent/tree")), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a directory"), "{err}");
    }

    #[test]
    fn a_path_resolves_the_same_before_and_after_it_exists() {
        // Build resolves the path before creation and run after creation; both must produce
        // the same cache key.
        let dir = std::env::temp_dir().join(format!("vk-absolute-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _guard = TmpDir(dir.clone());

        let target = dir.join("state");
        let before = super::absolute(&target).unwrap();
        std::fs::create_dir(&target).unwrap();
        let after = super::absolute(&target).unwrap();
        assert_eq!(before, after);

        // Lexical noise also normalizes consistently before and after creation.
        let noisy = dir.join("./sub/../state");
        assert_eq!(super::absolute(&noisy).unwrap(), after);
        std::fs::remove_dir(&target).unwrap();
        assert_eq!(super::absolute(&noisy).unwrap(), after);
    }
}
