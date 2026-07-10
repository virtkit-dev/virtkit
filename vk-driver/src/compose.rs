//! The docker-compose subset `vk run --compose` consumes — the service
//! declaration, kept isomorphic to compose so a compose file (or a GitLab CI
//! `services:` block, which is a subset of it) migrates mechanically.
//!
//! Supported per service: `image` xor `build.{context, dockerfile (string or list —
//! a vk extension merging the files into one stage namespace), target, args}`,
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
//!     depends_on: [db, redis]
//! ```
//!
//! Runtime config follows the compose model: the image (its config sidecar / OCI
//! config) carries the defaults, the service entries are start-time overrides —
//! merged by [`merged_config`] and handed to the guest at boot. Changing an
//! override never rebuilds an image.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use vk_core::runcfg::RunConfig;

/// One declared service, mapped from a compose `services.<name>` entry.
#[derive(Debug)]
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
}

/// Where a unit's image comes from.
#[derive(Debug)]
pub enum Source {
    /// pulled from a registry (fingerprint: the manifest digest)
    Image(String),
    /// built in-process from Dockerfile stage(s) (fingerprint: the stage key)
    Build {
        /// the service's Dockerfile(s); several merge into one stage namespace
        dockerfiles: Vec<PathBuf>,
        /// the build context, shared by all the service's files (compose semantics)
        context: PathBuf,
        target: Option<String>,
        args: Vec<(String, String)>,
    },
}

/// A bind mount (`host:guest[:ro]`); named volumes are not supported.
#[derive(Debug, Clone)]
pub struct Volume {
    pub host: PathBuf,
    pub guest: String,
    pub read_only: bool,
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

/// Load + map a compose file. `base` (the file's directory) anchors every relative
/// path: build contexts, Dockerfiles, and bind-mount sources. Variable references
/// (`$VAR`, `${VAR}`, `${VAR:-default}`) are interpolated first, docker-compose
/// style — from the process environment layered over a sibling `.env` (the process
/// env wins) — so machine-specific values (a repo path, a uid) stay out of the
/// committed file.
pub fn load(path: &Path) -> Result<Vec<Unit>> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let dotenv = load_dotenv(base)?;
    let resolve = |name: &str| {
        // process environment first (docker precedence), then the sibling .env. A
        // set-but-empty process value wins over a .env value — and, being empty, is
        // then treated as unset by `interpolate` (so it takes a default or errors).
        std::env::var(name).ok().or_else(|| {
            dotenv
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    };
    parse(&raw, base, &resolve).with_context(|| format!("in {}", path.display()))
}

/// Load `KEY=VALUE` pairs from a `.env` beside the compose file — docker-compose's
/// interpolation source. A missing file is not an error (no vars). Blank lines and
/// `#` comments are skipped; the value is taken raw (same convention as `--env-file`),
/// so no quoting or escaping is interpreted.
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
            Some((k, v)) => vars.push((k.trim().to_string(), v.to_string())),
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
fn interpolate(text: &str, resolve: &dyn Fn(&str) -> Option<String>) -> Result<String> {
    // set-and-non-empty; treated as unset otherwise so `:-default` and the
    // unset-error path both fire on an empty value.
    let value = |name: &str| resolve(name).filter(|v| !v.is_empty());
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
) -> Result<Vec<Unit>> {
    // Interpolate on the parsed YAML *values* (never keys), then deserialize: a
    // value may expand to embedded newlines (a volume-list variable) without
    // disturbing the document structure, and `deny_unknown_fields` still runs.
    let mut doc: serde_yaml_ng::Value = serde_yaml_ng::from_str(yaml)?;
    interpolate_values(&mut doc, resolve)?;
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
) -> Result<()> {
    use serde_yaml_ng::Value;
    match v {
        Value::String(s) => *s = interpolate(s, resolve)?,
        Value::Sequence(seq) => {
            for e in seq {
                interpolate_values(e, resolve)?;
            }
        }
        Value::Mapping(m) => {
            for (_k, val) in m.iter_mut() {
                interpolate_values(val, resolve)?;
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
    Ok(Source::Build {
        dockerfiles,
        context,
        target: spec.target,
        args: spec.args.map(Env::into_pairs).unwrap_or_default(),
    })
}

/// A bind-mount `host:guest[:ro|rw]`. A source that is not a path (a compose named
/// volume) is rejected — there is no volume manager here. Public: `run -v/--volume`
/// parses the same syntax, anchored at the caller's cwd instead of the compose
/// file's directory.
pub fn parse_volume(spec: &str, base: &Path) -> Result<Volume> {
    let parts: Vec<&str> = spec.split(':').collect();
    let (host, guest, mode) = match parts.as_slice() {
        [h, g] => (*h, *g, "rw"),
        [h, g, m] => (*h, *g, *m),
        _ => bail!("bad volume {spec:?} (want host:guest[:ro])"),
    };
    if !(host.starts_with('/') || host.starts_with('.') || host.starts_with('~')) {
        bail!("volume {spec:?}: named volumes are not supported (bind-mount a path)");
    }
    if host.starts_with('~') {
        bail!("volume {spec:?}: ~ expansion is not supported (use an absolute path)");
    }
    let read_only = match mode {
        "ro" => true,
        "rw" => false,
        other => bail!("volume {spec:?}: unsupported mode {other:?} (want ro or rw)"),
    };
    if !guest.starts_with('/') {
        bail!("volume {spec:?}: the guest path must be absolute");
    }
    Ok(Volume {
        host: base.join(host),
        guest: guest.to_string(),
        read_only,
    })
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
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BuildSpec {
    context: Option<PathBuf>,
    dockerfile: Option<OneOrMany>,
    target: Option<String>,
    args: Option<Env>,
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

#[derive(Deserialize)]
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
    use super::*;

    // Most tests need no interpolation: shadow `parse` with a no-vars variant so
    // the call sites stay two-arg. Tests exercising `${VAR}` call `super::parse`
    // with a real resolver.
    fn parse(yaml: &str, base: &Path) -> Result<Vec<Unit>> {
        super::parse(yaml, base, &|_| None)
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
        };
        let mut unit = one("services:\n  s:\n    image: x\n    environment: [PORT=2]\n");
        // env upserts; everything else keeps the image defaults
        let m = merged_config(&image, &unit);
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
            "# a comment\n\nexport A=1\nB = two words\nC=\n",
        )
        .unwrap();
        let v = load_dotenv(&dir).unwrap();
        assert_eq!(v.iter().find(|(k, _)| k == "A").unwrap().1, "1");
        // value is taken raw after the first '='; key is trimmed, `export ` stripped
        assert_eq!(v.iter().find(|(k, _)| k == "B").unwrap().1, " two words");
        assert_eq!(v.iter().find(|(k, _)| k == "C").unwrap().1, "");
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
        let u = super::parse(yaml, Path::new("/base"), &r)
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
        let u2 = super::parse(yaml, Path::new("/base"), &r2)
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(u2.volumes.len(), 1);
    }
}
