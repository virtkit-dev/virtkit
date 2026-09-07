//! `.virtkit/config.toml`: a project's description of its development environments, and
//! the machine-local layer over it.
//!
//! A project states its environment once, in a tracked file, and every `vk dev` command works
//! from that. Compose stays the description of a service LAN; the config names which service
//! is the one you work in, or an image or Dockerfile when there is no LAN, and adds what
//! compose cannot say — who you are inside, what the host mounts and publishes, which hooks
//! run and when.
//!
//! ```text
//! .virtkit/
//!   config.toml   # tracked: the environment and its project integration
//!   local.toml    # gitignored: this machine's overrides
//!   local.env     # gitignored, optional: local values, read as data rather than shell
//! ```
//!
//! The schema is versioned and strict: an unknown key is an error in either file, because a
//! key that is silently ignored silently changes what the environment is. TOML is the syntax;
//! the strictness comes from the schema, not the format.
//!
//! Layering: `local.toml` applies over `config.toml`. Scalars replace, tables merge, arrays
//! replace — an empty array clears an inherited list, since an implicit append would make it
//! impossible to narrow an allowlist. Named entries such as mounts and endpoints are switched
//! off with `enabled = false`, and a top-level `remove` list in the local file drops inherited
//! fields before the rest of the layer applies. `remove` and `env-files` belong to the local
//! layer alone.
//!
//! Substitutions, wherever a path or a value is written — mounts, `exec-env`,
//! `container-env`, `build.args`, hook working directories: `~`, `${HOME}`, `${workspace}`,
//! `${state}`, `${VK_UID}`, `${VK_GID}` and `${localEnv:NAME}` (or
//! `${localEnv:NAME:default}`) are expanded, and anything else in `${…}` is an error.
//!
//! This module reads, layers and validates; resolving the result against a host — expanding
//! paths and variables, deriving state — is a separate step.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::dev::schema::directive;

/// The tracked config, relative to the workspace root.
pub const CONFIG_FILE: &str = ".virtkit/config.toml";
/// This machine's overrides, under the workspace root. Gitignored.
pub const LOCAL_FILE: &str = ".virtkit/local.toml";
/// Local values for `${localEnv:…}`, under the workspace root. Gitignored.
pub const LOCAL_ENV_FILE: &str = ".virtkit/local.env";
/// The schema version this build reads.
pub const SCHEMA: i64 = 1;

/// The release that ships `vk dev`, as a literal so [`TEMPLATE`] can `concat!` it.
macro_rules! min_version {
    () => {
        "0.64.0"
    };
}

/// What a written config pins as `requires.min-version`: the release that implements
/// everything `vk dev init` writes.
pub const MIN_VERSION: &str = min_version!();

// ---------------------------------------------------------------------------
// The schema
// ---------------------------------------------------------------------------

/// One layer as written: the tracked file, or the local overrides. Every field is optional —
/// down to a mount's `source` — so a partial local layer deserializes on its own, with its
/// unknown keys and type errors located in its own file; what the merged result must have is
/// checked by [`Schema::validate`].
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Schema {
    /// the schema version; required in the tracked file
    pub schema: Option<i64>,
    /// local overrides only: dotted paths to drop from the inherited config before this
    /// layer applies, such as `dev.compose`
    #[serde(default)]
    pub remove: Vec<String>,
    /// local overrides only: further env files, read after `local.env`, relative to the
    /// workspace root
    #[serde(default)]
    pub env_files: Vec<String>,
    #[serde(default)]
    pub requires: Requires,
    /// the development environment
    pub dev: Option<Environment>,
    /// further named environments, selected with `--environment`; each stands alone and
    /// inherits nothing from `dev`
    #[serde(default)]
    pub environments: BTreeMap<String, Environment>,
}

/// What this project needs of the `vk` reading it.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Requires {
    /// the oldest release that implements everything the config uses
    pub min_version: Option<String>,
    /// `vk check --feature` names the build must answer for
    #[serde(default)]
    pub features: Vec<String>,
}

/// One environment: exactly one source, and how to be in it.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Environment {
    // --- the source: exactly one ---------------------------------------------------------
    /// a compose file, relative to the workspace root; the environment is one of its services
    pub compose: Option<String>,
    /// the compose service to work in — the primary VM
    pub service: Option<String>,
    /// an image reference, for an environment with no service LAN
    pub image: Option<String>,
    /// a Dockerfile target, for an environment built from the project
    pub build: Option<Build>,
    /// take the image from the build cache and never build it; with `fallback`, a cache miss
    /// runs the fallback target instead. A `build` source only.
    #[serde(default)]
    pub cached_only: bool,
    /// what to build when `cached-only` misses the cache
    pub fallback: Option<Fallback>,

    // --- being in it ------------------------------------------------------------------
    /// where the workspace is mounted in the guest
    pub workspace: Option<String>,
    /// the user exec, shell and SSH sessions run as
    pub user: Option<String>,
    /// what to do when the running environment no longer matches the config
    pub freshness: Option<Freshness>,
    /// compose profiles activated eagerly, besides the primary's dependencies
    #[serde(default)]
    pub profiles: Vec<String>,
    /// vCPUs for the primary: a count, or `"host"` for as many as the host has. Unset
    /// inherits the compose service's `x-virtkit.cpus`, then vk's default.
    pub cpus: Option<Cpus>,
    /// memory for the primary (`16G`); unset inherits like `cpus`
    pub mem: Option<String>,
    /// environment for development sessions: exec, shell, SSH and editor processes
    #[serde(default)]
    pub exec_env: BTreeMap<String, String>,
    /// environment for the guest's own processes, set at boot
    #[serde(default)]
    pub container_env: BTreeMap<String, String>,
    /// extra host directories or files in the guest, by name
    #[serde(default)]
    pub mounts: BTreeMap<String, Mount>,
    #[serde(default)]
    pub editor: Editor,
    #[serde(default)]
    pub host: Host,
    #[serde(default)]
    pub cache: Cache,
    /// guest ports published on the host, by name
    #[serde(default)]
    pub endpoints: BTreeMap<String, Endpoint>,
    #[serde(default)]
    pub network: Network,
    #[serde(default)]
    pub hooks: Hooks,
    /// project commands `vk dev task <name>` runs, by name
    #[serde(default)]
    pub tasks: BTreeMap<String, Task>,
}

/// `build = { context = "docker/x", dockerfile = "Dockerfile", target = "dev" }`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Build {
    /// the build context, relative to the workspace root; required once layered
    pub context: Option<String>,
    /// the Dockerfile, relative to the context (default `Dockerfile`)
    pub dockerfile: Option<String>,
    /// the stage to boot (default: the last one)
    pub target: Option<String>,
    /// `--build-arg` values for the build, by name
    #[serde(default)]
    pub args: BTreeMap<String, String>,
}

/// `fallback = { target = "hook" }`: the smaller stage a `cached-only` environment builds
/// when its own is not in the cache.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Fallback {
    /// the Dockerfile stage to build instead; required once layered
    pub target: Option<String>,
}

/// `[dev.tasks.<name>]`: a project command, and where and how it is executed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Task {
    /// a shell string or an argv list, run in the workspace folder; required once layered
    pub run: Option<Command>,
    /// where it runs: `dev` (default), or a name under `[environments]`
    pub environment: Option<String>,
    /// which running environment the reusing policies attach to, when that is not the one
    /// an ephemeral run would boot (default: `environment`)
    pub reuse: Option<String>,
    /// how the environment is obtained (default `reuse-or-ephemeral`)
    pub policy: Option<Policy>,
    /// how the checkout reaches the guest for this task
    pub checkout: Option<CheckoutMode>,
    /// added to the environment's `exec-env` for this task
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// `false` in a local layer switches an inherited task off
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// What a task does about the environment it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Policy {
    /// attach to a running environment, and fail when none runs
    Reuse,
    /// boot it first
    Require,
    /// boot a throwaway VM for the command and tear it down
    Ephemeral,
    /// the running one when there is one, a throwaway otherwise
    ReuseOrEphemeral,
}

impl Policy {
    /// The spelling the config uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Policy::Reuse => "reuse",
            Policy::Require => "require",
            Policy::Ephemeral => "ephemeral",
            Policy::ReuseOrEphemeral => "reuse-or-ephemeral",
        }
    }
}

/// What a task sees of the checkout.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckoutMode {
    /// the host's tree, written through
    #[default]
    Shared,
    /// a tmpfs overlay over it: the task's writes go with the VM
    Overlay,
}

/// What `vk dev` does when the environment that is running was booted from something other
/// than what the config now says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Freshness {
    /// offer a refresh on a terminal; declining, or having no terminal, reuses with a note
    Ask,
    /// attach to the recorded running environment and report the differences
    Reuse,
    /// rebuild and replace it
    Refresh,
    /// fail, naming the differences and the command that reconciles them
    RequireCurrent,
}

impl Freshness {
    /// The spelling the config uses.
    pub fn as_str(self) -> &'static str {
        match self {
            Freshness::Ask => "ask",
            Freshness::Reuse => "reuse",
            Freshness::Refresh => "refresh",
            Freshness::RequireCurrent => "require-current",
        }
    }
}

/// `cpus = 4` or `cpus = "host"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cpus {
    Count(u32),
    /// as many as the host has
    Host,
}

impl std::fmt::Display for Cpus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cpus::Count(n) => write!(f, "{n}"),
            Cpus::Host => f.write_str("host"),
        }
    }
}

/// By hand rather than `untagged`, whose "did not match any variant" says nothing about
/// what a count or `"host"` is — and which is the whole answer for `cpus = 1.5`.
impl<'de> Deserialize<'de> for Cpus {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = Cpus;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a whole number of vCPUs or \"host\"")
            }

            fn visit_u64<E: serde::de::Error>(self, n: u64) -> Result<Cpus, E> {
                u32::try_from(n)
                    .map(Cpus::Count)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Unsigned(n), &self))
            }

            fn visit_i64<E: serde::de::Error>(self, n: i64) -> Result<Cpus, E> {
                u32::try_from(n)
                    .map(Cpus::Count)
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Signed(n), &self))
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Cpus, E> {
                match s {
                    "host" => Ok(Cpus::Host),
                    _ => Err(E::invalid_value(serde::de::Unexpected::Str(s), &self)),
                }
            }
        }
        de.deserialize_any(Visitor)
    }
}

/// As the config spells it, so a plan reads back the way it was written.
impl Serialize for Cpus {
    fn serialize<S: serde::Serializer>(&self, se: S) -> Result<S::Ok, S::Error> {
        match self {
            Cpus::Count(n) => se.serialize_u32(*n),
            Cpus::Host => se.serialize_str("host"),
        }
    }
}

/// `[dev.mounts.<name>]`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Mount {
    /// the host path; `~`, `${HOME}`, `${workspace}`, `${state}`, `${VK_UID}`, `${VK_GID}`
    /// and `${localEnv:NAME}` (or `${localEnv:NAME:default}`) are expanded. Required once
    /// layered.
    pub source: Option<String>,
    /// the guest path; required once layered
    pub to: Option<String>,
    #[serde(default)]
    pub read_only: bool,
    /// skip the mount when the source does not exist, rather than failing the boot
    #[serde(default)]
    pub optional: bool,
    /// `false` in a local layer switches an inherited mount off
    #[serde(default = "yes")]
    pub enabled: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Editor {
    pub vscode: Option<VsCode>,
}

/// `[dev.editor.vscode]`: the managed VS Code server state and how it is reconciled.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct VsCode {
    /// `persistent` keeps the server and its extensions across refreshes in managed storage;
    /// `ephemeral` lets them go with the environment generation
    pub state: Option<EditorState>,
    /// the user's home in the guest, where the server data directory lives; default `/root`
    /// for root and `/home/<user>` otherwise
    pub home: Option<String>,
    /// a project command run in the guest once the editor server is up, after the imported
    /// settings and extensions are applied
    pub reconcile: Option<Hook>,
    /// extensions to install in the remote
    #[serde(default)]
    pub extensions: Vec<String>,
    /// remote settings to apply, without touching unrelated user preferences
    #[serde(default)]
    pub settings: toml::Table,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EditorState {
    #[default]
    Persistent,
    Ephemeral,
}

impl EditorState {
    /// The spelling the config uses.
    pub fn as_str(self) -> &'static str {
        match self {
            EditorState::Persistent => "persistent",
            EditorState::Ephemeral => "ephemeral",
        }
    }
}

/// `[dev.host]`: what the guest may reach on the host. Everything here is off by default.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Host {
    /// the built-in Git GUI policy: `gitk` and `git gui` on the host, over the mapped
    /// workspace, with their arguments and environment filtered
    #[serde(default)]
    pub git_gui: bool,
    /// forward the host's SSH agent into the guest
    #[serde(default)]
    pub ssh_agent: bool,
    /// a project's own host-command dispatcher, relative to the workspace root — the escape
    /// hatch for what the built-in policies do not cover
    pub wrapper: Option<String>,
    /// environment variable patterns passed through to the wrapper
    #[serde(default)]
    pub wrapper_env: Vec<String>,
}

/// `[dev.cache]`: where built stages are cached.
#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Cache {
    pub registry: Option<String>,
    #[serde(default)]
    pub insecure: bool,
}

/// `[dev.endpoints.<name>]`: one guest port, published on the host.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Endpoint {
    /// the compose service that listens (default: the primary)
    pub service: Option<String>,
    /// the guest port; required once layered
    pub target: Option<u16>,
    /// the preferred host port (default: the same number)
    pub host_port: Option<u16>,
    /// the host address: `auto` for a stable loopback allocation, or an address
    pub address: Option<String>,
    /// for `vk dev open`: the URL scheme …
    pub scheme: Option<String>,
    /// … and path
    pub path: Option<String>,
    /// the environment is not ready until this is published
    #[serde(default)]
    pub required: bool,
    #[serde(default = "yes")]
    pub enabled: bool,
}

/// `[dev.network]`.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Network {
    /// `unrestricted` (default)
    pub egress: Option<Egress>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Egress {
    Unrestricted,
    /// read so that a config asking for it is refused by name; nothing implements it, and
    /// the allowlist it needs is not a key until something does
    Restricted,
}

/// `[dev.hooks]`: when project commands run around the environment.
#[derive(Debug, Default, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Hooks {
    /// on the host, from the workspace, before every build or start attempt
    pub init: Option<Hook>,
    /// in the guest, once per materialized environment generation
    pub create: Option<Hook>,
    /// in the guest, on each actual start — not on a reused attachment
    pub start: Option<Hook>,
}

/// A hook in any of its forms: a shell string, an argv array, a table with `run` and its
/// options, or a table of named hooks that run as a group.
///
/// A table holding any of [`HOOK_OPTIONS`] is the option form; anything else is a group, so
/// a member cannot be called `run`, `cwd`, `timeout` or `required`.
#[derive(Debug, Clone, PartialEq)]
pub enum Hook {
    /// through a shell
    Shell(String),
    /// argv, run directly
    Argv(Vec<String>),
    /// a command with options
    Detailed(HookSpec),
    /// the named hooks run in turn; the group fails if any required member does
    Group(BTreeMap<String, Hook>),
}

/// The keys that make a table the option form rather than a group.
const HOOK_OPTIONS: [&str; 4] = ["run", "cwd", "timeout", "required"];

/// Dispatched on the keys rather than left to `untagged`, which answered a typo in an
/// option (`timout`) with "data did not match any variant" after trying the group form —
/// losing the located, named error the module promises.
impl<'de> Deserialize<'de> for Hook {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        Ok(match toml::Value::deserialize(de)? {
            toml::Value::String(s) => Hook::Shell(s),
            v @ toml::Value::Array(_) => Hook::Argv(Vec::deserialize(v).map_err(D::Error::custom)?),
            toml::Value::Table(t) => match t.keys().any(|k| HOOK_OPTIONS.contains(&k.as_str())) {
                true => Hook::Detailed(
                    HookSpec::deserialize(toml::Value::Table(t)).map_err(D::Error::custom)?,
                ),
                false => Hook::Group(
                    BTreeMap::deserialize(toml::Value::Table(t)).map_err(D::Error::custom)?,
                ),
            },
            other => {
                return Err(D::Error::custom(format!(
                    "a hook is a command string, an argv list, a table with `run`, or a table \
                     of named hooks, not {}",
                    other.type_str()
                )));
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct HookSpec {
    /// a shell string or an argv array; required once layered
    pub run: Option<Command>,
    /// the working directory (default: the workspace)
    pub cwd: Option<String>,
    /// how long it may take (`10m`, `90s`)
    pub timeout: Option<String>,
    /// a failure fails the operation (default), or is reported and lets it continue
    #[serde(default = "yes")]
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Command {
    Shell(String),
    Argv(Vec<String>),
}

fn yes() -> bool {
    true
}

// ---------------------------------------------------------------------------
// Validation and description
// ---------------------------------------------------------------------------

impl Schema {
    /// What the merged config must satisfy. Unknown keys were already refused per layer,
    /// with their location; this is the semantics — one source, a schema this build reads,
    /// values that mean something.
    pub fn validate(&self) -> Result<()> {
        match self.schema {
            None => bail!("`schema = {SCHEMA}` is required at the top of config.toml"),
            Some(SCHEMA) => {}
            Some(n) => bail!("schema {n} is not one this vk reads (it reads {SCHEMA})"),
        }
        if let Some(v) = &self.requires.min_version {
            v.parse::<crate::check::Version>()
                .map_err(|e| anyhow::anyhow!("requires.min-version {v:?}: {e}"))?;
        }
        for f in &self.requires.features {
            if crate::check::Feature::from_name(f).is_none() {
                bail!(
                    "requires.features names {f:?}, which is not a feature `vk check` knows \
                     (see `vk check --help`)"
                );
            }
        }
        let Some(dev) = &self.dev else {
            bail!("config.toml has no [dev] table: which environment is the one you work in?");
        };
        dev.validate("dev")?;
        for (name, env) in &self.environments {
            if name == "dev" {
                bail!("[environments.dev] clashes with [dev]: name it something else");
            }
            valid_name(name).with_context(|| format!("[environments.{name}]"))?;
            env.validate(&format!("environments.{name}"))?;
        }
        Ok(())
    }
}

/// A name a shell can export, checked here rather than where a session's environment is
/// assembled: a name holding `=` reaches the guest as a different variable with a longer
/// value, and one holding a newline is dropped without a word.
fn valid_env_name(name: &str) -> Result<()> {
    let mut chars = name.chars();
    let ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        bail!("{name:?} is not a variable name (a letter or `_`, then letters, digits and `_`)");
    }
    Ok(())
}

/// A name usable in a file name and an ssh alias: letters, digits, `.`, `_`, `-`.
fn valid_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("{name:?} is not a name (letters, digits, `.`, `_` and `-` only)");
    }
    Ok(())
}

impl Environment {
    /// What one environment must satisfy. Entries a local layer switched off are skipped:
    /// `enabled = false` says this machine does not have that mount, endpoint or task, and
    /// what is not there does not have to be complete.
    fn validate(&self, at: &str) -> Result<()> {
        let sources = [
            self.compose.is_some(),
            self.image.is_some(),
            self.build.is_some(),
        ]
        .iter()
        .filter(|s| **s)
        .count();
        match sources {
            0 => bail!("[{at}] names no source: set one of compose, image or build"),
            1 => {}
            _ => bail!(
                "[{at}] names more than one source; set exactly one of compose, image or \
                 build (a local layer switching source must `remove` the inherited one)"
            ),
        }
        if self.compose.is_some() && self.service.is_none() {
            bail!("[{at}] compose needs `service`: which one you work in");
        }
        if self.compose.is_none() {
            if self.service.is_some() {
                bail!("[{at}] service only applies to a compose source");
            }
            if !self.profiles.is_empty() {
                bail!("[{at}] profiles are compose profiles, and this is not a compose source");
            }
            for (name, e) in self.endpoints.iter().filter(|(_, e)| e.enabled) {
                if e.service.is_some() {
                    bail!(
                        "[{at}.endpoints.{name}] names a service, and this is not a compose \
                         source"
                    );
                }
            }
        }
        if let Some(b) = &self.build {
            if b.context.as_deref().unwrap_or_default().is_empty() {
                bail!("[{at}] build needs `context`: the directory it builds from");
            }
            // Empty is not "the last stage": it is what `vk dev init` writes for a
            // multi-stage Dockerfile, and `--target ""` builds nothing.
            if b.target.as_deref().is_some_and(str::is_empty) {
                bail!("[{at}] build target is empty: name the stage to boot, or drop the key");
            }
        }
        // Both are about which Dockerfile stage is materialized, so both need one to talk
        // about: a compose service's image is compose's business, and an image is already built.
        if self.build.is_none() {
            if self.cached_only {
                bail!(
                    "[{at}] cached-only applies to a build source: there is no stage to take from the cache"
                );
            }
            if self.fallback.is_some() {
                bail!("[{at}] fallback names a build target, and this is not a build source");
            }
        }
        if let Some(f) = &self.fallback {
            if !self.cached_only {
                bail!(
                    "[{at}] fallback is what `cached-only` builds on a cache miss; set \
                     cached-only = true or drop it"
                );
            }
            if f.target.as_deref().unwrap_or_default().is_empty() {
                bail!("[{at}.fallback] needs `target`: the stage a cache miss builds instead");
            }
        }
        for (name, t) in self.tasks.iter().filter(|(_, t)| t.enabled) {
            valid_name(name).with_context(|| format!("[{at}.tasks]"))?;
            match &t.run {
                Some(Command::Shell(s)) if s.trim().is_empty() => {
                    bail!("[{at}.tasks.{name}] the command is empty")
                }
                Some(Command::Argv(a)) if a.is_empty() => {
                    bail!("[{at}.tasks.{name}] the argv list is empty")
                }
                Some(_) => {}
                None => bail!("[{at}.tasks.{name}] needs `run`: the command"),
            }
            for var in t.env.keys() {
                valid_env_name(var).with_context(|| format!("[{at}.tasks.{name}.env]"))?;
            }
        }
        if let Some(w) = &self.workspace
            && !w.starts_with('/')
        {
            bail!("[{at}] workspace {w:?} is a guest path and must be absolute");
        }
        if self.cpus == Some(Cpus::Count(0)) {
            bail!("[{at}] cpus must be at least 1");
        }
        if let Some(m) = &self.mem
            && crate::run::parse_mem_mib(m).is_none()
        {
            bail!("[{at}] mem {m:?}: expected a non-zero <n>G, <n>M or MiB");
        }
        for (scope, env) in [
            ("exec-env", &self.exec_env),
            ("container-env", &self.container_env),
        ] {
            for name in env.keys() {
                valid_env_name(name).with_context(|| format!("[{at}.{scope}]"))?;
            }
        }
        for (name, m) in self.mounts.iter().filter(|(_, m)| m.enabled) {
            valid_name(name).with_context(|| format!("[{at}.mounts]"))?;
            if m.source.as_deref().unwrap_or_default().is_empty() {
                bail!("[{at}.mounts.{name}] needs `source`: the host path");
            }
            match &m.to {
                Some(to) if to.starts_with('/') => {}
                Some(to) => bail!("[{at}.mounts.{name}] to {to:?} must be an absolute guest path"),
                None => bail!("[{at}.mounts.{name}] needs `to`: the guest path"),
            }
        }
        for (name, e) in self.endpoints.iter().filter(|(_, e)| e.enabled) {
            valid_name(name).with_context(|| format!("[{at}.endpoints]"))?;
            match e.target {
                Some(1..) => {}
                Some(0) => bail!("[{at}.endpoints.{name}] target 0 is not a port"),
                None => bail!("[{at}.endpoints.{name}] needs `target`: the guest port"),
            }
            if e.host_port == Some(0) {
                bail!("[{at}.endpoints.{name}] host-port 0 is not a port");
            }
            if let Some(a) = &e.address
                && a != "auto"
                && a.parse::<std::net::IpAddr>().is_err()
            {
                bail!("[{at}.endpoints.{name}] address {a:?}: expected \"auto\" or an IP address");
            }
        }
        if self.network.egress == Some(Egress::Restricted) {
            bail!(
                "[{at}.network] egress = \"restricted\" is not implemented: the guest reaches \
                 what the host reaches"
            );
        }
        for (hook, cmd) in [
            ("init", &self.hooks.init),
            ("create", &self.hooks.create),
            ("start", &self.hooks.start),
        ] {
            if let Some(c) = cmd {
                c.validate()
                    .with_context(|| format!("[{at}.hooks] {hook}"))?;
            }
        }
        if let Some(vs) = &self.editor.vscode {
            if let Some(r) = &vs.reconcile {
                r.validate()
                    .with_context(|| format!("[{at}.editor.vscode] reconcile"))?;
            }
            if let Some(h) = &vs.home
                && !h.starts_with('/')
            {
                bail!("[{at}.editor.vscode] home {h:?} must be an absolute guest path");
            }
        }
        Ok(())
    }

    /// What this environment says, one aligned line per subject: `vk dev init`'s report for
    /// a config that already exists, and a reader's check that vk read what they meant.
    fn describe(&self) -> String {
        let mut out = String::new();
        let mut line = |k: &str, v: String| out.push_str(&format!("  {k:<12}{v}\n"));
        match (&self.compose, &self.image, &self.build) {
            (Some(c), _, _) => line(
                "source",
                format!(
                    "compose {c}, service {}",
                    self.service.as_deref().unwrap_or("?")
                ),
            ),
            (_, Some(i), _) => line("source", format!("image {i}")),
            (_, _, Some(b)) => line(
                "source",
                format!(
                    "build {}{}{}",
                    b.context.as_deref().unwrap_or("?"),
                    b.dockerfile
                        .as_deref()
                        .map(|d| format!(", {d}"))
                        .unwrap_or_default(),
                    b.target
                        .as_deref()
                        .map(|t| format!(", target {t}"))
                        .unwrap_or_default()
                ),
            ),
            _ => line("source", "none".into()),
        }
        if self.cached_only || self.fallback.is_some() {
            line(
                "cached-only",
                match &self.fallback {
                    Some(f) => format!(
                        "yes, falling back to {}",
                        f.target.as_deref().unwrap_or("?")
                    ),
                    None => "yes, with no fallback".into(),
                },
            );
        }
        if !self.profiles.is_empty() {
            line("profiles", self.profiles.join(", "));
        }
        if let Some(w) = &self.workspace {
            line("workspace", w.clone());
        }
        if let Some(u) = &self.user {
            line("user", u.clone());
        }
        if let Some(f) = self.freshness {
            line("freshness", f.as_str().to_string());
        }
        if self.cpus.is_some() || self.mem.is_some() {
            let cpus = self
                .cpus
                .map(|c| c.to_string())
                .unwrap_or_else(|| "inherited".into());
            line(
                "size",
                format!(
                    "cpus {cpus}, mem {}",
                    self.mem.as_deref().unwrap_or("inherited")
                ),
            );
        }
        if !self.exec_env.is_empty() || !self.container_env.is_empty() {
            line(
                "env",
                format!(
                    "{} for sessions, {} for the guest",
                    self.exec_env.len(),
                    self.container_env.len()
                ),
            );
        }
        let mounts: Vec<String> = self
            .mounts
            .iter()
            .filter(|(_, m)| m.enabled)
            .map(|(n, m)| {
                format!(
                    "{n} -> {}{}",
                    m.to.as_deref().unwrap_or("?"),
                    if m.read_only { " (ro)" } else { "" }
                )
            })
            .collect();
        if !mounts.is_empty() {
            line("mounts", mounts.join(", "));
        }
        let endpoints: Vec<String> = self
            .endpoints
            .iter()
            .filter(|(_, e)| e.enabled)
            .map(|(n, e)| {
                format!(
                    "{n} ({}:{}{})",
                    e.service.as_deref().unwrap_or("primary"),
                    e.target
                        .map(|t| t.to_string())
                        .unwrap_or_else(|| "?".into()),
                    if e.required { ", required" } else { "" }
                )
            })
            .collect();
        if !endpoints.is_empty() {
            line("endpoints", endpoints.join(", "));
        }
        if let Some(r) = &self.cache.registry {
            line(
                "cache",
                format!(
                    "{r}{}",
                    if self.cache.insecure {
                        " (insecure)"
                    } else {
                        ""
                    }
                ),
            );
        }
        let mut host = Vec::new();
        if self.host.git_gui {
            host.push("git-gui".to_string());
        }
        if self.host.ssh_agent {
            host.push("ssh-agent".to_string());
        }
        if let Some(w) = &self.host.wrapper {
            host.push(format!("wrapper {w}"));
        }
        if !host.is_empty() {
            line("host", host.join(", "));
        }
        let hooks: Vec<&str> = [
            ("init", &self.hooks.init),
            ("create", &self.hooks.create),
            ("start", &self.hooks.start),
        ]
        .into_iter()
        .filter(|(_, h)| h.is_some())
        .map(|(n, _)| n)
        .collect();
        if !hooks.is_empty() {
            line("hooks", hooks.join(", "));
        }
        let tasks: Vec<String> = self
            .tasks
            .iter()
            .filter(|(_, t)| t.enabled)
            .map(|(n, t)| {
                format!(
                    "{n} ({} in {})",
                    t.policy.unwrap_or(Policy::ReuseOrEphemeral).as_str(),
                    t.environment.as_deref().unwrap_or("dev")
                )
            })
            .collect();
        if !tasks.is_empty() {
            line("tasks", tasks.join(", "));
        }
        if let Some(vs) = &self.editor.vscode {
            line(
                "vscode",
                format!(
                    "{} state{}{}",
                    vs.state.unwrap_or_default().as_str(),
                    if vs.reconcile.is_some() {
                        ", reconcile hook"
                    } else {
                        ""
                    },
                    if vs.extensions.is_empty() {
                        String::new()
                    } else {
                        format!(", {} extension(s)", vs.extensions.len())
                    }
                ),
            );
        }
        out
    }
}

impl Hook {
    fn validate(&self) -> Result<()> {
        match self {
            Hook::Shell(s) if s.trim().is_empty() => bail!("the command is empty"),
            Hook::Shell(_) => Ok(()),
            Hook::Argv(a)
            | Hook::Detailed(HookSpec {
                run: Some(Command::Argv(a)),
                ..
            }) if a.is_empty() => {
                bail!("the argv list is empty")
            }
            Hook::Detailed(HookSpec {
                run: Some(Command::Shell(s)),
                ..
            }) if s.trim().is_empty() => {
                bail!("the command is empty")
            }
            Hook::Detailed(HookSpec { run: None, .. }) => bail!("needs `run`: the command"),
            Hook::Argv(_) => Ok(()),
            Hook::Detailed(spec) => {
                if let Some(t) = &spec.timeout {
                    parse_duration(t).with_context(|| format!("timeout {t:?}"))?;
                }
                Ok(())
            }
            Hook::Group(group) => {
                if group.is_empty() {
                    bail!("the group is empty");
                }
                for (name, member) in group {
                    valid_name(name)?;
                    member.validate().with_context(|| name.clone())?;
                }
                Ok(())
            }
        }
    }
}

/// `90s`, `10m`, `1h`, or a bare number of seconds.
pub fn parse_duration(text: &str) -> Result<std::time::Duration> {
    let (digits, unit) = match text.find(|c: char| !c.is_ascii_digit()) {
        Some(i) => text.split_at(i),
        None => (text, "s"),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| anyhow::anyhow!("expected a duration such as 90s, 10m or 1h"))?;
    let secs = match unit {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(3600),
        _ => bail!("expected a duration such as 90s, 10m or 1h"),
    };
    Ok(std::time::Duration::from_secs(secs))
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// The files one environment description is read from.
#[derive(Debug, Clone, PartialEq)]
pub struct Files {
    /// the project root: what paths in the config are relative to
    pub workspace: PathBuf,
    pub config: PathBuf,
    /// present when the file exists
    pub local: Option<PathBuf>,
    pub local_env: Option<PathBuf>,
}

/// The root of the checkout `dir` is in: the nearest ancestor (or `dir` itself) holding a
/// `.git` entry, a directory or a linked worktree's file. `None` outside any checkout.
///
/// The entry itself, not what it may point at: a symlink called `.git` is not what git puts
/// there, and following one would stop the walk at a directory that is not a checkout.
pub fn worktree_root(dir: &Path) -> Option<PathBuf> {
    dir.ancestors()
        .find(|d| {
            std::fs::symlink_metadata(d.join(".git")).is_ok_and(|m| m.is_dir() || m.is_file())
        })
        .map(Path::to_path_buf)
}

/// Find the config for a caller in `from`, failing when the project has none. `--workspace`
/// names the root outright and `--dev-config` names the file, whose own directory's parent
/// is then the workspace unless `--workspace` says otherwise.
pub fn discover(from: &Path, workspace: Option<&Path>, config: Option<&Path>) -> Result<Files> {
    let (workspace, config) = match (workspace, config) {
        (Some(w), Some(c)) => (absolute(w)?, absolute(c)?),
        (Some(w), None) => {
            let w = absolute(w)?;
            (w.clone(), w.join(CONFIG_FILE))
        }
        (None, Some(c)) => {
            let c = absolute(c)?;
            // `.virtkit/config.toml` under the project; an arbitrary file's own directory
            // otherwise, which `--workspace` corrects when that is wrong.
            let dir = c.parent().unwrap_or(Path::new("/"));
            let ws = match dir.file_name() {
                Some(n) if n == ".virtkit" => dir.parent().unwrap_or(dir),
                _ => dir,
            };
            (ws.to_path_buf(), c)
        }
        (None, None) => {
            let from = absolute(from)?;
            let Some(files) = search(&from) else {
                let looked = match worktree_root(&from) {
                    Some(root) if root != from => {
                        format!("{} up to {}", from.display(), root.display())
                    }
                    _ => from.display().to_string(),
                };
                bail!(
                    "no {CONFIG_FILE} in {looked} — `vk dev init` writes one, --workspace names \
                     the project, --dev-config names the file"
                );
            };
            return Ok(files);
        }
    };
    if !config.is_file() {
        bail!("{} is not a file", config.display());
    }
    Ok(files_of(workspace, config))
}

/// The config for a caller in `from`, or `None` where there is none — the question
/// `vk dev init` asks before writing one, so a directory it cannot resolve is an error
/// rather than "no project here".
pub fn discover_here(from: &Path) -> Result<Option<Files>> {
    Ok(search(&absolute(from)?))
}

/// `.virtkit/config.toml` in `from` or an ancestor, no further up than the checkout root —
/// and no further than `from` itself outside a checkout, where the walk would otherwise
/// reach `$HOME` and adopt a config written for another project.
fn search(from: &Path) -> Option<Files> {
    let Some(root) = worktree_root(from) else {
        let config = from.join(CONFIG_FILE);
        return config
            .is_file()
            .then(|| files_of(from.to_path_buf(), config));
    };
    for dir in from.ancestors() {
        let config = dir.join(CONFIG_FILE);
        if config.is_file() {
            return Some(files_of(dir.to_path_buf(), config));
        }
        if dir == root {
            break;
        }
    }
    None
}

/// The config and the local layers over it. The local files are the workspace's own, at
/// `workspace/.virtkit/`, wherever `--dev-config` took the tracked file from.
fn files_of(workspace: PathBuf, config: PathBuf) -> Files {
    let in_workspace = |name: &str| {
        let p = workspace.join(name);
        p.is_file().then_some(p)
    };
    Files {
        local: in_workspace(LOCAL_FILE),
        local_env: in_workspace(LOCAL_ENV_FILE),
        workspace,
        config,
    }
}

/// `p` as an absolute path: resolved when it exists, else taken lexically against the cwd.
pub fn absolute(p: &Path) -> Result<PathBuf> {
    match std::fs::canonicalize(p) {
        Ok(abs) => Ok(abs),
        Err(_) if p.is_absolute() => Ok(p.to_path_buf()),
        Err(_) => Ok(std::env::current_dir()
            .with_context(|| format!("resolving {} against the cwd", p.display()))?
            .join(p)),
    }
}

/// `path` with `.` and `..` folded without touching the filesystem: a config's
/// `../shared/compose.yaml` reads back as the path it means, and a draft is text, so a path
/// that does not exist yet still has to read well. A `..` that cannot be folded away is
/// kept, so a relative path does not silently become its own root — except at `/`, whose
/// parent is itself.
pub fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::ParentDir => {
                if !out.pop() && !out.has_root() {
                    out.push("..");
                }
            }
            std::path::Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

/// `base/rel`, folded by [`lexical_normalize`].
pub fn lexical_join(base: &Path, rel: &Path) -> PathBuf {
    lexical_normalize(&base.join(rel))
}

// ---------------------------------------------------------------------------
// Loading and layering
// ---------------------------------------------------------------------------

/// Where a configured value came from, for `plan --explain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Project,
    Local,
}

/// A config read, layered and validated, with its layers kept for attribution.
#[derive(Debug, Clone)]
pub struct Loaded {
    pub files: Files,
    pub schema: Schema,
    /// `local.env` and the local layer's `env-files`, later files winning
    pub env_file: BTreeMap<String, String>,
    merged: toml::Table,
    local: Option<toml::Table>,
}

/// Read, layer and validate the files [`discover`] found.
pub fn load(files: Files) -> Result<Loaded> {
    let (project_schema, project) = parse_layer(&files.config)?;
    if !project_schema.remove.is_empty() {
        bail!(
            "{}: `remove` belongs in {LOCAL_FILE}, which is what has something to remove",
            files.config.display()
        );
    }
    if !project_schema.env_files.is_empty() {
        bail!(
            "{}: `env-files` belongs in {LOCAL_FILE}: which files a machine reads is that \
             machine's business",
            files.config.display()
        );
    }
    let (local_schema, local) = match &files.local {
        Some(p) => {
            let (s, t) = parse_layer(p)?;
            (Some(s), Some(t))
        }
        None => (None, None),
    };
    let mut merged = project;
    let mut local_applied = None;
    if let (Some(schema), Some(table)) = (&local_schema, &local) {
        for path in &schema.remove {
            let local_path = files.local.as_deref().unwrap_or(Path::new(LOCAL_FILE));
            remove_path(&mut merged, path)
                .with_context(|| format!("{}: remove {path:?}", local_path.display()))?;
        }
        let mut table = table.clone();
        // Layer directives, not configuration: applied above, and not part of the tree.
        table.remove("remove");
        table.remove("env-files");
        merge_tables(&mut merged, table.clone());
        local_applied = Some(table);
    }
    let schema: Schema = merged
        .clone()
        .try_into()
        .with_context(|| format!("reading the layered {}", files.config.display()))?;
    schema
        .validate()
        .with_context(|| format!("in {}", files.config.display()))?;

    let mut env_file = BTreeMap::new();
    if let Some(p) = &files.local_env {
        env_file.extend(read_env_file(p)?);
    }
    for name in local_schema.iter().flat_map(|s| &s.env_files) {
        env_file.extend(read_env_file(&files.workspace.join(name))?);
    }
    Ok(Loaded {
        files,
        schema,
        env_file,
        merged,
        local: local_applied,
    })
}

/// One configured value and where it came from, as `plan --explain` reports them.
pub struct Origin {
    /// the dotted path, quoted where a segment needs it
    pub key: String,
    pub value: toml::Value,
    pub layer: Layer,
    /// a value the config hands to a command or an image — an environment variable or a
    /// build argument — which `plan --explain` prints only with `--show-secrets`
    pub secret: bool,
}

/// Whether a key path names a value handed to a command or an image. Which of them carries
/// a token is the project's business: a literal written into `local.toml` is as much a
/// secret as one this shell exported.
fn secret_key(keys: &[String]) -> bool {
    let nth_last = |n: usize| keys.len().checked_sub(n).and_then(|i| keys.get(i));
    matches!(
        nth_last(2).map(String::as_str),
        Some("exec-env" | "container-env" | "env")
    ) || (nth_last(3).map(String::as_str) == Some("build")
        && nth_last(2).map(String::as_str) == Some("args"))
}

impl Loaded {
    /// Every configured value with the layer that last set it, as `plan --explain` reports
    /// them: dotted paths in file order, the local layer winning where both speak.
    pub fn origins(&self) -> Vec<Origin> {
        let mut out = Vec::new();
        leaves(&self.merged, &mut Vec::new(), &mut out);
        out.into_iter()
            .map(|(keys, value)| Origin {
                layer: match &self.local {
                    Some(local) if lookup(local, &keys).is_some() => Layer::Local,
                    _ => Layer::Project,
                },
                secret: secret_key(&keys),
                key: join_path(&keys),
                value,
            })
            .collect()
    }

    /// The environment `name` selects: `dev`, or one under `[environments]`.
    pub fn environment(&self, name: &str) -> Result<&Environment> {
        if name == "dev" {
            return self
                .schema
                .dev
                .as_ref()
                .context("config.toml has no [dev] table");
        }
        self.schema.environments.get(name).with_context(|| {
            let mut known: Vec<&str> = vec!["dev"];
            known.extend(self.schema.environments.keys().map(String::as_str));
            format!(
                "no [environments.{name}] in {} (there is {})",
                self.files.config.display(),
                known.join(", ")
            )
        })
    }

    /// What the files describe, one environment per paragraph — `vk dev init`'s report for
    /// a config that already exists, and a reader's check that vk read what they meant.
    pub fn describe(&self) -> String {
        let mut out = format!("{}: ok\n", self.files.config.display());
        if let Some(local) = &self.files.local {
            out.push_str(&format!("  with {}\n", local.display()));
        }
        if !self.env_file.is_empty() {
            out.push_str(&format!(
                "  {} local value(s) for ${{localEnv:…}}\n",
                self.env_file.len()
            ));
        }
        if let Some(v) = &self.schema.requires.min_version {
            out.push_str(&format!("  requires vk {v}\n"));
        }
        if !self.schema.requires.features.is_empty() {
            out.push_str(&format!(
                "  requires features {}\n",
                self.schema.requires.features.join(", ")
            ));
        }
        for (name, env) in std::iter::once(("dev", self.schema.dev.as_ref())).chain(
            self.schema
                .environments
                .iter()
                .map(|(n, e)| (n.as_str(), Some(e))),
        ) {
            let Some(env) = env else { continue };
            out.push_str(&format!("\n[{name}]\n"));
            out.push_str(&env.describe());
        }
        out
    }
}

/// One file as a typed layer, for its unknown-key and type errors with their location, and
/// as a tree, for merging.
fn parse_layer(path: &Path) -> Result<(Schema, toml::Table)> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let schema: Schema =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}:\n{e}", path.display()))?;
    let table: toml::Table =
        toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}:\n{e}", path.display()))?;
    Ok((schema, table))
}

/// Layer `over` onto `base`: tables merge key by key, everything else — scalars and arrays
/// alike — replaces.
fn merge_tables(base: &mut toml::Table, over: toml::Table) {
    for (key, value) in over {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge_tables(b, o),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// Drop the value at a dotted `path`. Absent is an error: a `remove` that names nothing is a
/// typo or a stale override, and either is worth hearing about.
fn remove_path(table: &mut toml::Table, path: &str) -> Result<()> {
    let keys = split_path(path)?;
    let Some((last, parents)) = keys.split_last() else {
        bail!("empty path");
    };
    let mut cur = table;
    for k in parents {
        cur = match cur.get_mut(k) {
            Some(toml::Value::Table(t)) => t,
            Some(_) => bail!("{k:?} is not a table"),
            None => bail!("nothing at {k:?}"),
        };
    }
    if cur.remove(last).is_none() {
        bail!("nothing to remove");
    }
    Ok(())
}

/// Every scalar and array in `table`, with its key path. Tables are the structure, not
/// values; an empty table is reported as itself so `[dev.exec-env]` with nothing in it still
/// shows where it came from.
fn leaves(table: &toml::Table, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, toml::Value)>) {
    for (k, v) in table {
        path.push(k.clone());
        match v {
            toml::Value::Table(t) if !t.is_empty() => leaves(t, path, out),
            v => out.push((path.clone(), v.clone())),
        }
        path.pop();
    }
}

/// A key path back in its dotted spelling, quoting a key a bare dotted path could not carry.
fn join_path(keys: &[String]) -> String {
    keys.iter()
        .map(|k| quote_key(k))
        .collect::<Vec<_>>()
        .join(".")
}

fn lookup<'a>(table: &'a toml::Table, keys: &[String]) -> Option<&'a toml::Value> {
    let (first, rest) = keys.split_first()?;
    let mut cur = table.get(first)?;
    for k in rest {
        cur = cur.as_table()?.get(k)?;
    }
    Some(cur)
}

/// `dev.endpoints."runner.https".target` → its keys, with TOML's quoting for a key that
/// contains a dot. A quoted key spans its whole segment, as it does in TOML: `a"b"c` is a
/// typo, not the key `abc`.
fn split_path(path: &str) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for segment in split_segments(path) {
        let key = match segment.strip_prefix('"') {
            Some(rest) => match rest.strip_suffix('"') {
                Some(inner) if !inner.contains('"') => inner,
                _ => bail!("{path:?}: {segment:?} is not a quoted key"),
            },
            None if segment.contains('"') => {
                bail!("{path:?}: {segment:?} quotes part of a key")
            }
            None => segment,
        };
        if key.is_empty() {
            bail!("{path:?}: empty key");
        }
        keys.push(key.to_string());
    }
    if keys.is_empty() {
        bail!("{path:?}: empty key");
    }
    Ok(keys)
}

/// The dot-separated segments of `path`, with dots inside a quoted key left alone.
fn split_segments(path: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut quoted) = (0, false);
    for (i, c) in path.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '.' if !quoted => {
                out.push(&path[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&path[start..]);
    out
}

/// Read `NAME=value` lines as data: no expansion, no command substitution, no sourcing. A
/// leading `export ` is accepted, ` #` starts a comment, and a value may be single- or
/// double-quoted — inside double quotes `\"` and `\\` are the only escapes, and text after
/// the closing quote is an error.
///
/// Deliberately not docker's `.env` rules, which [`crate::compose`] reads for a compose
/// project: there a value is raw to the end of the line (`#` included) and one matching pair
/// of quotes is stripped with no escapes. This file is vk's own, and a token written into it
/// should mean what it looks like rather than what docker would have made of it.
pub fn read_env_file(path: &Path) -> Result<BTreeMap<String, String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_env_file(&text).with_context(|| format!("in {}", path.display()))
}

fn parse_env_file(text: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export ")
            .map(str::trim_start)
            .unwrap_or(line);
        let (name, value) = line
            .split_once('=')
            .with_context(|| format!("line {}: expected NAME=value, got {raw:?}", i + 1))?;
        let name = name.trim_end();
        let valid = name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            bail!("line {}: {name:?} is not a variable name", i + 1);
        }
        let value = value.trim_start();
        let value = match value.chars().next() {
            Some('\'') => {
                let inner = &value[1..];
                let end = inner
                    .find('\'')
                    .with_context(|| format!("line {}: unterminated quote", i + 1))?;
                trailing_ok(&inner[end + 1..], i)?;
                inner[..end].to_string()
            }
            Some('"') => {
                let mut s = String::new();
                let mut chars = value[1..].chars();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => match chars.next() {
                            Some(e @ ('"' | '\\')) => s.push(e),
                            Some(other) => {
                                s.push('\\');
                                s.push(other);
                            }
                            None => s.push('\\'),
                        },
                        '"' => {
                            closed = true;
                            break;
                        }
                        c => s.push(c),
                    }
                }
                if !closed {
                    bail!("line {}: unterminated quote", i + 1);
                }
                trailing_ok(chars.as_str(), i)?;
                s
            }
            // Unquoted: to the end of the line, minus a trailing comment.
            _ => match value.find(" #") {
                Some(at) => value[..at].trim_end().to_string(),
                None => value.trim_end().to_string(),
            },
        };
        out.insert(name.to_string(), value);
    }
    Ok(out)
}

fn trailing_ok(rest: &str, line: usize) -> Result<()> {
    let rest = rest.trim_start();
    if rest.is_empty() || rest.starts_with('#') {
        return Ok(());
    }
    bail!(
        "line {}: unexpected {rest:?} after the closing quote",
        line + 1
    )
}

// ---------------------------------------------------------------------------
// `vk dev init`: a first config
// ---------------------------------------------------------------------------

/// The commented config `vk dev init` writes when it has nothing to translate from.
pub const TEMPLATE: &str = concat!(
    directive!(),
    r#"
# The development environment `vk dev` boots. Paths are relative to this project's root.
# See `vk dev --help`; every key here is checked, and an unknown one is an error.
schema = 1

[requires]
# The oldest vk release that implements everything this file uses.
# min-version = ""#,
    min_version!(),
    r#""
features = []

[dev]
# Exactly one source: a compose service, an image, or a Dockerfile target.
image = "docker.io/library/debian:13"
# compose = ".virtkit/compose.yaml"
# service = "devcontainer"
# build = { context = ".", dockerfile = "Dockerfile", target = "dev" }

# Where the checkout is mounted in the guest, and who sessions run as.
workspace = "/workdir"
# user = "dev"

# When the running environment no longer matches this file:
# ask | reuse | refresh | require-current
freshness = "ask"

# Guest sizing. Unset inherits the compose service's x-virtkit, then vk's defaults.
# cpus = "host"
# mem = "8G"

# Environment for exec, shell, SSH and editor sessions.
[dev.exec-env]

# Host paths in the guest, by name. `~`, `${HOME}`, `${workspace}`, `${state}`,
# `${VK_UID}`, `${VK_GID}` and `${localEnv:NAME}` (or `${localEnv:NAME:default}`)
# are expanded.
# [dev.mounts.gitconfig]
# source = "~/.gitconfig"
# to = "/home/dev/.gitconfig"
# read-only = true
# optional = true

# Guest ports published on the host, by name.
# [dev.endpoints.web]
# target = 8080
"#
);

/// Write the template at `workspace/.virtkit/config.toml`.
pub fn write_template(workspace: &Path, force: bool) -> Result<PathBuf> {
    write_config(workspace, TEMPLATE, force)
}

// ---------------------------------------------------------------------------
// Drafting a config
// ---------------------------------------------------------------------------

/// How one piece of an imported source fared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Fate {
    /// carried into the draft
    Translated,
    /// needs a person: the draft says what, and an `essential` one leaves it unusable
    Action { essential: bool },
    /// nothing to carry, and nothing lost
    Omitted,
}

/// One line of a conversion report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Item {
    pub fate: Fate,
    /// the source key, as the source spells it
    pub key: String,
    pub note: String,
}

/// A config being written: sections of keys, each a TOML value or a commented-out line for
/// a choice the writer could not make, plus the report of how it came to be. Rendered in the
/// order things were added, so a draft reads like a hand-written file.
#[derive(Debug, Default)]
pub(crate) struct Draft {
    header: Vec<String>,
    /// what stands before the first `[table]`
    root: Vec<Entry>,
    sections: Vec<Section>,
    pub items: Vec<Item>,
}

#[derive(Debug)]
struct Section {
    /// `["dev", "mounts", "gitconfig"]`; empty for the top level
    path: Vec<String>,
    entries: Vec<Entry>,
}

#[derive(Debug)]
enum Entry {
    Set(String, toml::Value),
    /// `# key = …` — a line for the reader to finish
    Commented(String, String),
    Comment(String),
}

impl Draft {
    /// A line for the comment block at the top of the file.
    pub(crate) fn header(&mut self, line: impl Into<String>) {
        self.header.push(line.into());
    }

    /// Start (or continue) the table at `path`; entries go there until the next call.
    pub(crate) fn section(&mut self, path: &[&str]) {
        let path: Vec<String> = path.iter().map(|s| s.to_string()).collect();
        if self.sections.last().is_some_and(|s| s.path == path) {
            return;
        }
        self.sections.push(Section {
            path,
            entries: Vec::new(),
        });
    }

    /// Where the next entry goes: the section last opened, or the top of the file.
    fn entries(&mut self) -> &mut Vec<Entry> {
        match self.sections.last_mut() {
            Some(section) => &mut section.entries,
            None => &mut self.root,
        }
    }

    pub(crate) fn set(&mut self, key: &str, value: impl Into<toml::Value>) {
        let value = value.into();
        self.entries().push(Entry::Set(key.to_string(), value));
    }

    /// `# key = text`, for a value the reader must supply.
    pub(crate) fn commented(&mut self, key: &str, text: impl Into<String>) {
        self.entries()
            .push(Entry::Commented(key.to_string(), text.into()));
    }

    pub(crate) fn comment(&mut self, text: impl Into<String>) {
        self.entries().push(Entry::Comment(text.into()));
    }

    pub(crate) fn translated(&mut self, key: &str, note: impl Into<String>) {
        self.note(Fate::Translated, key, note);
    }

    pub(crate) fn action(&mut self, key: &str, note: impl Into<String>) {
        self.note(Fate::Action { essential: false }, key, note);
    }

    /// Something without which the draft cannot describe the environment.
    pub(crate) fn essential(&mut self, key: &str, note: impl Into<String>) {
        self.note(Fate::Action { essential: true }, key, note);
    }

    pub(crate) fn omitted(&mut self, key: &str, note: impl Into<String>) {
        self.note(Fate::Omitted, key, note);
    }

    fn note(&mut self, fate: Fate, key: &str, note: impl Into<String>) {
        self.items.push(Item {
            fate,
            key: key.to_string(),
            note: note.into(),
        });
    }

    /// Whether anything essential is missing.
    pub(crate) fn needs_work(&self) -> bool {
        self.items
            .iter()
            .any(|i| i.fate == Fate::Action { essential: true })
    }

    /// The file, with the schema directive editors read on its first line.
    pub(crate) fn render(&self) -> String {
        let mut out = format!("{}\n", crate::dev::schema::DIRECTIVE);
        for line in &self.header {
            out.push_str(&format!("# {line}\n"));
        }
        if !self.header.is_empty() {
            out.push('\n');
        }
        render_entries(&self.root, &mut out);
        for section in &self.sections {
            out.push('\n');
            let keys: Vec<String> = section.path.iter().map(|k| quote_key(k)).collect();
            out.push_str(&format!("[{}]\n", keys.join(".")));
            render_entries(&section.entries, &mut out);
        }
        out
    }

    /// The opening every import writes: where the draft came from, the schema version and
    /// the `[requires]` table, with the environment's own section open after it.
    pub(crate) fn preamble(&mut self, from: &str) {
        self.header(format!(
            "Written by `vk dev init` from {from}. Paths are relative to the project root."
        ));
        self.set("schema", SCHEMA);
        self.section(&["requires"]);
        self.comment("The oldest vk release that implements everything this file uses.");
        self.commented("min-version", format!("{MIN_VERSION:?}"));
        self.set("features", toml::Value::Array(Vec::new()));
        self.section(&["dev"]);
    }

    /// The report: what was carried over, what needs a person, what was left out.
    pub(crate) fn report(&self) -> String {
        let mut out = String::new();
        for (fate, title) in [
            (Fate::Translated, "translated"),
            (
                Fate::Action { essential: true },
                "requires action before the environment can start",
            ),
            (Fate::Action { essential: false }, "requires action"),
            (Fate::Omitted, "omitted"),
        ] {
            let items: Vec<&Item> = self.items.iter().filter(|i| i.fate == fate).collect();
            if items.is_empty() {
                continue;
            }
            out.push_str(&format!("{title}:\n"));
            for i in items {
                match i.note.is_empty() {
                    true => out.push_str(&format!("  {}\n", i.key)),
                    false => out.push_str(&format!("  {}: {}\n", i.key, i.note)),
                }
            }
        }
        out
    }
}

fn render_entries(entries: &[Entry], out: &mut String) {
    for entry in entries {
        match entry {
            Entry::Set(k, v) => out.push_str(&format!("{} = {v}\n", quote_key(k))),
            Entry::Commented(k, text) => out.push_str(&format!("# {} = {text}\n", quote_key(k))),
            Entry::Comment(text) => {
                for line in text.lines() {
                    out.push_str(&format!("# {line}\n"));
                }
            }
        }
    }
}

/// A TOML key, quoted when it is not bare.
fn quote_key(key: &str) -> String {
    if !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return key.to_string();
    }
    toml::Value::String(key.to_string()).to_string()
}

/// Write `text` as `workspace/.virtkit/config.toml`. Refuses an existing file unless `force`;
/// never touches the local files beside it.
///
/// Without `--force` the file is created outright: `create_new` is the refusal, so a second
/// `init` and a symlink planted at the name are answered by the create itself rather than by
/// a check a moment earlier. With it there is a file to replace, so the new one is written
/// whole under a temporary name and renamed over it — an interrupted init then leaves either
/// the old file or the new one, never half of each. Both are created `0644` rather than
/// whatever the umask says.
pub fn write_config(workspace: &Path, text: &str, force: bool) -> Result<PathBuf> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let path = workspace.join(CONFIG_FILE);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let at = match force {
        true => path.with_extension("toml.tmp"),
        false => path.clone(),
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(&at)
        .map_err(|e| match (e.kind(), force) {
            (std::io::ErrorKind::AlreadyExists, false) => anyhow::anyhow!(
                "{} exists — `vk dev init` validates it as is; --force overwrites it",
                path.display()
            ),
            _ => anyhow::Error::new(e).context(format!("creating {}", at.display())),
        })?;
    let written = file
        .write_all(text.as_bytes())
        .with_context(|| format!("writing {}", at.display()))
        .and_then(|()| match force {
            true => std::fs::rename(&at, &path)
                .with_context(|| format!("publishing {}", path.display())),
            false => Ok(()),
        });
    if written.is_err() {
        // Nothing readable was published, so the half-written file is only litter.
        let _ = std::fs::remove_file(&at);
    }
    written?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn workspace(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!("vk-devconfig-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".virtkit")).unwrap();
        std::fs::create_dir_all(root.join(".git")).unwrap();
        Fixture(root)
    }

    const WAB: &str = r#"
schema = 1

[requires]
features = ["entrypoint", "publish"]

[dev]
compose = ".virtkit/compose.yaml"
service = "devcontainer"
workspace = "/workdir"
user = "dev"
freshness = "ask"
profiles = []

[dev.exec-env]
GITLAB_WORKFLOW_INSTANCE_URL = "https://gitlab.corp.wallix.com"

[dev.mounts.gitconfig]
source = "~/.gitconfig"
to = "/home/dev/.gitconfig"
read-only = true
optional = true

[dev.editor.vscode]
state = "persistent"
reconcile = ["/workdir/.devcontainer/install-extensions.sh", "-postcreate"]

[dev.host]
git-gui = true
ssh-agent = false

[dev.cache]
registry = "https://vk-registry.corp:5000"
insecure = false

[dev.endpoints."runner.https"]
service = "runner"
target = 443
host-port = 8443
address = "auto"
scheme = "https"
path = "/ui"
required = true

[dev.endpoints."runner.ssh"]
service = "runner"
target = 22
host-port = 8022
address = "auto"

[dev.network]
egress = "unrestricted"

[dev.hooks]
init = "./scripts/prepare.sh"
create = { run = ["make", "fixtures"], timeout = "10m", required = false }
start = { redis = "redis-cli ping", db = ["mysqladmin", "ping"] }
"#;

    fn write(f: &Fixture, name: &str, text: &str) {
        std::fs::write(f.0.join(name), text).unwrap();
    }

    fn load_in(f: &Fixture) -> Result<Loaded> {
        load(discover(&f.0, None, None)?)
    }

    fn dev_of(l: &Loaded) -> &Environment {
        l.schema.dev.as_ref().unwrap()
    }

    #[test]
    fn the_illustrative_config_reads_as_written() {
        let f = workspace("wab");
        write(&f, CONFIG_FILE, WAB);
        let l = load_in(&f).unwrap();
        let dev = dev_of(&l);
        assert_eq!(dev.compose.as_deref(), Some(".virtkit/compose.yaml"));
        assert_eq!(dev.service.as_deref(), Some("devcontainer"));
        assert_eq!(dev.freshness, Some(Freshness::Ask));
        assert_eq!(l.schema.requires.features, ["entrypoint", "publish"]);
        let m = &dev.mounts["gitconfig"];
        assert!(m.read_only && m.optional && m.enabled);
        let e = &dev.endpoints["runner.https"];
        assert_eq!(
            (e.target, e.host_port, e.required),
            (Some(443), Some(8443), true)
        );
        assert!(dev.host.git_gui);
        assert_eq!(
            dev.hooks.init,
            Some(Hook::Shell("./scripts/prepare.sh".into()))
        );
        match &dev.hooks.create {
            Some(Hook::Detailed(spec)) => {
                assert_eq!(
                    spec.run,
                    Some(Command::Argv(vec!["make".into(), "fixtures".into()]))
                );
                assert_eq!(spec.timeout.as_deref(), Some("10m"));
                assert!(!spec.required);
            }
            other => panic!("{other:?}"),
        }
        match &dev.hooks.start {
            Some(Hook::Group(group)) => assert_eq!(group.len(), 2),
            other => panic!("{other:?}"),
        }
        match &dev.editor.vscode.as_ref().unwrap().reconcile {
            Some(Hook::Argv(argv)) => assert_eq!(argv[1], "-postcreate"),
            other => panic!("{other:?}"),
        }

        let report = l.describe();
        for expect in [
            "config.toml: ok",
            "requires features entrypoint, publish",
            "[dev]",
            "compose .virtkit/compose.yaml, service devcontainer",
            "gitconfig -> /home/dev/.gitconfig (ro)",
            "runner.https (runner:443, required)",
            "vk-registry.corp",
            "git-gui",
            "init, create, start",
            "persistent state, reconcile hook",
        ] {
            assert!(report.contains(expect), "{expect:?} in:\n{report}");
        }
    }

    #[test]
    fn an_unknown_key_is_refused_with_its_location() {
        let f = workspace("unknown");
        write(
            &f,
            CONFIG_FILE,
            "schema = 1\n[dev]\nimage = \"x\"\nworkspce = \"/w\"\n",
        );
        let err = load_in(&f).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("workspce"), "{msg}");
        assert!(msg.contains("config.toml"), "{msg}");
        assert!(msg.contains("4"), "line number: {msg}");
        // …in the local layer too, naming that file.
        write(&f, CONFIG_FILE, "schema = 1\n[dev]\nimage = \"x\"\n");
        write(&f, LOCAL_FILE, "[dev]\nmemory = \"8G\"\n");
        let msg = format!("{:#}", load_in(&f).unwrap_err());
        assert!(
            msg.contains("memory") && msg.contains("local.toml"),
            "{msg}"
        );
    }

    #[test]
    fn the_schema_version_and_a_source_are_required() {
        let f = workspace("schema");
        write(&f, CONFIG_FILE, "[dev]\nimage = \"x\"\n");
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("schema = 1"));
        write(&f, CONFIG_FILE, "schema = 2\n[dev]\nimage = \"x\"\n");
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("schema 2"));
        write(&f, CONFIG_FILE, "schema = 1\n");
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("[dev]"));
        write(&f, CONFIG_FILE, "schema = 1\n[dev]\nworkspace = \"/w\"\n");
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("no source"));
        write(&f, CONFIG_FILE, "schema = 1\n[dev]\ncompose = \"c.yaml\"\n");
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("service"));
        write(
            &f,
            CONFIG_FILE,
            "schema = 1\n[dev]\nimage = \"x\"\nservice = \"s\"\n",
        );
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("compose source"));
    }

    #[test]
    fn local_overrides_layer_scalars_tables_and_arrays_as_documented() {
        let f = workspace("layer");
        write(&f, CONFIG_FILE, WAB);
        write(
            &f,
            LOCAL_FILE,
            r#"
[dev]
mem = "32G"
profiles = ["runner"]

[dev.exec-env]
EXTRA = "1"

[dev.mounts.gitconfig]
enabled = false

[dev.mounts.ssh]
source = "~/.ssh"
to = "/home/dev/.ssh"

[dev.endpoints."runner.https"]
host-port = 9443
"#,
        );
        let l = load_in(&f).unwrap();
        let dev = dev_of(&l);
        // Scalars replace.
        assert_eq!(dev.mem.as_deref(), Some("32G"));
        assert_eq!(dev.freshness, Some(Freshness::Ask), "untouched");
        // Arrays replace.
        assert_eq!(dev.profiles, ["runner"]);
        // Tables merge: the inherited key stays, the new one joins.
        assert_eq!(dev.exec_env.len(), 2);
        assert_eq!(dev.exec_env["EXTRA"], "1");
        // A named entry merges field by field, and can be switched off.
        assert!(!dev.mounts["gitconfig"].enabled);
        assert_eq!(
            dev.mounts["gitconfig"].to.as_deref(),
            Some("/home/dev/.gitconfig")
        );
        assert_eq!(dev.mounts["ssh"].to.as_deref(), Some("/home/dev/.ssh"));
        let e = &dev.endpoints["runner.https"];
        assert_eq!(e.host_port, Some(9443));
        assert_eq!(e.target, Some(443), "the rest of the entry is inherited");
        let report = l.describe();
        assert!(
            report.contains("with ") && report.contains("local.toml"),
            "{report}"
        );
        assert!(!report.contains("gitconfig ->"), "disabled: {report}");
        assert!(report.contains("ssh -> /home/dev/.ssh"), "{report}");

        // Each value knows its layer, down to one field of a merged entry.
        let origins: BTreeMap<String, Layer> =
            l.origins().into_iter().map(|o| (o.key, o.layer)).collect();
        assert_eq!(origins["dev.mem"], Layer::Local);
        assert_eq!(origins["dev.service"], Layer::Project);
        assert_eq!(origins["dev.mounts.gitconfig.to"], Layer::Project);
        assert_eq!(origins["dev.mounts.gitconfig.enabled"], Layer::Local);
        assert_eq!(
            origins["dev.endpoints.\"runner.https\".host-port"],
            Layer::Local
        );
        assert_eq!(
            origins["dev.endpoints.\"runner.https\".target"],
            Layer::Project
        );
        assert_eq!(origins["dev.exec-env.EXTRA"], Layer::Local);
        assert!(!origins.contains_key("remove"), "a directive, not a value");

        // What a config hands to a command or an image is marked, so `plan --explain`
        // prints it only when asked.
        let secret: BTreeMap<String, bool> =
            l.origins().into_iter().map(|o| (o.key, o.secret)).collect();
        assert!(secret["dev.exec-env.EXTRA"]);
        assert!(!secret["dev.mem"] && !secret["dev.service"]);
    }

    #[test]
    fn a_value_whose_type_changes_across_layers_is_replaced_whole() {
        let f = workspace("retype");
        let hook = |body: &str| format!("schema = 1\n[dev]\nimage = \"x\"\n[dev.hooks]\n{body}");
        // A shell string under a table of options …
        write(&f, CONFIG_FILE, &hook("init = \"project\"\n"));
        write(&f, LOCAL_FILE, "[dev.hooks]\ninit = { run = \"local\" }\n");
        match &dev_of(&load_in(&f).unwrap()).hooks.init {
            Some(Hook::Detailed(spec)) => {
                assert_eq!(spec.run, Some(Command::Shell("local".into())))
            }
            other => panic!("{other:?}"),
        }
        // … and a table of options under a shell string.
        write(&f, CONFIG_FILE, &hook("init = { run = \"project\" }\n"));
        write(&f, LOCAL_FILE, "[dev.hooks]\ninit = \"local\"\n");
        assert_eq!(
            dev_of(&load_in(&f).unwrap()).hooks.init,
            Some(Hook::Shell("local".into()))
        );
    }

    #[test]
    fn a_disabled_entry_is_not_held_to_the_rules_of_one_that_runs() {
        let f = workspace("disabled");
        write(&f, CONFIG_FILE, WAB);
        // Off is off: an entry this machine does not have needs neither the fields a live
        // one needs nor a project entry to switch off.
        write(
            &f,
            LOCAL_FILE,
            "[dev.mounts.gitconfig]\nenabled = false\nsource = \"\"\n\
             [dev.mounts.nothing]\nenabled = false\n\
             [dev.endpoints.gone]\nenabled = false\n\
             [dev.tasks.gone]\nenabled = false\n",
        );
        let l = load_in(&f).unwrap();
        let dev = dev_of(&l);
        assert!(!dev.mounts["nothing"].enabled && !dev.endpoints["gone"].enabled);
        let report = l.describe();
        assert!(
            !report.contains("nothing") && !report.contains("gone"),
            "{report}"
        );
    }

    #[test]
    fn an_empty_array_clears_and_remove_drops_before_the_layer_applies() {
        let f = workspace("remove");
        write(&f, CONFIG_FILE, WAB);
        // Switching source locally: the inherited compose must go, or two sources remain.
        write(&f, LOCAL_FILE, "[dev]\nimage = \"debian:13\"\n");
        let msg = format!("{:#}", load_in(&f).unwrap_err());
        assert!(msg.contains("more than one source"), "{msg}");

        write(
            &f,
            LOCAL_FILE,
            "remove = [\"dev.compose\", \"dev.service\", \"dev.endpoints\"]\n\
             [dev]\nimage = \"debian:13\"\n\n[requires]\nfeatures = []\n",
        );
        let l = load_in(&f).unwrap();
        let dev = dev_of(&l);
        assert_eq!(dev.image.as_deref(), Some("debian:13"));
        assert!(dev.compose.is_none() && dev.service.is_none());
        assert!(dev.endpoints.is_empty(), "a whole table can go");
        assert!(
            l.schema.requires.features.is_empty(),
            "an empty array clears"
        );

        // A remove that names nothing is a stale override, and says so.
        write(&f, LOCAL_FILE, "remove = [\"dev.nope\"]\n");
        let msg = format!("{:#}", load_in(&f).unwrap_err());
        assert!(
            msg.contains("dev.nope") && msg.contains("local.toml"),
            "{msg}"
        );
        // A quoted key with a dot in it is one key.
        write(
            &f,
            LOCAL_FILE,
            "remove = ['dev.endpoints.\"runner.ssh\"']\n",
        );
        let l = load_in(&f).unwrap();
        let dev = dev_of(&l);
        assert_eq!(dev.endpoints.len(), 1);
        assert!(dev.endpoints.contains_key("runner.https"));

        // The directives belong to the local layer.
        write(&f, CONFIG_FILE, &format!("remove = [\"x\"]\n{WAB}"));
        std::fs::remove_file(f.0.join(LOCAL_FILE)).unwrap();
        let msg = format!("{:#}", load_in(&f).unwrap_err());
        assert!(
            msg.contains("remove") && msg.contains("local.toml"),
            "{msg}"
        );
    }

    #[test]
    fn named_environments_stand_alone_and_are_named_carefully() {
        let f = workspace("envs");
        write(
            &f,
            CONFIG_FILE,
            "schema = 1\n[dev]\nimage = \"a\"\nuser = \"dev\"\n\
             [environments.ci]\nimage = \"b\"\n",
        );
        let l = load_in(&f).unwrap();
        let ci = l.environment("ci").unwrap();
        assert_eq!(ci.image.as_deref(), Some("b"));
        assert!(ci.user.is_none(), "nothing is inherited from [dev]");
        assert!(l.describe().contains("[ci]"), "{}", l.describe());
        let msg = format!("{:#}", l.environment("qa").unwrap_err());
        assert!(msg.contains("dev, ci"), "{msg}");

        write(
            &f,
            CONFIG_FILE,
            "schema = 1\n[dev]\nimage = \"a\"\n[environments.dev]\nimage = \"b\"\n",
        );
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("clashes"));
        write(
            &f,
            CONFIG_FILE,
            "schema = 1\n[dev]\nimage = \"a\"\n[environments.\"a b\"]\nimage = \"b\"\n",
        );
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("not a name"));
    }

    #[test]
    fn values_are_checked_for_meaning_not_only_for_shape() {
        let f = workspace("values");
        let bad = [
            ("cpus = 0", "at least 1"),
            ("cpus = \"many\"", "\"host\""),
            ("cpus = -1", "\"host\""),
            ("cpus = 1.5", "\"host\""),
            ("mem = \"lots\"", "mem"),
            ("workspace = \"workdir\"", "absolute"),
            ("[dev.mounts.x]\nsource = \"/a\"\nto = \"b\"", "absolute"),
            ("[dev.mounts.x]\nsource = \"/a\"", "needs `to`"),
            ("[dev.mounts.x]\nto = \"/a\"", "needs `source`"),
            ("[dev.endpoints.x]\ntarget = 0", "not a port"),
            ("[dev.endpoints.x]\nhost-port = 80", "needs `target`"),
            ("[dev.hooks]\ninit = { cwd = \"x\" }", "needs `run`"),
            (
                "[dev.endpoints.x]\ntarget = 80\naddress = \"lo\"",
                "IP address",
            ),
            ("[dev.network]\negress = \"restricted\"", "not implemented"),
            ("[dev.network]\nallow = [\"a\"]", "allow"),
            ("[dev.exec-env]\n\"A=B\" = \"x\"", "not a variable name"),
            ("[dev.container-env]\nA-B = \"x\"", "not a variable name"),
            (
                "[dev.tasks.t]\nrun = \"true\"\n[dev.tasks.t.env]\n\"1\" = \"x\"",
                "not a variable name",
            ),
            ("[dev.hooks]\ninit = \"\"", "empty"),
            ("[dev.hooks]\ninit = []", "empty"),
            (
                "[dev.hooks]\ninit = { run = \"x\", timeout = \"soon\" }",
                "timeout",
            ),
            // A typo in an option is an unknown key of the option form, not a hook group
            // whose member happens to be misspelled.
            (
                "[dev.hooks]\ninit = { run = \"x\", timout = \"1m\" }",
                "timout",
            ),
            ("[dev.hooks]\ninit = 3", "a hook is"),
            ("[dev.hooks]\ninit = { a = { run = \"\" } }", "empty"),
            ("[requires]\nmin-version = \"latest\"", "min-version"),
            ("[requires]\nfeatures = [\"warp\"]", "warp"),
        ];
        for (body, expect) in bad {
            let (top, rest) = match body.starts_with("[requires]") {
                true => (body, ""),
                false => ("", body),
            };
            write(
                &f,
                CONFIG_FILE,
                &format!("schema = 1\n{top}\n[dev]\nimage = \"x\"\n{rest}\n"),
            );
            let msg = format!("{:#}", load_in(&f).unwrap_err());
            assert!(msg.contains(expect), "{body}: {msg}");
        }
        // A build source, whose keys are checked against each other rather than against
        // `image` above.
        for (body, expect) in [
            ("build = { target = \"x\" }", "needs `context`"),
            (
                "build = { context = \".\", target = \"\" }",
                "target is empty",
            ),
            (
                "build = { context = \".\" }\nfallback = { target = \"x\" }",
                "cached-only",
            ),
            (
                "build = { context = \".\" }\ncached-only = true\nfallback = { target = \"\" }",
                "needs `target`",
            ),
        ] {
            write(&f, CONFIG_FILE, &format!("schema = 1\n[dev]\n{body}\n"));
            let msg = format!("{:#}", load_in(&f).unwrap_err());
            assert!(msg.contains(expect), "{body}: {msg}");
        }
        write(
            &f,
            CONFIG_FILE,
            "schema = 1\n[requires]\nmin-version = \"0.61.0\"\nfeatures = [\"publish\"]\n\
             [dev]\nimage = \"x\"\ncpus = \"host\"\nmem = \"8G\"\n",
        );
        load_in(&f).unwrap();
    }

    #[test]
    fn discovery_walks_up_to_the_checkout_root_and_no_further() {
        let f = workspace("discover");
        write(&f, CONFIG_FILE, "schema = 1\n[dev]\nimage = \"x\"\n");
        let deep = f.0.join("src/a/b");
        std::fs::create_dir_all(&deep).unwrap();
        let files = discover(&deep, None, None).unwrap();
        assert_eq!(files.workspace, absolute(&f.0).unwrap());
        assert_eq!(files.config, absolute(&f.0).unwrap().join(CONFIG_FILE));
        assert!(files.local.is_none() && files.local_env.is_none());

        // A nested checkout is its own project: the search stops at its `.git`.
        let sub = f.0.join("vendor/other");
        std::fs::create_dir_all(sub.join(".git")).unwrap();
        let msg = format!("{:#}", discover(&sub, None, None).unwrap_err());
        assert!(msg.contains("vk dev init"), "{msg}");

        // Explicit forms.
        let files = discover(&sub, Some(&f.0), None).unwrap();
        assert_eq!(files.workspace, absolute(&f.0).unwrap());
        let files = discover(&sub, None, Some(&f.0.join(CONFIG_FILE))).unwrap();
        assert_eq!(
            files.workspace,
            absolute(&f.0).unwrap(),
            "from the file's .virtkit/"
        );
        assert!(discover(&sub, None, Some(&f.0.join("nope.toml"))).is_err());

        // Outside any checkout the walk stops where it started: an ancestor's config
        // belongs to that project, not to this directory.
        let outside = std::env::temp_dir().join(format!("vk-devdiscover-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(outside.join("a/b")).unwrap();
        std::fs::create_dir_all(outside.join(".virtkit")).unwrap();
        std::fs::write(
            outside.join(CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"x\"\n",
        )
        .unwrap();
        assert!(discover(&outside.join("a/b"), None, None).is_err());
        assert!(discover_here(&outside.join("a/b")).unwrap().is_none());
        assert!(discover(&outside, None, None).is_ok(), "its own directory");
        let _ = std::fs::remove_dir_all(&outside);

        // The local files are found beside the config.
        write(&f, LOCAL_FILE, "");
        write(&f, LOCAL_ENV_FILE, "TOKEN=x\n");
        let files = discover(&deep, None, None).unwrap();
        assert!(files.local.is_some() && files.local_env.is_some());
        let l = load(files).unwrap();
        assert_eq!(l.env_file["TOKEN"], "x");
    }

    #[test]
    fn env_files_are_data_not_shell() {
        let parsed = parse_env_file(
            "# comment\n\
             PLAIN=value with spaces # trailing comment\n\
             export EXPORTED=1\n\
             SINGLE='a \"b\" $(rm -rf /) ${HOME}'\n\
             DOUBLE=\"say \\\"hi\\\" \\\\ $HOME\"\n\
             EMPTY=\n\
             \n\
             URL=https://example.com/#anchor\n",
        )
        .unwrap();
        assert_eq!(parsed["PLAIN"], "value with spaces");
        assert_eq!(parsed["EXPORTED"], "1");
        assert_eq!(parsed["SINGLE"], "a \"b\" $(rm -rf /) ${HOME}");
        assert_eq!(parsed["DOUBLE"], "say \"hi\" \\ $HOME", "no expansion");
        assert_eq!(parsed["EMPTY"], "");
        assert_eq!(
            parsed["URL"], "https://example.com/#anchor",
            "`#` needs a space before it"
        );
        for bad in [
            "novalue\n",
            "1BAD=x\n",
            "A='open\n",
            "B=\"open\n",
            "C='x' junk\n",
        ] {
            assert!(parse_env_file(bad).is_err(), "{bad:?}");
        }
        // Later files win; the local layer names them.
        let f = workspace("envfiles");
        write(&f, CONFIG_FILE, "schema = 1\n[dev]\nimage = \"x\"\n");
        write(&f, LOCAL_ENV_FILE, "A=1\nB=1\n");
        write(&f, "extra.env", "B=2\nC=2\n");
        write(&f, LOCAL_FILE, "env-files = [\"extra.env\"]\n");
        let l = load_in(&f).unwrap();
        assert_eq!(
            (
                l.env_file["A"].as_str(),
                l.env_file["B"].as_str(),
                l.env_file["C"].as_str()
            ),
            ("1", "2", "2")
        );
        // …and only the local layer.
        write(
            &f,
            CONFIG_FILE,
            "schema = 1\nenv-files = [\"extra.env\"]\n[dev]\nimage = \"x\"\n",
        );
        assert!(format!("{:#}", load_in(&f).unwrap_err()).contains("env-files"));
    }

    #[test]
    fn the_template_is_a_valid_config_and_is_not_overwritten_by_accident() {
        let f = workspace("template");
        let path = write_template(&f.0, false).unwrap();
        assert_eq!(path, f.0.join(CONFIG_FILE));
        // Asked for at creation rather than left to the umask, and published whole.
        let mode = std::os::unix::fs::PermissionsExt::mode(&path.metadata().unwrap().permissions());
        assert_eq!(mode & 0o777, 0o644, "{mode:o}");
        assert!(!f.0.join(".virtkit/config.toml.tmp").exists());
        let l = load_in(&f).unwrap();
        assert_eq!(
            dev_of(&l).image.as_deref(),
            Some("docker.io/library/debian:13")
        );
        write(&f, LOCAL_FILE, "[dev]\nmem = \"2G\"\n");
        assert!(write_template(&f.0, false).is_err());
        write_template(&f.0, true).unwrap();
        assert_eq!(
            std::fs::read_to_string(f.0.join(LOCAL_FILE)).unwrap(),
            "[dev]\nmem = \"2G\"\n",
            "--force replaces the tracked file and nothing beside it"
        );
    }

    #[test]
    fn durations_and_paths_parse_as_expected() {
        assert_eq!(parse_duration("90s").unwrap().as_secs(), 90);
        assert_eq!(parse_duration("10m").unwrap().as_secs(), 600);
        assert_eq!(parse_duration("1h").unwrap().as_secs(), 3600);
        assert_eq!(parse_duration("5").unwrap().as_secs(), 5);
        assert!(parse_duration("5d").is_err() && parse_duration("").is_err());
        assert_eq!(split_path("a.b.c").unwrap(), ["a", "b", "c"]);
        assert_eq!(
            split_path("dev.endpoints.\"runner.https\".target").unwrap(),
            ["dev", "endpoints", "runner.https", "target"]
        );
        assert!(split_path("a..b").is_err() && split_path("").is_err());
        // A quoted key is the whole segment or a typo.
        for bad in [r#"a"b"c"#, r#""""#, r#""a"#, r#"a."b"c"#] {
            assert!(split_path(bad).is_err(), "{bad}");
        }
    }
}
