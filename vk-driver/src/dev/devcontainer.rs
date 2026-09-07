//! `devcontainer.json`, read for `vk dev init --from devcontainer`.
//!
//! Import the existing compose file, service, mounts and user to avoid describing the
//! environment twice by hand. Read the file once as data and translate it into
//! `.virtkit/config.toml`, the runtime input, reporting what did not carry over.
//!
//! Found at `.devcontainer/devcontainer.json`, then `.devcontainer.json`. Parsed strictly:
//! a key this module does not know fails to deserialize, since a key silently dropped is a
//! setting silently lost. Every known key is either carried into the draft or reported.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::dev::config::{absolute, lexical_normalize};

/// The config file names looked for in a workspace, in order.
const DISCOVERY: [&str; 2] = [".devcontainer/devcontainer.json", ".devcontainer.json"];

/// Find the devcontainer config for `workspace`: an explicit path wins, else the standard
/// names in order.
pub fn discover(workspace: &Path, explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if !p.is_file() {
            bail!("{} is not a file", p.display());
        }
        return Ok(p.to_path_buf());
    }
    for name in DISCOVERY {
        let candidate = workspace.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    bail!(
        "no devcontainer config in {} (looked for {})",
        workspace.display(),
        DISCOVERY.join(", ")
    )
}

/// Keep the unknown key and location from serde_json's error, dropping its list of every
/// struct field, including those declared only for reporting. Recover ` at line N column M`
/// from the tail of that list.
///
/// Coupled to serde_json's exact phrasing; a message that does not match falls back to the
/// raw error.
fn explain(e: serde_json::Error) -> anyhow::Error {
    let msg = e.to_string();
    let Some((head, tail)) = msg.split_once(", expected one of") else {
        return anyhow::Error::new(e);
    };
    let at = tail
        .rfind(" at line")
        .map(|i| &tail[i..])
        .unwrap_or_default();
    anyhow::anyhow!("{head} is not a supported devcontainer key{at}")
}

/// Replace `//` and `/* */` comments with spaces, one per byte, preserving line breaks
/// and string contents. This keeps serde_json's line and column accurate even for
/// non-ASCII comments.
fn strip_comments(text: &str) -> String {
    /// Preserve newlines; replace other characters with one space per byte.
    fn blank(out: &mut String, c: char) {
        match c {
            '\n' => out.push('\n'),
            c => out.extend(std::iter::repeat_n(' ', c.len_utf8())),
        }
    }

    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    let mut escaped = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => in_string = false,
                _ => escaped = false,
            }
            continue;
        }
        match (c, chars.peek()) {
            ('"', _) => {
                in_string = true;
                escaped = false;
                out.push(c);
            }
            // The second `/` is consumed by the loop that blanks the line out.
            ('/', Some('/')) => {
                blank(&mut out, c);
                for c in chars.by_ref() {
                    blank(&mut out, c);
                    if c == '\n' {
                        break;
                    }
                }
            }
            ('/', Some('*')) => {
                blank(&mut out, c);
                // Consume and blank the opener's `*` before scanning, so its own `*` cannot
                // pair with the next `/`: `/*/` runs to EOF as unterminated, not closed.
                chars.next();
                blank(&mut out, '*');
                let mut prev = ' ';
                for c in chars.by_ref() {
                    blank(&mut out, c);
                    if prev == '*' && c == '/' {
                        break;
                    }
                    prev = c;
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// Blank a comma that only whitespace separates from its closing `}` or `]`. JSONC allows a
/// trailing comma and VS Code writes them; serde_json rejects them. Run after
/// [`strip_comments`], so a comment between the comma and the bracket is already whitespace.
fn strip_trailing_commas(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    // Byte offset in `out` of a comma not yet followed by a value.
    let mut comma: Option<usize> = None;
    for c in text.chars() {
        if in_string {
            out.push(c);
            match c {
                '\\' if !escaped => escaped = true,
                '"' if !escaped => in_string = false,
                _ => escaped = false,
            }
            continue;
        }
        match c {
            '"' => {
                comma = None;
                in_string = true;
                escaped = false;
                out.push(c);
            }
            ',' => {
                comma = Some(out.len());
                out.push(c);
            }
            '}' | ']' => {
                if let Some(pos) = comma.take() {
                    // Comma and space are both one ASCII byte, so offsets stay aligned.
                    out.replace_range(pos..=pos, " ");
                }
                out.push(c);
            }
            _ if c.is_whitespace() => out.push(c),
            _ => {
                comma = None;
                out.push(c);
            }
        }
    }
    out
}

/// A devcontainer config, as written. Field presence is the contract: what the draft carries
/// is typed, what it only reports is `Value` so the report can quote it, and anything else
/// fails to deserialize.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Config {
    // --- accepted and ignored -------------------------------------------------------
    // Declared so they are accepted, not read: dropping the fields would turn two harmless
    // descriptive keys into unknown-key errors.
    /// a display name for the environment
    #[allow(dead_code)]
    pub name: Option<String>,
    /// editors resolve this; it says nothing about the environment
    #[serde(rename = "$schema")]
    #[allow(dead_code)]
    pub schema: Option<String>,

    // --- carried into the draft -----------------------------------------------------
    /// the compose file, resolved against this config's directory
    pub docker_compose_file: Option<OneOrMany>,
    /// the service to work in — the primary VM
    pub service: Option<String>,
    /// the exact set of services to start, rather than the primary's dependencies alone
    pub run_services: Option<Vec<String>>,
    /// the guest directory a session starts in
    pub workspace_folder: Option<String>,
    /// extra bind mounts
    pub mounts: Option<Vec<Mount>>,
    /// environment for everything in the container, set at boot
    pub container_env: Option<BTreeMap<String, String>>,
    /// environment for what the dev tooling runs — execs, lifecycle commands, editor
    /// sessions — and not for the container's own processes
    pub remote_env: Option<BTreeMap<String, String>>,
    /// the user those sessions run as
    pub remote_user: Option<String>,
    /// guest ports to publish to the host
    pub forward_ports: Option<Vec<Port>>,
    /// run on the host before the environment starts
    pub initialize_command: Option<Lifecycle>,
    /// run in the guest once, when the environment is first created
    pub post_create_command: Option<Lifecycle>,
    /// run in the guest each time it starts
    pub post_start_command: Option<Lifecycle>,
    /// per-tool settings; only `virtkit` is read (and validated)
    pub customizations: Option<Customizations>,

    // --- recognized for reporting ------------------------------------------------------
    // Declared so the report can name the key and what to do about it, rather than failing
    // on an unknown field. `image`, `build` and `dockerFile` are also translated into the
    // draft where they apply; the rest are only reported. Kept in spec order-ish; each is
    // explained in `translate`.
    image: Option<serde_json::Value>,
    build: Option<serde_json::Value>,
    docker_file: Option<serde_json::Value>,
    workspace_mount: Option<serde_json::Value>,
    app_port: Option<serde_json::Value>,
    container_user: Option<serde_json::Value>,
    #[serde(rename = "updateRemoteUserUID")]
    update_remote_user_uid: Option<serde_json::Value>,
    features: Option<serde_json::Value>,
    on_create_command: Option<serde_json::Value>,
    update_content_command: Option<serde_json::Value>,
    post_attach_command: Option<serde_json::Value>,
    wait_for: Option<serde_json::Value>,
    ports_attributes: Option<serde_json::Value>,
    other_ports_attributes: Option<serde_json::Value>,
    shutdown_action: Option<serde_json::Value>,
    privileged: Option<serde_json::Value>,
    init: Option<serde_json::Value>,
    cap_add: Option<serde_json::Value>,
    security_opt: Option<serde_json::Value>,
    run_args: Option<serde_json::Value>,
    override_command: Option<serde_json::Value>,
    user_env_probe: Option<serde_json::Value>,
    host_requirements: Option<serde_json::Value>,
}

/// A string or a list of them (`dockerComposeFile`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

/// A `mounts` entry: the string form (`source=…,target=…,type=bind`) or the object form.
#[derive(Debug)]
pub enum Mount {
    Str(String),
    Obj(MountObj),
}

/// The object form, strict like the rest of the file: a key this module does not know is an
/// error rather than a setting dropped on the way in.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MountObj {
    #[serde(rename = "type")]
    kind: Option<String>,
    source: String,
    target: String,
    /// a docker performance hint with no meaning for a virtio-fs share: accepted so a file
    /// written for both tools works, and otherwise ignored
    #[serde(default)]
    #[allow(dead_code)]
    consistency: Option<String>,
    #[serde(default)]
    readonly: bool,
}

/// Dispatched on the JSON shape: `untagged` would answer an unknown key in the object form
/// by trying the string form and reporting neither.
impl<'de> Deserialize<'de> for Mount {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        match serde_json::Value::deserialize(de)? {
            serde_json::Value::String(s) => Ok(Mount::Str(s)),
            v @ serde_json::Value::Object(_) => serde_json::from_value(v)
                .map(Mount::Obj)
                .map_err(D::Error::custom),
            other => Err(D::Error::custom(format!(
                "a mount is a string or an object, not {other}"
            ))),
        }
    }
}

/// A `forwardPorts` entry: a guest port on the primary, or `"service:port"`.
///
/// The number is accepted as an `i64` so an out-of-range one deserializes and is
/// range-checked with a targeted message, rather than failing the whole-file parse.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Port {
    Number(i64),
    Named(String),
}

/// A lifecycle command in any of the spec's three forms.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum Lifecycle {
    /// run through a shell
    Shell(String),
    /// argv, run directly
    Argv(Vec<String>),
    /// named commands, run in parallel; all must succeed
    Parallel(BTreeMap<String, Lifecycle>),
}

#[derive(Debug, Default, Deserialize)]
pub struct Customizations {
    pub virtkit: Option<Virtkit>,
    /// every other tool's namespace, kept out of our way
    #[serde(flatten)]
    #[allow(dead_code)]
    others: BTreeMap<String, serde_json::Value>,
}

/// `customizations.virtkit` — what an earlier `vk dev` read from a devcontainer file, so a
/// project that adopted it is translated.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Virtkit {
    // The same workspace does not have to be the same machine: a compose file describing a
    // VM LAN names kernels, disks and `x-virtkit` axes that docker cannot run. These two keys
    // let one devcontainer file carry both — the standard keys for the editors, these for vk.
    /// the compose file to drive instead of the top-level `dockerComposeFile`
    pub docker_compose_file: Option<String>,
    /// the service to work in instead of the top-level `service`
    pub service: Option<String>,

    /// vCPUs for the primary (`host` for as many as the host has)
    pub cpus: Option<String>,
    /// memory for the primary
    pub mem: Option<String>,
    /// compose profiles to activate — unrelated to `runServices`
    #[serde(default)]
    pub profiles: Vec<String>,
    /// the guest's host-command allowlist
    pub host_exec: Option<HostExec>,
    /// where built stages are cached
    pub cache: Option<Cache>,
    /// `auto` (default) derives it from the workspace path; a path pins it
    pub state_dir: Option<String>,
    /// mount a linked worktree's git common dir at its own absolute path
    #[serde(default)]
    pub git_worktree_mount: bool,
    /// build args to receive the host's uid/gid, for an image that builds its user
    pub local_user_build_args: Option<LocalUserBuildArgs>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HostExec {
    /// the dispatcher every host command goes through, relative to the config file
    pub wrapper: String,
    /// environment variable patterns passed through to it
    #[serde(default)]
    pub env: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Cache {
    pub registry: Option<String>,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalUserBuildArgs {
    #[serde(default)]
    pub uid: Vec<String>,
    #[serde(default)]
    pub gid: Vec<String>,
}

// ---------------------------------------------------------------------------
// Import: a devcontainer.json as a first `.virtkit/config.toml`
// ---------------------------------------------------------------------------

/// Parse the JSONC a devcontainer file is: `//` and `/* */` comments and trailing commas,
/// all of which VS Code writes. Everything past those is strict JSON.
pub fn parse_for_import(text: &str) -> Result<Config> {
    // serde_json rejects a leading BOM; strip one so a BOM-prefixed file parses.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let stripped = strip_trailing_commas(&strip_comments(text));
    serde_json::from_str(&stripped).map_err(explain)
}

/// Translate `config`, read from `config_path` in `workspace`, into a draft. Data
/// conversion only: nothing is executed, downloaded or booted.
///
/// Paths in a devcontainer file are relative to the file; in the draft they are relative to
/// the workspace root, so every one is rebased. Variables change spelling
/// (`${localWorkspaceFolder}` becomes `${workspace}`); `${localEnv:…}` stays as it is.
pub fn translate(
    config: &Config,
    config_path: &Path,
    workspace: &Path,
) -> Result<crate::dev::config::Draft> {
    use crate::dev::config::Draft;
    let config_path = absolute(config_path)?;
    let config_dir = config_path.parent().unwrap_or(Path::new("/")).to_path_buf();
    let workspace = absolute(workspace)?;
    let shown = config_path
        .strip_prefix(&workspace)
        .unwrap_or(&config_path)
        .display()
        .to_string();

    let mut d = Draft::default();
    d.preamble(&shown);
    d.header("Review the `requires action` items of the report before the first `vk dev shell`.");
    let virtkit = config
        .customizations
        .as_ref()
        .and_then(|c| c.virtkit.as_ref());
    let rebase = |d: &mut Draft, key: &str, p: &str| -> String {
        // Report non-UTF-8 paths with `to_str`; `to_string_lossy` would corrupt the config.
        let not_utf8 = |d: &mut Draft| -> String {
            d.action(
                key,
                "project path is not valid UTF-8; cannot be written to config.toml",
            );
            p.to_string()
        };
        let expanded = if p.contains("${localWorkspaceFolder}") {
            let Some(w) = workspace.to_str() else {
                return not_utf8(d);
            };
            p.replace("${localWorkspaceFolder}", w)
        } else {
            p.to_string()
        };
        let joined = lexical_normalize(&config_dir.join(&expanded));
        match joined.strip_prefix(&workspace) {
            Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
            Ok(rel) => match rel.to_str() {
                Some(s) => s.to_string(),
                None => not_utf8(d),
            },
            Err(_) => {
                let Some(abs) = joined.to_str() else {
                    return not_utf8(d);
                };
                d.action(
                    key,
                    format!(
                        "{p:?} points outside the project; the draft keeps it absolute, which \
                         only works on this machine"
                    ),
                );
                abs.to_string()
            }
        }
    };

    // --- the source -------------------------------------------------------------------
    let mut has_compose = false;
    match (
        virtkit.and_then(|v| v.docker_compose_file.as_deref()),
        &config.docker_compose_file,
    ) {
        (Some(vm), top) => {
            has_compose = true;
            let rel = rebase(&mut d, "customizations.virtkit.dockerComposeFile", vm);
            d.set("compose", rel);
            let mut note = "from customizations.virtkit.dockerComposeFile".to_string();
            let docker = match top {
                Some(OneOrMany::One(one)) if one != vm => Some(one.clone()),
                Some(OneOrMany::Many(files)) => Some(files.join(", ")),
                _ => None,
            };
            if let Some(docker) = docker {
                note.push_str(&format!(
                    "; the Docker devcontainer's {docker:?} was not taken — the editors keep \
                     reading it from devcontainer.json"
                ));
            }
            d.translated("compose", note);
        }
        (None, Some(OneOrMany::One(f))) => {
            has_compose = true;
            let rel = rebase(&mut d, "dockerComposeFile", f);
            d.set("compose", rel);
            d.action(
                "compose",
                "taken from dockerComposeFile as written; if the VM LAN is described by a \
                 different compose file than the Docker devcontainer's, point `compose` and \
                 `service` at it",
            );
        }
        (None, Some(OneOrMany::Many(files))) => {
            has_compose = true;
            let shown: Vec<String> = files
                .iter()
                .map(|f| rebase(&mut d, "dockerComposeFile", f))
                .collect();
            d.commented(
                "compose",
                format!("{:?}", shown.first().cloned().unwrap_or_default()),
            );
            d.essential(
                "dockerComposeFile",
                format!(
                    "lists {} files ({}); vk reads one — resolve them into one \
                     (`docker compose config`) or name the one that is the LAN",
                    files.len(),
                    shown.join(", ")
                ),
            );
        }
        (None, None) => {}
    }
    if has_compose {
        match virtkit
            .and_then(|v| v.service.clone())
            .or_else(|| config.service.clone())
        {
            Some(s) => {
                d.set("service", s);
                d.translated("service", "");
            }
            None => {
                d.commented("service", "\"\"");
                d.essential("service", "which compose service is the one you work in");
            }
        }
        if let Some(rs) = &config.run_services {
            d.action(
                "runServices",
                format!(
                    "{rs:?}: compose's dependency closure and `profiles` decide what starts; \
                     list profiled services' profiles under `profiles`"
                ),
            );
        }
    }
    if let Some(image) = &config.image {
        match image.as_str() {
            Some(i) if !has_compose => {
                d.set("image", i);
                d.translated("image", "");
            }
            Some(_) => d.action("image", "ignored beside a compose source"),
            None => d.action("image", format!("{image}: expected a string")),
        }
    }
    // `build` (object) and the legacy top-level `dockerFile` + `context` say the same thing.
    let build_obj = config.build.as_ref().and_then(|b| b.as_object());
    let dockerfile = build_obj
        .and_then(|b| b.get("dockerfile"))
        .or(config.docker_file.as_ref())
        .and_then(|v| v.as_str());
    if let Some(df) = dockerfile {
        if has_compose || config.image.is_some() {
            d.action("build", "ignored beside another source");
        } else {
            let context = build_obj
                .and_then(|b| b.get("context"))
                .and_then(|v| v.as_str())
                .unwrap_or(".");
            let context_rel = rebase(&mut d, "build.context", context);
            // The Dockerfile is relative to the context in the draft, to the config file in
            // the source; both are relative to the workspace by now.
            let df_rel = rebase(&mut d, "build.dockerfile", df);
            let df_in_context = match Path::new(&df_rel).strip_prefix(&context_rel) {
                // rel is a suffix of df_rel, itself a String, so it is UTF-8.
                Ok(rel) => rel.to_str().unwrap_or(&df_rel).to_string(),
                // "." is the workspace root, under which every workspace-relative path lies.
                Err(_) if context_rel == "." => df_rel.clone(),
                Err(_) => {
                    d.action(
                        "build.dockerfile",
                        format!(
                            "{df_rel:?} is outside the build context {context_rel:?}; the draft \
                             reads `dockerfile` relative to `context`, so set it by hand"
                        ),
                    );
                    df_rel.clone()
                }
            };
            let mut table = toml::Table::new();
            table.insert("context".into(), context_rel.clone().into());
            table.insert("dockerfile".into(), df_in_context.clone().into());
            let target = build_obj
                .and_then(|b| b.get("target"))
                .and_then(|v| v.as_str());
            match target {
                Some(t) => {
                    table.insert("target".into(), t.into());
                }
                // Count the stages only for a Dockerfile that resolved inside the workspace:
                // rebase returns an absolute path for one that escaped (already reported), and
                // reading a host path an untrusted repo chose would follow it anywhere or block
                // on a fifo. `read_regular` also rejects a symlink and a non-regular file.
                None if !Path::new(&df_rel).is_absolute() => {
                    let path = workspace.join(&df_rel);
                    // Both `Result`s are discarded to `None`, which the arm below reports as
                    // "could not read … to count its stages" — `target` is left to the reader.
                    match crate::dev::config::read_regular(&path)
                        .ok()
                        .flatten()
                        .and_then(|src| crate::build::dockerfile_stages(&src).ok())
                    {
                        Some(stages) if stages.len() > 1 => {
                            table.insert("target".into(), "".into());
                            d.essential(
                                "build.target",
                                format!(
                                    "{df_in_context} has {} named stages ({}); say which \
                                     one is the development environment rather than taking \
                                     the last",
                                    stages.len(),
                                    stages.join(", ")
                                ),
                            );
                        }
                        Some(_) => {}
                        None => d.action(
                            "build.target",
                            format!(
                                "could not read {} to count its stages; set `target` if it \
                                 has more than one",
                                path.display()
                            ),
                        ),
                    }
                }
                None => {}
            }
            // Copy literal args into `[dev.build.args]`; report unresolved devcontainer
            // `${…}` variables.
            let mut deferred_args = Vec::new();
            if let Some(args) = build_obj
                .and_then(|b| b.get("args"))
                .and_then(|a| a.as_object())
            {
                let mut carried = toml::Table::new();
                for (name, value) in args {
                    match value.as_str() {
                        Some(v) if !v.contains("${") => {
                            carried.insert(name.clone(), v.to_string().into());
                        }
                        _ => deferred_args.push(name.clone()),
                    }
                }
                if !carried.is_empty() {
                    table.insert("args".into(), toml::Value::Table(carried));
                }
            }
            d.set("build", toml::Value::Table(table));
            d.translated("build", "");
            if !deferred_args.is_empty() {
                d.action(
                    "build.args",
                    format!(
                        "{deferred_args:?} carry devcontainer variables; set them by hand under \
                         `build.args`"
                    ),
                );
            }
            for key in ["options", "cacheFrom"] {
                if build_obj.is_some_and(|b| b.contains_key(key)) {
                    d.omitted(&format!("build.{key}"), "docker build options");
                }
            }
        }
    } else if let Some(b) = &config.build {
        d.action(
            "build",
            format!("{b}: expected an object with `dockerfile`"),
        );
    }
    if !has_compose && config.image.is_none() && dockerfile.is_none() {
        d.commented("image", "\"docker.io/library/debian:13\"");
        d.essential(
            "source",
            "the file names no dockerComposeFile, image or build; set one of compose, image \
             or build",
        );
    }

    // --- being in it ------------------------------------------------------------------
    let vars = |d: &mut Draft, key: &str, s: &str| {
        rewrite_vars(d, key, s, config.workspace_folder.as_deref())
    };
    if let Some(w) = &config.workspace_folder {
        let w = vars(&mut d, "workspaceFolder", w);
        d.set("workspace", w);
        d.translated("workspaceFolder", "as `workspace`");
    } else if !has_compose {
        d.set("workspace", "/workspace");
        d.action(
            "workspace",
            "no workspaceFolder: the checkout is mounted at /workspace; change it if the image \
             expects another path",
        );
    }
    if config.workspace_mount.is_some() {
        d.action(
            "workspaceMount",
            "the checkout is mounted at `workspace`; a compose service declares its own \
             volumes",
        );
    }
    if let Some(u) = &config.remote_user {
        d.set("user", u.clone());
        d.translated("remoteUser", "as `user`");
    }
    if config.container_user.is_some() {
        d.action(
            "containerUser",
            "the image's own processes run as the image says; `user` is who sessions run as",
        );
    }
    if config.update_remote_user_uid.is_some() {
        d.action(
            "updateRemoteUserUID",
            "build the image's user with the host ids: compose `build.args` from `${VK_UID}` \
             and `${VK_GID}`",
        );
    }
    d.set("freshness", "ask");
    if let Some(v) = virtkit {
        if let Some(c) = &v.cpus {
            // Match `cpus`'s `u32` type to report negative or oversized counts during import.
            let set = match c.as_str() {
                "host" => {
                    d.set("cpus", "host");
                    true
                }
                n => match n.parse::<u32>() {
                    Ok(n) => {
                        d.set("cpus", i64::from(n));
                        true
                    }
                    Err(_) => {
                        d.action(
                            "customizations.virtkit.cpus",
                            format!("{c:?} is not a vCPU count"),
                        );
                        false
                    }
                },
            };
            if set {
                d.translated("customizations.virtkit.cpus", "as `cpus`");
            }
        }
        if let Some(m) = &v.mem {
            d.set("mem", m.clone());
            d.translated("customizations.virtkit.mem", "as `mem`");
        }
        if !v.profiles.is_empty() {
            d.set(
                "profiles",
                toml::Value::Array(v.profiles.iter().map(|p| p.clone().into()).collect()),
            );
            d.translated("customizations.virtkit.profiles", "as `profiles`");
        }
        if v.state_dir.is_some() {
            d.omitted(
                "customizations.virtkit.stateDir",
                "state is derived per workspace and environment",
            );
        }
        if v.git_worktree_mount {
            d.omitted(
                "customizations.virtkit.gitWorktreeMount",
                "a linked worktree's Git directory is mounted automatically",
            );
        }
        if let Some(a) = &v.local_user_build_args {
            d.action(
                "customizations.virtkit.localUserBuildArgs",
                format!(
                    "declare them in the compose service's build.args: {} from `${{VK_UID}}`, \
                     {} from `${{VK_GID}}`",
                    a.uid.join(", "),
                    a.gid.join(", ")
                ),
            );
        }
    }

    for (key, table, env) in [
        ("remoteEnv", "exec-env", &config.remote_env),
        ("containerEnv", "container-env", &config.container_env),
    ] {
        if let Some(env) = env
            && !env.is_empty()
        {
            d.section(&["dev", table]);
            for (name, value) in env {
                let value = vars(&mut d, key, value);
                d.set(name, value);
            }
            d.translated(key, format!("{} variable(s) as `{table}`", env.len()));
        }
    }

    let mut mount_names = std::collections::BTreeSet::new();
    for (i, m) in config.mounts.iter().flatten().enumerate() {
        let key = format!("mounts[{i}]");
        let (kind, source, target, read_only) = match mount_fields(m) {
            Ok(f) => f,
            Err(e) => {
                d.action(&key, format!("{e:#}"));
                continue;
            }
        };
        if kind != "bind" {
            d.action(&key, format!("type {kind:?}: only host paths are mounted"));
            continue;
        }
        let mut name = Path::new(&target)
            .file_name()
            .map(|n| {
                n.to_str()
                    .unwrap_or_default()
                    .trim_start_matches('.')
                    .to_string()
            })
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("mount{i}"));
        name = name
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        // The index is this mount's own, so one suffix is enough to tell two apart.
        if !mount_names.insert(name.clone()) {
            name = format!("{name}-{i}");
            mount_names.insert(name.clone());
        }
        let source = vars(&mut d, &key, &source);
        let target = vars(&mut d, &key, &target);
        d.section(&["dev", "mounts", &name]);
        d.set("source", source);
        d.set("to", target);
        if read_only {
            d.set("read-only", true);
        }
        d.translated(&key, format!("as `mounts.{name}`"));
    }

    if let Some(ports) = &config.forward_ports {
        let mut endpoint_names = std::collections::BTreeSet::new();
        for (i, p) in ports.iter().enumerate() {
            let (service, port): (Option<String>, u16) = match p {
                Port::Number(n) => match u16::try_from(*n) {
                    Ok(p) => (None, p),
                    Err(_) => {
                        d.action("forwardPorts", format!("{n}: a port is 0-65535"));
                        continue;
                    }
                },
                // `service:port`, or a bare port as a string (both valid in the spec).
                Port::Named(s) => {
                    let (host, num) = match s.rsplit_once(':') {
                        Some((h, p)) => (Some(h), p),
                        None => (None, s.as_str()),
                    };
                    match num.parse::<u16>() {
                        Ok(p) => (host.map(str::to_string), p),
                        Err(_) => {
                            d.action(
                                "forwardPorts",
                                format!("{s:?}: expected a port or service:port"),
                            );
                            continue;
                        }
                    }
                }
            };
            let mut name = match &service {
                Some(s) => format!("{s}-{port}"),
                None => format!("port-{port}"),
            };
            // Two entries can name the same endpoint (e.g. `3000` and `"3000"`); the index
            // is this entry's own, so one suffix keeps the sections from colliding into a
            // duplicate `target` key that would not parse.
            if !endpoint_names.insert(name.clone()) {
                name = format!("{name}-{i}");
                endpoint_names.insert(name.clone());
            }
            d.section(&["dev", "endpoints", &name]);
            if let Some(s) = &service {
                if !has_compose {
                    d.action(
                        "forwardPorts",
                        format!("{s}:{port} names a service, and there is no compose source"),
                    );
                }
                d.set("service", s.clone());
            }
            // `host-port` defaults to the target, which is what a forwarded port asks for.
            d.set("target", i64::from(port));
            d.translated(
                "forwardPorts",
                format!(
                    "{} as `endpoints.{name}`",
                    match &service {
                        Some(s) => format!("{s}:{port}"),
                        None => port.to_string(),
                    }
                ),
            );
        }
    }
    if config.app_port.is_some() {
        d.action("appPort", "publish it as an endpoint");
    }
    for (key, present) in [
        ("portsAttributes", config.ports_attributes.is_some()),
        (
            "otherPortsAttributes",
            config.other_ports_attributes.is_some(),
        ),
    ] {
        if present {
            d.omitted(
                key,
                "editor port labels; `scheme` and `path` on an endpoint serve `vk dev open`",
            );
        }
    }

    let hooks = [
        ("initializeCommand", "init", &config.initialize_command),
        ("postCreateCommand", "create", &config.post_create_command),
        ("postStartCommand", "start", &config.post_start_command),
    ];
    if hooks.iter().any(|(_, _, h)| h.is_some()) {
        d.section(&["dev", "hooks"]);
        for (key, name, hook) in hooks {
            if let Some(h) = hook {
                d.set(name, lifecycle_value(h));
                d.translated(key, format!("as `hooks.{name}`"));
            }
        }
    }
    for (key, present, note) in [
        (
            "onCreateCommand",
            config.on_create_command.is_some(),
            "fold it into `hooks.create`, which runs once per environment generation",
        ),
        (
            "updateContentCommand",
            config.update_content_command.is_some(),
            "fold it into `hooks.create`",
        ),
        (
            "postAttachCommand",
            config.post_attach_command.is_some(),
            "there is no attach hook; editor work belongs in `editor.vscode.reconcile`",
        ),
    ] {
        if present {
            d.action(key, note);
        }
    }
    if config.wait_for.is_some() {
        d.omitted("waitFor", "the hook order is fixed");
    }
    if config.features.is_some() {
        d.essential(
            "features",
            "Dev Container Features are not installed by vk; bake them into the image or \
             Dockerfile the environment boots from",
        );
    }
    if config.override_command.is_some() {
        d.action(
            "overrideCommand",
            "a compose service keeps the VM alive with `command: sleep infinity`",
        );
    }
    if config.host_requirements.is_some() {
        d.action(
            "hostRequirements",
            "set `cpus` and `mem` if the guest needs them",
        );
    }
    for (key, present) in [
        ("shutdownAction", config.shutdown_action.is_some()),
        ("privileged", config.privileged.is_some()),
        ("init", config.init.is_some()),
        ("capAdd", config.cap_add.is_some()),
        ("securityOpt", config.security_opt.is_some()),
        ("userEnvProbe", config.user_env_probe.is_some()),
    ] {
        if present {
            d.omitted(key, "a docker setting with no meaning for a microVM");
        }
    }
    if config.run_args.is_some() {
        d.action(
            "runArgs",
            "mostly docker flags without a microVM meaning, but `--gpus`, `--shm-size` and \
             `--device` do; carry those over by hand",
        );
    }
    if config.name.is_some() {
        d.omitted("name", "a display name");
    }

    // --- the editor and the host --------------------------------------------------------
    if let Some(c) = &config.customizations {
        let vscode = c.others.get("vscode");
        if let Some(vs) = vscode.and_then(|v| v.as_object()) {
            d.section(&["dev", "editor", "vscode"]);
            d.set("state", "persistent");
            if let Some(ext) = vs.get("extensions").and_then(|e| e.as_array()) {
                let list: Vec<toml::Value> = ext
                    .iter()
                    .filter_map(|e| e.as_str().map(|s| s.to_string().into()))
                    .collect();
                // Count imported strings; non-string entries are filtered out.
                let n = list.len();
                d.set("extensions", toml::Value::Array(list));
                d.translated(
                    "customizations.vscode.extensions",
                    format!("{n} as `editor.vscode.extensions`"),
                );
            }
            if let Some(settings) = vs.get("settings").and_then(|s| s.as_object()) {
                d.section(&["dev", "editor", "vscode", "settings"]);
                let mut n = 0;
                for (k, v) in settings {
                    match json_to_toml(v) {
                        Some(v) => {
                            d.set(k, v);
                            n += 1;
                        }
                        None => d.omitted(
                            &format!("customizations.vscode.settings.{k}"),
                            "null has no TOML spelling",
                        ),
                    }
                }
                d.translated(
                    "customizations.vscode.settings",
                    format!("{n} as `editor.vscode.settings`"),
                );
            }
            for k in vs
                .keys()
                .filter(|k| !matches!(k.as_str(), "extensions" | "settings"))
            {
                d.omitted(&format!("customizations.vscode.{k}"), "");
            }
        } else if let Some(v) = vscode {
            d.action("customizations.vscode", format!("{v}: expected an object"));
        }
        for k in c.others.keys().filter(|k| k.as_str() != "vscode") {
            d.omitted(&format!("customizations.{k}"), "another tool's settings");
        }
    }
    if let Some(h) = virtkit.and_then(|v| v.host_exec.as_ref()) {
        let rel = rebase(
            &mut d,
            "customizations.virtkit.hostExec.wrapper",
            &h.wrapper,
        );
        d.section(&["dev", "host"]);
        d.set("wrapper", rel);
        if !h.env.is_empty() {
            d.set(
                "wrapper-env",
                toml::Value::Array(h.env.iter().map(|e| e.clone().into()).collect()),
            );
        }
        d.translated("customizations.virtkit.hostExec", "as `host.wrapper`");
        d.action(
            "host.wrapper",
            "if the wrapper only launches Git GUIs, `git-gui = true` replaces it",
        );
    }
    if let Some(cache) = virtkit.and_then(|v| v.cache.as_ref()) {
        d.section(&["dev", "cache"]);
        if let Some(r) = &cache.registry {
            d.set("registry", r.clone());
        }
        if cache.insecure {
            d.set("insecure", true);
        }
        d.translated("customizations.virtkit.cache", "as `cache`");
    }
    Ok(d)
}

/// Rewrite devcontainer variables for the draft; report those with no equivalent.
fn rewrite_vars(
    d: &mut crate::dev::config::Draft,
    key: &str,
    s: &str,
    workspace_folder: Option<&str>,
) -> String {
    let mut out = s.replace("${localWorkspaceFolder}", "${workspace}");
    if out.contains("${containerWorkspaceFolder}") {
        match workspace_folder {
            Some(w) => out = out.replace("${containerWorkspaceFolder}", w),
            None => d.action(
                key,
                "${containerWorkspaceFolder} has no value without workspaceFolder",
            ),
        }
    }
    for name in [
        "localWorkspaceFolderBasename",
        "containerWorkspaceFolderBasename",
        "devcontainerId",
    ] {
        if out.contains(&format!("${{{name}}}")) {
            d.action(
                key,
                format!("${{{name}}} has no equivalent; replace it by hand"),
            );
        }
    }
    // `${containerEnv:NAME}` (common in remoteEnv) has no spelling here and config.rs rejects
    // any `${…}` it does not expand; report it rather than pass it through to that error.
    if out.contains("${containerEnv:") {
        d.action(
            key,
            "${containerEnv:…} has no equivalent; replace it by hand",
        );
    }
    out
}

/// A mount's fields in either spelling.
fn mount_fields(m: &Mount) -> Result<(String, String, String, bool)> {
    Ok(match m {
        Mount::Obj(o) => (
            o.kind.clone().unwrap_or_else(|| "bind".into()),
            o.source.clone(),
            o.target.clone(),
            o.readonly,
        ),
        Mount::Str(s) => {
            let (mut kind, mut source, mut target, mut read_only) =
                (String::from("bind"), String::new(), String::new(), false);
            for field in s.split(',') {
                match field.split_once('=') {
                    Some(("type", v)) => kind = v.to_string(),
                    Some(("source" | "src", v)) => source = v.to_string(),
                    Some(("target" | "dst" | "destination", v)) => target = v.to_string(),
                    Some(("consistency", _)) => {}
                    Some((other, _)) => bail!("mount {s:?}: unsupported option {other:?}"),
                    None if field == "readonly" || field == "ro" => read_only = true,
                    None if field.is_empty() => {}
                    None => bail!("mount {s:?}: expected key=value, got {field:?}"),
                }
            }
            if source.is_empty() || target.is_empty() {
                bail!("mount {s:?} needs both a source and a target");
            }
            (kind, source, target, read_only)
        }
    })
}

/// A lifecycle command as the draft's hook value: a string, an array, or a table of them.
fn lifecycle_value(l: &Lifecycle) -> toml::Value {
    match l {
        Lifecycle::Shell(s) => s.clone().into(),
        Lifecycle::Argv(a) => toml::Value::Array(a.iter().map(|s| s.clone().into()).collect()),
        Lifecycle::Parallel(map) => {
            let mut t = toml::Table::new();
            for (k, v) in map {
                t.insert(k.clone(), lifecycle_value(v));
            }
            toml::Value::Table(t)
        }
    }
}

/// JSON as TOML, where TOML has a spelling for it. `None` for `null`, which it does not.
fn json_to_toml(v: &serde_json::Value) -> Option<toml::Value> {
    Some(match v {
        serde_json::Value::Null => return None,
        serde_json::Value::Bool(b) => (*b).into(),
        serde_json::Value::Number(n) => match (n.as_i64(), n.as_f64()) {
            (Some(i), _) => i.into(),
            (None, Some(f)) => f.into(),
            _ => return None,
        },
        serde_json::Value::String(s) => s.clone().into(),
        serde_json::Value::Array(a) => {
            toml::Value::Array(a.iter().filter_map(json_to_toml).collect())
        }
        serde_json::Value::Object(o) => {
            let mut t = toml::Table::new();
            for (k, v) in o {
                if let Some(v) = json_to_toml(v) {
                    t.insert(k.clone(), v);
                }
            }
            toml::Value::Table(t)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_are_stripped_without_moving_anything_else() {
        let text = r#"{
  // a line comment
  "name": "x", /* and a block one */
  "service": "dev", // trailing
  /* multi
     line */
  "workspaceFolder": "/a//b"   // not a comment inside the string
}"#;
        let stripped = strip_comments(text);
        assert_eq!(stripped.len(), text.len(), "byte offsets must not move");
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(v["name"], "x");
        assert_eq!(v["workspaceFolder"], "/a//b");
        // A `//` inside a string is content, not a comment.
        assert!(stripped.contains("/a//b"));
    }

    #[test]
    fn a_comment_in_any_alphabet_leaves_every_offset_where_it_was() {
        let text = "{\n  // caf\u{e9} \u{2014} \u{4e2d}\u{6587}\n  \"service\": \"dev\", /* \u{e9}\u{e9} */\n  \"name\": \"x\"\n}";
        let stripped = strip_comments(text);
        assert_eq!(stripped.len(), text.len(), "byte offsets must not move");
        assert_eq!(
            stripped.lines().count(),
            text.lines().count(),
            "and neither may the lines"
        );
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(v["service"], "dev");
    }

    #[test]
    fn an_unsupported_key_is_reported_where_it_is() {
        let err = parse_for_import("{\n  \"service\": \"dev\",\n  \"nonsense\": 1\n}").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nonsense") && msg.contains("line 3"), "{msg}");
    }

    #[test]
    fn the_object_mount_form_is_read_whole() {
        let ok = parse_for_import(
            r#"{"image": "x", "mounts": [
                {"type": "bind", "source": "/a", "target": "/b", "readonly": true}]}"#,
        )
        .unwrap();
        let m = &ok.mounts.as_ref().unwrap()[0];
        assert_eq!(
            mount_fields(m).unwrap(),
            ("bind".into(), "/a".into(), "/b".into(), true)
        );
        // A key this module does not know is an error, as everywhere else in the file.
        let err = parse_for_import(
            r#"{"image": "x", "mounts": [{"source": "/a", "target": "/b", "nope": 1}]}"#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("nope"), "{err:#}");
    }

    #[test]
    fn a_trailing_comma_is_accepted_as_jsonc_allows() {
        // VS Code writes trailing commas; a devcontainer file with one must still import.
        let c =
            parse_for_import("{\n  \"dockerComposeFile\": \"c.yaml\",\n  \"service\": \"dev\",\n}")
                .unwrap();
        assert_eq!(c.service.as_deref(), Some("dev"));
        // Also before `]`, and after a comment the stripper already blanked.
        parse_for_import("{\"forwardPorts\": [1, 2, /* last */ ]}").unwrap();
    }

    #[test]
    fn an_unknown_key_is_refused_without_a_wall_of_alternatives() {
        let err =
            parse_for_import(r#"{"dockerComposeFile": "c.yaml", "service": "dev", "nonsense": 1}"#)
                .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("nonsense"), "{msg}");
        assert!(!msg.contains("expected one of"), "too noisy: {msg}");
    }

    #[test]
    fn another_tools_customizations_are_kept_and_ours_is_strict() {
        let ok = parse_for_import(
            r#"{"dockerComposeFile": "c.yaml", "service": "dev",
                "customizations": {"vscode": {"settings": {"a": 1}, "extensions": ["x"]}}}"#,
        )
        .unwrap();
        let c = ok.customizations.unwrap();
        assert!(c.virtkit.is_none());
        assert!(c.others.contains_key("vscode"), "carried for the draft");

        let err = parse_for_import(
            r#"{"dockerComposeFile": "c.yaml", "service": "dev",
                "customizations": {"virtkit": {"mem": "8G", "typo": 1}}}"#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("typo"), "{err:#}");
    }

    #[test]
    fn discovery_prefers_the_directory_form_then_the_dotfile() {
        let dir = std::env::temp_dir().join(format!("vk-dc-discover-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".devcontainer")).unwrap();
        assert!(discover(&dir, None).is_err(), "nothing to find yet");

        std::fs::write(dir.join(".devcontainer.json"), "{}").unwrap();
        assert_eq!(
            discover(&dir, None).unwrap(),
            dir.join(".devcontainer.json")
        );

        let nested = dir.join(".devcontainer/devcontainer.json");
        std::fs::write(&nested, "{}").unwrap();
        assert_eq!(
            discover(&dir, None).unwrap(),
            nested,
            "the directory form wins"
        );

        // An explicit path is used as given, and a missing one is an error rather than a
        // silent fall back to discovery.
        assert_eq!(discover(&dir, Some(&nested)).unwrap(), nested);
        assert!(discover(&dir, Some(&dir.join("nope.json"))).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn paths_normalize_lexically_and_json_becomes_toml() {
        assert_eq!(
            lexical_normalize(Path::new("/w/.devcontainer/../virtkit/./compose.yaml")),
            PathBuf::from("/w/virtkit/compose.yaml")
        );
        assert_eq!(
            lexical_normalize(Path::new("a/../../b")),
            PathBuf::from("../b"),
            "cannot climb above a relative root, so the climb is kept"
        );
        let v: serde_json::Value =
            serde_json::from_str(r#"{"a": 1, "b": [true, null, "s"], "c": null, "d": 1.5}"#)
                .unwrap();
        let t = json_to_toml(&v).unwrap();
        let t = t.as_table().unwrap();
        assert_eq!(t["a"].as_integer(), Some(1));
        assert_eq!(
            t["b"].as_array().unwrap().len(),
            2,
            "null has no TOML spelling"
        );
        assert!(!t.contains_key("c"));
        assert_eq!(t["d"].as_float(), Some(1.5));
    }

    // --- translate --------------------------------------------------------------------

    use crate::dev::config::Fate;

    /// A fresh empty workspace directory, named for the test.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-dc-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Translate `json` as a `.devcontainer.json` at the root of `ws`.
    fn translate_json(json: &str, ws: &Path) -> crate::dev::config::Draft {
        let config = parse_for_import(json).unwrap();
        translate(&config, &ws.join(".devcontainer.json"), ws).unwrap()
    }

    fn translated(d: &crate::dev::config::Draft, key: &str) -> bool {
        d.items
            .iter()
            .any(|i| i.key == key && i.fate == Fate::Translated)
    }

    fn actioned(d: &crate::dev::config::Draft, key: &str) -> bool {
        d.items
            .iter()
            .any(|i| i.key == key && matches!(i.fate, Fate::Action { .. }))
    }

    #[test]
    fn colliding_forward_ports_get_distinct_endpoint_names() {
        let ws = scratch("dup-ports");
        // `3000` and `"3000"` both name `port-3000`; without de-duping they render two
        // `target` keys in one section, which is not valid TOML.
        let d = translate_json(r#"{"image": "x", "forwardPorts": [3000, "3000"]}"#, &ws);
        let rendered = d.render();
        let cfg: toml::Value =
            toml::from_str(&rendered).unwrap_or_else(|e| panic!("{e}\n{rendered}"));
        let endpoints = cfg["dev"]["endpoints"].as_table().unwrap();
        assert_eq!(endpoints.len(), 2, "{rendered}");
        assert_eq!(endpoints["port-3000"]["target"].as_integer(), Some(3000));
        assert_eq!(endpoints["port-3000-1"]["target"].as_integer(), Some(3000));
    }

    #[test]
    fn block_comments_close_on_the_real_terminator() {
        // `/*/` is not a whole comment: the opener's own `*` must not pair with the next `/`.
        // The whole `/*/ "b":2 */` is one comment, so `b` is inside it and drops out.
        let stripped = strip_comments(r#"{"a":1 /*/ "b":2 */ }"#);
        let v: serde_json::Value = serde_json::from_str(&stripped).unwrap();
        assert_eq!(v["a"], 1);
        assert!(v.get("b").is_none(), "b was inside the comment");

        // `/**/` still closes on its own trailing `*/`.
        let stripped = strip_comments(r#"{"a": 1 /**/ }"#);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stripped).unwrap()["a"],
            1
        );

        // A `/* … */` and a bare `*/` inside a string are content, not comments.
        let stripped = strip_comments(r#"{"a": "/* x */ y */ z"}"#);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stripped).unwrap()["a"],
            "/* x */ y */ z"
        );

        // An escaped quote does not end the string, so the `*/` after it stays content.
        let stripped = strip_comments(r#"{"a": "q \" */ r"}"#);
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&stripped).unwrap()["a"],
            "q \" */ r"
        );

        // An unterminated block comment blanks to EOF, so the value never closes.
        let stripped = strip_comments(r#"{"a": /*/ 1 }"#);
        assert!(serde_json::from_str::<serde_json::Value>(&stripped).is_err());
    }

    #[test]
    fn a_leading_bom_is_stripped_before_parsing() {
        let ok = parse_for_import("\u{feff}{\"service\": \"dev\"}").unwrap();
        assert_eq!(ok.service.as_deref(), Some("dev"));
    }

    #[test]
    fn translate_round_trips_a_representative_devcontainer() {
        let ws = scratch("roundtrip");
        let json = r#"{
            "image": "docker.io/library/debian:13",
            "workspaceFolder": "/work",
            "remoteUser": "dev",
            "forwardPorts": [3000, "db:5432"],
            "mounts": [
                "source=/host/cache,target=/cache,type=bind,readonly",
                {"type": "bind", "source": "/host/data", "target": "/data"}
            ],
            "remoteEnv": {"FOO": "bar"},
            "containerEnv": {"TZ": "UTC"},
            "postCreateCommand": "echo hi",
            "customizations": {
                "vscode": {"extensions": ["ms-python.python"], "settings": {"editor.tabSize": 4}},
                "virtkit": {"cpus": "4", "mem": "8G"}
            }
        }"#;
        let d = translate_json(json, &ws);
        let cfg: toml::Value = toml::from_str(&d.render()).unwrap();
        let dev = &cfg["dev"];

        assert_eq!(dev["image"].as_str(), Some("docker.io/library/debian:13"));
        assert_eq!(dev["workspace"].as_str(), Some("/work"));
        assert_eq!(dev["user"].as_str(), Some("dev"));
        assert_eq!(dev["cpus"].as_integer(), Some(4));
        assert_eq!(dev["mem"].as_str(), Some("8G"));
        assert_eq!(
            dev["endpoints"]["port-3000"]["target"].as_integer(),
            Some(3000)
        );
        assert_eq!(
            dev["endpoints"]["db-5432"]["target"].as_integer(),
            Some(5432)
        );
        assert_eq!(dev["endpoints"]["db-5432"]["service"].as_str(), Some("db"));
        assert_eq!(
            dev["mounts"]["cache"]["source"].as_str(),
            Some("/host/cache")
        );
        assert_eq!(dev["mounts"]["cache"]["to"].as_str(), Some("/cache"));
        assert_eq!(dev["mounts"]["cache"]["read-only"].as_bool(), Some(true));
        assert_eq!(dev["mounts"]["data"]["source"].as_str(), Some("/host/data"));
        assert_eq!(dev["mounts"]["data"]["to"].as_str(), Some("/data"));
        assert_eq!(dev["exec-env"]["FOO"].as_str(), Some("bar"));
        assert_eq!(dev["container-env"]["TZ"].as_str(), Some("UTC"));
        assert_eq!(dev["hooks"]["create"].as_str(), Some("echo hi"));
        assert_eq!(
            dev["editor"]["vscode"]["state"].as_str(),
            Some("persistent")
        );
        assert_eq!(
            dev["editor"]["vscode"]["extensions"][0].as_str(),
            Some("ms-python.python")
        );
        assert_eq!(
            dev["editor"]["vscode"]["settings"]["editor.tabSize"].as_integer(),
            Some(4)
        );

        for key in [
            "image",
            "workspaceFolder",
            "remoteUser",
            "mounts[0]",
            "mounts[1]",
            "remoteEnv",
            "containerEnv",
            "postCreateCommand",
            "customizations.vscode.extensions",
            "customizations.vscode.settings",
            "customizations.virtkit.cpus",
            "customizations.virtkit.mem",
        ] {
            assert!(translated(&d, key), "expected {key} translated");
        }
        // A service-qualified port has no compose source to attach to here.
        assert!(
            actioned(&d, "forwardPorts"),
            "db:5432 needs a compose source"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn an_escaping_dockerfile_is_reported_and_never_read() {
        let ws = scratch("escape");
        // A real multi-stage Dockerfile outside the workspace: reading it would set `target`.
        let outside = ws
            .parent()
            .unwrap()
            .join(format!("vk-dc-outside-{}", std::process::id()));
        std::fs::create_dir_all(&outside).unwrap();
        let df = outside.join("Dockerfile");
        std::fs::write(&df, "FROM x AS a\nFROM x AS b\n").unwrap();

        let json = format!(
            r#"{{"build": {{"dockerfile": {:?}}}}}"#,
            df.to_str().unwrap()
        );
        let d = translate_json(&json, &ws);
        let cfg: toml::Value = toml::from_str(&d.render()).unwrap();
        assert!(
            cfg["dev"]["build"].get("target").is_none(),
            "the escaping Dockerfile must not be read to count its stages"
        );
        assert!(
            actioned(&d, "build.dockerfile"),
            "the escape must be reported"
        );
        assert!(
            !d.items.iter().any(|i| i.key == "build.target"),
            "no stage count, so no build.target item"
        );

        // A workspace-relative path that climbs out is reported the same way.
        let json = r#"{"build": {"dockerfile": "../outside/Dockerfile"}}"#;
        let d = translate_json(json, &ws);
        assert!(
            actioned(&d, "build.dockerfile"),
            "a `..` escape must be reported"
        );

        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn literal_build_args_carry_and_variable_ones_are_deferred() {
        let ws = scratch("buildargs");
        let json = r#"{"build": {"dockerfile": "Dockerfile", "target": "dev",
            "args": {"A": "1", "B": "${localWorkspaceFolderBasename}"}}}"#;
        let d = translate_json(json, &ws);
        let cfg: toml::Value = toml::from_str(&d.render()).unwrap();
        let args = &cfg["dev"]["build"]["args"];
        assert_eq!(args["A"].as_str(), Some("1"));
        assert!(args.get("B").is_none(), "a variable arg is not carried");
        let note = d
            .items
            .iter()
            .find(|i| i.key == "build.args")
            .map(|i| i.note.as_str())
            .unwrap_or_default();
        assert!(note.contains('B'), "the deferred arg is named: {note}");
        assert!(
            !note.contains("compose"),
            "no compose reference here: {note}"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_bare_string_port_is_forwarded() {
        let ws = scratch("bareport");
        let d = translate_json(r#"{"image": "x", "forwardPorts": ["3000"]}"#, &ws);
        let cfg: toml::Value = toml::from_str(&d.render()).unwrap();
        assert_eq!(
            cfg["dev"]["endpoints"]["port-3000"]["target"].as_integer(),
            Some(3000)
        );
        assert!(translated(&d, "forwardPorts"));
        assert!(!actioned(&d, "forwardPorts"));
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn an_out_of_range_port_parses_then_is_reported() {
        // The whole-file parse must survive an out-of-range integer.
        let config = parse_for_import(r#"{"image": "x", "forwardPorts": [70000, -1]}"#).unwrap();
        let ws = scratch("rangeport");
        let d = translate(&config, &ws.join(".devcontainer.json"), &ws).unwrap();
        assert!(
            actioned(&d, "forwardPorts"),
            "70000 and -1 are out of range"
        );
        let cfg: toml::Value = toml::from_str(&d.render()).unwrap();
        assert!(
            cfg["dev"].get("endpoints").is_none(),
            "neither out-of-range port becomes an endpoint"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_non_object_vscode_is_reported() {
        let ws = scratch("vscode");
        let d = translate_json(
            r#"{"image": "x", "customizations": {"vscode": "oops"}}"#,
            &ws,
        );
        assert!(
            actioned(&d, "customizations.vscode"),
            "a string vscode is not an object"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }

    #[test]
    fn a_containerenv_variable_is_reported() {
        let ws = scratch("containerenv");
        let d = translate_json(
            r#"{"image": "x", "remoteEnv": {"P": "${containerEnv:PATH}"}}"#,
            &ws,
        );
        assert!(
            actioned(&d, "remoteEnv"),
            "containerEnv var has no equivalent"
        );
        let _ = std::fs::remove_dir_all(&ws);
    }
}
