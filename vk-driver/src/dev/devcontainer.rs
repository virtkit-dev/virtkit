//! `devcontainer.json`, read for `vk dev init --from devcontainer`.
//!
//! A devcontainer file already describes an environment: which compose file, which service
//! is the one you work in, what it mounts, who you are inside it. `vk dev` does not run from
//! it — `.virtkit/config.toml` is the runtime input — but a project that has one should not
//! have to describe itself twice by hand, so the file is read once, as data, and translated
//! into a first config with a report of what did not carry over.
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

/// serde_json's message for an unknown key lists every field of the struct, including the
/// ones only declared so their rejection can explain itself. Keep the location and the
/// offending key, drop the list — which is where serde_json puts ` at line N column M`, so
/// the location is taken back off the tail.
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

/// Remove `//` and `/* */` comments, preserving everything inside strings and keeping every
/// byte offset and line break where it was — a comment becomes as many spaces as it had
/// bytes — so serde_json's line and column still point at the right place in the user's
/// file, whatever the comment was written in.
fn strip_comments(text: &str) -> String {
    /// A character as the blanks that stand for it: one per byte, a newline for a newline.
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
            // The second `/` or `*` is consumed by the loop that blanks the comment out.
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

    // --- recognized, reported rather than carried -------------------------------------
    // Declared so the report can name the key and what to do about it, rather than failing
    // on an unknown field. Kept in spec order-ish; each is explained in `translate`.
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
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Port {
    Number(u16),
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
/// project that adopted it is translated rather than stranded.
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

/// Parse the JSON-with-comments the spec allows. Trailing commas are *not* accepted: they
/// are not in the spec, and a config vk reads differently from the editor would be worse
/// than one it refuses.
pub fn parse_for_import(text: &str) -> Result<Config> {
    let stripped = strip_comments(text);
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
        let expanded = p.replace("${localWorkspaceFolder}", &workspace.to_string_lossy());
        let joined = config_dir.join(&expanded);
        match lexical_normalize(&joined).strip_prefix(&workspace) {
            Ok(rel) if rel.as_os_str().is_empty() => ".".to_string(),
            Ok(rel) => rel.to_string_lossy().to_string(),
            Err(_) => {
                d.action(
                    key,
                    format!(
                        "{p:?} points outside the project; the draft keeps it absolute, which \
                         only works on this machine"
                    ),
                );
                lexical_normalize(&joined).to_string_lossy().to_string()
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
            let df_in_context = Path::new(&df_rel)
                .strip_prefix(&context_rel)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| {
                    Path::new(&df_rel)
                        .strip_prefix(".")
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or(df_rel.clone())
                });
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
                None => {
                    let path = workspace.join(&df_rel);
                    match std::fs::read_to_string(&path)
                        .ok()
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
            }
            d.set("build", toml::Value::Table(table));
            d.translated("build", "");
            if let Some(args) = build_obj.and_then(|b| b.get("args")) {
                d.action(
                    "build.args",
                    format!(
                        "{args}: build arguments belong to a compose service's `build.args`, \
                         where `${{VK_UID}}` and `${{VK_GID}}` are available"
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
            match c.as_str() {
                "host" => d.set("cpus", "host"),
                n => match n.parse::<i64>() {
                    Ok(n) => d.set("cpus", n),
                    Err(_) => d.action(
                        "customizations.virtkit.cpus",
                        format!("{c:?} is not a count"),
                    ),
                },
            }
            d.translated("customizations.virtkit.cpus", "as `cpus`");
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
            .map(|n| n.to_string_lossy().trim_start_matches('.').to_string())
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
        for p in ports {
            let (service, port) = match p {
                Port::Number(n) => (None, *n),
                Port::Named(s) => match s
                    .rsplit_once(':')
                    .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p)))
                {
                    Some((h, p)) => (Some(h.to_string()), p),
                    None => {
                        d.action(
                            "forwardPorts",
                            format!("{s:?}: expected a port or service:port"),
                        );
                        continue;
                    }
                },
            };
            let name = match &service {
                Some(s) => format!("{s}-{port}"),
                None => format!("port-{port}"),
            };
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
        ("runArgs", config.run_args.is_some()),
        ("userEnvProbe", config.user_env_probe.is_some()),
    ] {
        if present {
            d.omitted(key, "a docker setting with no meaning for a microVM");
        }
    }
    if config.name.is_some() {
        d.omitted("name", "a display name");
    }

    // --- the editor and the host --------------------------------------------------------
    if let Some(c) = &config.customizations {
        if let Some(vs) = c.others.get("vscode").and_then(|v| v.as_object()) {
            d.section(&["dev", "editor", "vscode"]);
            d.set("state", "persistent");
            if let Some(ext) = vs.get("extensions").and_then(|e| e.as_array()) {
                let list: Vec<toml::Value> = ext
                    .iter()
                    .filter_map(|e| e.as_str().map(|s| s.to_string().into()))
                    .collect();
                d.set("extensions", toml::Value::Array(list));
                d.translated(
                    "customizations.vscode.extensions",
                    format!("{} as `editor.vscode.extensions`", ext.len()),
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

/// The devcontainer variables a draft spells differently, rewritten; the ones with no
/// spelling reported.
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
    fn a_trailing_comma_is_refused_rather_than_guessed_at() {
        let err =
            parse_for_import("{\n  \"dockerComposeFile\": \"c.yaml\",\n  \"service\": \"dev\",\n}")
                .unwrap_err();
        assert!(format!("{err:#}").contains("trailing"), "{err:#}");
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
}
