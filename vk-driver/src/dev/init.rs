//! `vk dev init`: a project's first `.virtkit/config.toml`, from what the project already
//! has — a `devcontainer.json`, a compose file, a Dockerfile — or from a stock image.
//!
//! Import is data conversion. Nothing here executes a hook, downloads a tool or boots a VM:
//! the source is read, a draft is written, and a report says what was carried over, what a
//! person must still decide, and what was left out. A draft missing an essential choice —
//! which compose service, which Dockerfile stage — is still written, for the reader to
//! finish, but the command exits unsuccessfully so a script does not take it for done.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::dev::config::Draft;

/// Where `vk dev init` reads from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Source {
    /// `.devcontainer/devcontainer.json` or `.devcontainer.json`
    Devcontainer,
    /// a compose file at the project root
    Compose,
    /// a Dockerfile at the project root
    Dockerfile,
    /// an image named with `--image`
    Image,
}

pub struct Opts {
    pub from: Option<Source>,
    pub image: Option<String>,
    pub force: bool,
}

/// What `init` did, and whether the result can be used as it stands.
#[derive(Debug)]
pub struct Outcome {
    pub report: String,
    pub ok: bool,
}

/// The compose file names looked for at the project root, in docker's own order.
const COMPOSE_FILES: [&str; 4] = [
    "compose.yaml",
    "compose.yml",
    "docker-compose.yaml",
    "docker-compose.yml",
];

/// Run `init` for a caller in `from`. The project is the checkout the caller is in, so an
/// `init` from a subdirectory writes at the root rather than starting a second project
/// halfway down.
pub fn run(from: &Path, opts: &Opts) -> Result<Outcome> {
    let existing = crate::dev::config::discover_here(from)?;
    let workspace = match &existing {
        Some(files) => files.workspace.clone(),
        None => crate::dev::config::worktree_root(from).unwrap_or_else(|| from.to_path_buf()),
    };
    if opts.from == Some(Source::Image) && opts.image.is_none() {
        bail!("--from image needs --image REF");
    }
    if opts.image.is_some() && !matches!(opts.from, None | Some(Source::Image)) {
        bail!("--image only goes with --from image");
    }
    // An existing config is validated, not replaced: what it says is what the project
    // means, and a translation would only be an older idea of it.
    if let Some(files) = existing
        && !opts.force
        && opts.from.is_none()
        && opts.image.is_none()
    {
        let loaded = crate::dev::config::load(files)?;
        return Ok(Outcome {
            report: loaded.describe(),
            ok: true,
        });
    }

    let source = match opts.from {
        Some(s) => s,
        None if opts.image.is_some() => Source::Image,
        None => match detect(&workspace) {
            Some(s) => s,
            None => {
                let path = crate::dev::config::write_template(&workspace, opts.force)?;
                return Ok(Outcome {
                    report: format!("wrote {} — edit it, then `vk dev shell`\n", path.display()),
                    ok: true,
                });
            }
        },
    };
    let (draft, read) = match source {
        Source::Devcontainer => {
            let path = crate::dev::devcontainer::discover(&workspace, None)?;
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            let config = crate::dev::devcontainer::parse_for_import(&text)
                .with_context(|| format!("in {}", path.display()))?;
            (
                crate::dev::devcontainer::translate(&config, &path, &workspace)?,
                path,
            )
        }
        Source::Compose => {
            let path = COMPOSE_FILES
                .iter()
                .map(|n| workspace.join(n))
                .find(|p| p.is_file())
                .with_context(|| {
                    format!(
                        "no compose file in {} (looked for {})",
                        workspace.display(),
                        COMPOSE_FILES.join(", ")
                    )
                })?;
            (from_compose(&path, &workspace)?, path)
        }
        Source::Dockerfile => {
            let path = workspace.join("Dockerfile");
            if !path.is_file() {
                bail!("no Dockerfile in {}", workspace.display());
            }
            (from_dockerfile(&path)?, path)
        }
        Source::Image => {
            let image = opts
                .image
                .as_deref()
                .context("--from image needs --image REF")?;
            (from_image(image), PathBuf::from(image))
        }
    };

    let path = crate::dev::config::write_config(&workspace, &draft.render(), opts.force)?;
    let mut report = format!("wrote {} from {}\n", path.display(), read.display());
    report.push_str(&draft.report());
    let mut ok = !draft.needs_work();
    // The draft is read back the way every other command reads it, so the report says now
    // what the first `vk dev shell` would otherwise say later.
    match crate::dev::config::discover(&workspace, None, None).and_then(crate::dev::config::load) {
        Ok(_) if ok => report.push_str("the config validates — `vk dev shell` boots it\n"),
        Ok(_) => report.push_str("finish the items above before the first `vk dev shell`\n"),
        Err(e) => {
            ok = false;
            report.push_str(&format!("the draft does not validate yet: {e:#}\n"));
        }
    }
    Ok(Outcome { report, ok })
}

/// What the project has, in the order the design fixes: a devcontainer, a compose file, a
/// Dockerfile.
fn detect(workspace: &Path) -> Option<Source> {
    if crate::dev::devcontainer::discover(workspace, None).is_ok() {
        return Some(Source::Devcontainer);
    }
    if COMPOSE_FILES.iter().any(|n| workspace.join(n).is_file()) {
        return Some(Source::Compose);
    }
    if workspace.join("Dockerfile").is_file() {
        return Some(Source::Dockerfile);
    }
    None
}

/// A compose file: the LAN is described; which service is the one you work in is not,
/// unless there is only one.
fn from_compose(path: &Path, workspace: &Path) -> Result<Draft> {
    let rel = path
        .strip_prefix(workspace)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string();
    let mut d = Draft::default();
    d.preamble(&rel);
    d.set("compose", rel.clone());
    d.translated("compose", rel.clone());
    match service_names(path) {
        Ok(names) if names.len() == 1 => {
            let only = names.into_iter().next().unwrap_or_default();
            d.set("service", only.clone());
            d.translated("service", format!("{only}, the only one"));
        }
        Ok(names) => {
            d.commented("service", "\"\"");
            d.essential(
                "service",
                format!("which of {} is the one you work in", names.join(", ")),
            );
        }
        Err(e) => {
            d.commented("service", "\"\"");
            d.essential(
                "service",
                format!("could not list the services ({e:#}); name the one you work in"),
            );
        }
    }
    d.comment("Where the checkout is mounted in the guest: the service's own `volumes:` say.");
    d.commented("workspace", "\"/workdir\"");
    d.action(
        "workspace",
        "set it to the guest path the service mounts the checkout at",
    );
    d.commented("user", "\"dev\"");
    d.set("freshness", "ask");
    Ok(d)
}

/// The service names a compose file declares, without resolving anything else in it.
fn service_names(path: &Path) -> Result<Vec<String>> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    let services = doc
        .get("services")
        .and_then(|s| s.as_mapping())
        .with_context(|| format!("{} declares no services", path.display()))?;
    let mut names = Vec::new();
    for key in services.keys() {
        match key.as_str() {
            Some(name) => names.push(name.to_string()),
            // Dropping it would leave the draft asking "which of a, b" about three services.
            None => bail!("{}: {key:?} is not a service name", path.display()),
        }
    }
    Ok(names)
}

/// A Dockerfile: built from the project root. The stage is the reader's choice when there is
/// more than one — the last stage of a build is where the product is, not where the work is.
fn from_dockerfile(path: &Path) -> Result<Draft> {
    let mut d = Draft::default();
    d.preamble("Dockerfile");
    let mut table = toml::Table::new();
    table.insert("context".into(), ".".into());
    table.insert("dockerfile".into(), "Dockerfile".into());
    let src =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let stages = crate::build::dockerfile_stages(&src)
        .with_context(|| format!("parsing {}", path.display()))?;
    if stages.len() > 1 {
        // Written empty rather than left out: the last stage is where the product is, not
        // where the work is, so the draft names the key and does not validate until it is
        // filled in.
        table.insert("target".into(), "".into());
        d.essential(
            "build.target",
            format!(
                "Dockerfile has {} named stages ({}); say which one is the development \
                 environment",
                stages.len(),
                stages.join(", ")
            ),
        );
    }
    d.set("build", toml::Value::Table(table));
    d.translated("build", "context ., Dockerfile");
    d.set("workspace", "/workspace");
    d.action(
        "workspace",
        "the checkout is mounted at /workspace; change it if the image expects another path",
    );
    d.commented("user", "\"dev\"");
    d.set("freshness", "ask");
    Ok(d)
}

fn from_image(image: &str) -> Draft {
    let mut d = Draft::default();
    d.preamble(&format!("image {image}"));
    d.set("image", image);
    d.translated("image", "");
    d.set("workspace", "/workspace");
    d.commented("user", "\"dev\"");
    d.set("freshness", "ask");
    d
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

    fn project(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!("vk-devinit-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join(".git")).unwrap();
        Fixture(root)
    }

    fn opts() -> Opts {
        Opts {
            from: None,
            image: None,
            force: false,
        }
    }

    fn config_of(f: &Fixture) -> String {
        std::fs::read_to_string(f.0.join(crate::dev::config::CONFIG_FILE)).unwrap()
    }

    #[test]
    fn nothing_to_read_from_writes_the_template_and_an_existing_config_is_validated() {
        let f = project("template");
        let out = run(&f.0, &opts()).unwrap();
        assert!(out.ok && out.report.contains("wrote"), "{}", out.report);
        assert_eq!(config_of(&f), crate::dev::config::TEMPLATE);
        // Again: validated, not rewritten — and from a subdirectory, the same project.
        let sub = f.0.join("src");
        std::fs::create_dir_all(&sub).unwrap();
        let out = run(&sub, &opts()).unwrap();
        assert!(
            out.ok && out.report.contains("config.toml: ok"),
            "{}",
            out.report
        );
        assert!(!f.0.join("src/.virtkit").exists(), "no second project");
        // A source asked for explicitly is refused over an existing file, unless forced.
        std::fs::write(f.0.join("Dockerfile"), "FROM debian:13\n").unwrap();
        let mut o = opts();
        o.from = Some(Source::Dockerfile);
        assert!(run(&f.0, &o).is_err());
        o.force = true;
        let out = run(&f.0, &o).unwrap();
        assert!(out.ok, "{}", out.report);
        assert!(
            config_of(&f).contains("build = { context"),
            "{}",
            config_of(&f)
        );
    }

    /// The real shape this is for: a Docker devcontainer whose compose file and service are
    /// not the VM's, beside a `customizations.virtkit` that names the VM's.
    fn wab_like(f: &Fixture, with_virtkit: bool) {
        std::fs::create_dir_all(f.0.join(".devcontainer")).unwrap();
        std::fs::create_dir_all(f.0.join("virtkit")).unwrap();
        std::fs::write(f.0.join("virtkit/host-dispatch.sh"), "#!/bin/sh\n").unwrap();
        std::fs::write(
            f.0.join("compose.yaml"),
            "services:\n  builder:\n    image: x\n",
        )
        .unwrap();
        let virtkit = if with_virtkit {
            r#""virtkit": {
                "dockerComposeFile": "../virtkit/compose.yaml", "service": "devcontainer",
                "cpus": "host", "mem": "16G", "profiles": ["runner"],
                "hostExec": { "wrapper": "../virtkit/host-dispatch.sh", "env": ["LC_*"] },
                "cache": { "registry": "127.0.0.1:5000/cache", "insecure": true },
                "gitWorktreeMount": true,
                "localUserBuildArgs": { "uid": ["DEVUSER_UID"], "gid": ["DEVUSER_GID"] }
            },"#
        } else {
            ""
        };
        std::fs::write(
            f.0.join(".devcontainer/devcontainer.json"),
            format!(
                r#"{{
  "name": "WAB Dev (${{localWorkspaceFolderBasename}})",
  "dockerComposeFile": "../compose.yaml",
  "workspaceFolder": "/workdir",
  "service": "builder",
  "remoteUser": "dev",
  "mounts": [
    "source=${{localWorkspaceFolder}}/home-config,target=/home/dev/.config,type=bind,readonly",
    {{ "type": "bind", "source": "${{localEnv:HOME}}/.gitconfig", "target": "/home/dev/.gitconfig" }}
  ],
  "containerEnv": {{ "WAB_IN_VM": "1" }},
  "remoteEnv": {{ "GITLAB_WORKFLOW_TOKEN": "${{localEnv:GITLAB_WORKFLOW_TOKEN}}",
                 "WS_NAME": "${{localWorkspaceFolderBasename}}" }},
  "forwardPorts": [8080, "runner:8443"],
  "initializeCommand": ["./scripts/prepare.sh"],
  "postCreateCommand": "/workdir/.devcontainer/install-extensions.sh -postcreate",
  "postStartCommand": {{ "redis": "redis-cli ping", "db": ["mysqladmin", "ping"] }},
  "features": {{ "ghcr.io/devcontainers/features/node:1": {{}} }},
  "shutdownAction": "none",
  "customizations": {{
    {virtkit}
    "vscode": {{
      "extensions": ["ms-python.python"],
      "settings": {{
        "python.analysis.typeCheckingMode": "standard",
        "extensions.autoUpdate": false,
        "coverage-gutters.manualCoverageFilePaths": ["/workdir/coverage.xml"],
        "some.nullable": null
      }}
    }}
  }}
}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn a_devcontainer_is_translated_with_a_report_and_not_silently_the_docker_lan() {
        let f = project("wab");
        wab_like(&f, true);
        let out = run(&f.0, &opts()).unwrap();
        let text = config_of(&f);
        let report = &out.report;
        // The machine vk drives is the one customizations.virtkit named, rebased to the
        // project root, and the Docker one is reported rather than taken.
        assert!(
            text.contains("compose = \"virtkit/compose.yaml\""),
            "{text}"
        );
        assert!(text.contains("service = \"devcontainer\""), "{text}");
        assert!(
            report.contains("../compose.yaml") || report.contains("compose.yaml\" was not taken"),
            "{report}"
        );
        for expect in [
            "workspace = \"/workdir\"",
            "user = \"dev\"",
            "cpus = \"host\"",
            "mem = \"16G\"",
            "profiles = [\"runner\"]",
            "[dev.container-env]\nWAB_IN_VM = \"1\"",
            "[dev.exec-env]\nGITLAB_WORKFLOW_TOKEN = \"${localEnv:GITLAB_WORKFLOW_TOKEN}\"",
            "[dev.mounts.config]\nsource = \"${workspace}/home-config\"\nto = \"/home/dev/.config\"\nread-only = true",
            "[dev.mounts.gitconfig]\nsource = \"${localEnv:HOME}/.gitconfig\"",
            "[dev.endpoints.port-8080]\ntarget = 8080\n",
            "[dev.endpoints.runner-8443]\nservice = \"runner\"\ntarget = 8443\n",
            "[dev.hooks]\ninit = [\"./scripts/prepare.sh\"]\ncreate = \"/workdir/.devcontainer/install-extensions.sh -postcreate\"\nstart = { db = [\"mysqladmin\", \"ping\"], redis = \"redis-cli ping\" }",
            "[dev.editor.vscode]\nstate = \"persistent\"\nextensions = [\"ms-python.python\"]",
            "[dev.editor.vscode.settings]\n\"coverage-gutters.manualCoverageFilePaths\" = [\"/workdir/coverage.xml\"]\n\"extensions.autoUpdate\" = false\n\"python.analysis.typeCheckingMode\" = \"standard\"",
            "[dev.host]\nwrapper = \"virtkit/host-dispatch.sh\"\nwrapper-env = [\"LC_*\"]",
            "[dev.cache]\nregistry = \"127.0.0.1:5000/cache\"\ninsecure = true",
        ] {
            assert!(text.contains(expect), "{expect:?} in:\n{text}");
        }
        // Features make the environment something else, so the draft is not done.
        assert!(!out.ok, "{report}");
        assert!(
            report.contains("requires action before the environment can start:\n  features"),
            "{report}"
        );
        for expect in [
            "localUserBuildArgs",
            "gitWorktreeMount",
            "some.nullable",
            "shutdownAction",
            "name: a display name",
            "localWorkspaceFolderBasename",
        ] {
            assert!(report.contains(expect), "{expect:?} in:\n{report}");
        }
        // The draft is itself a valid config, read the way every other command reads it.
        assert!(report.contains("finish the items above"), "{report}");
    }

    #[test]
    fn without_a_virtkit_section_the_docker_compose_is_taken_and_flagged() {
        let f = project("docker-only");
        wab_like(&f, false);
        let out = run(&f.0, &opts()).unwrap();
        let text = config_of(&f);
        assert!(
            text.contains("compose = \"compose.yaml\"\nservice = \"builder\""),
            "{text}"
        );
        assert!(
            out.report.contains("requires action:\n")
                && out
                    .report
                    .contains("compose: taken from dockerComposeFile as written"),
            "{}",
            out.report
        );
    }

    #[test]
    fn a_compose_file_needs_the_service_named_unless_there_is_one() {
        let f = project("compose");
        std::fs::write(
            f.0.join("compose.yaml"),
            "services:\n  web:\n    image: x\n  db:\n    image: y\n",
        )
        .unwrap();
        let out = run(&f.0, &opts()).unwrap();
        assert!(!out.ok, "{}", out.report);
        assert!(out.report.contains("which of web, db"), "{}", out.report);
        let text = config_of(&f);
        assert!(text.contains("# service = \"\""), "{text}");
        assert!(
            out.report.contains("does not validate yet"),
            "{}",
            out.report
        );

        std::fs::write(
            f.0.join("compose.yaml"),
            "services:\n  web:\n    image: x\n",
        )
        .unwrap();
        let mut o = opts();
        o.force = true;
        let out = run(&f.0, &o).unwrap();
        assert!(
            config_of(&f).contains("service = \"web\""),
            "{}",
            config_of(&f)
        );
        assert!(out.ok, "{}", out.report);
    }

    #[test]
    fn a_dockerfile_with_several_stages_does_not_get_the_last_one_guessed() {
        let f = project("dockerfile");
        std::fs::write(
            f.0.join("Dockerfile"),
            "FROM debian:13 AS base\nRUN true\nFROM base AS dev\nFROM base AS release\n",
        )
        .unwrap();
        let out = run(&f.0, &opts()).unwrap();
        assert!(!out.ok, "{}", out.report);
        assert!(out.report.contains("base, dev, release"), "{}", out.report);
        assert!(config_of(&f).contains("target = \"\""), "{}", config_of(&f));
        // The empty stage is not a config that runs: the draft says so itself, not only
        // through the exit code.
        assert!(
            out.report.contains("does not validate yet"),
            "{}",
            out.report
        );

        std::fs::write(f.0.join("Dockerfile"), "FROM debian:13\n").unwrap();
        let mut o = opts();
        o.force = true;
        let out = run(&f.0, &o).unwrap();
        assert!(out.ok, "{}", out.report);
        assert!(!config_of(&f).contains("target"), "{}", config_of(&f));
    }

    #[test]
    fn a_named_source_that_is_not_there_says_so_and_an_existing_config_is_read() {
        let f = project("missing");
        for (from, expect) in [
            (Source::Compose, "no compose file"),
            (Source::Devcontainer, "no devcontainer config"),
            (Source::Dockerfile, "no Dockerfile"),
        ] {
            let mut o = opts();
            o.from = Some(from);
            let msg = format!("{:#}", run(&f.0, &o).unwrap_err());
            assert!(msg.contains(expect), "{msg}");
        }
        // An existing config is read, not replaced — so what is wrong with it is what the
        // command reports, rather than a translation written over it.
        std::fs::create_dir_all(f.0.join(".virtkit")).unwrap();
        std::fs::write(
            f.0.join(crate::dev::config::CONFIG_FILE),
            "schema = 1\n[dev]\nimage = \"x\"\nnope = 1\n",
        )
        .unwrap();
        let msg = format!("{:#}", run(&f.0, &opts()).unwrap_err());
        assert!(msg.contains("nope"), "{msg}");
    }

    #[test]
    fn an_image_source_takes_an_explicit_reference() {
        let f = project("image");
        let mut o = opts();
        o.from = Some(Source::Image);
        assert!(run(&f.0, &o).is_err(), "needs --image");
        o.image = Some("docker.io/library/alpine:3".into());
        let out = run(&f.0, &o).unwrap();
        assert!(out.ok, "{}", out.report);
        assert!(config_of(&f).contains("image = \"docker.io/library/alpine:3\""));
        // Detection would have found a Dockerfile; the explicit source wins.
        std::fs::write(f.0.join("Dockerfile"), "FROM x\n").unwrap();
        o.force = true;
        run(&f.0, &o).unwrap();
        assert!(config_of(&f).contains("image = "), "{}", config_of(&f));
    }
}
