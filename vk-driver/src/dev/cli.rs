//! `vk dev` arguments and command dispatch.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};

use super::{config, init, plan, schema};
use crate::{exit_code, fail, write_report};

// `Cmd::Dev` supplies the help; a doc comment here would duplicate its `about`.
#[derive(Args)]
pub struct Dev {
    #[command(subcommand)]
    action: DevAction,
    /// the workspace, instead of finding it from the current directory
    #[arg(long, value_name = "DIR", global = true)]
    workspace: Option<PathBuf>,
    /// the config file to read, instead of `.virtkit/config.toml`
    ///
    /// Named `--dev-config` because `--config` is virtkit's own config file.
    #[arg(long = "dev-config", value_name = "FILE", global = true)]
    dev_config: Option<PathBuf>,
    /// the environment to work in: `dev`, or a name under `[environments]`
    #[arg(long, value_name = "NAME", default_value = "dev", global = true)]
    environment: String,
}

/// `vk dev`: the entry point `main` dispatches to.
pub async fn run(dev: Dev) -> ExitCode {
    dev_action(
        dev.action,
        dev.workspace.as_deref(),
        dev.dev_config.as_deref(),
        &dev.environment,
    )
    .await
}

/// `vk dev`: drive a workspace's dev environment from its `.virtkit/config.toml`.
#[derive(Subcommand)]
enum DevAction {
    /// Write a first `.virtkit/config.toml`, or validate the one that exists
    ///
    /// With a config already there, reads it — and `.virtkit/local.toml` beside it — and
    /// reports what it describes; an unknown key or a value that means nothing is an error
    /// with its location. Without one, translates what the project has: a devcontainer.json,
    /// a compose file at the root, a Dockerfile, else a commented config booting a stock
    /// image. The report says what was carried over, what still needs a decision, and what
    /// was left out; a draft missing an essential choice is written but exits 1. Data
    /// conversion only — nothing runs, downloads or boots. Never touches the local files.
    Init {
        /// what to translate from, instead of detecting it
        #[arg(long, value_name = "SOURCE")]
        from: Option<crate::dev::init::Source>,
        /// the image reference, with `--from image`
        #[arg(long, value_name = "REF")]
        image: Option<String>,
        /// replace an existing config
        #[arg(long)]
        force: bool,
    },
    /// Print what the config resolves to, without doing any of it
    ///
    /// Which source, mounts, environment, endpoints and state directory the config means
    /// on this host, with `.virtkit/local.toml` layered in. Nothing is built, bound,
    /// started or written. The values of `exec-env`, `container-env`, a task's `env` and
    /// `build.args` are redacted — in every format, `--explain` included — so a plan can be
    /// pasted anywhere; `--show-secrets` prints them.
    Plan {
        /// print as JSON (the canonical form) or as the `vk run` it stands for
        #[arg(long, value_name = "FORMAT", default_value = "json")]
        format: PlanFormat,
        /// print the environment values and build arguments instead of redacting them
        ///
        /// They are where a token would be, so a plan can otherwise be pasted anywhere.
        #[arg(long)]
        show_secrets: bool,
        /// list each configured value with the file it came from, before the plan
        #[arg(long)]
        explain: bool,
    },
    /// Print the JSON schema for .virtkit/config.toml
    ///
    /// The shape this `vk` accepts, for `taplo`, an editor, or a project that vendors its
    /// own copy. A `#:schema` directive on the config's first line is how an editor finds
    /// it without being told. Needs no config of its own.
    Schema,
}

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum PlanFormat {
    /// the canonical form: every resolved value, as JSON
    Json,
    /// the `vk run` the plan stands for, for reading rather than running
    Shell,
}

/// `vk dev`: resolve the workspace's config, then act on the plan.
async fn dev_action(
    action: DevAction,
    workspace: Option<&Path>,
    config: Option<&Path>,
    environment: &str,
) -> ExitCode {
    // Return the embedded schema before resolving cwd, even if that directory was deleted.
    if matches!(action, DevAction::Schema) {
        return write_report(schema::SCHEMA_JSON);
    }
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => return fail(&anyhow::anyhow!(e).context("resolving the current dir"), 1),
    };
    // Init writes a config rather than reading one, but still needs the workspace.
    if let DevAction::Init { from, image, force } = action {
        let opts = init::Opts { from, image, force };
        return match init::run(&cwd, workspace, &opts) {
            Ok(out) => {
                let code = write_report(&out.report);
                if out.ok { code } else { exit_code(1) }
            }
            Err(e) => fail(&e, 2),
        };
    }
    // A config that cannot be read or does not describe something virtkit can build is the
    // caller's to fix, like a usage error.
    let loaded = match config::discover(&cwd, workspace, config).and_then(config::load) {
        Ok(l) => l,
        Err(e) => return fail(&e, 2),
    };
    let plan = match plan::resolve(&loaded, environment) {
        Ok(p) => p,
        Err(e) => return fail(&e, 2),
    };
    match action {
        DevAction::Init { .. } | DevAction::Schema => {
            unreachable!("handled before the plan is resolved")
        }
        DevAction::Plan {
            format,
            show_secrets,
            explain,
        } => {
            let body = match format {
                PlanFormat::Json => plan.to_json(show_secrets),
                PlanFormat::Shell => plan.to_shell(show_secrets),
            };
            let body = match body {
                Ok(b) => b,
                Err(e) => return fail(&e, 1),
            };
            match explain {
                false => write_report(&body),
                true => {
                    let mut out = origins(&loaded, show_secrets);
                    out.push('\n');
                    out.push_str(&body);
                    write_report(&out)
                }
            }
        }
    }
}

/// Each configured value with the file it came from, one per line.
fn origins(loaded: &config::Loaded, show_secrets: bool) -> String {
    let mut out = String::new();
    for o in loaded.origins() {
        let file = match o.layer {
            config::Layer::Project => &loaded.files.config,
            config::Layer::Local => &loaded.files.local,
        };
        // The two files sit side by side, so their names tell them apart.
        let name = file.strip_prefix(&loaded.files.workspace).unwrap_or(file);
        let value = match o.secret && !show_secrets {
            true => "<redacted>".to_string(),
            false => o.value.to_string(),
        };
        out.push_str(&format!("{} = {value}  # {}\n", o.key, name.display()));
    }
    out
}
