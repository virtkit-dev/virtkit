//! The `vk dev` command line: its arguments, and the dispatch from each action to whatever
//! carries it out.
//!
//! Split out of `main` because `vk dev` is a command set of its own — its actions read a
//! project's `.virtkit/config.toml` rather than this host's executor config, and resolve it
//! to the plan ([`crate::dev::plan`]) every one of them then works from.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Subcommand};

use crate::{fail, write_report};

// The global flags of `vk dev` and the action they qualify. Carries no doc comment on
// purpose: `Cmd::Dev`'s is this command's help, and one here would be a second `about` for
// the same command.
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

/// `vk dev`: the entry point `main` dispatches to, holding the flags together as one.
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
    /// Print what the config resolves to, without doing any of it
    ///
    /// The plan is what every other `vk dev` command works from, so this is how to see
    /// which source, mounts, environment, endpoints and state directory a config actually
    /// means on this host, with `.virtkit/local.toml` layered in. Nothing is built, bound,
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
    /// The schema this `vk` checks a config against, for `taplo`, an editor, or a project
    /// that vendors its own copy. `vk dev init` writes a `#:schema` directive on the
    /// config's first line, which is how an editor finds it without being told. Needs no
    /// config of its own.
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
    let cwd = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => return fail(&anyhow::anyhow!(e).context("resolving the current dir"), 1),
    };
    // Nothing to read at all: the schema is embedded, so this answers anywhere.
    if matches!(action, DevAction::Schema) {
        return write_report(crate::dev::schema::SCHEMA_JSON);
    }
    // A config that cannot be read or does not describe something virtkit can build is the
    // caller's to fix, like a usage error.
    let loaded = match crate::dev::config::discover(&cwd, workspace, config)
        .and_then(crate::dev::config::load)
    {
        Ok(l) => l,
        Err(e) => return fail(&e, 2),
    };
    let plan = match crate::dev::plan::resolve(&loaded, environment) {
        Ok(p) => p,
        Err(e) => return fail(&e, 2),
    };
    match action {
        DevAction::Schema => unreachable!("handled before the plan is resolved"),
        DevAction::Plan {
            format,
            show_secrets,
            explain,
        } => match format {
            _ if explain => {
                let mut out = String::new();
                for o in loaded.origins() {
                    let file = match o.layer {
                        crate::dev::config::Layer::Project => &loaded.files.config,
                        crate::dev::config::Layer::Local => {
                            loaded.files.local.as_ref().unwrap_or(&loaded.files.config)
                        }
                    };
                    // The two files sit side by side, so their names tell them apart.
                    let name = file.strip_prefix(&loaded.files.workspace).unwrap_or(file);
                    let value = match o.secret && !show_secrets {
                        true => "<redacted>".to_string(),
                        false => o.value.to_string(),
                    };
                    out.push_str(&format!("{} = {value}  # {}\n", o.key, name.display()));
                }
                match plan.to_json(show_secrets) {
                    Ok(json) => {
                        out.push('\n');
                        out.push_str(&json);
                        write_report(&out)
                    }
                    Err(e) => fail(&e, 1),
                }
            }
            PlanFormat::Json => match plan.to_json(show_secrets) {
                Ok(json) => write_report(&json),
                Err(e) => fail(&e, 1),
            },
            PlanFormat::Shell => match plan.to_shell(show_secrets) {
                Ok(text) => write_report(&text),
                Err(e) => fail(&e, 1),
            },
        },
    }
}
