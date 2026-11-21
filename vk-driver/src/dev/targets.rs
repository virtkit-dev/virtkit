//! The environments a named `vk dev` command acts on. `vk dev` is scoped to its workspace: a
//! name that is a VM of another workspace is refused, and `vk` itself (`vk stop NAME`) is
//! what reaches it.
//!
//! [`pick_envs`] checks the supplied [`Scope`] first and consults the caller's host-wide
//! lookup only for names missing from the workspace.

use std::path::PathBuf;

use anyhow::{Result, bail};

/// One environment of this workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Env {
    /// its VM name, what `vk list` shows
    pub name: String,
    /// its state dir's own name, which names it too
    pub dir_name: String,
    /// `dev`, or a name under `[environments]`
    pub environment: String,
    pub dir: PathBuf,
}

/// What the names given to a command resolve against.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// every environment of this workspace that has state
    pub envs: Vec<Env>,
}

/// A name that is a VM, but not one of this workspace's.
#[derive(Debug)]
pub struct Outside(pub String);

impl std::fmt::Display for Outside {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} is not in this workspace", self.0)
    }
}

impl std::error::Error for Outside {}

impl Scope {
    /// The environment `name` names, by VM name or state dir name. A name that is one
    /// environment's VM name and another's state dir name is refused, as
    /// [`crate::names::resolve`] refuses it.
    pub fn env(&self, name: &str) -> Result<Option<&Env>> {
        let named = self.envs.iter().find(|e| e.name == name);
        let own = self.envs.iter().find(|e| e.dir_name == name);
        match (named, own) {
            (Some(a), Some(b)) if a.dir != b.dir => bail!(
                "{name} is ambiguous: it names {} and is the state directory {}, named {}",
                a.dir.display(),
                b.dir.display(),
                b.name
            ),
            (named, own) => Ok(named.or(own)),
        }
    }

    pub fn env_list(&self) -> String {
        let mut names: Vec<&str> = self.envs.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        match names.is_empty() {
            true => "none".into(),
            false => names.join(", "),
        }
    }
}

/// The environments of this workspace `names` name. `elsewhere` says whether a name is a VM
/// outside this workspace: such a name fails with [`Outside`].
pub fn pick_envs(
    scope: &Scope,
    names: &[String],
    elsewhere: &dyn Fn(&str) -> Result<bool>,
) -> Result<Vec<Env>> {
    let mut out = Vec::new();
    for name in names {
        match scope.env(name)? {
            Some(env) => out.push(env.clone()),
            None if elsewhere(name)? => return Err(Outside(name.clone()).into()),
            None => bail!(
                "no environment {name} in this workspace (environments: {})",
                scope.env_list()
            ),
        }
    }
    Ok(out)
}

/// This workspace's environments, as `vk dev list` finds them: those whose recorded workspace
/// is `workspace`. Read from their state alone, so neither the config nor its compose file
/// has to describe them still.
pub fn envs(workspace: &std::path::Path) -> Result<Scope> {
    let workspace = crate::vms::canonical(workspace);
    let envs = crate::dev::list::state(false)?
        .into_iter()
        .filter(|r| r.workspace.as_deref().map(crate::vms::canonical) == Some(workspace.clone()))
        .map(|r| Env {
            name: r.name,
            dir_name: r.dir_name,
            environment: r.environment.unwrap_or_else(|| "dev".into()),
            dir: r.dir,
        })
        .collect();
    Ok(Scope { envs })
}

/// Whether `name` names a VM `vk` knows of, wherever it is. A name of two different
/// directories is an error, as [`crate::names::resolve`] has it.
pub fn known_anywhere(name: &str) -> Result<bool> {
    Ok(crate::names::resolve(name)?.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(name: &str, environment: &str) -> Env {
        Env {
            name: name.into(),
            dir_name: format!("{name}-0123456789abcdef"),
            environment: environment.into(),
            dir: format!("/s/{name}").into(),
        }
    }

    /// `shop`'s `dev` environment, and its `test` environment named `shop-test`.
    fn shop() -> Scope {
        Scope {
            envs: vec![env("shop", "dev"), env("shop-test", "test")],
        }
    }

    fn picked(names: &[&str]) -> Result<Vec<Env>> {
        let names: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        pick_envs(&shop(), &names, &|n| Ok(n == "other"))
    }

    #[test]
    fn environments_resolve_by_vm_or_state_dir_name() {
        assert_eq!(
            picked(&["shop-test", "shop"]).unwrap(),
            [env("shop-test", "test"), env("shop", "dev")]
        );
        assert_eq!(
            picked(&["shop-test-0123456789abcdef"]).unwrap(),
            [env("shop-test", "test")]
        );
    }

    /// A VM of another workspace is [`Outside`]; a name nothing has lists what there is.
    #[test]
    fn outside_and_unknown_names_are_refused() {
        let err = picked(&["other"]).unwrap_err();
        assert!(err.downcast_ref::<Outside>().is_some(), "{err}");
        let err = picked(&["nope"]).unwrap_err();
        assert!(err.downcast_ref::<Outside>().is_none());
        assert!(
            err.to_string().contains("environments: shop, shop-test"),
            "{err}"
        );
    }

    /// A word that is one environment's name and another's state dir name is refused.
    #[test]
    fn a_name_of_two_environments_is_refused() {
        let mut scope = shop();
        let mut odd = env("odd", "odd");
        odd.dir_name = "shop-test".into();
        scope.envs.push(odd);
        let err = pick_envs(&scope, &["shop-test".into()], &|_| Ok(false)).unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "{err}");
    }
}
