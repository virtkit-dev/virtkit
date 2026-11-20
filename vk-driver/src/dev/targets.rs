//! What `vk dev up | start | stop | restart NAME…` acts on: compose services of the
//! environment, or environments of this workspace. `vk dev` is scoped to its workspace: a name
//! that is a VM of another workspace is refused, and `vk` itself (`vk stop NAME`) is what
//! reaches it.
//!
//! [`pick`] is pure: [`Scope`] holds what the caller read, so a test states the facts.

use std::path::{Path, PathBuf};

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

/// What the names given to a verb resolve against.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// the environment the command is about (`--environment`), named or not
    pub current: Option<Env>,
    /// every environment of this workspace that has state
    pub envs: Vec<Env>,
    /// the services the current environment's compose file declares, its primary among them
    pub services: Vec<String>,
    /// the compose service that is the current environment's primary VM
    pub primary: Option<String>,
}

/// What a name resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pick {
    /// an environment: its primary VM, with its services
    Env(Env),
    /// one compose service of an environment
    Service(Env, String),
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
    fn env(&self, name: &str) -> Option<&Env> {
        self.envs
            .iter()
            .chain(&self.current)
            .find(|e| e.name == name || e.dir_name == name)
    }

    fn current(&self) -> Result<&Env> {
        match &self.current {
            Some(e) => Ok(e),
            None => bail!("this environment has no state yet: `vk dev up` creates it"),
        }
    }

    /// The service `name` of the current environment: its primary is the environment itself.
    fn service(&self, name: &str) -> Result<Pick> {
        let env = self.current()?.clone();
        Ok(match self.primary.as_deref() == Some(name) {
            true => Pick::Env(env),
            false => Pick::Service(env, name.to_string()),
        })
    }

    /// Whether `name` is the key of one of this workspace's environments (`dev`, or a name
    /// under `[environments]`): what `--environment` takes, and no NAME.
    fn is_environment_key(&self, name: &str) -> bool {
        self.envs
            .iter()
            .chain(&self.current)
            .any(|e| e.environment == name)
    }

    fn service_list(&self) -> String {
        match self.services.is_empty() {
            true => "none".into(),
            false => self.services.join(", "),
        }
    }

    fn env_list(&self) -> String {
        let mut names: Vec<&str> = self.envs.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        match names.is_empty() {
            true => "none".into(),
            false => names.join(", "),
        }
    }
}

/// Resolve the names a verb was given. `names` may be a service or an environment, and is
/// refused when it could be either; `services` (`--service`) and `vms` (`--name`) say which.
/// `ENV/SERVICE` is a service of another environment of this workspace. `elsewhere` says
/// whether a name is a VM outside this workspace: such a name fails with [`Outside`].
pub fn pick(
    scope: &Scope,
    names: &[String],
    services: &[String],
    vms: &[String],
    elsewhere: &dyn Fn(&str) -> bool,
) -> Result<Vec<Pick>> {
    let outside = |name: &str| anyhow::Error::new(Outside(name.to_string()));
    let mut out = Vec::new();
    for name in names {
        if let Some((vm, service)) = name.split_once('/') {
            let Some(env) = scope.env(vm) else {
                if elsewhere(vm) {
                    return Err(outside(name));
                }
                bail!(
                    "no environment {vm} in this workspace (environments: {})",
                    scope.env_list()
                );
            };
            out.push(match scope.current.as_ref() == Some(env) {
                true => scope.service(service)?,
                false => Pick::Service(env.clone(), service.to_string()),
            });
            continue;
        }
        let is_service = scope.services.iter().any(|s| s == name);
        match (is_service, scope.env(name)) {
            (true, Some(_)) => bail!(
                "{name} is both a service and an environment of this workspace: \
                 `--service {name}` or `--name {name}`"
            ),
            (true, None) => out.push(scope.service(name)?),
            (false, Some(env)) => out.push(Pick::Env(env.clone())),
            (false, None) if scope.is_environment_key(name) => bail!(
                "{name} is an environment's key, not a name: select that environment with \
                 `vk dev --environment {name} …` (its VM is named {})",
                scope
                    .envs
                    .iter()
                    .chain(&scope.current)
                    .find(|e| e.environment == *name)
                    .map_or(name.as_str(), |e| e.name.as_str())
            ),
            (false, None) if elsewhere(name) => return Err(outside(name)),
            (false, None) => bail!(
                "no service or environment named {name} here (services: {}; environments: {})",
                scope.service_list(),
                scope.env_list()
            ),
        }
    }
    for name in services {
        if !scope.services.iter().any(|s| s == name) {
            bail!("no service {name} (services: {})", scope.service_list());
        }
        out.push(scope.service(name)?);
    }
    for name in vms {
        match scope.env(name) {
            Some(env) => out.push(Pick::Env(env.clone())),
            None if elsewhere(name) => return Err(outside(name)),
            None => bail!(
                "no environment {name} in this workspace (environments: {})",
                scope.env_list()
            ),
        }
    }
    Ok(out)
}

/// The scope of `plan`: this workspace's environments, as `vk dev list` finds them, and the
/// services the environment's compose file declares.
pub fn scope(plan: &crate::dev::plan::Plan) -> Result<Scope> {
    let workspace = crate::vms::canonical(&plan.workspace);
    let mut envs = Vec::new();
    for r in crate::dev::list::state(false)? {
        if r.workspace.as_deref().map(crate::vms::canonical) != Some(workspace.clone()) {
            continue;
        }
        envs.push(Env {
            name: r.name,
            dir_name: r.dir_name,
            environment: r.environment.unwrap_or_else(|| "dev".into()),
            dir: r.dir,
        });
    }
    let here = crate::vms::canonical(&plan.state_dir);
    let current = envs
        .iter()
        .find(|e| crate::vms::canonical(&e.dir) == here)
        .cloned();
    let (services, primary) = match &plan.source {
        crate::dev::plan::Source::Compose { file, service, .. } => (
            crate::dev::init::service_names(file)?,
            Some(service.clone()),
        ),
        _ => (Vec::new(), None),
    };
    Ok(Scope {
        current,
        envs,
        services,
        primary,
    })
}

/// Whether `name` names a VM `vk` knows of, wherever it is.
pub fn known_anywhere(name: &str) -> bool {
    let vm = name.split_once('/').map_or(name, |(vm, _)| vm);
    crate::names::resolve(vm).is_ok_and(|d| d.is_some())
}

/// Whether a VM runs on the state dir `dir`.
pub fn running(dir: &Path) -> bool {
    let dir = crate::vms::canonical(dir);
    crate::vms::running().iter().any(|e| e.state_dir == dir)
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

    /// `shop`, whose `dev` environment runs `app` with `db` and `redis`, and a `test`
    /// environment named `shop-test`.
    fn shop() -> Scope {
        Scope {
            current: Some(env("shop", "dev")),
            envs: vec![env("shop", "dev"), env("shop-test", "test")],
            services: vec!["app".into(), "db".into(), "redis".into()],
            primary: Some("app".into()),
        }
    }

    fn picked(names: &[&str], services: &[&str], vms: &[&str]) -> Result<Vec<Pick>> {
        let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        pick(&shop(), &own(names), &own(services), &own(vms), &|n| {
            n == "other" || n == "db"
        })
    }

    #[test]
    fn services_and_environments_resolve_by_name() {
        use Pick::*;
        let shop = env("shop", "dev");
        assert_eq!(
            picked(&["db", "redis"], &[], &[]).unwrap(),
            [
                Service(shop.clone(), "db".into()),
                Service(shop.clone(), "redis".into())
            ]
        );
        // The primary's service name is the environment itself.
        assert_eq!(picked(&["app"], &[], &[]).unwrap(), [Env(shop.clone())]);
        assert_eq!(
            picked(&["shop-test"], &[], &[]).unwrap(),
            [Env(env("shop-test", "test"))]
        );
        // The state dir's own name still names an environment.
        assert_eq!(
            picked(&["shop-test-0123456789abcdef"], &[], &[]).unwrap(),
            [Env(env("shop-test", "test"))]
        );
        assert_eq!(
            picked(&["shop-test/db"], &[], &[]).unwrap(),
            [Service(env("shop-test", "test"), "db".into())]
        );
        assert_eq!(
            picked(&["shop/db"], &[], &[]).unwrap(),
            [Service(shop.clone(), "db".into())]
        );
        assert_eq!(
            picked(&[], &["db"], &["shop-test"]).unwrap(),
            [Service(shop, "db".into()), Env(env("shop-test", "test"))]
        );
    }

    /// A name both a service and an environment is refused until `--service` or `--name`
    /// says which; a name elsewhere on the host is [`Outside`]; an unknown name lists what
    /// there is.
    #[test]
    fn ambiguous_outside_and_unknown_names_are_refused() {
        let mut scope = shop();
        scope.services.push("shop-test".into());
        let err = pick(&scope, &["shop-test".into()], &[], &[], &|_| false).unwrap_err();
        assert!(err.to_string().contains("--service shop-test"), "{err}");
        assert!(pick(&scope, &[], &["shop-test".into()], &[], &|_| false).is_ok());
        assert!(pick(&scope, &[], &[], &["shop-test".into()], &|_| false).is_ok());

        for (names, vms) in [
            (&["other"][..], &[][..]),
            (&["other/db"], &[]),
            (&[], &["other"]),
        ] {
            let err = picked(names, &[], vms).unwrap_err();
            assert!(err.downcast_ref::<Outside>().is_some(), "{err}");
        }
        // An environment's key is what `--environment` takes, not a NAME: the error says so.
        let err = picked(&["test"], &[], &[]).unwrap_err();
        assert!(err.downcast_ref::<Outside>().is_none());
        assert!(
            err.to_string().contains("--environment test")
                && err.to_string().contains("named shop-test"),
            "{err}"
        );
        let err = picked(&["nope"], &[], &[]).unwrap_err();
        assert!(err.downcast_ref::<Outside>().is_none());
        assert!(
            err.to_string()
                .contains("services: app, db, redis; environments: shop, shop-test"),
            "{err}"
        );
        // `--service` takes only a service, even when the name is a VM elsewhere.
        let err = picked(&[], &["other"], &[]).unwrap_err();
        assert!(err.to_string().contains("no service other"), "{err}");
        // A service here wins over a VM of the same name elsewhere.
        assert!(picked(&["db"], &[], &[]).is_ok());
    }

    #[test]
    fn a_service_needs_an_environment_with_state() {
        let mut scope = shop();
        scope.current = None;
        let err = pick(&scope, &["db".into()], &[], &[], &|_| false).unwrap_err();
        assert!(err.to_string().contains("`vk dev up`"), "{err}");
    }
}
