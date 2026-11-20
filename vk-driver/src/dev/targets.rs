//! What a named `vk dev` command acts on: compose services of an environment, or environments
//! of this workspace. `vk dev` is scoped to its workspace: a name that is a VM of another
//! workspace is refused, and `vk` itself (`vk stop NAME`) is what reaches it.
//!
//! [`pick`] and [`pick_envs`] resolve names against [`Scope`]. The caller supplies host VM
//! lookups and the compose catalogs for other environments.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// One environment of this workspace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    /// its VM name, what `vk list` shows
    pub name: String,
    /// its state dir's own name, which names it too
    pub dir_name: String,
    /// `dev`, or a name under `[environments]`
    pub environment: String,
    pub dir: PathBuf,
    /// the config its last boot read, when it recorded one
    pub config: Option<PathBuf>,
    /// the compose service its running VM booted as its primary, as its last boot recorded
    /// it; `None` when it is not running
    pub primary: Option<String>,
}

/// What an environment's compose file declares.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Catalog {
    /// its services, its primary among them
    pub services: Vec<String>,
    /// the service that is its primary VM
    pub primary: Option<String>,
}

impl Catalog {
    fn list(&self) -> String {
        match self.services.is_empty() {
            true => "none".into(),
            false => self.services.join(", "),
        }
    }

    /// The service `name` of `env`: its primary is the environment itself. That of a running
    /// environment is the one its VM booted, whatever the config names now, except for `up`
    /// (`fresh`), which boots from the config.
    fn service(&self, env: &Env, name: &str, fresh: bool) -> Result<Pick> {
        if !self.services.iter().any(|s| s == name) {
            bail!(
                "no service {name} in {} (services: {})",
                env.name,
                self.list()
            );
        }
        let primary = match (&env.primary, fresh) {
            (Some(booted), false) => Some(booted),
            _ => self.primary.as_ref(),
        };
        Ok(match primary.is_some_and(|p| p == name) {
            true => Pick::Env(env.clone()),
            false => Pick::Service(env.clone(), name.to_string()),
        })
    }
}

/// What the names given to a command resolve against.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// every environment of this workspace that has state
    pub envs: Vec<Env>,
    /// the environment the command is about (`--environment`), when it has state
    pub current: Option<Env>,
    /// that environment as its plan has it, state or not: what `up` creates
    pub planned: Env,
    /// what its compose file declares
    pub catalog: Catalog,
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

    /// The service `name` of the current environment. One with no state yet has its services
    /// only for `up` (`fresh`), which creates it.
    fn service(&self, name: &str, fresh: bool) -> Result<Pick> {
        let env = match (&self.current, fresh) {
            (Some(env), _) => env,
            (None, true) => &self.planned,
            (None, false) => bail!("this environment has no state yet: `vk dev up` creates it"),
        };
        self.catalog.service(env, name, fresh)
    }

    /// Whether `name` is the key of one of this workspace's environments (`dev`, or a name
    /// under `[environments]`): what `--environment` takes, and no NAME.
    fn is_environment_key(&self, name: &str) -> bool {
        self.envs.iter().any(|e| e.environment == name)
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

/// Resolve positional names, then `--service`, then `--name`. Keep the first occurrence of
/// each target. Positional names can identify a service or an environment. If a name matches
/// both, the caller must use `--service` or `--name`. Check `ENV/SERVICE` against the named
/// environment's compose catalog (`catalog_of`). Only `up` (`fresh`) accepts services of the
/// current environment before it has state. A VM found by `elsewhere` yields [`Outside`].
pub fn pick(
    scope: &Scope,
    names: &[String],
    services: &[String],
    vms: &[String],
    fresh: bool,
    elsewhere: &dyn Fn(&str) -> Result<bool>,
    catalog_of: &dyn Fn(&Env) -> Result<Catalog>,
) -> Result<Vec<Pick>> {
    let outside = |name: &str| anyhow::Error::new(Outside(name.to_string()));
    let mut out = Vec::new();
    for name in names {
        if let Some((vm, service)) = name.split_once('/') {
            crate::vms::check_service(service)?;
            let Some(env) = scope.env(vm)? else {
                if elsewhere(vm)? {
                    return Err(outside(name));
                }
                bail!(
                    "no environment {vm} in this workspace (environments: {})",
                    scope.env_list()
                );
            };
            out.push(match scope.current.as_ref() == Some(env) {
                true => scope.catalog.service(env, service, fresh)?,
                false => catalog_of(env)?.service(env, service, fresh)?,
            });
            continue;
        }
        let is_service = scope.catalog.services.iter().any(|s| s == name);
        match (is_service, scope.env(name)?) {
            (true, Some(_)) => bail!(
                "{name} is both a service and an environment of this workspace: \
                 `--service {name}` or `--name {name}`"
            ),
            (true, None) => out.push(scope.service(name, fresh)?),
            (false, Some(env)) => out.push(Pick::Env(env.clone())),
            (false, None) if scope.is_environment_key(name) => bail!(
                "{name} is an environment's key, not a name: select that environment with \
                 `vk dev --environment {name} …` (its VM is named {})",
                scope
                    .envs
                    .iter()
                    .find(|e| e.environment == *name)
                    .map_or(name.as_str(), |e| e.name.as_str())
            ),
            (false, None) if elsewhere(name)? => return Err(outside(name)),
            (false, None) => bail!(
                "no service or environment named {name} here (services: {}; environments: {})",
                scope.catalog.list(),
                scope.env_list()
            ),
        }
    }
    for name in services {
        out.push(scope.service(name, fresh)?);
    }
    out.extend(pick_envs(scope, vms, elsewhere)?.into_iter().map(Pick::Env));
    // Once each: `restart db --service db` restarts it once.
    let mut seen = Vec::new();
    out.retain(|p| match seen.contains(p) {
        true => false,
        false => {
            seen.push(p.clone());
            true
        }
    });
    Ok(out)
}

/// Environments whose recorded workspace is `workspace`, including environments removed
/// from its config or compose file.
pub fn recorded(workspace: &Path) -> Result<Vec<Env>> {
    let workspace = crate::vms::canonical(workspace);
    Ok(crate::dev::list::state(false)?
        .into_iter()
        .filter(|r| r.workspace.as_deref().map(crate::vms::canonical) == Some(workspace.clone()))
        .map(|r| Env {
            name: r.name,
            dir_name: r.dir_name,
            environment: r.environment.unwrap_or_else(|| "dev".into()),
            dir: r.dir,
            config: r.config,
            primary: r
                .primary
                .filter(|_| r.status == crate::dev::list::Status::Running),
        })
        .collect())
}

/// [`recorded`] for `plan`'s workspace, with the environment `plan` is about: [`Scope::catalog`]
/// is left empty, for [`scope`] to fill.
pub fn envs(plan: &crate::dev::plan::Plan) -> Result<Scope> {
    let envs = recorded(&plan.workspace)?;
    let here = crate::vms::canonical(&plan.state_dir);
    let current = envs
        .iter()
        .find(|e| crate::vms::canonical(&e.dir) == here)
        .cloned();
    let dir_name = plan
        .state_dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    Ok(Scope {
        envs,
        current,
        planned: Env {
            name: dir_name.clone(),
            dir_name,
            environment: plan.environment.clone(),
            dir: plan.state_dir.clone(),
            config: None,
            primary: None,
        },
        catalog: Catalog::default(),
    })
}

/// [`envs`], with what `plan`'s compose file declares.
pub fn scope(plan: &crate::dev::plan::Plan) -> Result<Scope> {
    Ok(Scope {
        catalog: catalog(plan)?,
        ..envs(plan)?
    })
}

/// What `plan`'s compose file declares; nothing for an environment that is no compose service.
pub fn catalog(plan: &crate::dev::plan::Plan) -> Result<Catalog> {
    Ok(match &plan.source {
        crate::dev::plan::Source::Compose { file, service, .. } => Catalog {
            services: crate::dev::init::service_names(file)?,
            primary: Some(service.clone()),
        },
        _ => Catalog::default(),
    })
}

/// Whether `name` names a VM `vk` knows of, wherever it is: its VM part, for `ENV/SERVICE`. A
/// name of two different directories is an error, as [`crate::names::resolve`] has it.
pub fn known_anywhere(name: &str) -> Result<bool> {
    let vm = name.split_once('/').map_or(name, |(vm, _)| vm);
    Ok(crate::names::resolve(vm)?.is_some())
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
            config: None,
            primary: None,
        }
    }

    fn catalog(services: &[&str], primary: &str) -> Catalog {
        Catalog {
            services: services.iter().map(|s| s.to_string()).collect(),
            primary: Some(primary.into()),
        }
    }

    /// `shop`, whose `dev` environment runs `app` with `db` and `redis`, and a `test`
    /// environment named `shop-test` that runs `web` with `db` and `queue`.
    fn shop() -> Scope {
        Scope {
            envs: vec![env("shop", "dev"), env("shop-test", "test")],
            current: Some(env("shop", "dev")),
            planned: env("shop", "dev"),
            catalog: catalog(&["app", "db", "redis"], "app"),
        }
    }

    fn own(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// [`pick`] in `scope`, where `other` and `db` are VMs of another workspace and
    /// `shop-test` declares its own services.
    fn picked_in(
        scope: &Scope,
        names: &[&str],
        services: &[&str],
        vms: &[&str],
        fresh: bool,
    ) -> Result<Vec<Pick>> {
        pick(
            scope,
            &own(names),
            &own(services),
            &own(vms),
            fresh,
            &|n| Ok(n == "other" || n == "db"),
            &|e| match e.environment.as_str() {
                "test" => Ok(catalog(&["web", "db", "queue"], "web")),
                other => panic!("{other}'s catalog is the scope's own"),
            },
        )
    }

    fn picked(names: &[&str], services: &[&str], vms: &[&str]) -> Result<Vec<Pick>> {
        picked_in(&shop(), names, services, vms, false)
    }

    #[test]
    fn services_and_environments_resolve_by_name() {
        use Pick::*;
        let shop = env("shop", "dev");
        let test = env("shop-test", "test");
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
            [Env(test.clone())]
        );
        // The state dir's own name still names an environment.
        assert_eq!(
            picked(&["shop-test-0123456789abcdef"], &[], &[]).unwrap(),
            [Env(test.clone())]
        );
        assert_eq!(
            picked(&["shop/db"], &[], &[]).unwrap(),
            [Service(shop.clone(), "db".into())]
        );
        assert_eq!(
            picked(&[], &["db"], &["shop-test"]).unwrap(),
            [Service(shop.clone(), "db".into()), Env(test)]
        );
        // Later aliases and explicit selectors do not repeat a positional target.
        assert_eq!(
            picked(&["db", "app", "shop/db"], &["db"], &["shop"]).unwrap(),
            [Service(shop.clone(), "db".into()), Env(shop)]
        );
    }

    /// `ENV/SERVICE` reads what that environment declares, whether or not it runs: its
    /// primary is the environment, a sibling a service, and a name it lacks is refused.
    #[test]
    fn a_qualified_name_goes_by_its_own_environment() {
        use Pick::*;
        let test = env("shop-test", "test");
        assert_eq!(
            picked(&["shop-test/web"], &[], &[]).unwrap(),
            [Env(test.clone())]
        );
        assert_eq!(
            picked(&["shop-test/queue"], &[], &[]).unwrap(),
            [Service(test, "queue".into())]
        );
        // `redis` is a service of this environment, not of `shop-test`.
        for name in ["shop-test/redis", "shop-test/typo", "shop/queue"] {
            let err = picked(&[name], &[], &[]).unwrap_err();
            assert!(err.to_string().contains("no service"), "{name}: {err}");
        }
    }

    /// A running environment's primary is the one its VM booted: after its config names another,
    /// a stop of the new one stops that service and leaves the VM up, and the old one is the VM.
    /// `up` boots from the config, so goes by the config's.
    #[test]
    fn a_running_environment_s_primary_is_the_one_it_booted() {
        use Pick::*;
        let mut scope = shop();
        let mut shop = env("shop", "dev");
        shop.primary = Some("db".into());
        scope.envs[0] = shop.clone();
        scope.current = Some(shop.clone());
        let mut test = env("shop-test", "test");
        test.primary = Some("db".into());
        scope.envs[1] = test.clone();
        assert_eq!(
            picked_in(
                &scope,
                &["app", "db", "shop-test/web", "shop-test/db"],
                &[],
                &[],
                false
            )
            .unwrap(),
            [
                Service(shop.clone(), "app".into()),
                Env(shop.clone()),
                Service(test.clone(), "web".into()),
                Env(test.clone()),
            ]
        );
        assert_eq!(
            picked_in(&scope, &["app", "shop-test/web"], &[], &[], true).unwrap(),
            [Env(shop), Env(test)]
        );
    }

    /// A name both a service and an environment is refused until `--service` or `--name`
    /// says which; a name elsewhere on the host is [`Outside`]; an unknown name lists what
    /// there is.
    #[test]
    fn ambiguous_outside_and_unknown_names_are_refused() {
        let mut scope = shop();
        scope.catalog.services.push("shop-test".into());
        let err = picked_in(&scope, &["shop-test"], &[], &[], false).unwrap_err();
        assert!(err.to_string().contains("--service shop-test"), "{err}");
        assert!(picked_in(&scope, &[], &["shop-test"], &[], false).is_ok());
        assert!(picked_in(&scope, &[], &[], &["shop-test"], false).is_ok());

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

    /// A word that is one environment's name and another's state dir name is refused.
    #[test]
    fn a_name_of_two_environments_is_refused() {
        let mut scope = shop();
        let mut odd = env("odd", "odd");
        odd.dir_name = "shop-test".into();
        scope.envs.push(odd);
        let err = picked_in(&scope, &["shop-test"], &[], &[], false).unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "{err}");
        let err = picked_in(&scope, &[], &[], &["shop-test"], false).unwrap_err();
        assert!(err.to_string().contains("ambiguous"), "{err}");
    }

    /// Before its first boot, an environment's services are `up`'s, which creates it, and
    /// not `start`'s, which only boots what an earlier `up` built.
    #[test]
    fn a_service_of_a_new_environment_is_up_s_only() {
        let mut scope = shop();
        scope.current = None;
        scope.envs.retain(|e| e.environment != "dev");
        for (names, services) in [(&["db"][..], &[][..]), (&[], &["db"])] {
            let err = picked_in(&scope, names, services, &[], false).unwrap_err();
            assert!(err.to_string().contains("`vk dev up`"), "{err}");
            assert_eq!(
                picked_in(&scope, names, services, &[], true).unwrap(),
                [Pick::Service(env("shop", "dev"), "db".into())]
            );
        }
        assert_eq!(
            picked_in(&scope, &["app"], &[], &[], true).unwrap(),
            [Pick::Env(env("shop", "dev"))]
        );
    }
}
