//! CI `services:` support: each service is a sibling microVM on the per-job
//! switch, exactly a compose unit.
//!
//! GitLab passes a job's `services:` to any executor as the `CI_JOB_SERVICES`
//! JSON (here `CUSTOM_ENV_CI_JOB_SERVICES`). This module is pure: it parses the
//! entries and maps them onto compose units, which the job supervisor
//! provisions (shared content-addressed store) and boots via the shared `units`
//! machinery — clean images, config at boot, resolvable by alias over the
//! switch's DNS. No docker in the job image, no registry proxy: the host pulls
//! service images itself, so registry credentials never enter any guest.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::{Deserialize, Deserializer};

/// Deserialize a possibly-`null` field as its `Default`. `#[serde(default)]`
/// alone only covers a *missing* key; GitLab runner 19.1 serializes an unset
/// `entrypoint`/`command` as an explicit `null`, which would otherwise fail
/// against a non-`Option` type. Applied uniformly to every optional field
/// (`alias`/`variables` too) so any of them tolerates an explicit `null`.
fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    Ok(Option::deserialize(deserializer)?.unwrap_or_default())
}

/// One `CI_JOB_SERVICES` entry — the subset of the runner's serialization we
/// consume (any other key the runner emits is ignored).
#[derive(Debug, Deserialize)]
pub struct Service {
    /// Image reference, with the registry already variable-expanded by GitLab.
    pub name: String,
    /// Hostname the job reaches the service by; defaults from the image name.
    #[serde(default, deserialize_with = "null_default")]
    pub alias: String,
    /// Per-service environment (the service-level `variables:`).
    #[serde(default, deserialize_with = "null_default")]
    pub variables: BTreeMap<String, String>,
    /// Entrypoint override (argv array); empty = the image's own.
    #[serde(default, deserialize_with = "null_default")]
    pub entrypoint: Vec<String>,
    /// Command override (argv array); empty = the image's own.
    #[serde(default, deserialize_with = "null_default")]
    pub command: Vec<String>,
}

/// Map the job's services onto compose units — the run/CI service shape — so a
/// CI service is provisioned and booted by the shared `units` machinery instead of a
/// bespoke path. Image-only (a GitLab service has no build context); the alias
/// becomes both the unit name and the guest hostname (it is what the job resolves);
/// `variables:` become environment overrides with compose semantics.
pub fn to_units(services: Vec<Service>) -> Vec<crate::compose::Unit> {
    services
        .into_iter()
        .map(|s| crate::compose::Unit {
            name: s.alias.clone(),
            hostname: s.alias,
            source: crate::compose::Source::Image(s.name),
            environment: s.variables.into_iter().collect(),
            entrypoint: (!s.entrypoint.is_empty()).then_some(s.entrypoint),
            command: (!s.command.is_empty()).then_some(s.command),
            user: None,
            depends_on: Vec::new(),
            volumes: Vec::new(),
            profiles: Vec::new(),
            // The GitLab `services:` model has no init/kernel axes: every executor
            // service keeps the default agent-as-PID1 pinned-kernel boot.
            init: crate::run::InitSource::Default,
            kernel: crate::run::KernelSource::Default,
        })
        .collect()
}

/// Parse the job's services from the environment. Empty/unset = no services.
pub fn from_env() -> Result<Vec<Service>> {
    parse(std::env::var("CUSTOM_ENV_CI_JOB_SERVICES").ok().as_deref())
}

/// Parse the `CI_JOB_SERVICES` payload, taken as a value rather than read from the
/// environment: a test that set the variable would be mutating process-wide state every other
/// test in the binary shares. Absent or blank = no services, which is what a job with no
/// `services:` sends.
fn parse(raw: Option<&str>) -> Result<Vec<Service>> {
    let Some(raw) = raw.filter(|s| !s.trim().is_empty()) else {
        return Ok(Vec::new());
    };
    let mut services: Vec<Service> = serde_json::from_str(raw)
        .map_err(|e| anyhow::anyhow!("parsing CI_JOB_SERVICES ({e}): {raw}"))?;
    for s in &mut services {
        if s.alias.is_empty() {
            s.alias = default_alias(&s.name);
        }
        validate_alias(&s.alias)?;
    }
    Ok(services)
}

/// GitLab's fallback alias: the image name with the registry/tag stripped and
/// the path separators flattened (e.g. `r/foo/bar:1` -> `foo__bar`). Our jobs
/// always set an explicit alias; this only covers the unusual unset case.
fn default_alias(image: &str) -> String {
    let no_tag = image.split(['@', ':']).next().unwrap_or(image);
    let path = no_tag.split_once('/').map_or(no_tag, |(_, rest)| rest);
    path.replace('/', "__")
}

/// The alias becomes the unit hostname and lands unquoted in VIRTKIT_HOSTNAME on
/// a kernel cmdline and in the switch's --host flag: keep it to characters that
/// cannot break out of either.
fn validate_alias(alias: &str) -> Result<()> {
    if alias.is_empty()
        || !alias
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid service alias {alias:?} (allowed: alphanumerics, '-', '_', '.')");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_validation_rejects_injection() {
        assert!(validate_alias("srv_mysql").is_ok());
        assert!(validate_alias("srv-mysql.1").is_ok());
        assert!(validate_alias("a;rm -rf").is_err());
        assert!(validate_alias("$(touch x)").is_err());
        assert!(validate_alias("").is_err());
    }

    #[test]
    fn no_payload_is_no_services() {
        // A job with no `services:` reaches the executor as an unset variable on one runner
        // version and as an empty string on another; both mean the same thing.
        assert!(parse(None).unwrap().is_empty());
        assert!(parse(Some("")).unwrap().is_empty());
        assert!(parse(Some(" \n")).unwrap().is_empty());
    }

    #[test]
    fn a_malformed_payload_is_an_error() {
        // The error names the variable and carries the payload, which is what a job trace
        // needs to show for the runner's own bug to be findable.
        let err = parse(Some("not json")).unwrap_err().to_string();
        assert!(err.contains("CI_JOB_SERVICES"), "{err}");
        assert!(err.contains("not json"), "{err}");
    }

    #[test]
    fn parses_services_json_and_defaults_alias() {
        let json = r#"[
            {"name":"reg.example.com/team/db:1","alias":"srv_mysql",
             "entrypoint":["/bin/db","--init"],"command":["--port","3307"]},
            {"name":"reg.io/team/cache:2","variables":{"X":"y"}}
        ]"#;
        let svcs = parse(Some(json)).unwrap();
        assert_eq!(svcs.len(), 2);
        assert_eq!(svcs[0].alias, "srv_mysql");
        assert_eq!(svcs[0].entrypoint, ["/bin/db", "--init"]);
        assert_eq!(svcs[0].command, ["--port", "3307"]);
        // second has no alias -> derived (registry stripped, path flattened)
        assert_eq!(svcs[1].alias, "team__cache");
        assert_eq!(svcs[1].variables.get("X").unwrap(), "y");
        assert!(svcs[1].entrypoint.is_empty() && svcs[1].command.is_empty());
    }

    #[test]
    fn parses_explicit_null_optional_fields() {
        // GitLab runner 19.1 serializes an unset optional field as `null`
        // rather than omitting the key; null must map to the empty default
        // for every optional field, not just entrypoint/command.
        let json = r#"[
            {"name":"reg.io/team/db:1","alias":null,"variables":null,"entrypoint":null,"command":null}
        ]"#;
        let svcs = parse(Some(json)).unwrap();
        assert_eq!(svcs.len(), 1);
        // alias:null -> empty -> derived from the image name
        assert_eq!(svcs[0].alias, "team__db");
        assert!(svcs[0].variables.is_empty());
        assert!(svcs[0].entrypoint.is_empty() && svcs[0].command.is_empty());
    }

    #[test]
    fn services_map_onto_compose_units() {
        let units = to_units(vec![
            Service {
                name: "reg.io/team/db:1".into(),
                alias: "db".into(),
                variables: [("PORT".to_string(), "3307".to_string())].into(),
                entrypoint: vec!["/bin/db".into()],
                command: vec!["--fast".into()],
            },
            Service {
                name: "redis:7".into(),
                alias: "redis".into(),
                variables: BTreeMap::new(),
                entrypoint: vec![],
                command: vec![],
            },
        ]);
        let db = &units[0];
        assert_eq!((db.name.as_str(), db.hostname.as_str()), ("db", "db"));
        assert!(matches!(&db.source, crate::compose::Source::Image(i) if i == "reg.io/team/db:1"));
        assert_eq!(db.environment, [("PORT".to_string(), "3307".to_string())]);
        assert_eq!(db.entrypoint.as_deref().unwrap(), ["/bin/db"]);
        assert_eq!(db.command.as_deref().unwrap(), ["--fast"]);
        // empty overrides map to None: the image's own entrypoint/cmd apply.
        let redis = &units[1];
        assert!(redis.entrypoint.is_none() && redis.command.is_none());
        assert!(redis.environment.is_empty() && redis.volumes.is_empty());
        assert!(redis.depends_on.is_empty() && redis.profiles.is_empty());
    }
}
