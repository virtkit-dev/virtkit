//! CI `services:` support (host-mediated, Path B).
//!
//! GitLab passes a job's `services:` to any executor as the `CI_JOB_SERVICES`
//! JSON (here `CUSTOM_ENV_CI_JOB_SERVICES`). We run each service as a container
//! *inside* the job VM, reachable by its alias — but the image is pulled through
//! the host registry pull-through proxy over a vsock forward, so the registry
//! credential never enters the guest. This module is pure: it parses the
//! services, rewrites each image onto the guest-local proxy endpoint, and emits
//! the root shell script vm::prepare runs in the guest. Everything job-derived
//! is validated or shell-quoted — the script is assembled from untrusted input.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use serde::Deserialize;

use crate::config::Services as ServicesCfg;

/// One `CI_JOB_SERVICES` entry. GitLab also sets `entrypoint`/`command`; we only
/// model what backing stores need, and serde ignores the rest.
#[derive(Debug, Deserialize)]
pub struct Service {
    /// Image reference, with the registry already variable-expanded by GitLab.
    pub name: String,
    /// Hostname the job reaches the service by; defaults from the image name.
    #[serde(default)]
    pub alias: String,
    /// Per-service environment (the service-level `variables:`).
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
}

/// Parse the job's services from the environment. Empty/unset = no services.
pub fn from_env() -> Result<Vec<Service>> {
    let raw = match std::env::var("CUSTOM_ENV_CI_JOB_SERVICES") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => return Ok(Vec::new()),
    };
    let mut services: Vec<Service> = serde_json::from_str(&raw)
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

/// The alias lands in `docker --name` and an `/etc/hosts` line in a generated
/// script: keep it to characters that cannot break out of either.
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

/// Swap the image's registry for the guest-local proxy endpoint, keeping the
/// repository path: `registry.example.com/team/db:tag` with endpoint
/// `127.0.0.1:5000` -> `127.0.0.1:5000/team/db:tag`. A bare name (docker.io image,
/// no registry component) is prefixed as-is.
fn rewrite_ref(image: &str, endpoint: &str) -> String {
    let path = match image.split_once('/') {
        Some((host, rest)) if host.contains('.') || host.contains(':') || host == "localhost" => {
            rest
        }
        _ => image,
    };
    format!("{endpoint}/{path}")
}

/// Wrap a string in single quotes for safe inclusion in the generated script.
fn sh_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

const SERVICE_BLOCK: &str = r#"
echo 'ci-services: starting __ALIAS__'
docker rm -f __ALIAS_Q__ >/dev/null 2>&1 || true
docker run -d --name __ALIAS_Q____ENV__ __REF_Q__
svc_ip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' __ALIAS_Q__)
[ -n "$svc_ip" ] || { echo 'ci-services: __ALIAS__ has no IP' >&2; exit 1; }
svc_port=$(docker inspect -f '{{range $p, $_ := .Config.ExposedPorts}}{{$p}}{{"\n"}}{{end}}' __ALIAS_Q__ | head -1 | cut -d/ -f1)
printf '%s %s\n' "$svc_ip" __ALIAS_Q__ >>/etc/hosts
if [ -n "$svc_port" ]; then
  for _i in $(seq 1 __TRIES__); do (echo >"/dev/tcp/$svc_ip/$svc_port") 2>/dev/null && break; sleep 0.1; done
fi
echo "ci-services: __ALIAS__ ready at $svc_ip:${svc_port:-?}"
"#;

/// The root script vm::prepare pipes into the guest: start the guest-side
/// registry forward (survives the script — torn down with the VM), then bring up
/// each service container, alias it in /etc/hosts, and wait for its port.
pub fn setup_script(cfg: &ServicesCfg, services: &[Service]) -> String {
    let tries = cfg.ready_timeout_secs * 10; // sleep 0.1 per try
    let mut s = String::new();
    s.push_str("set -euo pipefail\n");
    s.push_str("echo 'ci-services: starting the registry forward'\n");
    // guest -> host registry forward; setsid so it outlives this script (the VM
    // teardown reaps it). 127.0.0.1 is auto-insecure in docker, so no daemon
    // config is needed for the rewritten refs.
    s.push_str(&format!(
        "setsid /usr/local/bin/virtkit-agent --socket vsock://{port} forward \
         --listen tcp://127.0.0.1:{port} </dev/null >/var/log/ci-services-forward.log 2>&1 &\n",
        port = cfg.port,
    ));
    // wait for the forward's listener before the first pull races it
    s.push_str(&format!(
        "for _i in $(seq 1 50); do (echo >/dev/tcp/127.0.0.1/{port}) 2>/dev/null && break; sleep 0.1; done\n",
        port = cfg.port,
    ));

    let endpoint = format!("127.0.0.1:{}", cfg.port);
    for svc in services {
        let alias_q = sh_quote(&svc.alias);
        let ref_q = sh_quote(&rewrite_ref(&svc.name, &endpoint));
        let env: String = svc
            .variables
            .iter()
            .map(|(k, v)| format!(" -e {}", sh_quote(&format!("{k}={v}"))))
            .collect();
        s.push_str(
            &SERVICE_BLOCK
                .replace("__ALIAS_Q__", &alias_q)
                .replace("__ENV__", &env)
                .replace("__REF_Q__", &ref_q)
                .replace("__ALIAS__", &svc.alias)
                .replace("__TRIES__", &tries.to_string()),
        );
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_swaps_registry_keeps_path() {
        assert_eq!(
            rewrite_ref("registry.example.com/team/db:abc", "127.0.0.1:5000"),
            "127.0.0.1:5000/team/db:abc"
        );
        // registry with a port
        assert_eq!(
            rewrite_ref("192.0.2.10:5000/team/cache:1", "127.0.0.1:5000"),
            "127.0.0.1:5000/team/cache:1"
        );
        // bare name (no registry component) is prefixed as-is
        assert_eq!(
            rewrite_ref("redis:7", "127.0.0.1:5000"),
            "127.0.0.1:5000/redis:7"
        );
    }

    #[test]
    fn sh_quote_escapes() {
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn alias_validation_rejects_injection() {
        assert!(validate_alias("srv_mysql").is_ok());
        assert!(validate_alias("srv-mysql.1").is_ok());
        assert!(validate_alias("a;rm -rf").is_err());
        assert!(validate_alias("$(touch x)").is_err());
        assert!(validate_alias("").is_err());
    }

    #[test]
    fn parses_services_json_and_defaults_alias() {
        let json = r#"[
            {"name":"reg.example.com/team/db:1","alias":"srv_mysql"},
            {"name":"reg.io/team/cache:2","variables":{"X":"y"}}
        ]"#;
        // SAFETY: tests are single-threaded per process here; set + parse + clear
        unsafe { std::env::set_var("CUSTOM_ENV_CI_JOB_SERVICES", json) };
        let svcs = from_env().unwrap();
        unsafe { std::env::remove_var("CUSTOM_ENV_CI_JOB_SERVICES") };
        assert_eq!(svcs.len(), 2);
        assert_eq!(svcs[0].alias, "srv_mysql");
        // second has no alias -> derived (registry stripped, path flattened)
        assert_eq!(svcs[1].alias, "team__cache");
        assert_eq!(svcs[1].variables.get("X").unwrap(), "y");
    }

    #[test]
    fn setup_script_runs_and_aliases_each_service() {
        let cfg = ServicesCfg::default();
        let svcs = vec![Service {
            name: "registry.example.com/team/db:abc".into(),
            alias: "srv_mysql".into(),
            variables: BTreeMap::new(),
        }];
        let script = setup_script(&cfg, &svcs);
        assert!(script.contains("forward --listen tcp://127.0.0.1:5000"));
        assert!(script.contains("docker run -d --name 'srv_mysql' '127.0.0.1:5000/team/db:abc'"));
        assert!(script.contains("\"$svc_ip\" 'srv_mysql' >>/etc/hosts"));
    }
}
