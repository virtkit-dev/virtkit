//! The configuration file: a subset of gitlab-runner's `config.toml`, with the same key
//! names where the setting is the same, plus each runner's placement on the fleet (the
//! pool, node labels and envelope its jobs get; see virtkit's `docs/gitlab-dispatch.md`).
//!
//! ```toml
//! concurrent = 8            # jobs at once, over all runners
//! check_interval = 3        # seconds between job requests while idle
//!
//! [[runners]]               # `[[runner]]` is accepted too
//! name = "ci"
//! url = "https://gitlab.example.com"
//! token_file = "/etc/vk-gitlab/runner-ci.token"
//! pool = "ci"
//! labels = ["large-memory"]
//! envelope = { mem = "16G", cpus = 8, disk = "16G" }
//! limit = 4                 # jobs at once for this runner (0 = no limit)
//! request_concurrency = 1   # job requests in flight at once
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::api::api_base_url;
use crate::secret::Secret;

/// gitlab-runner's `CheckInterval`.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(3);
pub const DEFAULT_UNHEALTHY_REQUESTS_LIMIT: u32 = 3;
pub const DEFAULT_UNHEALTHY_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Jobs running at once over all runners (gitlab-runner's `concurrent`). Default 1.
    #[serde(default = "one")]
    pub concurrent: usize,
    /// Seconds between job requests while there is nothing to do. Default 3.
    #[serde(default)]
    pub check_interval: u64,
    /// Seconds to wait for running jobs on shutdown before aborting them. Default 30.
    #[serde(default)]
    pub shutdown_timeout: u64,
    /// This runner manager's system ID; read from (or created in) `system_id_file` when
    /// unset.
    #[serde(default)]
    pub system_id: Option<String>,
    /// Where the system ID is kept. Default: `.vk-gitlab-system-id` beside the config file.
    #[serde(default)]
    pub system_id_file: Option<PathBuf>,
    #[serde(default, alias = "runner")]
    pub runners: Vec<RunnerConfig>,
}

fn one() -> usize {
    1
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    /// Shown in logs; defaults to the shortened token.
    #[serde(default)]
    pub name: String,
    /// The GitLab instance URL.
    pub url: String,
    /// The runner authentication token (`glrt-…`). Prefer `token_file`.
    #[serde(default)]
    token: Option<String>,
    /// A file holding the token, surrounding whitespace ignored.
    #[serde(default)]
    token_file: Option<PathBuf>,
    #[serde(rename = "tls-ca-file", default)]
    pub tls_ca_file: Option<PathBuf>,
    #[serde(rename = "tls-cert-file", default)]
    pub tls_cert_file: Option<PathBuf>,
    #[serde(rename = "tls-key-file", default)]
    pub tls_key_file: Option<PathBuf>,
    /// The hub pool this runner's jobs go to. Default `default`.
    #[serde(default = "default_pool")]
    pub pool: String,
    /// Labels a node must declare to take this runner's jobs; non-empty and distinct.
    #[serde(default)]
    pub labels: Vec<String>,
    /// What each job of this runner reserves on a node. Default 4G memory, 2 CPUs, 16G
    /// disk.
    #[serde(default)]
    pub envelope: EnvelopeConfig,
    /// Jobs at once for this runner; 0 means only `concurrent` applies.
    #[serde(default)]
    pub limit: usize,
    /// Job requests in flight at once; at least 1.
    #[serde(default)]
    pub request_concurrency: usize,
    /// Overrides the global `check_interval` for this runner, in seconds.
    #[serde(default)]
    pub check_interval: Option<u64>,
    /// Request the next job right after receiving one only when false (the default),
    /// otherwise wait `check_interval` as after an empty poll.
    #[serde(default)]
    pub strict_check_interval: bool,
    /// How much of a job's log vk-gitlab keeps and sends to GitLab, in KiB, plus 64 KiB for
    /// the node's limit notice and the runner's own lines; the rest is dropped. Default 4096.
    #[serde(default)]
    pub output_limit: usize,
    /// Consecutive failed requests before the runner is considered unhealthy; values below
    /// 1 mean the default, 3.
    #[serde(default)]
    pub unhealthy_requests_limit: Option<u32>,
    /// Longest pause, in seconds, an unhealthy runner waits before trying again; 0 never
    /// pauses. Default 3600.
    #[serde(default)]
    pub unhealthy_interval: Option<u64>,
    /// Attempts at the final job update. Default 10.
    #[serde(default)]
    pub job_status_final_update_retry_limit: Option<u32>,

    #[serde(skip)]
    resolved_token: Secret,
}

fn default_pool() -> String {
    "default".to_owned()
}

/// `envelope = { mem = "16G", cpus = 8, disk = "16G" }`: sizes as a number of bytes or with
/// a `K`, `M`, `G` or `T` suffix (powers of 1024).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeConfig {
    pub mem: String,
    pub cpus: u32,
    pub disk: String,
}

impl Default for EnvelopeConfig {
    fn default() -> Self {
        Self {
            mem: "4G".to_owned(),
            cpus: 2,
            disk: "16G".to_owned(),
        }
    }
}

/// `16G` → bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, shift) = match s.char_indices().last()? {
        (i, 'K' | 'k') => (&s[..i], 10),
        (i, 'M' | 'm') => (&s[..i], 20),
        (i, 'G' | 'g') => (&s[..i], 30),
        (i, 'T' | 't') => (&s[..i], 40),
        _ => (s, 0),
    };
    num.trim().parse::<u64>().ok()?.checked_mul(1u64 << shift)
}

impl EnvelopeConfig {
    pub fn envelope(&self) -> Result<crate::dispatch::Envelope> {
        let mem = parse_size(&self.mem).with_context(|| format!("envelope mem {:?}", self.mem))?;
        let disk =
            parse_size(&self.disk).with_context(|| format!("envelope disk {:?}", self.disk))?;
        if mem < 1 << 20 || self.cpus == 0 || disk == 0 {
            bail!("envelope: mem (at least 1M), cpus and disk must be set");
        }
        Ok(crate::dispatch::Envelope {
            mem_mib: mem >> 20,
            cpus: self.cpus,
            disk_bytes: disk,
        })
    }
}

impl std::fmt::Debug for RunnerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RunnerConfig")
            .field("name", &self.name)
            .field("url", &self.url)
            .field("token", &self.resolved_token)
            .field("pool", &self.pool)
            .finish_non_exhaustive()
    }
}

impl RunnerConfig {
    /// The runner token, resolved from `token` or `token_file` at load.
    pub fn token(&self) -> &Secret {
        &self.resolved_token
    }

    /// Where this runner's jobs go on the fleet.
    pub fn placement(&self) -> crate::dispatch::Placement {
        crate::dispatch::Placement {
            pool: self.pool.clone(),
            labels: self.labels.clone(),
            // Validated at load.
            envelope: self.envelope.envelope().unwrap_or_default(),
        }
    }

    pub fn request_concurrency(&self) -> usize {
        self.request_concurrency.max(1)
    }

    pub fn output_limit_bytes(&self) -> usize {
        match self.output_limit {
            0 => crate::trace::DEFAULT_OUTPUT_LIMIT,
            kib => kib.saturating_mul(1024),
        }
    }

    pub fn unhealthy_requests_limit(&self) -> u32 {
        // gitlab-runner's GetUnhealthyRequestsLimit: below 1 is the default.
        self.unhealthy_requests_limit
            .filter(|&n| n >= 1)
            .unwrap_or(DEFAULT_UNHEALTHY_REQUESTS_LIMIT)
    }

    pub fn unhealthy_interval(&self) -> Duration {
        self.unhealthy_interval
            .map_or(DEFAULT_UNHEALTHY_INTERVAL, Duration::from_secs)
    }

    pub fn final_update_retry_limit(&self) -> u32 {
        match self.job_status_final_update_retry_limit {
            Some(n) if n >= 1 => n,
            _ => crate::trace::DEFAULT_FINAL_UPDATE_RETRY_LIMIT,
        }
    }
}

impl Config {
    /// Reads and validates `path`; relative paths in it are taken from its directory.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        let mut cfg =
            Self::parse(&text, base).with_context(|| format!("loading {}", path.display()))?;
        if cfg.system_id_file.is_none() {
            cfg.system_id_file = Some(base.join(".vk-gitlab-system-id"));
        }
        Ok(cfg)
    }

    /// Parses `text`, resolving relative paths against `base`.
    pub fn parse(text: &str, base: &Path) -> Result<Self> {
        let mut cfg: Config = toml::from_str(text)?;
        if cfg.concurrent == 0 {
            bail!("concurrent must be at least 1");
        }
        if let Some(f) = &cfg.system_id_file {
            cfg.system_id_file = Some(base.join(f));
        }
        let mut names = HashSet::new();
        for (i, r) in cfg.runners.iter_mut().enumerate() {
            let which = if r.name.is_empty() {
                format!("runner #{}", i + 1)
            } else {
                format!("runner {:?}", r.name)
            };
            api_base_url(&r.url).map_err(|e| anyhow::anyhow!("{which}: url {:?}: {e}", r.url))?;
            r.resolved_token = match (&r.token, &r.token_file) {
                (Some(t), None) => Secret::new(t.trim()),
                (None, Some(file)) => {
                    let file = base.join(file);
                    let raw = std::fs::read_to_string(&file).with_context(|| {
                        format!("{which}: reading token_file {}", file.display())
                    })?;
                    Secret::new(raw.trim())
                }
                (Some(_), Some(_)) => bail!("{which}: set token or token_file, not both"),
                (None, None) => bail!("{which}: token or token_file is required"),
            };
            if r.resolved_token.is_empty() {
                bail!("{which}: the token is empty");
            }
            for f in [
                &mut r.tls_ca_file,
                &mut r.tls_cert_file,
                &mut r.tls_key_file,
            ]
            .into_iter()
            .flatten()
            {
                *f = base.join(&*f);
            }
            if r.tls_cert_file.is_some() != r.tls_key_file.is_some() {
                bail!("{which}: tls-cert-file and tls-key-file go together");
            }
            if r.name.is_empty() {
                r.name = r.resolved_token.short();
            }
            r.envelope.envelope().with_context(|| which.clone())?;
            if r.pool.is_empty() {
                bail!("{which}: pool must not be empty");
            }
            let mut labels = HashSet::new();
            for l in &r.labels {
                if l.trim().is_empty() {
                    bail!("{which}: labels must not be empty");
                }
                if !labels.insert(l.as_str()) {
                    bail!("{which}: label {l:?} is listed twice");
                }
            }
            if !names.insert(r.name.clone()) {
                bail!("{which}: runner names must be unique");
            }
        }
        Ok(cfg)
    }

    pub fn check_interval(&self) -> Duration {
        match self.check_interval {
            0 => DEFAULT_CHECK_INTERVAL,
            s => Duration::from_secs(s),
        }
    }

    pub fn runner_check_interval(&self, r: &RunnerConfig) -> Duration {
        match r.check_interval {
            Some(s) if s > 0 => Duration::from_secs(s),
            _ => self.check_interval(),
        }
    }

    pub fn shutdown_timeout(&self) -> Duration {
        match self.shutdown_timeout {
            0 => Duration::from_secs(30),
            s => Duration::from_secs(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Config> {
        Config::parse(text, Path::new("/etc/vk-gitlab"))
    }

    #[test]
    fn minimal_runner() {
        let cfg = parse(
            r#"
            [[runner]]
            url = "https://gitlab.example.com/"
            token = " glrt-t1_abcdefghijklmnop "
            "#,
        )
        .unwrap();
        assert_eq!(cfg.concurrent, 1);
        assert_eq!(cfg.check_interval(), DEFAULT_CHECK_INTERVAL);
        let r = &cfg.runners[0];
        assert_eq!(r.token().expose(), "glrt-t1_abcdefghijklmnop");
        assert_eq!(r.name, "abcdefghi");
        assert_eq!(r.pool, "default");
        assert_eq!(r.request_concurrency(), 1);
        assert_eq!(r.output_limit_bytes(), 4 * 1024 * 1024);
        assert_eq!(r.final_update_retry_limit(), 10);
        assert_eq!(
            r.placement().envelope,
            crate::dispatch::Envelope {
                mem_mib: 4096,
                cpus: 2,
                disk_bytes: 16 << 30
            }
        );
    }

    #[test]
    fn sizes() {
        assert_eq!(parse_size("16G"), Some(16 << 30));
        assert_eq!(parse_size("512m"), Some(512 << 20));
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("1T"), Some(1 << 40));
        assert_eq!(parse_size("G"), None);
        assert_eq!(parse_size("-1G"), None);
        assert_eq!(parse_size("99999999999T"), None);
    }

    #[test]
    fn full_runner() {
        let cfg = parse(
            r#"
            concurrent = 8
            check_interval = 5
            [[runners]]
            name = "fleet"
            url = "https://gitlab.example.com"
            token = "glrt-x"
            tls-ca-file = "ca.pem"
            pool = "big"
            limit = 4
            request_concurrency = 2
            check_interval = 1
            output_limit = 100
            labels = ["large-memory"]
            envelope = { mem = "16G", cpus = 8, disk = "512M" }
            "#,
        )
        .unwrap();
        let r = &cfg.runners[0];
        assert_eq!(
            r.tls_ca_file.as_deref(),
            Some(Path::new("/etc/vk-gitlab/ca.pem"))
        );
        assert_eq!(cfg.runner_check_interval(r), Duration::from_secs(1));
        assert_eq!(r.output_limit_bytes(), 100 * 1024);
        let p = r.placement();
        assert_eq!(p.labels, ["large-memory"]);
        assert_eq!(p.envelope.mem_mib, 16 * 1024);
        assert_eq!(p.envelope.cpus, 8);
        assert_eq!(p.envelope.disk_bytes, 512 << 20);
    }

    #[test]
    fn rejects_bad_configs() {
        for (text, needle) in [
            (
                "[[runners]]\nurl = \"https://g\"\n",
                "token or token_file is required",
            ),
            (
                "[[runners]]\nurl = \"https://g\"\ntoken = \"a\"\ntoken_file = \"f\"\n",
                "not both",
            ),
            (
                "[[runners]]\nurl = \"gitlab\"\ntoken = \"a\"\n",
                "only http or https",
            ),
            (
                "[[runners]]\nurl = \"https://g\"\ntoken = \"a\"\ntypo = 1\n",
                "unknown field",
            ),
            ("concurent = 2\n", "unknown field"),
            ("concurrent = 0\n", "at least 1"),
            (
                "[[runners]]\nurl = \"https://g\"\ntoken = \"a\"\nenvelope = { mem = \"lots\", cpus = 1, disk = \"1G\" }\n",
                "envelope mem",
            ),
            (
                "[[runners]]\nname = \"a\"\nurl = \"https://g\"\ntoken = \"x\"\n[[runners]]\nname = \"a\"\nurl = \"https://g\"\ntoken = \"y\"\n",
                "unique",
            ),
            (
                "[[runners]]\nurl = \"https://g\"\ntoken = \"a\"\ntls-cert-file = \"c\"\n",
                "go together",
            ),
            (
                "[[runners]]\nurl = \"https://g\"\ntoken = \"a\"\nlabels = [\"\"]\n",
                "labels must not be empty",
            ),
            (
                "[[runners]]\nurl = \"https://g\"\ntoken = \"a\"\nlabels = [\"x\", \"x\"]\n",
                "listed twice",
            ),
        ] {
            let err = format!("{:#}", parse(text).unwrap_err());
            assert!(err.contains(needle), "{text}: {err}");
        }
    }

    #[test]
    fn unhealthy_requests_limit_below_one_is_the_default() {
        for (set, want) in [
            ("", 3),
            ("unhealthy_requests_limit = 0\n", 3),
            ("unhealthy_requests_limit = 5\n", 5),
        ] {
            let cfg = parse(&format!(
                "[[runners]]\nurl = \"https://g\"\ntoken = \"a\"\n{set}"
            ))
            .unwrap();
            assert_eq!(cfg.runners[0].unhealthy_requests_limit(), want, "{set}");
        }
    }

    #[test]
    fn debug_hides_the_token() {
        let cfg =
            parse("[[runners]]\nurl = \"https://g\"\ntoken = \"glrt-secretvalue\"\n").unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("secretvalue"), "{dbg}");
    }
}
