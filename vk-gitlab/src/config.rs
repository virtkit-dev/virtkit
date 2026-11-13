//! The configuration file: a subset of gitlab-runner's `config.toml`, with the same key
//! names where the setting is the same, plus what each runner's jobs ask of a node (the
//! labels and envelope; where they run is the runner's lane on the hub; see
//! `docs/gitlab-dispatch.md`).
//!
//! ```toml
//! concurrent = 8            # jobs at once, over all runners (at most 128)
//! check_interval = 3        # seconds between job requests while idle
//!
//! state_dir = "/var/lib/vk-gitlab"   # each runner's taken jobs
//!
//! [gitlab]
//! url = "https://gitlab.example.com"   # the one GitLab server every runner takes jobs from
//!
//! [[runners]]
//! name = "ci"
//! token_file = "/etc/vk-gitlab/runner-ci.token"
//! labels = ["large-memory"]
//! envelope = { mem = "16G", cpus = 8, disk = "16G" }
//! limit = 4                 # jobs at once for this runner (0 = no limit)
//! request_concurrency = 1   # job requests queued or in flight at once (at most 128)
//!
//! [hub]                     # optional: what the hub this relay is enrolled with may do
//! allow = ["update"]        # update vk-gitlab to a release the hub holds; "runners" lets
//!                           # it add runners and remove them
//! release_keys = ["…"]      # an update must be signed by one of these
//! # require_signed = true   # the default once release_keys names a key
//! # allow_downgrade = false # whether an update may install an older version
//! ```

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use vk_hub_proto::gitlab::RunnerPlacement;

use crate::api::api_base_url;
use crate::secret::Secret;

/// gitlab-runner's `CheckInterval`.
pub const DEFAULT_CHECK_INTERVAL: Duration = Duration::from_secs(3);
pub const DEFAULT_UNHEALTHY_REQUESTS_LIMIT: u32 = 3;
pub const DEFAULT_STATE_DIR: &str = "/var/lib/vk-gitlab";
pub const DEFAULT_UNHEALTHY_INTERVAL: Duration = Duration::from_secs(60 * 60);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Jobs running at once over all runners (gitlab-runner's `concurrent`). Default 1, at most
    /// [`MAX_ADMISSIONS`](vk_hub_proto::gitlab::MAX_ADMISSIONS).
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
    /// Where each runner's state file (`<runner name>.json`) is kept. Default
    /// `/var/lib/vk-gitlab`.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// The GitLab server the runners take jobs from; required with runners.
    #[serde(default)]
    pub gitlab: Option<GitlabConfig>,
    /// At most [`MAX_RUNNERS`](vk_hub_proto::gitlab::MAX_RUNNERS).
    #[serde(default)]
    pub runners: Vec<RunnerConfig>,
    /// What the hub may do to this relay; by default nothing but run its jobs.
    #[serde(default)]
    pub hub: HubConfig,
}

/// `[hub]`: what the hub the relay is enrolled with may do beyond running its jobs.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    /// What the hub may ask: `update`, to install a `vk-gitlab` release it holds; `runners`,
    /// to add runners and remove them.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Ed25519 public keys, base64, an update must be signed by one of.
    #[serde(default)]
    pub release_keys: Vec<String>,
    /// Whether an update must be signed; by default, when `release_keys` names any.
    #[serde(default)]
    pub require_signed: Option<bool>,
    /// Whether an update may install an older version.
    #[serde(default)]
    pub allow_downgrade: bool,
}

impl HubConfig {
    /// Whether the hub may do what [`vk_hub_proto::gitlab`]'s `ALLOW_*` value `what` names.
    pub fn allows(&self, what: &str) -> bool {
        self.allow.iter().any(|a| a == what)
    }

    /// The signature policy `release_keys` and `require_signed` set for `vk-gitlab` releases.
    pub fn release_policy(&self) -> Result<vk_peer::release_key::Policy> {
        vk_peer::release_key::Policy::from_config_in(
            "[hub]",
            vk_peer::release_key::Program::Gitlab,
            &self.release_keys,
            self.require_signed,
        )
    }
}

/// `[gitlab]`: the one GitLab server of this daemon.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitlabConfig {
    /// The GitLab instance URL.
    pub url: String,
}

fn one() -> usize {
    1
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunnerConfig {
    /// Shown in logs and names the runner's state file; defaults to the shortened token.
    /// Set it explicitly: with the default, a new token starts an empty state file and
    /// the old one's jobs are no longer resumed.
    #[serde(default)]
    pub name: String,
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
    /// Before 0.111, the hub pool its jobs went to; the runner's lane on the hub decides now.
    /// Read so a config from then still loads, warned about and ignored.
    #[serde(default)]
    pool: Option<String>,
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
    /// Job requests queued at the hub or in flight to GitLab at once; at least 1, at most
    /// [`MAX_ADMISSIONS`](vk_hub_proto::gitlab::MAX_ADMISSIONS).
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
    /// For a runner added on the hub, where it came from; `None` for the config's.
    #[serde(skip)]
    pub hub: Option<HubOrigin>,
}

/// What a runner added on the hub keeps beside its settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HubOrigin {
    /// The command that added it.
    pub command: String,
    /// Its GitLab runner ID, as `verify` returned it.
    pub runner_id: u64,
    /// Being removed: it asks for no job, and goes once its jobs have ended.
    pub removed: bool,
}

/// Whether `name` may name a runner: it names the runner's files.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !name.starts_with('.')
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
            .field("token", &self.resolved_token)
            .finish_non_exhaustive()
    }
}

impl RunnerConfig {
    /// A runner added on the hub: `name`, `token` and the settings of an `add_runner`
    /// command, checked as a `[[runners]]` table is.
    pub fn from_hub(
        name: &str,
        token: &str,
        placement: &RunnerPlacement,
        limit: Option<u32>,
        request_concurrency: u32,
        hub: HubOrigin,
    ) -> Result<Self> {
        let mut r = RunnerConfig {
            name: name.to_owned(),
            token: None,
            token_file: None,
            tls_ca_file: None,
            tls_cert_file: None,
            tls_key_file: None,
            pool: None,
            labels: placement.labels.clone(),
            envelope: EnvelopeConfig {
                mem: format!("{}M", placement.envelope.mem_mib),
                cpus: placement.envelope.cpus,
                disk: placement.envelope.disk_bytes.to_string(),
            },
            limit: limit.map_or(0, |l| usize::try_from(l).unwrap_or(usize::MAX)),
            request_concurrency: usize::try_from(request_concurrency).unwrap_or(usize::MAX),
            check_interval: None,
            strict_check_interval: false,
            output_limit: 0,
            unhealthy_requests_limit: None,
            unhealthy_interval: None,
            job_status_final_update_retry_limit: None,
            resolved_token: Secret::new(token.trim()),
            hub: Some(hub),
        };
        let which = format!("runner {name:?}");
        if r.resolved_token.is_empty() {
            bail!("{which}: the token is empty");
        }
        if r.name.is_empty() {
            bail!("{which}: a runner added on the hub requires a name");
        }
        r.check(&which)?;
        Ok(r)
    }

    /// The checks every runner's settings pass, wherever they come from.
    fn check(&mut self, which: &str) -> Result<()> {
        if self.request_concurrency() > vk_hub_proto::gitlab::MAX_ADMISSIONS {
            bail!("{which}: request_concurrency exceeds the hub's admission limit");
        }
        self.envelope.envelope().with_context(|| which.to_owned())?;
        if let Some(pool) = self.pool.take() {
            log::warn!(
                runner = self.name.as_str(),
                pool = pool.as_str();
                "`pool` is ignored since 0.111: the runner's lane on the hub selects where its jobs run; drop it from the config"
            );
        }
        let mut labels = HashSet::new();
        for l in &self.labels {
            if l.trim().is_empty() {
                bail!("{which}: labels must not be empty");
            }
            if !labels.insert(l.as_str()) {
                bail!("{which}: label {l:?} is listed twice");
            }
        }
        if !valid_name(&self.name) {
            bail!("{which}: a runner name is letters, digits, `-`, `_` and `.`");
        }
        Ok(())
    }

    /// The runner token, resolved from `token` or `token_file` at load.
    pub fn token(&self) -> &Secret {
        &self.resolved_token
    }

    /// What this runner's jobs ask of a node, as the hub's client API takes it: no pool, its
    /// lane on the hub selecting where they go.
    pub fn placement(&self) -> crate::dispatch::Placement {
        crate::dispatch::Placement {
            pool: String::new(),
            labels: self.labels.clone(),
            // Validated at load.
            envelope: self.envelope.envelope().unwrap_or_default(),
        }
    }

    /// What this runner's jobs ask of a node, as the relay reports it.
    pub fn runner_placement(&self) -> RunnerPlacement {
        RunnerPlacement {
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
        if cfg.concurrent > vk_hub_proto::gitlab::MAX_ADMISSIONS {
            bail!("concurrent exceeds the hub's admission limit");
        }
        if cfg.runners.len() > vk_hub_proto::gitlab::MAX_RUNNERS {
            bail!("too many runners for the hub session");
        }
        cfg.state_dir = Some(
            base.join(
                cfg.state_dir
                    .as_deref()
                    .unwrap_or(Path::new(DEFAULT_STATE_DIR)),
            ),
        );
        if let Some(f) = &cfg.system_id_file {
            cfg.system_id_file = Some(base.join(f));
        }
        match &cfg.gitlab {
            Some(g) => {
                let url = api_base_url(&g.url)
                    .map_err(|e| anyhow::anyhow!("gitlab: url {:?}: {e}", g.url))?;
                // The URL is the server's identity on the hub, which takes none of these.
                if !url.username().is_empty()
                    || url.password().is_some()
                    || g.url.contains(['?', '#'])
                {
                    bail!("gitlab: url {:?}: no credentials, query or fragment", g.url);
                }
            }
            None if !cfg.runners.is_empty() => {
                bail!("[gitlab] url is required: the GitLab server the runners take jobs from")
            }
            None => {}
        }
        for a in &cfg.hub.allow {
            if a != vk_hub_proto::gitlab::ALLOW_UPDATE && a != vk_hub_proto::gitlab::ALLOW_RUNNERS {
                bail!(
                    "[hub] allow: {a:?} is not something the hub may do; only {:?} and {:?}",
                    vk_hub_proto::gitlab::ALLOW_UPDATE,
                    vk_hub_proto::gitlab::ALLOW_RUNNERS
                );
            }
        }
        if cfg.gitlab.is_none() && cfg.hub.allows(vk_hub_proto::gitlab::ALLOW_RUNNERS) {
            bail!(
                "[gitlab] url is required: the GitLab server the runners the hub adds take jobs \
                 from"
            );
        }
        cfg.hub.release_policy()?;
        let mut names = HashSet::new();
        for (i, r) in cfg.runners.iter_mut().enumerate() {
            let which = if r.name.is_empty() {
                format!("runner #{}", i + 1)
            } else {
                format!("runner {:?}", r.name)
            };
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
            r.check(&which)?;
            if !names.insert(r.name.clone()) {
                bail!("{which}: runner names must be unique");
            }
        }
        Ok(cfg)
    }

    /// Whether the hub may add runners to this relay and remove them.
    pub fn takes_runners(&self) -> bool {
        self.hub.allows(vk_hub_proto::gitlab::ALLOW_RUNNERS)
    }

    /// The GitLab server's URL; empty without `[gitlab]`, which only a config without
    /// runners may leave out.
    pub fn gitlab_url(&self) -> &str {
        self.gitlab.as_ref().map_or("", |g| g.url.as_str())
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
            [gitlab]
            url = "https://gitlab.example.com/"
            [[runners]]
            token = " glrt-t1_abcdefghijklmnop "
            "#,
        )
        .unwrap();
        assert_eq!(cfg.concurrent, 1);
        assert_eq!(cfg.check_interval(), DEFAULT_CHECK_INTERVAL);
        let r = &cfg.runners[0];
        assert_eq!(r.token().expose(), "glrt-t1_abcdefghijklmnop");
        assert_eq!(r.name, "abcdefghi");
        assert!(r.placement().pool.is_empty());
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
    fn limits_past_the_hubs_are_refused() {
        let runner = |n: usize, extra: &str| {
            format!("[[runners]]\nname = \"r{n}\"\ntoken = \"glrt-{n}\"\n{extra}")
        };
        let config = |concurrent: usize, runners: &str| {
            format!(
                "concurrent = {concurrent}\n[gitlab]\nurl = \"https://gitlab.example.com\"\n{runners}"
            )
        };
        let max = vk_hub_proto::gitlab::MAX_ADMISSIONS;
        assert!(parse(&config(max, &runner(0, ""))).is_ok());
        let e = parse(&config(max + 1, &runner(0, ""))).unwrap_err();
        assert!(e.to_string().contains("concurrent"), "{e:#}");
        let extra = format!("request_concurrency = {}", max + 1);
        let e = parse(&config(1, &runner(0, &extra))).unwrap_err();
        assert!(e.to_string().contains("request_concurrency"), "{e:#}");
        let runners = |n| (0..n).map(|i| runner(i, "")).collect::<String>();
        let most = vk_hub_proto::gitlab::MAX_RUNNERS;
        assert!(parse(&config(1, &runners(most))).is_ok());
        let e = parse(&config(1, &runners(most + 1))).unwrap_err();
        assert!(e.to_string().contains("too many runners"), "{e:#}");
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
            [gitlab]
            url = "https://gitlab.example.com"
            [[runners]]
            name = "fleet"
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
        // The pool of a config from before 0.111 is read and ignored.
        let p = r.placement();
        assert!(p.pool.is_empty());
        assert_eq!(p.labels, ["large-memory"]);
        assert_eq!(p.envelope.mem_mib, 16 * 1024);
        assert_eq!(p.envelope.cpus, 8);
        assert_eq!(r.runner_placement().labels, ["large-memory"]);
        assert_eq!(p.envelope.disk_bytes, 512 << 20);
    }

    #[test]
    fn rejects_bad_configs() {
        for (text, needle) in [
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\n",
                "token or token_file is required",
            ),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\ntoken = \"a\"\ntoken_file = \"f\"\n",
                "not both",
            ),
            (
                "[gitlab]\nurl = \"gitlab\"\n[[runners]]\ntoken = \"a\"\n",
                "only http or https",
            ),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\ntoken = \"a\"\ntypo = 1\n",
                "unknown field",
            ),
            ("concurent = 2\n", "unknown field"),
            ("concurrent = 0\n", "at least 1"),
            (
                "[gitlab]\nurl = \"https://u:p@g\"\n",
                "no credentials, query or fragment",
            ),
            (
                "[gitlab]\nurl = \"https://g/?x=1\"\n",
                "no credentials, query or fragment",
            ),
            ("[[runners]]\ntoken = \"a\"\n", "[gitlab] url is required"),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\nurl = \"https://g\"\ntoken = \"a\"\n",
                "unknown field `url`",
            ),
            ("[[runner]]\ntoken = \"a\"\n", "unknown field"),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\nname = \"../x\"\ntoken = \"a\"\n",
                "runner name",
            ),
            ("[hub]\nurl = \"https://h\"\n", "unknown field `url`"),
            ("[hub]\nallow = [\"gc\"]\n", "not something the hub may do"),
            (
                "[hub]\nrequire_signed = true\n",
                "require_signed = true needs release_keys",
            ),
            (
                "[hub]\nrelease_keys = [\"x\"]\n",
                "not an ed25519 public key",
            ),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\ntoken = \"a\"\nenvelope = { mem = \"lots\", cpus = 1, disk = \"1G\" }\n",
                "envelope mem",
            ),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\nname = \"a\"\ntoken = \"x\"\n[[runners]]\nname = \"a\"\ntoken = \"y\"\n",
                "unique",
            ),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\ntoken = \"a\"\ntls-cert-file = \"c\"\n",
                "go together",
            ),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\ntoken = \"a\"\nlabels = [\"\"]\n",
                "labels must not be empty",
            ),
            (
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\ntoken = \"a\"\nlabels = [\"x\", \"x\"]\n",
                "listed twice",
            ),
        ] {
            let err = format!("{:#}", parse(text).unwrap_err());
            assert!(err.contains(needle), "{text}: {err}");
        }
    }

    /// A relay the hub adds runners to may have none of its own, but needs its GitLab.
    #[test]
    fn a_relay_taking_runners_from_the_hub_needs_its_gitlab_only() {
        let cfg =
            parse("[gitlab]\nurl = \"https://g\"\n[hub]\nallow = [\"update\", \"runners\"]\n")
                .unwrap();
        assert!(cfg.takes_runners() && cfg.runners.is_empty());
        let e = format!("{:#}", parse("[hub]\nallow = [\"runners\"]\n").unwrap_err());
        assert!(e.contains("[gitlab] url is required"), "{e}");
        assert!(!parse("").unwrap().takes_runners());
    }

    #[test]
    fn unhealthy_requests_limit_below_one_is_the_default() {
        for (set, want) in [
            ("", 3),
            ("unhealthy_requests_limit = 0\n", 3),
            ("unhealthy_requests_limit = 5\n", 5),
        ] {
            let cfg = parse(&format!(
                "[gitlab]\nurl = \"https://g\"\n[[runners]]\ntoken = \"a\"\n{set}"
            ))
            .unwrap();
            assert_eq!(cfg.runners[0].unhealthy_requests_limit(), want, "{set}");
        }
    }

    #[test]
    fn debug_hides_the_token() {
        let cfg =
            parse("[gitlab]\nurl = \"https://g\"\n[[runners]]\ntoken = \"glrt-secretvalue\"\n")
                .unwrap();
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("secretvalue"), "{dbg}");
    }
}
