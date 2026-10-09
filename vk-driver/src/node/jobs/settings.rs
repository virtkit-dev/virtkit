//! What a job's variables ask of the runner — its git strategy, attempts, debug trace and
//! timeouts — read as gitlab-runner reads them, defaults and range checks included, each
//! problem kept as the warning gitlab-runner prints for it.
//!
//! Ported from gitlab-runner v19.5's `common/build_settings.go` and `common/consts.go` (MIT;
//! see [`super::mask`] for the notice).

use std::time::Duration;

use vk_hub_proto::job::CiJob;

use super::vars::Vars;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GitStrategy {
    Clone,
    Fetch,
    None,
    Empty,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submodules {
    None,
    Normal,
    Recursive,
    /// Not a strategy gitlab-runner knows: get_sources fails.
    Invalid,
}

/// `common.AfterScriptTimeout`.
pub const AFTER_SCRIPT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub debug_trace: bool,
    pub git_strategy: GitStrategy,
    pub git_checkout: bool,
    pub submodules: Submodules,
    pub submodule_depth: u32,
    pub submodule_paths: Vec<String>,
    pub submodule_update_flags: Vec<String>,
    pub clean_flags: Vec<String>,
    pub fetch_flags: Vec<String>,
    pub lfs_skip_smudge: bool,
    pub get_sources_attempts: u32,
    pub artifact_download_attempts: u32,
    pub restore_cache_attempts: u32,
    pub after_script_ignore_errors: bool,
    /// `RUNNER_SCRIPT_TIMEOUT`: the steps' own bound, inside the job's.
    pub script_timeout: Option<Duration>,
    /// `RUNNER_AFTER_SCRIPT_TIMEOUT`, else the after_script step's own, else 5 minutes.
    pub after_script_timeout: Duration,
    /// What gitlab-runner would warn about, in its words.
    pub warnings: Vec<String>,
}

impl Settings {
    pub fn of(job: &CiJob, vars: &Vars) -> Settings {
        let mut warnings = Vec::new();
        let default_strategy = match job.sources.allow_fetch {
            true => GitStrategy::Fetch,
            false => GitStrategy::Clone,
        };
        let git_strategy = match vars.value("GIT_STRATEGY").as_str() {
            "clone" => GitStrategy::Clone,
            "fetch" => GitStrategy::Fetch,
            "none" => GitStrategy::None,
            "empty" => GitStrategy::Empty,
            "" => default_strategy,
            raw => {
                warnings.push(format!(
                    "GIT_STRATEGY: expected either 'clone', 'fetch', 'none' or 'empty' got \
                     {raw:?}, using default value '{}'",
                    strategy_name(default_strategy)
                ));
                default_strategy
            }
        };
        let submodules = match vars.value("GIT_SUBMODULE_STRATEGY").as_str() {
            "normal" => Submodules::Normal,
            "recursive" => Submodules::Recursive,
            "none" | "" => Submodules::None,
            raw => {
                warnings.push(format!(
                    "GIT_SUBMODULE_STRATEGY: expected either 'normal', 'recursive' or 'none' \
                     got {raw:?}"
                ));
                Submodules::Invalid
            }
        };
        let no_sources = matches!(git_strategy, GitStrategy::None | GitStrategy::Empty);
        let mut read = Reader {
            vars,
            warnings: &mut warnings,
        };
        let debug_trace = read.bool("CI_DEBUG_TRACE", false);
        let git_checkout = read.bool("GIT_CHECKOUT", true) && !no_sources;
        let submodule_depth = read.int("GIT_SUBMODULE_DEPTH", job.sources.depth);
        let clean_flags = read.flags("GIT_CLEAN_FLAGS", &["-ffdx"]);
        let fetch_flags = read.flags("GIT_FETCH_EXTRA_FLAGS", &["--prune", "--quiet"]);
        let submodule_paths = read.fields("GIT_SUBMODULE_PATHS");
        let submodule_update_flags = read.fields("GIT_SUBMODULE_UPDATE_FLAGS");
        let lfs_skip_smudge = read.bool("GIT_LFS_SKIP_SMUDGE", false);
        let get_sources_attempts = read.attempts("GET_SOURCES_ATTEMPTS");
        let artifact_download_attempts = read.attempts("ARTIFACT_DOWNLOAD_ATTEMPTS");
        let restore_cache_attempts = read.attempts("RESTORE_CACHE_ATTEMPTS");
        let after_script_ignore_errors = read.bool("AFTER_SCRIPT_IGNORE_ERRORS", true);
        let script_timeout = read.duration("RUNNER_SCRIPT_TIMEOUT");
        read.unsupported("GIT_CLONE_PATH", "the project dir is the node's");
        read.unsupported(
            "GIT_CLONE_EXTRA_FLAGS",
            "the guest fetches; it never clones (FF_USE_GIT_NATIVE_CLONE)",
        );
        read.unsupported(
            "GIT_SUBMODULE_FORCE_HTTPS",
            "submodule URLs are used as .gitmodules writes them",
        );
        read.unsupported("EXECUTOR_JOB_SECTION_ATTEMPTS", "a stage is attempted once");
        if read.bool("CI_DEBUG_SERVICES", false) {
            read.warnings
                .push("CI_DEBUG_SERVICES: not supported on vk nodes; ignored".into());
        }
        for v in vars.all().iter().filter(|v| v.file) {
            if !super::script::file_key_ok(&v.key) {
                read.warnings.push(format!(
                    "{:?}: a file variable's key must be a shell variable name; skipped",
                    v.key
                ));
            }
        }
        // `CI_JOB_SERVICES` gives the executor one alias per service.
        for s in job.services.iter().filter(|s| s.aliases.len() > 1) {
            read.warnings.push(format!(
                "service {:?}: only its first alias {:?} is reachable; {} ignored",
                s.name,
                s.aliases[0],
                s.aliases[1..].join(", ")
            ));
        }
        let step = job
            .steps
            .iter()
            .find(|s| s.name == vk_hub_proto::job::STEP_AFTER_SCRIPT)
            .map(|s| s.timeout_secs)
            .filter(|&secs| secs > 0)
            .map(Duration::from_secs);
        let after_script_timeout = read
            .duration("RUNNER_AFTER_SCRIPT_TIMEOUT")
            .or(step)
            .unwrap_or(AFTER_SCRIPT_TIMEOUT);
        Settings {
            debug_trace,
            git_strategy,
            git_checkout,
            submodules: if no_sources {
                Submodules::None
            } else {
                submodules
            },
            submodule_depth,
            submodule_paths,
            submodule_update_flags,
            clean_flags,
            fetch_flags,
            lfs_skip_smudge,
            get_sources_attempts,
            artifact_download_attempts,
            restore_cache_attempts,
            after_script_ignore_errors,
            script_timeout,
            after_script_timeout,
            warnings,
        }
    }
}

pub fn strategy_name(s: GitStrategy) -> &'static str {
    match s {
        GitStrategy::Clone => "clone",
        GitStrategy::Fetch => "fetch",
        GitStrategy::None => "none",
        GitStrategy::Empty => "empty",
    }
}

struct Reader<'a> {
    vars: &'a Vars,
    warnings: &'a mut Vec<String>,
}

impl Reader<'_> {
    fn bool(&mut self, name: &str, default: bool) -> bool {
        let raw = self.vars.value(name);
        if raw.is_empty() {
            return default;
        }
        match parse_bool(&raw) {
            Some(b) => b,
            None => {
                self.warnings.push(format!(
                    "{name}: expected bool got {raw:?}, using default value: {default}"
                ));
                default
            }
        }
    }

    fn int(&mut self, name: &str, default: u32) -> u32 {
        let raw = self.vars.value(name);
        if raw.is_empty() {
            return default;
        }
        match raw.parse::<i64>() {
            Ok(n) => u32::try_from(n.max(0)).unwrap_or(u32::MAX),
            Err(_) => {
                self.warnings.push(format!(
                    "{name}: expected int got {raw:?}, using default value: {default}"
                ));
                default
            }
        }
    }

    /// Whitespace-separated flags; `none` for none.
    fn flags(&mut self, name: &str, default: &[&str]) -> Vec<String> {
        match self.vars.value(name).as_str() {
            "" => default.iter().map(|s| s.to_string()).collect(),
            "none" => Vec::new(),
            raw => raw.split_whitespace().map(String::from).collect(),
        }
    }

    fn fields(&mut self, name: &str) -> Vec<String> {
        self.vars
            .value(name)
            .split_whitespace()
            .map(String::from)
            .collect()
    }

    /// An attempt count, clamped into 1..=10 with gitlab-runner's warning.
    fn attempts(&mut self, name: &str) -> u32 {
        let n = self.int(name, 1);
        let clamped = n.clamp(1, 10);
        if clamped != n {
            self.warnings.push(format!(
                "{name}: number of attempts out of the range [1, 10], clamping to: {clamped}"
            ));
        }
        clamped
    }

    /// A Go duration (`1h30m`, `90s`), as `RUNNER_*_TIMEOUT` are written; zero for none
    /// (`getStageTimeoutContexts`).
    fn duration(&mut self, name: &str) -> Option<Duration> {
        let raw = self.vars.value(name);
        if raw.trim().is_empty() {
            return None;
        }
        match parse_go_duration(&raw) {
            None => {
                self.warnings
                    .push(format!("Ignoring malformed {name} timeout: {raw}"));
                None
            }
            Some((true, d)) if !d.is_zero() => {
                self.warnings
                    .push(format!("Ignoring relative {name} timeout: {raw}"));
                None
            }
            Some((_, d)) => Some(d).filter(|d| !d.is_zero()),
        }
    }

    /// A variable gitlab-runner reads and a vk node does not act on: warned about when set.
    fn unsupported(&mut self, name: &str, why: &str) {
        if !self.vars.value(name).is_empty() {
            self.warnings.push(format!(
                "{name}: not supported on vk nodes ({why}); ignored"
            ));
        }
    }
}

/// Go's `strconv.ParseBool`.
fn parse_bool(raw: &str) -> Option<bool> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Go's `time.ParseDuration`: whether the duration is negative, and its magnitude.
fn parse_go_duration(raw: &str) -> Option<(bool, Duration)> {
    let (negative, mut rest) = match raw.as_bytes().first() {
        Some(b'-') => (true, &raw[1..]),
        Some(b'+') => (false, &raw[1..]),
        _ => (false, raw),
    };
    if rest == "0" {
        return Some((negative, Duration::ZERO));
    }
    if rest.is_empty() {
        return None;
    }
    let mut total = 0f64;
    while !rest.is_empty() {
        let num_len = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        if num_len == 0 {
            return None;
        }
        let value: f64 = rest[..num_len].parse().ok()?;
        rest = &rest[num_len..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let secs = match &rest[..unit_len] {
            "ns" => 1e-9,
            "us" | "µs" | "μs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return None,
        };
        rest = &rest[unit_len..];
        total += value * secs;
    }
    // Go's durations are int64 nanoseconds: anything longer overflows.
    let d = Duration::try_from_secs_f64(total).ok()?;
    (d.as_nanos() <= i64::MAX as u128).then_some((negative, d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_hub_proto::job::{Image, Step, Variable};

    fn job(vars: &[(&str, &str)]) -> (CiJob, Vars) {
        let job = CiJob {
            variables: vars
                .iter()
                .map(|(k, v)| Variable {
                    key: k.to_string(),
                    value: v.to_string(),
                    public: true,
                    ..Variable::default()
                })
                .collect(),
            steps: vec![Step {
                name: "after_script".into(),
                timeout_secs: 120,
                ..Step::default()
            }],
            ..CiJob::default()
        };
        let place = super::super::vars::Place {
            builds_dir: "/builds".into(),
            project_dir: "/builds/p".into(),
            concurrent_id: 0,
            concurrent_project_id: 0,
        };
        let vars = Vars::of(&job, &place);
        (job, vars)
    }

    #[test]
    fn defaults_are_gitlab_runners() {
        let (job, vars) = job(&[]);
        let s = Settings::of(&job, &vars);
        assert_eq!(s.git_strategy, GitStrategy::Clone);
        assert!(s.git_checkout && !s.debug_trace && !s.lfs_skip_smudge);
        assert_eq!(s.submodules, Submodules::None);
        assert_eq!(s.clean_flags, ["-ffdx"]);
        assert_eq!(s.fetch_flags, ["--prune", "--quiet"]);
        assert_eq!(s.get_sources_attempts, 1);
        assert!(s.after_script_ignore_errors);
        assert_eq!(s.after_script_timeout, Duration::from_secs(120));
        assert!(s.warnings.is_empty());
    }

    #[test]
    fn variables_are_read_and_bad_ones_warned_about() {
        let (job, vars) = job(&[
            ("GIT_STRATEGY", "none"),
            ("GIT_SUBMODULE_STRATEGY", "recursive"),
            ("GIT_CLEAN_FLAGS", "none"),
            ("GET_SOURCES_ATTEMPTS", "20"),
            ("CI_DEBUG_TRACE", "yes"),
            ("RUNNER_SCRIPT_TIMEOUT", "1h30m"),
            ("RUNNER_AFTER_SCRIPT_TIMEOUT", "10m"),
        ]);
        let s = Settings::of(&job, &vars);
        assert_eq!(s.git_strategy, GitStrategy::None);
        // No sources, so no checkout and no submodules whatever was asked.
        assert!(!s.git_checkout);
        assert_eq!(s.submodules, Submodules::None);
        assert!(s.clean_flags.is_empty());
        assert_eq!(s.get_sources_attempts, 10);
        assert!(!s.debug_trace);
        assert_eq!(s.script_timeout, Some(Duration::from_secs(5400)));
        assert_eq!(s.after_script_timeout, Duration::from_secs(600));
        assert_eq!(s.warnings.len(), 2, "{:?}", s.warnings);
        assert!(s.warnings[0].starts_with("CI_DEBUG_TRACE: expected bool got \"yes\""));
    }

    #[test]
    fn go_durations_parse() {
        let secs = |n| Some((false, Duration::from_secs(n)));
        assert_eq!(parse_go_duration("90s"), secs(90));
        assert_eq!(parse_go_duration("+90s"), secs(90));
        assert_eq!(parse_go_duration("1.5h"), secs(5400));
        assert_eq!(parse_go_duration("1m30s"), secs(90));
        assert_eq!(parse_go_duration("0"), secs(0));
        assert_eq!(parse_go_duration("+0"), secs(0));
        assert_eq!(parse_go_duration("-0"), Some((true, Duration::ZERO)));
        assert_eq!(
            parse_go_duration("-5s"),
            Some((true, Duration::from_secs(5)))
        );
        for bad in [
            "10",
            "",
            "-",
            "1x",
            " 5s",
            "5s ",
            ".s",
            "99999999999999999999h",
            "2562048h",
        ] {
            assert_eq!(parse_go_duration(bad), None, "{bad:?}");
        }
        // Go's longest duration, int64 nanoseconds.
        assert!(parse_go_duration("2562047h").is_some());
    }

    #[test]
    fn a_bad_timeout_is_ignored_with_gitlab_runners_warning() {
        for (raw, warning) in [
            ("99999999999999999999h", "Ignoring malformed"),
            ("-5m", "Ignoring relative"),
        ] {
            let (job, vars) = job(&[("RUNNER_SCRIPT_TIMEOUT", raw)]);
            let s = Settings::of(&job, &vars);
            assert_eq!(s.script_timeout, None);
            assert_eq!(
                s.warnings,
                [format!("{warning} RUNNER_SCRIPT_TIMEOUT timeout: {raw}")]
            );
        }
        let (job, vars) = job(&[("RUNNER_SCRIPT_TIMEOUT", "0")]);
        let s = Settings::of(&job, &vars);
        assert_eq!(s.script_timeout, None);
        assert!(s.warnings.is_empty());
    }

    #[test]
    fn an_unknown_submodule_strategy_is_invalid() {
        let (job, vars) = job(&[("GIT_SUBMODULE_STRATEGY", "deep")]);
        let s = Settings::of(&job, &vars);
        assert_eq!(s.submodules, Submodules::Invalid);
        assert!(s.warnings[0].starts_with("GIT_SUBMODULE_STRATEGY: expected either"));
    }

    #[test]
    fn variables_a_node_does_not_act_on_are_warned_about() {
        let (set, vars) = job(&[
            ("GIT_CLONE_PATH", "$CI_BUILDS_DIR/x"),
            ("GIT_CLONE_EXTRA_FLAGS", "--no-tags"),
            ("GIT_SUBMODULE_FORCE_HTTPS", "true"),
            ("EXECUTOR_JOB_SECTION_ATTEMPTS", "3"),
            ("CI_DEBUG_SERVICES", "true"),
        ]);
        let s = Settings::of(&set, &vars);
        assert_eq!(s.warnings.len(), 5, "{:?}", s.warnings);
        assert!(
            s.warnings
                .iter()
                .all(|w| w.contains("not supported on vk nodes"))
        );
        let (off, vars) = job(&[("CI_DEBUG_SERVICES", "false")]);
        assert!(Settings::of(&off, &vars).warnings.is_empty());
    }

    #[test]
    fn a_services_aliases_after_the_first_are_warned_about() {
        let (mut set, vars) = job(&[]);
        set.services = vec![
            Image {
                name: "postgres:16".into(),
                aliases: vec!["db".into(), "pg".into(), "sql".into()],
                ..Image::default()
            },
            Image {
                name: "redis".into(),
                aliases: vec!["cache".into()],
                ..Image::default()
            },
        ];
        let s = Settings::of(&set, &vars);
        assert_eq!(
            s.warnings,
            [r#"service "postgres:16": only its first alias "db" is reachable; pg, sql ignored"#]
        );
    }
}
