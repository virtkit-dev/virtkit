//! GitLab's job payload translated into the hub's job spec (`gitlab_ci`), field by field as
//! `docs/gitlab-dispatch.md`, "The job spec", accounts for them. Normalized so the
//! node interprets nothing GitLab-specific: defaults filled in, cache keys expanded against
//! the job's and the runner's variables and sanitized (a port of gitlab-runner's
//! `cache/cachekey`), aliases split, empty formats made `zip`.

use vk_hub_proto::job::{
    ArtifactFormat, ArtifactSpec, CachePolicy, CacheSpec, CiJob, CiJobInfo, Dependency,
    DependencyFile, Hook, HookName, Image, ObjectFormat, Port, PullPolicy, RefType,
    RegistryCredential, Sources, Step, TraceOptions, Variable, When,
};

use crate::job::{self, Job};

/// gitlab-runner's `DefaultTimeout`, for a job GitLab gives no timeout.
const DEFAULT_TIMEOUT_SECS: u64 = 7200;

/// Runner settings used when translating a job.
#[derive(Debug, Clone, Default)]
pub struct SpecContext {
    /// The runner's configured GitLab URL.
    pub server_url: String,
    /// The CA bundle the daemon verifies GitLab against, when it is not the system roots.
    pub server_ca_pem: Option<String>,
    /// The runner ID `/runners/verify` returned.
    pub runner_id: u64,
    /// The runner's `output_limit`, in bytes.
    pub output_limit: u64,
    /// The runner token's short form (`CI_RUNNER_SHORT_TOKEN`).
    pub short_token: String,
}

/// The spec, and what was dropped on the way (logged, and not fatal). `Debug` shows the
/// spec [redacted](CiJob::redacted).
#[derive(Clone)]
pub struct Translated {
    pub job: CiJob,
    pub warnings: Vec<String>,
}

impl std::fmt::Debug for Translated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Translated")
            .field("job", &self.job.redacted())
            .field("warnings", &self.warnings)
            .finish()
    }
}

fn u64_of(n: i64) -> u64 {
    u64::try_from(n).unwrap_or(0)
}

fn when_of(s: &str) -> When {
    match s {
        "on_failure" => When::OnFailure,
        "always" => When::Always,
        _ => When::OnSuccess,
    }
}

fn variables_of(vars: &[job::Variable]) -> Vec<Variable> {
    vars.iter()
        .map(|v| Variable {
            key: v.key.clone(),
            value: v.value.clone(),
            public: v.public,
            file: v.file,
            masked: v.masked,
            raw: v.raw,
        })
        .collect()
}

fn image_of(img: &job::Image, warnings: &mut Vec<String>) -> Image {
    let opts = &img.executor_options;
    let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_owned());
    Image {
        name: img.name.clone(),
        aliases: img.aliases().into_iter().map(str::to_owned).collect(),
        entrypoint: img.entrypoint.clone(),
        command: img.command.clone(),
        ports: img
            .ports
            .iter()
            .filter_map(|p| match u16::try_from(p.number) {
                Ok(number) if number > 0 => Some(Port {
                    number,
                    protocol: if p.protocol.is_empty() {
                        "http".to_owned()
                    } else {
                        p.protocol.clone()
                    },
                    name: non_empty(&p.name),
                }),
                _ => {
                    warnings.push(format!("port {} of {:?} dropped", p.number, img.name));
                    None
                }
            })
            .collect(),
        variables: variables_of(&img.variables),
        pull_policy: img
            .pull_policies
            .iter()
            .filter_map(|p| match p.as_str() {
                "always" => Some(PullPolicy::Always),
                "if-not-present" => Some(PullPolicy::IfNotPresent),
                "never" => Some(PullPolicy::Never),
                other => {
                    warnings.push(format!("pull policy {other:?} of {:?} dropped", img.name));
                    None
                }
            })
            .collect(),
        platform: non_empty(&opts.docker.platform),
        user: non_empty(&opts.docker.user.0).or_else(|| non_empty(&opts.kubernetes.user.0)),
    }
}

/// `git_info.repo_url` without its credentials (the node adds the job token itself). A URL
/// that does not parse with a host loses its authority's user info as the node splits it:
/// everything up to the last `@` before the path; without `://`, the URL is dropped.
fn without_credentials(url: &str, warnings: &mut Vec<String>) -> String {
    if url.is_empty() {
        return String::new();
    }
    // `user:token@host/p.git` parses too, as a scheme and an opaque path.
    if let Ok(mut u) = reqwest::Url::parse(url)
        && u.has_host()
    {
        let _ = u.set_username("");
        let _ = u.set_password(None);
        return u.to_string();
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        warnings.push("git_info.repo_url has no scheme: dropped".to_owned());
        return String::new();
    };
    warnings.push("git_info.repo_url is not a valid URL".to_owned());
    let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    format!("{scheme}://{host}{path}")
}

/// gitlab-runner's `GetAllVariables()` as far as the daemon knows them: the job's variables
/// and the runner's, each value not `raw` expanded once against the whole list
/// (`JobVariables.Expand`). Variables only the node sets (`CI_PROJECT_DIR`, …) are absent.
fn expanded_variables(job_vars: &[job::Variable], runner: &[Variable]) -> Vec<job::Variable> {
    let all: Vec<job::Variable> = job_vars
        .iter()
        .cloned()
        .chain(runner.iter().map(|v| job::Variable {
            key: v.key.clone(),
            value: v.value.clone(),
            public: v.public,
            file: v.file,
            masked: v.masked,
            raw: v.raw,
        }))
        .collect();
    all.iter()
        .map(|v| job::Variable {
            value: if v.raw {
                v.value.clone()
            } else {
                expand(&v.value, &all)
            },
            ..v.clone()
        })
        .collect()
}

/// The runner's own predefined variables, appended after GitLab's.
fn runner_variables(ctx: &SpecContext) -> Vec<Variable> {
    let arch = crate::api::Info::this_runner().architecture;
    [
        ("CI_RUNNER_VERSION", env!("CARGO_PKG_VERSION").to_owned()),
        ("CI_RUNNER_REVISION", crate::api::revision()),
        (
            "CI_RUNNER_EXECUTABLE_ARCH",
            format!("{}/{arch}", std::env::consts::OS),
        ),
        ("CI_RUNNER_SHORT_TOKEN", ctx.short_token.clone()),
    ]
    .into_iter()
    .map(|(key, value)| Variable {
        key: key.to_owned(),
        value,
        public: true,
        file: false,
        masked: false,
        raw: true,
    })
    .collect()
}

/// Translates `job` for the hub.
pub fn translate(job: &Job, ctx: &SpecContext) -> Translated {
    let mut warnings = Vec::new();
    let info = &job.job_info;
    let git = &job.git_info;
    let timeout = match u64_of(job.runner_info.timeout) {
        0 => DEFAULT_TIMEOUT_SECS,
        t => t,
    };
    let runner_vars = runner_variables(ctx);
    let all_vars = expanded_variables(&job.variables, &runner_vars);
    // Warnings name a key as written: expanded, it may hold a variable's secret value.
    let caches = job
        .cache
        .iter()
        .filter_map(|c| {
            let (written, raw) = if c.key.is_empty() {
                // gitlab-runner's default: `<job name>/<ref>` under a virtual root.
                let key = format!("{}/{}", info.name, git.git_ref);
                (key.clone(), key)
            } else {
                (c.key.clone(), expand(&c.key, &all_vars))
            };
            let key = match sanitize_cache_key(&raw) {
                Ok(k) if !k.is_empty() => k,
                Ok(_) | Err(_) => {
                    warnings.push(format!(
                        "cache key {written:?} could not be sanitized: cache skipped"
                    ));
                    return None;
                }
            };
            if key != raw {
                warnings.push(format!("cache key {written:?} sanitized"));
            }
            let fallback_keys = c
                .fallback_keys
                .iter()
                .filter_map(|k| match sanitize_cache_key(&expand(k, &all_vars)) {
                    Ok(key) if !key.is_empty() => Some(key),
                    _ => {
                        warnings.push(format!("fallback cache key {k:?} dropped"));
                        None
                    }
                })
                .collect();
            Some(CacheSpec {
                key,
                fallback_keys,
                untracked: c.untracked,
                paths: c.paths.clone(),
                policy: match c.policy.as_str() {
                    "pull" => CachePolicy::Pull,
                    "push" => CachePolicy::Push,
                    _ => CachePolicy::PullPush,
                },
                when: when_of(&c.when),
            })
        })
        .collect();
    let artifacts = job
        .artifacts
        .iter()
        .map(|a| ArtifactSpec {
            name: if a.name.is_empty() {
                "artifacts".to_owned()
            } else {
                a.name.clone()
            },
            untracked: a.untracked,
            paths: a.paths.clone(),
            exclude: a.exclude.clone(),
            when: when_of(&a.when),
            artifact_type: if a.artifact_type.is_empty() {
                "archive".to_owned()
            } else {
                a.artifact_type.clone()
            },
            format: match a.artifact_format.as_str() {
                "" | "zip" => ArtifactFormat::Zip,
                "gzip" => ArtifactFormat::Gzip,
                "raw" => ArtifactFormat::Raw,
                "zipzstd" => ArtifactFormat::ZipZstd,
                "tarzstd" => ArtifactFormat::TarZstd,
                other => {
                    warnings.push(format!("artifact format {other:?} read as zip"));
                    ArtifactFormat::Zip
                }
            },
            expire_in: a.expire_in.clone(),
        })
        .collect();
    let mut variables = variables_of(&job.variables);
    variables.extend(runner_vars);
    let image = image_of(&job.image, &mut warnings);
    let services = job
        .services
        .iter()
        .map(|s| image_of(s, &mut warnings))
        .collect();
    let ci = CiJob {
        server_url: ctx.server_url.clone(),
        server_ca_pem: ctx.server_ca_pem.clone(),
        job: CiJobInfo {
            id: u64_of(job.id),
            name: info.name.clone(),
            stage: info.stage.clone(),
            pipeline_id: u64_of(info.pipeline_id),
            project_id: u64_of(info.project_id),
            project_name: info.project_name.clone(),
            project_path: info.project_full_path.clone(),
            namespace_id: u64_of(info.namespace_id),
            root_namespace_id: u64_of(info.root_namespace_id),
            user_id: u64_of(info.user_id),
            runner_id: ctx.runner_id,
        },
        token: job.token.expose().to_owned(),
        timeout_secs: timeout,
        sources: Sources {
            repo_url: without_credentials(&git.repo_url, &mut warnings),
            object_format: if git.repo_object_format == "sha256" {
                ObjectFormat::Sha256
            } else {
                ObjectFormat::Sha1
            },
            git_ref: git.git_ref.clone(),
            ref_type: if git.ref_type == "tag" {
                RefType::Tag
            } else {
                RefType::Branch
            },
            sha: git.sha.clone(),
            before_sha: git.before_sha.clone(),
            refspecs: git.refspecs.clone(),
            depth: u32::try_from(git.depth).unwrap_or(0),
            protected: git.protected,
            allow_fetch: job.allow_git_fetch,
        },
        image,
        services,
        variables,
        steps: job
            .steps
            .iter()
            .map(|s| Step {
                name: s.name.clone(),
                script: s.script.clone(),
                timeout_secs: u64_of(s.timeout),
                when: when_of(&s.when),
                allow_failure: s.allow_failure,
            })
            .collect(),
        hooks: job
            .hooks
            .iter()
            .filter_map(|h| {
                let name = match h.name.as_str() {
                    "pre_get_sources_script" => HookName::PreGetSourcesScript,
                    "post_get_sources_script" => HookName::PostGetSourcesScript,
                    other => {
                        warnings.push(format!("hook {other:?} dropped"));
                        return None;
                    }
                };
                Some(Hook {
                    name,
                    script: h.script.clone(),
                })
            })
            .collect(),
        artifacts,
        caches,
        dependencies: job
            .dependencies
            .iter()
            .map(|d| Dependency {
                id: u64_of(d.id),
                token: d.token.expose().to_owned(),
                name: d.name.clone(),
                artifacts_file: (!d.artifacts_file.filename.is_empty()).then(|| DependencyFile {
                    filename: d.artifacts_file.filename.clone(),
                    size: u64_of(d.artifacts_file.size),
                }),
            })
            .collect(),
        // As gitlab-runner, only credentials of type `registry` are used.
        registry_credentials: job
            .credentials
            .iter()
            .filter(|c| c.kind == "registry")
            .map(|c| RegistryCredential {
                url: c.url.clone(),
                username: c.username.clone(),
                password: c.password.expose().to_owned(),
            })
            .collect(),
        trace: TraceOptions {
            sections: job.features.trace_sections,
            mask_prefixes: job.features.token_mask_prefixes.clone(),
            limit_bytes: ctx.output_limit,
        },
    };
    Translated { job: ci, warnings }
}

/// Go's `os.Expand` (adapted from its source; see NOTICE) with gitlab-runner's
/// `JobVariables.Get`: `$NAME` and `${NAME}` use the last variable with that key, `$$`
/// becomes `$`, and other shell special parameters and unknown names expand to nothing.
pub fn expand(value: &str, vars: &[job::Variable]) -> String {
    let lookup = |name: &str| -> String {
        match name {
            "$" => "$".to_owned(),
            "*" | "#" | "@" | "!" | "?" | "-" => String::new(),
            n if n.len() == 1 && n.as_bytes()[0].is_ascii_digit() => String::new(),
            n => vars
                .iter()
                .rev()
                .find(|v| v.key == n)
                .map(|v| v.value.clone())
                .unwrap_or_default(),
        }
    };
    let special =
        |b: u8| matches!(b, b'*' | b'#' | b'$' | b'@' | b'!' | b'?' | b'-') || b.is_ascii_digit();
    let s = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut i = 0;
    let mut j = 0;
    while j < s.len() {
        if s[j] == b'$' && j + 1 < s.len() {
            out.push_str(&value[i..j]);
            let rest = &value[j + 1..];
            let r = rest.as_bytes();
            // getShellName
            let (name, width): (&str, usize) = if r[0] == b'{' {
                if r.len() > 2 && special(r[1]) && r[2] == b'}' {
                    (&rest[1..2], 3)
                } else {
                    match rest[1..].find('}') {
                        Some(0) => ("", 2),
                        Some(end) => (&rest[1..=end], end + 2),
                        None => ("", 1),
                    }
                }
            } else if special(r[0]) {
                (&rest[..1], 1)
            } else {
                let n = r
                    .iter()
                    .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
                    .count();
                (&rest[..n], n)
            };
            if name.is_empty() && width > 0 {
                // Bad syntax: the characters are dropped, as in Go.
            } else if name.is_empty() {
                out.push('$');
            } else {
                out.push_str(&lookup(name));
            }
            j += width;
            i = j + 1;
        }
        j += 1;
    }
    if i < value.len() {
        out.push_str(&value[i..]);
    }
    out
}

/// Port of gitlab-runner's `cache/cachekey.Sanitize`: decode `%2f`/`%2e`, turn `\` into
/// `/`, resolve `.` and `..` under a virtual root, and strip trailing whitespace from the
/// rightmost segments. An empty key stays empty; one that cannot be sanitized is an error.
pub fn sanitize_cache_key(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Ok(String::new());
    }
    let mut normal = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(c) = rest.chars().next() {
        let three = rest.get(..3);
        if matches!(three, Some("%2f" | "%2F")) {
            normal.push('/');
            rest = &rest[3..];
        } else if matches!(three, Some("%2e" | "%2E")) {
            normal.push('.');
            rest = &rest[3..];
        } else {
            normal.push(if c == '\\' { '/' } else { c });
            rest = &rest[c.len_utf8()..];
        }
    }
    // path.Clean("/" + key), then the leading "/" removed.
    let mut stack: Vec<&str> = Vec::new();
    for seg in normal.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    let mut parts: Vec<String> = stack.into_iter().map(str::to_owned).collect();
    while let Some(last) = parts.last_mut() {
        let trimmed = last.trim_end().to_owned();
        if trimmed.is_empty() {
            parts.pop();
        } else {
            *last = trimmed;
            break;
        }
    }
    let key = parts.join("/");
    if key.is_empty() {
        return Err(format!("cache key {raw:?} could not be sanitized"));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from gitlab-runner v19.5.0 cache/cachekey/cachekey_test.go, TestSanitize,
    // TestSanitizeInvariants and TestSanitizeIdempotent (MIT, Copyright (c) 2015-2019
    // GitLab Inc.). `None` is upstream's wantErr.
    #[test]
    fn sanitize() {
        let cases: &[(&str, Option<&str>)] = &[
            ("", Some("")),
            ("fallback_key", Some("fallback_key")),
            ("some-job/some-ref", Some("some-job/some-ref")),
            (".../....", Some(".../....")),
            ("...", Some("...")),
            ("fallback_key/", Some("fallback_key")),
            ("fallback_key ", Some("fallback_key")),
            ("fallback_key\\", Some("fallback_key")),
            ("fallback_key/ \\", Some("fallback_key")),
            ("fallback_key/ / \\  \\", Some("fallback_key")),
            ("fallback_key/o", Some("fallback_key/o")),
            ("fallback_key / \\o", Some("fallback_key / /o")),
            ("\t foo bar \t\r", Some("\t foo bar")),
            (" foo / bar ", Some(" foo / bar")),
            ("foo\r", Some("foo")),
            ("foo\t", Some("foo")),
            ("foo \t \r ", Some("foo")),
            ("\\", None),
            ("\\.", None),
            ("/", None),
            (" ", None),
            (".", None),
            ("..", None),
            (" / ", None),
            ("//", None),
            ("//\\", None),
            ("../.", None),
            ("foo\\bar\\..\\..", None),
            ("foo/bar/../..", None),
            (" \t\r\n", None),
            ("something %2F something", Some("something / something")),
            ("something %2f something", Some("something / something")),
            ("some%2f../job/some/ref/.", Some("job/some/ref")),
            ("%2E", None),
            ("%2E%2E", None),
            ("%2E%2E%2E", Some("...")),
            ("%2e", None),
            ("%2e%2E", None),
            (".%2E", None),
            ("%2e.", None),
            ("%2E%2e%2E", Some("...")),
            ("%5C", Some("%5C")),
            ("%5c", Some("%5c")),
            ("foo/./bar", Some("foo/bar")),
            ("foo/blipp/../bar", Some("foo/bar")),
            ("/foo/bar", Some("foo/bar")),
            ("//foo/bar", Some("foo/bar")),
            ("./foo/bar", Some("foo/bar")),
            ("../foo/bar", Some("foo/bar")),
            (".../foo/bar", Some(".../foo/bar")),
            ("foo/bar/..", Some("foo")),
            ("foo/bar/../../../.././blerp", Some("blerp")),
            ("a/b/c/../../d", Some("a/d")),
            ("job\\name/git\\ref", Some("job/name/git/ref")),
            ("foo\\.\\bar", Some("foo/bar")),
            ("foo\\blipp\\..\\bar", Some("foo/bar")),
            ("\\foo\\bar", Some("foo/bar")),
            ("\\\\foo\\bar", Some("foo/bar")),
            (".\\foo\\bar", Some("foo/bar")),
            ("..\\foo\\bar", Some("foo/bar")),
            ("...\\foo\\bar", Some(".../foo/bar")),
            ("foo\\bar\\..", Some("foo")),
            ("foo\\bar\\..\\..\\..\\..\\.\\blerp", Some("blerp")),
            ("foo/ /bar", Some("foo/ /bar")),
            ("foo/ /", Some("foo")),
            ("foo/ / /", Some("foo")),
        ];
        for (raw, want) in cases {
            assert_eq!(sanitize_cache_key(raw).ok().as_deref(), *want, "{raw:?}");
        }
        for raw in [
            "a",
            "a/b",
            "../a",
            "a/../b",
            "a/./b",
            "a\\b",
            "a\\..\\\\b",
            "/a/b/",
            " a ",
            "...",
            "%2e%2e/%2f",
            "a/b/c/../../d/e",
        ] {
            let Ok(key) = sanitize_cache_key(raw) else {
                continue;
            };
            assert!(!key.starts_with('/') && !key.ends_with('/') && !key.ends_with(' '));
            assert!(!key.contains('\\'));
            assert!(
                key.split('/').all(|s| s != "." && s != ".."),
                "{raw:?} → {key:?}"
            );
        }
        for raw in [
            "fallback_key",
            "some-job/some-ref",
            "a/b/c",
            "...",
            ".../foo/bar",
        ] {
            let once = sanitize_cache_key(raw).unwrap();
            assert_eq!(sanitize_cache_key(&once).unwrap(), once);
        }
    }

    fn var(key: &str, value: &str) -> job::Variable {
        job::Variable {
            key: key.to_owned(),
            value: value.to_owned(),
            ..job::Variable::default()
        }
    }

    // Go's os.Expand with gitlab-runner's variable lookup.
    #[test]
    fn expansion() {
        let vars = [var("A", "first"), var("A", "x"), var("B_2", "b")];
        for (input, want) in [
            ("$A", "x"),
            ("${A}", "x"),
            ("pre-$A-$B_2-post", "pre-x-b-post"),
            ("$$", "$"),
            ("$1$*", ""),
            ("${}", ""),
            ("${A", "A"),
            ("$", "$"),
            ("cost: 5$", "cost: 5$"),
            ("$UNKNOWN!", "!"),
            ("plain", "plain"),
        ] {
            assert_eq!(expand(input, &vars), want, "{input:?}");
        }
    }
}
