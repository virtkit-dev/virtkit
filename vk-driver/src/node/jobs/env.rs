//! The gitlab-runner custom executor environment for a placed job's `vk gitlab
//! prepare|run|cleanup`: every job variable as `CUSTOM_ENV_<key>`, `JOB_RESPONSE_FILE`,
//! failure exit codes and `BUILD_EXIT_CODE_FILE`, and the GitLab the job came from
//! ([`crate::jobctx::JOB_SERVER_URL`]). This lets placed jobs reuse the executor.

use std::path::Path;

use anyhow::{Result, bail};
use vk_hub_proto::job::CiJob;

use super::journal::Meta;
use super::vars::{Place, Vars};
use crate::config::Config;

pub const BUILD_FAILURE_EXIT_CODE: i32 = 1;
pub const SYSTEM_FAILURE_EXIT_CODE: i32 = 2;
pub const EXIT_CODE_FILE: &str = "exit_code";
pub const JOB_RESPONSE: &str = "job_response.json";

/// Where the job runs in its guest: `$builds_dir/<project path>`, as gitlab-runner's custom
/// executor lays out a builds dir it does not share.
pub fn place(cfg: &Config, job: &CiJob, meta: &Meta) -> Result<Place> {
    let path = &job.job.project_path;
    let ok = !path.is_empty()
        && path.split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && c.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        });
    if !ok {
        bail!("the job's project path {path:?} is not one GitLab gives");
    }
    let builds_dir = cfg
        .executor
        .guest
        .builds_dir
        .trim_end_matches('/')
        .to_string();
    Ok(Place {
        project_dir: format!("{builds_dir}/{path}"),
        builds_dir,
        concurrent_id: meta.slot,
        concurrent_project_id: meta.project_slot,
    })
}

/// `# vk: mem=… cpus=…` in a step's script: the size the job asks for when no `MICROVM_MEM`
/// or `MICROVM_CPUS` variable does. The first hint of each wins.
pub fn size_hints(job: &CiJob) -> (Option<String>, Option<String>) {
    let (mut mem, mut cpus) = (None, None);
    for line in job
        .steps
        .iter()
        .flat_map(|s| s.script.iter())
        .flat_map(|c| c.lines())
    {
        let Some(rest) = line.trim().strip_prefix("# vk:") else {
            continue;
        };
        for word in rest.split_whitespace() {
            match word.split_once('=') {
                Some(("mem", v)) if mem.is_none() && !v.is_empty() => mem = Some(v.to_string()),
                Some(("cpus", v)) if cpus.is_none() && !v.is_empty() => cpus = Some(v.to_string()),
                _ => {}
            }
        }
    }
    (mem, cpus)
}

/// The clone URL with the job token in it, as GitLab's `CI_REPOSITORY_URL` carries it: what
/// the host checkout fetches with. Never printed: the checkout redacts it.
pub fn clone_url(repo_url: &str, token: &str) -> Result<String> {
    let Some((scheme, host, path)) = super::script::url_parts(repo_url) else {
        bail!("the job's repository URL has no scheme");
    };
    Ok(format!("{scheme}://gitlab-ci-token:{token}@{host}{path}"))
}

/// `CI_JOB_SERVICES` as GitLab sends it to a custom executor, which `vk gitlab prepare`
/// reads. A service with several aliases answers to the first: the executor takes one.
pub fn services_json(job: &CiJob, vars: &Vars) -> String {
    let services: Vec<serde_json::Value> = job
        .services
        .iter()
        .map(|s| {
            let variables: serde_json::Map<String, serde_json::Value> = s
                .variables
                .iter()
                .map(|v| (v.key.clone(), vars.expand(&v.value).into()))
                .collect();
            serde_json::json!({
                "name": s.name,
                "alias": s.aliases.first().cloned().unwrap_or_default(),
                "variables": variables,
                "entrypoint": s.entrypoint,
                "command": s.command,
            })
        })
        .collect();
    serde_json::Value::Array(services).to_string()
}

/// Everything the job's executor commands are given, on top of the node's own environment. A
/// file variable's `CUSTOM_ENV_` is its content, as gitlab-runner gives it.
pub fn child_env(
    job: &CiJob,
    vars: &Vars,
    place: &Place,
    dir: &Path,
) -> Result<Vec<(String, String)>> {
    let mut env: Vec<(String, String)> = vars
        .all()
        .iter()
        .map(|v| (format!("CUSTOM_ENV_{}", v.key), v.value.clone()))
        .collect();
    let mut set = |k: &str, v: String| env.push((k.to_string(), v));
    set("CUSTOM_ENV_CI_PROJECT_DIR", place.project_dir.clone());
    set("CUSTOM_ENV_CI_BUILDS_DIR", place.builds_dir.clone());
    set(
        "CUSTOM_ENV_CI_CONCURRENT_ID",
        place.concurrent_id.to_string(),
    );
    set(
        "CUSTOM_ENV_CI_REPOSITORY_URL",
        clone_url(&job.sources.repo_url, &job.token)?,
    );
    set("CUSTOM_ENV_CI_COMMIT_SHA", job.sources.sha.clone());
    set("CUSTOM_ENV_CI_COMMIT_REF_NAME", job.sources.git_ref.clone());
    set("CUSTOM_ENV_CI_JOB_SERVICES", services_json(job, vars));
    if vars.value("MICROVM_USER").is_empty()
        && let Some(user) = &job.image.user
    {
        set("CUSTOM_ENV_MICROVM_USER", user.clone());
    }
    let (mem, cpus) = size_hints(job);
    if vars.value("MICROVM_MEM").is_empty()
        && let Some(mem) = mem
    {
        set("CUSTOM_ENV_MICROVM_MEM", mem);
    }
    if vars.value("MICROVM_CPUS").is_empty()
        && let Some(cpus) = cpus
    {
        set("CUSTOM_ENV_MICROVM_CPUS", cpus);
    }
    set(
        "BUILD_FAILURE_EXIT_CODE",
        BUILD_FAILURE_EXIT_CODE.to_string(),
    );
    set(
        "SYSTEM_FAILURE_EXIT_CODE",
        SYSTEM_FAILURE_EXIT_CODE.to_string(),
    );
    set(
        "BUILD_EXIT_CODE_FILE",
        dir.join(EXIT_CODE_FILE).display().to_string(),
    );
    set(
        "JOB_RESPONSE_FILE",
        dir.join(JOB_RESPONSE).display().to_string(),
    );
    set(crate::jobctx::JOB_SERVER_URL, job.server_url.clone());
    Ok(env)
}

/// [`child_env`] of the job journaled in `dir`, as its driver computes it: what a later
/// `vk gitlab cleanup` of the job runs with when its driver is gone.
pub fn of_journal(cfg: &Config, dir: &Path) -> Result<Vec<(String, String)>> {
    let start = super::journal::read_start(dir)?;
    let meta = super::journal::read_meta(dir)?;
    let vk_hub_proto::job::JobSpec::GitlabCi(job) = start.spec;
    let place = place(cfg, &job, &meta)?;
    let vars = Vars::of(&job, &place);
    child_env(&job, &vars, &place, dir)
}

/// Strip what this process inherited of a custom executor's environment from `cmd` and give
/// it `env` instead: what a job of a local gitlab-runner would have passed down stays out.
pub fn apply(cmd: &mut std::process::Command, env: &[(String, String)]) {
    for (key, _) in std::env::vars_os() {
        let k = key.as_encoded_bytes();
        if k.starts_with(b"CUSTOM_ENV_")
            || [
                &b"JOB_RESPONSE_FILE"[..],
                crate::jobctx::JOB_SERVER_URL.as_bytes(),
                b"BUILD_EXIT_CODE_FILE",
                b"BUILD_FAILURE_EXIT_CODE",
                b"SYSTEM_FAILURE_EXIT_CODE",
            ]
            .contains(&k)
        {
            cmd.env_remove(key);
        }
    }
    cmd.envs(env.iter().map(|(k, v)| (k, v)));
}

/// The part of GitLab's job response the executor reads its identity from: no token in it.
pub fn job_response(job: &CiJob) -> serde_json::Value {
    serde_json::json!({
        "id": job.job.id,
        "job_info": {
            "name": job.job.name,
            "project_id": job.job.project_id,
            "project_full_path": job.job.project_path,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vk_hub_proto::job::{Image, Step, Variable};

    fn job() -> CiJob {
        let mut job = CiJob {
            server_url: "https://gitlab.example.com".into(),
            ..CiJob::default()
        };
        job.job.id = 42;
        job.job.project_path = "acme/web".into();
        job.token = "glcbt-tok".into();
        job.sources.repo_url = "https://gitlab.example.com/acme/web.git".into();
        job.sources.sha = "ab".repeat(20);
        job.image.user = Some("1000".into());
        job.steps = vec![Step {
            name: "script".into(),
            script: vec!["# vk: mem=8G cpus=4\nmake".into(), "# vk: mem=2G".into()],
            ..Step::default()
        }];
        job.services = vec![Image {
            name: "postgres:17".into(),
            aliases: vec!["db".into(), "pg".into()],
            variables: vec![Variable {
                key: "POSTGRES_DB".into(),
                value: "$CI_JOB_ID".into(),
                public: true,
                ..Variable::default()
            }],
            ..Image::default()
        }];
        job.variables = vec![
            Variable {
                key: "CI_JOB_ID".into(),
                value: "42".into(),
                public: true,
                ..Variable::default()
            },
            Variable {
                key: "KUBECONFIG".into(),
                value: "apiVersion: v1".into(),
                file: true,
                ..Variable::default()
            },
        ];
        job
    }

    fn cfg() -> Config {
        toml::from_str("").unwrap()
    }

    fn meta() -> Meta {
        Meta {
            gitlab_id: 42,
            slot: 3,
            project_slot: 0,
            project_id: 12,
        }
    }

    #[test]
    fn the_executor_sees_what_a_custom_executor_is_given() {
        let job = job();
        let place = place(&cfg(), &job, &meta()).unwrap();
        assert_eq!(place.project_dir, "/builds/acme/web");
        let vars = Vars::of(&job, &place);
        let env = child_env(&job, &vars, &place, Path::new("/n/j")).unwrap();
        let get = |k: &str| {
            env.iter()
                .rev()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("CUSTOM_ENV_CI_JOB_ID").as_deref(), Some("42"));
        assert_eq!(get("CUSTOM_ENV_CI_CONCURRENT_ID").as_deref(), Some("3"));
        assert_eq!(
            get("CUSTOM_ENV_KUBECONFIG").as_deref(),
            Some("apiVersion: v1")
        );
        assert_eq!(
            get("CUSTOM_ENV_CI_REPOSITORY_URL").as_deref(),
            Some("https://gitlab-ci-token:glcbt-tok@gitlab.example.com/acme/web.git")
        );
        assert_eq!(get("CUSTOM_ENV_MICROVM_USER").as_deref(), Some("1000"));
        assert_eq!(get("CUSTOM_ENV_MICROVM_MEM").as_deref(), Some("8G"));
        assert_eq!(get("CUSTOM_ENV_MICROVM_CPUS").as_deref(), Some("4"));
        assert_eq!(
            get("BUILD_EXIT_CODE_FILE").as_deref(),
            Some("/n/j/exit_code")
        );
        assert_eq!(
            get(crate::jobctx::JOB_SERVER_URL).as_deref(),
            Some("https://gitlab.example.com")
        );
        let services: serde_json::Value =
            serde_json::from_str(&get("CUSTOM_ENV_CI_JOB_SERVICES").unwrap()).unwrap();
        assert_eq!(services[0]["alias"], "db");
        assert_eq!(services[0]["variables"]["POSTGRES_DB"], "42");
        // The identity file carries no token.
        assert!(!job_response(&job).to_string().contains("glcbt"));
    }

    #[test]
    fn a_project_path_that_escapes_is_refused() {
        let mut job = job();
        for bad in ["", "../etc", "acme//web", "/abs", "a/./b", "a b"] {
            job.job.project_path = bad.into();
            assert!(place(&cfg(), &job, &meta()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_clone_url_carries_the_token_once() {
        assert_eq!(
            clone_url("https://old:creds@h.example/p.git", "t").unwrap(),
            "https://gitlab-ci-token:t@h.example/p.git"
        );
        // Only the authority's user info goes: an `@` in the path stays.
        assert_eq!(
            clone_url("https://h.example/g/p@v2.git", "t").unwrap(),
            "https://gitlab-ci-token:t@h.example/g/p@v2.git"
        );
        assert!(clone_url("h.example/p.git", "t").is_err());
    }
}
