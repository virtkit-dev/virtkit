//! Field-by-field translation of GitLab jobs, following docs/gitlab-dispatch.md,
//! "The job spec". The contract's fixture, `request_job_valid.json`, comes from
//! gitlab-runner v19.5.0's network/gitlab_test.go getRequestJobResponse (MIT, Copyright
//! (c) 2015-2019 GitLab Inc.); `full_job.json` is ours and covers every field.

use vk_gitlab::job::Job;
use vk_gitlab::spec::{SpecContext, translate};
use vk_hub_proto::job::*;

fn load(name: &str) -> Job {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn ctx() -> SpecContext {
    SpecContext {
        server_url: "https://gitlab.example.com".to_owned(),
        server_ca_pem: Some("-----BEGIN CERTIFICATE-----\n…".to_owned()),
        runner_id: 5,
        output_limit: 4 << 20,
        short_token: "abcdefghi".to_owned(),
    }
}

fn var<'a>(job: &'a CiJob, key: &str) -> &'a Variable {
    job.variables.iter().rev().find(|v| v.key == key).unwrap()
}

#[test]
fn upstream_request_job_response() {
    let t = translate(&load("request_job_valid.json"), &ctx());
    let job = t.job;
    assert_eq!(job.server_url, "https://gitlab.example.com");
    assert!(job.server_ca_pem.is_some());
    assert_eq!(job.job.id, 10);
    assert_eq!(job.job.name, "test-job");
    assert_eq!(job.job.stage, "test");
    assert_eq!(job.job.project_id, 123);
    assert_eq!(job.job.project_name, "test-project");
    assert_eq!(job.job.runner_id, 5);
    assert_eq!(job.token, "job-token");
    assert_eq!(job.timeout_secs, 3600);
    // credentials stripped from the clone URL
    assert_eq!(
        job.sources.repo_url,
        "https://gitlab.example.com/test/test-project.git"
    );
    assert_eq!(job.sources.git_ref, "main");
    assert_eq!(job.sources.sha, "abcdef123456");
    assert_eq!(job.sources.before_sha, "654321fedcba");
    assert_eq!(job.sources.ref_type, RefType::Branch);
    assert!(!job.sources.allow_fetch);
    let ci_ref = var(&job, "CI_REF_NAME");
    assert!(ci_ref.public && ci_ref.file && ci_ref.raw);
    assert_eq!(var(&job, "CI_RUNNER_SHORT_TOKEN").value, "abcdefghi");
    assert_eq!(
        var(&job, "CI_RUNNER_VERSION").value,
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(job.steps.len(), 2);
    assert_eq!(job.steps[0].script, ["date", "ls -ls"]);
    assert_eq!(job.steps[1].name, "after_script");
    assert_eq!(job.steps[1].when, When::Always);
    assert!(job.steps[1].allow_failure);
    assert_eq!(job.image.name, "ruby:3.3");
    assert_eq!(job.image.entrypoint, ["/bin/sh"]);
    assert_eq!(job.image.platform.as_deref(), Some("arm64/v8"));
    assert_eq!(job.services[0].aliases, ["db-pg"]);
    assert_eq!(job.services[0].command, ["sleep", "30"]);
    assert_eq!(job.services[0].platform.as_deref(), Some("amd64/linux"));
    assert_eq!(job.services[1].platform.as_deref(), Some("arm"));
    let a = &job.artifacts[0];
    assert_eq!(
        (
            a.name.as_str(),
            a.when,
            a.format,
            a.expire_in.as_str(),
            a.artifact_type.as_str()
        ),
        (
            "artifact.zip",
            When::Always,
            ArtifactFormat::Zip,
            "7d",
            "archive"
        )
    );
    // `$CI_COMMIT_SHA` is not among this job's variables: it expands to nothing, leaving a
    // key that cannot be sanitized, and the cache is skipped as gitlab-runner skips it.
    assert!(job.caches.is_empty());
    assert!(
        t.warnings.iter().any(|w| w.contains("cache")),
        "{:?}",
        t.warnings
    );
    assert_eq!(
        job.registry_credentials.len(),
        0,
        "type `Registry` is not `registry`"
    );
    assert_eq!(job.dependencies[0].id, 9);
    assert_eq!(job.dependencies[0].token, "other-job-token");
    assert_eq!(
        job.dependencies[0].artifacts_file.as_ref().unwrap().size,
        13_631_488
    );
    assert_eq!(job.trace.limit_bytes, 4 << 20);
    let spec = JobSpec::GitlabCi(job);
    assert!(serde_json::to_vec(&spec).unwrap().len() < MAX_JOB_SPEC);
}

#[test]
fn every_field_of_a_busy_job() {
    let t = translate(&load("full_job.json"), &ctx());
    let job = t.job;
    let info = &job.job;
    assert_eq!(
        (
            info.id,
            info.pipeline_id,
            info.project_id,
            info.namespace_id,
            info.root_namespace_id,
            info.user_id
        ),
        (42, 1001, 7, 3, 2, 99)
    );
    assert_eq!(info.project_path, "group/app");
    let s = &job.sources;
    assert_eq!(s.repo_url, "https://gitlab.example.com/group/app.git");
    assert!(!s.repo_url.contains("glcbt"));
    assert_eq!(s.object_format, ObjectFormat::Sha1);
    assert_eq!(s.refspecs, ["+refs/heads/main:refs/remotes/origin/main"]);
    assert_eq!(s.depth, 20);
    assert_eq!(s.protected, Some(true));
    assert!(s.allow_fetch);
    assert_eq!(job.image.aliases, ["build"]);
    assert_eq!(job.image.entrypoint, [""]);
    assert_eq!(job.image.ports[0].number, 8080);
    assert_eq!(job.image.ports[0].protocol, "http");
    assert_eq!(job.image.ports[0].name.as_deref(), Some("web"));
    assert_eq!(job.image.variables[0].key, "IMG");
    assert_eq!(job.image.pull_policy, [PullPolicy::IfNotPresent]);
    assert_eq!(job.image.platform.as_deref(), Some("linux/amd64"));
    assert_eq!(job.image.user.as_deref(), Some("1000"));
    assert_eq!(job.services[0].aliases, ["db", "database"]);
    assert_eq!(
        job.services[0].user.as_deref(),
        Some("999"),
        "kubernetes.user when docker has none"
    );
    let secret = var(&job, "SECRET");
    assert!(secret.masked && secret.raw && !secret.public);
    assert_eq!(job.steps[1].timeout_secs, 300);
    assert_eq!(job.hooks[0].name, HookName::PreGetSourcesScript);
    let a = &job.artifacts[1];
    assert_eq!(a.name, "artifacts", "an empty name becomes `artifacts`");
    assert_eq!(a.artifact_type, "junit");
    assert_eq!(a.format, ArtifactFormat::Gzip);
    assert_eq!(job.artifacts[0].exclude, ["out/tmp"]);
    let c = &job.caches[0];
    assert_eq!(
        (c.key.as_str(), c.policy, c.untracked),
        ("deps", CachePolicy::Pull, true)
    );
    assert_eq!(c.fallback_keys, ["deps-main"]);
    assert_eq!(job.registry_credentials[0].url, "registry.example.com");
    assert_eq!(job.registry_credentials[0].password, "glcbt-64_jobtoken");
    assert_eq!(job.trace.mask_prefixes, ["ghp_"]);
    assert!(job.trace.sections);
}

#[test]
fn defaults_and_normalization() {
    let job: Job = serde_json::from_value(serde_json::json!({
        "id": 3,
        "token": "t",
        "job_info": {"name": "test:unit"},
        "git_info": {"ref": "feature/x", "ref_type": "tag", "repo_object_format": "sha256"},
        "variables": [{"key": "KEY", "value": "deps"}],
        "image": {"name": "alpine", "ports": [{"number": 80}], "pull_policy": ["always", "sometimes"]},
        "cache": [
            {"key": ""},
            {"key": "$KEY/../${KEY}-%2Fx ", "fallback_keys": ["..", "${KEY}"]}
        ],
        "artifacts": [{"paths": ["a"], "artifact_format": "zipzstd"}],
        "hooks": [{"name": "unknown_hook", "script": ["x"]}],
        "credentials": [{"type": "registry", "url": "r", "username": "u", "password": "p"}]
    }))
    .unwrap();
    let t = translate(&job, &SpecContext::default());
    let ci = t.job;
    assert_eq!(ci.timeout_secs, 7200, "gitlab-runner's default timeout");
    assert_eq!(ci.sources.ref_type, RefType::Tag);
    assert_eq!(ci.sources.object_format, ObjectFormat::Sha256);
    assert_eq!(
        ci.image.ports[0].protocol, "http",
        "gitlab-runner's default"
    );
    assert_eq!(ci.image.pull_policy, [PullPolicy::Always]);
    assert_eq!(ci.caches[0].key, "test:unit/feature/x", "<job name>/<ref>");
    assert_eq!(ci.caches[1].key, "deps-/x");
    assert_eq!(ci.caches[1].fallback_keys, ["deps"]);
    assert_eq!(ci.caches[0].policy, CachePolicy::PullPush);
    assert_eq!(ci.artifacts[0].name, "artifacts");
    assert_eq!(ci.artifacts[0].format, ArtifactFormat::ZipZstd);
    assert!(ci.hooks.is_empty());
    assert_eq!(ci.registry_credentials.len(), 1);
    for dropped in ["sometimes", "unknown_hook", ".."] {
        assert!(
            t.warnings.iter().any(|w| w.contains(dropped)),
            "{dropped}: {:?}",
            t.warnings
        );
    }
}

#[test]
fn cache_keys_expand_as_gitlab_runners_variables_do() {
    let job: Job = serde_json::from_value(serde_json::json!({
        "id": 4,
        "token": "t",
        "variables": [
            {"key": "BASE", "value": "deps"},
            {"key": "K", "value": "$BASE-v1"},
            {"key": "RAW", "value": "$BASE", "raw": true},
            {"key": "SECRET", "value": "s3cr3t", "masked": true}
        ],
        "cache": [
            {"key": "$K", "fallback_keys": ["$RAW", "${SECRET}/.."]},
            {"key": "runner-$CI_RUNNER_SHORT_TOKEN"},
            {"key": "${SECRET}/.."}
        ]
    }))
    .unwrap();
    let t = translate(&job, &ctx());
    let ci = t.job;
    // `K` was expanded once against the whole list, `RAW` was not.
    assert_eq!(ci.caches[0].key, "deps-v1");
    assert_eq!(ci.caches[0].fallback_keys, ["$BASE"]);
    assert_eq!(ci.caches[1].key, "runner-abcdefghi");
    assert_eq!(ci.caches.len(), 2, "the last key cannot be sanitized");
    // The variables themselves go to the node unexpanded.
    assert_eq!(var(&ci, "K").value, "$BASE-v1");
    assert_eq!(t.warnings.len(), 2, "{:?}", t.warnings);
    assert!(t.warnings.iter().all(|w| w.contains("${SECRET}/..")));
    assert!(!format!("{:?}", t.warnings).contains("s3cr3t"));
}

#[test]
fn a_repo_url_that_does_not_parse_still_loses_its_credentials() {
    let with = |url: &str| {
        let job: Job = serde_json::from_value(serde_json::json!({
            "id": 5,
            "token": "t",
            "git_info": {"repo_url": url}
        }))
        .unwrap();
        translate(&job, &ctx())
    };
    let t = with("https://gitlab-ci-token:glcbt-tok@bad host/g/p@v2.git");
    assert_eq!(t.job.sources.repo_url, "https://bad host/g/p@v2.git");
    assert_eq!(t.warnings, ["git_info.repo_url is not a valid URL"]);
    let t = with("gitlab-ci-token:glcbt-tok@host/p.git");
    assert_eq!(t.job.sources.repo_url, "");
    assert!(!format!("{:?}", t.warnings).contains("glcbt"));
}
