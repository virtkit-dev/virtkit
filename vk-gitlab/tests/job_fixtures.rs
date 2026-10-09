//! Job payloads decode, keep every field, and round-trip.
//!
//! `request_job_valid.json` and `request_job_unsupported_options.json` are the job response
//! of gitlab-runner v19.5.0 network/gitlab_test.go, getRequestJobResponse (valid and
//! invalid executor options), checked as its assertOnJobResponse does;
//! `job_inputs_complex.json` wraps the inputs of common/spec/inputs_test.go,
//! complexExampleInputs (TestJobInputs_Unmarshalling). MIT, Copyright (c) 2015-2019 GitLab
//! Inc. `full_job.json` is ours: one of every field the job types model.

use vk_gitlab::job::Job;

fn load(name: &str) -> (Job, serde_json::Value) {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap();
    let job: Job = serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
    (job, serde_json::from_str(&text).unwrap())
}

/// Serializing and decoding again gives the same job.
fn assert_round_trip(job: &Job) {
    let text = serde_json::to_string(job).unwrap();
    let again: Job = serde_json::from_str(&text).unwrap();
    assert_eq!(&again, job);
}

// assertOnJobResponse
fn assert_on_job_response(job: &Job, unsupported: bool) {
    assert_eq!(job.id, 10);
    assert_eq!(job.image.name, "ruby:3.3");
    assert_eq!(job.image.entrypoint, ["/bin/sh"]);
    assert_eq!(job.services.len(), 2);
    assert_eq!(job.services[0].name, "postgresql:9.5");
    assert_eq!(job.services[0].entrypoint, ["/bin/sh"]);
    assert_eq!(job.services[0].command, ["sleep", "30"]);
    assert_eq!(job.services[0].alias, "db-pg");
    assert_eq!(job.services[1].name, "mysql:5.6");
    assert_eq!(job.services[1].alias, "db-mysql");
    assert_eq!(job.services[1].executor_options.docker.platform, "arm");
    assert_eq!(job.variables.len(), 1);
    let v = &job.variables[0];
    assert_eq!((v.key.as_str(), v.value.as_str()), ("CI_REF_NAME", "main"));
    assert!(v.public && v.file && v.raw && !v.masked);
    if unsupported {
        let msg = job.unsupported_options().expect("unsupported options");
        assert!(msg.contains("blammo"), "{msg}");
        assert!(msg.contains("powpow"), "{msg}");
    } else {
        assert_eq!(job.unsupported_options(), None);
        assert_eq!(job.image.executor_options.docker.platform, "arm64/v8");
        assert_eq!(
            job.services[0].executor_options.docker.platform,
            "amd64/linux"
        );
    }
}

#[test]
fn upstream_request_job_response() {
    let (job, _) = load("request_job_valid.json");
    assert_on_job_response(&job, false);
    assert_eq!(job.token.expose(), "job-token");
    assert_eq!(job.job_info.name, "test-job");
    assert_eq!(job.job_info.project_id, 123);
    assert_eq!(job.git_info.git_ref, "main");
    assert_eq!(job.git_info.ref_type, "branch");
    assert_eq!(job.runner_info.timeout, 3600);
    assert_eq!(job.steps.len(), 2);
    assert_eq!(job.steps[1].name, "after_script");
    assert_eq!(job.steps[1].when, "always");
    assert!(job.steps[1].allow_failure);
    assert_eq!(job.artifacts[0].expire_in, "7d");
    assert_eq!(job.cache[0].policy, "push");
    assert_eq!(job.credentials[0].password.expose(), "job-token");
    assert_eq!(job.dependencies[0].token.expose(), "other-job-token");
    assert_eq!(job.dependencies[0].artifacts_file.size, 13_631_488);
    assert_eq!(
        job.repo_clean_url(),
        "https://gitlab.example.com/test/test-project.git"
    );
    assert!(job.extra.is_empty(), "{:?}", job.extra.keys());
    assert_round_trip(&job);
}

#[test]
fn upstream_request_job_response_with_unsupported_options() {
    let (job, _) = load("request_job_unsupported_options.json");
    assert_on_job_response(&job, true);
    assert_round_trip(&job);
}

#[test]
fn upstream_complex_inputs() {
    let (job, _) = load("job_inputs_complex.json");
    let keys: Vec<&str> = job.inputs.iter().map(|i| i.key.as_str()).collect();
    assert_eq!(
        keys,
        [
            "username",
            "fullname",
            "password",
            "age",
            "likes_spaghetti",
            "friends",
            "address"
        ]
    );
    let password = &job.inputs[2];
    assert!(password.value.sensitive);
    assert_eq!(password.value.kind, "string");
    assert_eq!(job.inputs[3].value.content, serde_json::json!(1));
    assert_eq!(
        job.inputs[5].value.content,
        serde_json::json!(["bob", "sally"])
    );
    assert_eq!(job.inputs[6].value.content["line1"], "42 Wallaby Way");
    assert_round_trip(&job);
}

#[test]
fn every_modeled_field() {
    let (job, raw) = load("full_job.json");
    assert_eq!(job.job_info.scoped_user_id, Some(100));
    assert_eq!(
        job.job_info.project_jobs_running_on_instance_runners_count,
        "+Inf"
    );
    assert_eq!(job.git_info.protected, Some(true));
    assert_eq!(job.git_info.depth, 20);
    assert_eq!(job.git_info.refspecs.len(), 1);
    assert_eq!(job.image.executor_options.docker.user.0, "1000");
    assert_eq!(job.image.pull_policies, ["if-not-present"]);
    assert_eq!(job.image.ports[0].number, 8080);
    assert_eq!(job.services[0].aliases(), ["db", "database"]);
    assert_eq!(job.services[0].executor_options.kubernetes.user.0, "999");
    assert_eq!(job.unsupported_options(), None);
    assert_eq!(
        job.artifacts[1].expire_in, "",
        "null decodes to the zero value"
    );
    assert_eq!(job.cache[0].fallback_keys, ["deps-main"]);
    assert!(job.debug_mode_enabled());
    assert_eq!(job.features.token_mask_prefixes, ["ghp_"]);
    assert_eq!(job.features.failure_reasons.len(), 4);
    let tracing = job.features.tracing.as_ref().unwrap();
    assert_eq!(
        tracing.otel_endpoints[0]
            .auth
            .as_ref()
            .unwrap()
            .http_bearer_gcp_oidc
            .as_ref()
            .unwrap()
            .audience,
        "aud"
    );
    let vault = job.secrets["DB_PASSWORD"].vault.as_ref().unwrap();
    assert_eq!(vault.server.auth.data["role"], "ci");
    assert_eq!(job.secrets["DB_PASSWORD"].file, Some(false));
    assert!(job.secrets["GCP_KEY"].gcp_secret_manager.is_some());
    assert!(job.secrets["AZURE_KEY"].azure_key_vault.is_some());
    assert_eq!(
        job.secrets["AWS_KEY"]
            .aws_secrets_manager
            .as_ref()
            .unwrap()
            .server
            .region,
        "eu-west-1"
    );
    assert_eq!(
        job.secrets["GL_KEY"]
            .gitlab_secrets_manager
            .as_ref()
            .unwrap()
            .server
            .inline_auth
            .auth_mount,
        "jwt"
    );
    assert_eq!(job.hooks[0].name, "pre_get_sources_script");
    assert!(job.run.as_deref().unwrap().contains("hello world"));
    assert!(job.policy_options.policy_job);
    assert_eq!(job.policy_options.variable_override_allowed, Some(false));
    assert!(job.suspend_options.suspend_on_failure);
    assert_eq!(job.suspend_options.runtime_environment_key, "env-1");
    // An unmodeled field survives and is forwarded as received.
    assert_eq!(job.extra["a_field_added_later"], raw["a_field_added_later"]);
    assert_round_trip(&job);

    // Every top-level field of the payload is either modeled or kept.
    let reencoded = serde_json::to_value(&job).unwrap();
    for key in raw.as_object().unwrap().keys() {
        assert!(reencoded.get(key).is_some(), "{key} lost in re-encoding");
    }
}

#[test]
fn debug_output_hides_secrets() {
    let (job, _) = load("full_job.json");
    let dbg = format!("{job:?}");
    for secret in ["glcbt-64_jobtoken", "glcbt-64_dep", "s3cr3t-value"] {
        assert!(!dbg.contains(secret), "{secret} in Debug output");
    }
    // The secret providers' JWTs, Vault's in its auth data included.
    let dbg = format!("{:?}", job.secrets);
    assert!(!dbg.contains("eyJ"), "a JWT in Debug output: {dbg}");
    assert!(dbg.contains("\"role\""), "Vault auth data keys are listed");
}
