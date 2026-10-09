//! Compatibility tests of the runner API client against a fake GitLab.
//!
//! Ported from gitlab-runner v19.5.0 (MIT, Copyright (c) 2015-2019 GitLab Inc.),
//! network/gitlab_test.go and network/retry_requester_test.go; each test names the upstream
//! test it follows. Upstream also asserts log lines; these assert the outcome and the
//! requests on the wire.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use support::{FakeGitLab, Recorded, Reply, TEST_SYSTEM_ID, client, client_with_retry};
use vk_gitlab::api::{
    JobCredentials, PatchState, PatchTraceResult, RetryPolicy, UpdateJobInfo, UpdateJobResult,
    UpdateState, api_base_url,
};
use vk_gitlab::failure::{FailureReason, JobState};
use vk_gitlab::secret::Secret;

const VALID_TOKEN: &str = "valid";
const VALID_GLRT_TOKEN: &str = "glrt-valid-token";
const INVALID_TOKEN: &str = "invalid";

fn job(id: i64, token: &str) -> JobCredentials {
    JobCredentials {
        id,
        token: Secret::new(token),
    }
}

// --- runners/verify -------------------------------------------------------------------

// mockVerifyRunnerHandler
fn verify_handler(legacy: bool) -> impl Fn(&Recorded) -> Reply + Send + Sync + 'static {
    move |r: &Recorded| {
        assert!(!r.header("x-request-id").is_empty());
        if r.path != "/api/v4/runners/verify" {
            return Reply::status(404);
        }
        if r.method != "POST" {
            return Reply::status(406);
        }
        let req = r.json();
        let token = req["token"].as_str().unwrap_or_default().to_owned();
        assert!(
            !r.header("runner-token").is_empty(),
            "runner-token header is required"
        );
        assert_eq!(
            token,
            r.header("runner-token"),
            "token in header and body must match"
        );
        assert!(
            req["info"]["features"].is_object(),
            "info is sent with verify"
        );
        match token.as_str() {
            VALID_TOKEN | VALID_GLRT_TOKEN if legacy => {
                return Reply::status(200).header("Content-Type", "plain/text");
            }
            VALID_TOKEN | VALID_GLRT_TOKEN => {}
            INVALID_TOKEN => return Reply::status(403),
            _ => return Reply::status(400),
        }
        Reply::status(200).json(&format!(
            r#"{{"id": 54321, "token": "{token}", "token_expires_at": "2684-10-16T13:25:59Z"}}"#
        ))
    }
}

// TestVerifyRunner
#[tokio::test]
async fn verify_runner() {
    let s = FakeGitLab::start(verify_handler(false)).await;
    for token in [VALID_TOKEN, VALID_GLRT_TOKEN] {
        let res = client(&s.url, token, 1).verify().await.unwrap().unwrap();
        assert_eq!(res.id, 54321);
        assert_eq!(res.token, Some(Secret::new(token)));
        assert!(!format!("{res:?}").contains(token), "token in Debug output");
        assert_eq!(
            res.token_expires_at.as_deref(),
            Some("2684-10-16T13:25:59Z")
        );
    }
    assert!(
        client(&s.url, INVALID_TOKEN, 1)
            .verify()
            .await
            .unwrap()
            .is_none()
    );
    assert!(client(&s.url, "other", 1).verify().await.is_err());
    // "broken credentials": a URL that is not http(s) never makes a client.
    assert!(api_base_url("broken").is_err());
    let body = s.requests_to("/api/v4/runners/verify")[0].json();
    assert_eq!(body["system_id"], TEST_SYSTEM_ID);
}

// TestVerifyRunnerOnLegacyServer
#[tokio::test]
async fn verify_runner_on_legacy_server() {
    let s = FakeGitLab::start(verify_handler(true)).await;
    for token in [VALID_TOKEN, VALID_GLRT_TOKEN] {
        let res = client(&s.url, token, 1).verify().await.unwrap().unwrap();
        assert_eq!(res.id, 0);
    }
    assert!(
        client(&s.url, INVALID_TOKEN, 1)
            .verify()
            .await
            .unwrap()
            .is_none()
    );
    assert!(client(&s.url, "other", 1).verify().await.is_err());
}

// --- jobs/request ----------------------------------------------------------------------

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

// TestGitLabClient_RequestJob and mockRequestJobHandler
#[tokio::test]
async fn request_job() {
    let too_many = Arc::new(AtomicUsize::new(0));
    let unavailable = Arc::new(AtomicUsize::new(0));
    let (tm, un) = (Arc::clone(&too_many), Arc::clone(&unavailable));
    let valid = fixture("request_job_valid.json");
    let unsupported = fixture("request_job_unsupported_options.json");
    let s = FakeGitLab::start(move |r: &Recorded| {
        let mut path = r.path.as_str();
        let mut response = valid.as_str();
        if let Some(p) = path.strip_prefix("/unsupported") {
            path = p;
            response = unsupported.as_str();
        }
        if path.starts_with("/unavailable") {
            un.fetch_add(1, Ordering::SeqCst);
            return Reply::status(503).header("Retry-After", "1");
        }
        if path.starts_with("/too-many") {
            tm.fetch_add(1, Ordering::SeqCst);
            return Reply::status(429)
                .header("Retry-After", "60")
                .header("RateLimit-ResetTime", "Wed, 21 Oct 2015 07:28:00 GMT");
        }
        let reply = Reply::status(0).header("X-Request-Id", "foobar");
        if path != "/api/v4/jobs/request" {
            return Reply {
                status: 404,
                ..reply
            };
        }
        if r.method != "POST" {
            return Reply {
                status: 406,
                ..reply
            };
        }
        let req = r.json();
        assert_eq!(req["system_id"], TEST_SYSTEM_ID);
        let token = req["token"].as_str().unwrap_or_default();
        assert_eq!(
            token,
            r.header("runner-token"),
            "token in header and body must match"
        );
        match token {
            VALID_TOKEN => {}
            "no-jobs" => {
                return Reply {
                    status: 204,
                    ..reply
                }
                .header("X-GitLab-Last-Update", "a nice timestamp");
            }
            INVALID_TOKEN => {
                return Reply {
                    status: 403,
                    ..reply
                };
            }
            _ => {
                return Reply {
                    status: 400,
                    ..reply
                };
            }
        }
        if r.header("accept") != "application/json" {
            return Reply {
                status: 400,
                ..reply
            };
        }
        Reply {
            status: 201,
            ..reply
        }
        .json(response)
    })
    .await;

    // valid token
    let res = client(&s.url, VALID_TOKEN, 5).request_job().await;
    assert!(res.healthy);
    let job = res.job.unwrap();
    assert_eq!(job.id, 10);
    assert_eq!(job.image.name, "ruby:3.3");
    assert_eq!(job.unsupported_options(), None);

    // no jobs: healthy, and X-GitLab-Last-Update is kept and echoed next time
    let c = client(&s.url, "no-jobs", 5);
    let res = c.request_job().await;
    assert!(res.healthy, "If no jobs, runner is healthy");
    assert!(res.job.is_none());
    assert_eq!(
        c.last_update(),
        "a nice timestamp",
        "Last-Update should be set"
    );
    c.request_job().await;
    let reqs = s.requests_to("/api/v4/jobs/request");
    assert_eq!(
        reqs.last().unwrap().json()["last_update"],
        "a nice timestamp"
    );
    assert!(
        reqs[0].json().get("last_update").is_none(),
        "empty last_update is omitted"
    );

    // invalid token: unhealthy
    let res = client(&s.url, INVALID_TOKEN, 5).request_job().await;
    assert!(!res.healthy);
    assert!(res.job.is_none());

    // unsupported executor options: the job is received, its options flagged
    let res = client(&format!("{}/unsupported", s.url), VALID_TOKEN, 5)
        .request_job()
        .await;
    let msg = res.job.unwrap().unsupported_options().unwrap();
    assert!(msg.contains("blammo") && msg.contains("powpow"), "{msg}");

    // service unavailable: retried (Retry-After honoured), then healthy and empty
    let started = Instant::now();
    let res = client(&format!("{}/unavailable", s.url), VALID_TOKEN, 2)
        .request_job()
        .await;
    assert!(res.healthy && res.job.is_none());
    assert_eq!(unavailable.load(Ordering::SeqCst), 2);
    assert!(started.elapsed() >= Duration::from_secs(1));

    // too many requests: a rate-limited job request is not retried
    let res = client(&format!("{}/too-many", s.url), VALID_TOKEN, 5)
        .request_job()
        .await;
    assert!(res.healthy && res.job.is_none());
    assert_eq!(
        too_many.load(Ordering::SeqCst),
        1,
        "a rate limited job request must not be retried"
    );
}

#[tokio::test]
async fn request_job_advertises_runner_info() {
    // TestGitLabClient_RequestJob_TransmitsTwoPhaseJobCommit and TestFeaturesInfo_JSONMarshaling,
    // with the feature set of virtkit's docs/gitlab-dispatch.md.
    let s = FakeGitLab::start(|_: &Recorded| Reply::status(204)).await;
    client(&s.url, VALID_TOKEN, 1).request_job().await;
    let body = s.requests()[0].json();
    let f = body["info"]["features"].as_object().unwrap();
    let mut on: Vec<&str> = f
        .iter()
        .filter(|(_, v)| **v == true)
        .map(|(k, _)| k.as_str())
        .collect();
    on.sort_unstable();
    let mut want = [
        "variables",
        "image",
        "services",
        "artifacts",
        "cache",
        "fallback_cache_keys",
        "upload_multiple_artifacts",
        "upload_raw_artifacts",
        "refspecs",
        "masking",
        "raw_variables",
        "artifacts_exclude",
        "multi_build_steps",
        "trace_reset",
        "trace_checksum",
        "trace_size",
        "cancelable",
        "cancel_gracefully",
        "return_exit_code",
        "service_variables",
        "two_phase_job_commit",
    ];
    want.sort_unstable();
    assert_eq!(on, want);
    assert_eq!(f.len(), 31, "every feature is sent, set or not");
    assert_eq!(body["info"]["name"], "vk-gitlab");
    assert_eq!(body["info"]["executor"], "vk");
    assert_eq!(body["info"]["shell"], "bash");
    assert_eq!(body["info"]["config"]["gpus"], "");
    assert!(
        s.requests()[0]
            .header("user-agent")
            .starts_with("vk-gitlab ")
    );
}

#[tokio::test]
async fn undecodable_job_is_failed_not_dropped() {
    // Not upstream: upstream drops a job it cannot decode, leaving it to time out.
    let s = FakeGitLab::start(|r: &Recorded| match r.path.as_str() {
        "/api/v4/jobs/request" => Reply::status(201)
            .json(r#"{"id": 77, "token": "jt", "variables": "s3cr3t-in-payload"}"#),
        "/api/v4/jobs/77/trace" => Reply::status(202),
        "/api/v4/jobs/77" => Reply::status(200),
        _ => Reply::status(404),
    })
    .await;
    let res = client(&s.url, VALID_TOKEN, 1).request_job().await;
    assert!(res.job.is_none() && res.healthy);
    // The decoding error names the position only: serde's message quotes the payload.
    let line = String::from_utf8(s.requests_to("/api/v4/jobs/77/trace")[0].body.to_vec()).unwrap();
    assert!(
        line.starts_with("ERROR: the runner could not decode this job (at line 1, column "),
        "{line}"
    );
    assert!(!line.contains("s3cr3t"), "{line}");
    let update = &s.requests_to("/api/v4/jobs/77")[0];
    assert_eq!(update.header("job-token"), "jt");
    assert_eq!(update.json()["state"], "failed");
    assert_eq!(update.json()["failure_reason"], "runner_system_failure");
}

// --- PUT jobs/:id ----------------------------------------------------------------------

// testUpdateJobHandler + setStateForUpdateJobHandlerResponse
fn update_job_handler(r: &Recorded) -> Reply {
    assert!(!r.header("x-request-id").is_empty());
    let reply = Reply::status(0).header("X-Request-Id", "foobar");
    if r.method != "PUT" {
        return Reply {
            status: 406,
            ..reply
        };
    }
    match r.path.as_str() {
        "/api/v4/jobs/200" => {}
        "/api/v4/jobs/202" => {
            return Reply {
                status: 202,
                ..reply
            };
        }
        "/api/v4/jobs/403" => {
            return Reply {
                status: 403,
                ..reply
            };
        }
        "/api/v4/jobs/412" => {
            return Reply {
                status: 412,
                ..reply
            };
        }
        _ => {
            return Reply {
                status: 404,
                ..reply
            };
        }
    }
    let req = r.json();
    let token = req["token"].as_str().unwrap_or_default();
    assert_eq!(
        token,
        r.header("job-token"),
        "token in header and body must match"
    );
    assert_eq!(token, "token");
    let status = match req["state"].as_str() {
        Some("running") | Some("canceling") => 200,
        Some("failed") => match req["failure_reason"].as_str() {
            Some("script_failure") | Some("runner_system_failure") => 200,
            _ => 400,
        },
        _ => 400,
    };
    Reply { status, ..reply }
}

fn update_info(id: i64, state: JobState, reason: Option<&str>) -> UpdateJobInfo {
    let mut info = UpdateJobInfo::new(id, state);
    info.failure_reason = reason.map(FailureReason::new);
    info.output.checksum = "checksum".to_owned();
    info.output.bytesize = 42;
    info
}

fn update_result(state: UpdateState) -> UpdateJobResult {
    UpdateJobResult {
        state,
        cancel_requested: false,
        new_update_interval: 0,
    }
}

// TestUpdateJob ("Update fails for badly formatted request" sends a state the typed
// JobState cannot hold, so it has no counterpart here).
#[tokio::test]
async fn update_job() {
    let s = FakeGitLab::start(update_job_handler).await;
    let c = client(&s.url, "runner", 1);
    let creds = job(0, "token");
    let cases = [
        (
            update_info(200, JobState::Running, None),
            UpdateState::Succeeded,
        ),
        (
            update_info(403, JobState::Success, None),
            UpdateState::Abort,
        ),
        (
            update_info(404, JobState::Success, None),
            UpdateState::Abort,
        ),
        (
            update_info(202, JobState::Success, None),
            UpdateState::AcceptedButNotCompleted,
        ),
        (
            update_info(412, JobState::Success, None),
            UpdateState::TraceValidationFailed,
        ),
        (
            update_info(200, JobState::Failed, Some("script_failure")),
            UpdateState::Succeeded,
        ),
        (
            update_info(200, JobState::Failed, Some("invalid-failure-reason")),
            UpdateState::Failed,
        ),
    ];
    for (info, want) in cases {
        assert_eq!(
            c.update_job(&creds, &info).await,
            update_result(want),
            "{info:?}"
        );
    }
    let body = s.requests_to("/api/v4/jobs/200")[0].json();
    assert_eq!(body["output"]["checksum"], "checksum");
    assert_eq!(body["output"]["bytesize"], 42);
    assert_eq!(
        body["checksum"], "checksum",
        "the deprecated top-level checksum is still sent"
    );
    assert!(
        body.get("exit_code").is_none(),
        "a zero exit code is omitted"
    );
    assert!(body.get("failure_reason").is_none());
}

// TestUpdateJobAsKeepAlive
#[tokio::test]
async fn update_job_as_keep_alive() {
    let s = FakeGitLab::start(|r: &Recorded| {
        let reply = Reply::status(200).header("X-Request-Id", "foobar");
        let reply = match r.path.as_str() {
            "/api/v4/jobs/10" => reply,
            "/api/v4/jobs/11" => reply.header("Job-Status", "canceled"),
            "/api/v4/jobs/12" => reply.header("Job-Status", "failed"),
            "/api/v4/jobs/13" => reply.header("Job-Status", "canceling"),
            _ => return Reply::status(404),
        };
        assert_eq!(r.json()["token"], "token");
        reply
    })
    .await;
    let c = client(&s.url, "runner", 1);
    let creds = job(0, "token");
    let run = |id| UpdateJobInfo::new(id, JobState::Running);
    assert_eq!(
        c.update_job(&creds, &run(10)).await,
        update_result(UpdateState::Succeeded)
    );
    assert_eq!(
        c.update_job(&creds, &run(11)).await,
        update_result(UpdateState::Abort)
    );
    assert_eq!(
        c.update_job(&creds, &run(12)).await,
        update_result(UpdateState::Abort)
    );
    assert_eq!(
        c.update_job(&creds, &run(13)).await,
        UpdateJobResult {
            state: UpdateState::Succeeded,
            cancel_requested: true,
            new_update_interval: 0
        }
    );
}

// TestUpdateJob_RuntimeEnvironmentKey
#[tokio::test]
async fn update_job_runtime_environment_key() {
    let s = FakeGitLab::start(|_: &Recorded| Reply::status(200)).await;
    let c = client(&s.url, "runner", 1);
    let mut info = UpdateJobInfo::new(1, JobState::Success);
    c.update_job(&job(1, "t"), &info).await;
    info.runtime_environment_key = "27/sys-1/namespace=ns&pvc=x".to_owned();
    c.update_job(&job(1, "t"), &info).await;
    let reqs = s.requests();
    assert!(reqs[0].json().get("runtime_environment_key").is_none());
    assert_eq!(
        reqs[1].json()["runtime_environment_key"],
        "27/sys-1/namespace=ns&pvc=x"
    );
}

// --- PATCH jobs/:id/trace --------------------------------------------------------------

const PATCH_TOKEN: &str = "token";
const PATCH_CONTENT: &[u8] = b"trace trace trace";

/// getPatchServer: checks path, method, token and Content-Range, then hands the body and
/// range to `handler`.
async fn patch_server(
    handler: impl Fn(&Recorded, &[u8], usize, usize) -> Reply + Send + Sync + 'static,
) -> FakeGitLab {
    FakeGitLab::start(move |r: &Recorded| {
        assert!(!r.header("x-request-id").is_empty());
        if r.path != "/api/v4/jobs/1/trace" {
            return Reply::status(404);
        }
        if r.method != "PATCH" {
            return Reply::status(406);
        }
        assert_eq!(r.header("job-token"), PATCH_TOKEN);
        let (start, end) = r.header("content-range").split_once('-').unwrap();
        handler(r, &r.body, start.parse().unwrap(), end.parse().unwrap())
    })
    .await
}

async fn patch(s: &FakeGitLab, content: &[u8], start: usize) -> PatchTraceResult {
    client(&s.url, "runner", 1)
        .patch_trace(&job(1, PATCH_TOKEN), content, start, false)
        .await
}

// TestUnknownPatchTrace, TestForbiddenPatchTrace, TestJobFailedStatePatchTrace
#[tokio::test]
async fn patch_trace_states() {
    let s = patch_server(|_, _, _, _| Reply::status(404)).await;
    assert_eq!(
        patch(&s, PATCH_CONTENT, 0).await.state,
        PatchState::NotFound
    );
    let s = patch_server(|_, _, _, _| Reply::status(403)).await;
    assert_eq!(patch(&s, PATCH_CONTENT, 0).await.state, PatchState::Abort);
    let s = patch_server(|_, _, _, _| Reply::status(202).header("Job-Status", "failed")).await;
    assert_eq!(patch(&s, PATCH_CONTENT, 0).await.state, PatchState::Abort);
}

// TestPatchTrace
#[tokio::test]
async fn patch_trace() {
    for (remote, cancel) in [("running", false), ("canceling", true)] {
        let s = patch_server(move |_, body, start, end| {
            assert_eq!(body, &PATCH_CONTENT[start..=end]);
            Reply::status(202)
                .header("Job-Status", remote)
                .header("X-Request-Id", "foobar")
        })
        .await;
        for (content, start, sent) in [
            (PATCH_CONTENT, 0, PATCH_CONTENT.len()),
            (&PATCH_CONTENT[3..], 3, PATCH_CONTENT.len()),
            (&PATCH_CONTENT[3..10], 3, 10),
        ] {
            let res = patch(&s, content, start).await;
            assert_eq!(res.state, PatchState::Succeeded);
            assert_eq!(res.cancel_requested, cancel);
            assert_eq!(res.sent_offset, sent);
        }
    }
}

// TestRangeMismatchPatchTrace
#[tokio::test]
async fn range_mismatch_patch_trace() {
    for (remote, cancel) in [("running", false), ("canceling", true)] {
        let s = patch_server(move |_, _, start, _| {
            if start > 10 {
                return Reply::status(416).header("Range", "0-10");
            }
            Reply::status(202).header("Job-Status", remote)
        })
        .await;
        let mismatch = PatchTraceResult::new(10, PatchState::RangeMismatch, 0);
        assert_eq!(patch(&s, &PATCH_CONTENT[11..], 11).await, mismatch);
        assert_eq!(patch(&s, &PATCH_CONTENT[15..], 15).await, mismatch);
        assert_eq!(
            patch(&s, &PATCH_CONTENT[5..], 5).await,
            PatchTraceResult {
                sent_offset: PATCH_CONTENT.len(),
                cancel_requested: cancel,
                state: PatchState::Succeeded,
                new_update_interval: 0
            }
        );
    }
}

// TestPatchTraceCantConnect
#[tokio::test]
async fn patch_trace_cant_connect() {
    let url = {
        let s = patch_server(|_, _, _, _| Reply::status(202)).await;
        s.url.clone()
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let res = client(&url, "runner", 1)
        .patch_trace(&job(1, PATCH_TOKEN), PATCH_CONTENT, 0, false)
        .await;
    assert_eq!(res.state, PatchState::Failed);
}

/// (update, Job-Status, Content-Range, sent offset, cancel requested, not sent)
type UpdatedTraceCase = (&'static [u8], &'static str, &'static str, usize, bool, bool);

// TestPatchTraceUpdatedTrace
#[tokio::test]
async fn patch_trace_updated_trace() {
    let updates: [UpdatedTraceCase; 7] = [
        (b"test", "running", "0-3", 4, false, false),
        (b"", "running", "", 4, false, true),
        (b" ", "running", "4-4", 5, false, false),
        (b"test", "running", "5-8", 9, false, false),
        (b"test", "canceling", "9-12", 13, true, false),
        (b" ", "canceling", "13-13", 14, true, false),
        // Empty patches are not sent, so they carry no cancel request.
        (b"", "canceling", "", 14, false, true),
    ];
    let mut trace: Vec<u8> = Vec::new();
    let mut sent = 0;
    for (update, remote, range, want_sent, want_cancel, not_sent) in updates {
        let expected_body = update.to_vec();
        let s = patch_server(move |r, body, _, _| {
            assert!(!not_sent, "PatchTrace endpoint should not be called");
            assert_eq!(body, &expected_body[..]);
            assert_eq!(r.header("content-range"), range);
            assert_eq!(r.header("content-length"), body.len().to_string());
            Reply::status(202).header("Job-Status", remote)
        })
        .await;
        trace.extend_from_slice(update);
        let res = patch(&s, &trace[sent..], sent).await;
        assert_eq!(
            res,
            PatchTraceResult {
                sent_offset: want_sent,
                cancel_requested: want_cancel,
                state: PatchState::Succeeded,
                new_update_interval: 0
            }
        );
        assert_eq!(s.requests().len(), usize::from(!not_sent));
        sent = res.sent_offset;
    }
}

// TestPatchTraceContentRangeAndLength, TestPatchTraceContentRangeHeaderValues
#[tokio::test]
async fn patch_trace_content_range_and_length() {
    for (trace, remote, range, sent, cancel) in [
        (&b""[..], "running", "", 0, false),
        (&b"1"[..], "running", "0-0", 1, false),
        (&b"12"[..], "running", "0-1", 2, false),
        (&b"12"[..], "canceling", "0-1", 2, true),
    ] {
        let s = patch_server(move |r, body, _, _| {
            assert_eq!(r.header("content-range"), range);
            assert_eq!(r.header("content-length"), body.len().to_string());
            Reply::status(202).header("Job-Status", remote)
        })
        .await;
        let res = patch(&s, trace, 0).await;
        assert_eq!(
            res,
            PatchTraceResult {
                sent_offset: sent,
                cancel_requested: cancel,
                state: PatchState::Succeeded,
                new_update_interval: 0
            }
        );
        assert_eq!(s.requests().len(), usize::from(!trace.is_empty()));
    }
}

// TestPatchTraceUrlParams
#[tokio::test]
async fn patch_trace_url_params() {
    let s = patch_server(|_, _, _, _| Reply::status(202)).await;
    let c = client(&s.url, "runner", 1);
    for debug in [false, true] {
        let res = c
            .patch_trace(&job(1, PATCH_TOKEN), PATCH_CONTENT, 0, debug)
            .await;
        assert_eq!(res.state, PatchState::Succeeded);
    }
    let queries: Vec<String> = s.requests().iter().map(|r| r.query.clone()).collect();
    assert_eq!(queries, ["debug_trace=false", "debug_trace=true"]);
}

// TestUpdateIntervalHeaderHandling
#[tokio::test]
async fn update_interval_header_handling() {
    for (header, want) in [
        (Some("-10"), -10),
        (Some("0"), 0),
        (Some("10"), 10),
        (Some("some text"), 0),
        (Some(""), 0),
        (None, 0),
    ] {
        let s = FakeGitLab::start(move |r: &Recorded| {
            let reply = if r.path.ends_with("/trace") {
                Reply::status(202)
            } else {
                Reply::status(404)
            };
            match header {
                Some(v) => reply.header("X-GitLab-Trace-Update-Interval", v),
                None => reply,
            }
        })
        .await;
        let c = client(&s.url, "runner", 1);
        let update = c
            .update_job(&job(10, ""), &UpdateJobInfo::new(10, JobState::Success))
            .await;
        assert_eq!(update.new_update_interval, want, "{header:?}");
        assert_eq!(update.state, UpdateState::Abort);
        let res = c
            .patch_trace(&job(1, PATCH_TOKEN), PATCH_CONTENT, 0, false)
            .await;
        assert_eq!(res.new_update_interval, want, "{header:?}");
    }
}

// TestAbortedPatchTrace
#[tokio::test]
async fn aborted_patch_trace() {
    for (status, want) in [
        (
            "canceling",
            PatchTraceResult {
                sent_offset: 17,
                cancel_requested: true,
                state: PatchState::Succeeded,
                new_update_interval: 0,
            },
        ),
        ("canceled", PatchTraceResult::new(0, PatchState::Abort, 0)),
        ("failed", PatchTraceResult::new(0, PatchState::Abort, 0)),
    ] {
        let s =
            patch_server(move |_, _, _, _| Reply::status(202).header("Job-Status", status)).await;
        assert_eq!(patch(&s, PATCH_CONTENT, 0).await, want, "{status}");
    }
}

// --- retries (network/retry_requester_test.go) -----------------------------------------

// TestRetryRequester_Do: "retry-able status code" and "retries exhausted", plus
// TestRetryRequester_Do_BodyCopiedBetweenRequests.
#[tokio::test]
async fn retries_resend_the_same_body() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&calls);
    let s = FakeGitLab::start(move |_: &Recorded| {
        if c2.fetch_add(1, Ordering::SeqCst) < 2 {
            Reply::status(500)
        } else {
            Reply::status(200)
        }
    })
    .await;
    let res = client(&s.url, "runner", 3)
        .update_job(&job(5, "t"), &UpdateJobInfo::new(5, JobState::Running))
        .await;
    assert_eq!(res.state, UpdateState::Succeeded);
    let reqs = s.requests();
    assert_eq!(reqs.len(), 3);
    assert!(
        reqs.iter()
            .all(|r| r.body == reqs[0].body && !r.body.is_empty())
    );
    assert!(
        reqs.iter()
            .all(|r| r.header("x-request-id") == reqs[0].header("x-request-id")),
        "one correlation ID per logical request"
    );

    // retries exhausted: the last retriable answer stands
    let s = FakeGitLab::start(|_: &Recorded| Reply::status(502)).await;
    let res = client(&s.url, "runner", 3)
        .update_job(&job(5, "t"), &UpdateJobInfo::new(5, JobState::Running))
        .await;
    assert_eq!(res.state, UpdateState::Failed);
    assert_eq!(s.requests().len(), 3);
}

// TestRetryRequester_Do: "non retry-able status code", "with invalid reset header" and
// "with retry header".
#[tokio::test]
async fn retry_waits() {
    let s = FakeGitLab::start(|_: &Recorded| Reply::status(400)).await;
    client(&s.url, "runner", 3)
        .update_job(&job(5, "t"), &UpdateJobInfo::new(5, JobState::Running))
        .await;
    assert_eq!(s.requests().len(), 1, "a 400 is not retried");

    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&calls);
    let s = FakeGitLab::start(move |_: &Recorded| {
        if c2.fetch_add(1, Ordering::SeqCst) == 0 {
            Reply::status(429)
                .header("RateLimit-ResetTime", "invalid")
                .header("Retry-After", "1")
        } else {
            Reply::status(200)
        }
    })
    .await;
    let started = Instant::now();
    let res = client(&s.url, "runner", 3)
        .update_job(&job(5, "t"), &UpdateJobInfo::new(5, JobState::Running))
        .await;
    assert_eq!(res.state, UpdateState::Succeeded);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_secs(1) && took < Duration::from_secs(3),
        "{took:?}"
    );

    // Not upstream: a requested wait is capped at the backoff ceiling.
    let calls = Arc::new(AtomicUsize::new(0));
    let c2 = Arc::clone(&calls);
    let s = FakeGitLab::start(move |_: &Recorded| {
        if c2.fetch_add(1, Ordering::SeqCst) == 0 {
            Reply::status(503).header("Retry-After", "3600")
        } else {
            Reply::status(200)
        }
    })
    .await;
    let retry = RetryPolicy {
        max_attempts: 3,
        backoff_max: Duration::from_millis(200),
        ..RetryPolicy::default()
    };
    let started = Instant::now();
    let res = client_with_retry(&s.url, "runner", retry)
        .update_job(&job(5, "t"), &UpdateJobInfo::new(5, JobState::Running))
        .await;
    assert_eq!(res.state, UpdateState::Succeeded);
    let took = started.elapsed();
    assert!(
        took >= Duration::from_millis(200) && took < Duration::from_secs(2),
        "{took:?}"
    );
}

// --- redirects ---------------------------------------------------------------------------

#[tokio::test]
async fn cross_origin_redirect_drops_the_job_token() {
    // Not upstream: Go forwards JOB-TOKEN to wherever GitLab redirects a request.
    let elsewhere = FakeGitLab::start(|r: &Recorded| {
        assert_eq!(
            r.header("job-token"),
            "",
            "job token leaked to another origin"
        );
        Reply::status(202)
    })
    .await;
    let target = format!("{}/elsewhere/trace", elsewhere.url);
    let gitlab =
        FakeGitLab::start(move |_: &Recorded| Reply::status(307).header("Location", &target)).await;
    let res = client(&gitlab.url, "runner", 1)
        .patch_trace(&job(10, "secret-job-token"), b"log", 0, false)
        .await;
    assert_eq!(res.state, PatchState::Succeeded);
    let reqs = elsewhere.requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "PATCH", "a 307 repeats the request");
    assert_eq!(&reqs[0].body[..], b"log");
    assert_eq!(gitlab.requests()[0].header("job-token"), "secret-job-token");
}

// --- TLS settings --------------------------------------------------------------------------

fn tls_fixture(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

fn build(
    ca: Option<&str>,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<vk_gitlab::api::GitLabClient, String> {
    let mut opts = support::options(
        "https://gitlab.example.com",
        "runner",
        RetryPolicy::default(),
    );
    opts.tls_ca_file = ca.map(tls_fixture);
    opts.tls_cert_file = cert.map(tls_fixture);
    opts.tls_key_file = key.map(tls_fixture);
    vk_gitlab::api::GitLabClient::new(opts).map_err(|e| e.to_string())
}

// Not upstream: the CA bundle and client certificate options.
#[test]
fn tls_settings() {
    build(Some("cert.pem"), None, None).expect("a CA bundle is trusted");
    build(None, Some("cert.pem"), Some("key.pem")).expect("a client certificate is loaded");
    build(Some("cert.pem"), Some("cert.pem"), Some("key.pem")).expect("both together");

    let err = build(Some("missing.pem"), None, None).unwrap_err();
    assert!(err.starts_with("reading tls-ca-file "), "{err}");
    let err = build(None, Some("cert.pem"), Some("missing.pem")).unwrap_err();
    assert!(err.starts_with("reading tls-key-file "), "{err}");
    let err = build(None, Some("cert.pem"), Some("cert.pem")).unwrap_err();
    assert!(
        err.starts_with("loading the TLS client certificate"),
        "a certificate without its key: {err}"
    );
    for (cert, key) in [(Some("cert.pem"), None), (None, Some("key.pem"))] {
        let err = build(None, cert, key).unwrap_err();
        assert_eq!(err, "tls-cert-file and tls-key-file go together");
    }
}
