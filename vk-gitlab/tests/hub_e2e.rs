//! The daemon against the fake hub's HTTP API, for what only the wire shows: retries on the
//! hub's 503s, and a restarted daemon resuming its jobs from the state file.
//!
//! vk-hub has no library target, so its handlers cannot run in process here; the fake hub
//! follows `vk-hub/src/client.rs`, idempotent submissions included.

mod support;

use std::path::Path;
use std::time::Duration;

use support::fakehub::TEST_API_KEY;
use support::gl::{Harness, TOKEN, Via, eventually, job_json, runner_toml, within};
use vk_gitlab::dispatch::{CancelMode, Dispatcher, FakeCall, Placement, Submission};
use vk_gitlab::spec::{self, SpecContext};
use vk_gitlab::state::{JobRecord, Phase, StateFile, key_fingerprint};
use vk_hub_proto::client::ErrorCode;
use vk_hub_proto::job::JobSpec;

fn p1() -> Placement {
    Placement {
        pool: "p1".to_owned(),
        ..Default::default()
    }
}

fn spec_for(h: &Harness, id: i64) -> JobSpec {
    let job: vk_gitlab::job::Job = serde_json::from_value(job_json(id)).unwrap();
    let translated = spec::translate(
        &job,
        &SpecContext {
            server_url: h.fake.url.clone(),
            output_limit: 4 << 20,
            ..Default::default()
        },
    );
    JobSpec::GitlabCi(translated.job)
}

/// A request ID of its own for each job.
fn request_id(id: i64) -> String {
    format!("{id:032x}")
}

fn record(h: &Harness, id: i64, phase: Phase, hub_job: Option<String>) -> JobRecord {
    JobRecord {
        gitlab_job: id,
        job_token: format!("jt-{id}"),
        request_id: request_id(id),
        reservation: None,
        place_within_secs: 1,
        hub_job,
        phase,
        trace_offset: 0,
        failure_reasons: vec![],
        debug_trace: false,
        placement: p1(),
        spec: (phase == Phase::Taken).then(|| spec_for(h, id)),
    }
}

/// Submits GitLab job `id` to the hub as an earlier daemon did; returns its hub ID.
async fn submitted(h: &Harness, id: i64, reservation: Option<String>) -> String {
    h.hub
        .submit(Submission {
            request_id: request_id(id),
            placement: p1(),
            reservation,
            place_within: Duration::from_secs(1),
            gitlab_job: id,
            spec: spec_for(h, id),
        })
        .await
        .unwrap()
        .id
}

fn put(h: &Harness, runner: &str, records: Vec<JobRecord>) {
    let state = StateFile::open(&h.state_dir.join(format!("{runner}.json"))).unwrap();
    for r in records {
        state.put(r).unwrap();
    }
}

fn records(path: &Path) -> Vec<JobRecord> {
    StateFile::read(path).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hub_503s_are_retried_after_retry_after() {
    let h = Harness::start(2, Via::Http).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.fail_next(2, "/v1/reservations", 503, ErrorCode::Unavailable, Some(1));
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(30));
    let started = std::time::Instant::now();
    let (hub_id, _) = h.accepted_job(1).await;
    assert!(
        started.elapsed() >= Duration::from_secs(2),
        "retry_after_secs honoured"
    );
    assert!(fake_hub.requests_to("/v1/reservations") >= 3);
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(30).await["state"], "success");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_daemon_resumes_a_running_job() {
    let mut h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(31));
    let (hub_id, _) = h.accepted_job(1).await;
    let first = "first half\n";
    h.hub.push_output(&hub_id, first.as_bytes());
    eventually("the first half in GitLab", || h.gl.log(31) == first).await;
    // Wait for the acknowledged offset to reach the state file.
    let state = h.state_dir.join("r1.json");
    eventually("the trace offset recorded", || {
        records(&state)
            .iter()
            .any(|r| r.gitlab_job == 31 && r.trace_offset == first.len() as u64)
    })
    .await;

    h.daemon.kill();
    let patches_before = h.fake.requests_to("/api/v4/jobs/31/trace").len();
    let second = "second half\n";
    h.hub.push_output(&hub_id, second.as_bytes());
    h.daemon = h.spawn_daemon();
    h.hub.finish(&hub_id, None, None);
    let fin = h.final_update(31).await;
    assert_eq!(fin["state"], "success");
    assert_eq!(h.gl.log(31), format!("{first}{second}"));
    // The resumed trace continued from GitLab's offset, not from 0.
    let after: Vec<String> = h.fake.requests_to("/api/v4/jobs/31/trace")[patches_before..]
        .iter()
        .map(|r| r.header("content-range").to_owned())
        .collect();
    assert_eq!(
        after.first().map(String::as_str),
        Some("11-22"),
        "{after:?}"
    );
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    eventually("the job dropped from the state file", || {
        records(&state).is_empty()
    })
    .await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_taken_but_not_submitted_is_submitted_with_the_same_request_id() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    let reservation = "ab".repeat(16);
    let mut rec = record(&h, 32, Phase::Taken, None);
    rec.reservation = Some(reservation.clone());
    put(&h, "r1", vec![rec]);
    h.daemon = h.spawn_daemon();
    let (hub_id, sub) = within("the resubmission", h.hub.wait_for_job(1)).await;
    assert_eq!(sub.request_id, request_id(32));
    // The body of the first submission, which the hub compares.
    assert_eq!(sub.reservation, Some(reservation));
    assert_eq!(sub.place_within, Duration::from_secs(1));
    h.hub.accept(&hub_id);
    eventually("the commit", || h.committed(32)).await;
    h.hub.push_output(&hub_id, b"done\n");
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(32).await["state"], "success");
    assert_eq!(h.gl.log(32), "done\n");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_taken_job_the_hub_already_has_is_attached_to() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    h.hub.set_slots("p1", 2);
    // Submitted on its reservation before the daemon died, unrecorded.
    let reservation = "cd".repeat(16);
    let hub_id = submitted(&h, 37, Some(reservation.clone())).await;
    let mut rec = record(&h, 37, Phase::Taken, None);
    rec.reservation = Some(reservation);
    put(&h, "r1", vec![rec]);
    h.daemon = h.spawn_daemon();
    within(
        "the resubmission",
        h.hub.wait_for_call(FakeCall::Submit {
            job: 37,
            reservation: Some("cd".repeat(16)),
        }),
    )
    .await;
    h.hub.accept(&hub_id);
    eventually("the commit", || h.committed(37)).await;
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(37).await["state"], "success");
    assert_eq!(
        h.count_calls(|c| matches!(c, FakeCall::Submit { job: 37, .. })),
        2
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lagging_trace_offset_is_corrected_by_gitlab() {
    let mut h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(38));
    let (hub_id, _) = h.accepted_job(1).await;
    let (first, more, last) = ("first half\n", "more\n", "second half\n");
    h.hub.push_output(&hub_id, first.as_bytes());
    h.hub.push_output(&hub_id, more.as_bytes());
    eventually("both parts in GitLab", || {
        h.gl.log(38) == format!("{first}{more}")
    })
    .await;
    h.daemon.kill();
    // The state file is behind GitLab, as after a crash between two offset writes.
    let state = StateFile::open(&h.state_dir.join("r1.json")).unwrap();
    state
        .update(38, |r| r.trace_offset = first.len() as u64)
        .unwrap();
    let patches_before = h.fake.requests_to("/api/v4/jobs/38/trace").len();
    h.hub.push_output(&hub_id, last.as_bytes());
    h.daemon = h.spawn_daemon();
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(38).await["state"], "success");
    assert_eq!(h.gl.log(38), format!("{first}{more}{last}"));
    let after: Vec<String> = h.fake.requests_to("/api/v4/jobs/38/trace")[patches_before..]
        .iter()
        .map(|r| r.header("content-range").to_owned())
        .collect();
    assert_eq!(
        after.first().map(String::as_str),
        Some("11-27"),
        "{after:?}"
    );
    // GitLab's 416 moved the offset to what it holds.
    assert_eq!(after.get(1).map(String::as_str), Some("16-27"), "{after:?}");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_committed_job_the_hub_lost_fails() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    put(
        &h,
        "r1",
        vec![record(&h, 39, Phase::Committed, Some("f".repeat(32)))],
    );
    h.daemon = h.spawn_daemon();
    let fin = h.final_update(39).await;
    assert_eq!(fin["state"], "failed");
    assert_eq!(fin["failure_reason"], "runner_system_failure");
    let state = h.state_dir.join("r1.json");
    eventually("the job dropped", || records(&state).is_empty()).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reported_jobs_are_settled_on_restart() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    h.hub.set_slots("p1", 2);
    let done = submitted(&h, 41, None).await;
    h.hub.accept(&done);
    h.hub.finish(&done, None, None);
    let running = submitted(&h, 42, None).await;
    h.hub.accept(&running);
    put(
        &h,
        "r1",
        vec![
            record(&h, 41, Phase::Reported, Some(done.clone())),
            record(&h, 42, Phase::Reported, Some(running.clone())),
        ],
    );
    h.daemon = h.spawn_daemon();
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(done))).await;
    // Not finished: canceled, then settled once the hub reports it over.
    within(
        "the cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(running.clone(), CancelMode::Immediate)),
    )
    .await;
    h.hub.finish(
        &running,
        Some(vk_gitlab::dispatch::FailureClass::Canceled),
        None,
    );
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(running))).await;
    let state = h.state_dir.join("r1.json");
    eventually("both jobs dropped", || records(&state).is_empty()).await;
    assert!(
        h.updates(41).is_empty() && h.updates(42).is_empty(),
        "GitLab has their outcome"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_runner_still_resumes_its_jobs() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    *h.gl.verify_refused.lock().unwrap() = true;
    h.hub.set_slots("p1", 2);
    let hub_id = submitted(&h, 43, None).await;
    h.hub.accept(&hub_id);
    put(
        &h,
        "r1",
        vec![record(&h, 43, Phase::Committed, Some(hub_id.clone()))],
    );
    h.gl.push_job(job_json(44));
    h.daemon = h.spawn_daemon();
    h.hub.push_output(&hub_id, b"ok\n");
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(43).await["state"], "success");
    assert_eq!(h.gl.log(43), "ok\n");
    assert_eq!(h.job_requests(), 0, "a refused runner requests nothing");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_runners_resumed_jobs_come_before_any_request() {
    const OTHER: &str = "glrt-other-token";
    let mut h = Harness::unstarted(1, Via::Http).await;
    h.runners =
        runner_toml("r1", TOKEN, &h.fake.url, "") + &runner_toml("r2", OTHER, &h.fake.url, "");
    h.hub.set_slots("p1", 5);
    let first = submitted(&h, 45, None).await;
    let second = submitted(&h, 46, None).await;
    h.hub.accept(&first);
    h.hub.accept(&second);
    // r1 has nothing to resume; r2's two jobs take more than the one slot.
    put(
        &h,
        "r2",
        vec![
            record(&h, 45, Phase::Committed, Some(first.clone())),
            record(&h, 46, Phase::Committed, Some(second.clone())),
        ],
    );
    h.gl.push_job(job_json(47));
    h.daemon = h.spawn_daemon();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(h.job_requests(), 0, "no request past concurrent");
    h.hub.finish(&first, None, None);
    h.final_update(45).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(h.job_requests(), 0, "one resumed job still runs");
    h.hub.finish(&second, None, None);
    h.final_update(46).await;
    let (third, sub) = h.accepted_job(3).await;
    assert_eq!(sub.gitlab_job, 47);
    h.hub.finish(&third, None, None);
    h.final_update(47).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn jobs_of_another_hub_key_refuse_the_start() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    put(
        &h,
        "r1",
        vec![record(&h, 48, Phase::Committed, Some("e".repeat(32)))],
    );
    let path = h.state_dir.join("r1.json");
    let state = StateFile::open(&path).unwrap();
    state.set_hub_key(key_fingerprint("vkk_another")).unwrap();
    h.daemon = h.spawn_daemon();
    let err = format!("{:#}", h.daemon.exit().await.unwrap_err());
    assert!(err.contains("another hub API key"), "{err}");
    assert_eq!(records(&path).len(), 1, "the jobs are kept");
    // Under the key they were submitted with, they resume.
    state.set_hub_key(key_fingerprint(TEST_API_KEY)).unwrap();
    h.daemon = h.spawn_daemon();
    h.final_update(48).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_submission_without_an_answer_is_canceled_on_restart() {
    let mut h = Harness::start(2, Via::Http).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    // Unanswered past place_within: the hub may or may not have the job.
    fake_hub.fail_next(1000, "/v1/jobs", 503, ErrorCode::Unavailable, None);
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(49));
    let fin = h.final_update(49).await;
    assert_eq!(fin["failure_reason"], "runner_system_failure");
    let state = h.state_dir.join("r1.json");
    eventually("the job kept as abandoned", || {
        records(&state)
            .iter()
            .any(|r| r.gitlab_job == 49 && r.phase == Phase::Abandoned)
    })
    .await;
    h.daemon.stop().await;
    h.http_hub.as_ref().unwrap().clear_faults();
    h.daemon = h.spawn_daemon();
    let (hub_id, _) = within("the submission again", h.hub.wait_for_job(1)).await;
    within(
        "the cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Immediate)),
    )
    .await;
    // Recorded before the cancel: a restart now would cancel and settle it, not drop it.
    assert!(records(&state).iter().any(|r| r.gitlab_job == 49
        && r.phase == Phase::Reported
        && r.hub_job.as_deref() == Some(hub_id.as_str())));
    h.hub.finish(
        &hub_id,
        Some(vk_gitlab::dispatch::FailureClass::Canceled),
        None,
    );
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    eventually("the job dropped", || records(&state).is_empty()).await;
    assert!(!h.committed(49));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_submission_is_retried_until_place_within() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    h.options.hub.place_within = Duration::from_secs(5);
    h.daemon = h.spawn_daemon();
    let fake_hub = h.http_hub.as_ref().unwrap();
    // More 503s than the other calls' five attempts, well within place_within.
    fake_hub.fail_next(6, "/v1/jobs", 503, ErrorCode::Unavailable, None);
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(33));
    let (hub_id, _) = h.accepted_job(1).await;
    assert!(fake_hub.requests_to("/v1/jobs") >= 7);
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(33).await["state"], "success");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resumed_jobs_hold_their_slots() {
    let mut h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("p1", 5);
    h.gl.push_job(job_json(34));
    h.gl.push_job(job_json(35));
    let (first, _) = h.accepted_job(1).await;
    let (second, _) = h.accepted_job(2).await;
    let state = h.state_dir.join("r1.json");
    eventually("both jobs committed in the state file", || {
        let recs = records(&state);
        [34, 35].iter().all(|&id| {
            recs.iter()
                .any(|r| r.gitlab_job == id && r.phase == Phase::Committed)
        })
    })
    .await;
    h.daemon.kill();
    // Restarted with one slot: the two resumed jobs take it, and request nothing more.
    h.concurrent = 1;
    h.gl.push_job(job_json(36));
    let requests = h.job_requests();
    h.daemon = h.spawn_daemon();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(h.job_requests(), requests, "no request past concurrent");
    h.hub.finish(&first, None, None);
    h.final_update(34).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(h.job_requests(), requests, "one resumed job still runs");
    h.hub.finish(&second, None, None);
    h.final_update(35).await;
    let (third, sub) = h.accepted_job(3).await;
    assert_eq!(sub.gitlab_job, 36);
    h.hub.finish(&third, None, None);
    h.final_update(36).await;
    h.stop().await;
}
