//! The daemon against the fake hub's HTTP API, for what only the wire shows: retries on the
//! hub's 503s, a restarted daemon resuming its jobs from the state file, and every request
//! sent on the connection of the enrolled relay's session.
//!
//! vk-hub has no library target, so its handlers cannot run in process here; the fake hub
//! follows `vk-hub/src/client.rs`, idempotent submissions included.

mod support;

use std::path::Path;
use std::time::Duration;

use std::sync::Arc;

use support::fakehub::TEST_RELAY_ID;
use support::gl::{Harness, TOKEN, Via, eventually, job_json, runner_toml, within};
use vk_gitlab::dispatch::{CancelMode, Dispatcher, FakeCall, Placement, QueueAnswer, Submission};
use vk_gitlab::hub::HubRetry;
use vk_gitlab::relay;
use vk_gitlab::spec::{self, SpecContext};
use vk_gitlab::state::{JobRecord, Phase, StateFile};
use vk_hub_proto::client::{AdmissionOutcome, CancelRequest, ErrorCode};
use vk_hub_proto::job::JobSpec;
use vk_peer::identity::Identity;

/// A relay's placement: no pool, its runner's lane on the hub placing its work.
fn placement() -> Placement {
    Placement::default()
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
        runner: Some("ci".into()),
        reservation: None,
        admission: None,
        place_within_secs: 1,
        hub_job,
        phase,
        trace_offset: 0,
        failure_reasons: vec![],
        debug_trace: false,
        timestamps: true,
        placement: placement(),
        spec: (phase == Phase::Taken).then(|| spec_for(h, id)),
    }
}

/// Submits GitLab job `id` to the hub as an earlier daemon did; returns its hub ID.
async fn submitted(h: &Harness, id: i64, reservation: Option<String>) -> String {
    h.hub
        .submit(Submission {
            request_id: request_id(id),
            runner: Some("ci".into()),
            admission: None,
            placement: placement(),
            reservation,
            place_within: Duration::from_secs(1),
            gitlab_job: id,
            spec: spec_for(h, id),
        })
        .await
        .unwrap()
        .id
}

/// Records jobs as an earlier daemon, this relay, did.
fn put(h: &Harness, runner: &str, records: Vec<JobRecord>) {
    let state = StateFile::open(&h.state_dir.join(format!("{runner}.json"))).unwrap();
    state.set_relay(TEST_RELAY_ID).unwrap();
    for r in records {
        state.put(r).unwrap();
    }
}

fn records(path: &Path) -> Vec<JobRecord> {
    StateFile::read(path).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_ticket_releases_a_grant_whose_response_was_lost() {
    let h = Harness::unstarted(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    let (client, session) = support::gl::client(&h, HubRetry::default());
    let QueueAnswer::Ticket(ticket) = client
        .queue(
            "r1",
            &request_id(99),
            &placement(),
            Duration::from_secs(10),
            Duration::ZERO,
        )
        .await
        .unwrap()
    else {
        panic!("expected a ticket");
    };
    // Fetched at once, then once the hub tells of the grant.
    let grant = within("the grant", async {
        loop {
            match client.poll_ticket(&ticket, Duration::from_secs(50)).await {
                Ok(QueueAnswer::Grant(grant)) => return grant,
                Ok(QueueAnswer::Ticket(_)) => {}
                Err(e) => panic!("{e}"),
            }
        }
    })
    .await;
    let QueueAnswer::Grant(repeated) = client.poll_ticket(&ticket, Duration::ZERO).await.unwrap()
    else {
        panic!("expected the same grant");
    };
    assert_eq!(repeated.id, grant.id);
    assert_eq!(h.hub.reservations().len(), 1);
    client.cancel_ticket(&ticket).await.unwrap();
    assert!(h.hub.reservations().is_empty());
    session.abort();
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prepared_state_reports_held_admissions_before_the_session() {
    let h = Harness::unstarted(1, Via::Http).await;
    let mut job = record(&h, 1, Phase::Taken, None);
    job.admission = Some("a".repeat(32));
    put(&h, "r1", vec![job]);
    let cfg = h.config();
    let status = vk_gitlab::session::Status::new(&cfg, "s_test", "test");
    assert!(vk_gitlab::poll::prepare_state(&cfg, "another-relay", Arc::clone(&status)).is_err());
    let _prepared =
        vk_gitlab::poll::prepare_state(&cfg, TEST_RELAY_ID, Arc::clone(&status)).unwrap();
    let heartbeat = status.heartbeat();
    assert_eq!(heartbeat.runners[0].jobs, 1);
    assert_eq!(heartbeat.runners[0].job_admissions, vec!["a".repeat(32)]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_runner_holds_no_slot_and_grant_is_claimed_and_reported() {
    const OTHER: &str = "glrt-other-token";
    let mut h = Harness::unstarted(1, Via::Http).await;
    h.runners = runner_toml("r1", TOKEN, "") + &runner_toml("r2", OTHER, "");
    h.gl.push_job_for(OTHER, job_json(301));
    h.daemon = h.spawn_daemon();
    let fake_hub = h.http_hub.as_ref().unwrap();
    eventually("both runners queue at zero capacity", || {
        let requests = fake_hub.requests.lock().unwrap();
        ["r1", "r2"].iter().all(|name| {
            requests.iter().any(|r| {
                r.method == "POST"
                    && r.path == "/v1/reservations"
                    && serde_json::from_slice::<serde_json::Value>(&r.body)
                        .ok()
                        .is_some_and(|v| v["runner"] == *name && v["queue"] == true)
            })
        })
    })
    .await;
    assert_eq!(h.job_requests(), 0);
    h.hub.set_slots("r2", 1);
    let (job, _) = h.accepted_job(1).await;
    eventually("grant claim and job outcome", || {
        let requests = fake_hub.requests.lock().unwrap();
        requests.iter().any(|r| r.path.ends_with("/claim"))
            && requests.iter().any(|r| {
                r.path.ends_with("/outcome")
                    && serde_json::from_slice::<serde_json::Value>(&r.body)
                        .ok()
                        .is_some_and(|v| v["outcome"] == "job" && v["admission"].is_string())
            })
    })
    .await;
    h.hub.finish(&job, None, None);
    h.final_update(301).await;
    h.daemon.stop().await;
    let requests = fake_hub.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|r| r.method == "DELETE" && r.path.contains("/tickets/"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_recovers_and_cancels_a_ticket_when_queue_answer_is_lost() {
    let mut h = Harness::unstarted(1, Via::Http).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.delay_next_queue_response(Duration::from_secs(5));
    h.daemon = h.spawn_daemon();
    let request_id = || {
        let requests = fake_hub.requests.lock().unwrap();
        requests
            .iter()
            .find(|r| r.method == "POST" && r.path == "/v1/reservations")
            .map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).unwrap())
            .and_then(|v| v["request_id"].as_str().map(str::to_owned))
    };
    // The hub has queued the request; its answer is still on the way.
    eventually("the request queued", || {
        request_id().is_some_and(|id| fake_hub.ticket_for(&id).is_some())
    })
    .await;
    h.daemon.stop().await;
    let ticket = fake_hub.ticket_for(&request_id().unwrap()).unwrap();
    assert_ne!(
        Some(&ticket),
        request_id().as_ref(),
        "the hub's own ticket ID"
    );
    let requests = fake_hub.requests.lock().unwrap();
    let posts: Vec<_> = requests
        .iter()
        .filter(|r| r.method == "POST" && r.path == "/v1/reservations")
        .map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).unwrap())
        .collect();
    assert_eq!(posts.len(), 2, "shutdown retries the unanswered request");
    assert_eq!(posts[0]["request_id"], posts[1]["request_id"]);
    assert!(
        requests
            .iter()
            .any(|r| r.method == "DELETE" && r.path == format!("/v1/reservations/tickets/{ticket}"))
    );
    assert_eq!(h.job_requests(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_gitlab_answer_reports_empty_and_releases_grant() {
    let h = Harness::start(1, Via::Http).await;
    h.hub.set_slots("r1", 1);
    let fake_hub = h.http_hub.as_ref().unwrap();
    eventually("empty outcome", || {
        fake_hub.requests.lock().unwrap().iter().any(|r| {
            r.path.ends_with("/outcome")
                && serde_json::from_slice::<serde_json::Value>(&r.body)
                    .ok()
                    .is_some_and(|v| v["outcome"] == "empty")
        })
    })
    .await;
    eventually("reservation released", || h.hub.reservations().is_empty()).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hub_503s_are_retried_after_retry_after() {
    let h = Harness::start(2, Via::Http).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.fail_next(2, "/v1/reservations", 503, ErrorCode::Unavailable, Some(1));
    h.hub.set_slots("r1", 1);
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
async fn a_queue_request_with_no_answer_is_sent_again_under_its_id() {
    let mut h = Harness::unstarted(1, Via::Http).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    // A refusal, then a request whose every attempt (quick_retry's 5) loses its stream.
    let queue = "/v1/reservations";
    fake_hub.fail_next_ending(1, queue, queue, 403, ErrorCode::Forbidden, None);
    fake_hub.fail_next_ending(5, queue, queue, 0, ErrorCode::Unavailable, None);
    h.daemon = h.spawn_daemon();
    let posts = || -> Vec<String> {
        let requests = fake_hub.requests.lock().unwrap();
        requests
            .iter()
            .filter(|r| r.method == "POST" && r.path == queue)
            .map(|r| serde_json::from_slice::<serde_json::Value>(&r.body).unwrap())
            .map(|v| v["request_id"].as_str().unwrap().to_owned())
            .collect()
    };
    eventually("the request queued", || {
        posts()
            .get(6)
            .is_some_and(|id| fake_hub.ticket_for(id).is_some())
    })
    .await;
    let ids = posts();
    assert_ne!(ids[0], ids[1], "a refused request is not sent again");
    assert!(
        ids[1..7].iter().all(|id| *id == ids[1]),
        "an unanswered request keeps its ID: {ids:?}"
    );
    h.daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_daemon_resumes_a_running_job() {
    let mut h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
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
    h.hub.set_slots("r1", 2);
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
async fn a_legacy_submission_is_replayed_without_a_runner_name() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    let hub_id = h
        .hub
        .submit(Submission {
            request_id: request_id(47),
            runner: None,
            admission: None,
            placement: placement(),
            reservation: None,
            place_within: Duration::from_secs(1),
            gitlab_job: 47,
            spec: spec_for(&h, 47),
        })
        .await
        .unwrap()
        .id;
    let mut rec = record(&h, 47, Phase::Taken, None);
    rec.runner = None;
    put(&h, "r1", vec![rec]);
    h.daemon = h.spawn_daemon();
    within(
        "the resubmission",
        h.hub.wait_for_call(FakeCall::Submit {
            job: 47,
            reservation: None,
        }),
    )
    .await;
    h.hub.accept(&hub_id);
    eventually("the commit", || h.committed(47)).await;
    {
        let requests = h.http_hub.as_ref().unwrap().requests.lock().unwrap();
        let replay = requests
            .iter()
            .find(|r| r.method == "POST" && r.path == "/v1/jobs")
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&replay.body).unwrap();
        assert!(body.get("runner").is_none());
    }
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(47).await["state"], "success");
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lagging_trace_offset_is_corrected_by_gitlab() {
    let mut h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
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
    h.hub.set_slots("r1", 2);
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
    h.hub.set_slots("r1", 2);
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
    h.runners = runner_toml("r1", TOKEN, "") + &runner_toml("r2", OTHER, "");
    h.hub.set_slots("r1", 5);
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
async fn jobs_of_another_relay_refuse_the_start() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    put(
        &h,
        "r1",
        vec![record(&h, 48, Phase::Committed, Some("e".repeat(32)))],
    );
    let path = h.state_dir.join("r1.json");
    let state = StateFile::open(&path).unwrap();
    state.set_relay(&"a".repeat(32)).unwrap();
    h.daemon = h.spawn_daemon();
    let err = format!("{:#}", h.daemon.exit().await.unwrap_err());
    assert!(err.contains("submitted as another relay"), "{err}");
    assert_eq!(records(&path).len(), 1, "the jobs are kept");
    // As the relay they were submitted as, they resume.
    state.set_relay(TEST_RELAY_ID).unwrap();
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
    h.hub.set_slots("r1", 1);
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
    h.hub.set_slots("r1", 1);
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
    h.hub.set_slots("r1", 5);
    h.gl.push_job(job_json(34));
    h.gl.push_job(job_json(35));
    // Taken one after the other, but submitted by tasks of their own, in either order.
    let (first, a) = h.accepted_job(1).await;
    let (second, b) = h.accepted_job(2).await;
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
    h.final_update(a.gitlab_job).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(h.job_requests(), requests, "one resumed job still runs");
    h.hub.finish(&second, None, None);
    h.final_update(b.gitlab_job).await;
    let (third, sub) = h.accepted_job(3).await;
    assert_eq!(sub.gitlab_job, 36);
    h.hub.finish(&third, None, None);
    h.final_update(36).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hub_requests_ride_the_sessions_connection_unsigned() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    // A retried request too.
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.fail_next(1, "/v1/jobs", 503, ErrorCode::Unavailable, None);
    h.daemon = h.spawn_daemon();
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(50));
    let (hub_id, _) = h.accepted_job(1).await;
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(50).await["state"], "success");
    let fake_hub = h.http_hub.as_ref().unwrap();
    let requests = fake_hub.requests.lock().unwrap().clone();
    let submissions = requests
        .iter()
        .filter(|r| r.method == "POST" && r.path == "/v1/jobs")
        .count();
    assert!(submissions >= 2, "the 503'd submission retried");
    // One connection, its session never lost: the fake refuses a request off it.
    assert_eq!((fake_hub.connections(), fake_hub.sessions()), (2, 1));
    for r in requests.iter().filter(|r| r.path != "/v1/gitlab/enroll") {
        for header in ["vk-relay", "vk-signature", "vk-time", "authorization"] {
            assert!(
                !r.headers.contains_key(header),
                "{} {} {header}",
                r.method,
                r.path
            );
        }
        assert!(
            !r.query.contains("wait"),
            "{} {}?{}",
            r.method,
            r.path,
            r.query
        );
    }
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_the_hub_did_not_enroll_is_refused() {
    let h = Harness::unstarted(2, Via::Http).await;
    // The relay's key, replaced by one the hub never saw.
    let dir = relay::dir(&h.state_dir);
    std::fs::remove_file(dir.join("key.pk8")).unwrap();
    Identity::load_or_create(&dir).unwrap();
    let (_client, session) = support::gl::client(&h, HubRetry::default());
    within("the session to give up", session).await.unwrap();
    let fake_hub = h.http_hub.as_ref().unwrap();
    assert_eq!(fake_hub.sessions(), 0);
    assert_eq!(
        fake_hub.requests_to("/v1/jobs") + fake_hub.requests_to("/v1/reservations"),
        0
    );
    h.stop().await;
}

/// The admission of the first queued request, once it was queued.
fn first_admission(h: &Harness) -> Option<String> {
    h.http_hub.as_ref().unwrap().first_ticket()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outcome_the_hub_did_not_take_is_reported_again() {
    let mut h = Harness::unstarted(1, Via::Http).await;
    // More 503s than the client's five attempts at a call.
    h.http_hub.as_ref().unwrap().fail_next_ending(
        8,
        "/v1/reservations/",
        "/outcome",
        503,
        ErrorCode::Unavailable,
        None,
    );
    h.daemon = h.spawn_daemon();
    h.hub.set_slots("r1", 1);
    let fake_hub = h.http_hub.as_ref().unwrap();
    eventually("the first admission's outcome taken", || {
        first_admission(&h)
            .is_some_and(|a| fake_hub.outcome_of(&a) == Some(AdmissionOutcome::Empty))
    })
    .await;
    assert!(fake_hub.requests_to("/v1/reservations/") > 8);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outcome_the_hub_refuses_as_conflicting_is_dropped() {
    let mut h = Harness::unstarted(1, Via::Http).await;
    h.http_hub.as_ref().unwrap().fail_next_ending(
        1,
        "/v1/reservations/",
        "/outcome",
        409,
        ErrorCode::Conflict,
        None,
    );
    h.daemon = h.spawn_daemon();
    h.hub.set_slots("r1", 1);
    let fake_hub = h.http_hub.as_ref().unwrap();
    // Later admissions' outcomes are taken, and the refused one is not reported again.
    eventually("later admissions' outcomes taken", || {
        fake_hub.outcomes_reported() >= 2
    })
    .await;
    let first = first_admission(&h).unwrap();
    assert_eq!(fake_hub.outcome_of(&first), None);
    let path = format!("/v1/reservations/{first}/outcome");
    assert_eq!(fake_hub.requests_to(&path), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_grant_whose_claim_failed_is_given_back() {
    let mut h = Harness::unstarted(1, Via::Http).await;
    h.http_hub.as_ref().unwrap().fail_next_ending(
        1,
        "/v1/reservations/",
        "/claim",
        409,
        ErrorCode::Conflict,
        None,
    );
    h.daemon = h.spawn_daemon();
    h.hub.set_slots("r1", 1);
    let fake_hub = h.http_hub.as_ref().unwrap();
    eventually("the unclaimed grant returned", || {
        first_admission(&h)
            .is_some_and(|a| fake_hub.outcome_of(&a) == Some(AdmissionOutcome::Released))
    })
    .await;
    eventually("its reservation released", || {
        h.count_calls(|c| matches!(c, FakeCall::Release(_))) >= 1
    })
    .await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_the_hub_refuses_leaves_its_admission_empty() {
    let mut h = Harness::unstarted(1, Via::Http).await;
    h.daemon = h.spawn_daemon();
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.fail_next(1, "/v1/jobs", 403, ErrorCode::Forbidden, None);
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(40));
    assert_eq!(h.final_update(40).await["state"], "failed");
    let admission = first_admission(&h).unwrap();
    // Taken under its admission, then dropped before the hub had it: no job came of it.
    eventually("the admission reported empty", || {
        fake_hub.outcome_of(&admission) == Some(AdmissionOutcome::Empty)
    })
    .await;
    let state = h.state_dir.join("r1.json");
    eventually("the record dropped", || records(&state).is_empty()).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restarted_relay_submits_under_the_admission_it_held() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    let admission = "ad".repeat(16);
    // Claimed before the relay died, its job taken but not submitted.
    h.http_hub.as_ref().unwrap().hold_admission(&admission);
    let mut rec = record(&h, 41, Phase::Taken, None);
    rec.runner = Some("r1".into());
    rec.admission = Some(admission.clone());
    put(&h, "r1", vec![rec]);
    h.daemon = h.spawn_daemon();
    let status = h.daemon.status.clone().unwrap();
    let (hub_id, sub) = within("the resubmission", h.hub.wait_for_job(1)).await;
    assert_eq!(sub.admission.as_deref(), Some(admission.as_str()));
    let held = |status: &vk_gitlab::session::Status| {
        status.heartbeat().runners[0]
            .job_admissions
            .contains(&admission)
    };
    assert!(held(&status), "the heartbeat lists the held admission");
    h.hub.accept(&hub_id);
    eventually("the commit", || h.committed(41)).await;
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(41).await["state"], "success");
    eventually("the admission no longer held once settled", || {
        !held(&status)
    })
    .await;
    h.stop().await;
}

/// Requests to the hub for job `hub_id` whose path ends with `what`.
fn job_requests(h: &Harness, hub_id: &str, what: &str) -> usize {
    let path = format!("/v1/jobs/{hub_id}/{what}");
    h.http_hub.as_ref().unwrap().requests_to(&path)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settle_the_hub_did_not_take_is_retried() {
    let h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(60));
    let (hub_id, _) = h.accepted_job(1).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    // More failures than the client's five attempts at a call: refused, then cut off.
    fake_hub.fail_next_ending(4, "/v1/jobs/", "/settle", 503, ErrorCode::Unavailable, None);
    fake_hub.fail_next_ending(4, "/v1/jobs/", "/settle", 0, ErrorCode::Unavailable, None);
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(60).await["state"], "success");
    within(
        "the settle",
        h.hub.wait_for_call(FakeCall::Settle(hub_id.clone())),
    )
    .await;
    assert_eq!(job_requests(&h, &hub_id, "settle"), 9);
    let state = h.state_dir.join("r1.json");
    eventually("the job dropped", || records(&state).is_empty()).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settle_of_a_job_the_hub_does_not_have_is_not_retried() {
    let h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(61));
    let (hub_id, _) = h.accepted_job(1).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.fail_next_ending(1, "/v1/jobs/", "/settle", 404, ErrorCode::NotFound, None);
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(61).await["state"], "success");
    let state = h.state_dir.join("r1.json");
    eventually("the job dropped", || records(&state).is_empty()).await;
    assert_eq!(job_requests(&h, &hub_id, "settle"), 1);
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_settle_is_not_retried() {
    let h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(58));
    let (hub_id, _) = h.accepted_job(1).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.fail_next_ending(1, "/v1/jobs/", "/settle", 400, ErrorCode::Invalid, None);
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(58).await["state"], "success");
    eventually("the settle", || job_requests(&h, &hub_id, "settle") == 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(job_requests(&h, &hub_id, "settle"), 1);
    let state = h.state_dir.join("r1.json");
    assert!(
        records(&state)
            .iter()
            .any(|r| r.gitlab_job == 58 && r.phase == Phase::Reported),
        "kept for the next start"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_settle_of_a_job_still_running_is_sent_again_until_it_ends() {
    let h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(59));
    let (hub_id, _) = h.accepted_job(1).await;
    // GitLab ends the job; its node does not stop it within the settle wait.
    h.gl.set_status(59, "canceled");
    h.hub.push_output(&hub_id, b"x\n");
    within(
        "an immediate cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Immediate)),
    )
    .await;
    eventually("the settle refused twice", || {
        job_requests(&h, &hub_id, "settle") >= 2
    })
    .await;
    let state = h.state_dir.join("r1.json");
    assert!(
        records(&state)
            .iter()
            .any(|r| r.gitlab_job == 59 && r.phase == Phase::Reported)
    );
    h.hub.finish(
        &hub_id,
        Some(vk_gitlab::dispatch::FailureClass::Canceled),
        None,
    );
    eventually("the job dropped", || records(&state).is_empty()).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stopping_relay_leaves_an_unsettled_job_to_its_next_start() {
    let mut h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(62));
    let (hub_id, _) = h.accepted_job(1).await;
    h.http_hub.as_ref().unwrap().fail_next_ending(
        1000,
        "/v1/jobs/",
        "/settle",
        503,
        ErrorCode::Unavailable,
        None,
    );
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(62).await["state"], "success");
    // Past one call's five attempts: retried while the relay runs.
    eventually("the settle retried", || {
        job_requests(&h, &hub_id, "settle") > 5
    })
    .await;
    let state = h.state_dir.join("r1.json");
    let reported = |state: &Path| {
        records(state)
            .iter()
            .any(|r| r.gitlab_job == 62 && r.phase == Phase::Reported)
    };
    assert!(reported(&state));
    h.daemon.stop().await;
    assert!(reported(&state), "kept for the next start");
    h.http_hub.as_ref().unwrap().clear_faults();
    h.daemon = h.spawn_daemon();
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    eventually("the job dropped", || records(&state).is_empty()).await;
    h.stop().await;
}

/// Cancels of job `hub_id` the hub received asking for `mode`.
fn cancels_asking(h: &Harness, hub_id: &str, mode: CancelMode) -> usize {
    let path = format!("/v1/jobs/{hub_id}/cancel");
    h.http_hub
        .as_ref()
        .unwrap()
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| {
            r.path == path
                && serde_json::from_slice::<CancelRequest>(&r.body).is_ok_and(|c| c.mode == mode)
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_graceful_cancel_the_hub_did_not_take_is_sent_again() {
    let h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(63));
    let (hub_id, _) = h.accepted_job(1).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.fail_next_ending(
        1000,
        "/v1/jobs/",
        "/cancel",
        503,
        ErrorCode::Unavailable,
        None,
    );
    h.gl.set_status(63, "canceling");
    eventually("a cancel refused", || {
        job_requests(&h, &hub_id, "cancel") >= 1
    })
    .await;
    // The job's output reaches GitLab while the cancel is retried.
    h.hub.push_output(&hub_id, b"still running\n");
    eventually("the output in the trace", || {
        h.gl.log(63) == "still running\n"
    })
    .await;
    let refused = job_requests(&h, &hub_id, "cancel");
    // Past the hub client's own five attempts: the cancel itself is sent again.
    eventually("the cancel retried", || {
        job_requests(&h, &hub_id, "cancel") > refused.max(5)
    })
    .await;
    fake_hub.clear_faults();
    within(
        "the graceful cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Graceful)),
    )
    .await;
    // Taken: not sent again, though GitLab still asks.
    let sent = job_requests(&h, &hub_id, "cancel");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(job_requests(&h, &hub_id, "cancel"), sent);
    h.gl.clear_status(63);
    h.hub.finish(
        &hub_id,
        Some(vk_gitlab::dispatch::FailureClass::Canceled),
        None,
    );
    assert_eq!(h.final_update(63).await["state"], "failed");
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_immediate_cancel_replaces_a_graceful_one_not_taken() {
    let h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(64));
    let (hub_id, _) = h.accepted_job(1).await;
    let fake_hub = h.http_hub.as_ref().unwrap();
    fake_hub.fail_next_ending(
        1000,
        "/v1/jobs/",
        "/cancel",
        0,
        ErrorCode::Unavailable,
        None,
    );
    h.gl.set_status(64, "canceling");
    eventually("a graceful cancel cut off", || {
        cancels_asking(&h, &hub_id, CancelMode::Graceful) >= 1
    })
    .await;
    // GitLab then ends the job.
    h.gl.set_status(64, "canceled");
    h.hub.push_output(&hub_id, b"x\n");
    eventually("an immediate cancel cut off", || {
        cancels_asking(&h, &hub_id, CancelMode::Immediate) >= 1
    })
    .await;
    fake_hub.clear_faults();
    within(
        "the immediate cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Immediate)),
    )
    .await;
    h.hub.finish(
        &hub_id,
        Some(vk_gitlab::dispatch::FailureClass::Canceled),
        None,
    );
    within(
        "the settle",
        h.hub.wait_for_call(FakeCall::Settle(hub_id.clone())),
    )
    .await;
    assert!(
        !h.hub
            .calls()
            .contains(&FakeCall::Cancel(hub_id, CancelMode::Graceful)),
        "the graceful cancel was replaced, not sent after"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_job_not_placed_in_time_is_canceled_until_the_hub_takes_it() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    // Room for the cut cancels before the job's settle wait ends.
    h.options.hub.settle_wait = Duration::from_secs(10);
    h.daemon = h.spawn_daemon();
    h.hub.set_slots("r1", 1);
    h.http_hub.as_ref().unwrap().fail_next_ending(
        8,
        "/v1/jobs/",
        "/cancel",
        0,
        ErrorCode::Unavailable,
        None,
    );
    h.gl.push_job(job_json(65));
    // Never accepted: past place_within, failed in GitLab and canceled on the hub.
    let (hub_id, _) = within("a submitted job", h.hub.wait_for_job(1)).await;
    let fin = h.final_update(65).await;
    assert_eq!(fin["failure_reason"], "runner_system_failure");
    assert!(h.gl.log(65).contains("did not report it placed in time"));
    assert!(!h.committed(65));
    within(
        "the immediate cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Immediate)),
    )
    .await;
    assert_eq!(cancels_asking(&h, &hub_id, CancelMode::Immediate), 9);
    h.hub.finish(
        &hub_id,
        Some(vk_gitlab::dispatch::FailureClass::Canceled),
        None,
    );
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    let state = h.state_dir.join("r1.json");
    eventually("the job dropped", || records(&state).is_empty()).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_immediate_cancel_the_hub_did_not_take_is_sent_again() {
    let mut h = Harness::unstarted(2, Via::Http).await;
    // Room for the cut cancels before the job's settle wait ends.
    h.options.hub.settle_wait = Duration::from_secs(10);
    h.daemon = h.spawn_daemon();
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(66));
    let (hub_id, _) = h.accepted_job(1).await;
    h.http_hub.as_ref().unwrap().fail_next_ending(
        8,
        "/v1/jobs/",
        "/cancel",
        0,
        ErrorCode::Unavailable,
        None,
    );
    // GitLab ends the job.
    h.gl.set_status(66, "canceled");
    h.hub.push_output(&hub_id, b"x\n");
    within(
        "the immediate cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Immediate)),
    )
    .await;
    assert_eq!(cancels_asking(&h, &hub_id, CancelMode::Immediate), 9);
    h.hub.finish(
        &hub_id,
        Some(vk_gitlab::dispatch::FailureClass::Canceled),
        None,
    );
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    let state = h.state_dir.join("r1.json");
    eventually("the job dropped", || records(&state).is_empty()).await;
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_of_a_job_the_hub_does_not_have_is_not_retried() {
    let h = Harness::start(2, Via::Http).await;
    h.hub.set_slots("r1", 1);
    h.gl.push_job(job_json(67));
    let (hub_id, _) = h.accepted_job(1).await;
    h.http_hub.as_ref().unwrap().fail_next_ending(
        1,
        "/v1/jobs/",
        "/cancel",
        404,
        ErrorCode::NotFound,
        None,
    );
    h.gl.set_status(67, "canceling");
    eventually("the cancel", || job_requests(&h, &hub_id, "cancel") == 1).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(job_requests(&h, &hub_id, "cancel"), 1);
    h.gl.clear_status(67);
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(67).await["state"], "success");
    h.stop().await;
}
