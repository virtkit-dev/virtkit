//! The whole runner against a fake GitLab and the fake hub, in the order of
//! docs/gitlab-dispatch.md: capacity, reservation, job request, submission, commit once a
//! node accepted, output from the hub, final state, settle. Each scenario runs twice: with
//! the fake hub in process, and behind its HTTP API through the real hub client.

mod support;

use std::time::{Duration, Instant};

use support::gl::{Harness, RUNNER_ID, TOKEN, Via, eventually, job_json, runner_toml, within};
use vk_gitlab::dispatch::{CancelMode, DispatchError, ErrorKind, FailureClass, FakeCall};
use vk_gitlab::trace::TraceBuffer;
use vk_hub_proto::job::JobSpec;

/// Each scenario, in process and over HTTP.
macro_rules! both {
    ($($name:ident),* $(,)?) => {
        mod direct {
            $(#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn $name() { super::$name(super::Via::Direct).await })*
        }
        mod http {
            $(#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
            async fn $name() { super::$name(super::Via::Http).await })*
        }
    };
}

both!(
    job_runs_and_reports,
    no_capacity_no_requests,
    empty_answers_give_the_reservation_back,
    reservation_lost_during_the_request,
    gitlab_cancel_is_graceful_and_reported,
    gitlab_abort_cancels_now_and_writes_nothing_more,
    failure_classes_reach_gitlab_mapped,
    unsupported_jobs_fail_before_submission,
    a_job_the_hub_refuses_is_a_system_failure,
    a_job_not_placed_in_time_is_failed_uncommitted,
    concurrent_bounds_running_jobs,
    shutdown_abort_interrupts_running_jobs,
    an_idle_runner_leaves_the_slot_to_another,
    limit_bounds_a_runners_jobs,
    failing_renewals_do_not_stretch_the_lease,
    stop_lets_a_running_job_finish,
    an_unhealthy_runner_backs_off,
    strict_check_interval_paces_requests_after_a_job,
    output_the_hub_lost_fails_the_job,
    abort_reports_a_job_the_hub_never_ends,
    a_failed_verify_is_retried_for_the_runner_id,
    a_running_jobs_view_poll_outlives_the_tick,
);

async fn job_runs_and_reports(via: Via) {
    let h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(5));
    let (hub_id, sub) = within("a submitted job", h.hub.wait_for_job(1)).await;
    // Reserved before the job was requested, submitted on that reservation.
    let calls = h.hub.calls();
    let FakeCall::Reserve(reservation) = calls[0].clone() else {
        panic!("{calls:?}")
    };
    assert_eq!(sub.reservation.as_deref(), Some(reservation.as_str()));
    assert_eq!(sub.placement.pool, "p1");
    assert_eq!(sub.placement.labels, ["big"]);
    assert_eq!(sub.placement.envelope.mem_mib, 8192);
    assert_eq!(sub.request_id.len(), 32);
    let JobSpec::GitlabCi(spec) = &sub.spec;
    assert_eq!(spec.server_url, h.fake.url);
    assert_eq!(spec.token, "jt-5");
    assert_eq!(
        spec.job.runner_id, RUNNER_ID as u64,
        "the ID /runners/verify returned"
    );
    assert_eq!(spec.sources.repo_url, "https://gitlab.example.com/g/p.git");
    // Not committed until a node accepts it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!h.committed(5), "committed before a node accepted the job");
    h.hub.accept(&hub_id);
    eventually("the commit", || h.committed(5)).await;
    assert_eq!(h.updates(5)[0]["state"], "running");

    // The node's output, masked by the node, is copied byte for byte.
    let out1 = "Running on node-1\nhello [MASKED]\n";
    let out2 = "\u{fffd} bytes as the node cut them\n";
    h.hub.push_output(&hub_id, out1.as_bytes());
    eventually("the first output in the trace", || h.gl.log(5) == out1).await;
    h.hub.push_output(&hub_id, out2.as_bytes());
    h.hub.finish(&hub_id, None, None);
    let fin = h.final_update(5).await;
    assert_eq!(fin["state"], "success");
    let log = h.gl.log(5);
    assert_eq!(log, format!("{out1}{out2}"));
    let mut b = TraceBuffer::new(usize::MAX);
    b.write(log.as_bytes());
    assert_eq!(fin["output"]["checksum"], b.checksum());
    assert_eq!(fin["output"]["bytesize"], log.len());
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    h.stop().await;
}

async fn no_capacity_no_requests(via: Via) {
    let h = Harness::start(2, via).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(h.fake.requests_to("/api/v4/jobs/request").is_empty());
    assert!(h.hub.calls().is_empty(), "no reservation without capacity");
    h.hub.set_slots("p1", 1);
    eventually("a job request once capacity appears", || {
        !h.fake.requests_to("/api/v4/jobs/request").is_empty()
    })
    .await;
    let hub = h.stop().await;
    assert!(hub.reservations().is_empty(), "released on shutdown");
}

async fn empty_answers_give_the_reservation_back(via: Via) {
    let h = Harness::start(2, via).await;
    // Past a third of the lease: 300 ms in process, the hub's 1 s minimum over HTTP.
    *h.gl.request_delay.lock().unwrap() = Some(Duration::from_millis(400));
    h.hub.set_slots("p1", 1);
    eventually("three job requests", || h.job_requests() >= 3).await;
    // Each request had its own reservation, renewed while the request was out, and released
    // once GitLab answered with nothing.
    eventually("the third release", || {
        h.count_calls(|c| matches!(c, FakeCall::Release(_))) >= 3
    })
    .await;
    let calls = h.hub.calls();
    let reserves = h.count_calls(|c| matches!(c, FakeCall::Reserve(_)));
    let renews = h.count_calls(|c| matches!(c, FakeCall::Renew(_)));
    assert!(reserves >= 3, "{calls:?}");
    assert!(renews >= 3, "renewed every third of the lease: {calls:?}");
    // Idle requests are paced by check_interval (1 s).
    let reqs = h.job_requests();
    assert!(reqs <= 4, "{reqs} requests");
    let hub = h.stop().await;
    assert!(hub.reservations().is_empty(), "released on shutdown");
}

async fn reservation_lost_during_the_request(via: Via) {
    let h = Harness::start(2, via).await;
    *h.gl.request_delay.lock().unwrap() = Some(Duration::from_millis(600));
    h.gl.push_job(job_json(6));
    h.hub.set_slots("p1", 1);
    eventually("a reservation", || !h.hub.reservations().is_empty()).await;
    let r = h.hub.reservations()[0].clone();
    h.hub.drop_reservation(&r);
    let (hub_id, sub) = within("a submitted job", h.hub.wait_for_job(1)).await;
    assert_eq!(
        sub.reservation, None,
        "a lost reservation is not submitted on"
    );
    assert_eq!(sub.place_within, Duration::from_secs(1));
    // The hub found no node within place_within.
    h.hub.finish(&hub_id, Some(FailureClass::NoCapacity), None);
    assert_eq!(
        h.final_update(6).await["failure_reason"],
        "runner_system_failure"
    );
    h.stop().await;
}

async fn gitlab_cancel_is_graceful_and_reported(via: Via) {
    let h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(7));
    let (hub_id, _) = h.accepted_job(1).await;
    h.hub.push_output(&hub_id, b"working\n");
    eventually("output", || !h.gl.log(7).is_empty()).await;
    h.gl.set_status(7, "canceling");
    within(
        "a graceful cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Graceful)),
    )
    .await;
    h.gl.clear_status(7);
    h.hub.push_output(&hub_id, b"running after_script\n");
    h.hub.finish(&hub_id, Some(FailureClass::Canceled), None);
    let fin = h.final_update(7).await;
    assert_eq!(fin["state"], "failed");
    // GitLab keeps the job canceled; `job_canceled` is not a reason it knows.
    assert_eq!(fin["failure_reason"], "unknown_failure");
    assert_eq!(h.gl.log(7), "working\nrunning after_script\n");
    assert!(
        !h.hub
            .calls()
            .contains(&FakeCall::Cancel(hub_id, CancelMode::Immediate))
    );
    h.stop().await;
}

async fn gitlab_abort_cancels_now_and_writes_nothing_more(via: Via) {
    let h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(8));
    let (hub_id, _) = h.accepted_job(1).await;
    h.gl.set_status(8, "canceled");
    h.hub.push_output(&hub_id, b"x\n");
    within(
        "an immediate cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Immediate)),
    )
    .await;
    h.hub.finish(&hub_id, Some(FailureClass::Canceled), None);
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    assert!(
        h.updates(8).iter().all(|b| b["state"] == "running"),
        "no final state after GitLab ended the job"
    );
    h.stop().await;
}

async fn failure_classes_reach_gitlab_mapped(via: Via) {
    let h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(9));
    let (hub_id, _) = h.accepted_job(1).await;
    h.hub
        .finish(&hub_id, Some(FailureClass::ImagePull), Some(2));
    let fin = h.final_update(9).await;
    assert_eq!(fin["state"], "failed");
    // `image_pull_failure` is not in this GitLab's list: its older equivalent.
    assert_eq!(fin["failure_reason"], "runner_system_failure");
    assert_eq!(fin["exit_code"], 2);
    h.stop().await;
}

async fn unsupported_jobs_fail_before_submission(via: Via) {
    let h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    let mut job = job_json(10);
    job["image"] =
        serde_json::json!({"name": "alpine", "executor_opts": {"docker": {"blammo": 1}}});
    h.gl.push_job(job);
    let fin = h.final_update(10).await;
    assert_eq!(fin["state"], "failed");
    assert_eq!(fin["failure_reason"], "runner_system_failure");
    assert_eq!(fin["exit_code"], 3);
    assert!(
        h.gl.log(10)
            .contains("Unsupported \"image\" options [blammo]")
    );
    assert!(!h.committed(10));

    let mut job = job_json(11);
    job["secrets"] = serde_json::json!({"K": {"vault": {"path": "p"}}});
    h.gl.push_job(job);
    let fin = h.final_update(11).await;
    // runner_configuration_error, mapped for a GitLab that does not know it
    assert_eq!(fin["failure_reason"], "script_failure");
    let log = h.gl.log(11);
    assert!(log.contains("external secrets are not supported"));
    // The runner's own line is stamped as gitlab-runner stamps it.
    assert_eq!(log.get(26..45), Some("Z 00O \x1b[31;1mERROR:"), "{log:?}");

    let mut job = job_json(12);
    job["run"] = serde_json::json!("[{\"name\":\"s\",\"script\":\"true\"}]");
    job["variables"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"key": "FF_TIMESTAMPS", "value": "false"}));
    h.gl.push_job(job);
    let fin = h.final_update(12).await;
    assert_eq!(fin["failure_reason"], "script_failure");
    assert!(h.gl.log(12).starts_with("\x1b[31;1mERROR: "));
    assert!(
        !h.hub
            .calls()
            .iter()
            .any(|c| matches!(c, FakeCall::Submit { .. }))
    );
    h.stop().await;
}

async fn a_job_the_hub_refuses_is_a_system_failure(via: Via) {
    let h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.hub
        .refuse_submit(DispatchError::new(ErrorKind::TooLarge, "spec over 512 KiB"));
    h.gl.push_job(job_json(13));
    let fin = h.final_update(13).await;
    assert_eq!(fin["state"], "failed");
    assert_eq!(fin["failure_reason"], "runner_system_failure");
    assert!(
        h.gl.log(13)
            .contains("the fleet did not take the job: spec over 512 KiB")
    );
    assert!(!h.committed(13));
    h.stop().await;
}

async fn a_job_not_placed_in_time_is_failed_uncommitted(via: Via) {
    let h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(14));
    let (hub_id, _) = within("a submitted job", h.hub.wait_for_job(1)).await;
    h.hub.finish(&hub_id, Some(FailureClass::NoCapacity), None);
    let fin = h.final_update(14).await;
    assert_eq!(fin["state"], "failed");
    assert_eq!(fin["failure_reason"], "runner_system_failure");
    assert!(!h.committed(14));
    assert!(h.gl.log(14).contains("could not place the job"));
    within("the settle", h.hub.wait_for_call(FakeCall::Settle(hub_id))).await;
    h.stop().await;
}

async fn concurrent_bounds_running_jobs(via: Via) {
    let h = Harness::start(1, via).await;
    h.hub.set_slots("p1", 5);
    h.gl.push_job(job_json(15));
    h.gl.push_job(job_json(16));
    let (first, _) = h.accepted_job(1).await;
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        h.fake.requests_to("/api/v4/jobs/request").len(),
        1,
        "concurrent = 1 holds the next request back"
    );
    h.hub.finish(&first, None, None);
    let (second, sub) = h.accepted_job(2).await;
    assert_eq!(sub.gitlab_job, 16);
    h.hub.finish(&second, None, None);
    h.final_update(16).await;
    h.stop().await;
}

async fn shutdown_abort_interrupts_running_jobs(via: Via) {
    let mut h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(17));
    let (hub_id, _) = h.accepted_job(1).await;
    h.daemon.stop_handle().abort();
    within(
        "an immediate cancel on shutdown",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id.clone(), CancelMode::Immediate)),
    )
    .await;
    h.hub.finish(&hub_id, Some(FailureClass::Canceled), None);
    let fin = h.final_update(17).await;
    assert_eq!(fin["state"], "failed");
    assert_eq!(fin["failure_reason"], "runner_interrupted");
    h.daemon.join().await;
}

async fn an_idle_runner_leaves_the_slot_to_another(via: Via) {
    // One slot over two runners: the idle one must not keep it.
    let h = Harness::start_with(1, via, |url| {
        runner_toml("r1", TOKEN, url, "") + &runner_toml("r2", "glrt-other-token", url, "")
    })
    .await;
    h.hub.set_slots("p1", 5);
    h.gl.push_job_for("glrt-other-token", job_json(20));
    let (hub_id, sub) = h.accepted_job(1).await;
    assert_eq!(sub.gitlab_job, 20);
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(20).await["state"], "success");
    h.stop().await;
}

async fn limit_bounds_a_runners_jobs(via: Via) {
    let h = Harness::start_with(5, via, |url| {
        runner_toml("r1", TOKEN, url, "limit = 1\nrequest_concurrency = 2\n")
    })
    .await;
    h.hub.set_slots("p1", 5);
    h.gl.push_job(job_json(21));
    h.gl.push_job(job_json(22));
    let (first, _) = h.accepted_job(1).await;
    let reqs = h.job_requests();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        h.job_requests(),
        reqs,
        "limit = 1 holds the next request back"
    );
    h.hub.finish(&first, None, None);
    let (second, sub) = h.accepted_job(2).await;
    assert_eq!(sub.gitlab_job, 22);
    h.hub.finish(&second, None, None);
    h.final_update(22).await;
    h.stop().await;
}

async fn failing_renewals_do_not_stretch_the_lease(via: Via) {
    let h = Harness::start(2, via).await;
    // The request outlasts the lease (300 ms in process, the hub's 1 s minimum over HTTP);
    // every renewal fails.
    *h.gl.request_delay.lock().unwrap() = Some(Duration::from_millis(1500));
    h.hub
        .refuse_renew(Some(DispatchError::new(ErrorKind::Unavailable, "hub down")));
    h.gl.push_job(job_json(23));
    h.hub.set_slots("p1", 2);
    let (hub_id, sub) = within("a submitted job", h.hub.wait_for_job(1)).await;
    assert_eq!(
        sub.reservation, None,
        "a lease that ran out is not submitted on"
    );
    assert!(h.count_calls(|c| matches!(c, FakeCall::Renew(_))) >= 2);
    h.hub.refuse_renew(None);
    h.hub.accept(&hub_id);
    h.hub.finish(&hub_id, None, None);
    h.final_update(23).await;
    h.stop().await;
}

async fn stop_lets_a_running_job_finish(via: Via) {
    let mut h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(24));
    let (hub_id, _) = h.accepted_job(1).await;
    h.daemon.stop_handle().stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(h.daemon.is_running(), "returned with a job running");
    h.hub.push_output(&hub_id, b"done\n");
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(24).await["state"], "success");
    h.daemon.join().await;
    assert_eq!(h.gl.log(24), "done\n");
    assert!(h.hub.calls().contains(&FakeCall::Settle(hub_id)));
    assert!(h.hub.reservations().is_empty());
    assert_eq!(
        h.count_calls(|c| matches!(c, FakeCall::Cancel(..))),
        0,
        "a stop cancels nothing"
    );
}

async fn an_unhealthy_runner_backs_off(via: Via) {
    let h = Harness::start_with(2, via, |url| {
        runner_toml("r1", TOKEN, url, "unhealthy_requests_limit = 2\n")
    })
    .await;
    h.gl.forbidden.lock().unwrap().insert(TOKEN.to_owned());
    h.hub.set_slots("p1", 1);
    eventually("two refused requests", || h.job_requests() >= 2).await;
    // Disabled for at least the initial 30 s backoff.
    tokio::time::sleep(Duration::from_millis(3000)).await;
    assert_eq!(h.job_requests(), 2);
    let hub = h.stop().await;
    assert!(hub.reservations().is_empty());
}

/// How long after the first job request the second one started.
async fn second_request_gap(via: Via, strict: bool) -> Duration {
    let extra = if strict {
        "strict_check_interval = true\n"
    } else {
        ""
    };
    let h = Harness::start_with(5, via, |url| runner_toml("r1", TOKEN, url, extra)).await;
    h.gl.push_job(job_json(25));
    h.gl.push_job(job_json(26));
    h.hub.set_slots("p1", 5);
    eventually("the first request", || h.job_requests() >= 1).await;
    let first = Instant::now();
    eventually("the second request", || h.job_requests() >= 2).await;
    let gap = first.elapsed();
    let mut daemon = h.daemon;
    daemon.stop_handle().abort();
    daemon.join().await;
    gap
}

async fn strict_check_interval_paces_requests_after_a_job(via: Via) {
    let gap = second_request_gap(via, true).await;
    assert!(gap >= Duration::from_millis(700), "{gap:?}");
    let gap = second_request_gap(via, false).await;
    assert!(gap < Duration::from_millis(700), "{gap:?}");
}

async fn output_the_hub_lost_fails_the_job(via: Via) {
    let h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(27));
    let (hub_id, _) = h.accepted_job(1).await;
    h.hub.push_output(&hub_id, b"0123456789\n");
    eventually("the output", || !h.gl.log(27).is_empty()).await;
    // Shorter than what was copied: the offset is out of range.
    h.hub.truncate_output(&hub_id, 3);
    let fin = h.final_update(27).await;
    assert_eq!(fin["state"], "failed");
    assert_eq!(fin["failure_reason"], "runner_system_failure");
    // The node is told to stop the job it can no longer report.
    within(
        "an immediate cancel",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id, CancelMode::Immediate)),
    )
    .await;
    h.stop().await;
}

async fn abort_reports_a_job_the_hub_never_ends(via: Via) {
    let mut h = Harness::start(2, via).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(28));
    let (hub_id, _) = h.accepted_job(1).await;
    h.daemon.stop_handle().abort();
    within(
        "an immediate cancel on shutdown",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id, CancelMode::Immediate)),
    )
    .await;
    // The node never reports the job ended: after settle_wait it is interrupted anyway.
    let fin = h.final_update(28).await;
    assert_eq!(fin["failure_reason"], "runner_interrupted");
    h.daemon.join().await;
}

async fn a_failed_verify_is_retried_for_the_runner_id(via: Via) {
    let mut h = Harness::unstarted(2, via).await;
    *h.gl.verify_failures.lock().unwrap() = 1;
    h.daemon = h.spawn_daemon();
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(29));
    let (hub_id, sub) = h.accepted_job(1).await;
    let JobSpec::GitlabCi(spec) = &sub.spec;
    assert_eq!(
        spec.job.runner_id, RUNNER_ID as u64,
        "verified with the job"
    );
    assert_eq!(h.fake.requests_to("/api/v4/runners/verify").len(), 2);
    h.hub.finish(&hub_id, None, None);
    h.final_update(29).await;
    h.stop().await;
}

async fn a_running_jobs_view_poll_outlives_the_tick(via: Via) {
    let mut h = Harness::unstarted(2, via).await;
    h.options.hub.wait = Duration::from_secs(5);
    h.daemon = h.spawn_daemon();
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(40));
    let (hub_id, _) = h.accepted_job(1).await;
    let reads = h.hub.view_reads(&hub_id);
    // Three ticks of the follow loop, within one long poll.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let more = h.hub.view_reads(&hub_id) - reads;
    assert!(more <= 1, "{more} reads of the job's view in 3 s");
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(40).await["state"], "success");
    h.stop().await;
}
