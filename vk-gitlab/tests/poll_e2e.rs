//! The whole runner against a fake GitLab and the in-memory fake hub, in the order of
//! virtkit's docs/gitlab-dispatch.md: capacity, reservation, job request, submission,
//! commit once a node accepted, output from the hub, final state, settle.

mod support;

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use support::{FakeGitLab, Recorded, Reply};
use vk_gitlab::config::Config;
use vk_gitlab::dispatch::{
    CancelMode, DispatchError, ErrorKind, FailureClass, FakeCall, FakeDispatcher, Submission,
};
use vk_gitlab::poll::{self, HubTimings, RunOptions, ShutdownHandle};
use vk_gitlab::trace::{TraceBuffer, TraceSettings};

const TOKEN: &str = "glrt-test-token";

/// GitLab's side: jobs to hand out per runner token, the `Job-Status` of each job, and each
/// job's log as assembled from the patches.
#[derive(Default)]
struct Gl {
    queues: Mutex<HashMap<String, VecDeque<String>>>,
    /// Runner tokens whose job requests are answered 403.
    forbidden: Mutex<HashSet<String>>,
    status: Mutex<HashMap<i64, String>>,
    logs: Mutex<HashMap<i64, Vec<u8>>>,
    request_delay: Mutex<Option<Duration>>,
}

impl Gl {
    fn handler(self: &Arc<Self>) -> impl Fn(&Recorded) -> Reply + Send + Sync + 'static {
        let gl = Arc::clone(self);
        move |r: &Recorded| {
            if r.path == "/api/v4/jobs/request" {
                let token = r.json()["token"].as_str().unwrap_or_default().to_owned();
                if gl.forbidden.lock().unwrap().contains(&token) {
                    return Reply::status(403);
                }
                let next = gl
                    .queues
                    .lock()
                    .unwrap()
                    .get_mut(&token)
                    .and_then(VecDeque::pop_front);
                let reply = match next {
                    Some(job) => Reply::status(201).json(&job),
                    None => Reply::status(204),
                };
                return match *gl.request_delay.lock().unwrap() {
                    Some(d) => reply.after(d),
                    None => reply,
                };
            }
            let Some(rest) = r.path.strip_prefix("/api/v4/jobs/") else {
                return Reply::status(404);
            };
            let (id, is_trace) = match rest.strip_suffix("/trace") {
                Some(id) => (id, true),
                None => (rest, false),
            };
            let Ok(id) = id.parse::<i64>() else {
                return Reply::status(404);
            };
            let status = gl.status.lock().unwrap().get(&id).cloned();
            let reply = if is_trace {
                let start: usize = r
                    .header("content-range")
                    .split('-')
                    .next()
                    .unwrap()
                    .parse()
                    .unwrap();
                let mut logs = gl.logs.lock().unwrap();
                let log = logs.entry(id).or_default();
                log.truncate(start);
                log.extend_from_slice(&r.body);
                Reply::status(202)
            } else {
                Reply::status(200)
            };
            match status {
                Some(s) => reply.header("Job-Status", &s),
                None => reply,
            }
        }
    }

    fn push_job(&self, job: serde_json::Value) {
        self.push_job_for(TOKEN, job);
    }

    fn push_job_for(&self, token: &str, job: serde_json::Value) {
        self.queues
            .lock()
            .unwrap()
            .entry(token.to_owned())
            .or_default()
            .push_back(job.to_string());
    }

    fn set_status(&self, id: i64, status: &str) {
        self.status.lock().unwrap().insert(id, status.to_owned());
    }

    fn log(&self, id: i64) -> String {
        String::from_utf8_lossy(self.logs.lock().unwrap().get(&id).map_or(&[][..], |v| v))
            .into_owned()
    }
}

/// A job whose GitLab knows `runner_interrupted`, but not `job_canceled` (no GitLab does),
/// `image_pull_failure` or `runner_configuration_error`.
fn job_json(id: i64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "token": format!("jt-{id}"),
        "job_info": {"name": "build", "project_full_path": "g/p"},
        "git_info": {"repo_url": "https://gitlab-ci-token:jt@gitlab.example.com/g/p.git"},
        "runner_info": {"timeout": 3600},
        "variables": [{"key": "SECRET", "value": "s3cr3t", "masked": true}],
        "features": {"failure_reasons": [
            "script_failure", "runner_system_failure", "job_execution_timeout",
            "runner_interrupted"
        ]}
    })
}

struct Harness {
    gl: Arc<Gl>,
    fake: FakeGitLab,
    hub: FakeDispatcher,
    handle: ShutdownHandle,
    run: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// One runner, `r1`, on pool `p1`.
async fn start(concurrent: usize) -> Harness {
    start_with(concurrent, |url| runner_toml("r1", TOKEN, url, "")).await
}

/// A `[[runner]]` table; `extra` is appended to it.
fn runner_toml(name: &str, token: &str, url: &str, extra: &str) -> String {
    format!(
        "[[runner]]\nname = \"{name}\"\nurl = \"{url}\"\ntoken = \"{token}\"\npool = \"p1\"\nlabels = [\"big\"]\nenvelope = {{ mem = \"8G\", cpus = 4, disk = \"10G\" }}\n{extra}"
    )
}

/// `runners(url)` gives the `[[runner]]` tables, all against the one fake GitLab.
async fn start_with(concurrent: usize, runners: impl FnOnce(&str) -> String) -> Harness {
    let gl = Arc::new(Gl::default());
    let fake = FakeGitLab::start(gl.handler()).await;
    let cfg = Config::parse(
        &format!(
            "concurrent = {concurrent}\ncheck_interval = 1\n{}",
            runners(&fake.url)
        ),
        Path::new("/"),
    )
    .unwrap();
    let hub = FakeDispatcher::new();
    let (handle, shutdown) = ShutdownHandle::new();
    let options = RunOptions {
        trace: TraceSettings {
            update_interval: Duration::from_millis(50),
            force_send_interval: Duration::from_millis(100),
            ..Default::default()
        },
        retry: Default::default(),
        hub: HubTimings {
            lease: Duration::from_millis(300),
            wait: Duration::from_millis(200),
            place_within: Duration::from_secs(1),
            retry_pause: Duration::from_millis(50),
            settle_wait: Duration::from_secs(2),
        },
    };
    let d = hub.clone();
    let run = tokio::spawn(async move {
        poll::run(&cfg, "s_0123456789ab", Arc::new(d), options, shutdown).await
    });
    Harness {
        gl,
        fake,
        hub,
        handle,
        run,
    }
}

async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

impl Harness {
    fn updates(&self, id: i64) -> Vec<serde_json::Value> {
        self.fake
            .requests_to(&format!("/api/v4/jobs/{id}"))
            .iter()
            .map(Recorded::json)
            .collect()
    }

    fn job_requests(&self) -> usize {
        self.fake.requests_to("/api/v4/jobs/request").len()
    }

    fn count_calls(&self, f: impl Fn(&FakeCall) -> bool) -> usize {
        self.hub.calls().iter().filter(|c| f(c)).count()
    }

    fn committed(&self, id: i64) -> bool {
        self.updates(id).iter().any(|b| b["state"] == "running")
    }

    async fn final_update(&self, id: i64) -> serde_json::Value {
        let mut fin = None;
        eventually(&format!("the final update of job {id}"), || {
            fin = self
                .updates(id)
                .into_iter()
                .find(|b| b["state"] != "running");
            fin.is_some()
        })
        .await;
        fin.unwrap()
    }

    /// Waits for the `n`th submitted job, and has the node accept it.
    async fn accepted_job(&self, n: usize) -> (String, Submission) {
        let (id, sub) = within("a submitted job", self.hub.wait_for_job(n)).await;
        self.hub.accept(&id);
        let gitlab_id = sub.job.id;
        eventually("the commit", || self.committed(gitlab_id)).await;
        (id, sub)
    }

    /// Stops the loop; returns the hub to inspect afterwards.
    async fn stop(self) -> FakeDispatcher {
        self.handle.stop();
        within("the loop to stop", self.run).await.unwrap().unwrap();
        self.hub
    }
}

#[tokio::test]
async fn job_runs_and_reports() {
    let h = start(2).await;
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
    assert_eq!(sub.runner, "r1");
    assert_eq!(sub.server_url, h.fake.url);
    assert_eq!(sub.request_id.len(), 32);
    assert_eq!(sub.job.token.expose(), "jt-5");
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

#[tokio::test]
async fn no_capacity_no_requests() {
    let h = start(2).await;
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

#[tokio::test]
async fn empty_answers_give_the_reservation_back() {
    let h = start(2).await;
    *h.gl.request_delay.lock().unwrap() = Some(Duration::from_millis(250));
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

#[tokio::test]
async fn reservation_lost_during_the_request() {
    let h = start(2).await;
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

#[tokio::test]
async fn gitlab_cancel_is_graceful_and_reported() {
    let h = start(2).await;
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
    h.gl.status.lock().unwrap().remove(&7);
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

#[tokio::test]
async fn gitlab_abort_cancels_now_and_writes_nothing_more() {
    let h = start(2).await;
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

#[tokio::test]
async fn failure_classes_reach_gitlab_mapped() {
    let h = start(2).await;
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

#[tokio::test]
async fn unsupported_jobs_fail_before_submission() {
    let h = start(2).await;
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
    assert!(h.gl.log(11).contains("external secrets are not supported"));

    let mut job = job_json(12);
    job["run"] = serde_json::json!("[{\"name\":\"s\",\"script\":\"true\"}]");
    h.gl.push_job(job);
    let fin = h.final_update(12).await;
    assert_eq!(fin["failure_reason"], "script_failure");
    assert!(
        !h.hub
            .calls()
            .iter()
            .any(|c| matches!(c, FakeCall::Submit { .. }))
    );
    h.stop().await;
}

#[tokio::test]
async fn a_job_the_hub_refuses_is_a_system_failure() {
    let h = start(2).await;
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

#[tokio::test]
async fn a_job_not_placed_in_time_is_failed_uncommitted() {
    let h = start(2).await;
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

#[tokio::test]
async fn concurrent_bounds_running_jobs() {
    let h = start(1).await;
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
    assert_eq!(sub.job.id, 16);
    h.hub.finish(&second, None, None);
    h.final_update(16).await;
    h.stop().await;
}

#[tokio::test]
async fn shutdown_abort_interrupts_running_jobs() {
    let h = start(2).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(17));
    let (hub_id, _) = h.accepted_job(1).await;
    h.handle.abort();
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
    within("the loop to stop", h.run).await.unwrap().unwrap();
}

#[tokio::test]
async fn an_idle_runner_leaves_the_slot_to_another() {
    // One slot over two runners: the idle one must not keep it.
    let h = start_with(1, |url| {
        runner_toml("r1", TOKEN, url, "") + &runner_toml("r2", "glrt-other-token", url, "")
    })
    .await;
    h.hub.set_slots("p1", 5);
    h.gl.push_job_for("glrt-other-token", job_json(20));
    let (hub_id, sub) = h.accepted_job(1).await;
    assert_eq!(sub.runner, "r2");
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(20).await["state"], "success");
    h.stop().await;
}

#[tokio::test]
async fn limit_bounds_a_runners_jobs() {
    let h = start_with(5, |url| {
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
    assert_eq!(sub.job.id, 22);
    h.hub.finish(&second, None, None);
    h.final_update(22).await;
    h.stop().await;
}

#[tokio::test]
async fn failing_renewals_do_not_stretch_the_lease() {
    let h = start(2).await;
    // The request outlasts the 300 ms lease; every renewal fails.
    *h.gl.request_delay.lock().unwrap() = Some(Duration::from_millis(900));
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

#[tokio::test]
async fn stop_lets_a_running_job_finish() {
    let h = start(2).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(24));
    let (hub_id, _) = h.accepted_job(1).await;
    h.handle.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!h.run.is_finished(), "returned with a job running");
    h.hub.push_output(&hub_id, b"done\n");
    h.hub.finish(&hub_id, None, None);
    assert_eq!(h.final_update(24).await["state"], "success");
    within("the loop to stop", h.run).await.unwrap().unwrap();
    assert_eq!(h.gl.log(24), "done\n");
    assert!(h.hub.calls().contains(&FakeCall::Settle(hub_id)));
    assert!(h.hub.reservations().is_empty());
    assert!(
        !h.hub
            .calls()
            .iter()
            .any(|c| matches!(c, FakeCall::Cancel(..))),
        "a stop cancels nothing"
    );
}

#[tokio::test]
async fn an_unhealthy_runner_backs_off() {
    let h = start_with(2, |url| {
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
async fn second_request_gap(strict: bool) -> Duration {
    let extra = if strict {
        "strict_check_interval = true\n"
    } else {
        ""
    };
    let h = start_with(5, |url| runner_toml("r1", TOKEN, url, extra)).await;
    h.gl.push_job(job_json(25));
    h.gl.push_job(job_json(26));
    h.hub.set_slots("p1", 5);
    eventually("the first request", || h.job_requests() >= 1).await;
    let first = Instant::now();
    eventually("the second request", || h.job_requests() >= 2).await;
    let gap = first.elapsed();
    h.handle.abort();
    within("the loop to stop", h.run).await.unwrap().unwrap();
    gap
}

#[tokio::test]
async fn strict_check_interval_paces_requests_after_a_job() {
    let gap = second_request_gap(true).await;
    assert!(gap >= Duration::from_millis(700), "{gap:?}");
    let gap = second_request_gap(false).await;
    assert!(gap < Duration::from_millis(700), "{gap:?}");
}

#[tokio::test]
async fn output_the_hub_lost_fails_the_job() {
    let h = start(2).await;
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

#[tokio::test]
async fn abort_reports_a_job_the_hub_never_ends() {
    let h = start(2).await;
    h.hub.set_slots("p1", 1);
    h.gl.push_job(job_json(28));
    let (hub_id, _) = h.accepted_job(1).await;
    h.handle.abort();
    within(
        "an immediate cancel on shutdown",
        h.hub
            .wait_for_call(FakeCall::Cancel(hub_id, CancelMode::Immediate)),
    )
    .await;
    // The node never reports the job ended: after settle_wait it is interrupted anyway.
    let fin = h.final_update(28).await;
    assert_eq!(fin["failure_reason"], "runner_interrupted");
    within("the loop to stop", h.run).await.unwrap().unwrap();
}
