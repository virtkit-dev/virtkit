//! GitLab's side of an end-to-end test, and a harness running the daemon against it with
//! the fake hub — in process, or behind the fake hub's HTTP API through the real client.

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vk_gitlab::config::Config;
use vk_gitlab::dispatch::{FakeCall, FakeDispatcher, Submission};
use vk_gitlab::hub::{HubClient, HubOptions, HubRetry};
use vk_gitlab::poll::{self, HubTimings, RunOptions, ShutdownHandle};
use vk_gitlab::secret::Secret;
use vk_gitlab::trace::TraceSettings;

use super::fakehub::{FakeHub, TEST_API_KEY};
use super::{FakeGitLab, Recorded, Reply};

/// The runner ID the fake GitLab's `/runners/verify` answers.
pub const RUNNER_ID: i64 = 77;
/// The token of the default runner, `r1`.
pub const TOKEN: &str = "glrt-test-token";

/// GitLab: jobs to hand out per runner token, the `Job-Status` of each job, and each job's
/// log as the patches assembled it — a patch must start where the log ends (or at 0, a
/// reset), else it is answered 416 with the log's length, as GitLab does.
#[derive(Default)]
pub struct Gl {
    pub queues: Mutex<HashMap<String, VecDeque<String>>>,
    /// Runner tokens whose job requests are answered 403.
    pub forbidden: Mutex<HashSet<String>>,
    /// How many `/runners/verify` requests to answer 400 first.
    pub verify_failures: Mutex<u32>,
    /// Whether `/runners/verify` refuses the token (403).
    pub verify_refused: Mutex<bool>,
    pub status: Mutex<HashMap<i64, String>>,
    pub logs: Mutex<HashMap<i64, Vec<u8>>>,
    pub request_delay: Mutex<Option<Duration>>,
}

impl Gl {
    pub fn handler(self: &Arc<Self>) -> impl Fn(&Recorded) -> Reply + Send + Sync + 'static {
        let gl = Arc::clone(self);
        move |r: &Recorded| {
            if r.path == "/api/v4/runners/verify" {
                let mut failures = gl.verify_failures.lock().unwrap();
                if *failures > 0 {
                    *failures -= 1;
                    return Reply::status(400);
                }
                if *gl.verify_refused.lock().unwrap() {
                    return Reply::status(403);
                }
                return Reply::status(200).json(&format!(r#"{{"id": {RUNNER_ID}}}"#));
            }
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
                if start != 0 && start != log.len() {
                    return Reply::status(416).header("Range", &format!("0-{}", log.len()));
                }
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

    pub fn push_job(&self, job: serde_json::Value) {
        self.push_job_for(TOKEN, job);
    }

    pub fn push_job_for(&self, token: &str, job: serde_json::Value) {
        self.queues
            .lock()
            .unwrap()
            .entry(token.to_owned())
            .or_default()
            .push_back(job.to_string());
    }

    pub fn set_status(&self, id: i64, status: &str) {
        self.status.lock().unwrap().insert(id, status.to_owned());
    }

    pub fn clear_status(&self, id: i64) {
        self.status.lock().unwrap().remove(&id);
    }

    pub fn log(&self, id: i64) -> String {
        String::from_utf8_lossy(self.logs.lock().unwrap().get(&id).map_or(&[][..], |v| v))
            .into_owned()
    }
}

/// A job whose GitLab knows `runner_interrupted`, but not `job_canceled` (no GitLab does),
/// `image_pull_failure` or `runner_configuration_error`.
pub fn job_json(id: i64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "token": format!("jt-{id}"),
        "job_info": {"name": "build", "project_full_path": "g/p"},
        "git_info": {"repo_url": "https://gitlab-ci-token:jt@gitlab.example.com/g/p.git", "ref": "main"},
        "runner_info": {"timeout": 3600},
        "variables": [{"key": "SECRET", "value": "s3cr3t", "masked": true}],
        "steps": [{"name": "script", "script": ["true"], "timeout": 3600, "when": "on_success"}],
        "features": {"failure_reasons": [
            "script_failure", "runner_system_failure", "job_execution_timeout",
            "runner_interrupted"
        ]}
    })
}

pub fn temp_dir(what: &str) -> PathBuf {
    let n: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let dir = std::env::temp_dir().join(format!("vk-gitlab-{what}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A state directory must be private.
    std::fs::set_permissions(
        &dir,
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    dir
}

pub fn options() -> RunOptions {
    RunOptions {
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
        trace_offset_interval: Duration::from_millis(200),
    }
}

/// How the daemon reaches the fake hub.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// The fake dispatcher, in process.
    Direct,
    /// The fake hub's HTTP API, through the real hub client.
    Http,
}

/// The daemon, on a runtime of its own so a test can kill it outright.
pub struct Daemon {
    rt: Option<tokio::runtime::Runtime>,
    handle: Option<ShutdownHandle>,
    task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl Daemon {
    /// Kills the daemon mid-flight, as a crash would: nothing more runs. The runtime goes
    /// first, its state file writes included, so the dropped handle aborts nothing.
    pub fn kill(&mut self) {
        self.task.take();
        if let Some(rt) = self.rt.take() {
            tokio::task::block_in_place(|| rt.shutdown_timeout(Duration::from_secs(10)));
        }
        self.handle.take();
    }

    /// Waits for the daemon's loop to return, and returns what it did.
    pub async fn exit(&mut self) -> anyhow::Result<()> {
        let task = self.task.take().expect("a running daemon");
        within("the daemon to exit", task).await.unwrap()
    }

    pub fn stop_handle(&self) -> &ShutdownHandle {
        self.handle.as_ref().unwrap()
    }

    /// Whether the daemon's loop is still running.
    pub fn is_running(&self) -> bool {
        self.task.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Stops the daemon and waits for it.
    pub async fn stop(&mut self) {
        if let Some(h) = &self.handle {
            h.stop();
        }
        self.join().await;
    }

    pub async fn join(&mut self) {
        if let Some(task) = self.task.take() {
            within("the daemon to stop", task).await.unwrap().unwrap();
        }
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

pub struct Harness {
    pub gl: Arc<Gl>,
    pub fake: FakeGitLab,
    pub hub: FakeDispatcher,
    pub http_hub: Option<FakeHub>,
    pub state_dir: PathBuf,
    pub concurrent: usize,
    /// The `[[runners]]` tables.
    pub runners: String,
    pub via: Via,
    pub options: RunOptions,
    pub daemon: Daemon,
}

/// A `[[runners]]` table on pool `p1`; `extra` is appended to it.
pub fn runner_toml(name: &str, token: &str, url: &str, extra: &str) -> String {
    format!(
        "[[runners]]\nname = \"{name}\"\nurl = \"{url}\"\ntoken = \"{token}\"\npool = \"p1\"\nlabels = [\"big\"]\nenvelope = {{ mem = \"8G\", cpus = 4, disk = \"10G\" }}\n{extra}"
    )
}

impl Harness {
    /// One runner, `r1`, on pool `p1`.
    pub async fn start(concurrent: usize, via: Via) -> Harness {
        Self::start_with(concurrent, via, |url| runner_toml("r1", TOKEN, url, "")).await
    }

    /// `runners(url)` gives the `[[runners]]` tables, all against the one fake GitLab.
    pub async fn start_with(
        concurrent: usize,
        via: Via,
        runners: impl FnOnce(&str) -> String,
    ) -> Harness {
        let mut h = Self::unstarted(concurrent, via).await;
        h.runners = runners(&h.fake.url);
        h.daemon = h.spawn_daemon();
        h
    }

    /// The fakes and the state directory, without the daemon yet.
    pub async fn unstarted(concurrent: usize, via: Via) -> Harness {
        let gl = Arc::new(Gl::default());
        let fake = FakeGitLab::start(gl.handler()).await;
        let hub = FakeDispatcher::new();
        let http_hub = match via {
            Via::Direct => None,
            Via::Http => Some(FakeHub::start(hub.clone()).await),
        };
        let state_dir = temp_dir("state");
        let runners = runner_toml("r1", TOKEN, &fake.url, "");
        Harness {
            gl,
            fake,
            hub,
            http_hub,
            state_dir,
            concurrent,
            runners,
            via,
            options: options(),
            daemon: Daemon {
                rt: None,
                handle: None,
                task: None,
            },
        }
    }

    pub fn config(&self) -> Config {
        let hub = match &self.http_hub {
            Some(hub) => format!(
                "[hub]\nurl = \"{}\"\napi_key = \"{TEST_API_KEY}\"\n",
                hub.url
            ),
            None => String::new(),
        };
        Config::parse(
            &format!(
                "concurrent = {}\ncheck_interval = 1\nstate_dir = \"{}\"\n{hub}{}",
                self.concurrent,
                self.state_dir.display(),
                self.runners
            ),
            Path::new("/"),
        )
        .unwrap()
    }

    /// Starts the daemon (again, after a kill: it resumes from the state file).
    pub fn spawn_daemon(&self) -> Daemon {
        let cfg = self.config();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let (handle, shutdown) = ShutdownHandle::new();
        let options = self.options.clone();
        let task = match self.via {
            Via::Direct => {
                let d = Arc::new(self.hub.clone());
                rt.spawn(
                    async move { poll::run(&cfg, "s_0123456789ab", d, options, shutdown).await },
                )
            }
            Via::Http => {
                let hub = cfg.hub.clone().unwrap();
                let client = HubClient::new(HubOptions {
                    url: hub.url.clone(),
                    api_key: Secret::new(TEST_API_KEY),
                    ca_file: None,
                    retry: HubRetry {
                        max_attempts: 5,
                        backoff_min: Duration::from_millis(50),
                        backoff_max: Duration::from_millis(200),
                    },
                })
                .unwrap();
                let d = Arc::new(client);
                rt.spawn(
                    async move { poll::run(&cfg, "s_0123456789ab", d, options, shutdown).await },
                )
            }
        };
        Daemon {
            rt: Some(rt),
            handle: Some(handle),
            task: Some(task),
        }
    }

    pub fn updates(&self, id: i64) -> Vec<serde_json::Value> {
        self.fake
            .requests_to(&format!("/api/v4/jobs/{id}"))
            .iter()
            .map(Recorded::json)
            .collect()
    }

    pub fn job_requests(&self) -> usize {
        self.fake.requests_to("/api/v4/jobs/request").len()
    }

    pub fn count_calls(&self, f: impl Fn(&FakeCall) -> bool) -> usize {
        self.hub.calls().iter().filter(|c| f(c)).count()
    }

    pub fn committed(&self, id: i64) -> bool {
        self.updates(id).iter().any(|b| b["state"] == "running")
    }

    pub async fn final_update(&self, id: i64) -> serde_json::Value {
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
    pub async fn accepted_job(&self, n: usize) -> (String, Submission) {
        let (id, sub) = within("a submitted job", self.hub.wait_for_job(n)).await;
        self.hub.accept(&id);
        let gitlab_id = sub.gitlab_job;
        eventually("the commit", || self.committed(gitlab_id)).await;
        (id, sub)
    }

    pub async fn stop(mut self) -> FakeDispatcher {
        self.daemon.stop().await;
        let _ = std::fs::remove_dir_all(&self.state_dir);
        self.hub.clone()
    }
}

pub async fn eventually(what: &str, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub async fn within<T>(what: &str, fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), fut)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}
