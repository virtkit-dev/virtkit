//! No runner or job token reaches a log line, whatever the runner API answers. One test in
//! its own binary: it installs the process's logger.

mod support;

use std::fmt::Write as _;
use std::sync::Mutex;

use log::kv::{self, VisitSource};
use support::{FakeGitLab, Recorded, Reply, client};
use vk_gitlab::api::{JobCredentials, UpdateJobInfo};
use vk_gitlab::failure::JobState;
use vk_gitlab::secret::Secret;

const RUNNER_TOKEN: &str = "glrt-RUNNERSECRET-tail0123456789";
const JOB_TOKEN: &str = "glcbt-JOBSECRET-tail9876543210";
/// A job token no header can carry.
const BAD_JOB_TOKEN: &str = "glcbt-BADSECRET\n-tail5555555555";

static LINES: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

struct Fields<'a>(&'a mut String);

impl<'kvs> VisitSource<'kvs> for Fields<'_> {
    fn visit_pair(&mut self, key: kv::Key<'kvs>, value: kv::Value<'kvs>) -> Result<(), kv::Error> {
        let _ = write!(self.0, " {key}={value}");
        Ok(())
    }
}

impl log::Log for Capture {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        let mut line = record.args().to_string();
        let _ = record.key_values().visit(&mut Fields(&mut line));
        LINES.lock().unwrap().push(line);
    }

    fn flush(&self) {}
}

fn job(token: &str) -> JobCredentials {
    JobCredentials {
        id: 7,
        token: Secret::new(token),
    }
}

async fn exercise(url: &str) {
    let c = client(url, RUNNER_TOKEN, 1);
    let _ = c.verify().await;
    c.request_job().await;
    for token in [JOB_TOKEN, BAD_JOB_TOKEN] {
        c.update_job(&job(token), &UpdateJobInfo::new(7, JobState::Failed))
            .await;
        c.patch_trace(&job(token), b"log", 0, false).await;
        c.patch_trace(&job(token), b"log", 3, false).await;
    }
}

#[tokio::test]
async fn tokens_never_reach_a_log_line() {
    log::set_logger(&Capture).unwrap();
    log::set_max_level(log::LevelFilter::Trace);

    // An undecodable job carrying the job token, then failures on every call.
    let failing = FakeGitLab::start(|r: &Recorded| match r.path.as_str() {
        "/api/v4/jobs/request" => Reply::status(201).json(&format!(
            r#"{{"id": 7, "token": "{JOB_TOKEN}", "variables": "{RUNNER_TOKEN}"}}"#
        )),
        "/api/v4/jobs/7/trace" if r.header("content-range").starts_with("3-") => {
            Reply::status(416).header("Range", "0-1")
        }
        _ => Reply::status(500).json(r#"{"message": "boom"}"#),
    })
    .await;
    exercise(&failing.url).await;

    // Refusals.
    let refusing = FakeGitLab::start(|r: &Recorded| match r.path.as_str() {
        "/api/v4/jobs/7/trace" => Reply::status(404),
        _ => Reply::status(403),
    })
    .await;
    exercise(&refusing.url).await;

    // Nothing listening.
    exercise("http://127.0.0.1:1").await;

    let lines = LINES.lock().unwrap().clone();
    assert!(lines.len() > 20, "too few log lines captured: {lines:#?}");
    for line in &lines {
        for token in [RUNNER_TOKEN, JOB_TOKEN, BAD_JOB_TOKEN] {
            let tail = &token[token.len() - 14..];
            assert!(!line.contains(tail), "a token in a log line: {line}");
        }
    }
    assert!(
        lines.iter().any(|l| l.contains("header=JOB-TOKEN")),
        "the dropped header is reported: {lines:#?}"
    );
}
