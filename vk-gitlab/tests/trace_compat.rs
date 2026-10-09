//! Compatibility tests of the job log reporter.
//!
//! Ported from gitlab-runner v19.5.0 (MIT, Copyright (c) 2015-2019 GitLab Inc.),
//! network/trace_test.go — driven by a scripted `JobApi` in place of upstream's
//! `MockNetwork`, on tokio's paused clock — and network/trace_canceling_integration_test.go,
//! against the fake GitLab. Each test names the upstream test it follows.

mod support;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vk_gitlab::api::{
    JobApi, JobCredentials, PatchState, PatchTraceResult, UpdateJobInfo, UpdateJobResult,
    UpdateState,
};
use vk_gitlab::failure::{FailureReason, JobState};
use vk_gitlab::secret::Secret;
use vk_gitlab::trace::{
    DEFAULT_UPDATE_INTERVAL, JobTrace, MAX_UPDATE_INTERVAL, OUTPUT_LIMIT_SLACK, TraceSettings,
};

#[derive(Debug, Clone, PartialEq)]
enum Call {
    Patch {
        content: Vec<u8>,
        offset: usize,
    },
    /// A `running` update.
    Touch,
    /// A final update.
    Final(UpdateJobInfo),
}

/// Patch and final-update answers are taken in order; running updates (touches) answer
/// from their own queue, `Succeeded` once it is empty, as upstream's optional touch mock.
#[derive(Default)]
struct ScriptedApi {
    patches: Mutex<VecDeque<PatchTraceResult>>,
    touches: Mutex<VecDeque<UpdateJobResult>>,
    finals: Mutex<VecDeque<UpdateJobResult>>,
    calls: Mutex<Vec<Call>>,
}

fn ok_update(state: UpdateState) -> UpdateJobResult {
    UpdateJobResult {
        state,
        cancel_requested: false,
        new_update_interval: 0,
    }
}

impl ScriptedApi {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn patch(&self, r: PatchTraceResult) -> &Self {
        self.patches.lock().unwrap().push_back(r);
        self
    }

    fn touch(&self, r: UpdateJobResult) -> &Self {
        self.touches.lock().unwrap().push_back(r);
        self
    }

    fn final_update(&self, r: UpdateJobResult) -> &Self {
        self.finals.lock().unwrap().push_back(r);
        self
    }

    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn patches_sent(&self) -> Vec<(String, usize)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Patch { content, offset } => {
                    Some((String::from_utf8_lossy(&content).into_owned(), offset))
                }
                _ => None,
            })
            .collect()
    }

    fn finals_sent(&self) -> Vec<UpdateJobInfo> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Final(i) => Some(i),
                _ => None,
            })
            .collect()
    }

    /// Every scripted answer was used.
    fn assert_done(&self) {
        assert!(
            self.patches.lock().unwrap().is_empty(),
            "patch answers left over"
        );
        assert!(
            self.finals.lock().unwrap().is_empty(),
            "final update answers left over"
        );
    }
}

impl JobApi for ScriptedApi {
    async fn patch_trace(
        &self,
        _job: &JobCredentials,
        content: &[u8],
        start: usize,
        _debug_trace: bool,
    ) -> PatchTraceResult {
        self.calls.lock().unwrap().push(Call::Patch {
            content: content.to_vec(),
            offset: start,
        });
        self.patches.lock().unwrap().pop_front().unwrap_or_else(|| {
            panic!(
                "unexpected patch at {start}: {:?}",
                String::from_utf8_lossy(content)
            )
        })
    }

    async fn update_job(&self, _job: &JobCredentials, info: &UpdateJobInfo) -> UpdateJobResult {
        if info.state == JobState::Running {
            assert!(
                info.runtime_environment_key.is_empty(),
                "touches carry no environment key"
            );
            self.calls.lock().unwrap().push(Call::Touch);
            return self
                .touches
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(ok_update(UpdateState::Succeeded));
        }
        self.calls.lock().unwrap().push(Call::Final(info.clone()));
        self.finals
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| panic!("unexpected final update {info:?}"))
    }
}

fn creds() -> JobCredentials {
    JobCredentials {
        id: -1,
        token: Secret::new("token"),
    }
}

fn start(api: &Arc<ScriptedApi>, settings: TraceSettings) -> JobTrace<ScriptedApi> {
    JobTrace::start(Arc::clone(api), creds(), None, settings)
}

fn patch_ok(sent: usize) -> PatchTraceResult {
    PatchTraceResult::new(sent, PatchState::Succeeded, 0)
}

/// Polls `cond` on the paused clock.
async fn eventually(mut cond: impl FnMut() -> bool) {
    for _ in 0..10_000 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("condition not reached");
}

// TestIgnoreStatusChange
#[tokio::test(start_paused = true)]
async fn ignore_status_change() {
    let api = ScriptedApi::new();
    api.final_update(ok_update(UpdateState::Succeeded));
    let t = start(&api, TraceSettings::default());
    t.success().await.unwrap();
    t.fail(FailureReason::script_failure(), 1).await.unwrap();
    let finals = api.finals_sent();
    assert_eq!(finals.len(), 1, "just one status");
    assert_eq!(finals[0].state, JobState::Success);
}

// TestClientJobTrace_RuntimeEnvironmentKey_InFinalUpdate
#[tokio::test(start_paused = true)]
async fn runtime_environment_key_in_final_update() {
    for key in [
        "27/sys-1/namespace=gitlab-runner&pvc=gl-runner-env-abc123",
        "",
    ] {
        let api = ScriptedApi::new();
        api.final_update(ok_update(UpdateState::Succeeded));
        let t = start(&api, TraceSettings::default());
        if !key.is_empty() {
            t.set_runtime_environment_key(key);
        }
        t.success().await.unwrap();
        assert_eq!(api.finals_sent()[0].runtime_environment_key, key);
    }
}

// TestTouchJobAbort
#[tokio::test(start_paused = true)]
async fn touch_job_abort() {
    let api = ScriptedApi::new();
    api.touch(ok_update(UpdateState::Abort))
        .final_update(ok_update(UpdateState::Abort));
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::ZERO,
            ..Default::default()
        },
    );
    let mut remote = t.remote_requests();
    let r = *remote.wait_for(|r| r.abort).await.unwrap();
    assert!(!r.cancel, "should not cancel job");
    t.success().await.unwrap();
    assert_eq!(
        api.calls(),
        [Call::Touch, Call::Final(api.finals_sent()[0].clone())]
    );
}

// TestTouchJobCancel
#[tokio::test(start_paused = true)]
async fn touch_job_cancel() {
    let api = ScriptedApi::new();
    api.touch(UpdateJobResult {
        cancel_requested: true,
        ..ok_update(UpdateState::Succeeded)
    })
    .final_update(UpdateJobResult {
        cancel_requested: true,
        ..ok_update(UpdateState::Succeeded)
    });
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::ZERO,
            ..Default::default()
        },
    );
    let mut remote = t.remote_requests();
    let r = *remote.wait_for(|r| r.cancel).await.unwrap();
    assert!(!r.abort);
    t.success().await.unwrap();
    api.assert_done();
}

// TestSendPatchAbort
#[tokio::test(start_paused = true)]
async fn send_patch_abort() {
    let api = ScriptedApi::new();
    // aborted on the incremental patch, then again on the final one
    api.patch(PatchTraceResult::new(0, PatchState::Abort, 0))
        .patch(PatchTraceResult::new(0, PatchState::Abort, 0))
        .final_update(ok_update(UpdateState::Abort));
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::from_micros(1),
            ..Default::default()
        },
    );
    t.write(b"Trace\n");
    let mut remote = t.remote_requests();
    remote.wait_for(|r| r.abort).await.unwrap();
    t.success().await.unwrap();
    api.assert_done();
}

// Not upstream (the node cuts the log at `output_limit`): output past the limit plus
// the slack is dropped.
#[tokio::test(start_paused = true)]
async fn output_past_the_ceiling_is_dropped() {
    let ceiling = 1024 + OUTPUT_LIMIT_SLACK;
    let api = ScriptedApi::new();
    api.patch(patch_ok(ceiling))
        .final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            // prevent any update before success()
            update_interval: Duration::from_secs(25),
            output_limit: 1024,
            ..Default::default()
        },
    );
    for _ in 0..ceiling / 5 + 100 {
        t.write(b"abcde");
    }
    t.success().await.unwrap();
    let (sent, _) = &api.patches_sent()[0];
    assert_eq!(sent.len(), ceiling);
    assert_eq!(api.finals_sent()[0].output.bytesize, ceiling);
    api.assert_done();
}

// TestJobFinishTraceUpdateRetry
#[tokio::test(start_paused = true)]
async fn job_finish_trace_update_retry() {
    let api = ScriptedApi::new();
    api.patch(patch_ok(3)) // accept just 3 bytes
        .patch(PatchTraceResult::new(0, PatchState::Failed, 0)) // retry the next ones
        .patch(patch_ok(9)) // accept 6 more
        .patch(PatchTraceResult::new(6, PatchState::RangeMismatch, 0)) // restart from 6
        .patch(patch_ok(13))
        .final_update(ok_update(UpdateState::Succeeded));
    let t = start(&api, TraceSettings::default());
    t.write(b"My trace send");
    t.success().await.unwrap();
    assert_eq!(
        api.patches_sent(),
        [
            ("My trace send".to_owned(), 0),
            ("trace send".to_owned(), 3),
            ("trace send".to_owned(), 3),
            ("send".to_owned(), 9),
            ("ce send".to_owned(), 6),
        ]
    );
    api.assert_done();
}

// TestJobDelayedTraceProcessingWithRejection
#[tokio::test(start_paused = true)]
async fn job_delayed_trace_processing_with_rejection() {
    let api = ScriptedApi::new();
    let chunks = |api: &ScriptedApi| {
        api.patch(PatchTraceResult::new(10, PatchState::Succeeded, 1))
            .patch(PatchTraceResult::new(13, PatchState::Succeeded, 1));
    };
    let not_yet = UpdateJobResult {
        new_update_interval: 1,
        ..ok_update(UpdateState::AcceptedButNotCompleted)
    };
    chunks(&api);
    api.final_update(not_yet).final_update(not_yet);
    api.final_update(UpdateJobResult {
        new_update_interval: 1,
        ..ok_update(UpdateState::TraceValidationFailed)
    });
    chunks(&api);
    api.final_update(not_yet).final_update(not_yet);
    api.final_update(UpdateJobResult {
        new_update_interval: 1,
        ..ok_update(UpdateState::Succeeded)
    });
    let t = start(
        &api,
        TraceSettings {
            max_patch_size: 10,
            ..Default::default()
        },
    );
    t.write(b"My trace send");
    t.success().await.unwrap();
    let chunk_calls = [("My trace s".to_owned(), 0), ("end".to_owned(), 10)];
    assert_eq!(
        api.patches_sent(),
        [chunk_calls.clone(), chunk_calls].concat()
    );
    assert_eq!(api.finals_sent().len(), 6);
    api.assert_done();
}

// TestJobMaxTracePatchSize
#[tokio::test(start_paused = true)]
async fn job_max_trace_patch_size() {
    let api = ScriptedApi::new();
    api.patch(patch_ok(5))
        .patch(patch_ok(10))
        .patch(patch_ok(13))
        .final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::from_millis(10),
            max_patch_size: 5,
            ..Default::default()
        },
    );
    t.write(b"My trace send");
    t.success().await.unwrap();
    assert_eq!(
        api.patches_sent(),
        [
            ("My tr".to_owned(), 0),
            ("ace s".to_owned(), 5),
            ("end".to_owned(), 10)
        ]
    );
}

// TestJobFinishStatusUpdateRetry
#[tokio::test(start_paused = true)]
async fn job_finish_status_update_retry() {
    let api = ScriptedApi::new();
    for _ in 0..5 {
        api.final_update(ok_update(UpdateState::Failed));
    }
    api.final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            final_update_backoff_max: Duration::from_secs(1),
            ..Default::default()
        },
    );
    t.success().await.unwrap();
    assert_eq!(api.finals_sent().len(), 6);
}

// Not upstream: the final update gives up after the retry limit.
#[tokio::test(start_paused = true)]
async fn final_update_gives_up_after_the_limit() {
    let api = ScriptedApi::new();
    for _ in 0..3 {
        api.final_update(ok_update(UpdateState::Failed));
    }
    let t = start(
        &api,
        TraceSettings {
            final_update_retry_limit: 3,
            ..Default::default()
        },
    );
    assert!(t.success().await.is_err());
    assert_eq!(api.finals_sent().len(), 3);
}

// TestJobIncrementalPatchSend
#[tokio::test(start_paused = true)]
async fn job_incremental_patch_send() {
    let api = ScriptedApi::new();
    api.patch(patch_ok(10))
        .final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    t.write(b"123456789\n");
    eventually(|| !api.patches_sent().is_empty()).await;
    t.success().await.unwrap();
    assert_eq!(api.patches_sent(), [("123456789\n".to_owned(), 0)]);
    api.assert_done();
}

// TestJobIncrementalStatusRefresh
#[tokio::test(start_paused = true)]
async fn job_incremental_status_refresh() {
    let api = ScriptedApi::new();
    api.final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    eventually(|| api.calls().contains(&Call::Touch)).await;
    t.success().await.unwrap();
    assert_eq!(api.finals_sent().len(), 1);
}

// TestCancelingJobIncrementalUpdate
#[tokio::test(start_paused = true)]
async fn canceling_job_incremental_update() {
    for patch_canceling in [false, true] {
        let api = ScriptedApi::new();
        api.patch(PatchTraceResult {
            cancel_requested: patch_canceling,
            ..patch_ok(10)
        });
        let canceling_touch = UpdateJobResult {
            cancel_requested: true,
            ..ok_update(UpdateState::Succeeded)
        };
        // When the update asked for a cancel, the log keeps flowing.
        api.touch(canceling_touch).touch(canceling_touch);
        api.patch(PatchTraceResult {
            cancel_requested: true,
            ..patch_ok(20)
        });
        for _ in 0..100 {
            api.touch(canceling_touch);
        }
        api.final_update(ok_update(UpdateState::Succeeded));
        let t = start(
            &api,
            TraceSettings {
                update_interval: Duration::from_millis(10),
                max_patch_size: 10,
                force_send_interval: Duration::from_millis(1),
                ..Default::default()
            },
        );
        t.write(b"123456789\n987654321\n");
        eventually(|| {
            let calls = api.calls();
            calls.iter().filter(|c| **c == Call::Touch).count() >= 2
                && calls
                    .iter()
                    .filter(|c| matches!(c, Call::Patch { .. }))
                    .count()
                    >= 2
        })
        .await;
        assert!(t.remote_requests().borrow().cancel);
        t.success().await.unwrap();
        assert_eq!(
            api.patches_sent(),
            [
                ("123456789\n".to_owned(), 0),
                ("987654321\n".to_owned(), 10)
            ]
        );
    }
}

// TestUpdateIntervalChanges: the sendPatch and finalStatusUpdate cases.
#[tokio::test(start_paused = true)]
async fn update_interval_changes() {
    let initial = Duration::from_millis(10);
    let over_limit = i64::try_from(MAX_UPDATE_INTERVAL.as_secs()).unwrap() + 10;
    let cases = [
        (
            -10,
            PatchState::Succeeded,
            UpdateState::Succeeded,
            initial,
            DEFAULT_UPDATE_INTERVAL,
        ),
        (
            0,
            PatchState::Succeeded,
            UpdateState::Succeeded,
            initial,
            DEFAULT_UPDATE_INTERVAL,
        ),
        (
            10,
            PatchState::Succeeded,
            UpdateState::Succeeded,
            Duration::from_secs(10),
            Duration::from_secs(10),
        ),
        (
            10,
            PatchState::Abort,
            UpdateState::Abort,
            Duration::from_secs(10),
            Duration::from_secs(10),
        ),
        (
            over_limit,
            PatchState::Succeeded,
            UpdateState::Succeeded,
            MAX_UPDATE_INTERVAL,
            MAX_UPDATE_INTERVAL,
        ),
    ];
    for (requested, patch_state, update_state, after_patch, after_final) in cases {
        // sendPatch
        let api = ScriptedApi::new();
        api.patch(PatchTraceResult::new(11, patch_state, requested));
        if patch_state != PatchState::Succeeded {
            api.patch(patch_ok(11));
        }
        api.final_update(ok_update(UpdateState::Succeeded));
        let t = start(
            &api,
            TraceSettings {
                update_interval: initial,
                ..Default::default()
            },
        );
        assert_eq!(t.update_interval(), initial);
        t.write(b"Test trace\n");
        eventually(|| t.update_interval() == after_patch && !api.patches_sent().is_empty()).await;
        t.success().await.unwrap();

        // finalStatusUpdate
        let api = ScriptedApi::new();
        api.final_update(UpdateJobResult {
            new_update_interval: requested,
            ..ok_update(update_state)
        });
        let t = start(
            &api,
            TraceSettings {
                update_interval: initial,
                ..Default::default()
            },
        );
        t.success().await.unwrap();
        assert_eq!(t.update_interval(), after_final, "requested {requested}");
    }
}

// TestJobChecksum
#[tokio::test(start_paused = true)]
async fn job_checksum() {
    let msg = "This is a basic log line";
    let api = ScriptedApi::new();
    api.patch(patch_ok(24))
        .final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            max_patch_size: 22,
            ..Default::default()
        },
    );
    t.write(msg.as_bytes());
    t.success().await.unwrap();
    assert_eq!(api.patches_sent(), [(msg[..22].to_owned(), 0)]);
    let f = &api.finals_sent()[0];
    assert_eq!(f.state, JobState::Success);
    assert_eq!(f.output.checksum, "crc32:367dfeeb");
    assert_eq!(f.output.bytesize, msg.len());
}

// TestJobBytesize
#[tokio::test(start_paused = true)]
async fn job_bytesize() {
    let msg = "Build trace with secret and multi-byte ü character";
    let api = ScriptedApi::new();
    api.patch(patch_ok(msg.len()))
        .final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            max_patch_size: 100,
            ..Default::default()
        },
    );
    t.write(msg.as_bytes());
    t.success().await.unwrap();
    let f = &api.finals_sent()[0];
    assert_eq!(f.output.checksum, "crc32:0d7cf601");
    assert_eq!(f.output.bytesize, 51);
}

// Not upstream: a 416 pointing past the end of the log while the job runs waits for more
// output, then sends from GitLab's offset.
#[tokio::test(start_paused = true)]
async fn range_past_the_log_waits_for_output() {
    let api = ScriptedApi::new();
    api.patch(PatchTraceResult::new(5, PatchState::RangeMismatch, 0))
        .patch(patch_ok(7))
        .final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::from_millis(10),
            ..Default::default()
        },
    );
    t.write(b"abc");
    eventually(|| api.patches_sent().len() == 1).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        api.patches_sent().len(),
        1,
        "nothing to send below GitLab's offset"
    );
    t.write(b"defg");
    eventually(|| api.patches_sent().len() == 2).await;
    t.success().await.unwrap();
    assert_eq!(
        api.patches_sent(),
        [("abc".to_owned(), 0), ("fg".to_owned(), 5)]
    );
    assert_eq!(api.finals_sent()[0].output.bytesize, 7);
    api.assert_done();
}

// Not upstream: a 416 pointing past the end of a complete log does not hold back the
// final state.
#[tokio::test(start_paused = true)]
async fn range_past_the_complete_log_sends_the_final_state() {
    let api = ScriptedApi::new();
    api.patch(PatchTraceResult::new(100, PatchState::RangeMismatch, 0))
        .final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::from_secs(25),
            ..Default::default()
        },
    );
    t.write(b"abc");
    t.success().await.unwrap();
    assert_eq!(api.patches_sent(), [("abc".to_owned(), 0)]);
    let f = &api.finals_sent()[0];
    assert_eq!(f.state, JobState::Success);
    assert_eq!(f.output.bytesize, 3);
    api.assert_done();
}

// Not upstream: a 416 that keeps sending the log back to the start (no usable `Range`)
// gives up on the log after a few tries and sends the final state.
#[tokio::test(start_paused = true)]
async fn endless_range_mismatch_sends_the_final_state() {
    let api = ScriptedApi::new();
    for _ in 0..6 {
        api.patch(PatchTraceResult::new(0, PatchState::RangeMismatch, 0));
    }
    api.final_update(ok_update(UpdateState::Succeeded));
    let t = start(
        &api,
        TraceSettings {
            update_interval: Duration::from_secs(25),
            ..Default::default()
        },
    );
    t.write(b"abc");
    t.success().await.unwrap();
    assert_eq!(api.patches_sent().len(), 6);
    assert_eq!(api.finals_sent().len(), 1);
    api.assert_done();
}

// --- network/trace_canceling_integration_test.go ---------------------------------------

// TestCancelingJobReportsFinalState
#[tokio::test]
async fn canceling_job_reports_final_state() {
    use support::{FakeGitLab, Recorded, Reply};
    for (first_status, first_code, cancel) in [(Some("canceling"), 200, true), (None, 403, false)] {
        let first = Arc::new(Mutex::new(true));
        let f2 = Arc::clone(&first);
        let s = FakeGitLab::start(move |r: &Recorded| {
            assert_eq!(r.method, "PUT");
            assert_eq!(r.path, "/api/v4/jobs/123");
            let mut first = f2.lock().unwrap();
            if *first {
                *first = false;
                let reply = Reply::status(first_code).header("X-Request-Id", "foobar");
                return match first_status {
                    Some(st) => reply.header("Job-Status", st),
                    None => reply,
                };
            }
            Reply::status(200)
        })
        .await;
        let client = Arc::new(support::client(&s.url, "runner", 1));
        let creds = JobCredentials {
            id: 123,
            token: Secret::new("token"),
        };
        let t = JobTrace::start(
            Arc::clone(&client),
            creds.clone(),
            None,
            TraceSettings::default(),
        );
        let first_update = client
            .update_job(&creds, &UpdateJobInfo::new(123, JobState::Running))
            .await;
        if cancel {
            assert!(
                first_update.cancel_requested,
                "server should request cancel"
            );
            assert_eq!(first_update.state, UpdateState::Succeeded);
            t.fail(FailureReason::new(FailureReason::JOB_CANCELED), 0)
                .await
                .unwrap();
        } else {
            assert_eq!(first_update.state, UpdateState::Abort);
            t.finish().await;
        }
        let states: Vec<(String, String)> = s
            .requests()
            .iter()
            .map(|r| {
                let b = r.json();
                (
                    b["state"].as_str().unwrap_or("").to_owned(),
                    b["failure_reason"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect();
        let mut expected = vec![("running".to_owned(), String::new())];
        if cancel {
            expected.push(("failed".to_owned(), "job_canceled".to_owned()));
        }
        assert_eq!(states, expected);
    }
}
