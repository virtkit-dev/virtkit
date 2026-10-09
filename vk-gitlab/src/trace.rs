//! [`TraceBuffer`] holds a fleet node's job log byte for byte, with its checksum.
//! [`JobTrace`] (a port of `network/trace.go`, `clientJobTrace`) sends it incrementally,
//! keeps the job alive, relays GitLab's cancel requests and sends the final state.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::api::{
    JobApi, JobCredentials, JobTraceOutput, PatchState, PatchTraceResult, UpdateJobInfo,
    UpdateJobResult, UpdateState,
};
use crate::backoff::Backoff;
use crate::failure::{FailureReason, FailureReasonMapper, JobState};

/// gitlab-runner's `DefaultTraceOutputLimit`, used when a runner sets no `output_limit`.
pub const DEFAULT_OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
/// Room above `output_limit` for what follows the node's cut (its limit notice) and for
/// the runner's own error lines. Output past it is dropped.
pub const OUTPUT_LIMIT_SLACK: usize = 64 * 1024;
/// gitlab-runner's `DefaultTracePatchLimit`: the most one trace patch carries.
pub const DEFAULT_PATCH_LIMIT: usize = 1024 * 1024;
pub const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(3);
pub const MAX_UPDATE_INTERVAL: Duration = Duration::from_secs(15 * 60);
/// How long the job can go without an update before the reporter sends one anyway, to keep
/// it alive on GitLab's side (`MinTraceForceSendInterval`).
pub const FORCE_SEND_INTERVAL: Duration = Duration::from_secs(30);
pub const DEFAULT_FINAL_UPDATE_RETRY_LIMIT: u32 = 10;
pub const DEFAULT_FINAL_UPDATE_BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);
/// Consecutive 416 answers the final flush of the log accepts before giving up on it.
const MAX_RANGE_MISMATCHES: u32 = 5;

/// CRC-32 (IEEE), the log checksum GitLab verifies against its own copy.
#[derive(Debug, Clone)]
struct Crc32(u32);

const CRC_TABLE: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

impl Crc32 {
    fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    fn update(&mut self, data: &[u8]) {
        let mut c = self.0;
        for &b in data {
            c = CRC_TABLE[((c ^ u32::from(b)) & 0xFF) as usize] ^ (c >> 8);
        }
        self.0 = c;
    }

    fn sum(&self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

/// The offset asked for lies past the end of the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidOffset {
    pub written: usize,
    pub offset: usize,
}

impl std::fmt::Display for InvalidOffset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid offset information: offset={}, written={}",
            self.offset, self.written
        )
    }
}

/// The job log sent to GitLab, preserved byte for byte so offsets match the node's.
/// The node masks, fixes up and cuts the log; this buffer checksums it on write and drops
/// output past `ceiling`.
#[derive(Debug)]
pub struct TraceBuffer {
    data: Vec<u8>,
    ceiling: usize,
    crc: Crc32,
}

impl TraceBuffer {
    pub fn new(ceiling: usize) -> Self {
        Self {
            data: Vec::new(),
            ceiling,
            crc: Crc32::new(),
        }
    }

    /// Appends as much of `p` as fits under the ceiling; returns how many bytes were dropped.
    pub fn write(&mut self, p: &[u8]) -> usize {
        let room = self.ceiling.saturating_sub(self.data.len());
        let kept = &p[..p.len().min(room)];
        self.data.extend_from_slice(kept);
        self.crc.update(kept);
        p.len() - kept.len()
    }

    pub fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Bytes `[offset, offset + n)` of the log, fewer at its end.
    pub fn bytes(&self, offset: usize, n: usize) -> Result<&[u8], InvalidOffset> {
        let Some(rest) = self.data.get(offset..) else {
            return Err(InvalidOffset {
                written: self.data.len(),
                offset,
            });
        };
        Ok(&rest[..n.min(rest.len())])
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// `crc32:<8 hex digits>`, as gitlab-runner reports it.
    pub fn checksum(&self) -> String {
        format!("crc32:{:08x}", self.crc.sum())
    }
}

/// What GitLab asked for while the job ran.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RemoteRequests {
    /// `Job-Status: canceling`: stop gracefully (after_script still runs).
    pub cancel: bool,
    /// The job is over on GitLab's side (canceled, failed, gone, or not ours): stop now.
    pub abort: bool,
}

/// Timings and sizes of a [`JobTrace`]; the defaults are gitlab-runner's.
#[derive(Debug, Clone)]
pub struct TraceSettings {
    pub update_interval: Duration,
    pub force_send_interval: Duration,
    pub max_patch_size: usize,
    /// The node's log cap; the buffer holds up to [`OUTPUT_LIMIT_SLACK`] more.
    pub output_limit: usize,
    pub final_update_retry_limit: u32,
    pub final_update_backoff_max: Duration,
    /// `debug_trace` on each patch (`CI_DEBUG_TRACE` / `CI_DEBUG_SERVICES`).
    pub debug_trace: bool,
}

impl Default for TraceSettings {
    fn default() -> Self {
        Self {
            update_interval: DEFAULT_UPDATE_INTERVAL,
            force_send_interval: FORCE_SEND_INTERVAL,
            max_patch_size: DEFAULT_PATCH_LIMIT,
            output_limit: DEFAULT_OUTPUT_LIMIT,
            final_update_retry_limit: DEFAULT_FINAL_UPDATE_RETRY_LIMIT,
            final_update_backoff_max: DEFAULT_FINAL_UPDATE_BACKOFF_MAX,
            debug_trace: false,
        }
    }
}

/// The final update could not be delivered within the retry limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceError {
    InvalidPatchTraceResponse,
    InvalidUpdateJobResponse,
}

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TraceError::InvalidPatchTraceResponse => "received invalid patch trace response",
            TraceError::InvalidUpdateJobResponse => "received invalid job update response",
        })
    }
}

impl std::error::Error for TraceError {}

struct State {
    buffer: TraceBuffer,
    /// Output was dropped at the buffer's ceiling (warned once).
    overflowed: bool,
    /// No more output comes: the job is finishing.
    closed: bool,
    sent: usize,
    sent_time: Option<Instant>,
    update_interval: Duration,
    force_send_interval: Duration,
    job_state: JobState,
    failure_reason: Option<FailureReason>,
    exit_code: i32,
    runtime_environment_key: String,
}

struct Shared<A> {
    api: Arc<A>,
    job: JobCredentials,
    settings: TraceSettings,
    mapper: Option<FailureReasonMapper>,
    state: Mutex<State>,
    remote: watch::Sender<RemoteRequests>,
    finished: watch::Sender<bool>,
}

/// The reporter for one running job.
pub struct JobTrace<A: JobApi> {
    shared: Arc<Shared<A>>,
    watcher: Mutex<Option<JoinHandle<()>>>,
}

impl<A: JobApi> JobTrace<A> {
    /// Starts reporting job `job`: the log is sent in the background every update interval,
    /// byte for byte as a fleet node produced it. `mapper` maps failure reasons onto those
    /// the GitLab instance knows; without one they are sent as given.
    pub fn start(
        api: Arc<A>,
        job: JobCredentials,
        mapper: Option<FailureReasonMapper>,
        settings: TraceSettings,
    ) -> Self {
        Self::resume(api, job, mapper, settings, &[])
    }

    /// Like [`start`](Self::start), but resumes after a restart with the `prefix` GitLab
    /// already holds. The log starts with it and the first patch follows it. A 416
    /// corrects the offset if GitLab holds more.
    pub fn resume(
        api: Arc<A>,
        job: JobCredentials,
        mapper: Option<FailureReasonMapper>,
        settings: TraceSettings,
        prefix: &[u8],
    ) -> Self {
        let mut buffer = TraceBuffer::new(settings.output_limit.saturating_add(OUTPUT_LIMIT_SLACK));
        buffer.write(prefix);
        let sent = buffer.size();
        let state = State {
            buffer,
            overflowed: false,
            closed: false,
            sent,
            sent_time: None,
            update_interval: settings.update_interval,
            force_send_interval: settings.force_send_interval,
            job_state: JobState::Running,
            failure_reason: None,
            exit_code: 0,
            runtime_environment_key: String::new(),
        };
        let shared = Arc::new(Shared {
            api,
            job,
            settings,
            mapper,
            state: Mutex::new(state),
            remote: watch::channel(RemoteRequests::default()).0,
            finished: watch::channel(false).0,
        });
        // Subscribed before the task runs, so a finish that comes first is not missed.
        let finished = shared.finished.subscribe();
        let watcher = tokio::spawn(watch_loop(Arc::clone(&shared), finished));
        Self {
            shared,
            watcher: Mutex::new(Some(watcher)),
        }
    }

    pub fn job(&self) -> &JobCredentials {
        &self.shared.job
    }

    /// Appends job output; output past the buffer's ceiling is dropped.
    pub fn write(&self, data: &[u8]) {
        let mut st = self.shared.lock();
        if st.buffer.write(data) > 0 && !std::mem::replace(&mut st.overflowed, true) {
            log::warn!(job = self.shared.job.id, limit = st.buffer.ceiling(); "Job log is past its output limit; dropping the rest");
        }
    }

    /// How much of the log GitLab has acknowledged.
    pub fn sent(&self) -> usize {
        self.shared.lock().sent
    }

    /// The log's length so far.
    pub fn len(&self) -> usize {
        self.shared.lock().buffer.size()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// GitLab's cancel and abort requests, as they arrive.
    pub fn remote_requests(&self) -> watch::Receiver<RemoteRequests> {
        self.shared.remote.subscribe()
    }

    pub fn set_runtime_environment_key(&self, key: &str) {
        key.clone_into(&mut self.shared.lock().runtime_environment_key);
    }

    pub fn checksum(&self) -> String {
        self.shared.lock().buffer.checksum()
    }

    pub fn bytesize(&self) -> usize {
        self.shared.lock().buffer.size()
    }

    /// The update interval now in force, as GitLab last set it.
    pub fn update_interval(&self) -> Duration {
        self.shared.lock().update_interval
    }

    /// Reports success: sends the rest of the log, then the final state.
    pub async fn success(&self) -> Result<(), TraceError> {
        self.complete(None).await
    }

    /// Reports failure with `reason` (mapped onto what GitLab supports) and `exit_code`.
    pub async fn fail(&self, reason: FailureReason, exit_code: i32) -> Result<(), TraceError> {
        self.complete(Some((reason, exit_code))).await
    }

    /// Stops reporting without a final state: GitLab told the runner the job is not its own
    /// any more.
    pub async fn finish(&self) {
        self.stop_watcher().await;
        self.shared.lock().closed = true;
    }

    async fn complete(&self, failure: Option<(FailureReason, i32)>) -> Result<(), TraceError> {
        {
            let mut st = self.shared.lock();
            if st.job_state != JobState::Running {
                return Ok(());
            }
            match failure {
                None => st.job_state = JobState::Success,
                Some((reason, exit_code)) => {
                    st.job_state = JobState::Failed;
                    st.exit_code = exit_code;
                    st.failure_reason = Some(match &self.shared.mapper {
                        Some(m) => m.map(&reason),
                        None => reason,
                    });
                }
            }
        }
        self.finish().await;
        let mut backoff = Backoff::new(
            Duration::from_secs(1),
            self.shared.settings.final_update_backoff_max,
            2.0,
            false,
        );
        let mut tries = 0;
        loop {
            tries += 1;
            match self.shared.final_update().await {
                Ok(()) => return Ok(()),
                Err(e) if tries >= self.shared.settings.final_update_retry_limit => {
                    log::error!(job = self.shared.job.id, error = e.to_string().as_str(); "Final job update failed");
                    return Err(e);
                }
                Err(e) => {
                    log::warn!(job = self.shared.job.id, error = e.to_string().as_str(); "Retrying...");
                    tokio::time::sleep(backoff.next_delay()).await;
                }
            }
        }
    }

    /// Stops the background sender and waits for an update in flight to finish, so the
    /// final update never races an incremental one.
    async fn stop_watcher(&self) {
        // `send_replace` stores the value even when the watcher has already gone.
        self.shared.finished.send_replace(true);
        let handle = self.watcher.lock().ok().and_then(|mut guard| guard.take());
        if let Some(handle) = handle {
            // A panicked watcher has nothing left to wait for.
            let _ = handle.await;
        }
    }
}

impl<A: JobApi> Drop for JobTrace<A> {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.watcher.lock()
            && let Some(handle) = guard.take()
        {
            handle.abort();
        }
    }
}

async fn watch_loop<A: JobApi>(shared: Arc<Shared<A>>, mut finished: watch::Receiver<bool>) {
    loop {
        let interval = shared.interval();
        let stop = tokio::select! {
            _ = tokio::time::sleep(interval) => false,
            _ = finished.wait_for(|f| *f) => true,
        };
        if stop {
            return;
        }
        if !shared.incremental_update().await {
            let _ = finished.wait_for(|f| *f).await;
            return;
        }
    }
}

impl<A: JobApi> Shared<A> {
    fn lock(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock leaves plain data behind; keep reporting.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn interval(&self) -> Duration {
        self.lock().update_interval
    }

    fn cancel(&self) {
        self.remote
            .send_if_modified(|r| !std::mem::replace(&mut r.cancel, true));
    }

    fn abort(&self) {
        self.remote
            .send_if_modified(|r| !std::mem::replace(&mut r.abort, true));
    }

    fn set_update_interval(&self, seconds: i64) {
        if seconds <= 0 {
            return;
        }
        let d = Duration::from_secs(seconds.unsigned_abs()).min(MAX_UPDATE_INTERVAL);
        self.lock().update_interval = d;
    }

    /// Port of `incrementalUpdate`: false once the job must stop.
    async fn incremental_update(&self) -> bool {
        let patch = self.send_patch().await;
        if patch.cancel_requested {
            self.cancel();
        }
        match patch.state {
            PatchState::Succeeded => {
                let touch = self.touch_job().await;
                if touch.cancel_requested {
                    self.cancel();
                }
                if touch.state == UpdateState::Abort {
                    self.abort();
                    return false;
                }
            }
            PatchState::Abort => {
                self.abort();
                return false;
            }
            _ => {}
        }
        true
    }

    fn any_trace_to_send(&self) -> bool {
        let st = self.lock();
        st.buffer.size() != st.sent
    }

    async fn send_patch(&self) -> PatchTraceResult {
        let (content, sent) = {
            let mut st = self.lock();
            let size = st.buffer.size();
            if st.sent > size {
                // A 416 said GitLab holds more than was written here. More output can still
                // make up the difference; once the log is complete, there is nothing left to
                // send and the final state goes out as is.
                if !st.closed {
                    return PatchTraceResult::new(st.sent, PatchState::Succeeded, 0);
                }
                log::warn!(job = self.job.id, offset = st.sent, written = size; "GitLab holds more of the job log than was written; sending the final state");
                st.sent = size;
                return PatchTraceResult::new(size, PatchState::Succeeded, 0);
            }
            match st.buffer.bytes(st.sent, self.settings.max_patch_size) {
                Ok(c) => (c.to_vec(), st.sent),
                Err(e) => {
                    log::error!(job = self.job.id, offset = e.offset, written = e.written; "Failed to read trace buffer bytes");
                    return PatchTraceResult::new(0, PatchState::Failed, 0);
                }
            }
        };
        if content.is_empty() {
            return PatchTraceResult::new(0, PatchState::Succeeded, 0);
        }
        let result = self
            .api
            .patch_trace(&self.job, &content, sent, self.settings.debug_trace)
            .await;
        self.set_update_interval(result.new_update_interval);
        if matches!(
            result.state,
            PatchState::Succeeded | PatchState::RangeMismatch
        ) {
            let mut st = self.lock();
            st.sent_time = Some(Instant::now());
            st.sent = result.sent_offset;
        }
        result
    }

    /// Port of `touchJob`: a `running` update when nothing was sent for a while.
    async fn touch_job(&self) -> UpdateJobResult {
        let info = {
            let st = self.lock();
            let due = st
                .sent_time
                .is_none_or(|t| t.elapsed() > st.force_send_interval);
            if !due {
                return UpdateJobResult {
                    state: UpdateState::Succeeded,
                    cancel_requested: false,
                    new_update_interval: 0,
                };
            }
            let mut info = UpdateJobInfo::new(self.job.id, JobState::Running);
            info.output = JobTraceOutput {
                checksum: st.buffer.checksum(),
                bytesize: st.buffer.size(),
            };
            info
        };
        let result = self.api.update_job(&self.job, &info).await;
        self.set_update_interval(result.new_update_interval);
        if result.state == UpdateState::Succeeded {
            self.lock().sent_time = Some(Instant::now());
        }
        result
    }

    async fn send_update(&self) -> UpdateState {
        let info = {
            let st = self.lock();
            UpdateJobInfo {
                id: self.job.id,
                state: st.job_state,
                failure_reason: st.failure_reason.clone(),
                output: JobTraceOutput {
                    checksum: st.buffer.checksum(),
                    bytesize: st.buffer.size(),
                },
                exit_code: st.exit_code,
                runtime_environment_key: st.runtime_environment_key.clone(),
            }
        };
        let result = self.api.update_job(&self.job, &info).await;
        self.set_update_interval(result.new_update_interval);
        match result.state {
            UpdateState::Succeeded => self.lock().sent_time = Some(Instant::now()),
            UpdateState::TraceValidationFailed => {
                // GitLab's copy does not match: send the whole log again.
                let mut st = self.lock();
                st.sent_time = Some(Instant::now());
                st.sent = 0;
            }
            _ => {}
        }
        result.state
    }

    async fn ensure_all_trace_sent(&self) -> Result<(), TraceError> {
        let mut mismatches = 0;
        while self.any_trace_to_send() {
            match self.send_patch().await.state {
                PatchState::Succeeded => mismatches = 0,
                PatchState::Abort | PatchState::NotFound => return Ok(()),
                // A 416 that never lets the log through (no usable `Range`, say) must not
                // hold back the final state forever.
                PatchState::RangeMismatch if mismatches >= MAX_RANGE_MISMATCHES => {
                    let mut st = self.lock();
                    log::warn!(job = self.job.id, offset = st.sent, written = st.buffer.size(); "GitLab keeps refusing the job log's range; sending the final state");
                    st.sent = st.buffer.size();
                    return Ok(());
                }
                PatchState::RangeMismatch => {
                    mismatches += 1;
                    tokio::time::sleep(self.interval()).await;
                }
                PatchState::Failed => {
                    tokio::time::sleep(self.interval()).await;
                    return Err(TraceError::InvalidPatchTraceResponse);
                }
            }
        }
        Ok(())
    }

    async fn final_update(&self) -> Result<(), TraceError> {
        self.lock().update_interval = DEFAULT_UPDATE_INTERVAL;
        loop {
            self.ensure_all_trace_sent().await?;
            match self.send_update().await {
                UpdateState::Succeeded | UpdateState::Abort | UpdateState::NotFound => {
                    return Ok(());
                }
                UpdateState::AcceptedButNotCompleted | UpdateState::TraceValidationFailed => {
                    tokio::time::sleep(self.interval()).await;
                }
                UpdateState::Failed => {
                    tokio::time::sleep(self.interval()).await;
                    return Err(TraceError::InvalidUpdateJobResponse);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The checksum expectations are gitlab-runner v19.5.0's (MIT, Copyright (c) 2015-2019
    //! GitLab Inc.): `network/trace_test.go` (TestJobChecksum, TestJobBytesize), and
    //! `helpers/trace/buffer_test.go` (TestReferenceBiggerOffsetThanWritten).
    use super::*;

    // TestReferenceBiggerOffsetThanWritten
    #[test]
    fn reference_bigger_offset_than_written() {
        let mut b = TraceBuffer::new(DEFAULT_OUTPUT_LIMIT);
        b.write(b"test");
        let err = b.bytes(8, 10124).unwrap_err();
        assert_eq!(
            err,
            InvalidOffset {
                written: 4,
                offset: 8
            }
        );
        assert_eq!(b.bytes(4, 10).unwrap(), b"");
    }

    // TestJobChecksum, TestJobBytesize
    #[test]
    fn checksum_and_bytesize() {
        let mut b = TraceBuffer::new(DEFAULT_OUTPUT_LIMIT);
        b.write(b"This is a basic log line");
        assert_eq!(b.checksum(), "crc32:367dfeeb");
        let mut b = TraceBuffer::new(DEFAULT_OUTPUT_LIMIT);
        b.write("Build trace with secret and multi-byte ü character".as_bytes());
        assert_eq!(b.checksum(), "crc32:0d7cf601");
        assert_eq!(b.size(), 51);
    }

    // Not upstream: a fleet node's output is kept byte for byte, so offsets stay the node's.
    #[test]
    fn keeps_every_byte() {
        let mut b = TraceBuffer::new(DEFAULT_OUTPUT_LIMIT);
        b.write(b"a\xff");
        b.write(&[b'x'; 10]);
        assert_eq!(b.size(), 12);
        assert_eq!(b.bytes(0, 2).unwrap(), b"a\xff");
    }

    // Not upstream: output past the ceiling is dropped, and only that.
    #[test]
    fn drops_output_past_the_ceiling() {
        let mut b = TraceBuffer::new(10);
        assert_eq!(b.write(b"12345678"), 0);
        assert_eq!(b.write(b"abcde"), 3);
        assert_eq!(b.write(b"z"), 1);
        assert_eq!(b.bytes(0, 100).unwrap(), b"12345678ab");
        let mut whole = TraceBuffer::new(100);
        whole.write(b"12345678ab");
        assert_eq!(b.checksum(), whole.checksum());
    }
}
