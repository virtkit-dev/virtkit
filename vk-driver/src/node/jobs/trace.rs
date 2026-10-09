//! A placed job's output as GitLab will hold it: masked ([`super::mask`]), with gitlab-runner's
//! section markers and log-line colours, and cut at the trace limit with gitlab-runner's
//! notice. Appended to the job's `output` file, whose length is the offset the node streams to
//! the hub from.
//!
//! The line formats and the limit notice follow gitlab-runner v19.5's
//! `common/buildlogger/internal/tee.go`, `helpers/build_section.go` and `helpers/trace/buffer.go`
//! (MIT; see [`super::mask`] for the notice).

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result};

use super::mask::Masker;

pub const ANSI_BOLD_RED: &str = "\x1b[31;1m";
pub const ANSI_BOLD_GREEN: &str = "\x1b[32;1m";
pub const ANSI_BOLD_YELLOW: &str = "\x1b[33;1m";
pub const ANSI_BOLD_CYAN: &str = "\x1b[36;1m";
pub const ANSI_YELLOW: &str = "\x1b[0;33m";
pub const ANSI_RESET: &str = "\x1b[0;m";
pub const ANSI_CLEAR: &str = "\x1b[0K";

pub struct Trace {
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    masker: Masker,
    /// Bytes in the file.
    written: u64,
    limit: u64,
    /// Past the limit: the notice is written and everything after it dropped.
    cut: bool,
    /// Whether section markers are written (`features.trace_sections`).
    sections: bool,
}

impl Trace {
    /// Append to `path`, which holds `written` bytes already (a driver restarted on the same
    /// output). `phrases` are the masked variables' values, `prefixes` GitLab's token
    /// prefixes.
    pub fn open(
        path: &Path,
        phrases: &[String],
        prefixes: &[String],
        limit: u64,
        sections: bool,
    ) -> Result<Trace> {
        use std::os::unix::fs::OpenOptionsExt;
        let file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        let written = file
            .metadata()
            .with_context(|| format!("reading {}", path.display()))?
            .len();
        Ok(Trace {
            inner: Mutex::new(Inner {
                file,
                masker: Masker::new(phrases, prefixes),
                written,
                limit,
                cut: written >= limit,
                sections,
            }),
        })
    }

    /// Output of the job's own processes: masked, held back no more than a partial match.
    pub fn write(&self, bytes: &[u8]) {
        let mut inner = lock(&self.inner);
        let (masker, mut sink) = inner.split();
        masker.write(bytes, &mut |b| sink.put(b));
    }

    /// Emit whatever a partial match holds back, at the end of a stage.
    pub fn flush(&self) {
        let mut inner = lock(&self.inner);
        let (masker, mut sink) = inner.split();
        masker.flush(&mut |b| sink.put(b));
    }

    /// A log line as gitlab-runner's `Println`: cleared, reset after.
    pub fn print(&self, text: &str) {
        self.line(ANSI_CLEAR, text);
    }

    /// `Infoln`: bold green.
    pub fn notice(&self, text: &str) {
        self.line(ANSI_BOLD_GREEN, text);
    }

    /// `Warningln`.
    pub fn warning(&self, text: &str) {
        self.line(&format!("{ANSI_YELLOW}WARNING: "), text);
    }

    /// `Errorln`.
    pub fn error(&self, text: &str) {
        self.line(&format!("{ANSI_BOLD_RED}ERROR: "), text);
    }

    fn line(&self, prefix: &str, text: &str) {
        self.flush();
        self.write(format!("{prefix}{text}{ANSI_RESET}\n").as_bytes());
        self.flush();
    }

    /// `section_start:<now>:<name>` as gitlab-runner's `BuildSection` writes it, raw — no
    /// mask can apply to it — when the job's GitLab folds sections.
    pub fn section_start(&self, name: &str) {
        self.raw_marker(&format!("section_start:{}:{name}\r{ANSI_CLEAR}", now()));
    }

    pub fn section_end(&self, name: &str) {
        self.raw_marker(&format!("section_end:{}:{name}\r{ANSI_CLEAR}", now()));
    }

    fn raw_marker(&self, marker: &str) {
        self.flush();
        let mut inner = lock(&self.inner);
        if inner.sections {
            inner.split().1.put(marker.as_bytes());
        }
    }

    /// The output's length so far.
    pub fn len(&self) -> u64 {
        lock(&self.inner).written
    }
}

/// Where masked bytes land: the file, up to the limit.
struct Sink<'a> {
    file: &'a mut File,
    written: &'a mut u64,
    limit: u64,
    cut: &'a mut bool,
}

impl Inner {
    /// The masker, and the sink it writes into.
    fn split(&mut self) -> (&mut Masker, Sink<'_>) {
        let sink = Sink {
            file: &mut self.file,
            written: &mut self.written,
            limit: self.limit,
            cut: &mut self.cut,
        };
        (&mut self.masker, sink)
    }
}

impl Sink<'_> {
    /// `limitWriter.Write`: past the limit, cut on a UTF-8 boundary, say so once, and drop the
    /// rest.
    fn put(&mut self, b: &[u8]) {
        if *self.cut {
            return;
        }
        let room = self.limit.saturating_sub(*self.written);
        let take = usize::try_from(room).unwrap_or(usize::MAX);
        if b.len() < take {
            self.append(b);
            return;
        }
        let kept = utf8_cut(b, take);
        self.append(kept);
        *self.cut = true;
        let notice = format!(
            "\n{ANSI_BOLD_YELLOW}Job's log exceeded limit of {} bytes.\nJob execution will \
             continue but no more output will be collected.{ANSI_RESET}\n",
            self.limit
        );
        self.append(notice.as_bytes());
    }

    fn append(&mut self, b: &[u8]) {
        // A write that fails (a full disk) may have stored part of `b`: the offset is the
        // file's length, whatever got through. Nothing else can be done with output nobody
        // can store.
        match self.file.write_all(b) {
            Ok(()) => *self.written = self.written.saturating_add(b.len() as u64),
            Err(_) => {
                if let Ok(meta) = self.file.metadata() {
                    *self.written = meta.len();
                }
            }
        }
    }
}

/// `b` cut to at most `cap` bytes without splitting a UTF-8 sequence (`truncateSafeUTF8`).
fn utf8_cut(b: &[u8], cap: usize) -> &[u8] {
    let mut cap = cap.min(b.len());
    for _ in 0..4 {
        let head = &b[..cap];
        match std::str::from_utf8(head) {
            Err(e) if e.error_len().is_none() && cap > 0 => cap -= 1,
            _ => break,
        }
    }
    &b[..cap]
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-trace-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("output")
    }

    #[test]
    fn lines_are_coloured_and_masked_as_gitlab_runner_writes_them() {
        let path = tmp("lines");
        let trace = Trace::open(&path, &["hunter22".into()], &[], 1 << 20, true).unwrap();
        trace.warning("the password is hunter22");
        trace.write(b"$ echo hunter");
        trace.write(b"22\n");
        trace.flush();
        let out = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            out,
            "\x1b[0;33mWARNING: the password is [MASKED]\x1b[0;m\n$ echo [MASKED]\n"
        );
        assert_eq!(trace.len(), out.len() as u64);
    }

    #[test]
    fn output_past_the_limit_is_cut_with_gitlab_runners_notice() {
        let path = tmp("limit");
        let trace = Trace::open(&path, &[], &[], 9, false).unwrap();
        trace.write("12345678é9".as_bytes());
        trace.write(b"later");
        trace.flush();
        let out = std::fs::read_to_string(&path).unwrap();
        // é is two bytes and would straddle the limit: it goes with the rest.
        assert!(out.starts_with("12345678\n\x1b[33;1mJob's log exceeded limit of 9 bytes."));
        assert!(!out.contains("later"));
    }

    #[test]
    fn a_write_that_fills_the_limit_exactly_is_cut() {
        let path = tmp("exact");
        let trace = Trace::open(&path, &[], &[], 4, false).unwrap();
        trace.write(b"123");
        trace.write(b"4");
        trace.write(b"5");
        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.starts_with("1234\n\x1b[33;1mJob's log exceeded limit of 4 bytes."));
        assert!(!out.contains('5'));
        assert_eq!(trace.len(), out.len() as u64);
    }

    #[test]
    fn a_reopened_output_continues_from_its_length() {
        let path = tmp("reopen");
        std::fs::write(&path, b"earlier\n").unwrap();
        let trace = Trace::open(&path, &[], &[], 1 << 20, false).unwrap();
        assert_eq!(trace.len(), 8);
        trace.write(b"later\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier\nlater\n");
        assert_eq!(trace.len(), 14);
        // An output already at the limit takes nothing more, not even the notice again.
        let trace = Trace::open(&path, &[], &[], 10, false).unwrap();
        trace.write(b"more");
        trace.print("more");
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier\nlater\n");
        assert_eq!(trace.len(), 14);
    }

    #[test]
    fn sections_are_written_only_when_gitlab_folds_them() {
        let path = tmp("sections");
        let trace = Trace::open(&path, &[], &[], 1 << 20, false).unwrap();
        trace.section_start("step_script");
        trace.section_end("step_script");
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        let path = tmp("sections-on");
        let trace = Trace::open(&path, &[], &[], 1 << 20, true).unwrap();
        trace.section_start("step_script");
        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.starts_with("section_start:") && out.ends_with(":step_script\r\x1b[0K"));
    }
}
