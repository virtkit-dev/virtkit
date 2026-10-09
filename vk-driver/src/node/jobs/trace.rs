//! A placed job's output as GitLab will hold it: masked ([`super::mask`]), with gitlab-runner's
//! section markers and log-line colours, its lines timestamped unless the job turns
//! `FF_TIMESTAMPS` off ([`vk_hub_proto::stamp`]), and cut at the trace limit with
//! gitlab-runner's notice. Appended to the job's `output` file, whose length is the offset the
//! node streams to the hub from.
//!
//! As in gitlab-runner's build logger, each stream — the node's own lines, and each executor
//! command's stdout and stderr — is masked and stamped on its own, masked first so no stamp
//! lands inside a secret; the limit counts the stamps, and its notice follows them unstamped.
//!
//! The line formats and the limit notice follow gitlab-runner v19.5's
//! `common/buildlogger/build_logger.go`, `common/buildlogger/internal/tee.go`,
//! `helpers/build_section.go` and `helpers/trace/buffer.go` (MIT; see [`super::mask`] for the
//! notice).

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::{Context, Result};
use vk_hub_proto::stamp::{self, Kind, Stamper};

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
    phrases: Vec<String>,
    prefixes: Vec<String>,
    timestamps: bool,
}

struct Inner {
    file: File,
    /// The node's own lines and the section markers (the build logger's own writer).
    own: Stream,
    /// Bytes in the file.
    written: u64,
    limit: u64,
    /// Past the limit: the notice is written and everything after it dropped.
    cut: bool,
    /// Whether section markers are written (`features.trace_sections`).
    sections: bool,
}

/// One stream of the output (`Logger.Stream`): its masks, then its stamps when the job has
/// them.
pub struct Stream {
    masker: Masker,
    stamper: Option<Stamper>,
    /// Output buffer reused across writes.
    out: Vec<u8>,
}

impl Stream {
    fn new(phrases: &[String], prefixes: &[String], stamps: Option<(u8, Kind)>) -> Stream {
        Stream {
            masker: Masker::new(phrases, prefixes),
            stamper: stamps.map(|(id, kind)| Stamper::new(id, kind)),
            out: Vec::new(),
        }
    }

    /// `p` masked, then stamped, into `out`; a partial match or line held back.
    fn write(&mut self, p: &[u8], out: &mut Vec<u8>) {
        let now = SystemTime::now();
        let stamper = &mut self.stamper;
        self.masker
            .write(p, &mut |b| stamped(stamper.as_mut(), b, now, out));
    }

    /// What the masks hold back, stamped; with `close`, the stream's last line ended too.
    fn flush(&mut self, close: bool, out: &mut Vec<u8>) {
        let now = SystemTime::now();
        let stamper = &mut self.stamper;
        self.masker
            .flush(&mut |b| stamped(stamper.as_mut(), b, now, out));
        if close && let Some(s) = stamper {
            s.close(&mut |b| out.extend_from_slice(b));
        }
    }
}

fn stamped(stamper: Option<&mut Stamper>, b: &[u8], now: SystemTime, out: &mut Vec<u8>) {
    match stamper {
        Some(s) => s.write(b, now, &mut |b| out.extend_from_slice(b)),
        None => out.extend_from_slice(b),
    }
}

impl Trace {
    /// Append to `path`, which holds `written` bytes already (a driver restarted on the same
    /// output). `phrases` are the masked variables' values, `prefixes` GitLab's token
    /// prefixes; `timestamps` stamps every line.
    pub fn open(
        path: &Path,
        phrases: &[String],
        prefixes: &[String],
        limit: u64,
        sections: bool,
        timestamps: bool,
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
        // A line held unterminated (at most 8 KiB and its stamp) dies with the driver, and a
        // reopened trace's streams start on a new line, not a `+` one.
        let own = Stream::new(
            phrases,
            prefixes,
            timestamps.then_some((stamp::STREAM_EXECUTOR, Kind::Stdout)),
        );
        Ok(Trace {
            inner: Mutex::new(Inner {
                file,
                own,
                written,
                limit,
                cut: written >= limit,
                sections,
            }),
            phrases: phrases.to_vec(),
            prefixes: prefixes.to_vec(),
            timestamps,
        })
    }

    /// Whether the lines are stamped.
    pub fn timestamps(&self) -> bool {
        self.timestamps
    }

    /// A stream for one command's stdout or stderr, numbered as gitlab-runner numbers its
    /// executor's ([`stamp::STREAM_EXECUTOR`], [`stamp::STREAM_WORK`]); [`Trace::close`] it
    /// once the command is done.
    pub fn stream(&self, id: u8, kind: Kind) -> Stream {
        Stream::new(
            &self.phrases,
            &self.prefixes,
            self.timestamps.then_some((id, kind)),
        )
    }

    /// A command's output on `stream`.
    pub fn write(&self, stream: &mut Stream, bytes: &[u8]) {
        let mut out = std::mem::take(&mut stream.out);
        stream.write(bytes, &mut out);
        lock(&self.inner).sink().put(&out);
        out.clear();
        stream.out = out;
    }

    /// The end of `stream`: what it holds back, its last line ended.
    pub fn close(&self, mut stream: Stream) {
        let mut out = std::mem::take(&mut stream.out);
        stream.flush(true, &mut out);
        lock(&self.inner).sink().put(&out);
    }

    /// Emit whatever the node's own lines hold back, at the end of a stage.
    pub fn flush(&self) {
        let mut inner = lock(&self.inner);
        let mut out = Vec::new();
        inner.own.flush(true, &mut out);
        inner.sink().put(&out);
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
        let mut inner = lock(&self.inner);
        let mut out = Vec::new();
        inner.own.flush(false, &mut out);
        let line = format!("{prefix}{text}{ANSI_RESET}\n");
        inner.own.write(line.as_bytes(), &mut out);
        inner.own.flush(false, &mut out);
        inner.sink().put(&out);
    }

    /// `section_start:<now>:<name>` as gitlab-runner's `BuildSection` writes it, unmasked — no
    /// mask can apply to it — when the job's GitLab folds sections. Stamped, its carriage
    /// return makes the node's next line a continuation of it, as in gitlab-runner's trace.
    pub fn section_start(&self, name: &str) {
        self.raw_marker(&format!("section_start:{}:{name}\r{ANSI_CLEAR}", now()));
    }

    pub fn section_end(&self, name: &str) {
        self.raw_marker(&format!("section_end:{}:{name}\r{ANSI_CLEAR}", now()));
    }

    fn raw_marker(&self, marker: &str) {
        let mut inner = lock(&self.inner);
        if !inner.sections {
            return;
        }
        let mut out = Vec::new();
        inner.own.flush(false, &mut out);
        stamped(
            inner.own.stamper.as_mut(),
            marker.as_bytes(),
            SystemTime::now(),
            &mut out,
        );
        inner.sink().put(&out);
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
    fn sink(&mut self) -> Sink<'_> {
        Sink {
            file: &mut self.file,
            written: &mut self.written,
            limit: self.limit,
            cut: &mut self.cut,
        }
    }
}

impl Sink<'_> {
    /// `limitWriter.Write`: past the limit, cut on a UTF-8 boundary, say so once, and drop the
    /// rest.
    fn put(&mut self, b: &[u8]) {
        if *self.cut || b.is_empty() {
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

    /// `output` with each line's time replaced by `T`, checking it has the stamp's shape.
    fn untimed(output: &str) -> String {
        output
            .split_inclusive('\n')
            .map(|line| {
                let b = line.as_bytes();
                assert!(
                    b.len() >= stamp::HEADER_LEN
                        && b[4] == b'-'
                        && b[10] == b'T'
                        && b[19] == b'.'
                        && b[26] == b'Z'
                        && b[27] == b' ',
                    "{line:?}"
                );
                format!("T {}", &line[28..])
            })
            .collect()
    }

    #[test]
    fn lines_are_coloured_and_masked_as_gitlab_runner_writes_them() {
        let path = tmp("lines");
        let trace = Trace::open(&path, &["hunter22".into()], &[], 1 << 20, true, false).unwrap();
        trace.warning("the password is hunter22");
        let mut out = trace.stream(stamp::STREAM_WORK, Kind::Stdout);
        trace.write(&mut out, b"$ echo hunter");
        trace.write(&mut out, b"22\n");
        trace.close(out);
        let out = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            out,
            "\x1b[0;33mWARNING: the password is [MASKED]\x1b[0;m\n$ echo [MASKED]\n"
        );
        assert_eq!(trace.len(), out.len() as u64);
    }

    #[test]
    fn stamped_lines_name_their_stream_and_continue_section_markers() {
        let path = tmp("stamped");
        let trace = Trace::open(&path, &["hunter22".into()], &[], 1 << 20, true, true).unwrap();
        trace.print("Running with vk");
        trace.section_start("step_script");
        trace.print("Executing \"step_script\" stage of the job script");
        let mut out = trace.stream(stamp::STREAM_WORK, Kind::Stdout);
        let mut err = trace.stream(stamp::STREAM_WORK, Kind::Stderr);
        // A secret split across writes is masked whole, never cut by a stamp.
        trace.write(&mut out, b"$ echo hun");
        trace.write(&mut err, "warning: é\npartial".as_bytes());
        trace.write(&mut out, b"ter22\n10%\r");
        trace.write(&mut out, b"done\n");
        trace.close(out);
        trace.close(err);
        trace.flush();
        trace.section_end("step_script");
        let raw = std::fs::read_to_string(&path).unwrap();
        assert_eq!(trace.len(), raw.len() as u64);
        let untimed = untimed(&raw);
        let section = |s: &str| {
            let at = untimed.find(s).unwrap() + s.len();
            let secs = &untimed[at..at + 10];
            assert!(secs.bytes().all(|b| b.is_ascii_digit()), "{secs}");
            secs.to_owned()
        };
        let start = section("section_start:");
        let end = section("section_end:");
        assert_eq!(
            untimed,
            format!(
                "T 00O \x1b[0KRunning with vk\x1b[0;m\n\
                 T 00O section_start:{start}:step_script\r\x1b[0K\n\
                 T 00O+\x1b[0KExecuting \"step_script\" stage of the job script\x1b[0;m\n\
                 T 01E warning: é\n\
                 T 01O $ echo [MASKED]\n\
                 T 01O 10%\r\n\
                 T 01O+done\n\
                 T 01E partial\n\
                 T 00O section_end:{end}:step_script\r\x1b[0K\n"
            )
        );
    }

    #[test]
    fn the_limit_counts_the_stamps_and_its_notice_is_not_stamped() {
        let path = tmp("stamped-limit");
        let trace = Trace::open(&path, &[], &[], 40, false, true).unwrap();
        let mut out = trace.stream(stamp::STREAM_WORK, Kind::Stdout);
        trace.write(&mut out, b"12345678\n");
        trace.write(&mut out, b"later\n");
        trace.close(out);
        let raw = std::fs::read_to_string(&path).unwrap();
        // 32 bytes of stamp, the 8 of the line: the newline is past the limit.
        assert!(
            raw[32..].starts_with("12345678\n\x1b[33;1mJob's log exceeded limit of 40 bytes."),
            "{raw:?}"
        );
        assert!(!raw.contains("later"));
        assert_eq!(trace.len(), raw.len() as u64);
    }

    #[test]
    fn output_past_the_limit_is_cut_with_gitlab_runners_notice() {
        let path = tmp("limit");
        let trace = Trace::open(&path, &[], &[], 9, false, false).unwrap();
        let mut out = trace.stream(stamp::STREAM_WORK, Kind::Stdout);
        trace.write(&mut out, "12345678é9".as_bytes());
        trace.write(&mut out, b"later");
        trace.close(out);
        let out = std::fs::read_to_string(&path).unwrap();
        // é is two bytes and would straddle the limit: it goes with the rest.
        assert!(out.starts_with("12345678\n\x1b[33;1mJob's log exceeded limit of 9 bytes."));
        assert!(!out.contains("later"));
    }

    #[test]
    fn a_write_that_fills_the_limit_exactly_is_cut() {
        let path = tmp("exact");
        let trace = Trace::open(&path, &[], &[], 4, false, false).unwrap();
        let mut out = trace.stream(stamp::STREAM_WORK, Kind::Stdout);
        trace.write(&mut out, b"123");
        trace.write(&mut out, b"4");
        trace.write(&mut out, b"5");
        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.starts_with("1234\n\x1b[33;1mJob's log exceeded limit of 4 bytes."));
        assert!(!out.contains('5'));
        assert_eq!(trace.len(), out.len() as u64);
    }

    #[test]
    fn a_reopened_output_continues_from_its_length() {
        let path = tmp("reopen");
        std::fs::write(&path, b"earlier\n").unwrap();
        let trace = Trace::open(&path, &[], &[], 1 << 20, false, false).unwrap();
        assert_eq!(trace.len(), 8);
        let mut out = trace.stream(stamp::STREAM_WORK, Kind::Stdout);
        trace.write(&mut out, b"later\n");
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier\nlater\n");
        assert_eq!(trace.len(), 14);
        // An output already at the limit takes nothing more, not even the notice again.
        let trace = Trace::open(&path, &[], &[], 10, false, true).unwrap();
        let mut out = trace.stream(stamp::STREAM_WORK, Kind::Stdout);
        trace.write(&mut out, b"more");
        trace.close(out);
        trace.print("more");
        assert_eq!(std::fs::read(&path).unwrap(), b"earlier\nlater\n");
        assert_eq!(trace.len(), 14);
    }

    #[test]
    fn sections_are_written_only_when_gitlab_folds_them() {
        let path = tmp("sections");
        let trace = Trace::open(&path, &[], &[], 1 << 20, false, true).unwrap();
        trace.section_start("step_script");
        trace.section_end("step_script");
        assert_eq!(std::fs::read(&path).unwrap(), b"");
        let path = tmp("sections-on");
        let trace = Trace::open(&path, &[], &[], 1 << 20, true, false).unwrap();
        trace.section_start("step_script");
        let out = std::fs::read_to_string(&path).unwrap();
        assert!(out.starts_with("section_start:") && out.ends_with(":step_script\r\x1b[0K"));
    }
}
