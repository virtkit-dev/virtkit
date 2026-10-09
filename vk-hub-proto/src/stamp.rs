//! A job's log lines timestamped as gitlab-runner stamps its trace (`FF_TIMESTAMPS`, on by
//! default), so GitLab shows when each line came. Every line starts with a 32-byte header:
//!
//! ```text
//! 2026-10-09T12:10:43.123456Z 01O <line>
//! ```
//!
//! the time in UTC to the microsecond, the stream (two hex digits: 00 for the runner's own lines
//! and the executor's preparation, 01 for the job's scripts), `O` for stdout or `E` for stderr,
//! and ` `, or `+` when the line continues the stream's last one. A line is cut where the
//! output has a newline, after a write holding a carriage return but no newline (a progress
//! bar), and when 8 KiB pile up without either; the cut line's rest follows as `+` lines.
//!
//! Whoever receives the output stamps it, before it is stored: the time is when it arrived.
//! The stamps are bytes of the output like any other, counted against its limit.
//!
//! Ported from gitlab-runner v19.5's `common/buildlogger/internal/timestamper` and the flag's
//! resolution in `common/build_settings.go`. gitlab-runner is Copyright (c) 2015-2019 GitLab
//! Inc., under the MIT License: permission is hereby granted, free of charge, to any person
//! obtaining a copy of this software and associated documentation files (the "Software"), to
//! deal in the Software without restriction, including without limitation the rights to use,
//! copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
//! and to permit persons to whom the Software is furnished to do so, subject to the following
//! conditions: The above copyright notice and this permission notice shall be included in all
//! copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT
//! WARRANTY OF ANY KIND.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::job::parse_bool;

/// The job variable that turns the stamps off (`false`) or on.
pub const FLAG: &str = "FF_TIMESTAMPS";

/// Whether a job is stamped when its variables do not say.
pub const DEFAULT: bool = true;

/// gitlab-runner's own lines and the executor's preparation (`StreamExecutorLevel`).
pub const STREAM_EXECUTOR: u8 = 0;
/// The job's scripts (`StreamWorkLevel`).
pub const STREAM_WORK: u8 = 1;

/// The bytes a header takes.
pub const HEADER_LEN: usize = 32;
/// The bytes of a header's date and time to the second, with the `.` after them.
const DATE_TIME_LEN: usize = 20;

/// Held for a line with neither newline nor carriage return before it is cut (`bufSize`).
const LINE_BUF: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Stdout,
    Stderr,
}

/// Whether a job is stamped, from its `FF_TIMESTAMPS` value (`None` or empty when unset). A
/// value Go's `strconv.ParseBool` rejects leaves the default, with gitlab-runner's warning.
pub fn enabled(value: Option<&str>) -> (bool, Option<String>) {
    let Some(raw) = value.filter(|v| !v.is_empty()) else {
        return (DEFAULT, None);
    };
    match parse_bool(raw) {
        Some(on) => (on, None),
        None => (
            DEFAULT,
            Some(format!(
                "{FLAG}: could not parse feature flag, expected bool, got {raw}"
            )),
        ),
    }
}

/// The header of a line written at `now`; `continued` for a `+` line.
pub fn header(now: SystemTime, stream: u8, kind: Kind, continued: bool) -> [u8; HEADER_LEN] {
    let d = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    compose(
        &date_time(d.as_secs()),
        d.subsec_micros(),
        stream,
        kind,
        continued,
    )
}

/// `YYYY-MM-DDTHH:MM:SS.`, `secs` after the epoch: what a header changes once a second.
fn date_time(secs: u64) -> [u8; DATE_TIME_LEN] {
    let (year, month, day) = civil(i64::try_from(secs / 86_400).unwrap_or(0));
    let rem = secs % 86_400;
    let mut t = [0u8; DATE_TIME_LEN];
    digits(&mut t[0..4], u64::try_from(year).unwrap_or(0));
    digits(&mut t[5..7], month);
    digits(&mut t[8..10], day);
    digits(&mut t[11..13], rem / 3600);
    digits(&mut t[14..16], rem % 3600 / 60);
    digits(&mut t[17..19], rem % 60);
    for (at, c) in [
        (4, b'-'),
        (7, b'-'),
        (10, b'T'),
        (13, b':'),
        (16, b':'),
        (19, b'.'),
    ] {
        t[at] = c;
    }
    t
}

/// A header from its date and time to the second, and the rest.
fn compose(
    date_time: &[u8; DATE_TIME_LEN],
    micros: u32,
    stream: u8,
    kind: Kind,
    continued: bool,
) -> [u8; HEADER_LEN] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut h = [0u8; HEADER_LEN];
    h[..DATE_TIME_LEN].copy_from_slice(date_time);
    digits(&mut h[20..26], u64::from(micros));
    h[26] = b'Z';
    h[27] = b' ';
    h[28] = HEX[usize::from(stream >> 4)];
    h[29] = HEX[usize::from(stream & 0xf)];
    h[30] = match kind {
        Kind::Stdout => b'O',
        Kind::Stderr => b'E',
    };
    h[31] = if continued { b'+' } else { b' ' };
    h
}

/// `n` in decimal, zero-padded to fill `out`.
fn digits(out: &mut [u8], mut n: u64) {
    for b in out.iter_mut().rev() {
        *b = b'0' + (n % 10) as u8;
        n /= 10;
    }
}

/// Stamp the runner's own lines in `p` at `now` using gitlab-runner's logger format
/// (stream 00, stdout). Add a final newline if missing.
pub fn own_lines(p: &[u8], now: SystemTime) -> Vec<u8> {
    let mut s = Stamper::new(STREAM_EXECUTOR, Kind::Stdout);
    let mut out = Vec::new();
    s.write(p, now, &mut |b| out.extend_from_slice(b));
    s.close(&mut |b| out.extend_from_slice(b));
    out
}

/// Days since 1970-01-01 as a proleptic Gregorian date (Howard Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, u64, u64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (
        year,
        u64::try_from(month).unwrap_or(0),
        u64::try_from(day).unwrap_or(0),
    )
}

/// One stream's lines stamped, write by write (`timestamper.Logger`).
pub struct Stamper {
    stream: u8,
    kind: Kind,
    /// The line held until it ends: its header and what came of it so far.
    buf: Vec<u8>,
    /// The next header is a `+` one.
    continued: bool,
    /// The second of the last header and its [`date_time`], as gitlab-runner caches it.
    second: Option<(u64, [u8; DATE_TIME_LEN])>,
}

impl Stamper {
    pub fn new(stream: u8, kind: Kind) -> Stamper {
        Stamper {
            stream,
            kind,
            buf: Vec::new(),
            continued: false,
            second: None,
        }
    }

    /// `p`, written at `now`: what is ready to store goes to `out`, a line not ended yet is
    /// held.
    pub fn write(&mut self, p: &[u8], now: SystemTime, out: &mut dyn FnMut(&[u8])) {
        let mut n = 0;
        // Each line ended in `p`: the held one first, completed.
        while let Some(i) = p[n..].iter().position(|&b| b == b'\n') {
            let line = &p[n..=n + i];
            if self.buf.is_empty() {
                out(&self.header(now));
            } else {
                out(&self.buf);
                self.buf.clear();
            }
            out(line);
            n += i + 1;
        }
        let rest = &p[n..];
        if rest.is_empty() {
            return;
        }
        // A carriage return: the whole rest goes out as a line now, continued by the next.
        if rest.contains(&b'\r') {
            if self.buf.is_empty() {
                out(&self.header(now));
            } else {
                out(&self.buf);
                self.buf.clear();
            }
            out(rest);
            out(b"\n");
            self.continued = true;
            return;
        }
        if rest.len() + self.buf.len() > LINE_BUF {
            if self.buf.is_empty() {
                out(&self.header(now));
            } else {
                out(&self.buf);
                self.buf.clear();
            }
            self.continued = true;
            out(rest);
            out(b"\n");
            return;
        }
        if self.buf.is_empty() {
            let h = self.header(now);
            self.buf.extend_from_slice(&h);
        }
        self.buf.extend_from_slice(rest);
    }

    /// The held line, ended: when the stream closes.
    pub fn close(&mut self, out: &mut dyn FnMut(&[u8])) {
        if self.buf.is_empty() {
            return;
        }
        self.buf.push(b'\n');
        out(&self.buf);
        self.buf.clear();
    }

    /// The next line's header; the line after it is a new one.
    fn header(&mut self, now: SystemTime) -> [u8; HEADER_LEN] {
        let d = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = d.as_secs();
        let date_time = match self.second {
            Some((s, t)) if s == secs => t,
            _ => {
                let t = date_time(secs);
                self.second = Some((secs, t));
                t
            }
        };
        let h = compose(
            &date_time,
            d.subsec_micros(),
            self.stream,
            self.kind,
            self.continued,
        );
        self.continued = false;
        h
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    /// 2026-10-09T12:10:43.123456Z.
    fn at(micros: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_micros(1_791_547_843_123_456 + micros)
    }

    fn stamped(stamper: &mut Stamper, writes: &[&[u8]]) -> String {
        let mut out = Vec::new();
        for (i, w) in writes.iter().enumerate() {
            stamper.write(w, at(i as u64), &mut |b| out.extend_from_slice(b));
        }
        stamper.close(&mut |b| out.extend_from_slice(b));
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn headers_are_gitlab_runners() {
        assert_eq!(
            &header(at(0), STREAM_WORK, Kind::Stdout, false),
            b"2026-10-09T12:10:43.123456Z 01O "
        );
        assert_eq!(
            &header(UNIX_EPOCH, 0xab, Kind::Stderr, true),
            b"1970-01-01T00:00:00.000000Z abE+"
        );
        // Leap day, and the microseconds truncated, not rounded.
        let leap = UNIX_EPOCH + Duration::from_nanos(951_782_400_000_000_999);
        assert_eq!(
            &header(leap, 0, Kind::Stdout, false),
            b"2000-02-29T00:00:00.000000Z 00O "
        );
    }

    #[test]
    fn each_line_is_stamped_and_a_partial_one_held_until_it_ends() {
        let mut s = Stamper::new(STREAM_WORK, Kind::Stdout);
        let mut out = Vec::new();
        s.write(b"one\ntw", at(0), &mut |b| out.extend_from_slice(b));
        assert_eq!(out, b"2026-10-09T12:10:43.123456Z 01O one\n");
        // The held line keeps the time it started at.
        s.write(b"o\nthree\n", at(5), &mut |b| out.extend_from_slice(b));
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "2026-10-09T12:10:43.123456Z 01O one\n\
             2026-10-09T12:10:43.123456Z 01O two\n\
             2026-10-09T12:10:43.123461Z 01O three\n"
        );
    }

    #[test]
    fn a_new_second_gets_its_own_date_and_time() {
        let mut s = Stamper::new(STREAM_WORK, Kind::Stdout);
        assert_eq!(
            stamped(&mut s, &[b"a\n"]),
            "2026-10-09T12:10:43.123456Z 01O a\n"
        );
        let mut out = Vec::new();
        s.write(b"b\n", at(1_000_000), &mut |b| out.extend_from_slice(b));
        assert_eq!(out, b"2026-10-09T12:10:44.123456Z 01O b\n");
    }

    #[test]
    fn a_line_left_open_is_ended_on_close() {
        let mut s = Stamper::new(STREAM_EXECUTOR, Kind::Stderr);
        assert_eq!(
            stamped(&mut s, &[b"no newline"]),
            "2026-10-09T12:10:43.123456Z 00E no newline\n"
        );
    }

    #[test]
    fn a_carriage_return_sends_the_write_out_whole_and_continues_it() {
        let mut s = Stamper::new(STREAM_WORK, Kind::Stdout);
        assert_eq!(
            stamped(&mut s, &[b"10%\r", b"50%\r\x1b[0K", b"done\n", b"next\n"]),
            "2026-10-09T12:10:43.123456Z 01O 10%\r\n\
             2026-10-09T12:10:43.123457Z 01O+50%\r\x1b[0K\n\
             2026-10-09T12:10:43.123458Z 01O+done\n\
             2026-10-09T12:10:43.123459Z 01O next\n"
        );
        // A held line goes out with the write that brings the carriage return.
        let mut s = Stamper::new(STREAM_WORK, Kind::Stdout);
        assert_eq!(
            stamped(&mut s, &[b"a", b"b\rc"]),
            "2026-10-09T12:10:43.123456Z 01O ab\rc\n"
        );
        // A carriage return before a newline is the line's own.
        let mut s = Stamper::new(STREAM_WORK, Kind::Stdout);
        assert_eq!(
            stamped(&mut s, &[b"a\r\nb"]),
            "2026-10-09T12:10:43.123456Z 01O a\r\n2026-10-09T12:10:43.123456Z 01O b\n"
        );
    }

    #[test]
    fn a_long_line_is_cut_and_continued() {
        let mut s = Stamper::new(STREAM_WORK, Kind::Stdout);
        let big = vec![b'x'; LINE_BUF - 1];
        let out = stamped(&mut s, &[&big, b"yz", b"end\n"]);
        let want = format!(
            "2026-10-09T12:10:43.123456Z 01O {}yz\n2026-10-09T12:10:43.123458Z 01O+end\n",
            "x".repeat(LINE_BUF - 1)
        );
        assert_eq!(out, want);
        // A single write past the buffer goes straight through.
        let mut s = Stamper::new(STREAM_WORK, Kind::Stdout);
        let big = vec![b'x'; LINE_BUF + 1];
        let out = stamped(&mut s, &[&big]);
        assert!(out.starts_with("2026-10-09T12:10:43.123456Z 01O xxx"));
        assert_eq!(out.len(), HEADER_LEN + LINE_BUF + 2);
    }

    #[test]
    fn multibyte_characters_on_line_boundaries_are_kept_whole() {
        let mut s = Stamper::new(STREAM_WORK, Kind::Stdout);
        assert_eq!(
            stamped(&mut s, &["é\nü".as_bytes()]),
            "2026-10-09T12:10:43.123456Z 01O é\n2026-10-09T12:10:43.123456Z 01O ü\n"
        );
    }

    #[test]
    fn own_lines_are_each_stamped() {
        assert_eq!(
            String::from_utf8(own_lines(b"ERROR: one\ntwo", at(0))).unwrap(),
            "2026-10-09T12:10:43.123456Z 00O ERROR: one\n\
             2026-10-09T12:10:43.123456Z 00O two\n"
        );
    }

    #[test]
    fn the_flag_is_read_as_gitlab_runner_reads_it() {
        assert_eq!(enabled(None), (true, None));
        assert_eq!(enabled(Some("false")), (false, None));
        assert_eq!(enabled(Some("0")), (false, None));
        assert_eq!(enabled(Some("True")), (true, None));
        let (on, warning) = enabled(Some("off"));
        assert!(on);
        assert_eq!(
            warning.as_deref(),
            Some("FF_TIMESTAMPS: could not parse feature flag, expected bool, got off")
        );
        // An empty value is an unset one.
        assert_eq!(enabled(Some("")), (true, None));
    }
}
