//! Process logging: one logfmt line per record on stderr, `time=… level=… msg=…` followed
//! by the record's structured fields.

use std::fmt::Write as _;
use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use log::kv::{self, VisitSource};
use log::{Level, LevelFilter, Log, Metadata, Record};

struct Logger {
    level: LevelFilter,
}

/// Installs the logger. Records from other crates (the HTTP and TLS stacks) are shown from
/// `warn` up unless `level` is `trace`.
pub fn init(level: LevelFilter) {
    if log::set_boxed_logger(Box::new(Logger { level })).is_ok() {
        log::set_max_level(level);
    }
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata<'_>) -> bool {
        if m.level() > self.level {
            return false;
        }
        m.target().starts_with("vk_gitlab")
            || m.level() <= Level::Warn
            || self.level == LevelFilter::Trace
    }

    fn log(&self, record: &Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let line = format_record(record, SystemTime::now());
        // Nothing sensible is left to do when stderr is gone.
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
    }

    fn flush(&self) {}
}

fn level_name(level: Level) -> &'static str {
    match level {
        Level::Error => "error",
        Level::Warn => "warning",
        Level::Info => "info",
        Level::Debug => "debug",
        Level::Trace => "trace",
    }
}

/// A value, quoted when logfmt needs it.
fn push_value(out: &mut String, v: &str) {
    let plain = !v.is_empty()
        && v.chars()
            .all(|c| !c.is_whitespace() && !c.is_control() && c != '"' && c != '=');
    if plain {
        out.push_str(v);
    } else {
        let _ = write!(out, "{v:?}");
    }
}

struct Fields<'a>(&'a mut String);

impl<'kvs> VisitSource<'kvs> for Fields<'_> {
    fn visit_pair(&mut self, key: kv::Key<'kvs>, value: kv::Value<'kvs>) -> Result<(), kv::Error> {
        self.0.push(' ');
        self.0.push_str(key.as_str());
        self.0.push('=');
        push_value(self.0, &value.to_string());
        Ok(())
    }
}

fn format_record(record: &Record<'_>, now: SystemTime) -> String {
    let mut out = String::with_capacity(128);
    out.push_str("time=");
    out.push_str(&rfc3339(now));
    out.push_str(" level=");
    out.push_str(level_name(record.level()));
    out.push_str(" msg=");
    push_value(&mut out, &record.args().to_string());
    let _ = record.key_values().visit(&mut Fields(&mut out));
    if !record.target().starts_with("vk_gitlab") {
        out.push_str(" target=");
        push_value(&mut out, record.target());
    }
    out.push('\n');
    out
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ` in UTC.
fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(1_445_412_480_123);
        assert_eq!(rfc3339(t), "2015-10-21T07:28:00.123Z");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(rfc3339(leap), "2000-02-29T00:00:00.000Z");
    }

    #[test]
    fn logfmt_line() {
        let line = format_record(
            &Record::builder()
                .args(format_args!("Checking for jobs... received"))
                .level(Level::Info)
                .target("vk_gitlab::api")
                .key_values(&[("job", 10i64)])
                .build(),
            UNIX_EPOCH,
        );
        assert_eq!(
            line,
            "time=1970-01-01T00:00:00.000Z level=info msg=\"Checking for jobs... received\" job=10\n"
        );
    }
}
