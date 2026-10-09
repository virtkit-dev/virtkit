//! Display [`crate::jobs::readable`] output on `/jobs/<id>`: the tail still held by the
//! hub, a settled failed job's retained tail, or the reason no output is available.
//!
//! Running jobs stream updates over `/events/job/<id>`. Each step reads from the previous
//! offset, appends completed lines to the page's `<pre>`, and replaces open lines that
//! stamped continuations or carriage returns may change. The first step replaces the
//! displayed tail, so reconnecting duplicates no lines. If output is already gone, it
//! sends only the record. Changes to the job's output or record ([`Hub::job_changed`])
//! wake the stream, with at most one step per second. Once the job finishes and all output
//! is read, the stream sends the record with its result and closes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use vk_hub_proto::client::JobState;

use super::html::Html;
use super::pages::bytes;
use super::sse::{Source, Step};
use crate::jobs::{Stretch, Trace, TraceLine};
use crate::server::Hub;
use crate::store::{JobOutcome, JobRow};

/// Where a job's page follows it: `/events/job/<id>`.
pub(super) const EVENTS: &str = "/events/job/";

/// The event a job's record is swapped in on, and a session's end shown in.
pub(super) const RECORD: &str = "job";

/// The event that replaces the output's lines: a stream's first.
const START: &str = "output-start";

/// The event whose lines are appended to the output's.
const LINES: &str = "output";

/// The event that replaces the lines of the output still open.
const HELD: &str = "held";

/// The most of the end of a job's output its page shows, and a stream's first step sends.
pub(super) const OPENING: u64 = 1 << 20;

/// The most of a job's output one later step reads; more is read at the next.
const STEP: u64 = 256 << 10;

/// What a job's page shows of its output.
pub(super) enum Output {
    /// The end of the output the hub holds, up to [`OPENING`].
    Held(Stretch),
    /// The end of a failed job's output, kept when its producer settled it.
    Kept(Vec<u8>),
    /// Nothing held or kept.
    Gone,
}

/// A job's output section. `live`: the job runs, and the section is in its page's stream.
pub(super) fn section(h: &mut Html, j: &JobRow, output: &Output, live: bool) {
    match output {
        Output::Kept(tail) => {
            h.raw("<section><h2>End of its output</h2><p class=\"sub\">The last ")
                .text(bytes(tail.len() as u64))
                .raw(", masked as the node streamed it.</p><pre class=\"log\">");
            for line in crate::jobs::readable(tail) {
                line_html(h, &line);
                h.raw("\n");
            }
            h.raw("</pre></section>");
        }
        Output::Gone => {
            h.raw("<section><h2>Output</h2><p class=\"empty\">");
            if j.outcome() == JobOutcome::Failed {
                h.raw("none kept");
            } else if j.settled_at.is_some() {
                h.raw("dropped once its producer had it");
                if j.job_url.as_deref().is_some_and(vk_hub_proto::is_web_link) {
                    h.raw(": ")
                        .external_link(j.job_url.as_deref(), "GitLab has it");
                }
            } else if j.expired_at.is_some() {
                h.raw("dropped, never taken by its producer");
            } else {
                h.raw("none held");
            }
            h.raw("</p></section>");
        }
        Output::Held(stretch) => held(h, stretch, live),
    }
}

/// The output the hub holds: its lines, then those still open in a place of their own.
fn held(h: &mut Html, stretch: &Stretch, live: bool) {
    h.raw("<section><h2>Output</h2><p class=\"sub\">As the node masked it");
    if live {
        h.raw(", followed as it comes");
    }
    h.raw(".</p>");
    if live {
        // A stream's first event replaces the lines; the rest are appended.
        h.raw("<span hidden sse-swap=\"")
            .raw(START)
            .raw("\" hx-target=\"#job-lines\"></span>");
    }
    // `data-follow`: `follow.js` keeps it scrolled to its end while the reader is there.
    h.raw("<pre class=\"log\" data-follow><span id=\"job-lines\"");
    if live {
        h.raw(" sse-swap=\"")
            .raw(LINES)
            .raw("\" hx-swap=\"beforeend\"");
    }
    h.raw(">");
    cut(h, stretch.from);
    let mut trace = Trace::default();
    // For display alone: an invalid sequence shows as U+FFFD.
    for line in trace.push(&String::from_utf8_lossy(&stretch.bytes)) {
        line_html(h, &line);
        h.raw("\n");
    }
    let last = if live { trace.held() } else { trace.finish() };
    if !live {
        for line in &last {
            line_html(h, line);
            h.raw("\n");
        }
    }
    h.raw("</span><span id=\"job-held\"");
    if live {
        h.raw(" sse-swap=\"").raw(HELD).raw("\"");
    }
    h.raw(">");
    if live {
        held_html(h, &last);
    }
    h.raw("</span></pre></section>");
}

/// Say how much of the output precedes `from`, where what is shown starts, if any does.
fn cut(h: &mut Html, from: u64) {
    if from > 0 {
        h.raw("<span class=\"cut\">… ")
            .text(bytes(from))
            .raw(" before this not shown</span>\n");
    }
}

/// The lines held back, as they read so far: the last one without its newline, which the
/// next may still rewrite.
fn held_html(h: &mut Html, lines: &[TraceLine]) {
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            h.raw("\n");
        }
        line_html(h, line);
    }
}

/// One line of output, without its newline: its stamp as its time of day, the instant on
/// hover, then its text.
fn line_html(h: &mut Html, line: &TraceLine) {
    // `ui.css` numbers each `.l`, as GitLab's log does.
    h.raw("<span class=\"l\">");
    if let Some(at) = &line.at {
        // A plain `<time>`: `time.js` rewrites only those with a `datetime`.
        h.raw("<time title=\"")
            .text(at)
            .raw("\">")
            .text(at.get(11..19).unwrap_or(at))
            .raw("</time> ");
    }
    h.raw("<span class=\"t\">");
    for run in &line.runs {
        let classes = run.style.classes();
        if classes.is_empty() {
            h.text(&run.text);
        } else {
            h.raw("<span class=\"")
                .text(&classes)
                .raw("\">")
                .text(&run.text)
                .raw("</span>");
        }
    }
    h.raw("</span></span>");
}

/// What `/events/job/<id>` streams: job `id`'s output and record as they change. Each stream
/// reads the output for itself, from where it stands, rather than sharing a rendering as
/// `/jobs`' streams do: a job's page has few readers, and each read is bounded ([`STEP`]).
pub(super) fn source(hub: &Arc<Hub>, id: &str) -> Source {
    let changes = hub.subscribe_job(id);
    let following = Mutex::new(Following::default());
    let (hub, id) = (hub.clone(), id.to_string());
    Source::Follow {
        name: RECORD,
        changes,
        next: Arc::new(move || step(&hub, &id, &mut lock(&following))),
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // One stream's place in the output, taken one step at a time: a step that panicked
    // ends the stream it was taken for.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where one stream is in a job's output, and what it last sent.
#[derive(Default)]
struct Following {
    /// Where the next step reads from; `None` before the first.
    at: Option<u64>,
    trace: Trace,
    /// The lines still open, as last sent.
    held: Option<String>,
    /// The job's record's revision and output length, as last sent: the record shows both.
    record: Option<(u64, u64)>,
}

/// One step of job `id`'s stream.
fn step(hub: &Hub, id: &str, f: &mut Following) -> Result<Step> {
    let first = f.at.is_none();
    let max = if first { OPENING } else { STEP };
    let Some((row, stretch)) = crate::jobs::output_stretch(hub, id, f.at, max)? else {
        // Gone from the history.
        return Ok(Step {
            last: true,
            ..Step::default()
        });
    };
    if first && stretch.is_none() {
        // Its output went before the stream opened: the page keeps what it was served, and
        // takes the record, with how the job ended.
        return Ok(Step {
            events: vec![(RECORD, record_html(hub, &row)?)],
            more: false,
            last: true,
        });
    }
    let mut lines = Html::new();
    // Without output held — settled, expired — there is nothing more to follow.
    let (mut more, mut ended) = (false, true);
    if let Some(s) = stretch {
        if first {
            cut(&mut lines, s.from);
        }
        let read_to = s.from.saturating_add(s.bytes.len() as u64);
        // Its file went under the stream: settled since its record was read.
        let gone = s.bytes.is_empty() && s.from < s.len;
        more = read_to < s.len;
        ended = gone || (row.state == JobState::Finished && !more);
        let take = taken(&s.bytes, ended, s.bytes.len() as u64 >= max);
        // For display alone: `take` cuts no character, and an invalid sequence shows as U+FFFD.
        let text = String::from_utf8_lossy(s.bytes.get(..take).unwrap_or_default());
        for line in f.trace.push(&text) {
            line_html(&mut lines, &line);
            lines.raw("\n");
        }
        f.at = Some(s.from.saturating_add(take as u64));
    }
    if ended {
        for line in f.trace.finish() {
            line_html(&mut lines, &line);
            lines.raw("\n");
        }
    }
    let mut events = Vec::new();
    let lines = lines.into_string();
    if first {
        // The page already carries this opening, for readers without JavaScript: each page
        // open costs it twice, served and sent, so a reconnect can replace it whole.
        events.push((START, lines));
    } else if !lines.is_empty() {
        events.push((LINES, lines));
    }
    let mut held = Html::new();
    held_html(&mut held, &f.trace.held());
    let held = held.into_string();
    if f.held.as_ref() != Some(&held) {
        f.held = Some(held.clone());
        events.push((HELD, held));
    }
    let record = (row.revision, row.output_len);
    if f.record != Some(record) || ended {
        f.record = Some(record);
        events.push((RECORD, record_html(hub, &row)?));
    }
    Ok(Step {
        events,
        more: more && !ended,
        last: ended,
    })
}

/// Job `row`'s record, as its page shows it.
fn record_html(hub: &Hub, row: &JobRow) -> Result<String> {
    let names = hub.db.node_names()?;
    let names: HashMap<&str, &str> = names
        .iter()
        .map(|(id, name)| (id.as_str(), name.as_str()))
        .collect();
    let mut record = Html::new();
    super::jobs::record(&mut record, row, &names, crate::now_secs());
    Ok(record.into_string())
}

/// How many of `bytes`, read from the output where the last step stopped, a step takes: up to
/// the end of their last line, as a line is made readable whole; all of them once the output
/// has `ended`; for a `full` read with no line's end, a line longer than a step, all but a
/// character it cut.
fn taken(bytes: &[u8], ended: bool, full: bool) -> usize {
    if ended {
        return bytes.len();
    }
    match bytes.iter().rposition(|&b| b == b'\n') {
        Some(nl) => nl.saturating_add(1),
        None if full => match std::str::from_utf8(bytes) {
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            _ => bytes.len(),
        },
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Output that arrives in pieces cut anywhere, mid-line and mid-character, read a step of
    /// at most `max` bytes at a time, reads as it does whole: every line once, in order.
    #[test]
    fn output_followed_a_piece_at_a_time_reads_as_it_does_whole() {
        let stamp = |kind: char| format!("2026-10-09T12:10:43.123456Z 01O{kind}");
        let output = format!(
            "{} déjà vu ✓\n{} section_start:1:build\r\x1b[0K\n{} 10%\r\n{}20%\r\n{}done ✓\n\
             unstamped line ünïcode\n{} {}\n{} \x1b[31mred\x1b[0m end",
            stamp(' '),
            stamp(' '),
            stamp(' '),
            stamp('+'),
            stamp('+'),
            stamp(' '),
            "long ".repeat(30),
            stamp(' '),
        );
        let whole: Vec<TraceLine> = crate::jobs::readable(output.as_bytes());
        let bytes = output.as_bytes();
        for max in [40, 1 << 20] {
            for piece in [1, 2, 3, 5, 7, 64] {
                let mut trace = Trace::default();
                let (mut at, mut shown, mut arrived) = (0, Vec::new(), 0);
                while arrived < bytes.len() {
                    arrived = (arrived + piece).min(bytes.len());
                    loop {
                        let read = &bytes[at..arrived.min(at + max)];
                        let take = taken(read, false, read.len() >= max);
                        shown.extend(trace.push(std::str::from_utf8(&read[..take]).unwrap()));
                        at += take;
                        if take == 0 || at == arrived {
                            break;
                        }
                    }
                }
                let rest = &bytes[at..];
                let take = taken(rest, true, false);
                shown.extend(trace.push(std::str::from_utf8(&rest[..take]).unwrap()));
                shown.extend(trace.finish());
                assert_eq!(shown, whole, "max {max}, pieces of {piece}");
            }
        }
        assert_eq!(whole.len(), 5, "{whole:?}");
        assert_eq!(whole[1].text, "done ✓");
    }
}
