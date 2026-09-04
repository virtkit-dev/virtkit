//! Reading a guest's console log: which of its lines are the kernel's, which the agent's,
//! and which the guest's own programs'.
//!
//! One serial console carries three writers. The kernel stamps its lines `[   12.345678] `
//! (`printk.time`), the agent writes `HH:MM:SS [LEVEL] vk-agent …` (its
//! `install_console_logger`, colour-free so the level parses), and whatever the guest runs
//! writes the rest. Telling them apart is what lets a boot failure show the agent's
//! complaints first instead of the last twenty lines of whatever scrolled by, and what
//! `vk logs --level warn` filters on.
//!
//! The split is a reading aid, not a guarantee: everything here writes to the same console,
//! so a guest program that prints `[    1.234567] Kernel panic` is classified as the kernel.
//! Nothing acts on the classification — it selects lines to show a person.

use std::borrow::Cow;

/// Who wrote a console line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Kernel,
    Agent,
    /// The guest's own programs: a service's stdout, an image init's messages.
    Guest,
}

/// An agent log level, ordered from most to least severe (`Error < Warn < …`), so
/// `level <= min` reads "at least as severe as".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum Level {
    /// what stopped something working
    Error,
    /// what went wrong but was worked around or continued past
    Warn,
    /// what the agent did
    Info,
    /// what the agent did in detail (only where a guest was booted with agent --debug)
    Debug,
    /// every step the agent took (only where a guest was booted with agent --debug)
    Trace,
}

impl Level {
    fn from_tag(tag: &str) -> Option<Level> {
        Some(match tag {
            "ERROR" => Level::Error,
            "WARN" => Level::Warn,
            "INFO" => Level::Info,
            "DEBUG" => Level::Debug,
            "TRACE" => Level::Trace,
            _ => return None,
        })
    }
}

/// One classified console line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub source: Source,
    /// The agent's level; for the kernel, `Error` on a panic/oops/OOM line and `None`
    /// otherwise (the console carries no priority); always `None` for the guest's programs.
    pub level: Option<Level>,
    /// The line with terminal escapes removed.
    pub text: String,
}

/// Drop ANSI escape sequences (`ESC [ … m` and the other CSI/OSC shapes) — an older agent
/// coloured its level tag, and guest programs colour freely. Returns the input borrowed when
/// there is nothing to strip, which is every line the current agent writes.
fn strip_ansi(s: &str) -> Cow<'_, str> {
    if !s.contains('\x1b') {
        return Cow::Borrowed(s);
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            // CSI: ESC [ parameters… final byte in 0x40..=0x7e
            Some('[') => {
                chars.next();
                for c in chars.by_ref() {
                    if ('\x40'..='\x7e').contains(&c) {
                        break;
                    }
                }
            }
            // OSC: ESC ] … terminated by BEL, or by ST (ESC \) whose second byte is eaten
            // here and nowhere else.
            Some(']') => {
                chars.next();
                while let Some(c) = chars.next() {
                    if c == '\x07' {
                        break;
                    }
                    if c == '\x1b' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            // A two-character escape. The string-opening ones (DCS/APC/PM: ESC P, ESC _,
            // ESC ^) leak their payload rather than being scanned to their terminator, and a
            // lone ESC eats the character after it. Both are cosmetic on a log nobody parses
            // further, and the alternative is a full terminal state machine.
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    Cow::Owned(out)
}

/// A kernel `printk.time` stamp: `[` spaces digits `.` six digits `] `. The trailing space is
/// part of the match: printk always emits it, and requiring it keeps `[1.234567]` written by
/// a guest program out.
fn kernel_stamped(s: &str) -> bool {
    let Some(rest) = s.strip_prefix('[') else {
        return false;
    };
    let rest = rest.trim_start_matches(' ');
    let Some((secs, rest)) = rest.split_once('.') else {
        return false;
    };
    if secs.is_empty() || !secs.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Exactly six fractional digits, as printk formats them: `[1.2] x` is a guest's line.
    let digits = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
    digits == 6 && rest[digits..].starts_with("] ")
}

/// The agent's `HH:MM:SS [LEVEL] ` prefix, returning the level.
fn agent_level(s: &str) -> Option<Level> {
    let b = s.as_bytes();
    if b.len() < 10
        || !(b[0].is_ascii_digit() && b[1].is_ascii_digit() && b[2] == b':')
        || !(b[3].is_ascii_digit() && b[4].is_ascii_digit() && b[5] == b':')
        || !(b[6].is_ascii_digit() && b[7].is_ascii_digit() && b[8] == b' ' && b[9] == b'[')
    {
        return None;
    }
    let tag = s[10..].split_once("] ")?.0;
    Level::from_tag(tag)
}

/// Kernel lines a reader would call an error: a panic, an oops, a BUG, a WARN_ON, an OOM
/// kill, and the two ways a boot ends before userspace starts.
fn kernel_alarm(msg: &str) -> bool {
    [
        "Kernel panic",
        "Oops:",
        "BUG:",
        "WARNING:",
        "Call Trace:",
        "general protection fault",
        "segfault at",
        "VFS: Unable to mount root fs",
        "No working init found",
        // The same two prefixes the guest agent keys on, matched loosely here: this only
        // picks a line to show someone, where the agent is parsing a victim out of it.
        vk_core::oomkills::OOM_PREFIX,
        vk_core::oomkills::OOM_PREFIX_CGROUP,
    ]
    .iter()
    .any(|needle| msg.contains(needle))
}

/// Classify one raw console line.
fn classify(raw: &str) -> Line {
    let text = strip_ansi(raw.trim_end_matches(['\r', '\n'])).into_owned();
    if kernel_stamped(&text) {
        let level = kernel_alarm(&text).then_some(Level::Error);
        return Line {
            source: Source::Kernel,
            level,
            text,
        };
    }
    if let Some(level) = agent_level(&text) {
        return Line {
            source: Source::Agent,
            level: Some(level),
            text,
        };
    }
    Line {
        source: Source::Guest,
        level: None,
        text,
    }
}

/// The lines of `text` from `sources` at least as severe as `min_level` (a line with no
/// level — a guest program's, a routine kernel line — passes only when no level is asked).
pub fn select<'a>(
    text: &'a str,
    sources: &'a [Source],
    min_level: Option<Level>,
) -> impl Iterator<Item = Line> + 'a {
    text.lines().map(classify).filter(move |l| {
        (sources.is_empty() || sources.contains(&l.source))
            && match (min_level, l.level) {
                (None, _) => true,
                (Some(min), Some(level)) => level <= min,
                (Some(_), None) => false,
            }
    })
}

/// The most complaints [`problems`] returns. A boot failure is spliced into an error string
/// that reaches a CI trace; an oops or a chatty agent can produce hundreds of lines, and the
/// tails it precedes are capped at twenty for the same reason.
pub const MAX_PROBLEMS: usize = 20;

/// Return the last [`MAX_PROBLEMS`] distinct agent WARN/ERROR lines and kernel alarms
/// in order, with the count of earlier entries dropped. Show these before the boot failure
/// tail so errors remain visible after they scroll past its last twenty lines.
pub fn problems(text: &str) -> (Vec<String>, usize) {
    let mut seen = std::collections::HashSet::new();
    let mut kept: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut dropped = 0usize;
    for line in select(text, &[Source::Agent, Source::Kernel], Some(Level::Warn)) {
        if !seen.insert(line.text.clone()) {
            continue;
        }
        kept.push_back(line.text);
        if kept.len() > MAX_PROBLEMS {
            kept.pop_front();
            dropped += 1;
        }
    }
    (kept.into(), dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_are_classified_by_their_writer() {
        let k = classify("[    1.234567] virtio_blk virtio1: [vda] 8388608 512-byte sectors");
        assert_eq!((k.source, k.level), (Source::Kernel, None));
        let a = classify("13:46:39 [INFO] vk-agent init: service as root");
        assert_eq!((a.source, a.level), (Source::Agent, Some(Level::Info)));
        let g = classify("Killed");
        assert_eq!((g.source, g.level), (Source::Guest, None));
    }

    #[test]
    fn a_kernel_alarm_reads_as_an_error() {
        for msg in [
            "Out of memory: Killed process 1234 (cc1plus) …",
            "Memory cgroup out of memory: Killed process 7 (x)",
            "Kernel panic - not syncing: Attempted to kill init!",
            "VFS: Unable to mount root fs on unknown-block(0,0)",
            "No working init found.  Try passing init= option",
            "WARNING: CPU: 0 PID: 1 at kernel/sched/core.c:1",
        ] {
            let l = classify(&format!("[   48.291057] {msg}"));
            assert_eq!(
                (l.source, l.level),
                (Source::Kernel, Some(Level::Error)),
                "{msg}"
            );
        }
        // A routine kernel line carries no level.
        assert_eq!(classify("[    0.000000] Linux version 6.18.49").level, None);
    }

    #[test]
    fn look_alikes_belong_to_the_guest() {
        // A bracketed word, a time without a level, a stamp printk would not write.
        for line in [
            "[main] starting",
            "13:46:39 starting",
            "[1.2] x",
            "[    1.23456] five digits",
            "[    1.2345678] eight digits",
            "[abc.123456] not a number",
            "[    1.234567]no space",
        ] {
            assert_eq!(classify(line).source, Source::Guest, "{line:?}");
        }
    }

    #[test]
    fn an_older_agents_coloured_tag_still_parses() {
        // Before the agent went colour-free its level tag was painted; those consoles are
        // still on disk and still worth reading.
        let c = classify("14:16:39 \x1b[0m\x1b[33m[WARN] \x1b[0mvk-agent: guest OOM");
        assert_eq!((c.source, c.level), (Source::Agent, Some(Level::Warn)));
        assert_eq!(c.text, "14:16:39 [WARN] vk-agent: guest OOM");
    }

    #[test]
    fn strip_ansi_removes_the_shapes_a_console_carries() {
        // Nothing to strip: the string comes back borrowed, untouched.
        assert!(matches!(strip_ansi("plain"), Cow::Borrowed("plain")));
        // CSI, with and without parameters.
        assert_eq!(strip_ansi("\x1b[33mred\x1b[0m"), "red");
        assert_eq!(strip_ansi("a\x1b[Kb"), "ab");
        // OSC, both terminators — the character after the terminator survives.
        assert_eq!(strip_ansi("\x1b]0;title\x07after"), "after");
        assert_eq!(strip_ansi("\x1b]0;title\x1b\\after"), "after");
        // An unterminated sequence eats the rest rather than emitting garbage.
        assert_eq!(strip_ansi("keep\x1b[33"), "keep");
        // A lone trailing ESC is dropped.
        assert_eq!(strip_ansi("keep\x1b"), "keep");
    }

    #[test]
    fn a_line_keeps_its_content_however_it_ends() {
        // The VMM writes CRLF on a serial console; the classification and the text must not
        // depend on which ending arrived.
        assert_eq!(classify("13:46:39 [INFO] x\r\n").text, "13:46:39 [INFO] x");
        assert_eq!(classify("13:46:39 [INFO] x").text, "13:46:39 [INFO] x");
    }

    #[test]
    fn select_filters_by_source_and_severity() {
        let text = "[    0.000000] Linux version 6.18.49\n\
                    13:46:39 [INFO] vk-agent init: eth0 up\n\
                    13:46:40 [WARN] vk-agent init: dhclient failed\n\
                    hello from the service\n\
                    [   48.291057] Out of memory: Killed process 7 (x)\n\
                    13:46:41 [ERROR] vk-agent init: boot config unreadable\n";
        assert_eq!(select(text, &[], None).count(), 6);
        assert_eq!(select(text, &[Source::Agent], None).count(), 3);
        let warn: Vec<String> = select(text, &[], Some(Level::Warn))
            .map(|l| l.text)
            .collect();
        assert_eq!(
            warn,
            vec![
                "13:46:40 [WARN] vk-agent init: dhclient failed",
                "[   48.291057] Out of memory: Killed process 7 (x)",
                "13:46:41 [ERROR] vk-agent init: boot config unreadable",
            ]
        );
    }

    #[test]
    fn problems_keeps_each_complaint_once_and_in_order() {
        let text = "13:46:40 [WARN] a\n\
                    hello\n\
                    [   1.000000] Kernel panic - not syncing\n\
                    13:46:41 [ERROR] b\n";
        let (lines, dropped) = problems(&format!("{text}{text}"));
        assert_eq!(dropped, 0);
        assert_eq!(
            lines,
            vec![
                "13:46:40 [WARN] a",
                "[   1.000000] Kernel panic - not syncing",
                "13:46:41 [ERROR] b",
            ]
        );
    }

    #[test]
    fn problems_keeps_the_last_of_a_flood_and_counts_the_rest() {
        // An oops walks the whole stack; the report it lands in must stay legible.
        let text: String = (0..MAX_PROBLEMS + 5)
            .map(|i| format!("13:46:40 [WARN] complaint {i}\n"))
            .collect();
        let (lines, dropped) = problems(&text);
        assert_eq!((lines.len(), dropped), (MAX_PROBLEMS, 5));
        assert_eq!(lines[0], "13:46:40 [WARN] complaint 5");
    }
}
