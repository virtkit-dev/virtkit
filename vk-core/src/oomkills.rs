//! Shared record format for guest OOM kills.
//!
//! The guest appends one line per kill, and `vk-agent oomkills` sends those lines to the
//! host over the exec channel. Keeping rendering and parsing here prevents either side from
//! accepting records that the other rejects.

/// The prefixes the kernel's OOM killer puts before `: Killed process` (mm/oom_kill.c): the
/// whole-guest one and the cgroup one. Here rather than in the agent so a host-side reader
/// of the guest console can recognise the same two records the agent does.
pub const OOM_PREFIX: &str = "Out of memory";
pub const OOM_PREFIX_CGROUP: &str = "Memory cgroup out of memory";

/// Published format tag. A format change requires a new tag because `comm` is the final,
/// space-containing field; older hosts would treat appended fields as part of the name.
const TAG: &str = "oomkill1";

/// One OOM kill, as the guest kernel reported it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kill {
    /// Guest uptime at the kill, in microseconds (the kernel record's own stamp).
    pub uptime_us: u64,
    /// The victim's pid — what tells two victims sharing a `comm` apart.
    pub pid: u32,
    /// The victim's `comm` (15 chars at most, as the kernel keeps it). Attacker-chosen
    /// (`prctl(PR_SET_NAME)`) but safe to print: `/dev/kmsg` escapes every byte below 0x20,
    /// every byte from 0x7f up, and `\` itself as `\xNN`, so no control or escape sequence
    /// survives into it.
    pub comm: String,
    /// Its *anonymous* RSS in bytes: what killing it gave back. File-backed and shmem pages
    /// are excluded, so a process killed while holding mostly page cache shows a small
    /// figure.
    pub anon_rss: u64,
    /// `true` for a cgroup limit ("Memory cgroup out of memory"), `false` for the whole guest.
    pub cgroup: bool,
}

impl Kill {
    /// The published line: `oomkill1 <uptime_us> <pid> <anon_rss> <cgroup> <comm>`, comm last
    /// because it may contain spaces. Newline-terminated.
    pub fn render(&self) -> String {
        format!(
            "{TAG} {} {} {} {} {}\n",
            self.uptime_us,
            self.pid,
            self.anon_rss,
            u8::from(self.cgroup),
            self.comm
        )
    }

    /// Parse one published line; `None` for anything else (a partial write, another file, a
    /// newer agent's format).
    pub fn parse(line: &str) -> Option<Kill> {
        let mut f = line.trim_end_matches('\n').splitn(6, ' ');
        if f.next()? != TAG {
            return None;
        }
        let uptime_us = f.next()?.parse().ok()?;
        let pid = f.next()?.parse().ok()?;
        let anon_rss = f.next()?.parse().ok()?;
        let cgroup = match f.next()? {
            "0" => false,
            "1" => true,
            _ => return None,
        };
        let comm = f.next()?;
        if comm.is_empty() {
            return None;
        }
        Some(Kill {
            uptime_us,
            pid,
            comm: comm.to_string(),
            anon_rss,
            cgroup,
        })
    }

    /// Parse at most `max` complete records from `vk-agent oomkills`, skipping malformed
    /// lines. Ignore a non-newline-terminated tail that may have been read during an append.
    pub fn parse_all(text: &str, max: usize) -> Vec<Kill> {
        text.split_inclusive('\n')
            .filter(|l| l.ends_with('\n'))
            .filter_map(Kill::parse)
            .take(max)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kill() -> Kill {
        Kill {
            uptime_us: 48_291_057,
            pid: 1234,
            comm: "cc1plus".into(),
            anon_rss: 1_998_812 * 1024,
            cgroup: false,
        }
    }

    #[test]
    fn a_rendered_kill_parses_back() {
        let k = kill();
        assert_eq!(Kill::parse(&k.render()), Some(k));
    }

    #[test]
    fn a_comm_with_spaces_survives_the_round_trip() {
        // `comm` is last precisely so the kernel's 15 bytes can hold spaces.
        let k = Kill {
            comm: "a b".into(),
            cgroup: true,
            ..kill()
        };
        assert_eq!(Kill::parse(&k.render()), Some(k));
    }

    #[test]
    fn a_line_that_is_not_this_format_is_no_kill() {
        for line in [
            "oomkill1 1 2 3 0",      // no comm
            "oomkill1 1 2 3 x comm", // cgroup is not a flag
            "oomkill1 1 2 3 0 ",     // empty comm
            "oomkill2 1 2 3 0 comm", // a format this host does not know
            "1 2 3 0 comm",          // the untagged first format
            "",
        ] {
            assert_eq!(Kill::parse(line), None, "{line:?}");
        }
    }

    #[test]
    fn parse_all_skips_garbage_and_stops_at_max() {
        let k = kill();
        let cg = Kill {
            comm: "a b".into(),
            cgroup: true,
            ..kill()
        };
        assert_eq!(
            Kill::parse_all(&format!("{}garbage\n{}", k.render(), cg.render()), 8),
            vec![k.clone(), cg]
        );
        let many: String = std::iter::repeat_n(k.render(), 10).collect();
        assert_eq!(Kill::parse_all(&many, 3).len(), 3);
    }

    #[test]
    fn a_torn_final_record_is_dropped_rather_than_named() {
        // The agent appends while the host reads: a record without its newline may be half a
        // victim's name, and naming that would be worse than missing the kill.
        let k = kill();
        let torn = format!("{}{}", k.render(), &k.render()[..20]);
        assert_eq!(Kill::parse_all(&torn, 8), vec![k]);
    }
}
