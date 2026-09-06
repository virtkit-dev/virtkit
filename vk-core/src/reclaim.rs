//! Idle page-cache trimming: the host–guest contract.
//!
//! A guest kernel keeps every file page it ever read until something in the guest needs the
//! memory. With free-page reporting, only pages the guest *frees* return to the host, so a
//! VM that read a few gigabytes converges on holding its whole allocation whatever it is
//! doing now — and the same bytes sit in the host's page cache too, or, on a busy host, in
//! its swap. The agent's `reclaim` loop trims the guest's file cache down to a floor whenever
//! the guest is not under memory pressure, and the freed pages flow back to the host through
//! the balloon. `auto` asks for age-based trimming: pages untouched for a couple of minutes
//! go, whatever their amount, through the multi-gen LRU (the floor rides along for the kernels
//! without it); a size or a share asks for a fixed floor of cache to keep. The request crosses
//! the kernel cmdline as [`CMDLINE_KEY`], with `psi=1` so the loop can tell a busy guest from
//! an idle one.

use std::fmt;
use std::str::FromStr;

/// The kernel cmdline variable carrying the floor, in MiB.
pub const CMDLINE_KEY: &str = "VIRTKIT_RECLAIM";

/// How a VM's guest is asked to trim its file cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
    /// Evict what the guest has not touched for a while, however much that is (multi-gen
    /// LRU aging); on a kernel without it, keep a floor sized from the guest's RAM
    /// ([`auto_floor_mib`]). The default.
    Auto,
    /// Never trim: the guest keeps whatever it caches.
    Off,
    /// Keep this much file cache, in MiB.
    Floor(u64),
    /// Keep this share of the guest's RAM as file cache, in percent.
    Percent(u32),
}

impl Policy {
    /// The floor for a guest of `mem_mib`; `None` when trimming is off.
    pub fn floor_mib(self, mem_mib: u64) -> Option<u64> {
        match self {
            Policy::Off => None,
            Policy::Auto => Some(auto_floor_mib(mem_mib)),
            Policy::Floor(mib) => Some(mib),
            Policy::Percent(pct) => Some((mem_mib.saturating_mul(u64::from(pct)) / 100).max(16)),
        }
    }
}

/// The `auto` floor: a sixteenth of the guest's RAM, never under 64 MiB nor over 512 MiB.
/// Enough for the working set of a shell and its tools; anything a job or a build reads on top
/// stays cached for as long as it is being used (see the agent's pressure gate) and goes back
/// once it is not.
pub fn auto_floor_mib(mem_mib: u64) -> u64 {
    (mem_mib / 16).clamp(64, 512)
}

impl FromStr for Policy {
    type Err = String;

    /// `auto`, `off`, `<n>%`, or a size: `<n>G`, `<n>M`, or a bare MiB count.
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        // The three spellings of off are what a YAML or TOML scalar turns "no" into; they are
        // not sizes, so `0M` stays an error rather than a fourth way to write it.
        match s {
            "auto" => return Ok(Policy::Auto),
            "off" | "false" | "0" => return Ok(Policy::Off),
            _ => {}
        }
        if let Some(pct) = s.strip_suffix('%') {
            return pct
                .parse::<u32>()
                .ok()
                .filter(|p| (1..=100).contains(p))
                .map(Policy::Percent)
                .ok_or_else(|| format!("expected 1%..100%, got {s:?}"));
        }
        let (digits, scale) = match s.strip_suffix(['G', 'g']) {
            Some(d) => (d, 1024),
            None => (s.strip_suffix(['M', 'm']).unwrap_or(s), 1),
        };
        digits
            .parse::<u64>()
            .ok()
            .and_then(|n| n.checked_mul(scale))
            .filter(|mib| *mib > 0)
            .map(Policy::Floor)
            .ok_or_else(|| {
                format!("expected auto, off, <n>%, <n>G, <n>M or a MiB count, got {s:?}")
            })
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Policy::Auto => f.write_str("auto"),
            Policy::Off => f.write_str("off"),
            Policy::Floor(mib) => write!(f, "{mib}M"),
            Policy::Percent(pct) => write!(f, "{pct}%"),
        }
    }
}

/// What the guest is asked to do, as carried by the cmdline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// `auto`: trim by age through the multi-gen LRU where the kernel has it.
    pub by_age: bool,
    /// The cache floor, in MiB. It governs the fixed-floor mode; under `auto` it is only the
    /// fallback for a kernel with no multi-gen LRU, so on the pinned kernel the floor an
    /// `auto:<mib>` on `/proc/cmdline` names is never reached — age decides, not amount.
    pub floor_mib: u64,
}

/// The cmdline fragment asking a guest of `mem_mib` to trim under `policy`; empty for `off`.
/// `psi=1` because the guest kernel is built with pressure stall information available but
/// off, and the loop reclaims only while memory pressure is low.
pub fn cmdline_knob(policy: Policy, mem_mib: u64) -> String {
    let Some(floor_mib) = policy.floor_mib(mem_mib) else {
        return String::new();
    };
    let mode = if policy == Policy::Auto { "auto:" } else { "" };
    format!(" {CMDLINE_KEY}={mode}{floor_mib} psi=1")
}

/// Parse [`cmdline_knob`]'s `auto:<mib>` or `<mib>` value; return `None` otherwise.
pub fn parse_cmdline_value(value: &str) -> Option<Request> {
    let (by_age, floor) = match value.strip_prefix("auto:") {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    let floor_mib = floor.parse::<u64>().ok().filter(|mib| *mib > 0)?;
    Some(Request { by_age, floor_mib })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_parses_every_spelling() {
        assert_eq!("auto".parse::<Policy>(), Ok(Policy::Auto));
        assert_eq!("off".parse::<Policy>(), Ok(Policy::Off));
        assert_eq!("false".parse::<Policy>(), Ok(Policy::Off));
        assert_eq!("0".parse::<Policy>(), Ok(Policy::Off));
        assert_eq!("512M".parse::<Policy>(), Ok(Policy::Floor(512)));
        assert_eq!("2G".parse::<Policy>(), Ok(Policy::Floor(2048)));
        assert_eq!("768".parse::<Policy>(), Ok(Policy::Floor(768)));
        assert_eq!(" 5% ".parse::<Policy>(), Ok(Policy::Percent(5)));
        for bad in ["", "big", "-1", "0%", "101%", "1T", "1.5G", "12GB"] {
            assert!(bad.parse::<Policy>().is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn floor_follows_the_policy() {
        assert_eq!(Policy::Off.floor_mib(8192), None);
        assert_eq!(Policy::Floor(300).floor_mib(8192), Some(300));
        assert_eq!(Policy::Percent(25).floor_mib(8192), Some(2048));
        // A share of a tiny guest still leaves a usable floor.
        assert_eq!(Policy::Percent(1).floor_mib(256), Some(16));
        // auto: a sixteenth, clamped to [64, 512].
        assert_eq!(Policy::Auto.floor_mib(512), Some(64));
        assert_eq!(Policy::Auto.floor_mib(4096), Some(256));
        assert_eq!(Policy::Auto.floor_mib(16384), Some(512));
    }

    #[test]
    fn knob_round_trips_through_the_cmdline() {
        let value = |knob: &str| {
            knob.split_whitespace()
                .find_map(|tok| tok.strip_prefix("VIRTKIT_RECLAIM="))
                .map(str::to_owned)
        };
        // auto: by age, the RAM-derived floor riding along for kernels without MGLRU
        let knob = cmdline_knob(Policy::Auto, 4096);
        assert_eq!(knob, " VIRTKIT_RECLAIM=auto:256 psi=1");
        assert_eq!(
            parse_cmdline_value(&value(&knob).unwrap()),
            Some(Request {
                by_age: true,
                floor_mib: 256
            })
        );
        // an explicit size or share: a fixed floor
        let knob = cmdline_knob(Policy::Percent(25), 4096);
        assert_eq!(knob, " VIRTKIT_RECLAIM=1024 psi=1");
        assert_eq!(
            parse_cmdline_value(&value(&knob).unwrap()),
            Some(Request {
                by_age: false,
                floor_mib: 1024
            })
        );
        // off: nothing on the cmdline, nothing forked
        assert_eq!(cmdline_knob(Policy::Off, 4096), "");
        for bad in ["0", "auto:0", "auto:", "lots", "auto:lots", "age:5"] {
            assert_eq!(parse_cmdline_value(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn display_round_trips() {
        for p in [
            Policy::Auto,
            Policy::Off,
            Policy::Floor(300),
            Policy::Percent(7),
        ] {
            assert_eq!(p.to_string().parse::<Policy>(), Ok(p));
        }
    }
}
