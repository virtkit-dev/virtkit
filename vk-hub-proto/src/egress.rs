//! The hub's own egress layer for a job ([`HubEgress`]), resolved from its rules, sent in the
//! job's start: what each phase may reach under the rules enforced, and under each dry-run rule
//! were it enforced. The node enforces the first below its own cap and reports what the others
//! would deny.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// The longest text a report carries in any one field, in bytes.
pub const MAX_EGRESS_TEXT: usize = 255;
/// The longest domain name, in bytes (RFC 1035, without the root's dot).
const MAX_DOMAIN: usize = 253;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressPhase {
    /// The job's VM and its services.
    Run,
    /// The `RUN` steps of the images the job builds.
    Build,
    /// A phase from a later peer.
    #[serde(other)]
    Other,
}

/// The hub's layer for a job (`docs/fleet-design.md`, *Job egress from the hub*): what each
/// phase may reach under the rules that select the job, below the node's cap and above the
/// job's own narrowing, and what each dry-run rule would allow were it enforced. Resolved by
/// the hub at placement; the node only checks destinations against it, in turn with its other
/// layers, and never computes a rule's effect itself.
///
/// [`HubEgress::check`] holds it to the bounds below; each entry's syntax is the node's to
/// check, as it checks its own `[egress]` lists.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubEgress {
    /// The names of the enforced rules applied, in the hub's order: `default` when only the
    /// Fallback does. Empty when no rule selects the job and none is enforced, as with rules
    /// off.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<String>,
    pub run: HubPhase,
    pub build: HubPhase,
    /// The dry-run rules that select the job: the node blocks nothing for them, and reports what
    /// each would block.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dry_run: Vec<DryRunRule>,
}

/// A dry-run rule, with the hub layer the job would have in each phase were the rule enforced:
/// the enforced rules and this one added up, the Fallback dropped where this one would select
/// the job instead. What that layer refuses and the job's layers carry is a would-be denial.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DryRunRule {
    pub rule: String,
    pub run: HubPhase,
    pub build: HubPhase,
}

/// One phase of a hub layer. Each phase is an explicit choice, never an absent list beside an
/// empty one: [`HubPhase::Allow`] lists both dimensions, and an empty one denies it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HubPhase {
    /// Nothing below the node's cap.
    Unrestricted,
    /// Only these: DNS-name suffixes, dot-anchored as `allow_name`'s are, and IPv4 CIDRs,
    /// optionally `CIDR:port`, as `allow_ip`'s are. Both empty allow nothing.
    Allow {
        names: Vec<String>,
        ips: Vec<String>,
    },
    /// A kind from a later hub, which no node may read as either: [`HubEgress::check`]
    /// refuses it, and the job with it.
    #[serde(other)]
    Other,
}

/// The most rules a hub layer names, enforced and dry-run together.
pub const MAX_HUB_RULES: usize = 32;
/// The most entries in one dimension of a [`HubPhase::Allow`].
pub const MAX_HUB_ENTRIES: usize = 256;
/// The longest rule name, in bytes.
pub const MAX_RULE_NAME: usize = 64;
/// The largest serialized hub layer, in bytes: a job's start carrying one still fits one
/// session message.
pub const MAX_HUB_EGRESS: usize = 256 * 1024;
const _: () = assert!(MAX_HUB_EGRESS < crate::MAX_MESSAGE / 2);

/// Whether `name` may name a hub rule: 1 to [`MAX_RULE_NAME`] ASCII letters, digits, `.`, `_`
/// and `-`, so that it reads the same in a trace, a report and a page.
pub fn valid_rule_name(name: &str) -> bool {
    (1..=MAX_RULE_NAME).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Why `name` is not an `allow_name` entry, as a node's switch reads one: a DNS suffix, its
/// leading dots dropped, that also allows every host under it. A URL, a pattern or a fully
/// qualified name (a trailing dot) would match nothing. The hub holds its rules to it, so that
/// it never sends what a node would refuse.
pub fn check_allow_name(name: &str) -> Result<(), String> {
    let bare = name.trim_start_matches('.');
    if bare.is_empty()
        || bare.ends_with('.')
        || bare.contains(|c: char| c.is_whitespace() || "/:@*".contains(c))
    {
        return Err(format!(
            "{name:?}: expected a DNS suffix such as \"debian.org\", which also allows every \
             host under it"
        ));
    }
    Ok(())
}

/// An `allow_ip` entry as a node's switch reads one: an IPv4 CIDR, `a.b.c.d/prefix`, a bare
/// address standing for `/32`, optionally scoped to one destination port, `CIDR:port`. Returns
/// the address, the prefix length and the port; IPv6 is refused as such. The hub holds its
/// rules to it, so that it never sends what a node would refuse.
pub fn parse_allow_ip(s: &str) -> Result<(Ipv4Addr, u8, Option<u16>), String> {
    // Report IPv6 explicitly before port or IPv4 parsing.
    let host = s.split(['/', '%']).next().unwrap_or(s);
    if s.starts_with('[') || host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Err(format!(
            "{s:?}: IPv6 is refused; an allowlist takes IPv4 CIDRs (optionally CIDR:port)"
        ));
    }
    // Optional `:port` suffix; IPv4 has no colons, so a colon unambiguously starts it.
    let (cidr, port) = match s.rsplit_once(':') {
        Some((c, p)) => (
            c,
            Some(
                p.parse::<u16>()
                    .map_err(|e| format!("bad port in {s:?}: {e}"))?,
            ),
        ),
        None => (s, None),
    };
    let (addr, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
    let ip: Ipv4Addr = addr
        .parse()
        .map_err(|e| format!("bad CIDR address in {s:?}: {e}"))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|p| *p <= 32)
        .ok_or_else(|| format!("bad CIDR prefix in {s:?}"))?;
    Ok((ip, prefix, port))
}

impl HubPhase {
    /// Whether it restricts anything.
    pub fn restricts(&self) -> bool {
        !matches!(self, HubPhase::Unrestricted)
    }

    fn check(&self, what: &str) -> Result<(), String> {
        let HubPhase::Allow { names, ips } = self else {
            return match self {
                HubPhase::Other => Err(format!("{what}: a kind this node does not know")),
                _ => Ok(()),
            };
        };
        for (dimension, list) in [("names", names), ("ips", ips)] {
            if list.len() > MAX_HUB_ENTRIES {
                return Err(format!(
                    "{what}: {} {dimension}, past {MAX_HUB_ENTRIES}",
                    list.len()
                ));
            }
            if let Some(e) = list.iter().find(|e| e.len() > MAX_DOMAIN) {
                return Err(format!(
                    "{what}: {dimension} entry {:?} is longer than {MAX_DOMAIN} bytes",
                    safe_text(e)
                ));
            }
        }
        Ok(())
    }
}

impl HubEgress {
    /// Whether it restricts either phase.
    pub fn restricts(&self) -> bool {
        self.run.restricts() || self.build.restricts()
    }

    /// The layer of `phase`; `None` for a phase this side does not know.
    pub fn phase(&self, phase: EgressPhase) -> Option<&HubPhase> {
        match phase {
            EgressPhase::Run => Some(&self.run),
            EgressPhase::Build => Some(&self.build),
            EgressPhase::Other => None,
        }
    }

    /// Hold it to the bounds: no kind this side does not know, at most [`MAX_HUB_RULES`] rules
    /// with distinct, valid names ([`valid_rule_name`]), at most [`MAX_HUB_ENTRIES`] entries of at
    /// most 253 bytes per dimension, and at most [`MAX_HUB_EGRESS`] bytes serialized. A node
    /// refuses to run a job whose layer fails it rather than run the job under less.
    pub fn check(&self) -> Result<(), String> {
        let names = self
            .rules
            .iter()
            .chain(self.dry_run.iter().map(|d| &d.rule));
        let mut seen: Vec<&String> = Vec::new();
        for name in names {
            if !valid_rule_name(name) {
                return Err(format!("hub rule name {:?} is not valid", safe_text(name)));
            }
            if seen.contains(&name) {
                return Err(format!("hub rule {name:?} is named twice"));
            }
            seen.push(name);
        }
        if seen.len() > MAX_HUB_RULES {
            return Err(format!("{} hub rules, past {MAX_HUB_RULES}", seen.len()));
        }
        self.run.check("the hub's run-phase egress")?;
        self.build.check("the hub's build-phase egress")?;
        for d in &self.dry_run {
            d.run
                .check(&format!("dry-run rule {:?}'s run phase", d.rule))?;
            d.build
                .check(&format!("dry-run rule {:?}'s build phase", d.rule))?;
        }
        if json_len(self) > MAX_HUB_EGRESS {
            return Err(format!(
                "the hub's egress is larger than {MAX_HUB_EGRESS} bytes"
            ));
        }
        Ok(())
    }
}

/// `s` with control and [`crate::invisible`] characters replaced by U+FFFD, cut to
/// [`MAX_EGRESS_TEXT`] bytes on a character boundary.
pub fn safe_text(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        let c = if c.is_control() || crate::invisible(c) {
            '\u{fffd}'
        } else {
            c
        };
        if out.len() + c.len_utf8() > MAX_EGRESS_TEXT {
            break;
        }
        out.push(c);
    }
    out
}

/// The serialized length of `v`; one that does not serialize counts as too large.
fn json_len<T: Serialize>(v: &T) -> usize {
    serde_json::to_vec(v).map_or(usize::MAX / 2, |v| v.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_entries_are_read_as_a_node_reads_them() {
        for ok in ["debian.org", ".debian.org", "a_b.example"] {
            assert!(check_allow_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", ".", "debian.org.", "https://x", "*.x", "a b", "u@x"] {
            assert!(check_allow_name(bad).is_err(), "{bad}");
        }
        let ip = |s| parse_allow_ip(s);
        assert_eq!(ip("10.0.0.1"), Ok((Ipv4Addr::new(10, 0, 0, 1), 32, None)));
        assert_eq!(
            ip("10.0.0.0/8:443"),
            Ok((Ipv4Addr::new(10, 0, 0, 0), 8, Some(443)))
        );
        for bad in [
            "10.0.0.0/33",
            "10.0.0/8",
            "10.0.0.1:x",
            "::1",
            "[::1]:80",
            "x",
        ] {
            assert!(ip(bad).is_err(), "{bad}");
        }
        assert!(ip("fe80::1/64").unwrap_err().contains("IPv6 is refused"));
    }

    #[test]
    fn a_hub_layer_is_held_to_its_bounds() {
        let allow = |n: usize, len: usize| HubPhase::Allow {
            names: vec![format!("{}.example", "a".repeat(len)); n],
            ips: Vec::new(),
        };
        let layer = |rules: &[&str], run: HubPhase| HubEgress {
            rules: rules.iter().map(|r| r.to_string()).collect(),
            run,
            build: HubPhase::Unrestricted,
            dry_run: Vec::new(),
        };
        assert_eq!(
            layer(&["default"], allow(MAX_HUB_ENTRIES, 8)).check(),
            Ok(())
        );
        assert!(!layer(&[], HubPhase::Unrestricted).restricts());
        assert!(layer(&[], allow(0, 1)).restricts());
        for bad in [
            layer(&["default"], allow(MAX_HUB_ENTRIES + 1, 8)),
            layer(&["default"], allow(1, MAX_DOMAIN)),
            layer(&["wab", "wab"], HubPhase::Unrestricted),
            layer(&["a b"], HubPhase::Unrestricted),
            layer(&[""], HubPhase::Unrestricted),
            layer(&["default"], HubPhase::Other),
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        let names: Vec<String> = (0..=MAX_HUB_RULES).map(|i| format!("r{i}")).collect();
        let many = HubEgress {
            rules: names,
            ..layer(&[], HubPhase::Unrestricted)
        };
        assert!(many.check().is_err());
        // A dry-run rule shares the names' bounds, and a later kind fails it too.
        let dry = HubEgress {
            dry_run: vec![DryRunRule {
                rule: "wab".into(),
                run: HubPhase::Unrestricted,
                build: HubPhase::Other,
            }],
            ..layer(&["default"], HubPhase::Unrestricted)
        };
        assert!(dry.check().is_err());
        // The size bound holds where the counts alone would not.
        let big = HubEgress {
            dry_run: (0..MAX_HUB_RULES - 1)
                .map(|i| DryRunRule {
                    rule: format!("r{i}"),
                    run: allow(MAX_HUB_ENTRIES, 200),
                    build: HubPhase::Unrestricted,
                })
                .collect(),
            ..layer(&["default"], HubPhase::Unrestricted)
        };
        assert!(big.check().is_err());
        assert!(valid_rule_name(&"a".repeat(MAX_RULE_NAME)));
        assert!(!valid_rule_name(&"a".repeat(MAX_RULE_NAME + 1)));
    }
}
