//! Whether a hub layer's phase allows a destination, as a node's switch decides it: a domain
//! against the names, dot-anchored suffixes; an address and port against the IPv4 CIDRs, each
//! optionally scoped to one port. For the Egress page's comparisons only: the node decides, and
//! the hub never computes a rule's effect for it.
//!
//! The switch also carries a connection to an address one of the job's lookups of an allowed
//! name resolved to, which nothing the hub keeps can tell: an address no IP range lists, in a
//! phase that lists names, is [`Verdict::ByNameOnly`], neither allowed nor refused.

use vk_hub_proto::egress::{EgressDestination, HubPhase, parse_allow_ip};

/// What a phase says of a destination.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// It restricts nothing.
    Unrestricted,
    /// These of its entries allow it: every one that does, so a broad entry is never passed
    /// over for a narrow one.
    Allowed(Vec<&'a str>),
    /// An address no IP range lists, while names are listed: allowed only if a lookup of one
    /// of them resolved to it.
    ByNameOnly,
    /// Refused.
    Outside,
}

impl Verdict<'_> {
    /// Whether it allows the destination for certain.
    pub fn allows(&self) -> bool {
        matches!(self, Verdict::Unrestricted | Verdict::Allowed(_))
    }
}

/// Whether `allow_name` entry `entry` allows host `name`: equal to it or under it, its leading
/// dots and the name's trailing ones dropped, ASCII case ignored.
pub fn name_matches(entry: &str, name: &str) -> bool {
    let entry = entry.trim_start_matches('.').to_ascii_lowercase();
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    !entry.is_empty()
        && (name == entry
            || name
                .strip_suffix(entry.as_str())
                .is_some_and(|head| head.ends_with('.')))
}

/// Whether `allow_ip` entry `entry` allows `ip`, on `port` when the entry names one; `None` a
/// port unknown, which only an entry with no port allows.
pub fn ip_matches(entry: &str, ip: std::net::Ipv4Addr, port: Option<u16>) -> bool {
    let Ok((net, prefix, only)) = parse_allow_ip(entry) else {
        return false;
    };
    let mask = match prefix {
        0 => 0,
        p => u32::MAX << (32 - u32::from(p.min(32))),
    };
    (u32::from(ip) & mask) == (u32::from(net) & mask) && only.is_none_or(|p| Some(p) == port)
}

/// What phase `p` says of `d`.
pub fn verdict<'a>(p: &'a HubPhase, d: &Dest) -> Verdict<'a> {
    let HubPhase::Allow { names, ips } = p else {
        return match p {
            HubPhase::Unrestricted => Verdict::Unrestricted,
            // Refused when stored, and read as allowing nothing as resolution reads it.
            _ => Verdict::Outside,
        };
    };
    match d {
        Dest::Name(name) => {
            let hits: Vec<&str> = names
                .iter()
                .filter(|e| name_matches(e, name))
                .map(String::as_str)
                .collect();
            if hits.is_empty() {
                Verdict::Outside
            } else {
                Verdict::Allowed(hits)
            }
        }
        Dest::Address(ip, port) => {
            let hits: Vec<&str> = ips
                .iter()
                .filter(|e| ip_matches(e, *ip, *port))
                .map(String::as_str)
                .collect();
            match (hits.is_empty(), names.is_empty()) {
                (false, _) => Verdict::Allowed(hits),
                (true, false) => Verdict::ByNameOnly,
                (true, true) => Verdict::Outside,
            }
        }
    }
}

/// A destination as an allow entry would be checked against it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Dest {
    Name(String),
    /// An IPv4 address, and its port when known.
    Address(std::net::Ipv4Addr, Option<u16>),
}

impl Dest {
    /// What a report's destination is checked as; `None` for one that is neither.
    pub fn of(d: &EgressDestination) -> Option<Dest> {
        match d {
            EgressDestination::Domain { name } => Some(Dest::Name(name.clone())),
            EgressDestination::Address { ip, port } => Some(Dest::Address(*ip, Some(*port))),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(names: &[&str], ips: &[&str]) -> HubPhase {
        HubPhase::Allow {
            names: names.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn names_match_as_dot_anchored_suffixes() {
        assert!(name_matches("debian.org", "deb.debian.org"));
        assert!(name_matches(".debian.org", "debian.org"));
        assert!(name_matches("Debian.ORG", "deb.debian.org."));
        assert!(!name_matches("debian.org", "notdebian.org"));
        assert!(!name_matches("deb.debian.org", "debian.org"));
        assert!(!name_matches("", "debian.org"));
    }

    #[test]
    fn addresses_match_ranges_and_their_port() {
        let ip = "10.10.140.49".parse().unwrap();
        assert!(ip_matches("10.10.140.49", ip, Some(1)));
        assert!(ip_matches("10.0.0.0/8:443", ip, Some(443)));
        assert!(!ip_matches("10.0.0.0/8:443", ip, Some(80)));
        assert!(!ip_matches("10.0.0.0/8:443", ip, None));
        assert!(ip_matches("0.0.0.0/0", ip, None));
        assert!(!ip_matches("10.10.140.48/32", ip, None));
        assert!(!ip_matches("not an ip", ip, None));
    }

    #[test]
    fn a_phase_names_every_entry_that_allows_a_destination() {
        let p = allow(&["debian.org", "deb.debian.org", "x.org"], &["10.0.0.0/8"]);
        let name = |n: &str| Dest::Name(n.to_string());
        let addr = |a: &str, port| Dest::Address(a.parse().unwrap(), port);
        let deb = name("deb.debian.org");
        assert_eq!(
            verdict(&p, &deb),
            Verdict::Allowed(vec!["debian.org", "deb.debian.org"])
        );
        assert_eq!(verdict(&p, &name("pypi.org")), Verdict::Outside);
        assert_eq!(
            verdict(&p, &addr("192.168.0.1", Some(443))),
            Verdict::ByNameOnly
        );
        assert_eq!(
            verdict(&allow(&[], &["10.0.0.0/8"]), &addr("192.168.0.1", None)),
            Verdict::Outside
        );
        assert_eq!(
            verdict(&p, &addr("10.1.2.3", Some(22))),
            Verdict::Allowed(vec!["10.0.0.0/8"])
        );
        assert_eq!(
            verdict(&HubPhase::Unrestricted, &deb),
            Verdict::Unrestricted
        );
        assert_eq!(verdict(&allow(&[], &[]), &deb), Verdict::Outside);
    }
}
