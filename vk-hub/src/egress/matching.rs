//! Whether a hub layer's phase allows a destination, as a node's switch decides it: a domain
//! against the names, dot-anchored suffixes; an address and port against the IPv4 CIDRs, each
//! optionally scoped to one port. For the Egress page's comparisons only: the node decides, and
//! the hub never computes a rule's effect for it.
//!
//! The switch also carries a connection to an address one of the job's lookups of an allowed
//! name resolved to, which nothing the hub keeps can tell: an address no IP range lists, in a
//! phase that lists names, is [`Verdict::ByNameOnly`], neither allowed nor refused. A phase
//! that restricts refuses every address on DNS's port, [`DNS_PORT`], whatever it lists: the
//! switch sends a job's lookups through its own resolver, so that names it allows are pinned.

use vk_hub_proto::egress::{EgressDestination, HubPhase, parse_allow_ip};

/// DNS's port, which a restricting phase refuses on every address ([`dns_refused`]).
pub const DNS_PORT: u16 = 53;

/// Whether a phase that restricts refuses `d` whatever it lists: an address on [`DNS_PORT`].
/// The switch's own resolver, the one exception, is no destination a report or a person names.
pub fn dns_refused(d: &Dest) -> bool {
    matches!(d, Dest::Address(_, Some(DNS_PORT)))
}

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

/// Whether `allow_ip` entries `a` and `b` share an address and port: the shorter prefix holds
/// both networks, and either names no port or both the same one.
pub fn cidrs_overlap(a: &str, b: &str) -> bool {
    let (Ok((a_ip, a_prefix, a_port)), Ok((b_ip, b_prefix, b_port))) =
        (parse_allow_ip(a), parse_allow_ip(b))
    else {
        return false;
    };
    let mask = match a_prefix.min(b_prefix) {
        0 => 0,
        p => u32::MAX << (32 - u32::from(p.min(32))),
    };
    (u32::from(a_ip) & mask) == (u32::from(b_ip) & mask)
        && match (a_port, b_port) {
            (Some(a), Some(b)) => a == b,
            _ => true,
        }
}

/// Whether `allow_name` entries `a` and `b` share a host: one under the other, either way.
pub fn names_overlap(a: &str, b: &str) -> bool {
    name_matches(a, b.trim_start_matches('.')) || name_matches(b, a.trim_start_matches('.'))
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
    if dns_refused(d) {
        return Verdict::Outside;
    }
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

    /// What a person typed: a DNS name, or an IPv4 address with or without its port. `None`
    /// for anything else.
    pub fn parse(text: &str) -> Option<Dest> {
        let text = text.trim();
        if let Ok(addr) = text.parse::<std::net::SocketAddrV4>() {
            return Some(Dest::Address(*addr.ip(), Some(addr.port())));
        }
        if let Ok(ip) = text.parse::<std::net::Ipv4Addr>() {
            return Some(Dest::Address(ip, None));
        }
        let name = text.trim_end_matches('.').to_ascii_lowercase();
        vk_hub_proto::egress::is_domain(&name).then_some(Dest::Name(name))
    }

    /// As a page shows it: `crates.io`, `10.0.0.1:443`, `10.0.0.1`.
    pub fn text(&self) -> String {
        match self {
            Dest::Name(n) => n.clone(),
            Dest::Address(ip, Some(port)) => format!("{ip}:{port}"),
            Dest::Address(ip, None) => ip.to_string(),
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
        // Ranges overlap wider or narrower, on a port both allow.
        assert!(cidrs_overlap("10.1.0.0/16", "10.0.0.0/8"));
        assert!(cidrs_overlap("10.0.0.0/7", "10.0.0.0/8"));
        assert!(cidrs_overlap("10.1.2.3:443", "10.0.0.0/8:443"));
        assert!(cidrs_overlap("10.1.2.3", "10.0.0.0/8:443"));
        assert!(!cidrs_overlap("10.1.2.3:22", "10.0.0.0/8:443"));
        assert!(!cidrs_overlap("11.0.0.1", "10.0.0.0/8"));
        assert!(!cidrs_overlap("not an ip", "0.0.0.0/0"));
    }

    #[test]
    fn names_overlap_one_under_the_other() {
        assert!(names_overlap("debian.org", "deb.debian.org"));
        assert!(names_overlap(".deb.debian.org", "Debian.ORG"));
        assert!(!names_overlap("debian.org", "notdebian.org"));
        assert!(!names_overlap("a.debian.org", "b.debian.org"));
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
        // DNS goes through the switch's resolver: no entry allows an address on its port.
        let dns = addr("1.1.1.1", Some(53));
        assert_eq!(
            verdict(&allow(&[], &["1.1.1.1/32:53"]), &dns),
            Verdict::Outside
        );
        assert_eq!(verdict(&p, &addr("10.0.0.1", Some(53))), Verdict::Outside);
        assert_eq!(
            verdict(&HubPhase::Unrestricted, &dns),
            Verdict::Unrestricted
        );
        assert_eq!(Dest::parse("https://x"), None);
        assert_eq!(Dest::parse("10.0.0.1:443").unwrap().text(), "10.0.0.1:443");
        assert_eq!(Dest::parse(" Deb.Debian.org. ").unwrap(), deb);
        assert_eq!(Dest::parse("10.0.0.1").unwrap(), addr("10.0.0.1", None));
    }
}
