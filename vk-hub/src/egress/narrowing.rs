//! A job's own egress filter, and its services', as its spec declares them
//! (`MICROVM_EGRESS_ALLOW_*`, `MICROVM_BUILD_EGRESS_ALLOW_*`), for the Egress page's *Test a
//! job*. Each is a layer of its own, which the node checks on its own as the job runs, beside
//! its cap and the hub's rules: it neither narrows them nor is narrowed by them. Within one, a
//! dimension not declared is unrestricted while the other is not declared either, and allows
//! nothing once it is, as the node reads its caps. The node splits a value as [`entries`] does,
//! fails the job on an invalid entry in either dimension ([`Declared::Invalid`], checked as the
//! node checks it), and warns of one a layer above leaves nothing of
//! ([`Narrowing::unreachable`]), which it keeps.
//!
//! The spec the hub keeps is redacted: a variable masked, protected or written to a file reads
//! `[MASKED]`, and is [`Declared::Hidden`]; one whose value the node would expand from other
//! variables is [`Declared::Expands`]. The node ignores a job's empty variable, and takes a
//! service's as an empty list.

use vk_hub_proto::egress::{EgressPhase, HubPhase, check_allow_name, parse_allow_ip};
use vk_hub_proto::job::{CiJob, Variable};

use super::matching::{Dest, cidrs_overlap, dns_refused, ip_matches, name_matches, names_overlap};

/// What a spec declares of one dimension.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Declared {
    /// Nothing.
    Absent,
    /// A value the redacted spec hides.
    Hidden,
    /// A value that names other variables, expanded by the node.
    Expands,
    List(Vec<String>),
    /// A list with these invalid entries, which fail the job.
    Invalid(Vec<String>),
}

/// One VM's filter of one phase, by the variables that declare it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Narrowing {
    pub names: (&'static str, Declared),
    pub ips: (&'static str, Declared),
}

/// What a filter says of a destination, on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Says {
    /// Neither dimension is declared: it restricts nothing.
    Silent,
    /// Its dimension's value is not known here.
    Unknown(&'static str),
    Allows(&'static str),
    /// An address its IP ranges do not list, while names may allow it: only if a lookup of one
    /// of them resolved to it.
    ByNameOnly(&'static str),
    Refuses(&'static str),
    /// An address on DNS's port, which it refuses whatever it lists as it restricts, this
    /// variable declared.
    Dns(&'static str),
    /// This variable has an invalid entry: the job fails before it reaches anything.
    Invalid(&'static str),
    /// Its dimension is not declared while the other, this variable, is: it then allows none of
    /// this one, an address only if a lookup of a declared name resolved to it (`by_name`).
    Undeclared {
        declared: &'static str,
        by_name: bool,
    },
}

impl Narrowing {
    /// Whether it declares anything.
    pub fn declares(&self) -> bool {
        self.names.1 != Declared::Absent || self.ips.1 != Declared::Absent
    }

    /// The variable with an invalid entry, the IPs' first as the node names it.
    pub fn invalid(&self) -> Option<&'static str> {
        [&self.ips, &self.names]
            .into_iter()
            .find(|(_, d)| matches!(d, Declared::Invalid(_)))
            .map(|(v, _)| *v)
    }

    /// What it says of `d` on its own: its dimension's verdict, the variable named. Once either
    /// dimension is declared it restricts the phase, and a dimension it does not declare allows
    /// none. An invalid entry in either dimension says the job fails, whatever `d`.
    pub fn says(&self, d: &Dest) -> Says {
        if let Some(variable) = self.invalid() {
            return Says::Invalid(variable);
        }
        if dns_refused(d)
            && let Some((variable, _)) = [&self.ips, &self.names]
                .into_iter()
                .find(|(_, d)| matches!(d, Declared::List(_)))
        {
            return Says::Dns(variable);
        }
        let ((variable, declared), (other, other_declared), hit): (_, _, &dyn Fn(&str) -> bool) =
            match d {
                Dest::Name(n) => (&self.names, &self.ips, &|e: &str| name_matches(e, n)),
                Dest::Address(ip, port) => {
                    (&self.ips, &self.names, &|e: &str| ip_matches(e, *ip, *port))
                }
            };
        // Whether the names its VM may look up are none, when known: for an address its IPs
        // miss, which a lookup of one of them may still reach.
        let no_names = match &self.names.1 {
            Declared::List(l) => Some(l.is_empty()),
            Declared::Hidden | Declared::Expands => None,
            // The IPs declared restrict the phase: names it does not declare are none.
            Declared::Absent => Some(true),
            Declared::Invalid(_) => Some(true),
        };
        let by_name = matches!(d, Dest::Address(..)) && no_names != Some(true);
        match declared {
            Declared::Hidden | Declared::Expands => Says::Unknown(variable),
            Declared::Invalid(_) => Says::Invalid(variable),
            Declared::List(list) if list.iter().any(|e| hit(e)) => Says::Allows(variable),
            Declared::List(_) if by_name => Says::ByNameOnly(variable),
            Declared::List(_) => Says::Refuses(variable),
            Declared::Absent => match other_declared {
                Declared::Absent => Says::Silent,
                // Hidden, it may be empty, which declares nothing.
                Declared::Hidden | Declared::Expands => Says::Unknown(other),
                Declared::Invalid(_) => Says::Invalid(other),
                Declared::List(_) => Says::Undeclared {
                    declared: other,
                    by_name,
                },
            },
        }
    }

    /// The declared entries a layer above, `above`, leaves nothing of, each with its variable:
    /// a name none of its names overlaps, a range none of its ranges does. The node keeps them,
    /// warns of them and reports them; that layer refuses them when the job runs. None where an
    /// entry is invalid: the job fails first.
    pub fn unreachable<'a>(&'a self, above: &HubPhase) -> Vec<(&'static str, &'a str)> {
        let HubPhase::Allow { names, ips } = above else {
            return Vec::new();
        };
        if self.invalid().is_some() {
            return Vec::new();
        }
        let mut out = Vec::new();
        if let (variable, Declared::List(list)) = &self.ips {
            for e in list {
                if !ips.iter().any(|outer| cidrs_overlap(e, outer)) {
                    out.push((*variable, e.as_str()));
                }
            }
        }
        if let (variable, Declared::List(list)) = &self.names {
            for e in list {
                if !names.iter().any(|n| names_overlap(n, e)) {
                    out.push((*variable, e.as_str()));
                }
            }
        }
        out
    }

    /// It as a layer above a service's: its lists, a dimension not declared none once the
    /// other is; `None` where a value is not known here, is invalid, or it declares nothing.
    pub fn as_phase(&self) -> Option<HubPhase> {
        let list = |d: &Declared| match d {
            Declared::List(l) => Some(l.clone()),
            Declared::Absent => Some(Vec::new()),
            Declared::Hidden | Declared::Expands | Declared::Invalid(_) => None,
        };
        match self.declares() {
            false => None,
            true => Some(HubPhase::Allow {
                names: list(&self.names.1)?,
                ips: list(&self.ips.1)?,
            }),
        }
    }
}

/// How one layer stands for a destination, as a result is made of every layer's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stand {
    Allows,
    /// Only if a lookup of a name it allows resolved to the address.
    ByName,
    /// Not known here.
    Unknown,
    Refuses,
}

impl Says {
    /// How it stands for the destination.
    pub fn stand(&self) -> Stand {
        match self {
            Says::Silent | Says::Allows(_) => Stand::Allows,
            Says::Unknown(_) => Stand::Unknown,
            Says::Refuses(_)
            | Says::Dns(_)
            | Says::Invalid(_)
            | Says::Undeclared { by_name: false, .. } => Stand::Refuses,
            Says::ByNameOnly(_) | Says::Undeclared { by_name: true, .. } => Stand::ByName,
        }
    }
}

/// How phase `p` of a layer stands for `d`; `None`, a layer not known here.
pub fn phase_stand(p: Option<&HubPhase>, d: &Dest) -> Stand {
    use super::matching::{Verdict, verdict};
    match p.map(|p| verdict(p, d)) {
        None => Stand::Unknown,
        Some(Verdict::Unrestricted | Verdict::Allowed(_)) => Stand::Allows,
        Some(Verdict::ByNameOnly) => Stand::ByName,
        Some(Verdict::Outside) => Stand::Refuses,
    }
}

/// The result of layers each standing for a destination, as the node checks each in turn: the
/// first that refuses it decides, by its index; else one that admits it only through a name's
/// lookup, as that lookup must pass every layer too; else one not known; else every layer
/// allows it.
pub fn every(stands: &[Stand]) -> (Stand, Option<usize>) {
    for want in [Stand::Refuses, Stand::ByName, Stand::Unknown] {
        if let Some(i) = stands.iter().position(|s| *s == want) {
            return (want, Some(i));
        }
    }
    (Stand::Allows, None)
}

/// A variable's value split into entries as the node splits it: on commas, spaces, tabs and
/// lines, each `#` starting a comment to the end of its line.
pub fn entries(value: &str) -> Vec<String> {
    value
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(head, _)| head))
        .flat_map(|line| line.split([',', ' ', '\t']))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The variables of `phase`, names then IPs; `None` for a phase this hub does not know.
fn variables(phase: EgressPhase) -> Option<(&'static str, &'static str)> {
    match phase {
        EgressPhase::Run => Some(("MICROVM_EGRESS_ALLOW_NAME", "MICROVM_EGRESS_ALLOW_IP")),
        EgressPhase::Build => Some((
            "MICROVM_BUILD_EGRESS_ALLOW_NAME",
            "MICROVM_BUILD_EGRESS_ALLOW_IP",
        )),
        EgressPhase::Other => None,
    }
}

/// What `vars` declare of `key`: the last of that key, as the later one is exported over it;
/// an empty one declares nothing when `empty_absent`, as for a job. Each entry is checked by
/// `valid`, as the node checks it.
fn declared(vars: &[Variable], key: &str, empty_absent: bool, valid: fn(&str) -> bool) -> Declared {
    match vars.iter().rev().find(|v| v.key == key) {
        None => Declared::Absent,
        Some(v) if !v.public || v.masked || v.file => Declared::Hidden,
        Some(v) if v.value.is_empty() && empty_absent => Declared::Absent,
        Some(v) if !v.raw && v.value.contains('$') => Declared::Expands,
        Some(v) => {
            let list = entries(&v.value);
            let invalid: Vec<String> = list.iter().filter(|e| !valid(e)).cloned().collect();
            match invalid.is_empty() {
                true => Declared::List(list),
                false => Declared::Invalid(invalid),
            }
        }
    }
}

/// The narrowing a job's `vars` declare of `phase`.
pub fn narrowing(vars: &[Variable], phase: EgressPhase) -> Option<Narrowing> {
    narrowing_of(vars, phase, true)
}

fn narrowing_of(vars: &[Variable], phase: EgressPhase, empty_absent: bool) -> Option<Narrowing> {
    let (names, ips) = variables(phase)?;
    Some(Narrowing {
        names: (
            names,
            declared(vars, names, empty_absent, |e| check_allow_name(e).is_ok()),
        ),
        ips: (
            ips,
            declared(vars, ips, empty_absent, |e| parse_allow_ip(e).is_ok()),
        ),
    })
}

/// Whether a job's `vars` ask for a dry-run run phase with `MICROVM_EGRESS_DRY_RUN`, read as the
/// node reads it; a value not readable here asks nothing. The node grants it only where its cap
/// restricts no run phase.
pub fn dry_run_requested(vars: &[Variable]) -> bool {
    vars.iter()
        .rev()
        .find(|v| v.key == "MICROVM_EGRESS_DRY_RUN")
        .is_some_and(|v| {
            v.public
                && !v.masked
                && !v.file
                && matches!(
                    v.value.trim().to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
        })
}

/// The run-phase narrowing each of `ci`'s services declares, by the name it answers to, for
/// those that declare one.
pub fn services(ci: &CiJob) -> Vec<(String, Narrowing)> {
    ci.services
        .iter()
        .filter_map(|s| {
            let n = narrowing_of(&s.variables, EgressPhase::Run, false)?;
            let name = s.aliases.first().cloned().unwrap_or_else(|| s.name.clone());
            n.declares().then_some((name, n))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn var(key: &str, value: &str) -> Variable {
        Variable {
            key: key.into(),
            value: value.into(),
            public: true,
            ..Variable::default()
        }
    }

    #[test]
    fn a_job_declares_its_filter_in_variables_the_last_one_counting() {
        assert_eq!(
            entries("crates.io # Rust\npypi.org, debian.org\n#all\n"),
            ["crates.io", "pypi.org", "debian.org"]
        );
        let vars = [
            var("MICROVM_EGRESS_ALLOW_NAME", "a.example"),
            var("MICROVM_EGRESS_ALLOW_NAME", "corp.example.com b.example"),
            Variable {
                masked: true,
                ..var("MICROVM_BUILD_EGRESS_ALLOW_NAME", "[MASKED]")
            },
        ];
        let run = narrowing(&vars, EgressPhase::Run).unwrap();
        assert_eq!(
            run.names.1,
            Declared::List(vec!["corp.example.com".into(), "b.example".into()])
        );
        assert_eq!(run.ips.1, Declared::Absent);
        let api = Dest::Name("api.corp.example.com".into());
        assert_eq!(run.says(&api), Says::Allows("MICROVM_EGRESS_ALLOW_NAME"));
        assert_eq!(
            run.says(&Dest::Name("a.example".into())),
            Says::Refuses("MICROVM_EGRESS_ALLOW_NAME")
        );
        // Its IP ranges not declared beside its names: none, but what a name resolved to.
        assert_eq!(
            run.says(&Dest::Address("10.0.0.1".parse().unwrap(), Some(1))),
            Says::Undeclared {
                declared: "MICROVM_EGRESS_ALLOW_NAME",
                by_name: true
            }
        );
        let build = narrowing(&vars, EgressPhase::Build).unwrap();
        assert_eq!(
            build.says(&api),
            Says::Unknown("MICROVM_BUILD_EGRESS_ALLOW_NAME")
        );
        assert!(narrowing(&[], EgressPhase::Run).is_some_and(|n| !n.declares()));
        // An empty job variable declares nothing; one naming another is expanded on the node.
        let vars = [
            var("MICROVM_EGRESS_ALLOW_NAME", ""),
            var("MICROVM_EGRESS_ALLOW_IP", "$CORP_RANGE"),
        ];
        let run = narrowing(&vars, EgressPhase::Run).unwrap();
        assert_eq!(
            (&run.names.1, &run.ips.1),
            (&Declared::Absent, &Declared::Expands)
        );
        assert_eq!(run.as_phase(), None);

        // An address its ranges miss may still come through a listed name's lookup.
        let vars = [
            var("MICROVM_EGRESS_ALLOW_NAME", "corp.example.com"),
            var("MICROVM_EGRESS_ALLOW_IP", "10.0.0.0/8:443 192.168.1.1"),
        ];
        let run = narrowing(&vars, EgressPhase::Run).unwrap();
        let addr = Dest::Address("172.16.0.1".parse().unwrap(), Some(443));
        assert_eq!(run.says(&addr), Says::ByNameOnly("MICROVM_EGRESS_ALLOW_IP"));
        // What a layer above leaves nothing of is reported, never what only overlaps it.
        let hub = HubPhase::Allow {
            names: vec!["example.com".into()],
            ips: vec!["10.0.0.0/8".into()],
        };
        assert_eq!(
            run.unreachable(&hub),
            [("MICROVM_EGRESS_ALLOW_IP", "192.168.1.1")]
        );
        assert!(run.unreachable(&HubPhase::Unrestricted).is_empty());
        let narrow = HubPhase::Allow {
            names: vec!["api.corp.example.com".into()],
            ips: vec![],
        };
        assert_eq!(
            run.unreachable(&narrow),
            [
                ("MICROVM_EGRESS_ALLOW_IP", "10.0.0.0/8:443"),
                ("MICROVM_EGRESS_ALLOW_IP", "192.168.1.1"),
            ]
        );
        // As a layer above a service's.
        assert_eq!(
            run.as_phase(),
            Some(HubPhase::Allow {
                names: vec!["corp.example.com".into()],
                ips: vec!["10.0.0.0/8:443".into(), "192.168.1.1".into()],
            })
        );
    }

    /// Each combination of a dimension absent, declared empty or listed says, on its own, what
    /// the node enforces of the filter: once either dimension is listed, the other is what it
    /// lists, nothing if it lists none. Then, beside a node's cap restricting nothing,
    /// restricting the phase, or not known, the result is what every layer allows: the first
    /// to refuse decides it.
    #[test]
    fn a_filter_says_what_the_node_enforces_and_every_layer_decides() {
        use Says::*;
        const N: &str = "MICROVM_EGRESS_ALLOW_NAME";
        const I: &str = "MICROVM_EGRESS_ALLOW_IP";
        // Its range holds the listed address, not the other.
        let cap_allow = HubPhase::Allow {
            names: vec!["corp.example".into()],
            ips: vec!["10.1.0.0/16".into()],
        };
        let caps = [Some(&HubPhase::Unrestricted), Some(&cap_allow), None];
        let decl = |c: char, entry: &str| match c {
            'a' => Declared::Absent,
            'e' => Declared::List(vec![]),
            _ => Declared::List(vec![entry.to_string()]),
        };
        let name = Dest::Name("api.corp.example".into());
        let listed = Dest::Address("10.1.2.3".parse().unwrap(), Some(443));
        let other = Dest::Address("10.9.9.9".parse().unwrap(), Some(443));
        let u = |declared, by_name| Undeclared { declared, by_name };
        // (names, ips): what it says of the name, of an address the IPs list, and of one they do
        // not.
        let table: [(&str, [Says; 3]); 9] = [
            ("aa", [Silent, Silent, Silent]),
            ("ae", [u(I, false), Refuses(I), Refuses(I)]),
            ("al", [u(I, false), Allows(I), Refuses(I)]),
            ("ea", [Refuses(N), u(N, false), u(N, false)]),
            ("ee", [Refuses(N), Refuses(I), Refuses(I)]),
            ("el", [Refuses(N), Allows(I), Refuses(I)]),
            ("la", [Allows(N), u(N, true), u(N, true)]),
            ("le", [Allows(N), ByNameOnly(I), ByNameOnly(I)]),
            ("ll", [Allows(N), Allows(I), ByNameOnly(I)]),
        ];
        // Beside the cap — unrestricted, restricting, not known — the result for each
        // destination, and the layer deciding it: 0 the cap, 1 the job's filter.
        use Stand::{Allows as A, ByName as B, Refuses as R, Unknown as Q};
        type ByDest = [(Stand, Option<usize>); 3];
        let results: [[ByDest; 3]; 9] = [
            [
                [(A, None), (A, None), (A, None)],
                [(A, None), (A, None), (B, Some(0))],
                [(Q, Some(0)), (Q, Some(0)), (Q, Some(0))],
            ],
            [
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
            ],
            [
                [(R, Some(1)), (A, None), (R, Some(1))],
                [(R, Some(1)), (A, None), (R, Some(1))],
                [(R, Some(1)), (Q, Some(0)), (R, Some(1))],
            ],
            [
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
            ],
            [
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
                [(R, Some(1)), (R, Some(1)), (R, Some(1))],
            ],
            [
                [(R, Some(1)), (A, None), (R, Some(1))],
                [(R, Some(1)), (A, None), (R, Some(1))],
                [(R, Some(1)), (Q, Some(0)), (R, Some(1))],
            ],
            [
                [(A, None), (B, Some(1)), (B, Some(1))],
                [(A, None), (B, Some(1)), (B, Some(0))],
                [(Q, Some(0)), (B, Some(1)), (B, Some(1))],
            ],
            [
                [(A, None), (B, Some(1)), (B, Some(1))],
                [(A, None), (B, Some(1)), (B, Some(0))],
                [(Q, Some(0)), (B, Some(1)), (B, Some(1))],
            ],
            [
                [(A, None), (A, None), (B, Some(1))],
                [(A, None), (A, None), (B, Some(0))],
                [(Q, Some(0)), (Q, Some(0)), (B, Some(1))],
            ],
        ];
        // The other dimension hidden, or expanded on the node: it may be empty, declaring
        // nothing.
        for hidden in [Declared::Hidden, Declared::Expands] {
            let n = Narrowing {
                names: (N, Declared::Absent),
                ips: (I, hidden),
            };
            assert_eq!(n.says(&name), Unknown(I));
        }
        for ((dims, says), by_cap) in table.iter().zip(&results) {
            let mut chars = dims.chars();
            let (n, i) = (chars.next().unwrap(), chars.next().unwrap());
            let filter = Narrowing {
                names: (N, decl(n, "corp.example")),
                ips: (I, decl(i, "10.1.0.0/16")),
            };
            let dests = [&name, &listed, &other];
            assert_eq!(&dests.map(|d| filter.says(d)), says, "names {n}, ips {i}");
            for (cap, want) in caps.iter().zip(by_cap) {
                let got = dests.map(|d| every(&[phase_stand(*cap, d), filter.says(d).stand()]));
                assert_eq!(&got, want, "names {n}, ips {i}, cap {cap:?}");
            }
        }
    }

    /// An invalid entry in either dimension fails the job, whatever the destination, as the node
    /// refuses the whole declaration; an address on DNS's port is refused once it restricts.
    #[test]
    fn an_invalid_entry_fails_the_job_and_dns_goes_to_the_resolver() {
        let vars = [
            var("MICROVM_EGRESS_ALLOW_NAME", "example.com bad/name"),
            var("MICROVM_EGRESS_ALLOW_IP", "10.0.0.0/8"),
        ];
        let run = narrowing(&vars, EgressPhase::Run).unwrap();
        assert_eq!(run.names.1, Declared::Invalid(vec!["bad/name".into()]));
        let name = Dest::Name("example.com".into());
        assert_eq!(run.says(&name), Says::Invalid("MICROVM_EGRESS_ALLOW_NAME"));
        assert_eq!(run.says(&name).stand(), Stand::Refuses);
        let addr = Dest::Address("10.0.0.1".parse().unwrap(), Some(443));
        assert_eq!(run.says(&addr), Says::Invalid("MICROVM_EGRESS_ALLOW_NAME"));
        assert_eq!(run.as_phase(), None);
        let hub = HubPhase::Allow {
            names: Vec::new(),
            ips: Vec::new(),
        };
        assert!(run.unreachable(&hub).is_empty());
        // The IPs' invalid entry is the one named, as the node names it.
        let vars = [
            var("MICROVM_EGRESS_ALLOW_NAME", "https://x"),
            var("MICROVM_EGRESS_ALLOW_IP", "10.0.0.0/33"),
        ];
        let run = narrowing(&vars, EgressPhase::Run).unwrap();
        assert_eq!(run.invalid(), Some("MICROVM_EGRESS_ALLOW_IP"));

        let vars = [var("MICROVM_EGRESS_ALLOW_IP", "1.1.1.1/32:53")];
        let run = narrowing(&vars, EgressPhase::Run).unwrap();
        let dns = Dest::Address("1.1.1.1".parse().unwrap(), Some(53));
        assert_eq!(run.says(&dns), Says::Dns("MICROVM_EGRESS_ALLOW_IP"));
        assert_eq!(run.says(&dns).stand(), Stand::Refuses);
        assert!(narrowing(&[], EgressPhase::Run).is_some_and(|n| n.says(&dns) == Says::Silent));
    }

    #[test]
    fn a_job_asks_for_dry_run_with_a_readable_truthy_value() {
        assert!(dry_run_requested(&[var("MICROVM_EGRESS_DRY_RUN", " On ")]));
        assert!(!dry_run_requested(&[var("MICROVM_EGRESS_DRY_RUN", "0")]));
        assert!(!dry_run_requested(&[
            var("MICROVM_EGRESS_DRY_RUN", "1"),
            var("MICROVM_EGRESS_DRY_RUN", "no"),
        ]));
        let masked = Variable {
            masked: true,
            ..var("MICROVM_EGRESS_DRY_RUN", "1")
        };
        assert!(!dry_run_requested(&[masked]));
    }
}
