//! What a node saw of a placed job's egress ([`EgressReport`]), sent with the job's result: the
//! destinations its switches refused, or would have under dry-run, and those its guests
//! reached; the egress declarations that failed the job before anything ran; and how much of
//! each phase the node recorded, so that no report never reads as no traffic.
//!
//! Destinations, service names and declared entries are the job's or its guests' to choose.
//! [`EgressReport::bounded`] holds a report to the bounds below and replaces the characters
//! that could rewrite a terminal or a page; the node applies it before sending and the hub
//! again on receipt. A destination that is neither a domain nor an IPv4 address and port stays
//! [`EgressDestination::Malformed`] text, which nothing may turn into an allow entry.
//!
//! The hub's own layer for a job ([`HubEgress`]), resolved from its rules, goes the other way,
//! in the job's start: what each phase may reach under the rules enforced, and under each
//! dry-run rule were it enforced. The node enforces the first below its own cap and reports
//! what the others would deny.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// The most denials (blocked and would-block entries) a report lists.
pub const MAX_EGRESS_DENIALS: usize = 512;
/// The most observed entries a report lists.
pub const MAX_EGRESS_CONTACTS: usize = 512;
/// The most declaration refusals a report lists.
pub const MAX_EGRESS_REFUSALS: usize = 64;
/// The most phases a report accounts for: each appears once.
pub const MAX_EGRESS_PHASES: usize = 4;
/// The largest serialized report, in bytes.
pub const MAX_EGRESS_REPORT: usize = 256 * 1024;
// A result carrying a whole report still fits one session message, with room for the rest.
const _: () = assert!(MAX_EGRESS_REPORT < crate::MAX_MESSAGE / 2);
/// The longest text a report carries in any one field, in bytes.
pub const MAX_EGRESS_TEXT: usize = 255;
/// The longest domain name, in bytes (RFC 1035, without the root's dot).
const MAX_DOMAIN: usize = 253;

/// A job's egress as its node recorded it: a cumulative snapshot. The hub keeps the one with
/// the highest `revision`, so a snapshot sent again replaces the counts rather than adding to
/// them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressReport {
    #[serde(default)]
    pub revision: u64,
    /// Denials first, then what was observed, each in the order first seen.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<EgressEntry>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refusals: Vec<EgressRefusal>,
    /// Refusals past [`MAX_EGRESS_REFUSALS`].
    #[serde(default, skip_serializing_if = "is_zero")]
    pub refusals_omitted: u64,
    /// Each phase the job ran, once; a phase it never reached is absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phases: Vec<EgressPhaseReport>,
    /// The enforced hub rules the job ran under ([`HubEgress::rules`]), which together decide
    /// every denial by [`EgressLayer::HubRule`] but a dry-run one; empty without a hub layer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hub_rules: Vec<String>,
}

/// One destination, as one VM reached it or was refused it in one phase, with the same
/// outcome and, for a denial, by the same layer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressEntry {
    pub outcome: EgressOutcome,
    pub protocol: EgressProtocol,
    pub destination: EgressDestination,
    pub phase: EgressPhase,
    pub source: EgressSource,
    /// The layer that decided a denial; absent from an observed entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<EgressLayer>,
    /// The attempts it stands for: lookups for DNS, connections or flows otherwise.
    pub count: u64,
    /// Milliseconds since the Unix epoch.
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// The job's stage when it was first seen, when the node knows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// The dry-run hub rule that would have refused it ([`DryRunRule::rule`]): a would-block
    /// entry of [`EgressLayer::HubRule`] only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressOutcome {
    /// Refused.
    Blocked,
    /// A dry-run allowlist would have refused it, and the switch carried it.
    WouldBlock,
    /// Allowed and seen: for DNS a lookup, not proof of a connection.
    Observed,
    /// An outcome from a later peer.
    #[serde(other)]
    Other,
}

impl EgressOutcome {
    /// Whether it is a denial, and counts toward [`MAX_EGRESS_DENIALS`] rather than
    /// [`MAX_EGRESS_CONTACTS`].
    pub fn is_denial(self) -> bool {
        !matches!(self, EgressOutcome::Observed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressProtocol {
    Dns,
    Tcp,
    Udp,
    /// A protocol from a later peer, or one the node did not record.
    #[serde(other)]
    Other,
}

/// Where a flow went, typed as an allow entry would name it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EgressDestination {
    /// A DNS name, lower-cased.
    Domain {
        name: String,
    },
    Address {
        ip: Ipv4Addr,
        port: u16,
    },
    /// Neither: what the guest sent, cut and with its control characters replaced. Never the
    /// seed of an allow entry.
    Malformed {
        text: String,
    },
    /// A kind from a later peer.
    #[serde(other)]
    Other,
}

impl EgressDestination {
    /// `name` as a domain, or malformed text when it is not one.
    pub fn domain(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if is_domain(&lower) {
            EgressDestination::Domain { name: lower }
        } else {
            EgressDestination::Malformed {
                text: safe_text(name),
            }
        }
    }

    /// `text`, an `ip:port`, as an address, or malformed text when it is not one.
    pub fn address(text: &str) -> Self {
        match text.parse::<std::net::SocketAddrV4>() {
            Ok(addr) => EgressDestination::Address {
                ip: *addr.ip(),
                port: addr.port(),
            },
            Err(_) => EgressDestination::Malformed {
                text: safe_text(text),
            },
        }
    }

    /// Whether an allow entry may be written from it: a domain or an address.
    pub fn allowable(&self) -> bool {
        matches!(
            self,
            EgressDestination::Domain { .. } | EgressDestination::Address { .. }
        )
    }
}

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

/// The VM a flow came from: in the build phase, the VM whose image was being built.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EgressSource {
    Job,
    Service {
        name: String,
    },
    /// A source from a later peer, or a service whose name was too long to keep.
    #[serde(other)]
    Other,
}

/// The layer that decided a denial, or that a declaration falls outside
/// (`docs/fleet-design.md`, *Job egress from the hub*).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressLayer {
    /// The node's `[egress]` or `[egress.build]`.
    NodeCap,
    /// The hub's rule for the job.
    HubRule,
    /// The job's `MICROVM_EGRESS_*` or `MICROVM_BUILD_EGRESS_*`.
    Job,
    /// A service's own `MICROVM_EGRESS_*`.
    Service,
    /// A layer the node could not tell, or one from a later peer.
    #[serde(other)]
    Unknown,
}

impl EgressLayer {
    /// How the wire names it.
    pub fn as_str(self) -> &'static str {
        match self {
            EgressLayer::NodeCap => "node_cap",
            EgressLayer::HubRule => "hub_rule",
            EgressLayer::Job => "job",
            EgressLayer::Service => "service",
            EgressLayer::Unknown => "unknown",
        }
    }

    /// The layer named `s` by [`EgressLayer::as_str`]; [`EgressLayer::Unknown`] otherwise.
    pub fn parse(s: &str) -> Self {
        match s {
            "node_cap" => EgressLayer::NodeCap,
            "hub_rule" => EgressLayer::HubRule,
            "job" => EgressLayer::Job,
            "service" => EgressLayer::Service,
            _ => EgressLayer::Unknown,
        }
    }
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
/// qualified name (a trailing dot) would match nothing, and a comma would split it where a list
/// travels comma-joined. The hub holds its rules to it, so that it never sends what a node would
/// refuse.
pub fn check_allow_name(name: &str) -> Result<(), String> {
    let bare = name.trim_start_matches('.');
    if bare.is_empty()
        || bare.ends_with('.')
        || bare.contains(|c: char| c.is_whitespace() || "/:@*,".contains(c))
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

/// A node's own egress caps, `[egress]` and `[egress.build]`, as its inventory reports them
/// (`docs/fleet-design.md`, *Layers*): what each phase may ever reach on that node, so that the
/// hub can show the cap beside its own layer. Absent from older nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeEgressCaps {
    Listed(EgressCaps),
    /// A list past [`MAX_HUB_ENTRIES`], or an entry past 253 bytes: not reported, rather than
    /// cut short into a cap that reads complete.
    TooLarge,
    /// A kind from a later peer, or caps the hub could not read.
    #[serde(other)]
    Other,
}

/// A node's caps, each phase as a hub layer's reads ([`HubPhase`]): unrestricted when the node
/// lists neither dimension, and once it lists one, an allowlist whose other dimension, unlisted,
/// is empty. Normalized ([`EgressCaps::normalized`]), so that the same caps always read the same
/// and carry the same fingerprint, which versions them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressCaps {
    /// The hex SHA-256 of [`EgressCaps::canonical`].
    pub fingerprint: String,
    /// What the run phase may reach: under `[net] mode = "switch"`, `[egress]`; with no network,
    /// nothing; over a tap, whatever the host's network reaches.
    pub run: HubPhase,
    /// `[egress] dry_run`: the run phase's cap reports what it would refuse, and refuses
    /// nothing.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub run_dry_run: bool,
    /// `[egress.build]`.
    pub build: HubPhase,
}

impl EgressCaps {
    /// `run` and `build` normalized — names lower-cased and their leading dots dropped, ranges
    /// trimmed, each list sorted and each entry once — with an empty fingerprint, for the node
    /// to set from [`EgressCaps::canonical`]. `None` past the bounds.
    pub fn normalized(run: HubPhase, run_dry_run: bool, build: HubPhase) -> Option<EgressCaps> {
        let norm = |p: HubPhase| -> Option<HubPhase> {
            let HubPhase::Allow { names, ips } = p else {
                return Some(p);
            };
            let mut names: Vec<String> = names
                .iter()
                .map(|n| n.trim().trim_start_matches('.').to_ascii_lowercase())
                .collect();
            let mut ips: Vec<String> = ips.iter().map(|i| i.trim().to_string()).collect();
            for list in [&mut names, &mut ips] {
                list.sort();
                list.dedup();
                if list.len() > MAX_HUB_ENTRIES || list.iter().any(|e| e.len() > MAX_DOMAIN) {
                    return None;
                }
            }
            Some(HubPhase::Allow { names, ips })
        };
        Some(EgressCaps {
            fingerprint: String::new(),
            run: norm(run)?,
            run_dry_run,
            build: norm(build)?,
        })
    }

    /// What its fingerprint hashes: its phases and its dry-run, as JSON.
    pub fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(&(&self.run, self.run_dry_run, &self.build)).unwrap_or_default()
    }

    /// Hold it to the bounds and to what a node's switch takes: each phase unrestricted or an
    /// allowlist, at most [`MAX_HUB_ENTRIES`] valid entries per dimension, normalized, and a
    /// well-formed fingerprint. Whether the fingerprint is the canonical form's hash is the
    /// reader's to check: this crate hashes nothing.
    pub fn check(&self) -> Result<(), String> {
        if !crate::valid_sha256(&self.fingerprint) {
            return Err("the caps' fingerprint is not a SHA-256".to_string());
        }
        for (what, p) in [("run", &self.run), ("build", &self.build)] {
            p.check(&format!("the node's {what}-phase cap"))?;
            if let HubPhase::Allow { names, ips } = p {
                if let Some(e) = names.iter().chain(ips).find(|e| safe_text(e) != **e) {
                    return Err(format!(
                        "the {what}-phase cap lists {:?}, which is not an entry",
                        safe_text(e)
                    ));
                }
                for n in names {
                    check_allow_name(n)
                        .map_err(|e| format!("the {what}-phase cap's names: {e}"))?;
                }
                for i in ips {
                    parse_allow_ip(i).map_err(|e| format!("the {what}-phase cap's ips: {e}"))?;
                }
            }
            let normal =
                EgressCaps::normalized(p.clone(), false, HubPhase::Unrestricted).map(|c| c.run);
            if normal.as_ref() != Some(p) {
                return Err(format!("the node's {what}-phase cap is not normalized"));
            }
        }
        Ok(())
    }
}

/// A job's or a service's `MICROVM_*EGRESS_ALLOW_*` entry its node found fault with at
/// validation: one that failed the job ([`RefusalReason::fails_job`]), or one kept that a layer
/// above leaves nothing of. Nothing was attempted, so it has no count.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressRefusal {
    /// The variable that declared it, e.g. `MICROVM_EGRESS_ALLOW_NAME`.
    pub variable: String,
    pub entry: String,
    pub dimension: EgressDimension,
    pub phase: EgressPhase,
    pub source: EgressSource,
    /// The layer it falls outside; absent for an entry that is not valid at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<EgressLayer>,
    pub reason: RefusalReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressDimension {
    /// A DNS-name suffix.
    Name,
    /// An IPv4 CIDR, optionally port-scoped.
    Ip,
    #[serde(other)]
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalReason {
    /// Not a name suffix or a CIDR at all: the job failed.
    InvalidEntry,
    /// Valid, and kept, but outside the layer above ([`EgressRefusal::layer`]): nothing it lists
    /// passes that layer, an address only through a name the layer allows. The job runs.
    Unreachable,
    #[serde(other)]
    Other,
}

impl RefusalReason {
    /// Whether the job failed for it; `None` for a reason from a later node.
    pub fn fails_job(self) -> Option<bool> {
        match self {
            RefusalReason::InvalidEntry => Some(true),
            RefusalReason::Unreachable => Some(false),
            RefusalReason::Other => None,
        }
    }
}

/// How much of one phase the node recorded, and what it forwarded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressPhaseReport {
    pub phase: EgressPhase,
    pub coverage: EgressCoverage,
    /// Attempts seen but not listed, past the bounds.
    #[serde(default, skip_serializing_if = "EgressOmitted::is_empty")]
    pub omitted: EgressOmitted,
    /// Payload bytes forwarded out of the phase's guests and into them; absent when the node
    /// did not count them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sent_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_bytes: Option<u64>,
    /// The fingerprint of the node's caps ([`EgressCaps::fingerprint`]) the phase was held to,
    /// as the node's config said them where it enforced them; [`UNKNOWN_CAPS`] when its VMs
    /// were held to more than one, or to caps too large to report. Absent from older nodes,
    /// whose jobs were held to the caps they were placed under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caps: Option<String>,
}

/// [`EgressPhaseReport::caps`] when no one fingerprint says them.
pub const UNKNOWN_CAPS: &str = "unknown";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressCoverage {
    /// Everything the phase's switches recorded is in the report.
    Complete,
    /// Some of it is not: past the bounds, or past what the node could read.
    Partial,
    /// The phase ran, but nothing recorded its egress.
    Unavailable,
    #[serde(other)]
    Other,
}

/// Attempts left out of a report, by outcome.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressOmitted {
    #[serde(default, skip_serializing_if = "is_zero")]
    pub blocked: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub would_block: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub observed: u64,
}

impl EgressOmitted {
    pub fn is_empty(&self) -> bool {
        *self == EgressOmitted::default()
    }

    /// Count `n` attempts with `outcome` as left out. An outcome from a later peer has no
    /// counter of its own and counts as blocked.
    pub fn add(&mut self, outcome: EgressOutcome, n: u64) {
        let counter = match outcome {
            EgressOutcome::Observed => &mut self.observed,
            EgressOutcome::WouldBlock => &mut self.would_block,
            EgressOutcome::Blocked | EgressOutcome::Other => &mut self.blocked,
        };
        *counter = counter.saturating_add(n);
    }
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// Whether `name` is a DNS name as an allow entry may name one: dot-separated labels of 1 to
/// 63 ASCII letters, digits, `-` and `_`, no label starting or ending with `-`, at most 253
/// bytes, no trailing dot.
pub fn is_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_DOMAIN
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
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

/// `s` if it is already safe and within [`MAX_EGRESS_TEXT`], so that it can stand for an
/// identity: a cut or rewritten name could name something else.
fn exact_text(s: &str) -> Option<&str> {
    (safe_text(s) == s).then_some(s)
}

impl EgressSource {
    fn bounded(self) -> Self {
        match self {
            EgressSource::Service { name } => match exact_text(&name) {
                Some(_) => EgressSource::Service { name },
                None => EgressSource::Other,
            },
            other => other,
        }
    }
}

impl EgressDestination {
    fn bounded(self) -> Self {
        match self {
            // Checked whole, before any cut: a prefix of an overlong name is a different name.
            EgressDestination::Domain { name } => EgressDestination::domain(&name),
            EgressDestination::Malformed { text } => EgressDestination::Malformed {
                text: safe_text(&text),
            },
            other => other,
        }
    }
}

impl EgressEntry {
    fn bounded(self) -> Self {
        EgressEntry {
            destination: self.destination.bounded(),
            source: self.source.bounded(),
            // A layer is a denial's alone.
            layer: self.layer.filter(|_| self.outcome.is_denial()),
            last_seen_ms: self.last_seen_ms.max(self.first_seen_ms),
            stage: self.stage.map(|s| safe_text(&s)),
            // A dry-run rule's would-be denial alone names its rule, and only by its exact name.
            rule: self.rule.filter(|r| {
                self.outcome == EgressOutcome::WouldBlock
                    && self.layer == Some(EgressLayer::HubRule)
                    && valid_rule_name(r)
            }),
            ..self
        }
    }
}

impl EgressRefusal {
    fn bounded(self) -> Self {
        EgressRefusal {
            variable: safe_text(&self.variable),
            entry: safe_text(&self.entry),
            source: self.source.bounded(),
            ..self
        }
    }
}

impl EgressReport {
    /// The report as the last of a job whose reporting stopped before the job ended, its
    /// driver lost or the job ended by the hub: what it recorded of each phase is complete only
    /// as far as it went, so [`EgressCoverage::Partial`], and its revision is past this one's.
    pub fn interrupted(mut self) -> Self {
        self.revision = self.revision.saturating_add(1);
        for p in &mut self.phases {
            if p.coverage == EgressCoverage::Complete {
                p.coverage = EgressCoverage::Partial;
            }
        }
        self
    }

    /// The report held to the bounds: its text made safe ([`safe_text`]), every domain checked
    /// again, at most [`MAX_EGRESS_DENIALS`] denials, [`MAX_EGRESS_CONTACTS`] observed entries
    /// and [`MAX_EGRESS_REFUSALS`] refusals, each phase once, and at most [`MAX_EGRESS_REPORT`]
    /// bytes serialized. The entries kept are the first; those past a bound are counted in
    /// their phase's `omitted`, and that phase becomes [`EgressCoverage::Partial`]. Pure, and
    /// idempotent: the hub applies it to what a node sends.
    pub fn bounded(self) -> Self {
        let mut phases: Vec<EgressPhaseReport> = Vec::new();
        for mut p in self.phases {
            // Anything but a fingerprint says the caps are not known, never that they are absent.
            if p.caps.as_deref().is_some_and(|c| !crate::valid_sha256(c)) {
                p.caps = Some(UNKNOWN_CAPS.to_string());
            }
            if phases.len() < MAX_EGRESS_PHASES && !phases.iter().any(|q| q.phase == p.phase) {
                phases.push(p);
            }
        }
        let (mut denials, mut contacts) = (0, 0);
        let mut entries = Vec::new();
        for e in self.entries {
            let e = e.bounded();
            let (kept, max) = match e.outcome.is_denial() {
                true => (&mut denials, MAX_EGRESS_DENIALS),
                false => (&mut contacts, MAX_EGRESS_CONTACTS),
            };
            if *kept < max {
                *kept += 1;
                entries.push(e);
            } else {
                omit(&mut phases, &e);
            }
        }
        let mut refusals: Vec<EgressRefusal> = Vec::new();
        let mut refusals_omitted = self.refusals_omitted;
        // Those that failed the job first, each kind in its order: past the bound only
        // warnings are left out while any failure is listed, so the failure cause stays shown.
        let mut sorted = self.refusals;
        sorted.sort_by_key(|r| r.reason.fails_job() == Some(false));
        for r in sorted {
            if refusals.len() < MAX_EGRESS_REFUSALS {
                refusals.push(r.bounded());
            } else {
                refusals_omitted = refusals_omitted.saturating_add(1);
            }
        }
        let mut hub_rules: Vec<String> = Vec::new();
        for r in self.hub_rules {
            if hub_rules.len() < MAX_HUB_RULES && valid_rule_name(&r) && !hub_rules.contains(&r) {
                hub_rules.push(r);
            }
        }
        let mut report = EgressReport {
            revision: self.revision,
            entries: Vec::new(),
            refusals,
            refusals_omitted,
            phases,
            hub_rules,
        };
        // Within the size bound, from the last entry back. A JSON array of entries is their
        // serializations joined by commas, so its size is a sum; the report around it is
        // measured with the omissions counted so far, so a second pass cuts nothing more.
        let lens: Vec<usize> = entries.iter().map(|e| json_len(e) + 1).collect();
        let mut total: usize = lens.iter().sum();
        // `"entries":[` and `]`, and the comma before them.
        const AROUND: usize = 13;
        while json_len(&report) + total + AROUND > MAX_EGRESS_REPORT {
            let (Some(e), Some(len)) = (entries.pop(), lens.get(entries.len())) else {
                break;
            };
            total -= len;
            omit(&mut report.phases, &e);
        }
        report.entries = entries;
        report
    }
}

/// Count `e` as left out of its phase, which is then [`EgressCoverage::Partial`]. An entry of
/// a phase the report does not account for adds that phase; past [`MAX_EGRESS_PHASES`], none.
fn omit(phases: &mut Vec<EgressPhaseReport>, e: &EgressEntry) {
    let at = match phases.iter().position(|p| p.phase == e.phase) {
        Some(at) => at,
        None if phases.len() < MAX_EGRESS_PHASES => {
            phases.push(EgressPhaseReport {
                phase: e.phase,
                coverage: EgressCoverage::Partial,
                omitted: EgressOmitted::default(),
                sent_bytes: None,
                received_bytes: None,
                caps: None,
            });
            phases.len() - 1
        }
        None => return,
    };
    if let Some(p) = phases.get_mut(at) {
        p.omitted.add(e.outcome, e.count);
        if p.coverage == EgressCoverage::Complete {
            p.coverage = EgressCoverage::Partial;
        }
    }
}

/// The serialized length of `v`; one that does not serialize counts as too large.
fn json_len<T: Serialize>(v: &T) -> usize {
    serde_json::to_vec(v).map_or(usize::MAX / 2, |v| v.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(outcome: EgressOutcome, destination: EgressDestination) -> EgressEntry {
        EgressEntry {
            outcome,
            protocol: EgressProtocol::Dns,
            destination,
            phase: EgressPhase::Run,
            source: EgressSource::Job,
            layer: outcome.is_denial().then_some(EgressLayer::Job),
            count: 2,
            first_seen_ms: 1_000,
            last_seen_ms: 2_000,
            stage: Some("step_script".into()),
            rule: None,
        }
    }

    fn run_phase() -> EgressPhaseReport {
        EgressPhaseReport {
            phase: EgressPhase::Run,
            coverage: EgressCoverage::Complete,
            omitted: EgressOmitted::default(),
            sent_bytes: Some(10),
            received_bytes: Some(20),
            caps: None,
        }
    }

    /// A phase names the caps it was held to, absent from an older node's report; anything but
    /// a fingerprint reads as caps not known, never as none named.
    #[test]
    fn a_phase_names_the_caps_it_was_held_to() {
        let old: EgressPhaseReport =
            serde_json::from_value(json!({"phase": "run", "coverage": "complete"})).unwrap();
        assert_eq!(old.caps, None);
        let held = EgressPhaseReport {
            caps: Some("ab".repeat(32)),
            ..run_phase()
        };
        let json = serde_json::to_value(&held).unwrap();
        assert_eq!(json["caps"], json!("ab".repeat(32)));
        assert_eq!(
            serde_json::from_value::<EgressPhaseReport>(json).unwrap(),
            held
        );
        assert!(
            serde_json::to_value(run_phase())
                .unwrap()
                .get("caps")
                .is_none()
        );
        let report = |caps: &str| EgressReport {
            phases: vec![EgressPhaseReport {
                caps: Some(caps.to_string()),
                ..run_phase()
            }],
            ..EgressReport::default()
        };
        let bounded = |caps: &str| report(caps).bounded().phases[0].caps.clone();
        assert_eq!(bounded(&"ab".repeat(32)), Some("ab".repeat(32)));
        for bad in ["", "ab", UNKNOWN_CAPS, &"x".repeat(64), &"a".repeat(10_000)] {
            assert_eq!(bounded(bad).as_deref(), Some(UNKNOWN_CAPS), "{bad}");
        }
    }

    #[test]
    fn allow_entries_are_read_as_a_node_reads_them() {
        for ok in ["debian.org", ".debian.org", "a_b.example"] {
            assert!(check_allow_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", ".", "debian.org.", "https://x", "*.x", "a b", "u@x"] {
            assert!(check_allow_name(bad).is_err(), "{bad}");
        }
        // A list's separator: a cap travels to the switch comma-joined.
        assert!(check_allow_name("a.x,b.x").is_err());
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

    /// The wire form, pinned: a hub reads what any node of this version sends.
    #[test]
    fn a_report_is_pinned_on_the_wire() {
        let report = EgressReport {
            revision: 1,
            entries: vec![
                entry(
                    EgressOutcome::Blocked,
                    EgressDestination::domain("Evil.Example"),
                ),
                EgressEntry {
                    protocol: EgressProtocol::Tcp,
                    source: EgressSource::Service { name: "db".into() },
                    stage: None,
                    ..entry(
                        EgressOutcome::Observed,
                        EgressDestination::address("10.0.0.1:443"),
                    )
                },
            ],
            refusals: vec![EgressRefusal {
                variable: "MICROVM_BUILD_EGRESS_ALLOW_NAME".into(),
                entry: "crates.io".into(),
                dimension: EgressDimension::Name,
                phase: EgressPhase::Build,
                source: EgressSource::Job,
                layer: Some(EgressLayer::NodeCap),
                reason: RefusalReason::Unreachable,
            }],
            refusals_omitted: 0,
            phases: vec![run_phase()],
            hub_rules: Vec::new(),
        };
        let wire = json!({
            "revision": 1,
            "entries": [
                {"outcome": "blocked", "protocol": "dns",
                 "destination": {"kind": "domain", "name": "evil.example"},
                 "phase": "run", "source": {"kind": "job"}, "layer": "job", "count": 2,
                 "first_seen_ms": 1000, "last_seen_ms": 2000, "stage": "step_script"},
                {"outcome": "observed", "protocol": "tcp",
                 "destination": {"kind": "address", "ip": "10.0.0.1", "port": 443},
                 "phase": "run", "source": {"kind": "service", "name": "db"}, "count": 2,
                 "first_seen_ms": 1000, "last_seen_ms": 2000},
            ],
            "refusals": [
                {"variable": "MICROVM_BUILD_EGRESS_ALLOW_NAME", "entry": "crates.io",
                 "dimension": "name", "phase": "build", "source": {"kind": "job"},
                 "layer": "node_cap", "reason": "unreachable"},
            ],
            "phases": [
                {"phase": "run", "coverage": "complete", "sent_bytes": 10, "received_bytes": 20},
            ],
        });
        assert_eq!(serde_json::to_value(&report).unwrap(), wire);
        assert_eq!(
            serde_json::from_value::<EgressReport>(wire).unwrap(),
            report
        );
    }

    /// Kinds, outcomes and layers from a later peer read as their fallbacks rather than failing
    /// the whole result.
    #[test]
    fn later_kinds_read_as_their_fallbacks() {
        let later: EgressReport = serde_json::from_value(json!({
            "revision": 3,
            "entries": [
                {"outcome": "quarantined", "protocol": "quic",
                 "destination": {"kind": "ipv6", "ip": "::1"},
                 "phase": "deploy", "source": {"kind": "sidecar", "name": "x"},
                 "layer": "org_policy", "count": 1,
                 "first_seen_ms": 1, "last_seen_ms": 1, "colour": "red"},
            ],
            "phases": [{"phase": "deploy", "coverage": "sampled"}],
        }))
        .unwrap();
        let e = &later.entries[0];
        assert_eq!(
            (e.outcome, e.protocol, e.phase, e.layer),
            (
                EgressOutcome::Other,
                EgressProtocol::Other,
                EgressPhase::Other,
                Some(EgressLayer::Unknown)
            )
        );
        assert_eq!(
            (&e.destination, &e.source),
            (&EgressDestination::Other, &EgressSource::Other)
        );
        assert!(!e.destination.allowable());
        assert_eq!(later.phases[0].coverage, EgressCoverage::Other);
        assert_eq!(
            serde_json::from_value::<EgressReport>(json!({})).unwrap(),
            EgressReport::default()
        );
    }

    /// Past the bound, warnings are left out before a declaration that failed the job, which
    /// stays listed however late it came.
    #[test]
    fn a_bounded_report_keeps_the_declaration_that_failed_the_job() {
        let refusal = |reason| EgressRefusal {
            variable: "MICROVM_EGRESS_ALLOW_NAME".into(),
            entry: "pypi.org".into(),
            dimension: EgressDimension::Name,
            phase: EgressPhase::Run,
            source: EgressSource::Job,
            layer: None,
            reason,
        };
        let mut refusals = vec![refusal(RefusalReason::Unreachable); MAX_EGRESS_REFUSALS];
        refusals.push(refusal(RefusalReason::InvalidEntry));
        let report = EgressReport {
            refusals,
            ..EgressReport::default()
        }
        .bounded();
        assert_eq!(report.refusals[0].reason, RefusalReason::InvalidEntry);
        assert_eq!(
            (report.refusals.len(), report.refusals_omitted),
            (MAX_EGRESS_REFUSALS, 1)
        );
    }

    /// A refusal says whether its job failed for it: an invalid entry failed it; one kept
    /// unreachable did not; a later reason is not known.
    #[test]
    fn a_refusal_reason_says_whether_it_failed_the_job() {
        let reason = |wire: &str| serde_json::from_value::<RefusalReason>(json!(wire)).unwrap();
        assert_eq!(
            ["invalid_entry", "unreachable", "forbidden"].map(reason),
            [
                RefusalReason::InvalidEntry,
                RefusalReason::Unreachable,
                RefusalReason::Other
            ]
        );
        assert_eq!(
            serde_json::to_value(RefusalReason::Unreachable).unwrap(),
            json!("unreachable")
        );
        assert_eq!(
            ["invalid_entry", "unreachable", "forbidden"].map(|w| reason(w).fails_job()),
            [Some(true), Some(false), None]
        );
    }

    #[test]
    fn a_destination_is_typed_only_when_it_parses() {
        assert_eq!(
            EgressDestination::domain("Crates.IO"),
            EgressDestination::Domain {
                name: "crates.io".into()
            }
        );
        assert_eq!(
            EgressDestination::address("10.1.2.3:53"),
            EgressDestination::Address {
                ip: Ipv4Addr::new(10, 1, 2, 3),
                port: 53
            }
        );
        for bad in [
            "",
            "a..b",
            "-a.example",
            "a-.example",
            "a.example.",
            "evil\nforged.example",
            "a b.example",
            "an unparsable question",
        ] {
            let d = EgressDestination::domain(bad);
            assert!(
                matches!(d, EgressDestination::Malformed { .. }),
                "{bad:?}: {d:?}"
            );
            assert!(!d.allowable());
        }
        assert!(matches!(
            EgressDestination::address("10.0.0.1"),
            EgressDestination::Malformed { .. }
        ));
        assert!(is_domain(&format!("{}.example", "a".repeat(63))));
        assert!(!is_domain(&format!("{}.example", "a".repeat(64))));
        assert!(!is_domain(&format!("{}.e", "a.".repeat(126))));
    }

    /// An overlong name is malformed as a whole: cut, it would be a different, valid name.
    #[test]
    fn an_overlong_domain_is_not_cut_into_another() {
        let long = format!("{}evil.example", "a.".repeat(200));
        assert!(long.len() > MAX_DOMAIN);
        let report = EgressReport {
            entries: vec![entry(
                EgressOutcome::Blocked,
                EgressDestination::Domain { name: long.clone() },
            )],
            ..EgressReport::default()
        }
        .bounded();
        match &report.entries[0].destination {
            EgressDestination::Malformed { text } => {
                assert!(text.len() <= MAX_EGRESS_TEXT && long.starts_with(text.as_str()))
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn text_is_made_safe_and_identities_are_not_rewritten() {
        let report = EgressReport {
            entries: vec![EgressEntry {
                source: EgressSource::Service {
                    name: "db\u{202e}x".into(),
                },
                stage: Some("step\nscript".into()),
                ..entry(
                    EgressOutcome::Observed,
                    EgressDestination::Malformed {
                        text: format!("x\u{1b}[2J{}", "é".repeat(300)),
                    },
                )
            }],
            refusals: vec![EgressRefusal {
                variable: "V".into(),
                entry: "a\tb".into(),
                dimension: EgressDimension::Ip,
                phase: EgressPhase::Run,
                source: EgressSource::Service { name: "db".into() },
                layer: None,
                reason: RefusalReason::InvalidEntry,
            }],
            ..EgressReport::default()
        }
        .bounded();
        let e = &report.entries[0];
        assert_eq!(e.source, EgressSource::Other);
        assert_eq!(e.stage.as_deref(), Some("step\u{fffd}script"));
        // An observed entry carries no layer.
        assert_eq!(e.layer, None);
        match &e.destination {
            EgressDestination::Malformed { text } => {
                assert!(text.starts_with("x\u{fffd}[2J") && text.len() <= MAX_EGRESS_TEXT)
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(report.refusals[0].entry, "a\u{fffd}b");
        assert_eq!(
            report.refusals[0].source,
            EgressSource::Service { name: "db".into() }
        );
    }

    /// Past its bound an entry is counted, not listed, and its phase says the report is
    /// partial; the entries kept are the first. Applying the bounds again changes nothing.
    #[test]
    fn entries_past_the_bounds_are_counted_in_their_phase() {
        let mut entries = Vec::new();
        for i in 0..MAX_EGRESS_DENIALS + 3 {
            entries.push(entry(
                EgressOutcome::WouldBlock,
                EgressDestination::domain(&format!("d{i}.example")),
            ));
        }
        for i in 0..MAX_EGRESS_CONTACTS + 1 {
            entries.push(entry(
                EgressOutcome::Observed,
                EgressDestination::domain(&format!("c{i}.example")),
            ));
        }
        let refusal = EgressRefusal {
            variable: "MICROVM_EGRESS_ALLOW_IP".into(),
            entry: "10.0.0.0/8".into(),
            dimension: EgressDimension::Ip,
            phase: EgressPhase::Run,
            source: EgressSource::Job,
            layer: Some(EgressLayer::NodeCap),
            reason: RefusalReason::Unreachable,
        };
        let report = EgressReport {
            revision: 1,
            entries,
            refusals: vec![refusal; MAX_EGRESS_REFUSALS + 2],
            refusals_omitted: 0,
            phases: vec![run_phase(), run_phase()],
            hub_rules: Vec::new(),
        }
        .bounded();
        assert_eq!(report.phases.len(), 1);
        let run = &report.phases[0];
        assert_eq!(run.coverage, EgressCoverage::Partial);
        assert_eq!(
            run.omitted,
            EgressOmitted {
                blocked: 0,
                would_block: 6,
                observed: 2,
            }
        );
        assert_eq!(
            report.entries.len(),
            MAX_EGRESS_DENIALS + MAX_EGRESS_CONTACTS
        );
        assert_eq!(
            report.entries[0].destination,
            EgressDestination::domain("d0.example")
        );
        assert_eq!(report.refusals.len(), MAX_EGRESS_REFUSALS);
        assert_eq!(report.refusals_omitted, 2);
        assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_EGRESS_REPORT);
        assert_eq!(report.clone().bounded(), report);
    }

    /// A report cut short reads as partial wherever it read as complete, past its revision.
    #[test]
    fn an_interrupted_report_is_partial_and_newer() {
        let phase = |phase, coverage| EgressPhaseReport {
            phase,
            coverage,
            omitted: EgressOmitted::default(),
            sent_bytes: None,
            received_bytes: None,
            caps: None,
        };
        let report = EgressReport {
            revision: 4,
            phases: vec![
                phase(EgressPhase::Build, EgressCoverage::Complete),
                phase(EgressPhase::Run, EgressCoverage::Unavailable),
            ],
            ..EgressReport::default()
        }
        .interrupted();
        assert_eq!(report.revision, 5);
        assert_eq!(
            report.phases,
            [
                phase(EgressPhase::Build, EgressCoverage::Partial),
                phase(EgressPhase::Run, EgressCoverage::Unavailable),
            ]
        );
    }

    /// Entries of the longest text fill the size bound before the count bounds; those cut are
    /// counted, a phase the report did not list included.
    #[test]
    fn a_report_is_held_to_its_size() {
        let long = |i: usize| format!("{i:04}{}", "x".repeat(MAX_EGRESS_TEXT - 4));
        let mut entries = Vec::new();
        for i in 0..MAX_EGRESS_DENIALS {
            entries.push(EgressEntry {
                phase: EgressPhase::Build,
                source: EgressSource::Service { name: long(i) },
                stage: Some(long(i)),
                ..entry(
                    EgressOutcome::Blocked,
                    EgressDestination::Malformed { text: long(i) },
                )
            });
        }
        let report = EgressReport {
            entries,
            ..EgressReport::default()
        }
        .bounded();
        let len = serde_json::to_vec(&report).unwrap().len();
        assert!(len <= MAX_EGRESS_REPORT, "{len}");
        assert!(report.entries.len() < MAX_EGRESS_DENIALS);
        let build = &report.phases[0];
        assert_eq!(
            (build.phase, build.coverage),
            (EgressPhase::Build, EgressCoverage::Partial)
        );
        let cut = (MAX_EGRESS_DENIALS - report.entries.len()) as u64;
        assert_eq!(build.omitted.blocked, cut * 2);
        assert_eq!(report.clone().bounded(), report);
    }

    /// The rules a report names: the enforced ones once each, and a dry-run rule on its own
    /// would-be denials only, each by its exact name.
    #[test]
    fn a_report_names_the_hub_rules_it_ran_under() {
        let would = EgressEntry {
            layer: Some(EgressLayer::HubRule),
            rule: Some("wab-release".into()),
            ..entry(
                EgressOutcome::WouldBlock,
                EgressDestination::domain("partner.example.net"),
            )
        };
        let report = EgressReport {
            entries: vec![
                would.clone(),
                // Not a dry-run rule's: a blocked entry, and one of another layer.
                EgressEntry {
                    outcome: EgressOutcome::Blocked,
                    ..would.clone()
                },
                EgressEntry {
                    layer: Some(EgressLayer::Job),
                    ..would.clone()
                },
                EgressEntry {
                    rule: Some("wab\nrelease".into()),
                    ..would.clone()
                },
            ],
            hub_rules: vec![
                "wab".into(),
                "wab".into(),
                "bad name".into(),
                "default".into(),
            ],
            ..EgressReport::default()
        };
        let wire = serde_json::to_value(&report).unwrap();
        assert_eq!(wire["entries"][0]["rule"], "wab-release");
        assert_eq!(
            serde_json::from_value::<EgressReport>(wire).unwrap(),
            report
        );
        let bounded = report.bounded();
        let rules: Vec<_> = bounded.entries.iter().map(|e| e.rule.as_deref()).collect();
        assert_eq!(rules, [Some("wab-release"), None, None, None]);
        assert_eq!(bounded.hub_rules, ["wab", "default"]);
        assert_eq!(bounded.clone().bounded(), bounded);
        assert!(
            serde_json::to_value(EgressReport::default())
                .unwrap()
                .get("hub_rules")
                .is_none()
        );
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

    /// A node's caps read the same however its config spells them, within the bounds, and are
    /// checked as a switch reads its lists.
    #[test]
    fn a_node_s_caps_are_normalized_and_bounded() {
        let allow = |names: &[&str], ips: &[&str]| HubPhase::Allow {
            names: names.iter().map(|s| s.to_string()).collect(),
            ips: ips.iter().map(|s| s.to_string()).collect(),
        };
        let a = EgressCaps::normalized(
            allow(
                &["Corp.example.com", ".crates.io", "crates.io"],
                &[" 10.0.0.0/8 "],
            ),
            false,
            HubPhase::Unrestricted,
        )
        .unwrap();
        assert_eq!(
            a.run,
            allow(&["corp.example.com", "crates.io"], &["10.0.0.0/8"])
        );
        let b = EgressCaps::normalized(
            allow(&["crates.io", "corp.example.com"], &["10.0.0.0/8"]),
            false,
            HubPhase::Unrestricted,
        )
        .unwrap();
        assert_eq!(a.canonical(), b.canonical());
        let dry = EgressCaps {
            run_dry_run: true,
            ..b.clone()
        };
        assert_ne!(dry.canonical(), b.canonical());
        let too_many: Vec<String> = (0..=MAX_HUB_ENTRIES).map(|i| format!("h{i}.x")).collect();
        let many: Vec<&str> = too_many.iter().map(String::as_str).collect();
        assert_eq!(
            EgressCaps::normalized(allow(&many, &[]), false, HubPhase::Unrestricted),
            None
        );
        assert!(a.check().is_err(), "no fingerprint yet");
        let signed = EgressCaps {
            fingerprint: "ab".repeat(32),
            ..a
        };
        signed.check().unwrap();
        for bad in [
            allow(&["https://x"], &[]),
            allow(&[], &["::1"]),
            allow(&["b.x", "a.x"], &[]),
            allow(&["a\u{1b}x"], &[]),
            HubPhase::Other,
        ] {
            let c = EgressCaps {
                build: bad.clone(),
                ..signed.clone()
            };
            assert!(c.check().is_err(), "{bad:?}");
        }
    }
}
