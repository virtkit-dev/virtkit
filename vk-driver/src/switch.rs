//! Userspace L2 network gateway + switch for a LAN of microVMs.
//!
//! Each VM port has one listening host unix socket carrying qemu vhost framing: a 4-byte
//! big-endian length followed by one ethernet frame. libkrun backs the guest's virtio-net
//! device with that socket. Under Cloud Hypervisor, virtkit-agent bridges a tap over hybrid
//! vsock: the guest dials host CID 2 and CH connects to `<vsock.sock>_<port>`.
//!
//! With no host privileges we are both:
//!   - an L2 switch — VMs share one segment, so they reach each other directly
//!     (MAC learning + unicast forward, flood for broadcast/unknown), and
//!   - the gateway — answer ARP for our address, serve DHCP (a per-MAC lease from
//!     the subnet pool), and hand off-subnet IPv4 to `ipstack`, which terminates
//!     the guest's TCP/UDP so each flow re-originates through the host's own
//!     sockets (transparent egress). ipstack's reply packets are routed back to
//!     the owning VM by destination IP.

use anyhow::{Context, Result, bail};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io::IoSlice;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::task::{Context as TaskCtx, Poll};
use std::time::{Duration, Instant};

use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket, UnixListener, UnixStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Gateway MAC — locally administered, unicast. The guest learns it via ARP.
const GW_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x01];
const BCAST_MAC: [u8; 6] = [0xff; 6];
/// Largest ethernet frame the switch's 4-byte-length framing carries, either direction.
const MAX_FRAME: usize = 65535;
/// Ethernet header: destination MAC, source MAC, ethertype.
const ETH_HDR: usize = 14;
/// Link MTU of the switch's LAN. Every guest NIC on a switch is configured with it, the
/// gateway's own stack runs at it, and it sets the MSS the gateway advertises — siblings
/// share the LAN, so they have to agree. Jumbo packets reduce per-frame overhead during
/// bulk transfers. The ceiling is an IPv4 datagram (65535) and [`MAX_FRAME`] once the
/// 14-byte ethernet header is added.
pub(crate) const MTU: u16 = vk_core::net::SWITCH_MTU;
const _: () = assert!(MAX_FRAME >= 14 + MTU as usize);
/// Largest TCP payload the link carries: the MTU less the IPv4 and TCP headers. The gateway
/// advertises it in the SYN-ACK.
const MSS: u16 = MTU - 40;
/// Guest-bound write ceiling, reserving 12 bytes of [`MSS`] for timestamps
/// (RFC 7323 § 2.2: 10 bytes plus two NOPs). On a timestamp-enabled flow with the link's
/// MSS, enough receive window and no SACK blocks, this avoids a 12-byte tail segment.
/// Smaller peer MSS/windows or extra SACK options can still split a write.
const GUEST_BOUND_CHUNK: usize = MSS as usize - 12;
/// Ceiling for the host-bound half of a spliced flow, matching ipstack's maximum read
/// handoff of one 8 KiB reassembly chunk. The guest kernel sizes that direction's segments.
const HOST_BOUND_CHUNK: usize = 8 << 10;
/// What a spliced flow's copy buffer is first allocated at, in either direction. A job
/// opens hundreds of flows and most carry a request and a short reply, so a direction starts
/// with a small buffer on its first poll and grows it while the reader keeps filling it —
/// up to [`HOST_BOUND_CHUNK`] host-bound and [`GUEST_BOUND_CHUNK`] guest-bound, which is
/// what a bulk transfer settles at.
const SPLICE_INIT: usize = 8 << 10;
/// Frame I/O on a guest's socket works in bursts: one read takes in whatever frames the
/// socket holds, and queued frames share a write buffer. The bounds limit each batch;
/// neither direction waits for a batch to fill.
const READ_BUF: usize = 256 * 1024;
const WRITE_BATCH_BYTES: usize = 256 * 1024;
const WRITE_BATCH_FRAMES: usize = 64;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_LEASE_SECS: u32 = 86400;
const DNS_PORT: u16 = 53;
/// Upstream resolver used when /etc/resolv.conf yields no nameserver.
const FALLBACK_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// Overall deadline for resolving one guest query upstream — the whole budget a lookup may
/// spend across its UDP retries and any TCP fallback. Held at a guest resolver's usual
/// patience so a slow-but-alive resolver still answers within it rather than the guest giving
/// up first.
const DNS_UPSTREAM_BUDGET: Duration = Duration::from_secs(5);
/// Upstream tries per guest query, rotating across the configured nameservers. A single
/// dropped UDP datagram — common when a guest fires a burst of parallel lookups (a yarn/npm
/// fetch) at a loaded resolver — must not surface to the guest as SERVFAIL, so a lookup gets
/// more than one shot, across more than one resolver, before it gives up.
const DNS_UPSTREAM_TRIES: usize = 3;
/// Reply deadline for every try but the last: short, so a dropped datagram fails over to the
/// next resolver quickly. The final try instead waits out whatever remains of
/// [`DNS_UPSTREAM_BUDGET`], so a lone slow-but-alive resolver is still given a full chance.
const DNS_UPSTREAM_PROBE_TIMEOUT: Duration = Duration::from_millis(700);
/// At most one upstream-failure line per distinct fault per window: a resolver that is
/// down fails every lookup a guest makes, and switch.log is read as a whole.
const DNS_LOG_WINDOW: Duration = Duration::from_secs(30);
/// At most one failed-flow line per distinct fault per window: a destination that has stopped
/// answering fails every flow a guest opens to it, and one line per flow would bury the log.
const FLOW_LOG_WINDOW: Duration = Duration::from_secs(30);
/// Response codes the gateway resolver answers with itself.
const RCODE_SERVFAIL: u8 = 2;
const RCODE_NXDOMAIN: u8 = 3;
/// First host index handed out by DHCP (.1 is the gateway).
const FIRST_LEASE: u32 = 2;
/// Host-side connect timeout for a guest egress flow. ipstack completes the guest's
/// TCP handshake in userspace *before* we dial the real destination, so the guest's
/// connect() has already returned OK and it blocks on the first read. Without a bound,
/// dialing an unreachable destination stalls on the OS default (~127s of SYN retries),
/// which surfaces in the guest as a multi-minute hang (e.g. a TLS ClientHello with no
/// ServerHello). Bounding the dial fails the flow in seconds — we drop the guest stream
/// and ipstack RSTs it — so a dead backend degrades to a fast connection error, not a hang.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the switch keeps writing guest bytes to their host sockets after it is asked to
/// stop. SIGTERM reaches the switch once the VM it serves is already gone, so what an egress
/// flow still holds is the tail of an upload whose sender has exited: the switch acknowledged
/// those bytes to the guest and is the only thing left that can deliver them. Long enough for
/// a receiver on a slow link to take what a handful of flows hold, short enough that a
/// destination which has stopped reading altogether costs the teardown seconds rather than
/// minutes. Whoever stops a switch allows for it (see run's `SWITCH_STOP`).
pub(crate) const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
/// How long a draining flow with nothing left to write waits for more guest bytes before
/// closing the host writer. It covers the hand-off from the stack's session task
/// to the flow — a task wakeup — and deliberately little more: a connection the guest left
/// open and idle (one pooled by a package manager, say) must still send EOF to the host.
/// A flow that still holds bytes is not subject to it: a slow receiver is waited for until
/// the deadline.
const DRAIN_SETTLE: Duration = Duration::from_millis(100);
/// Keepalive on an upstream flow: probe after this long idle, repeat every
/// [`KEEPALIVE_INTERVAL`] seconds, give up after [`KEEPALIVE_PROBES`] unanswered probes — about
/// 90 seconds to notice a destination that vanished without a FIN or a RST (powered off, a NAT
/// that dropped the flow), which nothing else would ever fail: the socket, and the guest
/// waiting on it, would stay open for good. Six probes ten seconds apart rather than a tighter
/// schedule: a job's uplink is often a lossy VPN, and killing a live connection over a handful
/// of dropped probes is the worse failure. Data the switch has sent and the peer never
/// acknowledges is left to the kernel's own retransmission limit: a user timeout would also
/// abort a peer that merely advertises a zero window, and it overrides the probe count above.
const KEEPALIVE_IDLE: libc::c_int = 30;
const KEEPALIVE_INTERVAL: libc::c_int = 10;
const KEEPALIVE_PROBES: libc::c_int = 6;
/// Retransmissions of a guest-bound TCP segment before the next timeout resets the flow.
/// With the measured timeout at its 200 ms floor, eight retransmissions allow 102.2 s
/// of silence (0.2 + 0.4 + … + 51.2); six would allow 25.4 s. Before an RTT sample,
/// the 1 s initial timeout and 60 s ceiling allow 243 s. This gives a busy guest or
/// an unscheduled switch time to recover.
const TCP_MAX_RETRANSMITS: usize = 8;
/// How long a guest flow may go without a packet from the guest before the stack resets it.
/// A leak guard for flows whose guest is gone, not a liveness check: a pooled HTTP or
/// interactive connection is idle for minutes at a time, and resetting one is a worse failure
/// than holding a socket longer — fifteen minutes is well past any real idle. A guest that has
/// stopped answering is reset by retransmission exhaustion ([`TCP_MAX_RETRANSMITS`]) first.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
/// The window the switch advertises to a guest, and the ceiling on what one flow holds
/// unacknowledged in the other direction. Scaling lets a guest that offers it use the full
/// 4 MiB; other peers retain the unscaled limit. Buffered data can occupy roughly three
/// windows per flow: reassembly, the reader handoff, and unacknowledged outgoing data.
const TCP_WINDOW: usize = 4 << 20;

#[derive(Clone, Copy)]
struct Cfg {
    gateway: Ipv4Addr,
    prefix: u8,
}

type Mac = [u8; 6];
type PortId = u32;
/// Groups the ports and addresses owned by one VM.
type VmId = u32;

/// Parse a colon-separated MAC (`aa:bb:cc:dd:ee:ff`) into 6 bytes; None if it is
/// not six hex octets.
pub fn parse_mac(s: &str) -> Option<Mac> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for byte in &mut out {
        *byte = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None; // more than six octets
    }
    Some(out)
}

/// Egress policy — which off-subnet destinations the switch originates flows to.
/// Default `AllowAll` (dev use is unrestricted); CI passes an allowlist.
/// Direct (non-proxied) TCP/UDP egress is gated by destination IP (`allows_ip`);
/// the in-switch http(s) proxy gates web egress by hostname (`allows_host`).
#[derive(Clone, Default)]
pub enum Egress {
    #[default]
    AllowAll,
    Allow {
        /// allowed destination IPv4 ranges for direct (non-proxied) egress, each
        /// optionally scoped to a single destination port (`CIDR:port`)
        ips: Vec<Cidr4>,
        /// allowed hostname suffixes for the http(s) proxy, dot-anchored:
        /// `corp.example.com` allows that host and `*.corp.example.com`
        names: Vec<String>,
    },
}

/// An egress IP allowlist rule: an IPv4 CIDR (`a.b.c.d/prefix`), optionally scoped to a
/// single destination port (`a.b.c.d/prefix:port`). `port = None` allows any port.
#[derive(Clone, Copy)]
pub struct Cidr4 {
    net: u32,
    prefix: u8,
    port: Option<u16>,
}

impl Cidr4 {
    fn parse(s: &str) -> Result<Self> {
        // Optional `:port` suffix; IPv4 has no colons, so a colon unambiguously starts it.
        let (cidr, port) = match s.rsplit_once(':') {
            Some((c, p)) => (
                c,
                Some(p.parse().with_context(|| format!("bad port in {s:?}"))?),
            ),
            None => (s, None),
        };
        let (addr, prefix) = cidr.split_once('/').unwrap_or((cidr, "32"));
        let ip: Ipv4Addr = addr
            .parse()
            .with_context(|| format!("bad CIDR address in {s:?}"))?;
        let prefix: u8 = prefix
            .parse()
            .ok()
            .filter(|p| *p <= 32)
            .with_context(|| format!("bad CIDR prefix in {s:?}"))?;
        Ok(Cidr4 {
            net: u32::from(ip) & mask4(prefix),
            prefix,
            port,
        })
    }
    /// Does this rule admit `ip:port`? The IP must fall in the CIDR and, if the rule is
    /// port-scoped, the port must match (an unscoped rule admits any port).
    fn matches(&self, ip: Ipv4Addr, port: u16) -> bool {
        (u32::from(ip) & mask4(self.prefix)) == self.net && self.port.is_none_or(|p| p == port)
    }
    /// Is `other` entirely within this rule (this ⊇ other)? Used host-side to check a
    /// per-job `allow_ip` request stays inside the configured cap: `other`'s network must
    /// sit in this CIDR (so this prefix is no longer than other's), and if this rule is
    /// port-scoped `other` must carry the same port (an unscoped cap admits any).
    fn contains(&self, other: &Cidr4) -> bool {
        self.prefix <= other.prefix
            && (other.net & mask4(self.prefix)) == self.net
            && self.port.is_none_or(|p| Some(p) == other.port)
    }
}

/// IPv4 netmask for a prefix length (0 => 0.0.0.0, avoiding the `u32 << 32` UB).
fn mask4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

impl Egress {
    /// Build a policy from `--allow-ip` CIDRs + `--allow-name` suffixes; empty both
    /// => `AllowAll`. The dev/CLI convenience path where an unset allowlist means
    /// unrestricted; the CI executor uses [`Egress::restricted`] so an explicit empty
    /// allowlist denies everything instead.
    pub fn new(ips: &[String], names: &[String]) -> Result<Egress> {
        if ips.is_empty() && names.is_empty() {
            return Ok(Egress::AllowAll);
        }
        Self::restricted(ips, names)
    }
    /// Build an allowlist policy that is *always* restricted — empty lists deny everything
    /// (`Egress::Allow { ips: [], names: [] }`), never collapsing to `AllowAll`. The CI
    /// executor uses this when a job's phase configures egress (see the switch's
    /// `--egress-restrict`), so `allow_name = []` means "no names", not "any name".
    pub fn restricted(ips: &[String], names: &[String]) -> Result<Egress> {
        let ips = ips.iter().map(|s| Cidr4::parse(s)).collect::<Result<_>>()?;
        let names = names
            .iter()
            .map(|s| s.trim_start_matches('.').to_ascii_lowercase())
            .collect();
        Ok(Egress::Allow { ips, names })
    }
    /// Is the CIDR request `cidr` (`a.b.c.d/prefix[:port]`) entirely within this policy?
    /// `AllowAll` contains anything; an `Allow` policy contains it iff some allowed rule
    /// does (see [`Cidr4::contains`]). Host-side check that a per-job `allow_ip` request
    /// stays inside the configured cap — the executor's `narrow_ips`.
    pub fn contains_cidr(&self, cidr: &str) -> Result<bool> {
        let req = Cidr4::parse(cidr)?;
        Ok(match self {
            Egress::AllowAll => true,
            Egress::Allow { ips, .. } => ips.iter().any(|c| c.contains(&req)),
        })
    }
    /// Direct (non-proxied) egress: allow only listed IPv4 ranges, each optionally scoped
    /// to a destination port (IPv6 denied under an allowlist).
    fn allows_ip(&self, ip: IpAddr, port: u16) -> bool {
        match self {
            Egress::AllowAll => true,
            Egress::Allow { ips, .. } => match ip {
                IpAddr::V4(v4) => ips.iter().any(|c| c.matches(v4, port)),
                IpAddr::V6(_) => false,
            },
        }
    }
    /// Resolver name check: allow a host equal to or under an allowed suffix.
    /// Also used host-side to validate a per-job allow_name request stays within
    /// the configured cap (the executor's `narrow_names`).
    pub fn allows_host(&self, host: &str) -> bool {
        match self {
            Egress::AllowAll => true,
            Egress::Allow { names, .. } => {
                let h = host.trim_end_matches('.').to_ascii_lowercase();
                names
                    .iter()
                    .any(|n| h == *n || h.ends_with(&format!(".{n}")))
            }
        }
    }
}

/// Runtime egress enforcement: the static [`Egress`] policy + the set of IPs the
/// DNS resolver dynamically pinned (the A-records it returned for allowed names,
/// with their TTL). Transparent — the guest needs no proxy env: it resolves through
/// us (we refuse names outside the allowlist) and we only let it connect to a static
/// allowed CIDR or an IP we just resolved for an allowed name. A restricted switch
/// serves a single job VM, so the pin set is per-switch (not keyed by VM).
struct EgressGuard {
    /// The default policy — the primary guest and any service without its own override.
    policy: Egress,
    /// Per-source overrides, keyed by the source VM's IPv4 (a service that declared its own
    /// egress in its `variables:`). A flow's policy is `per_source[src]` or `policy`.
    per_source: HashMap<Ipv4Addr, Egress>,
    gateway: Ipv4Addr,
    /// Enforce the policy, or only observe it. `true` (the default) blocks a denied flow —
    /// NXDOMAIN for a name outside the allowlist, RST/drop for a direct dial. `false` is
    /// dry-run: the verdict is still computed and each would-be denial recorded to
    /// `denied_log`, but the flow is carried anyway (a denied name is resolved and pinned so
    /// the guest's connection succeeds). Lets a job discover what an allowlist would reject
    /// before it is made to bite. Only meaningful under a restricted policy — an unrestricted
    /// one denies nothing to observe.
    enforce: bool,
    /// DNS-pinned A-records, keyed by `(source, resolved_ip)` so one VM's resolution never
    /// admits a connection from another VM with a different policy (per-source isolation).
    pinned: Mutex<HashMap<(Ipv4Addr, Ipv4Addr), Instant>>,
    /// `(sentinel, host)`: a guest flow to `sentinel` is redirected to the host-local
    /// credential registry proxy at `host` (see regproxy.rs). `None` = disabled.
    registry_proxy: Option<(Ipv4Addr, SocketAddr)>,
    /// Where denials are appended as typed records for the job trace (see egress_report).
    /// `None` = don't record (dev `vk run`, or an unrestricted policy that denies nothing).
    denied_log: Option<PathBuf>,
    /// Audit mode: where the switch appends, for the end-of-job summaries (see egress_report),
    /// every allowed external domain the guest resolves and every external IP it dials without
    /// a matching resolution. `None` = audit off. Independent of the allowlist — an unrestricted
    /// policy still records every contact.
    audit_log: Option<PathBuf>,
    /// Audit mode: every external IP the switch handed a guest in a DNS answer, keyed by
    /// `(source, resolved_ip)` so a subsequent connection from that same VM to one of them is
    /// attributed to its name (already in the domains summary) rather than logged again as a
    /// direct-IP contact — and one VM's resolution never masks another VM's direct dial to the
    /// same IP. Tracked independently of `pinned` because audit runs even under `AllowAll`,
    /// where nothing is pinned. Empty when audit is off.
    dns_ips: Mutex<HashSet<(Ipv4Addr, Ipv4Addr)>>,
    /// Where the bytes forwarded are written for the job trace to read. `None` = don't
    /// count. Unlike the audit channel this is not opt-in: what a job moved over the network
    /// is part of what it cost, and the counting is one relaxed add per copy buffer.
    bytes_log: Option<PathBuf>,
    /// Payload forwarded out of and into the guests, in bytes. Not wire bytes: headers,
    /// retransmits and the vsock framing around them are the host's business, not the job's.
    sent: AtomicU64,
    received: AtomicU64,
    /// What the last publish wrote out, so each one appends only what is new.
    published: Mutex<(u64, u64)>,
    /// Throttles the upstream-resolver failure log (see `log_dns_upstream`).
    dns_log: LogLimiter,
    /// Throttles the failed-flow log (see `log_flow_failure`).
    flow_log: LogLimiter,
}

impl EgressGuard {
    fn new(policy: Egress, gateway: Ipv4Addr) -> Self {
        EgressGuard {
            policy,
            per_source: HashMap::new(),
            gateway,
            enforce: true,
            pinned: Mutex::new(HashMap::new()),
            registry_proxy: None,
            denied_log: None,
            audit_log: None,
            dns_ips: Mutex::new(HashSet::new()),
            bytes_log: None,
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            published: Mutex::new((0, 0)),
            dns_log: LogLimiter::new(DNS_LOG_WINDOW),
            flow_log: LogLimiter::new(FLOW_LOG_WINDOW),
        }
    }
    fn with_per_source(mut self, per_source: HashMap<Ipv4Addr, Egress>) -> Self {
        self.per_source = per_source;
        self
    }
    /// Set enforcement. `false` puts the guard in dry-run: policy is evaluated and would-be
    /// denials are recorded, but no flow is blocked (see the `enforce` field).
    fn with_enforce(mut self, enforce: bool) -> Self {
        self.enforce = enforce;
        self
    }
    fn with_registry_proxy(mut self, redirect: Option<(Ipv4Addr, SocketAddr)>) -> Self {
        self.registry_proxy = redirect;
        self
    }
    fn with_denied_log(mut self, path: Option<PathBuf>) -> Self {
        self.denied_log = path;
        self
    }
    fn with_audit_log(mut self, path: Option<PathBuf>) -> Self {
        self.audit_log = path;
        self
    }
    fn with_bytes_log(mut self, path: Option<PathBuf>) -> Self {
        self.bytes_log = path;
        self
    }

    /// Add what has just crossed to the running totals: once per copy buffer for TCP — 8 KiB
    /// at a time, not per byte — and once per datagram for UDP.
    fn count(&self, sent: u64, received: u64) {
        // Only the half that moved. A copy is one direction at a time, and the two counters
        // share a cache line, so adding zero to the other would contend it for nothing.
        if sent > 0 {
            self.sent.fetch_add(sent, Ordering::Relaxed);
        }
        if received > 0 {
            self.received.fetch_add(received, Ordering::Relaxed);
        }
    }

    /// Open the byte channel with a line of zeros, so its existence says a switch is
    /// counting for this phase. Without it an absent file means both "nothing was
    /// forwarded" and "nothing is watching", and a `net.mode = "tap"` job — whose traffic
    /// is real and goes nowhere near here — would be reported as having moved none.
    fn open_bytes(&self) {
        let Some(path) = &self.bytes_log else {
            return;
        };
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            let _ = file.write_all(b"0 0\n");
        }
    }

    /// Publish what has been forwarded since the last time, appending it to the channel the
    /// reader sums. A delta rather than a total, so several switches can share one file — a
    /// build gives every stage guest its own LAN, and each would otherwise overwrite the
    /// others' figure. Best-effort: a lost update costs a trace one number and the LAN
    /// nothing.
    fn publish_bytes(&self) {
        let Some(path) = &self.bytes_log else {
            return;
        };
        // Read and advanced under the one lock. The totals only rise, so serialising the
        // whole read-modify-write is what keeps a delta positive: loading them outside it
        // lets two publishers take the lock in the opposite order to their loads, and the
        // one that arrives second subtracts a larger total from a smaller one.
        let (d_sent, d_received) = {
            let mut published = self.published.lock().unwrap_or_else(|e| e.into_inner());
            let (sent, received) = (
                self.sent.load(Ordering::Relaxed),
                self.received.load(Ordering::Relaxed),
            );
            let delta = (sent - published.0, received - published.1);
            *published = (sent, received);
            delta
        };
        if d_sent == 0 && d_received == 0 {
            return; // nothing moved; leave the channel alone
        }
        // One `write_all` of one line, as the audit channel does it: two switches appending
        // at once interleave whole records rather than fragments of them.
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            use std::io::Write;
            let _ = file.write_all(format!("{d_sent} {d_received}\n").as_bytes());
        }
    }
    /// Record a refused flow to the denial channel for the job trace to surface. Paired
    /// with the switch's own `eprintln!` operator log at each call site.
    fn record_denial(&self, proto: crate::egress_report::Proto, target: &str) {
        if let Some(path) = &self.denied_log {
            crate::egress_report::append(path, proto, target);
        }
    }
    /// Name the upstream resolver and the reason it failed a guest's lookup, throttled to
    /// one line per fault per [`DNS_LOG_WINDOW`]: nothing else in the switch says why a
    /// guest's name resolution stopped working, and a host with no resolver fails every
    /// lookup every VM makes.
    fn log_dns_upstream(&self, upstream: SocketAddr, question: &str, err: &UpstreamError) {
        let Some(suppressed) = self.dns_log.admit((upstream, err.kind()), Instant::now()) else {
            return;
        };
        let more = match suppressed {
            0 => String::new(),
            n => format!(" ({n} more since the last line)"),
        };
        eprintln!("switch: dns upstream {upstream} failed for {question}: {err}{more}");
    }
    /// Name a flow that ended with an error and the fault behind it, throttled to one line per
    /// fault per [`FLOW_LOG_WINDOW`]. Keyed by (destination, error kind), so the named guest is
    /// whichever hit the fault first this window and the count spans every guest that hit it.
    fn log_flow_failure(&self, guest: SocketAddr, dst: SocketAddr, err: &std::io::Error) {
        let Some(suppressed) = self.flow_log.admit((dst, err.kind()), Instant::now()) else {
            return;
        };
        let more = match suppressed {
            0 => String::new(),
            n => format!(" ({n} more since the last line)"),
        };
        eprintln!("switch: tcp {guest} -> {dst} failed: {err}{more}");
    }
    /// Record an allowed external domain the guest resolved to the audit channel, for the
    /// end-of-job "domains contacted" summary and the standing list of names a job reaches
    /// (see sites). No-op only where nothing reads the channel: a CI job always has one.
    fn record_contact(&self, name: &str) {
        if let Some(path) = &self.audit_log {
            crate::egress_report::append_contact(path, name);
        }
    }
    /// Remember the A-record IPs the switch just handed `src` for an allowed name, so a
    /// connection from that VM to one of them is not re-logged as a direct-IP contact. No-op
    /// where there is no channel. Bounded by the answers the switch handed out, so a job's
    /// worth of resolutions, and paid by every CI job now that the channel is always open.
    fn record_dns_ips(&self, src: Ipv4Addr, ips: &[Ipv4Addr]) {
        if self.audit_log.is_none() {
            return;
        }
        let mut dns_ips = self.dns_ips.lock().unwrap();
        dns_ips.extend(ips.iter().map(|ip| (src, *ip)));
    }
    /// Record an allowed external `ip:port` that `src` dialed to the audit channel — but only
    /// when the switch never resolved that IP for that same VM, so the "IPs/ports contacted"
    /// summary shows exactly the direct-IP egress the "domains contacted" summary cannot
    /// (dedup is on `(src, ip)`; DNS answers carry no port). No-op where there is no channel.
    /// A set lookup per outbound connection, which a CI job now always pays; the append
    /// behind it is reached only by a guest that dials an address it never resolved.
    fn record_ip_contact(&self, src: Ipv4Addr, dst: SocketAddrV4) {
        let Some(path) = &self.audit_log else {
            return;
        };
        if self.dns_ips.lock().unwrap().contains(&(src, *dst.ip())) {
            return;
        }
        crate::egress_report::append_ip_contact(path, &dst.to_string());
    }
    /// Any restriction at all — the default policy or any per-source override. Drives the
    /// startup log summary.
    fn restricted(&self) -> bool {
        !matches!(self.policy, Egress::AllowAll) || !self.per_source.is_empty()
    }
    /// The policy that governs flows from source `src`: its per-source override, else the
    /// default. `src` is authenticated by `handle_frame` against the address bound to its
    /// port, so a guest cannot forge a sibling's source to select the sibling's policy.
    fn policy_for(&self, src: Ipv4Addr) -> &Egress {
        self.per_source.get(&src).unwrap_or(&self.policy)
    }
    /// May `src`'s resolver answer this name? (allowed names get forwarded + pinned.)
    fn name_allowed(&self, src: Ipv4Addr, host: &str) -> bool {
        self.policy_for(src).allows_host(host)
    }
    /// Pin the A-records returned for an allowed name for its TTL (+ a small grace), scoped
    /// to the resolving source so the guest's imminent connection to one of them is
    /// permitted — and only that guest's, not another VM's.
    fn record(&self, src: Ipv4Addr, ips: &[Ipv4Addr], ttl: u32) {
        if matches!(self.policy_for(src), Egress::AllowAll) || ips.is_empty() {
            return;
        }
        let until = Instant::now() + Duration::from_secs(u64::from(ttl).max(30) + 60);
        let mut pinned = self.pinned.lock().unwrap();
        for ip in ips {
            pinned.insert((src, *ip), until);
        }
    }
    /// May `src` open a direct flow to `dst`? Unrestricted => yes. Otherwise DNS must go to
    /// our resolver (so pinning holds), and the dst must be in `src`'s static allowlist or
    /// freshly pinned by one of `src`'s own allowed-name lookups.
    fn allows(&self, src: Ipv4Addr, dst: SocketAddr) -> bool {
        let policy = self.policy_for(src);
        if matches!(policy, Egress::AllowAll) {
            return true;
        }
        if dst.port() == DNS_PORT && dst.ip() != IpAddr::V4(self.gateway) {
            return false; // force DNS through the switch
        }
        if policy.allows_ip(dst.ip(), dst.port()) {
            return true;
        }
        let IpAddr::V4(v4) = dst.ip() else {
            return false;
        };
        let mut pinned = self.pinned.lock().unwrap();
        match pinned.get(&(src, v4)) {
            Some(&until) if until > Instant::now() => true,
            Some(_) => {
                pinned.remove(&(src, v4));
                false
            }
            None => false,
        }
    }

    /// If the SYN in `ip` opens a TCP connection this switch will not carry — its source's
    /// policy denies it, or its destination is one no network routes — return the RST frame
    /// refusing it; otherwise `None`, so the packet egresses normally. Rejecting the SYN
    /// (rather than letting ipstack complete the handshake and then drop the flow) makes the
    /// guest's connect() fail at once with ECONNREFUSED instead of stalling until a read
    /// timeout. The source IPv4 comes from the SYN itself, so the right per-source policy
    /// applies.
    fn reject_denied_syn(&self, ip: &[u8], client_mac: Mac) -> Option<Vec<u8>> {
        let syn = parse_tcp_syn(ip)?;
        // The registry-proxy sentinel bypasses the allowlist (a host-local
        // service, spliced in proxy_tcp), so it must never be rejected here.
        if let Some((sentinel, _)) = self.registry_proxy
            && *syn.dst.ip() == sentinel
        {
            return None;
        }
        if !self.allows(*syn.src.ip(), SocketAddr::V4(syn.dst)) {
            self.record_denial(crate::egress_report::Proto::Tcp, &syn.dst.to_string());
            if self.enforce {
                eprintln!("switch: egress denied (tcp) {} — sent RST", syn.dst);
                return tcp_rst_frame(&syn, client_mac);
            }
            // Dry-run: recorded, but carry the flow. proxy_tcp will not re-record it (this
            // SYN gate is the authoritative one; its fallback only fires on a pin race).
            eprintln!("switch: egress would deny (tcp) {} — dry-run, allowed", syn.dst);
        }
        if unroutable(*syn.dst.ip()) {
            // Not a policy decision, so it is not recorded as a denial: the address itself
            // goes nowhere, and the host would fail the dial too, just seconds later.
            eprintln!("switch: unroutable destination {} — sent RST", syn.dst);
            return tcp_rst_frame(&syn, client_mac);
        }
        None
    }
}

/// The `log` backend of the switch process: `ipstack` reports a reset connection or a
/// dropped packet through the `log` crate, and without a backend those lines are
/// dropped. stderr is switch.log, so they land next to the switch's own diagnostics.
struct SwitchLog(log::LevelFilter);

impl log::Log for SwitchLog {
    fn enabled(&self, meta: &log::Metadata) -> bool {
        meta.level() <= self.0
    }
    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            eprintln!(
                "{}",
                log_line(record.level(), record.target(), record.args())
            );
        }
    }
    fn flush(&self) {}
}

/// Use the usual `switch:` prefix, followed by level and reporting module,
/// to distinguish ipstack messages from the switch's own diagnostics.
fn log_line(level: log::Level, target: &str, args: &std::fmt::Arguments) -> String {
    format!(
        "switch: {} {target}: {args}",
        level.as_str().to_ascii_lowercase()
    )
}

/// Install the switch's log backend with `VK_SWITCH_LOG` (default: `warn`).
/// `debug` and `trace` enable ipstack's per-flow and per-packet diagnostics without
/// a rebuild. One bare level applies process-wide; `RUST_LOG`-style per-module
/// filters fail to parse and fall back to `warn`.
fn install_logger() {
    let level = std::env::var("VK_SWITCH_LOG")
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(log::LevelFilter::Warn);
    if log::set_boxed_logger(Box::new(SwitchLog(level))).is_ok() {
        log::set_max_level(level);
    }
}

/// Logs once per window per fault, counting suppressed lines so the operator sees the scale.
/// Keying by fault rather than by lookup keeps one entry per upstream failure kind. The window
/// is per instance, so callers throttle independently.
struct LogLimiter {
    window: Duration,
    /// Per key: when it last printed, and how many lines it has suppressed since.
    seen: Mutex<HashMap<(SocketAddr, std::io::ErrorKind), (Instant, u64)>>,
}

impl LogLimiter {
    fn new(window: Duration) -> Self {
        LogLimiter {
            window,
            seen: Mutex::new(HashMap::new()),
        }
    }
    /// Returns the suppressed count if `key` can print now, or `None` to stay quiet.
    /// Passing `now` lets tests run without sleeping.
    fn admit(&self, key: (SocketAddr, std::io::ErrorKind), now: Instant) -> Option<u64> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        match seen.get_mut(&key) {
            None => {
                seen.insert(key, (now, 0));
                Some(0)
            }
            Some((last, suppressed)) if now.duration_since(*last) < self.window => {
                *suppressed += 1;
                None
            }
            Some((last, suppressed)) => {
                *last = now;
                Some(std::mem::take(suppressed))
            }
        }
    }
}

/// A destination no network carries, decided from the address alone: RFC 5737 documentation
/// ranges, `0.0.0.0/8`, loopback, link-local, multicast and broadcast. Forwarding such a SYN
/// only buys the guest a handshake ipstack completes locally and a host dial that fails a
/// few seconds later — a connect that wrongly succeeds, where a real network refuses at once.
/// Private ranges are deliberately absent: a guest reaching the host's LAN is ordinary.
fn unroutable(dst: Ipv4Addr) -> bool {
    dst.is_documentation()
        || dst.is_unspecified()
        || dst.is_loopback()
        || dst.is_link_local()
        || dst.is_multicast()
        || dst.is_broadcast()
}

#[derive(Default)]
struct Inner {
    /// frame sink for each connected VM (its writer task)
    ports: HashMap<PortId, UnboundedSender<Vec<u8>>>,
    /// learned source MAC -> port (inter-VM L2 delivery)
    mac_port: HashMap<Mac, PortId>,
    /// IP -> MAC, so egress replies carry the owning VM's ethernet destination. Only the VM
    /// whose port is bound to an IP can source frames from it (see `handle_frame`), so each
    /// entry is set by that IP's real owner.
    ip_mac: HashMap<Ipv4Addr, Mac>,
    /// Authoritative IP -> port, from the executor-assigned address of each listen socket (a
    /// VM cannot choose which per-VM socket its frames arrive on). Selects the source's egress
    /// policy on ingress and routes egress replies on return — neither trusts a guest-supplied
    /// address.
    ip_port: HashMap<Ipv4Addr, PortId>,
    /// address -> owning VM, from the run's listen configuration
    ip_vm: HashMap<Ipv4Addr, VmId>,
    /// connected port -> owning VM, paired with `ip_vm` for anti-spoofing
    port_vm: HashMap<PortId, VmId>,
    /// DHCP: stable lease per client MAC
    leases: HashMap<Mac, Ipv4Addr>,
    /// DHCP: per-MAC address reservations (run-assigned svc.ips). A reserved MAC
    /// gets its fixed IP; the pool skips reserved IPs so it never collides.
    reservations: HashMap<Mac, Ipv4Addr>,
    next_idx: u32,
}

struct Switch {
    cfg: Cfg,
    inner: Mutex<Inner>,
    /// IPv4 packets from any VM destined off-subnet -> the shared ipstack
    egress_tx: UnboundedSender<Vec<u8>>,
    next_port: AtomicU32,
    /// service name -> IP, answered by the gateway resolver (replaces /etc/hosts)
    hosts: Arc<HashMap<String, Ipv4Addr>>,
    /// upstream resolvers (the host's own) for everything else; forwarded across in order,
    /// with retries, so one flaky resolver or a dropped datagram does not fail a lookup
    upstreams: Arc<[SocketAddr]>,
    /// egress policy + the DNS-pinned IP set (shared with the ipstack egress tasks)
    egress: Arc<EgressGuard>,
}

/// How a consumer spawns its switch: the listen sockets (one per VM on the LAN),
/// the gateway identity, the resolver's local names, the egress allowlists
/// (empty = unrestricted), and where the log goes.
pub struct Spawn {
    /// One `(socket, address, VM)` tuple per NIC. Shared VM ids let a multi-homed guest source
    /// any of its addresses on any of its ports without admitting another guest's addresses.
    pub listen: Vec<(PathBuf, Ipv4Addr, u32)>,
    pub gateway: Ipv4Addr,
    pub prefix: u8,
    /// resolver entries served over the gateway DNS (`name=ip`)
    pub hosts: Vec<(String, String)>,
    /// per-MAC DHCP reservations (`mac`, `ip`): a guest with this MAC gets exactly
    /// this address instead of a pool lease, so an image-init sibling that DHCPs
    /// eth0 lands on the IP the resolver advertises for its name
    pub reservations: Vec<(String, String)>,
    pub allow_ip: Vec<String>,
    pub allow_name: Vec<String>,
    /// Force allowlist mode even when both lists are empty: an empty allowlist then denies
    /// everything (`Egress::restricted`) instead of collapsing to unrestricted. Set by the
    /// CI executor for a phase whose egress is configured (so `allow_name = []` = deny all);
    /// `false` for dev `vk run`, where an unset allowlist means unrestricted.
    pub restrict: bool,
    /// Dry-run the allowlist: evaluate the policy and record every would-be denial for the
    /// job trace, but carry the flow instead of blocking it (see `EgressGuard::enforce`).
    /// `false` is the normal enforcing switch. Only meaningful together with `restrict`.
    pub dry_run: bool,
    /// Per-source egress overrides — a service that set its own `MICROVM_EGRESS_ALLOW_*`
    /// (see vm.rs). Each entry `(source-ip, allow_ip, allow_name)` is always a restricted
    /// allowlist (empty = deny); a source with no entry uses the default (run) policy.
    pub per_source: Vec<(Ipv4Addr, Vec<String>, Vec<String>)>,
    /// `(sentinel, host)`: redirect a guest flow to `sentinel` to the host-local
    /// credential registry proxy at `host` (see regproxy.rs). `None` = disabled.
    pub registry_proxy: Option<(Ipv4Addr, SocketAddr)>,
    pub log: PathBuf,
    /// Where the switch appends typed egress-denial records for the job trace (see
    /// egress_report). `None` = don't record (dev `vk run`).
    pub denied_log: Option<PathBuf>,
    /// Audit mode: where the switch appends every allowed external domain the guest
    /// resolves, for the end-of-job "domains contacted" summary. `None` = audit off.
    pub audit_log: Option<PathBuf>,
    /// Where the switch publishes the bytes it has forwarded, for the end-of-job resource
    /// line. `None` = don't count, which only the standalone `vk switch` reaches: every
    /// switch a run or a build boots is given a channel.
    pub bytes_log: Option<PathBuf>,
    /// Whether this switch serves a build stage, and so starts at the build's scheduling
    /// priority: it proxies everything the stage downloads (see [`crate::prio`]).
    pub prio: crate::prio::Prio,
}

/// How often the switch publishes what it has forwarded. Short, because a reader that cannot
/// stop the switch first is only ever as current as the last beat: a run and a build stop
/// theirs and lose nothing, but a CI job's figure is read while the job is still running and
/// its switch is killed with the supervisor, so this interval bounds the tail a job can miss.
/// The cost is an append of two numbers, and only when something moved.
const BYTES_PUBLISH: Duration = Duration::from_millis(500);

/// Spawn the switch as a tied child of this process (this binary's `switch`
/// subcommand). Every consumer — `run`, the gitlab job supervisor —
/// owns its LAN the way it owns its VMMs and virtiofsds: a child that dies with
/// it (PDEATHSIG), with its own pid and log to inspect when the LAN misbehaves.
/// Returns once every listen socket is bound, so a guest never dials a
/// not-yet-listening switch.
pub fn spawn(opts: &Spawn) -> Result<std::process::Child> {
    use std::process::{Command, Stdio};
    let exe = crate::spawn::self_exe();
    let log = std::fs::File::create(&opts.log)
        .with_context(|| format!("creating {}", opts.log.display()))?;
    let mut cmd = Command::new(exe);
    cmd.arg("switch")
        .arg("--gateway")
        .arg(opts.gateway.to_string())
        .arg("--prefix")
        .arg(opts.prefix.to_string());
    for (l, ip, vm) in &opts.listen {
        let _ = std::fs::remove_file(l);
        // Keep the path first so the parser can split the IP and VM id from the right even
        // when the path contains '='.
        cmd.arg("--listen")
            .arg(format!("{}={ip}={vm}", l.display()));
    }
    for (name, ip) in &opts.hosts {
        cmd.arg("--host").arg(format!("{name}={ip}"));
    }
    for (mac, ip) in &opts.reservations {
        cmd.arg("--reserve").arg(format!("{mac}={ip}"));
    }
    for a in &opts.allow_ip {
        cmd.arg("--allow-ip").arg(a);
    }
    for n in &opts.allow_name {
        cmd.arg("--allow-name").arg(n);
    }
    if opts.restrict {
        cmd.arg("--egress-restrict");
    }
    if opts.dry_run {
        cmd.arg("--egress-dry-run");
    }
    for (ip, ips, names) in &opts.per_source {
        // `<src-ip>;<cidr,cidr>;<name,name>` — a source's own restricted allowlist. IPv4
        // CIDRs and DNS names never contain a semicolon, so it is an unambiguous separator;
        // an empty field is an empty (deny) list.
        cmd.arg("--source-egress")
            .arg(format!("{ip};{};{}", ips.join(","), names.join(",")));
    }
    if let Some((sentinel, host)) = opts.registry_proxy {
        cmd.arg("--registry-proxy")
            .arg(format!("{sentinel}={host}"));
    }
    if let Some(denied) = &opts.denied_log {
        cmd.arg("--denied-log").arg(denied);
    }
    if let Some(audit) = &opts.audit_log {
        cmd.arg("--audit-log").arg(audit);
    }
    if let Some(bytes) = &opts.bytes_log {
        cmd.arg("--net-bytes").arg(bytes);
    }
    cmd.stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    opts.prio.apply(&mut cmd);
    let mut child = crate::spawn::spawn_tied(cmd).context("spawning the switch subprocess")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    for (l, _, _) in &opts.listen {
        while !l.exists() {
            // A switch that cannot bind — a path past the `sun_path` limit, an address
            // already in use — writes why to its log and exits. That is the error to
            // report, not this poll running out.
            if let Some(status) = child.try_wait().context("checking on the switch")? {
                bail!(
                    "the switch exited ({status}) before binding {}{}",
                    l.display(),
                    log_tail(&opts.log, 5)
                );
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!(
                    "the switch did not bind {}{}",
                    l.display(),
                    log_tail(&opts.log, 5)
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Ok(child)
}

/// Return the last `lines` non-blank log lines, trimmed and each prefixed with
/// a newline for appending to an error. Return an empty string if the log is
/// unreadable or has no content to show, keeping the error on one line.
fn log_tail(path: &Path, lines: usize) -> String {
    let Ok(text) = std::fs::read_to_string(path) else {
        return String::new();
    };
    let tail: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .rev()
        .take(lines)
        .collect();
    tail.iter().rev().fold(String::new(), |mut out, l| {
        out.push('\n');
        out.push_str(l);
        out
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    listen: &[(PathBuf, Ipv4Addr, VmId)],
    gateway: Ipv4Addr,
    prefix: u8,
    hosts: HashMap<String, Ipv4Addr>,
    reservations: HashMap<Mac, Ipv4Addr>,
    egress: Egress,
    per_source: HashMap<Ipv4Addr, Egress>,
    registry_proxy: Option<(Ipv4Addr, SocketAddr)>,
    denied_log: Option<PathBuf>,
    audit_log: Option<PathBuf>,
    bytes_log: Option<PathBuf>,
    dry_run: bool,
) -> Result<()> {
    if listen.is_empty() {
        bail!("switch: at least one --listen is required");
    }
    install_logger();
    // One shared ipstack for egress: it reads the off-subnet IPv4 packets the
    // switch forwards and writes reply packets back, which we route to the owning
    // VM by destination IP.
    let (egress_tx, egress_rx) = unbounded_channel::<Vec<u8>>();
    let (ret_tx, mut ret_rx) = unbounded_channel::<Vec<u8>>();
    let ip_stack = IpStack::new(
        ip_stack_config(),
        ChannelDevice {
            rx: egress_rx,
            tx: ret_tx,
        },
    );
    let per_source_count = per_source.len();
    let guard = Arc::new(
        EgressGuard::new(egress, gateway)
            .with_per_source(per_source)
            .with_registry_proxy(registry_proxy)
            .with_denied_log(denied_log)
            .with_audit_log(audit_log)
            .with_bytes_log(bytes_log)
            .with_enforce(!dry_run),
    );
    let restricted = guard.restricted();
    guard.open_bytes();
    let (drain, mut drained) = Drain::new();
    tokio::spawn(accept_loop(ip_stack, guard.clone(), drain.clone()));
    // The totals go out on a timer, so a reader that cannot stop the switch first — the job
    // trace, read while the job is still running — is at most a beat behind.
    tokio::spawn({
        let guard = guard.clone();
        async move {
            loop {
                tokio::time::sleep(BYTES_PUBLISH).await;
                guard.publish_bytes();
            }
        }
    });
    // The way out: hand the host what the guests are owed, then publish once more — which is
    // what makes a `vk run` figure whole, its last flow closing as the guest exits, too late
    // for the beat before teardown. A reader that stops the switch and waits for it therefore
    // has everything it carried.
    tokio::spawn({
        let guard = guard.clone();
        let drain = drain.clone();
        async move {
            if let Ok(mut term) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                term.recv().await;
                // PDEATHSIG is SIGTERM (see spawn_tied), so handling it puts this process's
                // death on the runtime where the default disposition needed nothing at all.
                // SIGALRM's default action terminates, so a drain or a publish that wedges
                // still goes, past the deadline the drain bounds itself with.
                // SAFETY: alarm(2) only arms this process's own timer.
                unsafe { libc::alarm(DRAIN_DEADLINE.as_secs() as u32 + 3) };
                drain.start();
                // Drain accepted flows; a switch with no flows exits immediately.
                // The receiver runs dry when the last of them is done.
                let _ = tokio::time::timeout(DRAIN_DEADLINE, drained.recv()).await;
                guard.publish_bytes();
                std::process::exit(0);
            }
        }
    });

    let upstreams = host_upstreams();
    let upstreams_display = upstreams
        .iter()
        .map(|s| s.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let sw = Arc::new(Switch {
        cfg: Cfg { gateway, prefix },
        inner: Mutex::new(Inner {
            next_idx: FIRST_LEASE,
            reservations,
            // Record ownership before any NIC connects so admission does not depend on
            // connection order.
            ip_vm: listen.iter().map(|(_, ip, vm)| (*ip, *vm)).collect(),
            ..Inner::default()
        }),
        egress_tx,
        next_port: AtomicU32::new(0),
        hosts: Arc::new(hosts),
        upstreams: upstreams.into(),
        egress: guard,
    });

    // ipstack egress replies -> the owning VM port.
    {
        let sw = sw.clone();
        tokio::spawn(async move {
            while let Some(frame) = ret_rx.recv().await {
                sw.route_in(frame);
            }
        });
    }

    eprintln!(
        "switch: {} port(s), gateway {}/{} (ARP + DHCP + DNS + egress, shared LAN); \
         resolver: {} service name(s), {} DHCP reservation(s), upstream(s) {}; egress: {}{}",
        listen.len(),
        gateway,
        prefix,
        sw.hosts.len(),
        sw.inner.lock().unwrap().reservations.len(),
        upstreams_display,
        // The audit channel is open for every CI job now — the standing list of names reads
        // it too — so its presence no longer says this job audits, and the log does not claim
        // it does.
        match (restricted, dry_run) {
            (true, false) => "allowlist",
            (true, true) => "allowlist (dry-run, observe-only)",
            (false, _) => "unrestricted",
        },
        if per_source_count > 0 {
            format!(" ({per_source_count} per-service override(s))")
        } else {
            String::new()
        },
    );
    let mut accepts = Vec::new();
    for (path, bound_ip, vm) in listen {
        let _ = std::fs::remove_file(path);
        let listener =
            UnixListener::bind(path).with_context(|| format!("switch: bind {}", path.display()))?;
        let sw = sw.clone();
        let bound_ip = *bound_ip;
        let vm = *vm;
        accepts.push(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((conn, _)) => {
                        let sw = sw.clone();
                        tokio::spawn(async move { sw.serve_port(conn, bound_ip, vm).await });
                    }
                    Err(e) => {
                        eprintln!("switch: accept: {e}");
                        return;
                    }
                }
            }
        }));
    }
    for a in accepts {
        let _ = a.await;
    }
    Ok(())
}

impl Switch {
    /// One connected VM: register a port, pump its frames into the switch, and
    /// drain queued frames back to it, until it disconnects.
    async fn serve_port(self: Arc<Self>, conn: UnixStream, bound_ip: Ipv4Addr, vm: VmId) {
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = unbounded_channel::<Vec<u8>>();
        {
            let mut inner = self.inner.lock().unwrap();
            inner.ports.insert(port, tx);
            // Bind this socket's assigned address to its port authoritatively (a reconnect on
            // the same socket rebinds to the new port). This is the only trustworthy source
            // identity — the guest picks its frames' addresses, not its socket.
            inner.ip_port.insert(bound_ip, port);
            // The socket supplies the VM identity; guest frames cannot choose it.
            inner.port_vm.insert(port, vm);
        }

        let (rd, wr) = conn.into_split();
        let writer = tokio::spawn(writer_task(wr, rx));
        self.reader(port, rd).await;

        writer.abort();
        self.drop_port(port);
    }

    async fn reader(&self, port: PortId, mut rd: tokio::net::unix::OwnedReadHalf) {
        let mut frames = FrameReader::new();
        loop {
            match frames.next(&mut rd).await {
                Ok(Some((a, b))) if b - a >= 14 => self.handle_frame(port, &frames.buf[a..b]),
                Ok(Some(_)) => {} // runt
                Ok(None) | Err(_) => return,
            }
        }
    }

    /// Switch one ethernet frame from `port`.
    fn handle_frame(&self, port: PortId, frame: &[u8]) {
        let dst: Mac = frame[0..6].try_into().unwrap();
        let src: Mac = frame[6..12].try_into().unwrap();
        let ethertype = u16::from_be_bytes([frame[12], frame[13]]);

        let mut inner = self.inner.lock().unwrap();
        let sip = (ethertype == ETHERTYPE_IPV4)
            .then(|| ipv4_src(&frame[14..]))
            .flatten();
        // Admit only unspecified pre-configuration sources (such as DHCP's 0.0.0.0) or an
        // address owned by this port's VM. The socket supplies the VM identity, so accepted
        // sources are safe inputs to `policy_for` and `route_in`; a guest cannot borrow a
        // sibling's policy or steal its replies.
        //
        // Scope ownership by VM rather than port because Linux owns addresses at host scope:
        // it may answer ARP for one NIC through another and route the reply through either.
        // Per-port ownership would reject valid multi-homed traffic, and guest configuration
        // cannot be trusted to prevent it.
        if let Some(sip) = sip
            && !sip.is_unspecified()
            && inner.ip_vm.get(&sip) != inner.port_vm.get(&port)
        {
            return;
        }
        inner.mac_port.insert(src, port);
        if let Some(sip) = sip {
            inner.ip_mac.insert(sip, src);
        }

        // To the gateway (ARP for us, DHCP, or off-subnet egress).
        if dst == GW_MAC {
            self.to_gateway(&mut inner, port, frame, ethertype);
            return;
        }
        // Broadcast: the gateway inspects it (ARP-for-gateway, DHCP) AND it floods
        // to the other VMs (so inter-VM ARP resolves).
        if dst == BCAST_MAC {
            self.to_gateway(&mut inner, port, frame, ethertype);
            flood(&inner, port, frame);
            return;
        }
        // Unicast to a known VM -> that port; unknown -> flood.
        match inner.mac_port.get(&dst).copied() {
            Some(p) if p != port => send(&inner, p, frame),
            _ => flood(&inner, port, frame),
        }
    }

    /// Gateway side: ARP reply, DHCP, or hand IPv4 to ipstack for egress.
    fn to_gateway(&self, inner: &mut Inner, port: PortId, frame: &[u8], ethertype: u16) {
        match ethertype {
            ETHERTYPE_ARP => {
                if let Some(reply) = arp_reply(frame, &self.cfg) {
                    send(inner, port, &reply);
                }
            }
            ETHERTYPE_IPV4 => {
                let ip = &frame[14..];
                if is_dhcp(ip) {
                    if let Some(reply) = self.dhcp(inner, ip, frame[6..12].try_into().unwrap()) {
                        send(inner, port, &reply);
                    }
                } else if let Some((src_port, query)) = dns_query(ip, self.cfg.gateway) {
                    // DNS to the gateway: the resolver answers service names and forwards
                    // the rest to the host's resolver. Async (it may dial upstream), so
                    // hand it off with a clone of the port's sink and a copy of the query.
                    if let (Some(tx), Some(cip)) = (inner.ports.get(&port).cloned(), ipv4_src(ip)) {
                        let mac: Mac = frame[6..12].try_into().unwrap();
                        let hosts = self.hosts.clone();
                        let egress = self.egress.clone();
                        let (gw, upstreams, query) =
                            (self.cfg.gateway, self.upstreams.clone(), query.to_vec());
                        tokio::spawn(handle_dns(
                            query, hosts, upstreams, gw, cip, src_port, mac, tx, egress,
                        ));
                    }
                } else if let Some(rst) = self
                    .egress
                    .reject_denied_syn(ip, frame[6..12].try_into().unwrap())
                {
                    // A new connection the egress policy denies: refuse it with a
                    // RST so the guest's connect() fails immediately, instead of
                    // ipstack completing the handshake and then black-holing the
                    // flow (which leaves the guest stalled until a read timeout).
                    send(inner, port, &rst);
                } else {
                    // off-subnet (default route): egress via the shared ipstack
                    let mut pkt = FRAME_POOL.take(ip.len());
                    pkt.extend_from_slice(ip);
                    let _ = self.egress_tx.send(pkt);
                }
            }
            _ => {}
        }
    }

    /// Route an ipstack egress reply back to the VM that owns its destination IP. The frame
    /// arrives with its ethernet header reserved but not yet written (see `ChannelDevice`).
    fn route_in(&self, mut frame: Vec<u8>) {
        let Some(dip) = frame.get(ETH_HDR..).and_then(ipv4_dst) else {
            return;
        };
        let inner = self.inner.lock().unwrap();
        // Route by the authoritative IP -> port binding, not the learned `mac_port` (which a
        // guest can poison by sourcing a forged MAC), so an egress reply reaches only the VM
        // that actually owns the destination address.
        let Some(&port) = inner.ip_port.get(&dip) else {
            return;
        };
        let Some(mac) = inner.ip_mac.get(&dip).copied() else {
            return;
        };
        write_eth_header(&mut frame, mac);
        send_frame(&inner, port, frame);
    }

    /// Allocate (or reuse) a lease for `mac` and build the DHCP reply.
    fn dhcp(&self, inner: &mut Inner, req: &[u8], mac: Mac) -> Option<Vec<u8>> {
        let lease = alloc_lease(inner, &self.cfg, mac)?;
        inner.ip_mac.insert(lease, mac);
        dhcp_reply(req, mac, &self.cfg, lease)
    }

    fn drop_port(&self, port: PortId) {
        let mut inner = self.inner.lock().unwrap();
        inner.ports.remove(&port);
        inner.mac_port.retain(|_, p| *p != port);
        // Drop this port's authoritative address binding; a reconnect on the same socket
        // rebinds it. leases/ip_mac are kept: the VM keeps its address across a reconnect.
        inner.ip_port.retain(|_, p| *p != port);
        inner.port_vm.remove(&port);
    }
}

/// Send a frame to one port (non-blocking; dropped if the port is gone).
fn send(inner: &Inner, port: PortId, frame: &[u8]) {
    send_frame(inner, port, frame.to_vec());
}

/// The same, for a caller that already owns the frame's buffer.
fn send_frame(inner: &Inner, port: PortId, frame: Vec<u8>) {
    if let Some(tx) = inner.ports.get(&port) {
        let _ = tx.send(frame);
    }
}

/// Flood a frame to every port except the source.
fn flood(inner: &Inner, from: PortId, frame: &[u8]) {
    for (&p, tx) in &inner.ports {
        if p != from {
            let _ = tx.send(frame.to_vec());
        }
    }
}

fn ip_stack_config() -> IpStackConfig {
    let mut config = IpStackConfig::default();
    config.mtu_unchecked(MTU);
    // The default of 3 retransmissions abandons a segment after 3 s at the measured
    // timeout's floor. Allow a busy guest longer to answer before resetting its flow.
    let mut tcp = ipstack::TcpConfig::default();
    tcp.max_retransmit_count = TCP_MAX_RETRANSMITS;
    tcp.timeout = TCP_IDLE_TIMEOUT;
    tcp.read_buffer_size = TCP_WINDOW;
    tcp.max_unacked_bytes = TCP_WINDOW as u32;
    // Advertise the link's MSS so a guest sizes its segments to it instead of falling back
    // to the 536-byte default.
    tcp.options = Some(vec![ipstack::TcpOptions::MaximumSegmentSize(MSS)]);
    config.with_tcp_config(tcp);
    config
}

/// The switch's exit, shared with the egress flows. SIGTERM arrives once the VM the switch
/// serves has been torn down, so no flow has a guest left to answer to: what a guest was
/// still uploading when it died is lost with it, but the bytes the switch took off the LAN
/// and acknowledged are its own debt, and it settles them before it goes. Flows carrying a
/// download discard the host response — the guest reader is gone.
struct Drain {
    /// Set once, before `wake` fires, and read by every flow it wakes.
    started: AtomicBool,
    /// Wakes the flows parked in a splice so they notice the drain rather than the deadline.
    wake: tokio::sync::Notify,
    /// A sender cloned into every egress flow and dropped with the flow, plus the keeper
    /// [`Drain::start`] drops. The matching receiver reports the drain complete when the last
    /// of them goes; taking the keeper also refuses flows opened from here on.
    flows: Mutex<Option<UnboundedSender<()>>>,
}

impl Drain {
    /// A drain and the receiver that reports it complete.
    fn new() -> (Arc<Self>, UnboundedReceiver<()>) {
        let (tx, rx) = unbounded_channel();
        let drain = Drain {
            started: AtomicBool::new(false),
            wake: tokio::sync::Notify::new(),
            flows: Mutex::new(Some(tx)),
        };
        (Arc::new(drain), rx)
    }

    fn started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    /// Stop taking flows and wake the ones in flight. A flow parked on a read sees `started`
    /// set either through its own check or through the wakeup, whichever of the two it
    /// reaches first.
    fn start(&self) {
        self.started.store(true, Ordering::Release);
        self.flows.lock().unwrap_or_else(|e| e.into_inner()).take();
        self.wake.notify_waiters();
    }

    /// The token a flow holds while it may still owe the host bytes. `None` once the drain
    /// has started: a flow opened after that has a guest that is already gone.
    fn flow(&self) -> Option<UnboundedSender<()>> {
        self.flows.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

/// ipstack's accept loop: each guest flow becomes a host-side proxy, gated by the
/// egress policy (static IP allowlist + DNS-pinned IPs).
async fn accept_loop(mut ip_stack: IpStack, egress: Arc<EgressGuard>, drain: Arc<Drain>) {
    loop {
        match ip_stack.accept().await {
            Ok(IpStackStream::Tcp(tcp)) => {
                tokio::spawn(proxy_tcp(tcp, egress.clone(), drain.clone()));
            }
            Ok(IpStackStream::Udp(udp)) => {
                tokio::spawn(proxy_udp(udp, egress.clone()));
            }
            Ok(_) => {} // UnknownTransport (ICMP, ...) / UnknownNetwork: dropped
            Err(e) => {
                eprintln!("switch: ipstack accept: {e}");
                return;
            }
        }
    }
}

/// The IPv4 source of a guest egress flow (ipstack's `local_addr`), for per-source policy.
/// `None` for an IPv6 flow — egress is IPv4-only, so such a flow is denied by the caller.
fn guest_src(local: SocketAddr) -> Option<Ipv4Addr> {
    match local {
        SocketAddr::V4(a) => Some(*a.ip()),
        SocketAddr::V6(_) => None,
    }
}

/// Terminate a guest TCP flow and splice it to a host connection to its original
/// destination (egress through the host's own socket).
fn proxy_tcp(
    mut guest: ipstack::IpStackTcpStream,
    egress: Arc<EgressGuard>,
    drain: Arc<Drain>,
) -> impl Future<Output = ()> {
    // Register before the proxy is spawned: ipstack can acknowledge guest bytes while
    // the upstream connection is still pending.
    let owed = drain.flow();
    async move {
        let Some(_owed) = owed else {
            return;
        };
        let dst = guest.peer_addr();
        // The guest's own address, so the right per-source policy applies (`local_addr` is the
        // flow's source; egress is IPv4).
        let src = guest_src(guest.local_addr());
        // Registry proxy: a flow to the sentinel address is spliced to the host-local
        // credential proxy instead of egressing (it bypasses the egress allowlist — it is our
        // own host service, and it never touches the guest's credentials).
        let target = match egress.registry_proxy {
            Some((sentinel, host)) if dst.ip() == IpAddr::V4(sentinel) => host,
            _ => {
                let allowed = src.is_some_and(|s| egress.allows(s, dst));
                if !allowed && egress.enforce {
                    // Fallback deny path: a denied SYN is normally RST'd earlier in
                    // `reject_denied_syn` before ipstack completes the handshake, so this only
                    // fires for a flow that slipped through (e.g. a DNS pin expiring between the
                    // SYN and here). Per-stage dedup collapses any double-record.
                    eprintln!("switch: egress denied (tcp) {dst}");
                    egress.record_denial(crate::egress_report::Proto::Tcp, &dst.to_string());
                    return;
                }
                // A genuinely-allowed flow is an audited IP contact; a dry-run would-be denial
                // is not — `reject_denied_syn` already recorded it at the SYN, and it must not
                // also count as an allowed contact.
                if allowed && let (Some(s), SocketAddr::V4(v4)) = (src, dst) {
                    egress.record_ip_contact(s, v4);
                }
                dst
            }
        };
        match connect_egress(target, CONNECT_TIMEOUT).await {
            Ok(host) => {
                // Counted as the bytes pass rather than from what the copy returns: a flow torn
                // down by either end — which is how most of them end — reports an error and no
                // counts at all, and a job's traffic would read as zero.
                let mut host = Counted {
                    inner: host,
                    egress: egress.clone(),
                };
                // The splice errors when a side tears the flow down rather than closing it
                // cleanly. A reset is how a peer routinely closes — an HTTP server without keepalive,
                // a client that aborts — so it is left unlogged; the rarer faults are worth a line: a
                // timeout, a broken pipe, the upstream gone (see `detect_dead_peer`). Either way,
                // returning drops `guest` and resets its connection, which is all the guest sees.
                if let Err(e) = splice(
                    &mut guest,
                    &mut host,
                    HOST_BOUND_CHUNK,
                    GUEST_BOUND_CHUNK,
                    Some(&drain),
                )
                .await
                    && e.kind() != std::io::ErrorKind::ConnectionReset
                {
                    egress.log_flow_failure(guest.local_addr(), dst, &e);
                }
            }
            // Connect refused, failed, or timed out: return so the guest stream drops and
            // ipstack RSTs it, failing the guest's flow at once instead of leaving it hung.
            Err(e) => eprintln!("switch: tcp connect {target}: {e} — resetting the guest flow"),
        }
    }
}

/// One direction of a spliced flow. The copy loop is tokio's `copy_bidirectional`, with the
/// buffer allocated on the direction's first poll and doubled up to `max` whenever a read
/// fills it: a flow that carries a request and a short reply keeps kilobytes instead of a
/// jumbo segment, and a bulk one still hands the writer a full buffer per write.
/// Adapted from Tokio 1.53.1's `io/util/{copy,copy_bidirectional}.rs`; see NOTICE for
/// the pinned source and MIT license.
struct CopyBuffer {
    read_done: bool,
    /// New input since the drain last checked whether this direction was idle.
    read_progress: bool,
    need_flush: bool,
    /// The last read filled the buffer, so the next one is worth taking more room for.
    saturated: bool,
    pos: usize,
    cap: usize,
    max: usize,
    buf: Vec<u8>,
}

impl CopyBuffer {
    fn new(max: usize) -> Self {
        Self {
            read_done: false,
            read_progress: false,
            need_flush: false,
            saturated: false,
            pos: 0,
            cap: 0,
            max,
            buf: Vec::new(),
        }
    }

    /// Whether the buffer still holds bytes the writer has not taken.
    fn pending(&self) -> bool {
        self.pos < self.cap
    }

    /// Whether another read can add to the buffer, growing it if that is what it takes.
    fn has_room(&self) -> bool {
        self.cap < self.buf.len() || self.buf.len() < self.max
    }

    fn poll_fill_buf<R: AsyncRead + ?Sized>(
        &mut self,
        cx: &mut TaskCtx<'_>,
        reader: Pin<&mut R>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;
        if me.buf.is_empty() {
            me.buf.resize(SPLICE_INIT.min(me.max), 0);
        } else if me.saturated && me.buf.len() < me.max {
            me.saturated = false;
            me.buf.resize((me.buf.len() * 2).min(me.max), 0);
        }
        let size = me.buf.len();
        let mut buf = ReadBuf::new(&mut me.buf);
        buf.set_filled(me.cap);

        let res = reader.poll_read(cx, &mut buf);
        if let Poll::Ready(Ok(())) = res {
            let filled_len = buf.filled().len();
            me.read_done = me.cap == filled_len;
            me.read_progress |= filled_len > me.cap;
            me.saturated = filled_len == size;
            me.cap = filled_len;
        }
        res
    }

    fn poll_write_buf<R: AsyncRead + ?Sized, W: AsyncWrite + ?Sized>(
        &mut self,
        cx: &mut TaskCtx<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<std::io::Result<usize>> {
        let me = &mut *self;
        match writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]) {
            Poll::Pending => {
                // Top up the buffer towards full if we can read a bit more data — this
                // should improve the chances of a large write.
                if !me.read_done && me.has_room() {
                    std::task::ready!(me.poll_fill_buf(cx, reader.as_mut()))?;
                }
                Poll::Pending
            }
            res => res,
        }
    }

    fn poll_copy<R: AsyncRead + ?Sized, W: AsyncWrite + ?Sized>(
        &mut self,
        cx: &mut TaskCtx<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            // If there is some space left in our buffer, then we try to read some data to
            // continue, thus maximizing the chances of a large write.
            if self.has_room() && !self.read_done {
                match self.poll_fill_buf(cx, reader.as_mut()) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        // Ignore pending reads when our buffer is not empty, because we can
                        // try to write data immediately.
                        if self.pos == self.cap {
                            // Try flushing when the reader has no progress, to avoid a
                            // deadlock when the reader depends on a buffered writer.
                            if self.need_flush {
                                std::task::ready!(writer.as_mut().poll_flush(cx))?;
                                self.need_flush = false;
                            }
                            return Poll::Pending;
                        }
                    }
                }
            }

            while self.pos < self.cap {
                let i =
                    std::task::ready!(self.poll_write_buf(cx, reader.as_mut(), writer.as_mut()))?;
                if i == 0 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                }
                self.pos += i;
                self.need_flush = true;
            }
            // A writer reporting more written than it was given would leave `pos` past `cap`
            // and this loop would never stop.
            debug_assert!(
                self.pos <= self.cap,
                "writer returned length larger than input slice"
            );

            self.pos = 0;
            self.cap = 0;

            // Everything written and EOF seen: flush and finish the transfer.
            if self.read_done {
                std::task::ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(()));
            }
        }
    }
}

enum TransferState {
    Running(CopyBuffer),
    ShuttingDown,
    Done,
}

fn transfer_one_direction<R, W>(
    cx: &mut TaskCtx<'_>,
    state: &mut TransferState,
    r: &mut R,
    w: &mut W,
) -> Poll<std::io::Result<()>>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);
    loop {
        match state {
            TransferState::Running(buf) => {
                std::task::ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown;
            }
            TransferState::ShuttingDown => {
                std::task::ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done;
            }
            TransferState::Done => return Poll::Ready(Ok(())),
        }
    }
}

/// Copy in both directions between `a` and `b` until both have reported EOF and the opposing
/// writer has been shut down, or either side errors — tokio's `copy_bidirectional_with_sizes`
/// with the buffer sizes read as ceilings rather than as what to allocate up front.
///
/// With a `drain`, the flow answers the switch's exit: from then on it finishes writing what
/// `a` has already handed it to `b` and shuts `b` down, and abandons the other direction —
/// `a` is a guest that no longer exists. Replies are discarded until host EOF to avoid
/// resetting the socket with unread input. After [`DRAIN_SETTLE`] without guest bytes,
/// the host writer is shut down; the caller bounds the drain with [`DRAIN_DEADLINE`].
async fn splice<A, B>(
    a: &mut A,
    b: &mut B,
    a_to_b_max: usize,
    b_to_a_max: usize,
    drain: Option<&Drain>,
) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut a_to_b = TransferState::Running(CopyBuffer::new(a_to_b_max));
    let mut b_to_a = TransferState::Running(CopyBuffer::new(b_to_a_max));
    // Registered before the flag is first read, so a drain starting between the two wakes
    // this flow instead of leaving it parked: `Notify` keeps no permit for a late waiter.
    let mut wake = drain.map(|d| Box::pin(d.wake.notified()));
    if let Some(wake) = wake.as_mut() {
        wake.as_mut().enable();
    }
    let mut draining = drain.is_some_and(Drain::started);
    let mut settle: Option<Pin<Box<tokio::time::Sleep>>> = None;
    let mut discard = tokio::io::sink();
    std::future::poll_fn(|cx| {
        if !draining && let Some(wake) = wake.as_mut() {
            draining = wake.as_mut().poll(cx).is_ready();
        }
        let a_to_b_done = transfer_one_direction(cx, &mut a_to_b, a, b)?;
        if draining {
            // Keep reading replies, but discard them: the guest is gone. Closing a TCP
            // socket with unread input resets it and can discard queued upload bytes.
            let b_to_a_done = transfer_one_direction(cx, &mut b_to_a, b, &mut discard)?;
            if a_to_b_done.is_ready() {
                return b_to_a_done.map(Ok);
            }
            match &mut a_to_b {
                TransferState::Running(buf) if !buf.pending() => {
                    if std::mem::take(&mut buf.read_progress) {
                        settle = None;
                    }
                    // Allow the stack to hand over its last bytes, then send EOF even if
                    // the vanished guest never closed its stream.
                    let settle =
                        settle.get_or_insert_with(|| Box::pin(tokio::time::sleep(DRAIN_SETTLE)));
                    if settle.as_mut().poll(cx).is_ready() {
                        buf.read_done = true;
                        cx.waker().wake_by_ref();
                    }
                }
                _ => settle = None,
            }
            // Await the host's EOF after shutting down its writer. The outer deadline
            // bounds receivers that stop reading or never close their reply stream.
            return Poll::Pending;
        }
        let b_to_a_done = transfer_one_direction(cx, &mut b_to_a, b, a)?;
        // An early return is not a problem: the other direction keeps reporting Done on the
        // polls that follow.
        std::task::ready!(a_to_b_done);
        std::task::ready!(b_to_a_done);
        Poll::Ready(Ok(()))
    })
    .await
}

/// The host side of a guest flow, with what crosses it added to the switch's totals. Wraps
/// the host end rather than the guest end so what is counted is what actually left the box:
/// a write to the host is the guest sending, a read from it the guest receiving.
struct Counted<S> {
    inner: S,
    egress: Arc<EgressGuard>,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Counted<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &polled {
            let read = buf.filled().len() - before;
            self.egress.count(0, read as u64);
        }
        polled
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(written)) = &polled {
            self.egress.count(*written as u64, 0);
        }
        polled
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Dial `target` for a guest egress flow, bounded by `timeout`. On expiry, returns a
/// `TimedOut` error instead of blocking on the OS default connect timeout — see
/// [`CONNECT_TIMEOUT`] for why an unbounded dial stalls the guest.
async fn connect_egress(target: SocketAddr, timeout: Duration) -> std::io::Result<TcpStream> {
    let sock = match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect timed out after {}s", timeout.as_secs()),
            ));
        }
    };
    // Best effort: the socket erroring out is what gets the guest its RST, but a flow is
    // worth carrying without its timeouts — just not silently.
    if let Err(e) = detect_dead_peer(&sock) {
        log::warn!("could not set the keepalive timeouts for {target}: {e}");
    }
    Ok(sock)
}

/// Arm the kernel's keepalive on an upstream socket, so a destination that stops answering
/// surfaces as an error within about a minute and a half. See [`KEEPALIVE_IDLE`]. The options
/// are Linux-only, as is `vk`.
fn detect_dead_peer(sock: &TcpStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let fd = sock.as_raw_fd();
    set_sock_opt(fd, libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1)?;
    set_sock_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPIDLE, KEEPALIVE_IDLE)?;
    set_sock_opt(
        fd,
        libc::IPPROTO_TCP,
        libc::TCP_KEEPINTVL,
        KEEPALIVE_INTERVAL,
    )?;
    set_sock_opt(fd, libc::IPPROTO_TCP, libc::TCP_KEEPCNT, KEEPALIVE_PROBES)
}

/// One integer-valued socket option.
fn set_sock_opt(
    fd: std::os::fd::RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> std::io::Result<()> {
    // SAFETY: every option here takes one int, and `value` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    match rc {
        0 => Ok(()),
        _ => Err(std::io::Error::last_os_error()),
    }
}

/// Relay a guest UDP flow (e.g. DNS) to its destination via a host socket. ipstack
/// closes the stream after its udp_timeout, ending the task.
async fn proxy_udp(mut guest: ipstack::IpStackUdpStream, egress: Arc<EgressGuard>) {
    let dst = guest.peer_addr();
    let src = guest_src(guest.local_addr());
    let allowed = src.is_some_and(|s| egress.allows(s, dst));
    if !allowed {
        egress.record_denial(crate::egress_report::Proto::Udp, &dst.to_string());
        if egress.enforce {
            eprintln!("switch: egress denied (udp) {dst}");
            return;
        }
        eprintln!("switch: egress would deny (udp) {dst} — dry-run, allowed");
    }
    // Only a genuinely-allowed dial is an audited IP contact; a dry-run would-be denial is
    // in the denial channel above instead, not double-counted as a contact.
    if allowed && let (Some(s), SocketAddr::V4(v4)) = (src, dst) {
        egress.record_ip_contact(s, v4);
    }
    let bind: SocketAddr = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }
        .parse()
        .unwrap();
    let host = match UdpSocket::bind(bind).await {
        Ok(s) => s,
        Err(e) => return eprintln!("switch: udp bind: {e}"),
    };
    if host.connect(dst).await.is_err() {
        return;
    }
    let mut from_guest = vec![0u8; MAX_FRAME];
    let mut from_host = vec![0u8; MAX_FRAME];
    loop {
        tokio::select! {
            r = guest.read(&mut from_guest) => match r {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if host.send(&from_guest[..n]).await.is_ok() {
                        egress.count(n as u64, 0);
                    }
                }
            },
            r = host.recv(&mut from_host) => match r {
                Ok(n) => {
                    if guest.write_all(&from_host[..n]).await.is_err() {
                        return;
                    }
                    egress.count(0, n as u64);
                }
                Err(_) => return,
            },
        }
    }
}

/// Every `nameserver` from resolv.conf text, in file order. Per resolv.conf(5) the keyword
/// and its value are separated by any run of whitespace (space(s) or tab) — matching only a
/// single space silently drops tab-separated entries (as some provisioners emit). Taking all
/// of them lets the forwarder fail over between the host's resolvers instead of pinning every
/// lookup to the first.
fn all_nameservers(text: &str) -> Vec<std::net::IpAddr> {
    text.lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("nameserver")?;
            // Require a whitespace separator so `nameserverfoo` is not treated as a match,
            // then read the first token — like glibc, ignore any trailing junk on the line.
            if !rest.starts_with(|c: char| c.is_ascii_whitespace()) {
                return None;
            }
            rest.split_whitespace().next()?.parse().ok()
        })
        .collect()
}

/// The first configured resolver — retained for the resolv.conf parsing tests; the switch
/// itself forwards across all of them (see [`all_nameservers`]).
#[cfg(test)]
fn first_nameserver(text: &str) -> Option<std::net::IpAddr> {
    all_nameservers(text).into_iter().next()
}

/// The `nameserver` entries of a resolv.conf file, or empty if it cannot be read.
fn read_nameservers(path: &str) -> Vec<std::net::IpAddr> {
    std::fs::read_to_string(path)
        .map(|text| all_nameservers(&text))
        .unwrap_or_default()
}

/// Pick the resolvers to forward guest DNS to: the host's own (`/etc/resolv.conf`), followed
/// by the real uplinks behind a local resolver stub such as systemd-resolved (127.0.0.53) as
/// trailing fallbacks. The stub stays first because it is the only resolver that knows the
/// host's split-DNS routing: a VPN's `corp.example` or Tailscale's MagicDNS domain is served by
/// per-link resolvers that never appear in the stub's default uplink list, so asking those
/// uplinks directly answers NXDOMAIN for every such name. Querying the stub first concentrates
/// guest DNS load there to preserve split-DNS routing. If the stub stalls, uplinks provide
/// best-effort fallback for public names but cannot resolve split-DNS names they do not know.
fn choose_upstreams(
    etc: Vec<std::net::IpAddr>,
    uplinks: Vec<std::net::IpAddr>,
) -> Vec<std::net::IpAddr> {
    let mut servers = etc;
    if servers.iter().all(|ip| ip.is_loopback()) {
        for ip in uplinks {
            if !ip.is_loopback() && !servers.contains(&ip) {
                servers.push(ip);
            }
        }
    }
    servers
}

/// The resolvers guest DNS is forwarded to (see [`choose_upstreams`]), as socket addresses.
/// Falls back to a public resolver when nothing usable is configured.
fn host_upstreams() -> Vec<SocketAddr> {
    let servers = choose_upstreams(
        read_nameservers("/etc/resolv.conf"),
        read_nameservers("/run/systemd/resolve/resolv.conf"),
    );
    if servers.is_empty() {
        return vec![SocketAddr::new(FALLBACK_DNS.into(), DNS_PORT)];
    }
    servers
        .into_iter()
        .map(|ip| SocketAddr::new(ip, DNS_PORT))
        .collect()
}

/// Resolve a guest DNS query and send the response back to it: service names are
/// answered from the local map; everything else is forwarded to the host's resolver.
#[allow(clippy::too_many_arguments)]
async fn handle_dns(
    query: Vec<u8>,
    hosts: Arc<HashMap<String, Ipv4Addr>>,
    upstreams: Arc<[SocketAddr]>,
    gateway: Ipv4Addr,
    client_ip: Ipv4Addr,
    client_port: u16,
    client_mac: Mac,
    tx: UnboundedSender<Vec<u8>>,
    egress: Arc<EgressGuard>,
) {
    const TYPE_A: u16 = 1;
    // The name the failure log attributes an upstream fault to: the primary resolver, even
    // when the fault was met (and retried) across the others.
    let primary = upstreams
        .first()
        .copied()
        .unwrap_or_else(|| SocketAddr::new(FALLBACK_DNS.into(), DNS_PORT));
    let response = if let Some(r) = local_answer(&query, &hosts) {
        Some(r) // service name: on-subnet, not subject to egress pinning
    } else if let Some((name, qtype, qend)) = parse_question(&query) {
        // Format the lookup only when reporting a failure.
        let question = || format!("{name} ({})", qtype_name(qtype));
        if is_reverse_dns(&name) {
            // A PTR lookup resolves an IP to a name; it never opens a flow, so it
            // needn't be allowlisted. Forward it without pinning (its answer is a
            // name, not an A-record to admit for egress).
            match resolve_upstream(&query, &upstreams).await {
                Ok(a) => Some(a.reply),
                Err(e) => {
                    egress.log_dns_upstream(primary, &question(), &e);
                    Some(dns_servfail(&query, qend))
                }
            }
        } else if egress.name_allowed(client_ip, &name) || !egress.enforce {
            if egress.name_allowed(client_ip, &name) {
                // Audit: count the guest's A-record lookups as its external contacts (egress
                // is IPv4, so an A query is what precedes a connection); the paired AAAA query
                // for the same name is not double-counted.
                if qtype == TYPE_A {
                    egress.record_contact(&name);
                }
            } else {
                // Dry-run: the allowlist would refuse this name. Record the would-be denial,
                // but resolve and pin it below anyway so the guest's connection succeeds — the
                // point of the mode is to observe without breaking the job.
                egress.record_denial(crate::egress_report::Proto::Dns, &name);
                eprintln!("switch: dns would refuse (egress allowlist): {name} — dry-run, resolved");
            }
            // forward, then pin the A-records (scoped to this resolving guest) so its
            // connection is allowed — and only its, not another VM's with a different policy.
            match resolve_upstream(&query, &upstreams).await {
                Ok(a) => {
                    // A truncated answer is pinned from its TCP-recovered full record set; when
                    // that recovery failed, pinning saw only the partial set, worth a log line.
                    if let Some(e) = &a.degraded {
                        egress.log_dns_upstream(primary, &question(), e);
                    }
                    let (ips, ttl) = parse_a_records(a.pin_source());
                    egress.record(client_ip, &ips, ttl);
                    // Audit: these IPs are now attributable to `name` for this VM, so a later
                    // connection from it is counted under the domains summary, not re-logged as
                    // a direct-IP contact.
                    egress.record_dns_ips(client_ip, &ips);
                    Some(a.reply)
                }
                // SERVFAIL rather than silence: the guest's resolver gives up on the lookup
                // at once instead of sitting out its whole retry schedule for every name.
                Err(e) => {
                    egress.log_dns_upstream(primary, &question(), &e);
                    Some(dns_servfail(&query, qend))
                }
            }
        } else {
            eprintln!("switch: dns refused (egress allowlist): {name}");
            egress.record_denial(crate::egress_report::Proto::Dns, &name);
            Some(dns_nxdomain(&query, qend))
        }
    } else {
        // An unparsable question leaves nothing to echo back, so a failure can only be
        // dropped — but it is still logged.
        resolve_upstream(&query, &upstreams)
            .await
            .inspect_err(|e| egress.log_dns_upstream(primary, "an unparsable question", e))
            .ok()
            .map(|a| a.reply)
    };
    if let Some(resp) = response
        && let Some(frame) = dns_frame(gateway, client_ip, client_port, client_mac, &resp)
    {
        let _ = tx.send(frame);
    }
}

/// Why forwarding a query to the upstream resolver failed. The upstream is the host's
/// own resolver, so every variant is a host-side fault the operator has to see — the
/// guest only ever learns that the lookup failed.
#[derive(Debug)]
enum UpstreamError {
    /// Socket setup or I/O toward the upstream: bind, connect, send, or recv (which on
    /// a connected UDP socket reports the ICMP error a closed port answers with).
    Io(std::io::Error),
    /// No reply within the deadline.
    Timeout(Duration),
    /// A reply too short to be a DNS message (the header alone is 12 bytes).
    Short(usize),
}

impl UpstreamError {
    /// The fault, without its message — the log limiter's key, so a burst of the same
    /// failure collapses to one line. Timeout and a short reply borrow the io kinds
    /// that name them.
    fn kind(&self) -> std::io::ErrorKind {
        match self {
            UpstreamError::Io(e) => e.kind(),
            UpstreamError::Timeout(_) => std::io::ErrorKind::TimedOut,
            UpstreamError::Short(_) => std::io::ErrorKind::InvalidData,
        }
    }
}

impl From<std::io::Error> for UpstreamError {
    fn from(e: std::io::Error) -> Self {
        UpstreamError::Io(e)
    }
}

impl std::fmt::Display for UpstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpstreamError::Io(e) => write!(f, "{e}"),
            UpstreamError::Timeout(d) => write!(f, "no reply in {d:?}"),
            UpstreamError::Short(n) => write!(f, "reply too short ({n} bytes)"),
        }
    }
}

/// An answer from the host's resolvers. `reply` is the datagram to send the guest — a
/// UDP-sized answer, truncated (TC) when the full record set did not fit. `full` is that full
/// set, recovered over TCP, present only when `reply` was truncated and the TCP retry
/// succeeded: egress pinning reads its A-records so a connection to any returned IP is allowed
/// even though the guest itself only receives `reply`. `degraded` carries the TCP fault when
/// that retry failed, for the caller to log — pinning then saw only the truncated answer.
#[derive(Debug)]
struct UpstreamAnswer {
    reply: Vec<u8>,
    full: Option<Vec<u8>>,
    degraded: Option<UpstreamError>,
}

impl UpstreamAnswer {
    /// The bytes egress pinning reads A-records from: the full TCP answer when one was
    /// recovered, otherwise the guest reply itself.
    fn pin_source(&self) -> &[u8] {
        self.full.as_deref().unwrap_or(&self.reply)
    }
}

/// Resolve a guest query against the host's resolvers. A dropped UDP datagram
/// must not reach the guest as SERVFAIL, so a lookup gets up to [`DNS_UPSTREAM_TRIES`] tries
/// rotating across the configured nameservers — each early try bounded by
/// [`DNS_UPSTREAM_PROBE_TIMEOUT`] for a quick failover, the last waiting out the rest of
/// [`DNS_UPSTREAM_BUDGET`]. A truncated (TC) answer is re-asked over TCP so pinning sees the
/// full A-set, while the guest still gets the UDP-sized reply. The last fault is returned only
/// if every try failed.
async fn resolve_upstream(
    query: &[u8],
    upstreams: &[SocketAddr],
) -> Result<UpstreamAnswer, UpstreamError> {
    resolve_upstream_with(
        query,
        upstreams,
        DNS_UPSTREAM_TRIES,
        DNS_UPSTREAM_PROBE_TIMEOUT,
        DNS_UPSTREAM_BUDGET,
    )
    .await
}

/// [`resolve_upstream`] with the try count, probe deadline, and overall budget as parameters,
/// for faster tests.
async fn resolve_upstream_with(
    query: &[u8],
    upstreams: &[SocketAddr],
    tries: usize,
    probe_timeout: Duration,
    budget: Duration,
) -> Result<UpstreamAnswer, UpstreamError> {
    let fallback = [SocketAddr::new(FALLBACK_DNS.into(), DNS_PORT)];
    let servers: &[SocketAddr] = if upstreams.is_empty() {
        &fallback
    } else {
        upstreams
    };
    let deadline = Instant::now() + budget;
    let tries = tries.max(1);
    let mut last = UpstreamError::Timeout(probe_timeout);
    for attempt in 0..tries {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Every try but the last gets the short probe, so a dropped datagram rotates to the
        // next resolver fast; the last waits out the remaining budget, so a lone slow-but-alive
        // resolver is not abandoned before it answers.
        let this_timeout = if attempt + 1 == tries {
            remaining
        } else {
            probe_timeout.min(remaining)
        };
        let upstream = servers[attempt % servers.len()];
        match forward_upstream_with(query, upstream, this_timeout).await {
            // Truncated: the answer did not fit a UDP datagram (a CDN name behind a long CNAME
            // chain and many A records). DNS over TCP has no size limit, so the full record set
            // — and thus the pin — is recovered, bounded by whatever budget is left. The guest
            // still gets the truncated `reply`, which fits the buffer it asked over; a failed
            // recovery is reported so the operator sees pinning ran on a partial answer.
            Ok(reply) if is_truncated(&reply) => {
                let tcp_budget = deadline.saturating_duration_since(Instant::now());
                return Ok(
                    match forward_upstream_tcp(query, upstream, tcp_budget).await {
                        Ok(full) => UpstreamAnswer {
                            reply,
                            full: Some(full),
                            degraded: None,
                        },
                        Err(e) => UpstreamAnswer {
                            reply,
                            full: None,
                            degraded: Some(e),
                        },
                    },
                );
            }
            Ok(reply) => {
                return Ok(UpstreamAnswer {
                    reply,
                    full: None,
                    degraded: None,
                });
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// The DNS TC (truncation) flag of a response — set when the answer was too large for the UDP
/// transport and the querier must retry over TCP. (Bit 1 of the flags byte after the id.)
fn is_truncated(msg: &[u8]) -> bool {
    msg.len() >= 3 && msg[2] & 0x02 != 0
}

/// Forward a query over DNS-over-TCP (RFC 1035 §4.2.2: the message framed by a 2-byte
/// big-endian length prefix, both ways) and return the raw response — recovers a truncated
/// UDP answer without a size limit.
async fn forward_upstream_tcp(
    query: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let len = u16::try_from(query.len()).map_err(|_| {
        UpstreamError::Io(std::io::Error::other("query exceeds DNS-over-TCP length"))
    })?;
    let exchange = async {
        let mut sock = TcpStream::connect(upstream).await?;
        sock.write_all(&len.to_be_bytes()).await?;
        sock.write_all(query).await?;
        let mut lenbuf = [0u8; 2];
        sock.read_exact(&mut lenbuf).await?;
        let mut resp = vec![0u8; u16::from_be_bytes(lenbuf) as usize];
        sock.read_exact(&mut resp).await?;
        Ok::<Vec<u8>, std::io::Error>(resp)
    };
    let resp = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| UpstreamError::Timeout(timeout))??;
    if resp.len() < 12 {
        return Err(UpstreamError::Short(resp.len()));
    }
    Ok(resp)
}

/// Send a raw DNS query to a single upstream over UDP and return its raw response, with a
/// configurable reply deadline.
async fn forward_upstream_with(
    query: &[u8],
    upstream: SocketAddr,
    timeout: Duration,
) -> Result<Vec<u8>, UpstreamError> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .unwrap();
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(upstream).await?;
    sock.send(query).await?;
    let mut buf = vec![0u8; MAX_FRAME];
    let n = tokio::time::timeout(timeout, sock.recv(&mut buf))
        .await
        .map_err(|_| UpstreamError::Timeout(timeout))??;
    if n < 12 {
        return Err(UpstreamError::Short(n));
    }
    buf.truncate(n);
    Ok(buf)
}

/// A query type as its mnemonic where the guest resolvers use one, else the number —
/// an A and an AAAA failing are different symptoms, so the log names which.
fn qtype_name(qtype: u16) -> std::borrow::Cow<'static, str> {
    match qtype {
        1 => "A".into(),
        5 => "CNAME".into(),
        12 => "PTR".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        other => other.to_string().into(),
    }
}

/// If the query's name is a known service name, build the answer locally (an A record
/// for A queries, NODATA otherwise so the name never leaks upstream); else None.
fn local_answer(query: &[u8], hosts: &HashMap<String, Ipv4Addr>) -> Option<Vec<u8>> {
    let (name, qtype, qend) = parse_question(query)?;
    let ip = hosts.get(&name)?;
    Some(dns_response(query, qend, qtype, *ip))
}

/// True if `ip` is a UDP datagram to the gateway's DNS port; returns the guest's
/// source port and the DNS query payload.
fn dns_query(ip: &[u8], gateway: Ipv4Addr) -> Option<(u16, &[u8])> {
    if ip.len() < 20 || (ip[0] >> 4) != 4 || ip[9] != 17 || ipv4_dst(ip)? != gateway {
        return None;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let udp = ip.get(ihl..)?;
    if udp.len() < 8 || u16::from_be_bytes([udp[2], udp[3]]) != DNS_PORT {
        return None;
    }
    Some((u16::from_be_bytes([udp[0], udp[1]]), udp.get(8..)?))
}

/// A reverse-DNS (PTR) query name — IPv4 `*.in-addr.arpa` or IPv6 `*.ip6.arpa`.
/// `name` is already lowercased and stripped of any trailing dot by `parse_question`.
fn is_reverse_dns(name: &str) -> bool {
    name.ends_with(".in-addr.arpa") || name.ends_with(".ip6.arpa")
}

/// Parse the first DNS question: lowercased name, qtype, and the byte offset just
/// past the question (where answers begin). Rejects compressed names in the question.
fn parse_question(msg: &[u8]) -> Option<(String, u16, usize)> {
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) < 1 {
        return None;
    }
    let mut i = 12;
    let mut name = String::new();
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointer in the question: unexpected
        }
        let label = msg.get(i + 1..i + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label));
        i += 1 + len;
    }
    let qtype = u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]);
    Some((name.to_ascii_lowercase(), qtype, i + 4)) // + qtype(2) + qclass(2)
}

/// Build a DNS response echoing the question: one A record for an A query, else
/// NODATA (NOERROR, no answers).
fn dns_response(query: &[u8], qend: usize, qtype: u16, ip: Ipv4Addr) -> Vec<u8> {
    const TYPE_A: u16 = 1;
    let mut out = Vec::with_capacity(qend + 16);
    out.extend_from_slice(&query[0..2]); // transaction id
    out.push(0x84 | (query[2] & 0x01)); // QR=1, AA=1, RD copied
    out.push(0x80); // RA=1, rcode=0
    out.extend_from_slice(&[0, 1]); // QDCOUNT
    out.extend_from_slice(&(u16::from(qtype == TYPE_A)).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT + ARCOUNT
    out.extend_from_slice(&query[12..qend]); // echo the question
    if qtype == TYPE_A {
        out.extend_from_slice(&[0xc0, 0x0c]); // name -> pointer to the question (offset 12)
        out.extend_from_slice(&[0, 1, 0, 1]); // type A, class IN
        out.extend_from_slice(&300u32.to_be_bytes()); // TTL
        out.extend_from_slice(&[0, 4]); // RDLENGTH
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// An answerless response echoing the question, carrying `rcode`. AA is set only where the
/// switch is the name's authority: it owns the allowlist namespace it NXDOMAINs, but a
/// SERVFAIL means it could not reach the real resolver, so it must not claim authority.
fn dns_error(query: &[u8], qend: usize, rcode: u8) -> Vec<u8> {
    let aa = if rcode == RCODE_SERVFAIL { 0 } else { 0x04 };
    let mut out = Vec::with_capacity(qend);
    out.extend_from_slice(&query[0..2]); // transaction id
    out.push(0x80 | aa | (query[2] & 0x01)); // QR=1, AA per authority, RD copied
    out.push(0x80 | rcode); // RA=1
    out.extend_from_slice(&[0, 1]); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT + NSCOUNT + ARCOUNT
    out.extend_from_slice(&query[12..qend]); // echo the question
    out
}

/// An NXDOMAIN response — refuses a name outside the egress allowlist (the guest sees
/// "could not resolve"; the name never leaks upstream).
fn dns_nxdomain(query: &[u8], qend: usize) -> Vec<u8> {
    dns_error(query, qend, RCODE_NXDOMAIN)
}

/// A SERVFAIL response — the upstream resolver did not answer, and saying so is what
/// makes the guest's resolver fail the lookup now rather than retry until it times out.
fn dns_servfail(query: &[u8], qend: usize) -> Vec<u8> {
    dns_error(query, qend, RCODE_SERVFAIL)
}

/// Advance past a DNS name at `i`, returning the offset just after it. A compression
/// pointer (0xc0) ends the name in two bytes. Bounds-safe: returns msg.len() if it
/// runs off the end.
fn skip_name(msg: &[u8], mut i: usize) -> usize {
    while let Some(&len) = msg.get(i) {
        if len == 0 {
            return i + 1;
        }
        if len & 0xc0 == 0xc0 {
            return i + 2; // compression pointer: name ends here
        }
        i += 1 + len as usize;
    }
    msg.len()
}

/// Extract the A-record IPs (and the smallest TTL) from a DNS response, for pinning.
/// Best-effort + bounds-safe: stops at the first truncated/malformed record.
fn parse_a_records(msg: &[u8]) -> (Vec<Ipv4Addr>, u32) {
    const TYPE_A: u16 = 1;
    const CLASS_IN: u16 = 1;
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    if msg.len() < 12 {
        return (ips, 60);
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(msg, i) + 4; // qtype(2) + qclass(2)
    }
    for _ in 0..an {
        i = skip_name(msg, i);
        let Some(hdr) = msg.get(i..i + 10) else { break };
        let rtype = u16::from_be_bytes([hdr[0], hdr[1]]);
        let class = u16::from_be_bytes([hdr[2], hdr[3]]);
        let ttl = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let rdlen = u16::from_be_bytes([hdr[8], hdr[9]]) as usize;
        let rdata_at = i + 10;
        let Some(rdata) = msg.get(rdata_at..rdata_at + rdlen) else {
            break;
        };
        if rtype == TYPE_A && class == CLASS_IN && rdlen == 4 {
            ips.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            min_ttl = min_ttl.min(ttl);
        }
        i = rdata_at + rdlen;
    }
    (ips, if min_ttl == u32::MAX { 60 } else { min_ttl })
}

/// Wrap a DNS response payload as gateway:53 -> client:port over UDP/IPv4/ethernet.
fn dns_frame(
    gateway: Ipv4Addr,
    client_ip: Ipv4Addr,
    client_port: u16,
    client_mac: Mac,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let builder = etherparse::PacketBuilder::ethernet2(GW_MAC, client_mac)
        .ipv4(gateway.octets(), client_ip.octets(), 64)
        .udp(DNS_PORT, client_port);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut out, payload).ok()?;
    Some(out)
}

/// A connection-opening TCP SYN parsed from a guest IPv4 packet.
struct TcpSyn {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    seq: u32,
}

/// Parse `ip` (an IPv4 packet, no ethernet header) as a connection-opening TCP
/// segment. `Some` only for a pure SYN (SYN set, ACK clear) — the packet that
/// opens a connection; SYN-ACKs, retransmits carrying ACK, and mid-flow segments
/// return `None` so only the initial handshake is ever rejected.
fn parse_tcp_syn(ip: &[u8]) -> Option<TcpSyn> {
    let v4 = etherparse::Ipv4Slice::from_slice(ip).ok()?;
    if v4.header().protocol() != etherparse::IpNumber::TCP {
        return None;
    }
    let tcp = etherparse::TcpHeaderSlice::from_slice(v4.payload().payload).ok()?;
    if !tcp.syn() || tcp.ack() {
        return None;
    }
    Some(TcpSyn {
        src: SocketAddrV4::new(v4.header().source_addr(), tcp.source_port()),
        dst: SocketAddrV4::new(v4.header().destination_addr(), tcp.destination_port()),
        seq: tcp.sequence_number(),
    })
}

/// Build the ethernet frame refusing `syn`: a RST+ACK from the SYN's destination
/// back to the guest (`client_mac`), sourced from the gateway MAC like the other
/// gateway-originated replies. seq=0, ack=SYN.seq+1 per RFC 793 (a SYN spans one
/// sequence number), so no per-connection state is needed for the guest to
/// accept it and fail its connect() with ECONNREFUSED.
fn tcp_rst_frame(syn: &TcpSyn, client_mac: Mac) -> Option<Vec<u8>> {
    let builder = etherparse::PacketBuilder::ethernet2(GW_MAC, client_mac)
        .ipv4(syn.dst.ip().octets(), syn.src.ip().octets(), 64)
        .tcp(syn.dst.port(), syn.src.port(), 0, 0)
        .rst()
        .ack(syn.seq.wrapping_add(1));
    let mut out = Vec::with_capacity(builder.size(0));
    builder.write(&mut out, &[]).ok()?;
    Some(out)
}

/// Reuse jumbo packet buffers after consumers have copied them out. Small packets use
/// their actual size so a backlog of ACKs does not retain a jumbo allocation per packet.
struct FramePool {
    free: Mutex<Vec<Vec<u8>>>,
}

/// Capacity every pooled buffer holds: the largest frame the switch carries, so a buffer
/// out of the pool never has to grow.
const POOL_BUF: usize = ETH_HDR + MAX_FRAME;
/// Only large packets use the jumbo pool; smaller ones allocate their requested size.
const POOL_MIN: usize = 16 * 1024;
/// How many buffers the pool keeps: enough to cover the handful in flight between the
/// gateway and a guest's writer at any moment. Past this a returned buffer is freed, so a
/// queue that ran long does not pin memory for the rest of the run.
const POOL_FRAMES: usize = 32;

static FRAME_POOL: FramePool = FramePool {
    free: Mutex::new(Vec::new()),
};

impl FramePool {
    /// An empty buffer sized for the packet, reusing jumbo storage for large packets.
    fn take(&self, size: usize) -> Vec<u8> {
        if size < POOL_MIN {
            return Vec::with_capacity(size);
        }
        match self.free.lock().unwrap().pop() {
            Some(mut buf) => {
                buf.clear();
                buf
            }
            None => Vec::with_capacity(POOL_BUF),
        }
    }

    /// Take a buffer back. One that cannot hold a full frame, or that arrives when the pool
    /// is full, is dropped: the pool refills itself from the next `take`.
    fn give(&self, buf: Vec<u8>) {
        let mut free = self.free.lock().unwrap();
        if buf.capacity() >= POOL_BUF && free.len() < POOL_FRAMES {
            free.push(buf);
        }
    }
}

/// A tun-like device for ipstack backed by two channels: it reads the off-subnet
/// IP packets the switch forwards and writes the IP packets ipstack emits back.
struct ChannelDevice {
    rx: UnboundedReceiver<Vec<u8>>,
    tx: UnboundedSender<Vec<u8>>,
}

impl AsyncRead for ChannelDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskCtx<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut().rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let n = pkt.len().min(buf.remaining());
                buf.put_slice(&pkt[..n]);
                FRAME_POOL.give(pkt);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ChannelDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut TaskCtx<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Hand the packet on in a buffer that already reserves the ethernet header, so
        // routing it to its guest writes the header in place instead of copying the packet
        // into a second buffer (see `route_in`).
        let mut frame = FRAME_POOL.take(ETH_HDR + buf.len());
        frame.resize(ETH_HDR, 0);
        frame.extend_from_slice(buf);
        let _ = self.get_mut().tx.send(frame);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The single writer to one guest's qemu stream. Frames already queued behind the one
/// that woke us share a write, reducing calls when the socket accepts the batch.
async fn writer_task<W: AsyncWrite + Unpin>(mut wr: W, mut rx: UnboundedReceiver<Vec<u8>>) {
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(WRITE_BATCH_FRAMES);
    let mut headers = [[0u8; 4]; WRITE_BATCH_FRAMES];
    loop {
        if frames.is_empty() && rx.recv_many(&mut frames, WRITE_BATCH_FRAMES).await == 0 {
            return; // every sender is gone
        }
        // Always take the first frame, then as many as fit: the byte bound keeps a batch
        // to one write's worth whatever the frames' size.
        let mut taken = 0;
        let mut bytes = 0;
        for frame in &frames {
            if taken > 0 && bytes + 4 + frame.len() > WRITE_BATCH_BYTES {
                break;
            }
            headers[taken] = (frame.len() as u32).to_be_bytes();
            bytes += 4 + frame.len();
            taken += 1;
        }
        // Length prefixes and frames form a batch without copying frame data.
        // Short writes advance the remaining slices.
        let mut io = [IoSlice::new(&[]); 2 * WRITE_BATCH_FRAMES];
        for (i, frame) in frames[..taken].iter().enumerate() {
            io[2 * i] = IoSlice::new(&headers[i]);
            io[2 * i + 1] = IoSlice::new(frame);
        }
        let mut pending = &mut io[..2 * taken];
        while !pending.is_empty() {
            match wr.write_vectored(pending).await {
                Ok(0) | Err(_) => return,
                Ok(n) => IoSlice::advance_slices(&mut pending, n),
            }
        }
        for frame in frames.drain(..taken) {
            FRAME_POOL.give(frame);
        }
    }
}

/// Address a guest-bound frame to `guest_mac`, filling the [`ETH_HDR`] bytes it reserves
/// ahead of its IP packet. The frame carries that reservation from the moment ipstack hands
/// the packet over, so this writes a header rather than copying the packet.
fn write_eth_header(frame: &mut [u8], guest_mac: Mac) {
    let ethertype = match frame.get(ETH_HDR).map(|b| b >> 4) {
        Some(6) => ETHERTYPE_IPV6,
        _ => ETHERTYPE_IPV4,
    };
    frame[0..6].copy_from_slice(&guest_mac);
    frame[6..12].copy_from_slice(&GW_MAC);
    frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
}

/// A guest's qemu stream, read through a bounded buffer. One read can collect several
/// frames, which `next` hands out one by one.
struct FrameReader {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

impl FrameReader {
    fn new() -> Self {
        Self {
            // Hold at least one full frame, even if it arrives across several reads.
            buf: vec![0u8; READ_BUF.max(MAX_FRAME + 4)],
            start: 0,
            end: 0,
        }
    }

    /// The next frame as a range into `buf`, valid until the following call; `Ok(None)`
    /// on a clean EOF.
    async fn next<R: AsyncRead + Unpin>(&mut self, rd: &mut R) -> Result<Option<(usize, usize)>> {
        // Buffered frames bypass socket polls, so charge each frame to Tokio's cooperative
        // budget to keep a busy guest from monopolizing this executor thread.
        tokio::task::consume_budget().await;
        loop {
            if self.end - self.start >= 4 {
                let hdr: [u8; 4] = self.buf[self.start..self.start + 4].try_into().unwrap();
                let len = u32::from_be_bytes(hdr) as usize;
                if len > MAX_FRAME {
                    bail!("frame length {len} exceeds {MAX_FRAME}");
                }
                if self.end - self.start >= 4 + len {
                    let frame = (self.start + 4, self.start + 4 + len);
                    self.start += 4 + len;
                    return Ok(Some(frame));
                }
            }
            // Keep a whole frame's worth of tail free, so the next read can complete the
            // frame in one go however little of it arrived.
            if self.buf.len() - self.end < MAX_FRAME + 4 {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            match rd
                .read(&mut self.buf[self.end..])
                .await
                .context("read frame")?
            {
                0 if self.end == self.start => return Ok(None),
                0 => bail!("truncated frame"),
                n => self.end += n,
            }
        }
    }
}

/// Answer an ARP request for the gateway address; ignore everything else.
fn arp_reply(frame: &[u8], cfg: &Cfg) -> Option<Vec<u8>> {
    let a = frame.get(14..14 + 28)?;
    if a[0..2] != [0, 1] || a[2..4] != [0x08, 0x00] || a[4] != 6 || a[5] != 4 {
        return None;
    }
    if u16::from_be_bytes([a[6], a[7]]) != 1 {
        return None; // not a request
    }
    let sender_mac = &a[8..14];
    let sender_ip = &a[14..18];
    if a[24..28] != cfg.gateway.octets() {
        return None; // only proxy-ARP for the gateway itself
    }
    let mut out = Vec::with_capacity(42);
    out.extend_from_slice(sender_mac); // eth dst = requester
    out.extend_from_slice(&GW_MAC); // eth src = gateway
    out.extend_from_slice(&[0x08, 0x06]); // ethertype ARP
    out.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 2]); // reply
    out.extend_from_slice(&GW_MAC);
    out.extend_from_slice(&cfg.gateway.octets());
    out.extend_from_slice(sender_mac);
    out.extend_from_slice(sender_ip);
    Some(out)
}

/// True if this IPv4 payload is a UDP datagram to the DHCP server port.
fn is_dhcp(ip: &[u8]) -> bool {
    if ip.len() < 20 || (ip[0] >> 4) != 4 {
        return false;
    }
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    ip[9] == 17
        && ip.len() >= ihl + 8
        && u16::from_be_bytes([ip[ihl + 2], ip[ihl + 3]]) == DHCP_SERVER_PORT
}

fn ipv4_src(ip: &[u8]) -> Option<Ipv4Addr> {
    (ip.len() >= 20 && (ip[0] >> 4) == 4).then(|| Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]))
}

fn ipv4_dst(ip: &[u8]) -> Option<Ipv4Addr> {
    (ip.len() >= 20 && (ip[0] >> 4) == 4).then(|| Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]))
}

/// Build a DHCP OFFER/ACK granting `lease` to `client_mac`.
fn dhcp_reply(ip: &[u8], client_mac: Mac, cfg: &Cfg, lease: Ipv4Addr) -> Option<Vec<u8>> {
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    let req = ip.get(ihl + 8..)?; // UDP payload = the DHCP message
    if req.len() < 240 || req[0] != 1 || req[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let xid = &req[4..8];
    let reply_type = match dhcp_option(&req[240..], 53)?.first()? {
        1 => 2, // DISCOVER -> OFFER
        3 => 5, // REQUEST  -> ACK
        _ => return None,
    };

    let mut p = vec![0u8; 240];
    p[0] = 2; // BOOTREPLY
    p[1] = 1; // ethernet
    p[2] = 6;
    p[4..8].copy_from_slice(xid);
    p[16..20].copy_from_slice(&lease.octets()); // yiaddr
    p[20..24].copy_from_slice(&cfg.gateway.octets()); // siaddr
    p[28..34].copy_from_slice(&client_mac);
    p[236..240].copy_from_slice(&[99, 130, 83, 99]); // magic cookie

    let gw = cfg.gateway.octets();
    let opt = |p: &mut Vec<u8>, code: u8, val: &[u8]| {
        p.push(code);
        p.push(val.len() as u8);
        p.extend_from_slice(val);
    };
    opt(&mut p, 53, &[reply_type]);
    opt(&mut p, 54, &gw); // server id
    opt(&mut p, 51, &DHCP_LEASE_SECS.to_be_bytes());
    opt(&mut p, 1, &netmask(cfg.prefix));
    opt(&mut p, 3, &gw); // router
    opt(&mut p, 6, &gw); // DNS = the gateway's own resolver
    p.push(255);

    let builder = etherparse::PacketBuilder::ethernet2(GW_MAC, client_mac)
        .ipv4(cfg.gateway.octets(), [255, 255, 255, 255], 64)
        .udp(67, 68);
    let mut out = Vec::with_capacity(builder.size(p.len()));
    builder.write(&mut out, &p).ok()?;
    Some(out)
}

/// Find a DHCP option's value by code in the options area (TLV, 255 = end).
fn dhcp_option(opts: &[u8], code: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < opts.len() {
        match opts[i] {
            255 => break,
            0 => i += 1,
            c => {
                let len = *opts.get(i + 1)? as usize;
                let val = opts.get(i + 2..i + 2 + len)?;
                if c == code {
                    return Some(val);
                }
                i += 2 + len;
            }
        }
    }
    None
}

/// The address for `mac`: its run-assigned reservation if it has one, else a stable
/// per-MAC lease from the subnet pool (same MAC always gets the same IP). Reserved
/// IPs are skipped when advancing the pool so a non-reserved guest never collides
/// with a reserved address.
fn alloc_lease(inner: &mut Inner, cfg: &Cfg, mac: Mac) -> Option<Ipv4Addr> {
    if let Some(ip) = inner.reservations.get(&mac).copied() {
        inner.leases.insert(mac, ip);
        return Some(ip);
    }
    if let Some(ip) = inner.leases.get(&mac).copied() {
        return Some(ip);
    }
    let ip = loop {
        let ip = nth_host(cfg.gateway, cfg.prefix, inner.next_idx).ok()?;
        inner.next_idx += 1;
        if !inner.reservations.values().any(|r| *r == ip) {
            break ip;
        }
    };
    inner.leases.insert(mac, ip);
    Some(ip)
}

fn netmask(prefix: u8) -> [u8; 4] {
    let bits = if prefix >= 32 {
        !0u32
    } else {
        !0u32 << (32 - prefix)
    };
    bits.to_be_bytes()
}

/// The nth host address in the gateway's subnet (index 0 = network).
fn nth_host(gateway: Ipv4Addr, prefix: u8, index: u32) -> Result<Ipv4Addr> {
    let mask = u32::from_be_bytes(netmask(prefix));
    let network = u32::from(gateway) & mask;
    let addr = network | (index & !mask);
    if addr == network {
        bail!("host index {index} is the network address");
    }
    let broadcast = network | !mask;
    if addr == broadcast {
        bail!("host index {index} is the broadcast address");
    }
    Ok(Ipv4Addr::from(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The IP packet inside a frame `ChannelDevice` handed on, past the ethernet header it
    /// reserves for `route_in`.
    fn reply_ip(frame: &[u8]) -> &[u8] {
        &frame[ETH_HDR..]
    }

    #[test]
    fn log_tail_shows_the_last_lines_and_nothing_when_there_are_none() {
        let dir = std::env::temp_dir().join(format!("vk-switch-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("switch.log");
        assert_eq!(
            log_tail(&log, 5),
            "",
            "a log that is not there adds nothing"
        );
        std::fs::write(&log, "  \n\n").unwrap();
        assert_eq!(log_tail(&log, 5), "", "blank lines are nothing to show");
        std::fs::write(&log, "one\n\n  two  \nthree\nfour\n").unwrap();
        assert_eq!(log_tail(&log, 2), "\nthree\nfour");
        assert_eq!(log_tail(&log, 9), "\none\ntwo\nthree\nfour");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// One integer socket option, for checking what `detect_dead_peer` set.
    fn sock_opt(sock: &TcpStream, level: libc::c_int, name: libc::c_int) -> libc::c_int {
        use std::os::fd::AsRawFd;
        let mut value: libc::c_int = -1;
        let mut len = size_of::<libc::c_int>() as libc::socklen_t;
        // SAFETY: every option read here is one int, and both out-parameters are live.
        let rc = unsafe {
            libc::getsockopt(
                sock.as_raw_fd(),
                level,
                name,
                std::ptr::from_mut(&mut value).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "getsockopt: {}", std::io::Error::last_os_error());
        value
    }

    #[tokio::test]
    async fn an_upstream_socket_carries_the_dead_peer_options() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let accepted = tokio::spawn(async move { listener.accept().await });
        let sock = connect_egress(target, CONNECT_TIMEOUT).await.unwrap();
        accepted.await.unwrap().unwrap();

        assert_eq!(sock_opt(&sock, libc::SOL_SOCKET, libc::SO_KEEPALIVE), 1);
        let tcp = libc::IPPROTO_TCP;
        assert_eq!(sock_opt(&sock, tcp, libc::TCP_KEEPIDLE), KEEPALIVE_IDLE);
        assert_eq!(
            sock_opt(&sock, tcp, libc::TCP_KEEPINTVL),
            KEEPALIVE_INTERVAL
        );
        assert_eq!(sock_opt(&sock, tcp, libc::TCP_KEEPCNT), KEEPALIVE_PROBES);
    }

    #[test]
    fn log_line_names_the_level_and_the_reporting_module() {
        let line = log_line(
            log::Level::Warn,
            "ipstack::stream::tcp",
            &format_args!("reset"),
        );
        assert_eq!(line, "switch: warn ipstack::stream::tcp: reset");
    }

    #[tokio::test]
    async fn tcp_handshake_advertises_mss_and_negotiates_window_scaling() {
        use etherparse::{PacketBuilder, PacketHeaders, TcpOptionElement, TransportHeader};
        use tokio::time::timeout;

        for scaling in [false, true] {
            let (tx, rx) = unbounded_channel();
            let (reply_tx, mut replies) = unbounded_channel();
            let mut stack = IpStack::new(ip_stack_config(), ChannelDevice { rx, tx: reply_tx });
            let guest = [192, 168, 127, 2];
            let remote = [10, 0, 0, 1];
            let mut syn = Vec::new();
            let options = if scaling {
                vec![TcpOptionElement::WindowScale(7)]
            } else {
                Vec::new()
            };
            PacketBuilder::ipv4(guest, remote, 64)
                .tcp(40000, 443, 1000, 64240)
                .syn()
                .options(&options)
                .unwrap()
                .write(&mut syn, &[])
                .unwrap();
            tx.send(syn).unwrap();

            let reply = timeout(Duration::from_secs(2), replies.recv())
                .await
                .unwrap()
                .unwrap();
            let Some(TransportHeader::Tcp(synack)) = PacketHeaders::from_ip_slice(reply_ip(&reply))
                .unwrap()
                .transport
            else {
                panic!("expected a TCP SYN-ACK");
            };
            assert!(synack.syn && synack.ack);
            assert_eq!(synack.window_size, u16::MAX);
            assert_eq!(synack.acknowledgment_number, 1001);
            let mut expected = vec![TcpOptionElement::MaximumSegmentSize(MSS)];
            if scaling {
                expected.push(TcpOptionElement::WindowScale(7));
            }
            assert_eq!(
                synack
                    .options_iterator()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                expected
            );

            let mut ack = Vec::new();
            PacketBuilder::ipv4(guest, remote, 64)
                .tcp(40000, 443, 1001, 64240)
                .ack(synack.sequence_number.wrapping_add(1))
                .write(&mut ack, &[])
                .unwrap();
            tx.send(ack).unwrap();
            let IpStackStream::Tcp(mut stream) = timeout(Duration::from_secs(2), stack.accept())
                .await
                .unwrap()
                .unwrap()
            else {
                panic!("expected a TCP stream");
            };
            timeout(Duration::from_secs(2), stream.write_all(b"reply"))
                .await
                .unwrap()
                .unwrap();
            let reply = timeout(Duration::from_secs(2), replies.recv())
                .await
                .unwrap()
                .unwrap();
            let Some(TransportHeader::Tcp(data)) = PacketHeaders::from_ip_slice(reply_ip(&reply))
                .unwrap()
                .transport
            else {
                panic!("expected TCP data");
            };
            assert!(data.ack && !data.syn);
            assert!(data.options.is_empty());
            assert_eq!(
                data.window_size as usize,
                if scaling {
                    TCP_WINDOW >> 7
                } else {
                    u16::MAX as usize
                }
            );
        }
    }

    #[tokio::test]
    async fn a_download_can_reach_the_guest_in_packets_larger_than_8k() {
        use etherparse::{PacketBuilder, PacketHeaders, TcpOptionElement, TransportHeader};
        use tokio::time::timeout;

        timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let guest = [192, 168, 127, 2];
            let remote = [10, 0, 0, 1];
            let (tx, rx) = unbounded_channel();
            let (reply_tx, mut replies) = unbounded_channel();
            let mut stack = IpStack::new(ip_stack_config(), ChannelDevice { rx, tx: reply_tx });
            let mut syn = Vec::new();
            PacketBuilder::ipv4(guest, remote, 64)
                .tcp(40000, 443, 1000, u16::MAX)
                .syn()
                // Without an MSS offer the stack uses 536-byte segments.
                .options(&[TcpOptionElement::MaximumSegmentSize(MSS)])
                .unwrap()
                .write(&mut syn, &[])
                .unwrap();
            tx.send(syn).unwrap();
            let reply = replies.recv().await.unwrap();
            let Some(TransportHeader::Tcp(synack)) = PacketHeaders::from_ip_slice(reply_ip(&reply))
                .unwrap()
                .transport
            else {
                panic!("expected SYN-ACK");
            };
            let mut ack = Vec::new();
            PacketBuilder::ipv4(guest, remote, 64)
                .tcp(40000, 443, 1001, u16::MAX)
                .ack(synack.sequence_number.wrapping_add(1))
                .write(&mut ack, &[])
                .unwrap();
            tx.send(ack).unwrap();
            let IpStackStream::Tcp(stream) = stack.accept().await.unwrap() else {
                panic!("expected TCP stream");
            };
            let guard = EgressGuard::new(Egress::AllowAll, Ipv4Addr::new(192, 168, 127, 1))
                .with_registry_proxy(Some((remote.into(), listener.local_addr().unwrap())));
            // Poll the proxy together with the peer so it is dropped even on a timeout.
            let (drain, _drained) = Drain::new();
            let proxy = proxy_tcp(stream, Arc::new(guard), drain);
            let receive = async {
                let (mut host, _) = listener.accept().await.unwrap();
                let payload = vec![0x5a; 32 * 1024];
                host.write_all(&payload).await.unwrap();
                let mut received = Vec::new();
                let mut sizes = Vec::new();
                while received.len() < payload.len() {
                    let packet = replies.recv().await.unwrap();
                    let headers = PacketHeaders::from_ip_slice(reply_ip(&packet)).unwrap();
                    let bytes = headers.payload.slice();
                    if !bytes.is_empty() {
                        received.extend_from_slice(bytes);
                        sizes.push(bytes.len());
                    }
                }
                assert_eq!(received, payload);
                assert!(sizes.iter().any(|&n| n > 8192), "payload sizes: {sizes:?}");
                assert!(sizes.iter().all(|&n| n <= usize::from(MSS)));
                eprintln!("32 KiB loopback download TCP payload sizes: {sizes:?}");
            };
            tokio::select! {
                () = proxy => panic!("proxy closed before delivering the download"),
                () = receive => {},
            }
        })
        .await
        .unwrap();
    }

    /// A guest that closes its half the moment it has written everything leaves the flow
    /// holding the tail of the upload. Every byte of it still has to reach the host.
    #[tokio::test]
    async fn an_upload_the_guest_closes_reaches_the_host_whole() {
        use etherparse::{PacketBuilder, PacketHeaders, TcpOptionElement, TransportHeader};
        use std::os::fd::AsRawFd;
        use tokio::io::AsyncReadExt;
        use tokio::time::timeout;

        /// More than the flow hands the host in one turn, so the close lands with the tail
        /// of the upload still queued behind it.
        const TOTAL: usize = 256 << 10;
        /// What an MTU-1500 guest puts in a segment.
        const SEGMENT: usize = 1460;

        timeout(Duration::from_secs(30), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            // Use a small receive buffer to exercise backpressure.
            set_sock_opt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                4 << 10,
            )
            .unwrap();
            let guest = [192, 168, 127, 2];
            let remote = [10, 0, 0, 1];
            let (tx, rx) = unbounded_channel();
            let (reply_tx, mut replies) = unbounded_channel();
            let mut stack = IpStack::new(ip_stack_config(), ChannelDevice { rx, tx: reply_tx });
            let mut syn = Vec::new();
            PacketBuilder::ipv4(guest, remote, 64)
                .tcp(40000, 443, 1000, 64240)
                .syn()
                .options(&[TcpOptionElement::WindowScale(7)])
                .unwrap()
                .write(&mut syn, &[])
                .unwrap();
            tx.send(syn).unwrap();
            let reply = replies.recv().await.unwrap();
            let Some(TransportHeader::Tcp(synack)) = PacketHeaders::from_ip_slice(reply_ip(&reply))
                .unwrap()
                .transport
            else {
                panic!("expected SYN-ACK");
            };
            let gateway = synack.sequence_number.wrapping_add(1);
            let mut ack = Vec::new();
            PacketBuilder::ipv4(guest, remote, 64)
                .tcp(40000, 443, 1001, 64240)
                .ack(gateway)
                .write(&mut ack, &[])
                .unwrap();
            tx.send(ack).unwrap();
            let IpStackStream::Tcp(stream) = stack.accept().await.unwrap() else {
                panic!("expected TCP stream");
            };
            let guard = EgressGuard::new(Egress::AllowAll, Ipv4Addr::new(192, 168, 127, 1))
                .with_registry_proxy(Some((remote.into(), listener.local_addr().unwrap())));
            // Poll the proxy together with the peer so it is dropped even on a timeout.
            let (drain, _drained) = Drain::new();
            let proxy = proxy_tcp(stream, Arc::new(guard), drain);
            let receive = async {
                let (mut host, _) = listener.accept().await.unwrap();
                let payload = vec![0x5a; SEGMENT];
                let mut seq: u32 = 1001;
                let mut sent = 0;
                while sent < TOTAL {
                    let len = SEGMENT.min(TOTAL - sent);
                    let mut data = Vec::new();
                    PacketBuilder::ipv4(guest, remote, 64)
                        .tcp(40000, 443, seq, 64240)
                        .ack(gateway)
                        .write(&mut data, &payload[..len])
                        .unwrap();
                    tx.send(data).unwrap();
                    seq = seq.wrapping_add(len as u32);
                    sent += len;
                }
                // The guest is done writing and closes.
                let mut fin = Vec::new();
                PacketBuilder::ipv4(guest, remote, 64)
                    .tcp(40000, 443, seq, 64240)
                    .ack(gateway)
                    .fin()
                    .write(&mut fin, &[])
                    .unwrap();
                tx.send(fin).unwrap();
                let mut got = Vec::new();
                host.read_to_end(&mut got).await.unwrap();
                assert_eq!(got.len(), TOTAL, "the host received a truncated upload");
                assert!(
                    got.iter().all(|&byte| byte == 0x5a),
                    "the upload arrived corrupt"
                );
            };
            tokio::select! {
                () = proxy => panic!("the flow ended before the upload reached the host"),
                () = receive => {},
            }
        })
        .await
        .unwrap();
    }

    /// The addresses the drain tests' guest flow runs between.
    const FLOW_GUEST: [u8; 4] = [192, 168, 127, 2];
    const FLOW_REMOTE: [u8; 4] = [10, 0, 0, 1];

    /// A guest TCP flow through a real stack, handshake done, ready to be spliced. It keeps
    /// what the flow depends on alive — dropping the stack ends the flow, and dropping the
    /// reply channel breaks the stack's device — and drives the guest side of it.
    struct GuestFlow {
        _stack: IpStack,
        _replies: UnboundedReceiver<Vec<u8>>,
        /// Taken by the test and handed to the flow's proxy.
        stream: Option<ipstack::IpStackTcpStream>,
        tx: UnboundedSender<Vec<u8>>,
        /// Where the guest's stream is at, and what it acknowledges the gateway at.
        seq: u32,
        ack: u32,
    }

    impl GuestFlow {
        async fn open() -> Self {
            use etherparse::{PacketBuilder, PacketHeaders, TcpOptionElement, TransportHeader};
            let (tx, rx) = unbounded_channel();
            let (reply_tx, mut replies) = unbounded_channel();
            let mut stack = IpStack::new(ip_stack_config(), ChannelDevice { rx, tx: reply_tx });
            let mut syn = Vec::new();
            PacketBuilder::ipv4(FLOW_GUEST, FLOW_REMOTE, 64)
                .tcp(40000, 443, 1000, 64240)
                .syn()
                .options(&[TcpOptionElement::WindowScale(7)])
                .unwrap()
                .write(&mut syn, &[])
                .unwrap();
            tx.send(syn).unwrap();
            let reply = replies.recv().await.unwrap();
            let Some(TransportHeader::Tcp(synack)) = PacketHeaders::from_ip_slice(reply_ip(&reply))
                .unwrap()
                .transport
            else {
                panic!("expected SYN-ACK");
            };
            let ack = synack.sequence_number.wrapping_add(1);
            let mut handshake = Vec::new();
            PacketBuilder::ipv4(FLOW_GUEST, FLOW_REMOTE, 64)
                .tcp(40000, 443, 1001, 64240)
                .ack(ack)
                .write(&mut handshake, &[])
                .unwrap();
            tx.send(handshake).unwrap();
            let IpStackStream::Tcp(stream) = stack.accept().await.unwrap() else {
                panic!("expected TCP stream");
            };
            GuestFlow {
                _stack: stack,
                _replies: replies,
                stream: Some(stream),
                tx,
                seq: 1001,
                ack,
            }
        }

        /// One segment from the guest.
        fn send(&mut self, payload: &[u8]) {
            use etherparse::PacketBuilder;
            let mut data = Vec::new();
            PacketBuilder::ipv4(FLOW_GUEST, FLOW_REMOTE, 64)
                .tcp(40000, 443, self.seq, 64240)
                .ack(self.ack)
                .write(&mut data, payload)
                .unwrap();
            self.tx.send(data).unwrap();
            self.seq = self.seq.wrapping_add(payload.len() as u32);
        }

        /// The guest is done writing and closes its half.
        fn close(&mut self) {
            use etherparse::PacketBuilder;
            let mut fin = Vec::new();
            PacketBuilder::ipv4(FLOW_GUEST, FLOW_REMOTE, 64)
                .tcp(40000, 443, self.seq, 64240)
                .ack(self.ack)
                .fin()
                .write(&mut fin, &[])
                .unwrap();
            self.tx.send(fin).unwrap();
        }
    }

    /// The VM is torn down with the tail of its last upload still in the switch, and the
    /// switch is asked to stop while a slow host is taking it. Every byte still has to land.
    #[tokio::test]
    async fn a_drain_hands_the_host_the_tail_of_a_closed_upload() {
        use std::os::fd::AsRawFd;
        use tokio::time::timeout;

        /// Far more than the host end takes in one turn, so the switch is still holding most
        /// of the upload when the drain starts.
        const TOTAL: usize = 256 << 10;
        /// What an MTU-1500 guest puts in a segment.
        const SEGMENT: usize = 1460;
        /// What the host takes before the switch is asked to stop.
        const FIRST: usize = 4 << 10;

        timeout(Duration::from_secs(30), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            // A small receive buffer keeps enough of the upload in the switch to
            // exercise pending writes during shutdown.
            set_sock_opt(
                listener.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                4 << 10,
            )
            .unwrap();
            let mut flow = GuestFlow::open().await;
            let guard = EgressGuard::new(Egress::AllowAll, Ipv4Addr::new(192, 168, 127, 1))
                .with_registry_proxy(Some((FLOW_REMOTE.into(), listener.local_addr().unwrap())));
            let (drain, mut drained) = Drain::new();
            let proxy = tokio::spawn(proxy_tcp(
                flow.stream.take().unwrap(),
                Arc::new(guard),
                drain.clone(),
            ));
            let payload = vec![0x5a; SEGMENT];
            let mut sent = 0;
            while sent < TOTAL {
                let len = SEGMENT.min(TOTAL - sent);
                flow.send(&payload[..len]);
                sent += len;
            }
            // The guest has written everything and closed; its VM is then torn down and the
            // switch signalled, with the upload still crossing it.
            flow.close();
            let (mut host, _) = listener.accept().await.unwrap();
            let mut got = vec![0u8; FIRST];
            host.read_exact(&mut got).await.unwrap();
            drain.start();
            // A reply arrives after draining starts. It must be consumed even though
            // the guest cannot receive it, or closing the host socket resets the upload.
            host.write_all(&[0x42; 32 << 10]).await.unwrap();
            assert!(
                matches!(
                    drained.try_recv(),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                ),
                "the drain is not waiting for a flow that still owes the host"
            );
            // A receiver that takes its time still gets all of it, and the flow ends by
            // itself once it has handed the last byte over.
            let mut chunk = vec![0u8; 8 << 10];
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                let read = host.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                got.extend_from_slice(&chunk[..read]);
            }
            assert_eq!(got.len(), TOTAL, "the drained upload arrived short");
            assert!(
                got.iter().all(|&byte| byte == 0x5a),
                "the upload is corrupt"
            );
            host.shutdown().await.unwrap();
            proxy.await.unwrap();
            assert!(
                drained.recv().await.is_none(),
                "the drain is waiting on a flow that has ended"
            );
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_drain_waits_for_a_proxy_that_has_not_connected_yet() {
        use etherparse::{PacketHeaders, TransportHeader};

        tokio::time::timeout(Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut flow = GuestFlow::open().await;
            let guard = EgressGuard::new(Egress::AllowAll, Ipv4Addr::new(192, 168, 127, 1))
                .with_registry_proxy(Some((FLOW_REMOTE.into(), listener.local_addr().unwrap())));
            let (drain, mut drained) = Drain::new();
            // Keep the proxy unpolled until after shutdown starts. The stack can still
            // acknowledge the entire upload before its upstream connection is opened.
            let proxy = proxy_tcp(flow.stream.take().unwrap(), Arc::new(guard), drain.clone());
            flow.send(b"last upload");
            flow.close();
            loop {
                let reply = flow._replies.recv().await.unwrap();
                if let Some(TransportHeader::Tcp(header)) =
                    PacketHeaders::from_ip_slice(reply_ip(&reply))
                        .unwrap()
                        .transport
                    && header.acknowledgment_number == flow.seq.wrapping_add(1)
                {
                    break;
                }
            }
            drain.start();
            assert!(matches!(
                drained.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ));
            let peer = async {
                let (mut host, _) = listener.accept().await.unwrap();
                let mut got = Vec::new();
                host.read_to_end(&mut got).await.unwrap();
                assert_eq!(got, b"last upload");
                host.shutdown().await.unwrap();
            };
            tokio::join!(proxy, peer);
            assert!(drained.recv().await.is_none());
        })
        .await
        .unwrap();
    }

    /// A switch that owes nothing goes on the signal: the drain has nobody to wait for, and
    /// takes no flows on from there.
    #[tokio::test]
    async fn a_drain_with_no_flows_completes_at_once() {
        let (drain, mut drained) = Drain::new();
        drain.start();
        assert!(matches!(
            drained.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        assert!(
            drain.flow().is_none(),
            "a flow opened after the drain is refused"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_drain_settles_only_after_guest_bytes_stop_arriving() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (mut guest, mut guest_peer) = tokio::io::duplex(64);
            let (mut host, mut host_peer) = tokio::io::duplex(64);
            let (drain, _drained) = Drain::new();
            drain.start();
            let proxy =
                tokio::spawn(
                    async move { splice(&mut guest, &mut host, 64, 64, Some(&drain)).await },
                );
            for byte in 1..=3 {
                guest_peer.write_all(&[byte]).await.unwrap();
                let mut got = [0];
                host_peer.read_exact(&mut got).await.unwrap();
                assert_eq!(got, [byte]);
                // Each new handoff arrives before the idle interval, but the whole
                // transfer outlasts the first timer. Fully written bytes reset it too.
                tokio::time::advance(DRAIN_SETTLE * 3 / 4).await;
            }
            guest_peer.shutdown().await.unwrap();
            assert_eq!(host_peer.read(&mut [0]).await.unwrap(), 0);
            host_peer.shutdown().await.unwrap();
            proxy.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    /// An idle connection sends EOF after settling instead of waiting for the guest to
    /// close. A cooperating host then lets the drain finish before its deadline.
    #[tokio::test]
    async fn a_drain_does_not_wait_for_an_idle_flow() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut flow = GuestFlow::open().await;
            let guard = EgressGuard::new(Egress::AllowAll, Ipv4Addr::new(192, 168, 127, 1))
                .with_registry_proxy(Some((FLOW_REMOTE.into(), listener.local_addr().unwrap())));
            let (drain, _drained) = Drain::new();
            let proxy = tokio::spawn(proxy_tcp(
                flow.stream.take().unwrap(),
                Arc::new(guard),
                drain.clone(),
            ));
            let (mut host, _) = listener.accept().await.unwrap();
            // An idle peer closes its response stream once the proxy sends EOF.
            let peer = tokio::spawn(async move {
                assert_eq!(host.read(&mut [0; 1]).await.unwrap(), 0);
                host.shutdown().await.unwrap();
            });
            let start = Instant::now();
            drain.start();
            proxy.await.unwrap();
            peer.await.unwrap();
            assert!(
                start.elapsed() < DRAIN_DEADLINE * 4 / 5,
                "an idle flow held the drain for {:?}",
                start.elapsed()
            );
        })
        .await
        .unwrap();
    }

    #[test]
    fn tcp_syn_reject_builds_rst() {
        let guest = Ipv4Addr::new(192, 168, 231, 2);
        let denied = Ipv4Addr::new(10, 10, 140, 49);
        let client_mac: Mac = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
        let seq = 0x1234_5678u32;

        // A guest SYN opening 192.168.231.2:44444 -> 10.10.140.49:443.
        let mut syn_ip = Vec::new();
        etherparse::PacketBuilder::ipv4(guest.octets(), denied.octets(), 64)
            .tcp(44444, 443, seq, 64240)
            .syn()
            .write(&mut syn_ip, &[])
            .unwrap();

        // It parses as a pure SYN with the expected 5-tuple + seq.
        let parsed = parse_tcp_syn(&syn_ip).expect("pure SYN parses");
        assert_eq!(parsed.src, SocketAddrV4::new(guest, 44444));
        assert_eq!(parsed.dst, SocketAddrV4::new(denied, 443));
        assert_eq!(parsed.seq, seq);

        // The refusal frame: eth GW_MAC -> client_mac, carrying a RST+ACK from the
        // denied host:port back to the guest, seq=0, ack=SYN.seq+1.
        let frame = tcp_rst_frame(&parsed, client_mac).expect("rst frame built");
        assert_eq!(&frame[0..6], &client_mac); // eth dst = guest
        assert_eq!(&frame[6..12], &GW_MAC); // eth src = gateway
        assert_eq!(u16::from_be_bytes([frame[12], frame[13]]), ETHERTYPE_IPV4);

        let v4 = etherparse::Ipv4Slice::from_slice(&frame[14..]).unwrap();
        assert_eq!(v4.header().source_addr(), denied);
        assert_eq!(v4.header().destination_addr(), guest);
        let tcp = etherparse::TcpHeaderSlice::from_slice(v4.payload().payload).unwrap();
        assert_eq!(tcp.source_port(), 443);
        assert_eq!(tcp.destination_port(), 44444);
        assert!(tcp.rst(), "RST flag set");
        assert!(tcp.ack(), "ACK flag set");
        assert_eq!(tcp.sequence_number(), 0);
        assert_eq!(tcp.acknowledgment_number(), seq.wrapping_add(1));
    }

    #[test]
    fn tcp_syn_parse_ignores_non_opening_segments() {
        let a = Ipv4Addr::new(192, 168, 231, 2);
        let b = Ipv4Addr::new(10, 10, 140, 49);

        // A SYN-ACK (handshake reply) does not open a connection from the guest.
        let mut synack = Vec::new();
        etherparse::PacketBuilder::ipv4(a.octets(), b.octets(), 64)
            .tcp(44444, 443, 1, 64240)
            .syn()
            .ack(99)
            .write(&mut synack, &[])
            .unwrap();
        assert!(parse_tcp_syn(&synack).is_none(), "SYN-ACK is not rejected");

        // A plain ACK (mid-flow segment) is ignored.
        let mut ack = Vec::new();
        etherparse::PacketBuilder::ipv4(a.octets(), b.octets(), 64)
            .tcp(44444, 443, 2, 64240)
            .ack(100)
            .write(&mut ack, &[])
            .unwrap();
        assert!(
            parse_tcp_syn(&ack).is_none(),
            "mid-flow ACK is not rejected"
        );

        // A non-TCP (UDP) packet is ignored.
        let mut udp = Vec::new();
        etherparse::PacketBuilder::ipv4(a.octets(), b.octets(), 64)
            .udp(1000, 2000)
            .write(&mut udp, &[1, 2, 3])
            .unwrap();
        assert!(parse_tcp_syn(&udp).is_none(), "UDP is not a TCP SYN");
    }

    #[test]
    fn parse_tcp_syn_honors_ip_options() {
        let guest = Ipv4Addr::new(192, 168, 231, 2);
        let denied = Ipv4Addr::new(10, 10, 140, 49);

        // A pure SYN, then splice 4 bytes of IPv4 options (NOPs) after the fixed
        // 20-byte header: IHL 5 -> 6 and total length += 4. parse_tcp_syn must
        // locate the TCP header via IHL, not a hardcoded 20-byte offset.
        let mut ip = Vec::new();
        etherparse::PacketBuilder::ipv4(guest.octets(), denied.octets(), 64)
            .tcp(44444, 443, 7, 64240)
            .syn()
            .write(&mut ip, &[])
            .unwrap();
        ip[0] = 0x46; // version 4, IHL 6 (24-byte header)
        let total = u16::from_be_bytes([ip[2], ip[3]]) + 4;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        ip.splice(20..20, [0x01, 0x01, 0x01, 0x01]); // 4 NOP option bytes

        let parsed = parse_tcp_syn(&ip).expect("SYN with IP options parses");
        assert_eq!(parsed.src, SocketAddrV4::new(guest, 44444));
        assert_eq!(parsed.dst, SocketAddrV4::new(denied, 443));
        assert_eq!(parsed.seq, 7);
    }

    #[test]
    fn reject_denied_syn_honors_policy() {
        let gw = Ipv4Addr::new(192, 168, 231, 1);
        let guest = Ipv4Addr::new(192, 168, 231, 2);
        let client_mac: Mac = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
        let sentinel = Ipv4Addr::new(10, 0, 0, 254);

        // Allow 10.20.0.0/16; redirect a sentinel flow to the registry proxy.
        let guard = EgressGuard::new(Egress::new(&["10.20.0.0/16".into()], &[]).unwrap(), gw)
            .with_registry_proxy(Some((sentinel, "127.0.0.1:9000".parse().unwrap())));

        let syn_to = |dst: Ipv4Addr| {
            let mut ip = Vec::new();
            etherparse::PacketBuilder::ipv4(guest.octets(), dst.octets(), 64)
                .tcp(44444, 443, 1, 64240)
                .syn()
                .write(&mut ip, &[])
                .unwrap();
            ip
        };

        // A denied dst is refused with a RST frame.
        assert!(
            guard
                .reject_denied_syn(&syn_to(Ipv4Addr::new(203, 0, 113, 5)), client_mac)
                .is_some(),
            "denied dst is refused with a RST"
        );
        // An allowed dst returns None, so the SYN egresses normally.
        assert!(
            guard
                .reject_denied_syn(&syn_to(Ipv4Addr::new(10, 20, 30, 40)), client_mac)
                .is_none(),
            "allowed dst egresses"
        );
        // The registry-proxy sentinel is exempt from the allowlist.
        assert!(
            guard
                .reject_denied_syn(&syn_to(sentinel), client_mac)
                .is_none(),
            "sentinel is exempt"
        );
    }

    #[test]
    fn dry_run_records_a_denied_syn_but_carries_it() {
        let gw = Ipv4Addr::new(192, 168, 231, 1);
        let guest = Ipv4Addr::new(192, 168, 231, 2);
        let client_mac: Mac = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
        let dir = std::env::temp_dir().join(format!("vk-dryrun-syn-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let denied = dir.join("egress-denied.log");
        let _ = std::fs::remove_file(&denied);

        // Restricted to 10.20.0.0/16, but dry-run: the verdict still computes, nothing blocks.
        let guard = EgressGuard::new(Egress::new(&["10.20.0.0/16".into()], &[]).unwrap(), gw)
            .with_denied_log(Some(denied.clone()))
            .with_enforce(false);

        let syn_to = |dst: Ipv4Addr| {
            let mut ip = Vec::new();
            etherparse::PacketBuilder::ipv4(guest.octets(), dst.octets(), 64)
                .tcp(44444, 443, 1, 64240)
                .syn()
                .write(&mut ip, &[])
                .unwrap();
            ip
        };

        // A dst the allowlist denies is carried (no RST) — but recorded as a would-be denial.
        let denied_dst = Ipv4Addr::new(93, 184, 216, 34);
        assert!(
            guard
                .reject_denied_syn(&syn_to(denied_dst), client_mac)
                .is_none(),
            "dry-run carries a denied SYN instead of RSTing it"
        );
        let (recorded, _) = crate::egress_report::read_since(&denied, 0);
        assert_eq!(
            recorded,
            vec![crate::egress_report::Denial {
                proto: crate::egress_report::Proto::Tcp,
                target: format!("{denied_dst}:443"),
            }],
            "the would-be denial is recorded even in dry-run"
        );

        // An unroutable dst is not a policy call: it still gets a RST, dry-run or not.
        assert!(
            guard
                .reject_denied_syn(&syn_to(Ipv4Addr::new(203, 0, 113, 5)), client_mac)
                .is_some(),
            "an unroutable dst is RST even in dry-run"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unroutable_covers_reserved_space_but_not_the_lan() {
        let u = |s: &str| unroutable(s.parse().unwrap());
        // RFC 5737 documentation ranges — what a test dials when it wants nowhere.
        assert!(u("192.0.2.1"));
        assert!(u("198.51.100.1"));
        assert!(u("203.0.113.1"));
        assert!(u("0.0.0.0"));
        assert!(u("127.0.0.1"));
        assert!(u("169.254.1.1"));
        assert!(u("224.0.0.1"));
        assert!(u("255.255.255.255"));
        // The LAN and the internet must keep working: a guest reaching either is the point.
        assert!(!u("10.1.2.3"));
        assert!(!u("192.168.1.254"));
        assert!(!u("172.16.0.1"));
        assert!(!u("1.1.1.1"));
    }

    #[tokio::test]
    async fn connect_egress_never_hangs_on_unreachable() {
        // 192.0.2.1 is TEST-NET-1 (RFC 5737): guaranteed unroutable, so the dial either
        // black-holes (our timeout bounds it) or fails fast with a routing error. Either
        // way connect_egress must return an error well within the OS default connect
        // timeout — this is the fail-fast that stops a dead backend hanging the guest.
        let target: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let start = Instant::now();
        let res = connect_egress(target, Duration::from_millis(300)).await;
        assert!(res.is_err(), "unreachable dial must error, not connect");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "dial must fail fast, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn mac_roundtrip() {
        assert_eq!(
            parse_mac("52:54:00:d2:f0:01"),
            Some([0x52, 0x54, 0x00, 0xd2, 0xf0, 0x01])
        );
        assert_eq!(
            parse_mac("aa:bb:cc:dd:ee:ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn mac_rejects_malformed() {
        assert_eq!(parse_mac("52:54:00:d2:f0"), None); // too few
        assert_eq!(parse_mac("52:54:00:d2:f0:01:02"), None); // too many
        assert_eq!(parse_mac("52:54:00:zz:f0:01"), None); // non-hex
    }

    #[test]
    fn egress_allowlist() {
        let e = Egress::new(
            &["10.0.0.0/8".into(), "192.168.231.1/32".into()],
            &["corp.example.com".into(), ".github.com".into()],
        )
        .unwrap();
        // direct-egress IP allowlist (unscoped rules => any port)
        assert!(e.allows_ip("10.1.2.3".parse().unwrap(), 443));
        assert!(e.allows_ip("192.168.231.1".parse().unwrap(), 22));
        assert!(!e.allows_ip("8.8.8.8".parse().unwrap(), 443));
        assert!(!e.allows_ip("::1".parse().unwrap(), 443)); // v6 denied under an allowlist
        // proxy host allowlist (suffix-anchored)
        assert!(e.allows_host("gitlab.corp.example.com"));
        assert!(e.allows_host("corp.example.com"));
        assert!(e.allows_host("api.github.com"));
        assert!(!e.allows_host("evil.com"));
        assert!(!e.allows_host("corp.example.com.evil.com")); // not a real suffix match
        // no rules => allow all (the dev default)
        assert!(matches!(Egress::new(&[], &[]).unwrap(), Egress::AllowAll));
        let any = Egress::default();
        assert!(any.allows_ip("8.8.8.8".parse().unwrap(), 443) && any.allows_host("evil.com"));
    }

    #[test]
    fn restricted_empty_denies_everything() {
        // `restricted` never collapses to AllowAll — an empty allowlist is deny-all,
        // unlike `new` (the dev default) which treats empty as unrestricted.
        let deny = Egress::restricted(&[], &[]).unwrap();
        assert!(matches!(deny, Egress::Allow { .. }));
        assert!(!deny.allows_host("anything.com"));
        assert!(!deny.allows_ip("8.8.8.8".parse().unwrap(), 443));
    }

    #[test]
    fn contains_cidr_subset_check() {
        let cap =
            Egress::restricted(&["10.0.0.0/8".into(), "192.168.0.0/16:443".into()], &[]).unwrap();
        // subset of an unscoped cap rule
        assert!(cap.contains_cidr("10.1.2.0/24").unwrap());
        assert!(cap.contains_cidr("10.1.2.3/32").unwrap());
        // a superset (wider prefix) is not contained
        assert!(!cap.contains_cidr("10.0.0.0/4").unwrap());
        // a sibling range outside the cap
        assert!(!cap.contains_cidr("172.16.0.0/12").unwrap());
        // port must match a port-scoped cap rule
        assert!(cap.contains_cidr("192.168.1.0/24:443").unwrap());
        assert!(!cap.contains_cidr("192.168.1.0/24").unwrap()); // any-port request widens the cap
        assert!(!cap.contains_cidr("192.168.1.0/24:80").unwrap());
        // an empty allowlist contains nothing; AllowAll contains everything
        assert!(
            !Egress::restricted(&[], &[])
                .unwrap()
                .contains_cidr("10.0.0.0/8")
                .unwrap()
        );
        assert!(Egress::AllowAll.contains_cidr("8.8.8.8/32").unwrap());
    }

    #[test]
    fn egress_ip_port_scoping() {
        // a port-scoped rule alongside an any-port rule
        let e = Egress::new(&["10.0.0.0/8:443".into(), "192.168.0.0/16".into()], &[]).unwrap();
        // port-scoped: only 443 to 10/8
        assert!(e.allows_ip("10.1.2.3".parse().unwrap(), 443));
        assert!(!e.allows_ip("10.1.2.3".parse().unwrap(), 22));
        // unscoped: any port to 192.168/16
        assert!(e.allows_ip("192.168.5.5".parse().unwrap(), 22));
        assert!(e.allows_ip("192.168.5.5".parse().unwrap(), 443));
        // a bare host with a port (implied /32)
        let h = Egress::new(&["1.2.3.4:5432".into()], &[]).unwrap();
        assert!(h.allows_ip("1.2.3.4".parse().unwrap(), 5432));
        assert!(!h.allows_ip("1.2.3.4".parse().unwrap(), 5433));
        // a bad port is rejected at parse time
        assert!(Egress::new(&["1.2.3.4:notaport".into()], &[]).is_err());
    }

    #[test]
    fn parse_a_records_extracts_ips_and_ttl() {
        // header (qd=1, an=1) + question (a. A IN) + answer (A IN ttl=300 -> the IP)
        let msg: Vec<u8> = vec![
            0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, // header
            1, b'a', 0, 0, 1, 0, 1, // question "a" A IN
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34, // answer
        ];
        let (ips, ttl) = parse_a_records(&msg);
        assert_eq!(ips, vec![Ipv4Addr::new(93, 184, 216, 34)]);
        assert_eq!(ttl, 300);
        assert!(parse_a_records(&[0u8; 12]).0.is_empty()); // no answers
    }

    #[test]
    fn egress_guard_pins_and_blocks() {
        let gw = Ipv4Addr::new(192, 168, 231, 1);
        let src = Ipv4Addr::new(192, 168, 231, 2);
        let g = EgressGuard::new(Egress::new(&[], &["corp.example.com".into()]).unwrap(), gw);
        let corp: SocketAddr = "10.20.30.40:443".parse().unwrap();
        assert!(!g.allows(src, corp)); // not resolved yet
        g.record(src, &[Ipv4Addr::new(10, 20, 30, 40)], 300); // resolver pinned it for this src
        assert!(g.allows(src, corp)); // now allowed
        assert!(!g.allows(src, "8.8.8.8:443".parse().unwrap())); // unrelated dst
        assert!(!g.allows(src, "8.8.8.8:53".parse().unwrap())); // DNS forced through the switch
        // a different source does NOT inherit src's pin (per-source isolation)
        let other = Ipv4Addr::new(192, 168, 231, 3);
        assert!(!g.allows(other, corp));
        // unrestricted guard allows anything
        let any = EgressGuard::new(Egress::AllowAll, gw);
        assert!(any.allows(src, "8.8.8.8:443".parse().unwrap()));
        assert!(any.allows(src, "8.8.8.8:53".parse().unwrap()));
    }

    #[test]
    fn egress_guard_per_source_override() {
        let gw = Ipv4Addr::new(192, 168, 231, 1);
        // Default policy allows corp.example.com; a service source is pinned to deny-all.
        let db = Ipv4Addr::new(192, 168, 231, 5);
        let mut per = HashMap::new();
        per.insert(db, Egress::restricted(&[], &[]).unwrap());
        let g = EgressGuard::new(Egress::new(&["10.0.0.0/8".into()], &[]).unwrap(), gw)
            .with_per_source(per);
        let primary = Ipv4Addr::new(192, 168, 231, 2);
        // The default source may reach the allowlisted CIDR; the overridden service may not.
        assert!(g.allows(primary, "10.1.2.3:443".parse().unwrap()));
        assert!(!g.allows(db, "10.1.2.3:443".parse().unwrap()));
        // The DB's deny-all policy refuses every name at the resolver, so it never resolves
        // (and thus never pins) an external host — no egress at all.
        assert!(!g.name_allowed(db, "example.com"));
    }

    #[test]
    fn audit_ip_contacts_dedup_resolved_per_source() {
        let dir = std::env::temp_dir().join(format!("vk-switch-audit-ip-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("egress-audit.log");
        let _ = std::fs::remove_file(&path);

        let gw = Ipv4Addr::new(192, 168, 231, 1);
        let vm_a = Ipv4Addr::new(192, 168, 231, 2);
        let vm_b = Ipv4Addr::new(192, 168, 231, 3);
        let resolved = Ipv4Addr::new(93, 184, 216, 34);
        let direct = Ipv4Addr::new(1, 1, 1, 1);
        // Audit runs even under AllowAll — nothing is pinned, yet contacts are still recorded.
        let g = EgressGuard::new(Egress::AllowAll, gw).with_audit_log(Some(path.clone()));

        // vm_a resolved `resolved` through the switch, then dials it: already attributed to the
        // name in the domains summary, so it is NOT re-logged as a direct-IP contact.
        g.record_dns_ips(vm_a, &[resolved]);
        g.record_ip_contact(vm_a, SocketAddrV4::new(resolved, 443));
        // vm_a dials an IP it never resolved: a genuine direct-IP contact, logged.
        g.record_ip_contact(vm_a, SocketAddrV4::new(direct, 443));
        // vm_b never resolved `resolved`, so vm_a's resolution must not mask vm_b's direct dial
        // to the same IP — the per-source key keeps them distinct.
        g.record_ip_contact(vm_b, SocketAddrV4::new(resolved, 8080));

        // Only the two genuine direct dials survive; the resolved-then-dialed one is suppressed.
        assert_eq!(
            crate::egress_report::read_ip_contacts(&path),
            vec![("1.1.1.1:443".into(), 1), ("93.184.216.34:8080".into(), 1),]
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Audit off: both record entry points are silent no-ops (no channel to write to).
        let off = dir.join("never-written.log");
        let g = EgressGuard::new(Egress::AllowAll, gw);
        g.record_dns_ips(vm_a, &[resolved]);
        g.record_ip_contact(vm_a, SocketAddrV4::new(direct, 443));
        assert!(!off.exists());
    }

    #[test]
    fn netmask_and_host() {
        assert_eq!(netmask(24), [255, 255, 255, 0]);
        assert_eq!(
            nth_host(Ipv4Addr::new(192, 168, 127, 1), 24, 2).unwrap(),
            Ipv4Addr::new(192, 168, 127, 2)
        );
        assert_eq!(
            nth_host(Ipv4Addr::new(192, 168, 127, 1), 24, 3).unwrap(),
            Ipv4Addr::new(192, 168, 127, 3)
        );
    }

    fn arp_request_for(target: [u8; 4], sender_mac: Mac, sender_ip: [u8; 4]) -> Vec<u8> {
        let mut f = vec![0xff; 6];
        f.extend_from_slice(&sender_mac);
        f.extend_from_slice(&[0x08, 0x06]);
        f.extend_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
        f.extend_from_slice(&sender_mac);
        f.extend_from_slice(&sender_ip);
        f.extend_from_slice(&[0; 6]);
        f.extend_from_slice(&target);
        f
    }

    #[test]
    fn arp_answers_only_for_the_gateway() {
        let cfg = Cfg {
            gateway: Ipv4Addr::new(192, 168, 127, 1),
            prefix: 24,
        };
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let reply = arp_reply(
            &arp_request_for([192, 168, 127, 1], mac, [192, 168, 127, 2]),
            &cfg,
        )
        .expect("gateway arp");
        assert_eq!(&reply[0..6], &mac); // to requester
        assert_eq!(&reply[6..12], &GW_MAC);
        assert_eq!(reply[21], 2); // reply
        // ARP for another VM is not answered by the gateway (it floods instead).
        assert!(
            arp_reply(
                &arp_request_for([192, 168, 127, 3], mac, [192, 168, 127, 2]),
                &cfg
            )
            .is_none()
        );
    }

    fn eth(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + payload.len());
        f.extend_from_slice(&dst);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// A minimal 20-byte IPv4-header stand-in with `src` at bytes 12..16 (where `ipv4_src`
    /// reads it), plus an optional tail — enough for the switch's source-based handling.
    fn ipv4_payload(src: Ipv4Addr, tail: &[u8]) -> Vec<u8> {
        let mut p = vec![0x45u8; 20];
        p[12..16].copy_from_slice(&src.octets());
        p.extend_from_slice(tail);
        p
    }

    /// A stream that yields one byte per read, so a frame is split across as many reads
    /// as it has bytes.
    struct Trickle {
        data: Vec<u8>,
        pos: usize,
    }

    impl AsyncRead for Trickle {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut TaskCtx<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let me = self.get_mut();
            if me.pos < me.data.len() && buf.remaining() > 0 {
                buf.put_slice(&me.data[me.pos..me.pos + 1]);
                me.pos += 1;
            }
            Poll::Ready(Ok(()))
        }
    }

    fn framed(frames: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        for f in frames {
            out.extend_from_slice(&(f.len() as u32).to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    /// The reader hands frames out one at a time however the stream is chopped up: a
    /// whole burst arriving in one read, or a frame dribbling in a byte at a time.
    #[tokio::test]
    async fn frame_reader_is_indifferent_to_how_the_stream_is_chopped_up() {
        let frames: [&[u8]; 3] = [b"one", b"a longer second frame", b"three"];

        let (mut w, mut r) = tokio::io::duplex(64 * 1024);
        w.write_all(&framed(&frames)).await.unwrap();
        let mut burst = FrameReader::new();
        for expect in frames {
            let (a, b) = burst.next(&mut r).await.unwrap().unwrap();
            assert_eq!(&burst.buf[a..b], expect);
        }

        let mut trickle = Trickle {
            data: framed(&frames),
            pos: 0,
        };
        let mut split = FrameReader::new();
        for expect in frames {
            let (a, b) = split.next(&mut trickle).await.unwrap().unwrap();
            assert_eq!(&split.buf[a..b], expect);
        }
        // Drained, so the peer going away is a clean EOF rather than a truncated frame.
        assert!(split.next(&mut trickle).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn frame_reader_compacts_maximum_frames_and_accepts_empty_ones() {
        let large: Vec<u8> = (0..MAX_FRAME).map(|i| i as u8).collect();
        let frames = [
            large.as_slice(),
            &[],
            large.as_slice(),
            large.as_slice(),
            large.as_slice(),
            b"tail",
        ];
        let wire = framed(&frames);
        assert!(wire.len() > READ_BUF);
        let mut input = wire.as_slice();
        let mut reader = FrameReader::new();
        for expected in frames {
            let (a, b) = reader.next(&mut input).await.unwrap().unwrap();
            assert_eq!(&reader.buf[a..b], expected);
        }
        assert!(reader.next(&mut input).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn frame_reader_rejects_oversized_and_truncated_frames() {
        for size in [MAX_FRAME as u32 + 1, u32::MAX] {
            let header = size.to_be_bytes();
            let mut input = header.as_slice();
            let err = FrameReader::new().next(&mut input).await.unwrap_err();
            assert!(err.to_string().contains("exceeds"));
        }
        let wire = framed(&[b"payload"]);
        for end in 1..wire.len() {
            let mut input = &wire[..end];
            let err = FrameReader::new().next(&mut input).await.unwrap_err();
            assert!(err.to_string().contains("truncated"));
        }
        assert!(
            FrameReader::new()
                .next(&mut &b""[..])
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn buffered_frames_let_another_task_run() {
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let other = ran.clone();
        let task = tokio::spawn(async move { other.store(true, Ordering::SeqCst) });
        let wire = framed(&vec![b"small".as_slice(); 1024]);
        let mut input = wire.as_slice();
        let mut reader = FrameReader::new();
        for _ in 0..1024 {
            assert!(reader.next(&mut input).await.unwrap().is_some());
        }
        assert!(
            ran.load(Ordering::SeqCst),
            "buffered reads monopolized the executor"
        );
        task.await.unwrap();
    }

    enum WriteStep {
        Limit(usize),
        Pending,
        Error,
    }

    struct BatchWriter {
        writes: Vec<Vec<u8>>,
        max_write: usize,
        steps: std::collections::VecDeque<WriteStep>,
    }

    impl AsyncWrite for BatchWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut TaskCtx<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let n = buf.len().min(self.max_write);
            self.writes.push(buf[..n].to_vec());
            Poll::Ready(Ok(n))
        }
        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            cx: &mut TaskCtx<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            let max_write = match self.steps.pop_front() {
                Some(WriteStep::Pending) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Some(WriteStep::Error) => {
                    return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
                }
                Some(WriteStep::Limit(n)) => n,
                None => self.max_write,
            };
            let mut write = Vec::new();
            for buf in bufs {
                if write.len() >= max_write {
                    break;
                }
                let n = buf.len().min(max_write - write.len());
                write.extend_from_slice(&buf[..n]);
            }
            let n = write.len();
            self.writes.push(write);
            Poll::Ready(Ok(n))
        }
        fn is_write_vectored(&self) -> bool {
            true
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn writer_drains_closed_channels_in_bounded_batches_and_handles_short_writes() {
        let frames: Vec<Vec<u8>> = (0..WRITE_BATCH_FRAMES * 2 + 5)
            .map(|i| vec![i as u8; if i % 5 == 0 { MAX_FRAME } else { i % 14 }])
            .collect();
        let expected = framed(&frames.iter().map(Vec::as_slice).collect::<Vec<_>>());
        for max_write in [usize::MAX, 1024] {
            let (tx, rx) = unbounded_channel();
            for frame in &frames {
                tx.send(frame.clone()).unwrap();
            }
            drop(tx);
            let mut writer = BatchWriter {
                writes: Vec::new(),
                max_write,
                steps: Default::default(),
            };
            writer_task(&mut writer, rx).await;
            assert_eq!(writer.writes.concat(), expected);
            if max_write == usize::MAX {
                assert!(writer.writes.len() > 2);
                for batch in &writer.writes {
                    assert!(batch.len() <= WRITE_BATCH_BYTES);
                    let mut count = 0;
                    let mut rest = batch.as_slice();
                    while !rest.is_empty() {
                        let len = u32::from_be_bytes(rest[..4].try_into().unwrap()) as usize;
                        rest = &rest[4 + len..];
                        count += 1;
                    }
                    assert!(count <= WRITE_BATCH_FRAMES);
                }
            }
        }
    }

    #[tokio::test]
    async fn writer_limits_the_number_of_small_frames_per_batch() {
        let (tx, rx) = unbounded_channel();
        for _ in 0..WRITE_BATCH_FRAMES * 2 + 1 {
            tx.send(vec![0x5a]).unwrap();
        }
        drop(tx);
        let mut writer = BatchWriter {
            writes: Vec::new(),
            max_write: usize::MAX,
            steps: Default::default(),
        };
        writer_task(&mut writer, rx).await;
        assert_eq!(
            writer.writes.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![WRITE_BATCH_FRAMES * 5, WRITE_BATCH_FRAMES * 5, 5]
        );
    }

    #[tokio::test]
    async fn writer_resumes_partial_vectored_writes_past_an_empty_batch_tail() {
        let mut frames: Vec<&[u8]> = vec![b""; WRITE_BATCH_FRAMES];
        frames[1] = b"one";
        frames[2] = b"tail";
        // The next batch detects a writer mistaking the final frame's empty payload
        // for a closed socket after sending its header.
        frames.push(b"sentinel");
        let (tx, rx) = unbounded_channel();
        for frame in &frames {
            tx.send(frame.to_vec()).unwrap();
        }
        drop(tx);
        let mut writer = BatchWriter {
            writes: Vec::new(),
            max_write: usize::MAX,
            steps: [
                WriteStep::Limit(2),
                WriteStep::Pending,
                WriteStep::Limit(3),
                WriteStep::Pending,
                WriteStep::Limit(7),
            ]
            .into(),
        };
        tokio::time::timeout(Duration::from_secs(2), writer_task(&mut writer, rx))
            .await
            .unwrap();
        assert!(writer.steps.is_empty());
        assert_eq!(writer.writes.concat(), framed(&frames));
    }

    #[tokio::test]
    async fn writer_stops_on_zero_or_error_after_partial_vectored_progress() {
        for stop in [WriteStep::Limit(0), WriteStep::Error] {
            let (tx, rx) = unbounded_channel();
            tx.send(b"payload".to_vec()).unwrap();
            let mut writer = BatchWriter {
                writes: Vec::new(),
                max_write: usize::MAX,
                steps: [
                    WriteStep::Limit(2),
                    WriteStep::Pending,
                    stop,
                    WriteStep::Limit(usize::MAX),
                ]
                .into(),
            };
            tokio::time::timeout(Duration::from_secs(2), writer_task(&mut writer, rx))
                .await
                .unwrap();
            assert_eq!(writer.writes.concat(), framed(&[b"payload"])[..2]);
            assert_eq!(writer.steps.len(), 1, "polled again after zero or error");
            assert!(tx.is_closed(), "the failed port still accepts frames");
        }
    }

    #[tokio::test]
    async fn writer_sends_an_isolated_frame_without_waiting_for_a_full_batch() {
        let (writer, mut reader) = UnixStream::pair().unwrap();
        let (_, writer) = writer.into_split();
        let (tx, rx) = unbounded_channel();
        let task = tokio::spawn(writer_task(writer, rx));
        tx.send(b"one".to_vec()).unwrap();
        let mut bytes = [0; 7];
        tokio::time::timeout(Duration::from_secs(2), reader.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bytes.as_slice(), framed(&[b"one"]));
        drop(tx);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_reply_reaches_the_switch_with_its_ethernet_header_reserved() {
        let (_tx, rx) = unbounded_channel();
        let (reply_tx, mut replies) = unbounded_channel();
        let mut device = ChannelDevice { rx, tx: reply_tx };
        let mut packet = vec![0x45];
        packet.extend((1..40u8).map(|i| i * 3));
        device.write_all(&packet).await.unwrap();

        let mut frame = replies.recv().await.unwrap();
        assert_eq!(frame.len(), ETH_HDR + packet.len());
        assert_eq!(reply_ip(&frame), packet, "the packet is copied once, whole");

        let guest = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
        write_eth_header(&mut frame, guest);
        assert_eq!(&frame[0..6], guest);
        assert_eq!(&frame[6..12], GW_MAC);
        assert_eq!(&frame[12..14], ETHERTYPE_IPV4.to_be_bytes());
        assert_eq!(reply_ip(&frame), packet, "the payload is left alone");

        frame[ETH_HDR] = 0x60;
        write_eth_header(&mut frame, guest);
        assert_eq!(&frame[12..14], ETHERTYPE_IPV6.to_be_bytes());
    }

    #[test]
    fn the_frame_pool_hands_back_the_buffer_it_was_given() {
        let pool = FramePool {
            free: Mutex::new(Vec::new()),
        };
        let mut first = pool.take(POOL_BUF);
        assert!(first.capacity() >= POOL_BUF);
        first.extend_from_slice(b"spent");
        let address = first.as_ptr();
        pool.give(first);
        // A small packet must not take the jumbo buffer waiting in the pool.
        let mut small = pool.take(40);
        assert_eq!(small.capacity(), 40);
        small.extend_from_slice(&[0x45; 40]);
        let reused = pool.take(POOL_MIN);
        assert!(reused.is_empty(), "a buffer comes back ready to fill");
        assert_eq!(reused.as_ptr(), address, "and on the same allocation");
        pool.give(reused);
        pool.give(small);

        pool.give(Vec::with_capacity(8));
        assert_eq!(pool.free.lock().unwrap().len(), 1, "too small to keep");
        for _ in 0..POOL_FRAMES * 2 {
            pool.give(Vec::with_capacity(POOL_BUF));
        }
        assert_eq!(pool.free.lock().unwrap().len(), POOL_FRAMES);
    }

    /// A reader that fills whatever it is handed, `bursts` times, then stalls.
    struct Bursty {
        bursts: usize,
    }

    impl AsyncRead for Bursty {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut TaskCtx<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.bursts == 0 {
                return Poll::Pending;
            }
            self.bursts -= 1;
            let room = buf.remaining();
            buf.put_slice(&vec![0x5a; room]);
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn a_saturated_download_with_timestamps_has_no_tiny_tail_segments() {
        use etherparse::{PacketBuilder, PacketHeaders, TcpOptionElement, TransportHeader};
        use tokio::io::AsyncReadExt;

        tokio::time::timeout(Duration::from_secs(5), async {
            let (tx, rx) = unbounded_channel();
            let (reply_tx, mut replies) = unbounded_channel();
            let mut stack = IpStack::new(ip_stack_config(), ChannelDevice { rx, tx: reply_tx });
            let guest = [192, 168, 127, 2];
            let remote = [10, 0, 0, 1];
            let mut syn = Vec::new();
            PacketBuilder::ipv4(guest, remote, 64)
                .tcp(40000, 443, 1000, u16::MAX)
                .syn()
                .options(&[
                    TcpOptionElement::MaximumSegmentSize(MSS),
                    TcpOptionElement::WindowScale(7),
                    TcpOptionElement::Timestamp(7000, 0),
                ])
                .unwrap()
                .write(&mut syn, &[])
                .unwrap();
            tx.send(syn).unwrap();
            let reply = replies.recv().await.unwrap();
            let Some(TransportHeader::Tcp(synack)) = PacketHeaders::from_ip_slice(reply_ip(&reply))
                .unwrap()
                .transport
            else {
                panic!("expected SYN-ACK");
            };
            let timestamp = synack
                .options_iterator()
                .find_map(|option| match option.unwrap() {
                    TcpOptionElement::Timestamp(value, _) => Some(value),
                    _ => None,
                })
                .expect("timestamps were not negotiated");
            let mut ack = Vec::new();
            PacketBuilder::ipv4(guest, remote, 64)
                .tcp(40000, 443, 1001, u16::MAX)
                .ack(synack.sequence_number.wrapping_add(1))
                .options(&[TcpOptionElement::Timestamp(7000, timestamp)])
                .unwrap()
                .write(&mut ack, b"ready")
                .unwrap();
            tx.send(ack).unwrap();
            let IpStackStream::Tcp(mut stream) = stack.accept().await.unwrap() else {
                panic!("expected TCP stream");
            };
            // Reading the request confirms the ACK opened the scaled receive window.
            let mut request = [0; 5];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"ready");

            // Fill each buffer through its growth steps, then twice at the ceiling.
            let mut reader = Bursty { bursts: 5 };
            let mut copy = CopyBuffer::new(GUEST_BOUND_CHUNK);
            std::future::poll_fn(|cx| {
                assert!(
                    copy.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut stream))
                        .is_pending()
                );
                if reader.bursts == 0 && !copy.pending() {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;

            let full_segment = usize::from(MTU) - 20 - 32;
            let expected = [
                SPLICE_INIT,
                SPLICE_INIT * 2,
                SPLICE_INIT * 4,
                full_segment,
                full_segment,
            ];
            let mut sizes = Vec::new();
            let mut received = 0;
            while received < expected.iter().sum() {
                let packet = replies.recv().await.unwrap();
                let headers = PacketHeaders::from_ip_slice(reply_ip(&packet)).unwrap();
                let bytes = headers.payload.slice();
                if !bytes.is_empty() {
                    assert!(bytes.iter().all(|&byte| byte == 0x5a));
                    sizes.push(bytes.len());
                    received += bytes.len();
                }
            }
            assert_eq!(sizes, expected);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_spliced_direction_starts_small_and_grows_to_the_ceiling() {
        for (max, bursts) in [(GUEST_BOUND_CHUNK, 64), (HOST_BOUND_CHUNK, 8)] {
            let mut copy = CopyBuffer::new(max);
            assert!(copy.buf.is_empty(), "no buffer before the first poll");
            let mut reader = Bursty { bursts: 0 };
            let mut writer = tokio::io::sink();
            std::future::poll_fn(|cx| {
                assert!(
                    copy.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer))
                        .is_pending()
                );
                Poll::Ready(())
            })
            .await;
            assert_eq!(copy.buf.len(), SPLICE_INIT.min(max), "it starts small");

            reader.bursts = bursts;
            std::future::poll_fn(|cx| {
                assert!(
                    copy.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer))
                        .is_pending()
                );
                Poll::Ready(())
            })
            .await;
            assert_eq!(copy.buf.len(), max, "a bulk transfer reaches the ceiling");
        }
    }

    #[tokio::test]
    async fn a_spliced_flow_copies_both_ways_and_ends_once_both_sides_close() {
        tokio::time::timeout(Duration::from_secs(2), async {
            let (mut a, mut a_peer) = tokio::io::duplex(1024);
            // Queue enough input to grow the guest-bound buffer while its small
            // destination forces partial writes and backpressure.
            let (mut b, mut b_peer) = tokio::io::duplex(MSS as usize * 2);
            let spliced = tokio::spawn(async move {
                splice(&mut a, &mut b, HOST_BOUND_CHUNK, GUEST_BOUND_CHUNK, None).await
            });
            let request: Vec<u8> = (0..HOST_BOUND_CHUNK * 3 + 123)
                .map(|i| (i % 251) as u8)
                .collect();
            let mut received = Vec::new();
            let ((), read) = tokio::join!(
                async {
                    a_peer.write_all(&request).await.unwrap();
                    a_peer.shutdown().await.unwrap();
                },
                b_peer.read_to_end(&mut received)
            );
            read.unwrap();
            assert_eq!(received, request);

            // The first direction has reached EOF; the other must still carry a
            // reply larger than its maximum copy buffer without losing a byte.
            let reply: Vec<u8> = (0..MSS as usize * 3 + 321)
                .map(|i| (i % 239) as u8)
                .collect();
            received.clear();
            let ((), read) = tokio::join!(
                async {
                    b_peer.write_all(&reply).await.unwrap();
                    b_peer.shutdown().await.unwrap();
                },
                a_peer.read_to_end(&mut received)
            );
            read.unwrap();
            assert_eq!(received, reply);
            spliced.await.unwrap().unwrap();
        })
        .await
        .unwrap();
    }

    #[derive(Clone, Copy, PartialEq)]
    enum CopyFault {
        Read,
        Write,
        WriteZero,
        Flush,
        Shutdown,
    }

    struct CopyTestIo {
        fault: Option<CopyFault>,
        pending_read: bool,
        remaining: &'static [u8],
    }

    impl AsyncRead for CopyTestIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut TaskCtx<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let me = self.get_mut();
            if me.fault == Some(CopyFault::Read) {
                return Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()));
            }
            if me.pending_read {
                return Poll::Pending;
            }
            let take = me.remaining.len().min(buf.remaining());
            buf.put_slice(&me.remaining[..take]);
            me.remaining = &me.remaining[take..];
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for CopyTestIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut TaskCtx<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Ready(match self.fault {
                Some(CopyFault::Write) => Err(std::io::ErrorKind::BrokenPipe.into()),
                Some(CopyFault::WriteZero) => Ok(0),
                _ => Ok(buf.len()),
            })
        }

        fn poll_flush(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(if self.fault == Some(CopyFault::Flush) {
                Err(std::io::ErrorKind::TimedOut.into())
            } else {
                Ok(())
            })
        }

        fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(if self.fault == Some(CopyFault::Shutdown) {
                Err(std::io::ErrorKind::ConnectionAborted.into())
            } else {
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn splice_propagates_failures_while_the_other_direction_is_pending() {
        use std::io::ErrorKind;

        for (fault, expected) in [
            (CopyFault::Read, ErrorKind::ConnectionReset),
            (CopyFault::Write, ErrorKind::BrokenPipe),
            (CopyFault::WriteZero, ErrorKind::WriteZero),
            (CopyFault::Flush, ErrorKind::TimedOut),
            (CopyFault::Shutdown, ErrorKind::ConnectionAborted),
        ] {
            for reverse in [false, true] {
                let mut source = CopyTestIo {
                    fault: (fault == CopyFault::Read).then_some(fault),
                    pending_read: false,
                    remaining: b"payload",
                };
                let mut sink = CopyTestIo {
                    fault: (fault != CopyFault::Read).then_some(fault),
                    pending_read: true,
                    remaining: b"",
                };
                let (a, b) = if reverse {
                    (&mut sink, &mut source)
                } else {
                    (&mut source, &mut sink)
                };
                let error = tokio::time::timeout(
                    Duration::from_secs(2),
                    splice(a, b, HOST_BOUND_CHUNK, GUEST_BOUND_CHUNK, None),
                )
                .await
                .expect("a failure waited for the other direction")
                .unwrap_err();
                assert_eq!(error.kind(), expected);
            }
        }
    }

    async fn send(s: &mut UnixStream, frame: &[u8]) {
        s.write_all(&(frame.len() as u32).to_be_bytes())
            .await
            .unwrap();
        s.write_all(frame).await.unwrap();
    }

    async fn recv(s: &mut UnixStream) -> Vec<u8> {
        let mut hdr = [0u8; 4];
        s.read_exact(&mut hdr).await.unwrap();
        let mut buf = vec![0u8; u32::from_be_bytes(hdr) as usize];
        s.read_exact(&mut buf).await.unwrap();
        buf
    }

    /// Two "VMs" on the switch: a unicast frame from A to B's MAC is forwarded to
    /// B's port (MAC learning), and a broadcast floods to B.
    #[tokio::test]
    async fn forwards_between_vms() {
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("switchtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (sa, sb) = (dir.join("a.sock"), dir.join("b.sock"));
        let (ip_a, ip_b) = (
            Ipv4Addr::new(192, 168, 127, 2),
            Ipv4Addr::new(192, 168, 127, 3),
        );
        // Two separate guests, so a frame sourcing the other's address is a spoof.
        let listen = vec![(sa.clone(), ip_a, 0), (sb.clone(), ip_b, 1)];
        tokio::spawn(async move {
            let _ = run(
                &listen,
                Ipv4Addr::new(192, 168, 127, 1),
                24,
                HashMap::new(),
                HashMap::new(),
                Egress::AllowAll,
                HashMap::new(),
                None,
                None,
                None,
                None,
                false,
            )
            .await;
        });
        for _ in 0..100 {
            if sa.exists() && sb.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut a = UnixStream::connect(&sa).await.unwrap();
        let mut b = UnixStream::connect(&sb).await.unwrap();
        let (mac_a, mac_b) = ([2, 0, 0, 0, 0, 0xaa], [2, 0, 0, 0, 0, 0xbb]);

        // B sends first (from its own address) so the switch learns mac_b → B's port.
        send(
            &mut b,
            &eth(mac_a, mac_b, ETHERTYPE_IPV4, &ipv4_payload(ip_b, b"")),
        )
        .await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Unicast A → B (from A's own address) is delivered to B.
        let unicast = eth(mac_b, mac_a, ETHERTYPE_IPV4, &ipv4_payload(ip_a, b"to-b"));
        send(&mut a, &unicast).await;
        let got = tokio::time::timeout(Duration::from_secs(2), recv(&mut b))
            .await
            .unwrap();
        assert_eq!(got, unicast);

        // Broadcast A → flood reaches B.
        let bcast = eth(BCAST_MAC, mac_a, 0x88b5, b"broadcast-payload");
        send(&mut a, &bcast).await;
        let got = tokio::time::timeout(Duration::from_secs(2), recv(&mut b))
            .await
            .unwrap();
        assert_eq!(got, bcast);
    }

    /// A VM may only source IPv4 from the address bound to its socket: a frame forging a
    /// sibling's source is dropped before it can flood, egress, or select that sibling's
    /// egress policy. Since the source drives `policy_for`/`route_in`, this is the isolation
    /// that makes per-service egress sound against an untrusted guest.
    #[tokio::test]
    async fn drops_source_spoofed_frames() {
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("switchspoof-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (sa, sb) = (dir.join("a.sock"), dir.join("b.sock"));
        let (ip_a, ip_b) = (
            Ipv4Addr::new(192, 168, 127, 2),
            Ipv4Addr::new(192, 168, 127, 3),
        );
        // Two separate guests, so a frame sourcing the other's address is a spoof.
        let listen = vec![(sa.clone(), ip_a, 0), (sb.clone(), ip_b, 1)];
        tokio::spawn(async move {
            let _ = run(
                &listen,
                Ipv4Addr::new(192, 168, 127, 1),
                24,
                HashMap::new(),
                HashMap::new(),
                Egress::AllowAll,
                HashMap::new(),
                None,
                None,
                None,
                None,
                false,
            )
            .await;
        });
        for _ in 0..100 {
            if sa.exists() && sb.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut a = UnixStream::connect(&sa).await.unwrap();
        let mut b = UnixStream::connect(&sb).await.unwrap();
        let mac_b = [2, 0, 0, 0, 0, 0xbb];

        // B broadcasts a frame forging A's source address: it is dropped before the flood,
        // so A receives nothing.
        let spoofed = eth(
            BCAST_MAC,
            mac_b,
            ETHERTYPE_IPV4,
            &ipv4_payload(ip_a, b"spoof"),
        );
        send(&mut b, &spoofed).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), recv(&mut a))
                .await
                .is_err(),
            "a source-spoofed broadcast must be dropped, not flooded"
        );

        // The same broadcast from B's own address floods normally, reaching A — proving the
        // drop above is the spoof check, not a dead flood path.
        let honest = eth(
            BCAST_MAC,
            mac_b,
            ETHERTYPE_IPV4,
            &ipv4_payload(ip_b, b"honest"),
        );
        send(&mut b, &honest).await;
        let got = tokio::time::timeout(Duration::from_secs(2), recv(&mut a))
            .await
            .unwrap();
        assert_eq!(got, honest);
    }

    /// A multi-homed guest may use any of its addresses on any of its ports, while addresses
    /// owned by another guest remain blocked.
    #[tokio::test]
    async fn a_multi_nic_guest_may_source_any_of_its_own_addresses() {
        use std::time::Duration;
        let dir = std::env::temp_dir().join(format!("switchmultinic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (s0, s1, s_other) = (
            dir.join("eth0.sock"),
            dir.join("eth1.sock"),
            dir.join("other.sock"),
        );
        let (ip0, ip1, ip_other) = (
            Ipv4Addr::new(192, 168, 127, 2),
            Ipv4Addr::new(192, 168, 127, 254),
            Ipv4Addr::new(192, 168, 127, 3),
        );
        // eth0 and eth1 share VM 0; the observer belongs to VM 1.
        let listen = vec![
            (s0.clone(), ip0, 0),
            (s1.clone(), ip1, 0),
            (s_other.clone(), ip_other, 1),
        ];
        tokio::spawn(async move {
            let _ = run(
                &listen,
                Ipv4Addr::new(192, 168, 127, 1),
                24,
                HashMap::new(),
                HashMap::new(),
                Egress::AllowAll,
                HashMap::new(),
                None,
                None,
                None,
                None,
                false,
            )
            .await;
        });
        for _ in 0..100 {
            if s0.exists() && s1.exists() && s_other.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let mut eth0 = UnixStream::connect(&s0).await.unwrap();
        let mut other = UnixStream::connect(&s_other).await.unwrap();
        let mac0 = [2, 0, 0, 0, 0, 0x01];

        // Cross-NIC traffic within one VM must be forwarded.
        let cross = eth(
            BCAST_MAC,
            mac0,
            ETHERTYPE_IPV4,
            &ipv4_payload(ip1, b"cross-nic"),
        );
        send(&mut eth0, &cross).await;
        let got = tokio::time::timeout(Duration::from_secs(2), recv(&mut other))
            .await
            .unwrap();
        assert_eq!(got, cross);

        // The same port still cannot source another VM's address.
        let spoofed = eth(
            BCAST_MAC,
            mac0,
            ETHERTYPE_IPV4,
            &ipv4_payload(ip_other, b"spoof"),
        );
        send(&mut eth0, &spoofed).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(300), recv(&mut other))
                .await
                .is_err(),
            "another guest's address must still be refused"
        );
    }

    /// Build a minimal DNS query for `name` with the given qtype.
    fn dns_question(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut q = Vec::new();
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // RD set
        q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1, others 0
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]); // class IN
        q
    }

    #[test]
    fn first_nameserver_tolerates_any_whitespace() {
        use std::net::IpAddr;
        // Tab-separated (as some provisioners emit) must parse, not just single-space.
        assert_eq!(
            first_nameserver("nameserver\t10.10.1.219\n"),
            Some("10.10.1.219".parse::<IpAddr>().unwrap())
        );
        // Single space, multiple spaces, and leading indentation all work.
        assert_eq!(
            first_nameserver("nameserver 1.1.1.1"),
            Some("1.1.1.1".parse::<IpAddr>().unwrap())
        );
        assert_eq!(
            first_nameserver("  nameserver   8.8.8.8  "),
            Some("8.8.8.8".parse::<IpAddr>().unwrap())
        );
        // First entry wins; comments and other directives are skipped.
        assert_eq!(
            first_nameserver(
                "# comment\nsearch corp.example.com\nnameserver\t9.9.9.9\nnameserver 1.1.1.1\n"
            ),
            Some("9.9.9.9".parse::<IpAddr>().unwrap())
        );
        // Only the first token is read, so a trailing inline comment is ignored.
        assert_eq!(
            first_nameserver("nameserver 1.1.1.1 # corp resolver\n"),
            Some("1.1.1.1".parse::<IpAddr>().unwrap())
        );
        // A bare keyword, a glued token, a commented-out line, or no nameserver at
        // all yields None.
        assert_eq!(first_nameserver("nameserver\n"), None);
        assert_eq!(first_nameserver("nameserverfoo 1.2.3.4\n"), None);
        assert_eq!(first_nameserver(";nameserver 9.9.9.9\n"), None);
        assert_eq!(first_nameserver("search corp.example.com\n"), None);
    }

    #[test]
    fn all_nameservers_collects_every_entry_in_order() {
        use std::net::IpAddr;
        let p = |s: &str| s.parse::<IpAddr>().unwrap();
        // Every `nameserver` line, in file order, tab- or space-separated, other directives and
        // inline comments skipped — the switch rotates across all of them, not just the first.
        assert_eq!(
            all_nameservers(
                "search corp.example.com\nnameserver 1.1.1.1\nnameserver\t8.8.8.8\n  nameserver   9.9.9.9 # corp\n"
            ),
            vec![p("1.1.1.1"), p("8.8.8.8"), p("9.9.9.9")]
        );
        // A bare keyword and a glued token contribute nothing; empty input is empty.
        assert_eq!(
            all_nameservers("nameserver\nnameserverfoo 1.2.3.4\n"),
            Vec::<IpAddr>::new()
        );
        assert_eq!(all_nameservers(""), Vec::<IpAddr>::new());
    }

    #[test]
    fn resolver_answers_service_a_records() {
        let mut hosts = HashMap::new();
        hosts.insert("redis.lan".to_string(), Ipv4Addr::new(192, 168, 127, 3));
        // A query for a known name -> one A answer with the mapped IP.
        let resp = local_answer(&dns_question(0x1234, "redis.lan", 1), &hosts).expect("A answer");
        assert_eq!(&resp[0..2], &[0x12, 0x34]); // echoed id
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT
        assert_eq!(&resp[resp.len() - 4..], &[192, 168, 127, 3]); // A rdata
        // case-insensitive match
        assert!(local_answer(&dns_question(1, "REDIS.LAN", 1), &hosts).is_some());
        // AAAA for a known name -> NODATA (no answers), never forwarded upstream.
        let aaaa = local_answer(&dns_question(2, "redis.lan", 28), &hosts).expect("NODATA");
        assert_eq!(u16::from_be_bytes([aaaa[6], aaaa[7]]), 0); // ANCOUNT 0
        // unknown name -> not answered locally (caller forwards upstream)
        assert!(local_answer(&dns_question(3, "github.com", 1), &hosts).is_none());
    }

    #[test]
    fn reverse_dns_is_recognized() {
        // PTR names are forwarded regardless of the allowlist (they open no flow).
        assert!(is_reverse_dns("68.1.10.10.in-addr.arpa"));
        assert!(is_reverse_dns(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        ));
        // forward names are not reverse lookups
        assert!(!is_reverse_dns("repo.maven.apache.org"));
        assert!(!is_reverse_dns("in-addr.arpa.evil.com"));
        // the bare zone (no address label) is not a PTR query
        assert!(!is_reverse_dns("in-addr.arpa"));
        assert!(!is_reverse_dns("ip6.arpa"));
    }

    #[test]
    fn dns_query_matches_only_gateway_port_53() {
        let gw = Ipv4Addr::new(192, 168, 127, 1);
        let udp = |dst: [u8; 4], dport: u16| {
            let b = etherparse::PacketBuilder::ipv4([192, 168, 127, 2], dst, 64).udp(40000, dport);
            let mut v = Vec::with_capacity(b.size(1));
            b.write(&mut v, b"q").unwrap();
            v
        };
        assert!(dns_query(&udp(gw.octets(), 53), gw).is_some());
        assert!(dns_query(&udp(gw.octets(), 80), gw).is_none()); // wrong port
        assert!(dns_query(&udp([8, 8, 8, 8], 53), gw).is_none()); // not the gateway
    }

    #[test]
    fn dns_error_echoes_the_question_with_the_rcode() {
        let query = dns_question(0xbeef, "pool.ntp.org", 1);
        let (_, _, qend) = parse_question(&query).expect("question parses");
        for (build, rcode, aa) in [
            (
                dns_servfail as fn(&[u8], usize) -> Vec<u8>,
                RCODE_SERVFAIL,
                0,
            ),
            (
                dns_nxdomain as fn(&[u8], usize) -> Vec<u8>,
                RCODE_NXDOMAIN,
                0x04,
            ),
        ] {
            let resp = build(&query, qend);
            assert_eq!(&resp[0..2], &[0xbe, 0xef]); // echoed id
            assert_eq!(resp[2] & 0x80, 0x80); // QR=1
            assert_eq!(resp[2] & 0x04, aa); // AA only where the switch is authoritative
            assert_eq!(resp[2] & 0x01, 0x01); // RD copied from the query
            assert_eq!(resp[3] & 0x80, 0x80); // RA=1
            assert_eq!(resp[3] & 0x0f, rcode);
            assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1); // QDCOUNT
            assert_eq!(&resp[6..12], &[0, 0, 0, 0, 0, 0]); // no answers, NS or additional
            assert_eq!(&resp[12..], &query[12..qend]); // the question, verbatim
        }
    }

    #[tokio::test]
    async fn forward_upstream_reports_why_it_failed() {
        let query = dns_question(1, "pool.ntp.org", 1);
        // A bound socket that never answers: the deadline expires.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let err = forward_upstream_with(
            &query,
            silent.local_addr().unwrap(),
            Duration::from_millis(150),
        )
        .await
        .expect_err("a silent upstream times out");
        assert!(matches!(err, UpstreamError::Timeout(_)), "{err}");
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(err.to_string(), "no reply in 150ms");

        // Nothing bound: the ICMP port-unreachable surfaces on the connected socket's recv.
        let closed = {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            s.local_addr().unwrap()
        };
        let err = forward_upstream_with(&query, closed, Duration::from_secs(2))
            .await
            .expect_err("a closed port is refused");
        assert_eq!(err.kind(), std::io::ErrorKind::ConnectionRefused, "{err}");

        // A reply shorter than a DNS header is not a reply the switch can relay.
        let stub = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stub_addr = stub.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, from) = stub.recv_from(&mut buf).await.unwrap();
            stub.send_to(&[0u8; 4], from).await.unwrap();
        });
        let err = forward_upstream_with(&query, stub_addr, Duration::from_secs(2))
            .await
            .expect_err("a truncated reply is rejected");
        assert!(matches!(err, UpstreamError::Short(4)), "{err}");
        assert_eq!(err.to_string(), "reply too short (4 bytes)");
    }

    #[tokio::test]
    async fn resolve_upstream_retries_past_a_dropped_datagram() {
        // A resolver that drops the first datagram and answers the second — the pattern a
        // loaded resolver shows under a burst of parallel lookups (a yarn/npm fetch). One try
        // would SERVFAIL; the retry must recover it.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let _ = server.recv_from(&mut buf).await.unwrap(); // first datagram: dropped
            let (n, from) = server.recv_from(&mut buf).await.unwrap(); // second: answered
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x80; // QR: mark as a response
            server.send_to(&resp, from).await.unwrap();
        });
        let query = dns_question(1, "registry.yarnpkg.com", 1);
        let resp = resolve_upstream_with(
            &query,
            &[addr],
            3,
            Duration::from_millis(200),
            Duration::from_secs(1),
        )
        .await
        .expect("a retry recovers a single dropped datagram");
        assert_eq!(resp.reply[0..2], query[0..2]); // same transaction id
        assert_eq!(resp.reply[2] & 0x80, 0x80); // and it is a response
    }

    #[tokio::test]
    async fn resolve_upstream_fails_over_to_a_healthy_resolver() {
        // The first resolver is a black hole (bound, never answers); the second answers. The
        // lookup must succeed by rotating onto the second within the try budget.
        let dead = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap(); // held so the port stays bound (times out)
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let live_addr = live.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = live.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x80;
            live.send_to(&resp, from).await.unwrap();
        });
        let query = dns_question(7, "example.com", 1);
        let resp = resolve_upstream_with(
            &query,
            &[dead_addr, live_addr],
            3,
            Duration::from_millis(200),
            Duration::from_secs(1),
        )
        .await
        .expect("failover reaches the healthy resolver");
        assert_eq!(resp.reply[0..2], query[0..2]);
        drop(dead);
    }

    #[tokio::test]
    async fn resolve_upstream_gives_up_when_every_try_fails() {
        // Two bound-but-silent resolvers: every try times out, so the lookup surfaces the last
        // fault — the Err `handle_dns` turns into the guest's SERVFAIL.
        let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        let query = dns_question(3, "nope.example", 1);
        let err = resolve_upstream_with(
            &query,
            &[aa, ba],
            3,
            Duration::from_millis(60),
            Duration::from_millis(200),
        )
        .await
        .expect_err("every try times out");
        assert!(matches!(err, UpstreamError::Timeout(_)), "{err}");
        drop((a, b));
    }

    #[tokio::test]
    async fn a_truncated_answer_is_recovered_over_tcp_while_the_guest_keeps_the_udp_reply() {
        use tokio::net::TcpListener;
        // One address answers UDP with a TC-truncated datagram and TCP with the full record set.
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x80 | 0x02; // QR + TC: a truncated response
            udp.send_to(&resp, from).await.unwrap();
        });
        tokio::spawn(async move {
            let (mut sock, _) = tcp.accept().await.unwrap();
            let mut lenbuf = [0u8; 2];
            sock.read_exact(&mut lenbuf).await.unwrap();
            let mut msg = vec![0u8; u16::from_be_bytes(lenbuf) as usize];
            sock.read_exact(&mut msg).await.unwrap();
            msg[2] |= 0x80; // QR, and not truncated
            msg.push(0xAB); // a sentinel byte marking this as the full-record TCP body
            sock.write_all(&(msg.len() as u16).to_be_bytes())
                .await
                .unwrap();
            sock.write_all(&msg).await.unwrap();
        });
        let query = dns_question(4, "cdn.example", 1);
        let answer = resolve_upstream_with(
            &query,
            &[addr],
            3,
            Duration::from_millis(500),
            Duration::from_secs(2),
        )
        .await
        .expect("the truncated answer resolves");
        // The guest keeps the UDP-sized (still TC-marked) reply, not the oversized TCP body.
        assert_eq!(answer.reply[0..2], query[0..2]);
        assert_eq!(answer.reply[2] & 0x02, 0x02);
        // Pinning, though, reads the full TCP record set.
        let full = answer.full.as_deref().expect("TCP recovered the full set");
        assert_eq!(full[2] & 0x02, 0, "the TCP answer is not truncated");
        assert_eq!(*full.last().unwrap(), 0xAB);
        assert_eq!(answer.pin_source(), full);
        assert!(answer.degraded.is_none());
    }

    #[tokio::test]
    async fn a_truncated_answer_with_no_tcp_falls_back_to_the_udp_reply() {
        // UDP truncates; nothing answers TCP on that port, so the guest still gets the truncated
        // reply, pinning runs on it, and the TCP fault is recorded for the operator.
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (n, from) = udp.recv_from(&mut buf).await.unwrap();
            let mut resp = buf[..n].to_vec();
            resp[2] |= 0x80 | 0x02;
            udp.send_to(&resp, from).await.unwrap();
        });
        let query = dns_question(5, "cdn.example", 1);
        let answer = resolve_upstream_with(
            &query,
            &[addr],
            3,
            Duration::from_millis(500),
            Duration::from_secs(1),
        )
        .await
        .expect("a truncated answer still resolves for the guest");
        assert_eq!(answer.reply[2] & 0x02, 0x02);
        assert!(answer.full.is_none());
        assert!(
            answer.degraded.is_some(),
            "the failed TCP recovery is recorded"
        );
        assert_eq!(answer.pin_source(), answer.reply.as_slice());
    }

    #[tokio::test]
    async fn forward_upstream_tcp_round_trips_a_length_prefixed_message() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut lenbuf = [0u8; 2];
            sock.read_exact(&mut lenbuf).await.unwrap();
            let mut msg = vec![0u8; u16::from_be_bytes(lenbuf) as usize];
            sock.read_exact(&mut msg).await.unwrap();
            msg[2] |= 0x80; // QR
            sock.write_all(&(msg.len() as u16).to_be_bytes())
                .await
                .unwrap();
            sock.write_all(&msg).await.unwrap();
        });
        let query = dns_question(9, "files.pythonhosted.org", 1);
        let resp = forward_upstream_tcp(&query, addr, Duration::from_secs(1))
            .await
            .expect("tcp exchange returns the framed response");
        assert_eq!(resp[0..2], query[0..2]);
        assert_eq!(resp[2] & 0x80, 0x80);
    }

    #[test]
    fn truncation_flag_is_read_from_the_header() {
        let mut msg = dns_question(1, "x.example", 1);
        assert!(!is_truncated(&msg));
        msg[2] |= 0x02; // TC
        assert!(is_truncated(&msg));
        assert!(!is_truncated(&[0u8; 2])); // too short to carry a flags byte
    }

    #[test]
    fn upstreams_keep_the_local_resolver_stub_first_and_its_uplinks_as_fallbacks() {
        let stub: std::net::IpAddr = "127.0.0.53".parse().unwrap();
        let a: std::net::IpAddr = "10.10.1.218".parse().unwrap();
        let b: std::net::IpAddr = "10.10.1.219".parse().unwrap();
        // Keep the systemd-resolved stub first for split-DNS routing, then its uplinks.
        assert_eq!(choose_upstreams(vec![stub], vec![a, b]), vec![stub, a, b]);
        // Real resolvers already in resolv.conf -> keep them, ignore the uplink file.
        assert_eq!(choose_upstreams(vec![a], vec![b]), vec![a]);
        // Empty resolv.conf -> fall back to the uplinks.
        assert_eq!(choose_upstreams(vec![], vec![a, b]), vec![a, b]);
        // The stub, but no usable uplinks -> just the stub.
        assert_eq!(choose_upstreams(vec![stub], vec![]), vec![stub]);
        assert_eq!(choose_upstreams(vec![stub], vec![stub]), vec![stub]);
        // The host already lists a real resolver alongside the stub -> keep both as-is.
        assert_eq!(choose_upstreams(vec![stub, a], vec![a, b]), vec![stub, a]);
        // A repeated uplink is appended once.
        assert_eq!(
            choose_upstreams(vec![stub], vec![a, a, b]),
            vec![stub, a, b]
        );
    }

    #[test]
    fn qtype_name_is_the_mnemonic_or_the_number() {
        assert_eq!(qtype_name(1), "A");
        assert_eq!(qtype_name(28), "AAAA");
        assert_eq!(qtype_name(255), "255"); // ANY: no mnemonic, so the number
    }

    #[test]
    fn log_limiter_collapses_a_burst_into_one_line() {
        let limiter = LogLimiter::new(DNS_LOG_WINDOW);
        let up: SocketAddr = "127.0.0.53:53".parse().unwrap();
        let refused = (up, std::io::ErrorKind::ConnectionRefused);
        let t0 = Instant::now();
        assert_eq!(limiter.admit(refused, t0), Some(0)); // first of its kind: print it
        assert_eq!(limiter.admit(refused, t0 + Duration::from_secs(1)), None);
        assert_eq!(limiter.admit(refused, t0 + Duration::from_secs(29)), None);
        // A different fault on the same upstream is its own line.
        assert_eq!(
            limiter.admit((up, std::io::ErrorKind::TimedOut), t0),
            Some(0)
        );
        // Past the window: print again, carrying the two lines swallowed in between.
        let past = t0 + DNS_LOG_WINDOW + Duration::from_secs(1);
        assert_eq!(limiter.admit(refused, past), Some(2));
        // …and the count starts over.
        assert_eq!(limiter.admit(refused, past + Duration::from_secs(1)), None);
        assert_eq!(limiter.admit(refused, past + DNS_LOG_WINDOW), Some(1));
    }

    /// Each limiter throttles on its own window: the same fault prints again once the shorter
    /// window has passed while the longer one still suppresses it.
    #[test]
    fn a_limiters_window_is_its_own() {
        let short = LogLimiter::new(Duration::from_secs(1));
        let long = LogLimiter::new(Duration::from_secs(60));
        let dst: SocketAddr = "203.0.113.7:443".parse().unwrap();
        let fault = (dst, std::io::ErrorKind::ConnectionReset);
        let t0 = Instant::now();
        assert_eq!(short.admit(fault, t0), Some(0));
        assert_eq!(long.admit(fault, t0), Some(0));
        // Two seconds on: past the short window, still inside the long one.
        let t1 = t0 + Duration::from_secs(2);
        assert_eq!(short.admit(fault, t1), Some(0));
        assert_eq!(long.admit(fault, t1), None);
    }

    #[test]
    fn dhcp_pool_is_stable_per_mac() {
        let cfg = Cfg {
            gateway: Ipv4Addr::new(192, 168, 127, 1),
            prefix: 24,
        };
        let mut inner = Inner {
            next_idx: FIRST_LEASE,
            ..Inner::default()
        };
        let a = [0xaa; 6];
        let b = [0xbb; 6];
        // distinct MACs draw sequential leases; the same MAC keeps its address
        assert_eq!(
            alloc_lease(&mut inner, &cfg, a),
            Some(Ipv4Addr::new(192, 168, 127, 2))
        );
        assert_eq!(
            alloc_lease(&mut inner, &cfg, b),
            Some(Ipv4Addr::new(192, 168, 127, 3))
        );
        assert_eq!(
            alloc_lease(&mut inner, &cfg, a),
            Some(Ipv4Addr::new(192, 168, 127, 2))
        );
    }

    #[test]
    fn reserved_mac_gets_its_ip_and_pool_skips_it() {
        let cfg = Cfg {
            gateway: Ipv4Addr::new(192, 168, 127, 1),
            prefix: 24,
        };
        let reserved_mac = [0x52, 0x54, 0x00, 0xa8, 0x7f, 0xfe];
        let reserved_ip = Ipv4Addr::new(192, 168, 127, 254);
        let mut inner = Inner {
            next_idx: FIRST_LEASE,
            reservations: HashMap::from([(reserved_mac, reserved_ip)]),
            ..Inner::default()
        };
        // The reserved MAC always gets its reserved IP, not a pool address.
        assert_eq!(
            alloc_lease(&mut inner, &cfg, reserved_mac),
            Some(reserved_ip)
        );
        // …and it is recorded as a lease (so ARP/DNS route-back stays consistent).
        assert_eq!(inner.leases.get(&reserved_mac), Some(&reserved_ip));
        // A non-reserved MAC still draws from the pool bottom (.2).
        assert_eq!(
            alloc_lease(&mut inner, &cfg, [0xbb; 6]),
            Some(Ipv4Addr::new(192, 168, 127, 2))
        );

        // A reserved IP inside the pool range is skipped when advancing the pool.
        let low_reserved = Ipv4Addr::new(192, 168, 127, 3);
        let mut inner = Inner {
            next_idx: FIRST_LEASE,
            reservations: HashMap::from([([0x52, 0x54, 0x00, 0xa8, 0x7f, 0x03], low_reserved)]),
            ..Inner::default()
        };
        assert_eq!(
            alloc_lease(&mut inner, &cfg, [0xaa; 6]),
            Some(Ipv4Addr::new(192, 168, 127, 2))
        );
        // .3 is reserved for another MAC, so the next pool lease is .4, not .3.
        assert_eq!(
            alloc_lease(&mut inner, &cfg, [0xcc; 6]),
            Some(Ipv4Addr::new(192, 168, 127, 4))
        );
    }

    /// A scratch byte channel for the counter tests, where the rest of this module's tests
    /// put theirs.
    fn bytes_channel(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-switch-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch dir");
        dir.join(crate::run::NET_BYTES)
    }

    /// Every byte counted reaches the channel exactly once, however many publishers race.
    /// The reader sums the deltas, so a publish that went backwards would both lose its own
    /// figure and — the totals being unsigned — invent an astronomical one in its place,
    /// which `admit` would then remember as this job's appetite for a fortnight.
    #[test]
    fn racing_publishers_sum_to_exactly_what_was_counted() {
        const THREADS: u64 = 8;
        const EACH: u64 = 2000;
        const SENT: u64 = 8192;
        const RECEIVED: u64 = 4096;

        let path = bytes_channel("racing");
        let guard = Arc::new(
            EgressGuard::new(Egress::AllowAll, Ipv4Addr::new(192, 168, 127, 1))
                .with_bytes_log(Some(path.clone())),
        );
        guard.open_bytes();
        let writers: Vec<_> = (0..THREADS)
            .map(|_| {
                let guard = Arc::clone(&guard);
                std::thread::spawn(move || {
                    for _ in 0..EACH {
                        guard.count(SENT, RECEIVED);
                        guard.publish_bytes();
                    }
                })
            })
            .collect();
        for w in writers {
            w.join().expect("a publishing thread panicked");
        }
        // Whatever the threads left unpublished goes out here, so the sum is the whole of it.
        guard.publish_bytes();

        assert_eq!(
            crate::egress_report::read_net_bytes(&path),
            Some((THREADS * EACH * SENT, THREADS * EACH * RECEIVED))
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The two directions are kept apart, and a channel nobody wrote to reads as nothing at
    /// all rather than as a pair of zeros — the distinction the trace line rests on.
    #[test]
    fn each_direction_is_counted_on_its_own_side() {
        let path = bytes_channel("directions");
        let guard = EgressGuard::new(Egress::AllowAll, Ipv4Addr::new(192, 168, 127, 1))
            .with_bytes_log(Some(path.clone()));

        assert_eq!(crate::egress_report::read_net_bytes(&path), None);
        guard.open_bytes();
        assert_eq!(crate::egress_report::read_net_bytes(&path), Some((0, 0)));

        guard.count(1500, 0);
        guard.count(0, 9000);
        guard.publish_bytes();
        assert_eq!(
            crate::egress_report::read_net_bytes(&path),
            Some((1500, 9000))
        );

        // Nothing moved since, so nothing is appended and the totals stand.
        guard.publish_bytes();
        assert_eq!(
            crate::egress_report::read_net_bytes(&path),
            Some((1500, 9000))
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
