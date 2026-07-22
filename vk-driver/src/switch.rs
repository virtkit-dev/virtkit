//! Userspace L2 network gateway + switch for a LAN of microVMs.
//!
//! Each VM reaches us over Cloud Hypervisor's hybrid vsock: the guest dials host
//! CID 2 on a port and CH connects to the host unix socket `<vsock.sock>_<port>`,
//! where we listen (one `--listen` per VM). The stream carries the "qemu" vhost
//! framing — a 4-byte big-endian length then one ethernet frame; virtkit-agent's tap
//! bridge in the guest is the other end.
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
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::task::{Context as TaskCtx, Poll};
use std::time::{Duration, Instant};

use ipstack::{IpStack, IpStackConfig, IpStackStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket, UnixListener, UnixStream};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

/// Gateway MAC — locally administered, unicast. The guest learns it via ARP.
const GW_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x01];
const BCAST_MAC: [u8; 6] = [0xff; 6];
const MAX_FRAME: usize = 65535;
const MTU: u16 = 1500;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_LEASE_SECS: u32 = 86400;
const DNS_PORT: u16 = 53;
/// Upstream resolver used when /etc/resolv.conf yields no nameserver.
const FALLBACK_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
/// First host index handed out by DHCP (.1 is the gateway).
const FIRST_LEASE: u32 = 2;

#[derive(Clone, Copy)]
struct Cfg {
    gateway: Ipv4Addr,
    prefix: u8,
}

type Mac = [u8; 6];
type PortId = u32;

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
    /// DNS-pinned A-records, keyed by `(source, resolved_ip)` so one VM's resolution never
    /// admits a connection from another VM with a different policy (per-source isolation).
    pinned: Mutex<HashMap<(Ipv4Addr, Ipv4Addr), Instant>>,
    /// `(sentinel, host)`: a guest flow to `sentinel` is redirected to the host-local
    /// credential registry proxy at `host` (see regproxy.rs). `None` = disabled.
    registry_proxy: Option<(Ipv4Addr, SocketAddr)>,
    /// Where denials are appended as typed records for the job trace (see egress_report).
    /// `None` = don't record (dev `vk run`, or an unrestricted policy that denies nothing).
    denied_log: Option<PathBuf>,
    /// Audit mode: where every allowed external domain the guest resolves is appended for
    /// the end-of-job "domains contacted" summary (see egress_report). `None` = audit off.
    /// Independent of the allowlist — an unrestricted policy still records every contact.
    audit_log: Option<PathBuf>,
}

impl EgressGuard {
    fn new(policy: Egress, gateway: Ipv4Addr) -> Self {
        EgressGuard {
            policy,
            per_source: HashMap::new(),
            gateway,
            pinned: Mutex::new(HashMap::new()),
            registry_proxy: None,
            denied_log: None,
            audit_log: None,
        }
    }
    fn with_per_source(mut self, per_source: HashMap<Ipv4Addr, Egress>) -> Self {
        self.per_source = per_source;
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
    /// Record a refused flow to the denial channel for the job trace to surface. Paired
    /// with the switch's own `eprintln!` operator log at each call site.
    fn record_denial(&self, proto: crate::egress_report::Proto, target: &str) {
        if let Some(path) = &self.denied_log {
            crate::egress_report::append(path, proto, target);
        }
    }
    /// Record an allowed external domain the guest resolved to the audit channel, for the
    /// end-of-job "domains contacted" summary. No-op when audit is off.
    fn record_contact(&self, name: &str) {
        if let Some(path) = &self.audit_log {
            crate::egress_report::append_contact(path, name);
        }
    }
    /// Any restriction at all — the default policy or any per-source override. Drives the
    /// startup log summary.
    fn restricted(&self) -> bool {
        !matches!(self.policy, Egress::AllowAll) || !self.per_source.is_empty()
    }
    /// The policy that governs flows from source `src`: its per-source override, else the
    /// default. Source is the guest's own IPv4 (each VM has a fixed/leased address).
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

    /// If the SYN in `ip` opens a TCP connection its source's policy denies, return the RST
    /// frame refusing it; otherwise `None`, so the packet egresses normally. Rejecting the
    /// SYN (rather than letting ipstack complete the handshake and then drop the flow) makes
    /// the guest's connect() fail at once with ECONNREFUSED instead of stalling until a read
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
        if self.allows(*syn.src.ip(), SocketAddr::V4(syn.dst)) {
            return None;
        }
        eprintln!("switch: egress denied (tcp) {} — sent RST", syn.dst);
        self.record_denial(crate::egress_report::Proto::Tcp, &syn.dst.to_string());
        tcp_rst_frame(&syn, client_mac)
    }
}

#[derive(Default)]
struct Inner {
    /// frame sink for each connected VM (its writer task)
    ports: HashMap<PortId, UnboundedSender<Vec<u8>>>,
    /// learned source MAC -> port
    mac_port: HashMap<Mac, PortId>,
    /// IP -> MAC, so ipstack's egress replies route back to the owning VM
    ip_mac: HashMap<Ipv4Addr, Mac>,
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
    /// upstream resolver (the host's own) for everything else
    upstream: SocketAddr,
    /// egress policy + the DNS-pinned IP set (shared with the ipstack egress tasks)
    egress: Arc<EgressGuard>,
}

/// How a consumer spawns its switch: the listen sockets (one per VM on the LAN),
/// the gateway identity, the resolver's local names, the egress allowlists
/// (empty = unrestricted), and where the log goes.
pub struct Spawn {
    pub listen: Vec<PathBuf>,
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
}

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
    for l in &opts.listen {
        let _ = std::fs::remove_file(l);
        cmd.arg("--listen").arg(l);
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
    cmd.stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    let mut child = crate::spawn::spawn_tied(cmd).context("spawning the switch subprocess")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    for l in &opts.listen {
        while !l.exists() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                bail!("the switch did not bind {}", l.display());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    Ok(child)
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    listen: &[PathBuf],
    gateway: Ipv4Addr,
    prefix: u8,
    hosts: HashMap<String, Ipv4Addr>,
    reservations: HashMap<Mac, Ipv4Addr>,
    egress: Egress,
    per_source: HashMap<Ipv4Addr, Egress>,
    registry_proxy: Option<(Ipv4Addr, SocketAddr)>,
    denied_log: Option<PathBuf>,
    audit_log: Option<PathBuf>,
) -> Result<()> {
    if listen.is_empty() {
        bail!("switch: at least one --listen is required");
    }
    // One shared ipstack for egress: it reads the off-subnet IPv4 packets the
    // switch forwards and writes reply packets back, which we route to the owning
    // VM by destination IP.
    let (egress_tx, egress_rx) = unbounded_channel::<Vec<u8>>();
    let (ret_tx, mut ret_rx) = unbounded_channel::<Vec<u8>>();
    let mut config = IpStackConfig::default();
    config.mtu_unchecked(MTU);
    let ip_stack = IpStack::new(
        config,
        ChannelDevice {
            rx: egress_rx,
            tx: ret_tx,
        },
    );
    let audit = audit_log.is_some();
    let per_source_count = per_source.len();
    let guard = Arc::new(
        EgressGuard::new(egress, gateway)
            .with_per_source(per_source)
            .with_registry_proxy(registry_proxy)
            .with_denied_log(denied_log)
            .with_audit_log(audit_log),
    );
    let restricted = guard.restricted();
    tokio::spawn(accept_loop(ip_stack, guard.clone()));

    let upstream = host_upstream();
    let sw = Arc::new(Switch {
        cfg: Cfg { gateway, prefix },
        inner: Mutex::new(Inner {
            next_idx: FIRST_LEASE,
            reservations,
            ..Inner::default()
        }),
        egress_tx,
        next_port: AtomicU32::new(0),
        hosts: Arc::new(hosts),
        upstream,
        egress: guard,
    });

    // ipstack egress replies -> the owning VM port.
    {
        let sw = sw.clone();
        tokio::spawn(async move {
            while let Some(ip) = ret_rx.recv().await {
                sw.route_in(&ip);
            }
        });
    }

    eprintln!(
        "switch: {} port(s), gateway {}/{} (ARP + DHCP + DNS + egress, shared LAN); \
         resolver: {} service name(s), {} DHCP reservation(s), upstream {}; egress: {}{}",
        listen.len(),
        gateway,
        prefix,
        sw.hosts.len(),
        sw.inner.lock().unwrap().reservations.len(),
        upstream,
        match (restricted, audit) {
            (true, true) => "allowlist + audit",
            (true, false) => "allowlist",
            (false, true) => "unrestricted + audit",
            (false, false) => "unrestricted",
        },
        if per_source_count > 0 {
            format!(" ({per_source_count} per-service override(s))")
        } else {
            String::new()
        },
    );
    let mut accepts = Vec::new();
    for path in listen {
        let _ = std::fs::remove_file(path);
        let listener =
            UnixListener::bind(path).with_context(|| format!("switch: bind {}", path.display()))?;
        let sw = sw.clone();
        accepts.push(tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((conn, _)) => {
                        let sw = sw.clone();
                        tokio::spawn(async move { sw.serve_port(conn).await });
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
    async fn serve_port(self: Arc<Self>, conn: UnixStream) {
        let port = self.next_port.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = unbounded_channel::<Vec<u8>>();
        self.inner.lock().unwrap().ports.insert(port, tx);

        let (rd, wr) = conn.into_split();
        let writer = tokio::spawn(writer_task(wr, rx));
        self.reader(port, rd).await;

        writer.abort();
        self.drop_port(port);
    }

    async fn reader(&self, port: PortId, mut rd: tokio::net::unix::OwnedReadHalf) {
        let mut buf = vec![0u8; MAX_FRAME];
        loop {
            match read_frame(&mut rd, &mut buf).await {
                Ok(Some(n)) if n >= 14 => self.handle_frame(port, &buf[..n]),
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
        inner.mac_port.insert(src, port);
        if ethertype == ETHERTYPE_IPV4
            && let Some(sip) = ipv4_src(&frame[14..])
        {
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
                        let (gw, upstream, query) =
                            (self.cfg.gateway, self.upstream, query.to_vec());
                        tokio::spawn(handle_dns(
                            query, hosts, upstream, gw, cip, src_port, mac, tx, egress,
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
                    let _ = self.egress_tx.send(ip.to_vec());
                }
            }
            _ => {}
        }
    }

    /// Route an ipstack egress reply back to the VM that owns its destination IP.
    fn route_in(&self, ip: &[u8]) {
        let Some(dip) = ipv4_dst(ip) else { return };
        let inner = self.inner.lock().unwrap();
        let Some(mac) = inner.ip_mac.get(&dip).copied() else {
            return;
        };
        let Some(&port) = inner.mac_port.get(&mac) else {
            return;
        };
        send(&inner, port, &wrap_eth(ip, mac));
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
        // leases/ip_mac kept: the VM keeps its address across a reconnect
    }
}

/// Send a frame to one port (non-blocking; dropped if the port is gone).
fn send(inner: &Inner, port: PortId, frame: &[u8]) {
    if let Some(tx) = inner.ports.get(&port) {
        let _ = tx.send(frame.to_vec());
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

/// ipstack's accept loop: each guest flow becomes a host-side proxy, gated by the
/// egress policy (static IP allowlist + DNS-pinned IPs).
async fn accept_loop(mut ip_stack: IpStack, egress: Arc<EgressGuard>) {
    loop {
        match ip_stack.accept().await {
            Ok(IpStackStream::Tcp(tcp)) => {
                tokio::spawn(proxy_tcp(tcp, egress.clone()));
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
async fn proxy_tcp(mut guest: ipstack::IpStackTcpStream, egress: Arc<EgressGuard>) {
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
            if !src.is_some_and(|s| egress.allows(s, dst)) {
                // Fallback deny path: a denied SYN is normally RST'd earlier in
                // `reject_denied_syn` before ipstack completes the handshake, so this only
                // fires for a flow that slipped through (e.g. a DNS pin expiring between the
                // SYN and here). Per-stage dedup collapses any double-record.
                eprintln!("switch: egress denied (tcp) {dst}");
                egress.record_denial(crate::egress_report::Proto::Tcp, &dst.to_string());
                return;
            }
            dst
        }
    };
    match TcpStream::connect(target).await {
        Ok(mut host) => {
            let _ = tokio::io::copy_bidirectional(&mut guest, &mut host).await;
        }
        Err(e) => eprintln!("switch: tcp connect {target}: {e}"),
    }
}

/// Relay a guest UDP flow (e.g. DNS) to its destination via a host socket. ipstack
/// closes the stream after its udp_timeout, ending the task.
async fn proxy_udp(mut guest: ipstack::IpStackUdpStream, egress: Arc<EgressGuard>) {
    let dst = guest.peer_addr();
    let src = guest_src(guest.local_addr());
    if !src.is_some_and(|s| egress.allows(s, dst)) {
        eprintln!("switch: egress denied (udp) {dst}");
        egress.record_denial(crate::egress_report::Proto::Udp, &dst.to_string());
        return;
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
                Ok(n) => { let _ = host.send(&from_guest[..n]).await; }
            },
            r = host.recv(&mut from_host) => match r {
                Ok(n) => { if guest.write_all(&from_host[..n]).await.is_err() { return; } }
                Err(_) => return,
            },
        }
    }
}

/// The host's first configured resolver (from /etc/resolv.conf), used as the
/// gateway resolver's upstream so guest DNS honors host policy. Falls back to a
/// public resolver when resolv.conf names none.
fn host_upstream() -> SocketAddr {
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("nameserver ")
                && let Ok(ip) = rest.trim().parse::<std::net::IpAddr>()
            {
                return SocketAddr::new(ip, DNS_PORT);
            }
        }
    }
    SocketAddr::new(FALLBACK_DNS.into(), DNS_PORT)
}

/// Resolve a guest DNS query and send the response back to it: service names are
/// answered from the local map; everything else is forwarded to the host's resolver.
#[allow(clippy::too_many_arguments)]
async fn handle_dns(
    query: Vec<u8>,
    hosts: Arc<HashMap<String, Ipv4Addr>>,
    upstream: SocketAddr,
    gateway: Ipv4Addr,
    client_ip: Ipv4Addr,
    client_port: u16,
    client_mac: Mac,
    tx: UnboundedSender<Vec<u8>>,
    egress: Arc<EgressGuard>,
) {
    const TYPE_A: u16 = 1;
    let response = if let Some(r) = local_answer(&query, &hosts) {
        Some(r) // service name: on-subnet, not subject to egress pinning
    } else if let Some((name, qtype, qend)) = parse_question(&query) {
        if is_reverse_dns(&name) {
            // A PTR lookup resolves an IP to a name; it never opens a flow, so it
            // needn't be allowlisted. Forward it without pinning (its answer is a
            // name, not an A-record to admit for egress).
            forward_upstream(&query, upstream).await
        } else if egress.name_allowed(client_ip, &name) {
            // Audit: count the guest's A-record lookups as its external contacts (egress
            // is IPv4, so an A query is what precedes a connection); the paired AAAA query
            // for the same name is not double-counted.
            if qtype == TYPE_A {
                egress.record_contact(&name);
            }
            // forward, then pin the A-records (scoped to this resolving guest) so its
            // connection is allowed — and only its, not another VM's with a different policy.
            let resp = forward_upstream(&query, upstream).await;
            if let Some(r) = &resp {
                let (ips, ttl) = parse_a_records(r);
                egress.record(client_ip, &ips, ttl);
            }
            resp
        } else {
            eprintln!("switch: dns refused (egress allowlist): {name}");
            egress.record_denial(crate::egress_report::Proto::Dns, &name);
            Some(dns_nxdomain(&query, qend))
        }
    } else {
        forward_upstream(&query, upstream).await
    };
    if let Some(resp) = response
        && let Some(frame) = dns_frame(gateway, client_ip, client_port, client_mac, &resp)
    {
        let _ = tx.send(frame);
    }
}

/// Forward a raw DNS query to the upstream resolver and return its raw response.
async fn forward_upstream(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let bind: SocketAddr = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .unwrap();
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(upstream).await.ok()?;
    sock.send(query).await.ok()?;
    let mut buf = vec![0u8; MAX_FRAME];
    let n = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    Some(buf)
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

/// An NXDOMAIN response echoing the question — refuses a name outside the egress
/// allowlist (the guest sees "could not resolve"; the name never leaks upstream).
fn dns_nxdomain(query: &[u8], qend: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(qend);
    out.extend_from_slice(&query[0..2]); // transaction id
    out.push(0x84 | (query[2] & 0x01)); // QR=1, AA=1, RD copied
    out.push(0x83); // RA=1, rcode=3 (NXDOMAIN)
    out.extend_from_slice(&[0, 1]); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT + NSCOUNT + ARCOUNT
    out.extend_from_slice(&query[12..qend]); // echo the question
    out
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
        let _ = self.get_mut().tx.send(buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskCtx<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The single writer to one guest's qemu stream.
async fn writer_task(mut wr: tokio::net::unix::OwnedWriteHalf, mut rx: UnboundedReceiver<Vec<u8>>) {
    while let Some(frame) = rx.recv().await {
        if write_frame(&mut wr, &frame).await.is_err() {
            return;
        }
    }
}

/// Wrap an IP packet in an ethernet header addressed to the guest.
fn wrap_eth(ip: &[u8], guest_mac: Mac) -> Vec<u8> {
    let ethertype = if ip.first().map(|b| b >> 4) == Some(6) {
        ETHERTYPE_IPV6
    } else {
        ETHERTYPE_IPV4
    };
    let mut out = Vec::with_capacity(14 + ip.len());
    out.extend_from_slice(&guest_mac);
    out.extend_from_slice(&GW_MAC);
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(ip);
    out
}

/// Read one qemu-framed ethernet frame; `Ok(None)` on a clean EOF.
async fn read_frame<R: AsyncRead + Unpin>(rd: &mut R, buf: &mut [u8]) -> Result<Option<usize>> {
    let mut hdr = [0u8; 4];
    match rd.read_exact(&mut hdr).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e).context("read frame length"),
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len > buf.len() {
        bail!("frame length {len} exceeds {}", buf.len());
    }
    rd.read_exact(&mut buf[..len]).await.context("read frame")?;
    Ok(Some(len))
}

async fn write_frame<W: AsyncWrite + Unpin>(wr: &mut W, frame: &[u8]) -> Result<()> {
    wr.write_all(&(frame.len() as u32).to_be_bytes()).await?;
    wr.write_all(frame).await?;
    Ok(())
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
        let listen = vec![sa.clone(), sb.clone()];
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

        // B sends first so the switch learns mac_b → B's port.
        send(&mut b, &eth(mac_a, mac_b, ETHERTYPE_IPV4, &[0x45; 20])).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Unicast A → B is delivered to B.
        let unicast = eth(mac_b, mac_a, ETHERTYPE_IPV4, b"to-b-unicast-payload");
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
}
