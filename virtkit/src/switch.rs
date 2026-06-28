//! Userspace L2 network gateway + switch for a fleet of microVMs.
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

/// Egress policy — which off-subnet destinations the switch originates flows to.
/// Default `AllowAll` (the dev fleet is unrestricted); CI passes an allowlist.
/// Direct (non-proxied) TCP/UDP egress is gated by destination IP (`allows_ip`);
/// the in-switch http(s) proxy gates web egress by hostname (`allows_host`).
#[derive(Clone, Default)]
pub enum Egress {
    #[default]
    AllowAll,
    Allow {
        /// allowed destination IPv4 ranges for direct (non-proxied) egress
        ips: Vec<Cidr4>,
        /// allowed hostname suffixes for the http(s) proxy, dot-anchored:
        /// `corp.example.com` allows that host and `*.corp.example.com`
        names: Vec<String>,
    },
}

/// An IPv4 CIDR (`a.b.c.d/prefix`) for the egress IP allowlist.
#[derive(Clone, Copy)]
pub struct Cidr4 {
    net: u32,
    prefix: u8,
}

impl Cidr4 {
    fn parse(s: &str) -> Result<Self> {
        let (addr, prefix) = s.split_once('/').unwrap_or((s, "32"));
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
        })
    }
    fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & mask4(self.prefix)) == self.net
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
    /// => `AllowAll`.
    pub fn new(ips: &[String], names: &[String]) -> Result<Egress> {
        if ips.is_empty() && names.is_empty() {
            return Ok(Egress::AllowAll);
        }
        let ips = ips.iter().map(|s| Cidr4::parse(s)).collect::<Result<_>>()?;
        let names = names
            .iter()
            .map(|s| s.trim_start_matches('.').to_ascii_lowercase())
            .collect();
        Ok(Egress::Allow { ips, names })
    }
    /// Direct (non-proxied) egress: allow only listed IPv4 ranges (IPv6 denied).
    fn allows_ip(&self, ip: IpAddr) -> bool {
        match self {
            Egress::AllowAll => true,
            Egress::Allow { ips, .. } => match ip {
                IpAddr::V4(v4) => ips.iter().any(|c| c.contains(v4)),
                IpAddr::V6(_) => false,
            },
        }
    }
    /// Resolver name check: allow a host equal to or under an allowed suffix.
    fn allows_host(&self, host: &str) -> bool {
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
    policy: Egress,
    gateway: Ipv4Addr,
    pinned: Mutex<HashMap<Ipv4Addr, Instant>>,
}

impl EgressGuard {
    fn new(policy: Egress, gateway: Ipv4Addr) -> Self {
        EgressGuard {
            policy,
            gateway,
            pinned: Mutex::new(HashMap::new()),
        }
    }
    fn restricted(&self) -> bool {
        !matches!(self.policy, Egress::AllowAll)
    }
    /// May the resolver answer this name? (allowed names get forwarded + pinned.)
    fn name_allowed(&self, host: &str) -> bool {
        self.policy.allows_host(host)
    }
    /// Pin the A-records returned for an allowed name for its TTL (+ a small grace),
    /// so the guest's imminent connection to one of them is permitted.
    fn record(&self, ips: &[Ipv4Addr], ttl: u32) {
        if !self.restricted() || ips.is_empty() {
            return;
        }
        let until = Instant::now() + Duration::from_secs(u64::from(ttl).max(30) + 60);
        let mut pinned = self.pinned.lock().unwrap();
        for ip in ips {
            pinned.insert(*ip, until);
        }
    }
    /// May the guest open a direct flow to `dst`? Unrestricted => yes. Otherwise DNS
    /// must go to our resolver (so pinning holds), and the dst must be in the static
    /// allowlist or freshly pinned by an allowed-name lookup.
    fn allows(&self, dst: SocketAddr) -> bool {
        if !self.restricted() {
            return true;
        }
        if dst.port() == DNS_PORT && dst.ip() != IpAddr::V4(self.gateway) {
            return false; // force DNS through the switch
        }
        if self.policy.allows_ip(dst.ip()) {
            return true;
        }
        let IpAddr::V4(v4) = dst.ip() else {
            return false;
        };
        let mut pinned = self.pinned.lock().unwrap();
        match pinned.get(&v4) {
            Some(&until) if until > Instant::now() => true,
            Some(_) => {
                pinned.remove(&v4);
                false
            }
            None => false,
        }
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
    next_idx: u32,
}

struct Switch {
    cfg: Cfg,
    inner: Mutex<Inner>,
    /// IPv4 packets from any VM destined off-subnet -> the shared ipstack
    egress_tx: UnboundedSender<Vec<u8>>,
    next_port: AtomicU32,
    /// fleet name -> IP, answered by the gateway resolver (replaces /etc/hosts)
    hosts: Arc<HashMap<String, Ipv4Addr>>,
    /// upstream resolver (the host's own) for everything else
    upstream: SocketAddr,
    /// egress policy + the DNS-pinned IP set (shared with the ipstack egress tasks)
    egress: Arc<EgressGuard>,
}

pub async fn run(
    listen: &[PathBuf],
    gateway: Ipv4Addr,
    prefix: u8,
    hosts: HashMap<String, Ipv4Addr>,
    egress: Egress,
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
    let guard = Arc::new(EgressGuard::new(egress, gateway));
    let restricted = guard.restricted();
    tokio::spawn(accept_loop(ip_stack, guard.clone()));

    let upstream = host_upstream();
    let sw = Arc::new(Switch {
        cfg: Cfg { gateway, prefix },
        inner: Mutex::new(Inner {
            next_idx: FIRST_LEASE,
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
         resolver: {} fleet name(s), upstream {}; egress: {}",
        listen.len(),
        gateway,
        prefix,
        sw.hosts.len(),
        upstream,
        if restricted {
            "allowlist"
        } else {
            "unrestricted"
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
                    // DNS to the gateway: the resolver answers fleet names and forwards
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

/// Terminate a guest TCP flow and splice it to a host connection to its original
/// destination (egress through the host's own socket).
async fn proxy_tcp(mut guest: ipstack::IpStackTcpStream, egress: Arc<EgressGuard>) {
    let dst = guest.peer_addr();
    if !egress.allows(dst) {
        eprintln!("switch: egress denied (tcp) {dst}");
        return;
    }
    match TcpStream::connect(dst).await {
        Ok(mut host) => {
            let _ = tokio::io::copy_bidirectional(&mut guest, &mut host).await;
        }
        Err(e) => eprintln!("switch: tcp connect {dst}: {e}"),
    }
}

/// Relay a guest UDP flow (e.g. DNS) to its destination via a host socket. ipstack
/// closes the stream after its udp_timeout, ending the task.
async fn proxy_udp(mut guest: ipstack::IpStackUdpStream, egress: Arc<EgressGuard>) {
    let dst = guest.peer_addr();
    if !egress.allows(dst) {
        eprintln!("switch: egress denied (udp) {dst}");
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

/// Resolve a guest DNS query and send the response back to it: fleet names are
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
    let response = if let Some(r) = local_answer(&query, &hosts) {
        Some(r) // fleet name: on-subnet, not subject to egress pinning
    } else if let Some((name, _qtype, qend)) = parse_question(&query) {
        if egress.name_allowed(&name) {
            // forward, then pin the A-records so the guest's connection is allowed
            let resp = forward_upstream(&query, upstream).await;
            if let Some(r) = &resp {
                let (ips, ttl) = parse_a_records(r);
                egress.record(&ips, ttl);
            }
            resp
        } else {
            eprintln!("switch: dns refused (egress allowlist): {name}");
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

/// If the query's name is a known fleet name, build the answer locally (an A record
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

/// A stable per-MAC lease from the subnet pool (same MAC always gets the same IP).
fn alloc_lease(inner: &mut Inner, cfg: &Cfg, mac: Mac) -> Option<Ipv4Addr> {
    if let Some(ip) = inner.leases.get(&mac).copied() {
        return Some(ip);
    }
    let ip = nth_host(cfg.gateway, cfg.prefix, inner.next_idx).ok()?;
    inner.next_idx += 1;
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
    fn egress_allowlist() {
        let e = Egress::new(
            &["10.0.0.0/8".into(), "192.168.231.1/32".into()],
            &["corp.example.com".into(), ".github.com".into()],
        )
        .unwrap();
        // direct-egress IP allowlist
        assert!(e.allows_ip("10.1.2.3".parse().unwrap()));
        assert!(e.allows_ip("192.168.231.1".parse().unwrap()));
        assert!(!e.allows_ip("8.8.8.8".parse().unwrap()));
        assert!(!e.allows_ip("::1".parse().unwrap())); // v6 denied under an allowlist
        // proxy host allowlist (suffix-anchored)
        assert!(e.allows_host("gitlab.corp.example.com"));
        assert!(e.allows_host("corp.example.com"));
        assert!(e.allows_host("api.github.com"));
        assert!(!e.allows_host("evil.com"));
        assert!(!e.allows_host("corp.example.com.evil.com")); // not a real suffix match
        // no rules => allow all (the dev fleet default)
        assert!(matches!(Egress::new(&[], &[]).unwrap(), Egress::AllowAll));
        let any = Egress::default();
        assert!(any.allows_ip("8.8.8.8".parse().unwrap()) && any.allows_host("evil.com"));
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
        let g = EgressGuard::new(Egress::new(&[], &["corp.example.com".into()]).unwrap(), gw);
        let corp: SocketAddr = "10.20.30.40:443".parse().unwrap();
        assert!(!g.allows(corp)); // not resolved yet
        g.record(&[Ipv4Addr::new(10, 20, 30, 40)], 300); // resolver pinned it
        assert!(g.allows(corp)); // now allowed
        assert!(!g.allows("8.8.8.8:443".parse().unwrap())); // unrelated dst
        assert!(!g.allows("8.8.8.8:53".parse().unwrap())); // DNS forced through the switch
        // unrestricted guard allows anything
        let any = EgressGuard::new(Egress::AllowAll, gw);
        assert!(any.allows("8.8.8.8:443".parse().unwrap()));
        assert!(any.allows("8.8.8.8:53".parse().unwrap()));
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
                Egress::AllowAll,
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
    fn resolver_answers_fleet_a_records() {
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
}
