//! Tap pool allocation (net.mode = "pool"): the host pre-creates `count` taps
//! `<tap_prefix>0..N` owned by the runner user, all enslaved (isolated) to a
//! NATed bridge. Each job leases one tap — and the deterministic IP/MAC that go
//! with its index — through an exclusive lockfile; the lease is released at
//! cleanup. Locks live under the jobs dir (tmpfs on the hosts) so a host reboot
//! clears them together with the taps' users.

use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};

use crate::jobctx::JobCtx;

#[derive(Debug, PartialEq)]
pub struct Lease {
    pub tap: String,
    pub ip: String,
    pub prefix: u8,
    pub gw: String,
    pub dns: String,
    pub mac: String,
}

/// First host index handed to VMs: .1 is the bridge/gateway, leave headroom
/// for other static uses of the subnet.
const FIRST_HOST: u32 = 16;

pub fn allocate(ctx: &JobCtx) -> Result<Lease> {
    allocate_with(ctx, |tap| {
        PathBuf::from("/sys/class/net").join(tap).exists()
    })
}

fn allocate_with(ctx: &JobCtx, tap_exists: impl Fn(&str) -> bool) -> Result<Lease> {
    let net = &ctx.cfg.net;
    let (base, prefix) = parse_subnet(&net.subnet)?;
    if net.count + FIRST_HOST > 254 {
        bail!("net.count {} does not fit in {}", net.count, net.subnet);
    }

    let locks = locks_dir(ctx);
    std::fs::create_dir_all(&locks).with_context(|| format!("creating {}", locks.display()))?;

    let mut pool_seen = false;
    for i in 0..net.count {
        let lease = pool_entry(net, base, prefix, i);
        if !tap_exists(&lease.tap) {
            continue;
        }
        pool_seen = true;
        let lock = locks.join(format!("{}.lock", lease.tap));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock)
        {
            Ok(mut f) => {
                use std::io::Write;
                f.write_all(ctx.job_id.as_bytes())?;
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                // a leftover lock of THIS job (crashed earlier attempt) is ours
                if std::fs::read_to_string(&lock).unwrap_or_default() != ctx.job_id {
                    continue;
                }
            }
            Err(e) => return Err(e).with_context(|| format!("creating {}", lock.display())),
        }
        std::fs::write(ctx.net_lease(), &lease.tap)?;
        return Ok(lease);
    }
    if pool_seen {
        bail!(
            "no free tap in the pool ({}0..{}; raise net.count or lower the runner limit)",
            net.tap_prefix,
            net.count
        );
    }
    bail!(
        "tap pool missing ({}0..{} not found — is microvm-taps.service up?)",
        net.tap_prefix,
        net.count
    );
}

/// Release the tap leased by this job, if any. Idempotent: no lease file, or a
/// lock already taken over by another job, are fine.
pub fn release(ctx: &JobCtx) {
    release_lease(&locks_dir(ctx), &ctx.job_dir, &ctx.job_id);
}

/// [`release`] for job `job_id` in `job_dir`, its locks in `locks`: what a node's reset does
/// for the job dirs whose cleanup never ran.
pub fn release_lease(locks: &Path, job_dir: &Path, job_id: &str) {
    let lease = job_dir.join("net.lease");
    let Ok(tap) = std::fs::read_to_string(&lease) else {
        return;
    };
    // A tap name that is not a single path component names no lock of ours.
    let tap = tap.trim();
    let lock = locks.join(format!("{tap}.lock"));
    if !tap.is_empty()
        && !tap.contains('/')
        && !tap.contains("..")
        && std::fs::read_to_string(&lock).unwrap_or_default() == job_id
    {
        let _ = std::fs::remove_file(&lock);
    }
    let _ = std::fs::remove_file(&lease);
}

fn locks_dir(ctx: &JobCtx) -> PathBuf {
    ctx.cfg.state_dir().join("jobs").join(".net")
}

fn pool_entry(net: &crate::config::Net, base: Ipv4Addr, prefix: u8, i: u32) -> Lease {
    let octets = base.octets();
    let host = FIRST_HOST + i;
    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], host as u8);
    let gw = if net.gw.is_empty() {
        Ipv4Addr::new(octets[0], octets[1], octets[2], 1).to_string()
    } else {
        net.gw.clone()
    };
    let dns = if net.dns.is_empty() {
        gw.clone()
    } else {
        net.dns.clone()
    };
    Lease {
        tap: format!("{}{}", net.tap_prefix, i),
        ip: ip.to_string(),
        prefix,
        gw,
        dns,
        mac: format!("52:54:00:c1:{:02x}:{:02x}", (i >> 8) & 0xff, i & 0xff),
    }
}

/// Derive the per-job switch addresses from `net.subnet` (net.mode = "switch"):
/// the gateway is `.1` (DHCP/DNS/router, as in pool mode) and the single job VM
/// is `.2`. Reuses the pool subnet parser (a.b.c.0/17..24). Unlike pool mode the
/// subnet is internal to the VM (a userspace vsock LAN), so it never touches the
/// host network and need not match any host bridge.
pub fn switch_addrs(subnet: &str) -> Result<(Ipv4Addr, u8, Ipv4Addr)> {
    let (base, prefix) = parse_subnet(subnet)?;
    let o = base.octets();
    let gateway = Ipv4Addr::new(o[0], o[1], o[2], 1);
    let guest = Ipv4Addr::new(o[0], o[1], o[2], 2);
    Ok((gateway, prefix, guest))
}

/// "a.b.c.0/p" — only /17..=/24 subnets (hosts within the last octet, which is
/// all the pool addressing scheme supports).
fn parse_subnet(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (addr, prefix) = s
        .split_once('/')
        .with_context(|| format!("invalid net.subnet {s:?} (want a.b.c.0/p)"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("invalid net.subnet address {addr:?}"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid net.subnet prefix {prefix:?}"))?;
    if !(17..=24).contains(&prefix) || addr.octets()[3] != 0 {
        bail!("net.subnet {s:?} unsupported (want a.b.c.0 with /17../24)");
    }
    Ok((addr, prefix))
}

/// A guest NIC on a caller-provided host tap (`vk run --tap`, compose `x-virtkit.tap`): eth0
/// is a virtio-net device on the tap, so the guest sits on whatever LAN the tap is bridged to.
/// A guest that also has switch ports (`--net`, compose) gets them as eth1 upward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TapNet {
    pub tap: String,
    pub mac: String,
    /// static `(address, prefix, gateway, nameservers)`; `None` = DHCP
    pub addr: Option<(Ipv4Addr, u8, Ipv4Addr, Vec<Ipv4Addr>)>,
}

impl TapNet {
    /// Validate a tap spec. Errors name the field (`mac`, `ip`, `gw`, `dns`); the caller adds
    /// which flag or compose key it came from.
    pub fn new(
        tap: &str,
        mac: Option<&str>,
        ip: Option<&str>,
        gw: Option<Ipv4Addr>,
        dns: &[Ipv4Addr],
    ) -> Result<Self> {
        if !valid_ifname(tap) {
            bail!("{tap:?} is not an interface name");
        }
        let mac = match mac {
            Some(m) => {
                let bytes = crate::switch::parse_mac(m)
                    .with_context(|| format!("mac {m:?}: not a MAC address"))?;
                if bytes[0] & 1 != 0 {
                    bail!("mac {m}: a multicast address");
                }
                // virtio-net swaps an all-zero config MAC for a random one.
                if bytes == [0; 6] {
                    bail!("mac {m}: the zero address");
                }
                m.to_ascii_lowercase()
            }
            None => default_mac(tap, &host_mac_seed()?),
        };
        let addr = match ip {
            Some(cidr) => {
                let (ip, prefix) = cidr
                    .split_once('/')
                    .with_context(|| format!("ip {cidr:?}: want A.B.C.D/PREFIX"))?;
                let ip: Ipv4Addr = ip
                    .parse()
                    .with_context(|| format!("ip {cidr:?}: bad address"))?;
                let prefix: u8 = prefix
                    .parse()
                    .ok()
                    .filter(|p| (1..=32).contains(p))
                    .with_context(|| format!("ip {cidr:?}: bad prefix"))?;
                let gw = gw.context("a static ip needs a gateway (gw)")?;
                ensure!(
                    gw != ip && in_net(gw, ip, prefix),
                    "gw {gw} is not on {cidr}"
                );
                // The switch resolver is off the guest's route, and the image's resolv.conf
                // is rarely one this LAN answers.
                ensure!(!dns.is_empty(), "a static ip needs a nameserver (dns)");
                Some((ip, prefix, gw, dns.to_vec()))
            }
            None => {
                if gw.is_some() || !dns.is_empty() {
                    bail!("gw and dns go with a static ip");
                }
                None
            }
        };
        Ok(TapNet {
            tap: tap.to_string(),
            mac,
            addr,
        })
    }

    /// The agent's network fragment for a guest whose eth0 is this tap. `switch` is the
    /// guest's switch addresses (eth1 upward, all on `prefix`) when it also has switch ports:
    /// they are addressed without a route, so egress and DNS follow the tap's LAN. `hosts`
    /// (name, ip) pins the switch LAN's names in `/etc/hosts`, since the tap LAN's resolver
    /// does not know them.
    pub fn cmdline(&self, switch: &[Ipv4Addr], prefix: u8, hosts: &[(String, String)]) -> String {
        let mut out = String::from(" VIRTKIT_NET_VIRTIO=1 net.ifnames=0 biosdevname=0");
        match &self.addr {
            Some((ip, prefix, gw, dns)) => {
                let dns: Vec<String> = dns.iter().map(ToString::to_string).collect();
                out.push_str(&format!(
                    " VIRTKIT_VM_IP={ip}/{prefix} VIRTKIT_VM_GW={gw} VIRTKIT_VM_DNS={}",
                    dns.join(",")
                ));
            }
            None => out.push_str(" VIRTKIT_NET_DHCP=1"),
        }
        if !switch.is_empty() {
            let specs: Vec<String> = switch.iter().map(|ip| format!("{ip}/{prefix}")).collect();
            out.push_str(&format!(" VIRTKIT_NET_EXTRA_IPS={}", specs.join(",")));
        }
        if !hosts.is_empty() {
            let pairs: Vec<String> = hosts.iter().map(|(n, ip)| format!("{n}={ip}")).collect();
            out.push_str(&format!(" VIRTKIT_HOSTS={}", pairs.join(",")));
        }
        out
    }

    /// Refuse a static address whose network overlaps `subnet`, the switch LAN of the guest's
    /// eth1 upward: both NICs would hold a connected route into the overlap. A DHCP address
    /// is unknown until boot, so it is not checked.
    pub fn refuse_switch_overlap(&self, subnet: &str) -> Result<()> {
        let Some((ip, prefix, ..)) = &self.addr else {
            return Ok(());
        };
        let (base, sw_prefix) = parse_subnet(subnet)?;
        if in_net(*ip, base, (*prefix).min(sw_prefix)) {
            bail!("{ip}/{prefix} overlaps the switch LAN {subnet} the guest's other NICs sit on");
        }
        Ok(())
    }
}

/// Whether `name` fits IFNAMSIZ with its NUL and uses only `[A-Za-z0-9._-]`. "." and ".."
/// are no interface name, and would walk sysfs.
fn valid_ifname(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Whether `a` and `b` share their first `prefix` bits.
fn in_net(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(a) & mask == u32::from(b) & mask
}

/// Early diagnostic only: [`crate::libkrun_sys::keep`] attaches again in the VMM and holds the
/// descriptor; a successful probe reserves nothing.
pub fn probe_tap(tap: &str) -> Result<()> {
    attach_tap(tap).map(drop)
}

/// Open an existing single-queue tap, keeping it claimed until the returned fd is dropped.
/// The VMM consumes this descriptor rather than opening the name again at NIC activation.
pub fn attach_tap(tap: &str) -> Result<OwnedFd> {
    ensure!(valid_ifname(tap), "{tap:?} is not an interface name");
    // Diagnose a missing device before trying the attachment. The ioctl
    // itself runs without CAP_NET_ADMIN, so removal after this check cannot create a tap.
    let name = std::ffi::CString::new(tap)?;
    // SAFETY: name is NUL-terminated and valid for the call.
    if unsafe { libc::if_nametoindex(name.as_ptr()) } == 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.raw_os_error(), Some(libc::ENODEV | libc::ENXIO)) {
            bail!("tap {tap} does not exist (create it: ip tuntap add {tap} mode tap user $USER)");
        }
        return Err(err).with_context(|| format!("looking up tap {tap}"));
    }
    // Optional diagnostics only; the ioctl enforces ownership and the single-queue mode.
    let sys = Path::new("/sys/class/net").join(tap);
    let id = |f: &str| -> Option<u32> {
        let s = std::fs::read_to_string(sys.join(f)).ok()?;
        s.trim().parse().ok()
    };
    let diag = AttachDiag {
        owner: id("owner"),
        group: id("group"),
        // Every tun/tap device has the attribute, so its absence means some other kind.
        tun_flags: match std::fs::read_to_string(sys.join("tun_flags")) {
            Ok(s) => u32::from_str_radix(s.trim().trim_start_matches("0x"), 16)
                .ok()
                .map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && sys.is_dir() => Some(None),
            Err(_) => None,
        },
        // SAFETY: geteuid(2) has no preconditions and cannot fail.
        euid: unsafe { libc::geteuid() },
    };
    let tap_name = tap.to_string();
    let attached = std::thread::Builder::new()
        .name("tap-attach".into())
        .spawn(move || -> Result<std::io::Result<OwnedFd>> {
            drop_net_admin().context("dropping CAP_NET_ADMIN before attaching the tap")?;
            Ok(try_attach(&tap_name))
        })
        .context("starting tap attachment thread")?
        .join()
        .map_err(|_| anyhow::anyhow!("tap attachment thread panicked"))??;
    attached.map_err(|e| attach_error(tap, &e, &diag))
}

/// Drop only this thread's effective CAP_NET_ADMIN. Linux allows opening an existing tap
/// by its owner/group without it, but requires it to create a missing device. The thread
/// exits after the ioctl, leaving the caller's credentials untouched.
fn drop_net_admin() -> std::io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[derive(Clone, Copy, Default)]
    #[repr(C)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // Linux capability ABI v3 uses two 32-bit words per set. pid 0 means this thread.
    let mut header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [Data::default(); 2];
    // SAFETY: header and data match the Linux capget/capset ABI and live for both calls.
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    const NET_ADMIN: u32 = 1 << 12;
    if data[0].effective & NET_ADMIN != 0 {
        data[0].effective &= !NET_ADMIN;
        // SAFETY: same ABI as above; the raw syscall changes only the calling thread.
        if unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Attach with libkrun's flags and no privilege to create a device. Called only on the
/// disposable attachment thread, after dropping CAP_NET_ADMIN.
fn try_attach(tap: &str) -> std::io::Result<OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: the path is a NUL-terminated literal.
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened and is owned by nothing else.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: ifreq is plain old data; all-zero is a valid value.
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    // `attach_tap` bounds the name below IFNAMSIZ, so the zeroed tail keeps it terminated.
    for (dst, &b) in req.ifr_name.iter_mut().zip(tap.as_bytes()) {
        *dst = b as libc::c_char;
    }
    req.ifr_ifru.ifru_flags =
        (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;
    // SAFETY: TUNSETIFF reads and writes an ifreq, which `req` is, for the call's duration.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut req) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Validate the setup libkrun applies at activation, before any guest starts. vk offers
    // no offloads and the backend uses a 12-byte virtio-net header.
    let header_size: libc::c_int = 12;
    // SAFETY: both ioctls act on the attached tun fd; the header size points to an int.
    if unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETVNETHDRSZ, &header_size) } < 0
        || unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETOFFLOAD, 0 as libc::c_ulong) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// What sysfs and the caller's credentials say about a tap, read only to explain a failed
/// attachment.
struct AttachDiag {
    /// The tap's `owner`/`group`; `None` when unset or unreadable.
    owner: Option<u32>,
    group: Option<u32>,
    /// `Some(None)` when the device has no `tun_flags`, so is no tun/tap device; `None` when
    /// unknown.
    tun_flags: Option<Option<u32>>,
    euid: u32,
}

/// What a failed [`try_attach`] means for `tap`.
fn attach_error(tap: &str, err: &std::io::Error, diag: &AttachDiag) -> anyhow::Error {
    const IFF_TAP: u32 = libc::IFF_TAP as u32;
    const IFF_MULTI_QUEUE: u32 = libc::IFF_MULTI_QUEUE as u32;
    let euid = diag.euid;
    match err.raw_os_error() {
        Some(libc::EBUSY) => anyhow::anyhow!("tap {tap} is in use by another VM"),
        Some(libc::EINVAL) => match diag.tun_flags {
            Some(None) => anyhow::anyhow!("{tap} is not a tap device"),
            Some(Some(f)) if f & IFF_TAP == 0 => {
                anyhow::anyhow!("{tap} is a tun device, not a tap")
            }
            Some(Some(f)) if f & IFF_MULTI_QUEUE != 0 => {
                anyhow::anyhow!("tap {tap} is multi_queue")
            }
            _ => anyhow::anyhow!("tap {tap} is multi_queue or not a tap"),
        },
        Some(libc::EPERM) => match (diag.owner, diag.group) {
            (Some(o), _) if o != euid => anyhow::anyhow!(
                "tap {tap} is owned by uid {o}, not {euid} (recreate it: ip tuntap add {tap} \
                 mode tap user $USER)"
            ),
            (_, Some(g)) => {
                anyhow::anyhow!("tap {tap} is restricted to gid {g}, which this user is not in")
            }
            _ => anyhow::anyhow!("tap {tap}: attaching it is not permitted"),
        },
        _ => anyhow::anyhow!("tap {tap}: attaching it: {err}"),
    }
}

/// Refuse a `--tap`/`x-virtkit.tap` that names a tap the CI executor uses (`net.mode = tap`, or
/// a `pool` tap): taking an idle one would fail the next job to lease it.
pub fn refuse_runner_tap(net: &crate::config::Net, tap: &str) -> Result<()> {
    let runner_owns = match net.mode.as_str() {
        "tap" => net.tap == tap,
        "pool" => tap
            .strip_prefix(net.tap_prefix.as_str())
            .and_then(|n| n.parse::<u32>().ok())
            .is_some_and(|i| i < net.count && tap == format!("{}{i}", net.tap_prefix)),
        _ => false,
    };
    if runner_owns {
        bail!(
            "tap {tap} belongs to the CI executor (net.mode = {})",
            net.mode
        );
    }
    Ok(())
}

/// Minimal hosts may have no machine-id. Their boot ID still separates hosts, but an
/// explicit MAC is needed to retain a lease across host reboots in that case.
fn host_mac_seed() -> Result<Vec<u8>> {
    match std::fs::read("/etc/machine-id") {
        Ok(id)
            if id.trim_ascii().len() == 32
                && id.trim_ascii().iter().all(u8::is_ascii_hexdigit)
                && id.trim_ascii().iter().any(|b| *b != b'0') =>
        {
            Ok(id.trim_ascii().to_ascii_lowercase())
        }
        // Missing/uninitialized machine-id is normal in containers and minimal hosts.
        Ok(_) => boot_mac_seed(),
        Err(e) if e.kind() == ErrorKind::NotFound => boot_mac_seed(),
        Err(e) => Err(e).context("reading /etc/machine-id for the tap MAC; set an explicit mac"),
    }
}

fn boot_mac_seed() -> Result<Vec<u8>> {
    let id = std::fs::read("/proc/sys/kernel/random/boot_id")
        .context("reading the host boot ID for the tap MAC; set an explicit mac")?;
    ensure!(
        !id.trim_ascii().is_empty(),
        "empty host boot ID; set an explicit mac"
    );
    Ok(id.trim_ascii().to_vec())
}

/// Locally administered unicast MAC, separated by host as well as tap name. A plain tap
/// name is only host-local: two machines on the same bridge may both use `tap0`.
fn default_mac(tap: &str, host: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"virtkit-tap-mac\0");
    hash.update(host);
    hash.update([0]);
    hash.update(tap.as_bytes());
    let b = hash.finalize();
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        (b[0] & !3) | 2,
        b[1],
        b[2],
        b[3],
        b[4],
        b[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_cfg(dir: &std::path::Path) -> Config {
        Config {
            state_dir: Some(dir.to_path_buf()),
            net: crate::config::Net {
                mode: "pool".into(),
                tap_prefix: "tttap".into(),
                count: 3,
                subnet: "192.168.231.0/24".into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn test_ctx(dir: &std::path::Path, job_id: &str) -> JobCtx {
        let ctx = JobCtx::new_for_job(test_cfg(dir), job_id.into()).unwrap();
        std::fs::create_dir_all(&ctx.job_dir).unwrap();
        ctx
    }

    #[test]
    fn entry_math() {
        let cfg = test_cfg(std::path::Path::new("/unused"));
        let (base, prefix) = parse_subnet(&cfg.net.subnet).unwrap();
        let e = pool_entry(&cfg.net, base, prefix, 2);
        assert_eq!(e.tap, "tttap2");
        assert_eq!(e.ip, "192.168.231.18");
        assert_eq!(e.prefix, 24);
        assert_eq!(e.gw, "192.168.231.1");
        assert_eq!(e.dns, "192.168.231.1");
        assert_eq!(e.mac, "52:54:00:c1:00:02");
    }

    #[test]
    fn switch_addrs_derives_gateway_and_guest() {
        let (gw, prefix, guest) = switch_addrs("192.168.127.0/24").unwrap();
        assert_eq!(gw, Ipv4Addr::new(192, 168, 127, 1));
        assert_eq!(prefix, 24);
        assert_eq!(guest, Ipv4Addr::new(192, 168, 127, 2));
        // same parser/validation as the pool subnet
        assert!(switch_addrs("10.0.0.1/24").is_err());
        assert!(switch_addrs("10.0.0.0/25").is_err());
    }

    #[test]
    fn parse_subnet_rejects() {
        assert!(parse_subnet("10.0.0.0/16").is_err()); // host bits beyond last octet
        assert!(parse_subnet("10.0.0.1/24").is_err());
        assert!(parse_subnet("10.0.0.0").is_err());
        assert!(parse_subnet("10.0.0.0/25").is_err());
    }

    #[test]
    fn allocate_release_cycle() {
        let dir = std::env::temp_dir().join(format!("ch-net-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ctx = test_ctx(&dir, "42");

        // only tap 1 "exists": allocation must pick it, twice in a row (reuse
        // by the same job), and a second job must find the pool full
        let lease = allocate_with(&ctx, |t| t == "tttap1").unwrap();
        assert_eq!(lease.tap, "tttap1");
        let again = allocate_with(&ctx, |t| t == "tttap1").unwrap();
        assert_eq!(again.tap, "tttap1");

        let ctx2 = test_ctx(&dir, "43");
        let err = allocate_with(&ctx2, |t| t == "tttap1").unwrap_err();
        assert!(err.to_string().contains("no free tap"), "{err}");

        release(&ctx);
        let lease2 = allocate_with(&ctx2, |t| t == "tttap1").unwrap();
        assert_eq!(lease2.tap, "tttap1");

        // release is idempotent and never steals another job's lock
        release(&ctx);
        let err = allocate_with(&ctx, |t| t == "tttap1").unwrap_err();
        assert!(err.to_string().contains("no free tap"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tap_net_static_and_dhcp_cmdlines() {
        let gw = "10.10.132.1".parse().unwrap();
        let dns = ["10.10.0.53".parse().unwrap(), "10.10.0.54".parse().unwrap()];
        let t = TapNet::new(
            "vkdev0",
            Some("BC:24:11:00:27:D9"),
            Some("10.10.132.201/23"),
            Some(gw),
            &dns,
        )
        .unwrap();
        assert_eq!(t.mac, "bc:24:11:00:27:d9");
        assert_eq!(
            t.cmdline(&[], 24, &[]),
            " VIRTKIT_NET_VIRTIO=1 net.ifnames=0 biosdevname=0 \
             VIRTKIT_VM_IP=10.10.132.201/23 VIRTKIT_VM_GW=10.10.132.1 \
             VIRTKIT_VM_DNS=10.10.0.53,10.10.0.54"
        );
        // No address: DHCP, and a MAC that is stable, unicast and locally administered.
        let d = TapNet::new("vkdev0", None, None, None, &[]).unwrap();
        assert!(d.cmdline(&[], 24, &[]).ends_with(" VIRTKIT_NET_DHCP=1"));
        assert_eq!(
            d.mac,
            TapNet::new("vkdev0", None, None, None, &[]).unwrap().mac
        );
        assert_ne!(
            d.mac,
            TapNet::new("vkdev1", None, None, None, &[]).unwrap().mac
        );
        assert_eq!(crate::switch::parse_mac(&d.mac).unwrap()[0] & 3, 2);
        assert!(crate::switch::parse_mac(&d.mac).is_some());
    }

    #[test]
    fn default_tap_mac_separates_hosts_and_names() {
        let first = default_mac("tap0", b"host-a");
        assert_eq!(first, default_mac("tap0", b"host-a"));
        assert_ne!(first, default_mac("tap0", b"host-b"));
        assert_ne!(first, default_mac("tap1", b"host-a"));
        assert_eq!(crate::switch::parse_mac(&first).unwrap()[0] & 3, 2);
    }

    #[test]
    fn tap_attach_errors_name_the_cause() {
        let diag = |owner, group, tun_flags| AttachDiag {
            owner,
            group,
            tun_flags,
            euid: 1000,
        };
        let msg = |errno, d: AttachDiag| {
            attach_error("vk0", &std::io::Error::from_raw_os_error(errno), &d).to_string()
        };
        let tap = (libc::IFF_TAP | libc::IFF_NO_PI) as u32;
        let plain = || diag(None, None, Some(Some(tap)));
        assert_eq!(msg(libc::EBUSY, plain()), "tap vk0 is in use by another VM");
        assert_eq!(
            msg(libc::EINVAL, diag(None, None, Some(None))),
            "vk0 is not a tap device"
        );
        assert_eq!(
            msg(
                libc::EINVAL,
                diag(None, None, Some(Some(libc::IFF_TUN as u32)))
            ),
            "vk0 is a tun device, not a tap"
        );
        let multi = tap | libc::IFF_MULTI_QUEUE as u32;
        assert_eq!(
            msg(libc::EINVAL, diag(None, None, Some(Some(multi)))),
            "tap vk0 is multi_queue"
        );
        assert_eq!(
            msg(libc::EINVAL, diag(None, None, None)),
            "tap vk0 is multi_queue or not a tap"
        );
        assert!(
            msg(libc::EPERM, diag(Some(0), None, Some(Some(tap))))
                .starts_with("tap vk0 is owned by uid 0, not 1000")
        );
        assert_eq!(
            msg(libc::EPERM, diag(Some(1000), Some(50), Some(Some(tap)))),
            "tap vk0 is restricted to gid 50, which this user is not in"
        );
        assert_eq!(
            msg(libc::EPERM, plain()),
            "tap vk0: attaching it is not permitted"
        );
        assert!(msg(libc::EACCES, plain()).starts_with("tap vk0: attaching it: "));
    }

    #[test]
    #[ignore = "requires a private network namespace and /dev/net/tun"]
    fn tap_attachment_retains_queue_and_never_creates_devices() {
        use std::os::fd::AsRawFd;
        // Isolate every test device from the host, including on assertion failure. A new
        // thread can unshare its network namespace without changing the test runner's.
        std::thread::spawn(|| {
            // SAFETY: unshare affects only this disposable thread's network namespace.
            assert_eq!(
                unsafe { libc::unshare(libc::CLONE_NEWNET) },
                0,
                "unshare: {}",
                std::io::Error::last_os_error()
            );
            let create = |name: &str, flags: libc::c_short, owner: Option<u32>| {
                let fd = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/net/tun")
                    .unwrap();
                // SAFETY: ifreq is plain data, zeroed then filled within its name buffer.
                let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
                for (dst, b) in req.ifr_name.iter_mut().zip(name.bytes()) {
                    *dst = b as libc::c_char;
                }
                req.ifr_ifru.ifru_flags = flags;
                // SAFETY: the ioctls receive the required ifreq pointer or integer value.
                assert_eq!(
                    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut req) },
                    0
                );
                assert_eq!(
                    unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETPERSIST, 1) },
                    0
                );
                if let Some(owner) = owner {
                    assert_eq!(
                        unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETOWNER, owner) },
                        0
                    );
                }
            };
            let flags = (libc::IFF_TAP | libc::IFF_NO_PI | libc::IFF_VNET_HDR) as libc::c_short;
            create("vkclaim", flags, None);
            let fd = attach_tap("vkclaim").unwrap();
            assert!(
                attach_tap("vkclaim")
                    .unwrap_err()
                    .to_string()
                    .contains("in use")
            );
            // libkrun holds the same queue after the keeper's original closes. Releasing
            // both lets a subsequent boot claim it again.
            let duplicate = fd.try_clone().unwrap();
            let nic =
                krun::NetDevice::new_tap_fd("eth0", duplicate, &[2, 0, 0, 0, 0, 1], 0).unwrap();
            drop(fd);
            assert!(attach_tap("vkclaim").is_err());
            drop(nic);
            drop(attach_tap("vkclaim").unwrap());

            create(
                "vkmulti",
                flags | libc::IFF_MULTI_QUEUE as libc::c_short,
                None,
            );
            assert!(
                attach_tap("vkmulti")
                    .unwrap_err()
                    .to_string()
                    .contains("multi_queue")
            );
            // Even a privileged caller must satisfy the device's ownership rules. sysfs still
            // shows the host's namespace, so the owner diagnostic is unavailable here.
            create("vkother", flags, Some(424242));
            assert!(attach_tap("vkother").is_err());
            assert!(attach_tap("lo").is_err());
            assert!(
                attach_tap("vkmissing")
                    .unwrap_err()
                    .to_string()
                    .contains("does not exist")
            );

            // Exercise the race after the existence check: with no device by this name,
            // the ioctl must fail rather than create one, even when vk was started as root.
            drop_net_admin().unwrap();
            assert_eq!(
                try_attach("vkmissing").unwrap_err().raw_os_error(),
                Some(libc::EPERM)
            );
            // SAFETY: a valid, terminated interface name.
            assert_eq!(unsafe { libc::if_nametoindex(c"vkmissing".as_ptr()) }, 0);
        })
        .join()
        .unwrap();
    }

    #[test]
    fn tap_net_moves_switch_ports_after_eth0_and_pins_their_names() {
        let t = TapNet::new(
            "vkdev0",
            None,
            Some("10.0.0.5/24"),
            Some("10.0.0.1".parse().unwrap()),
            &["10.0.0.53".parse().unwrap()],
        )
        .unwrap();
        let switch = [
            "192.168.127.2".parse().unwrap(),
            "192.168.127.250".parse().unwrap(),
        ];
        let hosts = [
            ("db".to_string(), "192.168.127.3".to_string()),
            ("web".to_string(), "192.168.127.4".to_string()),
        ];
        assert_eq!(
            t.cmdline(&switch, 24, &hosts),
            " VIRTKIT_NET_VIRTIO=1 net.ifnames=0 biosdevname=0 \
             VIRTKIT_VM_IP=10.0.0.5/24 VIRTKIT_VM_GW=10.0.0.1 VIRTKIT_VM_DNS=10.0.0.53 \
             VIRTKIT_NET_EXTRA_IPS=192.168.127.2/24,192.168.127.250/24 \
             VIRTKIT_HOSTS=db=192.168.127.3,web=192.168.127.4"
        );
    }

    #[test]
    fn runner_taps_are_refused() {
        let mut net = crate::config::Net {
            mode: "pool".into(),
            tap_prefix: "civtap".into(),
            count: 4,
            ..Default::default()
        };
        assert!(refuse_runner_tap(&net, "civtap3").is_err());
        assert!(refuse_runner_tap(&net, "civtap4").is_ok());
        assert!(refuse_runner_tap(&net, "civtap03").is_ok());
        assert!(refuse_runner_tap(&net, "vkdev0").is_ok());
        net.mode = "tap".into();
        net.tap = "citap".into();
        assert!(refuse_runner_tap(&net, "citap").is_err());
        assert!(refuse_runner_tap(&net, "civtap3").is_ok());
        net.mode = "switch".into();
        assert!(refuse_runner_tap(&net, "citap").is_ok());
    }

    #[test]
    fn tap_net_refuses_bad_specs() {
        let gw = Some("10.0.0.1".parse().unwrap());
        let dns = ["10.0.0.53".parse().unwrap()];
        let err = |tap: &str, mac: Option<&str>, ip: Option<&str>, gw, dns: &[Ipv4Addr]| {
            format!("{:#}", TapNet::new(tap, mac, ip, gw, dns).unwrap_err())
        };
        assert!(err("", None, None, None, &[]).contains("interface name"));
        assert!(err("a-very-long-tapname", None, None, None, &[]).contains("interface name"));
        assert!(err("tap 0", None, None, None, &[]).contains("interface name"));
        assert!(err(".", None, None, None, &[]).contains("interface name"));
        assert!(err("..", None, None, None, &[]).contains("interface name"));
        assert!(err("tap0", Some("00:00:00:00:00:00"), None, None, &[]).contains("zero"));
        assert!(err("tap0", Some("zz:00:00:00:00:00"), None, None, &[]).contains("MAC"));
        assert!(err("tap0", Some("01:00:00:00:00:01"), None, None, &[]).contains("multicast"));
        assert!(err("tap0", None, Some("10.0.0.2"), gw, &[]).contains("A.B.C.D/PREFIX"));
        assert!(err("tap0", None, Some("10.0.0.2/33"), gw, &[]).contains("prefix"));
        assert!(err("tap0", None, Some("10.0.0.x/24"), gw, &[]).contains("address"));
        assert!(err("tap0", None, Some("10.0.0.2/24"), None, &[]).contains("gateway"));
        assert!(err("tap0", None, Some("10.0.0.2/24"), gw, &[]).contains("nameserver"));
        let off_net = Some("10.0.1.1".parse().unwrap());
        assert!(err("tap0", None, Some("10.0.0.2/24"), off_net, &dns).contains("not on"));
        assert!(err("tap0", None, Some("10.0.0.1/24"), gw, &dns).contains("not on"));
        // The gateway may sit anywhere inside a wider prefix.
        assert!(TapNet::new("tap0", None, Some("10.0.0.2/23"), off_net, &dns).is_ok());
        assert!(err("tap0", None, None, gw, &[]).contains("static ip"));
        assert!(err("tap0", None, None, None, &dns).contains("static ip"));
    }

    #[test]
    fn a_static_tap_address_must_clear_the_switch_lan() {
        let tap = |cidr: &str, gw: &str| {
            TapNet::new(
                "tap0",
                None,
                Some(cidr),
                Some(gw.parse().unwrap()),
                &["1.1.1.1".parse().unwrap()],
            )
            .unwrap()
        };
        let sw = "192.168.127.0/24";
        assert!(
            tap("192.168.127.9/24", "192.168.127.1")
                .refuse_switch_overlap(sw)
                .is_err()
        );
        assert!(
            tap("192.168.0.9/16", "192.168.0.1")
                .refuse_switch_overlap(sw)
                .is_err()
        );
        assert!(
            tap("192.168.126.9/24", "192.168.126.1")
                .refuse_switch_overlap(sw)
                .is_ok()
        );
        assert!(
            tap("10.0.0.5/8", "10.0.0.1")
                .refuse_switch_overlap(sw)
                .is_ok()
        );
        let dhcp = TapNet::new("tap0", None, None, None, &[]).unwrap();
        assert!(dhcp.refuse_switch_overlap(sw).is_ok());
    }

    #[test]
    fn a_missing_tap_is_reported_without_opening_it() {
        let e = probe_tap("vknosuchtap0").unwrap_err();
        assert!(format!("{e:#}").contains("does not exist"), "{e:#}");
    }
}
