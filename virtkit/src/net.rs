//! Tap pool allocation (net.mode = "pool"): the host pre-creates `count` taps
//! `<tap_prefix>0..N` owned by the runner user, all enslaved (isolated) to a
//! NATed bridge. Each job leases one tap — and the deterministic IP/MAC that go
//! with its index — through an exclusive lockfile; the lease is released at
//! cleanup. Locks live under the jobs dir (tmpfs on the hosts) so a host reboot
//! clears them together with the taps' users.

use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

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
    let Ok(tap) = std::fs::read_to_string(ctx.net_lease()) else {
        return;
    };
    let lock = locks_dir(ctx).join(format!("{}.lock", tap.trim()));
    if std::fs::read_to_string(&lock).unwrap_or_default() == ctx.job_id {
        let _ = std::fs::remove_file(&lock);
    }
    let _ = std::fs::remove_file(ctx.net_lease());
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
}
