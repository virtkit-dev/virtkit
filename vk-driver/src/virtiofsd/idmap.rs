//! Soft UID/GID mapping for the bundled virtio-fs daemon.
//!
//! Unprivileged translation of ownership between guest and host, compatible with
//! virtiofsd's `--uid-map`/`--gid-map` internal-idmap syntax (`type:args…`):
//!
//!   map:G:H:count           bidirectional 1:1 range map (guest G.. <-> host H..)
//!   guest:G:H:count         guest->host only
//!   host:H:G:count          host->guest only
//!   squash-guest:G:H:count  guest range G.. squashed onto the single host id H
//!   squash-host:H:G:count   host range H.. squashed onto the single guest id G
//!   forbid-guest:G:count    reject guest ids in the range (EPERM)
//!
//! IDs outside every rule translate as identity (virtiofsd semantics). Overlapping
//! rules resolve first-match-wins in argument order.
//!
//! [`IdMapFs`] applies the tables at the FileSystem trait boundary: request
//! credentials (`Context`, supplementary gid) and `setattr`/chown ids map
//! guest->host; ownership in returned attributes maps host->guest. Being a
//! boundary translation it does not rewrite ids stored *inside* file data or
//! POSIX-ACL xattr values (same as unprivileged cosmetic mapping in general).

use std::ffi::CStr;
use std::io;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::time::Duration;

use devices::virtio::bindings;
use devices::virtio::fs::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use devices::virtio::fs::fuse;

/// One direction of one rule.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Rule {
    /// 1:1 map `count` ids starting at `from` onto the range starting at `to`.
    Range { from: u32, to: u32, count: u32 },
    /// Squash `count` ids starting at `from` onto the single id `to`.
    Squash { from: u32, to: u32, count: u32 },
    /// Reject `count` ids starting at `from`.
    Forbid { from: u32, count: u32 },
}

impl Rule {
    fn matches(&self, id: u32) -> bool {
        let (from, count) = match *self {
            Rule::Range { from, count, .. }
            | Rule::Squash { from, count, .. }
            | Rule::Forbid { from, count } => (from, count),
        };
        id >= from && (id - from) < count
    }

    fn apply(&self, id: u32) -> io::Result<u32> {
        match *self {
            // `id` is guest-controlled: never let a range wrap past u32::MAX (parsing
            // rejects such rules, so this is defence in depth, not a reachable path).
            Rule::Range { from, to, .. } => to
                .checked_add(id - from)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EPERM)),
            Rule::Squash { to, .. } => Ok(to),
            Rule::Forbid { .. } => Err(io::Error::from_raw_os_error(libc::EPERM)),
        }
    }

    /// Reject rules whose source or target range would wrap past `u32::MAX` — with a
    /// guest-supplied id inside the range, a wrapping target would translate to an
    /// unintended (small) host id.
    fn validate(&self) -> Result<(), String> {
        let ok = |from: u32, count: u32| count == 0 || from.checked_add(count - 1).is_some();
        let valid = match *self {
            Rule::Range { from, to, count } => ok(from, count) && ok(to, count),
            Rule::Squash { from, count, .. } | Rule::Forbid { from, count } => ok(from, count),
        };
        if valid {
            Ok(())
        } else {
            Err("id range wraps past u32::MAX".to_string())
        }
    }
}

/// A parsed `--uid-map`/`--gid-map` argument (both directions of one rule).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IdMap {
    guest_to_host: Option<Rule>,
    host_to_guest: Option<Rule>,
}

impl FromStr for IdMap {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let mut parts = s.split(':');
        let kind = parts.next().unwrap_or_default();
        let mut num = |what: &str| -> Result<u32, String> {
            parts
                .next()
                .ok_or_else(|| format!("id map {s:?}: missing {what}"))?
                .parse::<u32>()
                .map_err(|e| format!("id map {s:?}: bad {what}: {e}"))
        };
        let map = match kind {
            "map" => {
                let (g, h, count) = (num("guest id")?, num("host id")?, num("count")?);
                IdMap {
                    guest_to_host: Some(Rule::Range {
                        from: g,
                        to: h,
                        count,
                    }),
                    host_to_guest: Some(Rule::Range {
                        from: h,
                        to: g,
                        count,
                    }),
                }
            }
            "guest" => {
                let (g, h, count) = (num("guest id")?, num("host id")?, num("count")?);
                IdMap {
                    guest_to_host: Some(Rule::Range {
                        from: g,
                        to: h,
                        count,
                    }),
                    host_to_guest: None,
                }
            }
            "host" => {
                let (h, g, count) = (num("host id")?, num("guest id")?, num("count")?);
                IdMap {
                    guest_to_host: None,
                    host_to_guest: Some(Rule::Range {
                        from: h,
                        to: g,
                        count,
                    }),
                }
            }
            "squash-guest" => {
                let (g, h, count) = (num("guest id")?, num("host id")?, num("count")?);
                IdMap {
                    guest_to_host: Some(Rule::Squash {
                        from: g,
                        to: h,
                        count,
                    }),
                    host_to_guest: None,
                }
            }
            "squash-host" => {
                let (h, g, count) = (num("host id")?, num("guest id")?, num("count")?);
                IdMap {
                    guest_to_host: None,
                    host_to_guest: Some(Rule::Squash {
                        from: h,
                        to: g,
                        count,
                    }),
                }
            }
            "forbid-guest" => {
                let (g, count) = (num("guest id")?, num("count")?);
                IdMap {
                    guest_to_host: Some(Rule::Forbid { from: g, count }),
                    host_to_guest: None,
                }
            }
            other => return Err(format!("id map {s:?}: unknown type {other:?}")),
        };
        if parts.next().is_some() {
            return Err(format!("id map {s:?}: too many fields"));
        }
        for rule in [&map.guest_to_host, &map.host_to_guest]
            .into_iter()
            .flatten()
        {
            rule.validate().map_err(|e| format!("id map {s:?}: {e}"))?;
        }
        Ok(map)
    }
}

/// Both directions of one id class (uids or gids), built from the rules in
/// argument order. Unmatched ids are identity; `forbid-guest` yields EPERM.
#[derive(Debug, Default)]
pub struct IdTable {
    guest_to_host: Vec<Rule>,
    host_to_guest: Vec<Rule>,
}

impl IdTable {
    pub fn new(maps: &[IdMap]) -> IdTable {
        IdTable {
            guest_to_host: maps.iter().filter_map(|m| m.guest_to_host).collect(),
            host_to_guest: maps.iter().filter_map(|m| m.host_to_guest).collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.guest_to_host.is_empty() && self.host_to_guest.is_empty()
    }

    fn guest_to_host(&self, id: u32) -> io::Result<u32> {
        match self.guest_to_host.iter().find(|r| r.matches(id)) {
            Some(rule) => rule.apply(id),
            None => Ok(id),
        }
    }

    /// Host->guest has no forbid form, so it is infallible.
    fn host_to_guest(&self, id: u32) -> u32 {
        match self.host_to_guest.iter().find(|r| r.matches(id)) {
            Some(rule) => rule.apply(id).expect("no Forbid rules host->guest"),
            None => id,
        }
    }
}

type Inode = u64;
type Handle = u64;

/// UID/GID-translating wrapper around a `FileSystem` (virtiofsd's soft idmap,
/// reimplemented over the libkrun fs engine). Forwards every operation the
/// passthrough implements, mapping credentials and ownership at the boundary.
pub struct IdMapFs<F> {
    inner: F,
    uid: IdTable,
    gid: IdTable,
}

impl<F: FileSystem<Inode = Inode, Handle = Handle>> IdMapFs<F> {
    pub fn new(inner: F, uid: IdTable, gid: IdTable) -> IdMapFs<F> {
        IdMapFs { inner, uid, gid }
    }

    /// Map request credentials guest->host (EPERM on a forbidden id).
    fn ctx(&self, ctx: Context) -> io::Result<Context> {
        Ok(Context {
            uid: self.uid.guest_to_host(ctx.uid)?,
            gid: self.gid.guest_to_host(ctx.gid)?,
            pid: ctx.pid,
        })
    }

    /// Credentials for void operations that cannot fail (forget): forbidden ids
    /// fall back to the unmapped value — the operation carries no authority.
    fn ctx_lossy(&self, ctx: Context) -> Context {
        self.ctx(ctx).unwrap_or(ctx)
    }

    fn ext(&self, ext: Extensions) -> io::Result<Extensions> {
        Ok(Extensions {
            secctx: ext.secctx,
            sup_gid: match ext.sup_gid {
                Some(gid) => Some(self.gid.guest_to_host(gid)?),
                None => None,
            },
        })
    }

    /// Map ownership in an outgoing stat host->guest.
    fn stat_out(&self, mut st: bindings::stat64) -> bindings::stat64 {
        st.st_uid = self.uid.host_to_guest(st.st_uid);
        st.st_gid = self.gid.host_to_guest(st.st_gid);
        st
    }

    fn entry_out(&self, mut entry: Entry) -> Entry {
        entry.attr = self.stat_out(entry.attr);
        entry
    }
}

impl<F: FileSystem<Inode = Inode, Handle = Handle> + Sync> FileSystem for IdMapFs<F> {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.inner.init(capable)
    }

    fn destroy(&self) {
        self.inner.destroy()
    }

    fn statfs(&self, ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        self.inner.statfs(self.ctx(ctx)?, inode)
    }

    fn lookup(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        self.inner
            .lookup(self.ctx(ctx)?, parent, name)
            .map(|e| self.entry_out(e))
    }

    fn forget(&self, ctx: Context, inode: Inode, count: u64) {
        self.inner.forget(self.ctx_lossy(ctx), inode, count)
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(Inode, u64)>) {
        self.inner.batch_forget(self.ctx_lossy(ctx), requests)
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.inner.opendir(self.ctx(ctx)?, inode, flags)
    }

    fn releasedir(&self, ctx: Context, inode: Inode, flags: u32, handle: Handle) -> io::Result<()> {
        self.inner.releasedir(self.ctx(ctx)?, inode, flags, handle)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.inner
            .mkdir(
                self.ctx(ctx)?,
                parent,
                name,
                mode,
                umask,
                self.ext(extensions)?,
            )
            .map(|e| self.entry_out(e))
    }

    fn rmdir(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.inner.rmdir(self.ctx(ctx)?, parent, name)
    }

    fn readdir<G>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: G,
    ) -> io::Result<()>
    where
        G: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.inner
            .readdir(self.ctx(ctx)?, inode, handle, size, offset, add_entry)
    }

    fn readdirplus<G>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        mut add_entry: G,
    ) -> io::Result<()>
    where
        G: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.inner
            .readdirplus(self.ctx(ctx)?, inode, handle, size, offset, |d, e| {
                add_entry(d, self.entry_out(e))
            })
    }

    fn open(
        &self,
        ctx: Context,
        inode: Inode,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.inner.open(self.ctx(ctx)?, inode, kill_priv, flags)
    }

    fn release(
        &self,
        ctx: Context,
        inode: Inode,
        flags: u32,
        handle: Handle,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.inner.release(
            self.ctx(ctx)?,
            inode,
            flags,
            handle,
            flush,
            flock_release,
            lock_owner,
        )
    }

    fn create(
        &self,
        ctx: Context,
        parent: Inode,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        self.inner
            .create(
                self.ctx(ctx)?,
                parent,
                name,
                mode,
                kill_priv,
                flags,
                umask,
                self.ext(extensions)?,
            )
            .map(|(e, h, o)| (self.entry_out(e), h, o))
    }

    fn unlink(&self, ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.inner.unlink(self.ctx(ctx)?, parent, name)
    }

    #[allow(clippy::too_many_arguments)]
    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        self.inner.read(
            self.ctx(ctx)?,
            inode,
            handle,
            w,
            size,
            offset,
            lock_owner,
            flags,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        self.inner.write(
            self.ctx(ctx)?,
            inode,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.inner
            .getattr(self.ctx(ctx)?, inode, handle)
            .map(|(st, d)| (self.stat_out(st), d))
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: Inode,
        mut attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        // chown: the guest names guest-side ids; map them onto the host.
        if valid.contains(SetattrValid::UID) {
            attr.st_uid = self.uid.guest_to_host(attr.st_uid)?;
        }
        if valid.contains(SetattrValid::GID) {
            attr.st_gid = self.gid.guest_to_host(attr.st_gid)?;
        }
        self.inner
            .setattr(self.ctx(ctx)?, inode, attr, handle, valid)
            .map(|(st, d)| (self.stat_out(st), d))
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.inner
            .rename(self.ctx(ctx)?, olddir, oldname, newdir, newname, flags)
    }

    fn mknod(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.inner
            .mknod(
                self.ctx(ctx)?,
                inode,
                name,
                mode,
                rdev,
                umask,
                self.ext(extensions)?,
            )
            .map(|e| self.entry_out(e))
    }

    fn link(
        &self,
        ctx: Context,
        inode: Inode,
        newparent: Inode,
        newname: &CStr,
    ) -> io::Result<Entry> {
        self.inner
            .link(self.ctx(ctx)?, inode, newparent, newname)
            .map(|e| self.entry_out(e))
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.inner
            .symlink(
                self.ctx(ctx)?,
                linkname,
                parent,
                name,
                self.ext(extensions)?,
            )
            .map(|e| self.entry_out(e))
    }

    fn readlink(&self, ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        self.inner.readlink(self.ctx(ctx)?, inode)
    }

    fn flush(&self, ctx: Context, inode: Inode, handle: Handle, lock_owner: u64) -> io::Result<()> {
        self.inner.flush(self.ctx(ctx)?, inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        self.inner.fsync(self.ctx(ctx)?, inode, datasync, handle)
    }

    fn fsyncdir(
        &self,
        ctx: Context,
        inode: Inode,
        datasync: bool,
        handle: Handle,
    ) -> io::Result<()> {
        self.inner.fsyncdir(self.ctx(ctx)?, inode, datasync, handle)
    }

    fn access(&self, ctx: Context, inode: Inode, mask: u32) -> io::Result<()> {
        self.inner.access(self.ctx(ctx)?, inode, mask)
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.inner
            .setxattr(self.ctx(ctx)?, inode, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: Inode,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.inner.getxattr(self.ctx(ctx)?, inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: Inode, size: u32) -> io::Result<ListxattrReply> {
        self.inner.listxattr(self.ctx(ctx)?, inode, size)
    }

    fn removexattr(&self, ctx: Context, inode: Inode, name: &CStr) -> io::Result<()> {
        self.inner.removexattr(self.ctx(ctx)?, inode, name)
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        self.inner
            .fallocate(self.ctx(ctx)?, inode, handle, mode, offset, length)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.inner
            .lseek(self.ctx(ctx)?, inode, handle, offset, whence)
    }

    #[allow(clippy::too_many_arguments)]
    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: Inode,
        handle_in: Handle,
        offset_in: u64,
        inode_out: Inode,
        handle_out: Handle,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        self.inner.copyfilerange(
            self.ctx(ctx)?,
            inode_in,
            handle_in,
            offset_in,
            inode_out,
            handle_out,
            offset_out,
            len,
            flags,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn setupmapping(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        self.inner.setupmapping(
            self.ctx(ctx)?,
            inode,
            handle,
            foffset,
            len,
            flags,
            moffset,
            host_shm_base,
            shm_size,
        )
    }

    fn removemapping(
        &self,
        ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        self.inner
            .removemapping(self.ctx(ctx)?, requests, host_shm_base, shm_size)
    }

    #[allow(clippy::too_many_arguments)]
    fn ioctl(
        &self,
        ctx: Context,
        inode: Inode,
        handle: Handle,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        self.inner.ioctl(
            self.ctx(ctx)?,
            inode,
            handle,
            flags,
            cmd,
            arg,
            in_size,
            out_size,
            exit_code,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(specs: &[&str]) -> IdTable {
        IdTable::new(
            &specs
                .iter()
                .map(|s| s.parse().unwrap())
                .collect::<Vec<IdMap>>(),
        )
    }

    #[test]
    fn identity_when_unmapped() {
        let t = table(&["map:1000:2000:10"]);
        assert_eq!(t.guest_to_host(500).unwrap(), 500);
        assert_eq!(t.host_to_guest(500), 500);
    }

    #[test]
    fn bidirectional_range() {
        let t = table(&["map:1000:2000:10"]);
        assert_eq!(t.guest_to_host(1000).unwrap(), 2000);
        assert_eq!(t.guest_to_host(1009).unwrap(), 2009);
        assert_eq!(t.guest_to_host(1010).unwrap(), 1010); // past the range: identity
        assert_eq!(t.host_to_guest(2000), 1000);
        assert_eq!(t.host_to_guest(2009), 1009);
    }

    #[test]
    fn one_way_maps() {
        let t = table(&["guest:0:1000:1", "host:1000:0:1"]);
        assert_eq!(t.guest_to_host(0).unwrap(), 1000);
        assert_eq!(t.host_to_guest(1000), 0);
        // `guest:` adds no host->guest rule; the reverse comes from `host:` only.
        assert_eq!(t.host_to_guest(999), 999);
    }

    #[test]
    fn squash_both_ways() {
        let t = table(&["squash-guest:0:1000:100", "squash-host:0:0:4294967295"]);
        assert_eq!(t.guest_to_host(0).unwrap(), 1000);
        assert_eq!(t.guest_to_host(99).unwrap(), 1000);
        assert_eq!(t.host_to_guest(12345), 0);
    }

    #[test]
    fn forbid_guest_errors() {
        let t = table(&["forbid-guest:1:999"]);
        assert_eq!(t.guest_to_host(0).unwrap(), 0);
        let err = t.guest_to_host(1).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EPERM));
        assert_eq!(t.guest_to_host(1000).unwrap(), 1000);
    }

    #[test]
    fn first_match_wins() {
        let t = table(&["map:0:5000:10", "forbid-guest:0:100"]);
        assert_eq!(t.guest_to_host(5).unwrap(), 5005);
        assert!(t.guest_to_host(50).is_err());
    }

    #[test]
    fn parse_errors() {
        assert!("bogus:1:2:3".parse::<IdMap>().is_err());
        assert!("map:1:2".parse::<IdMap>().is_err());
        assert!("map:1:2:3:4".parse::<IdMap>().is_err());
        assert!("map:a:2:3".parse::<IdMap>().is_err());
        assert!("forbid-guest:1:2:3".parse::<IdMap>().is_err());
    }

    #[test]
    fn wrapping_ranges_rejected() {
        // target range would wrap: guest 0..10 -> host 4294967290..(past MAX)
        assert!("map:0:4294967290:10".parse::<IdMap>().is_err());
        // source range would wrap
        assert!("guest:4294967290:0:10".parse::<IdMap>().is_err());
        assert!("forbid-guest:4294967295:2".parse::<IdMap>().is_err());
        // exactly reaching MAX is fine
        assert!("map:0:4294967286:10".parse::<IdMap>().is_ok());
        assert!("squash-host:0:0:4294967295".parse::<IdMap>().is_ok());
    }
}
