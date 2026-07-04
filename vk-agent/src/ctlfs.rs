//! `/run/vk/services` — the run's compose services as a control filesystem,
//! /proc-style:
//!
//! ```text
//! /run/vk/services/<name>/state   read:  "running" | "stopped"
//! /run/vk/services/<name>/ctl     write: start | stop | restart (blocks until done)
//! /run/vk/services/<name>/log     read:  console tail
//! /run/vk/services/<name>/error   read:  the last failed ctl write's message
//! ```
//!
//! A tiny FUSE server (mounted by PID 1, `VIRTKIT_CTL=1`) that bridges every
//! operation to the host's service manager over the vsock control protocol
//! (`vk_core::fleetctl`) — so any shell or language talks to the orchestrator
//! with no client binary. Files are served with direct I/O: content is
//! generated per read, never cached against a stale size.
//!
//! The fs root *is* the services directory (each unit a top-level dir): PID 1
//! mounts it at `/run/vk/services`, keeping `/run/vk` itself a plain directory
//! with room for the run's other endpoints (e.g. the `host.sock` host-exec
//! socket).

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result};
use fuser::{
    BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, LockOwner, MountOption, OpenFlags, ReplyAttr, ReplyData, ReplyDirectory,
    ReplyEntry, ReplyOpen, ReplyWrite, SessionACL, TimeOrNow, WriteFlags,
};
use log::warn;
use vk_core::fleetctl::{Client, Reply, Request};

/// Directory attrs are stable; file attrs carry live content sizes and must
/// not be cached (a stale size clamps the next read).
const DIR_TTL: Duration = Duration::from_secs(1);
const FILE_TTL: Duration = Duration::ZERO;
const ROOT: u64 = 1;
/// Unit inodes: unit `i` owns the range `FIRST + i*STRIDE ..`, dir first.
const FIRST: u64 = 100;
const STRIDE: u64 = 8;

/// The per-unit files, in readdir/inode-offset order.
#[derive(Clone, Copy, PartialEq)]
enum Node {
    State,
    Ctl,
    Log,
    Error,
}

const NODES: [(Node, &str); 4] = [
    (Node::State, "state"),
    (Node::Ctl, "ctl"),
    (Node::Log, "log"),
    (Node::Error, "error"),
];

/// Mount the control fs on `mountpoint` and serve until unmounted. The declared
/// unit set is fixed for the owner's lifetime, so it is fetched once (with a
/// grace retry — PID 1 forks us early in boot, the host side may still be
/// binding its socket).
pub fn run(mountpoint: &Path) -> Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the tokio runtime")?;
    let mut client = Client::new();
    let mut units = Vec::new();
    for attempt in 0..10 {
        match rt.block_on(client.request(&Request::List)) {
            Ok(reply) => {
                units = reply.units.into_iter().map(|u| u.name).collect();
                break;
            }
            Err(e) if attempt == 9 => return Err(e.context("listing the declared services")),
            Err(_) => std::thread::sleep(Duration::from_millis(500)),
        }
    }
    std::fs::create_dir_all(mountpoint)
        .with_context(|| format!("creating {}", mountpoint.display()))?;
    let fs = CtlFs {
        rt,
        client: Mutex::new(client),
        units,
        errors: Mutex::new(HashMap::new()),
    };
    // DefaultPermissions: the kernel enforces the modes (ctl is root-write-only);
    // SessionACL::All (allow_other): every guest user may read states/logs.
    let mut opts = Config::default();
    opts.mount_options = vec![
        MountOption::FSName("vkctl".into()),
        MountOption::DefaultPermissions,
    ];
    opts.acl = SessionACL::All;
    fuser::mount2(fs, mountpoint, &opts)
        .with_context(|| format!("mounting the control fs on {}", mountpoint.display()))
}

fn ttl_of(attr: &FileAttr) -> &'static Duration {
    if attr.kind == FileType::Directory {
        &DIR_TTL
    } else {
        &FILE_TTL
    }
}

struct CtlFs {
    rt: tokio::runtime::Runtime,
    /// one control session for the mount's lifetime (reconnects itself); the
    /// `Filesystem` trait hands us `&self`, so the mutable session lives behind
    /// a mutex (fuser serializes our callbacks, so it is never contended)
    client: Mutex<Client>,
    /// declared unit names, in the manager's (sorted) order — inode identity
    units: Vec<String>,
    /// last failed ctl write per unit, served by its `error` file
    errors: Mutex<HashMap<usize, String>>,
}

impl CtlFs {
    fn call(&self, req: &Request) -> Result<Reply> {
        let mut client = self.client.lock().expect("ctlfs client mutex");
        self.rt.block_on(client.request(req))
    }

    fn decode(&self, ino: u64) -> Option<(usize, Option<Node>)> {
        let rel = ino.checked_sub(FIRST)?;
        let (idx, off) = ((rel / STRIDE) as usize, rel % STRIDE);
        if idx >= self.units.len() {
            return None;
        }
        match off {
            0 => Some((idx, None)),
            n if (n as usize) <= NODES.len() => Some((idx, Some(NODES[n as usize - 1].0))),
            _ => None,
        }
    }

    fn attr(&self, ino: u64) -> Option<FileAttr> {
        let (kind, perm, size) = match ino {
            ROOT => (FileType::Directory, 0o555, 0),
            _ => match self.decode(ino)? {
                (_, None) => (FileType::Directory, 0o555, 0),
                (_, Some(Node::Ctl)) => (FileType::RegularFile, 0o200, 0),
                // the kernel clamps reads at the attributed size even for
                // direct-I/O opens, so a synthetic file must attribute its
                // real content length — generated fresh, like the reads
                (idx, Some(node)) => (
                    FileType::RegularFile,
                    0o444,
                    self.content(idx, node).len() as u64,
                ),
            },
        };
        let now = SystemTime::now();
        Some(FileAttr {
            ino: INodeNo(ino),
            size,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            kind,
            perm,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }

    /// The content a read of `ino` serves, generated per call.
    fn content(&self, idx: usize, node: Node) -> String {
        let Some(unit) = self.units.get(idx) else {
            return String::new();
        };
        match node {
            Node::State => match self.call(&Request::Status { unit: unit.clone() }) {
                Ok(r) if !r.units.is_empty() => format!("{}\n", r.units[0].state),
                Ok(r) => format!("error: {}\n", r.message),
                Err(e) => format!("error: {e:#}\n"),
            },
            Node::Log => match self.call(&Request::Logs {
                unit: unit.clone(),
                lines: 200,
            }) {
                Ok(r) if r.ok => {
                    let mut m = r.message;
                    if !m.is_empty() && !m.ends_with('\n') {
                        m.push('\n');
                    }
                    m
                }
                Ok(r) => format!("error: {}\n", r.message),
                Err(e) => format!("error: {e:#}\n"),
            },
            Node::Error => self
                .errors
                .lock()
                .expect("ctlfs errors mutex")
                .get(&idx)
                .map(|e| format!("{e}\n"))
                .unwrap_or_default(),
            Node::Ctl => String::new(),
        }
    }
}

impl Filesystem for CtlFs {
    fn lookup(&self, _req: &fuser::Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let name = name.to_string_lossy();
        let ino = match parent.0 {
            ROOT => self
                .units
                .iter()
                .position(|u| *u == name)
                .map(|i| FIRST + i as u64 * STRIDE),
            _ => match self.decode(parent.0) {
                Some((idx, None)) => NODES
                    .iter()
                    .position(|(_, n)| *n == name)
                    .map(|n| FIRST + idx as u64 * STRIDE + n as u64 + 1),
                _ => None,
            },
        };
        match ino.and_then(|i| self.attr(i)) {
            Some(attr) => reply.entry(ttl_of(&attr), &attr, Generation(0)),
            None => reply.error(Errno::ENOENT),
        }
    }

    fn getattr(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        match self.attr(ino.0) {
            Some(attr) => reply.attr(ttl_of(&attr), &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    /// `> ctl` from a shell opens with O_TRUNC, which arrives as a size-0
    /// setattr; there is nothing to truncate, so acknowledge it.
    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        _size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        match self.attr(ino.0) {
            Some(attr) => reply.attr(ttl_of(&attr), &attr),
            None => reply.error(Errno::ENOENT),
        }
    }

    /// Direct I/O: content is generated per read (the attr size is 0, which
    /// would otherwise clamp reads to nothing under the page cache).
    fn open(&self, _req: &fuser::Request, _ino: INodeNo, _flags: OpenFlags, reply: ReplyOpen) {
        reply.opened(FileHandle(0), FopenFlags::FOPEN_DIRECT_IO);
    }

    fn read(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let Some((idx, Some(node))) = self.decode(ino.0) else {
            return reply.error(Errno::ENOENT);
        };
        let content = self.content(idx, node);
        let bytes = content.as_bytes();
        let start = (offset as usize).min(bytes.len());
        let end = (start + size as usize).min(bytes.len());
        reply.data(&bytes[start..end]);
    }

    fn write(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: FileHandle,
        _offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let Some((idx, Some(Node::Ctl))) = self.decode(ino.0) else {
            return reply.error(Errno::EACCES);
        };
        let Some(name) = self.units.get(idx).cloned() else {
            return reply.error(Errno::ENOENT);
        };
        // each write is one self-contained command (the `echo verb > ctl`
        // contract), so the offset is ignored; lossy is safe — the result is only
        // matched against the fixed ASCII verb set, non-UTF-8 falls through to EINVAL.
        let verb = String::from_utf8_lossy(data).trim().to_string();
        let req = match verb.as_str() {
            "start" => Request::Start { unit: name.clone() },
            "stop" => Request::Stop { unit: name.clone() },
            "restart" => Request::Restart { unit: name.clone() },
            _ => {
                self.errors.lock().expect("ctlfs errors mutex").insert(
                    idx,
                    format!("unknown command {verb:?} (start|stop|restart)"),
                );
                return reply.error(Errno::EINVAL);
            }
        };
        match self.call(&req) {
            Ok(r) if r.ok => {
                self.errors.lock().expect("ctlfs errors mutex").remove(&idx);
                reply.written(data.len() as u32);
            }
            Ok(r) => {
                warn!("ctlfs: {verb} {name}: {}", r.message);
                self.errors
                    .lock()
                    .expect("ctlfs errors mutex")
                    .insert(idx, r.message);
                reply.error(Errno::EIO);
            }
            Err(e) => {
                warn!("ctlfs: {verb} {name}: {e:#}");
                self.errors
                    .lock()
                    .expect("ctlfs errors mutex")
                    .insert(idx, format!("{e:#}"));
                reply.error(Errno::EIO);
            }
        }
    }

    fn readdir(
        &self,
        _req: &fuser::Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let entries: Vec<(u64, FileType, String)> = match ino.0 {
            ROOT => self
                .units
                .iter()
                .enumerate()
                .map(|(i, u)| (FIRST + i as u64 * STRIDE, FileType::Directory, u.clone()))
                .collect(),
            _ => match self.decode(ino.0) {
                Some((idx, None)) => NODES
                    .iter()
                    .enumerate()
                    .map(|(n, (_, name))| {
                        (
                            FIRST + idx as u64 * STRIDE + n as u64 + 1,
                            FileType::RegularFile,
                            (*name).into(),
                        )
                    })
                    .collect(),
                _ => return reply.error(Errno::ENOENT),
            },
        };
        for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            // i + 1 is the next readdir offset
            if reply.add(INodeNo(ino), (i + 1) as u64, kind, name) {
                break;
            }
        }
        reply.ok();
    }
}
