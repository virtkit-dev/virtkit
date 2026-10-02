#[cfg(target_os = "macos")]
use crossbeam_channel::Sender;
#[cfg(target_os = "macos")]
use utils::worker_message::WorkerMessage;

use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;
use std::thread;
#[cfg(windows)]
use utils::windows::AsRawFd;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{FsError, Queue};
use super::augment_fs::AugmentFs;
use super::defs::{HPQ_INDEX, REQ_INDEX};
use super::descriptor_utils::{Reader, Writer};
use super::idmap::{IdMap, IdMapFs, IdTable};
use super::inode_alloc::InodeAllocator;
use super::null_fs::NullFs;
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;
use super::virtual_entry::VirtualDirEntry;
use crate::virtio::{InterruptTransport, VirtioShmRegion};

enum FsServer {
    ReadWrite(Server<AugmentFs<PassthroughFs>>),
    ReadOnly(Server<AugmentFs<PassthroughFsRo>>),
    // As above, but with a virtiofsd-style soft UID/GID id-map applied at the
    // FileSystem boundary (used when the share carries a non-empty uid/gid map).
    ReadWriteMapped(Server<AugmentFs<IdMapFs<PassthroughFs>>>),
    ReadOnlyMapped(Server<AugmentFs<IdMapFs<PassthroughFsRo>>>),
    Null(Server<AugmentFs<NullFs>>),
    // A share whose root is a single host file: serves only that file, never its parent
    // (a single-file bind mount). No AugmentFs — it injects no virtual entries.
    #[cfg(target_os = "linux")]
    SingleFile(Server<super::single_file::SingleFileFs>),
}

impl FsServer {
    fn handle_message(
        &self,
        r: Reader,
        w: Writer,
        allow_idmap: bool,
        shm_region: &Option<VirtioShmRegion>,
        exit_code: &Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: &Option<Sender<WorkerMessage>>,
    ) -> super::Result<usize> {
        match self {
            FsServer::ReadWrite(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::ReadOnly(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::ReadWriteMapped(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::ReadOnlyMapped(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            FsServer::Null(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
            #[cfg(target_os = "linux")]
            FsServer::SingleFile(s) => s.handle_message(
                r,
                w,
                allow_idmap,
                shm_region,
                exit_code,
                #[cfg(target_os = "macos")]
                map_sender,
            ),
        }
    }
}

pub struct FsWorker {
    queues: Vec<Queue>,
    queue_evts: Vec<Arc<EventFd>>,
    interrupt: InterruptTransport,
    mem: GuestMemoryMmap,
    allow_idmap: bool,
    shm_region: Option<VirtioShmRegion>,
    server: FsServer,
    stop_fd: EventFd,
    exit_code: Arc<AtomicI32>,
    #[cfg(target_os = "macos")]
    map_sender: Option<Sender<WorkerMessage>>,
}

/// Whether INIT offers FUSE_ALLOW_IDMAP. A mapped share does not: with it the guest kernel
/// sends FUSE_INVALID_UIDGID for every request but the creating ones, which the soft map
/// would then translate (or let past `forbid-guest`) instead of the caller's ids.
fn offer_idmap(allow_idmap: bool, mapped: bool) -> bool {
    allow_idmap && !mapped
}

impl FsWorker {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        queues: Vec<Queue>,
        queue_evts: Vec<Arc<EventFd>>,
        interrupt: InterruptTransport,
        mem: GuestMemoryMmap,
        allow_idmap: bool,
        shm_region: Option<VirtioShmRegion>,
        passthrough_cfg: Option<passthrough::Config>,
        read_only: bool,
        uid_map: Vec<String>,
        gid_map: Vec<String>,
        virtual_entries: Vec<VirtualDirEntry<'static>>,
        stop_fd: EventFd,
        exit_code: Arc<AtomicI32>,
        #[cfg(target_os = "macos")] map_sender: Option<Sender<WorkerMessage>>,
    ) -> Result<Self, io::Error> {
        // Parse the virtiofsd-style spec strings into id tables; empty maps yield
        // empty (identity) tables and the passthrough is served without an id-map
        // wrap, so behaviour is byte-identical to an unmapped share.
        let parse = |maps: Vec<String>| -> Result<IdTable, io::Error> {
            let parsed = maps
                .iter()
                .map(|m| m.parse::<IdMap>())
                .collect::<Result<Vec<IdMap>, String>>()
                .map_err(io::Error::other)?;
            Ok(IdTable::new(&parsed))
        };
        let uid_table = parse(uid_map)?;
        let gid_table = parse(gid_map)?;
        let mapped = !uid_table.is_empty() || !gid_table.is_empty();
        let allow_idmap = offer_idmap(allow_idmap, mapped);

        let inode_alloc = Arc::new(InodeAllocator::new());
        let server = match passthrough_cfg {
            // A share rooted at a regular file → serve just that file (single-file bind),
            // never opening or exposing its parent directory. The single-file server does
            // not apply id maps; a caller wanting one must use a directory share. Linux only:
            // elsewhere a file root keeps failing in `PassthroughFs::new`.
            #[cfg(target_os = "linux")]
            Some(cfg)
                if std::fs::metadata(&cfg.root_dir)
                    .map(|m| m.is_file())
                    .unwrap_or(false) =>
            {
                let fs = super::single_file::SingleFileFs::new(cfg.root_dir.into(), read_only)?;
                FsServer::SingleFile(Server::new(fs))
            }
            Some(cfg) if read_only && mapped => {
                let inner = PassthroughFsRo::new(cfg, inode_alloc.clone())?;
                let inner = IdMapFs::new(inner, uid_table, gid_table);
                FsServer::ReadOnlyMapped(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            Some(cfg) if mapped => {
                let inner = PassthroughFs::new(cfg, inode_alloc.clone())?;
                let inner = IdMapFs::new(inner, uid_table, gid_table);
                FsServer::ReadWriteMapped(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            Some(cfg) if read_only => {
                let inner = PassthroughFsRo::new(cfg, inode_alloc.clone())?;
                FsServer::ReadOnly(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            Some(cfg) => {
                let inner = PassthroughFs::new(cfg, inode_alloc.clone())?;
                FsServer::ReadWrite(Server::new(AugmentFs::new(
                    inner,
                    &inode_alloc,
                    virtual_entries,
                )))
            }
            None => FsServer::Null(Server::new(AugmentFs::new(
                NullFs,
                &inode_alloc,
                virtual_entries,
            ))),
        };
        Ok(Self {
            queues,
            queue_evts,
            interrupt,
            mem,
            allow_idmap,
            shm_region,
            server,
            stop_fd,
            exit_code,
            #[cfg(target_os = "macos")]
            map_sender,
        })
    }

    pub fn run(self) -> thread::JoinHandle<()> {
        thread::Builder::new()
            .name("fs worker".into())
            .spawn(|| self.work())
            .unwrap()
    }

    fn work(mut self) {
        let virtq_hpq_ev_fd = self.queue_evts[HPQ_INDEX].as_raw_fd();
        let virtq_req_ev_fd = self.queue_evts[REQ_INDEX].as_raw_fd();
        let stop_ev_fd = self.stop_fd.as_raw_fd();

        let mut epoll = Epoll::new().unwrap();

        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_hpq_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_hpq_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            virtq_req_ev_fd,
            &EpollEvent::new(EventSet::IN, virtq_req_ev_fd as u64),
        );
        let _ = epoll.ctl(
            ControlOperation::Add,
            stop_ev_fd,
            &EpollEvent::new(EventSet::IN, stop_ev_fd as u64),
        );

        let mut epoll_events = vec![EpollEvent::new(EventSet::empty(), 0); 32];
        loop {
            match epoll.wait(epoll_events.len(), -1, epoll_events.as_mut_slice()) {
                Ok(ev_cnt) => {
                    for event in &epoll_events[0..ev_cnt] {
                        let source = event.fd();
                        let event_set = event.event_set();
                        match event_set {
                            EventSet::IN if source == virtq_hpq_ev_fd => {
                                self.handle_event(HPQ_INDEX);
                            }
                            EventSet::IN if source == virtq_req_ev_fd => {
                                self.handle_event(REQ_INDEX);
                            }
                            EventSet::IN if source == stop_ev_fd => {
                                debug!("stopping worker thread");
                                let _ = self.stop_fd.read();
                                return;
                            }
                            _ => {
                                log::warn!(
                                    "Received unknown event: {event_set:?} from fd: {source:?}"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("failed to consume muxer epoll event: {e}");
                }
            }
        }
    }

    fn handle_event(&mut self, queue_index: usize) {
        debug!("Fs: queue event: {queue_index}");
        if let Err(e) = self.queue_evts[queue_index].read() {
            error!("Failed to get queue event: {e:?}");
        }

        loop {
            self.queues[queue_index]
                .disable_notification(&self.mem)
                .unwrap();

            self.process_queue(queue_index);

            if !self.queues[queue_index]
                .enable_notification(&self.mem)
                .unwrap()
            {
                break;
            }
        }
    }

    fn process_queue(&mut self, queue_index: usize) {
        let queue = &mut self.queues[queue_index];
        while let Some(head) = queue.pop(&self.mem) {
            let reader = Reader::new(&self.mem, head.clone())
                .map_err(FsError::QueueReader)
                .unwrap();
            let writer = Writer::new(&self.mem, head.clone())
                .map_err(FsError::QueueWriter)
                .unwrap();

            let len = match self.server.handle_message(
                reader,
                writer,
                self.allow_idmap,
                &self.shm_region,
                &self.exit_code,
                #[cfg(target_os = "macos")]
                &self.map_sender,
            ) {
                Ok(len) => len,
                Err(e) => {
                    error!("error handling message: {e:?}");
                    0
                }
            };

            if let Err(e) = queue.add_used(&self.mem, head.index, len as u32) {
                error!("failed to add used elements to the queue: {e:?}");
            }

            if queue.needs_notification(&self.mem).unwrap() {
                self.interrupt.signal_used_queue();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::offer_idmap;

    #[test]
    fn a_mapped_share_never_offers_allow_idmap() {
        assert!(offer_idmap(true, false));
        assert!(!offer_idmap(true, true));
        assert!(!offer_idmap(false, false));
        assert!(!offer_idmap(false, true));
    }
}
