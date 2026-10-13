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
use std::time::{Duration, Instant};
#[cfg(windows)]
use utils::windows::AsRawFd;

use utils::epoll::{ControlOperation, Epoll, EpollEvent, EventSet};
use utils::eventfd::EventFd;
use vm_memory::GuestMemoryMmap;

use super::super::{FsError, Queue};
use super::augment_fs::AugmentFs;
use super::defs::{HPQ_INDEX, NUM_QUEUES, REQ_INDEX};
use super::descriptor_utils::{Reader, Writer};
use super::idmap::{IdMap, IdMapFs, IdTable};
use super::inode_alloc::InodeAllocator;
use super::null_fs::NullFs;
use super::passthrough::{self, PassthroughFs};
use super::read_only::PassthroughFsRo;
use super::server::Server;
use super::virtual_entry::VirtualDirEntry;
use crate::virtio::queue::{AvailPosition, Error as QueueError, UsedPosition};
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
    /// The shared host directory, naming the device in the stall log.
    label: String,
    /// What the stall checks saw of each queue, by queue index.
    stall_watch: [StallWatch; NUM_QUEUES],
}

/// What a stall check reads of one queue: where the avail ring stands, and with `EVENT_IDX`
/// where the used ring does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RingPositions {
    avail: AvailPosition,
    used: Option<UsedPosition>,
}

/// One queue's ring positions at the previous stall check, and those of the stall last
/// reported, so that a stall the recovery does not clear is warned about once.
#[derive(Default)]
struct StallWatch {
    last: Option<RingPositions>,
    reported: Option<RingPositions>,
}

/// A queue whose ring held work and did not move between two stall checks.
#[derive(Debug, PartialEq, Eq)]
struct Stall {
    /// Chains made available and never popped: a kick the worker did not see.
    lost_kick: Option<u16>,
    /// Completions past the driver's `used_event`: an interrupt it did not get.
    lost_interrupt: Option<u16>,
    /// The same positions as the stall last reported: the recovery did not clear it.
    repeat: bool,
}

impl StallWatch {
    /// Record this check's positions and return the stall they show, if the ring did not move
    /// since the previous check. More chains pending than the queue holds are not a ring the
    /// driver could have filled, so they are not read as a lost kick.
    fn observe(&mut self, now: RingPositions, queue_size: u16) -> Option<Stall> {
        if self.last.replace(now) != Some(now) {
            self.reported = None;
            return None;
        }
        let pending = now.avail.pending();
        let lost_kick = Some(pending).filter(|&n| n > 0 && n <= queue_size);
        let lost_interrupt = now.used.map(|u| u.unconsumed()).filter(|&n| n > 0);
        if lost_kick.is_none() && lost_interrupt.is_none() {
            return None;
        }
        Some(Stall {
            lost_kick,
            lost_interrupt,
            repeat: self.reported.replace(now) == Some(now),
        })
    }
}

/// How often the worker checks its queues for a lost notification, busy or idle: a ring that
/// held work and did not move between two checks is a stall. Idle shares cost one wakeup per
/// period; a lost kick or interrupt costs at most two periods instead of the guest's request
/// blocking for good.
const STALL_CHECK: Duration = Duration::from_secs(10);

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

        let label = passthrough_cfg
            .as_ref()
            .map_or_else(|| "(no share)".to_string(), |cfg| cfg.root_dir.clone());
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
            label,
            stall_watch: Default::default(),
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
        // On a deadline rather than an idle timeout: under EVENT_IDX, completions after a lost
        // interrupt raise none either, while the guest's other submissions keep waking this
        // thread, so a quiet period may never come.
        let mut next_check = Instant::now() + STALL_CHECK;
        loop {
            if Instant::now() >= next_check {
                self.check_stalled();
                next_check = Instant::now() + STALL_CHECK;
            }
            let timeout = next_check.saturating_duration_since(Instant::now());
            let timeout_ms = timeout.as_millis() as i32 + 1;
            match epoll.wait(epoll_events.len(), timeout_ms, epoll_events.as_mut_slice()) {
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
        self.drain(queue_index);
    }

    /// Every `STALL_CHECK`: look for a notification that went missing, from rings that held
    /// work and did not move since the previous check. Chains the driver made available that
    /// were never popped mean a kick this worker did not see; completions published past the
    /// `used_event` the driver last wrote mean an interrupt it did not get (a suspicion: that
    /// field is the driver's notification threshold, which Linux sets to what it last consumed
    /// when it re-arms). Either leaves a guest request blocked until something else happens to
    /// recover it. Log what the rings held, then serve the chains or signal again: a warning
    /// the first time, a debug line while the same positions come back.
    fn check_stalled(&mut self) {
        for queue_index in [HPQ_INDEX, REQ_INDEX] {
            let queue = &self.queues[queue_index];
            let avail = match queue.avail_position(&self.mem) {
                Ok(Some(position)) => position,
                // Bus mastering is off: the device may not touch the rings.
                Ok(None) => {
                    self.stall_watch[queue_index] = StallWatch::default();
                    continue;
                }
                Err(e) => {
                    debug!(
                        "virtio-fs {}: queue {queue_index}: stall check cannot read avail_idx: \
                         {e}",
                        self.label
                    );
                    self.stall_watch[queue_index] = StallWatch::default();
                    continue;
                }
            };
            let used = queue.unconsumed_used(&self.mem);
            if let Err(e) = &used {
                debug!(
                    "virtio-fs {}: queue {queue_index}: stall check cannot read used_event: {e}",
                    self.label
                );
            }
            let now = RingPositions {
                avail,
                used: used.as_ref().ok().copied().flatten(),
            };
            let Some(stall) = self.stall_watch[queue_index].observe(now, queue.actual_size())
            else {
                continue;
            };
            let level = if stall.repeat {
                log::Level::Debug
            } else {
                log::Level::Warn
            };
            if let Some(pending) = stall.lost_kick {
                log!(
                    level,
                    "virtio-fs {}: queue {queue_index}: {pending} request(s) available and not \
                     popped for {}s (avail_idx {}, next_avail {}, {}; {}): \
                     suspected lost kick, serving them",
                    self.label,
                    STALL_CHECK.as_secs(),
                    avail.avail_idx,
                    avail.next_avail,
                    describe_used(&used),
                    self.interrupt.describe(),
                );
                self.drain(queue_index);
                // `pop` refuses a chain with an invalid head, leaving `next_avail` where it was.
                if let Ok(Some(after)) = self.queues[queue_index].avail_position(&self.mem)
                    && after.next_avail == avail.next_avail
                {
                    log!(
                        level,
                        "virtio-fs {}: queue {queue_index}: the chain at next_avail {} could not \
                         be popped",
                        self.label,
                        avail.next_avail,
                    );
                }
            }
            if let (Some(count), Some(used)) = (stall.lost_interrupt, now.used) {
                log!(
                    level,
                    "virtio-fs {}: queue {queue_index}: {count} completion(s) past used_event \
                     for {}s (used_event {}, next_used {}, avail_idx {}; {}): suspected \
                     lost interrupt, signalling again",
                    self.label,
                    STALL_CHECK.as_secs(),
                    used.used_event,
                    used.next_used,
                    avail.avail_idx,
                    self.interrupt.describe(),
                );
                self.interrupt.signal_used_queue();
            }
        }
    }

    fn drain(&mut self, queue_index: usize) {
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

/// The used ring's state for the stall log.
fn describe_used(used: &Result<Option<UsedPosition>, QueueError>) -> String {
    match used {
        Ok(Some(used)) => format!(
            "used_event {}, next_used {}, {} unconsumed",
            used.used_event,
            used.next_used,
            used.unconsumed()
        ),
        Ok(None) => "used ring unknown without EVENT_IDX".to_string(),
        Err(e) => format!("used ring unreadable: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use std::num::Wrapping;

    use super::{AvailPosition, RingPositions, Stall, StallWatch, UsedPosition, offer_idmap};

    #[test]
    fn a_mapped_share_never_offers_allow_idmap() {
        assert!(offer_idmap(true, false));
        assert!(!offer_idmap(true, true));
        assert!(!offer_idmap(false, false));
        assert!(!offer_idmap(false, true));
    }

    fn ring(avail_idx: u16, next_avail: u16, used: Option<(u16, u16)>) -> RingPositions {
        RingPositions {
            avail: AvailPosition {
                avail_idx: Wrapping(avail_idx),
                next_avail: Wrapping(next_avail),
            },
            used: used.map(|(used_event, next_used)| UsedPosition {
                used_event: Wrapping(used_event),
                next_used: Wrapping(next_used),
            }),
        }
    }

    fn stall(lost_kick: Option<u16>, lost_interrupt: Option<u16>, repeat: bool) -> Stall {
        Stall {
            lost_kick,
            lost_interrupt,
            repeat,
        }
    }

    #[test]
    fn a_stall_needs_two_checks_on_an_unmoved_ring() {
        let mut watch = StallWatch::default();
        let stuck = ring(5, 3, Some((7, 9)));
        assert_eq!(
            watch.observe(stuck, 16),
            None,
            "the first sample is skipped"
        );
        assert_eq!(
            watch.observe(stuck, 16),
            Some(stall(Some(2), Some(2), false))
        );
    }

    #[test]
    fn a_moving_ring_never_stalls() {
        let mut watch = StallWatch::default();
        for i in 0..5 {
            assert_eq!(watch.observe(ring(i + 2, i, Some((i, i + 2))), 16), None);
        }
    }

    #[test]
    fn an_idle_ring_never_stalls() {
        let mut watch = StallWatch::default();
        let idle = ring(4, 4, Some((4, 4)));
        assert_eq!(watch.observe(idle, 16), None);
        assert_eq!(watch.observe(idle, 16), None);
        let no_event_idx = ring(4, 4, None);
        assert_eq!(watch.observe(no_event_idx, 16), None);
        assert_eq!(watch.observe(no_event_idx, 16), None);
    }

    #[test]
    fn more_chains_pending_than_the_queue_holds_are_not_a_lost_kick() {
        let mut watch = StallWatch::default();
        let full = ring(16, 0, None);
        watch.observe(full, 16);
        assert_eq!(watch.observe(full, 16), Some(stall(Some(16), None, false)));
        let mut watch = StallWatch::default();
        let past_full = ring(17, 0, None);
        watch.observe(past_full, 16);
        assert_eq!(watch.observe(past_full, 16), None);
    }

    #[test]
    fn a_stall_the_recovery_does_not_clear_is_warned_once() {
        let mut watch = StallWatch::default();
        let stuck = ring(0, 0, Some((1, 3)));
        watch.observe(stuck, 16);
        assert_eq!(watch.observe(stuck, 16), Some(stall(None, Some(2), false)));
        assert_eq!(watch.observe(stuck, 16), Some(stall(None, Some(2), true)));
        assert_eq!(watch.observe(stuck, 16), Some(stall(None, Some(2), true)));

        // The ring moves, then sticks again: a new episode.
        let moved = ring(0, 0, Some((3, 5)));
        assert_eq!(watch.observe(moved, 16), None);
        assert_eq!(watch.observe(moved, 16), Some(stall(None, Some(2), false)));
    }
}
