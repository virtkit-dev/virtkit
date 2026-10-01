//! A filesystem-backed SFTP server (russh-sftp), run in-process by ssh-serve over
//! the session channel when a client opens the `sftp` subsystem. This is the path
//! VS Code Remote-SSH uses to copy its server (scp/sftp), and what `scp`/`sftp`
//! clients use.
//!
//! ssh-serve runs as root (PID 1 of the dev VM), so the server runs the protocol
//! as root and chowns every file/dir it CREATES to the logged-in user, so the
//! VS Code server tree ends up owned by `dev`. NOTE: this means an sftp client can
//! touch root-owned paths — acceptable for a single-developer dev VM (the user
//! already has a shell there); running sftp as the user is a follow-up. What it never
//! does is hand the user something it did not create, since any process in the guest could
//! have planted a symlink, a file or a directory where the client is about to write: a file
//! is chowned only when an exclusive create made it, and a directory only when, opened
//! without following a link, it is still empty and root's. Ownership and mode changes
//! refuse a symlink at the final path component; plain opens, TRUNCATE included, follow one
//! as before, and a symlinked parent directory redirects any of them.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use log::debug;
use russh::Channel;
use russh::server::Msg;
use russh_sftp::protocol::{
    File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::ssh::ConnectionGone;

/// Bytes buffered each way between the channel and russh-sftp: one client packet's worth
/// (russh-sftp and OpenSSH cap it at 256 KiB), so a large read or write rarely waits on
/// the pipe while the copy on the other side drains it.
const PIPE_BUF: usize = 256 * 1024;

/// Serve SFTP over a session channel as the given user, then end the channel the way
/// scp and VS Code expect: exit-status, EOF and close, in that order.
///
/// russh-sftp owns its stream and drops it on client EOF. A channel stream spawns
/// a close on drop, racing a later exit-status; scp reports a completed copy as failed
/// if the close arrives first. Give russh-sftp an in-memory pipe instead and retain
/// the channel halves here. After client EOF drains through, queue exit-status, EOF
/// and close behind all replies on the same sender. On the wire, russh may send the
/// status before window-blocked data; EOF and close still follow both, as clients need.
///
/// Returns after ending the channel, or once the connection is gone; the caller spawns it.
pub(crate) async fn serve(chan: Channel<Msg>, uid: u32, gid: u32, mut gone: ConnectionGone) {
    let (mut read_half, write_half) = chan.split();
    // A duplex, not two simplex pipes: only `DuplexStream` closes both directions when
    // russh-sftp drops its end, and that close is what ends the outbound copy below.
    let (ours, theirs) = tokio::io::duplex(PIPE_BUF);
    russh_sftp::server::run(theirs, SftpFs::new(uid, gid)).await;

    let (mut from_sftp, mut to_sftp) = tokio::io::split(ours);
    let mut from_client = read_half.make_reader();
    let mut to_client = write_half.make_writer();
    // The client's EOF ends the inbound copy; shutting the pipe passes it on, russh-sftp
    // stops and drops its end, and the outbound copy ends once its last reply is through.
    let inbound = async {
        let copied = tokio::io::copy(&mut from_client, &mut to_sftp).await;
        // Shutting a pipe russh-sftp already dropped has nothing left to tell.
        let _ = to_sftp.shutdown().await;
        copied
    };
    let outbound = tokio::io::copy(&mut from_sftp, &mut to_client);
    // The copies end with the client's EOF — or with the connection, should that go first
    // while a writer sits parked on a window no one will adjust again.
    match gone.bound(async { tokio::join!(inbound, outbound) }).await {
        Some((inbound, outbound)) => {
            if let Err(e) = inbound.and(outbound) {
                debug!("sftp: splice ended early: {e}");
            }
        }
        None => debug!("sftp: connection gone mid-session"),
    }

    // The client may already be gone; there is no one left to tell.
    let _ = write_half.exit_status(0).await;
    let _ = write_half.eof().await;
    let _ = write_half.close().await;
}

struct SftpFs {
    uid: u32,
    gid: u32,
    version: Option<u32>,
    next: u64,
    files: HashMap<String, tokio::fs::File>,
    dirs: HashMap<String, DirHandle>,
}

impl SftpFs {
    fn new(uid: u32, gid: u32) -> Self {
        SftpFs {
            uid,
            gid,
            version: None,
            next: 0,
            files: HashMap::new(),
            dirs: HashMap::new(),
        }
    }

    /// Give the logged-in user ownership of `file`, created by this request.
    fn chown_open(&self, file: &tokio::fs::File) {
        give(file.as_raw_fd(), self.uid, self.gid);
    }
}

struct DirHandle {
    entries: Vec<File>,
    served: bool,
}

impl SftpFs {
    fn fresh(&mut self, prefix: char) -> String {
        let h = format!("{prefix}{}", self.next);
        self.next += 1;
        h
    }
}

/// fchown(2) `fd` to the user. A failure leaves the file root's, which the user can still
/// read but not change: logged, not fatal to the request.
fn give(fd: std::os::fd::RawFd, uid: u32, gid: u32) {
    // SAFETY: fchown(2) on a descriptor the caller keeps open for the call.
    if unsafe { libc::fchown(fd, uid, gid) } != 0 {
        debug!(
            "sftp: chown to {uid}:{gid} failed: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn map_err(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        _ => StatusCode::Failure,
    }
}

fn attrs_of(meta: &std::fs::Metadata) -> FileAttributes {
    FileAttributes::from(meta)
}

/// A minimal `ls -l`-style long name (some clients parse it; VS Code is lenient).
fn longname(name: &str, meta: &std::fs::Metadata) -> String {
    let kind = if meta.is_dir() { 'd' } else { '-' };
    format!(
        "{kind}--------- 1 {} {} {:>10} {name}",
        meta.uid(),
        meta.gid(),
        meta.len()
    )
}

impl russh_sftp::server::Handler for SftpFs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        self.version = Some(version);
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = if path.is_empty() {
            ".".to_string()
        } else {
            path
        };
        let canon = tokio::fs::canonicalize(&p)
            .await
            .map(|c| c.to_string_lossy().into_owned())
            .unwrap_or(p);
        Ok(Name {
            id,
            files: vec![File::dummy(&canon)],
        })
    }

    async fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let meta = tokio::fs::metadata(&path).await.map_err(map_err)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: attrs_of(&meta),
        })
    }

    async fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let meta = tokio::fs::symlink_metadata(&path).await.map_err(map_err)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: attrs_of(&meta),
        })
    }

    async fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        let f = self.files.get(&handle).ok_or(StatusCode::Failure)?;
        let meta = f.metadata().await.map_err(map_err)?;
        Ok(russh_sftp::protocol::Attrs {
            id,
            attrs: attrs_of(&meta),
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        _attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let opts = |create_new: bool| {
            let mut o = tokio::fs::OpenOptions::new();
            o.read(pflags.contains(OpenFlags::READ))
                .write(pflags.contains(OpenFlags::WRITE))
                .append(pflags.contains(OpenFlags::APPEND))
                .truncate(pflags.contains(OpenFlags::TRUNCATE))
                .create_new(create_new);
            o
        };
        // Only a file this open creates becomes the user's. Asked of the kernel in one step —
        // an exclusive create, which neither follows nor replaces a symlink — rather than by
        // looking first: a link planted between the look and the open would be followed, and
        // root would hand the user whatever it names. Anything already there keeps its owner.
        // A dangling symlink is thus an error (no such file), never a way to create its target.
        let file = if pflags.contains(OpenFlags::CREATE) || pflags.contains(OpenFlags::EXCLUDE) {
            let mut retried = false;
            loop {
                match opts(true).open(&filename).await {
                    Ok(file) => {
                        self.chown_open(&file);
                        break file;
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::AlreadyExists
                            && !pflags.contains(OpenFlags::EXCLUDE) =>
                    {
                        match opts(false).open(&filename).await {
                            Ok(file) => break file,
                            // The file disappeared after AlreadyExists; retry creation once.
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !retried => {
                                retried = true;
                            }
                            Err(e) => return Err(map_err(e)),
                        }
                    }
                    Err(e) => return Err(map_err(e)),
                }
            }
        } else {
            opts(false).open(&filename).await.map_err(map_err)?
        };
        let handle = self.fresh('f');
        self.files.insert(handle.clone(), file);
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<russh_sftp::protocol::Data, Self::Error> {
        let f = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        f.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(map_err)?;
        let mut buf = vec![0u8; len as usize];
        let n = f.read(&mut buf).await.map_err(map_err)?;
        if n == 0 {
            return Err(StatusCode::Eof);
        }
        buf.truncate(n);
        Ok(russh_sftp::protocol::Data { id, data: buf })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let f = self.files.get_mut(&handle).ok_or(StatusCode::Failure)?;
        f.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(map_err)?;
        f.write_all(&data).await.map_err(map_err)?;
        Ok(ok_status(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.files.remove(&handle);
        self.dirs.remove(&handle);
        Ok(ok_status(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let mut rd = tokio::fs::read_dir(&path).await.map_err(map_err)?;
        let mut entries = Vec::new();
        // "." and ".." keep clients that expect them happy.
        if let Ok(meta) = tokio::fs::metadata(&path).await {
            entries.push(named(".", &meta));
            entries.push(named("..", &meta));
        }
        while let Some(ent) = rd.next_entry().await.map_err(map_err)? {
            let name = ent.file_name().to_string_lossy().into_owned();
            if let Ok(meta) = ent.metadata().await {
                entries.push(named(&name, &meta));
            }
        }
        let handle = self.fresh('d');
        self.dirs.insert(
            handle.clone(),
            DirHandle {
                entries,
                served: false,
            },
        );
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let dir = self.dirs.get_mut(&handle).ok_or(StatusCode::Failure)?;
        if dir.served {
            return Err(StatusCode::Eof);
        }
        dir.served = true;
        Ok(Name {
            id,
            files: dir.entries.clone(),
        })
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let (uid, gid) = (self.uid, self.gid);
        tokio::task::spawn_blocking(move || mkdir_for(Path::new(&path), uid, gid))
            .await
            .map_err(|_| StatusCode::Failure)?
            .map_err(map_err)?;
        Ok(ok_status(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_dir(&path).await.map_err(map_err)?;
        Ok(ok_status(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_file(&filename).await.map_err(map_err)?;
        Ok(ok_status(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        tokio::fs::rename(&oldpath, &newpath)
            .await
            .map_err(map_err)?;
        Ok(ok_status(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        apply_setstat(&PathBuf::from(path), &attrs).await?;
        Ok(ok_status(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        _handle: String,
        _attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        // Best effort: permissions on the path matter more than on the open fd for
        // VS Code's transfer; accept silently so the upload proceeds.
        Ok(ok_status(id))
    }
}

fn ok_status(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

fn named(name: &str, meta: &std::fs::Metadata) -> File {
    File {
        filename: name.to_string(),
        longname: longname(name, meta),
        attrs: attrs_of(meta),
    }
}

/// Apply the setstat mode through a descriptor that does not follow symlinks, so a
/// planted link cannot make root chmod its target. VS Code uses this for the server binary +x.
async fn apply_setstat(path: &std::path::Path, attrs: &FileAttributes) -> Result<(), StatusCode> {
    if let Some(perms) = attrs.permissions {
        debug!("sftp setstat {} mode {:o}", path.display(), perms);
        // An O_PATH descriptor names the inode without opening it — so a device node's driver
        // never runs as root here — and O_NOFOLLOW makes a symlink at `path` an error. Its
        // mode is then set through the descriptor's /proc link, which reaches that inode.
        // Not through `OpenOptions::custom_flags`: on musl, std masks O_PATH out of custom
        // flags (`O_ACCMODE` includes `O_SEARCH == O_PATH`) and would really open the file.
        let c = CString::new(path.as_os_str().as_bytes()).map_err(|_| StatusCode::BadMessage)?;
        // SAFETY: the path is NUL-terminated and outlives the call.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(map_err(std::io::Error::last_os_error()));
        }
        // SAFETY: `fd` was just returned by open(2) and nothing else owns it.
        let pinned = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
        let meta = pinned.metadata().map_err(map_err)?;
        if meta.file_type().is_symlink() {
            return Err(StatusCode::PermissionDenied);
        }
        let via = format!("/proc/self/fd/{}", pinned.as_raw_fd());
        tokio::fs::set_permissions(&via, std::fs::Permissions::from_mode(perms))
            .await
            .map_err(map_err)?;
    }
    Ok(())
}

/// mkdir(2) `path` and give the new directory to the user — only if what then sits at the
/// name is that directory: opened through the same parent descriptor without following a
/// link, still owned by us (root), and empty. A directory renamed in at the name since
/// belongs to whoever made it or holds something, and keeps its owner; a symlink is refused.
fn mkdir_for(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
    let name = path.file_name().ok_or_else(invalid)?;
    let name = CString::new(name.as_bytes()).map_err(|_| invalid())?;
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(parent.unwrap_or(Path::new(".")))?;
    // SAFETY: the descriptor is live and the name is NUL-terminated and outlives the call.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o777) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: as above.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        debug!("sftp: not chowning {}: {e}", path.display());
        return Ok(());
    }
    // SAFETY: `fd` was just returned by openat(2) and nothing else owns it.
    let dir = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    match fresh_dir(&dir) {
        Ok(true) => give(dir.as_raw_fd(), uid, gid),
        Ok(false) => debug!("sftp: not chowning {}: replaced since", path.display()),
        Err(e) => debug!("sftp: not chowning {}: {e}", path.display()),
    }
    Ok(())
}

/// Whether the directory open as `dir` can be the one this process just made: ours and empty.
/// Emptiness is read through the descriptor's /proc link, which reaches that inode; the
/// link count is no help, as some filesystems report 1 for every directory.
fn fresh_dir(dir: &std::fs::File) -> std::io::Result<bool> {
    // SAFETY: geteuid(2) has no preconditions.
    if dir.metadata()?.uid() != unsafe { libc::geteuid() } {
        return Ok(false);
    }
    let via = format!("/proc/self/fd/{}", dir.as_raw_fd());
    Ok(std::fs::read_dir(via)?.next().is_none())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mode change lands on the path itself, never through a symlink planted there.
    #[tokio::test]
    async fn setstat_does_not_follow_a_symlink() {
        let dir = std::env::temp_dir().join(format!("vk-sftp-setstat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        std::fs::write(&target, b"x").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let attrs = FileAttributes {
            permissions: Some(0o777),
            ..FileAttributes::default()
        };

        assert!(apply_setstat(&link, &attrs).await.is_err());
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the link's target kept its mode");

        apply_setstat(&target, &attrs).await.unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o777, "the path itself is changed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FIFO (as a device node would be) has its mode set without being opened: an open
    /// would block on a FIFO and run a device's driver as root.
    #[tokio::test]
    async fn setstat_sets_a_fifos_mode_without_opening_it() {
        let dir = std::env::temp_dir().join(format!("vk-sftp-fifo-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("fifo");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: mkfifo(3) on a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let attrs = FileAttributes {
            permissions: Some(0o640),
            ..FileAttributes::default()
        };
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            apply_setstat(&fifo, &attrs),
        )
        .await
        .expect("setstat must not block on a FIFO")
        .unwrap();
        let mode = std::fs::metadata(&fifo).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CREATE makes a missing file or opens an existing one; only TRUNCATE discards contents.
    #[tokio::test]
    async fn open_with_create_takes_an_existing_file_as_it_is() {
        use russh_sftp::server::Handler;
        let dir = std::env::temp_dir().join(format!("vk-sftp-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: getuid(2)/getgid(2) have no preconditions.
        let mut fs = SftpFs::new(unsafe { libc::getuid() }, unsafe { libc::getgid() });
        let fresh = dir.join("fresh").to_string_lossy().into_owned();
        let flags = OpenFlags::CREATE | OpenFlags::WRITE;
        fs.open(1, fresh.clone(), flags, FileAttributes::default())
            .await
            .unwrap();
        assert!(std::path::Path::new(&fresh).is_file());

        let kept = dir.join("kept");
        std::fs::write(&kept, b"contents").unwrap();
        fs.open(
            2,
            kept.to_string_lossy().into_owned(),
            flags,
            FileAttributes::default(),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&kept).unwrap(), b"contents");
        // EXCLUDE on an existing file is refused.
        assert!(
            fs.open(
                3,
                kept.to_string_lossy().into_owned(),
                flags | OpenFlags::EXCLUDE,
                FileAttributes::default()
            )
            .await
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// CREATE on a dangling symlink fails rather than creating the file it names.
    #[tokio::test]
    async fn open_with_create_refuses_a_dangling_symlink() {
        use russh_sftp::server::Handler;
        let dir = std::env::temp_dir().join(format!("vk-sftp-dangling-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // SAFETY: getuid(2)/getgid(2) have no preconditions.
        let mut fs = SftpFs::new(unsafe { libc::getuid() }, unsafe { libc::getgid() });
        let flags = OpenFlags::CREATE | OpenFlags::WRITE;
        let opened = fs
            .open(
                1,
                link.to_string_lossy().into_owned(),
                flags,
                FileAttributes::default(),
            )
            .await;
        assert_eq!(opened.err(), Some(StatusCode::NoSuchFile));
        assert!(!target.exists(), "the link's target was not created");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// mkdir makes the directory and gives it to the user; an existing name is refused.
    #[tokio::test]
    async fn mkdir_creates_a_directory_for_the_user() {
        use russh_sftp::server::Handler;
        let dir = std::env::temp_dir().join(format!("vk-sftp-mkdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // SAFETY: getuid(2)/getgid(2) have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let mut fs = SftpFs::new(uid, gid);
        let new = dir.join("new");
        fs.mkdir(
            1,
            new.to_string_lossy().into_owned(),
            FileAttributes::default(),
        )
        .await
        .unwrap();
        let meta = std::fs::symlink_metadata(&new).unwrap();
        assert!(meta.is_dir());
        assert_eq!(meta.uid(), uid);
        assert!(
            fs.mkdir(
                2,
                new.to_string_lossy().into_owned(),
                FileAttributes::default()
            )
            .await
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A nonempty replacement directory keeps its owner; only an empty one of ours qualifies.
    #[test]
    fn fresh_dir_refuses_a_non_empty_directory() {
        let dir = std::env::temp_dir().join(format!("vk-sftp-fresh-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let open = |p: &Path| {
            std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY)
                .open(p)
                .unwrap()
        };
        let empty = dir.join("empty");
        std::fs::create_dir(&empty).unwrap();
        assert!(fresh_dir(&open(&empty)).unwrap());
        let full = dir.join("full");
        std::fs::create_dir(&full).unwrap();
        std::fs::write(full.join("x"), b"").unwrap();
        assert!(!fresh_dir(&open(&full)).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
