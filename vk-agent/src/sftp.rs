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
//! does is hand the user something it did not create: an ownership change applies only
//! to what this request made, and neither it nor a mode change follows a symlink, which
//! any process in the guest could have planted where the client is about to write.

use std::collections::HashMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

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

    /// Give a file this request just created, open as `file`, to the logged-in user.
    fn chown_open(&self, file: &tokio::fs::File) {
        use std::os::fd::AsRawFd;
        // SAFETY: fchown(2) on a descriptor `file` owns and keeps open for the call.
        unsafe { libc::fchown(file.as_raw_fd(), self.uid, self.gid) };
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
    use std::os::unix::fs::MetadataExt;
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
        let opts = |create: bool, create_new: bool| {
            let mut o = tokio::fs::OpenOptions::new();
            o.read(pflags.contains(OpenFlags::READ))
                .write(pflags.contains(OpenFlags::WRITE))
                .append(pflags.contains(OpenFlags::APPEND))
                .create(create)
                .truncate(pflags.contains(OpenFlags::TRUNCATE))
                .create_new(create_new);
            o
        };
        // Only a file this open creates becomes the user's. Asked of the kernel in one step —
        // an exclusive create, which neither follows nor replaces a symlink — rather than by
        // looking first: a link planted between the look and the open would be followed, and
        // root would hand the user whatever it names. Anything already there keeps its owner.
        let file = if pflags.contains(OpenFlags::CREATE) || pflags.contains(OpenFlags::EXCLUDE) {
            match opts(false, true).open(&filename).await {
                Ok(file) => {
                    self.chown_open(&file);
                    file
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::AlreadyExists
                        && !pflags.contains(OpenFlags::EXCLUDE) =>
                {
                    opts(false, false).open(&filename).await.map_err(map_err)?
                }
                Err(e) => return Err(map_err(e)),
            }
        } else {
            opts(false, false).open(&filename).await.map_err(map_err)?
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
        tokio::fs::create_dir(&path).await.map_err(map_err)?;
        // Through a descriptor on the directory just made, never following a link: one swapped
        // in at the name since keeps its owner, and the chown is simply skipped.
        if let Ok(dir) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&path)
        {
            use std::os::fd::AsRawFd;
            // SAFETY: fchown(2) on a descriptor `dir` owns and keeps open for the call.
            unsafe { libc::fchown(dir.as_raw_fd(), self.uid, self.gid) };
        }
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

/// Apply the file mode from setstat (VS Code chmods the server binary +x), through a
/// descriptor opened without following a symlink: a link planted at `path` must not have root
/// change the mode of whatever it names.
async fn apply_setstat(path: &std::path::Path, attrs: &FileAttributes) -> Result<(), StatusCode> {
    if let Some(perms) = attrs.permissions {
        use std::os::unix::fs::PermissionsExt;
        debug!("sftp setstat {} mode {:o}", path.display(), perms);
        // An O_PATH descriptor names the inode without opening it — so a device node's driver
        // never runs as root here — and O_NOFOLLOW makes a symlink at `path` an error. Its
        // mode is then set through the descriptor's /proc link, which reaches that inode.
        use std::os::fd::FromRawFd;
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| StatusCode::BadMessage)?;
        // SAFETY: the path is NUL-terminated and outlives the call; on success the descriptor
        // is fresh and owned by `pinned` from here on.
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
        let pinned = unsafe { std::fs::File::from_raw_fd(fd) };
        let meta = pinned.metadata().map_err(map_err)?;
        if meta.file_type().is_symlink() {
            return Err(StatusCode::PermissionDenied);
        }
        use std::os::fd::AsRawFd;
        let via = format!("/proc/self/fd/{}", pinned.as_raw_fd());
        tokio::fs::set_permissions(&via, std::fs::Permissions::from_mode(perms))
            .await
            .map_err(map_err)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

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

    /// Open-with-create makes a missing file and opens an existing one as asked, without
    /// truncating it unless told to.
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
}
