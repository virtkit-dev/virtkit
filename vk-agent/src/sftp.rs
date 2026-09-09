//! A filesystem-backed SFTP server (russh-sftp), run in-process by ssh-serve over
//! the session channel when a client opens the `sftp` subsystem. This is the path
//! VS Code Remote-SSH uses to copy its server (scp/sftp), and what `scp`/`sftp`
//! clients use.
//!
//! ssh-serve runs as root (PID 1 of the dev VM), so the server runs the protocol
//! as root and chowns every file/dir it CREATES to the logged-in user, so the
//! VS Code server tree ends up owned by `dev`. NOTE: this means an sftp client can
//! touch root-owned paths — acceptable for a single-developer dev VM (the user
//! already has a shell there); running sftp as the user is a follow-up.

use std::collections::HashMap;
use std::ffi::CString;
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
/// russh-sftp owns the stream it serves and drops it when the client's EOF arrives; a
/// stream made straight from the channel closes the channel on that drop, from a task of
/// its own. An exit-status sent afterwards races that close, and the client that loses the
/// race sees the channel end with no status — scp then fails a copy it just completed. So
/// russh-sftp gets one end of an in-memory pipe instead, and this task splices the other
/// end to the channel halves it keeps: once the client's EOF has drained through, the
/// trailer goes out from here, queued behind every reply on the one sender that orders
/// them. (On the wire, russh may still send the status ahead of data it holds back for
/// the window; EOF and close stay behind both, which is what the client relies on.)
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

    /// Give a freshly created path to the logged-in user (ssh-serve is root).
    fn chown(&self, path: &str) {
        if let Ok(c) = CString::new(path) {
            unsafe { libc::chown(c.as_ptr(), self.uid, self.gid) };
        }
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
        let mut opts = tokio::fs::OpenOptions::new();
        opts.read(pflags.contains(OpenFlags::READ))
            .write(pflags.contains(OpenFlags::WRITE))
            .append(pflags.contains(OpenFlags::APPEND))
            .create(pflags.contains(OpenFlags::CREATE))
            .truncate(pflags.contains(OpenFlags::TRUNCATE))
            .create_new(pflags.contains(OpenFlags::EXCLUDE));
        let file = opts.open(&filename).await.map_err(map_err)?;
        if pflags.contains(OpenFlags::CREATE) {
            self.chown(&filename);
        }
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
        self.chown(&path);
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

/// Apply the file mode from setstat (VS Code chmods the server binary +x).
async fn apply_setstat(path: &std::path::Path, attrs: &FileAttributes) -> Result<(), StatusCode> {
    if let Some(perms) = attrs.permissions {
        use std::os::unix::fs::PermissionsExt;
        debug!("sftp setstat {} mode {:o}", path.display(), perms);
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(perms))
            .await
            .map_err(map_err)?;
    }
    Ok(())
}
