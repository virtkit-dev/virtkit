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
use russh_sftp::protocol::{
    File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt};

/// Serve SFTP over `stream` (a session channel) as the given user. russh-sftp
/// serves on its own task until the client disconnects; the returned receiver
/// fires when that task ends, so the caller can send the channel's exit-status
/// (scp/VS Code treat a missing exit-status as failure).
pub async fn serve<S>(stream: S, uid: u32, gid: u32) -> tokio::sync::oneshot::Receiver<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = tokio::sync::oneshot::channel();
    russh_sftp::server::run(
        OnDrop {
            inner: stream,
            tx: Some(tx),
        },
        SftpFs::new(uid, gid),
    )
    .await;
    rx
}

/// Wraps the channel stream to fire a oneshot when russh-sftp drops it (session
/// end) — russh-sftp's `run` spawns detached and hands back no completion handle.
struct OnDrop<S> {
    inner: S,
    tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<S> Drop for OnDrop<S> {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(());
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for OnDrop<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for OnDrop<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
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
