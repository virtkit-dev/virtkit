//! Pull an OCI image's rootfs straight from a registry (no docker daemon) and
//! flatten its layers — applying whiteouts — into a single rootfs tar, the same
//! shape `docker export` produces, which the ext4/cpio builders consume. With
//! the native ext4 writer this lets the whole pipeline drop docker, leaving
//! cloud-hypervisor as the only external dependency.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use oci_client::Reference;
use oci_client::client::{Certificate, CertificateEncoding, ClientConfig, ClientProtocol};
use oci_client::manifest;
use oci_client::secrets::RegistryAuth;

/// The parts of an OCI image's config a build inherits into a stage: environment
/// (notably `PATH`), default user and working directory.
#[derive(Default, Debug, Clone)]
pub struct ImageConfig {
    pub env: Vec<(String, String)>,
    pub user: Option<String>,
    pub workdir: Option<String>,
}

/// Pull `reference` and flatten it into a rootfs tar at `out_tar`.
pub async fn pull_flatten(
    reference: &str,
    username: Option<&str>,
    password: Option<&str>,
    ca_pem: Option<Vec<u8>>,
    insecure: bool,
    out_tar: &Path,
) -> Result<()> {
    let reference: Reference = reference
        .parse()
        .with_context(|| format!("parsing OCI reference {reference:?}"))?;
    let mut cfg = ClientConfig::default();
    if insecure {
        cfg.protocol = ClientProtocol::Http;
    }
    if let Some(data) = ca_pem {
        cfg.extra_root_certificates.push(Certificate {
            encoding: CertificateEncoding::Pem,
            data,
        });
    }
    let client = oci_client::Client::new(cfg);
    let auth = match (username, password) {
        (Some(u), Some(p)) => RegistryAuth::Basic(u.to_string(), p.to_string()),
        _ => RegistryAuth::Anonymous,
    };
    let accepted = vec![
        manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
        manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
        manifest::IMAGE_LAYER_MEDIA_TYPE,
        manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
    ];
    println!("virtkit: pulling OCI image {reference} ...");
    let image = client
        .pull(&reference, &auth, accepted)
        .await
        .with_context(|| format!("pulling {reference}"))?;

    let blob_path = out_tar.with_extension("blob");
    let mut merger = Merger::new(&blob_path)?;
    for layer in &image.layers {
        merger.apply_layer(&layer.data[..], &layer.media_type)?;
    }
    let n = merger.finish(out_tar)?;
    let _ = std::fs::remove_file(&blob_path);
    println!(
        "virtkit: flattened {} layers -> {n} entries",
        image.layers.len()
    );
    Ok(())
}

struct Entry {
    header: tar::Header,
    /// (offset, len) in the spill blob for regular files
    data: Option<(u64, u64)>,
    /// full link target for hardlinks/symlinks — captured from the entry (which
    /// resolves PAX/GNU extensions), since the cloned fixed header truncates names
    /// over 100 bytes. Re-emitted via `append_link` so long targets survive.
    link: Option<PathBuf>,
    /// xattrs from the entry's PAX `SCHILY.xattr.*` records (e.g.
    /// /usr/bin/ping's security.capability). Captured here and re-emitted as a PAX
    /// header in `finish_to`, since the `tar` writer has no native xattr support and
    /// cloning the fixed header alone would drop them.
    xattrs: Vec<(String, Vec<u8>)>,
}

/// Accumulates OCI layers into a single flattened rootfs, applying whiteouts and
/// opaque dirs. Shared by the registry path (`pull_flatten`) and the local-archive
/// path (`mkoci`); `apply_layer` is reader-generic so callers feed it either an
/// in-memory layer slice or a seeked file range over an OCI tar.
pub(crate) struct Merger {
    entries: BTreeMap<String, Entry>,
    blob: std::fs::File,
    off: u64,
}

impl Merger {
    pub(crate) fn new(blob_path: &Path) -> Result<Self> {
        // read+write: apply_layer appends file data, finish seeks back to read it
        Ok(Merger {
            entries: BTreeMap::new(),
            blob: std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(blob_path)
                .with_context(|| format!("creating {}", blob_path.display()))?,
            off: 0,
        })
    }

    /// Apply one layer: collect its entries + whiteouts, remove whited-out paths
    /// from the accumulated set, then merge this layer's entries (override).
    pub(crate) fn apply_layer(&mut self, reader: impl Read, media_type: &str) -> Result<()> {
        let reader: Box<dyn Read> = if media_type.contains("gzip") {
            Box::new(GzDecoder::new(reader))
        } else {
            Box::new(reader)
        };
        let mut ar = tar::Archive::new(reader);
        let mut adds: Vec<(String, Entry)> = Vec::new();
        let mut whiteouts: Vec<String> = Vec::new();
        let mut opaque: Vec<String> = Vec::new();
        for entry in ar.entries()? {
            let mut e = entry?;
            let path = normalize(&e.path()?.to_string_lossy());
            if path.is_empty() {
                continue;
            }
            let (parent, base) = split(&path);
            if base == ".wh..wh..opq" {
                opaque.push(parent.to_string());
                continue;
            }
            if let Some(orig) = base.strip_prefix(".wh.") {
                whiteouts.push(join(parent, orig));
                continue;
            }
            let header = e.header().clone();
            let et = header.entry_type();
            // capture PAX xattrs before reading the data (pax_extensions reads the
            // already-parsed extension header, not the data stream).
            let xattrs = crate::ext4::tar_xattrs(&mut e);
            let mut data = None;
            let mut link = None;
            if et.is_file() {
                let start = self.off;
                self.off += std::io::copy(&mut e, &mut self.blob)?;
                data = Some((start, self.off - start));
            } else if et.is_hard_link() || et.is_symlink() {
                // capture the full (PAX/GNU-resolved) target; the fixed header alone
                // truncates targets over 100 bytes (e.g. uv's deep tool hardlinks).
                link = e.link_name()?.map(|p| p.into_owned());
            }
            adds.push((
                path,
                Entry {
                    header,
                    data,
                    link,
                    xattrs,
                },
            ));
        }
        for dir in opaque {
            let prefix = format!("{dir}/");
            self.entries.retain(|k, _| !k.starts_with(&prefix));
        }
        for w in whiteouts {
            let prefix = format!("{w}/");
            self.entries.remove(&w);
            self.entries.retain(|k, _| !k.starts_with(&prefix));
        }
        for (p, e) in adds {
            self.entries.insert(p, e);
        }
        Ok(())
    }

    /// Total file-content bytes accumulated in the spill (an upper bound on the
    /// rootfs data size, for sizing a streamed ext4).
    pub(crate) fn data_bytes(&self) -> u64 {
        self.off
    }

    /// Number of merged entries (files + dirs + links), for sizing the inode table.
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Write the merged set as a single rootfs tar to `out_tar`; returns the entry
    /// count.
    pub(crate) fn finish(self, out_tar: &Path) -> Result<usize> {
        let file = std::fs::File::create(out_tar)
            .with_context(|| format!("creating {}", out_tar.display()))?;
        self.finish_to(file)
    }

    /// Write the merged set as a single rootfs tar to any writer; returns the entry
    /// count. Lets the caller stream the flattened rootfs straight into the ext4
    /// builder (via a pipe) instead of materialising an intermediate tar file.
    pub(crate) fn finish_to<W: Write>(mut self, w: W) -> Result<usize> {
        let mut builder = tar::Builder::new(w);
        let n = self.entries.len();
        // BTreeMap iterates in path order, so parents precede children
        let entries = std::mem::take(&mut self.entries);
        for (path, entry) in entries {
            // Preserve xattrs (e.g. /usr/bin/ping's security.capability): emit a PAX
            // extended-header entry just before this member, which the tar reader pairs
            // with it. The `tar` writer has no native xattr support, but a manually
            // appended `x` header is enough — no fork needed.
            if !entry.xattrs.is_empty() {
                append_xattr_header(&mut builder, &entry.xattrs)?;
            }
            let mut header = entry.header;
            match (entry.data, entry.link) {
                (Some((off, len)), _) => {
                    self.blob.seek(SeekFrom::Start(off))?;
                    let mut r = (&mut self.blob).take(len);
                    builder.append_data(&mut header, &path, &mut r)?;
                }
                // hardlink/symlink: append_link emits a GNU long-link extension when
                // the target exceeds the 100-byte header field, so it isn't truncated.
                (None, Some(target)) => {
                    builder.append_link(&mut header, &path, &target)?;
                }
                (None, None) => {
                    builder.append_data(&mut header, &path, std::io::empty())?;
                }
            }
        }
        builder.into_inner()?.flush()?;
        Ok(n)
    }
}

/// Append a PAX extended-header (`x`) entry carrying `xattrs` as `SCHILY.xattr.<name>`
/// records — the encoding `docker export` uses and `ext4::tar_xattrs` reads. The tar
/// reader applies a preceding `x` entry to the next member, so this restores the
/// file capabilities the layer carried (the `tar` writer has no xattr API of its own).
fn append_xattr_header<W: Write>(
    builder: &mut tar::Builder<W>,
    xattrs: &[(String, Vec<u8>)],
) -> Result<()> {
    let mut body = Vec::new();
    for (name, value) in xattrs {
        body.extend_from_slice(&pax_record(&format!("SCHILY.xattr.{name}"), value));
    }
    let mut h = tar::Header::new_gnu(); // GNU magic, so the reader recognizes the header
    h.set_entry_type(tar::EntryType::XHeader);
    h.set_size(body.len() as u64);
    h.set_mode(0o644);
    h.set_uid(0);
    h.set_gid(0);
    h.set_mtime(0);
    // the name is irrelevant to pairing (it's positional); a conventional short one
    // keeps it inside the 100-byte field (no GNU long-name entry).
    let _ = h.set_path("PaxHeaders.0/xattr");
    h.set_cksum();
    builder
        .append(&h, &body[..])
        .context("appending a PAX xattr header")?;
    Ok(())
}

/// Encode one PAX record: `"<len> key=value\n"`, where `len` is the total byte length
/// of the record *including its own decimal digits* (the standard self-referential
/// length). Binary-safe: the value bytes are written verbatim (readers length-prefix).
fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
    // bytes other than the leading length digits: ' ' + key + '=' + value + '\n'
    let fixed = 1 + key.len() + 1 + value.len() + 1;
    let mut len = fixed + 1;
    loop {
        let digits = len.to_string().len();
        if fixed + digits == len {
            break;
        }
        len = fixed + digits;
    }
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(len.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(key.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    out
}

fn normalize(path: &str) -> String {
    path.trim_start_matches("./")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

fn split(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((p, b)) => (p, b),
        None => ("", path),
    }
}

fn join(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn pax_record_length_counts_itself() {
        assert_eq!(pax_record("k", b"v"), b"6 k=v\n");
        // a longer record whose length crosses a digit boundary still self-consistent:
        // the declared length equals the encoded record's total byte length.
        let r = pax_record("SCHILY.xattr.security.capability", &[0u8; 64]);
        let sp = r.iter().position(|&c| c == b' ').unwrap();
        let declared: usize = std::str::from_utf8(&r[..sp]).unwrap().parse().unwrap();
        assert_eq!(declared, r.len());
    }

    /// A file's `security.capability` xattr must survive the layer flatten: captured
    /// on input (PAX), re-emitted as a PAX header in the merged tar, and read back by
    /// the same reader the ext4 builder uses (`ext4::tar_xattrs`). This is the
    /// regression that broke `ping` (missing cap_net_raw).
    #[test]
    fn xattrs_survive_flatten() {
        // a realistic vfs_cap_data blob (magic/rev + cap_net_raw bit), any bytes do.
        let cap = vec![
            0x01, 0x00, 0x00, 0x02, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // input layer: a PAX xattr header followed by /usr/bin/ping.
        let mut b = tar::Builder::new(Vec::new());
        append_xattr_header(&mut b, &[("security.capability".to_string(), cap.clone())]).unwrap();
        let mut h = tar::Header::new_gnu();
        h.set_path("usr/bin/ping").unwrap();
        h.set_size(4);
        h.set_mode(0o755);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append(&h, &b"ping"[..]).unwrap();
        let layer = b.into_inner().unwrap();

        let dir = std::env::temp_dir().join(format!("virtkit-oci-xattr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut m = Merger::new(&dir.join("blob")).unwrap();
        m.apply_layer(
            Cursor::new(&layer),
            "application/vnd.oci.image.layer.v1.tar",
        )
        .unwrap();
        let mut out = Vec::new();
        m.finish_to(&mut out).unwrap();
        let _ = std::fs::remove_dir_all(&dir);

        // read the merged tar back; the xattr must be present on the file.
        let mut ar = tar::Archive::new(Cursor::new(&out));
        let mut found = None;
        for e in ar.entries().unwrap() {
            let mut e = e.unwrap();
            if e.path().unwrap().to_string_lossy() == "usr/bin/ping" {
                found = Some(crate::ext4::tar_xattrs(&mut e));
            }
        }
        assert_eq!(
            found.expect("ping entry present in the merged tar"),
            vec![("security.capability".to_string(), cap)],
            "security.capability must survive the flatten"
        );
    }
}
