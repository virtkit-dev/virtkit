//! Pull an OCI image's rootfs straight from a registry (no docker daemon) and
//! flatten its layers — applying whiteouts — into a single rootfs tar, the same
//! shape `docker export` produces, which the ext4/cpio builders consume. With
//! the native ext4 writer this lets the whole pipeline drop docker, leaving
//! cloud-hypervisor as the only external dependency.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use oci_client::Reference;
use oci_client::client::{Certificate, CertificateEncoding, ClientConfig, ClientProtocol};
use oci_client::manifest;
use oci_client::secrets::RegistryAuth;

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
        merger.apply_layer(&layer.data, &layer.media_type)?;
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
}

struct Merger {
    entries: BTreeMap<String, Entry>,
    blob: std::fs::File,
    off: u64,
}

impl Merger {
    fn new(blob_path: &Path) -> Result<Self> {
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
    fn apply_layer(&mut self, blob: &[u8], media_type: &str) -> Result<()> {
        let reader: Box<dyn Read> = if media_type.contains("gzip") {
            Box::new(GzDecoder::new(blob))
        } else {
            Box::new(blob)
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
            let data = if header.entry_type().is_file() {
                let start = self.off;
                self.off += std::io::copy(&mut e, &mut self.blob)?;
                Some((start, self.off - start))
            } else {
                None
            };
            adds.push((path, Entry { header, data }));
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

    /// Write the merged set as a single rootfs tar; returns the entry count.
    fn finish(mut self, out_tar: &Path) -> Result<usize> {
        let file = std::fs::File::create(out_tar)
            .with_context(|| format!("creating {}", out_tar.display()))?;
        let mut builder = tar::Builder::new(file);
        let n = self.entries.len();
        // BTreeMap iterates in path order, so parents precede children
        let entries = std::mem::take(&mut self.entries);
        for (path, entry) in entries {
            let mut header = entry.header;
            match entry.data {
                Some((off, len)) => {
                    self.blob.seek(SeekFrom::Start(off))?;
                    let mut r = (&mut self.blob).take(len);
                    builder.append_data(&mut header, &path, &mut r)?;
                }
                None => {
                    builder.append_data(&mut header, &path, std::io::empty())?;
                }
            }
        }
        builder.into_inner()?.flush()?;
        Ok(n)
    }
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
