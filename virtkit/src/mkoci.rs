//! Turn a local OCI image archive (the tar `buildctl --output type=oci` produces)
//! directly into a bootable ext4 rootfs — flattening layers AND extracting the
//! image config (Env/User/Entrypoint/Cmd) — with no docker/podman. This collapses
//! the old `podman load → create → export → mkext-tar` chain into a single
//! `buildctl … --output type=oci,dest=- | virtkit mkext-oci - out.ext4 …` pass.
//!
//! OCI archives need random access (`index.json` is last and blobs are sorted by
//! digest, so layers must be applied in manifest order, not tar order), so a
//! streamed stdin archive is spooled to a temp file first; then the blob byte
//! ranges are indexed in one scan and read back by seeking.

use std::collections::BTreeMap;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::ext4;
use crate::oci::Merger;

/// Minimal views of the OCI JSON documents we read out of the archive. Defined
/// locally (rather than via oci-client's types) because we deserialize raw blobs
/// off disk and only need a few fields; the platform enums live in oci-spec, not
/// a direct dependency.
#[derive(Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
}

#[derive(Deserialize)]
struct Index {
    manifests: Vec<IndexEntry>,
}

#[derive(Deserialize)]
struct IndexEntry {
    #[serde(rename = "mediaType")]
    media_type: String,
    digest: String,
    platform: Option<Platform>,
}

#[derive(Deserialize)]
struct Platform {
    architecture: String,
    os: String,
}

#[derive(Deserialize)]
struct Manifest {
    config: Descriptor,
    layers: Vec<Descriptor>,
}

#[derive(Deserialize)]
struct ConfigFile {
    config: Option<ImageConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImageConfig {
    env: Option<Vec<String>>,
    user: Option<String>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
}

/// Build an ext4 rootfs from a local OCI image archive.
///
/// `archive` is the OCI tar (or "-" to read stdin, spooled to a temp file). The
/// caller's `injects` (image-relative guest path, host path, octal mode) are
/// applied alongside three auto-generated config files derived from the image:
/// `/etc/virtkit/{env,user,cmd}`, so the caller never needs podman. Shared by the
/// `mkext-oci` CLI dispatch and the `build` subcommand.
pub(crate) fn archive_to_ext4(
    archive: &Path,
    out: &Path,
    injects: &[(&str, &Path, u16)],
    env_files: &[PathBuf],
    extra_free_blocks: u64,
    fsid: &ext4::FsId,
) -> Result<()> {
    // staging dir next to the output for the spooled archive, blob spill, and
    // generated config files; removed on the way out. (The flattened rootfs is
    // streamed straight into the ext4 builder, not staged.)
    let work = out.with_extension("mkoci.tmp");
    std::fs::create_dir_all(&work).with_context(|| format!("creating {}", work.display()))?;
    let r = build_inner(
        archive,
        out,
        injects,
        env_files,
        extra_free_blocks,
        fsid,
        &work,
    );
    let _ = std::fs::remove_dir_all(&work);
    r
}

fn build_inner(
    archive: &Path,
    out: &Path,
    injects: &[(&str, &Path, u16)],
    env_files: &[PathBuf],
    extra_free_blocks: u64,
    fsid: &ext4::FsId,
    work: &Path,
) -> Result<()> {
    // OCI archives need random access, so a streamed stdin archive is spooled to
    // a temp file first; an on-disk archive is opened in place.
    let archive_path: PathBuf = if archive.as_os_str() == "-" {
        let spool = work.join("archive.tar");
        let mut f = std::fs::File::create(&spool)
            .with_context(|| format!("creating {}", spool.display()))?;
        std::io::copy(&mut std::io::stdin().lock(), &mut f)
            .context("spooling OCI archive stdin")?;
        spool
    } else {
        archive.to_path_buf()
    };

    let mut ar = OciArchive::open(&archive_path)?;

    // index.json → first manifest descriptor; if it points at a multi-arch image
    // index, descend into it and pick linux/amd64.
    let index: Index = ar.read_json(INDEX_PATH)?;
    let top = index
        .manifests
        .into_iter()
        .next()
        .context("index.json has no manifests")?;
    let manifest_digest = if is_index(&top.media_type) {
        let sub: Index = ar.read_json(&blob_path(&top.digest))?;
        sub.manifests
            .iter()
            .find(|m| {
                m.platform
                    .as_ref()
                    .is_some_and(|p| p.os == "linux" && p.architecture == "amd64")
            })
            .map(|m| m.digest.clone())
            .context("image index has no linux/amd64 manifest")?
    } else {
        top.digest
    };

    let manifest: Manifest = ar.read_json(&blob_path(&manifest_digest))?;
    let config: ConfigFile = ar.read_json(&blob_path(&manifest.config.digest))?;

    // Auto-generate the three config files (dropped by the layer flattening,
    // restored at boot by the agent, VIRTKIT_MODE=service) up front, so they are
    // ready as injects before we start streaming the rootfs.
    let ic = config.config.unwrap_or(ImageConfig {
        env: None,
        user: None,
        entrypoint: None,
        cmd: None,
    });
    let env_file = work.join("env");
    let user_file = work.join("user");
    let cmd_file = work.join("cmd");
    std::fs::write(
        &env_file,
        render_env_with_files(ic.env.as_deref().unwrap_or(&[]), env_files)?,
    )
    .with_context(|| format!("writing {}", env_file.display()))?;
    std::fs::write(
        &user_file,
        format!("{}\n", ic.user.as_deref().unwrap_or("")),
    )
    .with_context(|| format!("writing {}", user_file.display()))?;
    std::fs::write(
        &cmd_file,
        render_cmd_file(
            ic.entrypoint.as_deref().unwrap_or(&[]),
            ic.cmd.as_deref().unwrap_or(&[]),
        ),
    )
    .with_context(|| format!("writing {}", cmd_file.display()))?;

    // caller injects first, then the generated config files (image-relative paths).
    let mut all: Vec<(&str, &Path, u16)> = injects.to_vec();
    all.push(("etc/virtkit/env", env_file.as_path(), 0o644));
    all.push(("etc/virtkit/user", user_file.as_path(), 0o644));
    all.push(("etc/virtkit/cmd", cmd_file.as_path(), 0o644));

    // flatten layers in manifest order through the shared Merger.
    let blob_spill = work.join("rootfs.blob");
    let mut merger = Merger::new(&blob_spill)?;
    for layer in &manifest.layers {
        let (off, size) = ar.blob_range(&blob_path(&layer.digest))?;
        ar.file.seek(SeekFrom::Start(off))?;
        let reader = (&mut ar.file).take(size);
        merger.apply_layer(reader, &layer.media_type)?;
    }

    let layers_n = manifest.layers.len();
    let entry_count = merger.entry_count();
    // Sparse upper bound for the streamed ext4: file-content bytes + per-file
    // block-rounding slack + a fixed margin (the image is sparse, so over-sizing
    // is free). inodes: one per entry plus the injects and headroom.
    let image_bytes = merger.data_bytes() + (entry_count as u64) * 4096 + 256 * 1024 * 1024;
    let inodes = entry_count as u64 + all.len() as u64 + 4096;

    // Stream the flattened rootfs straight from the Merger into the ext4 builder
    // through an OS pipe — no intermediate rootfs tar on disk (saves a multi-GB
    // write+read pass on large images). A writer thread emits the tar; this thread
    // consumes it and writes the ext4.
    let (rd, wr) = os_pipe()?;
    let writer = std::thread::spawn(move || -> Result<usize> {
        merger.finish_to(BufWriter::with_capacity(1 << 20, wr))
    });
    let build = ext4::build_from_tar_stream(
        BufReader::with_capacity(1 << 20, rd),
        &all,
        image_bytes,
        extra_free_blocks,
        Some(inodes),
        fsid,
        out,
    );
    // Surface the build error first (a writer BrokenPipe would just be its symptom);
    // otherwise propagate a merger failure. join() can't deadlock: when the ext4
    // builder returns it has dropped the read end, so a still-writing merger unblocks
    // with EPIPE.
    let merged = writer
        .join()
        .map_err(|_| anyhow::anyhow!("rootfs merger thread panicked"))?;
    build?;
    let n = merged?;
    println!("virtkit: flattened {layers_n} layers -> {n} entries");
    Ok(())
}

/// A unidirectional OS pipe as a (read, write) pair of owned files, for streaming
/// the flattened rootfs from the merger thread into the ext4 builder.
fn os_pipe() -> Result<(std::fs::File, std::fs::File)> {
    let mut fds = [0i32; 2];
    // SAFETY: pipe2(2) writes two fresh fds into the array on success. O_CLOEXEC
    // keeps them from leaking into any concurrent fork+exec.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(std::io::Error::last_os_error()).context("creating pipe");
    }
    // SAFETY: both fds are freshly created and owned; wrap them in Files.
    let read = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let write = unsafe { std::fs::File::from_raw_fd(fds[1]) };
    Ok((read, write))
}

const INDEX_PATH: &str = "index.json";

/// An OCI image media type is an image **index** (multi-arch) when its type names
/// an index/manifest list rather than a single image manifest.
fn is_index(media_type: &str) -> bool {
    media_type.contains("image.index") || media_type.contains("manifest.list")
}

/// Map a `sha256:<hex>` digest to its in-archive blob path.
fn blob_path(digest: &str) -> String {
    let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
    format!("blobs/sha256/{hex}")
}

/// Render `/etc/virtkit/env`: raw KEY=VALUE lines, dropping any without `=` (the
/// agent takes the rest of the line verbatim). Mirrors convert.rs::render_env_file.
fn render_env_file(env: &[String]) -> String {
    let mut out = String::new();
    for line in env {
        if line.split_once('=').is_some() {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Render `/etc/virtkit/env` from the image-config env first, then each caller
/// env-file's lines appended in order — all under the same `=`-only rule: lines
/// without an `=` are dropped (blank lines and typical `#` comments).
fn render_env_with_files(env: &[String], env_files: &[PathBuf]) -> Result<String> {
    let mut out = render_env_file(env);
    for ef in env_files {
        let raw = std::fs::read_to_string(ef)
            .with_context(|| format!("reading env-file {}", ef.display()))?;
        let lines: Vec<String> = raw.lines().map(str::to_string).collect();
        out.push_str(&render_env_file(&lines));
    }
    Ok(out)
}

/// Render `/etc/virtkit/cmd`: Entrypoint argv then Cmd argv, one element per line.
fn render_cmd_file(entrypoint: &[String], cmd: &[String]) -> String {
    let mut out = String::new();
    for arg in entrypoint.iter().chain(cmd) {
        out.push_str(arg);
        out.push('\n');
    }
    out
}

/// Random-access reader over an OCI archive: a one-pass index of every blob's
/// byte range plus the open file to seek into.
struct OciArchive {
    file: std::fs::File,
    /// in-archive path (`blobs/sha256/<hex>`, `index.json`, …) -> (offset, size)
    ranges: BTreeMap<String, (u64, u64)>,
}

impl OciArchive {
    fn open(path: &Path) -> Result<Self> {
        let mut ranges = BTreeMap::new();
        let file =
            std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let mut ar = tar::Archive::new(&file);
        for entry in ar.entries()? {
            let e = entry?;
            let name = e
                .path()?
                .to_string_lossy()
                .trim_start_matches("./")
                .to_string();
            ranges.insert(name, (e.raw_file_position(), e.size()));
        }
        Ok(OciArchive { file, ranges })
    }

    fn blob_range(&self, name: &str) -> Result<(u64, u64)> {
        self.ranges
            .get(name)
            .copied()
            .with_context(|| format!("blob {name} not found in OCI archive"))
    }

    fn read_blob(&mut self, name: &str) -> Result<Vec<u8>> {
        let (off, size) = self.blob_range(name)?;
        self.file.seek(SeekFrom::Start(off))?;
        let mut buf = vec![0u8; size as usize];
        self.file
            .read_exact(&mut buf)
            .with_context(|| format!("reading blob {name}"))?;
        Ok(buf)
    }

    fn read_json<T: serde::de::DeserializeOwned>(&mut self, name: &str) -> Result<T> {
        let buf = self.read_blob(name)?;
        serde_json::from_slice(&buf).with_context(|| format!("parsing {name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tar::{Builder, Header};

    /// Append a tar entry with explicit mode/path/contents.
    fn add(b: &mut Builder<Vec<u8>>, path: &str, mode: u32, data: &[u8]) {
        let mut h = Header::new_gnu();
        h.set_path(path).unwrap();
        h.set_size(data.len() as u64);
        h.set_mode(mode);
        h.set_entry_type(tar::EntryType::Regular);
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    /// Build a single (uncompressed) tar layer from (path, contents) pairs.
    fn layer(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = Builder::new(Vec::new());
        for (p, d) in entries {
            add(&mut b, p, 0o644, d);
        }
        b.into_inner().unwrap()
    }

    fn sha256_hex(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Drop a blob into the archive builder under blobs/sha256/<digest> and
    /// return its `sha256:` digest.
    fn put_blob(b: &mut Builder<Vec<u8>>, data: &[u8]) -> String {
        let hex = sha256_hex(data);
        add(b, &format!("blobs/sha256/{hex}"), 0o644, data);
        format!("sha256:{hex}")
    }

    /// Build a minimal valid OCI archive: two tar layers (the second whites out
    /// one of the first's files and overrides another), a config with Env/User/
    /// Entrypoint/Cmd, a manifest, and index.json — written in OCI order (blobs
    /// first, index.json last, blobs digest-sorted) to exercise random access.
    fn build_fixture() -> Vec<u8> {
        let l1 = layer(&[
            ("etc/keep.conf", b"keep\n"),
            ("etc/gone.conf", b"old\n"),
            ("app/main", b"v1\n"),
        ]);
        // layer 2: whiteout etc/gone.conf (the .wh. prefix sits on the basename)
        // and override app/main.
        let l2 = layer(&[("etc/.wh.gone.conf", b""), ("app/main", b"v2\n")]);

        let config = serde_json::json!({
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Env": ["PATH=/usr/bin", "FOO=bar", "MALFORMED"],
                "User": "svc",
                "Entrypoint": ["/app/main", "--serve"],
                "Cmd": ["--port", "8080"],
            }
        });
        let config_bytes = serde_json::to_vec(&config).unwrap();

        let mut b = Builder::new(Vec::new());
        add(
            &mut b,
            "oci-layout",
            0o644,
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        );
        let l1_digest = put_blob(&mut b, &l1);
        let l2_digest = put_blob(&mut b, &l2);
        let config_digest = put_blob(&mut b, &config_bytes);

        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config_bytes.len(),
            },
            "layers": [
                {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": l1_digest, "size": l1.len()},
                {"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": l2_digest, "size": l2.len()},
            ],
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let manifest_digest = put_blob(&mut b, &manifest_bytes);

        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": manifest_bytes.len(),
            }],
        });
        add(
            &mut b,
            "index.json",
            0o644,
            &serde_json::to_vec(&index).unwrap(),
        );
        b.into_inner().unwrap()
    }

    /// End-to-end of the parse + flatten + config-render path (no ext4 bytes):
    /// the flattened rootfs must show the whiteout applied and the override won,
    /// and the rendered env/user/cmd must match the image config.
    #[test]
    fn parse_flatten_and_render() {
        let dir = std::env::temp_dir().join(format!("virtkit-mkoci-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let archive_path = dir.join("image.tar");
        std::fs::File::create(&archive_path)
            .unwrap()
            .write_all(&build_fixture())
            .unwrap();

        let mut ar = OciArchive::open(&archive_path).unwrap();
        let index: Index = ar.read_json(INDEX_PATH).unwrap();
        let manifest: Manifest = ar
            .read_json(&blob_path(&index.manifests[0].digest))
            .unwrap();
        let config: ConfigFile = ar.read_json(&blob_path(&manifest.config.digest)).unwrap();

        // flatten through the shared Merger.
        let spill = dir.join("spill");
        let mut merger = Merger::new(&spill).unwrap();
        for layer in &manifest.layers {
            let (off, size) = ar.blob_range(&blob_path(&layer.digest)).unwrap();
            ar.file.seek(SeekFrom::Start(off)).unwrap();
            let reader = (&mut ar.file).take(size);
            merger.apply_layer(reader, &layer.media_type).unwrap();
        }
        let rootfs = dir.join("rootfs.tar");
        merger.finish(&rootfs).unwrap();

        // collect the flattened rootfs into path -> contents.
        let mut files = std::collections::BTreeMap::new();
        let mut a = tar::Archive::new(std::fs::File::open(&rootfs).unwrap());
        for e in a.entries().unwrap() {
            let mut e = e.unwrap();
            let p = e.path().unwrap().to_string_lossy().into_owned();
            let mut s = String::new();
            use std::io::Read as _;
            let _ = e.read_to_string(&mut s);
            files.insert(p, s);
        }
        assert_eq!(
            files.get("etc/keep.conf").map(String::as_str),
            Some("keep\n")
        );
        assert!(!files.contains_key("etc/gone.conf"), "whiteout not applied");
        assert_eq!(
            files.get("app/main").map(String::as_str),
            Some("v2\n"),
            "layer-2 override did not win"
        );

        // config render.
        let ic = config.config.unwrap();
        assert_eq!(
            render_env_file(ic.env.as_deref().unwrap()),
            "PATH=/usr/bin\nFOO=bar\n",
            "malformed env line should be dropped"
        );
        assert_eq!(format!("{}\n", ic.user.as_deref().unwrap()), "svc\n");
        assert_eq!(
            render_cmd_file(
                ic.entrypoint.as_deref().unwrap(),
                ic.cmd.as_deref().unwrap()
            ),
            "/app/main\n--serve\n--port\n8080\n"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    // An env-file appends its `=`-lines to the rendered image-config env, in order,
    // dropping any non-`=` line (blanks, comments, bare tokens).
    #[test]
    fn env_file_appends_eq_lines_and_drops_others() {
        let dir = std::env::temp_dir().join(format!("virtkit-envfile-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ef = dir.join("dev.env");
        std::fs::write(&ef, "FOO_TEST=bar\n# comment\nNOEQ\n\nBAZ=1\n").unwrap();

        let image_env = vec!["PATH=/usr/bin".to_string()];
        let rendered = render_env_with_files(&image_env, std::slice::from_ref(&ef)).unwrap();

        // image-config env first, then the env-file's `=`-lines in order; NOEQ/comment/
        // blank dropped.
        assert_eq!(rendered, "PATH=/usr/bin\nFOO_TEST=bar\nBAZ=1\n");
        assert!(!rendered.contains("NOEQ"));

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
