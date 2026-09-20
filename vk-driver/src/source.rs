//! Where a guest's rootfs tar comes from: a `docker export` (needs the docker
//! daemon) or a registry pull (oci.rs, no docker). Both are streamed — the flat
//! rootfs tar flows straight into the ext4/cpio builders, never touching disk.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

pub enum Source {
    /// `docker export` a local (already pulled) image — needs the docker daemon.
    Docker { docker: PathBuf, image: String },
    /// Pull straight from a registry, no docker daemon.
    Oci {
        reference: String,
        creds: crate::oci::Creds,
    },
}

/// Geometry hints for a streaming ext4 build of the rootfs (the tar is consumed in
/// one pass, so sizes must be known up front — see `ext4::build_from_tar_stream`).
pub struct TarHints {
    /// upper bound on the unpacked file-data bytes: exact for an OCI pull (the
    /// merger's spill size), the container's `SizeRootFs` for a docker export
    pub data_bytes: u64,
    /// exact entry count when known (OCI pull)
    pub entries: Option<u64>,
}

impl TarHints {
    /// Sparse upper bound on the ext4 data size (over-sizing is free — the image is
    /// sparse): file-data bytes plus per-file block-rounding slack — 4 KiB per entry
    /// when the count is known (an OCI pull), else 25% — plus a fixed margin.
    pub fn image_bytes(&self) -> u64 {
        let slack = match self.entries {
            Some(n) => self.data_bytes + n * 4096,
            None => self.data_bytes + self.data_bytes / 4,
        };
        slack + 256 * 1024 * 1024
    }

    /// Inode budget: exact when the entry count is known, else one inode per 8 KiB of
    /// data with a floor, so small-file-heavy images don't exhaust the inode table.
    pub fn inode_count(&self) -> u64 {
        match self.entries {
            Some(n) => n + 4096,
            None => (self.data_bytes / 8192).max(65_536),
        }
    }
}

impl Source {
    /// Stream the image's flattened rootfs tar into `consume` — no intermediate tar
    /// file. The producer (a `docker export` child or a merger writer thread) runs
    /// concurrently; once `consume` returns, its tail is drained, and the producer is
    /// reaped. A consumer error wins over the producer's (whose broken pipe is just
    /// the symptom). `scratch_dir` hosts the OCI merger's scratch file — pass the
    /// directory the output goes to (the docker path streams from the child directly).
    pub async fn stream_tar<T>(
        &self,
        scratch_dir: &Path,
        consume: impl FnOnce(&mut dyn Read, &TarHints) -> Result<T>,
    ) -> Result<T> {
        match self {
            Source::Docker { docker, image } => docker_export_stream(docker, image, consume),
            Source::Oci { reference, creds } => {
                let (merger, layers) =
                    crate::oci::pull_merged(reference, creds, scratch_dir, &|m| println!("{m}"))
                        .await?;
                let hints = TarHints {
                    data_bytes: merger.data_bytes(),
                    entries: Some(merger.entry_count() as u64),
                };
                let (out, n) = stream_pipe(move |w| merger.finish_to(w), |rd| consume(rd, &hints))?;
                println!("virtkit: flattened {layers} layers -> {n} entries");
                Ok(out)
            }
        }
    }

    /// The image's runtime config (`Env`/`User`/`WorkingDir`/`Entrypoint`/`Cmd`), so a
    /// command run in the booted guest sees the image's `PATH`, runs under its
    /// entrypoint and in its workdir — as `docker run` does. From the registry config
    /// (OCI) or `docker image inspect` (docker).
    pub async fn run_config(&self) -> Result<vk_core::runcfg::RunConfig> {
        match self {
            Source::Docker { docker, image } => docker_run_config(docker, image),
            Source::Oci { reference, creds } => {
                Ok(crate::oci::pull_config(reference, creds).await?.into())
            }
        }
    }
}

/// Pull an OCI `reference` and flatten it into a byte-clean ext4 at `out` — nothing
/// injected, since the embedded agent rides the boot initramfs — then write the image's
/// runtime config (`Env`/`User`/`WorkingDir`/`Entrypoint`/`Cmd`/`ExposedPorts`) to `config_sidecar(out)`
/// for the boot to apply. `extra_blocks` is writable free-space headroom beyond the sparse
/// fit (a guest boots through a CoW overlay, but the filesystem still needs free blocks to
/// allocate); `fs_id` sets the journal and any freshness UUID. The executor's OCI-direct
/// image path (`dockerimg.rs`) is its caller. Returns the config it wrote.
pub async fn oci_flatten(
    reference: &str,
    creds: &crate::oci::Creds,
    extra_blocks: u64,
    fs_id: &crate::ext4::FsId,
    out: &Path,
) -> Result<vk_core::runcfg::RunConfig> {
    let config: vk_core::runcfg::RunConfig =
        crate::oci::pull_config(reference, creds).await?.into();
    let source = Source::Oci {
        reference: reference.to_string(),
        creds: creds.clone(),
    };
    let scratch = out.parent().unwrap_or_else(|| Path::new("."));
    source
        .stream_tar(scratch, |tar, hints| {
            crate::ext4::build_from_tar_stream(
                tar,
                &[],
                hints.image_bytes(),
                extra_blocks,
                Some(hints.inode_count()),
                fs_id,
                out,
            )
        })
        .await?;
    let sidecar = crate::build::config_sidecar(out);
    std::fs::write(&sidecar, config.to_json())
        .with_context(|| format!("writing {}", sidecar.display()))?;
    Ok(config)
}

/// Stream `produce`'s output through an OS pipe into `consume`, the producer on its
/// own thread. Once `consume` returns Ok, its unread tail (e.g. the padding after a
/// tar's archive terminator) is drained so the producer finishes cleanly instead of
/// hitting EPIPE; on a consumer error the read end just closes, unblocking a
/// still-writing producer with EPIPE. The consumer's error wins over the producer's
/// (whose broken pipe is just the symptom).
fn stream_pipe<T, P: Send + 'static>(
    produce: impl FnOnce(std::io::BufWriter<std::fs::File>) -> Result<P> + Send + 'static,
    consume: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<(T, P)> {
    let (rd, wr) = crate::scratch::os_pipe()?;
    let producer =
        std::thread::spawn(move || produce(std::io::BufWriter::with_capacity(1 << 20, wr)));
    let mut rd = std::io::BufReader::with_capacity(1 << 20, rd);
    let result = consume(&mut rd);
    if result.is_ok() {
        let _ = std::io::copy(&mut rd, &mut std::io::sink());
    }
    // join() can't deadlock: the read end is dropped (or drained) by now, so a
    // still-writing producer unblocks with EPIPE.
    drop(rd);
    let produced = producer
        .join()
        .map_err(|_| anyhow::anyhow!("rootfs producer thread panicked"))?;
    Ok((result?, produced?))
}

/// One `docker image inspect --format` query against `image`, returning stdout.
fn docker_inspect(docker: &Path, image: &str, format: &str) -> Result<String> {
    let out = Command::new(docker)
        .args(["image", "inspect", "--format", format, image])
        .output()
        .with_context(|| format!("running {} image inspect", docker.display()))?;
    if !out.status.success() {
        bail!(
            "docker image inspect {image} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// The container's total rootfs size in bytes (`docker inspect -s .SizeRootFs`), or
/// `None` if the query fails. Needs `-s` (docker only computes sizes on request).
fn docker_container_rootfs_size(docker: &Path, cid: &str) -> Option<u64> {
    let out = Command::new(docker)
        .args(["inspect", "-s", "--format", "{{.SizeRootFs}}", cid])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<u64>()
        .ok()
}

/// Read Docker's runtime config (`Env`/`User`/`WorkingDir`/`Entrypoint`/`Cmd`/
/// `ExposedPorts`) with the same parser as OCI `pull_config`.
/// JSON preserves embedded newlines and distinguishes empty arguments from
/// the trailing newline added by `docker image inspect`.
fn docker_run_config(docker: &Path, image: &str) -> Result<vk_core::runcfg::RunConfig> {
    let json = docker_inspect(docker, image, "{{json .Config}}")?;
    let config: serde_json::Value = serde_json::from_str(&json)
        .with_context(|| format!("parsing the config docker image inspect {image} printed"))?;
    Ok(crate::oci::parse_config_object(&config).into())
}

/// `docker export` a local image's rootfs, streaming the child's stdout into
/// `consume`. The trailing dummy command lets `create` succeed on an image with no
/// CMD; export never runs it. The container is removed whatever the outcome.
fn docker_export_stream<T>(
    docker: &Path,
    image: &str,
    consume: impl FnOnce(&mut dyn Read, &TarHints) -> Result<T>,
) -> Result<T> {
    let create = Command::new(docker)
        .args(["create", image, "/sbin/init"])
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("running {} create", docker.display()))?;
    if !create.status.success() {
        bail!(
            "docker create {image} failed: {}",
            String::from_utf8_lossy(&create.stderr).trim()
        );
    }
    let cid = String::from_utf8_lossy(&create.stdout).trim().to_string();
    // Upper bound on the unpacked rootfs bytes. The container's SizeRootFs is the
    // real total; the image's `.Size` undercounts kernel-heavy images severalfold
    // (measured ~3x on a Debian + linux-image image), which would undersize the
    // ext4. Fall back to `.Size` if the container query fails, then to 0 if that
    // fails too — a 0 is safe because `TarHints::image_bytes` floors the ext4 at a
    // fixed margin, so the build still succeeds (or bails cleanly "out of space").
    let data_bytes = docker_container_rootfs_size(docker, &cid)
        .filter(|&n| n > 0)
        .or_else(|| {
            docker_inspect(docker, image, "{{.Size}}")
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
        })
        .unwrap_or(0);
    let hints = TarHints {
        data_bytes,
        entries: None,
    };
    let result = (|| {
        let mut child = Command::new(docker)
            .args(["export", &cid])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()
            .with_context(|| format!("running {} export", docker.display()))?;
        let mut stdout = std::io::BufReader::with_capacity(
            1 << 20,
            child.stdout.take().expect("stdout was piped"),
        );
        let result = consume(&mut stdout, &hints);
        if result.is_ok() {
            // Drain the archive terminator the tar reader left behind, so the export
            // exits cleanly instead of dying on EPIPE.
            let _ = std::io::copy(&mut stdout, &mut std::io::sink());
        } else {
            // The consumer failed mid-stream: stop the producer rather than blocking
            // on a full pipe.
            let _ = child.kill();
        }
        drop(stdout);
        let status = child.wait().context("waiting for docker export")?;
        let out = result?;
        if !status.success() {
            bail!("docker export {image} failed");
        }
        Ok(out)
    })();
    let _ = Command::new(docker)
        .args(["rm", "-f", &cid])
        .stdout(Stdio::null())
        .status();
    result
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::DirBuilderExt;

    use super::*;

    #[test]
    fn docker_run_config_reads_json() {
        let dir = std::env::temp_dir().join(format!("vk-docker-config-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let docker = dir.join("docker");
        vk_fs::write_atomic(
            &docker,
            br#"#!/bin/sh
set -eu
[ "$#" -eq 5 ]
[ "$1" = image ]
[ "$2" = inspect ]
[ "$3" = --format ]
[ "$4" = '{{json .Config}}' ]
case "$5" in
    missing) printf '%s\n' '{"Cmd":["/bin/sh"]}' ;;
    null) printf '%s\n' '{"Entrypoint":null,"Cmd":null}' ;;
    empty) printf '%s\n' '{"Entrypoint":[],"Cmd":[]}' ;;
    values)
        printf '%s\n' '{"Env":["MULTI=a\nb=c","EMPTY="],"User":"1000:1000","WorkingDir":"/space dir ","Entrypoint":["/bin/sh","-c"],"Cmd":["echo a\necho b",""],"ExposedPorts":{"8080/tcp":{},"53/udp":{}}}'
        ;;
    invalid) printf '%s\n' 'not json' ;;
    failed) printf '%s\n' 'image unavailable' >&2; exit 1 ;;
    *) exit 2 ;;
esac
"#,
            0o700,
        )
        .unwrap();

        for image in ["missing", "null", "empty"] {
            let c = docker_run_config(&docker, image).unwrap();
            assert!(c.entrypoint.is_empty(), "{image}");
            if image == "missing" {
                assert_eq!(c.cmd, ["/bin/sh"]);
            } else {
                assert!(c.cmd.is_empty(), "{image}");
            }
            assert!(c.user.is_empty());
            assert!(c.workdir.is_empty());
            assert!(c.env.is_empty());
            assert!(c.exposed_ports.is_empty());
        }
        let c = docker_run_config(&docker, "values").unwrap();
        assert_eq!(
            c.env,
            [
                ("MULTI".into(), "a\nb=c".into()),
                ("EMPTY".into(), "".into())
            ]
        );
        assert_eq!(c.user, "1000:1000");
        assert_eq!(c.workdir, "/space dir ");
        assert_eq!(c.entrypoint, ["/bin/sh", "-c"]);
        assert_eq!(c.cmd, ["echo a\necho b", ""]);
        assert_eq!(c.exposed_ports, [8080]);
        let err = docker_run_config(&docker, "invalid").unwrap_err();
        assert!(err.to_string().contains("parsing the config"));
        let err = docker_run_config(&docker, "failed").unwrap_err();
        assert!(err.to_string().contains("image unavailable"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // Pin the shared sizing heuristic for both the known-count (OCI pull) and the
    // unknown-count (docker export) branch, so the two call sites can't drift.
    #[test]
    fn tar_hints_sizing_is_stable() {
        const MARGIN: u64 = 256 * 1024 * 1024;
        let known = TarHints {
            data_bytes: 10_000_000,
            entries: Some(1000),
        };
        assert_eq!(known.image_bytes(), 10_000_000 + 1000 * 4096 + MARGIN);
        assert_eq!(known.inode_count(), 1000 + 4096);

        // Large unknown-count image: the one-inode-per-8-KiB rate wins over the floor.
        let unknown = TarHints {
            data_bytes: 1_000_000_000,
            entries: None,
        };
        assert_eq!(
            unknown.image_bytes(),
            1_000_000_000 + 1_000_000_000 / 4 + MARGIN
        );
        assert_eq!(unknown.inode_count(), 1_000_000_000 / 8192);
        // Tiny unknown-count image: the inode floor wins.
        let tiny = TarHints {
            data_bytes: 1024,
            entries: None,
        };
        assert_eq!(tiny.inode_count(), 65_536);
    }

    // Well past the pipe capacity, so a producer blocked mid-write only finishes
    // if the consumer side drains or closes the pipe.
    const PAYLOAD: usize = 1 << 22;

    #[test]
    fn stream_pipe_drains_tail_so_the_producer_finishes() {
        let (read, produced) = stream_pipe(
            |mut w| {
                w.write_all(&vec![7u8; PAYLOAD])?;
                Ok("done")
            },
            |rd| {
                // Stop early, like a tar reader at the archive terminator.
                let mut buf = [0u8; 1024];
                rd.read_exact(&mut buf)?;
                Ok(buf)
            },
        )
        .expect("stream_pipe");
        assert!(read.iter().all(|&b| b == 7));
        assert_eq!(produced, "done");
    }

    #[test]
    fn stream_pipe_consumer_error_wins_over_producer_epipe() {
        let err = stream_pipe(
            |mut w| {
                // The closed read end fails this write with EPIPE.
                w.write_all(&vec![0u8; PAYLOAD])?;
                Ok(())
            },
            |_rd| -> Result<()> { bail!("consumer failed") },
        )
        .expect_err("the consumer's error must surface");
        assert_eq!(err.to_string(), "consumer failed");
    }
}
