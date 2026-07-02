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
        username: Option<String>,
        password: Option<String>,
        ca_pem: Option<Vec<u8>>,
        insecure: bool,
    },
}

/// Geometry hints for a streaming ext4 build of the rootfs (the tar is consumed in
/// one pass, so sizes must be known up front — see `ext4::build_from_tar_stream`).
pub struct TarHints {
    /// upper bound on the unpacked file-data bytes: exact for an OCI pull (the
    /// merger's spill size), `docker image inspect .Size` for a docker export
    pub data_bytes: u64,
    /// exact entry count when known (OCI pull)
    pub entries: Option<u64>,
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
            Source::Oci {
                reference,
                username,
                password,
                ca_pem,
                insecure,
            } => {
                let (merger, layers) = crate::oci::pull_merged(
                    reference,
                    username.as_deref(),
                    password.as_deref(),
                    ca_pem.clone(),
                    *insecure,
                    scratch_dir,
                )
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

    /// The image's configured environment (`Config.Env` as `(KEY, VALUE)` pairs), so a
    /// command run in the booted guest sees the image's `PATH` etc. — as `docker run`
    /// does. From the registry config (OCI) or `docker image inspect` (docker).
    pub async fn config_env(&self) -> Result<Vec<(String, String)>> {
        match self {
            Source::Docker { docker, image } => docker_config_env(docker, image),
            Source::Oci {
                reference,
                username,
                password,
                ca_pem,
                insecure,
            } => Ok(crate::oci::pull_config(
                reference,
                username.as_deref(),
                password.as_deref(),
                ca_pem.clone(),
                *insecure,
            )
            .await?
            .env),
        }
    }
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

/// `docker image inspect` an image's `Config.Env` (one `KEY=VALUE` per line).
fn docker_config_env(docker: &Path, image: &str) -> Result<Vec<(String, String)>> {
    Ok(
        docker_inspect(docker, image, "{{range .Config.Env}}{{println .}}{{end}}")?
            .lines()
            .filter_map(|l| {
                l.split_once('=')
                    .map(|(k, v)| (k.to_string(), v.to_string()))
            })
            .collect(),
    )
}

/// `docker export` a local image's rootfs, streaming the child's stdout into
/// `consume`. The trailing dummy command lets `create` succeed on an image with no
/// CMD; export never runs it. The container is removed whatever the outcome.
fn docker_export_stream<T>(
    docker: &Path,
    image: &str,
    consume: impl FnOnce(&mut dyn Read, &TarHints) -> Result<T>,
) -> Result<T> {
    let hints = TarHints {
        // .Size is the image's unpacked byte total — the data upper bound.
        data_bytes: docker_inspect(docker, image, "{{.Size}}")?
            .trim()
            .parse::<u64>()
            .context("parsing docker image inspect .Size")?,
        entries: None,
    };
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

    use super::*;

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
