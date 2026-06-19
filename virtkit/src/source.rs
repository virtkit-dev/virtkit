//! Where a guest's rootfs tar comes from: a `docker export` (needs the docker
//! daemon) or a registry pull (oci.rs, no docker). Both yield a single flat
//! rootfs tar the ext4/cpio builders consume.

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

impl Source {
    /// Write the image's rootfs as a single tar at `out`.
    pub async fn to_tar(&self, out: &Path) -> Result<()> {
        match self {
            Source::Docker { docker, image } => docker_export(docker, image, out),
            Source::Oci {
                reference,
                username,
                password,
                ca_pem,
                insecure,
            } => {
                crate::oci::pull_flatten(
                    reference,
                    username.as_deref(),
                    password.as_deref(),
                    ca_pem.clone(),
                    *insecure,
                    out,
                )
                .await
            }
        }
    }
}

/// `docker export` a local image's rootfs to `out` (a tar file). The trailing
/// dummy command lets `create` succeed on an image with no CMD; export never
/// runs it.
fn docker_export(docker: &Path, image: &str, out: &Path) -> Result<()> {
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
    let status = Command::new(docker)
        .args(["export", "-o"])
        .arg(out)
        .arg(&cid)
        .status();
    let _ = Command::new(docker)
        .args(["rm", "-f", &cid])
        .stdout(Stdio::null())
        .status();
    if !status?.success() {
        bail!("docker export {image} failed");
    }
    Ok(())
}
