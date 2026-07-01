//! On-demand docker-image → bootable-bundle conversion, backing the
//! `MICROVM_IMAGE: docker/<name>[:tag|@sha256:…]` form.
//!
//! The reference is resolved against the host-configured `[convert] repo`
//! (the allowlist, same model as `[registry]`), pulled through the host docker
//! daemon, and flattened into a bootable rootfs: the rootfs is cloned and mkfs'ed
//! INSIDE a root container of the image itself (no host privileges), the agent is
//! injected, and the image's whole Config.Env is captured for the agent to restore
//! at boot. Conversions are cached under <state_dir>/converted/<name>/<digest>/ with
//! the same pull lock + GC as the bundle registry; the docker-side image is removed
//! after a successful conversion so the daemon's store stays lean.
//!
//! Two flavours, auto-detected from the `/etc/runner-vm.boot` marker the guest boot
//! layer writes:
//!   - **systemd** — a self-booting image (e2fsprogs + systemd): the description
//!     above (mkfs inside the image's own container; the agent hands off to systemd).
//!     It boots the image's own kernel + initrd if it ships one, otherwise the shared
//!     `[convert] generic_kernel` with no initrd.
//!   - **generic** — a plain OCI image with no kernel (alpine, distroless): its
//!     flattened rootfs is `docker export`ed and turned, host-side, into a native
//!     ext4 disk or a cpio initramfs (`[convert] generic_disk`) with the static agent
//!     injected as PID 1 — no mkfs container, no e2fsprogs. It boots the shared pinned
//!     `[convert] generic_kernel` (virtio + ext4 built in), so it carries no kernel,
//!     initrd or modules of its own.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::{Config, Convert};
use crate::image::{self, BootKind, Reference, ResolvedImage};
use crate::jobctx::JobCtx;

/// In-container conversion script (the out-of-VM bundle builder counterpart).
const CONVERT_SCRIPT: &str = r#"
set -e
mkdir -p /stage
tar -C / --one-file-system \
    --exclude=./out --exclude=./stage --exclude=./agent \
    -cf - . | tar -C /stage -xpf -
install -m 0755 /agent /stage/usr/local/bin/vk-agent
mkdir -p /stage/etc/virtkit
install -m 0644 /out/virtkit.env /stage/etc/virtkit/env
install -m 0644 /out/virtkit.user /stage/etc/virtkit/user
# copy the image's own kernel only if it ships one; otherwise the bundle boots
# the shared host kernel (generic_kernel) with no initrd
if ls /boot/vmlinuz-* >/dev/null 2>&1; then
    cp "$(ls /boot/vmlinuz-* | head -1)" /out/vmlinuz
    cp "$(ls /boot/initrd.img-* | head -1)" /out/initrd.img
fi
rm -f /out/runner.ext4
mkfs.ext4 -q -F -L runner-root -d /stage /out/runner.ext4 "$ROOTFS_SIZE"
chown "$HOST_UID:$HOST_GID" /out/runner.ext4 /out/virtkit.env /out/virtkit.user
[ -f /out/vmlinuz ] && chown "$HOST_UID:$HOST_GID" /out/vmlinuz /out/initrd.img || true
"#;

pub fn resolve(ctx: &JobCtx, docker_ref: &str) -> Result<ResolvedImage> {
    let Some(cv) = &ctx.cfg.convert else {
        bail!("MICROVM_IMAGE uses the docker/ form but the host has no [convert] configured");
    };
    let (name, reference) = image::parse_ref(docker_ref)?;
    let digest = match &reference {
        Reference::Digest(d) => d.clone(),
        Reference::Tag(tag) => {
            let out = image::oras_run(
                &cv.oras,
                cv.ca_file.as_deref(),
                &cv.username,
                cv.password_file.as_deref(),
                &["resolve", &format!("{}/{}:{}", cv.repo, name, tag)],
            )
            .with_context(|| format!("resolving {name}:{tag} against {}", cv.repo))?;
            image::parse_digest(out.trim())
                .with_context(|| format!("unexpected oras resolve output {out:?}"))?
        }
    };

    // the converted bundle embeds host-side inputs too (shim/agent/size, and the
    // kernel image a generic bundle draws from): fold their fingerprint into the
    // cache key, or a host update would keep serving conversions with the old ones
    let assets_fp = assets_fingerprint(cv)?;
    let images_dir = ctx.cfg.state_dir().join("converted").join(&name);
    let dir = images_dir.join(format!(
        "{}-{assets_fp:016x}",
        digest.trim_start_matches("sha256:")
    ));
    if !bundle_complete(&dir) {
        convert(&ctx.cfg, cv, &name, &digest, &dir)?;
        image::gc(&images_dir, &dir, cv.keep);
    }
    let boot_kind = image::read_boot_kind(&dir);
    println!("virtkit: image docker/{name}@{digest} (converted bundle, {boot_kind:?})");
    Ok(match boot_kind {
        // self-booting (systemd) guest: the image's own kernel + initrd if it
        // shipped one, otherwise the shared host kernel with no initrd
        BootKind::Systemd => {
            let vmlinuz = dir.join("vmlinuz");
            let (kernel, initrd) = if vmlinuz.is_file() {
                (vmlinuz, Some(dir.join("initrd.img")))
            } else {
                (cv.generic_kernel.clone(), None)
            };
            ResolvedImage::Disk {
                rootfs: dir.join("runner.ext4"),
                kernel,
                initrd,
                generic: false,
            }
        }
        // generic: the pinned guest kernel (built-in virtio+ext4, no initrd)
        BootKind::GenericDisk => ResolvedImage::Disk {
            rootfs: dir.join("runner.ext4"),
            kernel: cv.generic_kernel.clone(),
            initrd: None,
            generic: true,
        },
        BootKind::GenericCpio => ResolvedImage::Initramfs {
            kernel: cv.generic_kernel.clone(),
            initramfs: dir.join("initramfs.cpio"),
        },
    })
}

/// A converted bundle is present and usable. The artifacts differ by flavour
/// (recorded in `boot.kind`): only a self-booting systemd bundle carries its
/// own kernel; generic bundles boot the shared pinned guest kernel.
fn bundle_complete(dir: &Path) -> bool {
    match image::read_boot_kind(dir) {
        // a systemd bundle always has the rootfs; vmlinuz/initrd only when the
        // image shipped its own kernel (else it boots the shared host kernel)
        BootKind::Systemd => dir.join("runner.ext4").is_file(),
        BootKind::GenericDisk => dir.join("runner.ext4").is_file(),
        BootKind::GenericCpio => dir.join("initramfs.cpio").is_file(),
    }
}

fn convert(cfg: &Config, cv: &Convert, name: &str, digest: &str, dir: &Path) -> Result<()> {
    // same serialization as the bundle pulls: one converter per digest, losers
    // wait and find the result promoted by the winner
    let _lock = image::acquire_pull_lock(dir, name, digest)?;
    if bundle_complete(dir) {
        return Ok(());
    }
    let img = format!("{}/{}@{}", cv.repo, name, digest);
    let docker_config = write_docker_config(cfg.state_dir(), cv)?;

    println!("virtkit: pulling {img} ...");
    docker(cv, docker_config.as_deref(), &["pull", "--quiet", &img])?;

    // tmp sibling promoted on success: a killed prepare never leaves a
    // half-conversion that bundle_complete() could mistake for valid
    let tmp = dir.with_extension("tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;

    // the boot marker means a self-booting (systemd) guest; otherwise it is a
    // generic OCI image we boot from a cpio initramfs with virtkit-agent as PID 1.
    let boot_kind = if image_is_systemd(cv, &img, &tmp)? {
        println!(
            "virtkit: converting {img} (systemd, rootfs {}) ...",
            cv.rootfs_size
        );
        assemble_systemd(cv, &img, &tmp)?;
        BootKind::Systemd
    } else if cv.generic_disk {
        println!("virtkit: converting {img} (generic OCI, ext4 disk) ...");
        assemble_generic(cv, &img, &tmp, true)?;
        BootKind::GenericDisk
    } else {
        println!("virtkit: converting {img} (generic OCI, cpio initramfs) ...");
        assemble_generic(cv, &img, &tmp, false)?;
        BootKind::GenericCpio
    };
    write_boot_kind(&tmp, boot_kind)?;

    if !bundle_complete(&tmp) {
        bail!("conversion of {img} produced an incomplete bundle");
    }
    let _ = std::fs::remove_dir_all(dir);
    std::fs::rename(&tmp, dir)
        .with_context(|| format!("promoting {} to {}", tmp.display(), dir.display()))?;
    // keep the daemon's store lean: the converted bundle is our cache, the
    // docker image is only re-pulled when a new version converts
    let _ = docker(cv, None, &["image", "rm", &img]);
    Ok(())
}

/// systemd image: clone + mkfs inside a root container of the image itself
/// (it carries e2fsprogs), injecting virtkit-agent (the PID 1) and capturing its
/// Config.Env/User for the agent's init to restore at boot.
fn assemble_systemd(cv: &Convert, img: &str, tmp: &Path) -> Result<()> {
    write_env_file(cv, img, &tmp.join("virtkit.env"))?;
    write_user_file(cv, img, &tmp.join("virtkit.user"))?;
    // SAFETY: getuid/getgid have no failure mode
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    docker(
        cv,
        None,
        &[
            "run",
            "--rm",
            // force root: the script mkdirs /stage, mkfs's and chowns to the host
            // uid — all need root. The image's USER (captured separately into
            // runner-vm.user) is a job-runtime concern and must not govern this
            // build-time container, or the conversion fails with EPERM.
            "--user",
            "0:0",
            "-e",
            &format!("ROOTFS_SIZE={}", cv.rootfs_size),
            "-e",
            &format!("HOST_UID={uid}"),
            "-e",
            &format!("HOST_GID={gid}"),
            "-v",
            &format!("{}:/out", tmp.display()),
            "-v",
            &format!("{}:/agent:ro", cv.agent.display()),
            "--entrypoint",
            "sh",
            img,
            "-c",
            CONVERT_SCRIPT,
        ],
    )?;
    Ok(())
}

/// generic image: export the image's flattened rootfs and turn it into a boot
/// medium with the static virtkit-agent injected as PID 1 — a cpio initramfs in RAM
/// (`disk=false`) or a native ext4 disk (`disk=true`), the same assembly the dev
/// `launch` uses. No kernel, initrd or modules are bundled: a generic image
/// boots the shared pinned guest kernel (virtio + ext4 built in).
fn assemble_generic(cv: &Convert, img: &str, tmp: &Path, disk: bool) -> Result<()> {
    let tar = tmp.join("rootfs.tar");
    // export the flattened rootfs without a host privilege: `create` materialises
    // the image's layers, `export` streams them as a tar (the container never runs)
    let cid = docker(cv, None, &["create", img])?.trim().to_string();
    let export = docker(cv, None, &["export", "-o", &tar.to_string_lossy(), &cid]);
    let _ = docker(cv, None, &["rm", "-f", &cid]);
    export?;

    // capture the image config a `docker export` tar drops, so a generic guest runs
    // exactly like `docker run` would: the agent restores Config.Env (PATH, …) and
    // drops the stage scripts to Config.User. `docker export` loses both, so they are
    // injected as /etc/virtkit/{env,user} next to the agent (the systemd path installs
    // the same files via its in-container script).
    let env_file = tmp.join("virtkit.env");
    let user_file = tmp.join("virtkit.user");
    write_env_file(cv, img, &env_file)?;
    write_user_file(cv, img, &user_file)?;
    let injects: [(&str, &Path, u16); 3] = [
        ("usr/local/bin/vk-agent", cv.agent.as_path(), 0o755),
        ("etc/virtkit/env", env_file.as_path(), 0o644),
        ("etc/virtkit/user", user_file.as_path(), 0o644),
    ];

    if disk {
        crate::ext4::build_from_tar_injecting(
            &tar,
            &injects,
            0,
            &crate::ext4::FsId {
                with_journal: true,
                ..Default::default()
            },
            &tmp.join("runner.ext4"),
        )?;
    } else {
        crate::initramfs::build_initramfs_injecting(&tar, &injects, &tmp.join("initramfs.cpio"))?;
    }
    // the captures are baked into the rootfs now; drop the loose copies
    let _ = std::fs::remove_file(&tar);
    let _ = std::fs::remove_file(&env_file);
    let _ = std::fs::remove_file(&user_file);
    Ok(())
}

/// Detect whether the image is a self-booting (systemd) microVM guest, by the
/// `/etc/runner-vm.boot` marker setup-guest-boot-layer.sh writes. This is
/// independent of whether the image ships a kernel: a systemd guest may boot the
/// shared host kernel. `docker cp` needs no shell — a missing marker (the copy
/// fails) reads as a generic OCI image. The probe file lives under the
/// conversion tmp and is removed before promotion.
fn image_is_systemd(cv: &Convert, img: &str, tmp: &Path) -> Result<bool> {
    let cid = docker(cv, None, &["create", img])?.trim().to_string();
    let probe = tmp.join("probe-boot");
    let _ = std::fs::remove_file(&probe);
    let copied = Command::new(&cv.docker)
        .arg("cp")
        .arg(format!("{cid}:/etc/runner-vm.boot"))
        .arg(&probe)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let _ = docker(cv, None, &["rm", "-f", &cid]);
    let _ = std::fs::remove_file(&probe);
    Ok(copied)
}

/// Record the boot flavour in the bundle so a cache hit (which skips conversion)
/// still knows how to boot it. Absent marker = systemd (older bundles).
fn write_boot_kind(dir: &Path, kind: BootKind) -> Result<()> {
    std::fs::write(dir.join("boot.kind"), image::boot_kind_tag(kind))
        .with_context(|| format!("writing the boot marker in {}", dir.display()))
}

/// Fingerprint of the host-side conversion inputs baked into the result; part
/// of the cache key. Reading the files doubles as the provisioning check.
fn assets_fingerprint(cv: &Convert) -> Result<u64> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    // the guest agent baked in as PID 1; reading it doubles as the provisioning check
    parts.push(std::fs::read(&cv.agent).with_context(|| {
        format!(
            "reading {} — the host provisioning stages it next to virtkit",
            cv.agent.display()
        )
    })?);
    parts.push(cv.rootfs_size.as_bytes().to_vec());
    // generic bundles boot the shared pinned kernel rather than embedding one, so
    // the kernel is not part of a bundle's content and stays out of the cache key;
    // the disk-vs-cpio choice does change the artifact, so fold it in
    parts.push(
        if cv.generic_disk {
            b"disk" as &[u8]
        } else {
            b"cpio"
        }
        .to_vec(),
    );
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    Ok(image::fnv64(&refs))
}

/// Capture the image's Config.Env — exactly what a `docker run` of the image
/// would get — as raw KEY=VALUE lines (the agent's init reads them line by line,
/// splitting on the first '=', and never sources them).
fn write_env_file(cv: &Convert, img: &str, path: &Path) -> Result<()> {
    let out = docker(
        cv,
        None,
        &[
            "image",
            "inspect",
            "--format",
            "{{range .Config.Env}}{{println .}}{{end}}",
            img,
        ],
    )?;
    std::fs::write(path, render_env_file(&out))
        .with_context(|| format!("writing {}", path.display()))
}

/// Capture the image's Config.User (its last USER directive) — the user the
/// stage scripts run as, mirroring a `docker run`. Empty when the image sets none;
/// the agent exports it as VIRTKIT_DEFAULT_RUN_USER so the exec server drops to it.
fn write_user_file(cv: &Convert, img: &str, path: &Path) -> Result<()> {
    let out = docker(
        cv,
        None,
        &["image", "inspect", "--format", "{{.Config.User}}", img],
    )?;
    std::fs::write(path, format!("{}\n", out.trim()))
        .with_context(|| format!("writing {}", path.display()))
}

fn render_env_file(config_env: &str) -> String {
    let mut rendered = String::new();
    for line in config_env.lines() {
        // keep only well-formed KEY=VALUE lines; the value is written raw (the
        // agent takes the rest of the line verbatim, spaces and all).
        if line.split_once('=').is_some() {
            rendered.push_str(line);
            rendered.push('\n');
        }
    }
    rendered
}

/// Credentials for `docker pull`: a dedicated docker config dir under
/// state_dir (0700) so the runner user's ~/.docker is never touched. None =
/// anonymous (daemon defaults).
fn write_docker_config(state_dir: &Path, cv: &Convert) -> Result<Option<std::path::PathBuf>> {
    if cv.username.is_empty() {
        return Ok(None);
    }
    let file = cv
        .password_file
        .as_ref()
        .context("convert.username set but no convert.password_file")?;
    let password =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let registry = cv.repo.split('/').next().unwrap_or(&cv.repo);
    let auth = base64(format!("{}:{}", cv.username, password.trim_end()).as_bytes());
    let config = format!(r#"{{"auths":{{"{registry}":{{"auth":"{auth}"}}}}}}"#);

    let dir = state_dir.join("docker-config");
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let path = dir.join("config.json");
    std::fs::write(&path, config).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(Some(dir))
}

/// Run the docker CLI (optionally with the dedicated --config dir), capturing
/// stdout; stderr is passed through for pull/convert progress visibility.
fn docker(cv: &Convert, config_dir: Option<&Path>, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new(&cv.docker);
    if let Some(dir) = config_dir {
        cmd.arg("--config").arg(dir);
    }
    cmd.args(args);
    cmd.stdout(std::process::Stdio::piped());
    let out = cmd
        .spawn()
        .with_context(|| format!("spawning {}", cv.docker.display()))?
        .wait_with_output()?;
    if !out.status.success() {
        bail!(
            "docker {} failed ({})",
            args.first().unwrap_or(&""),
            out.status
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 0x3f] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_rfc_vectors() {
        for (input, expect) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("user:p4ss!word", "dXNlcjpwNHNzIXdvcmQ="),
        ] {
            assert_eq!(base64(input.as_bytes()), expect, "input {input:?}");
        }
    }

    #[test]
    fn env_file_rendering() {
        // raw KEY=VALUE (the agent splits on the first '='); lines without '=' dropped
        let rendered =
            render_env_file("APPDIR=/workdir\nLS_OPTS=--color=auto -F\nnoequal\nEMPTY=\n");
        assert_eq!(
            rendered,
            "APPDIR=/workdir\nLS_OPTS=--color=auto -F\nEMPTY=\n"
        );
    }
}
