//! `FROM winiso:<iso>@sha256:<hex> --drivers=<iso>@sha256:<hex> [--edition=<name>]`: a Windows
//! base layer installed from Microsoft's ISO under vk, with no AHCI or ATAPI and no other VMM.
//!
//! The install medium is a GPT disk whose FAT32 partition holds the ISO's files (built in a Linux
//! helper VM by `winiso/media.sh`: 7z, wimlib, mtools); WinPE loads viostor from `boot.wim`, sees
//! the virtio disks and runs Setup on `winiso/autounattend.xml`. The first logon installs
//! virtio-win and qemu-ga and powers off. A settle boot then waits out the servicing Windows does
//! on its first boots, gives the Administrator a random password and turns autologon off.
//!
//! Everything is cached under the data dir by content: the medium by the ISOs and the answer
//! file (it takes minutes to build), the install by the medium and the disk size, the base layer
//! by the install and the settle step. Each is made in a directory of its own and renamed into
//! place whole, so a concurrent build sees either nothing or the finished entry.
//!
//! `vk build --reinstall` keys the install and its base layer anew, so both and every layer on
//! them are built again. Nothing is deleted: bundles built on the old install keep working until
//! they are rebuilt, and a concurrent build still using it is not disturbed.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::build::hex;
use crate::qga::Client;
use crate::vmm::Disk;

/// The image scheme of a Windows install stage.
pub(crate) const SCHEME: &str = "winiso:";

const ANSWER_TEMPLATE: &str = include_str!("winiso/autounattend.xml");
const SETUP_CMD: &str = include_str!("winiso/setup.cmd");
/// The installers the first logon runs, from `C:\vk`.
const VIRTIO_WIN_MSI: &str = "virtio-win-gt-x64.msi";
const QEMU_GA_MSI: &str = "qemu-ga-x86_64.msi";
const WINPESHL: &str = include_str!("winiso/winpeshl.ini");
const MEDIA_SH: &str = include_str!("winiso/media.sh");
const HELPER_DOCKERFILE: &str = include_str!("winiso/Dockerfile");

/// The Administrator password of the install's own autologon; the settle boot replaces it.
const INSTALL_PASSWORD: &str = "vk-Install-Only-1";

/// How long Setup may take, WinPE to the first logon's power-off.
const INSTALL_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

/// How long a booting guest has for its qemu-ga to answer: generous, as a loaded host's
/// nested Windows 11 can take most of 15 minutes per boot, and a guest that powers off is
/// noticed within half a minute anyway.
const AGENT_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// What `winiso/setup.cmd` writes to the serial console when WinPE found no install medium.
const SETUP_FAILED: &str = "vk-install-failed";

/// How often the settle boot runs its script, restarts included, before giving up.
const SETTLE_ATTEMPTS: u32 = 6;

/// A file named with the digest it must have: `<path>@sha256:<hex>`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Pinned {
    pub path: PathBuf,
    pub sha256: String,
}

impl Pinned {
    /// `spec` with its path resolved against `context`.
    fn parse(spec: &str, context: &Path) -> Result<Pinned> {
        let Some((path, digest)) = spec.rsplit_once("@sha256:") else {
            bail!("{spec}: expected <path>@sha256:<hex digest>");
        };
        let sha256 = digest.to_ascii_lowercase();
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("{spec}: the sha256 digest must be 64 hex digits");
        }
        if path.contains("://") {
            bail!("{spec}: give a local path; downloading the ISO is not supported yet");
        }
        Ok(Pinned {
            path: context.join(path),
            sha256,
        })
    }

    /// Check the file's digest, remembering a match (by path, size and mtime) under `cache` so
    /// an 8 GB ISO is hashed once.
    fn verify(&self, cache: &Path) -> Result<()> {
        let meta =
            std::fs::metadata(&self.path).with_context(|| format!("{}", self.path.display()))?;
        let stamp_dir = cache.join("verified");
        let stamp = stamp_dir.join(hex(&Sha256::digest(
            format!(
                "{}\0{}\0{}\0{}",
                self.path.display(),
                meta.len(),
                meta.mtime(),
                self.sha256
            )
            .as_bytes(),
        )));
        if stamp.exists() {
            return Ok(());
        }
        eprintln!("virtkit: winiso: checking {}", self.path.display());
        let got = sha256_file(&self.path)?;
        if got != self.sha256 {
            bail!(
                "{}: sha256 is {got}, the Dockerfile pins {}",
                self.path.display(),
                self.sha256
            );
        }
        std::fs::create_dir_all(&stamp_dir)?;
        std::fs::write(&stamp, &got)?;
        Ok(())
    }

    /// The file itself, past any symlink: the helper VM sees only the directory mounted for it.
    fn real_path(&self) -> Result<PathBuf> {
        std::fs::canonicalize(&self.path).with_context(|| format!("{}", self.path.display()))
    }

    fn file_name(&self) -> Result<String> {
        let path = self.real_path()?;
        path.file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .with_context(|| format!("{}: no file name", path.display()))
    }

    fn dir(&self) -> Result<PathBuf> {
        let path = self.real_path()?;
        path.parent()
            .map(Path::to_path_buf)
            .with_context(|| format!("{}: no directory", path.display()))
    }
}

/// The sha256 of the file at `path`, in hex, read a piece at a time.
pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match file.read(&mut buf) {
            Ok(0) => return Ok(hex(&hasher.finalize())),
            Ok(n) => hasher.update(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }
}

/// The value of the flag `name` among `flags`, the `(name, value)` pairs of a `FROM` or `RUN`.
pub(crate) fn flag<'a>(flags: &'a [(String, String)], name: &str) -> Option<&'a str> {
    flags
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// The Windows editions vk knows, as an `--edition` name contains them, and virtio-win's
/// directory for each.
const EDITIONS: [(&str, &str); 6] = [
    ("server 2025", "2k25"),
    ("server 2022", "2k22"),
    ("server 2019", "2k19"),
    ("server 2016", "2k16"),
    ("windows 11", "w11"),
    ("windows 10", "w10"),
];

/// Publish the finished entry `tmp` as `dir`. When a concurrent build published the same key
/// first, theirs stays and `tmp` goes: the key names the content, so either will do.
pub(crate) fn publish(tmp: &Path, dir: &Path) -> Result<()> {
    match std::fs::rename(tmp, dir) {
        Ok(()) => Ok(()),
        Err(e) if matches!(e.raw_os_error(), Some(libc::EEXIST | libc::ENOTEMPTY)) => {
            // Only a duplicate is lost if this fails; the next build of the key clears it.
            let _ = std::fs::remove_dir_all(tmp);
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("renaming {} into place", tmp.display())),
    }
}

/// A fresh directory beside `dir` to make its entry in, named after this process.
pub(crate) fn scratch_beside(dir: &Path) -> Result<PathBuf> {
    let mut name = dir
        .file_name()
        .context("a cache entry with no name")?
        .to_os_string();
    name.push(format!(".tmp-{}", std::process::id()));
    let tmp = dir.with_file_name(name);
    // A leftover of an earlier build by a process that had this pid.
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    Ok(tmp)
}

/// What a `FROM winiso:` stage installs.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Source {
    pub iso: Pinned,
    pub drivers: Pinned,
    pub edition: Option<String>,
}

impl Source {
    /// The stage `FROM <image>` with its `--drivers`/`--edition` `flags`, paths against
    /// `context`; `None` when `image` is not a `winiso:` one.
    pub fn of_stage(
        image: &str,
        flags: &[(String, String)],
        context: &Path,
    ) -> Result<Option<Source>> {
        let Some(iso) = image.strip_prefix(SCHEME) else {
            return Ok(None);
        };
        if let Some((name, _)) = flags
            .iter()
            .find(|(k, _)| !matches!(k.as_str(), "edition" | "drivers"))
        {
            bail!("FROM {image}: unknown flag --{name} (expected --drivers, --edition)");
        }
        for name in ["drivers", "edition"] {
            if flags.iter().filter(|(k, _)| k == name).count() > 1 {
                bail!("FROM {image}: --{name} given twice");
            }
        }
        let drivers = flag(flags, "drivers").with_context(|| {
            format!("FROM {image}: --drivers=<virtio-win.iso>@sha256:<hex> is required")
        })?;
        let edition = flag(flags, "edition").filter(|e| !e.is_empty());
        if let Some(edition) = edition
            && edition_dir(edition).is_none()
        {
            bail!(
                "FROM {image}: --edition={edition:?} names no Windows vk knows (expected a name \
                 such as \"Windows Server 2025 Standard\": Server 2016 to 2025, Windows 10 or 11)"
            );
        }
        Ok(Some(Source {
            iso: Pinned::parse(iso, context)?,
            drivers: Pinned::parse(drivers, context)?,
            edition: edition.map(str::to_string),
        }))
    }

    /// virtio-win's directory for this Windows. Without `--edition` Setup installs the ISO's
    /// first image, taken to be a Windows Server 2025 one.
    fn driver_dir(&self) -> &'static str {
        self.edition
            .as_deref()
            .and_then(edition_dir)
            .unwrap_or("2k25")
    }

    /// The key of this install's medium: everything that goes into it.
    fn media_key(&self) -> String {
        hex(&Sha256::digest(
            [
                "winiso-media-v1",
                &self.iso.sha256,
                &self.drivers.sha256,
                self.driver_dir(),
                &self.answer_file(),
                &self.setup_cmd(),
                WINPESHL,
                MEDIA_SH,
                HELPER_DOCKERFILE,
            ]
            .join("\0")
            .as_bytes(),
        ))
    }

    /// Whether this is a Windows 10 or 11 client edition.
    fn is_client(&self) -> bool {
        matches!(self.driver_dir(), "w11" | "w10")
    }

    /// WinPE's script for this install. Windows 11 Setup refuses a machine without TPM 2.0 and
    /// Secure Boot, which vk does not emulate (yet): for a client edition the script sets
    /// Microsoft's `LabConfig` keys first, so Setup skips those checks (and the RAM, CPU and
    /// disk-size ones). A server's script carries none, unchanged.
    fn setup_cmd(&self) -> String {
        let labconfig = if self.is_client() {
            ["TPM", "SecureBoot", "RAM", "CPU", "Storage"]
                .iter()
                .map(|check| {
                    format!(
                        "reg add HKLM\\SYSTEM\\Setup\\LabConfig /v Bypass{check}Check /t REG_DWORD /d 1 /f >nul\r\n"
                    )
                })
                .collect::<String>()
        } else {
            String::new()
        };
        SETUP_CMD.replace("@LABCONFIG@\r\n", &labconfig)
    }

    /// The answer file for this install.
    fn answer_file(&self) -> String {
        let (key, value) = match &self.edition {
            Some(name) => ("/IMAGE/NAME", xml_escape(name)),
            None => ("/IMAGE/INDEX", "1".to_string()),
        };
        // The first logon installs virtio-win and qemu-ga. On a client the virtio-win package
        // updates drivers that only take over after a restart, the serial port's among them,
        // and qemu-ga's installer then waits on a service that cannot start: there qemu-ga
        // goes first, on the drivers Setup installed. On a loaded host its installer can still
        // time out (its VSS provider's registration, error 1722, or its service's start, 1920)
        // and roll back: a startup task installs it again on the settle boot while its service
        // is missing, since without an agent that boot cannot even ask.
        let (first, second) = if self.is_client() {
            (QEMU_GA_MSI, VIRTIO_WIN_MSI)
        } else {
            (VIRTIO_WIN_MSI, QEMU_GA_MSI)
        };
        ANSWER_TEMPLATE
            .replace("@FIRST_MSI@", first)
            .replace("@SECOND_MSI@", second)
            .replace("@QEMU_GA_MSI@", QEMU_GA_MSI)
            .replace("@IMAGE_KEY@", key)
            .replace("@IMAGE_VALUE@", &value)
            .replace("@INSTALL_PASSWORD@", INSTALL_PASSWORD)
    }
}

/// A base layer: its disk, the Administrator password the settle boot gave it, and its key.
#[derive(Debug, Clone)]
pub(crate) struct Base {
    pub disk: PathBuf,
    pub password: String,
    pub key: String,
}

/// The disk of the base layer `key` if `cache` holds it.
pub(crate) fn cached_base(cache: &Path, key: &str) -> Option<PathBuf> {
    let dir = cache.join("settled").join(key);
    dir.join("base.json")
        .is_file()
        .then(|| dir.join("disk.qcow2"))
}

/// The virtio-win directory of the Windows `edition` names, if vk knows it.
fn edition_dir(edition: &str) -> Option<&'static str> {
    let edition = edition.to_ascii_lowercase();
    EDITIONS
        .into_iter()
        .find(|(name, _)| edition.contains(name))
        .map(|(_, dir)| dir)
}

/// The key of the install from the medium `media_key` onto a `disk_size`-byte disk.
fn install_key(media_key: &str, disk_size: u64) -> String {
    hex(&Sha256::digest(
        format!("winiso-install-v1\0{media_key}\0{disk_size}").as_bytes(),
    ))
}

/// The keys of the install `first` names after `reinstalls` `--reinstall`s, and of its base
/// layer. A cache that never reinstalled keeps its keys.
fn keys(first: &str, reinstalls: u32) -> (String, String) {
    let install = if reinstalls == 0 {
        first.to_string()
    } else {
        hex(&Sha256::digest(
            format!("{first}\0reinstall {reinstalls}").as_bytes(),
        ))
    };
    let base = hex(&Sha256::digest(
        ["winiso-settled-v1", &install, SETTLE_PS1]
            .join("\0")
            .as_bytes(),
    ));
    (install, base)
}

/// How many times `--reinstall` re-keyed an install, as counted in the file `path` (none
/// when it is absent).
fn reinstalls(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(0)
}

/// Count one more reinstall in the file `path`.
fn count_reinstall(path: &Path) -> Result<()> {
    std::fs::create_dir_all(
        path.parent()
            .context("a reinstall count with no directory")?,
    )?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, (reinstalls(path) + 1).to_string())?;
    std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
}

/// Get or build `source`'s base layer on a `disk_size`-byte disk in `cache`; with `reinstall`,
/// a new one under new keys. Cache the install by its medium and disk size, and the settle
/// overlay by the install and settle step, so changing the settle does not reinstall.
pub(crate) fn base(
    source: &Source,
    disk_size: u64,
    cpus: u32,
    mem: &str,
    cache: &Path,
    reinstall: bool,
) -> Result<Base> {
    let first = install_key(&source.media_key(), disk_size);
    let count = cache.join("reinstalls").join(&first);
    if reinstall {
        // Unlocked: concurrent `--reinstall`s may count once and share the new install, which
        // is harmless; counted before the install, so every build from now on uses the new keys.
        count_reinstall(&count)?;
    }
    let (install_key, key) = keys(&first, reinstalls(&count));
    let dir = cache.join("settled").join(&key);
    let record = dir.join("base.json");
    if let Ok(text) = std::fs::read_to_string(&record) {
        let password = serde_json::from_str::<serde_json::Value>(&text)?["password"]
            .as_str()
            .context("base.json without a password")?
            .to_string();
        eprintln!("virtkit: winiso: base {} (cached)", &key[..12]);
        return Ok(Base {
            disk: dir.join("disk.qcow2"),
            password,
            key,
        });
    }

    let install_dir = cache.join("install").join(&install_key);
    let installed_disk = install_dir.join("disk.qcow2");
    if !install_dir.join("installed").exists() {
        source.iso.verify(cache)?;
        source.drivers.verify(cache)?;
        let media = media(source, cache)?;
        let tmp = scratch_beside(&install_dir)?;
        let disk = tmp.join("disk.qcow2");
        if let Err(e) = install(&tmp, &disk, &media, disk_size, cpus, mem) {
            // Its logs stay for whoever reads the error; its disk is no use to them.
            let _ = std::fs::remove_file(&disk);
            return Err(e);
        }
        let _ = std::fs::remove_dir_all(tmp.join("install"));
        std::fs::write(tmp.join("installed"), "")?;
        publish(&tmp, &install_dir)?;
    }

    let tmp = scratch_beside(&dir)?;
    let disk = tmp.join("disk.qcow2");
    crate::qcow2::create_overlay(&disk, &installed_disk)?;
    let password = match settle(&tmp, &disk, cpus, mem) {
        Ok(password) => password,
        Err(e) => {
            // Whatever failed, the next build installs again: a broken install is not reused,
            // and a transient failure costs one reinstall. The settle's logs stay.
            let _ = std::fs::remove_dir_all(&install_dir);
            let _ = std::fs::remove_file(&disk);
            return Err(e);
        }
    };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(tmp.join("base.json"))?;
    std::io::Write::write_all(
        &mut file,
        serde_json::to_string_pretty(&serde_json::json!({
            "password": password,
            "edition": source.edition,
            "iso": source.iso.sha256,
            "drivers": source.drivers.sha256,
        }))?
        .as_bytes(),
    )?;
    let _ = std::fs::remove_dir_all(tmp.join("settle"));
    publish(&tmp, &dir)?;
    Ok(Base {
        disk: dir.join("disk.qcow2"),
        password,
        key,
    })
}

/// The install medium of `source`, from `cache` or built there in a helper VM.
fn media(source: &Source, cache: &Path) -> Result<PathBuf> {
    let answer = source.answer_file();
    let setup_cmd = source.setup_cmd();
    let dir = cache.join("media").join(source.media_key());
    if dir.join("complete").exists() {
        return Ok(dir.join("media.img"));
    }
    let out = scratch_beside(&dir)?;
    let img = out.join("media.img");
    let assets = out.join("assets");
    std::fs::create_dir_all(&assets)?;
    for (name, body) in [
        ("Dockerfile", HELPER_DOCKERFILE),
        ("media.sh", MEDIA_SH),
        ("autounattend.xml", answer.as_str()),
        ("setup.cmd", setup_cmd.as_str()),
        ("winpeshl.ini", WINPESHL),
    ] {
        std::fs::write(assets.join(name), body)?;
    }
    eprintln!("virtkit: winiso: building the install medium (a Linux helper VM; several minutes)");
    let status = std::process::Command::new(crate::spawn::self_exe())
        .args(["run", "--file"])
        .arg(assets.join("Dockerfile"))
        .args(["--build-net", "all", "--mem", "4G", "--cpus", "4"])
        .args(["-v", &volume(&source.iso.dir()?, "/in/iso:ro")?])
        .args(["-v", &volume(&source.drivers.dir()?, "/in/drivers:ro")?])
        .args(["-v", &volume(&assets, "/assets:ro")?])
        .args(["-v", &volume(&out, "/out")?])
        .args(["--env", &format!("ISO={}", source.iso.file_name()?)])
        .args(["--env", &format!("DRIVERS={}", source.drivers.file_name()?)])
        .args(["--env", &format!("DRIVERDIR={}", source.driver_dir())])
        .args(["--", "sh", "/assets/media.sh"])
        .status()
        .context("starting the media helper")?;
    if !status.success() || !img.exists() {
        bail!("building the Windows install medium failed ({status})");
    }
    std::fs::write(out.join("complete"), "")?;
    publish(&out, &dir)?;
    Ok(dir.join("media.img"))
}

/// The `vk run -v` spec mounting `host` at `guest` (which may carry a `:ro`), refusing a host
/// path the spec's `:` separators would split.
fn volume(host: &Path, guest: &str) -> Result<String> {
    let host = host
        .to_str()
        .filter(|h| !h.contains(':'))
        .with_context(|| {
            format!(
                "{}: the helper VM cannot mount a path with a ':' or that is not UTF-8",
                host.display()
            )
        })?;
    Ok(format!("{host}:{guest}"))
}

/// Install Windows from `media` onto a fresh `disk` of `disk_size` bytes, in `dir`.
fn install(
    dir: &Path,
    disk: &Path,
    media: &Path,
    disk_size: u64,
    cpus: u32,
    mem: &str,
) -> Result<()> {
    let work = dir.join("install");
    std::fs::create_dir_all(&work)?;
    let _ = std::fs::remove_file(disk);
    crate::qcow2::Qcow2Writer::create(disk, disk_size, 0o644)?.finish()?;
    // Setup writes to its medium; the cached one stays as built.
    let media_overlay = work.join("media.qcow2");
    crate::qcow2::create_overlay(&media_overlay, media)?;
    eprintln!(
        "virtkit: winiso: installing Windows (console {})",
        work.join(crate::run::CONSOLE_LOG).display()
    );
    let mut guest = crate::uefi::Guest::boot(
        &work,
        "winiso-install",
        vec![
            Disk::overlay(disk.to_path_buf()),
            Disk::overlay(media_overlay),
        ],
        cpus,
        mem,
        Vec::new(),
    )?;
    let started = Instant::now();
    loop {
        if guest.wait_poweroff(Duration::from_secs(60))? {
            break;
        }
        if started.elapsed() > INSTALL_TIMEOUT {
            bail!("the Windows install did not finish within {INSTALL_TIMEOUT:?}");
        }
        let written = std::fs::metadata(disk)
            .map(|m| m.blocks() * 512)
            .unwrap_or(0);
        eprintln!(
            "virtkit: winiso: installing, {:.1} GiB written in {}",
            written as f64 / (1u64 << 30) as f64,
            humantime(started.elapsed())
        );
    }
    // No console log is no failure reported.
    let console = std::fs::read(work.join(crate::run::CONSOLE_LOG)).unwrap_or_default();
    if setup_failed(&console) {
        bail!(
            "WinPE found no Windows install medium; see {}",
            work.join(crate::run::CONSOLE_LOG).display()
        );
    }
    eprintln!(
        "virtkit: winiso: installed in {}",
        humantime(started.elapsed())
    );
    Ok(())
}

/// Whether the install's serial console says WinPE found no install medium (`winiso/setup.cmd`).
fn setup_failed(console: &[u8]) -> bool {
    console
        .windows(SETUP_FAILED.len())
        .any(|w| w == SETUP_FAILED.as_bytes())
}

/// Boot the installed `disk` until Windows has done its first-boot servicing, give the
/// Administrator a random password, turn autologon off and power off. Returns the password.
fn settle(dir: &Path, disk: &Path, cpus: u32, mem: &str) -> Result<String> {
    let work = dir.join("settle");
    std::fs::create_dir_all(&work)?;
    let password = random_password()?;
    // The password is in the script, which only SYSTEM and administrators can read, and on
    // `net user`'s command line while it runs, which any process in the guest can see: during
    // the settle boot, only Windows' own and the autologon session's.
    let script = SETTLE_PS1.replace("@PASSWORD@", &password);
    let mut guest = crate::uefi::Guest::boot(
        &work,
        "winiso-settle",
        vec![Disk::overlay(disk.to_path_buf())],
        cpus,
        mem,
        Vec::new(),
    )?;
    let mut attempts = 0;
    loop {
        attempts += 1;
        if !guest.running() {
            bail!(
                "the guest powered off while settling; see {}",
                guest.console().display()
            );
        }
        let socket = guest.agent_socket();
        let ga = Client::connect_while(&socket, AGENT_TIMEOUT, "winiso", &mut || guest.running());
        let ran = ga.and_then(|mut ga| {
            let code = crate::winexec::powershell(&mut ga, &script, "winiso: settle")?;
            Ok((ga, code))
        });
        match ran {
            Ok((_, 0)) => break,
            Ok((_, 2)) => bail!(
                "the Windows install failed in its first logon; see {}",
                guest.console().display()
            ),
            Ok((mut ga, 3010)) if attempts < SETTLE_ATTEMPTS => {
                eprintln!("virtkit: winiso: servicing wants a restart");
                crate::winexec::restart(&mut ga, 3010, &mut || guest.running())?;
            }
            Ok((_, code)) => bail!(
                "settling the install failed ({code}); see {}",
                guest.console().display()
            ),
            // Windows restarting on its own, before its agent answered or under the script:
            // ask again once it is back.
            Err(e) if attempts < SETTLE_ATTEMPTS => log::debug!("settle: {e:#}"),
            Err(e) => return Err(e).context("settling the install"),
        }
    }
    guest
        .shutdown()
        .context("powering the settled install off")?;
    Ok(password)
}

/// The settle step: refuse an install whose first logon did not finish (exit 2), wait for the
/// servicing Windows does on its first boots (3010 asks for a restart), then the password and
/// autologon.
const SETTLE_PS1: &str = r#"$ErrorActionPreference = 'Stop'
if (-not (Test-Path C:\vk\install-done.txt)) { 'the first logon did not finish (no C:\vk\install-done.txt)'; exit 2 }
$deadline = (Get-Date).AddMinutes(30)
while ((Get-Process TiWorker -ErrorAction SilentlyContinue) -and ((Get-Date) -lt $deadline)) { Start-Sleep 5 }
$cbs = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
$wu = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
if ((Test-Path $cbs) -or (Test-Path $wu)) { exit 3010 }
net user Administrator '@PASSWORD@' | Out-Null
if ($LASTEXITCODE -ne 0) { 'setting the Administrator password failed'; exit 1 }
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Set-ItemProperty $wl AutoAdminLogon '0'
Remove-ItemProperty $wl -Name DefaultPassword -ErrorAction SilentlyContinue
Remove-Item C:\vk\*.msi -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'vk qemu-ga' -Confirm:$false -ErrorAction SilentlyContinue
# A loaded host can take tens of seconds per write: past the disk class's 60 s, Windows fails the
# I/O, and BitLocker's conversion then ended in a bug check. Wait as long as a VM disk may take.
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Disk TimeOutValue 300 -Type DWord
# On a busy boot (servicing, Windows Update, a loaded host) qemu-ga can miss its service start
# (event 7009) and nothing starts it again: its agent stays silent until the next boot. Give
# services longer to start, and have a startup task start qemu-ga again, for ten minutes, while
# it is stopped by a failure (exit code 1053 after the timeout, 1077 never started) or stuck
# starting. A stop with exit code 0 is a shutdown's, which it must leave alone.
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control ServicesPipeTimeout 120000 -Type DWord
$watch = '$pending = 0; Start-Sleep 60; for ($i = 0; $i -lt 20; $i++) { $s = Get-CimInstance Win32_Service | Where-Object Name -eq QEMU-GA; if ($s) { if ($s.State -eq ''Start Pending'') { $pending++ } else { $pending = 0 }; if (($s.State -eq ''Stopped'' -and $s.ExitCode -ne 0) -or $pending -ge 4) { Stop-Process -Name qemu-ga -Force -ErrorAction SilentlyContinue; Start-Service QEMU-GA -ErrorAction SilentlyContinue; $pending = 0 } }; Start-Sleep 30 }'
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -NonInteractive -Command $watch"
Register-ScheduledTask -TaskName 'vk qemu-ga watch' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest -Force | Out-Null
# vk's network is identified (it has a gateway), so Windows files it as Public; a lab wants
# Private. A startup task moves every non-domain profile there once the network is up.
$fix = 'for ($i = 0; $i -lt 24; $i++) { Get-NetConnectionProfile | Where-Object NetworkCategory -ne DomainAuthenticated | Set-NetConnectionProfile -NetworkCategory Private; Start-Sleep 5 }'
$action = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -NonInteractive -Command $fix"
Register-ScheduledTask -TaskName 'vk private network' -Action $action -Trigger (New-ScheduledTaskTrigger -AtStartup) -User SYSTEM -RunLevel Highest -Force | Out-Null
exit 0
"#;

/// A random password Windows' complexity rules accept: letters, digits and a dash, no quote.
fn random_password() -> Result<String> {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut bytes = [0u8; 20];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let body: String = bytes
        .iter()
        .map(|b| CHARS[*b as usize % CHARS.len()] as char)
        .collect();
    Ok(format!("Vk-{body}-9a"))
}

pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn humantime(d: Duration) -> String {
    let s = d.as_secs();
    format!("{}m{:02}s", s / 60, s % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51";

    #[test]
    fn a_symlinked_iso_is_mounted_from_where_it_lives() {
        let tmp = std::env::temp_dir().join(format!("vk-winiso-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("store")).unwrap();
        std::fs::create_dir_all(tmp.join("ctx")).unwrap();
        std::fs::write(tmp.join("store").join("ws2025.iso"), b"").unwrap();
        std::os::unix::fs::symlink(
            tmp.join("store").join("ws2025.iso"),
            tmp.join("ctx").join("ws.iso"),
        )
        .unwrap();
        let pinned = Pinned::parse(&format!("ws.iso@sha256:{DIGEST}"), &tmp.join("ctx")).unwrap();
        let store = std::fs::canonicalize(tmp.join("store")).unwrap();
        assert_eq!(pinned.dir().unwrap(), store);
        assert_eq!(pinned.file_name().unwrap(), "ws2025.iso");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_winiso_stage_names_its_iso_drivers_and_edition() {
        let flags = vec![
            (
                "edition".to_string(),
                "Windows Server 2025 Standard Evaluation".to_string(),
            ),
            (
                "drivers".to_string(),
                format!("iso/virtio-win.iso@sha256:{DIGEST}"),
            ),
        ];
        let src = Source::of_stage(
            &format!("winiso:iso/ws.iso@sha256:{DIGEST}"),
            &flags,
            Path::new("/ctx"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(src.iso.path, Path::new("/ctx/iso/ws.iso"));
        assert_eq!(src.drivers.path, Path::new("/ctx/iso/virtio-win.iso"));
        assert_eq!(src.driver_dir(), "2k25");
        let answer = src.answer_file();
        assert!(answer.contains(
            "<Key>/IMAGE/NAME</Key><Value>Windows Server 2025 Standard Evaluation</Value>"
        ));
        assert!(!answer.contains('@'), "every placeholder filled");

        assert!(
            Source::of_stage("alpine:3.20", &[], Path::new("/"))
                .unwrap()
                .is_none()
        );
        assert!(
            Source::of_stage(
                &format!("winiso:ws.iso@sha256:{DIGEST}"),
                &[],
                Path::new("/")
            )
            .is_err()
        );
        let mut typo = flags.clone();
        typo.push(("editon".to_string(), "x".to_string()));
        let err = Source::of_stage(
            &format!("winiso:iso/ws.iso@sha256:{DIGEST}"),
            &typo,
            Path::new("/ctx"),
        )
        .err()
        .unwrap();
        assert!(err.to_string().contains("unknown flag --editon"), "{err}");
        assert!(Pinned::parse("ws.iso@sha256:abc", Path::new("/")).is_err());
        assert!(Pinned::parse("ws.iso", Path::new("/")).is_err());
    }

    #[test]
    fn only_a_client_install_skips_setups_hardware_checks() {
        let pinned =
            |name: &str| Pinned::parse(&format!("{name}@sha256:{DIGEST}"), Path::new("/")).unwrap();
        let source = |edition: &str| Source {
            iso: pinned("a.iso"),
            drivers: pinned("b.iso"),
            edition: Some(edition.into()),
        };
        // Server scripts match the file before the placeholder was added.
        let server = source("Windows Server 2025 Standard Evaluation").setup_cmd();
        assert_eq!(server, SETUP_CMD.replace("@LABCONFIG@\r\n", ""));
        assert!(!server.contains("LabConfig"));
        let client = source("Windows 11 Enterprise Evaluation").setup_cmd();
        for check in ["TPM", "SecureBoot", "RAM", "CPU", "Storage"] {
            assert!(
                client.contains(&format!(
                    "LabConfig /v Bypass{check}Check /t REG_DWORD /d 1"
                )),
                "{check}"
            );
        }
        // The keys are set before Setup starts.
        assert!(client.find("LabConfig").unwrap() < client.find("setup.exe").unwrap());
        // Clients install qemu-ga first; servers keep virtio-win first, preserving cached installs.
        let order =
            |answer: &str| answer.find(QEMU_GA_MSI).unwrap() < answer.find(VIRTIO_WIN_MSI).unwrap();
        assert!(order(
            &source("Windows 11 Enterprise Evaluation").answer_file()
        ));
        assert!(!order(
            &source("Windows Server 2025 Standard Evaluation").answer_file()
        ));
        // Both leave a startup task that installs qemu-ga again while its service is missing,
        // registered before the first logon says it finished; the settle step removes it.
        for edition in [
            "Windows 11 Enterprise Evaluation",
            "Windows Server 2025 Standard Evaluation",
        ] {
            let answer = source(edition).answer_file();
            let task = answer
                .find("Register-ScheduledTask -TaskName 'vk qemu-ga'")
                .unwrap();
            let retry = answer.find("Get-Service QEMU-GA").unwrap();
            assert!(retry < task, "{edition}");
            assert!(answer[retry..task].contains(&format!("/i C:\\vk\\{QEMU_GA_MSI} ")));
            assert!(answer[task..].contains("-AtStartup"), "{edition}");
            assert!(task < answer.find("install-done.txt").unwrap(), "{edition}");
            assert!(!answer.contains("@QEMU_GA_MSI@"), "{edition}");
        }
        assert!(SETTLE_PS1.contains("Unregister-ScheduledTask -TaskName 'vk qemu-ga'"));
        // The settled layer waits on a slow disk rather than failing its I/O.
        assert!(SETTLE_PS1.contains(r"Services\Disk TimeOutValue 300 -Type DWord"));
        // And starts qemu-ga again when a busy boot made it miss its service start.
        assert!(SETTLE_PS1.contains(r"Control ServicesPipeTimeout 120000 -Type DWord"));
        let watch = SETTLE_PS1.find("Register-ScheduledTask -TaskName 'vk qemu-ga watch'");
        assert!(watch.is_some_and(|at| SETTLE_PS1[..at].contains("Start-Service QEMU-GA")));
        // Never on a shutdown's clean stop (exit code 0).
        assert!(SETTLE_PS1.contains("-eq ''Stopped'' -and $s.ExitCode -ne 0"));
    }

    #[test]
    fn without_an_edition_the_first_image_is_installed() {
        let src = Source {
            iso: Pinned::parse(&format!("a.iso@sha256:{DIGEST}"), Path::new("/")).unwrap(),
            drivers: Pinned::parse(&format!("b.iso@sha256:{DIGEST}"), Path::new("/")).unwrap(),
            edition: None,
        };
        assert!(
            src.answer_file()
                .contains("<Key>/IMAGE/INDEX</Key><Value>1</Value>")
        );
    }

    #[test]
    fn a_pinned_file_is_checked_against_its_digest() {
        let dir = std::env::temp_dir().join(format!("vk-winiso-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f"), b"abc").unwrap();
        let good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let pinned = Pinned::parse(&format!("f@sha256:{good}"), &dir).unwrap();
        pinned.verify(&dir.join("cache")).unwrap();
        // The stamp stands in for the next check.
        pinned.verify(&dir.join("cache")).unwrap();
        let bad = Pinned::parse(&format!("f@sha256:{DIGEST}"), &dir).unwrap();
        assert!(bad.verify(&dir.join("cache")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_flag_given_twice_or_an_unknown_edition_is_refused() {
        let image = format!("winiso:ws.iso@sha256:{DIGEST}");
        let drivers = ("drivers".to_string(), format!("v.iso@sha256:{DIGEST}"));
        let edition = |name: &str| ("edition".to_string(), name.to_string());
        let of = |flags: &[(String, String)]| Source::of_stage(&image, flags, Path::new("/"));
        let err = of(&[drivers.clone(), drivers.clone()]).unwrap_err();
        assert!(err.to_string().contains("--drivers given twice"), "{err}");
        let err = of(&[
            drivers.clone(),
            edition("Windows Server 2025 Datacenter"),
            edition("x"),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("--edition given twice"), "{err}");
        let err = of(&[drivers.clone(), edition("Windows Server 2012 R2")]).unwrap_err();
        assert!(
            err.to_string().contains("names no Windows vk knows"),
            "{err}"
        );
        let w11 = of(&[drivers.clone(), edition("Windows 11 Enterprise")])
            .unwrap()
            .unwrap();
        assert_eq!(w11.driver_dir(), "w11");
        let default = of(&[drivers]).unwrap().unwrap();
        assert_eq!(default.driver_dir(), "2k25");
    }

    #[test]
    fn the_install_is_keyed_by_its_medium_and_disk_size() {
        let key = install_key("m", 40 << 30);
        assert_eq!(key, install_key("m", 40 << 30));
        assert_ne!(key, install_key("m", 60 << 30));
        assert_ne!(key, install_key("n", 40 << 30));
        let src = |edition: Option<&str>| Source {
            iso: Pinned::parse(&format!("a.iso@sha256:{DIGEST}"), Path::new("/")).unwrap(),
            drivers: Pinned::parse(&format!("b.iso@sha256:{DIGEST}"), Path::new("/")).unwrap(),
            edition: edition.map(str::to_string),
        };
        assert_ne!(
            src(None).media_key(),
            src(Some("Windows Server 2022 Standard")).media_key()
        );
    }

    #[test]
    fn a_failed_winpe_is_told_by_its_console() {
        assert!(setup_failed(b"boot\r\nvk-install-failed\r\n"));
        assert!(!setup_failed(b"boot\r\n"));
        // The marker's write is backgrounded and bounded: a blocked COM1 still powers off.
        let (_, failed) = SETUP_CMD.split_once(":failed\r\n").unwrap();
        let lines: Vec<&str> = failed.lines().collect();
        assert_eq!(
            lines,
            [
                format!("start \"\" /b cmd /c \"echo {SETUP_FAILED}>COM1\"").as_str(),
                "ping -n 3 127.0.0.1 >nul",
                "wpeutil shutdown",
                "exit /b 1",
            ]
        );
        // Only a missing medium is reported: Setup's own failures show at the settle.
        assert!(!SETUP_CMD.contains("errorlevel"));
    }

    #[test]
    fn the_answer_file_is_well_formed_xml_with_the_edition_escaped() {
        let src = Source {
            iso: Pinned::parse(&format!("a.iso@sha256:{DIGEST}"), Path::new("/")).unwrap(),
            drivers: Pinned::parse(&format!("b.iso@sha256:{DIGEST}"), Path::new("/")).unwrap(),
            edition: Some("Windows Server 2025 R&D <\"x\">".to_string()),
        };
        let answer = src.answer_file();
        assert!(
            answer.contains("<Value>Windows Server 2025 R&amp;D &lt;&quot;x&quot;&gt;</Value>")
        );
        assert_well_formed(&answer);
        assert_well_formed(&ANSWER_TEMPLATE.replace('@', ""));
    }

    /// Fail unless `xml` is well-formed as far as an answer file needs: balanced tags, no
    /// stray `<`, every `&` an entity.
    fn assert_well_formed(xml: &str) {
        let mut open: Vec<&str> = Vec::new();
        let mut rest = xml;
        let check_text = |text: &str| {
            for (i, _) in text.match_indices('&') {
                let entity = &text[i..];
                assert!(
                    ["&amp;", "&lt;", "&gt;", "&quot;", "&apos;"]
                        .iter()
                        .any(|e| entity.starts_with(e)),
                    "bare & in {text:?}"
                );
            }
        };
        while let Some(start) = rest.find('<') {
            check_text(&rest[..start]);
            rest = &rest[start..];
            let end = if rest.starts_with("<!--") {
                rest.find("-->").expect("unclosed comment") + 3
            } else {
                let end = rest.find('>').expect("unclosed tag") + 1;
                let tag = &rest[1..end - 1];
                assert!(!tag.contains('<'), "stray < in {tag:?}");
                check_text(tag);
                if let Some(name) = tag.strip_prefix('/') {
                    assert_eq!(open.pop(), Some(name), "mismatched </{name}>");
                } else if !tag.starts_with('?') && !tag.ends_with('/') {
                    open.push(tag.split_whitespace().next().unwrap());
                }
                end
            };
            rest = &rest[end..];
        }
        check_text(rest);
        assert!(open.is_empty(), "unclosed {open:?}");
    }

    #[test]
    fn helper_mounts_refuse_a_path_their_separator_would_split() {
        assert_eq!(
            volume(Path::new("/isos"), "/in/iso:ro").unwrap(),
            "/isos:/in/iso:ro"
        );
        assert!(volume(Path::new("/is:os"), "/in/iso:ro").is_err());
    }

    #[test]
    fn a_cache_entry_published_twice_keeps_the_first() {
        let root = std::env::temp_dir().join(format!("vk-winiso-pub-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("key");
        for content in ["first", "second"] {
            let tmp = scratch_beside(&dir).unwrap();
            std::fs::write(tmp.join("f"), content).unwrap();
            publish(&tmp, &dir).unwrap();
            assert!(!tmp.exists());
        }
        assert_eq!(std::fs::read_to_string(dir.join("f")).unwrap(), "first");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn passwords_are_random_and_quote_free() {
        let a = random_password().unwrap();
        assert_ne!(a, random_password().unwrap());
        assert!(!a.contains(['\'', '"']));
        assert!(a.len() >= 20);
    }

    #[test]
    fn a_reinstall_keys_the_install_and_its_base_anew() {
        let first = install_key("media", 40 << 30);
        let (install, base) = keys(&first, 0);
        assert_eq!(
            install, first,
            "a cache that never reinstalled keeps its keys"
        );
        let (install1, base1) = keys(&first, 1);
        let (install2, base2) = keys(&first, 2);
        assert!(install1 != install && install2 != install1);
        assert!(base1 != base && base2 != base1);

        let dir = std::env::temp_dir().join(format!("vk-winiso-reinstall-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let count = dir.join("reinstalls").join(&first);
        assert_eq!(reinstalls(&count), 0);
        count_reinstall(&count).unwrap();
        count_reinstall(&count).unwrap();
        assert_eq!(reinstalls(&count), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
