//! virtkit configuration (/etc/virtkit/config.toml, override with
//! VIRTKIT_CONFIG=). Every field has a default so the file can stay minimal;
//! a missing file yields the defaults (enough for `config`, not for `prepare`,
//! which validates the image paths).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

pub const DEFAULT_PATH: &str = "/etc/virtkit/config.toml";

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Per-job state lives under <state_dir>/jobs/<job id>/
    pub state_dir: Option<PathBuf>,
    /// Path of the cloud-hypervisor binary (a bare name resolves through PATH)
    pub cloud_hypervisor: Option<PathBuf>,
    /// qemu-img, used to create the per-job qcow2 overlay
    pub qemu_img: Option<PathBuf>,
    /// virtiofsd binary, only needed when [share] is set
    pub virtiofsd: Option<PathBuf>,
    pub image: Image,
    pub vm: Vm,
    pub guest: Guest,
    /// Dev only: host dir shared as the guest's /workdir over virtio-fs (the POC
    /// runner image assembles itself from the repo). CI images must NOT use this:
    /// the job clones into the VM, nothing of the host is exposed.
    pub share: Option<Share>,
    pub net: Net,
    /// On-demand docker-image → bootable-bundle conversion, backing the
    /// `MICROVM_IMAGE: docker/<name>[:tag|@sha256:…]` form; absent = that
    /// form is rejected
    pub convert: Option<Convert>,
    /// Native OCI bundle registry (push/pull with CDC+zstd chunk dedup), backing the
    /// `MICROVM_IMAGE: registry/<name>[:tag|@sha256:…]` form; absent = that form
    /// is rejected
    pub registry: Option<Registry>,
    /// CI `services:` support: each declared service runs as a container inside
    /// the job VM, its image pulled through the host registry proxy over a vsock
    /// forward (so the registry credential never enters the guest). Absent = a
    /// job that declares services fails in prepare.
    pub services: Option<Services>,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Image {
    /// Read-only ext4 rootfs (build-image.sh bundle); each job boots a throwaway
    /// qcow2 overlay backed by it
    pub rootfs: Option<PathBuf>,
    pub kernel: Option<PathBuf>,
    pub initrd: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// Registry repository prefix for the bundles — fixed host side: the
    /// allowlist (jobs only pick name[:ref]), e.g. "registry.example.com/team"
    pub repo: String,
    /// PEM CA bundle the registry's TLS cert chains to (rustls; the binary stays
    /// musl-static). Absent = the system roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Registry credentials (empty username = anonymous)
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Plain HTTP registry (a local/insecure registry); default TLS
    #[serde(default)]
    pub insecure: bool,
    /// Pinned guest kernel for generic (kernel-less) bundles — the shared vmlinux
    /// with virtio + ext4 built in, booted directly when a bundle ships no kernel.
    #[serde(default = "default_generic_kernel")]
    pub generic_kernel: PathBuf,
    /// Cached pulled bundles kept per image
    #[serde(default = "default_keep")]
    pub keep: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Vm {
    pub cpus: u32,
    pub mem: String,
    pub hostname: String,
    /// Guest vsock port the in-VM virtkit-agent listens on
    pub vsock_port: u32,
    /// virtio-balloon with free_page_reporting: memory freed by the guest
    /// returns to the host mid-job, making overcommit safe (like containers)
    pub balloon: bool,
    /// Ceilings for the per-job MICROVM_CPUS/MICROVM_MEM variables; unset =
    /// jobs cannot request more than the cpus/mem defaults above
    pub max_cpus: Option<u32>,
    pub max_mem: Option<String>,
    /// Appended verbatim to the kernel command line
    pub cmdline_extra: String,
    /// prepare: max seconds from cloud-hypervisor spawn to a virtkit-agent status reply
    pub boot_timeout_secs: u64,
    /// cleanup: seconds granted to the ACPI poweroff before escalating
    pub shutdown_timeout_secs: u64,
}

impl Default for Vm {
    fn default() -> Self {
        Vm {
            cpus: 4,
            mem: "4G".into(),
            hostname: "runner".into(),
            vsock_port: 4444,
            balloon: true,
            max_cpus: None,
            max_mem: None,
            cmdline_extra: String::new(),
            boot_timeout_secs: 120,
            shutdown_timeout_secs: 15,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Guest {
    /// Paths inside the VM, reported to gitlab-runner by `config`
    pub builds_dir: String,
    pub cache_dir: String,
    /// Command the stage scripts are piped into (stdin), run by the in-VM agent
    pub run_command: Vec<String>,
    /// In-guest tmpfs mounts, "path:size" (e.g. "/builds:64G") — mounted by the agent
    /// from the VIRTKIT_TMPFS kernel cmdline variable. RAM-backed scratch space for
    /// hosts with slow disks; count it into vm.mem.
    pub tmpfs: Vec<String>,
}

impl Default for Guest {
    fn default() -> Self {
        Guest {
            builds_dir: "/builds".into(),
            cache_dir: "/cache".into(),
            run_command: vec!["bash".into()],
            tmpfs: vec![],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Convert {
    /// Registry repository prefix for the docker images — fixed host side on
    /// purpose: this is the allowlist (jobs only pick name[:ref]),
    /// e.g. "registry.example.com/team"
    pub repo: String,
    /// docker CLI driving the host daemon (pull + the root conversion
    /// container; the runner user must be in the docker group)
    #[serde(default = "default_docker")]
    pub docker: PathBuf,
    /// The guest agent (virtkit-agent) injected into the converted rootfs as
    /// PID 1; staged on the host next to virtkit by the runner provisioning
    #[serde(default = "default_host_agent")]
    pub agent: PathBuf,
    /// ext4 size of the produced rootfs (sparse file)
    #[serde(default = "default_rootfs_size")]
    pub rootfs_size: String,
    /// Pinned guest kernel for generic (kernel-less) OCI images (alpine,
    /// distroless, …): the pinned vmlinux, with virtio (blk/net/vsock) + ext4
    /// built in, so such images boot it directly — no per-image kernel, initrd
    /// or modules.
    #[serde(default = "default_generic_kernel")]
    pub generic_kernel: PathBuf,
    /// Generic images boot from an ext4 disk (true) or a cpio initramfs in RAM
    /// (false). Disk suits larger images; RAM is faster for small ones.
    #[serde(default)]
    pub generic_disk: bool,
    /// tag → digest resolution (same wiring as [store])
    #[serde(default = "default_oras")]
    pub oras: PathBuf,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// Registry credentials, shared by oras and docker pull (empty username =
    /// anonymous). The docker daemon must also trust the registry TLS cert
    /// (/etc/docker/certs.d/<registry>/ca.crt).
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Cached conversions kept per image
    #[serde(default = "default_keep")]
    pub keep: u32,
}

fn default_docker() -> PathBuf {
    "docker".into()
}
fn default_host_agent() -> PathBuf {
    "/usr/local/lib/virtkit/virtkit-agent".into()
}
fn default_rootfs_size() -> String {
    "32G".into()
}
fn default_generic_kernel() -> PathBuf {
    "/usr/local/lib/virtkit/vmlinux".into()
}

fn default_oras() -> PathBuf {
    "/usr/local/bin/oras".into()
}
fn default_keep() -> u32 {
    3
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Services {
    /// Host-local registry pull-through proxy (gitlab-ci/runners 42-microvm-registry.sh)
    /// the per-job host forward targets; the guest pulls service images through
    /// it so the registry credential stays host-side.
    pub registry_proxy: String,
    /// vsock port linking the guest forward (listens on 127.0.0.1:<port>) to the
    /// host forward (listens on <vsock.sock>_<port>); also the guest-local port
    /// the rewritten service refs point at. 127.0.0.0/8 is auto-insecure in docker.
    pub port: u32,
    /// Seconds to wait for each service's first exposed port to accept TCP.
    pub ready_timeout_secs: u64,
}

impl Default for Services {
    fn default() -> Self {
        Services {
            registry_proxy: "127.0.0.1:5000".into(),
            port: 5000,
            ready_timeout_secs: 60,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Share {
    pub dir: PathBuf,
    #[serde(default = "default_true")]
    pub readonly: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Net {
    /// "none", or "tap" (pre-created persistent tap; one VM at a time per tap —
    /// the tap pool arrives with the hardened host networking)
    pub mode: String,
    pub tap: String,
    pub mac: String,
    /// Static guest config passed on the kernel command line (the kernel `ip=`
    /// autoconfig param + VIRTKIT_VM_DNS); ip is CIDR ("172.18.0.250/16")
    pub ip: String,
    /// Gateway/DNS; in pool mode they default to the subnet's .1 (the bridge)
    pub gw: String,
    pub dns: String,
    /// mode = "pool": host-precreated taps <tap_prefix>0..<count-1>, all on a
    /// NATed bridge; VM i gets a deterministic IP in `subnet` (see net.rs)
    pub tap_prefix: String,
    pub count: u32,
    pub subnet: String,
}

impl Default for Net {
    fn default() -> Self {
        Net {
            mode: "none".into(),
            tap: String::new(),
            mac: "52:54:00:d2:f0:01".into(),
            ip: String::new(),
            gw: String::new(),
            dns: String::new(),
            tap_prefix: "civtap".into(),
            count: 32,
            subnet: "192.168.231.0/24".into(),
        }
    }
}

impl Config {
    pub fn load() -> Result<Config> {
        let (path, explicit) = match std::env::var_os("VIRTKIT_CONFIG") {
            Some(p) => (PathBuf::from(p), true),
            None => (PathBuf::from(DEFAULT_PATH), false),
        };
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => {
                Ok(Config::default())
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn state_dir(&self) -> &Path {
        self.state_dir
            .as_deref()
            .unwrap_or(Path::new("/var/lib/virtkit"))
    }

    pub fn cloud_hypervisor(&self) -> &Path {
        self.cloud_hypervisor
            .as_deref()
            .unwrap_or(Path::new("cloud-hypervisor"))
    }

    pub fn qemu_img(&self) -> &Path {
        self.qemu_img.as_deref().unwrap_or(Path::new("qemu-img"))
    }

    /// The command that runs virtiofsd. With no `[virtiofsd]` configured it is the
    /// bundled daemon — this executable's `virtiofsd` subcommand (built in by the
    /// default `virtiofsd` feature); set the config path to use an external binary.
    pub fn virtiofsd_command(&self) -> std::process::Command {
        match &self.virtiofsd {
            Some(path) => std::process::Command::new(path),
            None => {
                let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("virtkit"));
                let mut c = std::process::Command::new(exe);
                c.arg("virtiofsd");
                c
            }
        }
    }
}
