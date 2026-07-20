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
    /// virtiofsd binary, only needed when [share] is set
    pub virtiofsd: Option<PathBuf>,
    pub vm: Vm,
    pub guest: Guest,
    /// Dev only: host dir shared as the guest's /workdir over virtio-fs (the POC
    /// runner image assembles itself from the repo). CI images must NOT use this:
    /// the job clones into the VM, nothing of the host is exposed.
    pub share: Option<Share>,
    pub net: Net,
    /// Egress allowlist for `net.mode = "switch"`: the per-job switch refuses DNS
    /// names outside `allow_name` and direct connections outside `allow_ip` (plus
    /// the IPs it resolved for an allowed name). Empty (the default) = unrestricted
    /// — dev use leaves it empty; CI sets it as the corp egress gate.
    pub egress: Egress,
    /// Direct OCI boot of a registry image, backing the
    /// `MICROVM_IMAGE: docker/<name>[:tag|@sha256:…]` form; absent = that
    /// form is rejected
    pub docker: Option<Docker>,
    /// Native OCI bundle registry (push/pull with CDC+zstd chunk dedup), backing the
    /// `MICROVM_IMAGE: virtkit/<name>[:tag|@sha256:…]` form; absent = that form
    /// is rejected
    pub registry: Option<Registry>,
    /// Local guest bundles on the host filesystem, backing the
    /// `MICROVM_IMAGE: local/<name>` form (and the `local/default` default).
    pub local: Local,
    /// CI `services:` support: each declared service runs as a container inside
    /// the job VM, its image pulled through the host registry proxy over a vsock
    /// forward (so the registry credential never enters the guest). Absent = a
    /// job that declares services fails in prepare.
    pub services: Option<Services>,
    /// CI tools shared into GitLab job VMs over virtio-fs; see [`Gitlab`]. Absent =
    /// no share (the job image must carry its own git/git-lfs/gitlab-runner).
    pub gitlab: Option<Gitlab>,
    /// Host credentials forwarded into job VMs (currently the SSH agent); see [`Auth`].
    pub auth: Auth,
    /// Defaults for `vk build` so a runner need not pass them every invocation;
    /// see [`Build`]. A CLI flag always overrides the matching config value.
    pub build: Build,
    /// Materialized image bases (`<state_dir>/{registry,docker}/…/runner.ext4`) that have
    /// sat idle this many seconds — no VM overlaying them — are evicted the next time that
    /// same cache tier (`registry/` or `docker/`) takes a fresh pull; a base under a live
    /// overlay is never touched (reference-counted). Keep this well above zero: a near-zero
    /// value races the brief window between resolving a base and locking it. Default 1800
    /// (30 min). The compressed chunk store is the durable tier; the full ext4 is transient
    /// and re-materialized on demand.
    pub image_cache_idle_secs: Option<u64>,
}

/// Defaults for `vk build` (the experimental microVM Dockerfile builder). Every
/// field backs a CLI flag; the flag wins when given, so this just sets a host's defaults
/// (e.g. the shared instruction-cache registry and the build guest's kernel/agent).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Build {
    /// cloud-hypervisor for the build guest (default: the top-level `cloud_hypervisor`).
    pub cloud_hypervisor: Option<PathBuf>,
    /// the build guest kernel (the pinned vmlinux with virtio + ext4 built in).
    pub kernel: Option<PathBuf>,
    /// the virtkit-agent injected into the build guest as PID 1.
    pub agent: Option<PathBuf>,
    /// instruction cache: a registry repo (a `vk-registry` server), an absolute store
    /// directory path, or `none` to disable; unset = the builtin local store.
    pub cache_registry: Option<String>,
    /// the cache registry speaks plain HTTP (a loopback vk-registry).
    pub cache_insecure: bool,
    /// how aggressively the instruction cache is populated: `auto` (default), `layers`
    /// (one snapshot per stage), or `instructions` (one per RUN/COPY).
    pub build_cache: crate::build::BuildCache,
    /// add an ext4 journal to the exported image (the build itself stays journal-less).
    pub journal: bool,
    /// use a RAM tmpfs for each stage guest's `/tmp` instead of the default disk-backed
    /// scratch. Disk-backed `/tmp` (the default) bounds bulk `/tmp` writes by disk rather
    /// than ½·guest-RAM; set this to trade that for a RAM tmpfs. Default off (disk-backed).
    pub tmp_tmpfs: bool,
}

/// Host credentials forwarded into job VMs. The SSH agent is relayed over a vsock
/// forward to the runner's `$SSH_AUTH_SOCK`, so the guest's ssh/git use the host keys
/// without the keys ever entering the guest (same model as the services registry proxy).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Auth {
    /// Forward the runner's SSH agent into every job VM (no-op if `$SSH_AUTH_SOCK` is
    /// unset on the runner). Default off.
    pub ssh_agent: bool,
}

/// GitLab job tooling. `dir` is a host directory of static tool binaries (e.g.
/// `git`, `git-lfs`, `gitlab-runner`) that virtkit shares **read-only over
/// virtio-fs** into every job VM; the in-guest agent links each one onto the guest
/// PATH (`/usr/local/bin`), but only for a tool the job image does not already
/// provide (per-image opt-out, checked in-guest). Dynamic: the binaries stay on the
/// host and are baked into no bundle, so updating them needs no re-conversion.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Gitlab {
    pub dir: Option<PathBuf>,
    /// Check the job's git sources out on the HOST at prepare and share the tree into the
    /// guest over virtio-fs, instead of the in-guest `get_sources` clone. The job then sets
    /// `GIT_STRATEGY: none` so the checkout is reused and the git token never enters the guest
    /// (a security win), and the host has the tree available to build a git-defined image
    /// (`ci-boots-git-defined-images`). Off by default. Trade-off: a read-write virtio-fs
    /// share into an untrusted job guest is added host-side attack surface.
    #[serde(default)]
    pub host_checkout: bool,
    /// Root directory the `host_checkout` trees are cloned into on the host, keyed under it by
    /// the runner's concurrent slot + project. Unset = `<state_dir>/checkouts`. Point it at the
    /// runner's RAM-backed builds tmpfs (e.g. `/builds`) so the clone and every in-job write to
    /// the shared tree stay in host RAM instead of hitting the state disk.
    pub checkout_dir: Option<PathBuf>,
}

/// Egress allowlist for the per-job switch (`net.mode = "switch"`). Both lists
/// empty = unrestricted; passed through to `vk switch --allow-ip/--allow-name`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Egress {
    /// Allowed destination IPv4 CIDRs for direct (non-DNS-resolved) egress, each
    /// optionally scoped to a single port as `CIDR:port` (e.g. `10.0.0.0/8:443`).
    pub allow_ip: Vec<String>,
    /// Allowed DNS name suffixes, dot-anchored (e.g. `corp.example.com` also
    /// allows `*.corp.example.com`).
    pub allow_name: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Local {
    /// Directory of local guest bundles: each `<dir>/<name>/` is a bundle
    /// (`runner.ext4` + `boot.kind` [+ `vmlinuz` + `initrd.img`]). Unset =
    /// `<state_dir>/images` (see `Local::dir`).
    pub dir: Option<PathBuf>,
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
    /// prepare: max seconds from cloud-hypervisor spawn to a vk-agent status reply
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

/// `[docker]` — OPTIONAL registry proxy for direct OCI image boots. Absent (the default),
/// an image reference is pulled directly from whatever registry it names: the microVM
/// boundary is the security model, so image sources are not gated. Present, it *routes*
/// bare docker-hub-style names through the configured `repo` (with these credentials) — a
/// shared pull-through cache for the CI runners — while a ref that names its own registry
/// is still pulled directly. It never refuses an image. The native OCI client fetches the
/// image, the embedded vk-agent is PID 1, the embedded kernel boots it. Auth mirrors
/// `[registry]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Docker {
    /// Registry repository prefix bare image names are routed through, e.g.
    /// "registry.example.com/team" — a pull-through cache/proxy, not an allowlist.
    pub repo: String,
    /// PEM CA bundle the registry's TLS cert chains to (rustls). Absent = system roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// HTTP Basic username. Empty = anonymous.
    #[serde(default)]
    pub username: String,
    /// Path to a file holding the Basic-auth password (read at runtime, trailing newline
    /// trimmed; only when `username` is set). Provision out of band, 0600.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Plain HTTP registry (a local/insecure registry); default TLS.
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// Registry repository prefix for the bundles — fixed host side: the
    /// allowlist (jobs only pick name[:ref]), e.g. "registry.example.com/team"
    pub repo: String,
    /// PEM CA bundle the registry's TLS cert chains to (rustls; the binary stays
    /// musl-static). Absent = the system roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    /// HTTP Basic username. Empty = anonymous (no Authorization header sent).
    #[serde(default)]
    pub username: String,
    /// Path to a file holding the Basic-auth password — the secret stays OUT of
    /// this config; it is read at runtime (trailing newline trimmed) only when
    /// `username` is set. Provision it out of band with restrictive perms (0600).
    /// Sent over the (TLS, see `ca_file`) connection; pair with an HTTPS `repo`.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Plain HTTP registry (a local/insecure registry); default TLS
    #[serde(default)]
    pub insecure: bool,
    /// Push ext4 chunks addressed by the **uncompressed** chunk digest (the casync
    /// model): the client uploads raw chunks and the registry stores them zstd —
    /// dedup becomes compression-level-independent and the client never compresses
    /// to learn a digest (no chunkmap). Requires a cooperating registry that
    /// understands the encoding (virtkit's own `regserve`); a dumb OCI registry
    /// rejects it (the wire bytes don't hash to the uncompressed digest). Tri-state:
    /// unset = **auto** (probe the registry's `/v2/` for the capability and use
    /// transparent-zstd only if advertised, else the compressed-digest layers any OCI
    /// registry stores compactly); `true`/`false` force the choice. Pull auto-detects
    /// either form from the chunk media type regardless.
    #[serde(default)]
    pub transparent_zstd: Option<bool>,
    /// Run a credential-injecting registry proxy for executor guests: each job's switch
    /// exposes this registry at `registry.vk`, injecting these credentials, so a job
    /// pushes/pulls without ever holding the secret. Off by default.
    #[serde(default)]
    pub proxy_guests: bool,
}

impl Registry {
    /// The store directory when `repo` names a local store rather than a remote
    /// registry: an absolute path (`/…`) or a `file://` URL. registry.rs then
    /// reads/writes the regserve content-addressed store in-process — no server,
    /// no port, no auth; `ca_file`/`username`/`insecure`/`transparent_zstd` are
    /// all meaningless and ignored for such a repo.
    pub fn local_root(&self) -> Option<PathBuf> {
        if let Some(p) = self.repo.strip_prefix("file://") {
            return Some(PathBuf::from(p));
        }
        self.repo
            .starts_with('/')
            .then(|| PathBuf::from(&self.repo))
    }

    /// Build a `Registry` for the build-sharing path, from the CLI flags rather than a
    /// config file (only push/pull-by-fingerprint; nothing boots or is cache-evicted here).
    pub fn for_share(
        repo: String,
        insecure: bool,
        ca_file: Option<PathBuf>,
        username: String,
        password_file: Option<PathBuf>,
        transparent_zstd: Option<bool>,
    ) -> Registry {
        Registry {
            repo,
            ca_file,
            username,
            password_file,
            insecure,
            transparent_zstd,
            proxy_guests: false,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Services {
    /// Retained for config compatibility; no longer consulted. CI service images now
    /// share the job's digest-keyed image cache under `<state_dir>` (see image.rs),
    /// rather than a separate per-service store.
    pub store_dir: Option<PathBuf>,
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
    /// "none"; "tap" (pre-created persistent tap; one VM at a time per tap);
    /// "pool" (a leased tap from the host pool — the hardened host networking);
    /// or "switch" (a per-job userspace switch over vsock, no host privileges
    /// and no virtio-net device — the in-guest agent bridges eth0 to it, and the
    /// `[egress]` allowlist gates egress in-switch).
    pub mode: String,
    pub tap: String,
    pub mac: String,
    /// mode = "switch": vsock port the in-guest agent bridges eth0 to the
    /// per-job switch over (the guest dials host CID 2 on this port; Cloud
    /// Hypervisor surfaces it as `<vsock.sock>_<net_port>`, where the switch
    /// listens). Must differ from the services port.
    pub net_port: u32,
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
            net_port: 1024,
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

    /// The local-bundles directory resolved against a caller-chosen `state_dir`:
    /// `[local] dir` if set, else `<state_dir>/images`. Threading the state dir (rather
    /// than reading the config default) lets a non-CI caller (`vk run`) share the resolve
    /// path while keeping its cache under its own state dir.
    pub fn local_dir_under(&self, state_dir: &Path) -> PathBuf {
        match &self.local.dir {
            Some(dir) => dir.clone(),
            None => state_dir.join("images"),
        }
    }

    /// How long a materialized image base may sit idle (no live overlay) before the
    /// cache GC evicts it. Default 30 min.
    pub fn image_cache_idle(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.image_cache_idle_secs.unwrap_or(1800))
    }

    pub fn cloud_hypervisor(&self) -> &Path {
        self.cloud_hypervisor
            .as_deref()
            .unwrap_or(Path::new("cloud-hypervisor"))
    }

    /// The command that runs virtiofsd. With no `[virtiofsd]` configured it is the
    /// bundled daemon — this executable's `virtiofsd` subcommand (built in by the
    /// default `virtiofsd` feature); set the config path to use an external binary.
    pub fn virtiofsd_command(&self) -> std::process::Command {
        match &self.virtiofsd {
            Some(path) => std::process::Command::new(path),
            None => {
                let mut c = std::process::Command::new(crate::spawn::self_exe());
                c.arg("virtiofsd");
                c
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitlab_tools_dir_parses() {
        let cfg: Config = toml::from_str(
            r#"
            [gitlab]
            dir = "/usr/local/lib/vk/ci-tools"
            "#,
        )
        .unwrap();
        assert_eq!(
            cfg.gitlab.as_ref().unwrap().dir.as_deref(),
            Some(Path::new("/usr/local/lib/vk/ci-tools"))
        );
    }

    #[test]
    fn gitlab_checkout_dir_parses() {
        let cfg: Config = toml::from_str(
            r#"
            [gitlab]
            host_checkout = true
            checkout_dir = "/builds"
            "#,
        )
        .unwrap();
        let g = cfg.gitlab.as_ref().unwrap();
        assert!(g.host_checkout);
        assert_eq!(g.checkout_dir.as_deref(), Some(Path::new("/builds")));
        // absent = None: the on-disk `<state_dir>/checkouts` default is preserved
        let bare: Config = toml::from_str("[gitlab]\ndir = \"/x\"\n").unwrap();
        assert!(bare.gitlab.as_ref().unwrap().checkout_dir.is_none());
    }

    #[test]
    fn no_gitlab_section_means_no_tools() {
        let cfg = Config::default();
        assert!(cfg.gitlab.is_none());
    }

    #[test]
    fn egress_allowlist_parses() {
        let cfg: Config = toml::from_str(
            r#"
            [egress]
            allow_ip = ["10.0.0.0/8", "192.168.1.1/32"]
            allow_name = ["corp.example.com", "github.com"]
            "#,
        )
        .unwrap();
        assert_eq!(cfg.egress.allow_ip, ["10.0.0.0/8", "192.168.1.1/32"]);
        assert_eq!(cfg.egress.allow_name, ["corp.example.com", "github.com"]);
        // absent [egress] = unrestricted (both lists empty)
        let none = Config::default();
        assert!(none.egress.allow_ip.is_empty() && none.egress.allow_name.is_empty());
    }

    #[test]
    fn net_port_default() {
        assert_eq!(Net::default().net_port, 1024);
    }

    #[test]
    fn auth_ssh_agent_parses() {
        let cfg: Config = toml::from_str("[auth]\nssh_agent = true\n").unwrap();
        assert!(cfg.auth.ssh_agent);
        // absent [auth] = off
        assert!(!Config::default().auth.ssh_agent);
    }

    #[test]
    fn build_defaults_parse() {
        let cfg: Config = toml::from_str(
            r#"
            [build]
            kernel = "/k/vmlinux"
            agent = "/k/virtkit-agent"
            cache_registry = "127.0.0.1:5000"
            cache_insecure = true
            build_cache = "layers"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.build.kernel.as_deref(), Some(Path::new("/k/vmlinux")));
        assert_eq!(cfg.build.cache_registry.as_deref(), Some("127.0.0.1:5000"));
        assert!(cfg.build.cache_insecure && !cfg.build.journal);
        assert_eq!(cfg.build.build_cache, crate::build::BuildCache::Layers);
        // absent [build] = all unset, cache mode defaults to auto
        assert!(Config::default().build.cache_registry.is_none());
        assert_eq!(
            Config::default().build.build_cache,
            crate::build::BuildCache::Auto
        );
    }
}
