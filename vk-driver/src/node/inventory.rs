//! What `vk node` reports: the inventory — hardware, storage, versions, runner — and the
//! heartbeat's readings, with the workloads read alongside them. Everything comes from what
//! the rest of `vk` already measures: the admission ledger, the scheduler's
//! desired-concurrency file, the memory budget, the NUMA topology and `vk check`.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use sha2::{Digest, Sha256};
use vk_hub_proto::{
    Admission, Check, Filesystem, FsUsage, Hardware, Heartbeat, Inventory, MemoryNode, Runner,
    StorageRole, Versions,
};

use crate::check::Feature;
use crate::config::Config;
use crate::workloads::{Ledger, Listed, Lister};

/// The `vk check` features a node must pass to enroll, and reports in its inventory: the
/// ones every VM this host boots depends on.
pub const GATE: [Feature; 3] = [Feature::Kvm, Feature::Vmm, Feature::Kernel];

/// `statfs`' `f_type` for tmpfs.
const TMPFS_MAGIC: u64 = 0x0102_1994;

/// The most of a gitlab-runner config read: a real one is a few kilobytes.
pub(super) const MAX_RUNNER_CONFIG: u64 = 1 << 20;

/// The most runner names reported, and the longest one kept.
const MAX_RUNNERS: usize = 64;
const MAX_RUNNER_NAME: usize = 256;

/// The `vk check` gate's results.
pub fn checks(cfg: &Config) -> Vec<Check> {
    GATE.iter()
        .map(|&f| {
            let result = crate::check::probe(cfg, f);
            Check {
                name: f.name().to_string(),
                ok: result.is_ok(),
                detail: result.err().unwrap_or_default(),
            }
        })
        .collect()
}

pub fn inventory(cfg: &Config) -> Inventory {
    Inventory {
        hostname: hostname(),
        hardware: Hardware {
            cpus: online_cpus(),
            cpu_model: cpu_model(Path::new("/proc/cpuinfo")),
            mem_total_mib: crate::schedule::host_total_mib(),
            memory_nodes: crate::numa::Topology::detect()
                .map(|t| {
                    t.nodes
                        .iter()
                        .map(|n| MemoryNode {
                            id: n.id,
                            cpus: u32::try_from(n.cpus.len()).unwrap_or(u32::MAX),
                            mem_total_mib: n.mem_total_mib,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            checks: checks(cfg),
        },
        storage: storage_roots(cfg)
            .into_iter()
            .filter_map(|(role, path, speed)| filesystem(role, &path, speed))
            .collect(),
        versions: Versions {
            vk: env!("CARGO_PKG_VERSION").to_string(),
            guest_kernel: guest_kernel().clone(),
            config_hash: config_hash(cfg),
            vk_sha256: super::update::known_sha256(),
            tools: None,
        },
        runner: runner_config(cfg),
        // Checked when `vk node run` starts; one gone wrong since is left out.
        labels: labels(cfg).unwrap_or_default(),
    }
}

/// Maximum label count and length.
const MAX_LABELS: usize = 32;
const MAX_LABEL: usize = 64;

/// Validate `[node] labels` as short words the hub can store and print unchanged.
pub fn labels(cfg: &Config) -> anyhow::Result<Vec<String>> {
    let labels = &cfg.node.labels;
    if labels.len() > MAX_LABELS {
        anyhow::bail!("[node] labels: at most {MAX_LABELS} labels");
    }
    for label in labels {
        let ok = (1..=MAX_LABEL).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.:/=".contains(&b));
        if !ok {
            anyhow::bail!(
                "[node] labels: {:?} is not 1 to {MAX_LABEL} of ASCII letters, digits and -_.:/=",
                vk_hub_proto::display_safe(label)
            );
        }
    }
    let mut out = labels.clone();
    out.sort();
    out.dedup();
    Ok(out)
}

/// What the heartbeat keeps from one reading to the next.
#[derive(Default)]
pub struct Readings {
    /// The admission as last read, standing in while an admission holds the ledger.
    admission: Option<Admission>,
    /// The VM registry the workloads are read from; `None` for the user's own.
    registry: Option<PathBuf>,
    /// The workloads' lister, for its measuring cadence and last figures; made on the first
    /// heartbeat.
    lister: Option<Lister>,
}

impl Readings {
    /// Readings of the VMs in `registry`, or the user's own registry's when `None`.
    pub fn new(registry: Option<PathBuf>) -> Self {
        Readings {
            registry,
            ..Readings::default()
        }
    }
}

/// The heartbeat, and the workloads its memory readings are for: both read off one look at
/// the admission ledger.
pub fn heartbeat(cfg: &Config, readings: &mut Readings) -> (Heartbeat, Listed) {
    let lister = readings.lister.get_or_insert_with(|| {
        Lister::new(cfg.node.workload_mem_every(), readings.registry.clone())
    });
    // Do not wait for the admission's ledger lock: that would delay the heartbeat.
    // Reuse the last admission reading until the lock is free.
    match lister.read_ledger(cfg) {
        Ledger::Read(held) => {
            readings.admission = Some(Admission {
                committed_mib: held.granted_mib,
                // An unresolvable budget (a percentage on a host whose memory cannot be
                // read) is reported as none: `vk tune` refuses to run on it, so there is no
                // budget in force.
                budget_mib: crate::vm::budget_mib(cfg).and_then(Result::ok),
                running: u32::try_from(held.granted).unwrap_or(u32::MAX),
                waiting: u32::try_from(held.ahead).unwrap_or(u32::MAX),
            });
        }
        Ledger::Busy => {}
        Ledger::Unreadable => readings.admission = None,
    }
    let (workloads, workload_mem_bytes) = lister.look(cfg);
    let heartbeat = Heartbeat {
        admission: readings.admission.clone(),
        desired_concurrency: std::fs::read_to_string(crate::schedule::desired_file(cfg))
            .ok()
            .and_then(|t| t.trim().parse().ok()),
        mem_available_mib: crate::schedule::host_memory().map(|m| m.available_mib),
        storage: storage_roots(cfg)
            .into_iter()
            .filter_map(|(role, path, _)| {
                let space = crate::usage::fs_space(&existing_ancestor(&path)?).ok()?;
                Some(FsUsage {
                    role,
                    free_bytes: space.avail,
                    free_inodes: space.files_avail,
                    inodes: space.files,
                })
            })
            .collect(),
        workload_mem_bytes,
    };
    (heartbeat, workloads)
}

/// The filesystems a node reports: the job dirs always, host checkouts when the executor
/// makes them.
fn storage_roots(cfg: &Config) -> Vec<(StorageRole, PathBuf, Option<vk_hub_proto::SpeedClass>)> {
    let mut roots = vec![(
        StorageRole::Jobs,
        cfg.state_dir().join("jobs"),
        cfg.node.jobs_speed,
    )];
    if cfg.executor.host_checkout {
        roots.push((
            StorageRole::Checkouts,
            cfg.checkout_root(),
            cfg.node.checkouts_speed,
        ));
    }
    roots
}

/// The filesystem that holds `path`, or will once it exists. `None` when nothing on the way
/// up can be read, which leaves the role out of the inventory rather than reporting zeros.
fn filesystem(
    role: StorageRole,
    path: &Path,
    speed: Option<vk_hub_proto::SpeedClass>,
) -> Option<Filesystem> {
    let at = existing_ancestor(path)?;
    let space = crate::usage::fs_space(&at).ok()?;
    let dev = std::fs::metadata(&at).ok()?.dev();
    Some(Filesystem {
        role,
        path: path.display().to_string(),
        device: format!("{}:{}", libc::major(dev), libc::minor(dev)),
        size_bytes: space.total,
        tmpfs: is_tmpfs(&at),
        speed,
    })
}

/// `path`, or its nearest ancestor that exists: a job dir root is created by the first job.
fn existing_ancestor(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|p| std::fs::symlink_metadata(p).is_ok())
        .map(Path::to_path_buf)
}

fn is_tmpfs(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: statfs fills the whole struct through the pointer, and only on success.
    unsafe {
        if libc::statfs(c_path.as_ptr(), buf.as_mut_ptr()) != 0 {
            return false;
        }
        // `f_type` is signed on glibc and unsigned on musl; the magic fits either.
        #[allow(clippy::unnecessary_cast)]
        let f_type = buf.assume_init().f_type as u64;
        f_type == TMPFS_MAGIC
    }
}

/// CPUs online on the host. Not `available_parallelism`, which answers for this process's
/// affinity and cgroup — a `vk node` started under a restricted unit would report a smaller
/// host than the one its jobs run on.
fn online_cpus() -> u32 {
    // SAFETY: sysconf reads a system value and touches no memory of ours.
    let n = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    u32::try_from(n).unwrap_or(0)
}

/// The host's name, or empty where it cannot be read: a name is for display only, the hub
/// knows the node by its ID.
pub(super) fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
}

/// The first `model name` in `/proc/cpuinfo`: x86's spelling, the one host `vk` runs on.
fn cpu_model(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|l| {
        let (key, value) = l.split_once(':')?;
        (key.trim() == "model name").then(|| value.trim().to_string())
    })
}

/// The guest kernel's release, from the `Linux version <release> ` banner every kernel image
/// carries: the embedded one, else the on-disk one `vk check` accepts in its place. Read once
/// per process: the image is tens of megabytes, and a replaced one is picked up by the next
/// `vk node run`, as it is by the next `vk`.
fn guest_kernel() -> &'static Option<String> {
    static RELEASE: OnceLock<Option<String>> = OnceLock::new();
    RELEASE.get_or_init(|| {
        let asset = crate::embed::Asset::Kernel;
        match asset.embedded() {
            Some(image) => kernel_release(image),
            None => kernel_release(&std::fs::read(asset.default_path()).ok()?),
        }
    })
}

fn kernel_release(image: &[u8]) -> Option<String> {
    const BANNER: &[u8] = b"Linux version ";
    let at = image.windows(BANNER.len()).position(|w| w == BANNER)? + BANNER.len();
    let rest = image.get(at..)?;
    let end = rest.iter().take(64).position(|&b| b == b' ')?;
    String::from_utf8(rest.get(..end)?.to_vec()).ok()
}

/// A hash of the effective configuration as `vk config` prints it, so two nodes loaded from
/// equivalent files agree however those files are laid out.
fn config_hash(cfg: &Config) -> String {
    // `Config` always serializes — `vk config` prints it the same way — so the fallback is
    // unreachable, and would only make every node's hash agree.
    let text = toml::to_string(cfg).unwrap_or_default();
    vk_hub_proto::to_hex(&Sha256::digest(text.as_bytes()))
}

/// The gitlab-runner configuration this node's runner reads: the one the node steers
/// ([`crate::schedule::runner_config`]) when there is one, else the root-managed one
/// `vk-runnerctl` steers, if it is readable.
fn runner_config(cfg: &Config) -> Option<Runner> {
    runner_config_in(cfg, std::env::var_os("HOME").as_deref())
}

/// [`runner_config`], with `home` for `$HOME`.
fn runner_config_in(cfg: &Config, home: Option<&std::ffi::OsStr>) -> Option<Runner> {
    let path = crate::schedule::runner_config_in(cfg, home)
        .unwrap_or_else(|| PathBuf::from("/etc/gitlab-runner/config.toml"));
    read_runner(&path)
}

fn read_runner(path: &Path) -> Option<Runner> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(MAX_RUNNER_CONFIG).read_to_string(&mut text))
        .ok()?;
    let mut runner = parse_runner(&text)?;
    runner.config = path.display().to_string();
    Some(runner)
}

/// `concurrent` and each `[[runners]]` name, up to [`MAX_RUNNERS`] of them, each cut to
/// [`MAX_RUNNER_NAME`] characters. Tags are not in this file — GitLab holds them — so they
/// are not reported.
fn parse_runner(text: &str) -> Option<Runner> {
    let table: toml::Table = toml::from_str(text).ok()?;
    Some(Runner {
        config: String::new(),
        concurrent: table
            .get("concurrent")
            .and_then(toml::Value::as_integer)
            .and_then(|n| u32::try_from(n).ok()),
        runners: table
            .get("runners")
            .and_then(toml::Value::as_array)
            .map(|rs| {
                rs.iter()
                    .filter_map(|r| r.get("name")?.as_str())
                    .take(MAX_RUNNERS)
                    .map(|name| name.chars().take(MAX_RUNNER_NAME).collect())
                    .collect()
            })
            .unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_checked_and_kept_sorted() {
        let cfg = |toml: &str| -> Config { toml::from_str(toml).unwrap() };
        assert_eq!(
            labels(&cfg(
                "[node]\nlabels = [\"large-memory\", \"gpu\", \"gpu\"]\n"
            ))
            .unwrap(),
            vec!["gpu".to_string(), "large-memory".to_string()]
        );
        for bad in ["\"\"", "\"two words\"", "\"tab\\t\"", "\"é\""] {
            assert!(
                labels(&cfg(&format!("[node]\nlabels = [{bad}]\n"))).is_err(),
                "{bad}"
            );
        }
        let many: Vec<String> = (0..33).map(|i| format!("\"l{i}\"")).collect();
        assert!(labels(&cfg(&format!("[node]\nlabels = [{}]\n", many.join(",")))).is_err());
    }

    #[test]
    fn the_kernel_release_is_read_from_its_banner() {
        let mut image = vec![0u8; 100];
        image.extend_from_slice(b"Linux version 6.18.52 (vk@build) #1 SMP");
        assert_eq!(kernel_release(&image).as_deref(), Some("6.18.52"));
        assert_eq!(kernel_release(b"no banner here"), None);
        assert_eq!(kernel_release(b"Linux version 6.18"), None);
    }

    #[test]
    fn the_runner_config_yields_concurrent_and_names() {
        let r = parse_runner(
            "concurrent = 12\ncheck_interval = 0\n\n[[runners]]\nname = \"ci-7\"\n\
             executor = \"custom\"\n\n[[runners]]\nname = \"ci-7-big\"\n",
        )
        .unwrap();
        assert_eq!(r.concurrent, Some(12));
        assert_eq!(r.runners, ["ci-7", "ci-7-big"]);
        let bare = parse_runner("").unwrap();
        assert_eq!((bare.concurrent, bare.runners.len()), (None, 0));
        assert!(parse_runner("not = [toml").is_none());
    }

    #[test]
    fn the_runner_config_the_node_steers_is_the_one_reported() {
        let dir = std::env::temp_dir().join(format!("vk-inventory-runner-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let cfg: Config = toml::from_str(&format!(
            "[node]\nrunner_config = {:?}\n",
            path.display().to_string()
        ))
        .unwrap();
        // An unreadable configured path reports no config, without falling back.
        assert!(runner_config(&cfg).is_none());
        std::fs::write(&path, "concurrent = 3\n[[runners]]\nname = \"mine\"\n").unwrap();
        let r = runner_config(&cfg).unwrap();
        assert_eq!(r.config, path.display().to_string());
        assert_eq!(
            (r.concurrent, r.runners.as_slice()),
            (Some(3), &["mine".to_string()][..])
        );

        // Without runner_config, managed runners use the user's config; external runners
        // use root's, even when the user's config exists.
        let home = dir.join("home");
        let own = home.join(".gitlab-runner/config.toml");
        std::fs::create_dir_all(own.parent().unwrap()).unwrap();
        std::fs::write(&own, "concurrent = 5\n").unwrap();
        let managed: Config = toml::from_str("[node]\nrunner = \"managed\"\n").unwrap();
        let r = runner_config_in(&managed, Some(home.as_os_str())).unwrap();
        assert_eq!(
            (r.config, r.concurrent),
            (own.display().to_string(), Some(5))
        );
        let external = Config::default();
        assert!(
            runner_config_in(&external, Some(home.as_os_str()))
                .is_none_or(|r| r.config == "/etc/gitlab-runner/config.toml")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_cpu_model_is_the_first_model_name() {
        let dir = std::env::temp_dir().join(format!("vk-node-cpuinfo-{}", std::process::id()));
        std::fs::write(
            &dir,
            "processor\t: 0\nmodel name\t: AMD EPYC 7543 32-Core Processor\n\
             processor\t: 1\nmodel name\t: other\n",
        )
        .unwrap();
        assert_eq!(
            cpu_model(&dir).as_deref(),
            Some("AMD EPYC 7543 32-Core Processor")
        );
        std::fs::remove_file(&dir).unwrap();
    }

    #[test]
    fn storage_is_reported_for_the_nearest_existing_directory() {
        let cfg: Config = toml::from_str(&format!(
            "state_dir = {:?}\n[node]\njobs_speed = \"slow\"\n",
            std::env::temp_dir()
                .join("vk-node-no-such-state")
                .display()
                .to_string()
        ))
        .unwrap();
        let roots = storage_roots(&cfg);
        assert_eq!(roots.len(), 1);
        let (role, path, speed) = &roots[0];
        let fs = filesystem(*role, path, *speed).unwrap();
        assert_eq!(fs.role, StorageRole::Jobs);
        assert_eq!(fs.speed, Some(vk_hub_proto::SpeedClass::Slow));
        assert!(fs.size_bytes > 0);
        assert!(fs.path.ends_with("vk-node-no-such-state/jobs"));
        // The VMs from a registry with none in it, not this host's.
        let registry = std::env::temp_dir().join("vk-node-no-such-registry");
        let (hb, listed) = heartbeat(&cfg, &mut Readings::new(Some(registry)));
        assert_eq!(listed, Default::default());
        assert_eq!(hb.storage.len(), 1);
        // No ledger at all is a fresh host, not a failure.
        assert_eq!(hb.admission.map(|a| a.committed_mib), Some(0));
    }

    #[test]
    fn equal_configurations_hash_equal() {
        // A default spelled out is the same configuration as one left unsaid.
        let a: Config = toml::from_str("state_dir = \"/x\"\n").unwrap();
        let b: Config = toml::from_str("state_dir = \"/x\"\n\n[numa]\nmode = \"auto\"\n").unwrap();
        let c: Config = toml::from_str("state_dir = \"/y\"\n").unwrap();
        assert_eq!(config_hash(&a), config_hash(&b));
        assert_ne!(config_hash(&a), config_hash(&c));
    }
}
