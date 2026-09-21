//! Selective cleanup of a stopped environment, without discarding its identity.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{File, Metadata, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::Args;

use super::plan::Plan;

#[derive(Args, Default)]
pub(super) struct Options {
    /// remove local boot images and disposable boot media (the default selection)
    #[arg(long)]
    images: bool,
    /// destroy persistent disks, overlays, editor data and managed directories in state
    #[arg(long)]
    storage: bool,
    /// select both images and storage; never includes external data or shared caches
    #[arg(long, conflicts_with_all = ["images", "storage"])]
    all: bool,
    /// show exactly what would be removed without removing anything
    #[arg(long)]
    dry_run: bool,
    /// remove the selected data without asking
    #[arg(short = 'y', long)]
    yes: bool,
}

impl Options {
    fn images(&self) -> bool {
        self.images || self.all || !self.storage
    }

    fn storage(&self) -> bool {
        self.storage || self.all
    }
}

// Named primary and service boot media. Shared cache tiers are not walked.
const MEDIA: &[&str] = &[
    "root.qcow2",
    "root.qcow2.json",
    "root.ext4",
    "root.ext4.json",
    "overlay.qcow2",
    "image.ext4",
    "image.ext4.json",
    "initramfs.cpio",
    "vmlinuz",
];
const STORAGE_DIRS: &[&str] = &["roots", "overlays", "editor"];

/// A selected name relative to a held parent descriptor. Never follow a symlink in
/// a selected path; links *inside* a removed directory are unlinked, not traversed.
struct Target {
    parent: File,
    relative: PathBuf,
    metadata: Metadata,
    category: &'static str,
}

impl Target {
    fn path(&self) -> Result<PathBuf> {
        let name = self.relative.file_name().context("empty prune target")?;
        Ok(fd_path(&self.parent).join(name))
    }

    fn unchanged(&self) -> Result<()> {
        let now = std::fs::symlink_metadata(self.path()?)?;
        ensure!(
            (now.dev(), now.ino(), now.mode())
                == (
                    self.metadata.dev(),
                    self.metadata.ino(),
                    self.metadata.mode()
                ),
            "{} changed while pruning; nothing further was removed",
            self.relative.display()
        );
        Ok(())
    }

    fn remove(&self) -> Result<()> {
        self.unchanged()?;
        let path = self.path()?;
        if self.metadata.is_dir() {
            std::fs::remove_dir_all(path)?;
        } else {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }
}

/// Prune inputs from the current plan (`vk dev prune`) or recorded `dev.json`
/// (`vk dev prune NAME`, host-wide without a config).
struct Env {
    state_dir: PathBuf,
    /// only labels the preview
    environment: String,
    /// the declared durable and managed backings, absolute. `None` means they were not
    /// recorded — a `dev.json` older than the field, or a state directory with none — and
    /// prune then removes only its fixed-name storage and says the rest could not be found.
    backings: Option<Vec<PathBuf>>,
}

struct Selection {
    targets: Vec<Target>,
    external: Vec<PathBuf>,
    /// storage was asked for but the declared backings were not recorded, so a loose disk
    /// backing sitting in the state directory could not be told from an unrelated file and
    /// was left alone
    warn_incomplete: bool,
    // Keep the root and service directory locks through preview, confirmation and removal.
    _locks: Vec<File>,
}

fn fd_path(dir: &File) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()))
}

fn open_dir(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn lock(dir: &File) -> Result<()> {
    // SAFETY: the descriptor is owned by `dir` and remains open for the lock's lifetime.
    if unsafe { libc::flock(dir.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("environment is in use; `vk dev stop` first, or wait for its boot to finish");
    }
    Ok(())
}

fn select_target(root: &File, relative: &Path, category: &'static str) -> Result<Option<Target>> {
    ensure!(
        !relative.as_os_str().is_empty()
            && relative
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
        "invalid prune path {}",
        relative.display()
    );
    let mut parent = root.try_clone()?;
    if let Some(ancestors) = relative.parent() {
        for name in ancestors.components() {
            parent = match open_dir(&fd_path(&parent).join(name)) {
                Ok(dir) => dir,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(e) => {
                    return Err(e).context("prune path contains a symlink or unreadable directory");
                }
            };
        }
    }
    let name = relative.file_name().context("empty prune target")?;
    let metadata = match std::fs::symlink_metadata(fd_path(&parent).join(name)) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    ensure!(
        metadata.is_file() || (category == "storage" && metadata.is_dir()),
        "{} is a symlink or an unexpected file type; left alone",
        relative.display()
    );
    Ok(Some(Target {
        parent,
        relative: relative.to_path_buf(),
        metadata,
        category,
    }))
}

fn select(env: &Env, opts: &Options) -> Result<Selection> {
    let root = match open_dir(&env.state_dir) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Selection {
                targets: Vec::new(),
                external: Vec::new(),
                warn_incomplete: false,
                _locks: Vec::new(),
            });
        }
        Err(e) => return Err(e).context("opening environment state for pruning"),
    };
    // Read liveness before taking our own lock, which would make a stale registry
    // entry appear to have a running owner. The locks below still exclude starts.
    let running = crate::vms::running();
    lock(&root)?;
    let canonical = std::fs::canonicalize(fd_path(&root))?;
    ensure!(
        !running
            .iter()
            .any(|vm| { crate::vms::canonical(&vm.state_dir).starts_with(&canonical) }),
        "environment or one of its services is running; `vk dev stop` first"
    );

    let mut storage: Vec<PathBuf> = STORAGE_DIRS.iter().map(PathBuf::from).collect();
    let mut external = Vec::new();
    for backing in env.backings.iter().flatten() {
        // Do not canonicalize a backing through symlinks: even a link to somewhere
        // inside state is not a path this operation owns. Traversal below refuses it.
        match backing
            .strip_prefix(&env.state_dir)
            .or_else(|_| backing.strip_prefix(&canonical))
        {
            Ok(relative) => {
                let first = relative
                    .components()
                    .next()
                    .context("storage names the state directory")?;
                let first = first.as_os_str();
                ensure!(
                    !super::plan::RESERVED_STATE_ENTRIES
                        .iter()
                        .any(|n| first == OsStr::new(n))
                        || STORAGE_DIRS.iter().any(|n| first == OsStr::new(n)),
                    "storage {} overlaps environment identity or control data; left alone",
                    backing.display()
                );
                storage.push(relative.to_path_buf());
            }
            Err(_) => external.push(backing.clone()),
        }
    }
    // Without recorded backings, a loose disk is indistinguishable from an unrelated file.
    // It may collide with fixed storage or a boot-media name at the state root. Every prune
    // selects storage or images, so warn in the preview before removal, even without --storage.
    let warn_incomplete = env.backings.is_none();
    let mut candidates = BTreeMap::new();
    if opts.storage() {
        for path in &storage {
            candidates.insert(path.clone(), "storage");
        }
    }
    let mut locks = Vec::new();
    let mut media: Vec<PathBuf> = MEDIA.iter().map(PathBuf::from).collect();
    for entry in std::fs::read_dir(fd_path(&root))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(service) = name.as_bytes().strip_prefix(b"svc-") else {
            continue;
        };
        // A managed mount or declared disk may use this prefix too.
        if storage.iter().any(|s| Path::new(&name).starts_with(s)) {
            continue;
        }
        let dir = open_dir(&fd_path(&root).join(&name))
            .with_context(|| format!("opening service directory {}", name.display()))?;
        lock(&dir)?;
        for file in MEDIA {
            media.push(PathBuf::from(&name).join(file));
        }
        let mut overlay = service.to_vec();
        overlay.extend_from_slice(b"-overlay.qcow2");
        media.push(PathBuf::from(&name).join(OsStr::from_bytes(&overlay)));
        locks.push(dir);
    }
    if opts.images() {
        for path in media {
            // A declared durable backing may happen to use a boot-media filename.
            if !storage
                .iter()
                .any(|s| path.starts_with(s) || s.starts_with(&path))
            {
                candidates.insert(path, "images");
            }
        }
    }
    let mut targets: Vec<Target> = Vec::new();
    for (path, category) in candidates {
        if targets.iter().any(|t| path.starts_with(&t.relative)) {
            continue;
        }
        if let Some(target) = select_target(&root, &path, category)
            .with_context(|| format!("selecting {}", env.state_dir.join(&path).display()))?
        {
            targets.push(target);
        }
    }
    // Recreating the same image does not change its generation digest. Invalidate
    // create explicitly, before any data is removed, including on partial failure.
    if !targets.is_empty()
        && let Some(stamp) = select_target(&root, Path::new("lifecycle/create"), "hook stamp")?
    {
        targets.insert(0, stamp);
    }
    locks.push(root);
    external.sort();
    external.dedup();
    Ok(Selection {
        targets,
        external,
        warn_incomplete,
        _locks: locks,
    })
}

impl Selection {
    fn preview(&self, env: &Env) -> String {
        let mut out = format!(
            "environment {} ({})\n",
            env.environment,
            env.state_dir.display()
        );
        for target in &self.targets {
            out.push_str(&format!(
                "  remove [{}] {}\n",
                target.category,
                env.state_dir.join(&target.relative).display()
            ));
        }
        for path in &self.external {
            out.push_str(&format!("  keep [external storage] {}\n", path.display()));
        }
        if self.targets.iter().any(|t| t.category == "storage") {
            out.push_str("selected persistent storage contents will be lost\n");
        }
        if self.warn_incomplete {
            out.push_str(
                "note: this environment's declared storage was not recorded (booted by an \
                 older vk); any disk backing left loose in the state directory cannot be \
                 identified — prune from its workspace, or boot it once to record it\n",
            );
        }
        out.push_str("shared image/build caches, environment identity and SSH keys are kept\n");
        out
    }

    fn remove(&self, env: &Env) -> Result<String> {
        // Validate the whole selection before deleting the first item.
        for target in &self.targets {
            target.unchanged()?;
        }
        let mut report = String::new();
        for target in &self.targets {
            target.remove().with_context(|| {
                format!(
                    "{report}could not finish removing {}; pruning may be partial",
                    env.state_dir.join(&target.relative).display()
                )
            })?;
            report.push_str(&format!(
                "removed {}\n",
                env.state_dir.join(&target.relative).display()
            ));
        }
        Ok(report)
    }
}

/// Inputs for workspace-local `vk dev prune`, with a fresh inventory of declared backings.
fn env_of_plan(plan: &Plan) -> Result<Env> {
    let backings = super::storage::inventory(plan, false)?
        .into_iter()
        .map(|i| i.backing)
        .collect();
    Ok(Env {
        state_dir: plan.state_dir.clone(),
        environment: plan.environment.clone(),
        backings: Some(backings),
    })
}

/// Read the boot's declared backings and label from `dev.json` for `vk dev prune NAME`,
/// without resolving a config. Missing or unreadable `dev.json` (an ephemeral run or
/// older vk state) leaves no recorded backings; prune falls back to fixed-name storage.
fn env_of_state(dir: &Path) -> Env {
    let identity = std::fs::read(dir.join("dev.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<super::Identity>(&b).ok());
    let environment = identity
        .as_ref()
        .and_then(|i| i.manifest.get("environment").and_then(|v| v.as_str()))
        .map(str::to_string)
        .unwrap_or_else(|| dir.file_name().unwrap_or_default().to_string_lossy().into());
    Env {
        state_dir: dir.to_path_buf(),
        environment,
        backings: identity.and_then(|i| i.storage_backings),
    }
}

pub(super) fn run(plan: &Plan, opts: &Options) -> Result<String> {
    run_env(&env_of_plan(plan)?, opts, default_confirm)
}

/// `vk dev prune NAME`: prune host-wide without a config, using the state-directory
/// name shared by `vk dev list` and `vk dev gc`.
pub(super) fn run_by_name(name: &str, opts: &Options) -> Result<String> {
    // Resolve against the same host-wide listing `vk dev list` shows, so an unknown name
    // fails here the way it does there.
    let Some(row) = super::list::state(false)?
        .into_iter()
        .find(|r| r.name == name)
    else {
        bail!("no dev environment state named {name} (`vk dev list` names them)");
    };
    run_env(&env_of_state(&row.dir), opts, default_confirm)
}

fn default_confirm() -> Result<bool> {
    ensure!(
        super::on_terminal(),
        "nothing was removed: use --yes to confirm, or --dry-run to preview"
    );
    super::ask_on_terminal("remove the selected data?")
}

fn run_env(env: &Env, opts: &Options, confirm: impl FnOnce() -> Result<bool>) -> Result<String> {
    let selected = select(env, opts)?;
    let preview = selected.preview(env);
    if selected.targets.is_empty() {
        return Ok(format!("{preview}nothing to remove\n"));
    }
    if opts.dry_run {
        return Ok(format!("{preview}dry run: nothing was removed\n"));
    }
    eprint!("{preview}");
    if !opts.yes && !confirm()? {
        bail!("nothing was removed");
    }
    selected.remove(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture {
        _env: std::sync::MutexGuard<'static, ()>,
        dir: PathBuf,
        plan: Plan,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            // Test scratch only; failure to clean it must not hide an assertion failure.
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn env(plan: &Plan) -> Env {
        env_of_plan(plan).unwrap()
    }

    fn fixture(name: &str) -> Fixture {
        let guard = super::super::testutil::env_guard();
        let dir = std::env::temp_dir().join(format!("vk-prune-{}-{name}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let mut plan = super::super::testutil::plan_in(&dir);
        std::fs::create_dir_all(&plan.workspace).unwrap();
        std::fs::write(plan.workspace.join("compose.yaml"), "services:\n  devcontainer:\n    image: test\n    x-virtkit:\n      persist_root: true\n    volumes:\n      - ${VK_STATE_DIR}/data.qcow2:/data:disk\n      - ${VK_WORKSPACE}/external.qcow2:/external:disk\n").unwrap();
        plan.managed_dirs = vec![
            plan.state_dir.join("cache"),
            plan.state_dir.join("cache/nested"),
        ];
        for name in [
            "root.qcow2",
            "root.qcow2.json",
            "overlay.qcow2",
            "initramfs.cpio",
            "svc-db/db-overlay.qcow2",
            "svc-db/initramfs.cpio",
            "svc-db/console.log",
            "roots/devcontainer.qcow2",
            "roots/devcontainer.qcow2.baseid",
            "roots/old-service.qcow2",
            "overlays/old-service/upper.qcow2",
            "editor/vscode-server/data",
            "cache/nested/data",
            "cache/.vk-generation",
            "data.qcow2",
            "id_ed25519",
            "dev.json",
            "endpoints.json",
            "lifecycle/create",
            "lifecycle/other",
            "console.log",
            "unrelated/data",
        ] {
            let path = plan.state_dir.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"keep or remove").unwrap();
        }
        std::fs::write(plan.workspace.join("external.qcow2"), b"external").unwrap();
        Fixture {
            _env: guard,
            dir,
            plan,
        }
    }

    #[test]
    fn default_removes_only_boot_media_and_rearms_the_create_hook() {
        let f = fixture("default");
        let opts = Options {
            yes: true,
            ..Default::default()
        };
        let report = run(&f.plan, &opts).unwrap();
        assert!(report.contains("root.qcow2"));
        for name in [
            "root.qcow2",
            "root.qcow2.json",
            "svc-db/db-overlay.qcow2",
            "lifecycle/create",
        ] {
            assert!(!f.plan.state_dir.join(name).exists(), "{name}");
        }
        for name in [
            "roots/devcontainer.qcow2",
            "overlays/old-service/upper.qcow2",
            "cache/nested/data",
            "editor/vscode-server/data",
            "data.qcow2",
            "id_ed25519",
            "dev.json",
            "endpoints.json",
            "svc-db/console.log",
            "lifecycle/other",
            "unrelated/data",
        ] {
            assert!(f.plan.state_dir.join(name).exists(), "{name}");
        }
        assert!(run(&f.plan, &opts).unwrap().contains("nothing to remove"));
    }

    #[test]
    fn storage_removes_backings_and_sidecars_but_keeps_images_and_external_data() {
        let f = fixture("storage");
        let e = env(&f.plan);
        let selected = select(
            &e,
            &Options {
                storage: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(selected.preview(&e).contains("keep [external storage]"));
        selected.remove(&e).unwrap();
        for name in [
            "roots",
            "overlays",
            "editor",
            "cache",
            "data.qcow2",
            "lifecycle/create",
        ] {
            assert!(!f.plan.state_dir.join(name).exists(), "{name}");
        }
        assert!(f.plan.state_dir.join("root.qcow2").exists());
        assert!(f.plan.workspace.join("external.qcow2").exists());
        assert!(f.plan.state_dir.join("dev.json").exists());
        drop(selected);
        super::super::boot::ensure_state_dir(&f.plan).unwrap();
        assert_ne!(
            std::fs::read(f.plan.state_dir.join("cache/.vk-generation")).unwrap(),
            b"keep or remove"
        );
        assert!(!f.plan.state_dir.join("lifecycle/create").exists());
    }

    #[test]
    fn storage_under_a_symlinked_state_base_is_still_local() {
        let mut f = fixture("state-alias");
        let alias = f.dir.join("alias");
        symlink(&f.dir, &alias).unwrap();
        f.plan.state_dir = alias.join("state");
        let e = env(&f.plan);
        let selected = select(
            &e,
            &Options {
                storage: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(selected.external, [f.plan.workspace.join("external.qcow2")]);
        selected.remove(&e).unwrap();
        assert!(!f.plan.state_dir.join("data.qcow2").exists());
        assert!(!f.plan.state_dir.join("cache").exists());
        assert!(f.plan.state_dir.join("dev.json").exists());
        assert!(f.plan.workspace.join("external.qcow2").exists());
    }

    #[test]
    fn all_combines_selections_but_never_selects_the_state_directory() {
        let f = fixture("all");
        run(
            &f.plan,
            &Options {
                all: true,
                yes: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(!f.plan.state_dir.join("root.qcow2").exists());
        assert!(!f.plan.state_dir.join("roots").exists());
        assert!(f.plan.state_dir.join("id_ed25519").exists());
        assert!(f.plan.workspace.join("external.qcow2").exists());
    }

    #[test]
    fn recorded_backings_let_a_loose_disk_be_pruned_by_name() {
        // What `env_of_state` reconstructs for a NAME: the state directory and the backings a
        // boot recorded in `dev.json` — no config, no compose file re-read.
        let f = fixture("byname");
        let recorded = Env {
            state_dir: f.plan.state_dir.clone(),
            environment: "dev".into(),
            backings: Some(vec![
                f.plan.state_dir.join("data.qcow2"),
                f.plan.workspace.join("external.qcow2"),
            ]),
        };
        run_env(
            &recorded,
            &Options {
                all: true,
                yes: true,
                ..Default::default()
            },
            || panic!("--yes must not ask"),
        )
        .unwrap();
        assert!(!f.plan.state_dir.join("data.qcow2").exists()); // the recorded loose disk
        assert!(!f.plan.state_dir.join("root.qcow2").exists()); // images
        assert!(!f.plan.state_dir.join("roots").exists()); // fixed storage
        assert!(f.plan.workspace.join("external.qcow2").exists()); // external, kept
        assert!(f.plan.state_dir.join("id_ed25519").exists()); // identity, kept
    }

    #[test]
    fn unrecorded_backings_keep_a_loose_disk_and_warn() {
        // A `dev.json` older than the recorded field: prune still clears images and its
        // fixed-name storage, but cannot identify the loose disk, and says so.
        let f = fixture("legacy");
        let legacy = Env {
            state_dir: f.plan.state_dir.clone(),
            environment: "dev".into(),
            backings: None,
        };
        let report = run_env(
            &legacy,
            &Options {
                all: true,
                dry_run: true,
                ..Default::default()
            },
            || panic!("dry run must not ask"),
        )
        .unwrap();
        assert!(report.contains("declared storage was not recorded"));
        run_env(
            &legacy,
            &Options {
                all: true,
                yes: true,
                ..Default::default()
            },
            || panic!("--yes must not ask"),
        )
        .unwrap();
        assert!(f.plan.state_dir.join("data.qcow2").exists()); // loose disk unidentified, kept
        assert!(!f.plan.state_dir.join("root.qcow2").exists()); // images gone
        assert!(!f.plan.state_dir.join("roots").exists()); // fixed storage gone
    }

    #[test]
    fn dry_run_overrides_yes_and_refusal_preserves_everything() {
        let f = fixture("consent");
        let opts = Options {
            all: true,
            yes: true,
            dry_run: true,
            ..Default::default()
        };
        let e = env(&f.plan);
        let report = run_env(&e, &opts, || panic!("dry run must not ask")).unwrap();
        assert!(report.contains("dry run: nothing was removed"));
        assert!(report.contains("persistent storage contents will be lost"));
        assert!(run_env(&e, &Options::default(), || Ok(false)).is_err());
        assert!(run_env(&e, &Options::default(), || bail!("no terminal")).is_err());
        for name in ["root.qcow2", "data.qcow2", "lifecycle/create", "dev.json"] {
            assert!(f.plan.state_dir.join(name).exists(), "{name}");
        }
        run_env(&e, &Options::default(), || Ok(true)).unwrap();
        assert!(!f.plan.state_dir.join("root.qcow2").exists());
    }

    #[test]
    fn declared_storage_overrides_a_boot_media_filename() {
        let f = fixture("overlap");
        let compose = f.plan.workspace.join("compose.yaml");
        let content = std::fs::read_to_string(&compose)
            .unwrap()
            .replace("data.qcow2", "root.qcow2");
        std::fs::write(compose, content).unwrap();
        run(
            &f.plan,
            &Options {
                yes: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(f.plan.state_dir.join("root.qcow2").exists());
    }

    #[test]
    fn options_default_to_images_and_allow_an_explicit_union() {
        use clap::Parser;
        #[derive(Parser)]
        struct Harness {
            #[command(flatten)]
            options: Options,
        }
        for (args, images, storage) in [
            (vec!["prune"], true, false),
            (vec!["prune", "--images"], true, false),
            (vec!["prune", "--storage"], false, true),
            (vec!["prune", "--images", "--storage"], true, true),
            (vec!["prune", "--all"], true, true),
        ] {
            let opts = Harness::parse_from(args).options;
            assert_eq!((opts.images(), opts.storage()), (images, storage));
        }
        assert!(Harness::try_parse_from(["prune", "--all", "--storage"]).is_err());
    }

    #[test]
    fn storage_cannot_select_identity_or_escape_above_state() {
        let mut f = fixture("protected");
        for relative in ["", "id_ed25519", "lifecycle", "../repo"] {
            f.plan.managed_dirs = vec![f.plan.state_dir.join(relative)];
            assert!(
                run(
                    &f.plan,
                    &Options {
                        all: true,
                        yes: true,
                        ..Default::default()
                    }
                )
                .is_err(),
                "{relative}"
            );
            assert!(f.plan.state_dir.join("root.qcow2").exists());
            assert!(f.plan.state_dir.join("id_ed25519").exists());
        }
    }

    #[test]
    fn held_environment_and_service_locks_refuse_removal() {
        let f = fixture("locks");
        for dir in [&f.plan.state_dir, &f.plan.state_dir.join("svc-db")] {
            let held = open_dir(dir).unwrap();
            lock(&held).unwrap();
            assert!(
                run(
                    &f.plan,
                    &Options {
                        yes: true,
                        storage: true,
                        ..Default::default()
                    }
                )
                .is_err()
            );
            assert!(f.plan.state_dir.join("root.qcow2").exists());
        }
    }

    #[test]
    fn symlinked_selected_paths_are_refused_but_links_inside_storage_are_not_followed() {
        let mut f = fixture("symlinks");
        let link = f.plan.state_dir.join("root.qcow2");
        std::fs::remove_file(&link).unwrap();
        symlink(f.plan.workspace.join("external.qcow2"), &link).unwrap();
        assert!(
            run(
                &f.plan,
                &Options {
                    yes: true,
                    ..Default::default()
                }
            )
            .is_err()
        );
        std::fs::remove_file(link).unwrap();
        symlink(&f.plan.workspace, f.plan.state_dir.join("escape")).unwrap();
        f.plan
            .managed_dirs
            .push(f.plan.state_dir.join("escape/subdir"));
        assert!(
            run(
                &f.plan,
                &Options {
                    storage: true,
                    yes: true,
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert!(f.plan.state_dir.join("data.qcow2").exists());
        f.plan.managed_dirs.pop();
        symlink(&f.plan.workspace, f.plan.state_dir.join("cache/link")).unwrap();
        run(
            &f.plan,
            &Options {
                storage: true,
                yes: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(f.plan.workspace.join("external.qcow2").exists());
    }

    #[test]
    fn changed_selection_fails_before_removing_anything() {
        let f = fixture("changed");
        let e = env(&f.plan);
        let selected = select(&e, &Options::default()).unwrap();
        let path = f.plan.state_dir.join("root.qcow2");
        std::fs::rename(&path, path.with_extension("old")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert!(selected.remove(&e).is_err());
        assert!(f.plan.state_dir.join("lifecycle/create").exists());
        assert!(f.plan.state_dir.join("initramfs.cpio").exists());
    }

    #[test]
    fn stale_registry_entries_do_not_make_pruning_look_like_a_live_vm() {
        const CHILD: &str = "VK_TEST_PRUNE_STALE_REGISTRY";
        if std::env::var_os(CHILD).is_some() {
            let f = fixture("stale-registry");
            let mut registrations = Vec::new();
            for state_dir in [&f.plan.state_dir, &f.plan.state_dir.join("svc-db")] {
                let entry = serde_json::from_value(serde_json::json!({
                    "state_dir": state_dir,
                    "pid": std::process::id(),
                    "label": "stale",
                    "exec_addr": "unused",
                    "created_secs": 0
                }))
                .unwrap();
                registrations.push(crate::vms::register(entry));
            }
            assert_eq!(
                std::fs::read_dir(crate::vms::registry_dir().unwrap())
                    .unwrap()
                    .count(),
                2
            );
            run(
                &f.plan,
                &Options {
                    yes: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(!f.plan.state_dir.join("root.qcow2").exists());
            assert!(!f.plan.state_dir.join("svc-db/db-overlay.qcow2").exists());
            return;
        }
        let _guard = super::super::testutil::env_guard();
        let tmp = super::super::testutil::scratch("prune-registry");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dev::prune::tests::stale_registry_entries_do_not_make_pruning_look_like_a_live_vm",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("XDG_DATA_HOME", &tmp.0)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }

    #[test]
    fn missing_state_is_a_read_only_noop() {
        let f = fixture("missing");
        std::fs::remove_dir_all(&f.plan.state_dir).unwrap();
        assert!(
            run(&f.plan, &Options::default())
                .unwrap()
                .contains("nothing to remove")
        );
        assert!(!f.plan.state_dir.exists());
    }

    #[test]
    fn unrecorded_backings_warn_even_on_a_default_images_prune() {
        // The images pass alone can remove a loose disk whose name collides with boot media in
        // the state root. With no recorded backings to tell them apart, the preview must warn
        // even though --storage was not asked for.
        let f = fixture("legacy-images");
        let legacy = Env {
            state_dir: f.plan.state_dir.clone(),
            environment: "dev".into(),
            backings: None,
        };
        let report = run_env(
            &legacy,
            &Options {
                dry_run: true,
                ..Default::default()
            },
            || panic!("dry run must not ask"),
        )
        .unwrap();
        assert!(report.contains("declared storage was not recorded"));
    }

    #[test]
    fn env_of_state_reads_the_recorded_label_and_backings() {
        let f = fixture("env-of-state");
        let identity = super::super::Identity {
            digest: "d".into(),
            booted_secs: 0,
            created_by: String::new(),
            generation: String::new(),
            manifest: serde_json::json!({ "environment": "web" }),
            storage_backings: Some(vec![f.plan.state_dir.join("data.qcow2")]),
        };
        std::fs::write(
            f.plan.state_dir.join("dev.json"),
            serde_json::to_vec(&identity).unwrap(),
        )
        .unwrap();
        let e = env_of_state(&f.plan.state_dir);
        assert_eq!(e.state_dir, f.plan.state_dir);
        assert_eq!(e.environment, "web"); // the manifest's label, not the state-dir name
        assert_eq!(e.backings, Some(vec![f.plan.state_dir.join("data.qcow2")]));
    }

    #[test]
    fn env_of_state_falls_back_without_a_recorded_environment_or_backings() {
        let f = fixture("env-of-state-legacy");
        // A dev.json an older vk wrote: no environment in the manifest, no storage_backings.
        let identity = super::super::Identity {
            digest: "d".into(),
            booted_secs: 0,
            created_by: String::new(),
            generation: String::new(),
            manifest: serde_json::json!({}),
            storage_backings: None,
        };
        std::fs::write(
            f.plan.state_dir.join("dev.json"),
            serde_json::to_vec(&identity).unwrap(),
        )
        .unwrap();
        let e = env_of_state(&f.plan.state_dir);
        assert_eq!(e.backings, None);
        assert_eq!(
            e.environment,
            f.plan.state_dir.file_name().unwrap().to_string_lossy()
        );
        // A directory with no dev.json at all records nothing either.
        std::fs::remove_file(f.plan.state_dir.join("dev.json")).unwrap();
        assert_eq!(env_of_state(&f.plan.state_dir).backings, None);
    }

    #[test]
    fn prune_by_name_resolves_host_wide_state_and_reports_an_unknown_name() {
        const CHILD: &str = "VK_TEST_PRUNE_BY_NAME";
        if std::env::var_os(CHILD).is_some() {
            let dir = super::super::plan::dev_state_base()
                .unwrap()
                .join("proj-1a2b");
            std::fs::create_dir_all(dir.join("roots")).unwrap();
            for (name, body) in [
                ("root.qcow2", "image"),
                ("roots/devcontainer.qcow2", "fixed storage"),
                ("data.qcow2", "recorded loose disk"),
                ("id_ed25519", "identity"),
            ] {
                std::fs::write(dir.join(name), body).unwrap();
            }
            let identity = super::super::Identity {
                digest: "d".into(),
                booted_secs: 0,
                created_by: String::new(),
                generation: String::new(),
                manifest: serde_json::json!({ "environment": "dev" }),
                storage_backings: Some(vec![dir.join("data.qcow2")]),
            };
            std::fs::write(dir.join("dev.json"), serde_json::to_vec(&identity).unwrap()).unwrap();
            run_by_name(
                "proj-1a2b",
                &Options {
                    all: true,
                    yes: true,
                    ..Default::default()
                },
            )
            .unwrap();
            assert!(!dir.join("data.qcow2").exists()); // the recorded loose disk
            assert!(!dir.join("root.qcow2").exists()); // images
            assert!(!dir.join("roots").exists()); // fixed storage
            assert!(dir.join("id_ed25519").exists()); // identity, kept
            let err = run_by_name("absent", &Options::default())
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("no dev environment state named absent"),
                "{err}"
            );
            return;
        }
        let _guard = super::super::testutil::env_guard();
        let tmp = super::super::testutil::scratch("prune-by-name");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "dev::prune::tests::prune_by_name_resolves_host_wide_state_and_reports_an_unknown_name",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("XDG_STATE_HOME", &tmp.0)
            .env("XDG_DATA_HOME", tmp.0.join("data"))
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}
