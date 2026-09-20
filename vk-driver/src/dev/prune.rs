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

struct Selection {
    targets: Vec<Target>,
    external: Vec<PathBuf>,
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

fn select(plan: &Plan, opts: &Options) -> Result<Selection> {
    let root = match open_dir(&plan.state_dir) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Selection {
                targets: Vec::new(),
                external: Vec::new(),
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
    for item in super::storage::inventory(plan, false)? {
        // Do not canonicalize a backing through symlinks: even a link to somewhere
        // inside state is not a path this operation owns. Traversal below refuses it.
        match item
            .backing
            .strip_prefix(&plan.state_dir)
            .or_else(|_| item.backing.strip_prefix(&canonical))
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
                    item.backing.display()
                );
                storage.push(relative.to_path_buf());
            }
            Err(_) => external.push(item.backing),
        }
    }
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
            .with_context(|| format!("selecting {}", plan.state_dir.join(&path).display()))?
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
        _locks: locks,
    })
}

impl Selection {
    fn preview(&self, plan: &Plan) -> String {
        let mut out = format!(
            "environment {} ({})\n",
            plan.environment,
            plan.state_dir.display()
        );
        for target in &self.targets {
            out.push_str(&format!(
                "  remove [{}] {}\n",
                target.category,
                plan.state_dir.join(&target.relative).display()
            ));
        }
        for path in &self.external {
            out.push_str(&format!("  keep [external storage] {}\n", path.display()));
        }
        if self.targets.iter().any(|t| t.category == "storage") {
            out.push_str("selected persistent storage contents will be lost\n");
        }
        out.push_str("shared image/build caches, environment identity and SSH keys are kept\n");
        out
    }

    fn remove(&self, plan: &Plan) -> Result<String> {
        // Validate the whole selection before deleting the first item.
        for target in &self.targets {
            target.unchanged()?;
        }
        let mut report = String::new();
        for target in &self.targets {
            target.remove().with_context(|| {
                format!(
                    "{report}could not finish removing {}; pruning may be partial",
                    plan.state_dir.join(&target.relative).display()
                )
            })?;
            report.push_str(&format!(
                "removed {}\n",
                plan.state_dir.join(&target.relative).display()
            ));
        }
        Ok(report)
    }
}

pub(super) fn run(plan: &Plan, opts: &Options) -> Result<String> {
    run_with_confirmation(plan, opts, || {
        ensure!(
            super::on_terminal(),
            "nothing was removed: use --yes to confirm, or --dry-run to preview"
        );
        super::ask_on_terminal("remove the selected data?")
    })
}

fn run_with_confirmation(
    plan: &Plan,
    opts: &Options,
    confirm: impl FnOnce() -> Result<bool>,
) -> Result<String> {
    let selected = select(plan, opts)?;
    let preview = selected.preview(plan);
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
    selected.remove(plan)
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
        let selected = select(
            &f.plan,
            &Options {
                storage: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            selected
                .preview(&f.plan)
                .contains("keep [external storage]")
        );
        selected.remove(&f.plan).unwrap();
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
        let selected = select(
            &f.plan,
            &Options {
                storage: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(selected.external, [f.plan.workspace.join("external.qcow2")]);
        selected.remove(&f.plan).unwrap();
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
    fn dry_run_overrides_yes_and_refusal_preserves_everything() {
        let f = fixture("consent");
        let opts = Options {
            all: true,
            yes: true,
            dry_run: true,
            ..Default::default()
        };
        let report =
            run_with_confirmation(&f.plan, &opts, || panic!("dry run must not ask")).unwrap();
        assert!(report.contains("dry run: nothing was removed"));
        assert!(report.contains("persistent storage contents will be lost"));
        assert!(run_with_confirmation(&f.plan, &Options::default(), || Ok(false)).is_err());
        assert!(
            run_with_confirmation(&f.plan, &Options::default(), || bail!("no terminal")).is_err()
        );
        for name in ["root.qcow2", "data.qcow2", "lifecycle/create", "dev.json"] {
            assert!(f.plan.state_dir.join(name).exists(), "{name}");
        }
        run_with_confirmation(&f.plan, &Options::default(), || Ok(true)).unwrap();
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
        let selected = select(&f.plan, &Options::default()).unwrap();
        let path = f.plan.state_dir.join("root.qcow2");
        std::fs::rename(&path, path.with_extension("old")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert!(selected.remove(&f.plan).is_err());
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
}
