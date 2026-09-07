//! The storage a dev environment's declarations amount to, and the one operation that
//! destroys any of it.
//!
//! Nothing is declared twice: data is named where the guest gets it — a compose `disk`
//! volume, an `x-virtkit.persist_root` root, a `${state}` mount, the editor's server
//! storage — and the inventory is derived from the same plan the boot reads, with the same
//! builtins, so a path here is the path the boot resolves.
//!
//! What separates the items is how long they are meant to live. A `disk` volume is the
//! service's own data and survives every refresh; a `persist_root` root and an
//! `overlay,persist` upper are bound to the image generation and are recreated under the
//! service whenever its image changes. [`reset`] therefore refuses the generation-bound ones
//! (refresh owns them) and the editor's (its adapter does), and removes nothing while the
//! owner is running: it offers to stop it, and declining keeps both. It holds the state
//! directory's lock — the one a boot takes — from the moment it asks what is running until
//! the backing is gone, so a `vk dev up` cannot start on top of what is being removed.
//!
//! Measuring a backing walks it, and a persist root is measured in gigabytes, so [`inventory`]
//! does it only when asked: `reset` and [`preview`] need names and categories, not sizes.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Serialize;

use crate::dev::plan::{Plan, Source};

/// How long an item is meant to live — the distinction the storage contract turns on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    /// application data: kept by stop, refresh and teardown alike
    Durable,
    /// recreated with the environment's image generation
    GenerationBound,
    /// the editor server's storage, reconciled by the editor adapter
    Editor,
}

impl Category {
    fn label(self) -> &'static str {
        match self {
            Category::Durable => "durable",
            Category::GenerationBound => "generation-bound",
            Category::Editor => "editor",
        }
    }
}

/// One piece of storage the environment declares.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Item {
    /// stable, and what [`reset`] takes: `<service>:<guest>`, `${state}/<name>`, `editor`
    pub name: String,
    /// the compose service the item belongs to; `None` is the environment's own
    pub owner: Option<String>,
    pub category: Category,
    /// `disk`, `persist-root`, `overlay-upper`, `managed-dir` or `editor`
    pub kind: &'static str,
    pub backing: PathBuf,
    /// where the guest sees it, when the declaration says
    pub guest: Option<String>,
    pub exists: bool,
    /// a file's apparent size, a directory's contents added up; `None` before it exists,
    /// and absent altogether when the caller did not ask for sizes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

/// Which owners are up. An item is only ever removed with its own owner stopped, and the
/// environment is the owner of everything that is not a service's.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Running {
    pub environment: bool,
    pub services: Vec<String>,
}

impl Running {
    /// Whether `owner` (the environment for `None`) is running.
    pub fn owns(&self, owner: Option<&str>) -> bool {
        match owner {
            None => self.environment,
            Some(name) => self.services.iter().any(|s| s == name),
        }
    }
}

/// What is up right now: the environment, and the services its manager reports as running.
/// An environment that is down owns nothing, which is what makes a reset work with no VM.
///
/// A control plane that does not answer is an error and not an empty list: reading it as
/// "nothing is running" is what would let a reset take a live service's disk out from under
/// it.
pub fn running(plan: &Plan) -> Result<Running> {
    let Some(entry) = crate::dev::running_vm(plan) else {
        return Ok(Running::default());
    };
    // No control socket: this environment is a single VM with no service manager, so it owns
    // everything itself and there is nothing to ask.
    let Some(ctl) = crate::vms::control_socket(&entry) else {
        return Ok(Running {
            environment: true,
            services: Vec::new(),
        });
    };
    let reply = crate::vms::control(
        &ctl,
        &vk_core::fleetctl::Request::List,
        Some(std::time::Duration::from_secs(10)),
        |_| {},
    )
    .context("asking the environment which services are running")?;
    Ok(Running {
        environment: true,
        services: reply
            .units
            .into_iter()
            .filter(|u| u.state == "running")
            .map(|u| u.name)
            .collect(),
    })
}

/// Every storage item the plan declares, in owner then name order. Reads only.
///
/// `sizes` measures each backing, which walks a whole persist root: ask for it where the
/// number is the point (`vk dev storage list --sizes`), not where names and categories are.
pub fn inventory(plan: &Plan, sizes: bool) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    if let Source::Compose { file, .. } = &plan.source {
        // The builtins a boot resolves the file with, so `${VK_WORKSPACE}/…` names the same
        // backing here as it does there.
        let builtins =
            crate::compose::Builtins::resolve(Some(&plan.workspace), Some(&plan.state_dir))?;
        for unit in crate::compose::load(file, Some(&builtins))? {
            for v in &unit.volumes {
                if v.disk {
                    items.push(item(
                        format!("{}:{}", unit.name, v.guest),
                        Some(unit.name.clone()),
                        Category::Durable,
                        "disk",
                        v.host.clone(),
                        Some(v.guest.clone()),
                        sizes,
                    ));
                } else if let Some(backing) = &v.persist_backing {
                    items.push(item(
                        format!("{}:{}:overlay", unit.name, v.guest),
                        Some(unit.name.clone()),
                        Category::GenerationBound,
                        "overlay-upper",
                        backing.clone(),
                        Some(v.guest.clone()),
                        sizes,
                    ));
                }
            }
            if let Some(backing) = &unit.persist_root_backing {
                items.push(item(
                    format!("{}:/", unit.name),
                    Some(unit.name.clone()),
                    Category::GenerationBound,
                    "persist-root",
                    backing.clone(),
                    Some("/".into()),
                    sizes,
                ));
            }
        }
    }
    // The mount sources under the state dir the boot creates. `editor/vscode-server` is the
    // one vk manages itself, for a source whose compose file cannot declare it; a project
    // that mounts its own `${state}/…` for the server keeps it a plain managed directory,
    // since nothing but the adapter's own storage is the adapter's to reconcile.
    let guests: BTreeMap<&PathBuf, String> = plan
        .mounts
        .iter()
        .map(|m| (&m.source, m.to.clone()))
        .collect();
    let editor = plan
        .vscode
        .as_ref()
        .filter(|v| v.persistent)
        .map(|_| plan.state_dir.join("editor/vscode-server"));
    for dir in &plan.managed_dirs {
        let guest = guests.get(dir).cloned();
        if Some(dir) == editor.as_ref() {
            items.push(item(
                "editor".into(),
                None,
                Category::Editor,
                "editor",
                dir.clone(),
                guest,
                sizes,
            ));
            continue;
        }
        let name = match dir.strip_prefix(&plan.state_dir) {
            Ok(rel) => format!("${{state}}/{}", rel.display()),
            Err(_) => dir.display().to_string(),
        };
        items.push(item(
            name,
            None,
            Category::Durable,
            "managed-dir",
            dir.clone(),
            guest,
            sizes,
        ));
    }
    items.sort_by(|a, b| (&a.owner, &a.name).cmp(&(&b.owner, &b.name)));
    Ok(items)
}

/// One item, with its backing measured as it stands when `sizes` asks for it.
#[allow(clippy::too_many_arguments)]
fn item(
    name: String,
    owner: Option<String>,
    category: Category,
    kind: &'static str,
    backing: PathBuf,
    guest: Option<String>,
    sizes: bool,
) -> Item {
    let (exists, size_bytes) = measure(&backing, sizes);
    Item {
        name,
        owner,
        category,
        kind,
        backing,
        guest,
        exists,
        size_bytes,
    }
}

/// Whether the backing is there, and how big it is: a file's apparent size (a sparse qcow2
/// reports what it holds, not what it was created as), a directory's contents added up.
fn measure(path: &Path, sizes: bool) -> (bool, Option<u64>) {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return (false, None);
    };
    if !sizes {
        return (true, None);
    }
    match meta.is_dir() {
        true => (true, Some(dir_size(path))),
        false => (true, Some(meta.len())),
    }
}

/// How deep [`dir_size`] descends. A backing is a few levels of cache or an extracted
/// server; deeper than this is a tree nobody meant to measure, and recursing to the bottom
/// of one is how a stack runs out.
const SIZE_MAX_DEPTH: u32 = 64;

/// A directory's contents added up, symlinks counted as themselves rather than followed.
/// Best-effort: what cannot be read counts as nothing, so a figure is a lower bound, and the
/// walk stops at [`SIZE_MAX_DEPTH`].
pub(crate) fn dir_size(path: &Path) -> u64 {
    dir_size_to(path, SIZE_MAX_DEPTH)
}

fn dir_size_to(path: &Path, depth: u32) -> u64 {
    let Some(depth) = depth.checked_sub(1) else {
        return 0;
    };
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_size_to(&e.path(), depth),
            _ => e.metadata().map(|m| m.len()).unwrap_or(0),
        })
        .sum()
}

/// `vk dev storage list` as text: one line per item.
pub fn render(items: &[Item], running: &Running) -> String {
    if items.is_empty() {
        return "no storage declared\n".into();
    }
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|i| {
            let state = match (i.exists, running.owns(i.owner.as_deref())) {
                (false, _) => "not created".to_string(),
                (true, false) => "created".to_string(),
                (true, true) => format!("created ({} running)", owner_of(i)),
            };
            vec![
                i.name.clone(),
                i.category.label().into(),
                i.kind.into(),
                i.backing.display().to_string(),
                crate::dev::list::fmt_size(i.size_bytes),
                state,
            ]
        })
        .collect();
    crate::dev::list::table(
        &["NAME", "CATEGORY", "KIND", "BACKING", "SIZE", "STATE"],
        &rows,
    )
}

/// How an item's owner is named in a message: the service, or the environment itself.
fn owner_of(item: &Item) -> String {
    match &item.owner {
        Some(service) => format!("service {service}"),
        None => "the environment".into(),
    }
}

/// `vk dev storage reset <name>`: remove one durable item's backing, with its owner stopped
/// first. Returns the one-line report; nothing is removed on any path that returns an error
/// or a refusal.
///
/// The state directory's lock is taken before anything is asked and held until the backing
/// is gone, so a `vk dev up` cannot start the owner back onto what is being removed. It is
/// already held while the environment's own VM is up, which is the case this stops it for:
/// the lock is taken after that stop, and what is running is asked again under it.
pub async fn reset(plan: &Plan, name: &str, yes: bool) -> Result<String> {
    let items = inventory(plan, false)?;
    let Some(item) = items.iter().find(|i| i.name == name) else {
        bail!(
            "no storage item {name:?} in this environment (declared: {})",
            match items.is_empty() {
                true => "none".into(),
                false => items
                    .iter()
                    .map(|i| i.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            }
        );
    };
    let backing = item.backing.display();
    match item.category {
        Category::GenerationBound => bail!(
            "{name} is recreated with the environment's image generation, so `vk dev refresh` \
             is what resets it — not this"
        ),
        Category::Editor => bail!(
            "{name} is the editor adapter's storage; it reconciles the server itself \
             (`vk dev editor retry`)"
        ),
        Category::Durable => {}
    }
    if !item.exists {
        return Ok(format!(
            "{name}: nothing to remove ({backing} is not there)"
        ));
    }
    let owner = owner_of(item);
    // Held from here to the removal. `None` is the environment's own VM holding it, or a
    // boot in flight — which `running` tells apart.
    let mut lock = crate::dev::list::try_lock_state_dir(&plan.state_dir);
    let up = running(plan)?;
    if lock.is_none() && !up.environment {
        bail!(
            "{} is being booted right now — try again when it is done",
            plan.environment
        );
    }
    if up.owns(item.owner.as_deref()) {
        if !yes {
            if !crate::dev::on_terminal() {
                bail!(
                    "{name} belongs to {owner}, which is running — stop it, or pass --yes to \
                     have this stop it and remove {backing}"
                );
            }
            if !crate::dev::ask_on_terminal(&format!("stop {owner} and remove {backing}?"))? {
                return Ok(format!("{name}: kept, and {owner} left running"));
            }
        }
        stop_owner(plan, item).await?;
        // Stopping the environment hands the lock back; take it before anything else can.
        if lock.is_none() {
            lock = crate::dev::list::try_lock_state_dir(&plan.state_dir);
        }
        if running(plan)?.owns(item.owner.as_deref()) {
            bail!("{owner} is running again, so {name} was left alone");
        }
    }
    remove_backing(&item.backing)?;
    drop(lock);
    Ok(format!(
        "{name}: removed {backing} — the next start recreates it empty"
    ))
}

/// Remove a backing: a directory whole, a regular file unlinked through its parent's
/// descriptor rather than by a path resolved again. Anything else — a symlink above all — is
/// left alone: unlinking one destroys the name and keeps the data, which is the opposite of
/// what the report would then say.
fn remove_backing(backing: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let shown = backing.display();
    let parent = backing
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = backing
        .file_name()
        .with_context(|| format!("{shown} names nothing to remove"))?;
    let dir =
        std::fs::File::open(parent).with_context(|| format!("opening {}", parent.display()))?;
    let cname = std::ffi::CString::new(name.as_bytes())
        .with_context(|| format!("{shown} is not a usable file name"))?;
    // SAFETY: `stat` is a plain C struct for which all-zero is a valid value, and `fstatat`
    // fills it in before anything below reads it.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir` owns the descriptor for the call, `cname` is a live NUL-terminated name,
    // and `st` is exclusively borrowed. `AT_SYMLINK_NOFOLLOW` describes the name itself.
    let rc = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            cname.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("reading {shown}"));
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFDIR => {
            std::fs::remove_dir_all(backing).with_context(|| format!("removing {shown}"))
        }
        libc::S_IFREG => {
            // SAFETY: as above; `0` (not `AT_REMOVEDIR`) unlinks the name just examined.
            match unsafe { libc::unlinkat(dir.as_raw_fd(), cname.as_ptr(), 0) } {
                0 => Ok(()),
                _ => Err(std::io::Error::last_os_error())
                    .with_context(|| format!("removing {shown}")),
            }
        }
        libc::S_IFLNK => bail!(
            "{shown} is a symlink: removing it would take the name and leave the data, so it \
             is left alone — remove what it points at, or the link, by hand"
        ),
        _ => bail!("{shown} is neither a regular file nor a directory, so it is left alone"),
    }
}

/// Stop what owns the item, so nothing has the backing open when it goes.
async fn stop_owner(plan: &Plan, item: &Item) -> Result<()> {
    let Some(service) = &item.owner else {
        let stopped = crate::dev::stop(plan, 10)?;
        print!("{}", stopped.report);
        if !stopped.all_down {
            bail!(
                "the environment did not stop, so {} was left alone",
                item.name
            );
        }
        return Ok(());
    };
    let reply = crate::dev::service(
        plan,
        &vk_core::fleetctl::Request::Stop {
            unit: service.clone(),
        },
    )
    .await?;
    if !reply.ok {
        bail!("stopping {service}: {}", reply.message);
    }
    Ok(())
}

/// The storage lines of a refresh preview: what a rebuild keeps, and what it recreates.
/// Empty when the environment declares no storage, or when the inventory cannot be read —
/// a preview reports, and has nothing to add when it cannot answer.
pub fn preview(plan: &Plan) -> String {
    let items = inventory(plan, false).unwrap_or_default();
    if items.is_empty() {
        return String::new();
    }
    let mut out = String::from("storage:\n");
    for i in &items {
        let fate = match i.category {
            Category::GenerationBound => "recreated when the image changes",
            _ => "kept",
        };
        out.push_str(&format!("  {}: {fate}\n", i.name));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::config::Freshness;
    use crate::dev::plan::VsCodePlan;
    use crate::dev::testutil::mount;

    struct TmpDir(PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).ok();
        }
    }

    fn scratch(tag: &str) -> TmpDir {
        let dir = std::env::temp_dir().join(format!("vk-devstorage-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("repo/.virtkit")).unwrap();
        std::fs::create_dir_all(dir.join("state")).unwrap();
        TmpDir(dir)
    }

    /// A workspace whose compose file declares one of each backing an item is derived from,
    /// plus a plain bind that is nobody's storage.
    fn fixture(tag: &str) -> (TmpDir, Plan) {
        let t = scratch(tag);
        std::fs::write(
            t.0.join("repo/.virtkit/compose.yaml"),
            "services:\n  \
             devcontainer:\n    image: x\n    volumes:\n      \
             - ${VK_WORKSPACE}:/workdir\n      \
             - ${VK_WORKSPACE}/cache:/cache:overlay,persist\n  \
             runner:\n    image: y\n    profiles: [runner]\n    \
             x-virtkit:\n      persist_root: true\n    volumes:\n      \
             - ${VK_WORKSPACE}/.virtkit/runner-var-wab.qcow2:/var/wab:disk\n",
        )
        .unwrap();
        let plan = Plan {
            workspace: t.0.join("repo"),
            config: t.0.join("repo/.virtkit/config.toml"),
            environment: "dev".into(),
            state_dir: t.0.join("state"),
            source: Source::Compose {
                file: t.0.join("repo/.virtkit/compose.yaml"),
                service: "devcontainer".into(),
                profiles: vec![],
            },
            workspace_folder: Some("/workdir".into()),
            user: None,
            freshness: Freshness::Ask,
            cpus: None,
            mem: None,
            mounts: vec![mount(
                "vscode-server",
                t.0.join("state/vscode-server"),
                "/home/dev/.vscode-server",
            )],
            container_env: vec![],
            exec_env: vec![],
            endpoints: vec![],
            host_exec: None,
            ssh_agent: false,
            cache: Default::default(),
            requires: Default::default(),
            cached_only: false,
            fallback_target: None,
            tasks: Vec::new(),
            hooks: Default::default(),
            vscode: None,
            managed_dirs: vec![t.0.join("state/vscode-server")],
            unresolved: vec![],
            secrets: Default::default(),
        };
        (t, plan)
    }

    #[test]
    fn the_inventory_is_what_the_compose_file_and_the_config_declare() {
        let (t, plan) = fixture("inventory");
        // Only the runner's disk exists yet; the rest is listed as not created.
        std::fs::write(
            t.0.join("repo/.virtkit/runner-var-wab.qcow2"),
            vec![0u8; 4096],
        )
        .unwrap();
        let items = inventory(&plan, true).unwrap();

        let names: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "${state}/vscode-server",
                "devcontainer:/cache:overlay",
                "runner:/",
                "runner:/var/wab",
            ],
            "the plain /workdir bind is nobody's storage, and profiles do not hide a service"
        );
        let by = |n: &str| items.iter().find(|i| i.name == n).unwrap().clone();
        assert_eq!(
            (by("runner:/var/wab").category, by("runner:/var/wab").kind),
            (Category::Durable, "disk")
        );
        assert_eq!(by("runner:/var/wab").owner.as_deref(), Some("runner"));
        assert_eq!(
            by("runner:/var/wab").backing,
            plan.workspace.join(".virtkit/runner-var-wab.qcow2")
        );
        assert_eq!(
            (
                by("runner:/var/wab").exists,
                by("runner:/var/wab").size_bytes
            ),
            (true, Some(4096))
        );
        assert_eq!(
            (
                by("runner:/").category,
                by("runner:/").kind,
                by("runner:/").exists
            ),
            (Category::GenerationBound, "persist-root", false)
        );
        assert_eq!(
            by("devcontainer:/cache:overlay").category,
            Category::GenerationBound
        );
        assert_eq!(by("devcontainer:/cache:overlay").kind, "overlay-upper");
        // A `${state}` mount is the environment's own durable storage, guest path and all.
        let state = by("${state}/vscode-server");
        assert_eq!(
            (state.owner, state.category, state.kind),
            (None, Category::Durable, "managed-dir")
        );
        assert_eq!(state.guest.as_deref(), Some("/home/dev/.vscode-server"));

        // Without --sizes nothing is measured, and the JSON leaves the field out rather
        // than reporting a size of nothing.
        let unmeasured = inventory(&plan, false).unwrap();
        assert!(unmeasured.iter().all(|i| i.size_bytes.is_none()));
        let disk = unmeasured
            .iter()
            .find(|i| i.name == "runner:/var/wab")
            .unwrap();
        assert!(disk.exists, "existence is still reported");
        let json = serde_json::to_string(&disk).unwrap();
        assert!(!json.contains("size_bytes"), "{json}");
    }

    #[test]
    fn only_vks_own_server_storage_is_the_editors() {
        let (t, mut plan) = fixture("editor");
        plan.vscode = Some(VsCodePlan {
            persistent: true,
            home: "/home/dev".into(),
            reconcile: None,
            extensions: vec![],
            settings: serde_json::Value::Null,
        });
        // The project's own `${state}` mount stays a managed directory even with a
        // persistent editor: the adapter owns the directory it manages, not the name.
        let items = inventory(&plan, false).unwrap();
        assert_eq!(items.iter().filter(|i| i.kind == "editor").count(), 0);

        let managed = t.0.join("state/editor/vscode-server");
        plan.managed_dirs.push(managed.clone());
        let items = inventory(&plan, false).unwrap();
        let editor = items.iter().find(|i| i.name == "editor").unwrap();
        assert_eq!((editor.category, editor.kind), (Category::Editor, "editor"));
        assert_eq!(editor.backing, managed);
    }

    #[test]
    fn render_aligns_the_columns_and_names_a_running_owner() {
        let items = vec![
            Item {
                name: "runner:/var/wab".into(),
                owner: Some("runner".into()),
                category: Category::Durable,
                kind: "disk",
                backing: "/w/.virtkit/runner-var-wab.qcow2".into(),
                guest: Some("/var/wab".into()),
                exists: true,
                size_bytes: Some(3 << 20),
            },
            Item {
                name: "runner:/".into(),
                owner: Some("runner".into()),
                category: Category::GenerationBound,
                kind: "persist-root",
                backing: "/w/.virtkit/roots/runner.qcow2".into(),
                guest: Some("/".into()),
                exists: false,
                size_bytes: None,
            },
        ];
        let running = Running {
            environment: true,
            services: vec!["runner".into()],
        };
        let text = render(&items, &running);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "NAME             CATEGORY          KIND          BACKING                           SIZE   STATE"
        );
        assert_eq!(
            lines[1],
            "runner:/var/wab  durable           disk          /w/.virtkit/runner-var-wab.qcow2  3 MiB  created (service runner running)"
        );
        assert_eq!(
            lines[2],
            "runner:/         generation-bound  persist-root  /w/.virtkit/roots/runner.qcow2    -      not created"
        );
        assert_eq!(render(&[], &running), "no storage declared\n");
    }

    #[test]
    fn reset_refuses_what_it_does_not_own() {
        let (t, plan) = fixture("reset");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();

        let e = rt.block_on(reset(&plan, "nope", true)).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("no storage item \"nope\""), "{msg}");
        assert!(msg.contains("runner:/var/wab"), "{msg}");

        let e = rt.block_on(reset(&plan, "runner:/", true)).unwrap_err();
        assert!(format!("{e:#}").contains("vk dev refresh"), "{e:#}");
        let e = rt
            .block_on(reset(&plan, "devcontainer:/cache:overlay", true))
            .unwrap_err();
        assert!(format!("{e:#}").contains("image generation"), "{e:#}");

        // Nothing to remove is success, and the backing of what does exist stays put.
        let report = rt.block_on(reset(&plan, "runner:/var/wab", true)).unwrap();
        assert!(report.contains("nothing to remove"), "{report}");
        let disk = t.0.join("repo/.virtkit/runner-var-wab.qcow2");
        std::fs::write(&disk, b"data").unwrap();
        assert!(inventory(&plan, false).unwrap().iter().any(|i| i.exists));
        assert!(disk.is_file());
    }

    #[test]
    fn a_reset_removes_a_backing_and_refuses_a_symlinked_one() {
        let (t, plan) = fixture("remove");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let disk = t.0.join("repo/.virtkit/runner-var-wab.qcow2");

        // A symlink is the one shape that is left alone: unlinking it would take the name
        // and keep the data, which is not what the report would say.
        let elsewhere = t.0.join("elsewhere.qcow2");
        std::fs::write(&elsewhere, b"precious").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &disk).unwrap();
        let e = rt
            .block_on(reset(&plan, "runner:/var/wab", true))
            .unwrap_err();
        assert!(format!("{e:#}").contains("is a symlink"), "{e:#}");
        assert!(disk.is_symlink(), "the link survived");
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"precious");

        // A regular backing goes, and the state directory's lock is free again after.
        std::fs::remove_file(&disk).unwrap();
        std::fs::write(&disk, b"data").unwrap();
        let report = rt.block_on(reset(&plan, "runner:/var/wab", true)).unwrap();
        assert!(report.contains("removed"), "{report}");
        assert!(!disk.exists(), "the backing survived the reset");
        assert!(
            crate::dev::list::try_lock_state_dir(&plan.state_dir).is_some(),
            "the lock was handed back"
        );
    }

    #[test]
    fn a_reset_refuses_while_the_environment_is_being_booted() {
        let (t, plan) = fixture("locked");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let disk = t.0.join("repo/.virtkit/runner-var-wab.qcow2");
        std::fs::write(&disk, b"data").unwrap();
        // What a boot in flight looks like from here: the state directory's lock is held and
        // no VM is registered on it yet.
        let held =
            crate::dev::list::try_lock_state_dir(&plan.state_dir).expect("free to begin with");
        let e = rt
            .block_on(reset(&plan, "runner:/var/wab", true))
            .unwrap_err();
        assert!(format!("{e:#}").contains("being booted"), "{e:#}");
        assert!(disk.is_file(), "nothing was removed under the boot");
        drop(held);
        assert!(rt.block_on(reset(&plan, "runner:/var/wab", true)).is_ok());
    }

    #[test]
    fn the_preview_says_what_a_refresh_keeps() {
        let (_t, plan) = fixture("preview");
        let text = preview(&plan);
        assert!(text.starts_with("storage:\n"), "{text}");
        assert!(text.contains("  runner:/var/wab: kept\n"), "{text}");
        assert!(
            text.contains("  runner:/: recreated when the image changes\n"),
            "{text}"
        );
        // A source with nothing declared adds no section.
        let mut bare = plan.clone();
        bare.source = Source::Image {
            reference: "debian:13".into(),
        };
        bare.managed_dirs.clear();
        assert_eq!(preview(&bare), "");
    }
}
