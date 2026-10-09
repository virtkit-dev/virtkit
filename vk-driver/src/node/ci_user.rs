//! Whether this host's CI jobs run as another user than the node. The node reads the
//! admission ledger (`<state_dir>/admit/`) and the job dirs (`<state_dir>/jobs/`) its runner's
//! vk executor writes, `0600` and `0700`; when the executor runs as another user, the node
//! cannot read them, under-counts admission and cannot tell when a drain is done — and the
//! executor cannot read what the node's own placed jobs leave there either.
//!
//! Two signs are read: who owns the jobs' entries under the state dir, and, with an external
//! runner, the user gitlab-runner's systemd unit runs as when its config runs the vk custom
//! executor: gitlab-runner runs a custom executor as itself. Handing the state dir to the
//! node's user (`vk node join --user`) erases the first sign once, not the cause, so it is
//! read before.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::config::Config;

/// Unit directories systemd reads `gitlab-runner.service` from, the first one found winning,
/// and its `gitlab-runner.service.d/` drop-ins, one in an earlier directory masking one of the
/// same name in a later.
const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];
const RUNNER_UNIT: &str = "gitlab-runner.service";
/// Where gitlab-runner run as root reads its config when no `--config` names one.
const ROOT_RUNNER_CONFIG: &str = "/etc/gitlab-runner/config.toml";

/// The user the node runs, or would run, as.
pub struct NodeUser<'a> {
    /// `None` for a user not created yet: anyone else's job is another user's.
    pub uid: Option<u32>,
    pub name: &'a str,
}

/// A sign that CI jobs run as `user`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// The user's name, or its uid when `/etc/passwd` has none.
    pub user: String,
    /// What says so: a path it owns, or the runner unit running it.
    pub at: String,
}

/// Every sign that the host's CI jobs run as another user than `node`. With
/// `[node] runner = "managed"` the node runs gitlab-runner itself, as its own user, so only
/// what is under the state dir is read.
pub fn others(cfg: &Config, node: &NodeUser<'_>) -> Vec<Seen> {
    others_by(cfg, node, owner)
}

/// [`others`], with `uid_of` for who owns a path.
fn others_by(
    cfg: &Config,
    node: &NodeUser<'_>,
    uid_of: impl Fn(&Path) -> Option<u32>,
) -> Vec<Seen> {
    let mut seen: Vec<Seen> = owners_by(cfg.state_dir(), uid_of)
        .into_iter()
        .filter(|(uid, _)| node.uid != Some(*uid))
        .map(|(uid, path)| Seen {
            user: user_name(uid),
            at: path.display().to_string(),
        })
        .collect();
    if cfg.node.runner == vk_hub_proto::RunnerMode::External
        && let Some((user, unit)) = runner_unit_user(UNIT_DIRS)
    {
        let uid = uid_of_user(&user);
        let same = match (uid, node.uid) {
            (Some(unit), Some(node)) => unit == node,
            _ => user == node.name,
        };
        if !same {
            seen.push(Seen {
                user: uid.map_or(user, user_name),
                at: format!("{} runs the vk custom executor", unit.display()),
            });
        }
    }
    seen
}

/// Explain this node's user mismatch, if any. Omit job paths so jobs coming and going do
/// not change the message and cause repeated logging.
pub fn this_node(cfg: &Config) -> Option<String> {
    let uid = super::service::euid();
    let name = user_name(uid);
    let node = NodeUser {
        uid: Some(uid),
        name: &name,
    };
    let seen = others(cfg, &node);
    (!seen.is_empty()).then(|| explain(&node, cfg.state_dir(), &seen, false))
}

fn owner(path: &Path) -> Option<u32> {
    std::fs::symlink_metadata(path).ok().map(|m| m.uid())
}

/// Who owns the jobs' entries in `<state>/admit/` and `<state>/jobs/`, by `uid_of`, each with
/// the first path found of theirs. The directories and the ledger's `.lock` are left out:
/// whichever user ran the node or a job first made them.
fn owners_by(state: &Path, uid_of: impl Fn(&Path) -> Option<u32>) -> Vec<(u32, PathBuf)> {
    let mut found: Vec<(u32, PathBuf)> = Vec::new();
    for sub in ["admit", "jobs"] {
        let Ok(entries) = std::fs::read_dir(state.join(sub)) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().is_some_and(is_job_entry))
            .collect();
        // Deterministic: the same evidence named on every run.
        paths.sort();
        for path in paths {
            if let Some(uid) = uid_of(&path)
                && !found.iter().any(|(u, _)| *u == uid)
            {
                found.push((uid, path));
            }
        }
    }
    found
}

/// Whether an `admit/` or `jobs/` entry is a job's: not the ledger's `.lock` or another dotted
/// name no job id takes, and not a `reservation-*` entry, a reservation the node holds for the
/// hub. A placed job's entries are named as a CI job's: a former node user's still running count
/// as that user's jobs.
fn is_job_entry(name: &std::ffi::OsStr) -> bool {
    let name = name.as_encoded_bytes();
    !name.starts_with(b".") && !name.starts_with(b"reservation-")
}

/// The name of the user with `uid`, else the number.
pub(super) fn user_name(uid: u32) -> String {
    super::service::Account::of(uid).map_or_else(|_| uid.to_string(), |a| a.name)
}

/// The uid a unit's `User=` names: a number is one; a name `/etc/passwd` lacks has none.
fn uid_of_user(user: &str) -> Option<u32> {
    user.parse().ok().or_else(|| {
        super::service::Account::lookup(user)
            .ok()
            .flatten()
            .map(|a| a.uid)
    })
}

/// The user gitlab-runner's unit runs as, and the unit, when the config it runs with runs the
/// vk custom executor; `None` when there is no such unit, it is masked, or its config cannot be
/// read.
fn runner_unit_user(unit_dirs: &[&str]) -> Option<(String, PathBuf)> {
    let (unit, text) = unit_dirs.iter().find_map(|dir| {
        let path = Path::new(dir).join(RUNNER_UNIT);
        std::fs::read_to_string(&path).ok().map(|t| (path, t))
    })?;
    // Masked: a link to /dev/null, or empty.
    if text.trim().is_empty() {
        return None;
    }
    let mut confs: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for dir in unit_dirs {
        let Ok(entries) = std::fs::read_dir(Path::new(dir).join(format!("{RUNNER_UNIT}.d"))) else {
            continue;
        };
        for path in entries.flatten().map(|e| e.path()) {
            if path.extension().is_some_and(|e| e == "conf")
                && let Some(name) = path.file_name()
            {
                confs.entry(name.to_owned()).or_insert(path);
            }
        }
    }
    let mut texts = vec![text];
    texts.extend(
        confs
            .values()
            .filter_map(|p| std::fs::read_to_string(p).ok()),
    );
    let service = parse_unit(&texts);
    // A unit whose program is gone runs nothing. Only an absolute program is checked: one
    // systemd looks up, or with specifiers or `${X}`, is kept. So is one whose absence cannot
    // be told, such as behind a directory this user cannot search.
    if service.program.as_deref().is_some_and(|p| {
        p.is_absolute()
            && p.to_str().is_some_and(|p| !p.contains(['%', '$']))
            && matches!(p.try_exists(), Ok(false))
    }) {
        return None;
    }
    let user = service.user.unwrap_or_else(|| "root".to_string());
    let config = match service.config {
        Some(config) => config,
        None if uid_of_user(&user) == Some(0) => PathBuf::from(ROOT_RUNNER_CONFIG),
        // Its home's `.gitlab-runner/config.toml`, a guess not worth making.
        None => return None,
    };
    let mut text = String::new();
    std::fs::File::open(config)
        .and_then(|f| {
            f.take(super::inventory::MAX_RUNNER_CONFIG)
                .read_to_string(&mut text)
        })
        .ok()?;
    runs_vk(&text).then_some((user, unit))
}

/// What a unit's `[Service]` section says of gitlab-runner, the unit then its drop-ins.
#[derive(Debug, Default, PartialEq, Eq)]
struct RunnerService {
    /// `User=`, `None` for root.
    user: Option<String>,
    /// `--config`/`-c` on the last `ExecStart=`.
    config: Option<PathBuf>,
    /// The last `ExecStart=` program without prefixes (`-`, `@`, `:`, `+`, `!`, `|`).
    program: Option<PathBuf>,
}

fn parse_unit(texts: &[String]) -> RunnerService {
    let mut out = RunnerService::default();
    for text in texts {
        let mut in_service = false;
        for line in text.lines().map(str::trim) {
            if line.starts_with('[') {
                in_service = line == "[Service]";
                continue;
            }
            if !in_service {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            match key.trim() {
                // An empty assignment resets it, to root.
                "User" => out.user = Some(value.to_string()).filter(|v| !v.is_empty()),
                // An empty assignment resets the commands: none is run.
                "ExecStart" if value.is_empty() => {
                    out.config = None;
                    out.program = None;
                }
                "ExecStart" => {
                    let words: Vec<&str> = value
                        .split_whitespace()
                        .map(|w| w.trim_matches('"'))
                        .collect();
                    out.config = words.iter().enumerate().find_map(|(at, w)| {
                        match *w {
                            "--config" | "-c" => words.get(at + 1).copied(),
                            w => w.strip_prefix("--config=").or(w.strip_prefix("-c=")),
                        }
                        .map(PathBuf::from)
                    });
                    // systemd unquotes the program after taking its prefixes off.
                    out.program = value.split_whitespace().next().map(|w| {
                        PathBuf::from(
                            w.trim_start_matches(['-', '@', ':', '+', '!', '|'])
                                .trim_matches('"'),
                        )
                    });
                }
                _ => {}
            }
        }
    }
    out
}

/// Whether a gitlab-runner config has a custom-executor runner running vk: an `*_exec` named
/// `vk`, or `*_args` with `gitlab` among them, as `vk gitlab <stage>` is run.
fn runs_vk(text: &str) -> bool {
    let Ok(table) = toml::from_str::<toml::Table>(text) else {
        return false;
    };
    let runners = table
        .get("runners")
        .and_then(toml::Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    runners
        .iter()
        .filter(|r| r.get("executor").and_then(toml::Value::as_str) == Some("custom"))
        .filter_map(|r| r.get("custom").and_then(toml::Value::as_table))
        .flat_map(|custom| custom.iter())
        .any(|(key, value)| {
            if key.ends_with("_exec") {
                value
                    .as_str()
                    .is_some_and(|exec| Path::new(exec).file_name().is_some_and(|f| f == "vk"))
            } else if key.ends_with("_args") {
                value
                    .as_array()
                    .is_some_and(|args| args.iter().any(|a| a.as_str() == Some("gitlab")))
            } else {
                false
            }
        })
}

/// Explain why `node` cannot share state with jobs run by the users in `seen`, and how to
/// fix it. With `detail`, include each user's first sign; `vk node run` omits it to keep
/// the message stable as jobs come and go.
pub fn explain(node: &NodeUser<'_>, state: &Path, seen: &[Seen], detail: bool) -> String {
    let (node_uid, node) = (node.uid, node.name);
    let mut users: Vec<&str> = Vec::new();
    for s in seen {
        if !users.contains(&s.user.as_str()) {
            users.push(&s.user);
        }
    }
    let who = users.join(" and ");
    let signs = if detail {
        let firsts: Vec<String> = users
            .iter()
            .filter_map(|u| seen.iter().find(|s| s.user == *u))
            .map(|s| format!("{}: {}", s.user, s.at))
            .collect();
        format!(" ({})", firsts.join("; "))
    } else {
        String::new()
    };
    let first = users.first().copied().unwrap_or_default();
    let as_first = if first == "root" {
        "run the node as root (`vk node join --replace` as root, without --user)".to_string()
    } else if first.bytes().all(|b| b.is_ascii_digit()) {
        format!("run the node as uid {first}, which /etc/passwd does not name, so --user cannot")
    } else {
        format!("run the node as {first} (`vk node join --replace --user {first}`)")
    };
    let state = state.display();
    // Root reads anything: then it is the executor that cannot read the node's.
    let unread = if node_uid == Some(0) {
        format!(
            "the vk executor, as {who}, cannot read the admission ledger entries and job dirs \
             the node leaves under {state}, so its admission under-counts the node's jobs"
        )
    } else {
        format!(
            "the node cannot read the admission ledger entries and job dirs they leave under \
             {state}, so it under-counts admission and cannot tell when a drain is done"
        )
    };
    format!(
        "CI jobs on this host run as {who}, not as {node}, the user the node runs as{signs}: \
         {unread}. The node must run as the user its runner's vk executor runs as: {as_first}; \
         or run gitlab-runner as {node} (`User={node}` in a drop-in from `systemctl edit \
         gitlab-runner`, and `chown -R {node}: /etc/gitlab-runner` for its config) and give \
         {node} what {first} left there"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::service::euid as me;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-ci-user-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn managed(state: &Path) -> Config {
        toml::from_str(&format!(
            "state_dir = {:?}\n[node]\nrunner = \"managed\"\n",
            state.display().to_string()
        ))
        .unwrap()
    }

    #[test]
    fn what_the_jobs_left_names_their_user_unless_it_is_the_nodes() {
        let state = scratch("owners");
        std::fs::create_dir_all(state.join("admit")).unwrap();
        std::fs::write(state.join("admit").join(".lock"), "").unwrap();
        std::fs::create_dir_all(state.join("jobs").join(".net")).unwrap();
        // The node's own, never a sign.
        std::fs::write(state.join("admit").join("reservation-ab"), "").unwrap();
        // The directories and the lock are no job's.
        assert!(owners_by(&state, owner).is_empty());
        std::fs::write(state.join("admit").join("8937298"), "1024 1 granted\n").unwrap();
        std::fs::create_dir_all(state.join("jobs").join("8937298")).unwrap();
        let entry = state.join("admit").join("8937298");
        assert_eq!(owners_by(&state, owner), [(me(), entry.clone())]);
        let cfg = managed(&state);
        let mine = NodeUser {
            uid: Some(me()),
            name: "n",
        };
        assert!(others(&cfg, &mine).is_empty());
        // As a node of another uid, or of a user still to be created, would see it.
        for uid in [Some(me().wrapping_add(1)), None] {
            let seen = others(&cfg, &NodeUser { uid, name: "n" });
            assert_eq!(seen.len(), 1, "{seen:?}");
            assert_eq!(seen[0].at, entry.display().to_string());
        }
        // Nothing there yet: nothing to say.
        let empty = scratch("owners-empty");
        assert!(owners_by(&empty, owner).is_empty());
        let _ = std::fs::remove_dir_all(&state);
        let _ = std::fs::remove_dir_all(&empty);
    }

    #[test]
    fn a_former_root_nodes_directories_and_lock_are_no_sign() {
        // A node that ran as root made admit/, its .lock and jobs/; the jobs ran as the user.
        let state = scratch("former-root");
        std::fs::create_dir_all(state.join("node")).unwrap();
        std::fs::create_dir_all(state.join("admit")).unwrap();
        std::fs::write(state.join("admit").join(".lock"), "").unwrap();
        std::fs::write(state.join("admit").join("8937298"), "1024 1 granted\n").unwrap();
        std::fs::create_dir_all(state.join("jobs").join("8937298")).unwrap();
        let root_made = |p: &Path| match p.file_name().and_then(|n| n.to_str()) {
            Some("admit" | "jobs" | ".lock") => Some(0),
            _ => Some(me()),
        };
        let node = NodeUser {
            uid: Some(me()),
            name: "n",
        };
        assert!(others_by(&managed(&state), &node, root_made).is_empty());
        let _ = std::fs::remove_dir_all(&state);
    }

    #[test]
    fn the_runner_units_user_and_config_are_read_with_its_drop_ins() {
        let unit = r#"[Unit]
Description=GitLab Runner
User=nobody-in-unit-section
[Service]
ExecStart=/usr/bin/gitlab-runner "run" "--config" "/etc/gitlab-runner/config.toml" "--user" "gitlab-runner"
"#;
        assert_eq!(
            parse_unit(&[unit.to_string()]),
            RunnerService {
                user: None,
                config: Some(PathBuf::from("/etc/gitlab-runner/config.toml")),
                program: Some(PathBuf::from("/usr/bin/gitlab-runner")),
            }
        );
        let drop_in = "[Service]\nUser=gitlab-runner\n".to_string();
        assert_eq!(
            parse_unit(&[unit.to_string(), drop_in.clone()])
                .user
                .as_deref(),
            Some("gitlab-runner")
        );
        let reset = "[Service]\nUser=\n".to_string();
        assert_eq!(parse_unit(&[unit.to_string(), drop_in, reset]).user, None);
        for exec in ["run --config=/c.toml", "run -c=/c.toml", "run -c /c.toml"] {
            let unit = format!("[Service]\nExecStart=/usr/bin/gitlab-runner {exec}\n");
            assert_eq!(
                parse_unit(&[unit]).config,
                Some(PathBuf::from("/c.toml")),
                "{exec}"
            );
        }
        // Strip program prefixes before unquoting.
        for exec in [
            "@/usr/bin/gitlab-runner gitlab-runner run -c /c.toml",
            "+/usr/bin/gitlab-runner run -c /c.toml",
            "!!/usr/bin/gitlab-runner run -c /c.toml",
            ":/usr/bin/gitlab-runner run -c /c.toml",
            "|/usr/bin/gitlab-runner run -c /c.toml",
            "-\"/usr/bin/gitlab-runner\" run -c /c.toml",
        ] {
            let unit = format!("[Service]\nExecStart={exec}\n");
            assert_eq!(
                parse_unit(&[unit]),
                RunnerService {
                    user: None,
                    config: Some(PathBuf::from("/c.toml")),
                    program: Some(PathBuf::from("/usr/bin/gitlab-runner")),
                },
                "{exec}"
            );
        }
        // An empty `ExecStart=` resets the commands.
        let reset = "[Service]\nExecStart=\n".to_string();
        assert_eq!(
            parse_unit(&[unit.to_string(), reset]),
            RunnerService::default()
        );
    }

    #[test]
    fn a_unit_running_the_vk_executor_names_its_user() {
        let dir = scratch("unit");
        let units = dir.join("units");
        let lib = dir.join("lib");
        std::fs::create_dir_all(units.join(format!("{RUNNER_UNIT}.d"))).unwrap();
        std::fs::create_dir_all(lib.join(format!("{RUNNER_UNIT}.d"))).unwrap();
        let config = dir.join("config.toml");
        let runner = dir.join("gitlab-runner");
        let unit = |program: &Path| {
            format!(
                "[Service]\nExecStart=-{} run --config {}\n",
                program.display(),
                config.display()
            )
        };
        let runs_vk = "[[runners]]\nexecutor = \"custom\"\n[runners.custom]\n\
                       run_exec = \"/usr/local/bin/vk\"\n";
        // The runner it names is gone.
        std::fs::write(lib.join(RUNNER_UNIT), unit(&runner)).unwrap();
        std::fs::write(&config, runs_vk).unwrap();
        let dirs = [units.to_str().unwrap(), lib.to_str().unwrap()];
        assert_eq!(runner_unit_user(&dirs), None);
        // Keep programs that systemd looks up on its PATH.
        std::fs::write(
            lib.join(RUNNER_UNIT),
            unit(Path::new("gitlab-runner-not-on-path")),
        )
        .unwrap();
        assert_eq!(
            runner_unit_user(&dirs),
            Some(("root".to_string(), lib.join(RUNNER_UNIT)))
        );
        // And programs systemd expands first.
        for program in [
            "/nonexistent/%h/gitlab-runner",
            "/nonexistent/${X}/gitlab-runner",
        ] {
            std::fs::write(lib.join(RUNNER_UNIT), unit(Path::new(program))).unwrap();
            assert_eq!(
                runner_unit_user(&dirs),
                Some(("root".to_string(), lib.join(RUNNER_UNIT))),
                "{program}"
            );
        }
        std::fs::write(lib.join(RUNNER_UNIT), unit(&runner)).unwrap();
        std::fs::write(&runner, "").unwrap();
        std::fs::remove_file(&config).unwrap();
        // No config to read: nothing said.
        assert_eq!(runner_unit_user(&dirs), None);
        std::fs::write(&config, runs_vk).unwrap();
        assert_eq!(
            runner_unit_user(&dirs),
            Some(("root".to_string(), lib.join(RUNNER_UNIT)))
        );
        // A drop-in beside the packaged unit applies; one of the same name earlier masks it.
        std::fs::write(
            lib.join(format!("{RUNNER_UNIT}.d")).join("user.conf"),
            "[Service]\nUser=gitlab-runner\n",
        )
        .unwrap();
        assert_eq!(
            runner_unit_user(&dirs).map(|(u, _)| u),
            Some("gitlab-runner".to_string())
        );
        std::fs::write(
            units.join(format!("{RUNNER_UNIT}.d")).join("user.conf"),
            "[Service]\nUser=ci\n",
        )
        .unwrap();
        assert_eq!(
            runner_unit_user(&dirs).map(|(u, _)| u),
            Some("ci".to_string())
        );
        // Masked: it runs nothing.
        std::os::unix::fs::symlink("/dev/null", units.join(RUNNER_UNIT)).unwrap();
        assert_eq!(runner_unit_user(&dirs), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_custom_executor_running_vk_counts() {
        assert!(runs_vk(
            "[[runners]]\nexecutor = \"custom\"\n[runners.custom]\nrun_exec = \"/usr/local/bin/vk\"\n"
        ));
        assert!(runs_vk(
            "[[runners]]\nexecutor = \"custom\"\n[runners.custom]\nrun_exec = \"/opt/x\"\n\
             run_args = [\"--config\", \"/c\", \"gitlab\", \"run\"]\n"
        ));
        assert!(!runs_vk(
            "[[runners]]\nexecutor = \"custom\"\n[runners.custom]\nrun_exec = \"/opt/other\"\n"
        ));
        assert!(!runs_vk(
            "[[runners]]\nexecutor = \"shell\"\n[runners.custom]\nrun_exec = \"vk\"\n"
        ));
        assert!(!runs_vk("not toml ["));
    }

    #[test]
    fn the_explanation_names_who_the_node_must_run_as() {
        let seen = [
            Seen {
                user: "root".into(),
                at: "/var/lib/virtkit/admit/8937298".into(),
            },
            Seen {
                user: "root".into(),
                at: "gitlab-runner.service runs the vk custom executor".into(),
            },
        ];
        let state = Path::new("/var/lib/virtkit");
        let runner = NodeUser {
            uid: Some(999),
            name: "gitlab-runner",
        };
        let long = explain(&runner, state, &seen, true);
        assert!(long.contains("run as root, not as gitlab-runner"), "{long}");
        assert!(
            long.contains("root: /var/lib/virtkit/admit/8937298"),
            "{long}"
        );
        assert!(long.contains("without --user"), "{long}");
        assert!(!long.contains("--user root"), "{long}");
        let short = explain(&runner, state, &seen, false);
        assert!(!short.contains("8937298"), "{short}");
        assert!(short.contains("User=gitlab-runner"), "{short}");
        assert!(short.contains("chown -R gitlab-runner:"), "{short}");
        assert!(short.contains("the node cannot read"), "{short}");
        let ci = |user: &str| {
            [Seen {
                user: user.into(),
                at: "x".into(),
            }]
        };
        let n = NodeUser {
            uid: Some(1000),
            name: "n",
        };
        let named = explain(&n, state, &ci("ci"), false);
        assert!(named.contains("--user ci`"), "{named}");
        let bare = explain(&n, state, &ci("4242"), false);
        assert!(bare.contains("/etc/passwd does not name"), "{bare}");
        assert!(!bare.contains("--user 4242"), "{bare}");
        // A root node reads anything; the executor cannot read what it leaves.
        let root = NodeUser {
            uid: Some(0),
            name: "root",
        };
        let as_root = explain(&root, state, &ci("ci"), false);
        assert!(
            as_root.contains("the vk executor, as ci, cannot read"),
            "{as_root}"
        );
    }
}
