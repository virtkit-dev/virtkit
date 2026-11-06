//! The fleet hub's settings on a node (`docs/fleet-design.md`, *Hub settings*): the entries of
//! the hub's desired state the node takes ([`Held::take`]), kept in
//! `<state_dir>/node/settings.json` with the hub, node ID and generation they came from, and
//! laid under the local config file by every `vk` on the enrolled host ([`layer`], [`merge`]).
//! A key the file sets, even to its default, is never overridden, and `[registry]` is taken
//! whole or not at all. Only the keys of [`KEYS`] may come from the hub; never a path or a
//! credential.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vk_hub_proto::{DesiredState, Setting, SettingSource, SettingsReport};

use super::state::Issuer;
use super::{read_enrollment, read_nofollow};
use crate::config::Config;

const FILE: &str = "settings.json";

/// Reads a key's effective value off a loaded config.
type Read = fn(&Config) -> Option<Value>;

/// The keys the hub may set, by dotted key, and how to read each one's effective value: its
/// default where it has one, as resolved for this host, `None` where unset means none.
const KEYS: &[(&str, Read)] = &[
    ("executor.schedule.mem_budget", |c| {
        json(&c.executor.schedule.mem_budget)
    }),
    ("executor.schedule.from_history", |c| {
        json(&c.executor.schedule.from_history)
    }),
    ("executor.schedule.disk_admission", |c| {
        json(&c.executor.schedule.disk_admission.unwrap_or(true))
    }),
    ("executor.schedule.disk_default", |c| {
        json(&c.executor.schedule.disk_default)
    }),
    ("executor.schedule.cpu_overcommit", |c| {
        json(&c.executor.schedule.cpu_overcommit)
    }),
    ("executor.schedule.wait_timeout_secs", |c| {
        let secs = c.executor.schedule.wait_timeout_secs;
        json(&secs.unwrap_or(crate::config::WAIT_TIMEOUT_SECS))
    }),
    ("executor.vm.cpus", |c| json(&c.executor.vm.cpus)),
    ("executor.vm.mem", |c| json(&c.executor.vm.mem)),
    ("executor.vm.max_cpus", |c| json(&c.executor.vm.max_cpus)),
    ("executor.vm.max_mem", |c| json(&c.executor.vm.max_mem)),
    ("image_cache_idle_secs", |c| {
        json(&c.image_cache_idle().as_secs())
    }),
    ("registry", |c| json(&c.registry)),
];

/// The `[registry]` keys the hub may name: the registry and how to reach it, never a path or a
/// credential of the node's.
const REGISTRY_KEYS: &[&str] = &[
    "repo",
    "insecure",
    "transparent_zstd",
    "proxy_guests",
    "guest_credential",
    "pipeline_root",
];

/// `value` as JSON; `None` for an unset `Option`.
fn json<T: Serialize>(value: &T) -> Option<Value> {
    serde_json::to_value(value).ok().filter(|v| !v.is_null())
}

fn allowed(key: &str) -> bool {
    KEYS.iter().any(|(k, _)| *k == key)
}

/// `settings.json`: the hub's entries the node took, and those it refused, from the desired
/// state of `generation` of `hub` for `node_id`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    pub hub: String,
    pub node_id: String,
    pub generation: u64,
    #[serde(default)]
    pub settings: BTreeMap<String, Value>,
    #[serde(default)]
    pub refused: BTreeMap<String, String>,
}

/// `settings.json` in the node dir `dir`.
fn read(dir: &Path) -> Result<Saved> {
    let path = dir.join(FILE);
    let text = read_nofollow(&path)?;
    serde_json::from_slice(&text).with_context(|| format!("parsing {}", path.display()))
}

/// The hub's settings for a host enrolled under `state_dir`, the ones the config is laid over:
/// `None` when the host is not enrolled, or has no settings for the enrollment it has. A file
/// that cannot be read is warned about and ignored.
pub fn layer(state_dir: &Path) -> Option<BTreeMap<String, Value>> {
    let dir = state_dir.join("node");
    // Not enrolled, or not as far as this user can tell.
    let enrollment = read_enrollment(&dir).ok()?;
    let saved = match read(&dir) {
        Ok(saved) => saved,
        Err(e) if super::is_not_found(&e) => return None,
        Err(e) => {
            eprintln!("virtkit: warning: ignoring the fleet hub's settings: {e:#}");
            return None;
        }
    };
    if (saved.hub.as_str(), saved.node_id.as_str())
        != (enrollment.hub.as_str(), enrollment.node_id.as_str())
    {
        eprintln!(
            "virtkit: warning: ignoring the fleet hub's settings in {}, kept for another \
             enrollment",
            dir.join(FILE).display()
        );
        return None;
    }
    Some(saved.settings)
}

/// Remove the hub's settings from the node dir `dir`, as a new enrollment starts without them.
pub fn remove(dir: &Path) -> Result<()> {
    let path = dir.join(FILE);
    match std::fs::remove_file(&path) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            Err(e).with_context(|| format!("removing {}", path.display()))
        }
        _ => Ok(()),
    }
}

/// Lay `settings` under `table`, a local config file's: each key the table leaves unset is
/// filled in. Returns the entries taken.
pub fn merge(
    table: &mut toml::Table,
    settings: &BTreeMap<String, Value>,
) -> BTreeMap<String, Value> {
    let mut taken = BTreeMap::new();
    for (key, value) in settings {
        // The file is only data: only keys the hub may set are taken, as when they were saved.
        // Their values were checked then and are not again; one the config refuses fails its
        // loading, which then sets the hub's settings aside.
        let Some(toml) = allowed(key)
            .then(|| toml::Value::try_from(value).ok())
            .flatten()
        else {
            continue;
        };
        if insert_unset(table, key, toml) {
            taken.insert(key.clone(), value.clone());
        }
    }
    taken
}

/// Set dotted `key` to `value` unless already set, creating parent tables as needed.
/// Return whether the value was inserted.
fn insert_unset(table: &mut toml::Table, key: &str, value: toml::Value) -> bool {
    let (parents, leaf) = match key.rsplit_once('.') {
        Some((parents, leaf)) => (parents.split('.').collect(), leaf),
        None => (Vec::new(), key),
    };
    let mut at = table;
    for part in parents {
        let next = at
            .entry(part)
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        // Not a table: the file's own mistake, which loading it reports.
        let toml::Value::Table(next) = next else {
            return false;
        };
        at = next;
    }
    if at.contains_key(leaf) {
        return false;
    }
    at.insert(leaf.to_string(), value);
    true
}

/// Whether dotted `key` is set in `table`.
pub(crate) fn is_set(table: &toml::Table, key: &str) -> bool {
    let mut at = table;
    let mut parts = key.split('.').peekable();
    while let Some(part) = parts.next() {
        match (at.get(part), parts.peek()) {
            (None, _) => return false,
            (Some(_), None) => return true,
            (Some(toml::Value::Table(next)), Some(_)) => at = next,
            (Some(_), Some(_)) => return false,
        }
    }
    false
}

/// The hub's `wanted` settings checked against `local`, the node's config file: the entries
/// the node takes, and why it refuses the others. An entry must be one the hub may set, of
/// its key's type and a value the key takes, and leave the config loadable with the entries
/// taken before it.
pub fn check(
    local: &toml::Table,
    wanted: &BTreeMap<String, Value>,
) -> (BTreeMap<String, Value>, BTreeMap<String, String>) {
    let mut taken = BTreeMap::new();
    let mut refused = BTreeMap::new();
    for (key, value) in wanted {
        let mut with = taken.clone();
        with.insert(key.clone(), value.clone());
        match check_entry(key, value).and_then(|()| loads(local, &with).map(drop)) {
            Ok(()) => taken = with,
            Err(why) => {
                refused.insert(key.clone(), why);
            }
        }
    }
    (taken, refused)
}

/// That the hub may set `key` to `value`, judged on its own.
fn check_entry(key: &str, value: &Value) -> Result<(), String> {
    if !allowed(key) {
        return Err("not a setting the hub may set".to_string());
    }
    let toml = toml::Value::try_from(value).map_err(|e| format!("not a TOML value: {e}"))?;
    if key == "registry" {
        check_registry(&toml)?;
    }
    let alone = loads(
        &toml::Table::new(),
        &BTreeMap::from([(key.to_string(), value.clone())]),
    )?;
    check_value(key, &alone).map_err(|e| format!("{e:#}"))
}

/// The config `settings` laid under `local` makes, or why it does not load.
fn loads(local: &toml::Table, settings: &BTreeMap<String, Value>) -> Result<Config, String> {
    let mut table = local.clone();
    merge(&mut table, settings);
    // One line, for a report.
    crate::config::from_table(table).map_err(|e| format!("{e:#}").replace('\n', " "))
}

/// That `cfg` holds a value `key` takes, beyond its type.
fn check_value(key: &str, cfg: &Config) -> Result<()> {
    let vm = &cfg.executor.vm;
    let schedule = &cfg.executor.schedule;
    let at_least_one = |n: u32| match n {
        0 => anyhow::bail!("must be at least 1"),
        _ => Ok(()),
    };
    match key {
        "executor.schedule.mem_budget" => crate::vm::budget_mib(cfg).transpose().map(drop),
        "executor.schedule.disk_default" => schedule
            .disk_default
            .as_deref()
            .map_or(Ok(0), crate::vm::parse_gib)
            .map(drop),
        "executor.vm.mem" => crate::vm::parse_gib(&vm.mem).map(drop),
        "executor.vm.max_mem" => vm
            .max_mem
            .as_deref()
            .map_or(Ok(0), crate::vm::parse_gib)
            .map(drop),
        "executor.vm.cpus" => at_least_one(vm.cpus),
        "executor.vm.max_cpus" => vm.max_cpus.map_or(Ok(()), at_least_one),
        _ => Ok(()),
    }
}

/// That a `[registry]` from the hub names a remote registry, and nothing of the node's: no
/// path, no credential.
fn check_registry(value: &toml::Value) -> Result<(), String> {
    let toml::Value::Table(table) = value else {
        return Err("not a table".to_string());
    };
    if let Some(key) = table.keys().find(|k| !REGISTRY_KEYS.contains(&k.as_str())) {
        return Err(format!(
            "`{key}` is the node's own to set: the hub may name only {}",
            REGISTRY_KEYS.join(", ")
        ));
    }
    match table.get("repo").and_then(toml::Value::as_str) {
        Some(repo) if crate::config::Registry::local_root_of(repo).is_some() => {
            Err("`repo` names a store on the host, not a registry".to_string())
        }
        _ => Ok(()),
    }
}

/// Every key the hub may set, its value in `cfg` and where it comes from, with the hub's
/// entries `refused`.
fn report(cfg: &Config, refused: &BTreeMap<String, String>) -> SettingsReport {
    let effective = KEYS
        .iter()
        .map(|(key, read)| {
            let source = if is_set(&cfg.layers.local, key) {
                SettingSource::Local
            } else if cfg.layers.hub.contains_key(*key) {
                SettingSource::Hub
            } else {
                SettingSource::Default
            };
            let value = read(cfg);
            (key.to_string(), Setting { value, source })
        })
        .collect();
    SettingsReport {
        effective,
        refused: refused.clone(),
    }
}

/// The entries from `saved` that fill unset keys in `local`.
fn taken(local: &toml::Table, saved: Option<&Saved>) -> BTreeMap<String, Value> {
    let mut table = local.clone();
    merge(
        &mut table,
        saved.map(|s| &s.settings).unwrap_or(&BTreeMap::new()),
    )
}

/// The hub's settings as `vk node run` holds them.
#[derive(Debug)]
pub struct Held {
    /// The local config file the running config was loaded from, which the hub's entries are
    /// checked against.
    local: toml::Table,
    /// The entries the running config would take of what `settings.json` held as it started:
    /// what it took, unless loading ignored them, which loading it again would do too.
    loaded: BTreeMap<String, Value>,
    /// What `settings.json` holds.
    saved: Option<Saved>,
    report: SettingsReport,
}

impl Held {
    /// The hub's settings `cfg` was loaded with, and what the node dir `dir` holds of them for
    /// `issuer`.
    pub fn new(cfg: &Config, dir: &Path, issuer: &Issuer) -> Held {
        let saved = read(dir)
            .ok()
            .filter(|s| s.hub == issuer.hub && s.node_id == issuer.node_id);
        let refused = saved
            .as_ref()
            .map(|s| s.refused.clone())
            .unwrap_or_default();
        Held {
            local: cfg.layers.local.clone(),
            loaded: taken(&cfg.layers.local, saved.as_ref()),
            report: report(cfg, &refused),
            saved,
        }
    }

    /// Take the settings of `desired`, from `issuer`, into the node dir `dir`, before its
    /// generation is recorded as applied: checked, and written whole when they changed, or
    /// removed when there are none. A refused entry is left out, and reported.
    pub fn take(&mut self, dir: &Path, issuer: &Issuer, desired: &DesiredState) -> Result<()> {
        let (settings, refused) = check(&self.local, &desired.settings);
        let saved = Saved {
            hub: issuer.hub.clone(),
            node_id: issuer.node_id.clone(),
            generation: desired.generation,
            settings,
            refused,
        };
        let unchanged = self.saved.as_ref().is_some_and(|s| {
            (&s.hub, &s.node_id, &s.settings, &s.refused)
                == (&saved.hub, &saved.node_id, &saved.settings, &saved.refused)
        });
        if unchanged || (self.saved.is_none() && desired.settings.is_empty()) {
            return Ok(());
        }
        for (key, why) in &saved.refused {
            say!(
                "refused the hub's setting {}: {why}",
                vk_hub_proto::display_safe(key)
            );
        }
        if desired.settings.is_empty() {
            remove(dir)?;
            self.saved = None;
        } else {
            let path = dir.join(FILE);
            let json = serde_json::to_vec_pretty(&saved).context("encoding the hub's settings")?;
            vk_fs::write_atomic(&path, &json, 0o600)
                .with_context(|| format!("writing {}", path.display()))?;
            self.saved = Some(saved);
        }
        self.report.refused = self
            .saved
            .as_ref()
            .map(|s| s.refused.clone())
            .unwrap_or_default();
        Ok(())
    }

    /// Whether the config would take other entries than the running one did: the node must
    /// load its config again.
    pub fn changed(&self) -> bool {
        taken(&self.local, self.saved.as_ref()) != self.loaded
    }

    pub fn report(&self) -> &SettingsReport {
        &self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn table(text: &str) -> toml::Table {
        toml::from_str(text).unwrap()
    }

    fn wanted(entries: &[(&str, Value)]) -> BTreeMap<String, Value> {
        entries
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    /// A key the file sets, even to its default, stays the file's; `[registry]` is the file's
    /// whole when it has one.
    #[test]
    fn the_local_file_wins_key_by_key() {
        let mut local = table("[executor.vm]\ncpus = 4\n[registry]\nrepo = \"/srv/store\"\n");
        let taken = merge(
            &mut local,
            &wanted(&[
                ("executor.vm.cpus", json!(8)),
                ("executor.vm.max_cpus", json!(16)),
                ("executor.schedule.mem_budget", json!("40G")),
                ("registry", json!({"repo": "reg.example.com/ci"})),
                ("state_dir", json!("/elsewhere")),
            ]),
        );
        assert_eq!(
            taken.keys().collect::<Vec<_>>(),
            ["executor.schedule.mem_budget", "executor.vm.max_cpus"]
        );
        let cfg = crate::config::from_table(local).unwrap();
        assert_eq!(cfg.executor.vm.cpus, 4);
        assert_eq!(cfg.executor.vm.max_cpus, Some(16));
        assert_eq!(cfg.registry.unwrap().repo, "/srv/store");
        assert_eq!(cfg.state_dir, None);
    }

    /// Each entry is judged on its own; one refused leaves the others applied.
    #[test]
    fn entries_off_the_list_or_of_the_wrong_kind_are_refused() {
        let local = table("[executor.vm]\ncpus = 2\n");
        let (taken, refused) = check(
            &local,
            &wanted(&[
                ("executor.vm.max_cpus", json!(16)),
                // Taken though the file sets it: the file still wins.
                ("executor.vm.cpus", json!(8)),
                ("executor.vm.mem", json!("lots")),
                ("executor.vm.max_mem", json!(8)),
                ("executor.schedule.mem_budget", json!("40")),
                ("executor.schedule.cpu_overcommit", json!(0)),
                ("state_dir", json!("/elsewhere")),
                ("egress.allow_ip", json!([])),
                ("node.release_keys", json!([])),
                ("executor.vm", json!({"cpus": 1})),
                ("image_cache_idle_secs", json!(null)),
                ("executor.schedule.from_history", json!(true)),
            ]),
        );
        assert_eq!(
            taken,
            wanted(&[
                ("executor.schedule.from_history", json!(true)),
                ("executor.vm.cpus", json!(8)),
                ("executor.vm.max_cpus", json!(16)),
            ])
        );
        assert_eq!(
            refused.keys().collect::<Vec<_>>(),
            [
                "egress.allow_ip",
                "executor.schedule.cpu_overcommit",
                "executor.schedule.mem_budget",
                "executor.vm",
                "executor.vm.max_mem",
                "executor.vm.mem",
                "image_cache_idle_secs",
                "node.release_keys",
                "state_dir",
            ]
        );
        assert!(
            refused["executor.vm.max_mem"].contains("invalid type"),
            "{refused:?}"
        );
        assert!(refused["state_dir"].contains("may set"), "{refused:?}");
        assert!(
            refused["executor.schedule.cpu_overcommit"].contains("positive"),
            "{refused:?}"
        );
    }

    /// The hub names a remote registry and how to reach it, never a credential or a path, and
    /// an entry that would leave the config unloadable beside the file's is refused.
    #[test]
    fn a_registry_from_the_hub_carries_nothing_of_the_nodes() {
        let none = toml::Table::new();
        let one = |registry: Value| check(&none, &wanted(&[("registry", registry)])).1;
        assert!(one(json!({"repo": "reg.example.com/ci", "guest_credential": "job"})).is_empty());
        for (registry, why) in [
            (
                json!({"repo": "r/ci", "password_file": "/p"}),
                "password_file",
            ),
            (json!({"repo": "r/ci", "ca_file": "/ca.pem"}), "ca_file"),
            (json!({"repo": "r/ci", "username": "u"}), "username"),
            (json!({"repo": "/srv/store"}), "store on the host"),
            (
                json!({"repo": "r/ci", "pipeline_root": "A"}),
                "pipeline_root",
            ),
            (json!("reg.example.com"), "not a table"),
        ] {
            let refused = one(registry);
            assert!(refused["registry"].contains(why), "{refused:?}");
        }
        let lends = json!({"repo": "r/ci", "proxy_guests": true});
        assert!(one(lends.clone()).is_empty());
        let building = table("[executor]\nguest_build = true\n");
        let refused = check(&building, &wanted(&[("registry", lends)])).1;
        assert!(refused["registry"].contains("guest_build"), "{refused:?}");
    }

    fn issuer() -> Issuer {
        Issuer {
            hub: "https://hub".into(),
            node_id: "ab".repeat(16),
        }
    }

    fn desired(generation: u64, settings: &[(&str, Value)]) -> DesiredState {
        DesiredState {
            generation,
            ceiling: None,
            acquisition: vk_hub_proto::Acquisition::Run,
            egress: None,
            settings: wanted(settings),
        }
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("vk-hubset-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Taken settings are written whole with where they came from, kept while they do not
    /// change, and removed when the hub sends none; the node reloads only when what its config
    /// would take moves, masked entries aside.
    #[test]
    fn taken_settings_are_saved_and_tell_when_to_reload() {
        let dir = scratch("take");
        let cfg = crate::config::from_table(table("[executor.vm]\ncpus = 2\n")).unwrap();
        let cfg = Config {
            layers: crate::config::Layers {
                local: table("[executor.vm]\ncpus = 2\n"),
                hub: BTreeMap::new(),
            },
            ..cfg
        };
        let mut held = Held::new(&cfg, &dir, &issuer());
        assert!(!held.changed());
        assert_eq!(
            held.report().effective["executor.vm.cpus"],
            Setting {
                value: Some(json!(2)),
                source: SettingSource::Local
            }
        );
        // Masked by the file: saved, but nothing to reload.
        held.take(
            &dir,
            &issuer(),
            &desired(3, &[("executor.vm.cpus", json!(8))]),
        )
        .unwrap();
        assert!(!held.changed());
        let saved = read(&dir).unwrap();
        assert_eq!((saved.generation, saved.settings.len()), (3, 1));
        held.take(
            &dir,
            &issuer(),
            &desired(
                4,
                &[
                    ("executor.vm.cpus", json!(8)),
                    ("executor.vm.max_cpus", json!(16)),
                    ("state_dir", json!("/x")),
                ],
            ),
        )
        .unwrap();
        assert!(held.changed());
        let saved = read(&dir).unwrap();
        assert_eq!(saved.generation, 4);
        assert_eq!(saved.refused.keys().collect::<Vec<_>>(), ["state_dir"]);
        assert_eq!(held.report().refused, saved.refused);
        // The same again in a later generation: the file stays as it was.
        held.take(
            &dir,
            &issuer(),
            &desired(
                5,
                &[
                    ("executor.vm.cpus", json!(8)),
                    ("executor.vm.max_cpus", json!(16)),
                    ("state_dir", json!("/x")),
                ],
            ),
        )
        .unwrap();
        assert_eq!(read(&dir).unwrap().generation, 4);
        held.take(&dir, &issuer(), &desired(6, &[])).unwrap();
        assert!(read(&dir).is_err_and(|e| super::super::is_not_found(&e)));
        assert!(!held.changed());
        assert!(held.report().refused.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
