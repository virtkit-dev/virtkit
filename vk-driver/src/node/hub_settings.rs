//! The fleet hub's settings on a node (`docs/fleet-design.md`, *Hub settings*): the entries of
//! the hub's desired state the node takes ([`Held::take`]), kept in
//! `<state_dir>/node/settings.json` with the hub, node ID and generation they came from, and
//! laid under the local config file by every `vk` on the enrolled host ([`layer`], [`merge`]).
//! A key the file sets, even to its default, is never overridden, and `[registry]` is taken
//! whole or not at all. Only the keys of [`KEYS`] may come from the hub; never a path or a
//! credential. A registry the hub names lends guests the job's token alone, and its CA, which
//! the hub sends as content, is pinned beside the settings as `registry-ca-<hash>.pem`.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vk_hub_proto::settings::REGISTRY_KEYS;
use vk_hub_proto::{DesiredState, Setting, SettingSource, SettingsReport};

use super::state::Issuer;
use super::{read_enrollment, read_nofollow};
use crate::config::Config;

const FILE: &str = "settings.json";
/// The CAs of the registries the hub names, pinned from their `ca_pem`, each named by its
/// content ([`ca_name`]) so a job keeps the one it started with.
const REGISTRY_CA: &str = "registry-ca-";
/// Retain retired CAs for the maximum job-token lifetime (`max_job_token_secs` at most),
/// so jobs that started with them keep registry access until their tokens expire.
const RETIRED_CA_KEPT: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 3600);

/// Reads a key's effective value off a loaded config.
type Read = fn(&Config) -> Option<Value>;

/// The keys the hub may set ([`vk_hub_proto::settings::KEYS`]), by dotted key, and how to read
/// each one's effective value: its default where it has one, as resolved for this host, `None`
/// where unset means none.
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
    ("executor.windows_cache_idle_secs", |c| {
        json(&c.windows_cache_idle().as_secs())
    }),
    ("executor.windows_media", |c| {
        json(&c.executor.windows_media)
    }),
    ("registry", |c| json(&c.registry)),
];

/// `value` as JSON; `None` for an unset `Option`.
fn json<T: Serialize>(value: &T) -> Option<Value> {
    serde_json::to_value(value).ok().filter(|v| !v.is_null())
}

fn allowed(key: &str) -> bool {
    vk_hub_proto::settings::kind(key).is_some()
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
    Some(for_node(&saved.settings, &dir))
}

/// `settings` as the config of a node whose node dir is `dir` takes them: a registry's
/// `ca_pem` becomes `ca_file`, naming where the node pinned it, and its guests get the job's
/// token unless the hub said so already. A key the hub may not name is left out, even from
/// the node's own file, and a registry whose CA cannot be named is left out whole, rather than
/// reached through the system's roots.
fn for_node(settings: &BTreeMap<String, Value>, dir: &Path) -> BTreeMap<String, Value> {
    let mut out = settings.clone();
    let Some(Value::Object(registry)) = out.get_mut("registry") else {
        return out;
    };
    registry.retain(|key, _| REGISTRY_KEYS.contains(&key.as_str()));
    if let Some(pem) = registry.remove("ca_pem") {
        let path = pem
            .as_str()
            .map(|pem| dir.join(ca_name(pem)))
            .and_then(|path| path.to_str().map(Value::from));
        match path {
            Some(path) => {
                registry.insert("ca_file".to_string(), path);
            }
            None => {
                out.remove("registry");
                return out;
            }
        }
    }
    registry
        .entry("guest_credential")
        .or_insert_with(|| Value::from("job"));
    out
}

/// The name `pem` is pinned under in the node dir.
fn ca_name(pem: &str) -> String {
    use sha2::Digest;
    ca_name_of(&vk_hub_proto::to_hex(&sha2::Sha256::digest(pem.as_bytes())))
}

/// The name a CA whose SHA-256 is `hash`, hex, is pinned under in the node dir.
fn ca_name_of(hash: &str) -> String {
    format!("{REGISTRY_CA}{}.pem", hash.get(..16).unwrap_or(hash))
}

/// Where the node dir `dir` pins a CA whose SHA-256 is `hash`, hex: the `ca_file` of a
/// `[registry]` the hub names with it.
pub fn ca_file(dir: &Path, hash: &str) -> std::path::PathBuf {
    dir.join(ca_name_of(hash))
}

/// The registry CA `settings` carry, as the hub sent it.
fn ca_pem(settings: &BTreeMap<String, Value>) -> Option<&str> {
    settings.get("registry")?.get("ca_pem")?.as_str()
}

/// The names of the registry CAs pinned in the node dir `dir`.
fn pinned_cas(dir: &Path) -> Result<Vec<std::ffi::OsString>> {
    let mut names = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(names),
        entries => entries.with_context(|| format!("listing {}", dir.display()))?,
    };
    for entry in entries {
        let name = entry
            .with_context(|| format!("listing {}", dir.display()))?
            .file_name();
        if name.as_encoded_bytes().starts_with(REGISTRY_CA.as_bytes()) {
            names.push(name);
        }
    }
    Ok(names)
}

/// Remove the registry CAs pinned in the node dir `dir` but `current`, retired longer ago than
/// [`RETIRED_CA_KEPT`].
fn prune_cas(dir: &Path, current: Option<&str>) -> Result<()> {
    for name in pinned_cas(dir)? {
        if current.is_some_and(|c| name == c) {
            continue;
        }
        let path = dir.join(&name);
        let age = std::fs::symlink_metadata(&path)
            .and_then(|m| m.modified())
            .map(|t| t.elapsed().unwrap_or_default());
        match age {
            Ok(age) if age < RETIRED_CA_KEPT => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            _ => remove_file(&path)?,
        }
    }
    Ok(())
}

/// Remove the hub's settings from the node dir `dir`, as a new enrollment starts without them.
pub fn remove(dir: &Path) -> Result<()> {
    remove_file(&dir.join(FILE))?;
    for name in pinned_cas(dir)? {
        remove_file(&dir.join(name))?;
    }
    Ok(())
}

/// Remove `path`, which may be gone already.
fn remove_file(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
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

/// Check the hub's `wanted` settings against the node's `local` config and node directory
/// `dir`, returning accepted entries and refusal reasons. Each entry must be allowed, have
/// a valid type and value, and leave the config loadable with previously accepted entries.
pub fn check(
    local: &toml::Table,
    wanted: &BTreeMap<String, Value>,
    dir: &Path,
) -> (BTreeMap<String, Value>, BTreeMap<String, String>) {
    let mut taken = BTreeMap::new();
    let mut refused = BTreeMap::new();
    for (key, value) in wanted {
        let mut with = taken.clone();
        with.insert(key.clone(), value.clone());
        match check_entry(key, value, dir).and_then(|()| loads(local, &with, dir).map(drop)) {
            Ok(()) => taken = with,
            Err(why) => {
                refused.insert(key.clone(), why);
            }
        }
    }
    (taken, refused)
}

/// That the hub may set `key` to `value`, judged on its own: by the hub's own check of it
/// first, so it holds to the bounds the hub does.
fn check_entry(key: &str, value: &Value, dir: &Path) -> Result<(), String> {
    let Some(kind) = vk_hub_proto::settings::kind(key) else {
        return Err("not a setting the hub may set".to_string());
    };
    kind.check(value)?;
    let toml = toml::Value::try_from(value).map_err(|e| format!("not a TOML value: {e}"))?;
    if key == "registry" {
        check_registry(&toml)?;
        let alone = BTreeMap::from([(key.to_string(), value.clone())]);
        if !for_node(&alone, dir).contains_key(key) {
            return Err(format!(
                "the node dir {} is not UTF-8, so no config can name the CA",
                dir.display()
            ));
        }
    }
    let alone = loads(
        &toml::Table::new(),
        &BTreeMap::from([(key.to_string(), value.clone())]),
        dir,
    )?;
    check_value(key, &alone).map_err(|e| format!("{e:#}"))
}

/// Load `settings` beneath `local` for node directory `dir`, or return the load error.
fn loads(
    local: &toml::Table,
    settings: &BTreeMap<String, Value>,
    dir: &Path,
) -> Result<Config, String> {
    let mut table = local.clone();
    merge(&mut table, &for_node(settings, dir));
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

/// That a `[registry]` from the hub, which the hub's own check of it passed, has a `ca_pem`
/// that holds certificates.
fn check_registry(value: &toml::Value) -> Result<(), String> {
    match value.get("ca_pem").and_then(toml::Value::as_str) {
        Some(pem) => super::roots_from_pem(pem.as_bytes(), Path::new("`ca_pem`"))
            .map(drop)
            .map_err(|e| format!("{e:#}")),
        None => Ok(()),
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
            } else if cfg.layers.detected.contains(key) {
                SettingSource::Detected
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
        let (settings, refused) = check(&self.local, &desired.settings, dir);
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
        let old = self.saved.as_ref().and_then(|s| ca_pem(&s.settings));
        let new = ca_pem(&saved.settings);
        // Pinned first, so the settings never name a CA the node does not hold.
        let pin = |pem: &str| {
            let path = dir.join(ca_name(pem));
            vk_fs::write_atomic(&path, pem.as_bytes(), 0o600)
                .with_context(|| format!("writing {}", path.display()))
        };
        if let Some(pem) = new {
            pin(pem)?;
        }
        // Rewrite the retired CA to restart retention while existing jobs can still use it.
        if let Some(pem) = old.filter(|o| Some(*o) != new) {
            pin(pem)?;
        }
        // The node's own access is bound to the registry the hub named: a new one is the hub's
        // to send.
        let registry = |s: Option<&Saved>| s.and_then(|s| s.settings.get("registry")).cloned();
        if registry(self.saved.as_ref()) != registry(Some(&saved)) {
            super::registry_access::clear(dir)?;
        }
        let path = dir.join(FILE);
        if desired.settings.is_empty() {
            remove_file(&path)?;
        } else {
            let json = serde_json::to_vec_pretty(&saved).context("encoding the hub's settings")?;
            vk_fs::write_atomic(&path, &json, 0o600)
                .with_context(|| format!("writing {}", path.display()))?;
        }
        let current = new.map(ca_name);
        if let Err(e) = prune_cas(dir, current.as_deref()) {
            say!("could not remove a retired registry CA: {e:#}");
        }
        self.saved = (!desired.settings.is_empty()).then_some(saved);
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

    /// The node reports every key the hub may set, as the hub lists them, and takes a value of
    /// each kind the hub checks it to be.
    #[test]
    fn the_keys_are_those_the_hub_may_set() {
        let ours: Vec<&str> = KEYS.iter().map(|(k, _)| *k).collect();
        let hubs: Vec<&str> = vk_hub_proto::settings::KEYS
            .iter()
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(ours, hubs);
        let dir = Path::new("/state/node");
        for (key, text) in [
            ("executor.schedule.mem_budget", "50%"),
            ("executor.schedule.mem_budget", "40G"),
            ("executor.schedule.from_history", "true"),
            ("executor.schedule.disk_default", "20G"),
            ("executor.schedule.cpu_overcommit", "1.5"),
            ("executor.schedule.cpu_overcommit", "3"),
            ("executor.schedule.wait_timeout_secs", "60"),
            ("executor.vm.cpus", "2"),
            ("executor.vm.max_mem", "64G"),
            ("image_cache_idle_secs", "0"),
            ("executor.windows_cache_idle_secs", "86400"),
            (
                "executor.windows_media",
                "abababababababababababababababababababababababababababababababab",
            ),
            ("executor.windows_media", "none"),
        ] {
            let value = vk_hub_proto::settings::kind(key)
                .unwrap()
                .parse(text)
                .unwrap();
            let (_, refused) = check(&toml::Table::new(), &wanted(&[(key, value)]), dir);
            assert!(refused.is_empty(), "{key} = {text}: {refused:?}");
        }
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

    /// Local settings override the hub's Windows settings. An empty local `windows_media`
    /// approves no media and is reported as local, regardless of the hub's list.
    #[test]
    fn the_windows_settings_from_the_hub_load() {
        let digest = "ab".repeat(32);
        let hub = wanted(&[
            ("executor.windows_media", json!([digest])),
            ("executor.windows_cache_idle_secs", json!(3600)),
        ]);
        let loaded = |text: &str| {
            let mut local = table(text);
            let taken = merge(&mut local, &hub);
            let cfg = crate::config::from_table(local).unwrap();
            Config {
                layers: crate::config::Layers {
                    local: table(text),
                    hub: taken,
                    detected: Default::default(),
                },
                ..cfg
            }
        };
        let cfg = loaded("");
        assert_eq!(cfg.executor.windows_media, std::slice::from_ref(&digest));
        assert_eq!(cfg.windows_cache_idle().as_secs(), 3600);
        let effective = report(&cfg, &BTreeMap::new()).effective;
        assert_eq!(
            effective["executor.windows_media"],
            Setting {
                value: Some(json!([digest])),
                source: SettingSource::Hub
            }
        );
        let cfg = loaded("[executor]\nwindows_media = []\n");
        assert!(cfg.executor.windows_media.is_empty());
        assert_eq!(cfg.windows_cache_idle().as_secs(), 3600);
        let effective = report(&cfg, &BTreeMap::new()).effective;
        assert_eq!(
            effective["executor.windows_media"],
            Setting {
                value: Some(json!([])),
                source: SettingSource::Local
            }
        );
        assert_eq!(
            effective["executor.windows_cache_idle_secs"].source,
            SettingSource::Hub
        );
        let other = "cd".repeat(32);
        let cfg = loaded(&format!(
            "[executor]\nwindows_media = [\"{other}\"]\nwindows_cache_idle_secs = 60\n"
        ));
        assert_eq!(cfg.executor.windows_media, std::slice::from_ref(&other));
        assert_eq!(cfg.windows_cache_idle().as_secs(), 60);
        let effective = report(&cfg, &BTreeMap::new()).effective;
        assert_eq!(
            effective["executor.windows_cache_idle_secs"],
            Setting {
                value: Some(json!(60)),
                source: SettingSource::Local
            }
        );
        assert_eq!(
            effective["executor.windows_media"].source,
            SettingSource::Local
        );
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
                ("executor.schedule.wait_timeout_secs", json!(u64::MAX)),
                (
                    "executor.schedule.disk_default",
                    json!("18014398509481984G"),
                ),
                ("state_dir", json!("/elsewhere")),
                ("egress.allow_ip", json!([])),
                ("node.release_keys", json!([])),
                ("executor.vm", json!({"cpus": 1})),
                ("image_cache_idle_secs", json!(null)),
                ("executor.windows_media", json!(["not-a-digest"])),
                ("executor.windows_cache_idle_secs", json!(0)),
                ("executor.schedule.from_history", json!(true)),
            ]),
            Path::new("/state/node"),
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
                "executor.schedule.disk_default",
                "executor.schedule.mem_budget",
                "executor.schedule.wait_timeout_secs",
                "executor.vm",
                "executor.vm.max_mem",
                "executor.vm.mem",
                "executor.windows_cache_idle_secs",
                "executor.windows_media",
                "image_cache_idle_secs",
                "node.release_keys",
                "state_dir",
            ]
        );
        assert!(
            refused["executor.vm.max_mem"].contains("expected a size"),
            "{refused:?}"
        );
        assert!(refused["state_dir"].contains("may set"), "{refused:?}");
        assert!(
            refused["executor.schedule.cpu_overcommit"].contains("positive"),
            "{refused:?}"
        );
    }

    /// The hub names a remote registry and how to reach it, never a credential or a path, nor
    /// a guest credential but the job's, and a CA only as certificates.
    #[test]
    fn a_registry_from_the_hub_carries_nothing_of_the_nodes() {
        let none = toml::Table::new();
        let dir = Path::new("/state/node");
        let one = |registry: Value| check(&none, &wanted(&[("registry", registry)]), dir).1;
        assert!(one(json!({"repo": "reg.example.com/ci", "guest_credential": "job"})).is_empty());
        assert!(one(json!({"repo": "r/ci", "ca_pem": CA})).is_empty());
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
            (json!("reg.example.com"), "a table"),
            (
                json!({"repo": "r/ci", "guest_credential": "node"}),
                "may only be \"job\"",
            ),
            (
                json!({"repo": "r/ci", "ca_pem": "not PEM"}),
                "no certificate",
            ),
            (json!({"repo": "r/ci", "ca_pem": 1}), "a string"),
            (
                json!({"repo": "r/ci", "ca_pem": "x".repeat(vk_hub_proto::settings::MAX_CA_PEM + 1)}),
                "over",
            ),
        ] {
            let refused = one(registry);
            assert!(refused["registry"].contains(why), "{refused:?}");
        }
        // Guests get the job's token alone, so they may build beside a proxy.
        let lends = json!({"repo": "r/ci", "proxy_guests": true});
        let building = table("[executor]\nguest_build = true\n");
        assert!(
            check(&building, &wanted(&[("registry", lends)]), dir)
                .1
                .is_empty()
        );
    }

    /// A CA the hub sends as content is named where the node pins it, and a hub registry
    /// lends guests the job's token; an entry the hub may not name, found in the node's file,
    /// is dropped rather than taken.
    #[test]
    fn a_hub_registry_is_loaded_with_its_pinned_ca_and_job_tokens() {
        let dir = Path::new("/state/node");
        let settings = wanted(&[(
            "registry",
            json!({"repo": "reg.example.com/ci", "ca_pem": CA, "token_file": "/t"}),
        )]);
        let cfg = loads(&toml::Table::new(), &settings, dir).unwrap();
        let rg = cfg.registry.unwrap();
        assert_eq!(rg.ca_file.as_deref(), Some(dir.join(ca_name(CA)).as_path()));
        assert_eq!(rg.token_file, None);
        assert!(rg.lends_job_token());
        let plain = wanted(&[("registry", json!({"repo": "reg.example.com/ci"}))]);
        let rg = loads(&toml::Table::new(), &plain, dir)
            .unwrap()
            .registry
            .unwrap();
        assert_eq!(rg.ca_file, None);
        assert!(rg.lends_job_token());
    }

    const CA: &str = include_str!("../../../vk-hub/src/testdata/tls-ca.pem");

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
    fn another_registry_drops_the_node_s_access() {
        let dir = scratch("access");
        let cfg = crate::config::from_table(toml::Table::new()).unwrap();
        let mut held = Held::new(&cfg, &dir, &issuer());
        let file = dir.join("registry-access.json");
        let registry = |repo: &str| json!({"repo": repo, "guest_credential": "job"});
        held.take(
            &dir,
            &issuer(),
            &desired(1, &[("registry", registry("a.example"))]),
        )
        .unwrap();
        std::fs::write(&file, "{}").unwrap();
        // Other settings leave it.
        held.take(
            &dir,
            &issuer(),
            &desired(
                2,
                &[
                    ("registry", registry("a.example")),
                    ("executor.vm.cpus", json!(8)),
                ],
            ),
        )
        .unwrap();
        assert!(file.exists());
        held.take(
            &dir,
            &issuer(),
            &desired(3, &[("registry", registry("b.example"))]),
        )
        .unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn taken_settings_are_saved_and_tell_when_to_reload() {
        let dir = scratch("take");
        let cfg = crate::config::from_table(table("[executor.vm]\ncpus = 2\n")).unwrap();
        let cfg = Config {
            layers: crate::config::Layers {
                local: table("[executor.vm]\ncpus = 2\n"),
                hub: BTreeMap::new(),
                detected: ["executor.vm.max_cpus"].into(),
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
        let source = |key: &str| held.report().effective[key].source;
        assert_eq!(source("executor.vm.max_cpus"), SettingSource::Detected);
        assert_eq!(
            source("executor.schedule.disk_admission"),
            SettingSource::Default
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

    /// The hub's registry CA is pinned beside the settings, by content; one the hub no longer
    /// names is kept for the jobs that started with it until it has been retired a while.
    #[test]
    fn a_registry_ca_is_pinned_and_kept_for_jobs_that_use_it() {
        let dir = scratch("ca");
        let cfg = crate::config::from_table(toml::Table::new()).unwrap();
        let mut held = Held::new(&cfg, &dir, &issuer());
        let registry = |ca: Option<&str>| {
            let mut r = json!({"repo": "reg.example.com/ci"});
            if let Some(ca) = ca {
                r["ca_pem"] = json!(ca);
            }
            r
        };
        let pinned = || {
            let mut names: Vec<_> = pinned_cas(&dir)
                .unwrap()
                .into_iter()
                .map(|n| n.into_string().unwrap())
                .collect();
            names.sort();
            names
        };
        held.take(
            &dir,
            &issuer(),
            &desired(1, &[("registry", registry(Some(CA)))]),
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(dir.join(ca_name(CA))).unwrap(), CA);
        assert!(held.changed());
        // Another CA: the first stays for the jobs that use it.
        let other = format!("{CA}{CA}");
        held.take(
            &dir,
            &issuer(),
            &desired(2, &[("registry", registry(Some(&other)))]),
        )
        .unwrap();
        let mut both = vec![ca_name(CA), ca_name(&other)];
        both.sort();
        assert_eq!(pinned(), both);
        // Retired long enough ago, it goes at the next change.
        let old = std::time::SystemTime::now() - RETIRED_CA_KEPT;
        std::fs::File::options()
            .write(true)
            .open(dir.join(ca_name(CA)))
            .unwrap()
            .set_modified(old)
            .unwrap();
        held.take(
            &dir,
            &issuer(),
            &desired(3, &[("registry", registry(None))]),
        )
        .unwrap();
        assert_eq!(pinned(), [ca_name(&other)]);
        held.take(&dir, &issuer(), &desired(4, &[])).unwrap();
        assert!(read(&dir).is_err_and(|e| super::super::is_not_found(&e)));
        assert_eq!(pinned(), [ca_name(&other)]);
        remove(&dir).unwrap();
        assert!(pinned().is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
