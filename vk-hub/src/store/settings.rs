//! The hub's settings for its nodes (`docs/fleet-design.md`, *Hub settings*): a fleet-wide
//! layer and one per node, the node's winning key by key, expanded into each node's desired
//! state ([`DesiredState::settings`]) for the nodes that take them. `registry` names a registry
//! the hub manages, by ID, which a node is sent as the `[registry]` table that reaches it.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use vk_hub_proto::REGISTRY_ACCESS;
use vk_hub_proto::settings::{GUEST_CREDENTIAL, GUEST_CREDENTIAL_JOB_OR_NODE, Kind};
use vk_hub_proto::{DesiredState, STEERING};

use super::namespaces::{CI_PIPELINE, NAMESPACES, NamespaceRow, ns_range};
use super::registries::{REGISTRIES, RegistryRow};
use super::tools::TOOLS;
use super::{Db, NODES, NodeRow, NotEnrolled, append_audit, decode, encode, steer};

/// Key: [`FLEET`], or [`NODE_PREFIX`] and a node's ID. Value: JSON [`Layer`].
pub(super) const SETTINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("settings");

/// The fleet-wide layer's key.
const FLEET: &str = "fleet";
/// What a node's layer's key starts with.
const NODE_PREFIX: &str = "node/";

/// Settings by dotted key; `registry` a registry's ID.
pub type Layer = BTreeMap<String, Value>;

/// Every layer of the hub's settings.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Layers {
    pub fleet: Layer,
    /// By node ID; a node with none is left out.
    pub nodes: BTreeMap<String, Layer>,
}

impl Layers {
    /// What node `id` is given, before a registry is expanded: the fleet's settings, its own
    /// over them.
    pub fn merged(&self, id: &str) -> Layer {
        let mut out = self.fleet.clone();
        if let Some(own) = self.nodes.get(id) {
            out.extend(own.iter().map(|(k, v)| (k.clone(), v.clone())));
        }
        out
    }
}

/// The layers in `table`.
pub(super) fn layers_in(table: &impl ReadableTable<&'static str, &'static [u8]>) -> Result<Layers> {
    let mut layers = Layers::default();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let layer = decode::<Layer>(value.value())?;
        match key.value() {
            FLEET => layers.fleet = layer,
            key => {
                if let Some(id) = key.strip_prefix(NODE_PREFIX) {
                    layers.nodes.insert(id.to_string(), layer);
                }
            }
        }
    }
    Ok(layers)
}

/// The `[registry]` table a node is sent for registry `row`, whose namespaces are `namespaces`:
/// its bound URL, the CA the operator gave with it, and the root of its `ci-pipeline`
/// namespace's path, guests lent the job's token. `None` while no URL is bound; why a node
/// would refuse the table, which is then not sent.
pub fn registry_table(
    row: &RegistryRow,
    namespaces: &[NamespaceRow],
) -> Option<Result<Value, String>> {
    let url = row.url.as_deref()?;
    let (scheme, authority) = url.split_once("://")?;
    let mut table = serde_json::Map::new();
    table.insert("repo".into(), Value::from(authority));
    if scheme == "http" {
        table.insert("insecure".into(), Value::Bool(true));
    }
    if let Some(pem) = &row.ca_pem {
        table.insert("ca_pem".into(), Value::from(pem.as_str()));
    }
    if let Some(root) = namespaces
        .iter()
        .find(|ns| ns.name == CI_PIPELINE)
        .and_then(NamespaceRow::static_prefix)
    {
        table.insert("pipeline_root".into(), Value::from(root));
    }
    table.insert("guest_credential".into(), Value::from(GUEST_CREDENTIAL));
    let table = Value::Object(table);
    Some(node_takes(&table).map(|()| table))
}

/// That a node takes `table` as its `[registry]`, as it checks one: by the shared check, and
/// its CA's certificates parsed.
fn node_takes(table: &Value) -> Result<(), String> {
    Kind::Registry.check(table)?;
    match table.get("ca_pem").and_then(Value::as_str) {
        Some(pem) => vk_peer::net::roots_from_pem(pem.as_bytes(), Path::new("the CA"))
            .map(drop)
            .map_err(|e| format!("{e:#}")),
        None => Ok(()),
    }
}

/// The namespaces of registry `id` in `namespaces`.
fn namespaces_of(
    namespaces: &impl ReadableTable<&'static str, &'static [u8]>,
    id: &str,
) -> Result<Vec<NamespaceRow>> {
    let (start, end) = ns_range(id);
    let mut ns = Vec::new();
    for entry in namespaces.range(start.as_str()..end.as_str())? {
        ns.push(decode::<NamespaceRow>(entry?.1.value())?);
    }
    Ok(ns)
}

/// The hub's settings as they are sent: every layer, and each registry's table by ID.
struct Expanded {
    layers: Layers,
    registries: BTreeMap<String, Option<Value>>,
}

impl Expanded {
    /// Read in `txn`.
    fn read(txn: &redb::WriteTransaction) -> Result<Expanded> {
        Expanded::from_tables(
            &txn.open_table(SETTINGS)?,
            &txn.open_table(REGISTRIES)?,
            &txn.open_table(NAMESPACES)?,
        )
    }

    fn from_tables(
        settings: &impl ReadableTable<&'static str, &'static [u8]>,
        registries: &impl ReadableTable<&'static str, &'static [u8]>,
        namespaces: &impl ReadableTable<&'static str, &'static [u8]>,
    ) -> Result<Expanded> {
        let layers = layers_in(settings)?;
        let mut tables = BTreeMap::new();
        for entry in registries.iter()? {
            let (id, row) = entry?;
            let id = id.value().to_string();
            let row = decode::<RegistryRow>(row.value())?;
            let table = registry_table(&row, &namespaces_of(namespaces, &id)?);
            tables.insert(id, table.and_then(Result::ok));
        }
        Ok(Expanded {
            layers,
            registries: tables,
        })
    }

    /// What node `id`, whose row is `row`, is sent: nothing unless it takes the hub's settings,
    /// and no registry while the one named has no URL bound, a node would refuse its table, or
    /// it is gone. A node that takes its own registry access is told to lend its runner's guests
    /// theirs ([`GUEST_CREDENTIAL_JOB_OR_NODE`]).
    fn wanted(&self, id: &str, row: &NodeRow) -> BTreeMap<String, Value> {
        if !takes(row) {
            return BTreeMap::new();
        }
        let mut wanted = self.layers.merged(id);
        // The hub's own: what it builds on the node, never a setting of the node's.
        wanted.remove(crate::deploy::KEY);
        if let Some(named) = wanted.remove("registry")
            && let Some(Some(table)) = named.as_str().and_then(|r| self.registries.get(r))
        {
            let mut table = table.clone();
            if row.protocol.is_some_and(|v| v >= REGISTRY_ACCESS)
                && let Value::Object(t) = &mut table
            {
                t.insert(
                    "guest_credential".into(),
                    Value::from(GUEST_CREDENTIAL_JOB_OR_NODE),
                );
            }
            wanted.insert("registry".to_string(), table);
        }
        wanted
    }
}

/// Whether node `row` takes the hub's settings: it can be steered and announces them.
fn takes(row: &NodeRow) -> bool {
    row.protocol.is_none_or(|v| v >= STEERING)
        && row.inventory.as_ref().is_some_and(|i| i.hub_settings)
}

/// What node `id`, whose row is `row`, is sent of the hub's settings in `txn`
/// ([`Expanded::wanted`]), read only for a node that takes them.
pub(super) fn wanted_in(
    txn: &redb::WriteTransaction,
    id: &str,
    row: &NodeRow,
) -> Result<BTreeMap<String, Value>> {
    if !takes(row) {
        return Ok(BTreeMap::new());
    }
    Ok(Expanded::read(txn)?.wanted(id, row))
}

/// Give node `row` the settings `wanted` in its desired state, as [`steer`] makes a change.
/// `Some` with the new generation if that changed it.
pub(super) fn steer_settings(row: &mut NodeRow, wanted: BTreeMap<String, Value>) -> Option<u64> {
    steer(row, |d: &mut DesiredState| d.settings = wanted)
}

/// The audit line for [`steer_settings`] having moved a node to `generation`.
pub(super) fn settings_event(generation: u64) -> String {
    format!("sent the node the hub's settings (generation {generation})")
}

/// Format `value` for audit lines and the CLI. String lists, such as digests, use the
/// input syntax of `vk-hub settings set`.
pub fn shown(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Array(items) if items.is_empty() => "none".to_string(),
        Value::Array(items) if items.iter().all(Value::is_string) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(","),
        other => other.to_string(),
    }
}

/// Every key the hub may set: those it sends its nodes, then its own.
pub fn keys() -> impl Iterator<Item = &'static str> {
    vk_hub_proto::settings::KEYS
        .iter()
        .map(|(k, _)| *k)
        .chain([crate::deploy::KEY])
}

/// `value` for the hub's own `tools`, as kept: `builtin`, `none`, or the full sha256 of the
/// one definition in `tools` it names, by a prefix of at least 8 hex digits.
fn tools_value(
    value: &Value,
    tools: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<Value> {
    use crate::deploy::{BUILTIN, NONE};
    let Some(text) = value.as_str().map(str::trim) else {
        bail!("tools: expected {}", crate::deploy::DESCRIBE);
    };
    if text == BUILTIN || text == NONE {
        return Ok(Value::from(text));
    }
    if text.len() < 8
        || text.len() > 64
        || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        bail!("tools: expected {}", crate::deploy::DESCRIBE);
    }
    let mut found = Vec::new();
    for entry in tools.range(text..)? {
        let key = entry?.0.value().to_string();
        if !key.starts_with(text) {
            break;
        }
        found.push(key);
    }
    match found.as_slice() {
        [sha] => Ok(Value::from(sha.as_str())),
        [] => bail!("there are no tools {text}"),
        _ => bail!("{text} names more than one tools definition; give more digits"),
    }
}

/// Check that the hub may set `key` and that `value` is of its kind and within its bounds; for
/// `registry`, require a registry the hub manages with a bound URL, whose table a node would
/// take. A node may still refuse an entry its own config leaves unloadable.
fn check(
    key: &str,
    value: &Value,
    registries: &impl ReadableTable<&'static str, &'static [u8]>,
    namespaces: &impl ReadableTable<&'static str, &'static [u8]>,
) -> Result<()> {
    let Some(kind) = vk_hub_proto::settings::kind(key) else {
        bail!(
            "{key} is not a setting the hub may set; it may set {}",
            keys().collect::<Vec<_>>().join(", ")
        );
    };
    if kind != Kind::Registry {
        return kind.check(value).map_err(|e| anyhow::anyhow!("{key}: {e}"));
    }
    let Some(id) = value.as_str() else {
        bail!("registry: expected a registry's ID");
    };
    let row = registries
        .get(id)?
        .map(|g| decode::<RegistryRow>(g.value()))
        .transpose()?
        .with_context(|| format!("there is no registry {id}"))?;
    match registry_table(&row, &namespaces_of(namespaces, id)?) {
        None => bail!(
            "registry {id} has no URL bound; bind one first (vk-hub registries set-url {id} \
             <url> [--ca <file>])"
        ),
        Some(Err(why)) => bail!("nodes would refuse registry {id}: {why}"),
        Some(Ok(_)) => Ok(()),
    }
}

impl Db {
    /// The hub's settings, every layer.
    pub fn settings_layers(&self) -> Result<Layers> {
        let txn = self.db.begin_read().context("starting a read")?;
        layers_in(&txn.open_table(SETTINGS)?)
    }

    /// Set `key` to `value`, or unset it with `None`, fleet-wide or for `node` alone, audited
    /// as `actor`'s, and steer every node it reaches. Returns whether it changed, and the
    /// nodes whose desired state that moved.
    pub fn set_setting(
        &self,
        node: Option<&str>,
        key: &str,
        value: Option<Value>,
        actor: &str,
        now: u64,
    ) -> Result<(bool, Vec<String>)> {
        let txn = self.db.begin_write().context("starting a write")?;
        let (changed, steered) = set_in(&txn, node, key, value, actor, now)?;
        if !changed {
            txn.abort().context("dropping a write")?;
            return Ok((false, Vec::new()));
        }
        txn.commit().context("setting a hub setting")?;
        Ok((true, steered))
    }

    /// Steer every node's settings to what the hub's make them now ([`steer_settings`]); the
    /// nodes it changed. For a change the settings name but do not hold: a registry's URL, CA
    /// or namespaces, and the hub's start.
    pub fn steer_settings(&self, now: u64) -> Result<Vec<String>> {
        let txn = self.db.begin_write().context("starting a write")?;
        let changed = steer_all_in(&txn, now)?;
        txn.commit().context("steering the hub's settings")?;
        Ok(changed)
    }
}

/// [`Db::set_setting`] in `txn`: whether it changed, and the nodes it steered.
pub(super) fn set_in(
    txn: &redb::WriteTransaction,
    node: Option<&str>,
    key: &str,
    value: Option<Value>,
    actor: &str,
    now: u64,
) -> Result<(bool, Vec<String>)> {
    let value = match value {
        Some(value) if key == crate::deploy::KEY => {
            Some(tools_value(&value, &txn.open_table(TOOLS)?)?)
        }
        Some(value) => {
            check(
                key,
                &value,
                &txn.open_table(REGISTRIES)?,
                &txn.open_table(NAMESPACES)?,
            )?;
            Some(value)
        }
        None if keys().all(|k| k != key) => bail!("{key} is not a setting the hub may set"),
        None => None,
    };
    if let Some(id) = node
        && txn.open_table(NODES)?.get(id)?.is_none()
    {
        return Err(NotEnrolled(id.to_string()).into());
    }
    let slot = match node {
        Some(id) => format!("{NODE_PREFIX}{id}"),
        None => FLEET.to_string(),
    };
    let changed = {
        let mut table = txn.open_table(SETTINGS)?;
        let mut layer = table
            .get(slot.as_str())?
            .map(|g| decode::<Layer>(g.value()))
            .transpose()?
            .unwrap_or_default();
        let before = match &value {
            Some(v) => layer.insert(key.to_string(), v.clone()),
            None => layer.remove(key),
        };
        let changed = before != value;
        if changed {
            if layer.is_empty() {
                table.remove(slot.as_str())?;
            } else {
                table.insert(slot.as_str(), encode(&layer)?.as_slice())?;
            }
        }
        changed
    };
    if !changed {
        return Ok((false, Vec::new()));
    }
    let scope = match node {
        Some(id) => format!(" for node {id}"),
        None => " fleet-wide".to_string(),
    };
    let event = match &value {
        Some(v) => format!("{actor} set {key} = {}{scope}", shown(v)),
        None => format!("{actor} unset {key}{scope}"),
    };
    append_audit(txn, node, actor, &event, now)?;
    let steered = steer_all_in(txn, now)?;
    Ok((true, steered))
}

/// The fleet-wide value of `key` in `table`, if set.
pub(super) fn fleet_value(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<Value>> {
    Ok(table
        .get(FLEET)?
        .map(|g| decode::<Layer>(g.value()))
        .transpose()?
        .and_then(|mut layer| layer.remove(key)))
}

/// [`Db::steer_settings`] in `txn`, audited as the hub's.
fn steer_all_in(txn: &redb::WriteTransaction, now: u64) -> Result<Vec<String>> {
    let expanded = Expanded::read(txn)?;
    let mut changed = Vec::new();
    {
        let mut table = txn.open_table(NODES)?;
        let mut rows = Vec::new();
        for entry in table.iter()? {
            let (id, row) = entry?;
            rows.push((id.value().to_string(), decode::<NodeRow>(row.value())?));
        }
        for (id, mut row) in rows {
            let wanted = expanded.wanted(&id, &row);
            if let Some(generation) = steer_settings(&mut row, wanted) {
                table.insert(id.as_str(), encode(&row)?.as_slice())?;
                changed.push((id, generation));
            }
        }
    }
    for (id, generation) in &changed {
        append_audit(txn, Some(id), "hub", &settings_event(*generation), now)?;
    }
    Ok(changed.into_iter().map(|(id, _)| id).collect())
}

/// Remove node `id`'s layer in `txn`, as the node goes.
pub(super) fn remove_node_in(txn: &redb::WriteTransaction, id: &str) -> Result<()> {
    txn.open_table(SETTINGS)?
        .remove(format!("{NODE_PREFIX}{id}").as_str())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;
    use vk_hub_proto::{Acquisition, Inventory, Report};

    use super::*;
    use crate::store::{Enrollment, NsGrant, RegistryEnrollment, TokenKind};

    /// A value is shown as `vk-hub settings set` takes it back.
    #[test]
    fn a_shown_value_parses_back() {
        let kind = vk_hub_proto::settings::kind("executor.windows_media").unwrap();
        for value in [json!([]), json!(["ab".repeat(32), "cd".repeat(32)])] {
            assert_eq!(kind.parse(&shown(&value)), Ok(value));
        }
        assert_eq!(shown(&json!(8)), "8");
        assert_eq!(shown(&json!("8G")), "8G");
    }

    fn node(db: &Db, takes: bool) -> String {
        let (token, _) = db.create_token(Duration::from_secs(60), "u", 0).unwrap();
        let key = format!("a{}", db.nodes().unwrap().len());
        let Enrollment::Enrolled { node_id } = db.enroll(&token, &key, "h", "peer p", 1).unwrap()
        else {
            panic!("not enrolled");
        };
        let inventory = Inventory {
            hub_settings: takes,
            ..Inventory::default()
        };
        db.record_inventory(&node_id, inventory, true, 1).unwrap();
        node_id
    }

    fn desired(db: &Db, id: &str) -> DesiredState {
        db.node(id)
            .unwrap()
            .unwrap()
            .desired
            .unwrap_or(DesiredState {
                generation: 0,
                ceiling: None,
                acquisition: Acquisition::Run,
                egress: None,
                settings: BTreeMap::new(),
            })
    }

    /// A node's own layer wins over the fleet's, key by key; only a node that takes settings is
    /// sent them, and each change moves its generation on.
    #[test]
    fn a_nodes_layer_wins_over_the_fleets() {
        let db = Db::open_memory().unwrap();
        let (a, b, old) = (node(&db, true), node(&db, true), node(&db, false));
        let set = |node: Option<&str>, key: &str, value: Option<Value>, now| {
            db.set_setting(node, key, value, "uid 0", now).unwrap()
        };
        let (changed, mut steered) = set(None, "executor.vm.cpus", Some(json!(4)), 2);
        steered.sort();
        let mut both = vec![a.clone(), b.clone()];
        both.sort();
        assert_eq!((changed, steered), (true, both));
        set(Some(&a), "executor.vm.cpus", Some(json!(8)), 3);
        set(Some(&a), "executor.vm.mem", Some(json!("8G")), 4);
        assert_eq!(
            desired(&db, &a).settings,
            BTreeMap::from([
                ("executor.vm.cpus".to_string(), json!(8)),
                ("executor.vm.mem".to_string(), json!("8G")),
            ])
        );
        assert_eq!(desired(&db, &a).generation, 3);
        assert_eq!(
            desired(&db, &b).settings,
            BTreeMap::from([("executor.vm.cpus".to_string(), json!(4))])
        );
        assert!(desired(&db, &old).settings.is_empty());
        // Setting it again changes nothing.
        assert_eq!(
            set(None, "executor.vm.cpus", Some(json!(4)), 5),
            (false, Vec::new())
        );
        // Unsetting a's own falls back to the fleet's.
        let (_, steered) = set(Some(&a), "executor.vm.cpus", None, 6);
        assert_eq!(steered, std::slice::from_ref(&a));
        assert_eq!(desired(&db, &a).settings["executor.vm.cpus"], json!(4));
        let layers = db.settings_layers().unwrap();
        assert_eq!(layers.nodes[&a].len(), 1);
        // A node's layer goes with it.
        db.remove_node(&a, "uid 0", 7).unwrap();
        assert!(!db.settings_layers().unwrap().nodes.contains_key(&a));
        let events: Vec<String> = db
            .audits(Some(&b), 20)
            .unwrap()
            .into_iter()
            .map(|l| l.event)
            .collect();
        assert!(
            events
                .iter()
                .any(|e| e == "sent the node the hub's settings (generation 1)"),
            "{events:?}"
        );
    }

    /// What a node could not take is refused on the hub first.
    #[test]
    fn a_setting_the_node_would_refuse_is_refused() {
        let db = Db::open_memory().unwrap();
        let id = node(&db, true);
        let err = |node: Option<&str>, key: &str, value: Value| {
            format!(
                "{:#}",
                db.set_setting(node, key, Some(value), "u", 2).unwrap_err()
            )
        };
        assert!(err(None, "state_dir", json!("/x")).contains("not a setting"));
        assert!(err(None, "executor.vm.cpus", json!(0)).contains("from 1 to 255"));
        assert!(err(None, "executor.vm.mem", json!(8)).contains("<n>G"));
        let huge = json!("18014398509481984G");
        assert!(err(None, "executor.vm.mem", huge).contains("to 1048576G"));
        assert!(err(None, "registry", json!("nope")).contains("no registry nope"));
        assert!(err(Some("ffff"), "executor.vm.cpus", json!(2)).contains("not enrolled"));
        assert!(db.set_setting(None, "state_dir", None, "u", 2).is_err());
        assert!(desired(&db, &id).settings.is_empty());
    }

    /// A registry is named by ID and sent as the table that reaches it once it has a URL; a
    /// change to its URL or its `ci-pipeline` namespace moves the nodes on.
    #[test]
    fn a_registry_is_sent_as_the_table_reaching_it() {
        let db = Db::open_memory().unwrap();
        let id = node(&db, true);
        let (token, _) = db
            .create_token_for(TokenKind::Registry, Duration::from_secs(60), None, "u", 1)
            .unwrap();
        let RegistryEnrollment::Enrolled { id: reg } =
            db.enroll_registry(&token, "bb", "reg", "p", 1).unwrap()
        else {
            panic!("not enrolled");
        };
        let named = |now| db.set_setting(None, "registry", Some(json!(reg)), "u", now);
        assert!(format!("{:#}", named(2).unwrap_err()).contains("no URL bound"));
        db.set_registry_url(&reg, Some("http://Reg.example:5000"), None, "u", 3)
            .unwrap();
        named(4).unwrap();
        assert_eq!(
            desired(&db, &id).settings["registry"],
            json!({"repo": "reg.example:5000", "insecure": true, "guest_credential": "job"})
        );
        let pipeline = NamespaceRow {
            name: CI_PIPELINE.into(),
            path: "pipes/{gitlab}/{project_id}/{pipeline_id}".into(),
            retention_days: None,
            alias: None,
            isolate: Vec::new(),
            grants: vec![NsGrant::parse("r:*").unwrap()],
            node_grants: Vec::new(),
            created_at: 0,
            created_by: "u".into(),
        };
        db.put_namespace(&reg, &pipeline, "u", 5).unwrap();
        // A table a node would refuse is not sent, nor can it be named.
        db.set_registry_url(&reg, Some("https://reg.example"), Some("PEM"), "u", 6)
            .unwrap();
        assert_eq!(db.steer_settings(7).unwrap(), std::slice::from_ref(&id));
        assert!(desired(&db, &id).settings.is_empty());
        let refused = db.set_setting(Some(&id), "registry", Some(json!(reg)), "u", 7);
        assert!(
            format!("{:#}", refused.unwrap_err()).contains("nodes would refuse"),
            "named"
        );
        let ca = include_str!("../testdata/tls-ca.pem");
        db.set_registry_url(&reg, Some("https://reg.example"), Some(ca), "u", 8)
            .unwrap();
        assert_eq!(db.steer_settings(8).unwrap(), std::slice::from_ref(&id));
        assert_eq!(
            desired(&db, &id).settings["registry"],
            json!({"repo": "reg.example", "ca_pem": ca, "pipeline_root": "pipes",
                   "guest_credential": "job"})
        );
        // A node that takes its own registry access lends its runner's guests theirs.
        db.record_session(&id, &"c".repeat(32), REGISTRY_ACCESS, None, 8, || true)
            .unwrap();
        assert_eq!(db.steer_settings(8).unwrap(), std::slice::from_ref(&id));
        assert_eq!(
            desired(&db, &id).settings["registry"]["guest_credential"],
            json!("job-or-node")
        );
        // Unbound or gone, the registry is no longer sent; the setting stays.
        db.set_registry_url(&reg, None, None, "u", 8).unwrap();
        db.steer_settings(9).unwrap();
        assert!(desired(&db, &id).settings.is_empty());
        assert_eq!(db.settings_layers().unwrap().fleet["registry"], json!(reg));
    }

    /// The hub's settings stand over those the node applied: after a hub restore, and over an
    /// operator's change made before the node's state was known.
    #[test]
    fn the_hubs_settings_win_over_the_nodes() {
        let db = Db::open_memory().unwrap();
        let id = node(&db, true);
        db.set_setting(None, "executor.vm.cpus", Some(json!(4)), "u", 2)
            .unwrap();
        let theirs = |generation, cpus: u32| Report {
            applied: Some(DesiredState {
                generation,
                ceiling: Some(3),
                acquisition: Acquisition::Run,
                egress: None,
                settings: BTreeMap::from([("executor.vm.cpus".to_string(), json!(cpus))]),
            }),
            ..Report::default()
        };
        // Set on the defaults before the node reported: merged onto its state, ours kept.
        db.record_report(&id, theirs(5, 9), 3).unwrap();
        let d = desired(&db, &id);
        assert_eq!((d.generation, d.ceiling), (6, Some(3)));
        assert_eq!(d.settings["executor.vm.cpus"], json!(4));
        // Restored from before the node's generation: re-issued past it, with ours.
        db.record_report(&id, theirs(20, 9), 4).unwrap();
        let d = desired(&db, &id);
        assert_eq!(d.generation, 21);
        assert_eq!(d.settings["executor.vm.cpus"], json!(4));
        // The node applying ours leaves it be.
        db.record_report(&id, theirs(21, 4), 5).unwrap();
        assert_eq!(desired(&db, &id).generation, 21);
    }
}
