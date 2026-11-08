//! What nodes installed from each CI tools definition, compared across nodes.
//!
//! A node reports, with the tools current, each file it installed by sha256 and each link by
//! its target, as it recorded them when it installed them, and whether they are still so
//! ([`vk_hub_proto::ToolsInstalled`]). The hub keeps that with the node's inventory and derives
//! the rest: built from the same definition, a reproducible build gives every node the same
//! files, so nodes that report other ones than each other for one definition are told apart
//! here. Which of them is right cannot be told from the reports alone: a build that is not
//! reproducible, a build that went wrong, and tools changed before they were recorded look
//! alike. Tools a node finds changed since it recorded them are its own report
//! ([`vk_hub_proto::ToolsCheck::Modified`]), apart from this.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use vk_hub_proto::{ToolsFile, ToolsInstalled};

/// What some nodes installed from one definition: the same files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Output {
    /// [`digest`] of `files`, which tells outputs apart at a glance.
    pub digest: String,
    pub files: BTreeMap<String, ToolsFile>,
    /// The nodes reporting them, by ID, sorted.
    pub nodes: Vec<String>,
}

/// What nodes installed from one definition, most reported first: more than one output when
/// they did not all install the same files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefinitionOutputs {
    /// The definition's sha256.
    pub sha256: String,
    pub outputs: Vec<Output>,
}

/// How one node's tools compare with those of the other nodes reporting the same definition.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peers {
    /// How many other nodes report the same files.
    pub same: usize,
    /// The other nodes reporting other files, each with the entries that differ, by hostname.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub differ: Vec<Differ>,
}

impl Peers {
    /// The entries that differ from any other node's, sorted, once.
    pub fn differing(&self) -> Vec<&str> {
        let mut entries: Vec<&str> = self
            .differ
            .iter()
            .flat_map(|d| d.entries.iter().map(String::as_str))
            .collect();
        entries.sort_unstable();
        entries.dedup();
        entries
    }

    /// The hostnames of the nodes that hold other files.
    pub fn hosts(&self) -> Vec<&str> {
        self.differ.iter().map(|d| d.hostname.as_str()).collect()
    }
}

/// Another node whose tools, from the same definition, hold other files.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Differ {
    pub id: String,
    pub hostname: String,
    /// The entries that differ, sorted: other contents or link, or held by one node alone.
    pub entries: Vec<String>,
}

/// The sha256 of `files` as JSON, keys in order: the same files, the same digest.
pub fn digest(files: &BTreeMap<String, ToolsFile>) -> String {
    // A map of plain data always encodes.
    let json = serde_json::to_vec(files).unwrap_or_default();
    vk_hub_proto::to_hex(&Sha256::digest(json))
}

/// The entries in which `a` and `b` differ, sorted.
pub fn differing(a: &BTreeMap<String, ToolsFile>, b: &BTreeMap<String, ToolsFile>) -> Vec<String> {
    let mut names: Vec<String> = a
        .iter()
        .filter(|(name, file)| b.get(*name) != Some(file))
        .map(|(name, _)| name.clone())
        .chain(b.keys().filter(|name| !a.contains_key(*name)).cloned())
        .collect();
    names.sort();
    names
}

/// What `nodes` — each its ID and the tools it reports current — installed, by definition.
/// A node that reports no files, having recorded none, is left out.
pub fn by_definition<'a>(
    nodes: impl IntoIterator<Item = (&'a str, &'a ToolsInstalled)>,
) -> BTreeMap<String, DefinitionOutputs> {
    let mut found: BTreeMap<String, BTreeMap<String, Output>> = BTreeMap::new();
    for (id, tools) in nodes {
        if tools.files.is_empty() {
            continue;
        }
        let digest = digest(&tools.files);
        found
            .entry(tools.sha256.clone())
            .or_default()
            .entry(digest.clone())
            .or_insert_with(|| Output {
                digest,
                files: tools.files.clone(),
                nodes: Vec::new(),
            })
            .nodes
            .push(id.to_string());
    }
    found
        .into_iter()
        .map(|(sha256, outputs)| {
            let mut outputs: Vec<Output> = outputs.into_values().collect();
            for o in &mut outputs {
                o.nodes.sort();
            }
            outputs.sort_by(|a, b| {
                b.nodes
                    .len()
                    .cmp(&a.nodes.len())
                    .then(a.digest.cmp(&b.digest))
            });
            (sha256.clone(), DefinitionOutputs { sha256, outputs })
        })
        .collect()
}

/// How node `id`'s `tools` compare with the other nodes' in `outputs`, `hostname` naming each
/// node; `None` when it reports no files or no other node reports the definition.
pub fn peers(
    id: &str,
    tools: &ToolsInstalled,
    outputs: &BTreeMap<String, DefinitionOutputs>,
    hostname: impl Fn(&str) -> String,
) -> Option<Peers> {
    if tools.files.is_empty() {
        return None;
    }
    let def = outputs.get(&tools.sha256)?;
    let mut peers = Peers::default();
    for output in &def.outputs {
        let others = output.nodes.iter().filter(|n| *n != id);
        if output.files == tools.files {
            peers.same += others.count();
            continue;
        }
        let entries = differing(&tools.files, &output.files);
        peers.differ.extend(others.map(|n| Differ {
            id: n.clone(),
            hostname: hostname(n),
            entries: entries.clone(),
        }));
    }
    peers
        .differ
        .sort_by(|a, b| (&a.hostname, &a.id).cmp(&(&b.hostname, &b.id)));
    (peers.same > 0 || !peers.differ.is_empty()).then_some(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(sha: &str) -> ToolsFile {
        ToolsFile::File {
            sha256: sha.repeat(64),
            size: 1,
        }
    }

    fn tools(def: &str, git: &str) -> ToolsInstalled {
        ToolsInstalled {
            sha256: def.repeat(64),
            version: "v".into(),
            tools: BTreeMap::new(),
            in_use: true,
            files: BTreeMap::from([
                ("git".into(), file(git)),
                (
                    "git-remote-https".into(),
                    ToolsFile::Link {
                        target: "git-remote-http".into(),
                    },
                ),
            ]),
            egress: None,
            check: None,
        }
    }

    #[test]
    fn nodes_are_told_apart_by_the_files_they_installed_from_one_definition() {
        let (a1, a2, a3) = (tools("a", "1"), tools("a", "1"), tools("a", "2"));
        let (b, mut none) = (tools("b", "2"), tools("a", "9"));
        none.files.clear();
        let nodes = [
            ("n1", &a1),
            ("n2", &a2),
            ("n3", &a3),
            ("n4", &b),
            ("n5", &none),
        ];
        let outputs = by_definition(nodes);
        let a = &outputs[&"a".repeat(64)];
        assert_eq!(
            (a.outputs.len(), outputs[&"b".repeat(64)].outputs.len()),
            (2, 1)
        );
        assert_eq!(a.outputs[0].nodes, ["n1", "n2"]);
        assert_eq!(a.outputs[1].nodes, ["n3"]);
        assert_eq!(a.outputs[0].digest, digest(&a1.files));
        assert_ne!(a.outputs[0].digest, a.outputs[1].digest);

        let host = |id: &str| format!("host-{id}");
        let p = peers("n1", &a1, &outputs, host).unwrap();
        assert_eq!(p.same, 1);
        assert_eq!(
            p.differ,
            [Differ {
                id: "n3".into(),
                hostname: "host-n3".into(),
                entries: vec!["git".into()],
            }]
        );
        let p = peers("n3", &a3, &outputs, host).unwrap();
        assert_eq!((p.same, p.differ.len()), (0, 2));
        // Alone with its definition, or with nothing recorded: nothing to compare.
        assert_eq!(peers("n4", &b, &outputs, host), None);
        assert_eq!(peers("n5", &none, &outputs, host), None);

        let mut extra = a1.files.clone();
        extra.insert("sh".into(), file("3"));
        extra.remove("git-remote-https");
        assert_eq!(differing(&a1.files, &extra), ["git-remote-https", "sh"]);
    }
}
