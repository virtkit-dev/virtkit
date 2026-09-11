//! Read-only OCI view under `/dav/repos/`: tags, manifests and blobs for readable repositories.
//! Downloads reuse `/v2/` handlers, including blob decoding and membership checks. Unauthorized
//! repositories return 404. Writes return 405 and must use `/v2/`.

use std::collections::BTreeSet;

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response};

use super::{
    ALLOWED_READ, Depth, Entry, href, method_not_allowed, multistatus, not_found, propfind_depth,
};
use crate::{Authz, Body, REPO_SUBDIRS, ServerState, Store};

/// What every blob is served as, matching `/v2/`.
const BLOB_TYPE: &str = "application/octet-stream";

/// A resolved `repos/` path.
enum Node {
    Root,
    /// A path component above one or more readable repositories that is not itself one:
    /// `team-a/` when the caller may read `team-a/app`.
    Prefix(String),
    Repo(String),
    Tags(String),
    Manifests(String),
    Blobs(String),
    Tag(String, String),
    Manifest(String, String),
    Blob(String, String),
}

/// Serve one `repos/` request; `segs` are the decoded components after `/dav/repos/`.
pub(super) async fn route(
    state: &ServerState,
    authz: &Authz<'_>,
    segs: &[String],
    method: &str,
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let mut parts: Vec<&str> = Vec::with_capacity(segs.len() + 1);
    parts.push("repos");
    parts.extend(segs.iter().map(String::as_str));
    if !matches!(method, "GET" | "HEAD" | "PROPFIND") {
        return Ok(method_not_allowed(&href(&parts, false), ALLOWED_READ));
    }
    let store = &state.store;
    let node = match resolve(store, authz, segs) {
        Ok(node) => node,
        Err(resp) => return Ok(*resp),
    };
    if method == "PROPFIND" {
        return propfind(state, authz, &node, &parts, req).await;
    }
    let head = method == "HEAD";
    let accept_zstd = crate::header_has(&req, hyper::header::ACCEPT_ENCODING, "zstd");
    match &node {
        Node::Tag(name, tag) => crate::get_manifest(store, name, tag, head),
        Node::Manifest(name, hex) if crate::readable_through(authz, store, name, hex) => {
            crate::get_manifest(store, name, &format!("sha256:{hex}"), head)
        }
        Node::Blob(name, hex) if crate::readable_through(authz, store, name, hex) => {
            crate::get_blob(store, &format!("sha256:{hex}"), head, accept_zstd)
        }
        // A collection has no body to serve; a digest this repository does not hold is
        // indistinguishable from an absent one, as on `/v2/`.
        _ => Ok(not_found(&href(&parts, false))),
    }
}

/// Resolve a repository path. The first structural component (`tags`, `manifests`, `blobs`)
/// ends the repository name; `valid_name` reserves these components. Check authorization before
/// accessing the repository on disk.
fn resolve(store: &Store, authz: &Authz<'_>, segs: &[String]) -> Result<Node, Box<Response<Body>>> {
    if segs.is_empty() {
        return Ok(Node::Root);
    }
    let mut parts: Vec<&str> = vec!["repos"];
    parts.extend(segs.iter().map(String::as_str));
    let missing = || Err(Box::new(not_found(&href(&parts, false))));
    let kind_at = segs.iter().position(|s| REPO_SUBDIRS.contains(&s.as_str()));
    let name_segs = &segs[..kind_at.unwrap_or(segs.len())];
    if name_segs.is_empty() {
        return missing();
    }
    let name = name_segs.join("/");
    if !crate::valid_name(&name) {
        return Err(Box::new(crate::error_response(
            hyper::StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            &name,
        )));
    }
    let Some(at) = kind_at else {
        if authz.may_read(&name) && store.has_repo(&name) {
            return Ok(Node::Repo(name));
        }
        let prefix = format!("{name}/");
        if readable_repos(store, authz)
            .iter()
            .any(|r| r.starts_with(&prefix))
        {
            return Ok(Node::Prefix(name));
        }
        return missing();
    };
    if !authz.may_read(&name) || !store.has_repo(&name) {
        return missing();
    }
    let rest = &segs[at + 1..];
    match (segs[at].as_str(), rest) {
        ("tags", []) => Ok(Node::Tags(name)),
        ("manifests", []) => Ok(Node::Manifests(name)),
        ("blobs", []) => Ok(Node::Blobs(name)),
        ("tags", [tag]) if crate::valid_tag(tag) => Ok(Node::Tag(name, tag.clone())),
        ("manifests", [hex]) if crate::is_blob_hex(hex) => Ok(Node::Manifest(name, hex.clone())),
        ("blobs", [hex]) if crate::is_blob_hex(hex) => Ok(Node::Blob(name, hex.clone())),
        _ => missing(),
    }
}

/// Every repository this caller may read, sorted. One walk of `repos/`, O(repositories);
/// computed only for the listings and the prefix check, never on a member's own path.
fn readable_repos(store: &Store, authz: &Authz<'_>) -> Vec<String> {
    store
        .all_repo_names()
        .into_iter()
        .filter(|r| authz.may_read(r))
        .collect()
}

/// The next path component of every readable repository below `prefix` (`""` for the
/// root), deduplicated: what a listing of that level shows.
fn children_under(store: &Store, authz: &Authz<'_>, prefix: &str) -> BTreeSet<String> {
    readable_repos(store, authz)
        .into_iter()
        .filter_map(|r| {
            let rest = if prefix.is_empty() {
                r
            } else {
                r.strip_prefix(prefix)?.strip_prefix('/')?.to_string()
            };
            Some(rest.split('/').next()?.to_string())
        })
        .collect()
}

/// `PROPFIND` a node: the resource, and at `Depth: 1` its members.
async fn propfind(
    state: &ServerState,
    authz: &Authz<'_>,
    node: &Node,
    parts: &[&str],
    req: Request<Incoming>,
) -> Result<Response<Body>> {
    let depth = match propfind_depth(req).await {
        Ok(d) => d,
        Err(resp) => return Ok(*resp),
    };
    let store = &state.store;
    let list = depth == Depth::One;
    let child = |name: &str, collection: bool| {
        let mut c: Vec<&str> = parts.to_vec();
        c.push(name);
        href(&c, collection)
    };
    // Repository enumeration requires configured credentials.
    let enumerate = list && super::may_enumerate(state);
    let refused_enumeration = list && !super::may_enumerate(state);
    let mut entries = Vec::new();
    match node {
        Node::Root | Node::Prefix(_) => {
            if refused_enumeration {
                return Ok(super::enumeration_refused());
            }
            let prefix = match node {
                Node::Prefix(p) => p.as_str(),
                _ => "",
            };
            entries.push(Entry::collection(
                href(parts, true),
                store.repos_path_modified(prefix),
            ));
            if enumerate {
                for c in children_under(store, authz, prefix) {
                    let rel = if prefix.is_empty() {
                        c.clone()
                    } else {
                        format!("{prefix}/{c}")
                    };
                    entries.push(Entry::collection(
                        child(&c, true),
                        store.repos_path_modified(&rel),
                    ));
                }
            }
        }
        Node::Repo(name) => {
            entries.push(Entry::collection(
                href(parts, true),
                store.repos_path_modified(name),
            ));
            if list {
                for kind in REPO_SUBDIRS {
                    entries.push(Entry::collection(
                        child(kind, true),
                        store.repos_path_modified(&format!("{name}/{kind}")),
                    ));
                }
                // Apply the root enumeration rule to nested repositories too.
                if enumerate {
                    for c in children_under(store, authz, name) {
                        entries.push(Entry::collection(
                            child(&c, true),
                            store.repos_path_modified(&format!("{name}/{c}")),
                        ));
                    }
                }
            }
        }
        Node::Tags(name) => {
            entries.push(Entry::collection(
                href(parts, true),
                store.repos_path_modified(&format!("{name}/tags")),
            ));
            if list {
                for tag in store.list_tags(name) {
                    if let Some(e) = tag_entry(store, name, &tag, child(&tag, false)) {
                        entries.push(e);
                    }
                }
            }
        }
        Node::Manifests(name) => {
            entries.push(Entry::collection(
                href(parts, true),
                store.repos_path_modified(&format!("{name}/manifests")),
            ));
            if list {
                for hex in store.repo_member_hexes(name, "manifests") {
                    if let Some(e) = manifest_entry(store, name, &hex, child(&hex, false)) {
                        entries.push(e);
                    }
                }
            }
        }
        Node::Blobs(name) => {
            entries.push(Entry::collection(
                href(parts, true),
                store.repos_path_modified(&format!("{name}/blobs")),
            ));
            if list {
                for hex in store.repo_member_hexes(name, "blobs") {
                    if let Some(e) = blob_entry(store, &hex, child(&hex, false)) {
                        entries.push(e);
                    }
                }
            }
        }
        Node::Tag(name, tag) => match tag_entry(store, name, tag, href(parts, false)) {
            Some(e) => entries.push(e),
            None => return Ok(not_found(&href(parts, false))),
        },
        Node::Manifest(name, hex) => {
            match crate::readable_through(authz, store, name, hex)
                .then(|| manifest_entry(store, name, hex, href(parts, false)))
                .flatten()
            {
                Some(e) => entries.push(e),
                None => return Ok(not_found(&href(parts, false))),
            }
        }
        Node::Blob(name, hex) => {
            match crate::readable_through(authz, store, name, hex)
                .then(|| blob_entry(store, hex, href(parts, false)))
                .flatten()
            {
                Some(e) => entries.push(e),
                None => return Ok(not_found(&href(parts, false))),
            }
        }
    }
    Ok(multistatus(&entries))
}

/// A tag as a file: the manifest it resolves to, sized and typed, dated by the tag.
fn tag_entry(store: &Store, name: &str, tag: &str, href: String) -> Option<Entry> {
    let (hex, modified) = store.tag_target(name, tag)?;
    let (len, ctype, _) = store.manifest_meta(name, &hex)?;
    Some(Entry::file(href, len, &ctype, modified))
}

/// A manifest as a file, dated by its membership record.
fn manifest_entry(store: &Store, name: &str, hex: &str, href: String) -> Option<Entry> {
    let (len, ctype, modified) = store.manifest_meta(name, hex)?;
    Some(Entry::file(href, len, &ctype, modified))
}

/// Blob entry with canonical length, read from the frame header for zstd storage.
fn blob_entry(store: &Store, hex: &str, href: String) -> Option<Entry> {
    let (len, modified) = store.blob_meta(hex)?;
    Some(Entry::file(href, len, BLOB_TYPE, modified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn store() -> (std::path::PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!(
            "vk-reg-dav-repos-{}-{:?}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        (dir.clone(), Store::new(dir).unwrap())
    }

    fn segs(path: &str) -> Vec<String> {
        path.split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// Test repository paths, structural components and invalid members.
    #[test]
    fn paths_resolve_to_the_view_and_nowhere_else() {
        let (dir, store) = store();
        let authz = Authz::NoScopes;
        store
            .put_manifest(
                "team-a/app",
                "v1",
                "application/vnd.oci.image.manifest.v1+json",
                b"{}",
            )
            .unwrap();
        let hex = "0".repeat(64);
        let r = |p: &str| resolve(&store, &authz, &segs(p));

        assert!(matches!(r(""), Ok(Node::Root)));
        assert!(matches!(r("team-a"), Ok(Node::Prefix(p)) if p == "team-a"));
        assert!(matches!(r("team-a/app"), Ok(Node::Repo(n)) if n == "team-a/app"));
        assert!(matches!(r("team-a/app/tags"), Ok(Node::Tags(_))));
        assert!(matches!(r("team-a/app/manifests"), Ok(Node::Manifests(_))));
        assert!(matches!(r("team-a/app/blobs"), Ok(Node::Blobs(_))));
        assert!(matches!(r("team-a/app/tags/v1"), Ok(Node::Tag(_, t)) if t == "v1"));
        assert!(matches!(
            r(&format!("team-a/app/manifests/{hex}")),
            Ok(Node::Manifest(_, h)) if h == hex
        ));
        assert!(matches!(
            r(&format!("team-a/app/blobs/{hex}")),
            Ok(Node::Blob(_, h)) if h == hex
        ));

        let gone = |p: &str| {
            let resp = r(p).err().expect(p);
            assert_eq!(resp.status(), 404, "{p}");
        };
        // a repository that is not there, and a prefix nothing readable is under
        gone("team-b");
        gone("team-a/other");
        gone("team-a/other/tags");
        // a structural name with no repository in front of it
        gone("tags");
        gone("blobs/abc");
        // too deep, and members that are not the shape they must be
        gone("team-a/app/tags/v1/x");
        gone("team-a/app/blobs/notahex");
        gone("team-a/app/blobs/sha256:abc");
        gone("team-a/app/manifests/ABC");
        // a bad name is a bad request, not a 404
        assert_eq!(r("bad name/app").err().unwrap().status(), 400);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// List each readable child component once.
    #[test]
    fn a_level_lists_the_next_component_of_each_readable_name() {
        let (dir, store) = store();
        let authz = Authz::NoScopes;
        for repo in ["team-a/app", "team-a/lib", "team-a", "solo"] {
            store
                .put_manifest(
                    repo,
                    "v1",
                    "application/vnd.oci.image.manifest.v1+json",
                    b"{}",
                )
                .unwrap();
        }
        let names = |prefix: &str| {
            children_under(&store, &authz, prefix)
                .into_iter()
                .collect::<Vec<_>>()
        };
        assert_eq!(names(""), vec!["solo", "team-a"]);
        assert_eq!(names("team-a"), vec!["app", "lib"]);
        assert!(names("solo").is_empty());
        // `team-a` is both a repository and a prefix, and resolves as the repository
        assert!(matches!(
            resolve(&store, &authz, &segs("team-a")),
            Ok(Node::Repo(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
