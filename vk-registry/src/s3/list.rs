//! A bucket's objects: ListObjectsV2 (`?list-type=2`) and ListObjects (v1, `marker`). The
//! listing is a depth-first walk of the bucket's directories that yields keys in byte order
//! of the whole key: a directory's members all start with `<name>/`, so at each level the
//! directories sort as `<name>/` among the tags, which puts tag `a-b` and `a.b` before
//! directory `a/` and that before tag `a_b`. Walked in that order, a page resumes by passing
//! over every subtree that sorts before its resume point unread, and stops at `max-keys + 1`
//! entries, so a page costs the directories on the way to the resume point and the page.
//!
//! A listing is admitted when the caller may read the bucket or the directory its prefix
//! names, and shows only what a read would serve: a directory the caller may not read is
//! passed over with everything below it, as `PROPFIND` passes it over, and an object only
//! when its bytes are readable through it.

use anyhow::Result;
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};

use super::path::MAX_KEY;
use super::{Ctx, bucket, conditional, refuse, sigv4, xml};
use crate::files::{self, FILES_REPO, Node, Object, allowed, repo_name};
use crate::{Authz, Body, ServerState, Store, accounts};

/// Most entries a page holds, and what `max-keys` is clamped to: S3's bound.
const MAX_KEYS: usize = 1000;

/// The query parameters a listing takes, of either version; an SDK's `x-id` hint too.
const PARAMS: &[&str] = &[
    "list-type",
    "prefix",
    "delimiter",
    "max-keys",
    "continuation-token",
    "start-after",
    "marker",
    "encoding-type",
    "fetch-owner",
    "x-id",
];

/// Whether a bucket `GET` with this query is a listing: one that names only [`PARAMS`].
pub(super) fn is_listing(query: &str) -> bool {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .all(|p| PARAMS.contains(&p.split_once('=').map_or(p, |(n, _)| n)))
}

/// What a listing asks for.
#[derive(Debug, Default, PartialEq, Eq)]
struct Query {
    /// `list-type=2`
    v2: bool,
    prefix: String,
    delimiter: Option<String>,
    max_keys: usize,
    /// the continuation token as sent, to echo
    token: Option<String>,
    /// `start-after` (v2) or `marker` (v1), as sent
    start: Option<String>,
    /// the key the page starts after: the token's, else `start`
    after: Option<String>,
    /// `encoding-type=url`
    url: bool,
    /// `fetch-owner=true`, or any v1 listing
    owner: bool,
}

/// The listing a query asks for, or why it is refused (400 `InvalidArgument`).
fn parse(query: &str) -> std::result::Result<Query, &'static str> {
    let mut q = Query {
        max_keys: MAX_KEYS,
        ..Query::default()
    };
    let (mut start_after, mut marker) = (None, None);
    let mut seen: Vec<&str> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, raw) = pair.split_once('=').unwrap_or((pair, ""));
        // The first of a repeated parameter is the one taken.
        if seen.contains(&name) {
            continue;
        }
        seen.push(name);
        let value = crate::dav::decode_segment(raw)
            .ok_or("a query parameter has a malformed percent escape or is not UTF-8")?;
        match name {
            "list-type" if value == "2" => q.v2 = true,
            "list-type" => return Err("list-type is 2, or absent for the first version"),
            "prefix" => q.prefix = text(value)?,
            "delimiter" => q.delimiter = Some(text(value)?).filter(|d| !d.is_empty()),
            "max-keys" => {
                let n: usize = value
                    .parse()
                    .map_err(|_| "max-keys is a whole number from 0")?;
                q.max_keys = n.min(MAX_KEYS);
            }
            "continuation-token" => q.token = Some(value),
            "start-after" => start_after = Some(text(value)?),
            "marker" => marker = Some(text(value)?),
            "encoding-type" if value == "url" => q.url = true,
            "encoding-type" => return Err("encoding-type is url, or absent"),
            "fetch-owner" => q.owner = value == "true",
            _ => {}
        }
    }
    // Each version resumes its own way; a first-version listing always names the owner.
    if q.v2 {
        q.start = start_after;
    } else {
        (q.start, q.token, q.owner) = (marker, None, true);
    }
    q.after = match &q.token {
        Some(token) => Some(
            resume_point(token).ok_or("the continuation token is not one this registry gave")?,
        ),
        None => q.start.clone(),
    };
    Ok(q)
}

/// A prefix, delimiter or start key, which a listing echoes in XML: no control character,
/// which XML 1.0 cannot carry, and no longer than a key.
fn text(v: String) -> std::result::Result<String, &'static str> {
    if v.chars().any(char::is_control) {
        Err("a prefix, delimiter or start key holds no control character")
    } else if v.len() > MAX_KEY {
        Err("a prefix, delimiter or start key is at most 1024 bytes")
    } else {
        Ok(v)
    }
}

/// The key a continuation token names: the last entry of the page it ended, which is a key
/// or a common prefix, so only the characters keys have.
fn resume_point(token: &str) -> Option<String> {
    let bytes = vk_hub_proto::token::from_base64url(token)?;
    let key = String::from_utf8(bytes).ok()?;
    let fits = !key.is_empty()
        && key.len() <= MAX_KEY
        && key
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'));
    fits.then_some(key)
}

/// One entry of a page.
enum Item {
    Object(String, Object),
    /// a common prefix, every key below which the delimiter folded into it
    Prefix(String),
}

impl Item {
    fn key(&self) -> &str {
        match self {
            Item::Object(key, _) | Item::Prefix(key) => key,
        }
    }
}

/// What a walk lists: the keys starting with `prefix`, after `after`, folded at the first
/// `delimiter` past the prefix, at most `limit` of them.
struct Walk<'a> {
    prefix: &'a str,
    delimiter: Option<&'a str>,
    after: Option<&'a str>,
    limit: usize,
}

/// The first [`Walk::limit`] entries of `bucket` the walk asks for, in key order, as this
/// caller may read them. The walk starts at the directory the prefix's whole components name,
/// which is the one directory every matching key is below: one the caller may not read, or
/// that is not there, holds nothing. Memory is a page and a directory listing per level.
fn walk(store: &Store, authz: &Authz<'_>, bucket: &str, how: &Walk<'_>) -> Result<Vec<Item>> {
    Ok(walked(store, authz, bucket, how)?.items)
}

/// [`walk`], handing back the walker with its entries.
fn walked<'a, 'b>(
    store: &'a Store,
    authz: &'a Authz<'b>,
    bucket: &str,
    how: &'a Walk<'a>,
) -> Result<Walker<'a, 'b>> {
    let mut segs = vec![bucket.to_string()];
    let mut key = String::new();
    if let Some((dirs, _)) = how.prefix.rsplit_once('/') {
        segs.extend(dirs.split('/').map(str::to_string));
        key = format!("{dirs}/");
    }
    let mut walker = Walker {
        store,
        authz,
        how,
        items: Vec::new(),
        #[cfg(test)]
        dirs_read: 0,
    };
    let start = repo_name(&segs);
    if how.limit > 0
        && crate::valid_name(&start)
        && authz.may_read(&start)
        && store.repo_dir_exists(&start)
    {
        walker.dir(&mut segs, &key)?;
    }
    Ok(walker)
}

struct Walker<'a, 'b> {
    store: &'a Store,
    authz: &'a Authz<'b>,
    how: &'a Walk<'a>,
    items: Vec<Item>,
    /// how many directories were listed, which resuming is to keep to the path down to the
    /// resume point
    #[cfg(test)]
    dirs_read: usize,
}

impl Walker<'_, '_> {
    fn full(&self) -> bool {
        self.items.len() >= self.how.limit
    }

    /// The directory at `segs`, whose members' keys start with `key`: its subdirectories and
    /// tags merged in key order.
    fn dir(&mut self, segs: &mut Vec<String>, key: &str) -> Result<()> {
        #[cfg(test)]
        {
            self.dirs_read += 1;
        }
        let repo = repo_name(segs);
        let mut members: Vec<String> = self
            .store
            .repo_children(&repo)?
            .into_iter()
            .map(|d| format!("{d}/"))
            .chain(self.store.list_tags(&repo))
            .collect();
        // A tag holds no `/`, so a directory and a tag never compare equal.
        members.sort_unstable();
        for member in members {
            if self.full() {
                break;
            }
            let full = format!("{key}{member}");
            match member.strip_suffix('/') {
                Some(name) => self.subtree(segs, &repo, name, &full)?,
                None => self.tag(segs, &member, &full)?,
            }
        }
        Ok(())
    }

    /// The subdirectory `name` of `repo`, whose members' keys start with `full`.
    fn subtree(
        &mut self,
        segs: &mut Vec<String>,
        repo: &str,
        name: &str,
        full: &str,
    ) -> Result<()> {
        let how = self.how;
        // Every key below starts with `full`: none can match a prefix that diverges from it.
        if !full.starts_with(how.prefix) && !how.prefix.starts_with(full) {
            return Ok(());
        }
        // Every key below sorts before the resume point unless that point is below too.
        if how.after.is_some_and(|a| !a.starts_with(full) && full < a) {
            return Ok(());
        }
        if !self.authz.may_read(&format!("{repo}/{name}")) {
            return Ok(());
        }
        // The delimiter folds the whole subtree into one prefix when it falls inside `full`.
        if full.len() >= how.prefix.len()
            && let Some(prefix) = self.folded(full)
        {
            self.common(prefix);
            return Ok(());
        }
        segs.push(name.to_string());
        let walked = self.dir(segs, full);
        segs.pop();
        walked
    }

    /// The tag `tag` at `segs`, whose key is `full`: listed when a read would serve it.
    fn tag(&mut self, segs: &[String], tag: &str, full: &str) -> Result<()> {
        let how = self.how;
        if !full.starts_with(how.prefix) || how.after.is_some_and(|a| full <= a) {
            return Ok(());
        }
        let folded = self.folded(full);
        if let Some(prefix) = &folded
            && !self.fresh(prefix)
        {
            return Ok(());
        }
        let mut path = segs.to_vec();
        path.push(tag.to_string());
        let Some(Node::Object(obj)) = files::resolve(self.store, &path)? else {
            return Ok(());
        };
        if !crate::readable_through(self.authz, self.store, &obj.repo, &obj.layer) {
            return Ok(());
        }
        self.items.push(match folded {
            Some(prefix) => Item::Prefix(prefix.to_string()),
            None => Item::Object(full.to_string(), obj),
        });
        Ok(())
    }

    /// The common prefix `key` folds into: up to and including the first delimiter past the
    /// listing's prefix. `key` starts with the prefix.
    fn folded<'k>(&self, key: &'k str) -> Option<&'k str> {
        let delimiter = self.how.delimiter?;
        let at = key.get(self.how.prefix.len()..)?.find(delimiter)?;
        key.get(..self.how.prefix.len() + at + delimiter.len())
    }

    /// Whether the common prefix `prefix` is still to be listed: past the resume point, and
    /// not the entry just listed.
    fn fresh(&self, prefix: &str) -> bool {
        self.how.after.is_none_or(|a| prefix > a)
            && !matches!(self.items.last(), Some(Item::Prefix(p)) if p == prefix)
    }

    fn common(&mut self, prefix: &str) {
        if self.fresh(prefix) {
            self.items.push(Item::Prefix(prefix.to_string()));
        }
    }
}

/// `key` for a document asking `encoding-type=url`: each component percent-encoded, the
/// slashes kept.
fn url_encode(key: &str) -> String {
    key.split('/')
        .map(crate::percent_encode)
        .collect::<Vec<_>>()
        .join("/")
}

/// An object's `LastModified` as S3's listings write it.
fn iso8601(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let stamp = sigv4::format_time(secs);
    format!("{}.000Z", stamp.trim_end_matches('Z'))
}

/// `GET /s3/<bucket>` with a listing's query: the page of keys it asks for.
pub(super) async fn list(
    state: &ServerState,
    authz: &Authz<'_>,
    bucket: String,
    query: &str,
    req: Request<Incoming>,
    ctx: &Ctx,
) -> Result<Response<Body>> {
    let q = match parse(query) {
        Ok(q) => q,
        Err(message) => {
            let resp = ctx.error(StatusCode::BAD_REQUEST, "InvalidArgument", message);
            return refuse(req, resp, ctx).await;
        }
    };
    if !admitted(authz, &bucket, &q.prefix) {
        return refuse(req, ctx.access_denied(), ctx).await;
    }
    let ctx = ctx.clone();
    crate::dav::blocking(state, authz, move |store, authz| {
        if !store.repo_dir_exists(&format!("{FILES_REPO}/{bucket}")) {
            return Ok(ctx.error(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
            ));
        }
        let (items, truncated) = page(store, authz, &bucket, &q)?;
        Ok(xml::document(
            "ListBucketResult",
            &render(&bucket, &q, &items, truncated),
        ))
    })
    .await
}

/// The page `q` asks for and whether more follow it: one entry past `max-keys` is walked to
/// know. A page of none is empty and complete.
fn page(store: &Store, authz: &Authz<'_>, bucket: &str, q: &Query) -> Result<(Vec<Item>, bool)> {
    if q.max_keys == 0 {
        return Ok((Vec::new(), false));
    }
    let how = Walk {
        prefix: &q.prefix,
        delimiter: q.delimiter.as_deref(),
        after: q.after.as_deref(),
        limit: q.max_keys.saturating_add(1),
    };
    let mut items = walk(store, authz, bucket, &how)?;
    let truncated = items.len() > q.max_keys;
    items.truncate(q.max_keys);
    Ok((items, truncated))
}

/// Whether this caller may list `bucket` with `prefix`: it may read the bucket, or the
/// directory the prefix's whole components name; the walk then shows what it may read.
fn admitted(authz: &Authz<'_>, bucket: &str, prefix: &str) -> bool {
    let read = |repo: &str| allowed(authz, accounts::Action::Read, repo);
    let bucket = format!("{FILES_REPO}/{bucket}");
    read(&bucket)
        || prefix.rsplit_once('/').is_some_and(|(dirs, _)| {
            let repo = format!("{bucket}/{dirs}");
            crate::valid_name(&repo) && read(&repo)
        })
}

/// The `ListBucketResult` of a page: its parameters, then the objects, then the common
/// prefixes, every caller string escaped and, under `encoding-type=url`, encoded.
fn render(bucket: &str, q: &Query, items: &[Item], truncated: bool) -> String {
    let enc = |s: &str| if q.url { url_encode(s) } else { s.to_string() };
    let mut out = xml::element("Name", bucket);
    out.push_str(&xml::element("Prefix", &enc(&q.prefix)));
    let next = truncated.then(|| items.last().map(Item::key)).flatten();
    if !q.v2 {
        out.push_str(&xml::element(
            "Marker",
            &enc(q.start.as_deref().unwrap_or("")),
        ));
        if let Some(next) = next {
            out.push_str(&xml::element("NextMarker", &enc(next)));
        }
    }
    out.push_str(&xml::element("MaxKeys", &q.max_keys.to_string()));
    if let Some(d) = &q.delimiter {
        out.push_str(&xml::element("Delimiter", &enc(d)));
    }
    if q.url {
        out.push_str(&xml::element("EncodingType", "url"));
    }
    if q.v2 {
        out.push_str(&xml::element("KeyCount", &items.len().to_string()));
    }
    out.push_str(&xml::element(
        "IsTruncated",
        if truncated { "true" } else { "false" },
    ));
    if q.v2 {
        if let Some(token) = &q.token {
            out.push_str(&xml::element("ContinuationToken", token));
        }
        if let Some(next) = next {
            let token = vk_hub_proto::token::to_base64url(next.as_bytes());
            out.push_str(&xml::element("NextContinuationToken", &token));
        }
        if let Some(start) = &q.start {
            out.push_str(&xml::element("StartAfter", &enc(start)));
        }
    }
    for item in items {
        if let Item::Object(key, obj) = item {
            out.push_str("<Contents>");
            out.push_str(&xml::element("Key", &enc(key)));
            out.push_str(&xml::element("LastModified", &iso8601(obj.modified)));
            out.push_str(&xml::element("ETag", &conditional::etag_of(obj)));
            out.push_str(&xml::element("Size", &obj.size.to_string()));
            if q.owner {
                out.push_str(&bucket::owner());
            }
            out.push_str(&xml::element("StorageClass", "STANDARD"));
            out.push_str("</Contents>");
        }
    }
    for item in items {
        if let Item::Prefix(prefix) = item {
            out.push_str(&format!(
                "<CommonPrefixes>{}</CommonPrefixes>",
                xml::element("Prefix", &enc(prefix))
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

    struct Tree {
        dir: std::path::PathBuf,
        store: Store,
    }

    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A store holding `keys` as objects of bucket `b`.
    fn tree(name: &str, keys: &[&str]) -> Tree {
        let dir =
            std::env::temp_dir().join(format!("vk-reg-s3-list-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        store.create_repo("files/b").unwrap();
        for key in keys {
            put(&store, &format!("b/{key}"));
        }
        Tree { dir, store }
    }

    /// An object at `path` below `files/`, its bytes its path.
    fn put(store: &Store, path: &str) {
        let (dirs, tag) = path.rsplit_once('/').unwrap();
        let hex = store.put_blob(path.as_bytes()).unwrap();
        let hex = hex.trim_start_matches("sha256:");
        store
            .put_raw_file(&format!("files/{dirs}"), tag, hex, path.len() as u64, None)
            .unwrap();
    }

    fn api_key(patterns: &[&str]) -> accounts::Principal {
        accounts::Principal::ApiKey(accounts::ApiKey {
            id: "hash".to_string(),
            owner_user_id: None,
            name: "k".to_string(),
            token_prefix: "0123abcd".to_string(),
            scopes: patterns
                .iter()
                .map(|p| accounts::Scope {
                    action: accounts::Action::Read,
                    repo_pattern: p.to_string(),
                })
                .collect(),
            created_at: SystemTime::UNIX_EPOCH,
            expires_at: None,
            last_used_at: None,
            revoked_at: None,
        })
    }

    /// The entries as text, a common prefix in brackets.
    fn names(items: &[Item]) -> Vec<String> {
        items
            .iter()
            .map(|i| match i {
                Item::Object(k, _) => k.clone(),
                Item::Prefix(p) => format!("[{p}]"),
            })
            .collect()
    }

    fn list_as(
        t: &Tree,
        authz: &Authz<'_>,
        prefix: &str,
        delimiter: Option<&str>,
        after: Option<&str>,
    ) -> Vec<String> {
        let how = Walk {
            prefix,
            delimiter,
            after,
            limit: usize::MAX,
        };
        names(&walk(&t.store, authz, "b", &how).unwrap())
    }

    fn list(t: &Tree, prefix: &str, delimiter: Option<&str>, after: Option<&str>) -> Vec<String> {
        list_as(t, &Authz::NoScopes, prefix, delimiter, after)
    }

    #[test]
    fn keys_come_in_byte_order_of_the_whole_key() {
        let t = tree("order", &["a_b", "a/x", "a.b", "a-b", "a/y/z", "A", "c"]);
        assert_eq!(
            list(&t, "", None, None),
            ["A", "a-b", "a.b", "a/x", "a/y/z", "a_b", "c"]
        );
        // A directory sorts as its name and a slash, not as its name: `a-c/` and `a.c/`
        // before `a/`.
        put(&t.store, "b/a-c/k");
        put(&t.store, "b/a.c/k");
        let all = list(&t, "", None, None);
        assert_eq!(
            all,
            [
                "A", "a-b", "a-c/k", "a.b", "a.c/k", "a/x", "a/y/z", "a_b", "c"
            ]
        );
        let mut sorted = all.clone();
        sorted.sort();
        assert_eq!(all, sorted);
        // A tag a directory of its name hides, as a read finds the directory, is not listed.
        put(&t.store, "b/a");
        assert_eq!(list(&t, "", None, None), all);
    }

    #[test]
    fn a_delimiter_folds_directories_without_descending_them() {
        let t = tree("fold", &["a-b", "a.b", "a/x", "a/y/z", "a_b"]);
        assert_eq!(list(&t, "", Some("/"), None), ["a-b", "a.b", "[a/]", "a_b"]);
        assert_eq!(list(&t, "a/", Some("/"), None), ["a/x", "[a/y/]"]);
        assert_eq!(list(&t, "a/y/", Some("/"), None), ["a/y/z"]);
        // A delimiter of any text, folding at its first occurrence past the prefix.
        assert_eq!(
            list(&t, "", Some("-"), None),
            ["[a-]", "a.b", "a/x", "a/y/z", "a_b"]
        );
        assert_eq!(
            list(&t, "", Some("y/"), None),
            ["a-b", "a.b", "a/x", "[a/y/]", "a_b"]
        );
        assert_eq!(
            list(&t, "", Some("."), None),
            ["a-b", "[a.]", "a/x", "a/y/z", "a_b"]
        );
        // Folding stops the walk there: a folded directory is not listed.
        let dirs_read = |prefix: &str, delimiter| {
            let how = Walk {
                prefix,
                delimiter,
                after: None,
                limit: usize::MAX,
            };
            walked(&t.store, &Authz::NoScopes, "b", &how)
                .unwrap()
                .dirs_read
        };
        assert_eq!(dirs_read("", Some("/")), 1);
        assert_eq!(dirs_read("", None), 3);
        // An empty directory is a prefix too, as WebDAV shows it.
        t.store.create_repo("files/b/empty").unwrap();
        assert_eq!(
            list(&t, "", Some("/"), None),
            ["a-b", "a.b", "[a/]", "a_b", "[empty/]"]
        );
    }

    #[test]
    fn a_prefix_may_end_inside_a_component() {
        let t = tree(
            "inside",
            &["a/b/x", "a/bc/x", "a/bc/y/z", "a/bd", "a/c", "ab"],
        );
        assert_eq!(
            list(&t, "a/b", Some("/"), None),
            ["[a/b/]", "[a/bc/]", "a/bd"]
        );
        assert_eq!(
            list(&t, "a/b", None, None),
            ["a/b/x", "a/bc/x", "a/bc/y/z", "a/bd"]
        );
        assert_eq!(list(&t, "a/bc/", Some("/"), None), ["a/bc/x", "[a/bc/y/]"]);
        assert_eq!(list(&t, "a", Some("/"), None), ["[a/]", "ab"]);
        assert_eq!(list(&t, "a/bc/y/z", None, None), ["a/bc/y/z"]);
        assert!(list(&t, "a/none/", None, None).is_empty());
        assert!(list(&t, "a b/", None, None).is_empty());
        assert!(list(&t, "a//", None, None).is_empty());
    }

    /// Every page size from one past the whole listing down to one, resumed from the last
    /// entry of each page as a continuation token does: nothing repeated, nothing skipped.
    #[test]
    fn pages_resume_where_the_last_one_ended() {
        let mut keys = vec!["a-b", "a.b", "a_b", "z"];
        let sharded: Vec<String> = (0..3)
            .flat_map(|x| (0..3).map(move |y| format!("s/{x}/{y}/k{x}{y}")))
            .collect();
        keys.extend(sharded.iter().map(String::as_str));
        keys.extend(["a/x", "a/y/z", "s/1/t", "s/1-t"]);
        let t = tree("pages", &keys);
        for (prefix, delimiter) in [
            ("", None),
            ("", Some("/")),
            ("s/", Some("/")),
            ("s/1", None),
            ("s/1", Some("/")),
            ("", Some("-")),
        ] {
            let whole = list(&t, prefix, delimiter, None);
            assert!(!whole.is_empty());
            for size in 1..=whole.len() + 1 {
                let mut seen = Vec::new();
                let mut after: Option<String> = None;
                loop {
                    let q = Query {
                        prefix: prefix.to_string(),
                        delimiter: delimiter.map(str::to_string),
                        max_keys: size,
                        after: after.clone(),
                        ..Query::default()
                    };
                    let (items, truncated) = page(&t.store, &Authz::NoScopes, "b", &q).unwrap();
                    assert!(items.len() <= size);
                    seen.extend(names(&items));
                    if !truncated {
                        break;
                    }
                    after = items.last().map(|i| i.key().to_string());
                }
                assert_eq!(seen, whole, "{prefix:?} {delimiter:?} by {size}");
            }
        }
    }

    #[test]
    fn max_keys_bounds_a_page_and_none_is_an_empty_complete_one() {
        let t = tree("max", &["a", "b", "c"]);
        let page_of = |max_keys| {
            let q = Query {
                max_keys,
                ..Query::default()
            };
            let (items, truncated) = page(&t.store, &Authz::NoScopes, "b", &q).unwrap();
            (names(&items), truncated)
        };
        assert_eq!(page_of(0), (vec![], false));
        assert_eq!(page_of(1), (vec!["a".to_string()], true));
        assert_eq!(
            page_of(3),
            (vec!["a".into(), "b".into(), "c".into()], false)
        );
        assert!(!page_of(4).1);
    }

    /// A start key inside a subtree resumes inside it; one past it passes over it whole,
    /// listing only the directories on the way down to it.
    #[test]
    fn a_page_starts_after_its_start_key_reading_only_the_way_there() {
        let sharded: Vec<String> = (0..4)
            .flat_map(|x| (0..4).map(move |y| format!("s/{x}/{y}/t")))
            .collect();
        let mut keys: Vec<&str> = sharded.iter().map(String::as_str).collect();
        keys.extend(["a", "s0", "z"]);
        let t = tree("after", &keys);
        assert_eq!(list(&t, "", None, Some("s/3/2/t")), ["s/3/3/t", "s0", "z"]);
        assert_eq!(
            list(&t, "", None, Some("s/3/2")),
            ["s/3/2/t", "s/3/3/t", "s0", "z"]
        );
        assert_eq!(list(&t, "", None, Some("s/")).first().unwrap(), "s/0/0/t");
        assert_eq!(list(&t, "", None, Some("s/9")), ["s0", "z"]);
        assert_eq!(list(&t, "", None, Some("s0")), ["z"]);
        assert_eq!(list(&t, "", Some("/"), Some("a")), ["[s/]", "s0", "z"]);
        // Past a folded prefix, or inside it, the prefix has been listed.
        assert_eq!(list(&t, "", Some("/"), Some("s/")), ["s0", "z"]);
        assert_eq!(list(&t, "", Some("/"), Some("s/1/0/t")), ["s0", "z"]);

        let how = Walk {
            prefix: "",
            delimiter: None,
            after: Some("s/3/2/t"),
            limit: 2,
        };
        let w = walked(&t.store, &Authz::NoScopes, "b", &how).unwrap();
        assert_eq!(names(&w.items), ["s/3/3/t", "s0"]);
        // The bucket, `s`, `s/3`, `s/3/2` and `s/3/3`, of its 22 directories.
        assert_eq!(w.dirs_read, 5);
    }

    #[test]
    fn what_the_caller_may_not_read_is_not_listed() {
        let t = tree("authz", &["a/x", "a/y/z", "k", "s/1/k"]);
        // Bucket `b` itself and `b/a` with what is below it: not `b/s`.
        let key = api_key(&["files/b", "files/b/a/*"]);
        let authz = Authz::Accounts(&key);
        assert_eq!(list_as(&t, &authz, "", None, None), ["a/x", "a/y/z", "k"]);
        assert_eq!(list_as(&t, &authz, "", Some("/"), None), ["[a/]", "k"]);
        assert!(list_as(&t, &authz, "s/", None, None).is_empty());
        // Only `b/a`: the walk starts there for its prefix, and nothing else is listed.
        let key = api_key(&["files/b/a/*"]);
        let authz = Authz::Accounts(&key);
        assert!(list_as(&t, &authz, "", None, None).is_empty());
        assert_eq!(list_as(&t, &authz, "a/", None, None), ["a/x", "a/y/z"]);
        assert!(admitted(&authz, "b", "a/"));
        assert!(admitted(&authz, "b", "a/y"));
        assert!(!admitted(&authz, "b", "a"));
        assert!(!admitted(&authz, "b", ""));
        assert!(!admitted(&authz, "b", "s/"));
        assert!(!admitted(&authz, "c", "a/"));
        assert!(admitted(&Authz::NoScopes, "b", ""));
    }

    #[test]
    fn foreign_tags_and_bytes_unreadable_through_the_key_are_not_listed() {
        let t = tree("foreign", &["k"]);
        let image = br#"{"schemaVersion":2,"layers":[]}"#;
        t.store
            .put_manifest("files/b", "img", MANIFEST_TYPE, image)
            .unwrap();
        t.store
            .put_manifest("files/b", "x-1", MANIFEST_TYPE, image)
            .unwrap();
        assert_eq!(list(&t, "", None, None), ["k"]);
        // A foreign tag is no key for a delimiter to fold either.
        assert_eq!(list(&t, "", Some("-"), None), ["k"]);

        // A manifest tagged in `files/b` whose layer only another repository holds.
        put(&t.store, "secret/s");
        let (manifest, _) = t.store.tag_target("files/secret", "s").unwrap();
        let body = t.store.get_blob(&manifest).unwrap().unwrap();
        t.store
            .put_manifest("files/b", "stolen", MANIFEST_TYPE, &body)
            .unwrap();
        assert_eq!(list(&t, "", None, None), ["k", "stolen"]);
        let key = api_key(&["files/b/*"]);
        assert_eq!(list_as(&t, &Authz::Accounts(&key), "", None, None), ["k"]);
        let key = api_key(&["files/b/*", "files/secret/*"]);
        assert_eq!(
            list_as(&t, &Authz::Accounts(&key), "", None, None),
            ["k", "stolen"]
        );
    }

    #[test]
    fn a_query_names_a_listing_of_either_version() {
        assert!(is_listing(""));
        assert!(is_listing("list-type=2&prefix=a%2F&delimiter=%2F"));
        assert!(is_listing("marker=a&max-keys=2&x-id=ListObjects"));
        assert!(!is_listing("location"));
        assert!(!is_listing("list-type=2&acl"));
        assert!(!is_listing("uploads"));

        let q =
            parse("list-type=2&prefix=a%2F&delimiter=%2F&max-keys=5000&fetch-owner=true").unwrap();
        assert!(q.v2 && q.owner);
        assert_eq!(
            (q.prefix.as_str(), q.delimiter.as_deref(), q.max_keys),
            ("a/", Some("/"), 1000)
        );
        let q = parse("list-type=2&start-after=a&marker=b").unwrap();
        assert_eq!(
            (q.start.as_deref(), q.after.as_deref()),
            (Some("a"), Some("a"))
        );
        let token = vk_hub_proto::token::to_base64url(b"s/1/");
        let q = parse(&format!(
            "list-type=2&start-after=a&continuation-token={token}"
        ))
        .unwrap();
        assert_eq!(q.after.as_deref(), Some("s/1/"));
        assert_eq!(q.token.as_deref(), Some(token.as_str()));
        let q = parse("marker=b&start-after=a&delimiter=").unwrap();
        assert!(!q.v2 && q.owner);
        assert_eq!((q.after.as_deref(), q.delimiter), (Some("b"), None));
        assert_eq!(parse("").unwrap().max_keys, 1000);
        assert_eq!(parse("max-keys=0").unwrap().max_keys, 0);
        assert!(parse("encoding-type=url").unwrap().url);

        let bad_token = |t: &[u8]| {
            let token = vk_hub_proto::token::to_base64url(t);
            parse(&format!("list-type=2&continuation-token={token}")).is_err()
        };
        assert!(bad_token(b"a b"));
        assert!(bad_token(b""));
        assert!(bad_token(&[0xff]));
        assert!(bad_token(&[b'a'; 1025]));
        assert!(!bad_token(&[b'a'; 1024]));
        for bad in [
            "list-type=2&continuation-token=!!",
            "list-type=2&continuation-token=YQ==",
            "list-type=1",
            "max-keys=-1",
            "max-keys=x",
            "encoding-type=base64",
            "prefix=%0A",
            "prefix=%FF",
            "delimiter=%2",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_page_is_escaped_and_url_encoded_when_asked() {
        let t = tree("render", &["d/k"]);
        let q = Query {
            v2: true,
            prefix: "d/".to_string(),
            max_keys: 1000,
            ..Query::default()
        };
        let (items, _) = page(&t.store, &Authz::NoScopes, "b", &q).unwrap();
        let xml = render("b", &q, &items, false);
        let Some(Item::Object(_, obj)) = items.first() else {
            panic!("an object");
        };
        assert!(
            xml.starts_with(
                "<Name>b</Name><Prefix>d/</Prefix><MaxKeys>1000</MaxKeys><KeyCount>1</KeyCount>\
                 <IsTruncated>false</IsTruncated><Contents><Key>d/k</Key><LastModified>"
            ),
            "{xml}"
        );
        assert!(
            xml.contains(&format!(
                ".000Z</LastModified><ETag>{}</ETag><Size>5</Size>\
                 <StorageClass>STANDARD</StorageClass></Contents>",
                xml::escape(&conditional::etag_of(obj))
            )),
            "{xml}"
        );
        assert!(!xml.contains("<Owner>"));

        let q = Query {
            v2: true,
            prefix: "<a b>/".to_string(),
            delimiter: Some("&".to_string()),
            start: Some("\"x".to_string()),
            max_keys: 2,
            ..Query::default()
        };
        let items = vec![Item::Prefix("<a b>/c&".to_string())];
        let xml = render("b", &q, &items, true);
        assert!(xml.contains("<Prefix>&lt;a b&gt;/</Prefix>"), "{xml}");
        assert!(xml.contains("<Delimiter>&amp;</Delimiter>"), "{xml}");
        assert!(xml.contains("<StartAfter>&quot;x</StartAfter>"), "{xml}");
        let token = vk_hub_proto::token::to_base64url(b"<a b>/c&");
        assert!(xml.contains(&format!(
            "<NextContinuationToken>{token}</NextContinuationToken>"
        )));
        assert!(
            xml.contains("<CommonPrefixes><Prefix>&lt;a b&gt;/c&amp;</Prefix></CommonPrefixes>")
        );

        let q = Query { url: true, ..q };
        let xml = render("b", &q, &items, true);
        assert!(xml.contains("<Prefix>%3Ca%20b%3E/</Prefix>"), "{xml}");
        assert!(xml.contains("<Delimiter>%26</Delimiter><EncodingType>url</EncodingType>"));
        assert!(xml.contains("<StartAfter>%22x</StartAfter>"), "{xml}");
        assert!(xml.contains("<Prefix>%3Ca%20b%3E/c%26</Prefix></CommonPrefixes>"));

        // The first version: a marker, the next one, and every object's owner.
        put(&t.store, "b/d/m");
        let q = Query {
            prefix: "d/".to_string(),
            start: Some("d/a".to_string()),
            after: Some("d/a".to_string()),
            max_keys: 1,
            owner: true,
            ..Query::default()
        };
        let (items, truncated) = page(&t.store, &Authz::NoScopes, "b", &q).unwrap();
        let xml = render("b", &q, &items, truncated);
        assert!(
            xml.starts_with(
                "<Name>b</Name><Prefix>d/</Prefix><Marker>d/a</Marker>\
                 <NextMarker>d/k</NextMarker><MaxKeys>1</MaxKeys><IsTruncated>true</IsTruncated>"
            ),
            "{xml}"
        );
        assert!(
            xml.contains(&format!("</Size>{}<StorageClass>", bucket::owner())),
            "{xml}"
        );
        assert!(!xml.contains("KeyCount"));
        assert_eq!(
            iso8601(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(86_401)),
            "1970-01-02T00:00:01.000Z"
        );
    }
}
