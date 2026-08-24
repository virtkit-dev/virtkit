//! `/browse`: read-only, human-facing pages over the same [`Store`] the OCI API serves
//! — a repo list, a repo's tag list, and one manifest's detail (with links to the
//! existing `/v2/<name>/blobs/<digest>` GET for the actual bytes; this module renders
//! HTML, it does not re-serve content).
//!
//! Reached only in accounts mode and only with a resolved principal — `route`'s caller
//! enforces both, and refuses the path outright in shared-secret mode. This is the one
//! surface that *enumerates* repository names, so on top of that gate every page here
//! filters by [`crate::accounts::authorize`]: a principal sees only the repositories it
//! may read, and one it may not read is answered as absent rather than as forbidden.
//!
//! Reference disambiguation reuses the OCI API's own marker instead of inventing one:
//! `/browse/<name>` lists tags, `/browse/<name>/manifests/<reference>` is the detail
//! page — the same `/manifests/` split `route`'s `/v2/` handling already relies on. A
//! repository name with a `manifests` component is the one ambiguous case — the split
//! takes the last one — and it is ambiguous on `/v2/` in exactly the same way.

use anyhow::Result;
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};

use crate::accounts::{Action, authorize};
use crate::html::{self, page, respond};
use crate::{
    Store, accounts, html_escape, human_bytes, manifest_descriptors, valid_digest, valid_name,
    valid_reference,
};

/// Ceiling on the rows any one table here renders, and the reason is the same for all
/// three: no table's length is this server's to decide. A repository count and a tag count
/// are whatever has been pushed — and a rendered repository row costs a `read_dir` for its
/// tag count on top — while a manifest's descriptor count is just a number in pushed JSON,
/// which the manifest PUT does not bound at all. One row per entry would let a push choose
/// how much HTML every later GET of that page builds. Truncate and say so.
const MAX_ROWS: usize = 500;

/// `rest` is the path with its `/browse` prefix already stripped — taking it that way
/// puts "this is a browse path" in the signature instead of in a runtime check the sole
/// caller has already made.
pub(crate) fn route(
    store: &Store,
    rest: &str,
    principal: &accounts::Principal,
    csrf: Option<&str>,
) -> Result<Response<Full<Bytes>>> {
    let rest = rest.trim_start_matches('/');
    if rest.is_empty() {
        return repo_list(store, principal, csrf);
    }
    if let Some(idx) = rest.rfind("/manifests/") {
        let name = &rest[..idx];
        let reference = &rest[idx + "/manifests/".len()..];
        return manifest_detail(store, name, reference, principal, csrf);
    }
    tag_list(store, rest, principal, csrf)
}

fn repo_list(
    store: &Store,
    principal: &accounts::Principal,
    csrf: Option<&str>,
) -> Result<Response<Full<Bytes>>> {
    // Built from the repo directories and their tags, not from `Store::stats()`: stats
    // walks every blob and parses every manifest in the store under the shared store
    // lock, which is a whole-store scan per page load and contention against a `gc`.
    // A listing needs the names and how many tags each has — which is still a bounded walk
    // of `repos/` plus one `read_dir` per rendered row, hence [`MAX_ROWS`].
    //
    // Filtered to what this principal may read: the listing is the only place a
    // repository name is enumerated, so an API key scoped to one team must not learn the
    // others exist from it.
    let mut repos: Vec<String> = store
        .repo_names()
        .into_iter()
        .filter(|name| authorize(principal, Action::Read, name))
        .collect();
    repos.sort();
    // After the scope filter, so the cap counts rows this caller may actually see.
    let total = repos.len();
    let mut rows = String::new();
    for name in repos.iter().take(MAX_ROWS) {
        let tags = store.list_tags(name);
        rows.push_str(&format!(
            "<tr><td><a href=\"/browse/{href}\">{name}</a></td><td>{count}</td>\
             <td>{last}</td></tr>\n",
            href = html_escape(name),
            name = html_escape(name),
            count = tags.len(),
            // The tags are sorted, so this is the last one alphabetically — which is not
            // the newest (`v9` sorts after `v10`), and the column does not claim to be.
            last = tags.last().map(|t| html_escape(t)).unwrap_or_default(),
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td colspan=\"3\"><em>no repositories yet</em></td></tr>\n".to_string();
    }
    if total > MAX_ROWS {
        rows.push_str(&format!(
            "<tr><td colspan=\"3\"><em>{} more not shown</em></td></tr>\n",
            total - MAX_ROWS
        ));
    }
    Ok(respond(
        StatusCode::OK,
        &page(
            "vk-registry",
            principal,
            csrf,
            &format!(
                "<h1>Repositories</h1>\n\
             <table><tr><th>Name</th><th>Tags</th><th>Last tag</th></tr>\n{rows}</table>"
            ),
        ),
    ))
}

fn tag_list(
    store: &Store,
    name: &str,
    principal: &accounts::Principal,
    csrf: Option<&str>,
) -> Result<Response<Full<Bytes>>> {
    // Out of scope reads as absent, not as forbidden: a 403 would confirm the repository
    // exists to someone who may not know that.
    if !valid_name(name) || !authorize(principal, Action::Read, name) {
        return Ok(not_found(principal, csrf));
    }
    let tags = store.list_tags(name);
    let mut rows = String::new();
    for t in tags.iter().take(MAX_ROWS) {
        rows.push_str(&format!(
            "<tr><td><a href=\"/browse/{name}/manifests/{tag}\">{tag}</a></td></tr>\n",
            name = html_escape(name),
            tag = html_escape(t),
        ));
    }
    if rows.is_empty() {
        rows = "<tr><td><em>no tags</em></td></tr>\n".to_string();
    }
    if tags.len() > MAX_ROWS {
        rows.push_str(&format!(
            "<tr><td><em>{} more not shown</em></td></tr>\n",
            tags.len() - MAX_ROWS
        ));
    }
    Ok(respond(
        StatusCode::OK,
        &page(
            &format!("vk-registry: {name}"),
            principal,
            csrf,
            &format!(
                "<p><a href=\"/browse\">&larr; repositories</a></p>\n\
             <h1>{}</h1>\n\
             <table><tr><th>Tag</th></tr>\n{rows}</table>",
                html_escape(name)
            ),
        ),
    ))
}

fn manifest_detail(
    store: &Store,
    name: &str,
    reference: &str,
    principal: &accounts::Principal,
    csrf: Option<&str>,
) -> Result<Response<Full<Bytes>>> {
    if !valid_name(name) || !valid_reference(reference) || !authorize(principal, Action::Read, name)
    {
        return Ok(not_found(principal, csrf));
    }
    // Note that this bumps the tag's mtime, which is the "last used" record `Store::gc`
    // keys tag retention on — so browsing a tag keeps it alive, the same as pulling it.
    // Deliberate (a tag someone is looking at is in use) but worth knowing: a crawler
    // pointed at `/browse` would hold every tag it visits.
    //
    // A browser gets a page, not the OCI JSON error envelope with an error chain in it.
    let found = match store.get_manifest(name, reference) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vk-registry: reading {name}@{reference}: {e:#}");
            return Ok(html::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(principal),
                csrf,
                "Could not read that manifest",
                "The store could not be read. Try again, or ask an operator to look at \
                 the server log.",
            ));
        }
    };
    let Some((digest, data, ctype)) = found else {
        return Ok(not_found(principal, csrf));
    };
    // Not `unwrap_or(Null)`: that renders "no referenced blobs", which is what a valid
    // manifest with no blobs also renders — one that will not parse must not be
    // indistinguishable from an intact one, and nobody would see it in the log either.
    // Reachable without any corruption, note: the manifest PUT stores the body without
    // parsing it, so this is also what a push of `{not json` renders.
    let manifest: serde_json::Value = match serde_json::from_slice(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("vk-registry: {name}@{reference} is not parseable JSON: {e:#}");
            return Ok(html::error(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(principal),
                csrf,
                "Could not read that manifest",
                "The stored manifest is not readable. Ask an operator to look at the \
                 server log.",
            ));
        }
    };
    let descriptors = manifest_descriptors(&manifest);
    let described = descriptors.len();
    let mut blob_rows = String::new();
    for (label, desc) in descriptors.into_iter().take(MAX_ROWS) {
        let raw_digest = desc.get("digest").and_then(|v| v.as_str()).unwrap_or("");
        let size = desc.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
        let media_type = desc.get("mediaType").and_then(|v| v.as_str()).unwrap_or("");
        // A descriptor's digest is whatever the pushed manifest says. Escaping keeps it
        // from breaking out of the attribute, but a link still has to point at a blob:
        // `../../../v2/other/blobs/…` would be a same-origin link to somewhere else.
        // Anything that is not a digest renders as inert text.
        let cell = if valid_digest(raw_digest) {
            format!(
                "<a href=\"/v2/{name}/blobs/{digest}\">{digest}</a>",
                name = html_escape(name),
                digest = html_escape(raw_digest),
            )
        } else {
            format!("<code>{}</code>", html_escape(raw_digest))
        };
        blob_rows.push_str(&format!(
            "<tr><td>{label}</td><td>{cell}</td><td>{size}</td><td>{media_type}</td></tr>\n",
            size = human_bytes(size),
            media_type = html_escape(media_type),
        ));
    }
    if blob_rows.is_empty() {
        // An image index has no config/layers of its own: its children are another level
        // of manifests, which the rest of the crate also handles as a distinct case.
        let children = manifest
            .pointer("/manifests")
            .and_then(|m| m.as_array())
            .map(|m| m.len());
        blob_rows = match children {
            Some(n) => format!(
                "<tr><td colspan=\"4\"><em>image index, {n} child manifest(s)</em></td></tr>\n"
            ),
            None => "<tr><td colspan=\"4\"><em>no referenced blobs</em></td></tr>\n".to_string(),
        };
    }
    if described > MAX_ROWS {
        blob_rows.push_str(&format!(
            "<tr><td colspan=\"4\"><em>{} more not shown</em></td></tr>\n",
            described - MAX_ROWS
        ));
    }
    Ok(respond(
        StatusCode::OK,
        &page(
            &format!("vk-registry: {name}@{reference}"),
            principal,
            csrf,
            &format!(
                "<p><a href=\"/browse\">&larr; repositories</a> / <a href=\"/browse/{name}\">{name}</a></p>\n\
             <h1>{reference}</h1>\n\
             <p>digest: <code>{digest}</code> &middot; content-type: <code>{ctype}</code></p>\n\
             <table><tr><th></th><th>Digest</th><th>Size</th><th>Media type</th></tr>\n{blob_rows}</table>",
                name = html_escape(name),
                reference = html_escape(reference),
                digest = html_escape(&digest),
                ctype = html_escape(&ctype),
            ),
        ),
    ))
}

/// A 404 a person can read, keeping the page chrome — which for a session carries a link
/// back to the listing, and for an API key carries only who it is: a machine credential is
/// not going to navigate.
fn not_found(principal: &accounts::Principal, csrf: Option<&str>) -> Response<Full<Bytes>> {
    html::error(
        StatusCode::NOT_FOUND,
        Some(principal),
        csrf,
        "Not found",
        "No such repository or reference.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    fn session(name: &str) -> accounts::Principal {
        accounts::Principal::Session(accounts::User {
            id: "https://issuer\u{1f}sub-1".to_string(),
            oidc_issuer: "https://issuer".to_string(),
            oidc_subject: "sub-1".to_string(),
            email: None,
            display_name: Some(name.to_string()),
            is_admin: false,
            created_at: std::time::SystemTime::UNIX_EPOCH,
            last_login_at: std::time::SystemTime::UNIX_EPOCH,
        })
    }

    async fn body_of(res: Response<Full<Bytes>>) -> String {
        String::from_utf8(res.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
    }

    const MANIFEST_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

    /// [`route`] by the URL a page is reached at, stripped the way `route`'s caller
    /// strips it — so a test names the URL it means rather than the remainder.
    fn page_at(
        store: &Store,
        path: &str,
        principal: &accounts::Principal,
        csrf: Option<&str>,
    ) -> Result<Response<Full<Bytes>>> {
        let rest = path
            .strip_prefix("/browse")
            .expect("a /browse path")
            .trim_start_matches('/');
        route(store, rest, principal, csrf)
    }

    fn store_in(tag: &str) -> (std::path::PathBuf, Store) {
        let dir = std::env::temp_dir().join(format!("vk-browse-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::new(dir.clone()).unwrap();
        (dir, store)
    }

    #[tokio::test]
    async fn repo_list_renders_an_empty_store() {
        let (dir, store) = store_in("empty");
        let res = page_at(&store, "/browse", &session("Alice"), Some("csrf-token")).unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let html = body_of(res).await;
        assert!(html.contains("no repositories yet"), "{html}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tag_list_rejects_a_traversal_attempt() {
        let (dir, store) = store_in("trav");
        let res = page_at(
            &store,
            "/browse/../../etc",
            &session("Alice"),
            Some("csrf-token"),
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every page carries the headers that keep an authenticated inventory listing from
    /// being cached, sniffed, framed, or leaked through a referrer.
    #[test]
    fn every_page_carries_its_security_headers() {
        let (dir, store) = store_in("headers");
        for path in ["/browse", "/browse/nope", "/browse/a/manifests/b"] {
            let res = page_at(&store, path, &session("Alice"), Some("csrf-token")).unwrap();
            let h = res.headers();
            assert_eq!(
                h.get(hyper::header::CONTENT_TYPE).unwrap(),
                "text/html; charset=utf-8",
                "{path}"
            );
            assert_eq!(h.get(hyper::header::CACHE_CONTROL).unwrap(), "no-store");
            assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
            assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
            assert_eq!(
                h.get("content-security-policy").unwrap(),
                crate::html::CSP,
                "{path}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn manifest_detail_round_trips_a_pushed_manifest() {
        let (dir, store) = store_in("detail");
        let cfg_digest = store.put_blob(b"config bytes").unwrap();
        let manifest = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": cfg_digest, "size": 12, "mediaType": "application/vnd.oci.image.config.v1+json"},
            "layers": []
        });
        store
            .put_manifest(
                "team-a/app",
                "v1",
                "application/vnd.oci.image.manifest.v1+json",
                &serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();

        let list = page_at(&store, "/browse", &session("Alice"), Some("csrf-token")).unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        let listing = body_of(list).await;
        assert!(listing.contains("/browse/team-a/app"), "{listing}");

        let tags = page_at(
            &store,
            "/browse/team-a/app",
            &session("Alice"),
            Some("csrf-token"),
        )
        .unwrap();
        assert_eq!(tags.status(), StatusCode::OK);

        let detail = page_at(
            &store,
            "/browse/team-a/app/manifests/v1",
            &session("Alice"),
            Some("csrf-token"),
        )
        .unwrap();
        assert_eq!(detail.status(), StatusCode::OK);
        let html = body_of(detail).await;
        assert!(
            html.contains(&format!("/v2/team-a/app/blobs/{cfg_digest}")),
            "{html}"
        );

        let missing = page_at(
            &store,
            "/browse/team-a/app/manifests/nope",
            &session("Alice"),
            Some("csrf-token"),
        )
        .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A descriptor's digest comes from pushed manifest JSON, so it is not trusted to be
    /// a digest at all: it must not become a link to somewhere else on this origin, and
    /// it must not break out of the attribute.
    #[tokio::test]
    async fn a_descriptor_digest_is_never_trusted_as_a_link() {
        let (dir, store) = store_in("digest");
        let manifest = serde_json::json!({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "digest": "../../../v2/other/blobs/sha256:aaa",
                "size": 1,
                "mediaType": "application/vnd.oci.image.config.v1+json",
            },
            "layers": [{
                "digest": "sha256:\"><script>alert(1)</script>",
                "size": 2,
                "mediaType": "text/plain",
            }],
        });
        store
            .put_manifest(
                "team-a/app",
                "v1",
                "application/vnd.oci.image.manifest.v1+json",
                &serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
        let html = body_of(
            page_at(
                &store,
                "/browse/team-a/app/manifests/v1",
                &session("A"),
                Some("csrf-token"),
            )
            .unwrap(),
        )
        .await;
        assert!(!html.contains("href=\"/v2/team-a/app/blobs/../"), "{html}");
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An image index has no config or layers; say so rather than render a blank table.
    #[tokio::test]
    async fn an_image_index_says_what_it_is() {
        let (dir, store) = store_in("index");
        let index = serde_json::json!({
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:aa", "size": 1},
                {"digest": "sha256:bb", "size": 2},
            ],
        });
        store
            .put_manifest(
                "team-a/multi",
                "v1",
                "application/vnd.oci.image.index.v1+json",
                &serde_json::to_vec(&index).unwrap(),
            )
            .unwrap();
        let html = body_of(
            page_at(
                &store,
                "/browse/team-a/multi/manifests/v1",
                &session("A"),
                Some("csrf-token"),
            )
            .unwrap(),
        )
        .await;
        assert!(html.contains("image index, 2 child manifest(s)"), "{html}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Repository names come off the filesystem and tag names come from a pusher, so
    /// both reach the page as text. `valid_name`/`valid_reference` already exclude the
    /// characters that would matter, which is exactly why a directory that is *not* a
    /// valid repository must not be rendered as one at all.
    #[tokio::test]
    async fn only_valid_repo_names_are_listed_and_they_reach_the_page_as_text() {
        let (dir, store) = store_in("names");
        store
            .put_manifest("team-a/app", "v1.0_x-y", MANIFEST_TYPE, b"{}")
            .unwrap();
        // a directory in `repos/` that this store would never have written
        let planted = dir.join("repos").join("<script>").join("tags");
        std::fs::create_dir_all(&planted).unwrap();
        std::fs::write(planted.join("evil"), b"sha256:aa").unwrap();

        let html = body_of(page_at(&store, "/browse", &session("A"), Some("t")).unwrap()).await;
        assert!(html.contains("/browse/team-a/app"), "{html}");
        assert!(
            !html.contains("script") && !html.contains("&lt;script&gt;"),
            "a name this store could not have written is not a repository: {html}"
        );

        let tags =
            body_of(page_at(&store, "/browse/team-a/app", &session("A"), Some("t")).unwrap()).await;
        assert!(tags.contains("v1.0_x-y"), "{tags}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No table's length is this server's to decide, so each truncates at [`MAX_ROWS`] and
    /// says by how much. Both halves are asserted: how many rows were actually rendered
    /// (the ceiling) and the note (that it says so).
    #[tokio::test]
    async fn every_table_truncates_at_the_row_cap_and_says_so() {
        let (dir, store) = store_in("rows");
        for i in 0..MAX_ROWS + 3 {
            store
                .put_manifest(&format!("repo-{i:04}"), "v1", MANIFEST_TYPE, b"{}")
                .unwrap();
        }
        let html = body_of(page_at(&store, "/browse", &session("A"), Some("t")).unwrap()).await;
        assert_eq!(
            html.matches("<a href=\"/browse/repo-").count(),
            MAX_ROWS,
            "the repo list renders exactly the cap"
        );
        assert!(html.contains("3 more not shown"), "and says it truncated");
        // sorted, so it is the tail of the names that is dropped
        assert!(
            !html.contains("repo-0502"),
            "the last name is the one dropped"
        );

        for i in 0..MAX_ROWS + 4 {
            store
                .put_manifest("many-tags", &format!("v{i:04}"), MANIFEST_TYPE, b"{}")
                .unwrap();
        }
        let html =
            body_of(page_at(&store, "/browse/many-tags", &session("A"), Some("t")).unwrap()).await;
        assert_eq!(
            html.matches("/manifests/v").count(),
            MAX_ROWS,
            "the tag list renders exactly the cap"
        );
        assert!(html.contains("4 more not shown"), "and says it truncated");

        let layers: Vec<_> = (0..MAX_ROWS + 2)
            .map(|i| serde_json::json!({"digest": format!("sha256:{i:064x}"), "size": 1}))
            .collect();
        let manifest = serde_json::json!({"layers": layers});
        store
            .put_manifest(
                "big",
                "v1",
                MANIFEST_TYPE,
                &serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
        let html =
            body_of(page_at(&store, "/browse/big/manifests/v1", &session("A"), Some("t")).unwrap())
                .await;
        assert_eq!(
            html.matches("/blobs/sha256:").count(),
            MAX_ROWS,
            "the descriptor table renders exactly the cap"
        );
        assert!(html.contains("2 more not shown"), "and says it truncated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A stored manifest that will not parse is a failure, not a manifest with no blobs —
    /// the two must not render the same page.
    #[tokio::test]
    async fn an_unparseable_manifest_is_an_error_not_an_empty_one() {
        let (dir, store) = store_in("corrupt");
        store
            .put_manifest("team-a/app", "v1", MANIFEST_TYPE, b"{not json")
            .unwrap();
        let res = page_at(
            &store,
            "/browse/team-a/app/manifests/v1",
            &session("A"),
            Some("t"),
        )
        .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let html = body_of(res).await;
        assert!(!html.contains("no referenced blobs"), "{html}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With no CSRF token there is nothing a sign-out POST could carry, so the control is
    /// left out rather than rendered as a button whose only outcome is a 403.
    #[tokio::test]
    async fn the_sign_out_control_is_omitted_without_a_token() {
        let (dir, store) = store_in("nocsrf");
        let html = body_of(page_at(&store, "/browse", &session("Alice"), None).unwrap()).await;
        assert!(html.contains("signed in as Alice"), "{html}");
        assert!(!html.contains("<form"), "{html}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A display name is an identity-provider claim: it reaches the page as text, never
    /// as markup. And the sign-out control is a CSRF-carrying POST, not a link.
    #[tokio::test]
    async fn identity_claims_are_escaped_and_sign_out_is_a_guarded_post() {
        let (dir, store) = store_in("nav");
        let html = body_of(
            page_at(
                &store,
                "/browse",
                &session("<script>alert(1)</script>"),
                Some("csrf-token"),
            )
            .unwrap(),
        )
        .await;
        assert!(!html.contains("<script>alert(1)</script>"), "{html}");
        assert!(html.contains("&lt;script&gt;"), "{html}");
        assert!(
            html.contains("<form method=\"post\" action=\"/logout\">"),
            "{html}"
        );
        assert!(
            html.contains("name=\"csrf\" value=\"csrf-token\""),
            "{html}"
        );
        assert!(!html.contains("<a href=\"/logout\""), "{html}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
