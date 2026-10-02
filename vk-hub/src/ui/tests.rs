//! The web UI over a real socket: sign-in, sessions, the checks on a state-changing request,
//! the headers on every response, and what a hostile host's strings become on a page.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;
use crate::local::{Listing, Local};
use crate::store::Db;

/// A hub with its UI on an ephemeral loopback port, plain HTTP; the UI's origin.
async fn start() -> (SocketAddr, Arc<Hub>, String) {
    let (addr, hub, origin, _) = start_local(None).await;
    (addr, hub, origin)
}

/// [`start`], the UI configured as reached at `origin` instead of at its own address.
async fn start_as(origin: Option<&str>) -> (SocketAddr, Arc<Hub>, String) {
    let (addr, hub, origin, _) = start_local(origin).await;
    (addr, hub, origin)
}

/// [`start_as`], with the machine whose VMs it shows: no `vk` is run, so its listing is the
/// test's to set.
async fn start_local(origin: Option<&str>) -> (SocketAddr, Arc<Hub>, String, Arc<Local>) {
    start_with_vk(origin, "/nonexistent/vk".into(), local::VIEWS_FRESH).await
}

/// [`start_local`], running `vk` for what it runs, and showing what a VM's page read again
/// for `fresh`.
async fn start_with_vk(
    origin: Option<&str>,
    vk: std::path::PathBuf,
    fresh: Duration,
) -> (SocketAddr, Arc<Hub>, String, Arc<Local>) {
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = origin.map_or_else(|| format!("http://{addr}"), str::to_string);
    let hub = Arc::new(Hub::new(
        Arc::new(Db::open_memory().unwrap()),
        origin.clone(),
    ));
    let local = Arc::new(Local::new(vk));
    let mut ui = Ui::new(hub.clone(), &origin, local.clone());
    ui.views = local::ViewCache::new(fresh);
    tokio::spawn(serve(listener, Arc::new(ui)));
    (addr, hub, origin, local)
}

struct Reply {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// One request by hand, `headers` given as whole lines; `Host` is the listener's address
/// unless they name one.
async fn request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &str,
) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !headers
        .iter()
        .any(|h| h.to_ascii_lowercase().starts_with("host:"))
    {
        head.push_str(&format!("Host: {addr}\r\n"));
    }
    for h in headers {
        head.push_str(h);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(body.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let resp = String::from_utf8(resp).unwrap();
    let (head, body) = resp.split_once("\r\n\r\n").unwrap();
    let mut lines = head.lines();
    let status = lines.next().unwrap()[9..12].parse().unwrap();
    let headers = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Reply {
        status,
        headers,
        body: body.to_string(),
    }
}

async fn get(addr: SocketAddr, path: &str, cookie: Option<&str>) -> Reply {
    match cookie {
        Some(c) => request(addr, "GET", path, &[&format!("Cookie: {c}")], "").await,
        None => request(addr, "GET", path, &[], "").await,
    }
}

/// Post sign-in token `token` as the sign-in page does, with `headers` besides.
async fn post_login(addr: SocketAddr, token: &str, headers: &[&str]) -> Reply {
    let mut all = vec!["Sec-Fetch-Site: same-origin"];
    all.extend_from_slice(headers);
    request(addr, "POST", LOGIN_PATH, &all, &format!("t={token}")).await
}

/// Sign in as `role`: the cookie pair, and the session's CSRF token.
async fn sign_in(addr: SocketAddr, hub: &Hub, role: Role) -> (String, String) {
    let (token, _) = hub
        .db
        .create_login(role, Duration::from_secs(60), "uid 0", crate::now_secs())
        .unwrap();
    let reply = post_login(addr, &token, &[]).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let set = reply.header("set-cookie").unwrap().to_string();
    let pair = set.split(';').next().unwrap().to_string();
    let secret = pair.split_once('=').unwrap().1;
    let csrf = csrf_token(secret);
    (pair, csrf)
}

/// The headers every response carries, whatever it is.
fn assert_secure(reply: &Reply) {
    assert_eq!(reply.header("content-security-policy"), Some(CSP));
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(reply.header("referrer-policy"), Some("same-origin"));
    assert_eq!(
        reply.header("cross-origin-resource-policy"),
        Some("same-origin")
    );
    assert_eq!(
        reply.header("cross-origin-opener-policy"),
        Some("same-origin")
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_link_opens_one_session_with_a_strict_cookie() {
    let (addr, hub, _) = start().await;
    let reply = get(addr, "/", None).await;
    assert_eq!(reply.status, 401);
    assert_secure(&reply);
    assert_eq!(reply.header("cache-control"), Some("no-store"));

    let (token, _) = hub
        .db
        .create_login(
            Role::Viewer,
            Duration::from_secs(60),
            "uid 0",
            crate::now_secs(),
        )
        .unwrap();
    // The link's page spends nothing, however often it is fetched: it posts the token back.
    for _ in 0..2 {
        let reply = get(addr, &format!("{LOGIN_PATH}?t={token}"), None).await;
        assert_eq!(reply.status, 200);
        assert_secure(&reply);
        assert!(reply.header("set-cookie").is_none());
        assert!(
            reply
                .body
                .contains(&format!("name=\"t\" value=\"{token}\"")),
            "{}",
            reply.body
        );
        assert!(reply.body.contains("method=\"post\" action=\"/login\""));
    }
    // Only from the sign-in page: not another site's, nor a post that says nothing of where
    // it came from.
    for headers in [
        vec!["Sec-Fetch-Site: cross-site"],
        vec!["Sec-Fetch-Site: same-site"],
        vec!["Origin: http://evil.example"],
    ] {
        let mut all = headers.clone();
        all.insert(0, "Content-Type: application/x-www-form-urlencoded");
        let reply = request(addr, "POST", LOGIN_PATH, &all, &format!("t={token}")).await;
        assert_eq!(reply.status, 403, "{headers:?}");
    }
    let reply = request(addr, "POST", LOGIN_PATH, &[], &format!("t={token}")).await;
    assert_eq!(reply.status, 403);
    let reply = post_login(addr, &token, &[]).await;
    assert_eq!(reply.status, 200);
    assert_secure(&reply);
    assert!(
        reply.body.contains("http-equiv=\"refresh\""),
        "{}",
        reply.body
    );
    let set = reply.header("set-cookie").unwrap();
    assert!(set.starts_with("vk-hub="), "{set}");
    for attr in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=43200"] {
        assert!(set.contains(attr), "{set}");
    }
    // Plain http: no `Secure`, which a browser would refuse to store.
    assert!(!set.contains("Secure"), "{set}");
    let pair = set.split(';').next().unwrap();

    // Spent, by that post alone; `Sec-Fetch-Site: none` is a post no page made, allowed.
    let again = post_login(addr, &token, &[]).await;
    assert_eq!(again.status, 403);
    let bogus = format!("vkl_{}", "0".repeat(64));
    assert_eq!(post_login(addr, &bogus, &[]).await.status, 403);
    let reply = request(
        addr,
        "POST",
        LOGIN_PATH,
        &["Sec-Fetch-Site: none"],
        &format!("t={bogus}"),
    )
    .await;
    assert!(
        reply.body.contains("unknown, used or expired"),
        "{}",
        reply.body
    );
    assert_eq!(
        get(addr, &format!("{LOGIN_PATH}?t=nope"), None)
            .await
            .status,
        403
    );

    let reply = get(addr, "/", Some(pair)).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_secure(&reply);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert!(reply.body.contains("(viewer)"), "{}", reply.body);
    // The database holds only the secret's hash, and the session lists by its prefix.
    let sessions = hub.db.ui_sessions(crate::now_secs()).unwrap();
    assert_eq!(sessions.len(), 1);
    let secret = pair.split_once('=').unwrap().1;
    assert!(!sessions[0].id.is_empty() && !secret.starts_with(&sessions[0].id));
    let events: Vec<String> = hub
        .db
        .audits(10)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    assert!(
        events.iter().any(|e| e
            == &format!(
                "ui session {} (viewer) signed in with a link uid 0 issued",
                sessions[0].id
            )),
        "{events:?}"
    );

    // Ended on the admin side: the cookie opens nothing.
    assert_eq!(
        hub.db
            .end_ui_sessions(Some(&sessions[0].id), "uid 0", crate::now_secs())
            .unwrap(),
        1
    );
    assert_eq!(get(addr, "/", Some(pair)).await.status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_post_needs_the_ui_origin_and_the_session_csrf_token() {
    let (addr, hub, origin) = start().await;
    let (cookie, csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let cookie = format!("Cookie: {cookie}");
    let origin_ok = format!("Origin: {origin}");
    let form = format!("_csrf={csrf}");
    let post = |headers: Vec<String>, body: String| async move {
        let headers: Vec<&str> = headers.iter().map(String::as_str).collect();
        request(addr, "POST", "/logout", &headers, &body).await
    };
    // Neither Origin nor Sec-Fetch-Site; another origin; a cross-site fetch.
    for headers in [
        vec![cookie.clone()],
        vec![cookie.clone(), "Origin: http://evil.example".to_string()],
        vec![
            cookie.clone(),
            origin_ok.clone(),
            "Sec-Fetch-Site: cross-site".to_string(),
        ],
    ] {
        let reply = post(headers, form.clone()).await;
        assert_eq!(reply.status, 403, "{}", reply.body);
        assert_secure(&reply);
    }
    // The right origin, without the token or with another session's.
    let reply = post(vec![cookie.clone(), origin_ok.clone()], String::new()).await;
    assert_eq!(reply.status, 403);
    assert!(reply.body.contains("CSRF"), "{}", reply.body);
    let reply = post(
        vec![cookie.clone(), origin_ok.clone()],
        format!("_csrf={}", csrf_token(&"ab".repeat(32))),
    )
    .await;
    assert_eq!(reply.status, 403);
    // No session at all.
    let reply = post(vec![origin_ok.clone()], form.clone()).await;
    assert_eq!(reply.status, 401);
    assert_eq!(hub.db.ui_sessions(crate::now_secs()).unwrap().len(), 1);

    // `Origin: null` names no origin, and alone proves nothing.
    let reply = post(
        vec![cookie.clone(), "Origin: null".to_string()],
        form.clone(),
    )
    .await;
    assert_eq!(reply.status, 403);

    // Same-origin by Sec-Fetch-Site alone, beside an opaque `Origin: null`, and the token in
    // a header.
    let reply = post(
        vec![
            cookie.clone(),
            "Origin: null".to_string(),
            "Sec-Fetch-Site: same-origin".to_string(),
            format!("X-CSRF-Token: {csrf}"),
        ],
        String::new(),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.header("set-cookie").unwrap().contains("Max-Age=0"));
    assert!(hub.db.ui_sessions(crate::now_secs()).unwrap().is_empty());
    let events: Vec<String> = hub
        .db
        .audits(10)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    assert!(
        events.iter().any(|e| e.ends_with("(viewer) signed out")),
        "{events:?}"
    );
}

fn workload(id: &str, label: &str) -> vk_hub_proto::Workload {
    vk_hub_proto::Workload {
        id: id.into(),
        kind: vk_hub_proto::WorkloadKind::Run,
        state_dir: format!("/s/{label}"),
        label: Some(label.into()),
        project: None,
        job_name: None,
        job_id: None,
        workspace: Some("/src/app".into()),
        environment: None,
        pid: Some(4242),
        cpus: Some(2),
        mem_reserved_mib: Some(2048),
        started_at: Some(1_790_755_279),
        ssh_alias: None,
        guest_workspace: None,
    }
}

fn listed(workloads: Vec<vk_hub_proto::Workload>) -> Listing {
    Listing::Listed(vk_hub_proto::WorkloadList {
        version: vk_hub_proto::WORKLOADS_VERSION,
        mem_bytes: workloads
            .iter()
            .map(|w| (w.id.clone(), 300 << 20))
            .collect(),
        workloads,
        omitted: 0,
    })
}

/// The list as `vk workloads` last gave it, each VM leading to a page of its own; before
/// the first list and after a failure, a line saying so.
#[tokio::test(flavor = "multi_thread")]
async fn the_vms_are_listed_each_with_a_page() {
    let (addr, hub, _, local) = start_local(None).await;
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let reply = get(addr, "/", Some(&cookie)).await;
    assert_eq!(reply.status, 200);
    assert!(reply.body.contains("Asking"), "{}", reply.body);
    local.set_listing(Listing::Failed("it exited (exit status: 1)".into()), &hub);
    let reply = get(addr, "/", Some(&cookie)).await;
    assert!(reply.body.contains("exit status: 1"), "{}", reply.body);
    local.set_listing(listed(Vec::new()), &hub);
    assert!(
        get(addr, "/", Some(&cookie))
            .await
            .body
            .contains("No VM is running")
    );

    let id = "0123456789abcdef";
    local.set_listing(listed(vec![workload(id, "alpine:3.20")]), &hub);
    let reply = get(addr, "/", Some(&cookie)).await;
    assert!(
        reply.body.contains(&format!("href=\"/vm/{id}\"")),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains("alpine:3.20 in /src/app"),
        "{}",
        reply.body
    );
    assert!(reply.body.contains("300 MiB"), "{}", reply.body);
    assert!(reply.body.contains("2026-09-30T08:01Z"), "{}", reply.body);
    let reply = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("/s/alpine:3.20"), "{}", reply.body);
    assert!(reply.body.contains("4242"), "{}", reply.body);
    // A malformed ID, or one no VM has, is no page.
    for path in ["/vm/zz", "/vm/0123456789ABCDEF", "/vm/fedcba9876543210"] {
        assert_eq!(get(addr, path, Some(&cookie)).await.status, 404, "{path}");
    }
}

/// What the host's `vk` reports reaches a page as text: nothing it says becomes markup or
/// script, and an ID that is not one of its own is not made into a link.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_vm_is_shown_as_text() {
    let (addr, hub, _, local) = start_local(None).await;
    let hostile = "<script>alert(1)</script>\"'><img src=x onerror=alert(2)>";
    let mut w = workload("0123456789abcdef", hostile);
    w.workspace = Some(format!("{hostile}\u{202e}"));
    let mut odd = workload(hostile, "x");
    odd.state_dir = hostile.into();
    local.set_listing(listed(vec![w, odd]), &hub);
    hub.db
        .create_login(
            Role::Viewer,
            Duration::from_secs(60),
            hostile,
            crate::now_secs(),
        )
        .unwrap();
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    for path in ["/", "/vm/0123456789abcdef", "/audit"] {
        let reply = get(addr, path, Some(&cookie)).await;
        assert_eq!(reply.status, 200, "{path}: {}", reply.body);
        assert!(
            !reply.body.contains("<script>alert"),
            "{path}: {}",
            reply.body
        );
        assert!(!reply.body.contains("<img"), "{path}: {}", reply.body);
        assert!(!reply.body.contains('\u{202e}'), "{path}");
        assert!(
            reply
                .body
                .contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&gt;"),
            "{path}: {}",
            reply.body
        );
    }
    let reply = get(addr, "/", Some(&cookie)).await;
    assert_eq!(
        reply.body.matches("href=\"/vm/").count(),
        1,
        "{}",
        reply.body
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn assets_are_served_for_good_under_their_hash() {
    let (addr, _, _) = start().await;
    let path = assets::url(assets::CSS);
    assert!(
        path.starts_with("/assets/") && path.ends_with("/ui.css"),
        "{path}"
    );
    let reply = get(addr, path, None).await;
    assert_eq!(reply.status, 200);
    assert_secure(&reply);
    assert_eq!(
        reply.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert!(
        reply
            .header("content-type")
            .unwrap()
            .starts_with("text/css")
    );
    let etag = reply.header("etag").unwrap().to_string();
    let reply = request(addr, "GET", path, &[&format!("If-None-Match: {etag}")], "").await;
    assert_eq!(reply.status, 304);
    for (name, script) in [
        (assets::HTMX, include_str!("../../assets/htmx.min.js")),
        (assets::SSE, include_str!("../../assets/sse.min.js")),
    ] {
        let reply = get(addr, assets::url(name), None).await;
        assert_eq!(reply.status, 200);
        assert!(
            reply
                .header("content-type")
                .unwrap()
                .starts_with("text/javascript")
        );
        assert_eq!(reply.body, script);
    }
    // Another hash is no asset: pages need a session.
    assert_eq!(get(addr, "/assets/0000/ui.css", None).await.status, 401);
}

#[test]
fn forms_and_cookies_parse() {
    assert_eq!(
        decode_form(b"a=1&b=x+y%21&&c=&d"),
        [
            ("a".to_string(), "1".to_string()),
            ("b".to_string(), "x y!".to_string()),
            ("c".to_string(), String::new()),
            ("d".to_string(), String::new()),
        ]
    );
    assert!(decode_form(b"a=%zz&b=%ff&c=%+f&d=%f").is_empty());
    assert_eq!(field(&decode_form(b"a=1&a=2"), "a"), Some("1"));
    let mut h = HeaderMap::new();
    h.append(header::COOKIE, HeaderValue::from_static("x=1; vk-hub=abc"));
    h.append(header::COOKIE, HeaderValue::from_static("y=2"));
    assert_eq!(session_cookie(&h), Ok(Some("abc")));
    h.append(header::COOKIE, HeaderValue::from_static("vk-hub=def"));
    assert_eq!(session_cookie(&h), Err(()));
    assert_eq!(session_cookie(&HeaderMap::new()), Ok(None));
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd") && !constant_time_eq(b"abc", b"ab"));
}

/// A request must name the UI's host, whatever else it carries: another name for this
/// address reaches nothing.
#[tokio::test(flavor = "multi_thread")]
async fn only_the_ui_s_own_name_is_served() {
    let host = "vk-0123456789abcdef.localhost:4242";
    let (addr, hub, _) = start_as(Some(&format!("http://{host}"))).await;
    let (token, _) = hub
        .db
        .create_login(
            Role::Viewer,
            Duration::from_secs(60),
            "uid 0",
            crate::now_secs(),
        )
        .unwrap();
    let reply = post_login(
        addr,
        &token,
        &[&format!("Host: {host}"), &format!("Origin: http://{host}")],
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let pair = reply
        .header("set-cookie")
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let ok = request(
        addr,
        "GET",
        "/",
        &[
            "Host: VK-0123456789abcdef.localhost:4242",
            &format!("Cookie: {pair}"),
        ],
        "",
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    for other in [
        format!("Host: {addr}"),
        "Host: vk-0123456789abcdef.localhost:4243".to_string(),
        "Host: evil.example".to_string(),
    ] {
        let rebound = request(addr, "GET", "/", &[&other, &format!("Cookie: {pair}")], "").await;
        assert_eq!(rebound.status, 421, "{other}");
        assert_secure(&rebound);
    }
}

/// A page goes only to a request of the UI's own pages or of none — not to another site's,
/// nor to a page on another port of the same name, which `SameSite` sends the cookie with.
#[tokio::test(flavor = "multi_thread")]
async fn a_page_is_not_for_another_site() {
    let (addr, hub, _) = start().await;
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let cookie = format!("Cookie: {cookie}");
    for site in ["same-origin", "none"] {
        let header = format!("Sec-Fetch-Site: {site}");
        let reply = request(addr, "GET", "/", &[&cookie, &header], "").await;
        assert_eq!(reply.status, 200, "{site}: {}", reply.body);
    }
    for site in ["same-site", "cross-site"] {
        let header = format!("Sec-Fetch-Site: {site}");
        for path in ["/", "/audit"] {
            let reply = request(addr, "GET", path, &[&cookie, &header], "").await;
            assert_eq!(reply.status, 403, "{site} {path}");
            assert!(reply.body.contains("another site"), "{}", reply.body);
            assert_secure(&reply);
        }
    }
    // A sign-in link is opened from wherever it was pasted.
    let reply = request(
        addr,
        "GET",
        &format!("{LOGIN_PATH}?t=vkl_{}", "0".repeat(64)),
        &["Sec-Fetch-Site: cross-site"],
        "",
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
}

/// A browser's sign-out ends its own session, not another listed under the same ID.
#[tokio::test(flavor = "multi_thread")]
async fn a_sign_out_ends_this_session_alone() {
    let (addr, hub, origin) = start().await;
    let (mine, csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let (other, _) = sign_in(addr, &hub, Role::Viewer).await;
    let reply = request(
        addr,
        "POST",
        "/logout",
        &[&format!("Cookie: {mine}"), &format!("Origin: {origin}")],
        &format!("_csrf={csrf}"),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(get(addr, "/", Some(&mine)).await.status, 401);
    assert_eq!(get(addr, "/", Some(&other)).await.status, 200);
}

/// A second session cookie is what one planted by another service on this host looks like:
/// neither is taken.
#[tokio::test(flavor = "multi_thread")]
async fn two_session_cookies_sign_in_neither() {
    let (addr, hub, _) = start().await;
    let (cookie, _) = sign_in(addr, &hub, Role::Operator).await;
    let planted = format!("vk-hub={}", "ab".repeat(32));
    for header in [
        format!("Cookie: {planted}; {cookie}"),
        format!("Cookie: {cookie}; vk-hub=x"),
    ] {
        let reply = request(addr, "GET", "/", &[&header], "").await;
        assert_eq!(reply.status, 401, "{header}");
        assert!(reply.body.contains("more than one"), "{}", reply.body);
    }
    let two = request(
        addr,
        "GET",
        "/",
        &[&format!("Cookie: {cookie}"), &format!("Cookie: {planted}")],
        "",
    )
    .await;
    assert_eq!(two.status, 401);
    assert_eq!(get(addr, "/", Some(&cookie)).await.status, 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_form_too_large_or_too_slow_is_refused() {
    let (addr, hub, origin) = start().await;
    let (cookie, csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let cookie = format!("Cookie: {cookie}");
    let origin = format!("Origin: {origin}");
    let big = format!("_csrf={csrf}&pad={}", "x".repeat(MAX_FORM));
    let reply = request(addr, "POST", "/logout", &[&cookie, &origin], &big).await;
    assert_eq!(reply.status, 413);
    // A body announced and never sent.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /logout HTTP/1.1\r\nHost: {addr}\r\n{cookie}\r\n{origin}\r\n\
         Content-Length: 100\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    tokio::time::timeout(FORM_TIMEOUT * 5, stream.read_to_end(&mut resp))
        .await
        .unwrap()
        .unwrap();
    assert!(
        resp.starts_with(b"HTTP/1.1 408"),
        "{}",
        String::from_utf8_lossy(&resp)
    );
    assert_eq!(hub.db.ui_sessions(crate::now_secs()).unwrap().len(), 1);
}

/// An event stream's response, read by hand through its chunked framing.
struct Events {
    stream: tokio::net::TcpStream,
    head: String,
    buf: Vec<u8>,
    /// Decoded body not yet returned.
    body: String,
    /// The last chunk has been read.
    ended: bool,
}

impl Events {
    async fn open(addr: SocketAddr, path: &str, cookie: &str) -> Events {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nCookie: {cookie}\r\n\r\n");
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut events = Events {
            stream,
            head: String::new(),
            buf: Vec::new(),
            body: String::new(),
            ended: false,
        };
        while !events.buf.windows(4).any(|w| w == b"\r\n\r\n") {
            assert!(events.fill().await, "no response head");
        }
        let split = events
            .buf
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .unwrap();
        events.head = String::from_utf8(events.buf[..split].to_vec()).unwrap();
        events.buf.drain(..split + 4);
        events
    }

    /// Read more; `false` at the end of the connection.
    async fn fill(&mut self) -> bool {
        let mut chunk = [0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(10), self.stream.read(&mut chunk))
            .await
            .expect("the stream went quiet")
            .unwrap();
        self.buf.extend_from_slice(&chunk[..n]);
        n > 0
    }

    /// The next event, comments skipped; `None` once the stream has ended.
    async fn next(&mut self) -> Option<String> {
        loop {
            // Whole chunks into `body`.
            while let Some(line_end) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let size =
                    usize::from_str_radix(std::str::from_utf8(&self.buf[..line_end]).unwrap(), 16)
                        .unwrap();
                if size == 0 {
                    self.ended = true;
                    break;
                }
                if self.buf.len() < line_end + 2 + size + 2 {
                    break;
                }
                let data = self.buf[line_end + 2..line_end + 2 + size].to_vec();
                self.body.push_str(&String::from_utf8(data).unwrap());
                self.buf.drain(..line_end + 2 + size + 2);
            }
            while let Some(end) = self.body.find("\n\n") {
                let event: String = self.body.drain(..end + 2).collect();
                if !event.starts_with(':') {
                    return Some(event);
                }
            }
            if self.ended || !self.fill().await {
                return None;
            }
        }
    }
}

/// The stream's next event containing `want`, within a few.
async fn next_with(events: &mut Events, want: &str) -> String {
    for _ in 0..5 {
        let event = events.next().await.unwrap();
        if event.contains(want) {
            return event;
        }
    }
    panic!("no event with {want:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_page_is_kept_live_over_server_sent_events() {
    let (addr, hub, origin, local) = start_local(None).await;
    let id = "0123456789abcdef";
    local.set_listing(listed(vec![workload(id, "alpine:3.20")]), &hub);
    assert_eq!(get(addr, "/events/vms", None).await.status, 401);
    let (cookie, csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let mut events = Events::open(addr, "/events/vms", &cookie).await;
    let head = events.head.to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("content-type: text/event-stream"), "{head}");
    assert!(head.contains("cache-control: no-store"), "{head}");
    assert!(
        head.contains(&format!("content-security-policy: {CSP}")),
        "{head}"
    );
    // The current table at once, as a single `vms` event.
    let first = events.next().await.unwrap();
    assert!(first.starts_with("event: vms\ndata: <table"), "{first}");
    assert!(first.contains("alpine:3.20"), "{first}");

    // A VM starting wakes the stream; what `vk` says of it arrives as text, however it is
    // written.
    let hostile = "app<script>alert(1)</script>\n\nevent: evil\ndata: <img src=x onerror=alert(2)>";
    local.set_listing(
        listed(vec![
            workload(id, "alpine:3.20"),
            workload("fedcba9876543210", hostile),
        ]),
        &hub,
    );
    let next = next_with(&mut events, "app&lt;script&gt;").await;
    assert!(next.starts_with("event: vms\ndata: "), "{next}");
    assert!(
        !next.contains("<script") && !next.contains("<img"),
        "{next}"
    );
    assert!(!next.contains("\nevent: evil"), "{next}");

    // A VM's page streams its own fragment, and says when the VM is gone.
    let mut detail = Events::open(addr, &format!("/events/vm/{id}"), &cookie).await;
    let first = detail.next().await.unwrap();
    assert!(first.starts_with("event: vm\ndata: "), "{first}");
    assert!(first.contains("/s/alpine:3.20"), "{first}");
    local.set_listing(listed(Vec::new()), &hub);
    next_with(&mut detail, "no longer running").await;
    next_with(&mut events, "No VM is running").await;
    assert_eq!(get(addr, "/events/vm/zz", Some(&cookie)).await.status, 404);

    // Signed out: each stream says so in its region, closes, and ends.
    let reply = request(
        addr,
        "POST",
        "/logout",
        &[&format!("Cookie: {cookie}"), &format!("Origin: {origin}")],
        &format!("_csrf={csrf}"),
    )
    .await;
    assert_eq!(reply.status, 200);
    for (stream, name) in [(&mut events, "vms"), (&mut detail, "vm")] {
        let last = next_with(stream, "Signed out").await;
        assert!(last.starts_with(&format!("event: {name}\n")), "{last}");
        assert_eq!(
            stream.next().await.as_deref(),
            Some("event: close\ndata: \n\n")
        );
        assert_eq!(stream.next().await, None);
    }
    // And a page asking again is told the same, rather than refused into retrying.
    let again = get(addr, "/events/vms", Some(&cookie)).await;
    assert_eq!(again.status, 200);
    assert_eq!(again.header("content-type"), Some("text/event-stream"));
    assert!(
        again.body.starts_with("event: vms\ndata: "),
        "{}",
        again.body
    );
    assert!(again.body.contains("Signed out"), "{}", again.body);
    assert!(
        again.body.ends_with("\n\nevent: close\ndata: \n\n"),
        "{}",
        again.body
    );
}

/// Open `path`'s stream as `cookie` and read its first event.
async fn live(addr: SocketAddr, path: &str, cookie: &str) -> Events {
    let mut events = Events::open(addr, path, cookie).await;
    assert!(events.head.starts_with("HTTP/1.1 200"), "{}", events.head);
    events.next().await.unwrap();
    events
}

/// `stream` says its session ended, closes, and ends.
async fn assert_signed_out(stream: &mut Events) {
    next_with(stream, "Signed out").await;
    assert_eq!(
        stream.next().await.as_deref(),
        Some("event: close\ndata: \n\n")
    );
    assert_eq!(stream.next().await, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn sessions_ended_over_the_admin_socket_close_their_streams() {
    let dir = std::env::temp_dir().join(format!("vk-hub-ui-admin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("admin.sock");
    let (addr, hub, _) = start().await;
    tokio::spawn(crate::admin::serve(
        crate::admin::bind(&path).unwrap(),
        hub.clone(),
    ));
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let mut events = live(addr, "/events/vms", &cookie).await;
    let id = "0123456789abcdef";
    let mut detail = live(addr, &format!("/events/vm/{id}"), &cookie).await;
    let ended = tokio::task::spawn_blocking(move || {
        crate::admin::Client::connect(&path)
            .unwrap()
            .ui_logout(None)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(ended, 1);
    assert_signed_out(&mut events).await;
    assert_signed_out(&mut detail).await;
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_s_streams_close_as_it_expires() {
    let (addr, hub, _) = start().await;
    let now = crate::now_secs();
    let (token, _) = hub
        .db
        .create_login(Role::Viewer, Duration::from_secs(60), "uid 0", now)
        .unwrap();
    // Opened as if hours ago, so it has seconds left.
    let opened = now + 3 - store::UI_SESSION_TTL.as_secs();
    let (secret, session) = hub.db.redeem_login(&token, opened).unwrap().unwrap();
    assert_eq!(session.expires_at, now + 3);
    let cookie = format!("{COOKIE}={secret}");
    let mut events = live(addr, "/events/vms", &cookie).await;
    tokio::time::timeout(Duration::from_secs(10), assert_signed_out(&mut events))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn live_pages_are_capped_per_session_and_in_all() {
    let (addr, hub, _) = start().await;
    let (first, _) = sign_in(addr, &hub, Role::Viewer).await;
    let (second, _) = sign_in(addr, &hub, Role::Viewer).await;
    let (third, _) = sign_in(addr, &hub, Role::Viewer).await;
    // Two sessions' worth fill the hub.
    const { assert!(sse::MAX_STREAMS <= 2 * sse::MAX_SESSION_STREAMS) };
    let mut open = Vec::new();
    for _ in 0..sse::MAX_SESSION_STREAMS {
        let mut stream = Events::open(addr, "/events/vms", &first).await;
        assert!(stream.head.starts_with("HTTP/1.1 200"), "{}", stream.head);
        stream.next().await.unwrap();
        open.push(stream);
    }
    let over = get(addr, "/events/vms", Some(&first)).await;
    assert_eq!(over.status, 429);
    assert_eq!(over.header("retry-after"), Some("5"));
    for _ in sse::MAX_SESSION_STREAMS..sse::MAX_STREAMS {
        let mut stream = Events::open(addr, "/events/vms", &second).await;
        stream.next().await.unwrap();
        open.push(stream);
    }
    assert_eq!(get(addr, "/events/vms", Some(&third)).await.status, 503);
    // A session at its cap, on a hub at its own, still has its pages answered.
    assert_eq!(get(addr, "/", Some(&first)).await.status, 200);
    assert_eq!(get(addr, "/", Some(&third)).await.status, 200);
    // A stream gone gives its place back.
    drop(open.pop());
    let mut again = None;
    for _ in 0..100 {
        let stream = Events::open(addr, "/events/vms", &third).await;
        if stream.head.starts_with("HTTP/1.1 200") {
            again = Some(stream);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(again.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn pages_load_only_the_embedded_scripts() {
    let (addr, hub, _, local) = start_local(None).await;
    let id = "0123456789abcdef";
    local.set_listing(listed(vec![workload(id, "alpine:3.20")]), &hub);
    let (cookie, _) = sign_in(addr, &hub, Role::Operator).await;
    for path in ["/".to_string(), format!("/vm/{id}"), "/audit".to_string()] {
        let body = get(addr, &path, Some(&cookie)).await.body;
        assert!(body.contains("\"allowEval\":false"), "{body}");
        assert!(body.contains("\"selfRequestsOnly\":true"), "{body}");
        assert_eq!(body.matches("<script").count(), 2, "{body}");
        assert_eq!(body.matches("<script src=\"/assets/").count(), 2, "{body}");
        assert!(!body.contains(" style="), "{body}");
        // No event handler attribute: ` on<letters>=`.
        let handler = body.split(" on").skip(1).any(|rest| {
            let name = rest.bytes().take_while(u8::is_ascii_alphabetic).count();
            name > 0 && rest.as_bytes().get(name) == Some(&b'=')
        });
        assert!(!handler, "{body}");
        assert_eq!(
            body.matches("sse-close=\"close\"").count(),
            usize::from(path != "/audit")
        );
    }
}

/// A `vk` that is a shell script: `body` runs with the arguments it was given.
fn stub_vk(tag: &str, body: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("vk-hub-stub-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let vk = dir.join("vk");
    // Written by `cp`, not here: a file this process holds open for writing, as a child
    // another test forks meanwhile inherits it, cannot be run (ETXTBSY).
    let source = vk.with_extension("sh");
    std::fs::write(&source, format!("#!/bin/sh\n{body}\n")).unwrap();
    let copied = std::process::Command::new("cp")
        .arg(&source)
        .arg(&vk)
        .status();
    assert!(copied.unwrap().success());
    std::fs::set_permissions(&vk, std::fs::Permissions::from_mode(0o755)).unwrap();
    vk
}

/// The ID `vk workloads` derives from a state dir.
fn id_of(dir: &str) -> String {
    use sha2::{Digest, Sha256};
    crate::hex::to_hex(&Sha256::digest(dir.as_bytes())[..8])
}

/// A VM's page shows its console's tail, atop's account of it when it records one, and its
/// egress report, each read by the `vk` command for it, as text — and none of them for a VM
/// whose state dir the list could not show as it is.
#[tokio::test(flavor = "multi_thread")]
async fn a_vm_s_page_shows_its_console_atop_and_egress() {
    let vk = stub_vk(
        "views",
        r#"echo "$*" >> "$(dirname "$0")/ran"
case "$1" in
logs) printf 'console of %s <b>bold</b>\n\033[0;32msecond\tline\033[0m\n' "$6" ;;
atop) echo "atop of $4" ;;
egress-report) echo "virtkit: egress refused:"; echo "  egress denied (dns) evil.example  (x2)" ;;
*) echo "unexpected $*" >&2; exit 3 ;;
esac"#,
    );
    let (addr, hub, _, local) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let scratch = vk.parent().unwrap();
    let (state, recording) = (scratch.join("state"), scratch.join("recording"));
    std::fs::create_dir_all(state.join("atop")).unwrap();
    std::fs::create_dir_all(recording.join("atop")).unwrap();
    std::fs::write(recording.join("atop/atop.log"), b"").unwrap();
    let (run, recorder) = (run_of(&state), run_of(&recording));
    // A CI job's recording is in the archive its job dir names, compressed once it ends.
    let (job_dir, archive) = (scratch.join("job"), scratch.join("archive"));
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::create_dir_all(&archive).unwrap();
    std::fs::write(archive.join("atop.log.zst"), b"").unwrap();
    std::fs::write(
        job_dir.join("atop.dir"),
        archive.as_os_str().as_encoded_bytes(),
    )
    .unwrap();
    let mut job = run_of(&job_dir);
    job.kind = vk_hub_proto::WorkloadKind::CiJob;
    // A job dir naming a relative archive is not read from.
    let relative = scratch.join("relative");
    std::fs::create_dir_all(&relative).unwrap();
    std::fs::write(relative.join("atop.dir"), b"archive\n").unwrap();
    let mut relative = run_of(&relative);
    relative.kind = vk_hub_proto::WorkloadKind::CiJob;
    // Nor one naming an archive `vk atop` cannot be given, a path that is not text.
    let binary = scratch.join("binary");
    std::fs::create_dir_all(&binary).unwrap();
    std::fs::write(binary.join("atop.dir"), b"/archive/\xff\n").unwrap();
    let mut binary = run_of(&binary);
    binary.kind = vk_hub_proto::WorkloadKind::CiJob;
    // Nor one too long to be a path, rather than one cut to look like it.
    let long = scratch.join("long");
    std::fs::create_dir_all(&long).unwrap();
    std::fs::write(long.join("atop.dir"), format!("/{}", "a".repeat(5000))).unwrap();
    let mut long = run_of(&long);
    long.kind = vk_hub_proto::WorkloadKind::CiJob;
    // Listed as `vk workloads` lists a path with a byte that is not UTF-8: decoded lossily,
    // so it no longer hashes to its ID.
    let mut altered = workload("0123456789abcdef", "a\u{fffd}b");
    altered.state_dir = format!("{}/a\u{fffd}b", scratch.display());
    let ids = [
        &run.id,
        &recorder.id,
        &job.id,
        &relative.id,
        &binary.id,
        &long.id,
    ]
    .map(|id| id.clone());
    local.set_listing(
        listed(vec![run, recorder, job, relative, binary, long, altered]),
        &hub,
    );
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;

    let ran = scratch.join("ran");
    let page = get(addr, &format!("/vm/{}", ids[0]), Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    // Escaped, and its terminal sequences dropped whole, its tab kept.
    let console = format!(
        "console of {} &lt;b&gt;bold&lt;/b&gt;\nsecond\tline\n",
        state.display()
    );
    assert!(page.body.contains(&console), "{}", page.body);
    assert!(page.body.contains("Not recording"), "{}", page.body);
    // A run's own state dir is asked of its egress too.
    assert!(
        page.body.contains("egress denied (dns) evil.example"),
        "{}",
        page.body
    );
    let before = std::fs::read_to_string(&ran).unwrap();
    assert!(
        before.contains(&format!("logs --exact -n 100 -- {}\n", state.display())),
        "{before}"
    );
    // Read again within moments: what was read is shown again, nothing is run.
    let page = get(addr, &format!("/vm/{}", ids[0]), Some(&cookie)).await;
    assert!(page.body.contains(&console), "{}", page.body);
    assert_eq!(std::fs::read_to_string(&ran).unwrap(), before);
    // Recording itself, atop is asked.
    let page = get(addr, &format!("/vm/{}", ids[1]), Some(&cookie)).await;
    assert!(
        page.body
            .contains(&format!("atop of {}/atop", recording.display())),
        "{}",
        page.body
    );
    let page = get(addr, &format!("/vm/{}", ids[2]), Some(&cookie)).await;
    assert!(
        page.body.contains("egress denied (dns) evil.example"),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains(&format!("atop of {}", archive.display())),
        "{}",
        page.body
    );
    let page = get(addr, &format!("/vm/{}", ids[3]), Some(&cookie)).await;
    assert!(
        page.body.contains("names no absolute path"),
        "{}",
        page.body
    );
    let page = get(addr, &format!("/vm/{}", ids[4]), Some(&cookie)).await;
    assert!(page.body.contains("is not UTF-8"), "{}", page.body);
    let page = get(addr, &format!("/vm/{}", ids[5]), Some(&cookie)).await;
    assert!(page.body.contains("too long to be a path"), "{}", page.body);
    // Its state dir shown altered: nothing is read of it, rather than of another directory.
    let before = std::fs::read_to_string(&ran).unwrap();
    let page = get(addr, "/vm/0123456789abcdef", Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("Not read"), "{}", page.body);
    assert_eq!(std::fs::read_to_string(&ran).unwrap(), before);
    // A failing command says how it failed, and the page still shows.
    let (addr, hub, _, local) = start_local(None).await;
    let id = id_of("/s/x");
    local.set_listing(listed(vec![workload(&id, "x")]), &hub);
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("/nonexistent/vk"), "{}", page.body);
    let _ = std::fs::remove_dir_all(scratch);
}

/// A workload listed as `vk workloads` lists a pinned run with state dir `dir`.
fn run_of(dir: &std::path::Path) -> vk_hub_proto::Workload {
    let dir = dir.display().to_string();
    let mut run = workload(&id_of(&dir), "alpine:3.20");
    run.state_dir = dir;
    run
}

/// What a failing command printed is shown as text: its markup escaped, its terminal
/// sequences dropped.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_view_shows_what_it_said_as_text() {
    let vk = stub_vk(
        "failed",
        r#"printf '<script>alert(1)</script> & \033[31mred\033[0m "q"\n' >&2; exit 4"#,
    );
    let (addr, hub, _, local) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let state = vk.parent().unwrap().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let w = run_of(&state);
    let id = w.id.clone();
    local.set_listing(listed(vec![w]), &hub);
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("exit status: 4"), "{}", page.body);
    assert!(
        page.body
            .contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; red &quot;q&quot;\n"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("<script>alert"), "{}", page.body);
    assert!(!page.body.contains('\u{1b}'), "{}", page.body);
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// Past its freshness window, what a page read is read again.
#[tokio::test(flavor = "multi_thread")]
async fn a_read_past_its_window_is_read_again() {
    let vk = stub_vk("expiry", r#"echo "$1" >> "$(dirname "$0")/ran""#);
    let (addr, hub, _, local) = start_with_vk(None, vk.clone(), Duration::ZERO).await;
    let state = vk.parent().unwrap().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let w = run_of(&state);
    let id = w.id.clone();
    local.set_listing(listed(vec![w]), &hub);
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let ran = vk.parent().unwrap().join("ran");
    let logs = || {
        std::fs::read_to_string(&ran)
            .unwrap()
            .lines()
            .filter(|l| *l == "logs")
            .count()
    };
    get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert_eq!(logs(), 1);
    get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert_eq!(logs(), 2);
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// Pages of one VM loaded while it is being read share that read: its commands run once.
#[tokio::test(flavor = "multi_thread")]
async fn loads_of_one_vm_at_once_share_one_read() {
    // Each command holds until the test lets it go, so the later loads are sent while the
    // first one's read is under way.
    let vk = stub_vk(
        "coalesce",
        r#"dir="$(dirname "$0")"; echo "$1" >> "$dir/ran"
while [ ! -e "$dir/go" ]; do sleep 0.05; done
echo "read by $$""#,
    );
    // Nothing read is shown again: a load that did not join the read would run its own.
    let (addr, hub, _, local) = start_with_vk(None, vk.clone(), Duration::ZERO).await;
    let scratch = vk.parent().unwrap().to_path_buf();
    let state = scratch.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let w = run_of(&state);
    let id = w.id.clone();
    local.set_listing(listed(vec![w]), &hub);
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let load = || {
        let (path, cookie) = (format!("/vm/{id}"), cookie.clone());
        tokio::spawn(async move { get(addr, &path, Some(&cookie)).await })
    };
    let ran = scratch.join("ran");
    let logs_run = || {
        std::fs::read_to_string(&ran)
            .unwrap_or_default()
            .lines()
            .filter(|l| *l == "logs")
            .count()
    };
    let first = load();
    for _ in 0..200 {
        if logs_run() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(logs_run(), 1);
    let (second, third) = (load(), load());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!first.is_finished() && !second.is_finished() && !third.is_finished());
    std::fs::write(scratch.join("go"), b"").unwrap();
    let pages = [
        first.await.unwrap(),
        second.await.unwrap(),
        third.await.unwrap(),
    ];
    let ran = std::fs::read_to_string(&ran).unwrap();
    assert_eq!(ran.lines().filter(|l| *l == "logs").count(), 1, "{ran}");
    assert_eq!(
        ran.lines().filter(|l| *l == "egress-report").count(),
        1,
        "{ran}"
    );
    for page in &pages {
        assert_eq!(page.status, 200, "{}", page.body);
        assert!(page.body.contains("read by"), "{}", page.body);
    }
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// A command whose output is cut says so beside what is shown, and nothing more of how it
/// ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_cut_view_says_so() {
    let vk = stub_vk(
        "cut",
        "i=0; while [ $i -lt 30000 ]; do echo \"line $i\"; i=$((i+1)); done",
    );
    let (addr, hub, _, local) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let state = vk.parent().unwrap().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let w = run_of(&state);
    let id = w.id.clone();
    local.set_listing(listed(vec![w]), &hub);
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert!(
        page.body.contains("(output cut at 256 KiB)"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("exit status"), "{}", page.body);
    // The console keeps its end.
    assert!(page.body.contains("line 29999\n</pre>"), "{}", page.body);
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}
