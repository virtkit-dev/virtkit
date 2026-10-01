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
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = origin.map_or_else(|| format!("http://{addr}"), str::to_string);
    let hub = Arc::new(Hub::new(
        Arc::new(Db::open_memory().unwrap()),
        origin.clone(),
    ));
    let local = Arc::new(Local::new("/nonexistent/vk".into()));
    let ui = Arc::new(Ui::new(hub.clone(), &origin, local.clone()));
    tokio::spawn(serve(listener, ui));
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
    local.set_listing(Listing::Failed("it exited (exit status: 1)".into()));
    let reply = get(addr, "/", Some(&cookie)).await;
    assert!(reply.body.contains("exit status: 1"), "{}", reply.body);
    local.set_listing(listed(Vec::new()));
    assert!(
        get(addr, "/", Some(&cookie))
            .await
            .body
            .contains("No VM is running")
    );

    let id = "0123456789abcdef";
    local.set_listing(listed(vec![workload(id, "alpine:3.20")]));
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
    local.set_listing(listed(vec![w, odd]));
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
