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
        Some(origin.clone()),
    ));
    let logs = vk.with_file_name("actions");
    let local = Arc::new(Local::new(vk, logs));
    let mut ui = Ui::local(hub.clone(), &origin, local.clone());
    if let Site::Local(site) = &mut ui.site {
        site.views = local::ViewCache::new(fresh);
    }
    tokio::spawn(serve(listener, None, Arc::new(ui)));
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
    request_bytes(addr, method, path, headers, body.as_bytes()).await
}

/// [`request`] with a body of bytes, whose `Content-Length` is its own unless `headers` give
/// one; a response cut short by a reset is taken as far as it got.
async fn request_bytes(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[&str],
    body: &[u8],
) -> Reply {
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nConnection: close\r\n");
    if !headers
        .iter()
        .any(|h| h.to_ascii_lowercase().starts_with("content-length:"))
    {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
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
    // A server refusing early may stop reading.
    let _ = stream.write_all(body).await;
    let mut resp = Vec::new();
    let mut buf = [0u8; 8192];
    while let Ok(n) = stream.read(&mut buf).await
        && n > 0
    {
        resp.extend_from_slice(&buf[..n]);
    }
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
    assert!(
        reply
            .body
            .contains("\">link from uid 0</span> <span class=\"badge\">viewer</span>"),
        "{}",
        reply.body
    );
    // The database holds only the secret's hash, and the session lists by its prefix.
    let sessions = hub.db.ui_sessions(crate::now_secs()).unwrap();
    assert_eq!(sessions.len(), 1);
    let secret = pair.split_once('=').unwrap().1;
    assert!(!sessions[0].id.is_empty() && !secret.starts_with(&sessions[0].id));
    let events: Vec<String> = hub
        .db
        .audits(None, 10)
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
        .audits(None, 10)
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
        job_url: None,
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
    assert!(
        reply.body.contains("<td class=\"num\">300 MiB</td>"),
        "{}",
        reply.body
    );
    assert!(
        reply.body.contains("<th class=\"num\">PID</th>"),
        "{}",
        reply.body
    );
    // In UTC, for the page's script to show in the browser's zone.
    assert!(
        reply.body.contains(
            "<td><time datetime=\"2026-09-30T08:01:19Z\" title=\"2026-09-30 08:01:19 UTC\">\
             2026-09-30T08:01Z</time></td>"
        ),
        "{}",
        reply.body
    );
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
    // The icon every page names: the docs' logo mark, kept in step with it.
    assert_eq!(
        include_bytes!("../../assets/favicon.svg"),
        include_bytes!("../../../docs/assets/logo-mark.svg")
    );
    let icon = assets::url(assets::ICON);
    let reply = get(addr, icon, None).await;
    assert_eq!(reply.status, 200);
    assert_secure(&reply);
    assert_eq!(reply.header("content-type"), Some("image/svg+xml"));
    assert!(reply.body.starts_with("<svg"));
    let page = get(addr, "/", None).await;
    assert!(
        page.body.contains(&format!(
            "<link rel=\"icon\" type=\"image/svg+xml\" href=\"{icon}\">"
        )),
        "{}",
        page.body
    );
    for (name, script) in [
        (assets::HTMX, include_str!("../../assets/htmx.min.js")),
        (assets::SSE, include_str!("../../assets/sse.min.js")),
        (assets::TIME, include_str!("../../assets/time.js")),
        (assets::FOLLOW, include_str!("../../assets/follow.js")),
        (assets::CHECKS, include_str!("../../assets/checks.js")),
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
    assert_eq!(session_cookie(&h, COOKIE), Ok(Some("abc")));
    assert_eq!(session_cookie(&h, SECURE_COOKIE), Ok(None));
    h.append(header::COOKIE, HeaderValue::from_static("vk-hub=def"));
    assert_eq!(session_cookie(&h, COOKIE), Err(()));
    assert_eq!(session_cookie(&HeaderMap::new(), COOKIE), Ok(None));
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
    // Refused on its declared length, before any of it arrives.
    let declared = format!("Content-Length: {}", MAX_FORM + 1);
    let reply = request(addr, "POST", "/logout", &[&cookie, &origin, &declared], "").await;
    assert_eq!(reply.status, 413);
    // A chunked body is refused once reading exceeds the limit.
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST /logout HTTP/1.1\r\nHost: {addr}\r\n{cookie}\r\n{origin}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{big}\r\n0\r\n\r\n",
        big.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    // What it left unread may reset the connection after its answer.
    let _ = tokio::time::timeout(FORM_TIMEOUT * 5, stream.read_to_end(&mut resp))
        .await
        .unwrap();
    assert!(
        resp.starts_with(b"HTTP/1.1 413"),
        "{}",
        String::from_utf8_lossy(&resp)
    );
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

/// Collect events through the first containing `want`, within 30s. A count limit can fail
/// after a slow stretch: streams render each heartbeat, and pages showing an age change each
/// render, leaving an event per second ahead of the expected one.
async fn events_until(events: &mut Events, want: &str) -> Vec<String> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut seen = Vec::new();
    while tokio::time::Instant::now() < deadline {
        let event = events.next().await.unwrap();
        let found = event.contains(want);
        seen.push(event);
        if found {
            return seen;
        }
    }
    panic!("no event with {want:?}: {seen:?}");
}

/// The stream's next event containing `want`, within 30s.
async fn next_with(events: &mut Events, want: &str) -> String {
    events_until(events, want).await.pop().unwrap()
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
        assert!(last.contains("<code>vk-hub local login</code>"), "{last}");
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
    assert!(again.body.contains("vk-hub local login"), "{}", again.body);
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
        assert_eq!(body.matches("<script").count(), 5, "{body}");
        assert_eq!(body.matches("<script src=\"/assets/").count(), 5, "{body}");
        // The script that shows times in the browser's zone, run once the page is read.
        let time = format!(
            "<script src=\"{}\" defer></script>",
            assets::url(assets::TIME)
        );
        assert!(body.contains(&time), "{body}");
        // The hub's time, by which the script measures ages.
        let now = body
            .strip_prefix("<!doctype html><html lang=\"en\" data-now=\"")
            .and_then(|rest| rest.get(..21));
        assert!(now.is_some_and(|now| now.ends_with("Z\"")), "{body}");
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
    vk_hub_proto::to_hex(&Sha256::digest(dir.as_bytes())[..8])
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

/// Post `form` to `path` as an operator's page would, by htmx or not.
async fn post_action(
    addr: SocketAddr,
    origin: &str,
    cookie: &str,
    path: &str,
    form: &str,
    htmx: bool,
) -> Reply {
    let cookie = format!("Cookie: {cookie}");
    let origin = format!("Origin: {origin}");
    let mut headers = vec![cookie.as_str(), origin.as_str()];
    if htmx {
        headers.push("HX-Request: true");
    }
    request(addr, "POST", path, &headers, form).await
}

/// The value of the hidden field `name` in `body`.
fn hidden(body: &str, name: &str) -> String {
    let start = format!("name=\"{name}\" value=\"");
    let at = body
        .find(&start)
        .unwrap_or_else(|| panic!("no {name}: {body}"))
        + start.len();
    body[at..].split('"').next().unwrap().to_string()
}

/// Ask `op` of `path` by htmx: the form that answers it, confirmed.
async fn ask(
    addr: SocketAddr,
    origin: &str,
    cookie: &str,
    csrf: &str,
    path: &str,
    op: &str,
) -> String {
    ask_with(addr, origin, cookie, csrf, path, op, &[]).await
}

/// [`ask`], with `fields` posted beside `op` in the question.
async fn ask_with(
    addr: SocketAddr,
    origin: &str,
    cookie: &str,
    csrf: &str,
    path: &str,
    op: &str,
    fields: &[(&str, &str)],
) -> String {
    let fields: String = fields.iter().map(|(f, v)| format!("&{f}={v}")).collect();
    let reply = post_action(
        addr,
        origin,
        cookie,
        path,
        &format!("_csrf={csrf}&op={op}{fields}"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    assert!(
        reply.body.contains("name=\"confirm\" value=\"yes\""),
        "{}",
        reply.body
    );
    // In the flash the answer posts by htmx.
    assert!(
        reply.body.contains(&format!(
            "action=\"{path}\" hx-post=\"{path}\" hx-swap=\"none\">"
        )),
        "{}",
        reply.body
    );
    let asked: String = ["pid", "started", "booted", "keep_images"]
        .into_iter()
        .filter(|f| reply.body.contains(&format!("name=\"{f}\"")))
        .map(|f| format!("&{f}={}", hidden(&reply.body, f)))
        .collect();
    format!(
        "_csrf={csrf}&op={op}{asked}&nonce={}&confirm=yes",
        hidden(&reply.body, "nonce")
    )
}

/// Wait for the audit log to hold a line containing `want`.
async fn audited(hub: &Hub, want: &str) -> Vec<String> {
    let mut events = Vec::new();
    for _ in 0..400 {
        events = hub
            .db
            .audits(None, 50)
            .unwrap()
            .into_iter()
            .map(|r| r.event)
            .collect();
        if events.iter().any(|e| e.contains(want)) {
            return events;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no audit line with {want:?}: {events:?}");
}

/// Read `path` with `cookie` until it shows `want`: the background task audits its outcome
/// before the page shows it.
async fn page_with(addr: SocketAddr, path: &str, cookie: &str, want: &str) -> String {
    let mut body = String::new();
    for _ in 0..400 {
        body = get(addr, path, Some(cookie)).await.body;
        if body.contains(want) {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{path} never showed {want:?}: {body}");
}

/// A VM is stopped and rebooted by running `vk`, as an operator alone, once a question asked
/// of the same `vk run` is answered once; the command and how it ended are audited and shown,
/// and a second is refused while the first runs.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_stops_a_vm_once_confirmed() {
    let vk = stub_vk(
        "actions",
        r#"d=$(dirname "$0")
case "$1" in
stop) echo "$*" >> "$d/ran"; echo "virtkit: stopped pid $3" >&2 ;;
reboot) echo "$*" >> "$d/ran"
    while [ ! -e "$d/go" ]; do sleep 0.05; done
    printf '%0300d\n' 0 | tr 0 x >&2; exit 1 ;;
logs|atop|egress-report) ;;
*) exit 3 ;;
esac"#,
    );
    let ran = vk.parent().unwrap().join("ran");
    let (addr, hub, origin, local) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let id = "0123456789abcdef";
    let mut job = workload("fedcba9876543210", "rust:1.90");
    job.kind = vk_hub_proto::WorkloadKind::CiJob;
    let run = workload(id, "alpine:3.20");
    local.set_listing(listed(vec![run.clone(), job.clone()]), &hub);
    let path = format!("/vm/{id}/action");

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let reply = post_action(
        addr,
        &origin,
        &viewer,
        &path,
        &format!("_csrf={viewer_csrf}&op=stop"),
        true,
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let page = get(addr, &format!("/vm/{id}"), Some(&viewer)).await;
    assert!(!page.body.contains("name=\"op\""), "{}", page.body);

    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert!(page.body.contains("value=\"reboot\""), "{}", page.body);
    // A refusal of either kind is swapped in, not dropped.
    assert!(
        page.body
            .contains(r#"{"code":"5..","swap":true,"error":false},{"code":"...""#),
        "{}",
        page.body
    );
    // Asked first, of this `vk run`, and nothing run.
    let confirmed = ask(addr, &origin, &cookie, &csrf, &path, "stop").await;
    assert!(confirmed.contains("&pid=4242&"), "{confirmed}");
    assert!(!ran.exists());
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        &path,
        &format!("_csrf={csrf}&op=stop"),
        false,
    )
    .await;
    assert!(reply.body.contains("<h1>Confirm</h1>"), "{}", reply.body);
    assert!(reply.body.contains("Stop this VM?"), "{}", reply.body);
    // On its own page the answer posts as a plain form: no flash there for an htmx answer.
    assert!(
        reply
            .body
            .contains(&format!("<form method=\"post\" action=\"{path}\">")),
        "{}",
        reply.body
    );
    assert!(
        reply
            .body
            .contains(&format!("<a href=\"/vm/{id}\">Cancel</a>")),
        "{}",
        reply.body
    );
    // A confirmation without its question's nonce is no answer.
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        &path,
        &format!("_csrf={csrf}&op=stop&pid=4242&confirm=yes"),
        true,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(!ran.exists());
    // Another session's answer is no answer, and leaves the question to its own.
    let (other, other_csrf) = sign_in(addr, &hub, Role::Operator).await;
    let theirs = confirmed.replace(&format!("_csrf={csrf}"), &format!("_csrf={other_csrf}"));
    let reply = post_action(addr, &origin, &other, &path, &theirs, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(!ran.exists());
    // Confirmed: run as `vk stop <pid>`, audited as it starts and as it ends.
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Started <code>vk stop -- 4242</code>"),
        "{}",
        reply.body
    );
    let about = format!("on VM {id} (/s/alpine:3.20)");
    let events = audited(&hub, &format!("`vk stop -- 4242` {about} succeeded")).await;
    assert!(
        events
            .iter()
            .any(|e| e.ends_with(&format!("(operator) ran `vk stop -- 4242` {about}"))),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.contains("(exit status: 0: virtkit: stopped pid 4242)")),
        "{events:?}"
    );
    // Answered once: the same form again runs nothing.
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("answered already"), "{}", reply.body);
    assert_eq!(std::fs::read_to_string(&ran).unwrap(), "stop -- 4242\n");
    let page = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert!(
        page.body
            .contains("<code>vk stop -- 4242</code> by ui session "),
        "{}",
        page.body
    );
    assert!(page.body.contains("succeeded, ended "), "{}", page.body);

    // Asked of one `vk run`, answered once another runs on the state dir: refused.
    let confirmed = ask(addr, &origin, &cookie, &csrf, &path, "reboot").await;
    let mut rerun = run.clone();
    rerun.pid = Some(4243);
    local.set_listing(listed(vec![rerun, job.clone()]), &hub);
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("it changed"), "{}", reply.body);
    local.set_listing(listed(vec![run.clone(), job.clone()]), &hub);

    // A plain form goes back to the page; a second action is refused until the first ends, and a
    // failure says how, in its last line cut short.
    let confirmed = ask(addr, &origin, &cookie, &csrf, &path, "reboot").await;
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some(format!("/vm/{id}").as_str()));
    let confirmed = ask(addr, &origin, &cookie, &csrf, &path, "stop").await;
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("already being done"), "{}", reply.body);
    let page = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert!(page.body.contains(", running since "), "{}", page.body);
    std::fs::write(vk.parent().unwrap().join("go"), "").unwrap();
    audited(
        &hub,
        &format!("`vk reboot -- 4242` {about} failed (exit status: 1: xxx"),
    )
    .await;
    let said = local
        .action(&format!("vm/{id}"))
        .unwrap()
        .ended
        .unwrap()
        .said;
    assert_eq!(said, format!("exit status: 1: {}…", "x".repeat(200)));

    // A run the list has no pid for is named by its state dir, quoted as a shell takes it.
    let dir = "/s/a b";
    let mut bare = workload(&id_of(dir), "a b");
    bare.pid = None;
    bare.state_dir = dir.into();
    local.set_listing(listed(vec![run.clone(), job.clone(), bare.clone()]), &hub);
    let path = format!("/vm/{}/action", bare.id);
    let confirmed = ask(addr, &origin, &cookie, &csrf, &path, "stop").await;
    assert!(
        confirmed.contains("&pid=-&started=1790755279&"),
        "{confirmed}"
    );
    // Without a pid, another run on the state dir is told apart by when it started.
    let mut again = bare.clone();
    again.started_at = Some(1_790_755_999);
    local.set_listing(listed(vec![run.clone(), job.clone(), again]), &hub);
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    local.set_listing(listed(vec![run, job, bare]), &hub);
    let confirmed = ask(addr, &origin, &cookie, &csrf, &path, "stop").await;
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("shows below"), "{}", reply.body);
    audited(&hub, "ran `vk stop -- '/s/a b'` on VM").await;

    // A CI job is its runner's; an unknown action or VM is no action.
    for (target, op) in [
        ("fedcba9876543210", "stop"),
        (id, "format"),
        ("1111111111111111", "stop"),
    ] {
        let reply = post_action(
            addr,
            &origin,
            &cookie,
            &format!("/vm/{target}/action"),
            &format!("_csrf={csrf}&op={op}&confirm=yes"),
            true,
        )
        .await;
        assert!(
            reply.status == 400 || reply.status == 404,
            "{target} {op}: {}",
            reply.status
        );
    }
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// An action's post from another origin, or without the session's CSRF token, is refused
/// before anything is run.
#[tokio::test(flavor = "multi_thread")]
async fn an_action_without_its_checks_runs_nothing() {
    let vk = stub_vk("unchecked", r#"echo "$*" >> "$(dirname "$0")/ran""#);
    let ran = vk.parent().unwrap().join("ran");
    let (addr, hub, origin, local) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let id = "0123456789abcdef";
    local.set_listing(listed(vec![workload(id, "alpine:3.20")]), &hub);
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let cookie_line = format!("Cookie: {cookie}");
    let origin_line = format!("Origin: {origin}");
    let other = csrf_token(&"ab".repeat(32));
    for path in [
        format!("/vm/{id}/action"),
        "/dev/app-1111/action".to_string(),
    ] {
        for (headers, form) in [
            (
                vec![cookie_line.as_str(), origin_line.as_str()],
                "op=start".to_string(),
            ),
            (
                vec![cookie_line.as_str(), origin_line.as_str()],
                format!("_csrf={other}&op=start"),
            ),
            (
                vec![cookie_line.as_str(), "Origin: http://evil.example"],
                format!("_csrf={csrf}&op=start"),
            ),
            (
                vec![cookie_line.as_str(), "Sec-Fetch-Site: cross-site"],
                format!("_csrf={csrf}&op=start"),
            ),
            (vec![cookie_line.as_str()], format!("_csrf={csrf}&op=start")),
        ] {
            let mut headers = headers;
            headers.push("HX-Request: true");
            let reply = request(addr, "POST", &path, &headers, &form).await;
            assert_eq!(reply.status, 403, "{path} {headers:?}: {}", reply.body);
        }
    }
    assert!(!ran.exists(), "{}", std::fs::read_to_string(&ran).unwrap());
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// An action past its time limit is ended, and says so where it is shown and in the audit
/// log.
#[tokio::test(flavor = "multi_thread")]
async fn an_action_past_its_time_is_ended_and_says_so() {
    let vk = stub_vk(
        "timeout",
        r#"exec 2>/dev/null
trap 'echo term >> "$(dirname "$0")/ran"' TERM
while :; do sleep 0.1; done"#,
    );
    let ran = vk.parent().unwrap().join("ran");
    let (_, hub, _, local) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let command = local
        .start(
            &hub,
            "vm/x",
            "VM x (/s/x)".into(),
            vec!["hang".into()],
            Duration::from_secs(1),
            "tester",
        )
        .await
        .unwrap();
    assert_eq!(command, "vk hang");
    audited(
        &hub,
        "`vk hang` on VM x (/s/x) failed (terminated after 1s, then killed 1s later)",
    )
    .await;
    let ended = local.action("vm/x").unwrap().ended.unwrap();
    assert!(!ended.ok);
    assert_eq!(ended.said, "terminated after 1s, then killed 1s later");
    // Asked to end first.
    assert_eq!(std::fs::read_to_string(&ran).unwrap(), "term\n");
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// `/dev` lists what `vk dev list` lists, stopped environments too, and no row whose name is
/// not one.
#[tokio::test(flavor = "multi_thread")]
async fn dev_environments_are_listed() {
    let vk = stub_vk(
        "dev",
        r#"case "$1 $2" in
"dev list") cat <<'JSON'
[{"name":"app-1111","dir":"/s/app-1111","workspace":"/src/app","environment":"dev","status":"stopped","created_by":null,"booted_secs":1790755279,"age_secs":5,"mem_used_bytes":null,"mem":null,"flags":[]},
 {"name":"old-2222","dir":"/s/old-2222","workspace":"/gone/old","environment":"dev","status":"stopped","created_by":null,"booted_secs":null,"age_secs":null,"mem_used_bytes":null,"mem":null,"flags":["workspace-missing"]},
 {"name":"../evil","dir":"/x","workspace":null,"environment":null,"status":"stopped","flags":[]}]
JSON
;;
*) exit 3 ;;
esac"#,
    );
    let (addr, hub, _, _) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/dev", Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body
            .contains("<td>app-1111</td><td>stopped</td><td>/src/app</td>")
    );
    assert!(page.body.contains("2026-09-30T08:01Z"), "{}", page.body);
    assert!(page.body.contains("workspace-missing"), "{}", page.body);
    assert!(!page.body.contains("evil"), "{}", page.body);
    assert!(
        page.body
            .contains("<a href=\"/dev\" aria-current=\"page\">Dev environments</a>")
    );
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// `/dev` lists what `vk dev list` lists, stopped environments too: a stopped one starts in
/// its workspace with no question, a running one stops once a question about its boot is
/// answered, and only a stale one is offered for removal.
#[tokio::test(flavor = "multi_thread")]
async fn dev_environments_are_started_stopped_and_cleaned_up() {
    let vk = stub_vk(
        "devact",
        r#"d=$(dirname "$0")
echo "$*" >> "$d/ran"
booted=$(cat "$d/booted" 2>/dev/null || echo 1790755000)
case "$1 $2" in
"dev list") cat <<JSON
[{"name":"app-1111","dir":"/s/app-1111","workspace":"/src/app","environment":"dev","status":"stopped","created_by":null,"booted_secs":1790755279,"age_secs":5,"mem_used_bytes":null,"mem":null,"flags":[]},
 {"name":"old-2222","dir":"/s/old-2222","workspace":"/gone/old","environment":"dev","status":"stopped","created_by":null,"booted_secs":null,"age_secs":null,"mem_used_bytes":null,"mem":null,"flags":["workspace-missing"]},
 {"name":"run-3333","dir":"/s/run-3333","workspace":"/src/run","environment":"dev","status":"running","booted_secs":$booted,"flags":[]},
 {"name":"dash-4444","dir":"/s/dash-4444","workspace":"-w","environment":"--yes","status":"stopped","booted_secs":1,"flags":[]},
 {"name":"../evil","dir":"/x","workspace":null,"environment":null,"status":"stopped","flags":[]}]
JSON
;;
"dev up"|"dev gc"|"dev stop") ;;
*) exit 3 ;;
esac"#,
    );
    let ran = vk.parent().unwrap().join("ran");
    let (addr, hub, origin, _) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;

    // A viewer sees the list, and nothing to act on it with.
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/dev", Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("run-3333"), "{}", page.body);
    assert!(!page.body.contains("<form method=\"post\" action=\"/dev"));
    let reply = post_action(
        addr,
        &origin,
        &viewer,
        "/dev/app-1111/action",
        &format!("_csrf={viewer_csrf}&op=start"),
        true,
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);

    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/dev", Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("app-1111") && page.body.contains("workspace-missing"));
    assert!(!page.body.contains("evil"), "{}", page.body);
    assert!(
        page.body.contains("action=\"/dev/app-1111/action\""),
        "{}",
        page.body
    );
    assert_eq!(
        page.body.matches("value=\"gc\"").count(),
        1,
        "{}",
        page.body
    );
    // Not one whose workspace is gone.
    assert_eq!(
        page.body.matches("value=\"start\"").count(),
        2,
        "{}",
        page.body
    );

    let reply = post_action(
        addr,
        &origin,
        &cookie,
        "/dev/app-1111/action",
        &format!("_csrf={csrf}&op=start"),
        true,
    )
    .await;
    assert!(
        reply
            .body
            .contains("Started <code>vk dev up --workspace=/src/app --environment=dev</code>"),
        "{}",
        reply.body
    );
    // `/dev` is read as it loads, not kept live.
    assert!(reply.body.contains("reload the page"), "{}", reply.body);
    audited(
        &hub,
        "`vk dev up --workspace=/src/app --environment=dev` on dev environment app-1111 succeeded",
    )
    .await;
    // Values that start with `-` stay joined to their options.
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        "/dev/dash-4444/action",
        &format!("_csrf={csrf}&op=start"),
        true,
    )
    .await;
    assert!(
        reply
            .body
            .contains("Started <code>vk dev up --workspace=-w --environment=--yes</code>"),
        "{}",
        reply.body
    );
    // Not stale: no removal, however asked.
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        "/dev/app-1111/action",
        &format!("_csrf={csrf}&op=gc&confirm=yes"),
        true,
    )
    .await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        "/dev/old-2222/action",
        &format!("_csrf={csrf}&op=gc"),
        true,
    )
    .await;
    assert!(reply.body.contains("cannot be undone"), "{}", reply.body);
    let confirmed = ask(addr, &origin, &cookie, &csrf, "/dev/old-2222/action", "gc").await;
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        "/dev/old-2222/action",
        &confirmed,
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    audited(
        &hub,
        "`vk dev gc --yes -- old-2222` on dev environment old-2222 succeeded",
    )
    .await;

    // A stop is asked of this boot: once it has booted again, the answer is refused.
    let stop = "/dev/run-3333/action";
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        stop,
        &format!("_csrf={csrf}&op=stop"),
        true,
    )
    .await;
    assert!(
        reply.body.contains("Stop this environment?"),
        "{}",
        reply.body
    );
    let confirmed = ask(addr, &origin, &cookie, &csrf, stop, "stop").await;
    assert!(confirmed.contains("&booted=1790755000&"), "{confirmed}");
    std::fs::write(vk.parent().unwrap().join("booted"), "1790755999").unwrap();
    let reply = post_action(addr, &origin, &cookie, stop, &confirmed, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("it changed"), "{}", reply.body);
    let confirmed = ask(addr, &origin, &cookie, &csrf, stop, "stop").await;
    let reply = post_action(addr, &origin, &cookie, stop, &confirmed, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    audited(
        &hub,
        "`vk dev stop -- run-3333` on dev environment run-3333 succeeded",
    )
    .await;

    assert_eq!(
        post_action(
            addr,
            &origin,
            &cookie,
            "/dev/../action",
            &format!("_csrf={csrf}&op=gc"),
            true
        )
        .await
        .status,
        404
    );
    let ran = std::fs::read_to_string(&ran).unwrap();
    assert!(!ran.contains("evil"), "{ran}");
    assert_eq!(ran.matches("dev stop").count(), 1, "{ran}");
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// Loads of `/dev` close together share one `vk dev list`.
#[tokio::test(flavor = "multi_thread")]
async fn loads_of_dev_close_together_share_one_list() {
    let vk = stub_vk(
        "devlist",
        r#"echo "$*" >> "$(dirname "$0")/ran"; sleep 0.5; echo '[]'"#,
    );
    let ran = vk.parent().unwrap().join("ran");
    let (addr, hub, _, _) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let (a, b) = tokio::join!(
        get(addr, "/dev", Some(&cookie)),
        get(addr, "/dev", Some(&cookie))
    );
    for page in [a, b] {
        assert!(
            page.body.contains("keeps no dev environment"),
            "{}",
            page.body
        );
    }
    assert_eq!(std::fs::read_to_string(&ran).unwrap().lines().count(), 1);
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// A `vk dev list` that failed is not shown again: the next load lists anew.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_dev_list_is_not_kept() {
    let vk = stub_vk(
        "devfail",
        r#"d=$(dirname "$0")
if [ -e "$d/failed" ]; then echo '[]'; else touch "$d/failed"; echo 'no state' >&2; exit 1; fi"#,
    );
    let (addr, hub, _, _) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/dev", Some(&cookie)).await;
    assert!(page.body.contains("no state"), "{}", page.body);
    let page = get(addr, "/dev", Some(&cookie)).await;
    assert!(
        page.body.contains("keeps no dev environment"),
        "{}",
        page.body
    );
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// An action whose start cannot be written to the audit log is refused and runs nothing, and
/// what was shown of the last one on it is shown again.
#[tokio::test(flavor = "multi_thread")]
async fn an_action_the_audit_log_cannot_record_is_not_run() {
    let vk = stub_vk(
        "unaudited",
        r#"case "$1" in
stop) echo "$*" >> "$(dirname "$0")/ran" ;;
logs|atop|egress-report) ;;
*) exit 3 ;;
esac"#,
    );
    let ran = vk.parent().unwrap().join("ran");
    let (addr, hub, origin, local) = start_with_vk(None, vk.clone(), local::VIEWS_FRESH).await;
    let id = "0123456789abcdef";
    local.set_listing(listed(vec![workload(id, "alpine:3.20")]), &hub);
    let path = format!("/vm/{id}/action");
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let confirmed = ask(addr, &origin, &cookie, &csrf, &path, "stop").await;
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    audited(&hub, "`vk stop -- 4242` on VM").await;
    let key = format!("vm/{id}");
    let before = loop {
        match local.action(&key) {
            Some(a) if a.ended.is_some() => break a,
            _ => tokio::time::sleep(Duration::from_millis(25)).await,
        }
    };

    local
        .refuse_audits
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let confirmed = ask(addr, &origin, &cookie, &csrf, &path, "stop").await;
    let reply = post_action(addr, &origin, &cookie, &path, &confirmed, true).await;
    assert_eq!(reply.status, 500, "{}", reply.body);
    assert!(
        reply.body.contains("audit log could not be written"),
        "{}",
        reply.body
    );
    assert_eq!(local.action(&key), Some(before));
    assert_eq!(std::fs::read_to_string(&ran).unwrap(), "stop -- 4242\n");
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// A fleet hub with its UI on an ephemeral loopback port, plain HTTP; the UI's origin.
async fn start_fleet() -> (SocketAddr, Arc<Hub>, String) {
    start_fleet_as("http").await
}

/// [`start_fleet`], the UI configured as reached over `scheme`: the test still speaks plain
/// HTTP to it, as to one behind a proxy that ends TLS.
async fn start_fleet_as(scheme: &str) -> (SocketAddr, Arc<Hub>, String) {
    start_fleet_with(scheme, None).await
}

/// [`start_fleet_as`], with `node_url` advertised as the hub's node endpoint.
async fn start_fleet_with(scheme: &str, node_url: Option<&str>) -> (SocketAddr, Arc<Hub>, String) {
    start_fleet_db(Db::open_memory().unwrap(), scheme, node_url).await
}

/// [`start_fleet`] with `[jobs] egress_rules = true` when `on`.
async fn start_fleet_rules(on: bool) -> (SocketAddr, Arc<Hub>, String) {
    start_fleet_db(
        Db::open_memory().unwrap().with_egress_rules(on),
        "http",
        None,
    )
    .await
}

/// [`start_fleet_with`], on `db`.
async fn start_fleet_db(
    db: Db,
    scheme: &str,
    node_url: Option<&str>,
) -> (SocketAddr, Arc<Hub>, String) {
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("{scheme}://{addr}");
    // Releases are written straight into the database, so their directory holds no files and
    // need not exist: removing one finds nothing to delete.
    let releases = std::env::temp_dir().join(format!("vk-hub-ui-releases-{}", std::process::id()));
    let hub = Arc::new(
        Hub::new(Arc::new(db), Some(origin.clone()))
            .with_releases(releases)
            .with_node_url(node_url.map(str::to_string)),
    );
    let ui = Arc::new(Ui::new(hub.clone(), &origin));
    tokio::spawn(serve(listener, None, ui));
    (addr, hub, origin)
}

/// A test's token-signing directory, removed on drop.
struct TempDir(std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0); // gone already, or never made: nothing left
    }
}

/// [`start_fleet`] with keys for minting registry tokens in a fresh directory.
/// The returned guard removes the directory on drop.
async fn start_fleet_keys(tag: &str) -> (SocketAddr, Arc<Hub>, TempDir) {
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("http://{addr}");
    let keys =
        TempDir(std::env::temp_dir().join(format!("vk-hub-ui-keys-{tag}-{}", std::process::id())));
    let _ = std::fs::remove_dir_all(&keys.0); // a leftover of an earlier run, if any
    let hub = Arc::new(
        Hub::new(Arc::new(Db::open_memory().unwrap()), Some(origin.clone()))
            .with_token_keys(keys.0.clone(), crate::tokens::DEFAULT_MAX_JOB_TOKEN),
    );
    let ui = Arc::new(Ui::new(hub.clone(), &origin));
    tokio::spawn(serve(listener, None, ui));
    (addr, hub, keys)
}

/// Operators receive a redeemable token once in the POST response, audited as their session.
/// Viewers see no form and cannot request a token.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_issues_an_enrollment_token_from_the_nodes_page() {
    let (addr, hub, origin) = start_fleet().await;
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/", Some(&viewer)).await;
    assert!(
        page.body.contains("an operator issues a token"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("action=\"/tokens\""), "{}", page.body);
    let form = format!("_csrf={viewer_csrf}&ttl=3600");
    let reply = post_action(addr, &origin, &viewer, "/tokens", &form, false).await;
    assert_eq!(reply.status, 403, "{}", reply.body);

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/", Some(&operator)).await;
    assert!(page.body.contains("action=\"/tokens\""), "{}", page.body);
    // Only a lifetime the form offers, and only with the session's CSRF token.
    for (form, status) in [
        (format!("_csrf={csrf}&ttl=5"), 400),
        ("ttl=3600".to_string(), 403),
    ] {
        let reply = post_action(addr, &origin, &operator, "/tokens", &form, false).await;
        assert_eq!(reply.status, status, "{form}: {}", reply.body);
    }
    let form = format!("_csrf={csrf}&ttl=3600");
    let reply = post_action(addr, &origin, &operator, "/tokens", &form, false).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert!(
        reply
            .body
            .contains("vk node join &lt;hub-url&gt; --token - --user gitlab-runner --service"),
        "{}",
        reply.body
    );
    let at = reply.body.find("vkh_").expect("the token");
    let token: String = reply.body[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    assert!(matches!(
        hub.db.enroll(&token, "aa", "node", "peer p", 1).unwrap(),
        crate::store::Enrollment::Enrolled { .. }
    ));
    let audit = hub.db.audit_page(None, None, 10).unwrap();
    assert!(
        audit.iter().any(|(_, row)| row.actor.contains("(operator)")
            && row
                .event
                .contains("issued an enrollment token valid for 3600s")),
        "{:?}",
        audit
            .iter()
            .map(|(_, r)| (&r.actor, &r.event))
            .collect::<Vec<_>>()
    );
}

/// The token page's `vk node join` command uses the hub's node address.
#[tokio::test(flavor = "multi_thread")]
async fn the_token_page_names_the_hubs_node_address() {
    let (addr, hub, origin) = start_fleet_with("http", Some("https://hub.example.com:8443")).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let form = format!("_csrf={csrf}&ttl=3600");
    let reply = post_action(addr, &origin, &operator, "/tokens", &form, false).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("vk node join https://hub.example.com:8443 --token -"),
        "{}",
        reply.body
    );
}

/// What a node sends reaches a page as text: nothing it says becomes markup or script.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_node_is_shown_as_text() {
    let (addr, hub, _) = start_fleet().await;
    let (token, _) = hub
        .db
        .create_token(Duration::from_secs(60), "uid 0", crate::now_secs())
        .unwrap();
    let hostile = "<script>alert(1)</script>\"'><img src=x onerror=alert(2)>";
    let crate::store::Enrollment::Enrolled { node_id } =
        hub.db.enroll(&token, "aa", hostile, "peer p", 1).unwrap()
    else {
        panic!("expected an enrollment");
    };
    let inventory = vk_hub_proto::Inventory {
        hostname: hostile.into(),
        versions: vk_hub_proto::Versions {
            vk: format!("0.80{hostile}\u{202e}"),
            config_hash: hostile.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    hub.db
        .record_inventory(&node_id, inventory, true, 2)
        .unwrap();
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    for path in ["/".to_string(), format!("/node/{node_id}")] {
        let reply = get(addr, &path, Some(&cookie)).await;
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
    // A malformed or unknown node ID is no page.
    assert_eq!(get(addr, "/node/zz", Some(&cookie)).await.status, 404);
    let unknown = format!("/node/{}", "0".repeat(32));
    assert_eq!(get(addr, &unknown, Some(&cookie)).await.status, 404);
}

fn enrolled_node(hub: &Hub, hostname: &str) -> String {
    let (token, _) = hub
        .db
        .create_token(Duration::from_secs(60), "uid 0", crate::now_secs())
        .unwrap();
    let crate::store::Enrollment::Enrolled { node_id } = hub
        .db
        .enroll(&token, &"ab".repeat(16), hostname, "peer p", 1)
        .unwrap()
    else {
        panic!("expected an enrollment");
    };
    node_id
}

#[tokio::test(flavor = "multi_thread")]
async fn the_fleet_s_pages_are_kept_live_over_server_sent_events() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    assert_eq!(get(addr, "/events/nodes", None).await.status, 401);
    let (cookie, csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let mut events = Events::open(addr, "/events/nodes", &cookie).await;
    let head = events.head.to_ascii_lowercase();
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert!(head.contains("content-type: text/event-stream"), "{head}");
    assert!(head.contains("cache-control: no-store"), "{head}");
    assert!(
        head.contains(&format!("content-security-policy: {CSP}")),
        "{head}"
    );
    // The current table at once, as a single `nodes` event.
    let first = events.next().await.unwrap();
    assert!(first.starts_with("event: nodes\ndata: <table"), "{first}");
    assert!(first.contains("ci-1"), "{first}");

    // A report through the session's path wakes the stream; what the node says arrives as
    // text, however it is written.
    let hostile =
        "ci-2<script>alert(1)</script>\n\nevent: evil\ndata: <img src=x onerror=alert(2)>";
    hub.db
        .record_inventory(
            &node,
            vk_hub_proto::Inventory {
                hostname: hostile.into(),
                ..Default::default()
            },
            true,
            2,
        )
        .unwrap();
    hub.changed(&node);
    let next = events.next().await.unwrap();
    assert!(next.starts_with("event: nodes\ndata: "), "{next}");
    assert!(
        next.contains("ci-2&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{next}"
    );
    assert!(
        !next.contains("<script") && !next.contains("<img"),
        "{next}"
    );
    assert!(!next.contains("\nevent: evil"), "{next}");

    // A node's page streams its own fragment.
    let mut detail = Events::open(addr, &format!("/events/node/{node}"), &cookie).await;
    let first = detail.next().await.unwrap();
    assert!(first.starts_with("event: node\ndata: "), "{first}");
    assert!(first.contains(&node), "{first}");
    assert!(
        !first.contains("<script") && !first.contains("<img"),
        "{first}"
    );

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
    for (stream, name) in [(&mut events, "nodes"), (&mut detail, "node")] {
        let last = stream.next().await.unwrap();
        assert!(last.starts_with(&format!("event: {name}\n")), "{last}");
        assert!(last.contains("Signed out"), "{last}");
        assert!(last.contains("<code>vk-hub ui login</code>"), "{last}");
        assert_eq!(
            stream.next().await.as_deref(),
            Some("event: close\ndata: \n\n")
        );
        assert_eq!(stream.next().await, None);
    }
    // And a page asking again is told the same, rather than refused into retrying.
    let again = get(addr, "/events/nodes", Some(&cookie)).await;
    assert_eq!(again.status, 200);
    assert!(
        again.body.starts_with("event: nodes\ndata: "),
        "{}",
        again.body
    );
    assert!(again.body.contains("Signed out"), "{}", again.body);
    assert!(again.body.contains("vk-hub ui login"), "{}", again.body);
}

fn ci_workload(id: &str, owner: &str) -> vk_hub_proto::Workload {
    vk_hub_proto::Workload {
        id: id.into(),
        kind: vk_hub_proto::WorkloadKind::CiJob,
        state_dir: format!("/jobs/{owner}"),
        label: None,
        project: Some(owner.into()),
        job_name: Some("test".into()),
        job_id: Some("7".into()),
        workspace: None,
        environment: None,
        pid: Some(4321),
        cpus: Some(2),
        mem_reserved_mib: Some(2048),
        started_at: Some(crate::now_secs()),
        ssh_alias: None,
        guest_workspace: None,
        job_url: None,
    }
}

/// Whether `body` has, right after some `before`, a `<time>` element with a UTC instant to
/// the second (`datetime="YYYY-MM-DDTHH:MM:SSZ"`).
fn utc_time_after(body: &str, before: &str) -> bool {
    let open = format!("{before}<time datetime=\"");
    body.match_indices(&open).any(|(i, _)| {
        let rest = &body[i + open.len()..];
        rest.len() > 21 && rest.as_bytes()[19] == b'Z' && rest.as_bytes()[20] == b'"'
    })
}

/// A node's workloads are on its page and counted in the nodes table, kept live, and what
/// the node says of them is text.
#[tokio::test(flavor = "multi_thread")]
async fn workloads_are_shown_live_and_as_text() {
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let hostile = "acme<script>alert(1)</script>\n\nevent: evil\ndata: <img src=x>";
    let report = |workloads| vk_hub_proto::Report {
        workloads: Some(workloads),
        ..Default::default()
    };
    hub.db
        .record_report(
            &node,
            report(vec![ci_workload("aaaaaaaaaaaaaaaa", hostile)]),
            2,
        )
        .unwrap();
    hub.db
        .record_heartbeat(
            &node,
            vk_hub_proto::Heartbeat {
                workload_mem_bytes: [("aaaaaaaaaaaaaaaa".to_string(), 3 << 30)].into(),
                ..Default::default()
            },
            2,
        )
        .unwrap();
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, &format!("/node/{node}"), Some(&cookie)).await;
    assert_eq!(page.status, 200);
    for want in [
        "<h2>Workloads</h2>",
        "<td>ci-job</td>",
        "acme&lt;script&gt;alert(1)&lt;/script&gt;",
        "<td class=\"num\">4321</td>",
        "<td class=\"num\">2.0 GiB</td>",
        "<td class=\"num\">3.0 GiB</td>",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    assert!(!page.body.contains("<script>alert") && !page.body.contains("<img"));
    // When the node was heard from, in UTC for the page's script.
    assert!(
        utc_time_after(&page.body, "<tr><th>Heartbeat</th><td>"),
        "{}",
        page.body
    );

    let mut nodes = Events::open(addr, "/events/nodes", &cookie).await;
    let first = nodes.next().await.unwrap();
    assert!(first.contains("<th class=\"num\">VMS</th>"), "{first}");
    assert!(utc_time_after(&first, "<td>"), "{first}");
    assert!(first.contains("<td class=\"num\">1</td></tr>"), "{first}");

    let mut detail = Events::open(addr, &format!("/events/node/{node}"), &cookie).await;
    let first = detail.next().await.unwrap();
    assert!(first.contains("acme&lt;script&gt;"), "{first}");
    assert!(!first.contains("<script") && !first.contains("\nevent: evil"));
    // A VM starting on the node reaches both pages; one stopping leaves them.
    hub.db
        .record_report(
            &node,
            report(vec![ci_workload("bbbbbbbbbbbbbbbb", "second-project")]),
            3,
        )
        .unwrap();
    hub.changed(&node);
    let next = next_with(&mut detail, "second-project").await;
    assert!(next.starts_with("event: node\ndata: "), "{next}");
    assert!(!next.contains("acme"), "{next}");
    hub.db.record_report(&node, report(Vec::new()), 4).unwrap();
    hub.changed(&node);
    next_with(&mut detail, "none running").await;
    next_with(&mut nodes, "<td class=\"num\">0</td></tr>").await;
}

/// A CI job the node names a GitLab page for leads to it, in a tab of its own; a URL that is
/// not a plain http(s) one leaves the job as text.
#[tokio::test(flavor = "multi_thread")]
async fn a_ci_job_links_to_its_gitlab_page() {
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let linked = vk_hub_proto::Workload {
        job_url: Some("https://gitlab.example.com/git/wab/-/jobs/8938680".into()),
        ..ci_workload("aaaaaaaaaaaaaaaa", "git/wab")
    };
    let forged = vk_hub_proto::Workload {
        job_url: Some("javascript:alert(1)".into()),
        ..ci_workload("bbbbbbbbbbbbbbbb", "acme/web")
    };
    hub.db
        .record_report(
            &node,
            vk_hub_proto::Report {
                workloads: Some(vec![linked, forged]),
                ..Default::default()
            },
            2,
        )
        .unwrap();
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, &format!("/node/{node}"), Some(&cookie)).await;
    assert!(
        page.body.contains(
            "<td><a href=\"https://gitlab.example.com/git/wab/-/jobs/8938680\" \
             target=\"_blank\" rel=\"noopener noreferrer\">git/wab test #7</a></td>"
        ),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("<td>acme/web test #7</td>"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("javascript:"), "{}", page.body);
}

/// A node's page follows that node alone.
#[tokio::test]
async fn a_node_change_wakes_that_node_s_followers_only() {
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
    let a = hub.subscribe_node("a");
    let mut all = hub.subscribe();
    hub.changed("b");
    assert!(!a.has_changed().unwrap());
    assert!(all.has_changed().unwrap());
    all.borrow_and_update();
    hub.changed("a");
    assert!(a.has_changed().unwrap() && all.has_changed().unwrap());
}

/// The page loads its script from the hub alone, configured to evaluate nothing, and has no
/// inline script or style for the policy to refuse.
#[tokio::test(flavor = "multi_thread")]
async fn the_fleet_s_pages_load_only_the_embedded_scripts() {
    let (addr, hub, _) = start_fleet().await;
    let (cookie, _) = sign_in(addr, &hub, Role::Operator).await;
    let node = enrolled_node(&hub, "ci-1");
    for path in [
        "/".to_string(),
        format!("/node/{node}"),
        "/audit".to_string(),
        "/users".to_string(),
        "/jobs".to_string(),
    ] {
        let body = get(addr, &path, Some(&cookie)).await.body;
        assert_only_embedded_scripts(&body);
        assert_eq!(
            body.matches("sse-close=\"close\"").count(),
            usize::from(!["/audit", "/users"].contains(&path.as_str()))
        );
    }
    // The users page with its forms, on a hub with `[oidc]`.
    let (addr, hub) = start_oidc(
        serde_json::json!({"sub": "s"}),
        &[("alice@example.com", Role::Operator), ("*", Role::Viewer)],
    )
    .await;
    let (cookie, _) = sign_in(addr, &hub, Role::Operator).await;
    let body = get(addr, "/users", Some(&cookie)).await.body;
    assert!(body.contains("value=\"revoke\""), "{body}");
    assert_only_embedded_scripts(&body);
}

/// `body` loads its script from the hub alone, configured to evaluate nothing, and has no
/// inline script, style or event handler.
fn assert_only_embedded_scripts(body: &str) {
    assert!(body.contains("\"allowEval\":false"), "{body}");
    assert!(body.contains("\"selfRequestsOnly\":true"), "{body}");
    assert_eq!(body.matches("<script").count(), 5, "{body}");
    assert_eq!(body.matches("<script src=\"/assets/").count(), 5, "{body}");
    // The script that shows times in the browser's zone, run once the page is read.
    let time = format!(
        "<script src=\"{}\" defer></script>",
        assets::url(assets::TIME)
    );
    assert!(body.contains(&time), "{body}");
    // The one that keeps a running job's output scrolled to its end.
    let follow = format!(
        "<script src=\"{}\" defer></script>",
        assets::url(assets::FOLLOW)
    );
    assert!(body.contains(&follow), "{body}");
    // The hub's time, by which the script measures ages.
    let now = body
        .strip_prefix("<!doctype html><html lang=\"en\" data-now=\"")
        .and_then(|rest| rest.get(..21));
    assert!(now.is_some_and(|now| now.ends_with("Z\"")), "{body}");
    assert!(!body.contains(" style="), "{body}");
    // No inline event handler: no ` on…=` attribute.
    let handler = body.match_indices(" on").any(|(i, _)| {
        let rest = &body[i + 3..];
        let name = rest.bytes().take_while(u8::is_ascii_alphabetic).count();
        name > 0 && rest[name..].starts_with('=')
    });
    assert!(!handler, "{body}");
}

/// What the pages say of signing in reads as written: no runs of spaces from a string's line
/// continuation.
#[test]
fn the_sign_in_texts_are_single_spaced() {
    for texts in [&FLEET_TEXTS, &LOCAL_TEXTS] {
        for text in [
            texts.misdirected,
            texts.not_a_link,
            texts.spent_link,
            texts.signed_out,
        ] {
            assert!(!text.contains("  "), "{text:?}");
        }
    }
}

/// Streams of nodes that may not exist, signed in or not, leave nothing followed behind them.
#[tokio::test(flavor = "multi_thread")]
async fn node_streams_leave_nothing_followed_behind() {
    let (addr, hub, _) = start_fleet().await;
    let signed_out = format!("{COOKIE}={}", "ab".repeat(32));
    for i in 0..20u32 {
        let reply = get(addr, &format!("/events/node/{i:032x}"), Some(&signed_out)).await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert!(reply.body.contains("Signed out"), "{}", reply.body);
    }
    assert_eq!(hub.followed_nodes(), 0);
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    for i in 0..20u32 {
        drop(Events::open(addr, &format!("/events/node/{i:032x}"), &cookie).await);
    }
    let followed = hub.followed_nodes();
    assert!(followed <= sse::MAX_SESSION_STREAMS + 1, "{followed}");
}

/// `/audit` lists the fleet's log, newest first, or one node's, chosen from the hub's nodes;
/// an event names a node by its name, linked.
#[tokio::test(flavor = "multi_thread")]
async fn the_fleet_s_audit_log_is_shown_and_filtered_by_node() {
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-<1>");
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let all = get(addr, "/audit", Some(&cookie)).await;
    assert_eq!(all.status, 200, "{}", all.body);
    for want in [
        "<a href=\"/audit\" aria-current=\"page\">Audit</a>",
        "<select name=\"node\" aria-label=\"Node or registry\">",
        &format!("<option value=\"{node}\">ci-&lt;1&gt; ("),
        "issued an enrollment token",
        &format!("node <a href=\"/node/{node}\">ci-&lt;1&gt;</a> enrolled as ci-&lt;1&gt;"),
        &format!("<a href=\"/node/{node}\">ci-&lt;1&gt;</a>"),
    ] {
        assert!(all.body.contains(want), "{want}: {}", all.body);
    }
    let one = get(addr, &format!("/audit?node={node}"), Some(&cookie)).await;
    assert_eq!(one.status, 200, "{}", one.body);
    assert!(
        one.body
            .contains(&format!("<option value=\"{node}\" selected>"))
    );
    assert!(one.body.contains("enrolled as"), "{}", one.body);
    assert!(!one.body.contains("enrollment token"), "{}", one.body);
    // A malformed filter is no filter.
    let bad = get(addr, "/audit?node=%3Cx%3E", Some(&cookie)).await;
    assert_eq!(bad.status, 200);
    assert!(
        bad.body.contains("issued an enrollment token"),
        "{}",
        bad.body
    );
}

/// `/audit` leaves jobs out unless asked for, narrows to one person across their sessions
/// from a select or their name in a line, and keeps the filter in its links.
#[tokio::test(flavor = "multi_thread")]
async fn the_fleet_s_audit_log_leaves_jobs_out_and_is_filtered_by_person() {
    let (addr, hub, _) = start_fleet().await;
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let job = "ab".repeat(16);
    let ann = "ui session 1a (admin, ann@example.com)";
    for (actor, event) in [
        (
            "key gitlab",
            format!("key gitlab submitted job {job}: build"),
        ),
        ("hub", format!("job {job} ended: lost")),
        (ann, "granted bob@example.com operator".to_string()),
        (
            "ui session 2b (operator, ann@example.com)",
            "drained a node".to_string(),
        ),
    ] {
        hub.db.audit(actor, &event, 10).unwrap();
    }
    let all = get(addr, "/audit", Some(&cookie)).await.body;
    for want in [
        "<option value=\"\" selected>Everything but jobs</option>",
        "<option value=\"ann@example.com\">ann@example.com</option>",
        "<a href=\"/audit?who=ann%40example.com\" title=\"Only theirs\">\
         ui session 1a (admin, ann@example.com)</a>",
        "drained a node",
    ] {
        assert!(all.contains(want), "{want}: {all}");
    }
    assert!(!all.contains(&job), "{all}");
    let jobs = get(addr, "/audit?category=jobs", Some(&cookie)).await.body;
    assert!(jobs.contains("<option value=\"jobs\" selected>Jobs</option>"));
    assert!(jobs.contains(&format!("job {job} ended: lost")), "{jobs}");
    assert!(!jobs.contains("drained a node"), "{jobs}");
    assert!(
        jobs.contains("<a href=\"/audit?category=jobs&amp;who=hub\""),
        "{jobs}"
    );
    let theirs = get(addr, "/audit?who=ann%40example.com", Some(&cookie))
        .await
        .body;
    assert!(
        theirs.contains("<option value=\"ann@example.com\" selected>"),
        "{theirs}"
    );
    assert!(
        theirs.contains("granted bob@example.com operator") && theirs.contains("drained a node"),
        "{theirs}"
    );
    assert!(!theirs.contains("enrollment token"), "{theirs}");
    let text = get(addr, "/audit?category=all&q=BUILD", Some(&cookie))
        .await
        .body;
    assert!(text.contains("submitted job"), "{text}");
    assert!(!text.contains("ended: lost"), "{text}");
    let none = get(addr, "/audit?who=key+gitlab", Some(&cookie)).await.body;
    assert!(
        none.contains("none match; jobs are left out unless Jobs or Everything is chosen"),
        "{none}"
    );
}

/// Reached over https, the session cookie is `__Host-` and `Secure`, every response asks for
/// https from then on, and an unprefixed cookie planted over plain http on the same host
/// locks no one out.
#[tokio::test(flavor = "multi_thread")]
async fn over_https_the_session_cookie_is_host_bound_and_secure() {
    let (addr, hub, origin) = start_fleet_as("https").await;
    let (token, _) = hub
        .db
        .create_login(
            Role::Viewer,
            Duration::from_secs(60),
            "uid 0",
            crate::now_secs(),
        )
        .unwrap();
    let reply = post_login(addr, &token, &[]).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let set = reply.header("set-cookie").unwrap().to_string();
    assert!(set.starts_with(&format!("{SECURE_COOKIE}=")), "{set}");
    assert!(set.contains("; Secure"), "{set}");
    assert_eq!(
        reply.header("strict-transport-security"),
        Some("max-age=31536000")
    );
    let pair = set.split(';').next().unwrap().to_string();
    let secret = pair.split_once('=').unwrap().1.to_string();
    assert_eq!(get(addr, "/", Some(&pair)).await.status, 200);
    let planted = format!("{COOKIE}={}; {pair}", "cd".repeat(32));
    assert_eq!(get(addr, "/", Some(&planted)).await.status, 200);
    let twice = format!("{SECURE_COOKIE}={}; {pair}", "cd".repeat(32));
    assert_eq!(get(addr, "/", Some(&twice)).await.status, 401);
    // The unprefixed name alone is no session here.
    let unprefixed = format!("{COOKIE}={secret}");
    assert_eq!(get(addr, "/", Some(&unprefixed)).await.status, 401);

    let reply = request(
        addr,
        "POST",
        "/logout",
        &[
            &format!("Cookie: {pair}"),
            &format!("Origin: {origin}"),
            &format!("X-CSRF-Token: {}", csrf_token(&secret)),
        ],
        "",
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let cleared = reply.header("set-cookie").unwrap();
    assert!(
        cleared.starts_with(&format!("{SECURE_COOKIE}=;"))
            && cleared.contains("Max-Age=0")
            && cleared.contains("; Secure"),
        "{cleared}"
    );
    assert!(hub.db.ui_sessions(crate::now_secs()).unwrap().is_empty());
}

/// A post to the fleet's pages is a node's action or none: one for a VM, or an action a node
/// has not, changes nothing, even from a signed-in operator's own page. A request for another
/// host is told where the fleet's UI is configured.
#[tokio::test(flavor = "multi_thread")]
async fn the_fleet_takes_only_node_actions_and_names_its_ui_url() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let audit_before = hub.db.audits(None, 100).unwrap();
    for (path, status) in [
        (format!("/node/{node}/action"), 400),
        ("/vm/0123456789abcdef/action".into(), 404),
    ] {
        let reply = request(
            addr,
            "POST",
            &path,
            &[
                &format!("Cookie: {cookie}"),
                &format!("Origin: {origin}"),
                "Content-Type: application/x-www-form-urlencoded",
            ],
            &format!("_csrf={csrf}&op=remove&confirm=yes"),
        )
        .await;
        assert_eq!(reply.status, status, "{path}: {}", reply.body);
        assert!(reply.body.contains("No such action."), "{}", reply.body);
    }
    assert!(hub.db.node(&node).unwrap().is_some());
    assert_eq!(hub.db.audits(None, 100).unwrap(), audit_before);

    let reply = request(addr, "GET", "/", &["Host: elsewhere.example"], "").await;
    assert_eq!(reply.status, 421);
    assert!(
        reply
            .body
            .contains("(its ui_url, or ui_addr when that is unset)"),
        "{}",
        reply.body
    );
}

/// The node's audit lines, as `(actor, event)`.
fn node_audit(hub: &Hub, node: &str) -> Vec<(String, String)> {
    hub.db
        .audits(Some(node), 100)
        .unwrap()
        .into_iter()
        .map(|r| (r.actor, r.event))
        .collect()
}

/// An operator's node page sets and lifts a ceiling, stops and resumes acquisition, and
/// issues each command, as the session's principal, which the audit log records; by htmx
/// it is told what came of it, and a plain form goes back to the node's page. The page,
/// live, shows what the hub asks, what the node reports and its commands, the node's words
/// as text.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_steers_a_node_from_its_page() {
    use vk_hub_proto::{Acquisition, NodeState, Outcome};
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    assert!(principal.ends_with("(operator)"), "{principal}");
    let path = format!("/node/{node}/action");

    let page = get(addr, &format!("/node/{node}"), Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for want in [
        &format!("action=\"{path}\" hx-post=\"{path}\""),
        "name=\"ceiling\"",
        "<p class=\"now\">Taking new jobs</p>",
        "<button>Pause intake</button>",
        "<p class=\"now\">Max concurrent jobs: no limit from the hub</p>",
        "<button>Set the limit</button>",
        "<p class=\"now\">State not reported yet</p>",
        "<button>Drain</button><span class=\"does\">Finish the running jobs",
        "<h3>Danger zone</h3>",
        "<button class=\"danger\">Quarantine</button>",
        &format!("name=\"_csrf\" value=\"{csrf}\""),
        "nothing asked: no ceiling, acquisition running",
        "<h2>Commands</h2><p class=\"empty\">none</p>",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    assert!(!page.body.contains("Remove the limit"), "{}", page.body);
    let mut live = Events::open(addr, &format!("/events/node/{node}"), &cookie).await;
    // The stream renders the operator's actions too, with the session's token.
    let first = live.next().await.unwrap();
    assert!(
        first.contains(&format!("name=\"_csrf\" value=\"{csrf}\"")),
        "{first}"
    );

    let steer = |form: String, htmx: bool| {
        let (cookie, origin, path) = (cookie.clone(), origin.clone(), path.clone());
        async move { post_action(addr, &origin, &cookie, &path, &form, htmx).await }
    };
    let desired = || hub.db.node(&node).unwrap().unwrap().desired.unwrap();

    let reply = steer(format!("_csrf={csrf}&op=ceiling&ceiling=3"), true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    assert!(
        reply
            .body
            .contains("generation 1: ceiling 3, acquisition run"),
        "{}",
        reply.body
    );
    assert_eq!(desired().ceiling, Some(3));
    // The node's page follows the change, and offers what applies now.
    let fragment = next_with(&mut live, "<tr><th>Ceiling</th><td>3</td></tr>").await;
    for want in [
        "<p class=\"now\">Max concurrent jobs: 3</p>",
        "<button>Remove the limit</button>",
    ] {
        assert!(fragment.contains(want), "{want}: {fragment}");
    }
    assert!(!fragment.contains("placeholder"), "{fragment}");

    let reply = steer(format!("_csrf={csrf}&op=stop"), true).await;
    assert!(reply.body.contains("acquisition stop"), "{}", reply.body);
    assert_eq!(desired().acquisition, Acquisition::Stop);
    let fragment = next_with(&mut live, "Not taking new jobs: intake paused").await;
    assert!(
        fragment.contains("<button>Resume intake</button>") && !fragment.contains("Pause intake"),
        "{fragment}"
    );
    let reply = steer(format!("_csrf={csrf}&op=stop"), true).await;
    assert_eq!(reply.status, 200);
    assert!(reply.body.contains("Already so"), "{}", reply.body);
    // A plain form goes back to the page.
    let reply = steer(format!("_csrf={csrf}&op=resume"), false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(
        reply.header("location"),
        Some(path.trim_end_matches("/action"))
    );
    assert_eq!(desired().acquisition, Acquisition::Run);
    steer(format!("_csrf={csrf}&op=lift-ceiling"), true).await;
    assert_eq!(desired().ceiling, None);
    assert_eq!(desired().generation, 4);
    // A ceiling of none, 0 or not a number is no action.
    for bad in ["", "&ceiling=0", "&ceiling=x"] {
        let reply = steer(format!("_csrf={csrf}&op=ceiling{bad}"), true).await;
        assert_eq!(reply.status, 400, "{bad}: {}", reply.body);
        assert!(reply.body.contains("at least 1"), "{}", reply.body);
    }
    assert_eq!(desired().generation, 4);

    for op in ["drain", "undrain", "quarantine", "release"] {
        let reply = steer(format!("_csrf={csrf}&op={op}"), true).await;
        assert_eq!(reply.status, 200, "{op}: {}", reply.body);
        assert!(
            reply.body.contains(&format!("Issued {op} (command ")),
            "{}",
            reply.body
        );
    }
    let commands = hub.db.node_commands(&node).unwrap();
    assert_eq!(commands.len(), 4);

    let audit = node_audit(&hub, &node);
    for want in [
        "set the concurrency ceiling to 3 (generation 1)",
        "stopped acquisition (generation 2)",
        "resumed acquisition (generation 3)",
        "lifted the concurrency ceiling (generation 4)",
        "issued drain (command ",
        "issued undrain (command ",
        "issued quarantine (command ",
        "issued release (command ",
    ] {
        assert!(
            audit
                .iter()
                .any(|(actor, e)| *actor == principal && e.contains(want)),
            "{want}: {audit:?}"
        );
    }

    // What the node says, of itself and of a command, is shown as text.
    let hostile = "<script>alert(1)</script>";
    let drain = commands
        .iter()
        .find(|c| c.command.op == vk_hub_proto::Operation::Drain)
        .unwrap();
    hub.db
        .record_ack(
            &node,
            &vk_hub_proto::CommandAck {
                id: drain.command.id.clone(),
                outcome: Outcome::Refused {
                    reason: hostile.into(),
                },
            },
            crate::now_secs(),
        )
        .unwrap();
    hub.db
        .record_report(
            &node,
            vk_hub_proto::Report {
                applied: Some(vk_hub_proto::DesiredState {
                    generation: 4,
                    ceiling: None,
                    acquisition: Acquisition::Run,
                    egress: None,
                }),
                state: Some(NodeState::Draining),
                acquisition: Some(Acquisition::Stop),
                unsupported: vec![format!("no {hostile}")],
                concurrency_error: Some(format!("cannot {hostile}")),
                drain: Some(vk_hub_proto::DrainProgress {
                    runner_stopped: true,
                    ledger_empty: false,
                    active_jobs: 2,
                }),
                ..Default::default()
            },
            crate::now_secs(),
        )
        .unwrap();
    hub.changed(&node);
    let fragment = next_with(&mut live, "draining").await;
    for want in [
        "<tr><th>Sync</th><td>ok</td></tr>",
        "<tr><th>Applied generation</th><td>4</td></tr>",
        "runner stopped, admission ledger in use, 2 job(s) running",
        "<tr><th>Cannot comply</th><td>no &lt;script&gt;",
        "<tr><th>Cannot set its concurrency</th><td>cannot &lt;script&gt;",
        "refused: &lt;script&gt;",
        "not taken yet",
        &format!("<a href=\"/audit?node={node}\">"),
        // A draining node is offered its undrain, not another drain.
        "<p class=\"now\">Not taking new jobs while draining</p>",
        "<p class=\"now\">Draining: finishing its running jobs, taking no new ones</p>",
        "<button>Undrain</button>",
    ] {
        assert!(fragment.contains(want), "{want}: {fragment}");
    }
    assert!(!fragment.contains("value=\"drain\""), "{fragment}");
    assert!(!fragment.contains("<script"), "{fragment}");
}

/// A viewer's page offers no action and its post is refused; an operator's without the
/// session's CSRF token, or from another origin, is refused too, and one for a node not
/// enrolled is not found. None of them changes the node or the audit log.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_is_steered_only_by_an_operator_s_own_page() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let path = format!("/node/{node}/action");
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let audit_before = hub.db.audits(None, 100).unwrap();

    let page = get(addr, &format!("/node/{node}"), Some(&viewer)).await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains(&path), "{}", page.body);
    assert!(page.body.contains("nothing asked"), "{}", page.body);
    // Where the node stands, without what an operator could change.
    assert!(
        page.body.contains("<p class=\"now\">Taking new jobs</p>"),
        "{}",
        page.body
    );
    assert!(
        !page.body.contains("class=\"act\"") && !page.body.contains("Danger zone"),
        "{}",
        page.body
    );
    let mut live = Events::open(addr, &format!("/events/node/{node}"), &viewer).await;
    let first = live.next().await.unwrap();
    assert!(
        first.contains("Taking new jobs") && !first.contains(&path) && !first.contains("_csrf"),
        "{first}"
    );

    let form = format!("_csrf={viewer_csrf}&op=drain");
    let reply = post_action(addr, &origin, &viewer, &path, &form, true).await;
    assert_eq!(reply.status, 403);
    assert!(reply.body.contains("operator role"), "{}", reply.body);
    let wrong = format!("_csrf={}&op=drain", csrf_token(&"ab".repeat(32)));
    let reply = post_action(addr, &origin, &operator, &path, &wrong, true).await;
    assert_eq!(reply.status, 403);
    assert!(reply.body.contains("CSRF"), "{}", reply.body);
    let form = format!("_csrf={csrf}&op=drain");
    let reply = post_action(addr, "http://evil.example", &operator, &path, &form, false).await;
    assert_eq!(reply.status, 403);
    assert!(reply.body.contains("did not come from"), "{}", reply.body);
    let unknown = format!("/node/{}/action", "0".repeat(32));
    let reply = post_action(addr, &origin, &operator, &unknown, &form, false).await;
    assert_eq!(reply.status, 404);
    assert!(
        reply.body.contains("There is no such node."),
        "{}",
        reply.body
    );

    let row = hub.db.node(&node).unwrap().unwrap();
    assert!(row.desired.is_none());
    assert!(hub.db.node_commands(&node).unwrap().is_empty());
    assert_eq!(hub.db.audits(None, 100).unwrap(), audit_before);

    // Its reach, as a badge.
    assert!(
        page.body
            .contains("<span class=\"badge bad\">unreachable</span>"),
        "{}",
        page.body
    );
    hub.open_session(&node);
    let page = get(addr, &format!("/node/{node}"), Some(&viewer)).await;
    assert!(
        page.body
            .contains("<span class=\"badge ok\">connected</span>"),
        "{}",
        page.body
    );
}

/// A node whose latest session ran protocol version 1 is shown as monitored only, with no
/// steering offered, and a post forged for it is refused saying so.
#[tokio::test(flavor = "multi_thread")]
async fn a_version_1_node_s_page_offers_no_steering() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    assert!(
        hub.db
            .record_session(&node, "inc", 1, crate::now_secs(), || true)
            .unwrap()
    );
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let path = format!("/node/{node}/action");
    let page = get(addr, &format!("/node/{node}"), Some(&cookie)).await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains(&path), "{}", page.body);
    assert!(
        page.body
            .contains("speaks fleet protocol version 1, so the hub monitors it"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("<h2>Commands</h2>"), "{}", page.body);

    for (op, htmx) in [("drain", true), ("ceiling&ceiling=2", false)] {
        let form = format!("_csrf={csrf}&op={op}");
        let reply = post_action(addr, &origin, &cookie, &path, &form, htmx).await;
        assert_eq!(reply.status, 409, "{op}: {}", reply.body);
        assert!(reply.body.contains("update its vk"), "{}", reply.body);
    }
    assert!(hub.db.node(&node).unwrap().unwrap().desired.is_none());
    assert!(hub.db.node_commands(&node).unwrap().is_empty());
}

/// A reset deletes what a node's past jobs left: the node's page asks again first, and only
/// the answer, once, issues it. A version 1 node is refused before anything is asked.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_is_issued_only_once_confirmed() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    let path = format!("/node/{node}/action");
    let page = get(addr, &format!("/node/{node}"), Some(&cookie)).await;
    assert!(
        page.body
            .contains("<button class=\"danger\">Reset</button>"),
        "{}",
        page.body
    );
    assert!(
        page.body.contains(
            "<input id=\"keep-images\" type=\"checkbox\" name=\"keep_images\" \
             value=\"yes\" hx-preserve=\"true\"> Keep cached images</label>"
        ),
        "{}",
        page.body
    );

    let answer = ask(addr, &origin, &cookie, &csrf, &path, "reset").await;
    assert!(answer.contains("&keep_images=no&"), "{answer}");
    assert!(hub.db.node_commands(&node).unwrap().is_empty());
    // An answer flipped to keep them is refused.
    let kept = answer.replace("keep_images=no", "keep_images=yes");
    let reply = post_action(addr, &origin, &cookie, &path, &kept, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("changed since"), "{}", reply.body);
    // So is one that leaves the field out.
    let answer = ask(addr, &origin, &cookie, &csrf, &path, "reset").await;
    let stripped = answer.replace("&keep_images=no", "");
    let reply = post_action(addr, &origin, &cookie, &path, &stripped, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("changed since"), "{}", reply.body);
    assert!(hub.db.node_commands(&node).unwrap().is_empty());
    let answer = ask(addr, &origin, &cookie, &csrf, &path, "reset").await;
    let reply = post_action(addr, &origin, &cookie, &path, &answer, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("Issued reset, images included (command "),
        "{}",
        reply.body
    );
    let commands = hub.db.pending_commands(&node, crate::now_secs()).unwrap();
    assert_eq!(
        commands.iter().map(|c| &c.op).collect::<Vec<_>>(),
        [&vk_hub_proto::Operation::Reset { images: true }]
    );
    assert!(
        node_audit(&hub, &node)
            .iter()
            .any(|(actor, e)| *actor == principal
                && e.contains("issued reset, images included (command ")),
        "{:?}",
        node_audit(&hub, &node)
    );
    // Answered once.
    let reply = post_action(addr, &origin, &cookie, &path, &answer, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert_eq!(hub.db.node_commands(&node).unwrap().len(), 1);

    let (token, _) = hub
        .db
        .create_token(Duration::from_secs(60), "uid 0", crate::now_secs())
        .unwrap();
    let crate::store::Enrollment::Enrolled { node_id: old } = hub
        .db
        .enroll(&token, &"cd".repeat(16), "ci-2", "peer p", 1)
        .unwrap()
    else {
        panic!("expected an enrollment");
    };
    assert!(
        hub.db
            .record_session(&old, "inc", 1, crate::now_secs(), || true)
            .unwrap()
    );
    let form = format!("_csrf={csrf}&op=reset");
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        &format!("/node/{old}/action"),
        &form,
        true,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("update its vk"), "{}", reply.body);
    assert!(hub.db.node_commands(&old).unwrap().is_empty());
}

/// Checking "Keep cached images" preserves that choice through confirmation and reset.
#[tokio::test(flavor = "multi_thread")]
async fn a_reset_keeps_images_when_ticked() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let path = format!("/node/{node}/action");
    let keep = [("keep_images", "yes")];
    let answer = ask_with(addr, &origin, &cookie, &csrf, &path, "reset", &keep).await;
    assert!(answer.contains("&keep_images=yes&"), "{answer}");
    // An answer flipped to evict them is refused.
    let evict = answer.replace("keep_images=yes", "keep_images=no");
    let reply = post_action(addr, &origin, &cookie, &path, &evict, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("changed since"), "{}", reply.body);
    assert!(hub.db.node_commands(&node).unwrap().is_empty());
    let answer = ask_with(addr, &origin, &cookie, &csrf, &path, "reset", &keep).await;
    let reply = post_action(addr, &origin, &cookie, &path, &answer, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Issued reset, images kept (command "),
        "{}",
        reply.body
    );
    let commands = hub.db.pending_commands(&node, crate::now_secs()).unwrap();
    assert_eq!(
        commands.iter().map(|c| &c.op).collect::<Vec<_>>(),
        [&vk_hub_proto::Operation::Reset { images: false }]
    );
}

/// Rollout `ef…`, running, of release `ab…` (unsigned; `cd…`, signed, beside it): node
/// `hostname` failed with a reason naming it, node `ci-2` still pending. Written straight
/// into the database; returns its ID.
fn rollout_of(hub: &Hub, hostname: &str) -> String {
    let node = enrolled_node(hub, hostname);
    let release = |version: &str, signature: Option<String>| crate::store::ReleaseRow {
        version: version.into(),
        size: 3 << 20,
        signature,
        program: None,
        added_at: 1,
        added_by: "uid 0".into(),
    };
    hub.db
        .add_release(&"ab".repeat(32), &release("0.85.0", None), "uid 0")
        .unwrap();
    hub.db
        .add_release(
            &"cd".repeat(32),
            &release("0.86.0", Some("c2ln".into())),
            "uid 0",
        )
        .unwrap();
    let id = "ef".repeat(16);
    let row = crate::rollout::RolloutRow {
        release: "ab".repeat(32),
        version: "0.85.0".into(),
        created_at: 1,
        created_by: "uid 0".into(),
        batch: 1,
        canary_per_profile: true,
        max_failures: 1,
        node_timeout_secs: 600,
        drain_timeout_secs: 600,
        force: false,
        state: crate::rollout::RolloutState::Running,
        failures: 0,
        nodes: vec![
            crate::rollout::RolloutNode {
                id: node,
                hostname: hostname.into(),
                profile: format!("{hostname} CPU · 64G · jobs fast"),
                wave: 0,
                status: crate::rollout::NodeStatus::Failed {
                    reason: format!("refused: {hostname}"),
                    at: 2,
                    ran: false,
                },
            },
            crate::rollout::RolloutNode {
                id: "12".repeat(16),
                hostname: "ci-2".into(),
                profile: "ci-2 CPU · 64G · jobs fast".into(),
                wave: 1,
                status: crate::rollout::NodeStatus::Pending,
            },
        ],
    };
    hub.db.create_rollout(&id, &row, "uid 0").unwrap();
    id
}

/// `/operations` lists the releases, signed or not, and the rollouts node by node, what nodes
/// said as text, live; a viewer's page has no buttons and no CSRF token.
#[tokio::test(flavor = "multi_thread")]
async fn releases_and_rollouts_are_shown_live() {
    let (addr, hub, _) = start_fleet().await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/operations", Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("<code>vk-hub release add</code>"),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("<code>vk-hub rollout create</code>"),
        "{}",
        page.body
    );

    let hostile = "ci<script>alert(1)</script>";
    let id = rollout_of(&hub, hostile);
    let page = get(addr, "/operations", Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert_secure(&page);
    for want in [
        "<a href=\"/operations\" aria-current=\"page\">Operations</a>",
        "sse-connect=\"/events/operations\"",
        &format!("<code title=\"{}\">abababababab</code>", "ab".repeat(32)),
        "<td>0.85.0</td><td>3.0 MiB</td><td>no</td>",
        "<td>0.86.0</td><td>3.0 MiB</td><td>yes</td>",
        &format!("<code>{}</code> vk 0.85.0", &id[..8]),
        "<span class=\"state running\">running</span>",
        "1 pending, 1 failed · wave 1 · release <code>abababababab</code> · batches of 1 after \
         a canary per profile · 0 of at most 1 failure(s)",
        &format!(
            "<a href=\"/node/{}\">ci-2</a></td><td>pending</td>",
            "12".repeat(16)
        ),
        "failed: refused: ci&lt;script&gt;",
        "ci&lt;script&gt;alert(1)&lt;/script&gt; CPU",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    assert!(!page.body.contains("<script>alert"), "{}", page.body);
    assert!(!page.body.contains("hx-post"), "{}", page.body);
    assert!(!page.body.contains("hx-headers"), "{}", page.body);
    assert!(!page.body.contains("start-rollout"), "{}", page.body);

    let mut events = Events::open(addr, "/events/operations", &viewer).await;
    let first = events.next().await.unwrap();
    assert!(first.starts_with("event: operations\ndata: "), "{first}");
    assert!(!first.contains("hx-post"), "{first}");
    assert!(!first.contains("start-rollout"), "{first}");
    // A release removed and a rollout steered, by the operations the admin socket runs,
    // reach a viewer's page.
    assert!(crate::releases::remove(&hub, "uid 0", &"cd".repeat(32)).unwrap());
    let mut gone = false;
    for _ in 0..5 {
        let event = events.next().await.unwrap();
        if event.contains("<td>0.85.0</td>") && !event.contains("<td>0.86.0</td>") {
            gone = true;
            break;
        }
    }
    assert!(gone, "release 0.86.0 still shown");
    crate::ops::steer_rollout(&hub, "uid 0", &id, crate::rollout::RolloutAction::Abort).unwrap();
    let next = next_with(&mut events, ">aborted<").await;
    assert!(next.contains("aborted by uid 0"), "{next}");
}

/// Placed jobs have a tab of their own, right after the nodes, and `/operations` no longer
/// lists them.
#[tokio::test(flavor = "multi_thread")]
async fn placed_jobs_are_a_tab_of_their_own() {
    let (addr, hub, _) = start_fleet().await;
    for role in [Role::Viewer, Role::Operator] {
        let (cookie, _) = sign_in(addr, &hub, role).await;
        let page = get(addr, "/operations", Some(&cookie)).await.body;
        assert!(
            page.contains(
                "<nav><a href=\"/\">Nodes</a><a href=\"/registries\">Registries</a>\
                 <a href=\"/jobs\">Jobs</a><a href=\"/egress\">Egress<span id=\"nav-count-egress\"></span></a>\
                 <a href=\"/clients\">Connections<span id=\"nav-count-clients\"></span></a>\
                 <a href=\"/operations\" aria-current=\"page\">Operations</a>\
                 <a href=\"/audit\">Audit</a>"
            ),
            "{page}"
        );
        assert!(
            !page.contains("<h2>Jobs</h2>") && !page.contains("none placed"),
            "{page}"
        );
    }
}

/// A Jobs page loaded while the hub reads the history says so, and polls for a reload once
/// it is read.
#[tokio::test(flavor = "multi_thread")]
async fn the_jobs_page_waits_for_the_history_to_be_read() {
    let (addr, hub, _) = start_fleet().await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    hub.db.forget_job_briefs();
    let page = get(addr, "/jobs", Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("still reading the job history"),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("hx-get=\"/jobs?reading=1\""),
        "{}",
        page.body
    );
    let poll = get(addr, "/jobs?reading=1", Some(&viewer)).await;
    assert_eq!(poll.status, 204, "{}", poll.body);
    assert_eq!(poll.header("hx-refresh"), None);
    hub.db.read_job_briefs().unwrap();
    let poll = get(addr, "/jobs?reading=1", Some(&viewer)).await;
    assert_eq!(poll.status, 200, "{}", poll.body);
    assert_eq!(poll.header("hx-refresh"), Some("true"));
    let page = get(addr, "/jobs", Some(&viewer)).await;
    assert!(page.body.contains("none placed yet"), "{}", page.body);
}

/// An operator sets how many jobs the history keeps from the Jobs page, and clears it; a
/// viewer sees the count and its source, without the form, and cannot post it.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_sets_the_job_history_from_the_jobs_page() {
    let (addr, hub, origin) = start_fleet().await;
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/jobs", Some(&viewer)).await;
    assert!(
        page.body
            .contains("keeps the newest 100,000 jobs, by default"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("set-history"), "{}", page.body);
    let form = format!("_csrf={viewer_csrf}&op=set-history&count=5");
    let refused = post_action(addr, &origin, &viewer, "/jobs", &form, false).await;
    assert_eq!(refused.status, 403, "{}", refused.body);
    assert_eq!(hub.db.job_history_set().unwrap(), None);

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    for bad in ["0", "1000001", "x", ""] {
        let form = format!("_csrf={csrf}&op=set-history&count={bad}");
        let refused = post_action(addr, &origin, &operator, "/jobs", &form, false).await;
        assert_eq!(refused.status, 400, "{bad}: {}", refused.body);
    }
    let form = format!("_csrf={csrf}&op=set-history&count=2500");
    let set = post_action(addr, &origin, &operator, "/jobs", &form, false).await;
    assert_eq!(set.status, 303, "{}", set.body);
    assert_eq!(hub.db.job_history_set().unwrap(), Some(2500));
    assert_eq!(
        crate::jobs::history_count(&hub).unwrap(),
        (2500, crate::jobs::HistorySource::Ui)
    );
    let page = get(addr, "/jobs", Some(&operator)).await;
    assert!(
        page.body
            .contains("keeps the newest 2,500 jobs, as set here, over the default of 100,000."),
        "{}",
        page.body
    );
    assert!(
        page.body.contains("value=\"clear-history\""),
        "{}",
        page.body
    );
    assert!(
        page.body
            .contains("<button>Use the default of 100,000</button>"),
        "{}",
        page.body
    );
    let audit = hub.db.audits(None, 10).unwrap();
    assert!(audit.iter().any(|r| r.event.contains("2500")), "{audit:?}");

    let form = format!("_csrf={csrf}&op=clear-history");
    let cleared = post_action(addr, &origin, &operator, "/jobs", &form, false).await;
    assert_eq!(cleared.status, 303, "{}", cleared.body);
    assert_eq!(hub.db.job_history_set().unwrap(), None);
    let audit = hub.db.audits(None, 10).unwrap();
    assert!(
        (audit.iter()).any(|r| r
            .event
            .ends_with("cleared: the default applies, 100000 jobs")),
        "{audit:?}"
    );
    let page = get(addr, "/jobs", Some(&operator)).await;
    assert!(page.body.contains("by default"), "{}", page.body);
    assert!(
        !page.body.contains("value=\"clear-history\""),
        "{}",
        page.body
    );
}

/// `/jobs` shows a viewer the job history newest first with what each job used, links a job
/// to GitLab only by a plain web URL and its node to the node's page, filters by node, project
/// and result, and pages back from the oldest job shown, keeping the filter.
#[tokio::test(flavor = "multi_thread")]
async fn the_job_history_is_shown_filtered_and_paged() {
    use vk_hub_proto::client::{JobState, Placement};
    use vk_hub_proto::job::{Envelope, FailureClass, JobResult, JobUsage};
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/jobs", Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(page.body.contains("none placed yet"), "{}", page.body);
    assert!(
        page.body
            .contains("<a href=\"/jobs\" aria-current=\"page\">Jobs</a>"),
        "{}",
        page.body
    );

    let now = crate::now_secs();
    let ended = |failure, exit_code, usage| {
        Some(JobResult {
            failure,
            exit_code,
            message: None,
            output_len: 0,
            artifacts: Vec::new(),
            usage,
            events: Vec::new(),
            egress: None,
        })
    };
    let job = |n: u64, project: &str, url: &str, state, result| crate::store::JobRow {
        key: "k".into(),
        key_name: "gitlab".into(),
        instance: None,
        request_id: format!("{n:032}"),
        scheduling: None,
        admission: None,
        placement: Placement {
            pool: "ci".into(),
            labels: vec![],
            envelope: Envelope::default(),
        },
        title: format!("GitLab job {n} of {project} (build)"),
        job_url: Some(url.to_string()),
        project: Some(project.to_string()),
        name: Some(format!("build-{n}")),
        created_at: now,
        state,
        revision: 1,
        node: None,
        stage: None,
        cancel: None,
        result,
        output_len: 0,
        started_at: None,
        finished_at: None,
        settled_at: None,
        git_ref: None,
        pipeline: None,
        expired_at: None,
        commit: None,
        activity: None,
        prepared_at: None,
        guest: None,
        registry_access: None,
        gitlab: None,
        project_id: None,
        protected: None,
        egress_rules: None,
        egress_caps: None,
        egress: None,
    };
    let submit = |n: u64, row: &crate::store::JobRow| {
        let id = format!("{n:032x}");
        hub.db
            .submit_job(&id, row, &n.to_string(), b"{}", "key gitlab", now)
            .unwrap();
        // As the hub notes a job it records: the newest page holds its reading until then.
        hub.jobs_changed();
    };
    // A page and a bit of jobs still queued, then three that ran.
    for n in 1..=101 {
        submit(n, &job(n, "bulk/x", "", JobState::Queued, None));
    }
    let mut measured = job(
        102,
        "acme/web",
        "https://gitlab.example.com/acme/web/-/jobs/102",
        JobState::Finished,
        ended(
            None,
            None,
            Some(JobUsage {
                wall_ms: 61_000,
                cpu_ms: Some(120_000),
                peak_mem_bytes: Some(3 << 30),
                cpus: Some(4),
                mem_mib: Some(8192),
                prepare_ms: None,
            }),
        ),
    );
    measured.node = Some(node.clone());
    measured.git_ref = Some("main".into());
    measured.commit = Some("ab12".into());
    measured.started_at = Some(now - 100);
    measured.finished_at = Some(now - 30);
    submit(102, &measured);
    let mut failed = job(
        103,
        "acme/api",
        "javascript:alert(1)",
        JobState::Finished,
        ended(Some(FailureClass::Script), Some(2), None),
    );
    failed.node = Some("ef".repeat(16));
    failed.git_ref = Some("fix/<x>".into());
    failed.pipeline = Some(77);
    failed.started_at = Some(now - 20);
    failed.finished_at = Some(now - 10);
    // What its reservation held is not the size of its VM, which its node did not say.
    failed.placement.envelope = Envelope {
        cpus: 8,
        mem_mib: 16384,
        disk_bytes: 0,
    };
    submit(103, &failed);
    let mut running = job(
        104,
        "acme/web",
        "https://gitlab.example.com/acme/web/-/jobs/104",
        JobState::Running,
        None,
    );
    running.node = Some(node.clone());
    running.git_ref = Some("feature/main-menu".into());
    running.pipeline = Some(77);
    running.stage = Some("step_script".into());
    running.started_at = Some(now - 90);
    running.guest = Some(vk_hub_proto::dispatch::GuestSize {
        cpus: 2,
        mem_mib: 4096,
    });
    submit(104, &running);

    let rows = |body: &str| body.matches("<tr><td title=").count();
    let page = get(addr, "/jobs", Some(&viewer)).await.body;
    assert_only_embedded_scripts(&page);
    assert_eq!(rows(&page), 100, "{page}");
    for want in [
        // 61 and 10 seconds.
        "104 jobs · 50% of 2 finished succeeded · median run of finished jobs 35s",
        "<a href=\"/jobs?name=build-102\">\
         <span class=\"mid\" title=\"build-102 · 00000000000000000000000000000066\">\
         <span class=\"head\">build-102</span></span></a> \
         <a href=\"https://gitlab.example.com/acme/web/-/jobs/102\" \
         target=\"_blank\" rel=\"noopener noreferrer\">↗</a></div></td><td><div class=\"fit\">\
         <span class=\"mid\" title=\"acme/web\"><span class=\"head\">acme/web</span></span>\
         </div></td><td><div class=\"fit\"><a href=\"/jobs?ref=main\">\
         <span class=\"mid\" title=\"main @ ab12\"><span class=\"head\">main</span></span></a></div></td>\
         <td>-</td>",
        &format!("<a href=\"/node/{node}\">ci-1</a>"),
        "<span class=\"badge ok\">success</span>",
        "<td class=\"num\">1m01s</td><td class=\"num\">3.0 GiB</td>\
         <td class=\"num\">2m00s</td><td class=\"num\">4 vCPUs, 8.0 GiB</td>",
        // Not a web link: no link to GitLab, for the job or its pipeline.
        "<a href=\"/jobs?name=build-103\">\
         <span class=\"mid\" title=\"build-103 · 00000000000000000000000000000067\">\
         <span class=\"head\">build-103</span></span></a></div></td><td><div class=\"fit\">\
         <span class=\"mid\" title=\"acme/api\"><span class=\"head\">acme/api</span></span>\
         </div></td><td><div class=\"fit\"><a href=\"/jobs?ref=fix%2F%3Cx%3E\">\
         <span class=\"mid\" title=\"fix/&lt;x&gt;\"><span class=\"head\">fix/&lt;x&gt;</span>\
         </span></a></div></td>\
         <td><a href=\"/jobs?pipeline=77\">77</a></td>\
         <td><a href=\"/node/efefefefefefefefefefefefefefefef\"><code>efefefef</code></a></td>",
        // A branch too long for its column keeps its end, and is whole on hover.
        "<a href=\"/jobs?ref=feature%2Fmain-menu\"><span class=\"mid\" title=\"feature/main-menu\">\
         <span class=\"head\">featu</span><span class=\"tail\">re/main-menu</span></span></a>",
        // A queued job with no branch.
        "<span class=\"mid\" title=\"bulk/x\"><span class=\"head\">bulk/x</span></span></div></td>\
         <td><div class=\"fit\">-</div></td>",
        // The job's pipeline, and its page on GitLab.
        "<td><a href=\"/jobs?pipeline=77\">77</a> \
         <a href=\"https://gitlab.example.com/acme/web/-/pipelines/77\" target=\"_blank\" \
         rel=\"noopener noreferrer\">↗</a></td>",
        "<span class=\"badge bad\">script failure, exit 2</span>",
        "<span class=\"badge busy\">running: step_script</span>",
        // Running for 90 seconds by the hub's clock; the browser advances the duration.
        "<td class=\"num\"><span data-since=\"",
        "\">1m3",
        "<span class=\"badge\">queued</span>",
    ] {
        assert!(page.contains(want), "{want}: {page}");
    }
    assert!(!page.contains("href=\"javascript"), "{page}");
    // The running job's size is its VM's, as its node said; the failed one's is not known.
    let row_of = |name: &str| {
        let row = page.split("<tr>").find(|r| r.contains(name)).unwrap();
        row.split("</tr>").next().unwrap()
    };
    assert!(
        row_of(">build-104<").ends_with("<td class=\"num\">2 vCPUs, 4.0 GiB</td>"),
        "{page}"
    );
    assert!(
        row_of(">build-103<").ends_with("<td class=\"num\">-</td>"),
        "{page}"
    );
    // Only the running job's duration advances.
    assert_eq!(page.matches("data-since=").count(), 1, "{page}");
    // Newest first.
    let at = |name: &str| page.find(name).unwrap();
    assert!(at("build-104") < at("build-103") && at("build-103") < at("build-102"));
    let older = page
        .split("<a href=\"/jobs?before=")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a link to older jobs");
    let page = get(addr, &format!("/jobs?before={older}"), Some(&viewer))
        .await
        .body;
    assert_eq!(rows(&page), 4, "{page}");
    assert!(
        page.contains(">build-1<") && !page.contains("Older</a>"),
        "{page}"
    );
    let page = get(addr, "/jobs?before=0", Some(&viewer)).await.body;
    assert_eq!(rows(&page), 0, "{page}");
    assert!(
        page.contains("104 jobs") && page.contains("<p class=\"empty\">no older jobs</p>"),
        "{page}"
    );

    let page = get(addr, "/jobs?result=failed", Some(&viewer)).await.body;
    assert_eq!(rows(&page), 1, "{page}");
    // Filtered on a result, the summary gives no success rate.
    assert!(
        page.contains("1 job · median run of finished jobs 10s</p>"),
        "{page}"
    );
    assert!(
        page.contains("<option value=\"failed\" selected>Failed</option>"),
        "{page}"
    );
    let page = get(addr, &format!("/jobs?node={node}"), Some(&viewer))
        .await
        .body;
    assert_eq!(rows(&page), 2, "{page}");
    let page = get(
        addr,
        "/jobs?project=acme%2Fweb&result=running",
        Some(&viewer),
    )
    .await
    .body;
    assert_eq!(rows(&page), 1, "{page}");
    assert!(page.contains("build-104"), "{page}");
    assert!(
        page.contains("<option value=\"acme/web\" selected>acme/web</option>"),
        "{page}"
    );
    let page = get(addr, "/jobs?project=no%3Cpe", Some(&viewer)).await.body;
    assert!(page.contains("none match"), "{page}");
    assert!(
        page.contains("<option value=\"no&lt;pe\" selected>no&lt;pe</option>"),
        "{page}"
    );
    // A node no longer enrolled, as the history still names it.
    let gone = "ef".repeat(16);
    let page = get(addr, &format!("/jobs?node={gone}"), Some(&viewer))
        .await
        .body;
    assert_eq!(rows(&page), 1, "{page}");
    assert!(
        page.contains(&format!(
            "<option value=\"{gone}\" selected>efefefef</option>"
        )),
        "{page}"
    );
    // A part of a job name or branch, in either case, and a pipeline; the form shows them.
    let page = get(addr, "/jobs?ref=MAIN", Some(&viewer)).await.body;
    assert_eq!(rows(&page), 2, "{page}");
    assert!(page.contains(">build-104<") && page.contains(">build-102<"));
    assert!(
        page.contains(
            "name=\"ref\" placeholder=\"Branch\" aria-label=\"Branch\" value=\"MAIN\" \
             maxlength=\"256\""
        ),
        "{page}"
    );
    let page = get(addr, "/jobs?pipeline=77&name=%20Build-10", Some(&viewer))
        .await
        .body;
    assert_eq!(rows(&page), 2, "{page}");
    assert!(
        page.contains("2 jobs · 0% of 1 finished succeeded"),
        "{page}"
    );
    assert!(page.contains("value=\"Build-10\""), "{page}");
    assert!(
        page.contains("aria-label=\"Pipeline\" value=\"77\""),
        "{page}"
    );
    // A row narrows the page it is on.
    assert!(
        page.contains(
            "<a href=\"/jobs?name=build-104&amp;pipeline=77\">\
             <span class=\"mid\" title=\"build-104 · 00000000000000000000000000000068\">\
             <span class=\"head\">build-104</span></span></a>"
        ),
        "{page}"
    );
    let page = get(addr, "/jobs?name=build-1&ref=fix%2F%3C", Some(&viewer))
        .await
        .body;
    assert_eq!(rows(&page), 1, "{page}");
    assert!(page.contains("value=\"fix/&lt;\""), "{page}");
    // The filter carries over to older jobs.
    let page = get(addr, "/jobs?result=running", Some(&viewer)).await.body;
    assert_eq!(rows(&page), 100, "{page}");
    assert!(
        page.contains("<a href=\"/jobs?result=running&amp;before="),
        "{page}"
    );

    let page = get(addr, &format!("/node/{node}"), Some(&viewer))
        .await
        .body;
    assert!(
        page.contains(&format!("<a href=\"/jobs?node={node}\">Its jobs</a>")),
        "{page}"
    );
}

/// `/jobs?key=` narrows the history, older pages and its stream to one API key's jobs. The
/// form keeps the key; the results show it by name, or by its ID's start once the key is gone,
/// with a link dropping it that follows the rest of the filter.
#[tokio::test(flavor = "multi_thread")]
async fn the_job_history_is_filtered_by_api_key() {
    use crate::store::{KeyPolicy, Scope};
    let (addr, hub, _) = start_fleet().await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let policy = KeyPolicy {
        scopes: vec![Scope::Jobs],
        pools: vec!["ci".into()],
        max_envelope: None,
    };
    let now = crate::now_secs();
    let ttl = Duration::from_secs(3600);
    hub.db
        .create_api_key("deploy", &policy, ttl, "uid 0", now)
        .unwrap();
    let keys = hub.db.api_keys_with_ids().unwrap();
    let (key, _) = keys.iter().find(|(_, r)| r.name == "deploy").unwrap();
    for n in 1..=3 {
        let mut row = history_job(n, "acme/web");
        if n != 2 {
            row.key = key.clone();
            row.key_name = "deploy".into();
        }
        hub.db
            .submit_job(
                &format!("{n:032x}"),
                &row,
                &n.to_string(),
                b"{}",
                "key deploy",
                now,
            )
            .unwrap();
    }
    hub.jobs_changed();
    let rows = |page: &str| page.matches("<tr><td title=").count();

    let page = get(
        addr,
        &format!("/jobs?project=acme%2Fweb&key={key}"),
        Some(&viewer),
    )
    .await
    .body;
    assert_eq!(rows(&page), 2, "{page}");
    assert!(!page.contains(">build-2<"), "{page}");
    assert!(
        page.contains(&format!(
            "<input type=\"hidden\" name=\"key\" value=\"{key}\">"
        )),
        "{page}"
    );
    let results = |page: &str| {
        page.split_once("<div id=\"jobs-results\">")
            .unwrap()
            .1
            .to_string()
    };
    assert!(
        results(&page).starts_with(
            "<p><span class=\"badge\">Key: deploy <a href=\"/jobs?project=acme%2Fweb\" \
             title=\"Every key's jobs\" aria-label=\"Every key's jobs\">×</a></span></p>"
        ),
        "{page}"
    );
    assert!(
        page.contains(&format!(
            "sse-connect=\"/events/jobs?key={key}&amp;project=acme%2Fweb\""
        )),
        "{page}"
    );
    let mut stream = Events::open(addr, &format!("/events/jobs?key={key}"), &viewer).await;
    assert!(stream.head.starts_with("HTTP/1.1 200"), "{}", stream.head);
    let first = stream.next().await.unwrap();
    assert!(
        first.contains("2 jobs") && !first.contains(">build-2<"),
        "{first}"
    );

    // The form's request swaps in the results, the chip's link following the new filter.
    let reply = request(
        addr,
        "GET",
        &format!("/jobs?project=acme%2Fapi&key={key}"),
        &[
            &format!("Cookie: {viewer}"),
            "HX-Request: true",
            "HX-Target: jobs-results",
        ],
        "",
    )
    .await;
    assert!(
        results(&reply.body).starts_with(
            "<p><span class=\"badge\">Key: deploy <a href=\"/jobs?project=acme%2Fapi\""
        ),
        "{}",
        reply.body
    );

    // An older page keeps the key, in the chip and in its link to the newest.
    let page = get(addr, &format!("/jobs?key={key}&before=99"), Some(&viewer))
        .await
        .body;
    assert_eq!(rows(&page), 2, "{page}");
    assert!(
        results(&page).starts_with("<p><span class=\"badge\">Key: deploy <a href=\"/jobs\""),
        "{page}"
    );
    assert!(
        page.contains(&format!("<a href=\"/jobs?key={key}\">the newest</a>")),
        "{page}"
    );

    // A key no longer kept, by its ID's start.
    let gone = "ab".repeat(32);
    let page = get(addr, &format!("/jobs?key={gone}"), Some(&viewer))
        .await
        .body;
    assert!(page.contains("none match"), "{page}");
    assert!(
        page.contains("<span class=\"badge\">Key: abababababab <a href=\"/jobs\""),
        "{page}"
    );
    // What cannot be a key's ID is ignored by the page, refused by the stream.
    let upper = key.to_ascii_uppercase();
    for bad in ["zz", upper.as_str()] {
        let page = get(addr, &format!("/jobs?key={bad}"), Some(&viewer))
            .await
            .body;
        assert_eq!(rows(&page), 3, "{page}");
        assert!(!page.contains("name=\"key\""), "{page}");
        let reply = get(addr, &format!("/events/jobs?key={bad}"), Some(&viewer)).await;
        assert_eq!(reply.status, 404, "{bad}");
    }
}

/// `/clients` shows viewers and operators alike, read only, each API key with its jobs linked
/// to the history filtered by it, and the instances using it, what they said shown as text and
/// a runner's URL without its credentials; a hello or a new instance reaches an open page.
#[tokio::test(flavor = "multi_thread")]
async fn api_keys_and_their_clients_are_shown_live() {
    use crate::store::{KeyPolicy, Scope};
    use vk_hub_proto::client::{ClientHello, ClientRunner};
    let (addr, hub, _) = start_fleet().await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/clients?tab=other", Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("<code>vk-hub keys create</code>"),
        "{}",
        page.body
    );

    let policy = KeyPolicy {
        scopes: vec![Scope::Jobs],
        pools: vec!["ci".into()],
        max_envelope: None,
    };
    let now = crate::now_secs();
    let (key, _) = hub
        .db
        .create_api_key("gitlab", &policy, Duration::from_secs(3600), "uid 0", now)
        .unwrap();
    let id = crate::store::token_key(&key);
    let mut row = history_job(1, "acme/web");
    row.key = id.clone();
    row.key_name = "gitlab".into();
    hub.db
        .submit_job(&format!("{:032x}", 1), &row, "1", b"{}", "key gitlab", now)
        .unwrap();
    let mut events = Events::open(addr, "/events/clients", &viewer).await;
    assert!(events.head.starts_with("HTTP/1.1 200"), "{}", events.head);
    let first = events.next().await.unwrap();
    assert!(first.starts_with("event: clients\ndata: "), "{first}");
    assert!(first.contains("no client has used a key yet"), "{first}");

    let hostile = "<script>alert(1)</script>\"'><img src=x onerror=alert(2)>";
    let runner = |name: &str, url: &str| ClientRunner {
        name: name.into(),
        url: url.into(),
        pool: "ci".into(),
        labels: vec![],
        limit: None,
    };
    let hello = ClientHello {
        instance: "s_1".into(),
        program: "vk-gitlab".into(),
        version: "0.91.1".into(),
        hostname: format!("ci-1{hostile}"),
        concurrent: Some(2),
        runners: vec![
            runner(&format!("docker{hostile}"), "https://gitlab.example.com/"),
            runner("shell", "https://user:pass@gitlab.example.com/"),
        ],
    };
    let principal = hub.db.api_key(&key, now).unwrap().unwrap();
    crate::clients::hello(&hub, &principal, hello)
        .await
        .unwrap();
    let event = next_with(&mut events, "vk-gitlab 0.91.1").await;
    assert!(event.contains("<code>s_1</code>"), "{event}");
    // A first contact of another instance reaches it too.
    let mut other = principal.clone();
    other.instance = Some("s_2".into());
    crate::clients::seen(&hub, &other, crate::now_secs());
    next_with(&mut events, "<code>s_2</code>").await;

    for role in [Role::Viewer, Role::Operator] {
        let (cookie, _) = sign_in(addr, &hub, role).await;
        let page = get(addr, "/clients?tab=other", Some(&cookie)).await.body;
        for want in [
            "<a href=\"/egress\">Egress<span id=\"nav-count-egress\"></span></a>\
             <a href=\"/clients\" aria-current=\"page\">Connections\
             <span id=\"nav-count-clients\"></span></a>",
            "sse-connect=\"/events/clients\"",
            &format!("<a href=\"/jobs?key={id}\">1</a>"),
            "ci-1&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&gt;&lt;img",
            "docker&lt;script&gt;",
            "<a href=\"https://gitlab.example.com/\" target=\"_blank\" \
             rel=\"noopener noreferrer\">https://gitlab.example.com/</a>",
            "shell · pool ci · <a href=\"https://gitlab.example.com/\"",
            "<span class=\"badge ok\">connected</span>",
        ] {
            assert!(page.contains(want), "{role:?}: {want}: {page}");
        }
        let main = page.split_once("<main>").unwrap().1;
        for not in ["<script>alert", "<img", "user:pass"] {
            assert!(!main.contains(not), "{role:?}: {not}: {page}");
        }
        if role == Role::Operator {
            assert!(
                main.contains("<button class=\"danger\">Revoke</button>"),
                "{page}"
            );
            continue;
        }
        // Nothing to act on: the sign-out form above `<main>` is the page's only one.
        for not in ["<form", "hx-post"] {
            assert!(!main.contains(not), "{role:?}: {not}: {page}");
        }
        assert!(!page.contains("hx-headers"), "{role:?}: {page}");
    }
}

/// The key in a page showing one.
fn shown_key(body: &str) -> String {
    let at = body.find("vkk_").expect("the key");
    body[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect()
}

/// An operator creates an API key from `/clients`: refused, with the reason, for a bad name or
/// policy, and otherwise shown once with the vk-gitlab config using it, audited without it,
/// and never in the live fragment or a later page. A viewer gets no form and is refused, as is
/// a post from another site or without the session's CSRF token.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_creates_an_api_key_shown_once() {
    use crate::store::Scope;
    let (addr, hub, origin) = start_fleet_with("http", Some("https://hub.example.com:8443")).await;
    let good = "op=create&name=gitlab&pools=ci%2C+build&scope=jobs&scope=capacity\
                &max_mem=16G&max_cpus=8&max_disk=&ttl=30";

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/clients?tab=other", Some(&viewer)).await;
    assert!(!page.body.contains("value=\"create\""), "{}", page.body);
    let form = format!("_csrf={viewer_csrf}&{good}");
    let reply = post_action(addr, &origin, &viewer, "/clients", &form, false).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    assert!(reply.body.contains("operator role"), "{}", reply.body);

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/clients?tab=other", Some(&operator)).await;
    for want in [
        "<form class=\"wide\" method=\"post\" action=\"/clients\">",
        "<input type=\"hidden\" name=\"op\" value=\"create\">",
        "<option value=\"90\">90 days</option>",
        "value=\"jobs\" checked>",
        "none: create one below",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    // Outside the live fragment.
    let fragment = page.body.split("id=\"clients\"").nth(1).unwrap();
    let fragment = fragment.split("<h2>Create an API key").next().unwrap();
    assert!(!fragment.contains("<form"), "{fragment}");
    let mut live = Events::open(addr, "/events/clients", &operator).await;
    live.next().await.unwrap();

    let form = format!("_csrf={csrf}&{good}");
    let reply = post_action(
        addr,
        "http://evil.example",
        &operator,
        "/clients",
        &form,
        false,
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let reply = post_action(addr, &origin, &operator, "/clients", good, false).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    assert!(reply.body.contains("CSRF"), "{}", reply.body);
    for (bad, said) in [
        (
            "name=..%2Fx&pools=ci&scope=jobs&ttl=90",
            "a key&#39;s name is 1 to",
        ),
        (
            "name=k&pools=&scope=jobs&ttl=90",
            "a key needs at least one pool",
        ),
        (
            "name=k&pools=ci%2C..&scope=jobs&ttl=90",
            "is not a pool&#39;s name",
        ),
        ("name=k&pools=ci&ttl=90", "a key needs at least one scope"),
        (
            "name=k&pools=ci&scope=all&ttl=90",
            "&quot;all&quot;: expected jobs or capacity",
        ),
        (
            "name=k&pools=ci&scope=jobs&max_mem=lots&ttl=90",
            "largest memory",
        ),
        (
            "name=k&pools=ci&scope=jobs&max_mem=512K&ttl=90",
            "expected at least 1M",
        ),
        (
            "name=k&pools=ci&scope=jobs&max_cpus=-1&ttl=90",
            "largest CPUs",
        ),
        (
            "name=k&pools=ci&scope=jobs&max_disk=9&ttl=90",
            "largest disk",
        ),
        (
            "name=k&pools=ci&scope=jobs&ttl=5",
            "not one of the form&#39;s lifetimes",
        ),
    ] {
        let form = format!("_csrf={csrf}&op=create&{bad}");
        let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
        assert_eq!(reply.status, 400, "{bad}: {}", reply.body);
        assert!(reply.body.contains(said), "{bad}: {said}: {}", reply.body);
    }
    assert!(hub.db.api_keys().unwrap().is_empty());

    let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    assert!(
        reply.body.contains(
            "client API, at <code>https://hub.example.com:8443</code>, as \
             <code>Authorization: Bearer &lt;key&gt;</code>"
        ),
        "{}",
        reply.body
    );
    let key = shown_key(&reply.body);
    assert_eq!(key.len(), 4 + 64, "{key}");
    let now = crate::now_secs();
    let principal = hub.db.api_key(&key, now).unwrap().expect("a working key");
    let crate::store::PrincipalKind::Key(row) = principal.kind else {
        panic!("not a key");
    };
    assert_eq!(row.scopes, [Scope::Jobs, Scope::Capacity]);
    assert_eq!(row.pools, ["build", "ci"]);
    assert_eq!(
        row.max_envelope,
        Some(vk_hub_proto::job::Envelope {
            mem_mib: 16 << 10,
            cpus: 8,
            disk_bytes: u64::MAX,
        })
    );
    assert!(row.expires_at.abs_diff(now + 30 * 86_400) < 60);
    assert!(row.created_by.contains("(operator)"));
    let audit = audited(&hub, "created API key gitlab").await;
    assert!(audit.iter().all(|e| !e.contains(&key)), "{audit:?}");

    let event = next_with(&mut live, "<td>gitlab</td>").await;
    assert!(!event.contains(&key), "{event}");
    let page = get(addr, "/clients?tab=other", Some(&operator)).await;
    assert!(page.body.contains("<td>gitlab</td>"), "{}", page.body);
    assert!(!page.body.contains(&key), "{}", page.body);

    // A working key's name is taken.
    let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert!(reply.body.contains("already works"), "{}", reply.body);
}

/// An operator revokes a working key, once asked first, saying its jobs under way are
/// stranded, then removes it once it no longer works; each is audited and the live page
/// follows. A viewer, an answer given twice and a button shown before the key changed are
/// refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_revokes_then_removes_an_api_key_once_confirmed() {
    use crate::store::{KeyPolicy, Scope};
    let (addr, hub, origin) = start_fleet().await;
    let policy = KeyPolicy {
        scopes: vec![Scope::Jobs],
        pools: vec!["ci".into()],
        max_envelope: None,
    };
    let now = crate::now_secs();
    let (key, _) = hub
        .db
        .create_api_key("gitlab", &policy, Duration::from_secs(3600), "uid 0", now)
        .unwrap();
    let id = crate::store::token_key(&key);

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let form = format!("_csrf={viewer_csrf}&op=revoke&name=gitlab");
    let reply = post_action(addr, &origin, &viewer, "/clients", &form, true).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let mut viewing = Events::open(addr, "/events/clients", &viewer).await;
    let first = viewing.next().await.unwrap();
    assert!(!first.contains("hx-post"), "{first}");

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/clients?tab=other", Some(&operator)).await;
    for want in [
        &format!("X-CSRF-Token&quot;:&quot;{csrf}&quot;"),
        "<div id=\"flash\"></div>",
        "action=\"/clients\" hx-post=\"/clients\" hx-swap=\"none\"",
        "<input type=\"hidden\" name=\"op\" value=\"revoke\">\
         <input type=\"hidden\" name=\"name\" value=\"gitlab\">\
         <button class=\"danger\">Revoke</button>",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    // The fragment, shared by every operator's page, carries no session's token.
    let fragment = page.body.split("id=\"clients\"").nth(1).unwrap();
    let fragment = fragment.split("<h2>Create an API key").next().unwrap();
    assert!(!fragment.contains(&csrf), "{fragment}");
    let mut live = Events::open(addr, "/events/clients", &operator).await;
    let first = live.next().await.unwrap();
    assert!(
        first.contains("<button class=\"danger\">Revoke</button>"),
        "{first}"
    );
    assert!(!first.contains(&csrf), "{first}");

    // Asked first; the key works until answered.
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients",
        &format!("_csrf={csrf}&op=revoke&name=gitlab"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    for want in [
        "can no longer follow or settle its jobs under way",
        "<button class=\"danger\">Yes, revoke</button>",
        "0 reservation(s), 0 job(s) queued or running",
    ] {
        assert!(reply.body.contains(want), "{want}: {}", reply.body);
    }
    assert_eq!(hidden(&reply.body, "keys"), id);
    assert!(hub.db.api_key(&key, now).unwrap().is_some());
    let answer = format!(
        "_csrf={csrf}&op=revoke&name=gitlab&keys={id}&nonce={}&confirm=yes",
        hidden(&reply.body, "nonce")
    );
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Revoked API key gitlab."),
        "{}",
        reply.body
    );
    assert!(hub.db.api_key(&key, crate::now_secs()).unwrap().is_none());
    audited(&hub, "revoked API key gitlab").await;
    let revoked = next_with(&mut live, "badge bad\">revoked").await;
    assert!(
        revoked.contains("<button class=\"danger\">Remove</button>"),
        "{revoked}"
    );
    next_with(&mut viewing, "badge bad\">revoked").await;

    // Answered once; and a revoke button shown before is now stale.
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    let form = format!("_csrf={csrf}&op=revoke&name=gitlab");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    let form = format!("_csrf={csrf}&op=revoke&name=other");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, true).await;
    assert_eq!(reply.status, 404, "{}", reply.body);

    // Removed, once asked, by a plain form back to the page.
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients",
        &format!("_csrf={csrf}&op=remove&name=gitlab"),
        false,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("<h1>Confirm</h1>"), "{}", reply.body);
    let answer = format!(
        "_csrf={csrf}&op=remove&name=gitlab&keys={id}&nonce={}&confirm=yes",
        hidden(&reply.body, "nonce")
    );
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients?tab=other"));
    assert!(hub.db.api_keys().unwrap().is_empty());
    audited(&hub, "removed 1 revoked or expired API key(s) named gitlab").await;
    next_with(&mut live, "none: create one below").await;
}

/// A revocation confirmed after the key was revoked and its name taken again is refused, the
/// new key left working; so is a removal while a key of that name works, and an unknown
/// action. The question counts what the key's instances hold.
#[tokio::test(flavor = "multi_thread")]
async fn a_key_changed_since_confirmed_is_left_alone() {
    use crate::store::{KeyPolicy, Scope};
    use vk_hub_proto::client::JobState;
    let scratch = Scratch::new("clients-changed");
    let (addr, hub) = start_fleet_placing(&scratch.0).await;
    let origin = format!("http://{addr}");
    let policy = KeyPolicy {
        scopes: vec![Scope::Jobs],
        pools: vec!["ci".into()],
        max_envelope: None,
    };
    let ttl = Duration::from_secs(3600);
    let now = crate::now_secs();
    let (old, _) = hub
        .db
        .create_api_key("gitlab", &policy, ttl, "uid 0", now)
        .unwrap();
    let old_id = crate::store::token_key(&old);
    // A job of its running on a node, picked back up as a restarted hub would.
    let mut row = history_job(1, "acme/web");
    row.key = old_id.clone();
    row.instance = Some("s_1".into());
    row.state = JobState::Running;
    row.node = Some("n1".into());
    row.started_at = Some(now);
    hub.db
        .submit_job(&format!("{:032x}", 1), &row, "1", b"{}", "key gitlab", now)
        .unwrap();
    crate::jobs::recover(&hub).await.unwrap();

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients",
        &format!("_csrf={csrf}&op=revoke&name=gitlab"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("0 reservation(s), 1 job(s) queued or running"),
        "{}",
        reply.body
    );
    let answer = format!(
        "_csrf={csrf}&op=revoke&name=gitlab&keys={old_id}&nonce={}&confirm=yes",
        hidden(&reply.body, "nonce")
    );
    assert!(hub.db.revoke_api_key("gitlab", "uid 0", now).unwrap());
    let (new, _) = hub
        .db
        .create_api_key("gitlab", &policy, ttl, "uid 0", now)
        .unwrap();
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(hub.db.api_key(&new, crate::now_secs()).unwrap().is_some());

    // The old key no longer works, but the new one holds the name.
    let form = format!("_csrf={csrf}&op=remove&name=gitlab");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert_eq!(hub.db.api_keys().unwrap().len(), 2);

    let form = format!("_csrf={csrf}&op=delete&name=gitlab");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, true).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert_eq!(hub.db.api_keys().unwrap().len(), 2);
}

/// Job `n` of `project`, as submitted.
pub(super) fn history_job(n: u64, project: &str) -> crate::store::JobRow {
    use vk_hub_proto::client::{JobState, Placement};
    crate::store::JobRow {
        key: "k".into(),
        key_name: "gitlab".into(),
        instance: None,
        request_id: format!("{n:032}"),
        scheduling: None,
        admission: None,
        placement: Placement {
            pool: "ci".into(),
            labels: vec![],
            envelope: vk_hub_proto::job::Envelope::default(),
        },
        title: format!("GitLab job {n} of {project} (build)"),
        job_url: None,
        project: Some(project.to_string()),
        name: Some(format!("build-{n}")),
        created_at: crate::now_secs(),
        state: JobState::Queued,
        revision: 1,
        node: None,
        stage: None,
        cancel: None,
        result: None,
        output_len: 0,
        started_at: None,
        finished_at: None,
        settled_at: None,
        git_ref: None,
        pipeline: None,
        expired_at: None,
        commit: None,
        activity: None,
        prepared_at: None,
        guest: None,
        registry_access: None,
        gitlab: None,
        project_id: None,
        protected: None,
        egress_rules: None,
        egress_caps: None,
        egress: None,
    }
}

/// A failed job links from the history to its page, which shows any session its record and
/// the end of its output the hub kept, as text: escaped, its escape sequences and GitLab's
/// section markers dropped, its stamps shown as times.
#[tokio::test(flavor = "multi_thread")]
async fn a_finished_job_s_page_shows_the_end_kept_of_its_output() {
    use vk_hub_proto::client::JobState;
    use vk_hub_proto::job::{FailureClass, JobResult};
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let now = crate::now_secs();
    let id = |n: u64| format!("{n:032x}");
    let ended = |n: u64, failure| {
        let mut row = history_job(n, "acme/web");
        row.state = JobState::Finished;
        row.node = Some(node.clone());
        row.job_url = Some(format!("https://gitlab.example.com/acme/web/-/jobs/{n}"));
        row.started_at = Some(now - 5);
        row.git_ref = Some("main".into());
        row.commit = Some("0123456789abcdef0123".into());
        row.finished_at = Some(now);
        row.settled_at = Some(now);
        row.result = Some(JobResult {
            failure,
            exit_code: None,
            message: Some("the VM <did> not boot".into()),
            output_len: 0,
            artifacts: Vec::new(),
            usage: None,
            events: Vec::new(),
            egress: None,
        });
        row
    };
    for (n, failure) in [
        (1, Some(FailureClass::System)),
        (2, None),
        (3, Some(FailureClass::Lost)),
        (4, None),
    ] {
        let mut row = ended(n, failure);
        if n == 3 {
            // A commit with no branch.
            row.git_ref = None;
        }
        hub.db
            .submit_job(&id(n), &row, &n.to_string(), b"{}", "key gitlab", now)
            .unwrap();
    }
    let stamp = "2026-10-09T12:10:43.123456Z";
    let tail = format!(
        "{stamp} 00O section_start:1700000000:prepare\r\x1b[0K\n\
         {stamp} 01E \x1b[31m<script>alert(1)</script>\x1b[0m\n"
    );
    assert!(hub.db.keep_job_tail(&id(1), tail.as_bytes()).unwrap());
    assert!(
        hub.db
            .cache_job_tail(&id(4), b"all good\n", 1 << 20)
            .unwrap()
    );

    let page = get(addr, "/jobs", Some(&viewer)).await.body;
    assert!(
        page.contains(&format!(
            "<a href=\"/jobs/{}\"><span class=\"badge bad\" title=\"the VM &lt;did&gt; not \
             boot\">system failure</span></a>",
            id(1)
        )),
        "{page}"
    );
    // With no branch, hovering over the dash shows the commit.
    assert!(
        page.contains("<span title=\"0123456789abcdef0123\">-</span>"),
        "{page}"
    );
    // Every job links to its page.
    assert!(
        page.contains(&format!(
            "<a href=\"/jobs/{}\"><span class=\"badge ok\" title=\"the VM &lt;did&gt; not \
             boot\">success</span></a>",
            id(2)
        )),
        "{page}"
    );

    let reply = get(addr, &format!("/jobs/{}", id(1)), Some(&viewer)).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let page = reply.body;
    assert_only_embedded_scripts(&page);
    for want in [
        "<h1>build-1</h1>",
        "<a href=\"https://gitlab.example.com/acme/web/-/jobs/1\" target=\"_blank\" \
         rel=\"noopener noreferrer\">On GitLab</a>",
        // Its branch and commit, the commit short and whole on hover.
        "<tr><th>Branch</th><td>main @ <code title=\"0123456789abcdef0123\">0123456789ab</code>\
         </td></tr>",
        "<tr><th>Failure class</th><td>system failure</td></tr>",
        "<tr><th>Message</th><td>the VM &lt;did&gt; not boot</td></tr>",
        &format!("<a href=\"/node/{node}\">ci-1</a>"),
        "<h2>End of its output</h2>",
        "<pre class=\"log\"><span class=\"l\"><time title=\"2026-10-09T12:10:43.123456Z\">\
         12:10:43</time> <span class=\"t\"><span class=\"c-f1\">&lt;script&gt;alert(1)&lt;/script&gt;\
         </span></span></span>\n</pre>",
    ] {
        assert!(page.contains(want), "{want}: {page}");
    }
    assert!(
        !page.contains('\x1b') && !page.contains("section_start"),
        "{page}"
    );
    let page = get(addr, &format!("/jobs/{}", id(3)), Some(&viewer))
        .await
        .body;
    assert!(page.contains("<p class=\"empty\">none kept</p>"), "{page}");
    assert!(
        page.contains(
            "<tr><th>Branch</th><td>- @ <code title=\"0123456789abcdef0123\">0123456789ab\
             </code></td></tr>"
        ),
        "{page}"
    );
    let page = get(addr, &format!("/jobs/{}", id(2)), Some(&viewer))
        .await
        .body;
    assert!(page.contains("<span class=\"badge ok\""), "{page}");
    assert!(!page.contains("End of its output"), "{page}");
    // A job settled that succeeded: its output went, GitLab has it.
    assert!(
        page.contains(
            "<p class=\"empty\">dropped once its producer had it: \
             <a href=\"https://gitlab.example.com/acme/web/-/jobs/2\" target=\"_blank\" \
             rel=\"noopener noreferrer\">GitLab has it</a></p>"
        ),
        "{page}"
    );
    assert!(!page.contains("sse-connect"), "{page}");
    // One that succeeded whose end is still in the hub's cache shows it.
    let page = get(addr, &format!("/jobs/{}", id(4)), Some(&viewer))
        .await
        .body;
    for want in [
        "<h2>End of its output</h2><p class=\"sub\">The last 9 B, masked as the node streamed \
         it, kept while the hub's cache of finished jobs' output has room.</p>",
        "<span class=\"t\">all good</span>",
    ] {
        assert!(page.contains(want), "{want}: {page}");
    }
    assert!(!page.contains("GitLab has it"), "{page}");

    let reply = get(addr, &format!("/jobs/{}", id(9)), Some(&viewer)).await;
    assert_eq!(reply.status, 404);
    assert!(
        reply.body.contains("There is no such job."),
        "{}",
        reply.body
    );
    let reply = get(addr, "/jobs/zz", Some(&viewer)).await;
    assert_eq!(reply.status, 404);
    let reply = get(addr, &format!("/jobs/{}", id(1)), None).await;
    assert_eq!(reply.status, 401);
    assert!(!reply.body.contains("alert"), "{}", reply.body);
}

/// An expired session makes a filter request load the full page rather than swap in a
/// page without the results container.
#[tokio::test(flavor = "multi_thread")]
async fn the_jobs_filter_loads_the_whole_page_when_refused() {
    let (addr, hub, _) = start_fleet().await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let path = "/jobs?result=failed";
    let cookie = format!("Cookie: {viewer}");
    let swap = [
        cookie.as_str(),
        "HX-Request: true",
        "HX-Target: jobs-results",
    ];
    let reply = request(addr, "GET", path, &swap, "").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("hx-redirect"), None);
    assert!(
        reply.body.contains("<div id=\"jobs-results\">"),
        "{}",
        reply.body
    );
    hub.db
        .end_ui_sessions(None, "uid 0", crate::now_secs())
        .unwrap();
    let reply = request(addr, "GET", path, &swap, "").await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("hx-redirect"), Some(path));
    // Any other request is refused as before.
    let reply = request(addr, "GET", path, &swap[..2], "").await;
    assert_eq!(reply.status, 401, "{}", reply.body);
    assert_eq!(reply.header("hx-redirect"), None);
}

/// A scratch directory, removed when dropped, by a failed test too.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("vk-hub-ui-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A fleet UI on a hub that keeps jobs' output in `dir`.
async fn start_fleet_placing(dir: &std::path::Path) -> (SocketAddr, Arc<Hub>) {
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("http://{addr}");
    let hub = Arc::new(
        Hub::new(Arc::new(Db::open_memory().unwrap()), Some(origin.clone()))
            .with_jobs(
                dir.to_path_buf(),
                crate::jobs::DEFAULT_LOST_AFTER,
                Some(100),
            )
            .unwrap(),
    );
    let ui = Arc::new(Ui::new(hub.clone(), &origin));
    tokio::spawn(serve(listener, None, ui));
    (addr, hub)
}

/// A stamp's header, `kind` ` ` for a line or `+` for a line's continuation.
fn stamp(kind: char) -> String {
    format!("2026-10-09T12:10:43.123456Z 01O{kind}")
}

/// Running job `n`'s record, with `output` stored as its output.
fn running_with_output(hub: &Hub, dir: &std::path::Path, n: u64, output: &[u8]) -> String {
    use vk_hub_proto::client::JobState;
    let id = format!("{n:032x}");
    std::fs::write(dir.join(format!("{id}.out")), output).unwrap();
    let mut row = history_job(n, "acme/web");
    row.state = JobState::Running;
    row.started_at = Some(crate::now_secs());
    row.stage = Some("step_script".into());
    row.output_len = output.len() as u64;
    let now = crate::now_secs();
    hub.db
        .submit_job(&id, &row, &n.to_string(), b"{}", "key gitlab", now)
        .unwrap();
    id
}

/// Job `id`'s output grows by `more`, as the hub stores what a node sends.
fn more_output(hub: &Hub, dir: &std::path::Path, id: &str, more: &[u8]) {
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join(format!("{id}.out")))
        .unwrap();
    file.write_all(more).unwrap();
    let mut row = hub.db.job(id).unwrap().unwrap();
    row.output_len += more.len() as u64;
    assert!(hub.db.put_job(id, &row, &[], crate::now_secs()).unwrap());
    hub.job_changed(id);
}

/// A running job's page follows its output and record over a stream of its own, for any
/// session: what the output gains appended in order however it was cut, mid-line or
/// mid-character, the last line so far replaced as it changes, and the stream closed with
/// the job's result.
#[tokio::test(flavor = "multi_thread")]
async fn a_running_job_s_page_follows_its_output() {
    use vk_hub_proto::client::JobState;
    use vk_hub_proto::job::JobResult;
    let scratch = Scratch::new("follow");
    let dir = &scratch.0;
    let (addr, hub) = start_fleet_placing(dir).await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let first = format!("{}<b>first</b>\n{}10%\r\n", stamp(' '), stamp(' '));
    let id = running_with_output(&hub, dir, 1, first.as_bytes());
    // A line as the page draws it: numbered by `ui.css`, its time, then its text.
    let time = "<span class=\"l\"><time title=\"2026-10-09T12:10:43.123456Z\">12:10:43</time> \
                <span class=\"t\">";
    let end = "</span></span>";

    // The history links every job to its page.
    let page = get(addr, "/jobs", Some(&viewer)).await.body;
    assert!(
        page.contains(&format!(
            "<a href=\"/jobs/{id}\"><span class=\"badge busy\">running: step_script</span></a>"
        )),
        "{page}"
    );
    // The browser advances the duration from its start time between updates.
    assert!(page.contains("<span data-since=\"20"), "{page}");
    let page = get(addr, &format!("/jobs/{id}"), Some(&viewer)).await.body;
    assert_only_embedded_scripts(&page);
    for want in [
        format!(
            "<div class=\"job-page\" hx-ext=\"sse\" sse-connect=\"/events/job/{id}\" \
             sse-close=\"close\"><div class=\"job-output\">"
        ),
        "<span hidden sse-swap=\"output-start\" hx-target=\"#job-lines\"></span>".to_string(),
        format!(
            "<pre class=\"log\" data-follow><span id=\"job-lines\" sse-swap=\"output\" hx-swap=\"beforeend\">\
             {time}&lt;b&gt;first&lt;/b&gt;{end}\n</span><span id=\"job-held\" sse-swap=\"held\">\
             {time}10%{end}</span></pre>"
        ),
    ] {
        assert!(page.contains(&want), "{want}: {page}");
    }
    for bad in [
        format!("/events/job/{id}?x=1"),
        "/events/job/zz".to_string(),
    ] {
        assert_eq!(get(addr, &bad, Some(&viewer)).await.status, 404, "{bad}");
    }

    let mut stream = Events::open(addr, &format!("/events/job/{id}"), &viewer).await;
    assert!(stream.head.starts_with("HTTP/1.1 200"), "{}", stream.head);
    // What the page shows, replacing it: a stream opened again shows no line twice.
    assert_eq!(
        stream.next().await.unwrap(),
        format!("event: output-start\ndata: {time}&lt;b&gt;first&lt;/b&gt;{end}\ndata: \n\n")
    );
    assert_eq!(
        stream.next().await.unwrap(),
        format!("event: held\ndata: {time}10%{end}\n\n")
    );
    let record = stream.next().await.unwrap();
    assert!(
        record.starts_with("event: job\ndata: <section><h2>Job</h2>")
            && record.contains("<span class=\"badge busy\">running: step_script</span>")
            // The navigation's count, kept current out of band.
            && record.contains("<span id=\"nav-count-egress\" hx-swap-oob=\"true\"></span>"),
        "{record}"
    );

    // The last line continued, then a line cut inside a character.
    let mut cut = format!("{}20%\r\n{}d", stamp('+'), stamp(' ')).into_bytes();
    cut.push(0xc3);
    more_output(&hub, dir, &id, &cut);
    assert_eq!(
        stream.next().await.unwrap(),
        format!("event: held\ndata: {time}20%{end}\n\n")
    );
    // The record shows the output's length: it follows it.
    let record = stream.next().await.unwrap();
    assert!(record.starts_with("event: job\ndata: "), "{record}");
    let mut rest = vec![0xa9];
    rest.extend_from_slice(format!("jà ✓\n{}last\n", stamp(' ')).as_bytes());
    more_output(&hub, dir, &id, &rest);
    assert_eq!(
        stream.next().await.unwrap(),
        format!("event: output\ndata: {time}20%{end}\ndata: {time}déjà ✓{end}\ndata: \n\n")
    );
    assert_eq!(
        stream.next().await.unwrap(),
        format!("event: held\ndata: {time}last{end}\n\n")
    );
    let record = stream.next().await.unwrap();
    assert!(record.starts_with("event: job\ndata: "), "{record}");

    // It ends: its last line, then its result, and the stream closes.
    let mut row = hub.db.job(&id).unwrap().unwrap();
    row.state = JobState::Finished;
    row.revision += 1;
    row.finished_at = Some(crate::now_secs());
    row.result = Some(JobResult {
        failure: None,
        exit_code: Some(0),
        message: None,
        output_len: row.output_len,
        artifacts: Vec::new(),
        usage: None,
        events: Vec::new(),
        egress: None,
    });
    hub.db.put_job(&id, &row, &[], crate::now_secs()).unwrap();
    hub.job_changed(&id);
    assert_eq!(
        stream.next().await.unwrap(),
        format!("event: output\ndata: {time}last{end}\ndata: \n\n")
    );
    assert_eq!(stream.next().await.unwrap(), "event: held\ndata: \n\n");
    let record = stream.next().await.unwrap();
    assert!(
        record.contains("<span class=\"badge ok\">success</span>"),
        "{record}"
    );
    // The duration stops advancing when the job ends.
    assert!(!record.contains("data-since"), "{record}");
    assert_eq!(
        stream.next().await.as_deref(),
        Some("event: close\ndata: \n\n")
    );
    assert_eq!(stream.next().await, None);
    // Its page now shows it all, followed no more.
    let page = get(addr, &format!("/jobs/{id}"), Some(&viewer)).await.body;
    assert!(!page.contains("sse-connect"), "{page}");
    assert!(
        page.contains(&format!("{time}déjà ✓{end}\n{time}last{end}\n</span>")),
        "{page}"
    );
}

/// A job's stream opened once its output went sends its record alone and closes, the page
/// keeping what it was served; one following it when it goes ends the lines it holds first.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_s_stream_ends_once_its_output_went() {
    let scratch = Scratch::new("settled");
    let dir = &scratch.0;
    let (addr, hub) = start_fleet_placing(dir).await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let time = "<span class=\"l\"><time title=\"2026-10-09T12:10:43.123456Z\">12:10:43</time> \
                <span class=\"t\">";
    let end = "</span></span>";
    let settle = |id: &str| {
        let mut row = hub.db.job(id).unwrap().unwrap();
        row.settled_at = Some(crate::now_secs());
        row.revision += 1;
        assert!(hub.db.put_job(id, &row, &[], crate::now_secs()).unwrap());
        hub.job_changed(id);
    };
    let output = format!("{}line\n{}open", stamp(' '), stamp(' '));
    let id = running_with_output(&hub, dir, 1, output.as_bytes());
    let page = get(addr, &format!("/jobs/{id}"), Some(&viewer)).await.body;
    assert!(page.contains("sse-connect"), "{page}");
    settle(&id);
    let mut stream = Events::open(addr, &format!("/events/job/{id}"), &viewer).await;
    let record = stream.next().await.unwrap();
    assert!(
        record.starts_with("event: job\ndata: <section><h2>Job</h2>"),
        "{record}"
    );
    assert_eq!(
        stream.next().await.as_deref(),
        Some("event: close\ndata: \n\n")
    );
    assert_eq!(stream.next().await, None);

    let id = running_with_output(&hub, dir, 2, output.as_bytes());
    let mut stream = Events::open(addr, &format!("/events/job/{id}"), &viewer).await;
    let start = stream.next().await.unwrap();
    assert!(start.starts_with("event: output-start\n"), "{start}");
    assert_eq!(
        stream.next().await.unwrap(),
        format!("event: held\ndata: {time}line{end}\n\n")
    );
    assert!(stream.next().await.unwrap().starts_with("event: job\n"));
    settle(&id);
    assert_eq!(
        stream.next().await.unwrap(),
        format!("event: output\ndata: {time}line{end}\ndata: \n\n")
    );
    assert_eq!(stream.next().await.unwrap(), "event: held\ndata: \n\n");
    assert!(stream.next().await.unwrap().starts_with("event: job\n"));
    assert_eq!(
        stream.next().await.as_deref(),
        Some("event: close\ndata: \n\n")
    );
}

/// A job's page, and its stream's first step, show the end of a long output, saying how much
/// precedes it; a later step reads a bounded stretch, the rest at the next.
#[tokio::test(flavor = "multi_thread")]
async fn a_running_job_s_page_shows_a_bounded_stretch_of_its_output() {
    let scratch = Scratch::new("bounded");
    let dir = &scratch.0;
    let (addr, hub) = start_fleet_placing(dir).await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    // 100-byte lines, stamped as a node sends them and numbered: 1000 past the opening.
    let lines = |from: usize, to: usize| {
        (from..to)
            .map(|n| {
                let x = "x".repeat(54);
                format!("2026-10-09T12:10:43.123456Z 01O line {n:07} {x}\n")
            })
            .collect::<String>()
    };
    let opening = job_output::OPENING as usize;
    let id = running_with_output(&hub, dir, 1, lines(0, opening / 100 + 1000).as_bytes());
    let page = get(addr, &format!("/jobs/{id}"), Some(&viewer)).await.body;
    assert!(page.contains(" before this not shown</span>\n"), "{page}");
    assert!(!page.contains("line 0000000 "), "{page}");

    let mut stream = Events::open(addr, &format!("/events/job/{id}"), &viewer).await;
    let start = stream.next().await.unwrap();
    assert!(
        start.starts_with("event: output-start\n"),
        "{}",
        &start[..80]
    );
    assert!(start.contains(" before this not shown"));
    // Each line's stamp grows into its `<time>`: bounded all the same.
    assert!(start.len() < 2 * opening, "{}", start.len());
    // Its last line is held, as the next may continue it.
    let last = opening / 100 + 999;
    assert!(start.contains(&format!("line {:07} ", last - 1)));
    assert!(!start.contains(&format!("line {last:07} ")));
    let held = stream.next().await.unwrap();
    assert!(
        held.starts_with("event: held\ndata: <span class=\"l\"><time "),
        "{held}"
    );
    assert!(held.contains(&format!("line {last:07} ")), "{held}");
    // Several steps more: read a stretch at a time, in order.
    let step = job_output::STEP as usize;
    let count = 6 * step / 100;
    let more = lines(last + 1, last + 1 + count);
    more_output(&hub, dir, &id, more.as_bytes());
    let mut seen = Vec::new();
    while seen.last() != Some(&(last + count - 1)) {
        let event = stream.next().await.unwrap();
        if !event.starts_with("event: output\n") {
            continue;
        }
        assert!(event.len() < 2 * step, "{}", event.len());
        seen.extend(
            event
                .split("line ")
                .skip(1)
                .map(|l| l[..7].parse::<usize>().unwrap()),
        );
    }
    assert_eq!(seen, (last..last + count).collect::<Vec<_>>());
}

/// `/jobs`' newest page follows the jobs as they change, filtered as the page is; an older
/// page stays as loaded, and a stream with a filter the page would not take is refused.
#[tokio::test(flavor = "multi_thread")]
async fn the_newest_jobs_are_kept_live_in_their_filter() {
    use vk_hub_proto::client::JobState;
    use vk_hub_proto::job::{FailureClass, JobResult};
    let (addr, hub, origin) = start_fleet().await;
    let (viewer, csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let (operator, _) = sign_in(addr, &hub, Role::Operator).await;

    let page = get(addr, "/jobs", Some(&viewer)).await.body;
    assert!(
        page.contains(
            "<div id=\"jobs\" hx-ext=\"sse\" sse-connect=\"/events/jobs\" sse-swap=\"jobs\" \
             sse-close=\"close\"><p class=\"empty\">none placed yet"
        ),
        "{page}"
    );
    // The form stays outside the live fragment. With htmx, changes replace the filtered
    // results and live fragment and update the URL. The button or Enter applies immediately
    // and loads the page without htmx.
    let form = page
        .split("<form id=\"jobs-filter\" class=\"filter\"")
        .nth(1)
        .and_then(|rest| rest.split("</form>").next())
        .expect("the filter's form");
    for want in [
        " method=\"get\" action=\"/jobs\" hx-get=\"/jobs\"",
        " hx-trigger=\"submit, change from:(#jobs-filter select), \
         change from:(#jobs-filter input[type=checkbox]), \
         input changed delay:300ms from:(#jobs-filter input)\"",
        " hx-target=\"#jobs-results\" hx-select=\"#jobs-results\" hx-swap=\"outerHTML\"",
        " hx-push-url=\"true\" hx-sync=\"this:replace\"",
        "<input type=\"checkbox\" name=\"events\" value=\"1\"> With events</label> \
         <button>Show</button>",
    ] {
        assert!(form.contains(want), "{want}: {form}");
    }
    assert_eq!(form.matches("<button").count(), 1, "{form}");
    assert!(
        page.contains("</form><div id=\"jobs-results\"><div id=\"jobs\" hx-ext=\"sse\""),
        "{page}"
    );
    // Going back loads the page its URL names, rather than a copy whose form is stale.
    assert!(
        page.contains("\"historyCacheSize\":0,\"refreshOnHistoryMiss\":true"),
        "{page}"
    );
    let page = get(
        addr,
        "/jobs?project=acme%2Fweb&result=failed",
        Some(&viewer),
    )
    .await
    .body;
    assert!(
        page.contains("sse-connect=\"/events/jobs?project=acme%2Fweb&amp;result=failed\""),
        "{page}"
    );
    // An older page has no stream, and says where the live one is.
    let page = get(addr, "/jobs?result=failed&before=9", Some(&viewer))
        .await
        .body;
    assert!(!page.contains("sse-connect"), "{page}");
    assert!(
        page.contains(
            "<div id=\"jobs-results\"><p class=\"sub\">Older jobs, as they stood when this page \
             was loaded; <a href=\"/jobs?result=failed\">the newest</a>"
        ),
        "{page}"
    );
    for bad in [
        "?result=lost",
        "?node=zz",
        "?before=9",
        "?result=failed&result=success",
    ] {
        let reply = get(addr, &format!("/events/jobs{bad}"), Some(&viewer)).await;
        assert_eq!(reply.status, 404, "{bad}");
    }

    let mut all = live(addr, "/events/jobs", &viewer).await;
    let mut failed = Events::open(
        addr,
        "/events/jobs?project=acme%2Fweb&result=failed",
        &operator,
    )
    .await;
    let first = failed.next().await.unwrap();
    assert_eq!(
        first,
        "event: jobs\ndata: <p class=\"empty\" role=\"status\">none match</p>\
         <span id=\"nav-count-egress\" hx-swap-oob=\"true\"></span>\
         <span id=\"nav-count-clients\" hx-swap-oob=\"true\"></span>\n\n"
    );

    // A job submitted after the page opened.
    let now = crate::now_secs();
    let id = |n: u64| format!("{n:032x}");
    let submit = |n: u64, row: &crate::store::JobRow| {
        hub.db
            .submit_job(&id(n), row, &n.to_string(), b"{}", "key gitlab", now)
            .unwrap();
        hub.jobs_changed();
    };
    submit(1, &history_job(1, "acme/web"));
    let next = next_with(&mut all, "build-1").await;
    assert!(
        next.starts_with("event: jobs\ndata: <p class=\"sub\" role=\"status\">1 job</p>"),
        "{next}"
    );
    assert!(
        next.contains("<span class=\"badge\">queued</span>"),
        "{next}"
    );

    // It fails, and another is submitted: the filtered stream shows the one it matches.
    let mut ended = history_job(1, "acme/web");
    ended.state = JobState::Finished;
    ended.revision = 2;
    ended.started_at = Some(now - 5);
    ended.finished_at = Some(now);
    ended.result = Some(JobResult {
        failure: Some(FailureClass::Script),
        exit_code: Some(1),
        message: None,
        output_len: 0,
        artifacts: Vec::new(),
        usage: None,
        events: Vec::new(),
        egress: None,
    });
    hub.db.put_job(&id(1), &ended, &[], now).unwrap();
    submit(2, &history_job(2, "acme/web"));
    let next = failed.next().await.unwrap();
    assert!(
        next.contains("1 job · median run of finished jobs 5s"),
        "{next}"
    );
    assert!(
        next.contains(">build-1<") && !next.contains(">build-2<"),
        "{next}"
    );
    assert!(next.contains("script failure, exit 1</span>"), "{next}");
    let next = next_with(&mut all, "build-2").await;
    assert!(
        next.contains("2 jobs · 0% of 1 finished succeeded"),
        "{next}"
    );
    assert!(next.contains("badge bad"), "{next}");

    // Signed out, a jobs stream ends as any other does.
    let reply = request(
        addr,
        "POST",
        "/logout",
        &[&format!("Cookie: {viewer}"), &format!("Origin: {origin}")],
        &format!("_csrf={csrf}"),
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_signed_out(&mut all).await;
    let again = get(addr, "/events/jobs?result=failed", Some(&viewer)).await;
    assert!(
        again.body.starts_with("event: jobs\ndata: "),
        "{}",
        again.body
    );
    assert!(
        again.body.ends_with("\n\nevent: close\ndata: \n\n"),
        "{}",
        again.body
    );
}

/// Node `hostname` enrolled straight into the database under `key` repeated 16 times, so
/// the hub's enrollment handler does not run and the caller touches it ([`Hub::touch`]).
fn enrolled_as(hub: &Hub, hostname: &str, key: &str) -> String {
    let (token, _) = hub
        .db
        .create_token(Duration::from_secs(60), "uid 0", crate::now_secs())
        .unwrap();
    let crate::store::Enrollment::Enrolled { node_id } = hub
        .db
        .enroll(&token, &key.repeat(16), hostname, "peer p", 1)
        .unwrap()
    else {
        panic!("expected an enrollment");
    };
    node_id
}

/// The ID of the rollout form in `html`.
fn rollout_form_id(html: &str) -> String {
    let at = html.find("<form id=\"rollout-").expect(html);
    html[at..at + 34].to_string()
}

/// An operator's stream sends the form that starts a rollout beside the fragment, without the
/// session's token, under an ID that changes with what it offers alone, and again only once
/// that changes: a node enrolled, a release added, not a rollout steered. Its live copy posts
/// with the token the page sets as a header around it.
#[tokio::test(flavor = "multi_thread")]
async fn the_rollout_form_follows_what_it_offers() {
    let (addr, hub, origin) = start_fleet().await;
    let rollout = rollout_of(&hub, "ci-1");
    let node = hub.db.nodes().unwrap()[0].0.clone();
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;

    let page = get(addr, "/operations", Some(&operator)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let form = rollout_form_id(&page.body);
    // The section and the fragment are inside the element setting the header.
    let at = |what: &str| page.body.find(what).expect(what);
    assert!(at("hx-headers=") < at("<section id=\"start-rollout\" sse-swap=\"start-rollout\">"));
    assert!(at("id=\"start-rollout\"") < at("<div id=\"operations\" sse-swap=\"operations\">"));
    assert!(
        page.body.ends_with("</div></div></main></body></html>"),
        "{}",
        page.body
    );
    let section = page.body.split("id=\"start-rollout\"").nth(1).unwrap();
    assert!(section.contains(&format!("value=\"{csrf}\"")), "{section}");
    assert!(section.contains("hx-preserve=\"true\""), "{section}");
    assert!(!section.contains("name=\"select\""), "{section}");

    let mut live = Events::open(addr, "/events/operations", &operator).await;
    let first = live.next().await.unwrap();
    assert!(first.starts_with("event: operations\ndata: "), "{first}");
    let offered = live.next().await.unwrap();
    assert!(
        offered.starts_with("event: start-rollout\ndata: <h2>Start a rollout</h2>"),
        "{offered}"
    );
    assert_eq!(rollout_form_id(&offered), form, "{offered}");
    assert!(!offered.contains(&csrf), "{offered}");

    // Posted as the live copy is, with the header's token and no field.
    let reply = request(
        addr,
        "POST",
        operations::ROLLOUT_PATH,
        &[
            &format!("Cookie: {operator}"),
            &format!("Origin: {origin}"),
            &format!("X-CSRF-Token: {csrf}"),
            "HX-Request: true",
            "Content-Type: application/x-www-form-urlencoded",
        ],
        &format!(
            "op=create&release={}&node={node}&batch=1&max_failures=0&node_timeout=30m&\
             drain_timeout=4h",
            "ab".repeat(32)
        ),
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("Start this rollout?"), "{}", reply.body);

    // A rollout steered changes the fragment, not the form: it is not sent again.
    crate::ops::steer_rollout(
        &hub,
        "uid 0",
        &rollout,
        crate::rollout::RolloutAction::Pause,
    )
    .unwrap();
    let mut seen = events_until(&mut live, ">paused<").await;
    crate::ops::steer_rollout(
        &hub,
        "uid 0",
        &rollout,
        crate::rollout::RolloutAction::Resume,
    )
    .unwrap();
    seen.extend(events_until(&mut live, ">running<").await);
    assert!(
        seen.iter().all(|e| e.starts_with("event: operations\n")),
        "{seen:?}"
    );
    // A stream of its own still starts with the form: what one stream left out is per stream.
    let mut other = Events::open(addr, "/events/operations", &operator).await;
    let again = next_with(&mut other, "event: start-rollout\n").await;
    assert_eq!(rollout_form_id(&again), form, "{again}");
    drop(other);

    // A node enrolled is offered, in a form of another ID.
    let added = enrolled_as(&hub, "ci-3", "cd");
    hub.touch();
    let next = next_with(&mut live, &format!("value=\"{added}\" checked> ci-3")).await;
    assert!(next.starts_with("event: start-rollout\n"), "{next}");
    let enrolled = rollout_form_id(&next);
    assert_ne!(enrolled, form, "{next}");

    // As is a release added.
    let release = crate::store::ReleaseRow {
        version: "0.87.0".into(),
        size: 3 << 20,
        signature: None,
        program: None,
        added_at: 2,
        added_by: "uid 0".into(),
    };
    hub.db
        .add_release(&"12".repeat(32), &release, "uid 0")
        .unwrap();
    hub.touch();
    let next = next_with(&mut live, ">vk 0.87.0 (").await;
    assert!(next.starts_with("event: start-rollout\n"), "{next}");
    assert_ne!(rollout_form_id(&next), enrolled, "{next}");
}

/// The live rollout section says what a rollout lacks, a vk release then a node, and offers
/// the form once there is both.
#[tokio::test(flavor = "multi_thread")]
async fn the_rollout_section_says_live_what_a_rollout_lacks() {
    let (addr, hub, _) = start_fleet().await;
    let (operator, _) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/operations", Some(&operator)).await;
    let section = page.body.split("id=\"start-rollout\"").nth(1).unwrap();
    assert!(section.contains("Add a vk release first."), "{section}");

    let mut live = Events::open(addr, "/events/operations", &operator).await;
    let first = next_with(&mut live, "event: start-rollout\n").await;
    assert!(first.contains("Add a vk release first."), "{first}");

    let release = crate::store::ReleaseRow {
        version: "0.85.0".into(),
        size: 3 << 20,
        signature: None,
        program: None,
        added_at: 1,
        added_by: "uid 0".into(),
    };
    hub.db
        .add_release(&"ab".repeat(32), &release, "uid 0")
        .unwrap();
    hub.touch();
    let next = next_with(&mut live, "No node has enrolled yet.").await;
    assert!(next.starts_with("event: start-rollout\n"), "{next}");

    let node = enrolled_as(&hub, "ci-1", "ab");
    hub.touch();
    let next = next_with(&mut live, "<form id=\"rollout-").await;
    assert!(next.starts_with("event: start-rollout\n"), "{next}");
    assert!(
        next.contains(&format!("value=\"{node}\" checked> ci-1")),
        "{next}"
    );
}

/// An operator's `/operations` pauses, resumes and aborts a rollout as the session's
/// principal, which the audit log records, and its live fragment follows; a change the
/// rollout's state does not allow is refused saying why.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_steers_a_rollout_from_operations() {
    use crate::rollout::RolloutState;
    let (addr, hub, origin) = start_fleet().await;
    let id = rollout_of(&hub, "ci-1");
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    let path = format!("/rollout/{id}/action");

    let page = get(addr, "/operations", Some(&operator)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for want in [
        &format!("action=\"{path}\" hx-post=\"{path}\""),
        "<button>Pause</button>",
        "<button>Abort</button>",
        &format!("X-CSRF-Token&quot;:&quot;{csrf}&quot;"),
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    // The fragment, shared by every operator's page, carries no session's token.
    let fragment = page.body.split("id=\"operations\"").nth(1).unwrap();
    assert!(!fragment.contains(&csrf), "{fragment}");

    let mut live = Events::open(addr, "/events/operations", &operator).await;
    let first = live.next().await.unwrap();
    assert!(first.contains("hx-post"), "{first}");

    let steer = |form: &str, htmx: bool| {
        let (operator, origin, path) = (operator.clone(), origin.clone(), path.clone());
        let form = form.to_string();
        async move {
            let headers = [
                format!("Cookie: {operator}"),
                format!("Origin: {origin}"),
                "Content-Type: application/x-www-form-urlencoded".into(),
                "HX-Request: true".into(),
            ];
            let n = if htmx { 4 } else { 3 };
            let headers: Vec<&str> = headers[..n].iter().map(String::as_str).collect();
            request(addr, "POST", &path, &headers, &form).await
        }
    };
    let state = || hub.db.resolve_rollout(&id).unwrap().1.state;

    let reply = steer(&format!("_csrf={csrf}&op=pause"), true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    assert!(
        reply
            .body
            .contains(&format!("Rollout {} is paused.", &id[..8])),
        "{}",
        reply.body
    );
    assert!(matches!(state(), RolloutState::Paused { .. }));
    let paused = next_with(&mut live, ">paused<").await;
    assert!(paused.contains("<button>Resume</button>"), "{paused}");

    // Pausing a paused rollout is the operation's refusal, said to the operator.
    let reply = steer(&format!("_csrf={csrf}&op=pause"), true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply.body.contains("is paused; it cannot be paused"),
        "{}",
        reply.body
    );
    let reply = steer(&format!("_csrf={csrf}&op=wipe"), true).await;
    assert_eq!(reply.status, 400, "{}", reply.body);

    // The CSRF token as the header the page sets, and a plain form back to the page.
    let reply = request(
        addr,
        "POST",
        &path,
        &[
            &format!("Cookie: {operator}"),
            &format!("Origin: {origin}"),
            &format!("X-CSRF-Token: {csrf}"),
            "HX-Request: true",
            "Content-Type: application/x-www-form-urlencoded",
        ],
        "op=resume",
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(state(), RolloutState::Running);
    let reply = steer(&format!("_csrf={csrf}&op=abort"), false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/operations"));
    assert!(matches!(state(), RolloutState::Aborted { .. }));
    let aborted = next_with(&mut live, ">aborted<").await;
    // Its nodes were refused or never started: deleting it is all that is left.
    for gone in ["Pause", "Resume", "Abort"] {
        assert!(
            !aborted.contains(&format!("<button>{gone}</button>")),
            "{aborted}"
        );
    }

    let audit: Vec<String> = hub
        .db
        .audits(None, 100)
        .unwrap()
        .into_iter()
        .filter(|r| r.actor == principal)
        .map(|r| r.event)
        .collect();
    let short = &id[..8];
    for want in ["paused", "resumed", "aborted"] {
        let line = format!("{principal} {want} rollout {short}");
        assert!(audit.contains(&line), "{line}: {audit:?}");
    }
}

/// An ended rollout that updated no node carries a "Delete" button, which deletes it once
/// confirmed, as the session's principal, and the live page drops it; one running or paused,
/// one whose update is under way, and one whose update may have run have none, and the handler
/// refuses them too.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_deletes_an_ended_rollout_that_updated_no_node() {
    use crate::rollout::{NodeStatus, RolloutAction, RolloutState};
    let (addr, hub, origin) = start_fleet().await;
    let id = rollout_of(&hub, "ci-1");
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    let path = |id: &str| format!("/rollout/{id}/action");
    let delete = format!("_csrf={csrf}&op=delete");
    let button = "<button>Delete</button>";
    let heading = |id: &str| format!("<h3><code>{}</code>", &id[..8]);

    // Running or paused: no button, and the handler says why.
    for (state, action) in [("running", None), ("paused", Some(RolloutAction::Pause))] {
        if let Some(action) = action {
            hub.db
                .steer_rollout(&id, action, "uid 0", crate::now_secs())
                .unwrap();
        }
        let page = get(addr, "/operations", Some(&operator)).await;
        assert!(!page.body.contains(button), "{}", page.body);
        let reply = post_action(addr, &origin, &operator, &path(&id), &delete, true).await;
        assert_eq!(reply.status, 409, "{}", reply.body);
        assert!(
            reply
                .body
                .contains(&format!("Refused: rollout {} is {state}; ", &id[..8])),
            "{}",
            reply.body
        );
    }

    hub.db
        .steer_rollout(&id, RolloutAction::Abort, "uid 0", crate::now_secs())
        .unwrap();
    let page = get(addr, "/operations", Some(&operator)).await;
    assert!(page.body.contains(button), "{}", page.body);
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/operations", Some(&viewer)).await;
    assert!(!page.body.contains(button), "{}", page.body);
    let form = format!("_csrf={viewer_csrf}&op=delete");
    let reply = post_action(addr, &origin, &viewer, &path(&id), &form, true).await;
    assert_eq!(reply.status, 403, "{}", reply.body);

    let mut live = Events::open(addr, "/events/operations", &operator).await;
    let first = live.next().await.unwrap();
    assert!(first.contains(&heading(&id)), "{first}");
    let reply = post_action(addr, &origin, &operator, &path(&id), &delete, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    for want in [
        "Delete this rollout?",
        &format!("Rollout <code>{}</code> of vk 0.85.0, aborted.", &id[..8]),
        "name=\"confirm\" value=\"yes\"",
    ] {
        assert!(reply.body.contains(want), "{want}: {}", reply.body);
    }
    assert!(hub.db.rollout(&id).unwrap().is_some());
    let answer = format!(
        "{delete}&nonce={}&confirm=yes",
        hidden(&reply.body, "nonce")
    );
    let reply = post_action(addr, &origin, &operator, &path(&id), &answer, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply
            .body
            .contains(&format!("Deleted rollout {} of vk 0.85.0.", &id[..8])),
        "{}",
        reply.body
    );
    assert!(hub.db.rollout(&id).unwrap().is_none());
    let gone = next_with(&mut live, "none yet").await;
    assert!(!gone.contains(&heading(&id)), "{gone}");
    let page = get(addr, "/operations", Some(&operator)).await;
    assert!(!page.body.contains(&heading(&id)), "{}", page.body);
    let line = format!("{principal} deleted rollout {} of vk 0.85.0", &id[..8]);
    let audit: Vec<String> = hub
        .db
        .audits(None, 100)
        .unwrap()
        .into_iter()
        .map(|r| r.event)
        .collect();
    assert!(audit.contains(&line), "{line}: {audit:?}");
    // Answered once: the same answer again finds no rollout.
    let reply = post_action(addr, &origin, &operator, &path(&id), &answer, true).await;
    assert_eq!(reply.status, 404, "{}", reply.body);

    let ended = |state, status| crate::rollout::RolloutRow {
        release: "ab".repeat(32),
        version: "0.85.0".into(),
        created_at: 1,
        created_by: "uid 0".into(),
        batch: 1,
        canary_per_profile: false,
        max_failures: 0,
        node_timeout_secs: 600,
        drain_timeout_secs: 600,
        force: false,
        state,
        failures: 0,
        nodes: vec![crate::rollout::RolloutNode {
            id: "12".repeat(16),
            hostname: "ci-2".into(),
            profile: "p".into(),
            wave: 0,
            status,
        }],
    };
    let aborted = || RolloutState::Aborted {
        reason: "aborted by uid 0".into(),
    };
    let failed = |reason: &str, ran| NodeStatus::Failed {
        reason: reason.into(),
        at: 2,
        ran,
    };
    let updating = NodeStatus::Updating {
        command: "c".into(),
        since: 1,
        resume: vk_hub_proto::NodeState::Ready,
        drained_at: None,
    };
    let ran = "an update it issued may have run, so only `vk-hub rollout delete` deletes it";
    let kept = [
        (
            aborted(),
            updating,
            "is aborted; an update it issued is still under way",
        ),
        (
            aborted(),
            failed("quarantined during its update", true),
            ran,
        ),
        (aborted(), failed("still draining after 10m", true), ran),
        (RolloutState::Done, NodeStatus::Succeeded { at: 2 }, ran),
    ];
    for (n, (state, status, why)) in kept.into_iter().enumerate() {
        let kept = format!("a{n}").repeat(16);
        hub.db
            .create_rollout(&kept, &ended(state, status), "uid 0")
            .unwrap();
        let page = get(addr, "/operations", Some(&operator)).await;
        assert!(page.body.contains(&heading(&kept)), "{}", page.body);
        assert!(!page.body.contains(&path(&kept)), "{}", page.body);
        let reply = post_action(addr, &origin, &operator, &path(&kept), &delete, true).await;
        assert_eq!(reply.status, 409, "{}", reply.body);
        let refused = format!("Refused: rollout {} ", &kept[..8]);
        assert!(reply.body.contains(&refused), "{}", reply.body);
        assert!(reply.body.contains(why), "{why}: {}", reply.body);
        assert!(hub.db.rollout(&kept).unwrap().is_some());
    }

    // Its only failure never ran: the operator may delete it.
    let expired = "b0".repeat(16);
    let row = ended(aborted(), failed("the update expired before it ran", false));
    hub.db.create_rollout(&expired, &row, "uid 0").unwrap();
    let page = get(addr, "/operations", Some(&operator)).await;
    assert!(page.body.contains(&path(&expired)), "{}", page.body);
    let reply = post_action(addr, &origin, &operator, &path(&expired), &delete, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Delete this rollout?"),
        "{}",
        reply.body
    );
    let answer = format!(
        "{delete}&nonce={}&confirm=yes",
        hidden(&reply.body, "nonce")
    );
    let reply = post_action(addr, &origin, &operator, &path(&expired), &answer, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Deleted rollout b0b0b0b0"),
        "{}",
        reply.body
    );
    assert!(hub.db.rollout(&expired).unwrap().is_none());

    // Deleted by someone else between the question and its answer.
    let raced = "c0".repeat(16);
    hub.db.create_rollout(&raced, &row, "uid 0").unwrap();
    let reply = post_action(addr, &origin, &operator, &path(&raced), &delete, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let answer = format!(
        "{delete}&nonce={}&confirm=yes",
        hidden(&reply.body, "nonce")
    );
    let deleted =
        crate::ops::delete_rollout(&hub, "uid 0", &raced, crate::rollout::DeleteRule::Ended)
            .unwrap();
    assert!(deleted.is_some());
    let reply = post_action(addr, &origin, &operator, &path(&raced), &answer, true).await;
    assert_eq!(reply.status, 404, "{}", reply.body);
    assert!(reply.body.contains("no such rollout"), "{}", reply.body);
}

/// A viewer's post, an operator's without the session's CSRF token or from another origin,
/// and one for no rollout are refused, and change nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_rollout_is_steered_only_by_an_operator_s_own_page() {
    let (addr, hub, origin) = start_fleet().await;
    let id = rollout_of(&hub, "ci-1");
    let path = format!("/rollout/{id}/action");
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let audit_before = hub.db.audits(None, 100).unwrap();

    let form = format!("_csrf={viewer_csrf}&op=pause");
    let reply = post_action(addr, &origin, &viewer, &path, &form, true).await;
    assert_eq!(reply.status, 403);
    assert!(reply.body.contains("operator role"), "{}", reply.body);
    let reply = post_action(addr, &origin, &operator, &path, "op=pause", true).await;
    assert_eq!(reply.status, 403);
    assert!(reply.body.contains("CSRF"), "{}", reply.body);
    let form = format!("_csrf={csrf}&op=pause");
    let reply = post_action(addr, "http://evil.example", &operator, &path, &form, false).await;
    assert_eq!(reply.status, 403);
    assert!(reply.body.contains("did not come from"), "{}", reply.body);

    // A well-formed ID of no rollout, and one that is no ID at all.
    let none = format!("/rollout/{}/action", "0".repeat(32));
    let reply = post_action(addr, &origin, &operator, &none, &form, true).await;
    assert_eq!(reply.status, 404, "{}", reply.body);
    assert!(reply.body.contains("no such rollout"), "{}", reply.body);
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/rollout/nothex/action",
        &form,
        true,
    )
    .await;
    assert_eq!(reply.status, 404, "{}", reply.body);

    let (_, row) = hub.db.resolve_rollout(&id).unwrap();
    assert_eq!(row.state, crate::rollout::RolloutState::Running);
    assert_eq!(hub.db.audits(None, 100).unwrap(), audit_before);
}

/// The nodes table says a node is updating and how far it has got, and that its last update
/// was rolled back; the node's page shows the update, with what the node said of it as text,
/// and the sha256 of the vk it runs.
#[tokio::test(flavor = "multi_thread")]
async fn a_node_s_update_is_shown_on_the_nodes_table_and_its_page() {
    use vk_hub_proto::{NodeState, Report, UpdatePhase, UpdateProgress};
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    hub.db
        .record_inventory(
            &node,
            vk_hub_proto::Inventory {
                hostname: "ci-1".into(),
                versions: vk_hub_proto::Versions {
                    vk: "0.84.0".into(),
                    vk_sha256: Some("12".repeat(32)),
                    ..Default::default()
                },
                ..Default::default()
            },
            true,
            2,
        )
        .unwrap();
    let report = |phase, message: Option<&str>| Report {
        state: Some(NodeState::Maintenance),
        update: Some(UpdateProgress {
            command: "c1".repeat(16),
            version: "0.85<b>".into(),
            sha256: "ab".repeat(32),
            phase,
            message: message.map(str::to_string),
        }),
        ..Report::default()
    };
    hub.db
        .record_report(
            &node,
            report(UpdatePhase::Validating, None),
            crate::now_secs(),
        )
        .unwrap();
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let mut nodes = Events::open(addr, "/events/nodes", &cookie).await;
    let first = nodes.next().await.unwrap();
    assert!(
        first.contains(
            "<td><span class=\"badge busy\">maintenance, updating to 0.85&lt;b&gt;: validating\
             </span></td>",
        ),
        "{first}"
    );
    let page = get(addr, &format!("/node/{node}"), Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for want in [
        "<tr><th>Update</th><td>vk 0.85&lt;b&gt; (<code>abababababab</code>): validating</td>",
        &format!("<tr><th>vk sha256</th><td>{}</td></tr>", "12".repeat(32)),
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    assert!(!page.body.contains("<b>"), "{}", page.body);

    hub.db
        .record_report(
            &node,
            report(UpdatePhase::RolledBack, Some("vk check: <i>failed</i>")),
            crate::now_secs(),
        )
        .unwrap();
    hub.changed(&node);
    next_with(
        &mut nodes,
        "maintenance, update to 0.85&lt;b&gt; rolled back",
    )
    .await;
    let page = get(addr, &format!("/node/{node}"), Some(&cookie)).await;
    assert!(
        page.body
            .contains("rolled back: vk check: &lt;i&gt;failed&lt;/i&gt;</td>"),
        "{}",
        page.body
    );
}

/// A fleet hub's UI reached over https, signing people in through a fake OIDC provider that
/// says `claims` of whoever signs in, with `grants` of roles by address (or `*`).
async fn start_oidc(claims: serde_json::Value, grants: &[(&str, Role)]) -> (SocketAddr, Arc<Hub>) {
    start_oidc_with(claims, grants, None).await
}

/// [`start_oidc`], with `default_role` as the `[oidc]` table's.
async fn start_oidc_with(
    claims: serde_json::Value,
    grants: &[(&str, Role)],
    default_role: Option<Role>,
) -> (SocketAddr, Arc<Hub>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let idp = vk_oidc::fake_idp::start(vk_oidc::fake_idp::Options {
        claims,
        ..Default::default()
    })
    .await;
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("https://{addr}");
    let mut db = Db::open_memory().unwrap();
    if let Some(role) = default_role {
        db = db.with_oidc_default_role(role);
    }
    for (email, role) in grants {
        db.grant_account(email, *role, "uid 0", 1).unwrap();
    }
    let hub = Arc::new(Hub::new(Arc::new(db), Some(origin.clone())).with_oidc());
    let oidc = OidcSignIn::new(
        &origin,
        format!("http://{idp}"),
        vk_oidc::fake_idp::CLIENT_ID.into(),
        vk_oidc::fake_idp::CLIENT_SECRET.into(),
    );
    let ui = Ui::new(hub.clone(), &origin).with_oidc(oidc);
    tokio::spawn(serve(listener, None, Arc::new(ui)));
    (addr, hub)
}

impl Reply {
    fn set_cookies(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// Start a sign-in at the provider as a browser does: the login cookie it is given.
async fn start_oidc_login(addr: SocketAddr) -> (String, String) {
    let reply = request(
        addr,
        "GET",
        "/auth/login",
        &["Sec-Fetch-Site: same-origin"],
        "",
    )
    .await;
    assert_eq!(reply.status, 302, "{}", reply.body);
    let location = reply.header("location").unwrap();
    assert!(location.contains("/authorize?"), "{location}");
    let redirect = format!(
        "redirect_uri=https%3A%2F%2F127.0.0.1%3A{}%2Fauth%2Fcallback&",
        addr.port()
    );
    assert!(location.contains(&redirect), "{location}");
    let set = reply.header("set-cookie").unwrap();
    assert!(set.starts_with("__Host-vk-hub-login="), "{set}");
    assert!(set.contains("SameSite=Lax"), "{set}");
    let pair = set.split(';').next().unwrap().to_string();
    let state = pair.split_once('=').unwrap().1.to_string();
    (pair, state)
}

/// The provider's redirect back, as the browser follows it: from the provider's page.
async fn oidc_callback(addr: SocketAddr, state: &str, cookie: Option<&str>) -> Reply {
    let path = format!("/auth/callback?code=the-code&state={state}");
    let mut headers = vec!["Sec-Fetch-Site: cross-site".to_string()];
    if let Some(c) = cookie {
        headers.push(format!("Cookie: {c}"));
    }
    let headers: Vec<&str> = headers.iter().map(String::as_str).collect();
    request(addr, "GET", &path, &headers, "").await
}

/// The OIDC sign-in end to end: the signed-out page offers it, the provider's callback opens
/// a session named after who signed in, in the role granted them, audited; the login cookie
/// is spent either way.
#[tokio::test(flavor = "multi_thread")]
async fn an_oidc_sign_in_opens_a_session_for_whom_a_grant_lets_in() {
    let (addr, hub) = start_oidc(
        serde_json::json!({"sub": "user-42", "email": "Alice@Example.com", "email_verified": true}),
        &[("alice@example.com", Role::Operator)],
    )
    .await;
    let reply = get(addr, "/", None).await;
    assert_eq!(reply.status, 401);
    assert!(
        reply.body.contains("Sign in with 127.0.0.1:"),
        "{}",
        reply.body
    );
    let page = get(addr, "/login", None).await;
    assert_eq!(page.status, 200);
    assert!(
        page.body
            .contains("<a class=\"button\" href=\"/auth/login\">")
            && !page.body.contains("<form"),
        "{}",
        page.body
    );

    let (login, state) = start_oidc_login(addr).await;
    let reply = oidc_callback(addr, &state, Some(&login)).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("url=/"), "{}", reply.body);
    let cookies = reply.set_cookies();
    assert_eq!(cookies.len(), 2, "{cookies:?}");
    let session = cookies
        .iter()
        .find(|c| c.starts_with(&format!("{SECURE_COOKIE}=")))
        .unwrap();
    assert!(session.contains("SameSite=Strict"), "{session}");
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("__Host-vk-hub-login=;") && c.ends_with("Max-Age=0")),
        "{cookies:?}"
    );
    let pair = session.split(';').next().unwrap();
    let home = request(
        addr,
        "GET",
        "/",
        &["Sec-Fetch-Site: same-origin", &format!("Cookie: {pair}")],
        "",
    )
    .await;
    assert_eq!(home.status, 200, "{}", home.body);
    assert!(
        home.body.contains("(operator, alice@example.com)"),
        "{}",
        home.body
    );

    let sessions = hub.db.ui_sessions(crate::now_secs()).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].role, Role::Operator);
    assert_eq!(sessions[0].identity.as_deref(), Some("alice@example.com"));
    let audit = hub.db.audits(None, 10).unwrap();
    assert!(
        audit.iter().any(|r| r
            .event
            .contains("signed in as alice@example.com through http://")),
        "{audit:?}"
    );

    // The state is spent: the same callback again opens nothing.
    let again = oidc_callback(addr, &state, Some(&login)).await;
    assert_eq!(again.status, 400, "{}", again.body);
    assert_eq!(hub.db.ui_sessions(crate::now_secs()).unwrap().len(), 1);
}

/// Deny by default: an identity granted nothing is refused with a page saying who signed in,
/// and the refusal is audited with its reason. An unverified email is no email: it matches no
/// grant. Nor is an `email` that is not an address: who signed in is named by their subject.
#[tokio::test(flavor = "multi_thread")]
async fn an_oidc_sign_in_granted_nothing_is_refused_and_audited() {
    for (claims, identity, why) in [
        (
            serde_json::json!({"sub": "user-7", "email": "mallory@example.com"}),
            "mallory@example.com",
            "granted no role",
        ),
        (
            serde_json::json!({"sub": "user-7", "email": "alice@example.com", "email_verified": false}),
            "sub user-7",
            "its email is marked unverified",
        ),
        (
            serde_json::json!({"sub": "s", "email": "sub x"}),
            "sub s",
            "granted no role",
        ),
    ] {
        let (addr, hub) = start_oidc(
            claims.clone(),
            &[
                ("alice@example.com", Role::Operator),
                ("bob@example.com", Role::Viewer),
            ],
        )
        .await;
        let (login, state) = start_oidc_login(addr).await;
        let reply = oidc_callback(addr, &state, Some(&login)).await;
        assert_eq!(reply.status, 403, "{claims}: {}", reply.body);
        assert!(
            reply.body.contains("may not use this hub"),
            "{}",
            reply.body
        );
        assert!(
            reply
                .set_cookies()
                .iter()
                .all(|c| !c.starts_with(&format!("{SECURE_COOKIE}="))),
            "no session cookie"
        );
        assert_eq!(
            reply.body.contains("marks your email unverified"),
            why.contains("unverified"),
            "{}",
            reply.body
        );
        assert!(hub.db.ui_sessions(crate::now_secs()).unwrap().is_empty());
        let audit = hub.db.audits(None, 10).unwrap();
        assert!(
            audit.iter().any(|r| r.actor == identity
                && r.event
                    .starts_with(&format!("{identity} was refused sign-in"))
                && r.event.ends_with(why)),
            "{claims}: {audit:?}"
        );
        // Refused again at once: the refusal is not audited a second time.
        let (login, state) = start_oidc_login(addr).await;
        let reply = oidc_callback(addr, &state, Some(&login)).await;
        assert_eq!(reply.status, 403, "{claims}: {}", reply.body);
        let refusals = hub.db.audits(None, 10).unwrap();
        let refusals = refusals
            .iter()
            .filter(|r| r.event.contains("was refused sign-in"))
            .count();
        assert_eq!(refusals, 1, "{claims}");
    }
}

/// An address's own grant is matched ignoring ASCII case, and wins over `*`'s.
#[tokio::test(flavor = "multi_thread")]
async fn an_oidc_sign_in_gets_its_own_grant_over_anyones() {
    let claims =
        serde_json::json!({"sub": "user-3", "email": "Carol@Example.com", "email_verified": true});
    for grants in [
        &[("carol@example.com", Role::Operator)][..],
        &[("carol@example.com", Role::Operator), ("*", Role::Viewer)][..],
    ] {
        let (addr, hub) = start_oidc(claims.clone(), grants).await;
        let (login, state) = start_oidc_login(addr).await;
        let reply = oidc_callback(addr, &state, Some(&login)).await;
        assert_eq!(reply.status, 200, "{}", reply.body);
        let sessions = hub.db.ui_sessions(crate::now_secs()).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].role, Role::Operator);
        assert_eq!(sessions[0].identity.as_deref(), Some("carol@example.com"));
    }
}

/// The default role lets whoever no grant names view, as `*` does; without it they are
/// refused.
#[tokio::test(flavor = "multi_thread")]
async fn the_default_role_lets_whoever_no_grant_names_view() {
    let claims = serde_json::json!({
        "sub": "user-5", "email": "eve<\"&>@example.com", "email_verified": true,
    });
    let grants = [("alice@example.com", Role::Operator)];
    for default_role in [None, Some(Role::Viewer)] {
        let (addr, hub) = start_oidc_with(claims.clone(), &grants, default_role).await;
        let (login, state) = start_oidc_login(addr).await;
        let reply = oidc_callback(addr, &state, Some(&login)).await;
        let sessions = hub.db.ui_sessions(crate::now_secs()).unwrap();
        if default_role.is_none() {
            assert_eq!(reply.status, 403, "{}", reply.body);
            assert!(sessions.is_empty());
            continue;
        }
        assert_eq!(reply.status, 200, "{}", reply.body);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].role, Role::Viewer);
        assert_eq!(
            sessions[0].identity.as_deref(),
            Some("eve<\"&>@example.com")
        );
        let audit = hub.db.audits(None, 10).unwrap();
        assert!(
            audit.iter().any(|r| r
                .event
                .contains("signed in as eve<\"&>@example.com through http://")),
            "{audit:?}"
        );
        // The top bar names who, escaped, with the full principal for the tooltip and label.
        let pair = reply
            .set_cookies()
            .into_iter()
            .find(|c| c.starts_with(&format!("{SECURE_COOKIE}=")))
            .unwrap()
            .split(';')
            .next()
            .unwrap();
        let home = request(
            addr,
            "GET",
            "/",
            &["Sec-Fetch-Site: same-origin", &format!("Cookie: {pair}")],
            "",
        )
        .await;
        assert_eq!(home.status, 200, "{}", home.body);
        let principal = format!(
            "ui session {} (viewer, eve&lt;&quot;&amp;&gt;@example.com)",
            sessions[0].id
        );
        let want = format!(
            "<span class=\"identity\" title=\"{principal}\" aria-label=\"{principal}\">\
             eve&lt;&quot;&amp;&gt;@example.com</span> <span class=\"badge\">viewer</span>"
        );
        assert!(home.body.contains(&want), "{want}: {}", home.body);
    }
}

/// A revoke ends the sessions its address opened, and the browser holding one is signed out.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_grant_ends_its_sessions() {
    let (addr, hub) = start_oidc(
        serde_json::json!({"sub": "user-3", "email": "carol@example.com"}),
        &[("carol@example.com", Role::Operator)],
    )
    .await;
    let (login, state) = start_oidc_login(addr).await;
    let reply = oidc_callback(addr, &state, Some(&login)).await;
    let session = reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{SECURE_COOKIE}=")))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let home = |cookie: String| async move {
        request(
            addr,
            "GET",
            "/",
            &["Sec-Fetch-Site: same-origin", &format!("Cookie: {cookie}")],
            "",
        )
        .await
        .status
    };
    assert_eq!(home(session.clone()).await, 200);
    let change = hub
        .db
        .revoke_account("carol@example.com", "uid 0", crate::now_secs())
        .unwrap();
    assert_eq!(change.ended, 1);
    assert_eq!(home(session).await, 401);
    // And the next sign-in is refused.
    let (login, state) = start_oidc_login(addr).await;
    assert_eq!(oidc_callback(addr, &state, Some(&login)).await.status, 403);
}

/// The `*` grant lets anyone the provider signs in view: one with no verified email is named
/// by their subject. Signing in again at once opens another session, not audited a second
/// time.
#[tokio::test(flavor = "multi_thread")]
async fn anyone_may_view_with_the_star_grant() {
    let (addr, hub) = start_oidc(
        serde_json::json!({"sub": "user-9", "email": "eve@example.com", "email_verified": "false"}),
        &[("alice@example.com", Role::Operator), ("*", Role::Viewer)],
    )
    .await;
    for _ in 0..2 {
        let (login, state) = start_oidc_login(addr).await;
        let reply = oidc_callback(addr, &state, Some(&login)).await;
        assert_eq!(reply.status, 200, "{}", reply.body);
    }
    let sessions = hub.db.ui_sessions(crate::now_secs()).unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].role, Role::Viewer);
    assert_eq!(sessions[0].identity.as_deref(), Some("sub user-9"));
    let audit = hub.db.audits(None, 10).unwrap();
    let sign_ins = audit
        .iter()
        .filter(|r| r.event.contains("signed in as sub user-9"))
        .count();
    assert_eq!(sign_ins, 1, "{audit:?}");
}

/// The login cookie is what binds the callback to the browser that started the sign-in: a
/// callback without it — a URL an attacker completed at the provider and handed over — opens
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_oidc_callback_this_browser_did_not_start_opens_nothing() {
    let (addr, hub) = start_oidc(
        serde_json::json!({"sub": "user-42", "email": "alice@example.com"}),
        &[("alice@example.com", Role::Operator)],
    )
    .await;
    let (_, state) = start_oidc_login(addr).await;
    let reply = oidc_callback(addr, &state, None).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    let reply = oidc_callback(addr, &state, Some("__Host-vk-hub-login=another")).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert!(hub.db.ui_sessions(crate::now_secs()).unwrap().is_empty());

    // A refusal at the provider ends the login, and says so.
    let reply = request(
        addr,
        "GET",
        "/auth/callback?error=access_denied&state=x",
        &["Sec-Fetch-Site: cross-site"],
        "",
    )
    .await;
    assert_eq!(reply.status, 400);
    assert!(reply.body.contains("did not complete"), "{}", reply.body);
}

/// Another site's page starts a sign-in only as a tab's own navigation, as a provider's
/// portal does; an image, a frame or a script's request is refused.
#[tokio::test(flavor = "multi_thread")]
async fn a_providers_portal_starts_an_oidc_sign_in_only_as_a_navigation() {
    let (addr, _hub) = start_oidc(
        serde_json::json!({"sub": "user-42", "email": "alice@example.com"}),
        &[("alice@example.com", Role::Operator)],
    )
    .await;
    for headers in [
        &["Sec-Fetch-Site: cross-site"][..],
        &[
            "Sec-Fetch-Site: cross-site",
            "Sec-Fetch-Mode: no-cors",
            "Sec-Fetch-Dest: image",
        ],
        &[
            "Sec-Fetch-Site: cross-site",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-Dest: iframe",
        ],
        &[
            "Sec-Fetch-Site: cross-site",
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-Dest: object",
        ],
        &[
            "Sec-Fetch-Site: same-site",
            "Sec-Fetch-Mode: cors",
            "Sec-Fetch-Dest: empty",
        ],
    ] {
        let reply = request(addr, "GET", "/auth/login", headers, "").await;
        assert_eq!(reply.status, 403, "{headers:?}");
        assert!(reply.header("set-cookie").is_none(), "{headers:?}");
    }
    for site in ["cross-site", "same-site"] {
        let site = format!("Sec-Fetch-Site: {site}");
        let headers = [
            site.as_str(),
            "Sec-Fetch-Mode: navigate",
            "Sec-Fetch-Dest: document",
        ];
        let reply = request(addr, "GET", "/auth/login", &headers, "").await;
        assert_eq!(reply.status, 302, "{site}: {}", reply.body);
        assert!(reply.header("location").unwrap().contains("/authorize?"));
        assert!(
            reply
                .header("set-cookie")
                .is_some_and(|c| c.contains("__Host-vk-hub-login")),
            "{site}"
        );
    }
}

/// Without `[oidc]`, neither address leads anywhere, and the pages say only how to get a link.
#[tokio::test(flavor = "multi_thread")]
async fn without_oidc_there_is_no_provider_to_sign_in_with() {
    let (addr, _, _) = start_fleet_as("https").await;
    assert_eq!(get(addr, "/auth/login", None).await.status, 404);
    assert_eq!(
        get(addr, "/auth/callback?code=a&state=b", None)
            .await
            .status,
        404
    );
    assert!(!get(addr, "/", None).await.body.contains("/auth/login"));
    assert_eq!(get(addr, "/login", None).await.status, 403);
}

/// Post `form` to `/users` from the UI's origin `https://<addr>`, by htmx.
async fn post_users(addr: SocketAddr, cookie: &str, form: &str) -> Reply {
    post_action(
        addr,
        &format!("https://{addr}"),
        cookie,
        users::PATH,
        form,
        true,
    )
    .await
}

/// Post `form`, which `/users` asks about first: the form that answers it, confirmed.
async fn ask_users(addr: SocketAddr, cookie: &str, csrf: &str, form: &str) -> String {
    let reply = post_users(addr, cookie, form).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("name=\"confirm\" value=\"yes\""),
        "{}",
        reply.body
    );
    assert!(reply.body.contains("<button class=\"danger\">Yes, "));
    let asked: String = ["op", "email", "role", "previous"]
        .into_iter()
        .filter(|f| reply.body.contains(&format!("name=\"{f}\"")))
        .map(|f| format!("&{f}={}", hidden(&reply.body, f)))
        .collect();
    format!(
        "_csrf={csrf}{asked}&nonce={}&confirm=yes",
        hidden(&reply.body, "nonce")
    )
}

/// The grants, as `(address, role, granted by)`.
fn grants(hub: &Hub) -> Vec<(String, Role, String)> {
    hub.db
        .accounts()
        .unwrap()
        .into_iter()
        .map(|(e, a)| (e, a.role, a.granted_by))
        .collect()
}

/// A session opened through the hub's fake provider, as the identity its claims name: its
/// cookie pair and CSRF token.
async fn oidc_session(addr: SocketAddr) -> (String, String) {
    let (login, state) = start_oidc_login(addr).await;
    let reply = oidc_callback(addr, &state, Some(&login)).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let pair = reply
        .set_cookies()
        .into_iter()
        .find(|c| c.starts_with(&format!("{SECURE_COOKIE}=")))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let csrf = csrf_token(pair.split_once('=').unwrap().1);
    (pair, csrf)
}

/// `/users` is an operator's: a viewer has no link to it, is refused the page with 403, and
/// cannot post to it.
#[tokio::test(flavor = "multi_thread")]
async fn the_users_page_is_for_operators_alone() {
    let (addr, hub) = start_oidc(serde_json::json!({"sub": "s"}), &[]).await;
    let (viewer, csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let home = get(addr, "/", Some(&viewer)).await;
    assert!(!home.body.contains("href=\"/users\""), "{}", home.body);
    let page = get(addr, "/users", Some(&viewer)).await;
    assert_eq!(page.status, 403, "{}", page.body);
    assert_secure(&page);
    assert!(
        page.body.contains("needs the operator role"),
        "{}",
        page.body
    );
    let form = format!("_csrf={csrf}&op=grant&email=eve@example.com&role=operator");
    assert_eq!(post_users(addr, &viewer, &form).await.status, 403);
    assert!(grants(&hub).is_empty());

    let (operator, _) = sign_in(addr, &hub, Role::Operator).await;
    let home = get(addr, "/", Some(&operator)).await;
    assert!(
        home.body.contains("<a href=\"/users\">Users</a>"),
        "{}",
        home.body
    );
    let page = get(addr, "/users", Some(&operator)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body
            .contains("<a href=\"/users\" aria-current=\"page\">Users</a>"),
        "{}",
        page.body
    );
}

/// An operator grants an address a role, raises it at once, and lowers and revokes it once
/// confirmed — each through the admin socket's operation, audited as the session's principal.
/// Every grant is listed with who made it, `*` as everyone the provider signs in, and the
/// page says what anyone else gets.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_grants_changes_and_revokes_from_the_users_page() {
    let (addr, hub) = start_oidc(
        serde_json::json!({"sub": "s"}),
        &[("alice@example.com", Role::Operator)],
    )
    .await;
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    let page = get(addr, "/users", Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for want in [
        "<td>alice@example.com</td><td><span class=\"badge busy\">operator</span></td>\
         <td>uid 0</td>",
        "Anyone else the provider signs in: <span class=\"badge bad\">refused</span>.",
        "<form class=\"wide\" method=\"post\" action=\"/users\" hx-post=\"/users\"",
        "<option value=\"operator\" selected>operator</option>",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }

    // A new grant, its address normalized: no question asked.
    let form = format!("_csrf={csrf}&op=grant&email=Bob%40Example.com&role=viewer");
    let reply = post_users(addr, &cookie, &form).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    assert!(
        reply.body.contains(
            "<div id=\"flash\" hx-swap-oob=\"true\">Granted bob@example.com the viewer role.</div>"
        ),
        "{}",
        reply.body
    );
    assert!(
        reply
            .body
            .contains("<section id=\"users\" hx-swap-oob=\"true\">")
            && reply.body.contains("<td>bob@example.com</td>"),
        "{}",
        reply.body
    );
    audited(
        &hub,
        &format!("{principal} granted bob@example.com the viewer role"),
    )
    .await;
    assert_eq!(
        grants(&hub)[1],
        ("bob@example.com".into(), Role::Viewer, principal.clone())
    );

    // Raised at once.
    let form = format!("_csrf={csrf}&op=change&email=bob@example.com&role=operator");
    let reply = post_users(addr, &cookie, &form).await;
    assert!(
        reply.body.contains("the operator role, replacing viewer."),
        "{}",
        reply.body
    );

    // Lowered once asked; the question names it, and its answer counts once.
    let form = format!("_csrf={csrf}&op=change&email=bob@example.com&role=viewer");
    let answer = ask_users(addr, &cookie, &csrf, &form).await;
    assert_eq!(grants(&hub)[1].1, Role::Operator, "nothing done yet");
    let reply = post_users(addr, &cookie, &answer).await;
    assert!(
        reply.body.contains("the viewer role, replacing operator."),
        "{}",
        reply.body
    );
    // Sent again, it lowers nothing, so nothing is asked or done.
    let again = post_users(addr, &cookie, &answer).await;
    assert!(
        again.body.contains("Already so; nothing changed."),
        "{}",
        again.body
    );
    audited(
        &hub,
        &format!("{principal} granted bob@example.com the viewer role, replacing operator"),
    )
    .await;

    // `*`, as a viewer only, shown as everyone the provider signs in.
    let form = format!("_csrf={csrf}&op=grant&email=*&role=operator");
    assert_eq!(post_users(addr, &cookie, &form).await.status, 400);
    let form = format!("_csrf={csrf}&op=grant&email=*&role=viewer");
    let reply = post_users(addr, &cookie, &form).await;
    assert!(
        reply.body.contains("<td>Everyone signed in through 127.0.0.1:")
            && reply
                .body
                .contains("Anyone else the provider signs in: <span class=\"badge\">viewer</span>, by the grant to everyone."),
        "{}",
        reply.body
    );

    // An answer to a question about a grant that has changed since is refused.
    let form = format!("_csrf={csrf}&op=revoke&email=bob@example.com");
    let stale = ask_users(addr, &cookie, &csrf, &form).await;
    hub.db
        .grant_account("bob@example.com", Role::Operator, "uid 0", 2)
        .unwrap();
    let reply = post_users(addr, &cookie, &stale).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("it changed"), "{}", reply.body);
    assert_eq!(grants(&hub)[2].1, Role::Operator);

    // Revoked once asked.
    let answer = ask_users(addr, &cookie, &csrf, &form).await;
    let reply = post_users(addr, &cookie, &answer).await;
    assert!(
        reply.body.contains("Revoked the grant of bob@example.com."),
        "{}",
        reply.body
    );
    audited(
        &hub,
        &format!("{principal} revoked bob@example.com's grant of the operator role"),
    )
    .await;
    assert_eq!(
        grants(&hub)
            .into_iter()
            .map(|(e, _, _)| e)
            .collect::<Vec<_>>(),
        ["*", "alice@example.com"]
    );

    // A plain form goes back to the page; what is not an address or a role is refused.
    let reply = post_action(
        addr,
        &format!("https://{addr}"),
        &cookie,
        "/users",
        &format!("_csrf={csrf}&op=grant&email=carol@example.com&role=viewer"),
        false,
    )
    .await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/users"));
    for form in [
        "op=grant&email=not-an-address&role=viewer",
        "op=grant&email=a%20b@example.com&role=viewer",
        "op=grant&email=dan@example.com&role=admin",
        "op=delete&email=dan@example.com",
    ] {
        let reply = post_users(addr, &cookie, &format!("_csrf={csrf}&{form}")).await;
        assert_eq!(reply.status, 400, "{form}: {}", reply.body);
    }

    // An address with markup in it is escaped in its row and in its forms' hidden field.
    let form = format!("_csrf={csrf}&op=grant&email=a%22%3Cb%3E%40example.com&role=viewer");
    let reply = post_users(addr, &cookie, &form).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    for want in [
        "<td>a&quot;&lt;b&gt;@example.com</td>",
        "<input type=\"hidden\" name=\"email\" value=\"a&quot;&lt;b&gt;@example.com\">",
    ] {
        assert!(reply.body.contains(want), "{want}: {}", reply.body);
    }
    assert!(!reply.body.contains("a\"<b>"), "{}", reply.body);
    assert_eq!(grants(&hub).len(), 4);
}

/// A post to `/users` from another origin, or without the session's CSRF token, changes
/// nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_users_post_needs_the_ui_origin_and_the_csrf_token() {
    let (addr, hub) = start_oidc(serde_json::json!({"sub": "s"}), &[]).await;
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let form = format!("_csrf={csrf}&op=grant&email=eve@example.com&role=operator");
    let reply = post_action(addr, "https://evil.example", &cookie, "/users", &form, true).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let reply = post_users(
        addr,
        &cookie,
        "op=grant&email=eve@example.com&role=operator",
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let reply = post_users(
        addr,
        &cookie,
        &format!(
            "_csrf={}&op=grant&email=eve@example.com&role=operator",
            "0".repeat(64)
        ),
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    assert!(grants(&hub).is_empty());
}

/// The operator role is never taken from the last address granted it from the page — the
/// operator's own included — and the refusal says how to get back in; nothing is asked first.
#[tokio::test(flavor = "multi_thread")]
async fn the_last_operator_grant_is_kept() {
    let (addr, hub) = start_oidc(
        serde_json::json!({"sub": "u", "email": "alice@example.com"}),
        &[
            ("alice@example.com", Role::Operator),
            ("bob@example.com", Role::Viewer),
        ],
    )
    .await;
    let (cookie, csrf) = oidc_session(addr).await;
    for form in [
        "op=revoke&email=alice@example.com",
        "op=change&email=Alice@example.com&role=viewer",
    ] {
        let reply = post_users(addr, &cookie, &format!("_csrf={csrf}&{form}")).await;
        assert_eq!(reply.status, 409, "{form}: {}", reply.body);
        assert!(
            reply.body.contains("no address granted the operator role")
                && reply.body.contains("vk-hub ui login --role operator"),
            "{}",
            reply.body
        );
        assert!(!reply.body.contains("name=\"confirm\""), "{}", reply.body);
    }
    // A viewer's grant goes all the same.
    let answer = ask_users(
        addr,
        &cookie,
        &csrf,
        &format!("_csrf={csrf}&op=revoke&email=bob@example.com"),
    )
    .await;
    assert_eq!(post_users(addr, &cookie, &answer).await.status, 200);
    assert_eq!(
        grants(&hub),
        [("alice@example.com".into(), Role::Operator, "uid 0".into())]
    );
}

/// Lowering a grant ends the sessions it admitted that now hold more — an operator lowering
/// their own, with another operator left, signs themselves out — audited as the session
/// opened through the provider.
#[tokio::test(flavor = "multi_thread")]
async fn a_lowered_grant_ends_its_sessions() {
    let (addr, hub) = start_oidc(
        serde_json::json!({"sub": "u", "email": "bob@example.com", "email_verified": true}),
        &[
            ("alice@example.com", Role::Operator),
            ("bob@example.com", Role::Operator),
        ],
    )
    .await;
    let (bob, csrf) = oidc_session(addr).await;
    let (other, _) = oidc_session(addr).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    assert!(
        principal.ends_with("(operator, bob@example.com)"),
        "{principal}"
    );
    let answer = ask_users(
        addr,
        &bob,
        &csrf,
        &format!("_csrf={csrf}&op=change&email=bob@example.com&role=viewer"),
    )
    .await;
    let reply = post_users(addr, &bob, &answer).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("Ended 2 web UI session(s) that held more than that."),
        "{}",
        reply.body
    );
    audited(
        &hub,
        "granted bob@example.com the viewer role, replacing operator",
    )
    .await;
    let events = hub.db.audits(None, 20).unwrap();
    assert!(
        events
            .iter()
            .any(|r| r.actor.ends_with("(operator, bob@example.com)")
                && r.event.contains("granted bob@example.com the viewer role")),
        "{events:?}"
    );
    for cookie in [&bob, &other] {
        assert_eq!(get(addr, "/", Some(cookie)).await.status, 401);
    }
    // Signing in again gets the lowered role.
    let (again, _) = oidc_session(addr).await;
    assert_eq!(get(addr, "/users", Some(&again)).await.status, 403);
}

/// Without `[oidc]`, `/users` lists the grants kept for when the hub has it, and says so; it
/// changes none.
#[tokio::test(flavor = "multi_thread")]
async fn without_oidc_the_users_page_only_lists_the_grants() {
    let (addr, hub, origin) = start_fleet().await;
    hub.db
        .grant_account("alice@example.com", Role::Operator, "uid 0", 1)
        .unwrap();
    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/users", Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains("take effect once OIDC is configured")
            && page.body.contains("<td>alice@example.com</td>")
            && !page.body.contains("<form class=\"wide\"")
            && !page.body.contains("value=\"revoke\""),
        "{}",
        page.body
    );
    let form = format!("_csrf={csrf}&op=grant&email=eve@example.com&role=viewer");
    let reply = post_action(addr, &origin, &cookie, "/users", &form, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("[oidc]"), "{}", reply.body);
    assert_eq!(grants(&hub).len(), 1);
}

/// A fleet hub keeping releases in a scratch directory and fetching them from `api`, if
/// given; the directory.
async fn start_fleet_releases(
    api: Option<&str>,
) -> (SocketAddr, Arc<Hub>, String, std::path::PathBuf) {
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("http://{addr}");
    let dir = std::env::temp_dir().join(format!(
        "vk-hub-ui-releases-{}-{}",
        std::process::id(),
        crate::random_hex(4).unwrap()
    ));
    let hub = Arc::new(
        Hub::new(Arc::new(Db::open_memory().unwrap()), Some(origin.clone()))
            .with_releases(dir.join("releases"))
            .with_release_source(api.map(crate::fetch::Source::at)),
    );
    let ui = Arc::new(Ui::new(hub.clone(), &origin));
    tokio::spawn(serve(listener, None, ui));
    (addr, hub, origin, dir)
}

/// What the releases directory holds that is not a release: nothing, once a request is over.
fn staged_files(dir: &std::path::Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir.join("releases")) else {
        return Vec::new();
    };
    entries
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with('.'))
        .collect()
}

/// A form as a browser posts it with a file input: its `Content-Type`, and its body.
fn multipart_form(fields: &[(&str, &[u8])]) -> (String, Vec<u8>) {
    let boundary = "----vkHubTestBoundary7MA4YWxk";
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        if *name == "file" {
            body.extend_from_slice(
                b"Content-Disposition: form-data; name=\"file\"; filename=\"vk\"\r\n\
                  Content-Type: application/octet-stream\r\n\r\n",
            );
        } else {
            body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            );
        }
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (format!("multipart/form-data; boundary={boundary}"), body)
}

async fn post_upload(
    addr: SocketAddr,
    origin: &str,
    cookie: &str,
    fields: &[(&str, &[u8])],
    extra: &[&str],
) -> Reply {
    let (content_type, body) = multipart_form(fields);
    let cookie = format!("Cookie: {cookie}");
    let origin = format!("Origin: {origin}");
    let content_type = format!("Content-Type: {content_type}");
    let mut headers = vec![cookie.as_str(), origin.as_str(), content_type.as_str()];
    headers.extend_from_slice(extra);
    request_bytes(addr, "POST", operations::UPLOAD_PATH, &headers, &body).await
}

/// An operator uploads a release from `/operations`: it is checked and held as the session's
/// principal, the audit log says so, and nothing is left staged.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_uploads_a_release() {
    let (addr, hub, origin, dir) = start_fleet_releases(None).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    let page = get(addr, "/operations", Some(&operator)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body.contains(
            "action=\"/releases/upload\" enctype=\"multipart/form-data\"><input type=\"hidden\" \
             name=\"_csrf\""
        ),
        "{}",
        page.body
    );
    // Fetching is off: no form for it.
    assert!(!page.body.contains("Fetch from GitHub"), "{}", page.body);

    let bin = crate::fetch::tests::fake_vk("0.85.0");
    let reply = post_upload(
        addr,
        &origin,
        &operator,
        &[
            ("_csrf", csrf.as_bytes()),
            ("version", b"0.85.0"),
            ("signature", b""),
            ("file", &bin),
        ],
        &[],
    )
    .await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/operations"));
    let releases = hub.db.releases().unwrap();
    assert_eq!(releases.len(), 1);
    let release = &releases[0];
    assert_eq!(
        (release.row.version.as_str(), release.row.added_by.as_str()),
        ("0.85.0", principal.as_str())
    );
    assert_eq!(release.row.signature, None);
    let held = std::fs::read(crate::releases::path(
        &dir.join("releases"),
        &release.sha256,
    ));
    assert_eq!(held.unwrap(), bin);
    assert!(staged_files(&dir).is_empty(), "{:?}", staged_files(&dir));
    audited(
        &hub,
        &format!(
            "{principal} added release {} as vk 0.85.0",
            crate::store::short(&release.sha256)
        ),
    )
    .await;

    // With a signature, as `vk release-key sign` prints one, and the token as a header.
    let signature = vk_hub_proto::to_base64(&[7u8; vk_hub_proto::SIGNATURE_LEN]);
    let bin = crate::fetch::tests::fake_vk("0.86.0");
    let token = format!("X-CSRF-Token: {csrf}");
    let reply = post_upload(
        addr,
        &origin,
        &operator,
        &[
            ("version", b"0.86.0"),
            ("signature", signature.as_bytes()),
            ("file", &bin),
        ],
        &[&token],
    )
    .await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    let releases = hub.db.releases().unwrap();
    assert!(
        releases
            .iter()
            .any(|r| r.row.version == "0.86.0" && r.row.signature.as_deref() == Some(&signature)),
        "{releases:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// An upload past the size a release may be, of no x86-64 ELF, of a version the binary does
/// not hold, from a viewer, without the session's token or from another origin is refused,
/// holds nothing, and leaves nothing staged.
#[tokio::test(flavor = "multi_thread")]
async fn an_upload_is_refused_and_leaves_nothing_behind() {
    let (addr, hub, origin, dir) = start_fleet_releases(None).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let bin = crate::fetch::tests::fake_vk("0.85.0");
    let mut huge = bin.clone();
    huge.resize(usize::try_from(operations::MAX_UPLOAD).unwrap() + 1, 0);
    fn fields<'a>(csrf: &'a str, version: &'a [u8], file: &'a [u8]) -> Vec<(&'a str, &'a [u8])> {
        vec![
            ("_csrf", csrf.as_bytes()),
            ("version", version),
            ("file", file),
        ]
    }
    let (csrf, viewer_csrf, bin, huge) = (&csrf, &viewer_csrf, &bin[..], &huge[..]);
    for (case, cookie, origin, form, status, said) in [
        (
            "huge",
            &operator,
            origin.as_str(),
            fields(csrf, b"0.85.0", huge),
            413,
            "at most",
        ),
        (
            "not elf",
            &operator,
            origin.as_str(),
            fields(csrf, b"0.85.0", b"#!/bin/sh\necho 0.85.0\n"),
            400,
            "not an x86-64 ELF",
        ),
        (
            "version",
            &operator,
            origin.as_str(),
            fields(csrf, b"0.84.0", bin),
            400,
            "appears nowhere",
        ),
        (
            "bad version",
            &operator,
            origin.as_str(),
            fields(csrf, b"0.8 4", bin),
            400,
            "not a version",
        ),
        (
            "viewer",
            &viewer,
            origin.as_str(),
            fields(viewer_csrf, b"0.85.0", bin),
            403,
            "operator role",
        ),
        (
            "csrf",
            &operator,
            origin.as_str(),
            fields("0000", b"0.85.0", bin),
            403,
            "CSRF",
        ),
        (
            "origin",
            &operator,
            "http://evil.example",
            fields(csrf, b"0.85.0", bin),
            403,
            "did not come from",
        ),
    ] {
        let reply = post_upload(addr, origin, cookie, &form, &[]).await;
        assert_eq!(reply.status, status, "{case}: {}", reply.body);
        assert!(reply.body.contains(said), "{case}: {}", reply.body);
        assert!(hub.db.releases().unwrap().is_empty(), "{case}");
        assert!(
            staged_files(&dir).is_empty(),
            "{case}: {:?}",
            staged_files(&dir)
        );
    }
    // A length past what any release may be is refused before a byte is read.
    let cookie = format!("Cookie: {operator}");
    let origin_header = format!("Origin: {origin}");
    let reply = request_bytes(
        addr,
        "POST",
        operations::UPLOAD_PATH,
        &[
            &cookie,
            &origin_header,
            "Content-Type: multipart/form-data; boundary=x",
            "Content-Length: 99999999999",
        ],
        b"",
    )
    .await;
    assert_eq!(reply.status, 413, "{}", reply.body);
    // A plain form's encoding is no upload.
    let reply = request(
        addr,
        "POST",
        operations::UPLOAD_PATH,
        &[
            &cookie,
            &origin_header,
            "Content-Type: application/x-www-form-urlencoded",
        ],
        &format!("_csrf={csrf}&version=0.85.0"),
    )
    .await;
    assert_eq!(reply.status, 415, "{}", reply.body);
    // A viewer's page offers none of the forms.
    let page = get(addr, "/operations", Some(&viewer)).await;
    for absent in [
        "/releases/upload",
        "/releases/fetch",
        "action=\"/rollouts\"",
    ] {
        assert!(!page.body.contains(absent), "{absent}: {}", page.body);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// An upload of `fields` from `cookie`'s session over a connection of its own, sent as far as
/// the end of the first `upto` in its body: the request and the connection, to go on with.
async fn upload_until(
    addr: SocketAddr,
    origin: &str,
    cookie: &str,
    fields: &[(&str, &[u8])],
    upto: &[u8],
) -> (Vec<u8>, usize, tokio::net::TcpStream) {
    let (content_type, body) = multipart_form(fields);
    let cut = body.windows(upto.len()).position(|w| w == upto).unwrap() + upto.len();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {addr}\r\nCookie: {cookie}\r\nOrigin: {origin}\r\n\
         Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        operations::UPLOAD_PATH,
        body.len()
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    stream.write_all(&body[..cut]).await.unwrap();
    (body, cut, stream)
}

/// [`upload_until`], then the rest of the body a byte at a time, each well inside the idle
/// limit, until the task is aborted: the connection drops, as when a browser leaves.
async fn trickle_upload(
    addr: SocketAddr,
    origin: &str,
    cookie: &str,
    fields: &[(&str, &[u8])],
    upto: &[u8],
) -> tokio::task::JoinHandle<()> {
    let (body, cut, mut stream) = upload_until(addr, origin, cookie, fields, upto).await;
    tokio::spawn(async move {
        for byte in &body[cut..] {
            tokio::time::sleep(Duration::from_millis(200)).await;
            if stream.write_all(&[*byte]).await.is_err() {
                return;
            }
        }
        std::future::pending::<()>().await;
    })
}

/// Waits for `dir`'s releases directory to hold a staged file, or for none, as `staged` says.
async fn until_staged(dir: &std::path::Path, staged: bool) {
    let started = std::time::Instant::now();
    while staged_files(dir).is_empty() == staged {
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "staged: {:?}",
            staged_files(dir)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Where a multipart body's file starts: what [`upload_until`] stops after to be inside it.
const FILE_START: &[u8] = b"application/octet-stream\r\n\r\n\x7fELF";

/// A browser leaving mid-upload, an upload that stalls, and one whose session ends while it
/// arrives each leave nothing staged or held, and the next upload goes through.
#[tokio::test(flavor = "multi_thread")]
async fn an_upload_cut_short_leaves_nothing_behind() {
    let (addr, hub, origin, dir) = start_fleet_releases(None).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let bin = crate::fetch::tests::fake_vk("0.85.0");
    let form = [
        ("_csrf", csrf.as_bytes()),
        ("version", b"0.85.0".as_slice()),
        ("file", &bin),
    ];

    // The browser leaves.
    let (_, _, stream) = upload_until(addr, &origin, &operator, &form, FILE_START).await;
    until_staged(&dir, true).await;
    drop(stream);
    until_staged(&dir, false).await;
    assert!(hub.db.releases().unwrap().is_empty());

    // The upload stalls past the idle limit.
    let (_, _, mut stream) = upload_until(addr, &origin, &operator, &form, FILE_START).await;
    let mut resp = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut resp))
        .await
        .unwrap()
        .unwrap();
    let resp = String::from_utf8_lossy(&resp);
    assert!(resp.starts_with("HTTP/1.1 408"), "{resp}");
    assert!(resp.contains("too slow"), "{resp}");
    until_staged(&dir, false).await;
    assert!(hub.db.releases().unwrap().is_empty());

    // The session ends while the file arrives.
    let (body, cut, mut stream) = upload_until(addr, &origin, &operator, &form, FILE_START).await;
    until_staged(&dir, true).await;
    hub.db
        .end_ui_sessions(None, "uid 0", crate::now_secs())
        .unwrap();
    stream.write_all(&body[cut..]).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let resp = String::from_utf8_lossy(&resp);
    assert!(resp.starts_with("HTTP/1.1 401"), "{resp}");
    until_staged(&dir, false).await;
    assert!(hub.db.releases().unwrap().is_empty());

    // Nothing was left holding the upload slot.
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let form = [
        ("_csrf", csrf.as_bytes()),
        ("version", b"0.85.0".as_slice()),
        ("file", &bin),
    ];
    let reply = post_upload(addr, &origin, &operator, &form, &[]).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(hub.db.releases().unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// One upload at a time: a second one is refused while the first's file arrives, and goes
/// through once it has ended. An upload still sending its fields holds nothing.
#[tokio::test(flavor = "multi_thread")]
async fn one_upload_at_a_time() {
    let (addr, hub, origin, dir) = start_fleet_releases(None).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let bin = crate::fetch::tests::fake_vk("0.85.0");
    let form = [
        ("_csrf", csrf.as_bytes()),
        ("version", b"0.85.0".as_slice()),
        ("file", &bin),
    ];

    // Still in its CSRF token, so far from its file.
    let fields = trickle_upload(addr, &origin, &operator, &form, &csrf.as_bytes()[..8]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let reply = post_upload(addr, &origin, &operator, &form, &[]).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    fields.abort();

    let file = trickle_upload(addr, &origin, &operator, &form, FILE_START).await;
    until_staged(&dir, true).await;
    let reply = post_upload(addr, &origin, &operator, &form, &[]).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("another release"), "{}", reply.body);
    file.abort();
    until_staged(&dir, false).await;
    let reply = post_upload(addr, &origin, &operator, &form, &[]).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An operator starts a rollout from `/operations` once they have answered the question that
/// says which nodes it updates in which waves; the answer counts once, from the same session,
/// and only while the plan is still what was shown.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_starts_a_rollout_once_confirmed() {
    let (addr, hub, origin) = start_fleet().await;
    let enroll = |hostname: &str, key: &str| {
        let (token, _) = hub
            .db
            .create_token(Duration::from_secs(60), "uid 0", crate::now_secs())
            .unwrap();
        match hub
            .db
            .enroll(&token, &key.repeat(16), hostname, "peer p", 1)
            .unwrap()
        {
            crate::store::Enrollment::Enrolled { node_id } => {
                // Ready, with a managed runner, as a rollout requires without --force.
                let ready = vk_hub_proto::Report {
                    state: Some(vk_hub_proto::NodeState::Ready),
                    runner: Some(vk_hub_proto::RunnerMode::Managed),
                    ..Default::default()
                };
                hub.db
                    .record_report(&node_id, ready, crate::now_secs())
                    .unwrap();
                node_id
            }
            _ => panic!("expected an enrollment"),
        }
    };
    let a = enroll("ci-a", "a1");
    let b = enroll("ci-b", "b1");
    let sha = "ab".repeat(32);
    let row = crate::store::ReleaseRow {
        version: "0.85.0".into(),
        size: 3 << 20,
        signature: None,
        program: None,
        added_at: 1,
        added_by: "uid 0".into(),
    };
    hub.db.add_release(&sha, &row, "uid 0").unwrap();
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    let page = get(addr, "/operations", Some(&operator)).await;
    for want in [
        "action=\"/rollouts\" hx-post=\"/rollouts\"",
        &format!("<option value=\"{sha}\">vk 0.85.0 (abababababab)</option>"),
        &format!("name=\"node\" value=\"{a}\" checked> ci-a"),
        &format!("name=\"node\" value=\"{b}\" checked> ci-b"),
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }

    let form = format!(
        "_csrf={csrf}&op=create&release={sha}&node={a}&node={b}&batch=1&max_failures=0&\
         node_timeout=30m&drain_timeout=4h"
    );
    let reply = post_action(
        addr,
        &origin,
        &operator,
        operations::ROLLOUT_PATH,
        &form,
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    for want in [
        "Start this rollout?",
        "vk 0.85.0 (<code>abababababab</code>, unsigned",
        "to 2 node(s) in 2 wave(s)",
        "<li>wave 0: ci-a</li><li>wave 1: ci-b</li>",
        "name=\"confirm\" value=\"yes\"",
    ] {
        assert!(reply.body.contains(want), "{want}: {}", reply.body);
    }
    assert_eq!(hidden(&reply.body, "nodes"), format!("{a},{b}"));
    assert!(hub.db.rollouts().unwrap().is_empty());
    let answer: String = [
        "_csrf",
        "op",
        "release",
        "nodes",
        "batch",
        "canary_per_profile",
        "max_failures",
        "node_timeout",
        "drain_timeout",
        "force",
        "plan",
        "nonce",
        "confirm",
    ]
    .iter()
    .map(|f| format!("{f}={}", hidden(&reply.body, f)))
    .collect::<Vec<_>>()
    .join("&");

    // Another session cannot answer it.
    let (other, other_csrf) = sign_in(addr, &hub, Role::Operator).await;
    let stolen = answer.replace(&csrf, &other_csrf);
    let reply = post_action(
        addr,
        &origin,
        &other,
        operations::ROLLOUT_PATH,
        &stolen,
        true,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);

    let reply = post_action(
        addr,
        &origin,
        &operator,
        operations::ROLLOUT_PATH,
        &answer,
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("Started rollout"), "{}", reply.body);
    let rollouts = hub.db.rollouts().unwrap();
    assert_eq!(rollouts.len(), 1);
    assert_eq!(rollouts[0].1.created_by, principal);
    assert_eq!(rollouts[0].1.nodes.len(), 2);
    audited(&hub, &format!("{principal} started rollout")).await;
    // Answered once.
    let reply = post_action(
        addr,
        &origin,
        &operator,
        operations::ROLLOUT_PATH,
        &answer,
        true,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert_eq!(hub.db.rollouts().unwrap().len(), 1);

    // An answer posting another plan than it was asked, and a node changed between the
    // question and the answer, are refused: neither is what was shown.
    let ask_for = |form: String| {
        let (operator, origin) = (operator.clone(), origin.clone());
        async move {
            let reply = post_action(
                addr,
                &origin,
                &operator,
                operations::ROLLOUT_PATH,
                &form,
                true,
            )
            .await;
            assert_eq!(reply.status, 200, "{}", reply.body);
            let answer = [
                "_csrf",
                "op",
                "release",
                "nodes",
                "batch",
                "canary_per_profile",
                "max_failures",
                "node_timeout",
                "drain_timeout",
                "force",
                "plan",
                "nonce",
                "confirm",
            ]
            .iter()
            .map(|f| format!("{f}={}", hidden(&reply.body, f)))
            .collect::<Vec<_>>()
            .join("&");
            (reply.body, answer)
        }
    };
    let some = format!(
        "_csrf={csrf}&op=create&release={sha}&node={a}&batch=1&max_failures=0&\
         node_timeout=30m&drain_timeout=4h"
    );
    let (asked, answer) = ask_for(some).await;
    assert!(asked.contains("to 1 node(s) in 1 wave(s)"), "{asked}");
    let answer = answer.replace("batch=1", "batch=2");
    let reply = post_action(
        addr,
        &origin,
        &operator,
        operations::ROLLOUT_PATH,
        &answer,
        true,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("changed"), "{}", reply.body);
    let (_, answer) = ask_for(form.clone()).await;
    // Its runner external now, so skipped without --force.
    let external = vk_hub_proto::Report {
        state: Some(vk_hub_proto::NodeState::Ready),
        runner: Some(vk_hub_proto::RunnerMode::External),
        ..Default::default()
    };
    hub.db
        .record_report(&b, external, crate::now_secs())
        .unwrap();
    let reply = post_action(
        addr,
        &origin,
        &operator,
        operations::ROLLOUT_PATH,
        &answer,
        true,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(reply.body.contains("changed"), "{}", reply.body);
    assert_eq!(hub.db.rollouts().unwrap().len(), 1);

    // A viewer is refused, and a plan with no release named.
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let form = form.replace(csrf.as_str(), &viewer_csrf);
    let reply = post_action(
        addr,
        &origin,
        &viewer,
        operations::ROLLOUT_PATH,
        &form,
        true,
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let form = format!("_csrf={csrf}&op=create&node={a}&batch=1");
    let reply = post_action(
        addr,
        &origin,
        &operator,
        operations::ROLLOUT_PATH,
        &form,
        true,
    )
    .await;
    assert_eq!(reply.status, 400, "{}", reply.body);
}

/// An operator asks for the latest release on GitHub and fetches it from `/operations`; the
/// page follows the fetch, which is held as the session's principal. A release whose binary
/// does not hash to its published digest is refused, and the page says so.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_fetches_a_release_from_github() {
    use crate::fetch::tests::{FakeRelease, fake_github, fake_vk};
    let _ = rustls::crypto::ring::default_provider().install_default();
    let api = fake_github(FakeRelease::new("v0.85.0", fake_vk("0.85.0"))).await;
    let (addr, hub, origin, dir) = start_fleet_releases(Some(&api)).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub.db.ui_sessions(crate::now_secs()).unwrap()[0].principal();
    let page = get(addr, "/operations", Some(&operator)).await;
    for want in [
        "action=\"/releases/fetch\" hx-post=\"/releases/fetch\"",
        "<input name=\"version\" value=\"latest\"",
        "<button name=\"op\" value=\"fetch\">Fetch from GitHub</button>",
        &format!("From <code>{api}/virtkit-dev/virtkit</code>"),
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    let path = operations::FETCH_PATH;
    let reply = post_action(
        addr,
        &origin,
        &operator,
        path,
        &format!("_csrf={csrf}&op=check"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("is 0.85.0."), "{}", reply.body);

    let form = format!("_csrf={csrf}&op=fetch&version=latest");
    let reply = post_action(addr, &origin, &operator, path, &form, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Fetching vk latest from"),
        "{}",
        reply.body
    );
    audited(&hub, &format!("{principal} added release")).await;
    let releases = hub.db.releases().unwrap();
    assert_eq!(releases[0].row.version, "0.85.0");
    assert_eq!(releases[0].row.added_by, principal);
    let page = page_with(addr, "/operations", &operator, "Fetched vk 0.85.0").await;
    assert!(page.contains("Latest on GitHub: vk 0.85.0"), "{page}");
    assert!(staged_files(&dir).is_empty(), "{:?}", staged_files(&dir));

    // A viewer may not; nor a version that is not one.
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let reply = post_action(
        addr,
        &origin,
        &viewer,
        path,
        &format!("_csrf={viewer_csrf}&op=fetch"),
        true,
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let form = format!("_csrf={csrf}&op=fetch&version=..%2Fx");
    let reply = post_action(addr, &origin, &operator, path, &form, true).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    let _ = std::fs::remove_dir_all(&dir);

    let mut tampered = FakeRelease::new("v0.86.0", fake_vk("0.86.0"));
    tampered.sha256 = "00".repeat(32);
    let api = fake_github(tampered).await;
    let (addr, hub, origin, dir) = start_fleet_releases(Some(&api)).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let form = format!("_csrf={csrf}&op=fetch&version=0.86.0");
    let reply = post_action(addr, &origin, &operator, path, &form, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    audited(&hub, "failed to fetch vk 0.86.0").await;
    assert!(hub.db.releases().unwrap().is_empty());
    let page = page_with(
        addr,
        "/operations",
        &operator,
        "Fetching vk 0.86.0 failed</span>",
    )
    .await;
    assert!(page.contains("does not match"), "{page}");
    assert!(staged_files(&dir).is_empty(), "{:?}", staged_files(&dir));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Viewers see registries with nothing to steer them; operators steer them with the session's
/// CSRF token, and issue registry tokens.
#[tokio::test(flavor = "multi_thread")]
async fn registries_are_shown_to_all_and_steered_by_operators() {
    use crate::store::{RegistryEnrollment, TokenKind};
    let (addr, hub, origin) = start_fleet().await;
    let (token, _) = hub
        .db
        .create_token_for(
            TokenKind::Registry,
            Duration::from_secs(60),
            None,
            "uid 0",
            crate::now_secs(),
        )
        .unwrap();
    let RegistryEnrollment::Enrolled { id } = hub
        .db
        .enroll_registry(&token, "aa", "reg-1", "peer p", 1)
        .unwrap()
    else {
        panic!("expected an enrollment");
    };
    let detail = format!("/registry/{id}");
    let action = format!("{detail}/action");
    let forms = ["action=\"/tokens\"", &format!("action=\"{action}\"")];

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    for path in ["/registries", detail.as_str()] {
        let page = get(addr, path, Some(&viewer)).await;
        assert_eq!(page.status, 200, "{path}: {}", page.body);
        assert!(page.body.contains("reg-1"), "{path}: {}", page.body);
        assert!(
            forms.iter().all(|f| !page.body.contains(f)),
            "{path}: {}",
            page.body
        );
    }
    let form = format!("_csrf={viewer_csrf}&op=read-only");
    let reply = post_action(addr, &origin, &viewer, &action, &form, false).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let form = format!("_csrf={viewer_csrf}&ttl=3600&kind=registry");
    let reply = post_action(addr, &origin, &viewer, "/tokens", &form, false).await;
    assert_eq!(reply.status, 403, "{}", reply.body);

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    assert!(
        get(addr, "/registries", Some(&operator))
            .await
            .body
            .contains(forms[0])
    );
    assert!(
        get(addr, &detail, Some(&operator))
            .await
            .body
            .contains(forms[1])
    );
    for (form, status) in [
        ("op=read-only".to_string(), 403),
        (
            format!("_csrf={csrf}&op=gc-now&retention_days=0&grace_days=1"),
            400,
        ),
        (format!("_csrf={csrf}&op=read-only"), 303),
        (
            format!("_csrf={csrf}&op=gc-now&retention_days=7&grace_days=2"),
            303,
        ),
    ] {
        let reply = post_action(addr, &origin, &operator, &action, &form, false).await;
        assert_eq!(reply.status, status, "{form}: {}", reply.body);
    }
    let row = hub.db.registry(&id).unwrap().unwrap();
    assert_eq!(row.desired.unwrap().read_only, Some(true));
    let commands = hub.db.registry_commands(&id).unwrap();
    assert!(
        matches!(
            commands[..],
            [crate::store::RegistryCommandRow {
                command: vk_hub_proto::registry::Command {
                    op: vk_hub_proto::registry::Operation::Gc {
                        retention_days: 7,
                        grace_days: 2,
                        dry_run: false,
                    },
                    ..
                },
                ..
            }]
        ),
        "{commands:?}"
    );

    // A registry token, from the Registries page's form.
    let form = format!("_csrf={csrf}&ttl=3600&kind=registry");
    let reply = post_action(addr, &origin, &operator, "/tokens", &form, false).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("vk-registry join"), "{}", reply.body);
    let at = reply.body.find("vkh_").expect("the token");
    let token: String = reply.body[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    assert!(matches!(
        hub.db.enroll(&token, "bb", "node", "peer p", 1).unwrap(),
        crate::store::Enrollment::BadToken
    ));
    assert!(matches!(
        hub.db
            .enroll_registry(&token, "bb", "reg-2", "peer p", 1)
            .unwrap(),
        RegistryEnrollment::Enrolled { .. }
    ));
    let form = format!("_csrf={csrf}&ttl=3600&kind=vm");
    let reply = post_action(addr, &origin, &operator, "/tokens", &form, false).await;
    assert_eq!(reply.status, 400, "{}", reply.body);

    // The audit log links each to its own page.
    let audit = get(addr, "/audit", Some(&operator)).await.body;
    assert!(
        audit.contains(&format!("<a href=\"/registry/{id}\">reg-1</a>")),
        "{audit}"
    );
    assert!(
        audit.contains(&format!("<option value=\"{id}\"")),
        "{audit}"
    );
}

/// The registries' list names each registry with its address, and says whether jobs get
/// access to it: off, set up, needing setup, or between signing keys.
#[tokio::test(flavor = "multi_thread")]
async fn the_registries_list_says_whether_jobs_get_access() {
    use crate::store::RegistryWrite;
    use crate::tests::tokens::{apply, enrolled_registry, token_registry, url_registry};
    let (addr, hub, _keys) = start_fleet_keys("list").await;
    url_registry(&hub, "https://off.example.com", "a1");
    token_registry(&hub, "https://ok.example.com", "a2");
    let unbound = enrolled_registry(&hub, "a3");
    let inventory = vk_hub_proto::registry::Inventory {
        tokens: true,
        ..Default::default()
    };
    hub.db
        .record_registry(
            &unbound,
            RegistryWrite::Inventory(inventory),
            crate::now_secs(),
        )
        .unwrap();
    crate::tokens::sync_registry(&hub, &unbound).unwrap();
    apply(&hub, &unbound);
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let body = get(addr, "/registries", Some(&viewer)).await.body;
    for want in [
        "<th>JOB ACCESS</th>",
        "https://off.example.com",
        "<span class=\"sub\">off</span>",
        "https://ok.example.com",
        "<span class=\"badge ok\">Configured</span><div class=\"sub\">2 storage areas</div>",
        "no address",
        "Setup needed</span><div class=\"sub\">no address bound",
    ] {
        assert!(body.contains(want), "{want}: {body}");
    }
    // A new signing key: the registry is between keys until it applies it.
    crate::tokens::rotate(&hub, "uid 0").unwrap();
    let body = get(addr, "/registries", Some(&viewer)).await.body;
    assert!(body.contains("Updating signing keys"), "{body}");
    // What a registry reports, and the address it is bound to, are escaped.
    let hostile = url_registry(&hub, "https://<script>.example.com", "a4");
    let inventory = vk_hub_proto::registry::Inventory {
        hostname: "<script>alert(1)</script>".into(),
        ..Default::default()
    };
    hub.db
        .record_registry(
            &hostile,
            RegistryWrite::Inventory(inventory),
            crate::now_secs(),
        )
        .unwrap();
    let body = get(addr, "/registries", Some(&viewer)).await.body;
    assert!(body.contains("&lt;script&gt;alert(1)"), "{body}");
    assert!(!body.contains("<script>"), "{body}");
}

/// A registry's page has three tabs: what it reports, its storage areas in plain words with
/// what keeps their cleanup from applying, and its address and signing keys.
#[tokio::test(flavor = "multi_thread")]
async fn a_registry_page_shows_its_job_access_and_settings_in_tabs() {
    use crate::store::{NamespaceRow, NsGrant, RegistryWrite};
    use crate::tests::tokens::{token_registry, url_registry};
    let (addr, hub, _keys) = start_fleet_keys("detail").await;
    let id = token_registry(&hub, "https://ok.example.com", "b1");
    hub.db
        .add_gitlab(
            "gl",
            "https://gitlab.example.com",
            "uid 0",
            crate::now_secs(),
        )
        .unwrap();
    let wab = NamespaceRow {
        name: "wab".into(),
        path: "wab".into(),
        retention_days: None,
        alias: None,
        grants: vec![
            NsGrant::parse("rwl:gitlab gl, projects wab/**, protected").unwrap(),
            NsGrant::parse("r:gitlab gl, projects wab/**").unwrap(),
        ],
        created_at: 0,
        created_by: "uid 0".into(),
    };
    hub.db
        .put_namespace(&id, &wab, "uid 0", crate::now_secs())
        .unwrap();
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = |path: String| {
        let viewer = viewer.clone();
        async move { get(addr, &path, Some(&viewer)).await.body }
    };
    let overview = page(format!("/registry/{id}")).await;
    assert!(
        overview.contains(&format!(
            "<a href=\"/registry/{id}\" aria-current=\"page\">Overview</a>"
        )),
        "{overview}"
    );
    assert!(overview.contains("Store size"), "{overview}");
    let access = page(format!("/registry/{id}?tab=access")).await;
    for want in [
        "aria-current=\"page\">Job access</a>",
        "<h2>Storage areas</h2>",
        "<strong>wab</strong>",
        "Projects under wab/, protected branches and tags only · can coordinate builds",
        "Projects under wab/</td>",
        "<summary>Managed by CI",
        "<strong>CI caches</strong>",
        "<strong>Pipeline storage</strong>",
        "Each pipeline, its own",
        &format!("<a href=\"/audit?category=all&amp;node={id}\">"),
    ] {
        assert!(access.contains(want), "{want}: {access}");
    }
    assert!(!access.contains("callout"), "{access}");
    // With a second instance, a rule names its own, and one of none every server.
    hub.db
        .add_gitlab("gl2", "https://gl2.example.com", "uid 0", crate::now_secs())
        .unwrap();
    let access = page(format!("/registry/{id}?tab=access")).await;
    for want in [
        "Projects under wab/ [gl], protected branches and tags only · can coordinate builds",
        "Projects under wab/ [gl]</td>",
        "Each pipeline [every server], its own",
    ] {
        assert!(access.contains(want), "{want}: {access}");
    }
    assert!(
        hub.db
            .remove_gitlab("gl2", "uid 0", crate::now_secs())
            .unwrap()
    );
    // The registry refused the hub's cleanup window: the tab says what it needs.
    let report = vk_hub_proto::registry::Report {
        applied: hub
            .db
            .registry(&id)
            .unwrap()
            .unwrap()
            .report
            .unwrap()
            .applied,
        refused: vec![vk_hub_proto::registry::REFUSED_PREFIX_RETENTION.into()],
        ..Default::default()
    };
    hub.db
        .record_registry(&id, RegistryWrite::Report(report), crate::now_secs())
        .unwrap();
    let access = page(format!("/registry/{id}?tab=access")).await;
    assert!(
        access.contains("callout warn") && access.contains("[[gc.prefix]]"),
        "{access}"
    );
    let settings = page(format!("/registry/{id}?tab=settings")).await;
    for want in [
        "https://ok.example.com",
        "Signs its tokens",
        "vk-hub token-keys rotate",
    ] {
        assert!(settings.contains(want), "{want}: {settings}");
    }
    // A registry that takes no tokens says so on both.
    let off = url_registry(&hub, "https://off.example.com", "b2");
    let access = page(format!("/registry/{off}?tab=access")).await;
    assert!(access.contains("Jobs get no access here"), "{access}");
    let settings = page(format!("/registry/{off}?tab=settings")).await;
    assert!(settings.contains("does not take the hub"), "{settings}");
    // A tab it does not know is the overview, and nothing of it comes back on the page.
    for query in ["?tab=bogus", "?tab=%3Cscript%3E"] {
        let body = page(format!("/registry/{id}{query}")).await;
        assert!(
            body.contains("aria-current=\"page\">Overview</a>") && body.contains("Store size"),
            "{query}: {body}"
        );
        assert!(!body.contains("<script>"), "{query}: {body}");
    }
}

/// Connections defaults to the GitLab servers; the API keys have a tab of their own.
#[tokio::test(flavor = "multi_thread")]
async fn connections_list_gitlab_servers() {
    use crate::store::{KeyPolicy, Scope};
    let (addr, hub, _) = start_fleet().await;
    let now = crate::now_secs();
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let body = get(addr, "/clients", Some(&viewer)).await.body;
    assert!(
        body.contains("None yet: <code>vk-hub gitlabs add"),
        "{body}"
    );
    for (name, url) in [
        ("gl", "https://gitlab.example.com"),
        ("partner", "https://gitlab.partner.example"),
    ] {
        hub.db.add_gitlab(name, url, "uid 0", now).unwrap();
    }
    let policy = KeyPolicy {
        scopes: vec![Scope::Jobs],
        pools: vec!["*".into()],
        max_envelope: None,
    };
    hub.db
        .create_api_key("deploy", &policy, Duration::from_secs(3600), "uid 0", now)
        .unwrap();
    let body = get(addr, "/clients", Some(&viewer)).await.body;
    for want in [
        "<h1>Connections</h1>",
        "aria-current=\"page\">GitLab</a>",
        "id=\"gitlab-servers\" hx-ext=\"sse\" sse-connect=\"/events/gitlab\" \
         sse-swap=\"gitlab\"",
        "<tr><td><strong>gl</strong></td><td>https://gitlab.example.com</td>\
         <td class=\"num\">0</td><td class=\"num\">0</td></tr>",
        "<strong>partner</strong>",
    ] {
        assert!(body.contains(want), "{want}: {body}");
    }
    assert!(!body.contains("<h2>API keys</h2>"), "{body}");
    assert!(!body.contains("deploy"), "{body}");
    // Unknown tab values select GitLab and are not reflected in the page.
    for query in ["?tab=bogus", "?tab=%3Cscript%3E"] {
        let body = get(addr, &format!("/clients{query}"), Some(&viewer))
            .await
            .body;
        assert!(
            body.contains("aria-current=\"page\">GitLab</a>"),
            "{query}: {body}"
        );
        assert!(!body.contains("<script>"), "{query}: {body}");
    }
    // A server's URL is escaped.
    hub.db
        .add_gitlab("odd", "https://<script>.example.com", "uid 0", now)
        .unwrap();
    let body = get(addr, "/clients", Some(&viewer)).await.body;
    assert!(
        body.contains("https://&lt;script&gt;.example.com"),
        "{body}"
    );
    assert!(!body.contains("<script>"), "{body}");
    let other = get(addr, "/clients?tab=other", Some(&viewer)).await.body;
    assert!(
        other.contains("aria-current=\"page\">Other API clients</a>")
            && other.contains("<h2>API keys</h2>")
            && other.contains("<tr><td>deploy</td>"),
        "{other}"
    );
    let mut events = Events::open(addr, "/events/gitlab", &viewer).await;
    next_with(&mut events, "<strong>odd</strong>").await;
}

/// The API keys and the instances using them are on the other tab, an instance that moved to
/// a new key shown once; an operator revokes a key there and comes back to it.
#[tokio::test(flavor = "multi_thread")]
async fn api_keys_and_their_instances_are_on_the_other_tab() {
    use crate::store::{KeyPolicy, Scope};
    use vk_hub_proto::client::ClientHello;
    let (addr, hub, origin) = start_fleet().await;
    let now = crate::now_secs();
    let key = |name: &str| {
        let policy = KeyPolicy {
            scopes: vec![Scope::Jobs],
            pools: vec!["*".into()],
            max_envelope: None,
        };
        let (key, _) = hub
            .db
            .create_api_key(name, &policy, Duration::from_secs(3600), "uid 0", now)
            .unwrap();
        hub.db.api_key(&key, now).unwrap().unwrap()
    };
    let hello = |instance: &str, host: &str| ClientHello {
        instance: instance.into(),
        program: "deployer".into(),
        version: "1.0".into(),
        hostname: host.into(),
        concurrent: Some(2),
        runners: vec![],
    };
    // The client's first key, revoked once its successor took over under the same name.
    let old = key("deploy");
    crate::clients::hello(&hub, &old, hello("s_1", "ci-1"))
        .await
        .unwrap();
    assert!(hub.db.revoke_api_key("deploy", "uid 0", now).unwrap());
    let new = key("deploy");
    crate::clients::hello(&hub, &new, hello("s_1", "ci-1"))
        .await
        .unwrap();
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let other = get(addr, "/clients?tab=other", Some(&viewer)).await.body;
    for want in [
        "<tr><td>deploy</td><td><code>vkk_",
        "<span class=\"badge bad\">revoked</span>",
        "<td>deploy</td><td>ci-1</td><td><code>s_1</code></td><td>deployer 1.0</td>",
    ] {
        assert!(other.contains(want), "{want}: {other}");
    }
    assert_eq!(other.matches("<code>s_1</code>").count(), 1, "{other}");
    let body = get(addr, "/clients", Some(&viewer)).await.body;
    assert!(!body.contains("s_1"), "{body}");

    // An operator revokes the key, and is sent back to the tab.
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let form = format!("_csrf={csrf}&op=revoke&name=deploy");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
    assert!(reply.body.contains("<h1>Confirm</h1>"), "{}", reply.body);
    let answer = format!(
        "{form}&keys={}&nonce={}&confirm=yes",
        hidden(&reply.body, "keys"),
        hidden(&reply.body, "nonce")
    );
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients?tab=other"));
}

/// A relay enrolled with key `key` and bound to the GitLab server at `url`.
fn bound_relay(hub: &Hub, key: &str, url: &str) -> String {
    use crate::store::{RelayEnrollment, RelayWrite, TokenKind};
    let now = crate::now_secs();
    let (token, _) = hub
        .db
        .create_token_for(TokenKind::Gitlab, Duration::from_secs(60), None, "u", now)
        .unwrap();
    let RelayEnrollment::Enrolled { id } = hub
        .db
        .enroll_relay(&token, key, "relay-1", "peer p", now)
        .unwrap()
    else {
        panic!("not enrolled");
    };
    let inventory = vk_hub_proto::gitlab::Inventory {
        version: "0.96.0".into(),
        hostname: "relay-1".into(),
        server: vk_hub_proto::gitlab::Server {
            url: url.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    hub.db
        .record_relay(&id, RelayWrite::Inventory(inventory), now)
        .unwrap();
    id
}

/// An operator adds a GitLab server from the GitLab tab, refused with the CLI's reason for a
/// bad name or URL or one taken, and removes one once asked, only while no relay is bound to
/// it and only the server asked about; each is audited and the tab follows live. A viewer gets
/// no form nor button and is refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_adds_and_removes_gitlab_servers() {
    let (addr, hub, origin) = start_fleet().await;
    let good = "op=add-server&name=gl&url=https%3A%2F%2FGitLab.example.com%2F";

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/clients", Some(&viewer)).await.body;
    assert!(page.contains("<code>vk-hub gitlabs add"), "{page}");
    for not in ["Add a GitLab server", "<form class=\"wide\""] {
        assert!(!page.contains(not), "{not}: {page}");
    }
    for form in [good, "op=remove&server=gl"] {
        let form = format!("_csrf={viewer_csrf}&{form}");
        let reply = post_action(addr, &origin, &viewer, "/clients", &form, false).await;
        assert_eq!(reply.status, 403, "{form}: {}", reply.body);
    }

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/clients", Some(&operator)).await.body;
    for want in [
        "None yet: add one below",
        "<h2>Add a GitLab server</h2><form class=\"wide\" method=\"post\" \
         action=\"/clients\">",
        "<input type=\"hidden\" name=\"op\" value=\"add-server\">",
    ] {
        assert!(page.contains(want), "{want}: {page}");
    }
    let mut live = Events::open(addr, "/events/gitlab", &operator).await;
    live.next().await.unwrap();
    let reply = post_action(addr, &origin, &operator, "/clients", good, false).await;
    assert_eq!(reply.status, 403, "no CSRF token: {}", reply.body);
    let form = format!("_csrf={csrf}&{good}");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients"));
    assert_eq!(
        hub.db.gitlab("gl").unwrap().map(|g| g.url).as_deref(),
        Some("https://gitlab.example.com")
    );
    audited(
        &hub,
        "added GitLab instance gl at https://gitlab.example.com",
    )
    .await;
    let event = next_with(&mut live, "<strong>gl</strong>").await;
    assert!(
        event.contains("<input type=\"hidden\" name=\"server\" value=\"gl\">"),
        "{event}"
    );
    for (bad, said) in [
        (
            "name=GL&url=https%3A%2F%2Fa.example",
            "an instance&#39;s name is",
        ),
        ("name=a&url=ftp%3A%2F%2Fa.example", "is not an http(s) URL"),
        (
            "name=gl&url=https%3A%2F%2Fa.example",
            "already an instance named gl",
        ),
        (
            "name=b&url=https%3A%2F%2Fgitlab.example.com",
            "is instance gl already",
        ),
    ] {
        let form = format!("_csrf={csrf}&op=add-server&{bad}");
        let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
        assert_eq!(reply.status, 400, "{bad}: {}", reply.body);
        assert!(reply.body.contains(said), "{bad}: {said}: {}", reply.body);
        assert!(
            reply
                .body
                .contains("<a href=\"/clients\">Back to the GitLab servers"),
            "{}",
            reply.body
        );
    }
    assert_eq!(hub.db.gitlabs().unwrap().len(), 1);

    // While a relay is bound to it: no button, and a post is refused.
    let now = crate::now_secs();
    let relay = bound_relay(&hub, "aa", "https://gitlab.example.com");
    let page = get(addr, "/clients", Some(&operator)).await.body;
    assert!(!page.contains("name=\"server\""), "{page}");
    let form = format!("_csrf={csrf}&op=remove&server=gl");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, true).await;
    assert!(reply.body.contains("Yes, remove"), "{}", reply.body);
    let answer = format!(
        "{form}&added={}&nonce={}&confirm=yes",
        hidden(&reply.body, "added").replace(' ', "+"),
        hidden(&reply.body, "nonce")
    );
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply
            .body
            .contains(&format!("relay {relay} is bound to instance gl")),
        "{}",
        reply.body
    );
    assert!(hub.db.gitlab("gl").unwrap().is_some());

    // Asked about one server, a namesake added since is left alone.
    assert!(hub.db.remove_relay(&relay, "uid 0", now).unwrap());
    let page = get(addr, "/clients", Some(&operator)).await.body;
    assert!(page.contains("name=\"server\" value=\"gl\""), "{page}");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
    assert!(reply.body.contains("<h1>Confirm</h1>"), "{}", reply.body);
    let answer = format!(
        "{form}&added={}&nonce={}&confirm=yes",
        hidden(&reply.body, "added").replace(' ', "+"),
        hidden(&reply.body, "nonce")
    );
    assert!(hub.db.remove_gitlab("gl", "uid 0", now).unwrap());
    hub.db
        .add_gitlab("gl", "https://other.example.com", "uid 0", now)
        .unwrap();
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, false).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(hub.db.gitlab("gl").unwrap().is_some());

    // Removed once asked, back to the tab.
    let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
    let answer = format!(
        "{form}&added={}&nonce={}&confirm=yes",
        hidden(&reply.body, "added").replace(' ', "+"),
        hidden(&reply.body, "nonce")
    );
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients"));
    assert!(hub.db.gitlab("gl").unwrap().is_none());
    let audit = audited(&hub, "removed GitLab instance gl").await;
    assert!(
        audit
            .iter()
            .any(|e| e.contains("(operator) removed GitLab instance gl")),
        "{audit:?}"
    );
    next_with(&mut live, "None yet: add one below").await;
    let reply = post_action(addr, &origin, &operator, "/clients", &form, true).await;
    assert_eq!(reply.status, 404, "{}", reply.body);
}

/// An operator adds a relay from the GitLab tab: a single-use relay token, shown once with the
/// `vk-gitlab join` redeeming it, that enrolls a relay and nothing else. A viewer has no form.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_issues_a_relay_token_from_the_gitlab_tab() {
    use crate::store::RelayEnrollment;
    let (addr, hub, origin) = start_fleet_with("http", Some("https://hub.example.com:8443")).await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/clients", Some(&viewer)).await.body;
    assert!(!page.contains("Add a relay"), "{page}");

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/clients", Some(&operator)).await.body;
    assert!(
        page.contains("<h2>Add a relay</h2><form method=\"post\" action=\"/tokens\">")
            && page.contains("<input type=\"hidden\" name=\"kind\" value=\"gitlab\">"),
        "{page}"
    );
    let form = format!("_csrf={csrf}&kind=gitlab&ttl=3600");
    let reply = post_action(addr, &origin, &operator, "/tokens", &form, false).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    for want in [
        "<h1>Relay enrollment token</h1>",
        "<pre>vk-gitlab join https://hub.example.com:8443 --token -</pre>",
        "<a href=\"/clients\">Back to the GitLab tab</a>",
        "aria-current=\"page\">Connections",
    ] {
        assert!(reply.body.contains(want), "{want}: {}", reply.body);
    }
    let at = reply.body.find("vkh_").expect("the token");
    let token: String = reply.body[at..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    // A node does not redeem it; a relay does.
    assert!(matches!(
        hub.db.enroll(&token, "aa", "node", "peer p", 1).unwrap(),
        crate::store::Enrollment::BadToken
    ));
    assert!(matches!(
        hub.db
            .enroll_relay(&token, "aa", "relay", "peer p", crate::now_secs())
            .unwrap(),
        RelayEnrollment::Enrolled { .. }
    ));
    let form = format!("_csrf={csrf}&kind=other&ttl=3600");
    let reply = post_action(addr, &origin, &operator, "/tokens", &form, false).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
}

/// The GitLab tab shows each relay, what the hub makes of its server and what it reports of it,
/// and each runner's placement, state and load, all as text; it follows a relay's reports live.
/// An operator removes a relay once asked, audited; a viewer has no button and is refused.
#[tokio::test(flavor = "multi_thread")]
async fn relays_and_their_runners_are_on_the_gitlab_tab() {
    use crate::store::RelayWrite;
    use vk_hub_proto::client::Placement;
    use vk_hub_proto::gitlab::{
        Heartbeat, Inventory, Report, Runner, RunnerLoad, RunnerReport, RunnerState, Server,
    };
    let (addr, hub, origin) = start_fleet().await;
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/clients", Some(&viewer)).await.body;
    assert!(
        page.contains("<h2>Relays</h2><p class=\"empty\">None yet"),
        "{page}"
    );
    let mut live = Events::open(addr, "/events/gitlab", &viewer).await;
    live.next().await.unwrap();

    let hostile = "<script>x</script>";
    let relay = bound_relay(&hub, "aa", "https://gitlab.example.com");
    let now = crate::now_secs();
    let inventory = Inventory {
        version: "0.96.0".into(),
        hostname: "relay-1".into(),
        system_id: "s_0123456789ab".into(),
        concurrent: 6,
        server: Server {
            url: "https://gitlab.example.com".into(),
            spki_sha256: Some("ab".repeat(32)),
            version: None,
        },
        runners: vec![
            Runner {
                name: "ci".into(),
                runner_id: Some(42),
                placement: Placement {
                    pool: "ci".into(),
                    labels: vec!["large".into()],
                    envelope: vk_hub_proto::job::Envelope {
                        mem_mib: 4096,
                        cpus: 2,
                        disk_bytes: 1 << 30,
                    },
                },
                limit: Some(4),
                request_concurrency: 1,
                verified: true,
            },
            Runner {
                name: hostile.into(),
                runner_id: None,
                placement: Placement {
                    pool: "ci".into(),
                    labels: vec![],
                    envelope: vk_hub_proto::job::Envelope {
                        mem_mib: 1024,
                        cpus: 1,
                        disk_bytes: 1 << 30,
                    },
                },
                limit: None,
                request_concurrency: 1,
                verified: false,
            },
        ],
    };
    let writes = [
        RelayWrite::Inventory(inventory),
        RelayWrite::Report(Report {
            runners: vec![
                RunnerReport {
                    name: "ci".into(),
                    state: RunnerState::ServerPending,
                    message: None,
                },
                RunnerReport {
                    name: hostile.into(),
                    state: RunnerState::TokenRefused,
                    message: Some(hostile.into()),
                },
            ],
        }),
        RelayWrite::Heartbeat(Heartbeat {
            runners: vec![RunnerLoad {
                name: "ci".into(),
                requests: 1,
                jobs: 3,
                request_admissions: vec![],
                job_admissions: vec![],
                last_answer_at: Some(now),
                last_status: Some(204),
            }],
        }),
    ];
    for write in writes {
        hub.db.record_relay(&relay, write, now).unwrap();
    }
    hub.clients_changed();
    // The stream's periodic heartbeat can render between writes. Wait for the relay's
    // heartbeat, written last, so the event includes its inventory and report too.
    let event = next_with(&mut live, " · HTTP 204</td>").await;
    for want in [
        "<strong>relay-1</strong> <code class=\"sub\">",
        "<span class=\"badge bad\">unreachable</span>",
        "https://gitlab.example.com <span class=\"badge warn\">pending</span>",
        &format!("certificate key sha256 <code>{}</code>", "ab".repeat(32)),
        "<td>0.96.0</td><td class=\"num\">2</td><td class=\"num\">6</td>",
        // Its server not approved: neither mapped nor unmapped.
        "<td>relay-1</td><td>ci</td><td>42</td><td>-</td><td>-</td><td>pool ci · large · 4096 MiB",
        "<td class=\"num\">4</td><td><span class=\"badge warn\">server not approved</span>",
        "<td class=\"num\">1</td><td class=\"num\">3</td><td><time",
        " · HTTP 204</td>",
        "<span class=\"badge bad\">token not verified</span> \
         <span class=\"badge bad\">token refused</span>",
        "&lt;script&gt;x&lt;/script&gt;",
    ] {
        assert!(event.contains(want), "{want}: {event}");
    }
    assert!(!event.contains("<script>"), "{event}");
    assert!(!event.contains("<form"), "{event}");
    hub.db
        .add_gitlab("gl", "https://gitlab.example.com", "uid 0", now)
        .unwrap();
    hub.clients_changed();
    let event = next_with(&mut live, "<td><strong>gl</strong></td><td>https://gitlab").await;
    // Its server approved: mapped to no tenant.
    assert!(
        event.contains("<td>42</td><td><span class=\"badge warn\">unmapped</span></td><td>-</td>"),
        "{event}"
    );
    // Mapped, by its approved instance's name and GitLab ID: its tenant and class.
    let mut policy = hub.db.capacity_policy().unwrap();
    policy.runners.push(crate::policy::RunnerMapping {
        gitlab: "gl".into(),
        runner_id: 42,
        tenant: "fallback".into(),
        class: crate::policy::Class::Production,
    });
    hub.db.set_capacity_policy(&policy, "u", now).unwrap();
    hub.clients_changed();
    let event = next_with(&mut live, "production</td>").await;
    assert!(
        event.contains(
            "<td>42</td><td><a href=\"/clients/tenants/fallback\">fallback</a></td>\
             <td>production</td><td>pool ci"
        ),
        "{event}"
    );
    // No request of it is queued: nothing waits.
    assert!(
        event.contains("<td class=\"num\">0</td><td>-</td><td>-</td><td>-</td></tr>"),
        "{event}"
    );
    assert!(
        event.contains("<td><a href=\"/clients/tenants/fallback\">fallback</a> <span"),
        "{event}"
    );
    // A session of protocol 1 gets no new jobs: the relay is marked for upgrade.
    assert!(!event.contains("upgrade vk-gitlab"), "{event}");
    assert!(
        hub.db
            .record_relay_session(&relay, "i", 1, now, || true)
            .unwrap()
    );
    hub.clients_changed();
    let event = next_with(&mut live, "upgrade vk-gitlab").await;
    assert!(
        event.contains("<span class=\"badge warn\">upgrade vk-gitlab: no new jobs</span></td>"),
        "{event}"
    );

    let form = format!("_csrf={viewer_csrf}&op=remove-relay&relay={relay}");
    let reply = post_action(addr, &origin, &viewer, "/clients", &form, false).await;
    assert_eq!(reply.status, 403, "{}", reply.body);

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/clients", Some(&operator)).await.body;
    assert!(
        page.contains(&format!(
            "<input type=\"hidden\" name=\"op\" value=\"remove-relay\"><input \
             type=\"hidden\" name=\"relay\" value=\"{relay}\">"
        )),
        "{page}"
    );
    let form = format!("_csrf={csrf}&op=remove-relay&relay={relay}");
    let reply = post_action(addr, &origin, &operator, "/clients", &form, false).await;
    assert!(reply.body.contains("<h1>Confirm</h1>"), "{}", reply.body);
    assert!(reply.body.contains("Remove this relay?"), "{}", reply.body);
    assert!(hub.db.relay(&relay).unwrap().is_some());
    let answer = format!("{form}&nonce={}&confirm=yes", hidden(&reply.body, "nonce"));
    let reply = post_action(addr, &origin, &operator, "/clients", &answer, false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients"));
    assert!(hub.db.relay(&relay).unwrap().is_none());
    audited(&hub, &format!("removed relay {relay}")).await;
    next_with(&mut live, "<h2>Relays</h2><p class=\"empty\">None yet").await;
    for bad in [relay.as_str(), "nope"] {
        let form = format!("_csrf={csrf}&op=remove-relay&relay={bad}");
        let reply = post_action(addr, &origin, &operator, "/clients", &form, true).await;
        assert_eq!(reply.status, 404, "{}", reply.body);
    }
}

/// What waits for approval is on top of the GitLab tab, counted on the Connections link: a
/// server a relay reports, with the certificate key to check, and the projects the approval
/// gate refused, by instance. An operator approves a server under a name, rejects it or forgets
/// its rejection, and approves, rejects or forgets the projects ticked; each is audited and the
/// tab follows live. A viewer sees the same without a form, and is refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_decides_on_pending_gitlab_servers_and_projects() {
    use crate::store::{GateJob, ProjectState, RelayWrite};
    let (addr, hub, origin) = start_fleet().await;
    let relay = bound_relay(&hub, "aa", "https://gitlab.example.com");
    let mut inventory = hub.db.relay(&relay).unwrap().unwrap().inventory.unwrap();
    inventory.server.spki_sha256 = Some("cd".repeat(32));
    let now = crate::now_secs();
    hub.db
        .record_relay(&relay, RelayWrite::Inventory(inventory), now)
        .unwrap();
    let count = |n: u64| {
        format!(
            "Connections<span id=\"nav-count-clients\"> <span class=\"count\">{n}</span></span>"
        )
    };

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/clients", Some(&viewer)).await.body;
    for want in [
        count(1).as_str(),
        "<section><h2>Pending</h2><h3>GitLab servers</h3>",
        "<tr><td>https://gitlab.example.com</td><td><code>cdcd",
        "<td>relay-1 since <time",
        "<code>vk-hub gitlabs approve &lt;url&gt; --name &lt;name&gt;</code>",
    ] {
        assert!(page.contains(want), "{want}: {page}");
    }
    assert!(!page.contains("approve-server"), "{page}");
    for form in [
        "op=approve-server&url=https%3A%2F%2Fgitlab.example.com&name=gl",
        "op=reject-server&url=https%3A%2F%2Fgitlab.example.com",
        "op=approve-projects&gitlab=gl&project=42",
    ] {
        let form = format!("_csrf={viewer_csrf}&{form}");
        let reply = post_action(addr, &origin, &viewer, "/clients", &form, true).await;
        assert_eq!(reply.status, 403, "{form}: {}", reply.body);
    }

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let mut live = Events::open(addr, "/events/gitlab", &operator).await;
    let first = next_with(&mut live, "approve-server").await;
    for want in [
        "name=\"op\" value=\"approve-server\"><input type=\"hidden\" name=\"url\" \
         value=\"https://gitlab.example.com\">",
        "hx-preserve=\"true\"",
        "name=\"op\" value=\"reject-server\"",
        // Kept current where the tab shows it.
        "<span id=\"nav-count-clients\" hx-swap-oob=\"true\"> <span class=\"count\">1</span>",
    ] {
        assert!(first.contains(want), "{want}: {first}");
    }
    let post = |form: String| {
        let (origin, operator) = (origin.clone(), operator.clone());
        async move { post_action(addr, &origin, &operator, "/clients", &form, true).await }
    };
    let url = "url=https%3A%2F%2Fgitlab.example.com";
    let reply = post(format!("_csrf={csrf}&op=approve-server&{url}&name=GL")).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply.body.contains("an instance&#39;s name is"),
        "{}",
        reply.body
    );
    let reply = post(format!("_csrf={csrf}&op=approve-server&{url}&name=gl")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("Approved GitLab server https://gitlab.example.com as gl."),
        "{}",
        reply.body
    );
    audited(
        &hub,
        "added GitLab instance gl at https://gitlab.example.com",
    )
    .await;
    next_with(&mut live, "<td><strong>gl</strong></td>").await;

    // Two projects' jobs refused: pending, under the instance.
    for (n, (id, path)) in [(42, "acme/web"), (43, "acme/api")].into_iter().enumerate() {
        let job = GateJob {
            server_url: "https://gitlab.example.com",
            project_id: id,
            project_path: path,
            job_id: 100 + id,
            job_url: Some("https://gitlab.example.com/acme/web/-/jobs/142"),
        };
        let rid = format!("{n:02x}").repeat(16);
        hub.db.gate_job(&relay, &job, (&rid, "d"), now).unwrap();
    }
    hub.clients_changed();
    let event = next_with(&mut live, "acme/api").await;
    for want in [
        "<input type=\"hidden\" name=\"gitlab\" value=\"gl\"><input type=\"hidden\" \
         name=\"url\" value=\"https://gitlab.example.com\"><fieldset>",
        "data-check=\"all\"",
        "<td><input id=\"pick-pending-gl-42\" hx-preserve=\"true\" type=\"checkbox\" \
         name=\"project\" value=\"42\" aria-label=\"42\"></td>\
         <td><a href=\"/clients/projects/gl/42\">acme/web</a></td><td class=\"num\">42</td><td><a \
         href=\"https://gitlab.example.com/acme/web/-/jobs/142\"",
        ">#142</a></td><td>relay-1</td><td><time",
        "name=\"op\" value=\"approve-projects\">Approve</button>",
        "name=\"op\" value=\"reject-projects\">Reject</button>",
        "name=\"op\" value=\"forget-projects\">Forget</button>",
        "<span class=\"count\">2</span>",
    ] {
        assert!(event.contains(want), "{want}: {event}");
    }
    let page = get(addr, "/clients", Some(&viewer)).await.body;
    assert!(page.contains(&count(2)), "{page}");
    assert!(!page.contains("type=\"checkbox\""), "{page}");
    assert!(page.contains("projects approve gl &lt;id&gt;"), "{page}");

    let gl = "gitlab=gl&url=https%3A%2F%2Fgitlab.example.com";
    let reply = post(format!("_csrf={csrf}&op=approve-projects&{gl}")).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    // Ticked on a page showing an instance gl elsewhere.
    let stale = "gitlab=gl&url=https%3A%2F%2Felsewhere.example&project=42";
    let reply = post(format!("_csrf={csrf}&op=approve-projects&{stale}")).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply.body.contains("changed since you looked"),
        "{}",
        reply.body
    );
    let reply = post(format!(
        "_csrf={csrf}&op=approve-projects&gitlab=nope&project=42"
    ))
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply.body.contains("no GitLab instance nope"),
        "{}",
        reply.body
    );
    let reply = post(format!("_csrf={csrf}&op=approve-projects&{gl}&project=42")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Approved 1 project(s) of gl."),
        "{}",
        reply.body
    );
    let reply = post(format!("_csrf={csrf}&op=reject-projects&{gl}&project=43")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    audited(
        &hub,
        "rejected project(s) 43 (acme/api) of GitLab instance gl",
    )
    .await;
    let state = |id: u64| {
        (hub.db.gitlab_projects(Some("gl")).unwrap().into_iter())
            .find(|p| p.id == id)
            .map(|p| p.row.state)
    };
    assert_eq!(state(42), Some(ProjectState::Approved));
    assert_eq!(state(43), Some(ProjectState::Rejected));
    let event = next_with(&mut live, "<h2>Rejected</h2>").await;
    assert!(
        event.contains("<section><h2>Pending</h2><p class=\"empty\">"),
        "{event}"
    );
    // The count of approved projects leads to them, listed below the servers.
    assert!(
        event.contains("<td class=\"num\"><a href=\"#projects-approved-gl\">1</a></td>"),
        "approved: {event}"
    );
    let rejected = event.split("<h2>Rejected</h2>").nth(1).unwrap();
    let rejected = rejected.split("<h2>GitLab servers</h2>").next().unwrap();
    assert!(
        rejected.contains("<a href=\"/clients/projects/gl/43\">acme/api</a>"),
        "{rejected}"
    );
    assert!(!rejected.contains("reject-projects"), "{rejected}");
    let approved = event.split("<h2>Approved projects</h2>").nth(1).unwrap();
    let approved = approved.split("<h2>Relays</h2>").next().unwrap();
    for want in [
        "<h3 id=\"projects-approved-gl\">",
        "<td><input id=\"pick-approved-gl-42\"",
        "<td><a href=\"/clients/projects/gl/42\">acme/web</a></td><td class=\"num\">42</td>\
         <td><time",
        "name=\"op\" value=\"reject-projects\">Reject</button>",
        "name=\"op\" value=\"forget-projects\">Forget</button>",
    ] {
        assert!(approved.contains(want), "{want}: {approved}");
    }
    assert!(!approved.contains("approve-projects"), "{approved}");
    assert!(!approved.contains("acme/api"), "{approved}");
    // A viewer sees them listed and linked, with nothing to decide.
    let page = get(addr, "/clients", Some(&viewer)).await.body;
    let listed = page.split("<h2>Approved projects</h2>").nth(1).unwrap();
    let listed = listed.split("<h2>Relays</h2>").next().unwrap();
    assert!(
        listed.contains("<td><a href=\"/clients/projects/gl/42\">acme/web</a></td>"),
        "{listed}"
    );
    assert!(!listed.contains("<form"), "{listed}");
    // A list of projects that does not parse is refused.
    for projects in ["42,x", ""] {
        let reply = post(format!(
            "_csrf={csrf}&op=reject-projects&{gl}&projects={projects}"
        ))
        .await;
        assert_eq!(reply.status, 400, "{projects:?}: {}", reply.body);
    }
    assert_eq!(state(42), Some(ProjectState::Approved));
    let reply = post(format!("_csrf={csrf}&op=forget-projects&{gl}&project=43")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(state(43), None);

    // Another server: rejected, then its rejection forgotten.
    let other = bound_relay(&hub, "bb", "https://other.example");
    let url = "url=https%3A%2F%2Fother.example";
    let reply = post(format!("_csrf={csrf}&op=reject-server&{url}")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("Rejected GitLab server https://other.example.")
    );
    assert_eq!(
        hub.db
            .relay_with_status(&other)
            .unwrap()
            .unwrap()
            .1
            .unwrap()
            .state,
        vk_hub_proto::gitlab::ServerState::Rejected
    );
    let event = next_with(&mut live, "<h2>Rejected</h2><p class=\"sub\">").await;
    assert!(
        event.contains("name=\"op\" value=\"forget-server\""),
        "{event}"
    );
    let reply = post(format!("_csrf={csrf}&op=forget-server&{url}")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    audited(&hub, "forgot rejected GitLab server https://other.example").await;
    assert!(hub.db.rejected_gitlabs().unwrap().is_empty());
    // An approved server is not rejected.
    let reply = post(format!(
        "_csrf={csrf}&op=reject-server&url=https%3A%2F%2Fgitlab.example.com"
    ))
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);

    // An approved project ticked on the list is rejected once asked in the flash's place.
    let reply = post(format!("_csrf={csrf}&op=reject-projects&{gl}&project=42")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Reject these approved projects?"),
        "{}",
        reply.body
    );
    assert_eq!(state(42), Some(ProjectState::Approved));
    let nonce = hidden(&reply.body, "nonce");
    let reply = post(format!(
        "_csrf={csrf}&op=reject-projects&{gl}&projects=42&approved=42&nonce={nonce}&confirm=yes"
    ))
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Rejected 1 project(s) of gl."),
        "{}",
        reply.body
    );
    assert_eq!(state(42), Some(ProjectState::Rejected));
}

/// Rejecting or forgetting an approved project requires confirmation: in the flash for htmx,
/// on a separate page for plain forms. Refuse the answer if the named approved set changes,
/// whether projects gain or lose approval.
#[tokio::test(flavor = "multi_thread")]
async fn deciding_against_approved_projects_is_asked_first() {
    use crate::store::{Decision, ProjectRef, ProjectState};
    let (addr, hub, origin) = start_fleet().await;
    let now = crate::now_secs();
    hub.db
        .add_gitlab("gl", "https://gitlab.example.com", "u", now)
        .unwrap();
    let refs = [
        ProjectRef {
            id: 42,
            path: Some("acme/web".into()),
        },
        ProjectRef { id: 44, path: None },
    ];
    hub.db
        .decide_projects("gl", &refs, Decision::Approve, "alice", now)
        .unwrap();
    let state = |id: u64| {
        (hub.db.gitlab_projects(Some("gl")).unwrap().into_iter())
            .find(|p| p.id == id)
            .map(|p| p.row.state)
    };
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let post = |form: String, htmx: bool| {
        let (origin, operator) = (origin.clone(), operator.clone());
        async move { post_action(addr, &origin, &operator, "/clients", &form, htmx).await }
    };
    let gl = "gitlab=gl&url=https%3A%2F%2Fgitlab.example.com";

    // In the flash's place, and nothing changes until answered.
    let reply = post(
        format!("_csrf={csrf}&op=forget-projects&{gl}&project=44"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    for want in [
        "Forget these approved projects?",
        "<p>Approved, of <strong>gl</strong>: project <code>44</code></p>",
        "name=\"projects\" value=\"44\"",
        "name=\"approved\" value=\"44\"",
    ] {
        assert!(reply.body.contains(want), "{want}: {}", reply.body);
    }
    assert_eq!(state(44), Some(ProjectState::Approved));

    // On a page of its own for a plain form, whose answer leads back to Connections.
    let reply = post(
        format!("_csrf={csrf}&op=reject-projects&{gl}&project=42&project=44"),
        false,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    for want in [
        "<h1>Confirm</h1>",
        "Reject these approved projects?",
        "<p>Approved, of <strong>gl</strong>: acme/web <code>42</code>, project <code>44</code></p>",
        "name=\"projects\" value=\"42,44\"",
        "<a href=\"/clients\">Cancel</a>",
        "<form method=\"post\" action=\"/clients\">",
    ] {
        assert!(reply.body.contains(want), "{want}: {}", reply.body);
    }
    let nonce = hidden(&reply.body, "nonce");
    let reply = post(
        format!(
            "_csrf={csrf}&op=reject-projects&{gl}&projects=42,44&approved=42,44&nonce={nonce}\
             &confirm=yes"
        ),
        false,
    )
    .await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients"));
    assert_eq!(state(42), Some(ProjectState::Rejected));
    assert_eq!(state(44), Some(ProjectState::Rejected));
    audited(
        &hub,
        "rejected project(s) 42 (acme/web), 44 of GitLab instance gl",
    )
    .await;
    hub.db
        .decide_projects("gl", &refs[..1], Decision::Approve, "bob", now)
        .unwrap();

    // Asked of 42 alone, answered once 44 is approved too: refused, and nothing changes.
    let reply = post(
        format!("_csrf={csrf}&op=forget-projects&{gl}&project=42&project=44"),
        true,
    )
    .await;
    assert!(
        reply.body.contains("name=\"approved\" value=\"42\""),
        "{}",
        reply.body
    );
    let nonce = hidden(&reply.body, "nonce");
    hub.db
        .decide_projects("gl", &refs[1..], Decision::Approve, "bob", now)
        .unwrap();
    let confirmed = format!(
        "_csrf={csrf}&op=forget-projects&{gl}&projects=42,44&approved=42&nonce={nonce}&confirm=yes"
    );
    let reply = post(confirmed, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("Refused: it changed since you were asked"),
        "{}",
        reply.body
    );
    assert_eq!(state(42), Some(ProjectState::Approved));
    assert_eq!(state(44), Some(ProjectState::Approved));

    // Asked while approved, answered once rejected since: refused, not forgotten unasked.
    let reply = post(
        format!("_csrf={csrf}&op=forget-projects&{gl}&project=42"),
        true,
    )
    .await;
    let nonce = hidden(&reply.body, "nonce");
    hub.db
        .decide_projects("gl", &refs[..1], Decision::Reject, "bob", now)
        .unwrap();
    let confirmed = format!(
        "_csrf={csrf}&op=forget-projects&{gl}&projects=42&approved=42&nonce={nonce}&confirm=yes"
    );
    let reply = post(confirmed, true).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("Refused: it changed since you were asked"),
        "{}",
        reply.body
    );
    assert_eq!(state(42), Some(ProjectState::Rejected));

    // Not approved: decided on at once.
    let reply = post(
        format!("_csrf={csrf}&op=forget-projects&{gl}&project=42"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Forgot 1 project(s) of gl."),
        "{}",
        reply.body
    );
    assert_eq!(state(42), None);
}

/// Project pages under Connections show the approval record and links to jobs and observed
/// traffic to viewers and operators. Only operators get decision buttons. Rejecting or
/// forgetting an approved project requires confirmation. Plain forms redirect to the project,
/// or Connections after forgetting it. Job pages link to their projects.
#[tokio::test(flavor = "multi_thread")]
async fn a_project_page_shows_and_decides_one_project() {
    use crate::store::{Decision, ProjectRef, ProjectState};
    let (addr, hub, origin) = start_fleet().await;
    let now = crate::now_secs();
    hub.db
        .add_gitlab("gl", "https://gitlab.example.com", "u", now)
        .unwrap();
    let refs = [
        ProjectRef {
            id: 42,
            path: Some("acme/web".into()),
        },
        ProjectRef { id: 44, path: None },
    ];
    hub.db
        .decide_projects("gl", &refs, Decision::Approve, "alice", now)
        .unwrap();
    let state = |id: u64| hub.db.gitlab_project("gl", id).unwrap().map(|p| p.state);
    let page_of = "/clients/projects/gl/42";

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, page_of, Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    for want in [
        // The hub's only instance goes unnamed.
        "<h1>acme/web</h1>",
        "<a href=\"/clients\" aria-current=\"page\">Connections",
        "<tr><th>GitLab ID</th><td>42</td></tr>",
        "<strong>gl</strong> https://gitlab.example.com",
        "<span class=\"badge ok\">approved</span>",
        "<tr><th>Last decided</th><td><time",
        " by alice</td>",
        "<tr><th>Jobs refused</th><td>0</td></tr>",
        "<a href=\"/jobs?project=acme%2Fweb\">Jobs with this path</a>",
        "<a href=\"/egress?tab=observed&amp;project=gitlab%3Agl%3A42\">Observed traffic</a>",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    assert!(!page.body.contains("name=\"op\""), "{}", page.body);
    assert!(!page.body.contains("First job refused"), "{}", page.body);
    let reply = post_action(
        addr,
        &origin,
        &viewer,
        "/clients",
        &format!("_csrf={viewer_csrf}&op=reject-projects&gitlab=gl&project=42&from=project"),
        false,
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    // Known by ID alone: no path, and no jobs to look for by one.
    let page = get(addr, "/clients/projects/gl/44", Some(&viewer)).await;
    assert!(page.body.contains("<h1>project 44</h1>"), "{}", page.body);
    assert!(
        page.body
            .contains("<tr><th>Path</th><td><span class=\"sub\">not known</span>"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("Jobs with this path"), "{}", page.body);
    // Pending since a relay's job of it was refused: the job, and the relay that submitted it.
    let relay = bound_relay(&hub, "aa", "https://gitlab.example.com");
    let job = crate::store::GateJob {
        server_url: "https://gitlab.example.com",
        project_id: 45,
        project_path: "acme/new",
        job_id: 145,
        job_url: Some("https://gitlab.example.com/acme/new/-/jobs/145"),
    };
    hub.db
        .gate_job(&relay, &job, (&"ab".repeat(16), "d"), now)
        .unwrap();
    let page = get(addr, "/clients/projects/gl/45", Some(&viewer)).await;
    for want in [
        "<span class=\"badge warn\">pending</span>",
        "<tr><th>First job refused</th><td><a href=\"https://gitlab.example.com/acme/new/-/jobs/145\"",
        ">#145</a>, submitted by relay relay-1</td>",
        "<tr><th>Jobs refused</th><td>1</td></tr>",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    assert!(!page.body.contains("Last decided"), "{}", page.body);
    for path in [
        "/clients/projects/gl/43",
        "/clients/projects/gl/042",
        "/clients/projects/gl/+42",
        "/clients/projects/gl/0",
        "/clients/projects/GL/42",
        "/clients/projects/gl/42/",
        "/clients/projects/gl",
    ] {
        assert_eq!(get(addr, path, Some(&viewer)).await.status, 404, "{path}");
    }

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, page_of, Some(&operator)).await.body;
    for want in [
        "<h2>Decide</h2><form method=\"post\" action=\"/clients\">",
        "<input type=\"hidden\" name=\"url\" value=\"https://gitlab.example.com\">\
         <input type=\"hidden\" name=\"project\" value=\"42\">\
         <input type=\"hidden\" name=\"from\" value=\"project\">",
        "name=\"op\" value=\"reject-projects\">Reject</button>",
        "name=\"op\" value=\"forget-projects\">Forget</button>",
    ] {
        assert!(page.contains(want), "{want}: {page}");
    }
    assert!(!page.contains("approve-projects"), "{page}");
    let pending = get(addr, "/clients/projects/gl/45", Some(&operator))
        .await
        .body;
    for want in [
        "name=\"op\" value=\"approve-projects\">Approve</button>",
        "name=\"op\" value=\"reject-projects\">Reject</button>",
    ] {
        assert!(pending.contains(want), "{want}: {pending}");
    }
    let post = |form: String| {
        let (origin, operator) = (origin.clone(), operator.clone());
        async move { post_action(addr, &origin, &operator, "/clients", &form, false).await }
    };
    let gl = "gitlab=gl&url=https%3A%2F%2Fgitlab.example.com";

    // Rejecting it, approved, is asked first, and nothing changes until answered.
    let reply = post(format!(
        "_csrf={csrf}&op=reject-projects&{gl}&project=42&from=project"
    ))
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    for want in [
        "<h1>Confirm</h1>",
        "Reject these approved projects?",
        "<p>Approved, of <strong>gl</strong>: acme/web <code>42</code></p>",
        "name=\"projects\" value=\"42\"",
        "name=\"approved\" value=\"42\"",
        "<a href=\"/clients/projects/gl/42\">Cancel</a>",
        // The confirmation page has no flash: it submits a plain form and redirects.
        "<form method=\"post\" action=\"/clients\">",
    ] {
        assert!(reply.body.contains(want), "{want}: {}", reply.body);
    }
    assert_eq!(state(42), Some(ProjectState::Approved));
    let nonce = hidden(&reply.body, "nonce");
    let confirmed = format!(
        "_csrf={csrf}&op=reject-projects&{gl}&projects=42&approved=42&from=project&nonce={nonce}\
         &confirm=yes"
    );
    let reply = post(confirmed).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some(page_of));
    assert_eq!(state(42), Some(ProjectState::Rejected));
    audited(
        &hub,
        "rejected project(s) 42 (acme/web) of GitLab instance gl",
    )
    .await;
    let page = get(addr, page_of, Some(&operator)).await.body;
    assert!(
        page.contains("<span class=\"badge bad\">rejected</span>"),
        "{page}"
    );
    assert!(!page.contains("reject-projects"), "{page}");

    // Approving it again is not asked, and leads back.
    let reply = post(format!(
        "_csrf={csrf}&op=approve-projects&{gl}&project=42&from=project"
    ))
    .await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some(page_of));
    assert_eq!(state(42), Some(ProjectState::Approved));
    // A page decides on its project alone, at the instance it showed.
    let reply = post(format!(
        "_csrf={csrf}&op=approve-projects&{gl}&project=42&project=44&from=project"
    ))
    .await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    let reply = post(format!(
        "_csrf={csrf}&op=approve-projects&gitlab=GL&url=x&project=42&from=project"
    ))
    .await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert!(
        reply.body.contains("not a GitLab instance&#39;s name"),
        "{}",
        reply.body
    );
    let stale = "gitlab=gl&url=https%3A%2F%2Felsewhere.example";
    let reply = post(format!(
        "_csrf={csrf}&op=approve-projects&{stale}&project=44&from=project"
    ))
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);

    // Forgotten once asked: its page is gone, so the answer leads to Connections.
    let reply = post(format!(
        "_csrf={csrf}&op=forget-projects&{gl}&project=42&from=project"
    ))
    .await;
    assert!(
        reply.body.contains("Forget these approved projects?"),
        "{}",
        reply.body
    );
    let nonce = hidden(&reply.body, "nonce");
    let reply = post(format!(
        "_csrf={csrf}&op=forget-projects&{gl}&projects=42&approved=42&from=project&nonce={nonce}\
         &confirm=yes"
    ))
    .await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients"));
    assert_eq!(state(42), None);
    assert_eq!(get(addr, page_of, Some(&operator)).await.status, 404);

    // A job of a project links its page.
    let mut row = history_job(1, "acme/api");
    row.gitlab = Some("gl".into());
    row.project_id = Some(44);
    let id = format!("{:032x}", 1);
    hub.db
        .submit_job(&id, &row, "1", b"{}", "key gitlab", now)
        .unwrap();
    let page = get(addr, &format!("/jobs/{id}"), Some(&viewer)).await.body;
    assert!(
        page.contains("<tr><th>Project</th><td><a href=\"/clients/projects/gl/44\">acme/api</a>"),
        "{page}"
    );
}

/// A placed job's page shows rights per storage area in plain words, with token details
/// folded away and never the token; or the reason it got no access.
#[tokio::test(flavor = "multi_thread")]
async fn a_job_page_says_what_registry_access_the_job_got() {
    use crate::store::{NoAccess, RegistryAccess};
    use crate::tests::tokens::token_registry;
    use vk_hub_proto::client::JobState;
    use vk_hub_proto::token::Grant;
    let (addr, hub, _keys) = start_fleet_keys("job").await;
    let registry = token_registry(&hub, "https://reg.example.com", "c1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let now = crate::now_secs();
    let grant = |prefix: &str, rights: &str| Grant {
        prefix: prefix.into(),
        read: rights.contains('r'),
        write: rights.contains('w'),
        lock: rights.contains('l'),
    };
    let job = |n: u64, access| {
        let mut row = history_job(n, "wab/core");
        row.state = JobState::Running;
        row.registry_access = Some(access);
        let id = format!("{n:032x}");
        hub.db
            .submit_job(&id, &row, &n.to_string(), b"{}", "key gitlab", now)
            .unwrap();
        id
    };
    let issued = job(
        1,
        RegistryAccess::Issued {
            registry: registry.clone(),
            grants: vec![
                grant("ci-cache/gl/42/protected", "rw"),
                grant("ci-pipeline/gl/42/7", "rwl"),
                grant("gone", "r"),
            ],
            expires_at: now + 3600,
            jti: "0b6e5d00000000000000000000001a7".into(),
        },
    );
    let body = get(addr, &format!("/jobs/{issued}"), Some(&viewer))
        .await
        .body;
    for want in [
        "<h2>Registry access</h2>",
        &format!(
            "<span class=\"badge ok\">Issued</span> for <a href=\"/registry/{registry}?tab=access\">reg-1</a>"
        ),
        "<li>CI caches: <strong>Read, Publish</strong></li>",
        "<li>Pipeline storage: <strong>Read, Publish, Coordinate builds</strong></li>",
        "<li>gone: <strong>Read</strong></li>",
        "<summary>Technical details</summary>",
        "<code>ci-pipeline/gl/42/7</code> rwl",
        "0b6e5d00000000000000000000001a7",
        "never stored or shown",
    ] {
        assert!(body.contains(want), "{want}: {body}");
    }
    assert!(!body.contains("vkt_"), "{body}");
    let none = |n, reason, registry: Option<&str>, url: Option<&str>| {
        job(
            n,
            RegistryAccess::None {
                reason,
                registry: registry.map(str::to_string),
                url: url.map(str::to_string),
            },
        )
    };
    for (id, want) in [
        (
            none(2, NoAccess::UnboundKey, None, None),
            "no longer approved. <a href=\"/clients\">Connections</a>",
        ),
        (
            none(3, NoAccess::NodeWithoutJobTokens, None, None),
            "does not announce job tokens",
        ),
        (
            none(
                4,
                NoAccess::UnknownRegistry,
                None,
                Some("http://10.0.0.9:5000"),
            ),
            "<code>http://10.0.0.9:5000</code>, an address no registry is bound to",
        ),
        (
            none(5, NoAccess::RegistryTakesNoTokens, Some(&registry), None),
            "reg-1</a> does not take the hub's tokens",
        ),
        (
            none(6, NoAccess::NoAppliedKey, Some(&registry), None),
            "?tab=settings\">reg-1</a> had applied no signing key yet",
        ),
        (
            none(7, NoAccess::MintFailed, None, None),
            "Minting its token failed",
        ),
    ] {
        let body = get(addr, &format!("/jobs/{id}"), Some(&viewer)).await.body;
        assert!(
            body.contains("<span class=\"badge warn\">Unavailable</span>") && body.contains(want),
            "{want}: {body}"
        );
    }
    // What a registry reports, and the address a node reported, are escaped.
    let inventory = vk_hub_proto::registry::Inventory {
        hostname: "<script>alert(1)</script>".into(),
        tokens: true,
        ..Default::default()
    };
    hub.db
        .record_registry(
            &registry,
            crate::store::RegistryWrite::Inventory(inventory),
            now,
        )
        .unwrap();
    for id in [
        issued.clone(),
        none(
            9,
            NoAccess::UnknownRegistry,
            None,
            Some("http://<script>alert(1)</script>"),
        ),
    ] {
        let body = get(addr, &format!("/jobs/{id}"), Some(&viewer)).await.body;
        assert!(body.contains("&lt;script&gt;alert(1)"), "{body}");
        assert!(!body.contains("<script>"), "{body}");
    }
    // A job placed by an older hub, or not yet, has no such section.
    let mut row = history_job(8, "wab/core");
    row.state = JobState::Queued;
    let old = format!("{:032x}", 8);
    hub.db
        .submit_job(&old, &row, "8", b"{}", "key gitlab", now)
        .unwrap();
    let body = get(addr, &format!("/jobs/{old}"), Some(&viewer)).await.body;
    assert!(!body.contains("Registry access"), "{body}");
}

/// Job `n` of `project` (`gitlab:gl:<project_id>`), ended on `node` with `report`, recorded as
/// the hub records one.
fn egress_job(
    hub: &Hub,
    n: u64,
    project_id: u64,
    node: &str,
    report: vk_hub_proto::egress::EgressReport,
) -> String {
    let id = format!("{n:032x}");
    let mut row = crate::egress::testing::job(n, report);
    row.node = Some(node.to_string());
    row.gitlab = Some("gl".into());
    row.project_id = Some(project_id);
    row.project = Some(format!("acme/p{project_id}"));
    row.protected = Some(true);
    let mut queued = row.clone();
    queued.result = None;
    hub.db
        .submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
        .unwrap();
    assert!(hub.db.put_job(&id, &row, &[], 11).unwrap());
    id
}

/// Two jobs' blocked destination, each with the evidence its node recorded.
fn blocked_report(dest: &str, count: u64) -> vk_hub_proto::egress::EgressReport {
    use vk_hub_proto::egress::*;
    EgressReport {
        entries: vec![EgressEntry {
            count,
            ..crate::egress::testing::entry(
                EgressOutcome::Blocked,
                EgressProtocol::Dns,
                EgressDestination::domain(dest),
                Some(EgressLayer::NodeCap),
            )
        }],
        ..EgressReport::default()
    }
}

/// The Egress page lists what jobs were refused by destination and project, as text, the
/// views apart with their counts; a row's page shows its latest jobs and where to allow it;
/// the navigation counts the New rows; nodes without reporting are named.
#[tokio::test(flavor = "multi_thread")]
async fn the_egress_page_lists_denials_by_destination_and_project() {
    use vk_hub_proto::egress::*;
    let (addr, hub, _) = start_fleet().await;
    hub.db
        .add_gitlab("gl", "https://gl.example.com", "uid 0", 1)
        .unwrap();
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let empty = get(addr, "/egress", Some(&viewer)).await;
    assert_eq!(empty.status, 200, "{}", empty.body);
    assert!(empty.body.contains("nothing refused yet"), "{}", empty.body);
    assert!(!empty.body.contains("class=\"count\""));

    let a = egress_job(&hub, 1, 42, &node, blocked_report("crates.io", 2));
    let b = egress_job(&hub, 2, 42, &node, blocked_report("crates.io", 3));
    let mut refused = blocked_report("pypi.org", 1);
    refused.refusals.push(EgressRefusal {
        variable: "MICROVM_EGRESS_ALLOW_NAME".into(),
        entry: "<script>x</script>".into(),
        dimension: EgressDimension::Name,
        phase: EgressPhase::Run,
        source: EgressSource::Job,
        layer: Some(EgressLayer::NodeCap),
        reason: RefusalReason::InvalidEntry,
    });
    let c = egress_job(&hub, 3, 7, &node, refused);

    let page = get(addr, "/egress", Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let body = &page.body;
    assert!(body.contains("<code>DNS crates.io</code>"), "{body}");
    // The hub's only instance goes unnamed.
    assert!(body.contains("\">acme/p42</a>"), "{body}");
    assert!(!body.contains("[gl]"), "{body}");
    assert!(body.contains("Blocked (2)") && body.contains("Declaration issues (1)"));
    assert!(body.contains("the node&#39;s cap"), "{body}");
    // Three New rows: two destinations and a declaration.
    assert!(
        body.contains("Egress<span id=\"nav-count-egress\"> <span class=\"count\">3</span></span>"),
        "{body}"
    );
    assert!(!body.contains("<script>x"));

    let refusals = get(addr, "/egress?view=refused", Some(&viewer)).await.body;
    assert!(
        refusals.contains("MICROVM_EGRESS_ALLOW_NAME &lt;script&gt;x&lt;/script&gt;"),
        "{refusals}"
    );
    assert!(!refusals.contains("crates.io</code>"));
    // By project, by job.
    let p7 = get(addr, "/egress?project=gitlab%3Agl%3A7", Some(&viewer))
        .await
        .body;
    assert!(
        p7.contains("pypi.org") && !p7.contains("crates.io</code>"),
        "{p7}"
    );
    let of_a = get(addr, &format!("/egress?job={a}"), Some(&viewer))
        .await
        .body;
    assert!(
        of_a.contains("crates.io") && !of_a.contains("pypi.org"),
        "{of_a}"
    );
    let of_c = get(addr, &format!("/egress?job={c}&layer=job"), Some(&viewer))
        .await
        .body;
    assert!(of_c.contains("none match"), "{of_c}");

    // A row's page: its jobs, latest first, and where to allow it.
    let subject = crate::egress::blocked::Subject::Gitlab {
        instance: "gl".into(),
        project_id: 42,
    };
    let finding = crate::egress::blocked::Finding::Denial {
        view: crate::egress::blocked::View::Blocked,
        protocol: EgressProtocol::Dns,
        destination: EgressDestination::domain("crates.io"),
    };
    let row = crate::egress::blocked::row_id(&subject, &finding);
    let detail = get(addr, &format!("/egress/rows/{row}"), Some(&viewer)).await;
    assert_eq!(detail.status, 200, "{}", detail.body);
    let body = &detail.body;
    assert!(body.contains("2 in the history"), "{body}");
    assert!(
        body.contains("<code>[egress] allow_name</code> on node ci-1"),
        "{body}"
    );
    assert!(body.contains("main (protected)"), "{body}");
    assert!(body.contains("effect on it is unknown"), "{body}");
    let (at_a, at_b) = (body.find(&a).unwrap(), body.find(&b).unwrap());
    assert!(at_b < at_a, "the latest first: {body}");
    let unknown = format!("/egress/rows/{}", "0".repeat(32));
    assert_eq!(get(addr, &unknown, Some(&viewer)).await.status, 404);
    // A job's page and its row in the Jobs table link to its rows.
    let job = get(addr, &format!("/jobs/{a}"), Some(&viewer)).await.body;
    assert!(
        job.contains(&format!("<a href=\"/egress/rows/{row}\">")),
        "{job}"
    );
    let jobs = get(addr, "/jobs", Some(&viewer)).await.body;
    assert!(
        jobs.contains(&format!(
            "<a href=\"/egress?view=refused&amp;state=all&amp;job={c}\">"
        )),
        "{jobs}"
    );

    // A node taking placed jobs without reporting is named; once it reports, it is not.
    hub.db
        .set_pools(&node, &["ci".to_string()], "uid 0", crate::now_secs())
        .unwrap();
    let inventory = vk_hub_proto::Inventory {
        hostname: "ci-1".into(),
        ..Default::default()
    };
    hub.db
        .record_inventory(&node, inventory.clone(), true, 2)
        .unwrap();
    let body = get(addr, "/egress", Some(&viewer)).await.body;
    assert!(
        body.contains("Reporting unavailable on <a href=\"/node/") && body.contains(">ci-1</a>"),
        "{body}"
    );
    let reporting = vk_hub_proto::Inventory {
        egress_reports: true,
        ..inventory
    };
    hub.db.record_inventory(&node, reporting, true, 3).unwrap();
    let body = get(addr, "/egress", Some(&viewer)).await.body;
    assert!(!body.contains("Reporting unavailable"), "{body}");

    // With a second instance, each project names its own.
    hub.db
        .add_gitlab("gl2", "https://gl2.example.com", "uid 0", 4)
        .unwrap();
    let body = get(addr, "/egress", Some(&viewer)).await.body;
    assert!(body.contains("\">acme/p42 [gl]</a>"), "{body}");
    assert!(body.contains(">acme/p42 [gl]</option>"), "{body}");
}

/// The Egress page's rows and their views' counts follow its filter over SSE, the filter's form
/// outside what is swapped in: a running job's report adds to them as it comes, and a triage
/// moves a row out of the inbox. The navigation's count follows on every live page.
#[tokio::test(flavor = "multi_thread")]
async fn the_egress_page_s_rows_follow_the_jobs_reports() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    egress_job(&hub, 1, 42, &node, blocked_report("crates.io", 2));
    let page = get(addr, "/egress?project=gitlab%3Agl%3A42", Some(&operator))
        .await
        .body;
    let swapped = "<div id=\"egress-results\"><div hx-ext=\"sse\" \
                sse-connect=\"/events/egress?project=gitlab%3Agl%3A42\" sse-swap=\"egress\" \
                sse-close=\"close\">";
    let (at_form, at_live) = (
        page.find("<form id=\"egress-filter\"").unwrap(),
        page.find(swapped).expect(&page),
    );
    assert!(at_form < at_live, "the form is outside the swapped part");
    assert!(!page[at_live..].contains("<form"), "{page}");

    let mut stream = live(addr, "/events/egress?project=gitlab%3Agl%3A42", &operator).await;
    let mut nodes = live(addr, "/events/nodes", &operator).await;
    let count = |n: u64| {
        format!(
            "<span id=\"nav-count-egress\" hx-swap-oob=\"true\"> <span class=\"count\">{n}</span></span>"
        )
    };
    // A running job of the project reports a denial: its row and the view's count appear.
    let id = format!("{:032x}", 2);
    let mut running = crate::egress::testing::job(2, Default::default());
    running.result = None;
    running.finished_at = None;
    running.state = vk_hub_proto::client::JobState::Running;
    running.node = Some(node.clone());
    running.gitlab = Some("gl".into());
    running.project_id = Some(42);
    hub.db
        .submit_job(&id, &running, &id, b"{}", "key gitlab", 10)
        .unwrap();
    running.revision += 1;
    running.egress = Some(blocked_report("pypi.org", 1));
    assert!(hub.db.put_job(&id, &running, &[], 11).unwrap());
    hub.jobs_changed();
    let event = next_with(&mut stream, "pypi.org").await;
    assert!(event.starts_with("event: egress\n"), "{event}");
    assert!(event.contains("Blocked (2)"), "{event}");
    assert!(event.contains(&count(2)), "the navigation's count: {event}");
    // Every live page keeps it current.
    next_with(&mut nodes, &count(2)).await;
    // Acknowledged, a row leaves the inbox.
    let rows = hub.db.egress_rows().unwrap();
    let (pypi, _) = rows
        .iter()
        .find(|(_, r)| r.finding.text().ends_with("pypi.org"))
        .unwrap();
    let form = format!("_csrf={csrf}&row={pypi}&op=acknowledge");
    let done = post_action(addr, &origin, &operator, "/egress/action", &form, false).await;
    assert_eq!(done.status, 303, "{}", done.body);
    let event = next_with(&mut stream, "Blocked (1)").await;
    assert!(!event.contains("pypi.org"), "{event}");
    assert!(event.contains(&count(1)), "{event}");
}

/// The Egress page's Observed traffic tab lists each project with how completely its jobs
/// reported, and one project's destinations by phase, with their refs, latest job and the
/// Blocked rows of the same destination; filtered by phase and protection, and following the
/// jobs' reports over SSE.
#[tokio::test(flavor = "multi_thread")]
async fn the_egress_page_s_observed_traffic_lists_each_project_s_destinations() {
    use vk_hub_proto::egress::*;
    let (addr, hub, _) = start_fleet().await;
    hub.db
        .add_gitlab("gl", "https://gl.example.com", "uid 0", 1)
        .unwrap();
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let empty = get(addr, "/egress?tab=observed", Some(&viewer)).await;
    assert_eq!(empty.status, 200, "{}", empty.body);
    assert!(
        empty.body.contains("nothing observed yet"),
        "{}",
        empty.body
    );
    assert!(
        empty.body.contains(
            "<a href=\"/egress?tab=observed\" aria-current=\"page\">Observed traffic</a>"
        ),
        "{}",
        empty.body
    );

    // A project whose jobs sent no report is not listed, nor offered by the filter.
    let silent_job = |n: u64, project_id: u64| {
        let id = format!("{n:032x}");
        let mut row = crate::egress::testing::job(n, EgressReport::default());
        row.result.as_mut().unwrap().egress = None;
        row.node = Some(node.to_string());
        row.gitlab = Some("gl".into());
        row.project_id = Some(project_id);
        row.project = Some(format!("acme/p{project_id}"));
        let mut queued = row.clone();
        queued.result = None;
        hub.db
            .submit_job(&id, &queued, &id, b"{}", "key gitlab", 10)
            .unwrap();
        assert!(hub.db.put_job(&id, &row, &[], 11).unwrap());
    };
    silent_job(9, 9);
    let subjects = hub.db.observed_subjects().unwrap();
    assert!(
        subjects
            .iter()
            .any(|(p, s)| p == "gitlab:gl:9" && s.unreported == 1),
        "{subjects:?}"
    );
    let empty = get(addr, "/egress?tab=observed", Some(&viewer)).await.body;
    assert!(empty.contains("nothing observed yet"), "{empty}");
    assert!(!empty.contains("acme/p9"), "{empty}");
    // An explicitly selected project keeps its name and summary.
    let p9 = get(
        addr,
        "/egress?tab=observed&project=gitlab%3Agl%3A9",
        Some(&viewer),
    )
    .await
    .body;
    assert!(p9.contains("<h2>acme/p9</h2>"), "{p9}");
    assert!(
        p9.contains("<option value=\"gitlab:gl:9\" selected>acme/p9</option>"),
        "{p9}"
    );

    let reached = |dest: &str| EgressEntry {
        count: 2,
        ..crate::egress::testing::entry(
            EgressOutcome::Observed,
            EgressProtocol::Dns,
            EgressDestination::domain(dest),
            None,
        )
    };
    let mut report = blocked_report("crates.io", 1);
    report.entries.push(reached("crates.io"));
    report.entries.push(EgressEntry {
        phase: EgressPhase::Build,
        ..reached("<b>.example")
    });
    report.phases = vec![
        crate::egress::testing::phase(EgressPhase::Run, EgressCoverage::Complete),
        crate::egress::testing::phase(EgressPhase::Build, EgressCoverage::Partial),
    ];
    let a = egress_job(&hub, 1, 42, &node, report);
    let mut later = EgressReport {
        entries: vec![reached("crates.io")],
        phases: vec![crate::egress::testing::phase(
            EgressPhase::Run,
            EgressCoverage::Complete,
        )],
        ..EgressReport::default()
    };
    later.entries[0].last_seen_ms = 2_000_000;
    let b = egress_job(&hub, 2, 42, &node, later);
    // A job that sent no report leaves a project with reports listed.
    silent_job(8, 42);

    let list = get(addr, "/egress?tab=observed", Some(&viewer)).await.body;
    assert!(
        list.contains("<a href=\"/egress?tab=observed&amp;project=gitlab%3Agl%3A42\">acme/p42</a>"),
        "{list}"
    );
    assert!(
        list.contains(
            "Run: 2 of 2 jobs reported this phase completely · Build: 0 of 1 job reported this \
             phase completely · 1 job sent no report"
        ),
        "{list}"
    );
    assert!(!list.contains("acme/p9"), "{list}");

    let p42 = "/egress?tab=observed&project=gitlab%3Agl%3A42";
    let page = get(addr, p42, Some(&viewer)).await.body;
    // The hub's only instance goes unnamed.
    assert!(page.contains("<h2>acme/p42</h2>"), "{page}");
    assert!(
        page.contains("<code>DNS crates.io</code> <span class=\"sub\">lookup</span>"),
        "{page}"
    );
    assert!(page.contains("main (protected) ×2"), "{page}");
    // The latest job of the destination, by its last attempt.
    assert!(page.contains(&format!("<a href=\"/jobs/{b}\">")), "{page}");
    // Refused too, in another job: the Blocked row.
    let blocked = crate::egress::blocked::row_id(
        &crate::egress::blocked::Subject::Gitlab {
            instance: "gl".into(),
            project_id: 42,
        },
        &crate::egress::blocked::Finding::Denial {
            view: crate::egress::blocked::View::Blocked,
            protocol: EgressProtocol::Dns,
            destination: EgressDestination::domain("crates.io"),
        },
    );
    assert!(
        page.contains(&format!(
            "<a href=\"/egress/rows/{blocked}\">Blocked</a> (1 job)"
        )),
        "{page}"
    );
    assert!(page.contains("A DNS entry is a lookup, not proof of a connection."));
    assert!(!page.contains("<b>"), "escaped: {page}");
    let run = get(addr, &format!("{p42}&phase=run"), Some(&viewer))
        .await
        .body;
    assert!(
        run.contains("crates.io") && !run.contains(".example"),
        "{run}"
    );
    let unprotected = get(
        addr,
        &format!("{p42}&protection=unprotected"),
        Some(&viewer),
    )
    .await
    .body;
    assert!(unprotected.contains("none match"), "{unprotected}");
    // The row's page links to its project's observed traffic.
    let row = get(addr, &format!("/egress/rows/{blocked}"), Some(&viewer))
        .await
        .body;
    assert!(
        row.contains("<a href=\"/egress?tab=observed&amp;project=gitlab%3Agl%3A42\">"),
        "{row}"
    );

    // Live: a third job's destination appears.
    let mut stream = live(
        addr,
        "/events/egress?tab=observed&project=gitlab%3Agl%3A42",
        &viewer,
    )
    .await;
    egress_job(
        &hub,
        3,
        42,
        &node,
        EgressReport {
            entries: vec![reached("pypi.org")],
            ..EgressReport::default()
        },
    );
    hub.jobs_changed();
    let event = next_with(&mut stream, "pypi.org").await;
    assert!(event.starts_with("event: egress\n"), "{event}");
    assert!(
        event.contains(&a[..8]) || event.contains(&b[..8]),
        "{event}"
    );
    // With a second instance, each project names its own.
    hub.db
        .add_gitlab("gl2", "https://gl2.example.com", "uid 0", 5)
        .unwrap();
    let page = get(addr, p42, Some(&viewer)).await.body;
    assert!(page.contains("<h2>acme/p42 [gl]</h2>"), "{page}");
}

/// An operator acknowledges a row and mutes its project from the row's page, each audited as a
/// person's action; the inbox and the navigation's count follow, a later job reopens the row,
/// and a muted project's rows stay listed under Muted. A viewer gets no form and is refused.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_triages_and_mutes_egress_rows() {
    let (addr, hub, origin) = start_fleet().await;
    hub.db
        .add_gitlab("gl", "https://gl.example.com", "uid 0", 1)
        .unwrap();
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    egress_job(&hub, 1, 42, &node, blocked_report("crates.io", 2));
    egress_job(&hub, 2, 7, &node, blocked_report("pypi.org", 1));
    let rows = hub.db.egress_rows().unwrap();
    let id_of = |dest: &str| {
        rows.iter()
            .find(|(_, r)| r.finding.text().ends_with(dest))
            .unwrap()
            .0
            .clone()
    };
    let (crates, pypi) = (id_of("crates.io"), id_of("pypi.org"));
    let row_page = format!("/egress/rows/{crates}");

    let seen = get(addr, &row_page, Some(&viewer)).await.body;
    assert!(seen.contains("New: no one has acknowledged it."), "{seen}");
    assert!(!seen.contains("/egress/action"), "{seen}");
    let form = format!("_csrf={viewer_csrf}&row={crates}&op=acknowledge");
    let refused = post_action(addr, &origin, &viewer, "/egress/action", &form, false).await;
    assert_eq!(refused.status, 403, "{}", refused.body);

    let page = get(addr, &row_page, Some(&operator)).await.body;
    assert!(page.contains("<button>Acknowledge</button>"), "{page}");
    assert!(
        page.contains("<button>Mute this project</button>"),
        "{page}"
    );
    let form = format!("_csrf={csrf}&row={crates}&op=acknowledge");
    let done = post_action(addr, &origin, &operator, "/egress/action", &form, false).await;
    assert_eq!(done.status, 303, "{}", done.body);
    assert_eq!(done.header("location"), Some(row_page.as_str()));
    let page = get(addr, &row_page, Some(&operator)).await.body;
    assert!(page.contains("Acknowledged by ui session"), "{page}");
    assert!(page.contains("<button>Reopen</button>"), "{page}");
    let inbox = get(addr, "/egress", Some(&operator)).await.body;
    assert!(!inbox.contains("crates.io</code>") && inbox.contains("pypi.org</code>"));
    assert!(
        inbox
            .contains("Egress<span id=\"nav-count-egress\"> <span class=\"count\">1</span></span>"),
        "{inbox}"
    );
    let acked = get(addr, "/egress?state=acknowledged", Some(&operator))
        .await
        .body;
    assert!(acked.contains("crates.io</code>") && !acked.contains("pypi.org</code>"));

    // A later job of the project reopens it.
    egress_job(&hub, 3, 42, &node, blocked_report("crates.io", 1));
    let page = get(addr, &row_page, Some(&operator)).await.body;
    assert!(page.contains("New again: acknowledged by"), "{page}");

    // Muting project 7 takes its row out of the inbox and the count, not out of the page.
    let pypi_page = format!("/egress/rows/{pypi}");
    for bad in ["&reason=+&for=7", "&reason=x&for=9"] {
        let form = format!("_csrf={csrf}&row={pypi}&op=mute{bad}");
        let reply = post_action(addr, &origin, &operator, "/egress/action", &form, false).await;
        assert_eq!(reply.status, 400, "{bad}: {}", reply.body);
    }
    let form = format!("_csrf={csrf}&row={pypi}&op=mute&reason=a+known+mirror&for=30");
    let done = post_action(addr, &origin, &operator, "/egress/action", &form, false).await;
    assert_eq!(done.status, 303, "{}", done.body);
    let inbox = get(addr, "/egress", Some(&viewer)).await.body;
    assert!(!inbox.contains("pypi.org</code>") && inbox.contains("crates.io</code>"));
    assert!(
        inbox
            .contains("Egress<span id=\"nav-count-egress\"> <span class=\"count\">1</span></span>"),
        "{inbox}"
    );
    assert!(
        inbox.contains(
            "<li><a href=\"/egress?state=muted&amp;project=gitlab%3Agl%3A7\">\
             acme/p7</a> until"
        ),
        "{inbox}"
    );
    assert!(inbox.contains("(a known mirror)"), "{inbox}");
    let muted = get(addr, "/egress?state=muted", Some(&viewer)).await.body;
    assert!(muted.contains("pypi.org</code>") && muted.contains(">Muted</span>"));
    let page = get(addr, &pypi_page, Some(&operator)).await.body;
    assert!(
        page.contains("This project is muted by ui session"),
        "{page}"
    );
    let form = format!("_csrf={csrf}&row={pypi}&op=unmute");
    let done = post_action(addr, &origin, &operator, "/egress/action", &form, false).await;
    assert_eq!(done.status, 303, "{}", done.body);
    let inbox = get(addr, "/egress", Some(&viewer)).await.body;
    assert!(
        inbox
            .contains("Egress<span id=\"nav-count-egress\"> <span class=\"count\">2</span></span>"),
        "{inbox}"
    );
    // A mute is also undone from the list, by its subject, as its rows may be gone.
    let form = format!("_csrf={csrf}&row={pypi}&op=mute&reason=again&for=never");
    post_action(addr, &origin, &operator, "/egress/action", &form, false).await;
    let listed = get(addr, "/egress", Some(&operator)).await.body;
    assert!(
        listed.contains("name=\"subject\" value=\"gitlab:gl:7\""),
        "{listed}"
    );
    let seen = get(addr, "/egress", Some(&viewer)).await.body;
    assert!(!seen.contains("name=\"subject\""), "{seen}");
    let form = format!("_csrf={csrf}&op=unmute&subject=gitlab%3Agl%3A7");
    let done = post_action(addr, &origin, &operator, "/egress/action", &form, false).await;
    assert_eq!(done.status, 303, "{}", done.body);
    assert_eq!(done.header("location"), Some("/egress"));
    assert!(hub.db.egress_mutes(crate::now_secs()).unwrap().is_empty());

    // Each audited as a person's action.
    let people = crate::store::AuditFilter {
        category: crate::store::AuditCategory::People,
        text: Some("egress".into()),
        ..Default::default()
    };
    let found = hub.db.audit_search(&people, None, 10).unwrap();
    let lines: Vec<&str> = found.rows.iter().map(|(_, r)| r.event.as_str()).collect();
    assert_eq!(lines.len(), 5, "{lines:?}");
    for unmuted in [lines[0], lines[2]] {
        assert!(
            unmuted.ends_with("unmuted egress of acme/p7 on gl"),
            "{lines:?}"
        );
    }
    assert!(lines[1].ends_with("until unmuted: again"), "{lines:?}");
    assert!(
        lines[3].contains("muted egress of acme/p7 on gl until "),
        "{lines:?}"
    );
    assert!(lines[3].ends_with(": a known mirror"), "{lines:?}");
    assert!(
        lines[4].ends_with("acknowledged egress blocked DNS crates.io for acme/p42 on gl"),
        "{lines:?}"
    );
}

/// Egress rule `name` stored as `uid 1`'s: `subject` none for the Fallback.
fn egress_rule(
    hub: &Hub,
    name: &str,
    subject: Option<&str>,
    run: vk_hub_proto::egress::HubPhase,
    build: vk_hub_proto::egress::HubPhase,
    mode: crate::store::RuleMode,
) {
    let change = crate::store::RuleChange {
        name: name.into(),
        subject: subject.map(|s| crate::subject::Subject::parse(s).unwrap()),
        run: Some(run),
        build: Some(build),
        mode: Some(mode),
    };
    hub.db
        .put_egress_rule(&change, false, "uid 1", crate::now_secs())
        .unwrap();
}

fn allow(names: &[&str], ips: &[&str]) -> vk_hub_proto::egress::HubPhase {
    vk_hub_proto::egress::HubPhase::Allow {
        names: names.iter().map(|s| s.to_string()).collect(),
        ips: ips.iter().map(|s| s.to_string()).collect(),
    }
}

/// The Rules tab lists the rules in plain words, the Fallback apart, with the recent jobs
/// placed under each; it says that rules off restrict nothing, and warns of rules on with no
/// enforced Fallback. A rule's page lists its entries.
#[tokio::test(flavor = "multi_thread")]
async fn the_rules_tab_lists_the_rules_in_plain_words() {
    use crate::store::RuleMode;
    use vk_hub_proto::egress::HubPhase;
    let (addr, hub, _) = start_fleet().await;
    hub.db
        .add_gitlab("gl", "https://gl.example.com", "uid 0", 1)
        .unwrap();
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let empty = get(addr, "/egress?tab=rules", Some(&viewer)).await;
    assert_eq!(empty.status, 200, "{}", empty.body);
    assert!(empty.body.contains("no rules yet"), "{}", empty.body);
    assert!(
        empty
            .body
            .contains("<a href=\"/egress?tab=rules\" aria-current=\"page\">Rules</a>"),
        "{}",
        empty.body
    );

    egress_rule(
        &hub,
        "wab",
        Some("gitlab gl, projects wab/**, protected"),
        allow(&["corp.example.com"], &["10.10.140.49/32"]),
        allow(&["debian.org", "crates.io", "pypi.org"], &[]),
        RuleMode::Enforce,
    );
    egress_rule(
        &hub,
        "wab-release",
        Some("gitlab gl, projects wab/**, ref release/*, protected"),
        allow(&["partner.example.net"], &[]),
        HubPhase::Unrestricted,
        RuleMode::DryRun,
    );
    egress_rule(
        &hub,
        crate::store::DEFAULT_RULE,
        None,
        allow(&[], &[]),
        allow(&["debian.org"], &[]),
        RuleMode::Enforce,
    );
    // Two jobs placed under wab, one of them also selected by wab-release, which would have
    // blocked a destination of it.
    use vk_hub_proto::egress::*;
    let mut would = blocked_report("x.example", 1);
    would.entries[0].outcome = EgressOutcome::WouldBlock;
    would.entries[0].layer = Some(EgressLayer::HubRule);
    would.entries[0].rule = Some("wab-release".into());
    for (n, report, dry) in [(1, EgressReport::default(), false), (2, would, true)] {
        let id = egress_job(&hub, n, 42, &node, report);
        let mut row = hub.db.job(&id).unwrap().unwrap();
        row.created_at = crate::now_secs();
        row.egress_rules = Some(crate::store::EgressRulesApplied {
            rules: vec!["wab".into()],
            dry_run: if dry {
                vec!["wab-release".into()]
            } else {
                vec![]
            },
            generation: 3,
        });
        row.revision += 1;
        assert!(hub.db.put_job(&id, &row, &[], 12).unwrap());
    }

    let tab = get(addr, "/egress?tab=rules", Some(&viewer)).await.body;
    assert!(tab.contains("<strong>Hub rules are off.</strong> Saved rules restrict nothing yet"));
    assert!(
        tab.contains("<code>[jobs] egress_rules = true</code>"),
        "{tab}"
    );
    assert!(
        tab.contains(
            "<td>Projects under wab/, protected branches and tags only</td>\
             <td>corp.example.com + 1 IP range</td><td>3 domains</td>\
             <td><span class=\"badge ok\">Enforce</span></td><td>2 jobs</td>"
        ),
        "{tab}"
    );
    assert!(
        tab.contains(
            "<td>partner.example.net</td><td>Unrestricted by this rule</td>\
             <td><span class=\"badge warn\">Dry-run</span></td><td>1 job · 1 would block</td>"
        ),
        "{tab}"
    );
    let (list, fallback) = tab.split_once("<h2>Fallback</h2>").unwrap();
    assert!(!list.contains("Fallback</strong>"), "{tab}");
    assert!(
        fallback.contains(
            "<strong>Fallback</strong></a></td><td>Jobs no enforced rule selects, and every \
             gitlab-runner job</td><td>No external access</td><td>debian.org</td>"
        ),
        "{tab}"
    );

    // The rollout, step by step, as far as the hub can tell.
    assert!(tab.contains("<a href=\"/egress?tab=rules#rollout\">How to turn them on safely</a>"));
    for step in [
        "<span class=\"badge\">To do</span> <span class=\"sub\">no job reported a phase \
         completely in the last 30 days</span>",
        "<span class=\"badge warn\">Check</span> <span class=\"sub\">enforced but narrowed: \
         turning rules on restricts every job no enforced rule selects</span>",
        "<span class=\"badge\">To do</span> <span class=\"sub\">hub rules are off</span>",
        "<span class=\"sub\">in dry-run, last 7 days: wab-release: 1 job · 1 would block</span>",
        "<span class=\"sub\">1 project rules enforced, 1 in dry-run</span>",
        "<span class=\"badge ok\">Done</span> <span class=\"sub\">the Fallback restricts what \
         it applies to</span>",
    ] {
        assert!(tab.contains(step), "{step}: {tab}");
    }

    let page = get(addr, "/egress?tab=rules&rule=wab", Some(&viewer))
        .await
        .body;
    assert!(
        page.contains("<tr><th>Domains</th><td><code>corp.example.com</code></td></tr>"),
        "{page}"
    );
    let page = get(addr, "/egress?tab=rules&rule=default", Some(&viewer))
        .await
        .body;
    assert!(page.contains("Allow none: no external access."), "{page}");
    let missing = get(addr, "/egress?tab=rules&rule=nope", Some(&viewer)).await;
    assert_eq!(missing.status, 404);

    // With a second instance, a rule names its own, and one of none every server.
    hub.db
        .add_gitlab("gl2", "https://gl2.example.com", "uid 0", 2)
        .unwrap();
    egress_rule(
        &hub,
        "any",
        Some("protected"),
        allow(&["example.org"], &[]),
        HubPhase::Unrestricted,
        RuleMode::DryRun,
    );
    let tab = get(addr, "/egress?tab=rules", Some(&viewer)).await.body;
    assert!(
        tab.contains("<td>Projects under wab/ [gl], protected branches and tags only</td>"),
        "{tab}"
    );
    assert!(
        tab.contains("<td>Every job [every server], protected branches and tags only</td>"),
        "{tab}"
    );

    // On, with no enforced Fallback: a warning.
    let (addr, hub, _) = start_fleet_rules(true).await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    egress_rule(
        &hub,
        "wab",
        Some("gitlab gl, projects wab/**"),
        HubPhase::Unrestricted,
        HubPhase::Unrestricted,
        RuleMode::Enforce,
    );
    let tab = get(addr, "/egress?tab=rules", Some(&viewer)).await.body;
    assert!(!tab.contains("Hub rules are off"), "{tab}");
    assert!(
        tab.contains("<p class=\"callout warn\">No Fallback is enforced: every job no enforced"),
        "{tab}"
    );
    assert!(
        tab.contains(
            "<span class=\"badge warn\">Check</span> <span class=\"sub\">hub rules are on with \
             no enforced Fallback"
        ),
        "{tab}"
    );
}

/// The Rules tab and a rule's page follow the rules live, their forms out of what is swapped.
#[tokio::test(flavor = "multi_thread")]
async fn the_rules_tab_follows_the_rules_live() {
    use crate::store::RuleMode;
    use vk_hub_proto::egress::HubPhase;
    let (addr, hub, _) = start_fleet().await;
    let (operator, _) = sign_in(addr, &hub, Role::Operator).await;
    egress_rule(
        &hub,
        "wab",
        Some("gitlab gl, projects wab/**"),
        HubPhase::Unrestricted,
        HubPhase::Unrestricted,
        RuleMode::Enforce,
    );
    let tab = get(addr, "/egress?tab=rules", Some(&operator)).await.body;
    assert!(
        tab.contains(
            "<div hx-ext=\"sse\" sse-connect=\"/events/egress?tab=rules\" sse-swap=\"egress\" \
             sse-close=\"close\">"
        ),
        "{tab}"
    );
    let page = get(addr, "/egress?tab=rules&rule=wab", Some(&operator))
        .await
        .body;
    let (_, rest) = page
        .split_once("sse-connect=\"/events/egress?tab=rules&amp;rule=wab\"")
        .unwrap();
    assert!(rest.contains("name=\"op\" value=\"preview\""), "{page}");

    let mut stream = live(addr, "/events/egress?tab=rules", &operator).await;
    let mut rule = live(addr, "/events/egress?tab=rules&rule=wab", &operator).await;
    egress_rule(
        &hub,
        "other",
        Some("gitlab gl, project-id 7"),
        HubPhase::Unrestricted,
        HubPhase::Unrestricted,
        RuleMode::DryRun,
    );
    hub.egress_changed();
    let event = next_with(&mut stream, "<strong>other</strong>").await;
    assert!(event.starts_with("event: egress\n"), "{event}");
    assert!(!event.contains("<form"), "{event}");
    hub.db.remove_egress_rule("wab", "uid 1", 2).unwrap();
    hub.egress_changed();
    let event = next_with(&mut rule, "There is no such rule").await;
    assert!(!event.contains("<form"), "{event}");
}

/// The hidden fields of the form in `body` posting `op`, encoded to post again.
fn form_of(body: &str, op: &str) -> String {
    let marker = format!("name=\"op\" value=\"{op}\"");
    let at = body
        .find(&marker)
        .unwrap_or_else(|| panic!("no {op} form: {body}"));
    let start = body[..at].rfind("<form").unwrap();
    let end = at + body[at..].find("</form>").unwrap();
    let mut out = Vec::new();
    for input in body[start..end]
        .split("<input type=\"hidden\" name=\"")
        .skip(1)
    {
        let (name, rest) = input.split_once("\" value=\"").unwrap();
        let value = rest.split('"').next().unwrap();
        let value = value
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&quot;", "\"")
            .replace("&#39;", "'")
            .replace("&amp;", "&");
        out.push(format!("{name}={}", super::jobs::percent_encode(&value)));
    }
    out.join("&")
}

/// A rules preview counts the destinations Observed traffic did not keep of the projects whose
/// access the change alters, which it cannot list.
#[test]
fn a_rules_preview_counts_what_its_projects_did_not_keep() {
    use crate::store::{MAX_OBSERVED_CONTACTS, RuleMode};
    use vk_hub_proto::egress::*;
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap()), None);
    egress_rule(
        &hub,
        crate::store::DEFAULT_RULE,
        None,
        HubPhase::Unrestricted,
        allow(&["debian.org"], &[]),
        RuleMode::Enforce,
    );
    let entries = (0..=MAX_OBSERVED_CONTACTS)
        .map(|i| {
            crate::egress::testing::entry(
                EgressOutcome::Observed,
                EgressProtocol::Dns,
                EgressDestination::domain(&format!("h{i}.example")),
                None,
            )
        })
        .collect();
    let report = EgressReport {
        entries,
        phases: vec![crate::egress::testing::phase(
            EgressPhase::Run,
            EgressCoverage::Complete,
        )],
        ..EgressReport::default()
    };
    egress_job(&hub, 1, 42, "ci-1", report);
    let (generation, rules) = hub.db.egress_rules().unwrap();
    let edit = crate::egress::preview::Edit::Remove(crate::store::DEFAULT_RULE.into());
    let p = crate::egress::preview::preview(&hub, generation, &rules, &edit).unwrap();
    assert_eq!(p.dropped, 1);
    assert_eq!(
        p.lost.len(),
        usize::try_from(MAX_OBSERVED_CONTACTS).unwrap()
    );
}

/// An operator adds, changes and removes egress rules through Preview → Save: the preview shows
/// the recent jobs it affects and what of Observed traffic it would block, Save stores only
/// what was previewed against the rules previewed, and each change is audited. Viewers read.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_changes_the_egress_rules_through_preview_and_save() {
    use crate::store::RuleMode;
    use vk_hub_proto::egress::*;
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    egress_rule(
        &hub,
        crate::store::DEFAULT_RULE,
        None,
        HubPhase::Unrestricted,
        allow(&["debian.org"], &[]),
        RuleMode::Enforce,
    );
    // A job of acme/p42 on gl that reached crates.io, reported completely.
    let mut report = EgressReport {
        entries: vec![crate::egress::testing::entry(
            EgressOutcome::Observed,
            EgressProtocol::Dns,
            EgressDestination::domain("crates.io"),
            None,
        )],
        phases: vec![crate::egress::testing::phase(
            EgressPhase::Run,
            EgressCoverage::Complete,
        )],
        ..EgressReport::default()
    };
    report.entries[0].count = 2;
    let job = egress_job(&hub, 1, 42, &node, report);

    let tab = get(addr, "/egress?tab=rules", Some(&viewer)).await.body;
    assert!(!tab.contains("Add a rule"), "{tab}");
    let tab = get(addr, "/egress?tab=rules", Some(&operator)).await.body;
    assert!(tab.contains("&amp;new=rule\">Add a rule</a>"), "{tab}");
    let form = get(addr, "/egress?tab=rules&new=rule", Some(&operator))
        .await
        .body;
    assert!(form.contains("<form class=\"wide rule\" method=\"post\" action=\"/egress/rules\">"));
    assert!(form.contains("Unrestricted by this rule"), "{form}");

    let rule = |extra: &str| {
        format!(
            "_csrf={csrf}&op=preview&new=1&name=acme&gitlab=gl&projects=path\
             &project_path=acme%2F**&protection=&run=allow&run_names=pypi.org&run_ips=\
             &build=unrestricted&build_names=&build_ips=&mode=enforce{extra}"
        )
    };
    let refused = post_action(addr, &origin, &viewer, "/egress/rules", &rule(""), false).await;
    assert_eq!(refused.status, 403, "{}", refused.body);
    let _ = viewer_csrf;
    // Refusals in plain words, the form kept as typed.
    let bad = post_action(
        addr,
        &origin,
        &operator,
        "/egress/rules",
        &rule("&git_ref=release%2F*"),
        false,
    )
    .await;
    assert_eq!(bad.status, 400, "{}", bad.body);
    assert!(
        bad.body.contains(
            "A branch or tag pattern needs \u{201c}Protected only\u{201d}: anyone who can push \
             can name a branch release/*."
        ),
        "{}",
        bad.body
    );
    assert!(bad.body.contains("value=\"release/*\""), "{}", bad.body);
    let bad = post_action(
        addr,
        &origin,
        &operator,
        "/egress/rules",
        &rule("").replace("run_names=pypi.org", "run_names=https%3A%2F%2Fpypi.org"),
        false,
    )
    .await;
    assert_eq!(bad.status, 400, "{}", bad.body);
    assert!(
        bad.body.contains(
            "The run phase&#39;s names: &quot;https://pypi.org&quot;: expected a DNS suffix"
        ),
        "{}",
        bad.body
    );

    // The preview: the job's group replaces the Fallback and loses crates.io.
    let preview = post_action(addr, &origin, &operator, "/egress/rules", &rule(""), false).await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    let body = &preview.body;
    assert!(body.contains("<h2>Preview: add rule acme</h2>"), "{body}");
    assert!(body.contains("Hub rules are off: saved, this change restricts nothing"));
    assert!(
        body.contains(&format!(
            "<td class=\"num\"><a href=\"/jobs/{job}\" title=\"Their latest job\">1</a></td>\
             <td>acme/p42 [gl] <span class=\"sub\">(project 42)</span></td>\
             <td>main (protected)</td><td>Fallback</td><td>acme \
             <span class=\"badge\">Replaces the Fallback</span></td>\
             <td>now limited to pypi.org</td><td>now unrestricted by hub rules</td>"
        )),
        "{body}"
    );
    assert!(
        body.contains(
            "<li>Run: 1 of 1 job whose access it changes reported this phase completely</li>\
             <li>Build: <span class=\"badge warn\">Insufficient evidence</span>"
        ),
        "{body}"
    );
    // Its project named as elsewhere: the hub has no instance, so not left unnamed.
    assert!(
        body.contains(
            "<td><code>DNS crates.io</code></td><td>Run</td><td><a \
             href=\"/egress?tab=observed&amp;project=gitlab%3Agl%3A42\">acme/p42 [gl]</a></td>"
        ),
        "{body}"
    );
    assert!(
        hub.db.egress_rules().unwrap().1.len() == 1,
        "nothing saved yet"
    );

    // Saved against rules that moved on since: refused, nothing stored.
    let save = form_of(body, "save");
    egress_rule(
        &hub,
        "other",
        Some("gitlab gl, project-id 7"),
        HubPhase::Unrestricted,
        HubPhase::Unrestricted,
        RuleMode::DryRun,
    );
    let stale = post_action(
        addr,
        &origin,
        &operator,
        "/egress/rules",
        &format!("_csrf={csrf}&{save}"),
        false,
    )
    .await;
    assert_eq!(stale.status, 409, "{}", stale.body);
    assert!(
        stale
            .body
            .contains("The rules changed since your preview: preview the change again.")
    );
    assert!(
        !hub.db
            .egress_rules()
            .unwrap()
            .1
            .iter()
            .any(|r| r.name == "acme")
    );

    // Previewed again, then saved.
    let preview = post_action(addr, &origin, &operator, "/egress/rules", &rule(""), false).await;
    let save = form_of(&preview.body, "save");
    let saved = post_action(
        addr,
        &origin,
        &operator,
        "/egress/rules",
        &format!("_csrf={csrf}&{save}"),
        false,
    )
    .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    assert_eq!(
        saved.header("location"),
        Some("/egress?tab=rules&rule=acme")
    );
    let (_, rules) = hub.db.egress_rules().unwrap();
    let acme = rules.iter().find(|r| r.name == "acme").unwrap();
    assert_eq!(acme.run, allow(&["pypi.org"], &[]));
    assert_eq!(acme.build, HubPhase::Unrestricted);
    assert_eq!(acme.mode, RuleMode::Enforce);
    assert_eq!(
        acme.subject.as_ref().unwrap().to_string(),
        "gitlab gl, projects acme/**"
    );

    // Its page offers the form, prefilled, to an operator alone.
    let page = get(addr, "/egress?tab=rules&rule=acme", Some(&operator))
        .await
        .body;
    assert!(page.contains("value=\"acme/**\""), "{page}");
    assert!(page.contains("pypi.org</textarea>"), "{page}");
    let page = get(addr, "/egress?tab=rules&rule=acme", Some(&viewer))
        .await
        .body;
    assert!(!page.contains("/egress/rules\""), "{page}");

    // A rule for jobs that reported nothing: insufficient evidence; in dry-run, compared as
    // enforced.
    let quiet = rule("")
        .replace("name=acme", "name=quiet")
        .replace("projects=path", "projects=id&project_id=9")
        .replace("mode=enforce", "mode=dry-run");
    let preview = post_action(addr, &origin, &operator, "/egress/rules", &quiet, false).await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    assert!(
        preview
            .body
            .contains("no recent job is affected or selected")
    );
    assert!(
        preview
            .body
            .contains("Insufficient evidence: no job whose access it changes reported"),
        "{}",
        preview.body
    );
    assert!(
        preview
            .body
            .contains("In dry-run this rule blocks nothing.")
    );

    // Removed through its preview too.
    let ask = format!("_csrf={csrf}&op=preview&remove=1&name=acme");
    let preview = post_action(addr, &origin, &operator, "/egress/rules", &ask, false).await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    assert!(preview.body.contains("<h2>Preview: remove rule acme</h2>"));
    assert!(
        preview.body.contains("<td>acme</td><td>Fallback</td>"),
        "{}",
        preview.body
    );
    let save = form_of(&preview.body, "save");
    let removed = post_action(
        addr,
        &origin,
        &operator,
        "/egress/rules",
        &format!("_csrf={csrf}&{save}"),
        false,
    )
    .await;
    assert_eq!(removed.status, 303, "{}", removed.body);
    assert_eq!(removed.header("location"), Some("/egress?tab=rules"));
    assert!(
        !hub.db
            .egress_rules()
            .unwrap()
            .1
            .iter()
            .any(|r| r.name == "acme")
    );
    let events = audited(&hub, "removed egress rule acme").await;
    assert!(
        events
            .iter()
            .any(|e| e.starts_with("ui session") && e.contains("added egress rule acme")),
        "{events:?}"
    );
}

/// Job `n` of project `project_id`, ended on `node` with `report`, placed under the hub's rules
/// as they stand: `rules` enforced at their generation now.
fn placed_job(
    hub: &Hub,
    n: u64,
    project_id: u64,
    node: &str,
    report: vk_hub_proto::egress::EgressReport,
    rules: &[&str],
) -> String {
    let id = egress_job(hub, n, project_id, node, report);
    let mut row = hub.db.job(&id).unwrap().unwrap();
    row.egress_rules = Some(crate::store::EgressRulesApplied {
        rules: rules.iter().map(|r| r.to_string()).collect(),
        dry_run: vec![],
        generation: hub.db.egress_rules().unwrap().0,
    });
    row.revision += 1;
    assert!(hub.db.put_job(&id, &row, &[], 12).unwrap());
    id
}

/// A destination a hub rule refused is proposed for its project from its Blocked row, its job's
/// page and Observed traffic, exactly as reported, to operators alone; the editor is prefilled,
/// and only Preview → Save saves it, which moves the row to Allow saved, awaiting confirmation,
/// until a later job reaches it: Allowed by current policy. A node's cap proposes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_hub_rule_s_denial_is_proposed_for_its_project_and_confirmed_by_a_later_job() {
    use crate::store::RuleMode;
    use vk_hub_proto::egress::*;
    let (addr, hub, origin) = start_fleet().await;
    hub.db
        .add_gitlab("gl", "https://gl.example.com", "uid 0", 1)
        .unwrap();
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    egress_rule(
        &hub,
        "acme",
        Some("gitlab gl, project-id 42"),
        HubPhase::Unrestricted,
        allow(&["crates.io"], &[]),
        RuleMode::Enforce,
    );
    let at_build = |e: EgressEntry| EgressEntry {
        phase: EgressPhase::Build,
        ..e
    };
    let mut refused = blocked_report("deb.debian.org", 3);
    refused.entries[0] = at_build(refused.entries[0].clone());
    refused.entries[0].layer = Some(EgressLayer::HubRule);
    refused.hub_rules = vec!["acme".into()];
    let job = placed_job(&hub, 1, 42, &node, refused, &["acme"]);
    // A node's cap, and a malformed name: nothing to propose.
    egress_job(&hub, 2, 7, &node, blocked_report("x.example", 1));
    let rows = hub.db.egress_rows().unwrap();
    let row_of = |text: &str| {
        rows.iter()
            .find(|(_, r)| r.finding.text() == text)
            .map(|(id, _)| id.clone())
            .unwrap()
    };
    let (deb, capped) = (row_of("DNS deb.debian.org"), row_of("DNS x.example"));
    let link = format!(
        "<a href=\"/egress?tab=rules&amp;propose={deb}&amp;phase=build\">Propose allowing for \
         acme/p42…</a>"
    );

    let page = get(addr, &format!("/egress/rows/{deb}"), Some(&viewer))
        .await
        .body;
    assert!(!page.contains("Propose allowing"), "{page}");
    assert!(
        page.contains("an operator may propose a rule allowing it"),
        "{page}"
    );
    let page = get(addr, &format!("/egress/rows/{deb}"), Some(&operator))
        .await
        .body;
    assert!(page.contains(&link), "{page}");
    let page = get(addr, &format!("/egress/rows/{capped}"), Some(&operator))
        .await
        .body;
    assert!(
        page.contains(
            "No hub rule to propose: a node&#39;s cap refused it, and a hub rule cannot override \
             a node&#39;s cap."
        ),
        "{page}"
    );
    // The job's page offers it beside the denial, to an operator.
    let page = get(addr, &format!("/jobs/{job}"), Some(&operator))
        .await
        .body;
    assert!(page.contains(&link), "{page}");
    let page = get(addr, &format!("/jobs/{job}"), Some(&viewer)).await.body;
    assert!(!page.contains("Propose allowing"), "{page}");
    // With a second instance, the link names the project's.
    hub.db
        .add_gitlab("gl2", "https://gl2.example.com", "uid 0", 2)
        .unwrap();
    let page = get(addr, &format!("/jobs/{job}"), Some(&operator))
        .await
        .body;
    assert!(
        page.contains(&link.replace("acme/p42…", "acme/p42 [gl]…")),
        "{page}"
    );
    assert!(hub.db.remove_gitlab("gl2", "uid 0", 3).unwrap());

    let path = format!("/egress?tab=rules&propose={deb}&phase=build");
    assert_eq!(get(addr, &path, Some(&viewer)).await.status, 403);
    let form = get(addr, &path, Some(&operator)).await;
    assert_eq!(form.status, 200, "{}", form.body);
    let body = &form.body;
    for want in [
        "<h2>Propose allowing <code>deb.debian.org</code> for acme/p42</h2>",
        "A hub rule refused DNS <code>deb.debian.org</code> to its jobs, in the build phase",
        "<input type=\"radio\" name=\"target\" value=\"acme\" checked> <strong>acme</strong>",
        "allows deb.debian.org and its subdomains. Nothing broader is proposed",
        "name=\"build_names\" rows=\"3\" spellcheck=\"false\">crates.io\ndeb.debian.org</textarea>",
        &format!("<input type=\"hidden\" name=\"from_row\" value=\"{deb}\">"),
        "> A new rule for exactly this project</label>",
    ] {
        assert!(body.contains(want), "{want}\n{body}");
    }
    assert!(hub.db.egress_rules().unwrap().1[0].build == allow(&["crates.io"], &[]));
    // A new rule for exactly the project, by its ID, in dry-run.
    let new = get(addr, &format!("{path}&target=new"), Some(&operator))
        .await
        .body;
    assert!(new.contains("<h3>A new rule, in dry-run</h3>"), "{new}");
    assert!(
        new.contains("name=\"project_id\" min=\"1\" value=\"42\""),
        "{new}"
    );

    // Previewed, then saved: the row awaits confirmation.
    let preview = post_action(
        addr,
        &origin,
        &operator,
        "/egress/rules",
        &format!(
            "_csrf={csrf}&op=preview&name=acme&gitlab=gl&projects=id&project_path=\
             &project_id=42&protection=&git_ref=&run=unrestricted&run_names=&run_ips=\
             &build=allow&build_names=crates.io%0Adeb.debian.org&build_ips=&mode=enforce\
             &from_row={deb}&from_phase=build"
        ),
        false,
    )
    .await;
    assert_eq!(preview.status, 200, "{}", preview.body);
    assert!(
        preview.body.contains(&format!(
            "Proposed for <a href=\"/egress/rows/{deb}\">a Blocked row</a>"
        )),
        "{}",
        preview.body
    );
    let save = form_of(&preview.body, "save");
    let saved = post_action(
        addr,
        &origin,
        &operator,
        "/egress/rules",
        &format!("_csrf={csrf}&{save}"),
        false,
    )
    .await;
    assert_eq!(saved.status, 303, "{}", saved.body);
    let back = format!("/egress/rows/{deb}?saved=build");
    assert_eq!(saved.header("location"), Some(back.as_str()));
    let page = get(addr, &back, Some(&operator)).await.body;
    assert!(
        page.contains("Saved: its allow awaits a later job"),
        "{page}"
    );
    assert!(
        page.contains(">Allow saved, awaiting confirmation</span>"),
        "{page}"
    );
    let listed = get(addr, "/egress?state=allow_saved", Some(&viewer))
        .await
        .body;
    assert!(
        listed.contains("<code>DNS deb.debian.org</code>"),
        "{listed}"
    );
    let inbox = get(addr, "/egress", Some(&viewer)).await.body;
    assert!(
        !inbox.contains("<code>DNS deb.debian.org</code>"),
        "{inbox}"
    );

    // A later job reaches it, and another destination outside the rules: Observed traffic
    // proposes that one.
    let reached = EgressReport {
        entries: ["deb.debian.org", "pypi.org"]
            .into_iter()
            .map(|d| {
                at_build(crate::egress::testing::entry(
                    EgressOutcome::Observed,
                    EgressProtocol::Dns,
                    EgressDestination::domain(d),
                    None,
                ))
            })
            .collect(),
        phases: vec![crate::egress::testing::phase(
            EgressPhase::Build,
            EgressCoverage::Complete,
        )],
        ..EgressReport::default()
    };
    placed_job(&hub, 3, 42, &node, reached, &["acme"]);
    let listed = get(addr, "/egress?state=allowed", Some(&viewer)).await.body;
    assert!(
        listed.contains(">Allowed by current policy</span>"),
        "{listed}"
    );
    let observed = get(
        addr,
        "/egress?tab=observed&project=gitlab%3Agl%3A42",
        Some(&operator),
    )
    .await
    .body;
    let (_, pypi) = observed.split_once("<code>DNS pypi.org</code>").unwrap();
    let pypi = pypi.split("</tr>").next().unwrap();
    assert!(
        pypi.contains("&amp;propose=observed&amp;project=gitlab%3Agl%3A42&amp;phase=build"),
        "{pypi}"
    );
    let href = pypi
        .split("<a href=\"")
        .find(|s| s.contains("propose=observed"))
        .and_then(|s| s.split('"').next())
        .unwrap()
        .replace("&amp;", "&");
    let page = get(addr, &href, Some(&operator)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert!(
        page.body
            .contains("<h2>Propose allowing <code>pypi.org</code> for acme/p42</h2>"),
        "{}",
        page.body
    );
    let viewer_observed = get(
        addr,
        "/egress?tab=observed&project=gitlab%3Agl%3A42",
        Some(&viewer),
    )
    .await
    .body;
    assert!(!viewer_observed.contains("Propose allowing"));
}

/// Test a job shows each layer apart for a recent job, or for claims typed in, then the result
/// per phase and the layer that decides a destination; a job's dispatch beside the rules now.
#[tokio::test(flavor = "multi_thread")]
async fn test_a_job_shows_each_layer_apart() {
    use crate::store::RuleMode;
    use vk_hub_proto::egress::HubPhase;
    use vk_hub_proto::job::{CiJob, JobSpec, Variable};
    let (addr, hub, _) = start_fleet_rules(true).await;
    hub.db
        .add_gitlab("gl", "https://gl.example.com", "uid 0", 1)
        .unwrap();
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    egress_rule(
        &hub,
        "wab",
        Some("gitlab gl, projects wab/**, protected"),
        allow(&["corp.example.com"], &["10.10.140.49/32"]),
        HubPhase::Unrestricted,
        RuleMode::Enforce,
    );
    egress_rule(
        &hub,
        "wab-release",
        Some("gitlab gl, projects wab/**, ref release/*, protected"),
        allow(&["partner.example.net"], &[]),
        HubPhase::Unrestricted,
        RuleMode::DryRun,
    );
    egress_rule(
        &hub,
        crate::store::DEFAULT_RULE,
        None,
        allow(&[], &[]),
        allow(&["debian.org"], &[]),
        RuleMode::Enforce,
    );
    let id = format!("{:032x}", 1);
    let mut row = crate::egress::testing::job(1, Default::default());
    row.node = Some(node.clone());
    row.gitlab = Some("gl".into());
    row.project_id = Some(42);
    row.project = Some("wab/api".into());
    row.git_ref = Some("release/2".into());
    row.protected = Some(true);
    row.egress_rules = Some(crate::store::EgressRulesApplied {
        rules: vec!["wab".into()],
        dry_run: vec!["wab-release".into()],
        generation: 3,
    });
    let mut ci = CiJob::default();
    ci.variables.push(Variable {
        key: "MICROVM_EGRESS_ALLOW_NAME".into(),
        value: "corp.example.com partner.example.net".into(),
        public: true,
        ..Variable::default()
    });
    let spec = serde_json::to_vec(&JobSpec::GitlabCi(ci)).unwrap();
    let mut queued = row.clone();
    queued.result = None;
    hub.db
        .submit_job(&id, &queued, &id, &spec, "key gitlab", 10)
        .unwrap();
    assert!(hub.db.put_job(&id, &row, &[], 11).unwrap());

    let empty = get(addr, "/egress?tab=test", Some(&viewer)).await;
    assert_eq!(empty.status, 200, "{}", empty.body);
    assert!(
        empty
            .body
            .contains("<a href=\"/egress?tab=test\" aria-current=\"page\">Test a job</a>"),
        "{}",
        empty.body
    );
    assert!(!empty.body.contains("<h2>Result</h2>"));
    assert!(
        empty
            .body
            .contains(&format!("href=\"/egress?tab=test&amp;job={id}\""))
    );

    let page = get(
        addr,
        &format!("/egress?tab=test&job={id}&destination=partner.example.net"),
        Some(&viewer),
    )
    .await
    .body;
    assert!(
        page.contains(
            "<p>Under current rules: enforced <a href=\"/egress?tab=rules&amp;rule=wab\">wab</a> \
             · dry-run candidates <a href=\"/egress?tab=rules&amp;rule=wab-release\">wab-release\
             </a> · Fallback not used.</p>"
        ),
        "{page}"
    );
    assert!(
        page.contains("<p>As dispatched: wab; dry-run wab-release (rules generation 3).</p>"),
        "{page}"
    );
    assert!(
        page.contains(
            "<li>Run: MICROVM_EGRESS_ALLOW_NAME corp.example.com, partner.example.net; IP \
             ranges not declared</li>"
        ),
        "{page}"
    );
    assert!(
        page.contains("It does not report its caps: node limits not evaluated."),
        "{page}"
    );
    assert!(
        page.contains(
            "<tr><td>Run</td><td>job</td><td>not evaluated</td><td>Blocked by hub rules</td>\
             <td>Would be allowed if wab-release were enforced</td>\
             <td>Allowed by MICROVM_EGRESS_ALLOW_NAME</td><td>—</td>\
             <td><span class=\"badge bad\">Blocked by hub rules</span></td></tr>"
        ),
        "{page}"
    );
    assert!(
        page.contains(
            "<p class=\"callout warn\">Run: MICROVM_EGRESS_ALLOW_NAME partner.example.net \
             (outside the hub&#39;s rules). The node keeps them and warns of them; that layer \
             refuses what they list when the job runs.</p>"
        ),
        "{page}"
    );
    // Typed in, the same claims meet the hub's rules alone.
    let page = get(
        addr,
        "/egress?tab=test&gitlab=gl&project=wab%2Fapi&project_id=42&ref=release%2F2\
         &protection=protected&destination=partner.example.net",
        Some(&viewer),
    )
    .await
    .body;
    assert!(
        page.contains(
            "<td>Not known</td><td>—</td><td><span class=\"badge bad\">Blocked by hub rules</span>\
             </td>"
        ),
        "{page}"
    );

    // Claims typed in: no enforced rule selects them, the Fallback applies.
    let page = get(
        addr,
        "/egress?tab=test&gitlab=gl&project=other%2Fx&ref=main&protection=protected\
         &destination=deb.debian.org",
        Some(&viewer),
    )
    .await
    .body;
    assert!(
        page.contains("no enforced rule selects it · Fallback used."),
        "{page}"
    );
    assert!(
        page.contains(
            "<tr><td>Build</td><td>job</td><td>not evaluated</td><td>Allowed by Fallback · \
             debian.org</td><td></td><td>Not known</td><td>—</td><td><span class=\"badge\">Not \
             refused by any layer known</span> <span class=\"sub\">The node&#39;s cap and the \
             job&#39;s restriction are not known; overall reachability cannot be determined.\
             </span>"
        ),
        "{page}"
    );
    // An invalid entry fails the job, whatever the destination; a build-phase one only if it
    // builds an image.
    for (n, key, failure) in [
        (
            2,
            "MICROVM_EGRESS_ALLOW_NAME",
            "<span class=\"badge bad\">The job fails: an invalid entry</span>",
        ),
        (
            3,
            "MICROVM_BUILD_EGRESS_ALLOW_NAME",
            "<span class=\"badge bad\">The job fails if it builds an image: an invalid \
             entry</span>",
        ),
    ] {
        let bad_id = format!("{n:032x}");
        let mut ci = CiJob::default();
        ci.variables.push(Variable {
            key: key.into(),
            value: "partner.example.net bad/name".into(),
            public: true,
            ..Variable::default()
        });
        let spec = serde_json::to_vec(&JobSpec::GitlabCi(ci)).unwrap();
        let mut row = row.clone();
        row.request_id = format!("{n:032}");
        let mut queued = row.clone();
        queued.result = None;
        hub.db
            .submit_job(&bad_id, &queued, &bad_id, &spec, "key gitlab", 10)
            .unwrap();
        assert!(hub.db.put_job(&bad_id, &row, &[], 11).unwrap());
        let page = get(
            addr,
            &format!("/egress?tab=test&job={bad_id}&destination=partner.example.net"),
            Some(&viewer),
        )
        .await
        .body;
        assert_eq!(page.matches(failure).count(), 2, "{page}");
        assert!(page.contains("bad/name"), "{page}");
    }
    let missing = get(
        addr,
        &format!("/egress?tab=test&job={:032x}", 9),
        Some(&viewer),
    )
    .await
    .body;
    assert!(
        missing.contains("There is no such job in the history."),
        "{missing}"
    );
    let bad = get(
        addr,
        &format!("/egress?tab=test&job={id}&destination=https%3A%2F%2Fx"),
        Some(&viewer),
    )
    .await
    .body;
    assert!(
        bad.contains("is neither a DNS name nor an IPv4 address"),
        "{bad}"
    );

    // The project tested names its instance unless it is the hub's only one.
    let tested = format!("/egress?tab=test&job={id}&destination=partner.example.net");
    let page = get(addr, &tested, Some(&viewer)).await.body;
    assert!(
        page.contains("<h2>Tested as</h2><p>wab/api (project 42)"),
        "{page}"
    );
    hub.db
        .add_gitlab("gl2", "https://gl2.example.com", "uid 0", 12)
        .unwrap();
    let page = get(addr, &tested, Some(&viewer)).await.body;
    assert!(
        page.contains("<h2>Tested as</h2><p>wab/api [gl] (project 42)"),
        "{page}"
    );
}

/// A node's caps, as it reports them, show on the Rules tab with their entries' use by the
/// jobs placed under them, and Test a job evaluates them, a job's declarations held to them.
#[tokio::test(flavor = "multi_thread")]
async fn node_caps_are_shown_and_evaluated() {
    use vk_hub_proto::egress::*;
    use vk_hub_proto::job::{CiJob, JobSpec, Variable};
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    egress_rule(
        &hub,
        crate::store::DEFAULT_RULE,
        None,
        HubPhase::Unrestricted,
        HubPhase::Unrestricted,
        crate::store::RuleMode::Enforce,
    );
    let mut caps = EgressCaps::normalized(
        allow(&["corp.example.com", "unused.example"], &[]),
        false,
        HubPhase::Unrestricted,
    )
    .unwrap();
    caps.fingerprint =
        vk_hub_proto::to_hex(&<sha2::Sha256 as sha2::Digest>::digest(caps.canonical()));
    let inventory = vk_hub_proto::Inventory {
        hostname: "ci-1".into(),
        egress_caps: Some(NodeEgressCaps::Listed(caps.clone())),
        ..vk_hub_proto::Inventory::default()
    };
    hub.db
        .record_inventory(&node, inventory, true, crate::now_secs())
        .unwrap();
    // A job placed under them reached corp.example.com, its run phase reported completely.
    let now = crate::now_secs();
    let report = EgressReport {
        entries: vec![crate::egress::testing::entry(
            EgressOutcome::Observed,
            EgressProtocol::Dns,
            EgressDestination::domain("api.corp.example.com"),
            None,
        )],
        phases: vec![crate::egress::testing::phase(
            EgressPhase::Run,
            EgressCoverage::Complete,
        )],
        ..EgressReport::default()
    };
    let id = format!("{:032x}", 1);
    let mut row = crate::egress::testing::job(1, report);
    row.node = Some(node.clone());
    row.finished_at = Some(now);
    row.egress_caps = Some(caps.fingerprint.clone());
    let mut ci = CiJob::default();
    ci.variables.push(Variable {
        key: "MICROVM_EGRESS_ALLOW_NAME".into(),
        value: "corp.example.com partner.example.net".into(),
        public: true,
        ..Variable::default()
    });
    // Its build declares only an address: under a cap and rules restricting nothing, its builds
    // reach no domain.
    ci.variables.push(Variable {
        key: "MICROVM_BUILD_EGRESS_ALLOW_IP".into(),
        value: "10.0.0.1/32:443".into(),
        public: true,
        ..Variable::default()
    });
    // A service declaring its own lists is held to them and to the job's.
    ci.services.push(vk_hub_proto::job::Image {
        name: "postgres:16".into(),
        variables: vec![Variable {
            key: "MICROVM_EGRESS_ALLOW_NAME".into(),
            value: "corp.example.com".into(),
            public: true,
            ..Variable::default()
        }],
        ..vk_hub_proto::job::Image::default()
    });
    let spec = serde_json::to_vec(&JobSpec::GitlabCi(ci)).unwrap();
    let mut queued = row.clone();
    queued.result = None;
    hub.db
        .submit_job(&id, &queued, &id, &spec, "key gitlab", 10)
        .unwrap();
    assert!(hub.db.put_job(&id, &row, &[], 11).unwrap());

    let tab = get(addr, "/egress?tab=rules", Some(&viewer)).await.body;
    assert!(
        tab.contains(&format!(
            "<tr><td><a href=\"/node/{node}\">ci-1</a></td><td>2 domains</td>\
             <td>Unrestricted</td><td>1 entry with no observed use</td></tr>"
        )),
        "{tab}"
    );
    assert!(
        tab.contains("· Run · <code>unused.example</code> · no observed use since"),
        "{tab}"
    );
    assert!(
        tab.contains("Hub-observed jobs only; other workloads on the node may use them"),
        "{tab}"
    );
    assert!(
        !tab.contains("<code>corp.example.com</code> · no observed"),
        "{tab}"
    );
    let observed = get(addr, "/egress?tab=observed", Some(&viewer)).await.body;
    assert!(
        observed.contains("<code>unused.example</code>"),
        "{observed}"
    );

    let page = get(
        addr,
        &format!("/egress?tab=test&job={id}&destination=other.example"),
        Some(&viewer),
    )
    .await
    .body;
    assert!(
        page.contains("<li>Run: 2 domains</li><li>Build: Unrestricted</li>"),
        "{page}"
    );
    assert!(
        page.contains("The caps the job was placed under."),
        "{page}"
    );
    assert!(
        page.contains(
            "A service that declares its own lists is held to them as well as to the job's, each \
             checked on its own: it may reach only what both allow."
        ),
        "{page}"
    );
    assert!(
        page.contains(
            "<p class=\"callout warn\">Run: MICROVM_EGRESS_ALLOW_NAME partner.example.net \
             (outside the node&#39;s cap). The node keeps them and warns of them; that layer \
             refuses what they list when the job runs"
        ),
        "{page}"
    );
    // Each VM of the run phase gets its result: the service's held to the job's lists and its
    // own, each layer on its own.
    assert!(
        page.contains(
            "<tr><td>Run</td><td>job</td><td>Blocked by the node&#39;s cap</td>\
             <td>Unrestricted</td><td></td><td>Blocked by MICROVM_EGRESS_ALLOW_NAME</td>\
             <td>—</td><td><span class=\"badge bad\">Blocked by the node&#39;s cap</span>\
             </td></tr>"
        ),
        "{page}"
    );
    assert!(
        page.contains(
            "<tr><td>Run</td><td>service postgres:16</td><td>Blocked by the node&#39;s cap</td>\
             <td>Unrestricted</td><td></td><td>Blocked by MICROVM_EGRESS_ALLOW_NAME</td>\
             <td>Blocked by MICROVM_EGRESS_ALLOW_NAME</td><td><span class=\"badge bad\">\
             Blocked by the node&#39;s cap</span></td></tr>"
        ),
        "{page}"
    );
    assert!(
        page.contains(
            "<tr><td>Build</td><td>job</td><td>Unrestricted</td><td>Unrestricted</td><td></td>\
             <td>Blocked: only MICROVM_BUILD_EGRESS_ALLOW_IP is declared, so its VM may reach \
             no domains</td><td>—</td><td><span class=\"badge bad\">Blocked: only \
             MICROVM_BUILD_EGRESS_ALLOW_IP is declared</span>"
        ),
        "{page}"
    );
}

/// Observed traffic compares each destination with the rules saved now, ref by ref, and names
/// the rules' entries no contact matched in 30 days, with their coverage and the caution that
/// goes with them; a rule's page shows each entry's use.
#[tokio::test(flavor = "multi_thread")]
async fn observed_traffic_is_compared_with_the_rules() {
    use crate::store::RuleMode;
    use vk_hub_proto::egress::*;
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    let now = crate::now_secs();
    let reached = |dest: &str, phase: EgressPhase| EgressEntry {
        phase,
        first_seen_ms: now * 1000,
        last_seen_ms: now * 1000,
        ..crate::egress::testing::entry(
            EgressOutcome::Observed,
            EgressProtocol::Dns,
            EgressDestination::domain(dest),
            None,
        )
    };
    let report = EgressReport {
        entries: vec![
            reached("deb.debian.org", EgressPhase::Build),
            reached("partner.example.net", EgressPhase::Run),
        ],
        phases: vec![
            crate::egress::testing::phase(EgressPhase::Run, EgressCoverage::Complete),
            crate::egress::testing::phase(EgressPhase::Build, EgressCoverage::Complete),
        ],
        ..EgressReport::default()
    };
    let id = egress_job(&hub, 1, 42, &node, report);
    let mut row = hub.db.job(&id).unwrap().unwrap();
    (row.finished_at, row.revision) = (Some(now), row.revision + 1);
    assert!(hub.db.put_job(&id, &row, &[], now).unwrap());
    let p42 = "/egress?tab=observed&project=gitlab%3Agl%3A42";

    let page = get(addr, p42, Some(&viewer)).await.body;
    assert!(
        page.contains("No saved rules: once on, the hub would allow nothing"),
        "{page}"
    );

    egress_rule(
        &hub,
        "acme",
        Some("gitlab gl, projects acme/**, protected"),
        allow(&["corp.example.com"], &[]),
        allow(&["debian.org", "pypi.org"], &[]),
        RuleMode::Enforce,
    );
    let page = get(addr, p42, Some(&viewer)).await.body;
    assert!(page.contains("<th>under current rules</th>"), "{page}");
    assert!(
        page.contains(
            "<td><span class=\"sub\">If on:</span> Allowed by acme · debian.org</td></tr>"
        ),
        "{page}"
    );
    assert!(
        page.contains(
            "<td><span class=\"sub\">If on:</span> <span class=\"badge warn\">Outside current \
             hub rules</span></td></tr>"
        ),
        "{page}"
    );

    let list = get(addr, "/egress?tab=observed", Some(&viewer)).await.body;
    assert!(
        list.contains("<span class=\"badge\">No observed use in 30 days</span>"),
        "{list}"
    );
    assert!(
        list.contains(
            "<strong>acme</strong></a> · Build · <code>pypi.org</code> · not seen in the history \
             kept · 1 of 1 applicable jobs reported this phase completely</li>"
        ),
        "{list}"
    );
    assert!(
        list.contains("<strong>acme</strong></a> · Run · <code>corp.example.com</code>"),
        "{list}"
    );
    assert!(!list.contains("<code>debian.org</code> · "), "{list}");
    assert!(
        list.contains("No reported use does not prove an entry unnecessary"),
        "{list}"
    );

    let page = get(addr, "/egress?tab=rules&rule=acme", Some(&viewer))
        .await
        .body;
    assert!(
        page.contains("<tr><td><code>debian.org</code></td><td class=\"num\">1</td><td>Used"),
        "{page}"
    );
    assert!(
        page.contains(
            "<tr><td><code>pypi.org</code></td><td class=\"num\">0</td><td><span \
             class=\"badge\">No observed use in 30 days</span>"
        ),
        "{page}"
    );
    let tab = get(addr, "/egress?tab=rules", Some(&viewer)).await.body;
    assert!(
        tab.contains("<div class=\"sub\">2 entries with no observed use in 30 days</div>"),
        "{tab}"
    );
}

/// Post `form`, confirm the edit and return the reply. Panic unless the confirmation lists
/// each of `changes`.
async fn capacity_confirmed(
    addr: SocketAddr,
    origin: &str,
    cookie: &str,
    form: &str,
    changes: &[&str],
) -> Reply {
    let question = post_action(addr, origin, cookie, "/clients/capacity", form, false).await;
    assert!(
        question.body.contains("<h1>Confirm</h1>")
            && question.body.contains("Change the capacity policy?"),
        "{}",
        question.body
    );
    for change in changes {
        assert!(
            question.body.contains(&format!("<li>{change}</li>")),
            "{change}: {}",
            question.body
        );
    }
    let answer = format!(
        "{form}&nonce={}&confirm=yes",
        hidden(&question.body, "nonce")
    );
    post_action(addr, origin, cookie, "/clients/capacity", &answer, false).await
}

/// Operators add a tenant on Connections, edit it with its runner mappings on its page, and a
/// project's production branches and placement rules on the project's, in every tenant listing
/// it. Every edit but adding a tenant asks first, listing what changes; each is audited as the
/// CLI's is, refused when the policy changed since its page, or its question, was shown, and
/// validated before it is asked. Viewers see the policy and cannot change it.
#[tokio::test]
async fn operators_edit_the_capacity_policy_from_its_pages() {
    use super::jobs::percent_encode as enc;
    use crate::policy::{Class, PlacementRule, Project, RunnerMapping, Tenant};
    use crate::store::{Decision, ProjectRef};
    let (addr, hub, origin) = start_fleet().await;
    let now = crate::now_secs();
    hub.db
        .add_gitlab("gl", "https://gitlab.example.com", "u", now)
        .unwrap();
    let project = ProjectRef {
        id: 42,
        path: Some("acme/web".into()),
    };
    hub.db
        .decide_projects("gl", &[project], Decision::Approve, "u", now)
        .unwrap();
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/clients", Some(&operator)).await.body;
    assert!(
        page.contains("<a href=\"/clients/tenants/fallback\">fallback</a> <span"),
        "{page}"
    );
    assert!(page.contains("value=\"capacity-add-tenant\""), "{page}");
    let page = get(addr, "/clients/projects/gl/42", Some(&operator))
        .await
        .body;
    assert!(page.contains("No capacity tenant lists it"), "{page}");

    // Adding a tenant asks nothing.
    let form = format!("_csrf={csrf}&op=capacity-add-tenant&tenant=web");
    let reply = post_action(addr, &origin, &operator, "/clients/capacity", &form, false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients/tenants/web"));
    audited(&hub, "; tenants: web").await;
    let reply = post_action(addr, &origin, &operator, "/clients/capacity", &form, false).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert!(reply.body.contains("exists already"), "{}", reply.body);
    let form = format!("_csrf={csrf}&op=capacity-add-tenant&tenant=not%20a%20name");
    let reply = post_action(addr, &origin, &operator, "/clients/capacity", &form, false).await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert!(
        reply.body.contains("not a valid tenant name"),
        "{}",
        reply.body
    );

    // An edit of no known kind, and one of a malformed project, are told apart.
    for (form, why) in [
        ("op=capacity-nope", "no such edit"),
        (
            "op=capacity-branches&expected=x&tenant=web&gitlab=gl&project=0&branches=main",
            "invalid project or tenant",
        ),
    ] {
        let form = format!("_csrf={csrf}&{form}");
        let reply = post_action(addr, &origin, &operator, "/clients/capacity", &form, false).await;
        assert_eq!(reply.status, 400, "{}", reply.body);
        assert!(reply.body.contains(why), "{why}: {}", reply.body);
    }

    // The tenant's page edits it with its runner mappings.
    let page = get(addr, "/clients/tenants/web", Some(&operator))
        .await
        .body;
    assert!(page.contains("name=\"settings\""), "{page}");
    assert!(
        page.contains(
            "<h2>Runners</h2><p>None.</p></section><section><h2>API clients</h2><p>None.</p>"
        ),
        "{page}"
    );
    let shown = hidden(&page, "expected");
    assert_eq!(shown, hub.db.capacity_policy().unwrap().digest().unwrap());
    let settings = Tenant {
        weight: 3,
        cap: Some(5),
        projects: vec![Project {
            gitlab: "gl".into(),
            id: 42,
            production_branches: vec!["main".into()],
            placement_rules: vec![],
        }],
    };
    let mapping = |tenant: &str| RunnerMapping {
        gitlab: "gl".into(),
        runner_id: 7,
        tenant: tenant.into(),
        class: Class::Production,
    };
    let tenant_form = |expected: &str, runners: &[RunnerMapping]| {
        format!(
            "_csrf={csrf}&op=capacity-tenant&expected={expected}&tenant=web&settings={}&runners={}",
            enc(&serde_json::to_string(&settings).unwrap()),
            enc(&serde_json::to_string(runners).unwrap()),
        )
    };
    // A mapping of another tenant is refused before anything is asked.
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients/capacity",
        &tenant_form(&shown, &[mapping("fallback")]),
        false,
    )
    .await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert!(reply.body.contains("gl/7"), "{}", reply.body);
    let form = tenant_form(&shown, &[mapping("web")]);
    let before = hub.db.capacity_policy().unwrap();
    let question = post_action(addr, &origin, &operator, "/clients/capacity", &form, false).await;
    assert!(
        question.body.contains("<li>tenants: web</li>"),
        "{}",
        question.body
    );
    assert!(
        question.body.contains("<li>runners: gl/7</li>"),
        "{}",
        question.body
    );
    assert_eq!(hub.db.capacity_policy().unwrap(), before);
    // Without its nonce, or with a field changed since asked: refused.
    let refused = format!("{form}&confirm=yes");
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients/capacity",
        &refused,
        false,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    let nonce = hidden(&question.body, "nonce");
    let tampered = tenant_form(&shown, &[]) + &format!("&nonce={nonce}&confirm=yes");
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients/capacity",
        &tampered,
        false,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert_eq!(hub.db.capacity_policy().unwrap(), before);
    let reply = capacity_confirmed(addr, &origin, &operator, &form, &["tenants: web"]).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients/tenants/web"));
    let saved = hub.db.capacity_policy().unwrap();
    assert_eq!(saved.tenant("web"), Some(&settings));
    assert_eq!(saved.runner("gl", 7), Some(&mapping("web")));
    audited(&hub, "; tenants: web; runners: gl/7").await;
    // The page it was made from is stale now.
    let reply = post_action(addr, &origin, &operator, "/clients/capacity", &form, false).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert!(
        reply
            .body
            .contains("the capacity policy changed since this page was shown; reload it"),
        "{}",
        reply.body
    );
    assert_eq!(hub.db.capacity_policy().unwrap(), saved);
    // The same tenant again changes nothing and asks nothing.
    let audits = hub.db.audits(None, 100).unwrap().len();
    let same = tenant_form(&saved.digest().unwrap(), &[mapping("web")]);
    let reply = post_action(addr, &origin, &operator, "/clients/capacity", &same, false).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(hub.db.audits(None, 100).unwrap().len(), audits);

    // A project listed by two tenants: its page edits it in both.
    let mut shared = saved.clone();
    let group = shared.tenants["web"].clone();
    shared.tenants.insert("group".into(), group);
    hub.db.set_capacity_policy(&shared, "u", now).unwrap();
    let page = get(addr, "/clients/projects/gl/42", Some(&operator))
        .await
        .body;
    for want in [
        "<a href=\"/clients/tenants/group\">group</a>",
        "<a href=\"/clients/tenants/web\">web</a></td><td class=\"num\">3</td><td>5</td>\
         <td>7 (production)</td>",
        "name=\"branches\"",
        "name=\"rules\"",
    ] {
        assert!(page.contains(want), "{want}: {page}");
    }
    let expected = hidden(&page, "expected");
    // As a browser posts a textarea: CRLF between lines.
    let form = format!(
        "_csrf={csrf}&op=capacity-branches&expected={expected}&tenant=group&gitlab=gl&project=42\
         &branches={}",
        enc("main\r\nrelease/**\r\n")
    );
    let reply = capacity_confirmed(addr, &origin, &operator, &form, &["tenants: group, web"]).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients/projects/gl/42"));
    let saved = hub.db.capacity_policy().unwrap();
    for tenant in ["group", "web"] {
        assert_eq!(
            saved.project(tenant, "gl", 42).unwrap().production_branches,
            ["main", "release/**"]
        );
    }

    // Placement rules: validated before asked, and refused when the policy changes between the
    // question and its answer.
    let node = "0123456789abcdef0123456789abcdef";
    let rules_form = |rules: &str| {
        format!(
            "_csrf={csrf}&op=capacity-placement&expected={}&tenant=web&gitlab=gl&project=42\
             &rules={}",
            saved.digest().unwrap(),
            enc(rules)
        )
    };
    for bad in [r#"[{"branches":["main"]}]"#, r#"[{"pool":["x"]}]"#, "nope"] {
        let reply = post_action(
            addr,
            &origin,
            &operator,
            "/clients/capacity",
            &rules_form(bad),
            false,
        )
        .await;
        assert_eq!(reply.status, 400, "{bad}: {}", reply.body);
        assert!(!reply.body.contains("<h1>Confirm</h1>"), "{}", reply.body);
    }
    let form = rules_form(&format!(r#"[{{"nodes":["{node}"]}}]"#));
    let question = post_action(addr, &origin, &operator, "/clients/capacity", &form, false).await;
    assert!(
        question.body.contains("<li>tenants: group, web</li>"),
        "{}",
        question.body
    );
    let mut meanwhile = saved.clone();
    meanwhile.probe_limit = 2;
    assert!(
        hub.db
            .replace_capacity_policy_if(&meanwhile, &saved.digest().unwrap(), "u", now)
            .unwrap()
    );
    let answer = format!(
        "{form}&nonce={}&confirm=yes",
        hidden(&question.body, "nonce")
    );
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients/capacity",
        &answer,
        false,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    assert_eq!(hub.db.capacity_policy().unwrap(), meanwhile);
    let form = form.replace(&saved.digest().unwrap(), &meanwhile.digest().unwrap());
    let reply = capacity_confirmed(addr, &origin, &operator, &form, &["tenants: group, web"]).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    let saved = hub.db.capacity_policy().unwrap();
    let rule = PlacementRule {
        branches: vec![],
        nodes: vec![node.into()],
        pools: vec![],
    };
    for tenant in ["group", "web"] {
        assert_eq!(
            saved.project(tenant, "gl", 42).unwrap().placement_rules,
            std::slice::from_ref(&rule)
        );
    }

    // The whole policy, as the CLI sets it.
    let page = get(addr, "/clients/capacity", Some(&operator)).await.body;
    assert!(page.contains("name=\"policy\""), "{page}");
    let mut whole = saved.clone();
    whole.busy_secs = 30;
    whole.runners.push(RunnerMapping {
        runner_id: 8,
        ..mapping("web")
    });
    let policy_form = |expected: &str, policy: &crate::policy::Policy| {
        format!(
            "_csrf={csrf}&op=capacity-policy&expected={expected}&policy={}",
            enc(&serde_json::to_string(policy).unwrap())
        )
    };
    let form = policy_form(&hidden(&page, "expected"), &whole);
    let changes = ["runners: gl/8", "settings: busy_secs"];
    let reply = capacity_confirmed(addr, &origin, &operator, &form, &changes).await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(reply.header("location"), Some("/clients/capacity"));
    assert_eq!(hub.db.capacity_policy().unwrap(), whole);
    // Its runner mappings only reordered: nothing asked, saved or audited.
    let mut swapped = whole.clone();
    swapped.runners.reverse();
    let audits = hub.db.audits(None, 100).unwrap().len();
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients/capacity",
        &policy_form(&whole.digest().unwrap(), &swapped),
        false,
    )
    .await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(hub.db.audits(None, 100).unwrap().len(), audits);
    assert_eq!(hub.db.capacity_policy().unwrap(), whole);
    // A policy larger than other forms is read; one past what the admin socket takes, as a
    // browser posts it (6 * 64 KiB) with its length, is refused on that length unread.
    let padded = |len: usize| {
        let form = format!(
            "_csrf={csrf}&op=capacity-policy&expected={}&policy=",
            whole.digest().unwrap()
        );
        let pad = len - form.len();
        form + &"x".repeat(pad)
    };
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients/capacity",
        &padded(64 * 1024),
        false,
    )
    .await;
    assert_eq!(reply.status, 400, "{}", reply.body);
    assert!(
        reply.body.contains("not a capacity policy"),
        "{}",
        reply.body
    );
    let reply = post_action(
        addr,
        &origin,
        &operator,
        "/clients/capacity",
        &padded(6 * 64 * 1024 + 1),
        false,
    )
    .await;
    assert_eq!(reply.status, 413, "{}", reply.body);
    assert_eq!(hub.db.capacity_policy().unwrap(), whole);

    // A viewer sees it all, with no form, and is refused.
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    for path in [
        "/clients/capacity",
        "/clients/tenants/web",
        "/clients/projects/gl/42",
    ] {
        let page = get(addr, path, Some(&viewer)).await.body;
        assert!(
            !page.contains("/clients/capacity\"><input"),
            "{path}: {page}"
        );
        assert!(!page.contains("<textarea"), "{path}: {page}");
    }
    let page = get(addr, "/clients/projects/gl/42", Some(&viewer))
        .await
        .body;
    assert!(page.contains(node), "{page}");
    let page = get(addr, "/clients/tenants/web", Some(&viewer)).await.body;
    assert!(
        page.contains("gl / 42") && page.contains("gl / 7 (production)"),
        "{page}"
    );
    let form = format!("_csrf={viewer_csrf}&op=capacity-add-tenant&tenant=other");
    let reply = post_action(addr, &origin, &viewer, "/clients/capacity", &form, false).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    assert_eq!(hub.db.capacity_policy().unwrap(), whole);
    let reply = get(addr, "/clients/tenants/nope", Some(&viewer)).await;
    assert_eq!(reply.status, 404, "{}", reply.body);
}

/// An unreadable policy leaves Connections, policy, tenant and project pages available.
/// They show the error and replacement digest for the CLI; editors refuse changes.
#[tokio::test]
async fn an_unreadable_capacity_policy_is_reported_not_fatal() {
    let (addr, hub, origin) = start_fleet().await;
    let now = crate::now_secs();
    hub.db
        .add_gitlab("gl", "https://gitlab.example.com", "u", now)
        .unwrap();
    let project = crate::store::ProjectRef { id: 42, path: None };
    hub.db
        .decide_projects("gl", &[project], crate::store::Decision::Approve, "u", now)
        .unwrap();
    hub.db
        .set_raw_capacity_policy(br#"{"from_a_later_hub":true}"#);
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let digest = crate::policy::digest_bytes(br#"{"from_a_later_hub":true}"#);
    for path in [
        "/clients",
        "/clients/capacity",
        "/clients/projects/gl/42",
        "/clients/tenants/fallback",
    ] {
        let reply = get(addr, path, Some(&operator)).await;
        assert_eq!(reply.status, 200, "{path}: {}", reply.body);
        assert!(
            reply.body.contains(&format!("--expected {digest}")),
            "{path}: {}",
            reply.body
        );
        assert!(!reply.body.contains("Tenants: "), "{path}: {}", reply.body);
    }
    let form = format!("_csrf={csrf}&op=capacity-add-tenant&tenant=web");
    let reply = post_action(addr, &origin, &operator, "/clients/capacity", &form, false).await;
    assert_eq!(reply.status, 409, "{}", reply.body);
}
