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
        assert_eq!(body.matches("<script").count(), 4, "{body}");
        assert_eq!(body.matches("<script src=\"/assets/").count(), 4, "{body}");
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
    let reply = post_action(
        addr,
        origin,
        cookie,
        path,
        &format!("_csrf={csrf}&op={op}"),
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
    let asked: String = ["pid", "started", "booted"]
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
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("{scheme}://{addr}");
    // Releases are written straight into the database, so their directory holds no files and
    // need not exist: removing one finds nothing to delete.
    let releases = std::env::temp_dir().join(format!("vk-hub-ui-releases-{}", std::process::id()));
    let hub = Arc::new(
        Hub::new(Arc::new(Db::open_memory().unwrap()), Some(origin.clone()))
            .with_releases(releases)
            .with_node_url(node_url.map(str::to_string)),
    );
    let ui = Arc::new(Ui::new(hub.clone(), &origin));
    tokio::spawn(serve(listener, None, ui));
    (addr, hub, origin)
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
    assert_eq!(body.matches("<script").count(), 4, "{body}");
    assert_eq!(body.matches("<script src=\"/assets/").count(), 4, "{body}");
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

/// `/audit` lists the fleet's log, newest first, or one node's, chosen from the hub's nodes.
#[tokio::test(flavor = "multi_thread")]
async fn the_fleet_s_audit_log_is_shown_and_filtered_by_node() {
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-<1>");
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let all = get(addr, "/audit", Some(&cookie)).await;
    assert_eq!(all.status, 200, "{}", all.body);
    for want in [
        "<a href=\"/audit\" aria-current=\"page\">Audit</a>",
        "<select name=\"node\">",
        &format!("<option value=\"{node}\">ci-&lt;1&gt; ("),
        "issued an enrollment token",
        &format!("node {node} enrolled as ci-&lt;1&gt;"),
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

    let answer = ask(addr, &origin, &cookie, &csrf, &path, "reset").await;
    assert!(hub.db.node_commands(&node).unwrap().is_empty());
    let reply = post_action(addr, &origin, &cookie, &path, &answer, true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Issued reset (command "),
        "{}",
        reply.body
    );
    let commands = hub.db.pending_commands(&node, crate::now_secs()).unwrap();
    assert_eq!(
        commands.iter().map(|c| &c.op).collect::<Vec<_>>(),
        [&vk_hub_proto::Operation::Reset { images: false }]
    );
    assert!(
        node_audit(&hub, &node)
            .iter()
            .any(|(actor, e)| *actor == principal && e.contains("issued reset (command ")),
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

/// Rollout `ef…`, running, of release `ab…` (unsigned; `cd…`, signed, beside it): node
/// `hostname` failed with a reason naming it, node `ci-2` still pending. Written straight
/// into the database; returns its ID.
fn rollout_of(hub: &Hub, hostname: &str) -> String {
    let node = enrolled_node(hub, hostname);
    let release = |version: &str, signature: Option<String>| crate::store::ReleaseRow {
        version: version.into(),
        size: 3 << 20,
        signature,
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
                    reason: format!("rolled back: {hostname}"),
                    at: 2,
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
        "failed: rolled back: ci&lt;script&gt;",
        "ci&lt;script&gt;alert(1)&lt;/script&gt; CPU",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    assert!(!page.body.contains("<script>alert"), "{}", page.body);
    assert!(!page.body.contains("hx-post"), "{}", page.body);
    assert!(!page.body.contains("hx-headers"), "{}", page.body);

    let mut events = Events::open(addr, "/events/operations", &viewer).await;
    let first = events.next().await.unwrap();
    assert!(first.starts_with("event: operations\ndata: "), "{first}");
    assert!(!first.contains("hx-post"), "{first}");
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
                "<nav><a href=\"/\">Nodes</a><a href=\"/jobs\">Jobs</a>\
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
        })
    };
    let job = |n: u64, project: &str, url: &str, state, result| crate::store::JobRow {
        key: "k".into(),
        key_name: "gitlab".into(),
        request_id: format!("{n:032}"),
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
            }),
        ),
    );
    measured.node = Some(node.clone());
    measured.git_ref = Some("main".into());
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
    submit(104, &running);

    let rows = |body: &str| body.matches("<tr><td title=").count();
    let page = get(addr, "/jobs", Some(&viewer)).await.body;
    assert_only_embedded_scripts(&page);
    assert_eq!(rows(&page), 100, "{page}");
    for want in [
        // 61 and 10 seconds.
        "104 jobs · 50% of 2 finished succeeded · median run of finished jobs 35s",
        "<a href=\"/jobs?name=build-102\">build-102</a> \
         <a href=\"https://gitlab.example.com/acme/web/-/jobs/102\" target=\"_blank\" \
         rel=\"noopener noreferrer\">↗</a></td><td>acme/web</td>\
         <td><a href=\"/jobs?ref=main\">main</a></td><td>-</td>",
        &format!("<a href=\"/node/{node}\">ci-1</a>"),
        "<span class=\"badge ok\">success</span>",
        "<td class=\"num\">1m01s</td><td class=\"num\">3.0 GiB</td>\
         <td class=\"num\">2m00s</td><td class=\"num\">4 vCPUs, 8.0 GiB</td>",
        // Not a web link: no link to GitLab, for the job or its pipeline.
        "<a href=\"/jobs?name=build-103\">build-103</a></td><td>acme/api</td>\
         <td><a href=\"/jobs?ref=fix%2F%3Cx%3E\">fix/&lt;x&gt;</a></td>\
         <td><a href=\"/jobs?pipeline=77\">77</a></td>\
         <td><a href=\"/node/efefefefefefefefefefefefefefefef\"><code>efefefef</code></a></td>",
        // The job's pipeline, and its page on GitLab.
        "<td><a href=\"/jobs?pipeline=77\">77</a> \
         <a href=\"https://gitlab.example.com/acme/web/-/pipelines/77\" target=\"_blank\" \
         rel=\"noopener noreferrer\">↗</a></td>",
        "<span class=\"badge bad\">script failure, exit 2</span>",
        "<span class=\"badge busy\">running: step_script</span>",
        // Running for a minute and a half, by the hub's clock.
        "<td class=\"num\">1m3",
        "<span class=\"badge\">queued</span>",
    ] {
        assert!(page.contains(want), "{want}: {page}");
    }
    assert!(!page.contains("href=\"javascript"), "{page}");
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
        page.contains("<a href=\"/jobs?name=build-104&amp;pipeline=77\">build-104</a>"),
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

/// Job `n` of `project`, as submitted.
pub(super) fn history_job(n: u64, project: &str) -> crate::store::JobRow {
    use vk_hub_proto::client::{JobState, Placement};
    crate::store::JobRow {
        key: "k".into(),
        key_name: "gitlab".into(),
        request_id: format!("{n:032}"),
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
    }
}

/// A failed job links from the history to its page, which shows any session its record and
/// the end of its output the hub kept, as text: escaped, its escape sequences and GitLab's
/// section markers dropped, its stamps shown as times.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_job_s_page_shows_the_end_of_its_output() {
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
        row.finished_at = Some(now);
        row.settled_at = Some(now);
        row.result = Some(JobResult {
            failure,
            exit_code: None,
            message: Some("the VM <did> not boot".into()),
            output_len: 0,
            artifacts: Vec::new(),
            usage: None,
        });
        row
    };
    for (n, failure) in [
        (1, Some(FailureClass::System)),
        (2, None),
        (3, Some(FailureClass::Lost)),
    ] {
        hub.db
            .submit_job(
                &id(n),
                &ended(n, failure),
                &n.to_string(),
                b"{}",
                "key gitlab",
                now,
            )
            .unwrap();
    }
    let stamp = "2026-10-09T12:10:43.123456Z";
    let tail = format!(
        "{stamp} 00O section_start:1700000000:prepare\r\x1b[0K\n\
         {stamp} 01E \x1b[31m<script>alert(1)</script>\x1b[0m\n"
    );
    assert!(hub.db.keep_job_tail(&id(1), tail.as_bytes()).unwrap());

    let page = get(addr, "/jobs", Some(&viewer)).await.body;
    assert!(
        page.contains(&format!(
            "<a href=\"/jobs/{}\"><span class=\"badge bad\" title=\"the VM &lt;did&gt; not \
             boot\">system failure</span></a>",
            id(1)
        )),
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
            .with_jobs(dir.to_path_buf(), crate::jobs::DEFAULT_LOST_AFTER, 100)
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
            "<a href=\"/jobs/{id}\"><span class=\"badge busy\">running</span></a>"
        )),
        "{page}"
    );
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
            && record.contains("<span class=\"badge busy\">running</span>"),
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
    let dir = std::env::temp_dir().join(format!("vk-hub-ui-bounded-{}", std::process::id()));
    let (addr, hub) = start_fleet_placing(&dir).await;
    let (viewer, _) = sign_in(addr, &hub, Role::Viewer).await;
    // 100-byte lines, stamped as a node sends them and numbered: 1.1 MiB of them.
    let lines = |from: usize, to: usize| {
        (from..to)
            .map(|n| {
                let x = "x".repeat(54);
                format!("2026-10-09T12:10:43.123456Z 01O line {n:07} {x}\n")
            })
            .collect::<String>()
    };
    let opening = job_output::OPENING as usize;
    let id = running_with_output(&hub, &dir, 1, lines(0, opening / 100 + 1000).as_bytes());
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
    // 600 KiB more: read a stretch at a time, in order.
    let more = lines(last + 1, last + 1 + 6000);
    more_output(&hub, &dir, &id, more.as_bytes());
    let mut seen = Vec::new();
    while seen.last() != Some(&(last + 5999)) {
        let event = stream.next().await.unwrap();
        if !event.starts_with("event: output\n") {
            continue;
        }
        assert!(event.len() < 512 * 1024, "{}", event.len());
        seen.extend(
            event
                .split("line ")
                .skip(1)
                .map(|l| l[..7].parse::<usize>().unwrap()),
        );
    }
    assert_eq!(seen, (last..last + 6000).collect::<Vec<_>>());
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
         input changed delay:300ms from:(#jobs-filter input)\"",
        " hx-target=\"#jobs-results\" hx-select=\"#jobs-results\" hx-swap=\"outerHTML\"",
        " hx-push-url=\"true\" hx-sync=\"this:replace\"",
        "\"> <button>Show</button>",
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
        "event: jobs\ndata: <p class=\"empty\" role=\"status\">none match</p>\n\n"
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
    assert!(!aborted.contains("<button>"), "{aborted}");

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
        page.body.contains("action=\"/auth/login\""),
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
        &format!("name=\"node\" value=\"{a}\"> ci-a"),
        &format!("name=\"node\" value=\"{b}\"> ci-b"),
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }

    let form = format!(
        "_csrf={csrf}&op=create&release={sha}&select=all&batch=1&max_failures=0&\
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

    // An answer posting another plan than it was asked, and a node enrolled between the
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
        "_csrf={csrf}&op=create&release={sha}&select=some&node={a}&batch=1&max_failures=0&\
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
    enroll("ci-c", "c1");
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
    let form = format!("_csrf={csrf}&op=create&select=all&batch=1");
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
    let page = get(addr, "/operations", Some(&operator)).await;
    assert!(
        page.body.contains("Latest on GitHub: vk 0.85.0"),
        "{}",
        page.body
    );
    assert!(page.body.contains("Fetched vk 0.85.0"), "{}", page.body);
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
    let page = get(addr, "/operations", Some(&operator)).await;
    assert!(
        page.body.contains("Fetching vk 0.86.0 failed</span>"),
        "{}",
        page.body
    );
    assert!(page.body.contains("does not match"), "{}", page.body);
    assert!(staged_files(&dir).is_empty(), "{:?}", staged_files(&dir));
    let _ = std::fs::remove_dir_all(&dir);
}
