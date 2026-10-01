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
    start_with_vk(origin, "/nonexistent/vk".into()).await
}

/// [`start_local`], running `vk` for what it runs.
async fn start_with_vk(
    origin: Option<&str>,
    vk: std::path::PathBuf,
) -> (SocketAddr, Arc<Hub>, String, Arc<Local>) {
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = origin.map_or_else(|| format!("http://{addr}"), str::to_string);
    let hub =
        Arc::new(Hub::new(Arc::new(Db::open_memory().unwrap())).with_ui_url(Some(origin.clone())));
    let local = Arc::new(Local::new(vk));
    let ui = Arc::new(Ui::local(hub.clone(), &origin, local.clone()));
    tokio::spawn(serve(listener, None, ui));
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

fn workload(id: &str, label: &str) -> vk_fleet_proto::Workload {
    vk_fleet_proto::Workload {
        id: id.into(),
        kind: vk_fleet_proto::WorkloadKind::Run,
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

fn listed(workloads: Vec<vk_fleet_proto::Workload>) -> Listing {
    Listing::Listed(vk_fleet_proto::WorkloadList {
        version: vk_fleet_proto::WORKLOADS_VERSION,
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
    for name in [assets::HTMX, assets::SSE] {
        let reply = get(addr, assets::url(name), None).await;
        assert_eq!(reply.status, 200);
        assert!(
            reply
                .header("content-type")
                .unwrap()
                .starts_with("text/javascript")
        );
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
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd") && !constant_time_eq(b"abc", b"ab"));
}

#[tokio::test(flavor = "multi_thread")]
async fn over_https_the_cookie_is_host_bound_and_secure() {
    let (addr, hub, _) = start_as(Some("https://hub.example")).await;
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
        &["Host: hub.example", "Origin: https://hub.example"],
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let set = reply.header("set-cookie").unwrap();
    assert!(set.starts_with("__Host-vk-hub="), "{set}");
    assert!(set.ends_with("; Secure"), "{set}");
    assert_eq!(
        reply.header("strict-transport-security"),
        Some("max-age=31536000")
    );
    let pair = set.split(';').next().unwrap();
    let ok = request(
        addr,
        "GET",
        "/",
        &["Host: HUB.example", &format!("Cookie: {pair}")],
        "",
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    // The plain name is not this UI's cookie here.
    let secret = pair.split_once('=').unwrap().1;
    let plain = request(
        addr,
        "GET",
        "/",
        &["Host: hub.example", &format!("Cookie: vk-hub={secret}")],
        "",
    )
    .await;
    assert_eq!(plain.status, 401);
    // Any other name for this address is refused, whatever else the request carries.
    let rebound = request(addr, "GET", "/", &[&format!("Cookie: {pair}")], "").await;
    assert_eq!(rebound.status, 421);
    assert_secure(&rebound);
    assert_eq!(
        request(addr, "GET", "/", &["Host: evil.example"], "")
            .await
            .status,
        421
    );
    // Plain http sends no HSTS.
    let (addr, _, _) = start().await;
    assert!(
        get(addr, "/", None)
            .await
            .header("strict-transport-security")
            .is_none()
    );
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
        format!("Cookie: {cookie}; __Host-vk-hub=x"),
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
    assert_eq!(get(addr, "/events/vms", Some(&cookie)).await.status, 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn live_pages_are_capped_per_session_and_in_all() {
    let (addr, hub, _) = start().await;
    let (first, _) = sign_in(addr, &hub, Role::Viewer).await;
    let (second, _) = sign_in(addr, &hub, Role::Viewer).await;
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
    assert_eq!(get(addr, "/events/vms", Some(&second)).await.status, 503);
    // Pages and posts still find a connection.
    assert_eq!(get(addr, "/", Some(&second)).await.status, 200);
    // A stream gone gives its place back.
    drop(open.pop());
    let mut again = None;
    for _ in 0..100 {
        let stream = Events::open(addr, "/events/vms", &second).await;
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
    std::fs::write(&vk, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&vk, std::fs::Permissions::from_mode(0o755)).unwrap();
    vk
}

/// A VM's page shows its console's tail, atop's account of it when it records one, and a CI
/// job's egress, each read by the `vk` command for it, as text.
#[tokio::test(flavor = "multi_thread")]
async fn a_vm_s_page_shows_its_console_atop_and_egress() {
    let vk = stub_vk(
        "views",
        r#"case "$1" in
logs) echo "console of $4 <b>bold</b>"; echo "second line" ;;
atop) echo "atop of $3" ;;
egress-report) echo "virtkit: egress refused:"; echo "  egress denied (dns) evil.example  (x2)" ;;
*) echo "unexpected $*" >&2; exit 3 ;;
esac"#,
    );
    let (addr, hub, _, local) = start_with_vk(None, vk.clone()).await;
    let state = vk.parent().unwrap().join("state");
    std::fs::create_dir_all(state.join("atop")).unwrap();
    let mut run = workload("0123456789abcdef", "alpine:3.20");
    run.state_dir = state.display().to_string();
    let mut job = workload("fedcba9876543210", "rust:1.90");
    job.kind = vk_fleet_proto::WorkloadKind::CiJob;
    local.set_listing(listed(vec![run, job]), &hub);
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;

    let page = get(addr, "/vm/0123456789abcdef", Some(&cookie)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    let console = format!(
        "console of {} &lt;b&gt;bold&lt;/b&gt;\nsecond line",
        state.display()
    );
    assert!(page.body.contains(&console), "{}", page.body);
    assert!(page.body.contains("Not recording"), "{}", page.body);
    assert!(page.body.contains("Only a CI job"), "{}", page.body);
    // Recording itself, atop is asked; a CI job's egress is.
    std::fs::write(state.join("atop/atop.log"), b"").unwrap();
    let page = get(addr, "/vm/0123456789abcdef", Some(&cookie)).await;
    assert!(
        page.body.contains(&format!("atop of {}", state.display())),
        "{}",
        page.body
    );
    let page = get(addr, "/vm/fedcba9876543210", Some(&cookie)).await;
    assert!(
        page.body.contains("egress denied (dns) evil.example"),
        "{}",
        page.body
    );
    // A failing command says how it failed, and the page still shows.
    let (addr, hub, _, local) = start_local(None).await;
    local.set_listing(listed(vec![workload("0123456789abcdef", "x")]), &hub);
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/vm/0123456789abcdef", Some(&cookie)).await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("/nonexistent/vk"), "{}", page.body);
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

/// Wait for the audit log to hold a line containing `want`.
async fn audited(hub: &Hub, want: &str) -> Vec<String> {
    for _ in 0..200 {
        let events: Vec<String> = hub
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
    panic!("no audit line with {want:?}");
}

/// A VM is stopped and rebooted by running `vk`, as an operator alone, once confirmed; the
/// command and how it ended are audited and shown, and a second waits for the first.
#[tokio::test(flavor = "multi_thread")]
async fn an_operator_stops_a_vm_once_confirmed() {
    let vk = stub_vk(
        "actions",
        r#"case "$1" in
stop) echo "$*" >> "$(dirname "$0")/ran"; echo "virtkit: stopped pid $2" >&2 ;;
reboot) echo "$*" >> "$(dirname "$0")/ran"; sleep 2; echo "no agent" >&2; exit 1 ;;
logs|atop|egress-report) ;;
*) exit 3 ;;
esac"#,
    );
    let ran = vk.parent().unwrap().join("ran");
    let (addr, hub, origin, local) = start_with_vk(None, vk.clone()).await;
    let id = "0123456789abcdef";
    let mut job = workload("fedcba9876543210", "rust:1.90");
    job.kind = vk_fleet_proto::WorkloadKind::CiJob;
    local.set_listing(listed(vec![workload(id, "alpine:3.20"), job]), &hub);
    let path = format!("/vm/{id}/action");

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let reply = post_action(
        addr,
        &origin,
        &viewer,
        &path,
        &format!("_csrf={viewer_csrf}&op=stop&confirm=yes"),
        true,
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let page = get(addr, &format!("/vm/{id}"), Some(&viewer)).await;
    assert!(!page.body.contains("name=\"op\""), "{}", page.body);

    let (cookie, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert!(page.body.contains("value=\"reboot\""), "{}", page.body);
    // Asked first, and nothing run.
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        &path,
        &format!("_csrf={csrf}&op=stop"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    assert!(
        reply.body.contains("name=\"confirm\" value=\"yes\""),
        "{}",
        reply.body
    );
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
    // Confirmed: run as `vk stop <pid>`, audited as it starts and as it ends.
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        &path,
        &format!("_csrf={csrf}&op=stop&confirm=yes"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("Started <code>vk stop 4242</code>"),
        "{}",
        reply.body
    );
    let events = audited(&hub, "`vk stop 4242` succeeded").await;
    assert!(
        events
            .iter()
            .any(|e| e.ends_with("(operator) ran `vk stop 4242`")),
        "{events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e.contains("(exit status: 0: virtkit: stopped pid 4242)")),
        "{events:?}"
    );
    assert_eq!(std::fs::read_to_string(&ran).unwrap(), "stop 4242\n");
    let page = get(addr, &format!("/vm/{id}"), Some(&cookie)).await;
    assert!(
        page.body.contains("<code>vk stop 4242</code> succeeded"),
        "{}",
        page.body
    );

    // A plain form goes back to the page; a second action waits for the first to end, and a
    // failure says how.
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        &path,
        &format!("_csrf={csrf}&op=reboot&confirm=yes"),
        false,
    )
    .await;
    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.header("location"),
        Some(path.trim_end_matches("/action"))
    );
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        &path,
        &format!("_csrf={csrf}&op=stop&confirm=yes"),
        true,
    )
    .await;
    assert_eq!(reply.status, 409, "{}", reply.body);
    audited(&hub, "`vk reboot 4242` failed (exit status: 1: no agent)").await;

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

/// `/dev` lists what `vk dev list` lists, stopped environments too: a stopped one starts in
/// its workspace with no question, and only a stale one is offered for removal.
#[tokio::test(flavor = "multi_thread")]
async fn dev_environments_are_started_and_cleaned_up() {
    let vk = stub_vk(
        "dev",
        r#"echo "$*" >> "$(dirname "$0")/ran"
case "$1 $2" in
"dev list") cat <<'JSON'
[{"name":"app-1111","dir":"/s/app-1111","workspace":"/src/app","environment":"dev","status":"stopped","created_by":null,"booted_secs":1790755279,"age_secs":5,"mem_used_bytes":null,"mem":null,"flags":[]},
 {"name":"old-2222","dir":"/s/old-2222","workspace":"/gone/old","environment":"dev","status":"stopped","created_by":null,"booted_secs":null,"age_secs":null,"mem_used_bytes":null,"mem":null,"flags":["workspace-missing"]},
 {"name":"../evil","dir":"/x","workspace":null,"environment":null,"status":"stopped","flags":[]}]
JSON
;;
"dev up"|"dev gc") ;;
*) exit 3 ;;
esac"#,
    );
    let ran = vk.parent().unwrap().join("ran");
    let (addr, hub, origin, _) = start_with_vk(None, vk.clone()).await;
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
            .contains("Started <code>vk dev up --workspace /src/app --environment dev</code>"),
        "{}",
        reply.body
    );
    audited(
        &hub,
        "`vk dev up --workspace /src/app --environment dev` succeeded",
    )
    .await;
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
    let reply = post_action(
        addr,
        &origin,
        &cookie,
        "/dev/old-2222/action",
        &format!("_csrf={csrf}&op=gc&confirm=yes"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    audited(&hub, "`vk dev gc --yes old-2222` succeeded").await;
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
    let _ = std::fs::remove_dir_all(vk.parent().unwrap());
}

/// A fleet hub with its UI on an ephemeral loopback port, plain HTTP; the UI's origin.
async fn start_fleet() -> (SocketAddr, Arc<Hub>, String) {
    let listener = crate::server::listen("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    let origin = format!("http://{addr}");
    let hub =
        Arc::new(Hub::new(Arc::new(Db::open_memory().unwrap())).with_ui_url(Some(origin.clone())));
    let ui = Arc::new(Ui::new(hub.clone(), &origin));
    tokio::spawn(serve(listener, None, ui));
    (addr, hub, origin)
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
        hub.db.enroll(&token, "aa", hostile, 1).unwrap()
    else {
        panic!("expected an enrollment");
    };
    let inventory = vk_fleet_proto::Inventory {
        hostname: hostile.into(),
        versions: vk_fleet_proto::Versions {
            vk: format!("0.80{hostile}\u{202e}"),
            config_hash: hostile.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    hub.db.record_inventory(&node_id, inventory, 2).unwrap();
    hub.db
        .record_report(
            &node_id,
            vk_fleet_proto::Report {
                unsupported: vec![hostile.into()],
                concurrency_error: Some(hostile.into()),
                ..Default::default()
            },
            3,
        )
        .unwrap();
    let (cookie, _) = sign_in(addr, &hub, Role::Viewer).await;
    for path in [
        "/".to_string(),
        format!("/node/{node_id}"),
        "/audit".to_string(),
    ] {
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
        .enroll(&token, &"ab".repeat(16), hostname, 1)
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
            vk_fleet_proto::Inventory {
                hostname: hostile.into(),
                ..Default::default()
            },
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
        assert_eq!(
            stream.next().await.as_deref(),
            Some("event: close\ndata: \n\n")
        );
        assert_eq!(stream.next().await, None);
    }
    assert_eq!(get(addr, "/events/nodes", Some(&cookie)).await.status, 401);
}

fn ci_workload(id: &str, owner: &str) -> vk_fleet_proto::Workload {
    vk_fleet_proto::Workload {
        id: id.into(),
        kind: vk_fleet_proto::WorkloadKind::CiJob,
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
    }
}

/// A node's workloads are on its page and counted in the nodes table, kept live, and what
/// the node says of them is text.
#[tokio::test(flavor = "multi_thread")]
async fn workloads_are_shown_live_and_as_text() {
    let (addr, hub, _) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let hostile = "acme<script>alert(1)</script>\n\nevent: evil\ndata: <img src=x>";
    let report = |workloads| vk_fleet_proto::Report {
        workloads: Some(workloads),
        ..Default::default()
    };
    hub.db
        .record_report(&node, report(vec![ci_workload("aaaa", hostile)]), 2)
        .unwrap();
    hub.db
        .record_heartbeat(
            &node,
            vk_fleet_proto::Heartbeat {
                workload_mem_bytes: [("aaaa".to_string(), 3 << 30)].into(),
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
        "<td>4321</td>",
        "<td>2.0 GiB</td>",
        "<td>3.0 GiB</td>",
    ] {
        assert!(page.body.contains(want), "{want}: {}", page.body);
    }
    assert!(!page.body.contains("<script>alert") && !page.body.contains("<img"));

    let mut nodes = Events::open(addr, "/events/nodes", &cookie).await;
    let first = nodes.next().await.unwrap();
    assert!(first.contains("<th>VMS</th>"), "{first}");
    assert!(first.contains("<td>1</td></tr>"), "{first}");

    let mut detail = Events::open(addr, &format!("/events/node/{node}"), &cookie).await;
    let first = detail.next().await.unwrap();
    assert!(first.contains("acme&lt;script&gt;"), "{first}");
    assert!(!first.contains("<script") && !first.contains("\nevent: evil"));
    // A VM starting on the node reaches both pages; one stopping leaves them.
    hub.db
        .record_report(
            &node,
            report(vec![ci_workload("bbbb", "second-project")]),
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
    next_with(&mut nodes, "<td>0</td></tr>").await;
}

/// A node's page follows that node alone.
#[tokio::test]
async fn a_node_change_wakes_that_node_s_followers_only() {
    let hub = Hub::new(Arc::new(Db::open_memory().unwrap()));
    let a = hub.subscribe_node("a");
    let mut all = hub.subscribe();
    hub.changed("b");
    assert!(!a.has_changed().unwrap());
    assert!(all.has_changed().unwrap());
    all.borrow_and_update();
    hub.changed("a");
    assert!(a.has_changed().unwrap() && all.has_changed().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_operator_steers_through_the_admin_operations_and_a_viewer_cannot() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let path = format!("/node/{node}/action");
    let origin = format!("Origin: {origin}");
    let post = |cookie: String, form: String, htmx: bool| {
        let (path, origin) = (path.clone(), origin.clone());
        async move {
            let cookie = format!("Cookie: {cookie}");
            let mut headers = vec![
                cookie.as_str(),
                origin.as_str(),
                "Content-Type: application/x-www-form-urlencoded",
            ];
            if htmx {
                headers.push("HX-Request: true");
            }
            request(addr, "POST", &path, &headers, &form).await
        }
    };
    let events = |hub: &Hub| -> Vec<(String, String)> {
        hub.db
            .audits(Some(&node), 100)
            .unwrap()
            .into_iter()
            .map(|r| (r.actor, r.event))
            .collect()
    };

    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, &format!("/node/{node}"), Some(&viewer)).await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("hx-post"), "{}", page.body);
    // A plain form post gets the page saying why.
    let reply = post(
        viewer.clone(),
        format!("_csrf={viewer_csrf}&op=drain"),
        false,
    )
    .await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    assert!(reply.header("hx-reswap").is_none());
    assert!(reply.body.contains("<!doctype html>") && reply.body.contains("operator role"));
    let reply = post(viewer, format!("_csrf={viewer_csrf}&op=drain"), true).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    assert!(reply.body.contains("operator role"), "{}", reply.body);
    assert!(hub.db.node_commands(&node).unwrap().is_empty());

    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let principal = hub
        .db
        .ui_sessions(crate::now_secs())
        .unwrap()
        .into_iter()
        .find(|s| s.role == Role::Operator)
        .unwrap()
        .principal();
    let page = get(addr, &format!("/node/{node}"), Some(&operator)).await;
    assert!(
        page.body.contains(&format!("hx-post=\"{path}\"")),
        "{}",
        page.body
    );
    // Without the token, nothing.
    let reply = post(operator.clone(), "op=drain".into(), true).await;
    assert_eq!(reply.status, 403);
    assert!(hub.db.node_commands(&node).unwrap().is_empty());

    let reply = post(
        operator.clone(),
        format!("_csrf={csrf}&op=ceiling&ceiling=3"),
        true,
    )
    .await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(
        reply.body.contains("hx-swap-oob=\"true\""),
        "{}",
        reply.body
    );
    assert!(reply.body.contains("generation 1"), "{}", reply.body);
    let desired = hub.db.node(&node).unwrap().unwrap().desired.unwrap();
    assert_eq!((desired.generation, desired.ceiling), (1, Some(3)));
    // The admin socket's operation, audited as the session.
    assert_eq!(
        events(&hub).last().unwrap(),
        &(
            principal.clone(),
            format!("{principal} set the concurrency ceiling to 3 (generation 1)")
        )
    );
    crate::ops::set_ceiling(&hub, "uid 0", &node, Some(4)).unwrap();
    assert_eq!(
        events(&hub).last().unwrap().1,
        "uid 0 set the concurrency ceiling to 4 (generation 2)"
    );
    // And refused by it: the operation's own check, said to the operator.
    let reply = post(
        operator.clone(),
        format!("_csrf={csrf}&op=ceiling&ceiling=0"),
        true,
    )
    .await;
    assert_eq!(reply.status, 400);
    assert!(
        reply.body.contains("stop acquisition instead"),
        "{}",
        reply.body
    );

    let reply = post(operator.clone(), format!("_csrf={csrf}&op=drain"), true).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let commands = hub.db.pending_commands(&node, crate::now_secs()).unwrap();
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].op, vk_fleet_proto::Operation::Drain);
    let (actor, event) = events(&hub).last().unwrap().clone();
    assert_eq!(actor, principal);
    assert!(
        event.starts_with(&format!("{principal} issued drain (command ")),
        "{event}"
    );

    // A plain form post is sent back to the node's page.
    let reply = post(operator.clone(), format!("_csrf={csrf}&op=stop"), false).await;
    assert_eq!(reply.status, 303);
    assert_eq!(
        reply.header("location"),
        Some(format!("/node/{node}").as_str())
    );
    let desired = hub.db.node(&node).unwrap().unwrap().desired.unwrap();
    assert_eq!(desired.acquisition, vk_fleet_proto::Acquisition::Stop);
    let reply = post(operator, format!("_csrf={csrf}&op=format-disks"), true).await;
    assert_eq!(reply.status, 400);
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
    ] {
        let body = get(addr, &path, Some(&cookie)).await.body;
        assert!(body.contains("\"allowEval\":false"), "{body}");
        assert!(body.contains("\"selfRequestsOnly\":true"), "{body}");
        assert_eq!(body.matches("<script").count(), 2, "{body}");
        assert_eq!(body.matches("<script src=\"/assets/").count(), 2, "{body}");
        assert!(!body.contains(" style="), "{body}");
        assert!(!body.contains(" on"), "{body}");
        assert_eq!(
            body.matches("sse-close=\"close\"").count(),
            usize::from(path != "/audit")
        );
    }
}

/// A rollout of one node named `hostname`, straight into the database.
fn rollout_of(hub: &Hub, hostname: &str) -> (String, String) {
    let node = enrolled_node(hub, hostname);
    let id = "cd".repeat(16);
    let row = crate::rollout::RolloutRow {
        release: "ab".repeat(32),
        version: "0.81.0".into(),
        created_at: 1,
        created_by: "uid 0".into(),
        batch: 1,
        canary_per_profile: true,
        max_failures: 0,
        node_timeout_secs: 600,
        drain_timeout_secs: 600,
        force: false,
        state: crate::rollout::RolloutState::Running,
        failures: 0,
        nodes: vec![crate::rollout::RolloutNode {
            id: node.clone(),
            hostname: hostname.into(),
            profile: format!("{hostname} CPU · 64G · jobs fast"),
            wave: 0,
            status: crate::rollout::NodeStatus::Failed {
                reason: format!("rolled back: {hostname}"),
                at: 2,
            },
        }],
    };
    hub.db
        .add_release(
            &row.release,
            &crate::store::ReleaseRow {
                version: "0.81.0".into(),
                size: 1,
                signature: None,
                added_at: 1,
                added_by: "uid 0".into(),
            },
            "uid 0",
        )
        .unwrap();
    hub.db.create_rollout(&id, &row, "uid 0").unwrap();
    (id, node)
}

#[tokio::test(flavor = "multi_thread")]
async fn rollouts_are_shown_live_and_steered_by_an_operator_alone() {
    let (addr, hub, origin) = start_fleet().await;
    let hostile = "ci<script>alert(1)</script>";
    let (id, _) = rollout_of(&hub, hostile);
    let (viewer, viewer_csrf) = sign_in(addr, &hub, Role::Viewer).await;
    let page = get(addr, "/operations", Some(&viewer)).await;
    assert_eq!(page.status, 200, "{}", page.body);
    assert_secure(&page);
    assert!(
        page.body.contains("sse-connect=\"/events/operations\""),
        "{}",
        page.body
    );
    assert!(page.body.contains("ci&lt;script&gt;"), "{}", page.body);
    assert!(!page.body.contains("<script>alert"), "{}", page.body);
    assert!(!page.body.contains("hx-post"), "{}", page.body);

    let path = format!("/rollout/{id}/action");
    let origin = format!("Origin: {origin}");
    let post = |cookie: &str, form: String| {
        let cookie = format!("Cookie: {cookie}");
        let (path, origin) = (path.clone(), origin.clone());
        async move {
            request(
                addr,
                "POST",
                &path,
                &[
                    &cookie,
                    &origin,
                    "HX-Request: true",
                    "Content-Type: application/x-www-form-urlencoded",
                ],
                &form,
            )
            .await
        }
    };
    let reply = post(&viewer, format!("_csrf={viewer_csrf}&op=pause")).await;
    assert_eq!(reply.status, 403, "{}", reply.body);
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let page = get(addr, "/operations", Some(&operator)).await;
    assert!(
        page.body.contains(&format!("hx-post=\"{path}\"")),
        "{}",
        page.body
    );
    // The fragment carries no token — it is rendered once for every operator — and the page
    // sets this session's as the header its buttons post with.
    assert!(
        page.body
            .contains(&format!("X-CSRF-Token&quot;:&quot;{csrf}&quot;")),
        "{}",
        page.body
    );
    let fragment = page.body.split("id=\"operations\"").nth(1).unwrap();
    assert!(!fragment.contains(&csrf), "{fragment}");
    let viewer_page = get(addr, "/operations", Some(&viewer)).await;
    assert!(
        !viewer_page.body.contains("hx-headers"),
        "{}",
        viewer_page.body
    );
    assert_eq!(post(&operator, "op=pause".into()).await.status, 403);

    let mut events = Events::open(addr, "/events/operations", &operator).await;
    let first = events.next().await.unwrap();
    assert!(first.starts_with("event: operations\ndata: "), "{first}");
    assert!(first.contains("running"), "{first}");

    let reply = post(&operator, format!("_csrf={csrf}&op=pause")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert!(reply.body.contains("is paused"), "{}", reply.body);
    let (_, row) = hub.db.resolve_rollout(&id).unwrap();
    assert!(matches!(
        row.state,
        crate::rollout::RolloutState::Paused { .. }
    ));
    let principal = hub
        .db
        .ui_sessions(crate::now_secs())
        .unwrap()
        .into_iter()
        .find(|s| s.role == Role::Operator)
        .unwrap()
        .principal();
    let last = hub.db.audits(None, 1).unwrap().remove(0);
    assert_eq!(last.actor, principal);
    // The stream follows.
    let next = events.next().await.unwrap();
    assert!(next.contains(">paused<"), "{next}");
    // Pausing a paused rollout is the operation's own refusal, said to the operator.
    let reply = post(&operator, format!("_csrf={csrf}&op=pause")).await;
    assert_eq!(reply.status, 400);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    assert_eq!(
        post(&operator, format!("_csrf={csrf}&op=wipe"))
            .await
            .status,
        400
    );
    let reply = request(
        addr,
        "POST",
        "/rollout/nothex/action",
        &[&format!("Cookie: {operator}"), &origin],
        "",
    )
    .await;
    assert_eq!(reply.status, 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_is_issued_only_once_confirmed() {
    let (addr, hub, origin) = start_fleet().await;
    let node = enrolled_node(&hub, "ci-1");
    let (operator, csrf) = sign_in(addr, &hub, Role::Operator).await;
    let post = |form: String| {
        let (cookie, origin) = (format!("Cookie: {operator}"), format!("Origin: {origin}"));
        let path = format!("/node/{node}/action");
        async move {
            request(
                addr,
                "POST",
                &path,
                &[
                    &cookie,
                    &origin,
                    "HX-Request: true",
                    "Content-Type: application/x-www-form-urlencoded",
                ],
                &form,
            )
            .await
        }
    };
    let reply = post(format!("_csrf={csrf}&op=reset")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    assert_eq!(reply.header("hx-reswap"), Some("none"));
    assert!(
        reply.body.contains("name=\"confirm\" value=\"yes\""),
        "{}",
        reply.body
    );
    assert!(hub.db.node_commands(&node).unwrap().is_empty());
    let reply = post(format!("_csrf={csrf}&op=reset&confirm=yes")).await;
    assert_eq!(reply.status, 200, "{}", reply.body);
    let commands = hub.db.pending_commands(&node, crate::now_secs()).unwrap();
    assert_eq!(
        commands[0].op,
        vk_fleet_proto::Operation::Reset { images: false }
    );
}
