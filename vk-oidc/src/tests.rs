use std::net::SocketAddr;

use super::*;
use crate::fake_idp::{self, Options};

const DEFAULT_TARGET: &str = "/browse";

fn client_for(addr: SocketAddr) -> Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Client::new(
        Config {
            issuer: format!("http://{addr}"),
            client_id: fake_idp::CLIENT_ID.to_string(),
            client_secret: fake_idp::CLIENT_SECRET.to_string(),
            redirect_uri: "https://registry.internal/auth/callback".to_string(),
            post_logout_redirect_uri: "https://registry.internal/browse".to_string(),
        },
        Landing {
            default: DEFAULT_TARGET,
            is_safe: |t| t == DEFAULT_TARGET || t.starts_with("/browse/"),
        },
    )
}

async fn fake_idp(basic_auth: bool) -> SocketAddr {
    fake_idp::start(Options {
        basic_auth,
        ..Options::default()
    })
    .await
}

/// The state out of a login URL, which is also what the browser's cookie must carry.
fn state_of(url: &str) -> String {
    url.split("state=")
        .nth(1)
        .expect("a state param")
        .split('&')
        .next()
        .expect("a value")
        .to_string()
}

#[test]
fn pkce_challenge_matches_the_rfc_7636_example() {
    // RFC 7636 appendix B's verifier/challenge pair
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    assert_eq!(
        b64url(Sha256::digest(verifier.as_bytes()).as_slice()),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    assert_eq!(b64url(b""), "");
    assert_eq!(b64url(b"f"), "Zg");
    assert_eq!(b64url(b"fo"), "Zm8");
    assert_eq!(b64url(b"foo"), "Zm9v");
}

#[test]
fn a_query_prefix_respects_an_endpoint_that_already_has_parameters() {
    assert_eq!(
        query_prefix("https://idp/authorize"),
        "https://idp/authorize?"
    );
    assert_eq!(
        query_prefix("https://idp/authorize?tenant=a"),
        "https://idp/authorize?tenant=a&"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discover_login_and_exchange_round_trip_against_a_fake_provider() {
    let addr = fake_idp(true).await;
    let client = client_for(addr);

    let (url, state) = client
        .login_url("/browse/team-a")
        .await
        .expect("a login url");
    assert!(url.starts_with(&format!("http://{addr}/authorize?")));
    assert!(url.contains("client_id=vk-client"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("code_challenge="));
    assert!(url.contains(&percent_encode("https://registry.internal/auth/callback")));
    assert_eq!(state_of(&url), state, "the cookie's state is the URL's");

    let (target, claims) = client
        .exchange("the-code", &state, Some(&state))
        .await
        .expect("the exchange succeeds");
    assert_eq!(target, "/browse/team-a");
    assert_eq!(claims["sub"], "user-42");
    assert_eq!(claims["email"], "alice@example.com");

    // single-use: the same state cannot be redeemed twice
    assert!(
        client
            .exchange("the-code", &state, Some(&state))
            .await
            .is_err()
    );
}

/// A target the caller's landing does not accept is replaced, not carried to the callback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unsafe_target_lands_on_the_default() {
    let addr = fake_idp(true).await;
    let client = client_for(addr);
    let (_, state) = client
        .login_url("//evil.example/x")
        .await
        .expect("a login url");
    let (target, _) = client
        .exchange("the-code", &state, Some(&state))
        .await
        .expect("the exchange succeeds");
    assert_eq!(target, DEFAULT_TARGET);
}

/// A provider registered for `client_secret_post` must still work — the secret moves
/// from the header into the body, and nowhere else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_secret_goes_where_the_provider_says_it_should() {
    let addr = fake_idp(false).await;
    let client = client_for(addr);
    let (_, state) = client.login_url("/browse").await.expect("a login url");
    client
        .exchange("the-code", &state, Some(&state))
        .await
        .expect("post-authenticated exchange succeeds");
}

/// The property `state` exists for: a callback the victim's browser never started
/// must not log the victim in. Without the cookie check, an attacker who completes a
/// login at the provider can hand over the callback URL and own the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_callback_without_this_browsers_cookie_is_refused() {
    let addr = fake_idp(true).await;
    let client = client_for(addr);
    let (_, state) = client.login_url("/browse").await.expect("a login url");

    assert!(
        client.exchange("the-code", &state, None).await.is_err(),
        "no cookie must not authenticate"
    );
    assert!(
        client
            .exchange("the-code", &state, Some("some-other-login"))
            .await
            .is_err(),
        "another browser's cookie must not authenticate"
    );
    // and the refusals did not consume the state, so the real browser still can
    client
        .exchange("the-code", &state, Some(&state))
        .await
        .expect("the browser that started the login still completes it");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn exchange_rejects_an_unknown_state() {
    let addr = fake_idp(true).await;
    let client = client_for(addr);
    assert!(
        client
            .exchange("code", "not-a-real-state", Some("not-a-real-state"))
            .await
            .is_err()
    );
}

/// Every endpoint this flow uses comes out of the discovery document, so a document
/// that names an issuer other than the configured one is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discovery_document_for_another_issuer_is_refused() {
    // served from 127.0.0.1, but claiming to be somebody else entirely
    let addr = fake_idp::start(Options {
        issuer: Some("https://idp.evil.example".to_string()),
        ..Options::default()
    })
    .await;
    let client = client_for(addr);
    let e = client
        .login_url("/browse")
        .await
        .expect_err("a mismatched issuer is refused")
        .to_string();
    assert!(e.contains("issuer"), "{e}");
}

/// The issuer comparison authenticates the document's *origin*, not the URLs inside
/// it — so an otherwise-honest provider naming a cleartext `token_endpoint`, which is
/// where the client secret and the code would go, fails discovery outright rather
/// than at the first exchange.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_discovery_document_naming_a_cleartext_endpoint_is_refused() {
    let addr = fake_idp::start(Options {
        token_endpoint: Some("http://idp.example/token".to_string()),
        ..Options::default()
    })
    .await;
    let client = client_for(addr);
    let e = client
        .login_url("/browse")
        .await
        .expect_err("a cleartext endpoint is refused")
        .to_string();
    assert!(e.contains("token_endpoint"), "{e}");
}

#[test]
fn a_usable_endpoint_is_absolute_https_or_loopback_and_header_safe() {
    assert!(is_usable_endpoint("https://idp.example/token"));
    assert!(is_usable_endpoint("http://127.0.0.1:9000/token"));
    assert!(!is_usable_endpoint("http://idp.example/token"));
    assert!(!is_usable_endpoint("/token"));
    // and nothing a `Location` header would refuse, which would 500 mid-flow
    assert!(!is_usable_endpoint("https://idp.example/token\r\nX: y"));
}

/// A login in flight costs memory until it expires, and a login route needs no
/// credential, so the map that holds them is capped — and at the cap it *evicts*
/// rather than refuses. Refusing would let 4096 unauthenticated GETs close sign-in
/// for everyone until the TTL ran out, including for whoever would fix it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_logins_is_evicted_not_allowed_to_close_sign_in() {
    let addr = fake_idp(true).await;
    let client = client_for(addr);
    {
        let mut pending = client.pending.lock().unwrap();
        for i in 0..MAX_PENDING_LOGINS {
            pending.insert(
                format!("state-{i}"),
                PendingLogin {
                    target: DEFAULT_TARGET.to_string(),
                    verifier: "v".to_string(),
                    expires_at: Instant::now() + LOGIN_TTL,
                },
            );
        }
    }
    let (_, state) = client
        .login_url("/browse")
        .await
        .expect("a login still starts at the cap");
    let pending = client.pending.lock().unwrap();
    assert_eq!(pending.len(), MAX_PENDING_LOGINS, "the cap still holds");
    assert!(
        pending.contains_key(&state),
        "the new login is the one kept"
    );
}

/// An in-flight login is redeemable for [`LOGIN_TTL`] and no longer: a code the
/// browser sits on for an hour must not still open a session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_login_past_its_ttl_is_refused_and_swept() {
    let addr = fake_idp(true).await;
    let client = client_for(addr);
    let stale = || PendingLogin {
        target: DEFAULT_TARGET.to_string(),
        verifier: "v".to_string(),
        // due now, so it is expired by the time anything compares against it
        expires_at: Instant::now(),
    };
    client
        .pending
        .lock()
        .unwrap()
        .insert("stale".to_string(), stale());

    let e = client
        .exchange("the-code", "stale", Some("stale"))
        .await
        .expect_err("an expired login is refused")
        .to_string();
    assert!(e.contains("expired"), "{e}");

    // and the opportunistic sweep on the next login drops it rather than leaving it
    client
        .pending
        .lock()
        .unwrap()
        .insert("stale".to_string(), stale());
    client.login_url("/browse").await.expect("a login url");
    assert!(!client.pending.lock().unwrap().contains_key("stale"));
}

/// A refused login does not sit in the map until its TTL — but only the browser that
/// started it gets to cancel it, or anyone who learned a `state` could.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_refusal_releases_the_login_only_for_its_own_browser() {
    let addr = fake_idp(true).await;
    let client = client_for(addr);
    let (_, state) = client.login_url("/browse").await.expect("a login url");

    client.abandon(&state, None);
    client.abandon(&state, Some("another-browsers-login"));
    assert!(
        client.pending.lock().unwrap().contains_key(&state),
        "nobody else may cancel this login"
    );

    client.abandon(&state, Some(&state));
    assert!(client.pending.lock().unwrap().is_empty(), "its own may");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_logout_url_names_the_client_and_where_to_land() {
    let addr = fake_idp(true).await;
    let client = client_for(addr);
    let url = client.logout_url().await.expect("advertised");
    assert_eq!(
        url,
        format!(
            "http://{addr}/logout?client_id=vk-client&post_logout_redirect_uri={}",
            percent_encode("https://registry.internal/browse")
        )
    );
}

#[test]
fn an_unverified_email_is_not_one() {
    use serde_json::json;
    let address = "admin@corp.example";
    let asserted = Email::Asserted(address);
    assert_eq!(email(&json!({"email": address})), asserted);
    assert_eq!(
        email(&json!({"email": address, "email_verified": true})),
        asserted
    );
    // Neither a bool nor a string: not a "false", so the address is kept.
    assert_eq!(
        email(&json!({"email": address, "email_verified": null})),
        asserted
    );
    assert_eq!(
        email(&json!({"email": address, "email_verified": 0})),
        asserted
    );
    assert_eq!(
        email(&json!({"email": address, "email_verified": false})),
        Email::Unverified
    );
    assert_eq!(
        email(&json!({"email": address, "email_verified": "false"})),
        Email::Unverified
    );
    assert_eq!(email(&json!({"email_verified": false})), Email::Unverified);
    assert_eq!(email(&json!({})), Email::Absent);
}

/// A log line is not a place an identity provider gets to write: a newline in an
/// `error_description` would otherwise forge whole entries.
#[test]
fn a_logged_provider_string_cannot_forge_a_log_line() {
    assert_eq!(loggable("access_denied"), "access_denied");
    assert_eq!(
        loggable("a\nvk-registry: all good\r\tb"),
        "a\u{fffd}vk-registry: all good\u{fffd}\u{fffd}b"
    );
    assert_eq!(
        loggable(&"x".repeat(MAX_LOG_FIELD_LEN + 10))
            .chars()
            .count(),
        MAX_LOG_FIELD_LEN
    );
}

/// Plain HTTP is a leak everywhere but loopback, and the loopback test has to cope
/// with a bracketed IPv6 literal as well as a port. A guard that can be fooled by its
/// own parsing is worse than none, so the URLs whose *real* host is not the one a
/// naive split sees are in here too.
#[test]
fn only_loopback_counts_as_a_local_url() {
    for ok in [
        "http://localhost",
        "http://localhost:5000",
        "http://127.0.0.1",
        "http://127.0.0.1:5000/path",
        "http://[::1]",
        "http://[::1]:5000",
        "http://[::1]:5000/path",
    ] {
        assert!(is_local_url(ok), "{ok}");
    }
    for bad in [
        "http://login.example.com",
        "http://127.0.0.1.evil.example",
        "http://[::2]:5000",
        "https://localhost",
        "localhost",
        "",
        // userinfo: the host is whatever follows the `@`
        "http://127.0.0.1@evil.example/",
        "http://[::1]@evil.example/",
        "http://localhost:x@evil.example/",
        // a bracketed literal has to end at its bracket
        "http://[::1]evil.example",
        "http://[::1",
    ] {
        assert!(!is_local_url(bad), "{bad}");
    }
}

#[test]
fn a_base_url_is_https_or_loopback_with_no_query() {
    let err = |u: &str| check_base_url("[oidc] issuer", u).unwrap_err().to_string();
    assert!(check_base_url("x", "https://login.example.com/app/1").is_ok());
    assert!(check_base_url("x", "http://127.0.0.1:9000").is_ok());
    assert!(err("http://login.example.com").contains("[oidc] issuer must be https"));
    assert!(err("https://login.example.com/?tenant=a").contains("base URL"));
    assert!(err("https://login.example.com/#x").contains("base URL"));
    assert!(err("https://login.example.com\r\nX: y").contains("control characters"));
}

#[test]
fn a_client_secret_file_is_read_bounded_trimmed_and_not_through_a_symlink() {
    let dir = std::env::temp_dir().join(format!("vk-oidc-secret-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("secret");
    let read = |p: &Path| read_client_secret(p, |_| ()).map_err(|e| format!("{e:#}"));

    std::fs::write(&path, "s3cr3t\n").unwrap();
    let mut checked = false;
    assert_eq!(
        read_client_secret(&path, |_| checked = true).unwrap(),
        "s3cr3t"
    );
    assert!(checked, "the mode check sees the opened file");

    std::fs::write(&path, "\n").unwrap();
    assert!(read(&path).unwrap_err().contains("is empty"));
    std::fs::write(&path, "x".repeat(MAX_CLIENT_SECRET_LEN as usize + 1)).unwrap();
    assert!(read(&path).unwrap_err().contains("not a client secret"));
    std::fs::write(&path, [0xff, 0xfe]).unwrap();
    assert!(read(&path).unwrap_err().contains("not text"));

    let link = dir.join("link");
    std::fs::write(&path, "s3cr3t").unwrap();
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(read(&link).is_err(), "a symlink is not followed");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A login taken from one client is the other's to redeem, with its target and verifier and
/// what was left of it, at most `LOGIN_TTL`; one with an unsafe target, no time left, or a
/// state already held is not taken on. Meanwhile the first starts and redeems none.
#[tokio::test]
async fn logins_taken_from_one_client_are_redeemed_by_another() {
    let addr = fake_idp(false).await;
    let (from, to) = (client_for(addr), client_for(addr));
    let (url, _) = from.login_url("/browse/r").await.unwrap();
    let state = state_of(&url);
    let mut taken = from.take_pending();
    assert!(from.pending.lock().unwrap().is_empty());
    assert_eq!(taken.len(), 1);
    assert!(taken[0].left > Duration::ZERO && taken[0].left <= LOGIN_TTL);
    // None is started or redeemed once they are taken, until some are given back.
    let e = from.login_url("/browse").await.unwrap_err();
    assert!(e.is::<LoginsHandedOver>(), "{e:#}");
    let e = from
        .exchange("the-code", &state, Some(&state))
        .await
        .unwrap_err();
    assert!(e.is::<LoginsHandedOver>(), "{e:#}");
    let pending = |state: &str, target: &str, left: Duration| Pending {
        state: state.into(),
        target: target.into(),
        verifier: "v".into(),
        left,
    };
    taken.push(pending("unsafe", "https://elsewhere.example/", LOGIN_TTL));
    taken.push(pending("lapsed", DEFAULT_TARGET, Duration::ZERO));
    taken.push(pending("long", DEFAULT_TARGET, 10 * LOGIN_TTL));
    taken.push(pending("", DEFAULT_TARGET, LOGIN_TTL));
    taken.push(Pending {
        verifier: String::new(),
        ..pending("no-verifier", DEFAULT_TARGET, LOGIN_TTL)
    });
    let (held, _) = to.login_url("/browse/held").await.unwrap();
    let held = state_of(&held);
    taken.push(pending(&held, DEFAULT_TARGET, LOGIN_TTL));
    assert_eq!(to.restore_pending(taken), 2);
    {
        let pending = to.pending.lock().unwrap();
        assert_eq!(pending.len(), 3);
        assert!(pending["long"].expires_at <= Instant::now() + LOGIN_TTL);
        assert_eq!(pending[&held].target, "/browse/held");
        assert_eq!(pending[&state].target, "/browse/r");
    }
    let (target, _) = to.exchange("the-code", &state, Some(&state)).await.unwrap();
    assert_eq!(target, "/browse/r");
    assert_eq!(from.restore_pending(Vec::new()), 0);
    from.login_url("/browse").await.unwrap();
    let e = from
        .exchange("the-code", &state, Some(&state))
        .await
        .unwrap_err();
    assert!(!e.is::<LoginsHandedOver>(), "{e:#}");
}

/// Logins taken on past the cap drop the soonest to expire, as starting one does.
#[tokio::test]
async fn logins_taken_on_past_the_cap_drop_the_soonest_to_expire() {
    let addr = fake_idp(false).await;
    let client = client_for(addr);
    let logins = (0..=MAX_PENDING_LOGINS)
        .map(|i| Pending {
            state: format!("s{i}"),
            target: DEFAULT_TARGET.into(),
            verifier: "v".into(),
            left: Duration::from_secs(10 + i as u64),
        })
        .collect();
    assert_eq!(client.restore_pending(logins), MAX_PENDING_LOGINS);
    let pending = client.pending.lock().unwrap();
    assert_eq!(pending.len(), MAX_PENDING_LOGINS);
    assert!(!pending.contains_key("s0"));
    assert!(pending.contains_key(&format!("s{MAX_PENDING_LOGINS}")));
}
