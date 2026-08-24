//! `vk-registry accounts`: operator CLI over the accounts db (`accounts.rs`) — the
//! admin-grant and API-key management surface with no HTTP route by design.
//!
//! It opens the same db a server would (`ServerConfig::accounts_db_of` resolves the same
//! path `into_state` does), which means **the server has to be stopped**: redb holds an
//! exclusive `flock` for the life of the process, so a running `serve` locks even the
//! read-only subcommands out.
//!
//! An operator who can run this already has filesystem access to the accounts db — the
//! same trust level `Db::set_admin` assumed when it had no route at all — so nothing here
//! re-checks `authorize()`; that gate is for the HTTP surface, not this one. One
//! consequence worth knowing: a key's scopes are its own, so `create-key` can hand a
//! non-admin user a write-scoped key, and `revoke-admin` does not revoke it. A key minted
//! with no owner at all has nothing to check a revoke against, so `/settings/keys` cannot
//! reach it and this CLI is the only way to take it back.

use std::collections::HashMap;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};

use vk_registry::accounts::{Action, ApiKey, Db, Scope, User};

pub fn list_users(db: &Db, path: &std::path::Path) -> Result<()> {
    let users = db.list_users()?;
    if users.is_empty() {
        // Name the db, so "no users" cannot be mistaken for "wrong --root".
        println!("vk-registry accounts: {} — no users yet", path.display());
        return Ok(());
    }
    let now = SystemTime::now();
    for u in &users {
        println!(
            "{}  {}{}  admin={}  first seen {}  last login {}",
            u.oidc_subject,
            u.email.as_deref().unwrap_or("-"),
            u.display_name
                .as_deref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default(),
            u.is_admin,
            relative(now, u.created_at),
            relative(now, u.last_login_at),
        );
        println!("    issuer: {}", u.oidc_issuer);
    }
    Ok(())
}

pub fn set_admin(db: &Db, email: &str, issuer: Option<&str>, admin: bool) -> Result<()> {
    let user = resolve_user(db, email, issuer)?;
    // `set_admin` reports whether it found the row: the lookup above already resolved
    // one, so a `false` here means it went away in between, not that the id was wrong.
    if !db.set_admin(&user.id, admin)? {
        bail!("user {email:?} disappeared while granting admin; try again");
    }
    println!(
        "vk-registry accounts: {} is now {}",
        email,
        if admin {
            "an admin"
        } else {
            "no longer an admin"
        }
    );
    Ok(())
}

pub fn list_keys(db: &Db, owner_email: Option<&str>, issuer: Option<&str>) -> Result<()> {
    let keys = match owner_email {
        Some(email) => {
            let user = resolve_user(db, email, issuer)?;
            db.list_api_keys(&user.id)?
        }
        None => db.list_all_api_keys()?,
    };
    if keys.is_empty() {
        match owner_email {
            Some(e) => println!("vk-registry accounts: no API keys for {e}"),
            None => println!("vk-registry accounts: no API keys yet"),
        }
        return Ok(());
    }
    let owners = owner_labels(db, &keys)?;
    let now = SystemTime::now();
    for k in &keys {
        println!("{}", key_line(k, &owners, now));
        println!(
            "    prefix {}…  created {}  last used {}",
            k.token_prefix,
            relative(now, k.created_at),
            match k.last_used_at {
                Some(t) => relative(now, t),
                None => "never".to_string(),
            },
        );
        for s in &k.scopes {
            // In the syntax `--scope` accepts, so a listing can be fed back in.
            println!("    scope {}:{}", action_word(s.action), s.repo_pattern);
        }
    }
    Ok(())
}

/// `owner_user_id`'s email, if the key has an owner and that user still exists;
/// `"system"` for an ownerless key (see [`create_key`]); `"<deleted user>"` if the
/// owner id no longer resolves (there is no user-deletion path today, but nothing
/// prevents editing the db directly, and this should not panic if that ever happens).
/// Every user id in `keys`, resolved to a label once — one read of the users table
/// instead of one per key, and resolved *before* any line is printed so a failure cannot
/// truncate a listing halfway.
///
/// The labels for the two special cases are parenthesised, which no email is, so an
/// owner's own email can never be mistaken for one of them.
fn owner_labels(db: &Db, keys: &[ApiKey]) -> Result<HashMap<String, String>> {
    let by_id: HashMap<String, User> = db
        .list_users()?
        .into_iter()
        .map(|u| (u.id.clone(), u))
        .collect();
    Ok(keys
        .iter()
        .filter_map(|k| k.owner_user_id.clone())
        .map(|id| {
            let label = match by_id.get(&id) {
                Some(u) => u
                    .email
                    .clone()
                    .unwrap_or_else(|| format!("{} at {}", u.oidc_subject, u.oidc_issuer)),
                // Nothing removes a user today; a hand-edited db could still leave this.
                None => "(unknown user)".to_string(),
            };
            (id, label)
        })
        .collect())
}

pub fn revoke_key(db: &Db, id: &str) -> Result<()> {
    // The operator's revoke, not an owner's: `revoke_api_key_unchecked` is the one that
    // reaches an ownerless key, and an operator with the db is already past any
    // ownership question. `Ok(false)` means there was nothing live to revoke.
    if !db.revoke_api_key_unchecked(id)? {
        bail!("no live API key with id {id:?} (see `accounts list-keys` for ids)");
    }
    println!("vk-registry accounts: revoked {id}");
    Ok(())
}

/// `owner_email`, when given, ties the key to that user (looked up via
/// [`resolve_user`]); `None` mints a **system key** — owned by no one, so it
/// keeps working if that person ever leaves or has their own admin status revoked.
/// The right choice for CI.
pub fn create_key(
    db: &Db,
    owner_email: Option<&str>,
    issuer: Option<&str>,
    name: &str,
    scopes: &[Scope],
    expires_days: Option<u64>,
) -> Result<()> {
    let owner = owner_email
        .map(|email| resolve_user(db, email, issuer))
        .transpose()?;
    // Checked: both the multiply and the addition are on operator input, and a silent
    // wrap would mint a credential that expires in hours rather than years.
    let expires_at = expires_days
        .map(|d| {
            // Zero is the other end of the same operator typo: it mints a token that is
            // already past its expiry, so it never authenticates once.
            if d == 0 {
                bail!("--expires-days must be at least 1 (omit it for a key that never expires)");
            }
            let secs = d
                .checked_mul(86_400)
                .with_context(|| format!("--expires-days {d} is too large"))?;
            SystemTime::now()
                .checked_add(std::time::Duration::from_secs(secs))
                .with_context(|| format!("--expires-days {d} is too far in the future"))
        })
        .transpose()?;
    let (key, token) = db.create_api_key(
        owner.as_ref().map(|u| u.id.as_str()),
        name,
        scopes,
        expires_at,
    )?;
    // The token alone on stdout, so `create-key > file` captures the credential and
    // nothing else; what to do with it goes to stderr, as `install-service` does.
    match owner_email {
        Some(email) => eprintln!("vk-registry accounts: created key {} for {email}", key.id),
        // No owner: nothing to revoke it *by*, so say which path can.
        // No owner means no owner-side revoke: `/settings/keys` cannot reach this key,
        // so the only way back is this CLI, which needs the server stopped.
        None => eprintln!(
            "vk-registry accounts: created system key {} — it belongs to nobody, so \
             revoking it means `accounts revoke-key {}` with the server stopped",
            key.id, key.id
        ),
    }
    eprintln!("Copy this token now — it is not stored and will not be shown again.");
    println!("{token}");
    Ok(())
}

/// `ACTION:repo_pattern`, e.g. `write:team-a/*` or `read:*`.
pub fn parse_scope(s: &str) -> Result<Scope> {
    let (action, pattern) = s
        .split_once(':')
        .with_context(|| format!("scope {s:?} must be ACTION:repo_pattern, e.g. write:team-a/*"))?;
    let action = match action {
        "read" => Action::Read,
        "write" => Action::Write,
        other => bail!("scope action {other:?} must be \"read\" or \"write\""),
    };
    if pattern.is_empty() {
        bail!("scope {s:?} has an empty repo pattern");
    }
    Ok(Scope {
        action,
        repo_pattern: pattern.to_string(),
    })
}

/// The one user matching `email` — narrowed by `issuer` when the email alone is
/// ambiguous, which it is as soon as two identity providers assert the same address.
/// Never guesses: zero or several matches is an error naming what to do next.
fn resolve_user(db: &Db, email: &str, issuer: Option<&str>) -> Result<User> {
    let mut matches = db.find_users_by_email(email)?;
    if let Some(want) = issuer {
        matches.retain(|u| u.oidc_issuer == want);
    }
    match matches.len() {
        0 => match issuer {
            Some(i) => bail!("no user with email {email:?} at issuer {i:?}"),
            None => bail!("no user with email {email:?} (see `accounts list-users`)"),
        },
        1 => Ok(matches.remove(0)),
        _ => {
            let candidates = matches
                .iter()
                .map(|u| {
                    format!(
                        "  --issuer {}   (subject {})",
                        u.oidc_issuer, u.oidc_subject
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "email {email:?} matches {} users at different issuers; add one of:\n{candidates}",
                matches.len()
            )
        }
    }
}

fn action_word(a: Action) -> &'static str {
    match a {
        Action::Read => "read",
        Action::Write => "write",
    }
}

/// One key's summary line. Split out so a test can read what `list-keys` actually prints,
/// rather than only what the helpers behind it would return.
///
/// The full id, because that is what `revoke-key` takes: it is `sha256(token)`, documented
/// as safe to display, so there is nothing to truncate. The owner is a label from
/// [`owner_labels`] rather than `User::id` — that id is `issuer\x1fsubject`, so printing it
/// would put a control byte mid-line and name somebody the operator cannot look up, which
/// is exactly what this column is *for* (see the module doc on `create-key` for a
/// non-admin).
///
/// An ownerless key is named by a marker of its own rather than a reserved `owner=` value.
/// `owner=(system)` would be imitable: `email` is a provider-asserted claim that
/// `clamp_claim` bounds but does not otherwise constrain, so a user whose provider says
/// their address is `(system)` would render identically to a genuine unattended CI
/// credential — in the one column an operator reads to decide whether an unattended
/// `write:*` key is expected. `owner=-` is what a row with no email already shows in
/// `list-users`, and the marker is what carries the meaning.
fn key_line(k: &ApiKey, owners: &HashMap<String, String>, now: SystemTime) -> String {
    let (owner, marker) = match k.owner_user_id.as_deref() {
        None => ("-", "  [system key]"),
        Some(id) => (owners.get(id).map_or("(unknown user)", String::as_str), ""),
    };
    format!(
        "{}  {}  owner={}  {}{}",
        k.id,
        k.name,
        owner,
        status_of(k, now),
        marker,
    )
}

fn status_of(k: &ApiKey, now: SystemTime) -> String {
    if k.revoked_at.is_some() {
        "revoked".to_string()
    } else if k.expires_at.is_some_and(|e| e <= now) {
        "expired".to_string()
    } else {
        match k.expires_at {
            Some(e) => format!("active, expires {}", relative(now, e)),
            None => "active, no expiry".to_string(),
        }
    }
}

/// A time relative to `now`, in whichever of seconds/minutes/hours/days is coarsest
/// without rounding to zero — calendar-free and timezone-free, so this report needs no
/// date crate.
fn relative(now: SystemTime, t: SystemTime) -> String {
    let (delta, suffix) = match t.duration_since(now) {
        Ok(d) => (d, "from now"),
        // `t` is in the past, so the difference is the other way round.
        Err(e) => (e.duration(), "ago"),
    };
    let secs = delta.as_secs();
    let (n, unit) = match secs {
        0..=59 => (secs, "s"),
        60..=3599 => (secs / 60, "m"),
        3600..=86_399 => (secs / 3600, "h"),
        _ => (secs / 86_400, "d"),
    };
    format!("{n}{unit} {suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_accepts_read_and_write() {
        let s = parse_scope("write:team-a/*").unwrap();
        assert_eq!(s.action, Action::Write);
        assert_eq!(s.repo_pattern, "team-a/*");

        let s = parse_scope("read:*").unwrap();
        assert_eq!(s.action, Action::Read);
        assert_eq!(s.repo_pattern, "*");
    }

    #[test]
    fn parse_scope_rejects_malformed_input() {
        assert!(parse_scope("team-a/*").is_err()); // no ACTION: prefix
        assert!(parse_scope("delete:team-a/*").is_err()); // unknown action
        assert!(parse_scope("write:").is_err()); // empty pattern
    }

    #[test]
    fn relative_time_picks_the_coarsest_nonzero_unit() {
        let at = |s: u64| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s);
        assert_eq!(relative(at(100), at(100)), "0s from now");
        assert_eq!(relative(at(100), at(40)), "1m ago"); // 60s
        assert_eq!(relative(at(100), at(0)), "1m ago"); // 100s -> 1m
        assert_eq!(relative(at(10_000), at(100)), "2h ago"); // 9900s
        assert_eq!(relative(at(200_000), at(100)), "2d ago"); // 199900s
        assert_eq!(relative(at(100), at(160)), "1m from now");
    }

    /// The email is an identity-provider claim, so two providers can assert the same
    /// one. This never guesses: it says which `--issuer` would resolve it.
    #[test]
    fn an_ambiguous_email_is_refused_and_says_how_to_narrow_it() -> Result<()> {
        let tmp = TempDb::new();
        let db = tmp.open()?;
        assert!(resolve_user(&db, "nobody@example.com", None).is_err());

        db.upsert_user("https://issuer-a", "sub", Some("dup@example.com"), None)?;
        db.upsert_user("https://issuer-b", "sub", Some("dup@example.com"), None)?;
        let err = resolve_user(&db, "dup@example.com", None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("2 users"), "{err}");
        assert!(err.contains("--issuer https://issuer-a"), "{err}");

        // and the advice works
        let one = resolve_user(&db, "dup@example.com", Some("https://issuer-b"))?;
        assert_eq!(one.oidc_issuer, "https://issuer-b");
        assert!(resolve_user(&db, "dup@example.com", Some("https://nope")).is_err());
        Ok(())
    }

    /// `--expires-days` is operator input, and a wrap here would mint a credential that
    /// dies in hours while reporting years.
    #[test]
    fn an_unrepresentable_expiry_is_refused_rather_than_wrapping() -> Result<()> {
        let tmp = TempDb::new();
        let db = tmp.open()?;
        db.upsert_user("https://issuer", "sub", Some("a@example.com"), None)?;
        let scope = [parse_scope("read:*")?];
        // 0 is the other end of the same typo: it mints a token already past its expiry
        for days in [0, u64::MAX, u64::MAX / 86_400, 200_000_000_000_000] {
            assert!(
                create_key(&db, Some("a@example.com"), None, "k", &scope, Some(days)).is_err(),
                "{days} days must be refused"
            );
        }
        assert!(db.list_all_api_keys()?.is_empty(), "nothing may be minted");
        Ok(())
    }

    /// A scope shape the store refuses must not reach it as something already parsed.
    #[test]
    fn a_scope_the_store_refuses_is_refused_here_too() -> Result<()> {
        let tmp = TempDb::new();
        let db = tmp.open()?;
        db.upsert_user("https://issuer", "sub", Some("a@example.com"), None)?;
        // `parse_scope` accepts the syntax; the store's own check rejects the shape, and
        // `main` runs that check before it opens the db so a typo is a usage error
        let bare_star = parse_scope("write:team-a*")?;
        assert!(
            vk_registry::accounts::validate_key_input("k", std::slice::from_ref(&bare_star))
                .is_err()
        );
        assert!(
            create_key(&db, Some("a@example.com"), None, "k", &[bare_star], None).is_err(),
            "the store must refuse it even if the CLI is called directly"
        );
        Ok(())
    }

    /// The owner column exists so an operator can see who holds a write-scoped key, so it
    /// has to name a person — not `User::id`, which is `issuer\x1fsubject` and would put a
    /// control byte mid-line that maps back to nobody.
    #[test]
    fn a_keys_owner_is_named_by_something_an_operator_can_read() -> Result<()> {
        let tmp = TempDb::new();
        let db = tmp.open()?;
        let u = db.upsert_user("https://issuer", "sub-1", Some("a@example.com"), None)?;
        db.create_api_key(Some(&u.id), "ci", &[], None)?;
        // no email on the row: the subject the provider knows them by, still not the id
        let v = db.upsert_user("https://issuer", "sub-2", None, None)?;
        db.create_api_key(Some(&v.id), "ci2", &[], None)?;
        // and one with no owner at all
        db.create_api_key(None, "system", &[], None)?;

        let keys = db.list_all_api_keys()?;
        let owners = owner_labels(&db, &keys)?;
        let now = SystemTime::now();
        // the rendered lines, not just the helpers behind them
        let lines: Vec<String> = keys.iter().map(|k| key_line(k, &owners, now)).collect();
        let all = lines.join("\n");
        assert!(!all.contains('\u{1f}'), "no control byte reaches a listing");

        let line_of = |name: &str| {
            lines
                .iter()
                .find(|l| l.contains(&format!("  {name}  owner=")))
                .cloned()
                .unwrap_or_default()
        };
        assert!(line_of("ci").contains("owner=a@example.com"), "{all}");
        let no_email = line_of("ci2");
        assert!(no_email.contains("sub-2"), "{no_email}");
        assert!(
            no_email.contains("owner=sub-2 at https://issuer"),
            "the subject and its issuer, not the joined id: {no_email}"
        );
        // An ownerless key is marked, not labelled: `email` is a provider-asserted claim,
        // so a reserved `owner=` value would be imitable by whoever controls it.
        let sys = line_of("system");
        assert!(
            sys.contains("owner=-") && sys.contains("[system key]"),
            "{sys}"
        );
        let spoof = db.upsert_user("https://issuer", "sub-3", Some("(system)"), None)?;
        db.create_api_key(Some(&spoof.id), "spoof", &[], None)?;
        let keys2 = db.list_all_api_keys()?;
        let owners2 = owner_labels(&db, &keys2)?;
        let spoofed = keys2
            .iter()
            .find(|k| k.name == "spoof")
            .map(|k| key_line(k, &owners2, now))
            .unwrap_or_default();
        assert!(
            !spoofed.contains("[system key]"),
            "an email cannot pass for a system key: {spoofed}"
        );

        // a key whose user row cannot be found says so rather than showing the id
        let orphan = ApiKey {
            owner_user_id: Some("https://issuer\u{1f}gone".to_string()),
            ..keys[0].clone()
        };
        let line = key_line(&orphan, &owners, now);
        assert!(line.contains("owner=(unknown user)"), "{line}");
        assert!(!line.contains('\u{1f}'), "{line}");
        Ok(())
    }

    /// Drives every `accounts_cli` function in sequence against a real `Db` — the
    /// same functions `main.rs`'s `run_accounts` calls, just without going through
    /// clap. Each one prints to stdout (part of the CLI's job) and returns `Ok`;
    /// this checks the state changes they claim to make, not their prose output.
    #[test]
    fn full_lifecycle_smoke() -> Result<()> {
        let tmp = TempDb::new();
        let path = tmp.path();
        let db = tmp.open()?;
        db.upsert_user(
            "https://issuer",
            "alice-sub",
            Some("alice@example.com"),
            Some("Alice"),
        )?;
        list_users(&db, &path)?; // must not error on a real row

        set_admin(&db, "alice@example.com", None, true)?;
        let alice = db.find_users_by_email("alice@example.com")?.remove(0);
        assert!(alice.is_admin);

        create_key(
            &db,
            Some("alice@example.com"),
            None,
            "ci",
            &[parse_scope("write:team-a/*")?],
            Some(30),
        )?;
        // A system key: no owner, so it is tied to nobody's admin status.
        create_key(
            &db,
            None,
            None,
            "system-ci",
            &[parse_scope("read:*")?],
            None,
        )?;
        list_keys(&db, Some("alice@example.com"), None)?;
        list_keys(&db, None, None)?; // renders an ownerless key with no user to name
        let keys = db.list_api_keys(&alice.id)?;
        assert_eq!(keys.len(), 1);
        assert!(keys[0].expires_at.is_some());

        let all = db.list_all_api_keys()?;
        assert_eq!(all.len(), 2);
        let system_key = all
            .iter()
            .find(|k| k.name == "system-ci")
            .expect("the system key is listed");
        assert!(system_key.owner_user_id.is_none());
        // Owners resolve once for the whole listing, and only owned keys contribute: the
        // ownerless one is named by `key_line`, not by a label derived from a user row.
        let labels = owner_labels(&db, &all)?;
        assert_eq!(labels.len(), 1, "the ownerless key contributes no entry");
        assert_eq!(
            labels.get(keys[0].owner_user_id.as_deref().unwrap()),
            Some(&"alice@example.com".to_string())
        );

        revoke_key(&db, &keys[0].id)?;
        assert!(db.get_api_key(&keys[0].id)?.unwrap().revoked_at.is_some());
        // an unknown id and an already-revoked one are refused the same way
        assert!(revoke_key(&db, "not-a-real-id").is_err());
        assert!(revoke_key(&db, &keys[0].id).is_err());

        set_admin(&db, "alice@example.com", None, false)?;
        let alice = db.find_users_by_email("alice@example.com")?.remove(0);
        assert!(!alice.is_admin);

        // Only the operator path can revoke an ownerless key: there is no owner to check
        // it against, so `revoke_key` — what the CLI tells the operator to run — is it.
        let system = system_key.id.clone();
        assert!(
            !db.revoke_api_key(&alice.id, &system)?,
            "an ownerless key is nobody's to revoke by ownership"
        );
        revoke_key(&db, &system)?;
        assert!(db.get_api_key(&system)?.unwrap().revoked_at.is_some());

        Ok(())
    }

    /// A db in its own directory, removed when the test drops it. The pid keeps
    /// concurrent test processes apart; the `Drop` is what stops the tree growing by one
    /// directory per run, including when a test fails partway through.
    struct TempDb {
        dir: std::path::PathBuf,
    }

    impl TempDb {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "vk-accounts-cli-test-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ));
            let _ = std::fs::remove_dir_all(&dir);
            TempDb { dir }
        }

        fn open(&self) -> Result<Db> {
            Db::open(&self.path())
        }

        fn path(&self) -> std::path::PathBuf {
            vk_registry::config::default_accounts_db(&self.dir)
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
}
