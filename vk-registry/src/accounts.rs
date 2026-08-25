//! Accounts mode: an embedded identity store (users, sessions, API keys) alongside the
//! filesystem CAS `Store`, and [`resolve_principal`] — turning a request's session
//! cookie or `vkr_…` bearer token into a [`Principal`]. See `DESIGN.md`'s "Accounts,
//! OIDC, and scoped API keys" section.
//!
//! Storage is [`redb`], three tables of JSON-blob rows — see `DESIGN.md` for why not
//! sqlite. Row counts are small (users, sessions, API keys for one team/org) so a linear
//! scan for "list a user's keys" is plenty.
//!
//! Credential lookup *is* on the request path (every `/v2/` request presents one), so it
//! runs in a read transaction. An API key lookup's only write is a coarse `last_used_at`
//! bump, rate-limited to [`LAST_USED_GRANULARITY_SECS`] and committed with
//! `Durability::Eventual` so a blob push does not pay an fsync per chunk; a session
//! lookup additionally deletes the row when it finds one expired, which is a durable
//! single-row write, but only ever once per dead cookie.
//!
//! Nothing here is stored in a form that a reader of the db file can present as a
//! credential: an API key row is keyed by `sha256(token)` and a session row by
//! `sha256(session_id)`, so the file holds no bearer string and no cookie value.
//!
//! This module only *authenticates* a request (who is this, if anyone). Authorization
//! (what a resolved principal may do) is [`Scope::allows`] plus route-level checks that
//! arrive in the order `DESIGN.md` sets out — until then, an accounts-mode server behind
//! [`crate::route`] accepts any resolved principal for any request, the same coarse shape
//! as the shared-secret mode it replaces.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::{HeaderMap, Request, Response};
use rand::Rng;
use redb::{Database, Durability, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::{hex_of, sha256_hex_raw};

/// Key: `"{issuer}\x1f{subject}"` (see [`user_key`]). Value: JSON [`UserRow`].
const USERS: TableDefinition<&str, &[u8]> = TableDefinition::new("users");
/// Key: `sha256(session id)`, hex — the cookie value itself is never stored, so the db
/// file holds nothing that can be replayed as a session. Value: JSON [`SessionRow`].
const SESSIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("sessions");
/// Key: `sha256(bearer token)`, hex. Value: JSON [`ApiKeyRow`].
const API_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("api_keys");

/// Every API key's bearer string starts with this, so a credential can be recognized as
/// one of ours before it is hashed and looked up.
const KEY_PREFIX: &str = "vkr_";

/// How stale a key's `last_used_at` is allowed to get before a lookup writes a fresh one.
/// The field drives "when was this key last seen" in a listing, where minute granularity
/// is ample; without a floor here every authenticated request would take the db's single
/// write lock (see the module doc).
const LAST_USED_GRANULARITY_SECS: i64 = 60;

/// Caps on the caller-supplied parts of an API key. These are stored verbatim and echoed
/// back in listings, and `/settings/keys` will hand them straight from a form, so the
/// bound belongs here — at the store, not at each caller.
const MAX_KEY_NAME_LEN: usize = 128;
const MAX_KEY_SCOPES: usize = 32;
const MAX_REPO_PATTERN_LEN: usize = 256;

/// Both halves of a user key are IdP-supplied, and the pair becomes a redb key.
const MAX_IDENTITY_LEN: usize = 512;

/// Cap on an IdP-supplied display claim (`email`, `name`). Like a key's name, these are
/// stored and rendered back into a page, so the bound belongs here — at the store, so
/// every caller gets it and not just the login handler.
const MAX_CLAIM_LEN: usize = 256;

// The three row types are the on-disk format. A decode failure is not recoverable — it
// fails the lookup, and `list_api_keys` fails the whole listing — so a field added to any
// of them later must be `Option` or `#[serde(default)]`, never a bare required field, or
// every row written before the upgrade stops decoding and its credentials stop working.
#[derive(Serialize, Deserialize)]
struct UserRow {
    oidc_issuer: String,
    oidc_subject: String,
    email: Option<String>,
    display_name: Option<String>,
    is_admin: bool,
    created_at: i64,
    last_login_at: i64,
}

#[derive(Serialize, Deserialize)]
struct SessionRow {
    user_key: String,
    csrf_secret: String,
    created_at: i64,
    /// Absolute, not sliding: a session dies `SESSION_TTL` after it was minted however
    /// much it is used, so a stolen cookie has a bounded shelf life and no request has to
    /// write to keep one alive. See `DESIGN.md`'s "OIDC login".
    expires_at: i64,
}

#[derive(Serialize, Deserialize)]
struct ApiKeyRow {
    owner_user_key: Option<String>,
    name: String,
    token_prefix: String,
    scopes: Vec<Scope>,
    created_at: i64,
    expires_at: Option<i64>,
    last_used_at: Option<i64>,
    revoked_at: Option<i64>,
}

/// A signed-in human (`sub`/`email` from an OIDC provider). `id` is the stable
/// `"{issuer}\x1f{subject}"` key — there is no separate autoincrement id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub oidc_issuer: String,
    pub oidc_subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub is_admin: bool,
}

/// A scoped, revocable CI credential. `id` is `sha256(token)`, hex — already
/// irreversible, so it doubles as a safe-to-display identifier for revoke calls. The
/// bearer string itself is returned once, at creation, and never stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiKey {
    pub id: String,
    pub owner_user_id: Option<String>,
    pub name: String,
    /// The first 8 characters of the key's random half. Enough to tell two of a user's
    /// keys apart in a listing; it is part of the secret, but 32 of its 256 bits, which
    /// leaves guessing the rest no easier than guessing all of it.
    pub token_prefix: String,
    pub scopes: Vec<Scope>,
    pub created_at: SystemTime,
    pub expires_at: Option<SystemTime>,
    pub last_used_at: Option<SystemTime>,
    pub revoked_at: Option<SystemTime>,
}

/// What a grant permits. `Write` also satisfies a `Read` check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Read,
    Write,
}

/// One `(action, repo_pattern)` grant. `repo_pattern` matches the same `<name>` used in
/// `/v2/<name>/...` and `repos/<name>` on disk; a trailing `*` is a prefix match, else
/// exact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub action: Action,
    pub repo_pattern: String,
}

impl Scope {
    pub fn allows(&self, action: Action, repo: &str) -> bool {
        let action_ok =
            self.action == action || (self.action == Action::Write && action == Action::Read);
        if !action_ok {
            return false;
        }
        match self.repo_pattern.strip_suffix('*') {
            Some(prefix) => repo.starts_with(prefix),
            None => repo == self.repo_pattern,
        }
    }
}

/// Who a request authenticated as, if anyone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Principal {
    Session(User),
    ApiKey(ApiKey),
}

/// The embedded identity store. Reads take a short read transaction; the writes are
/// login, session and key lifecycle, plus the throttled `last_used_at` bump — same
/// per-call granularity the `Store`'s `flock` already uses.
pub struct Db {
    db: Database,
}

impl Db {
    /// Open (creating if absent) and ensure the three tables exist.
    ///
    /// The file holds no usable credential, but it does hold who may write to the
    /// registry, so it is created `0600` and only ever opened `O_NOFOLLOW`: a db file that
    /// appeared at this path since the last start is not one this server made, and
    /// following a symlink planted there would let whoever planted it choose the admins.
    ///
    /// A directory this call has to create is `0700` — the default path puts the db in one
    /// of its own for exactly that reason, since a directory anyone else can write to lets
    /// them rename the db out from under a `0600` file. A directory that already exists (a
    /// configured `accounts_db` pointing into one) keeps its own mode and is warned about
    /// rather than silently tightened.
    pub fn open(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            let mut b = std::fs::DirBuilder::new();
            b.recursive(true);
            #[cfg(unix)]
            b.mode(0o700);
            b.create(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
            crate::warn_if_mode(
                parent,
                0o022,
                "the directory holding the accounts db",
                "it is writable by others, who could replace the db in it",
            );
        }

        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        // `create_new` rather than `create`: creation is the one moment the mode above is
        // honoured, and the one moment a planted symlink can be rejected outright.
        let file = match opts.clone().create_new(true).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // Open first, then judge the mode off the descriptor: checking the path and
                // then opening it resolves it twice, and the file described would not have
                // to be the file opened. `O_NOFOLLOW` is why a symlink is worth naming here
                // — the caller otherwise sees a bare ELOOP.
                let file = opts.open(path).with_context(|| {
                    format!(
                        "opening {} (a symlink at this path is refused)",
                        path.display()
                    )
                })?;
                crate::warn_if_file_mode(
                    &file,
                    path,
                    0o077,
                    "accounts db",
                    "it is group/world-accessible — restrict it to 0600",
                );
                file
            }
            Err(e) => {
                return Err(e).with_context(|| format!("creating {}", path.display()));
            }
        };
        // redb holds an exclusive `flock` for the life of the process, so a second
        // `vk-registry serve` on the same root fails here; say so, rather than leaving the
        // operator with redb's bare "database already open".
        let db = Database::builder().create_file(file).with_context(|| {
            format!(
                "opening the accounts db at {} (one server at a time per store: the \
                 accounts db is single-writer)",
                path.display()
            )
        })?;
        Self::init(db)
    }

    /// In-memory store, for tests.
    #[cfg(test)]
    fn open_memory() -> Result<Self> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .context("opening an in-memory accounts db")?;
        Self::init(db)
    }

    fn init(db: Database) -> Result<Self> {
        let txn = db
            .begin_write()
            .context("starting the accounts db's first write")?;
        txn.open_table(USERS).context("opening the users table")?;
        txn.open_table(SESSIONS)
            .context("opening the sessions table")?;
        txn.open_table(API_KEYS)
            .context("opening the api_keys table")?;
        txn.commit().context("initializing the accounts db")?;
        Ok(Db { db })
    }

    /// Create the user on first login, else update its claims and touch `last_login_at`.
    ///
    /// `is_admin` is never lowered here: it is set out of band (the `accounts` CLI, an
    /// admin UI), and a re-login must not silently revoke it. An absent optional claim is
    /// likewise treated as "the provider did not say", not "clear it".
    pub fn upsert_user(
        &self,
        issuer: &str,
        subject: &str,
        email: Option<&str>,
        display_name: Option<&str>,
    ) -> Result<User> {
        validate_identity(issuer, subject)?;
        let key = user_key(issuer, subject);
        let now = now_secs();
        let txn = self.db.begin_write().context("starting a write")?;
        let row = {
            let mut table = txn.open_table(USERS)?;
            let prior = table
                .get(key.as_str())?
                .map(|g| decode::<UserRow>(g.value()))
                .transpose()?;
            let (created_at, is_admin, prior_email, prior_name) = match prior {
                Some(p) => (p.created_at, p.is_admin, p.email, p.display_name),
                None => (now, false, None, None),
            };
            let row = UserRow {
                oidc_issuer: issuer.to_string(),
                oidc_subject: subject.to_string(),
                // `filter`, because clamping can empty a claim entirely (a `name` of
                // nothing but control characters), and an empty one must not overwrite a
                // good stored value any more than an absent one does.
                email: email
                    .map(clamp_claim)
                    .filter(|s| !s.is_empty())
                    .or(prior_email),
                display_name: display_name
                    .map(clamp_claim)
                    .filter(|s| !s.is_empty())
                    .or(prior_name),
                is_admin,
                created_at,
                last_login_at: now,
            };
            table.insert(key.as_str(), encode(&row)?.as_slice())?;
            row
        };
        txn.commit().context("upserting a user")?;
        Ok(user_from_row(key, row))
    }

    pub fn get_user(&self, id: &str) -> Result<Option<User>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(USERS)?;
        Ok(table
            .get(id)?
            .map(|g| decode::<UserRow>(g.value()))
            .transpose()?
            .map(|row| user_from_row(id.to_string(), row)))
    }

    /// Start a session for the user identified by `user_id` (a [`User::id`]), valid for
    /// `ttl`. Returns the opaque session id (the cookie value) — generated here, not by
    /// the caller, so it is always cryptographically random, and stored only as its hash.
    pub fn create_session(&self, user_id: &str, ttl: Duration) -> Result<String> {
        let id = random_token(32);
        let now = now_secs();
        let ttl_secs = i64::try_from(ttl.as_secs()).context("session ttl out of range")?;
        let expires_at = now
            .checked_add(ttl_secs)
            .context("session ttl out of range")?;
        let row = SessionRow {
            user_key: user_id.to_string(),
            csrf_secret: random_token(32),
            created_at: now,
            expires_at,
        };
        let txn = self.db.begin_write().context("starting a write")?;
        {
            // A session for a user that does not exist would resolve to `None` forever,
            // indistinguishable from expiry; reject it where the caller can still react.
            let users = txn.open_table(USERS)?;
            if users.get(user_id)?.is_none() {
                bail!("no such user: {user_id}");
            }
            let mut table = txn.open_table(SESSIONS)?;
            table.insert(session_key(&id).as_str(), encode(&row)?.as_slice())?;
        }
        txn.commit().context("creating a session")?;
        Ok(id)
    }

    /// The session's user, if the id exists and has not expired. A session found expired
    /// is deleted on the way out, so the table does not grow without bound; nothing else
    /// sweeps it.
    pub fn get_session_user(&self, id: &str) -> Result<Option<User>> {
        let key = session_key(id);
        let txn = self.db.begin_read().context("starting a read")?;
        let sessions = txn.open_table(SESSIONS)?;
        let Some(row) = sessions
            .get(key.as_str())?
            .map(|g| decode::<SessionRow>(g.value()))
            .transpose()?
        else {
            return Ok(None);
        };
        if row.expires_at <= now_secs() {
            drop(sessions);
            drop(txn);
            // Opportunistic: the answer is `None` whether or not the row goes away, and a
            // failed cleanup write must not turn an expired cookie into a 500.
            if let Err(e) = self.delete_session(id) {
                eprintln!("vk-registry: warning: dropping an expired session: {e:#}");
            }
            return Ok(None);
        }
        let users = txn.open_table(USERS)?;
        Ok(users
            .get(row.user_key.as_str())?
            .map(|g| decode::<UserRow>(g.value()))
            .transpose()?
            .map(|u| user_from_row(row.user_key, u)))
    }

    /// The session's CSRF secret, for guarding a state-changing form submitted with this
    /// cookie. `None` if the session is unknown or expired — the same three cases
    /// [`Self::get_session_user`] collapses.
    pub fn session_csrf(&self, id: &str) -> Result<Option<String>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let sessions = txn.open_table(SESSIONS)?;
        Ok(sessions
            .get(session_key(id).as_str())?
            .map(|g| decode::<SessionRow>(g.value()))
            .transpose()?
            .filter(|row| row.expires_at > now_secs())
            .map(|row| row.csrf_secret))
    }

    pub fn delete_session(&self, id: &str) -> Result<()> {
        let txn = self.db.begin_write().context("starting a write")?;
        {
            txn.open_table(SESSIONS)?.remove(session_key(id).as_str())?;
        }
        txn.commit().context("deleting a session")?;
        Ok(())
    }

    /// Mint a new API key. Returns the key row and the plaintext bearer token — the only
    /// time it is ever available; only its hash is stored (as the row's key).
    pub fn create_api_key(
        &self,
        owner_user_id: Option<&str>,
        name: &str,
        scopes: &[Scope],
        expires_at: Option<SystemTime>,
    ) -> Result<(ApiKey, String)> {
        validate_key_input(name, scopes)?;
        // The prefix comes from the random half, not from `token`: `"vkr_"` is a constant,
        // so a prefix of the whole token would carry only 16 bits of distinguishing
        // entropy — birthday collisions inside one user's listing at a few hundred keys.
        let secret = random_token(32);
        let token_prefix = secret.chars().take(8).collect::<String>();
        let token = format!("{KEY_PREFIX}{secret}");
        let id = sha256_hex_raw(token.as_bytes());
        let row = ApiKeyRow {
            owner_user_key: owner_user_id.map(str::to_string),
            name: name.to_string(),
            token_prefix,
            scopes: scopes.to_vec(),
            created_at: now_secs(),
            expires_at: expires_at.map(to_secs),
            last_used_at: None,
            revoked_at: None,
        };
        let txn = self.db.begin_write().context("starting a write")?;
        {
            // As in `create_session`: a key owned by a user that does not exist is absent
            // from its owner's listing and so unrevokable through `revoke_api_key`, and
            // indistinguishable from a deliberately ownerless one. `None` is the way to
            // ask for ownerless.
            if let Some(owner) = owner_user_id
                && txn.open_table(USERS)?.get(owner)?.is_none()
            {
                bail!("no such user: {owner}");
            }
            txn.open_table(API_KEYS)?
                .insert(id.as_str(), encode(&row)?.as_slice())?;
        }
        txn.commit().context("creating an API key")?;
        Ok((api_key_from_row(id, &row), token))
    }

    /// Look up a bearer token by its hash. `None` if absent, revoked, or expired — the
    /// three cases a caller treats identically (an invalid credential).
    ///
    /// Validation is a read, so concurrent authenticated requests do not serialize on the
    /// db's single write lock; only a `last_used_at` older than
    /// [`LAST_USED_GRANULARITY_SECS`] takes a (non-fsyncing) write.
    pub fn get_api_key_by_token(&self, token: &str) -> Result<Option<ApiKey>> {
        let id = sha256_hex_raw(token.as_bytes());
        let now = now_secs();
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(API_KEYS)?;
        let Some(row) = table
            .get(id.as_str())?
            .map(|g| decode::<ApiKeyRow>(g.value()))
            .transpose()?
        else {
            return Ok(None);
        };
        if row.revoked_at.is_some() {
            return Ok(None);
        }
        if let Some(exp) = row.expires_at
            && exp <= now
        {
            return Ok(None);
        }
        drop(table);
        drop(txn);
        let stale = row
            .last_used_at
            .is_none_or(|t| now.saturating_sub(t) >= LAST_USED_GRANULARITY_SECS);
        let mut key = api_key_from_row(id.clone(), &row);
        if stale {
            // Opportunistic, exactly as the expired-session sweep is: `last_used_at` drives
            // a "last seen" column, and a write that fails must not turn a valid key into a
            // 500 for a request that was properly authenticated.
            match self.touch_api_key(&id, now) {
                Ok(()) => key.last_used_at = Some(from_secs(now)),
                Err(e) => eprintln!("vk-registry: warning: recording an API key's use: {e:#}"),
            }
        }
        Ok(Some(key))
    }

    /// Record that a key was just used. Committed with `Durability::Eventual`: losing the
    /// most recent bump to a crash costs nothing, and an fsync per authenticated request
    /// would be felt on every chunk of a push.
    fn touch_api_key(&self, id: &str, now: i64) -> Result<()> {
        let mut txn = self.db.begin_write().context("starting a write")?;
        txn.set_durability(Durability::Eventual);
        {
            let mut table = txn.open_table(API_KEYS)?;
            let Some(mut row) = table
                .get(id)?
                .map(|g| decode::<ApiKeyRow>(g.value()))
                .transpose()?
            else {
                return Ok(());
            };
            row.last_used_at = Some(now);
            table.insert(id, encode(&row)?.as_slice())?;
        }
        txn.commit().context("touching an API key's last_used_at")?;
        Ok(())
    }

    /// Revoke one of `owner_user_id`'s keys. `Ok(false)` if there is no such key, if it
    /// belongs to someone else, or if it was already revoked — the caller cannot tell
    /// which, and an id it was never shown is indistinguishable from one that is gone.
    /// An already-revoked key keeps its original `revoked_at`.
    pub fn revoke_api_key(&self, owner_user_id: &str, id: &str) -> Result<bool> {
        self.revoke(id, Some(owner_user_id))
    }

    /// Revoke any key, ownerless ones included. For an admin or the `accounts` CLI, which
    /// answer to the operator rather than to a key's owner.
    pub fn revoke_api_key_unchecked(&self, id: &str) -> Result<bool> {
        self.revoke(id, None)
    }

    fn revoke(&self, id: &str, require_owner: Option<&str>) -> Result<bool> {
        let txn = self.db.begin_write().context("starting a write")?;
        let revoked = {
            let mut table = txn.open_table(API_KEYS)?;
            let existing = table
                .get(id)?
                .map(|g| decode::<ApiKeyRow>(g.value()))
                .transpose()?;
            match existing {
                Some(mut row)
                    if row.revoked_at.is_none()
                        && require_owner
                            .is_none_or(|o| row.owner_user_key.as_deref() == Some(o)) =>
                {
                    row.revoked_at = Some(now_secs());
                    table.insert(id, encode(&row)?.as_slice())?;
                    true
                }
                _ => false,
            }
        };
        txn.commit().context("revoking an API key")?;
        Ok(revoked)
    }

    /// All keys owned by `owner_user_id`, newest first. A linear scan — see the module
    /// doc for why that is fine at this data's expected scale. A row that fails to decode
    /// fails the whole listing rather than being silently dropped, so a key never goes
    /// missing from the page its owner revokes it from.
    pub fn list_api_keys(&self, owner_user_id: &str) -> Result<Vec<ApiKey>> {
        let txn = self.db.begin_read().context("starting a read")?;
        let table = txn.open_table(API_KEYS)?;
        let mut keys = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            let row = decode::<ApiKeyRow>(v.value())?;
            if row.owner_user_key.as_deref() == Some(owner_user_id) {
                keys.push(api_key_from_row(k.value().to_string(), &row));
            }
        }
        keys.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        Ok(keys)
    }
}

/// Resolve the request's principal: a `vkr_…` bearer token, else a session cookie.
/// Mutually exclusive — a bearer header present means the cookie is not even inspected,
/// matching the shared-secret path's precedent of one credential per request.
pub fn resolve_principal(
    db: &Db,
    req: &Request<Incoming>,
    secure: bool,
) -> Result<Option<Principal>> {
    resolve_headers(db, req.headers(), secure)
}

/// [`resolve_principal`]'s body, over the headers alone — a `Request<Incoming>` can only
/// be built by a live connection, so this is the testable half.
fn resolve_headers(db: &Db, headers: &HeaderMap, secure: bool) -> Result<Option<Principal>> {
    // An `Authorization` header is a claim to be authenticated by it, so one that does not
    // carry a `vkr_…` key is a failed authentication rather than a reason to fall back to
    // the cookie — otherwise a stale shared-secret client would silently authenticate as
    // whoever's browser session happened to be attached to the same request.
    if headers.contains_key(hyper::header::AUTHORIZATION) {
        let Some(token) = api_key_token(headers) else {
            return Ok(None);
        };
        return Ok(db.get_api_key_by_token(&token)?.map(Principal::ApiKey));
    }
    if let Some(session_id) = session_cookie(headers, secure) {
        return Ok(db.get_session_user(&session_id)?.map(Principal::Session));
    }
    Ok(None)
}

/// The `vkr_…` key a request presents, in either shape a client can send it.
///
/// `Authorization: Bearer vkr_…` is the native form. A standard OCI client (`docker
/// login`, podman, skopeo) has no way to send a raw bearer header, so a key handed to one
/// arrives as Basic credentials instead; either half is accepted, because which field a
/// client puts a token in is not something they agree on.
fn api_key_token(headers: &HeaderMap) -> Option<String> {
    if let Some(token) = credential(headers, "bearer") {
        return token.starts_with(KEY_PREFIX).then(|| token.to_string());
    }
    let raw = crate::auth::base64_decode(credential(headers, "basic")?)?;
    let creds = String::from_utf8(raw).ok()?;
    let (user, pass) = creds.split_once(':')?;
    [pass, user]
        .into_iter()
        .find(|half| half.starts_with(KEY_PREFIX))
        .map(str::to_string)
}

/// The 401 challenge for a request with no valid session cookie or API key.
///
/// `Bearer`, even though [`api_key_token`] also accepts a key presented as Basic. A client
/// that follows the challenge cannot use that: `oci-client` (and docker) read
/// `Bearer realm=…` as a token-endpoint URL to fetch from, and `"vk-registry"` is not one,
/// so they fail rather than fall back to Basic. Advertising both does not help — the first
/// parseable `Bearer` wins. The Basic path is therefore for a client sending credentials it
/// was configured with, not one discovering how to authenticate; making discovery work
/// needs a real token endpoint or the browser login flow, which is what the OIDC step
/// brings, so the choice belongs there rather than here.
pub fn challenge() -> Response<Full<Bytes>> {
    crate::unauthorized(
        "Bearer realm=\"vk-registry\"",
        "sign in or provide a vkr_ API key",
    )
}

/// The credential for `scheme`, if the request carries one. The scheme name is matched
/// case-insensitively and the separator is `1*SP`, both per RFC 7235.
fn credential<'h>(headers: &'h HeaderMap, scheme: &str) -> Option<&'h str> {
    let v = headers
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let (got, credential) = v.split_once(' ')?;
    got.eq_ignore_ascii_case(scheme)
        .then(|| credential.trim_start())
}

/// The session cookie's name in its `__Host-`-prefixed form — accepted by a browser only
/// with `Secure` and `Path=/`, and, the point, writable by no other host: without the
/// prefix a sibling or parent host on the same registrable domain can plant a session
/// cookie (fixation) or a login state of its own.
pub(crate) const SESSION_COOKIE_HOST: &str = "__Host-vk_session";

/// The same cookie without the prefix, for the loopback-plaintext deployment
/// `ServerConfig` allows: `__Host-` requires `Secure`, which a browser will not store
/// over plain HTTP.
pub(crate) const SESSION_COOKIE: &str = "vk_session";

/// How long a session lasts after login — an absolute lifetime, not sliding, so a
/// stolen cookie has a bounded shelf life regardless of continued use.
pub(crate) const SESSION_TTL: Duration = Duration::from_secs(8 * 3600);

/// The session cookie's value, hand-parsed (no cookie crate in the tree) out of a
/// `Cookie: a=b; __Host-vk_session=…; c=d` header — under *only* the name
/// [`set_cookie_header`] would have written on this deployment (see
/// [`crate::ServerState::cookies_are_secure`]).
///
/// Reading both names would give the `__Host-` prefix away: on a TLS deployment the
/// server never sets the bare name, so a bare cookie can only be one some *other* host
/// wrote — precisely the tossed cookie the prefix exists to reject. Accepting it as a
/// fallback would restore session fixation.
///
/// `pub(crate)` — the login/logout handlers (`oidc.rs`) need it too.
pub(crate) fn session_cookie(headers: &HeaderMap, secure: bool) -> Option<String> {
    cookie(headers, session_cookie_name(secure))
}

/// One named cookie's value, hand-parsed (no cookie crate in the tree). A client may
/// split its cookies over several `Cookie` headers, so all of them are scanned.
pub(crate) fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|header| header.split(';'))
        .find_map(|pair| {
            let (k, v) = pair.trim().split_once('=')?;
            (k == name).then(|| v.to_string())
        })
}

/// The `Set-Cookie` header value that logs a session in. `secure` should be true iff
/// this connection is TLS — marking a cookie `Secure` over plain HTTP would just make
/// the browser silently refuse to store it, breaking the loopback-plaintext deployment
/// `ServerConfig` otherwise allows. That is also what decides the name: `__Host-` is
/// only accepted alongside `Secure`, so the plaintext deployment gets the bare name and,
/// with it, no protection against a sibling host writing the cookie.
pub(crate) fn set_cookie_header(session_id: &str, secure: bool) -> String {
    let name = session_cookie_name(secure);
    let max_age = SESSION_TTL.as_secs();
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{name}={session_id}; Path=/; HttpOnly{secure_attr}; SameSite=Lax; Max-Age={max_age}")
}

/// Which of the two names [`set_cookie_header`] writes on this deployment — and so the
/// only one [`session_cookie`] reads.
fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        SESSION_COOKIE_HOST
    } else {
        SESSION_COOKIE
    }
}

/// The `Set-Cookie` header value that logs a session out (an immediately expiring
/// cookie with the same attributes as [`set_cookie_header`], so the browser matches and
/// clears the one it holds).
pub(crate) fn clear_cookie_header(secure: bool) -> String {
    let name = session_cookie_name(secure);
    let secure_attr = if secure { "; Secure" } else { "" };
    format!("{name}=; Path=/; HttpOnly{secure_attr}; SameSite=Lax; Max-Age=0")
}

/// The stable primary key for a user row: OIDC identity is `(issuer, subject)`, joined by
/// `\x1f`. [`validate_identity`] is what makes that unambiguous — without it,
/// `("iss", "a\x1fb")` and `("iss\x1fa", "b")` would be the same row.
fn user_key(issuer: &str, subject: &str) -> String {
    format!("{issuer}\u{1f}{subject}")
}

/// Reject an issuer/subject pair that would make [`user_key`] ambiguous. Both halves are
/// IdP-supplied, so they are untrusted: two distinct identities colliding on one row
/// would mean one inheriting the other's `is_admin`.
fn validate_identity(issuer: &str, subject: &str) -> Result<()> {
    for (what, value) in [("issuer", issuer), ("subject", subject)] {
        if value.is_empty() {
            bail!("an OIDC {what} may not be empty");
        }
        if value.len() > MAX_IDENTITY_LEN {
            bail!("an OIDC {what} may not exceed {MAX_IDENTITY_LEN} bytes");
        }
        if value.chars().any(char::is_control) {
            bail!("an OIDC {what} may not contain control characters");
        }
    }
    Ok(())
}

/// Bound a display claim and drop its control characters. Truncating rather than
/// refusing is deliberate: an over-long `name` is the IdP's business, not a reason to
/// refuse the person a login — unlike an identity, which is a key and must be exact.
fn clamp_claim(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_CLAIM_LEN)
        .collect()
}

fn validate_key_input(name: &str, scopes: &[Scope]) -> Result<()> {
    if name.is_empty() {
        bail!("an API key needs a name");
    }
    if name.len() > MAX_KEY_NAME_LEN {
        bail!("an API key name may not exceed {MAX_KEY_NAME_LEN} bytes");
    }
    // The name is echoed back in listings, so it does not get to carry control characters.
    if name.chars().any(char::is_control) {
        bail!("an API key name may not contain control characters");
    }
    if scopes.len() > MAX_KEY_SCOPES {
        bail!("an API key may not carry more than {MAX_KEY_SCOPES} scopes");
    }
    for s in scopes {
        if s.repo_pattern.len() > MAX_REPO_PATTERN_LEN {
            bail!(
                "a scope's repo pattern may not exceed {MAX_REPO_PATTERN_LEN} bytes (got {})",
                s.repo_pattern.len()
            );
        }
        if !valid_repo_pattern(&s.repo_pattern) {
            bail!(
                "{:?} cannot match any repository name, so it would grant nothing",
                s.repo_pattern
            );
        }
    }
    Ok(())
}

/// A repo pattern that [`Scope::allows`] can actually match: `*`, or a repository name
/// optionally followed by `/*`. Checked at the store rather than left to fail closed at
/// authorization time, because a grant that silently matches nothing is indistinguishable
/// from one that was never made — and the pattern is echoed back in listings alongside the
/// key's name, which gets the same treatment for the same reason.
fn valid_repo_pattern(pattern: &str) -> bool {
    pattern == "*" || crate::valid_name(pattern.strip_suffix("/*").unwrap_or(pattern))
}

/// The `sessions` key for a session id — the id is a credential, so only its hash is
/// stored, exactly as an API key's is.
fn session_key(id: &str) -> String {
    sha256_hex_raw(id.as_bytes())
}

fn user_from_row(id: String, row: UserRow) -> User {
    User {
        id,
        oidc_issuer: row.oidc_issuer,
        oidc_subject: row.oidc_subject,
        email: row.email,
        display_name: row.display_name,
        is_admin: row.is_admin,
    }
}

fn api_key_from_row(id: String, row: &ApiKeyRow) -> ApiKey {
    ApiKey {
        id,
        owner_user_id: row.owner_user_key.clone(),
        name: row.name.clone(),
        token_prefix: row.token_prefix.clone(),
        scopes: row.scopes.clone(),
        created_at: from_secs(row.created_at),
        expires_at: row.expires_at.map(from_secs),
        last_used_at: row.last_used_at.map(from_secs),
        revoked_at: row.revoked_at.map(from_secs),
    }
}

fn encode<T: Serialize>(row: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(row).context("serializing an accounts row")
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice(bytes).context("deserializing an accounts row")
}

/// Seconds since the epoch, for comparing against a stored deadline. Every expiry test is
/// `deadline <= now`, so a clock this cannot read has to read *late*, not early: a pre-epoch
/// or unrepresentable clock yields [`i64::MAX`] and every session and key reads as already
/// expired. Reading as 0 would instead make all of them immortal.
///
/// Minting is the same direction: `now + ttl` then overflows, so a deadline is never
/// written from a clock that cannot be trusted.
fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX)
}

/// A caller-supplied deadline in the same units. A pre-epoch one reads as 0 — the other
/// side of the comparison, so the same fail-closed direction: already expired. One too far
/// in the future to represent saturates to [`i64::MAX`] instead, which is the deadline the
/// caller asked for rounded to the furthest one there is, not a weakening of it.
fn to_secs(t: SystemTime) -> i64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A stored timestamp back to a `SystemTime`, for display. Saturating rather than
/// panicking: the value comes off disk, and `to_secs` can have saturated to [`i64::MAX`]
/// on the way in, so the addition is not one to do unchecked.
fn from_secs(secs: i64) -> SystemTime {
    u64::try_from(secs)
        .ok()
        .and_then(|s| UNIX_EPOCH.checked_add(Duration::from_secs(s)))
        .unwrap_or(UNIX_EPOCH)
}

/// `n` cryptographically random bytes, hex-encoded — the one token-generation primitive
/// shared by session ids, csrf secrets, API key secrets, and `oidc.rs`'s login state and
/// PKCE verifier.
pub(crate) fn random_token(n: usize) -> String {
    let mut buf = vec![0u8; n];
    rand::rng().fill_bytes(&mut buf);
    hex_of(&buf)
}

#[cfg(test)]
mod tests {
    use hyper::StatusCode;
    use redb::ReadableTableMetadata;

    use super::*;

    fn scope(action: Action, repo_pattern: &str) -> Scope {
        Scope {
            action,
            repo_pattern: repo_pattern.to_string(),
        }
    }

    #[test]
    /// `Scope::allows` alone, over patterns including ones `validate_key_input` no longer
    /// lets into the db (an interior `*`, the empty string): the matcher is what the stored
    /// rows are read back through, so its behaviour on them is worth pinning even where the
    /// write path has since made them unreachable.
    fn scope_matching() {
        let read_all = scope(Action::Read, "*");
        assert!(read_all.allows(Action::Read, "team-a/foo"));
        assert!(!read_all.allows(Action::Write, "team-a/foo"));

        let write_team_a = scope(Action::Write, "team-a/*");
        assert!(write_team_a.allows(Action::Write, "team-a/foo"));
        assert!(write_team_a.allows(Action::Read, "team-a/foo")); // write implies read
        assert!(!write_team_a.allows(Action::Write, "team-b/foo"));

        let exact = scope(Action::Read, "exact/name");
        assert!(exact.allows(Action::Read, "exact/name"));
        assert!(!exact.allows(Action::Read, "exact/name/sub"));

        // A bare `*` prefix is a *string* prefix, not a path-component one: `team-a*`
        // deliberately covers `team-abc`, so a pattern meant per-team ends with `/`.
        assert!(scope(Action::Read, "team-a*").allows(Action::Read, "team-abc/x"));
        assert!(scope(Action::Read, "").allows(Action::Read, ""));
        assert!(!scope(Action::Read, "").allows(Action::Read, "x"));
    }

    #[test]
    fn user_upsert_is_idempotent_and_updates_claims() -> Result<()> {
        let db = Db::open_memory()?;
        let u1 = db.upsert_user("https://issuer", "sub-1", Some("a@example.com"), Some("A"))?;
        assert!(!u1.is_admin);
        let u2 = db.upsert_user(
            "https://issuer",
            "sub-1",
            Some("new@example.com"),
            Some("New Name"),
        )?;
        assert_eq!(u1.id, u2.id);
        assert_eq!(u2.email, Some("new@example.com".to_string()));
        assert_eq!(u2.display_name, Some("New Name".to_string()));
        assert_eq!(db.get_user(&u2.id)?, Some(u2));
        assert_eq!(db.get_user("https://issuer\u{1f}nobody")?, None);
        Ok(())
    }

    /// Display claims are whatever an IdP chose to send, and they are stored and rendered
    /// back into a page — so the bound and the control-character strip are applied here,
    /// at the store, and not left to whichever caller happens to be signing someone in.
    #[test]
    fn upsert_bounds_the_claims_an_idp_supplies() -> Result<()> {
        let db = Db::open_memory()?;
        let long = "e".repeat(MAX_CLAIM_LEN + 50);
        let u = db.upsert_user(
            "https://issuer",
            "sub-1",
            Some(&long),
            Some("A\nvk-registry: not a log line\r\tB"),
        )?;
        assert_eq!(u.email.as_deref().map(str::len), Some(MAX_CLAIM_LEN));
        assert_eq!(
            u.display_name.as_deref(),
            Some("Avk-registry: not a log lineB"),
            "control characters do not survive into a stored claim"
        );
        // a claim that clamps away to nothing must not blank a good stored one, any more
        // than an absent claim does
        let again = db.upsert_user("https://issuer", "sub-1", Some("\u{7f}"), Some("\u{7f}"))?;
        assert_eq!(again.email.as_deref().map(str::len), Some(MAX_CLAIM_LEN));
        assert_eq!(
            again.display_name.as_deref(),
            Some("Avk-registry: not a log lineB")
        );

        // an identity, unlike a claim, is a key: it is refused rather than truncated
        assert!(
            db.upsert_user("https://issuer", "sub\n1", None, None)
                .is_err()
        );
        Ok(())
    }

    /// A provider that stops sending an optional claim must not blank the profile, and a
    /// re-login must not demote an admin.
    #[test]
    fn upsert_preserves_admin_and_known_claims() -> Result<()> {
        let db = Db::open_memory()?;
        let u = db.upsert_user("https://issuer", "sub-1", Some("a@example.com"), Some("A"))?;
        promote(&db, &u.id)?;

        let again = db.upsert_user("https://issuer", "sub-1", None, None)?;
        assert!(again.is_admin, "a re-login must not demote an admin");
        assert_eq!(again.email, Some("a@example.com".to_string()));
        assert_eq!(again.display_name, Some("A".to_string()));
        Ok(())
    }

    /// `\x1f` joins the two halves of a user key, so an identity containing it would
    /// collide with a different one — and inherit its `is_admin`.
    #[test]
    fn upsert_rejects_an_identity_that_would_collide() -> Result<()> {
        let db = Db::open_memory()?;
        assert_eq!(
            user_key("iss", "a\u{1f}b"),
            user_key("iss\u{1f}a", "b"),
            "the collision this validation exists to prevent"
        );
        assert!(db.upsert_user("iss", "a\u{1f}b", None, None).is_err());
        assert!(db.upsert_user("iss\u{1f}a", "b", None, None).is_err());
        assert!(db.upsert_user("", "sub", None, None).is_err());
        assert!(db.upsert_user("iss", "", None, None).is_err());
        assert!(db.upsert_user("iss\n", "sub", None, None).is_err());
        Ok(())
    }

    #[test]
    fn session_round_trips_and_resolves_as_a_principal() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        let session_id = db.create_session(&user.id, Duration::from_secs(3600))?;
        let resolved = db.get_session_user(&session_id)?;
        assert_eq!(resolved, Some(user.clone()));
        assert!(db.session_csrf(&session_id)?.is_some());

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::COOKIE,
            format!("vk_session={session_id}").parse().unwrap(),
        );
        assert_eq!(
            resolve_headers(&db, &headers, false)?,
            Some(Principal::Session(user))
        );

        db.delete_session(&session_id)?;
        assert_eq!(db.get_session_user(&session_id)?, None);
        assert_eq!(db.session_csrf(&session_id)?, None);
        assert_eq!(resolve_headers(&db, &headers, false)?, None);
        Ok(())
    }

    #[test]
    fn create_session_rejects_an_unknown_user() -> Result<()> {
        let db = Db::open_memory()?;
        assert!(
            db.create_session("https://issuer\u{1f}ghost", Duration::from_secs(60))
                .is_err()
        );
        Ok(())
    }

    /// The cookie value must not be recoverable from the db: only its hash is a key.
    #[test]
    fn a_session_id_is_stored_only_as_its_hash() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        let session_id = db.create_session(&user.id, Duration::from_secs(3600))?;

        let txn = db.db.begin_read()?;
        let table = txn.open_table(SESSIONS)?;
        let stored: Vec<String> = table
            .iter()?
            .map(|e| Ok(e?.0.value().to_string()))
            .collect::<Result<_>>()?;
        assert_eq!(stored, vec![sha256_hex_raw(session_id.as_bytes())]);
        assert!(!stored.contains(&session_id));
        Ok(())
    }

    /// A zero ttl sets `expires_at == now`, and the check is `<=`, so it is already
    /// expired — no sleeping needed to observe it.
    #[test]
    fn expired_session_does_not_resolve_and_is_swept() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        let session_id = db.create_session(&user.id, Duration::ZERO)?;
        assert_eq!(db.get_session_user(&session_id)?, None);
        assert_eq!(db.session_csrf(&session_id)?, None);

        // the lookup dropped the row rather than leaving it to accumulate
        let txn = db.db.begin_read()?;
        assert!(txn.open_table(SESSIONS)?.is_empty()?);
        Ok(())
    }

    #[test]
    fn a_session_ttl_that_cannot_be_represented_is_an_error() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        assert!(db.create_session(&user.id, Duration::MAX).is_err());
        Ok(())
    }

    #[test]
    fn api_key_round_trips_and_rejects_revoked_or_unknown() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        let scopes = vec![scope(Action::Write, "team-a/*")];
        let (key, token) = db.create_api_key(Some(&user.id), "ci key", &scopes, None)?;
        assert!(token.starts_with("vkr_"));
        // the prefix identifies the key, and it is the *random half's* first 8 chars —
        // not the token's, whose first 4 are the constant scheme
        assert_eq!(key.token_prefix, token["vkr_".len().."vkr_".len() + 8]);
        assert_eq!(key.last_used_at, None);

        let looked_up = db.get_api_key_by_token(&token)?.expect("key resolves");
        assert_eq!(looked_up.id, key.id);
        assert_eq!(looked_up.scopes, scopes);
        assert!(looked_up.last_used_at.is_some(), "first use is recorded");

        assert_eq!(db.get_api_key_by_token("vkr_not-a-real-token")?, None);

        assert!(db.revoke_api_key(&user.id, &key.id)?);
        assert_eq!(db.get_api_key_by_token(&token)?, None);
        Ok(())
    }

    /// A key's id is safe to display, so it turns up in listings — revoking by id alone
    /// must not be enough.
    #[test]
    fn revoke_is_scoped_to_the_owner_and_reports_what_it_did() -> Result<()> {
        let db = Db::open_memory()?;
        let alice = db.upsert_user("https://issuer", "alice", None, None)?;
        let bob = db.upsert_user("https://issuer", "bob", None, None)?;
        let (key, token) = db.create_api_key(Some(&alice.id), "alice's key", &[], None)?;

        assert!(!db.revoke_api_key(&bob.id, &key.id)?, "not bob's to revoke");
        assert!(db.get_api_key_by_token(&token)?.is_some());
        assert!(!db.revoke_api_key(&alice.id, "no-such-id")?);

        assert!(db.revoke_api_key(&alice.id, &key.id)?);
        let revoked_at = read_revoked_at(&db, &key.id)?;
        assert!(
            !db.revoke_api_key(&alice.id, &key.id)?,
            "a second revoke is a no-op"
        );
        assert_eq!(
            read_revoked_at(&db, &key.id)?,
            revoked_at,
            "the original revocation time is kept"
        );
        Ok(())
    }

    /// An ownerless key (a CI credential minted by the operator) has no owner to check,
    /// so only the unchecked path can revoke it.
    #[test]
    fn an_ownerless_key_resolves_and_only_admin_can_revoke_it() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        let (key, token) = db.create_api_key(None, "system key", &[], None)?;
        assert_eq!(key.owner_user_id, None);
        assert!(db.get_api_key_by_token(&token)?.is_some());
        assert!(db.list_api_keys(&user.id)?.is_empty());

        assert!(!db.revoke_api_key(&user.id, &key.id)?);
        assert!(db.revoke_api_key_unchecked(&key.id)?);
        assert_eq!(db.get_api_key_by_token(&token)?, None);
        Ok(())
    }

    #[test]
    fn api_key_expiry_is_enforced() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        // `expires_at == now` and the check is `<=`, so this is already past
        let (_, token) =
            db.create_api_key(Some(&user.id), "short-lived", &[], Some(SystemTime::now()))?;
        assert_eq!(db.get_api_key_by_token(&token)?, None);
        Ok(())
    }

    #[test]
    fn api_key_input_is_bounded() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        assert!(db.create_api_key(Some(&user.id), "", &[], None).is_err());
        assert!(
            db.create_api_key(Some(&user.id), &"n".repeat(MAX_KEY_NAME_LEN + 1), &[], None)
                .is_err()
        );
        let many = vec![scope(Action::Read, "*"); MAX_KEY_SCOPES + 1];
        assert!(
            db.create_api_key(Some(&user.id), "too many", &many, None)
                .is_err()
        );
        let long = [scope(Action::Read, &"r".repeat(MAX_REPO_PATTERN_LEN + 1))];
        assert!(
            db.create_api_key(Some(&user.id), "too long", &long, None)
                .is_err()
        );

        // a pattern no `/v2/<name>` can ever match would be a grant of nothing, which is
        // indistinguishable from a grant never made — so it is refused where it is written
        for dead in [
            "",
            "team a/*",
            "team:a",
            "svc-*/prod",
            "a/**",
            "..",
            "a/./b",
            "*/x",
        ] {
            assert!(
                db.create_api_key(Some(&user.id), "dead", &[scope(Action::Read, dead)], None)
                    .is_err(),
                "{dead:?} should be refused"
            );
        }
        for live in ["*", "app", "team-a/*", "team_a/app.v2", "a/b/c"] {
            assert!(
                db.create_api_key(Some(&user.id), "live", &[scope(Action::Read, live)], None)
                    .is_ok(),
                "{live:?} should be accepted"
            );
        }

        // an owner that does not exist, as `create_session` refuses (`None` is how to ask
        // for a key nobody owns)
        assert!(
            db.create_api_key(Some("nobody"), "orphan", &[], None)
                .is_err()
        );
        assert!(db.create_api_key(None, "ownerless", &[], None).is_ok());
        Ok(())
    }

    #[test]
    fn list_api_keys_is_scoped_to_owner_and_newest_first() -> Result<()> {
        let db = Db::open_memory()?;
        let alice = db.upsert_user("https://issuer", "alice", None, None)?;
        let bob = db.upsert_user("https://issuer", "bob", None, None)?;
        let carol = db.upsert_user("https://issuer", "carol", None, None)?;
        let (older, _) = db.create_api_key(Some(&alice.id), "older", &[], None)?;
        let (newer, _) = db.create_api_key(Some(&alice.id), "newer", &[], None)?;
        db.create_api_key(Some(&bob.id), "bob's key", &[], None)?;
        // Both were minted in the same second, so back-date one: otherwise the assertion
        // below could not tell a `created_at` sort from the id sort it replaced.
        backdate(&db, &older.id, 3600)?;

        let alice_keys = db.list_api_keys(&alice.id)?;
        assert_eq!(alice_keys.len(), 2);
        assert_eq!(alice_keys[0].id, newer.id, "newest first");
        assert_eq!(alice_keys[1].id, older.id);
        assert!(db.list_api_keys(&carol.id)?.is_empty());
        Ok(())
    }

    /// A bearer header wins over a cookie, and a bearer that is not a `vkr_` key is not
    /// tried against the session table.
    #[test]
    fn bearer_token_is_preferred_over_a_session_cookie() -> Result<()> {
        let db = Db::open_memory()?;
        let user = db.upsert_user("https://issuer", "sub-1", None, None)?;
        let session_id = db.create_session(&user.id, Duration::from_secs(3600))?;
        let (key, token) = db.create_api_key(Some(&user.id), "ci key", &[], None)?;

        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers.insert(
            hyper::header::COOKIE,
            format!("vk_session={session_id}").parse().unwrap(),
        );
        match resolve_headers(&db, &headers, false)? {
            Some(Principal::ApiKey(k)) => assert_eq!(k.id, key.id),
            other => panic!("expected the API key to win, got {other:?}"),
        }

        // a shared-secret-shaped bearer is rejected outright, cookie or no cookie
        headers.insert(
            hyper::header::AUTHORIZATION,
            "Bearer some-shared-secret".parse().unwrap(),
        );
        assert_eq!(resolve_headers(&db, &headers, false)?, None);
        Ok(())
    }

    #[test]
    fn credentials_are_parsed_out_of_the_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(
            hyper::header::AUTHORIZATION,
            "Bearer vkr_abc".parse().unwrap(),
        );
        assert_eq!(api_key_token(&headers).as_deref(), Some("vkr_abc"));
        // RFC 7235: the scheme is case-insensitive and the separator is 1*SP
        for header in ["bearer vkr_abc", "Bearer   vkr_abc"] {
            headers.insert(hyper::header::AUTHORIZATION, header.parse().unwrap());
            assert_eq!(
                api_key_token(&headers).as_deref(),
                Some("vkr_abc"),
                "{header}"
            );
        }
        // a key handed to an OCI client comes back as Basic, in whichever half it chose
        for creds in ["dXNlcjp2a3JfYWJj", "dmtyX2FiYzp4"] {
            headers.insert(
                hyper::header::AUTHORIZATION,
                format!("Basic {creds}").parse().unwrap(),
            );
            assert_eq!(
                api_key_token(&headers).as_deref(),
                Some("vkr_abc"),
                "{creds}"
            );
        }
        // something that is not one of ours is a failed authentication, not a fallthrough
        for header in [
            "Basic dXNlcg==",
            "Basic dXNlcjpwYXNz",
            "Bearer shared-secret",
        ] {
            headers.insert(hyper::header::AUTHORIZATION, header.parse().unwrap());
            assert_eq!(api_key_token(&headers), None, "{header}");
        }

        let mut cookie_only = HeaderMap::new();
        cookie_only.insert(
            hyper::header::COOKIE,
            "a=b; vk_session=deadbeef; c=d".parse().unwrap(),
        );
        assert_eq!(api_key_token(&cookie_only), None);
        assert_eq!(
            session_cookie(&cookie_only, false),
            Some("deadbeef".to_string())
        );

        // a client is free to split its cookies over several headers
        let mut split = HeaderMap::new();
        split.append(hyper::header::COOKIE, "a=b".parse().unwrap());
        split.append(
            hyper::header::COOKIE,
            "vk_session=beefdead".parse().unwrap(),
        );
        assert_eq!(session_cookie(&split, false), Some("beefdead".to_string()));
        assert_eq!(session_cookie(&HeaderMap::new(), false), None);
    }

    /// Only the name this deployment would have *written* is read. On a TLS deployment
    /// the server never sets the bare `vk_session`, so a bare cookie can only be one
    /// another host tossed in — reading it as a fallback would restore session fixation,
    /// which is the whole reason for the `__Host-` prefix.
    #[test]
    fn a_session_cookie_under_the_other_name_is_not_read() {
        let headers = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(hyper::header::COOKIE, v.parse().unwrap());
            h
        };
        assert_eq!(
            session_cookie(&headers("__Host-vk_session=ours"), true),
            Some("ours".to_string())
        );
        assert_eq!(
            session_cookie(&headers("vk_session=tossed; __Host-vk_session=ours"), true),
            Some("ours".to_string()),
            "the tossed one does not win"
        );
        assert_eq!(
            session_cookie(&headers("vk_session=tossed"), true),
            None,
            "and it is not a fallback either"
        );
        assert_eq!(
            session_cookie(&headers("__Host-vk_session=other"), false),
            None,
            "nor the other way round"
        );
    }

    /// The cookie is `__Host-` prefixed wherever `Secure` is possible — the prefix is what
    /// stops a sibling or parent host from writing a session cookie of its own (fixation),
    /// and a browser honours it only alongside `Secure` and `Path=/` with no `Domain`. On
    /// plain HTTP `Secure` is impossible, so the bare name is used and that protection is
    /// absent; clearing must reuse whichever name was set, or the browser keeps the cookie.
    #[test]
    fn the_session_cookie_is_host_prefixed_wherever_secure_is_possible() {
        let set = set_cookie_header("sess-1", true);
        assert!(set.starts_with("__Host-vk_session=sess-1;"), "{set}");
        assert!(set.contains("; Secure"), "{set}");
        assert!(set.contains("HttpOnly"), "{set}");
        assert!(set.contains("Path=/"), "{set}");
        assert!(!set.contains("Domain="), "{set}");
        assert!(set.contains("SameSite=Lax"), "{set}");

        let plain = set_cookie_header("sess-1", false);
        assert!(plain.starts_with("vk_session=sess-1;"), "{plain}");
        assert!(!plain.contains("Secure"), "{plain}");

        for secure in [true, false] {
            let cleared = clear_cookie_header(secure);
            assert!(cleared.contains("Max-Age=0"), "{cleared}");
            assert_eq!(
                cleared.split('=').next(),
                set_cookie_header("sess-1", secure).split('=').next(),
                "the same name, or the browser keeps the one it holds"
            );
        }
    }

    #[test]
    fn the_challenge_carries_a_www_authenticate_header() {
        let res = challenge();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            res.headers()
                .get(hyper::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok()),
            Some("Bearer realm=\"vk-registry\"")
        );
    }

    /// The on-disk path — the one every deployment takes — creating its file `0600`
    /// inside a `0700` directory it makes itself, and persisting across a reopen.
    #[test]
    fn an_on_disk_db_is_owner_only_and_persists() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("vk-reg-accounts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The shape a configured `accounts_db` takes: a directory `Db::open` did not make.
        // (The default path is the `nested` case below, one it makes itself.)
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("accounts.db");

        let user_id = {
            let db = Db::open(&path)?;
            db.upsert_user("https://issuer", "sub-1", Some("a@example.com"), None)?
                .id
        };

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)?.permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "the db is group/world-accessible: {mode:o}"
            );

            // a directory `Db::open` does have to create is its to lock down
            let owned = dir.join("nested").join("accounts.db");
            drop(Db::open(&owned)?);
            let dir_mode = std::fs::metadata(owned.parent().expect("it has a parent"))?
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o077, 0, "the dir it created: {dir_mode:o}");

            // and a symlink standing where the db should be is refused, not followed
            let planted = dir.join("planted.db");
            let linked = dir.join("linked.db");
            std::fs::write(&planted, b"")?;
            std::os::unix::fs::symlink(&planted, &linked)?;
            assert!(Db::open(&linked).is_err(), "a symlinked db must be refused");
        }

        let db = Db::open(&path)?;
        let user = db.get_user(&user_id)?.expect("the user survived a reopen");
        assert_eq!(user.email, Some("a@example.com".to_string()));

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Set `is_admin` out of band — the `accounts` CLI's job, not `upsert_user`'s.
    fn promote(db: &Db, id: &str) -> Result<()> {
        let txn = db.db.begin_write()?;
        {
            let mut table = txn.open_table(USERS)?;
            let mut row: UserRow = decode(table.get(id)?.expect("the user exists").value())?;
            row.is_admin = true;
            table.insert(id, encode(&row)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Move a key's `created_at` back by `secs`, so an ordering test does not depend on
    /// two `create_api_key` calls landing in different seconds.
    fn backdate(db: &Db, id: &str, secs: i64) -> Result<()> {
        let txn = db.db.begin_write()?;
        {
            let mut table = txn.open_table(API_KEYS)?;
            let mut row: ApiKeyRow = decode(table.get(id)?.expect("the key exists").value())?;
            row.created_at -= secs;
            table.insert(id, encode(&row)?.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    fn read_revoked_at(db: &Db, id: &str) -> Result<Option<i64>> {
        let txn = db.db.begin_read()?;
        let table = txn.open_table(API_KEYS)?;
        let row: ApiKeyRow = decode(table.get(id)?.expect("the key exists").value())?;
        Ok(row.revoked_at)
    }
}
