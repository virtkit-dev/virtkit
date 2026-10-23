//! Registry tokens: the keys the hub signs them with, what it sends registries to check them,
//! and minting one for an operator ([`mint`]).
//!
//! The keys live in `<data_dir>/token-keys/`, one file each, created on first need. A
//! registry that takes tokens gets the public halves in its desired state, with its
//! namespaces' retention windows. A new key signs a registry's tokens only once the registry
//! reports applying the generation that first carried it, so a token never reaches a registry
//! before the key to check it does; until then the previous key signs. A key superseded for
//! longer than any token lives goes, at the next sync or the hourly sweep.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use vk_hub_proto::token::{Claims, Grant, MAX_LABEL_LEN, MAX_TTL_SECS, SKEW_SECS, TokenKey};
use vk_peer::token::Signer;

use crate::server::Hub;
use crate::store::{Db, RegistryRow, TokenKeyRow};

/// The longest a job's token lives, by default: a day.
pub const DEFAULT_MAX_JOB_TOKEN: Duration = Duration::from_secs(86_400);

/// How often superseded keys are looked at for retirement, besides every sync.
pub const SWEEP_EVERY: Duration = Duration::from_secs(3600);

/// The signing keys, loaded as they are needed.
pub struct Keys {
    dir: Option<PathBuf>,
    max_token: Duration,
    loaded: Mutex<BTreeMap<String, Arc<Signer>>>,
    /// Held across a sync, a rotation and a sweep, so that a key list computed before a
    /// rotation is never written after it.
    sync: Mutex<()>,
}

impl Keys {
    /// Keys kept in `dir`, or none at all; tokens live at most `max_token`.
    pub fn new(dir: Option<PathBuf>, max_token: Duration) -> Self {
        Keys {
            dir,
            max_token,
            loaded: Mutex::new(BTreeMap::new()),
            sync: Mutex::new(()),
        }
    }

    /// The key directory, refusing one other users may read or enter.
    fn dir(&self) -> Result<&PathBuf> {
        let dir = self
            .dir
            .as_ref()
            .ok_or_else(|| anyhow!("this hub keeps no token-signing keys"))?;
        match std::fs::symlink_metadata(dir) {
            Ok(m) if !m.is_dir() => bail!("{} is not a directory", dir.display()),
            Ok(m) if m.permissions().mode() & 0o077 != 0 => bail!(
                "{} has mode {:o}: the token-signing keys' directory is its owner's only \
                 (chmod 700)",
                dir.display(),
                m.permissions().mode() & 0o7777
            ),
            _ => Ok(dir),
        }
    }

    pub(crate) fn signer(&self, row: &TokenKeyRow) -> Result<Arc<Signer>> {
        let mut loaded = self.loaded.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = loaded.get(&row.public.kid) {
            return Ok(s.clone());
        }
        let path = self.dir()?.join(key_file(row)?);
        let signer = Arc::new(Signer::load(&path)?);
        if signer.public() != &row.public {
            bail!(
                "{} is not token-signing key {}",
                path.display(),
                row.public.kid
            );
        }
        loaded.insert(row.public.kid.clone(), signer.clone());
        Ok(signer)
    }

    fn forget(&self, kid: &str) {
        self.loaded
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(kid);
    }

    /// A new key in the directory, `0700`, not yet recorded.
    pub(crate) fn generate(&self) -> Result<TokenKeyRow> {
        let dir = self
            .dir
            .as_ref()
            .ok_or_else(|| anyhow!("this hub keeps no token-signing keys"))?;
        std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700)
            .recursive(true)
            .create(dir)
            .with_context(|| format!("creating {}", dir.display()))?;
        let dir = self.dir()?;
        let file = format!("{}.pk8", crate::random_hex(16)?);
        let signer = Signer::generate(&dir.join(&file))?;
        let row = TokenKeyRow {
            file,
            public: signer.public().clone(),
            created_at: crate::now_secs(),
            seq: 0,
            superseded_at: None,
        };
        self.loaded
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(row.public.kid.clone(), Arc::new(signer));
        Ok(row)
    }

    /// Remove key `row`'s file; a failure is logged, since its private key then stays.
    fn remove(&self, row: &TokenKeyRow) {
        self.forget(&row.public.kid);
        let Ok(dir) = self.dir() else {
            return;
        };
        let Ok(file) = key_file(row) else {
            return;
        };
        let path = dir.join(file);
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "vk-hub: removing retired token-signing key {}: {e}",
                path.display()
            );
        }
    }
}

/// The file name of key `row`: `<32 hex digits>.pk8`, as [`Keys::generate`] writes it, never a
/// path.
fn key_file(row: &TokenKeyRow) -> Result<&str> {
    row.file
        .strip_suffix(".pk8")
        .filter(|hex| vk_hub_proto::valid_id(hex))
        .map(|_| row.file.as_str())
        .ok_or_else(|| anyhow!("{:?} is not a token-signing key's file name", row.file))
}

/// A new key, recorded as the signer by `actor`; its file goes again if recording fails.
fn create(hub: &Hub, actor: &str) -> Result<TokenKeyRow> {
    let row = hub.token_keys.generate()?;
    if let Err(e) = hub.db.add_token_key(&row, actor, row.created_at) {
        hub.token_keys.remove(&row);
        return Err(e);
    }
    Ok(row)
}

/// Make a new key the signer, as `actor`, and send it to every registry that takes tokens.
pub fn rotate(hub: &Hub, actor: &str) -> Result<TokenKeyRow> {
    let _sync = hub
        .token_keys
        .sync
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let row = create(hub, actor)?;
    for (id, _) in hub.db.registries()? {
        sync_locked(hub, &id)?;
    }
    Ok(row)
}

/// The keys registries should hold: every key but those retired now, generating the first
/// when there is none. A key is retired once superseded for longer than any token lives,
/// whatever `max_job_token_secs` says now: it may have been longer when the key signed.
fn published(hub: &Hub) -> Result<Vec<TokenKey>> {
    let now = crate::now_secs();
    let before = now.saturating_sub(MAX_TTL_SECS).saturating_sub(SKEW_SECS);
    for gone in hub.db.retire_token_keys(before, now)? {
        hub.token_keys.remove(&gone);
    }
    let mut rows = hub.db.token_keys()?;
    if rows.is_empty() {
        rows.push(create(hub, "hub")?);
    }
    Ok(rows.into_iter().map(|r| r.public).collect())
}

/// Bring registry `id`'s token state up to date: its default namespaces the first time it
/// takes tokens, then the keys and retention windows in its desired state. Sends the change.
pub fn sync_registry(hub: &Hub, id: &str) -> Result<()> {
    let _sync = hub
        .token_keys
        .sync
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    sync_locked(hub, id)
}

fn sync_locked(hub: &Hub, id: &str) -> Result<()> {
    let Some(row) = hub.db.registry(id)? else {
        return Ok(());
    };
    if !row.takes_tokens() {
        return Ok(());
    }
    let now = crate::now_secs();
    hub.db.seed_namespaces(id, now)?;
    let keys = published(hub)?;
    let retention = crate::store::prefix_retention(&hub.db.namespaces(id)?);
    if hub
        .db
        .sync_registry_tokens(id, &keys, &retention, now)?
        .is_some()
    {
        hub.kick(id);
        hub.changed(id);
    }
    Ok(())
}

/// [`sync_registry`] for every registry: at start, and every [`SWEEP_EVERY`] so that keys
/// retire even when nothing else changes.
pub fn sync_all(hub: &Hub) -> Result<()> {
    let _sync = hub
        .token_keys
        .sync
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for (id, _) in hub.db.registries()? {
        sync_locked(hub, &id)?;
    }
    Ok(())
}

/// [`sync_all`] every [`SWEEP_EVERY`], logging what fails.
pub async fn sweep(hub: Arc<Hub>) {
    loop {
        tokio::time::sleep(SWEEP_EVERY).await;
        let h = hub.clone();
        match tokio::task::spawn_blocking(move || sync_all(&h)).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => eprintln!("vk-hub: syncing registry tokens: {e:#}"),
            Err(e) => eprintln!("vk-hub: syncing registry tokens: {e}"),
        }
    }
}

/// The key to sign registry `row`'s tokens with: the newest whose generation it has applied.
/// This takes a registry that applied a generation to hold its keys; one that pins a fleet
/// root may refuse a key the root did not certify, which the trust model makes the hub check.
pub(crate) fn signing_key<'a>(
    keys: &'a [TokenKeyRow],
    row: &RegistryRow,
) -> Option<&'a TokenKeyRow> {
    let applied = row.applied();
    keys.iter().rev().find(|key| {
        row.key_generations
            .get(&key.public.kid)
            .is_some_and(|g| *g <= applied)
    })
}

/// Grants as the audit log and the CLI print them: `prefix=rwl`, comma-separated.
pub fn grants_text(grants: &[Grant]) -> String {
    if grants.is_empty() {
        return "no grants".to_string();
    }
    grants
        .iter()
        .map(|g| format!("{}={}", g.prefix, g.rights()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// A grant from `prefix=rights`, rights some of `r`, `w` and `l`.
pub fn parse_grant(s: &str) -> Result<Grant, String> {
    let (prefix, rights) = s
        .split_once('=')
        .ok_or_else(|| format!("{s:?}: expected <prefix>=<rights>, as images=r"))?;
    if !vk_hub_proto::token::valid_prefix(prefix) {
        return Err(format!("{prefix:?} is not a repository name"));
    }
    if rights.is_empty() || !rights.chars().all(|c| matches!(c, 'r' | 'w' | 'l')) {
        return Err(format!("{rights:?}: rights are some of r, w and l"));
    }
    Ok(Grant {
        prefix: prefix.to_string(),
        read: rights.contains('r'),
        write: rights.contains('w'),
        lock: rights.contains('l'),
    })
}

/// `actor` as a token's `sub`: `operator:` and the actor, every byte outside printable ASCII
/// (spaces included) replaced by `_`, cut to fit.
fn operator_sub(actor: &str) -> String {
    let mut sub: String = format!("operator:{actor}")
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .collect();
    sub.truncate(MAX_LABEL_LEN);
    sub
}

/// Whether `pipeline` is a pipeline claim the hub would mint: `<instance>/<pipeline id>`, the
/// instance one it knows.
fn known_pipeline(db: &Db, pipeline: &str) -> Result<bool> {
    let Some((gitlab, id)) = pipeline.split_once('/') else {
        return Ok(false);
    };
    if !id.parse::<u64>().is_ok_and(|id| id > 0) {
        return Ok(false);
    }
    Ok(db.gitlab(gitlab)?.is_some())
}

/// Mint and audit an operator (`actor`) token for registry `id`, with `grants` and lifetime
/// `ttl`, for automation or a test.
pub fn mint(
    hub: &Hub,
    actor: &str,
    id: &str,
    grants: Vec<Grant>,
    pipeline: Option<String>,
    ttl: Duration,
) -> Result<String> {
    if ttl.is_zero() || ttl > hub.token_keys.max_token {
        bail!(
            "a token lives between 1s and {}s (max_job_token_secs)",
            hub.token_keys.max_token.as_secs()
        );
    }
    if grants.len() > vk_hub_proto::token::MAX_GRANTS {
        bail!(
            "a token carries at most {} grants",
            vk_hub_proto::token::MAX_GRANTS
        );
    }
    if let Some(p) = &pipeline
        && !known_pipeline(&hub.db, p)?
    {
        bail!(
            "{p:?}: a pipeline is <GitLab instance>/<pipeline ID>, for an instance the hub knows"
        );
    }
    let Some(row) = hub.db.registry(id)? else {
        bail!("there is no registry {id}");
    };
    if !row.takes_tokens() {
        bail!("registry {id} does not take tokens: set `[hub] tokens = true` in its config");
    }
    let keys = hub.db.token_keys()?;
    let Some(key) = signing_key(&keys, &row) else {
        bail!("registry {id} has not applied a token-signing key yet; retry once it has");
    };
    let signer = hub.token_keys.signer(key)?;
    let now = crate::now_secs();
    let claims = Claims {
        kid: signer.public().kid.clone(),
        aud: id.to_string(),
        sub: operator_sub(actor),
        jti: vk_peer::token::new_jti()?,
        pipeline,
        iat: now,
        exp: now.saturating_add(ttl.as_secs()),
        grants,
    };
    let event = format!(
        "{actor} minted registry token {} for registry {id}, valid for {}s: {}",
        claims.jti,
        ttl.as_secs(),
        grants_text(&claims.grants)
    );
    let token = signer.sign(claims)?;
    hub.db.audit_node(Some(id), actor, &event, now)?;
    eprintln!("vk-hub: admin: {event}");
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_operator_sub_fits_a_token() {
        assert_eq!(operator_sub("uid 1001"), "operator:uid_1001");
        assert_eq!(operator_sub("é"), "operator:_");
        assert_eq!(operator_sub(&"a".repeat(300)).len(), MAX_LABEL_LEN);
    }

    #[test]
    fn key_files_are_bare_names() {
        let row = |file: &str| TokenKeyRow {
            file: file.into(),
            public: TokenKey {
                kid: "k".into(),
                public_key: String::new(),
            },
            created_at: 0,
            seq: 0,
            superseded_at: None,
        };
        assert!(key_file(&row(&format!("{}.pk8", "ab".repeat(16)))).is_ok());
        for bad in ["../x.pk8", "x.pk8", &format!("{}.key", "ab".repeat(16))] {
            assert!(key_file(&row(bad)).is_err(), "{bad}");
        }
    }
}
