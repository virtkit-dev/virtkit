//! Client for the vk-registry build-once lock — the counterpart to the server in
//! [`crate::lock`], used by runners to coordinate "who builds this content-key". POSTs to
//! the `/lock/{acquire,renew,release}` actions (names as `?name=` params); a single lock
//! is just a one-name batch. Async; callers on a sync path drive it through their own
//! runtime (vk-driver's `registry::block_on`), with a heartbeat renewing the lease.

use std::time::Duration;

use anyhow::{Context, Result};

/// How a client authenticates to the server — matches the server's [`crate::auth::Auth`]
/// schemes so a lock client can talk to a registry gated by either Basic or a static bearer
/// token (or none). The bearer-only past made the `/lock/` API 401 against a Basic registry.
#[derive(Clone, Default)]
pub enum ClientAuth {
    /// No credentials (loopback / trusted network).
    #[default]
    None,
    /// HTTP Basic.
    Basic { user: String, pass: String },
    /// Static bearer token.
    Bearer { token: String },
}

/// A handle to the vk-registry `/lock` endpoint on `base` (`scheme://host`).
pub struct LockClient {
    base: String,
    auth: ClientAuth,
    client: reqwest::Client,
}

/// A granted single lock: the name it holds and the server-minted owner token to
/// renew/release.
pub struct Held {
    pub name: String,
    pub owner: String,
}

impl LockClient {
    pub fn new(base: impl Into<String>, auth: ClientAuth, client: reqwest::Client) -> Self {
        LockClient {
            base: base.into(),
            auth,
            client,
        }
    }

    fn url(&self, action: &str) -> String {
        format!("{}/lock/{action}", self.base.trim_end_matches('/'))
    }

    fn auth(&self, r: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            ClientAuth::None => r,
            ClientAuth::Basic { user, pass } => r.basic_auth(user, Some(pass)),
            ClientAuth::Bearer { token } => r.bearer_auth(token),
        }
    }

    fn name_query<'a>(&self, names: &'a [String]) -> Vec<(&'static str, &'a str)> {
        names.iter().map(|n| ("name", n.as_str())).collect()
    }

    /// Atomically acquire ALL `names`, long-polling up to `wait`. `Ok(Some(owner))` on
    /// success (the shared batch owner token), `Ok(None)` if the wait elapsed with some
    /// name still held (409). All-or-nothing.
    pub async fn acquire_all(
        &self,
        names: &[String],
        ttl: Duration,
        wait: Duration,
        holder: &str,
    ) -> Result<Option<String>> {
        let mut query = self.name_query(names);
        let (ttl_s, wait_s) = (ttl.as_secs().to_string(), wait.as_secs().to_string());
        query.push(("ttl", &ttl_s));
        query.push(("wait", &wait_s));
        let resp = self
            .auth(self.client.post(self.url("acquire")))
            .query(&query)
            .header("x-vk-lock-holder", holder)
            .send()
            .await
            .context("acquiring lock(s)")?;
        if resp.status() == reqwest::StatusCode::CONFLICT {
            return Ok(None);
        }
        if !resp.status().is_success() {
            anyhow::bail!("acquiring lock(s): status {}", resp.status());
        }
        #[derive(serde::Deserialize)]
        struct Body {
            owner: String,
        }
        let body: Body = resp.json().await.context("parsing the acquire response")?;
        Ok(Some(body.owner))
    }

    /// Renew every name in the batch; returns how many the server still recognized as
    /// owned (fewer than `names.len()` means the batch was partly lost).
    pub async fn renew_all(&self, names: &[String], owner: &str, ttl: Duration) -> Result<usize> {
        let mut query = self.name_query(names);
        let ttl_s = ttl.as_secs().to_string();
        query.push(("ttl", &ttl_s));
        let resp = self
            .auth(self.client.post(self.url("renew")))
            .query(&query)
            .header("x-vk-lock-owner", owner)
            .send()
            .await
            .context("renewing lock(s)")?;
        // 200 = full renew, 409 = partial (some names already lost) — both carry the count
        // body. Any other status (auth/transport/server error) is a failure, not a partial.
        let status = resp.status();
        if !status.is_success() && status != reqwest::StatusCode::CONFLICT {
            anyhow::bail!("renewing lock(s): status {status}");
        }
        #[derive(serde::Deserialize)]
        struct Body {
            renewed: usize,
        }
        let body: Body = resp.json().await.context("parsing the renew response")?;
        Ok(body.renewed)
    }

    /// Release every name in the batch owned by `owner`; returns how many were released.
    pub async fn release_all(&self, names: &[String], owner: &str) -> Result<usize> {
        let query = self.name_query(names);
        let resp = self
            .auth(self.client.post(self.url("release")))
            .query(&query)
            .header("x-vk-lock-owner", owner)
            .send()
            .await
            .context("releasing lock(s)")?;
        if !resp.status().is_success() {
            anyhow::bail!("releasing lock(s): status {}", resp.status());
        }
        #[derive(serde::Deserialize)]
        struct Body {
            released: usize,
        }
        let body: Body = resp.json().await.context("parsing the release response")?;
        Ok(body.released)
    }

    /// The identity currently holding `name`, or `None` if it is free (best-effort: any
    /// transport/parse error also maps to `None`). Lets a waiter name who blocks it before
    /// parking on a contended [`Self::acquire`].
    pub async fn holder(&self, name: &str) -> Option<String> {
        let resp = self
            .auth(self.client.post(self.url("status")))
            .query(&[("name", name)])
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        #[derive(serde::Deserialize)]
        struct Entry {
            name: String,
            holder: String,
        }
        #[derive(serde::Deserialize)]
        struct Body {
            holders: Vec<Entry>,
        }
        let body: Body = resp.json().await.ok()?;
        body.holders
            .into_iter()
            .find(|h| h.name == name)
            .map(|h| h.holder)
    }

    // ---- single-lock convenience: a one-name batch ----

    /// Acquire `name`, long-polling up to `wait`. `Ok(Some(held))` on success, `Ok(None)`
    /// on timeout.
    pub async fn acquire(
        &self,
        name: &str,
        ttl: Duration,
        wait: Duration,
        holder: &str,
    ) -> Result<Option<Held>> {
        let names = [name.to_string()];
        Ok(self
            .acquire_all(&names, ttl, wait, holder)
            .await?
            .map(|owner| Held {
                name: name.to_string(),
                owner,
            }))
    }

    /// Extend the lease; false if the server no longer recognizes the owner.
    pub async fn renew(&self, held: &Held, ttl: Duration) -> Result<bool> {
        Ok(self
            .renew_all(std::slice::from_ref(&held.name), &held.owner, ttl)
            .await?
            >= 1)
    }

    /// Release the lock (best-effort; a lapsed lease is already free).
    pub async fn release(&self, held: &Held) -> Result<()> {
        self.release_all(std::slice::from_ref(&held.name), &held.owner)
            .await?;
        Ok(())
    }
}
