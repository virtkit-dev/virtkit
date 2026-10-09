//! The hub client: [`Dispatcher`] over vk-hub's client API (HTTP/1.1 and JSON, TLS 1.3, an
//! API key as `authorization: Bearer`), as `docs/gitlab-dispatch.md`, "Daemon ↔ hub",
//! and vk-hub's `src/client.rs` define it.
//!
//! Transport errors and the retryable codes (`unavailable`, `internal`, and `no_capacity`
//! outside a reservation) are retried with backoff from 1 to 30 seconds and jitter, honouring
//! `retry_after_secs` up to a minute; any other 4xx is not. A create carries the
//! caller's `request_id`, which the hub keeps for a day, so a retried create answers the
//! first answer: a submission is retried until its `place_within` is up. An answer whose
//! body is cut short is retried as a request without one is. A renewal is tried once, and
//! its caller retries it within the lease.

use std::path::PathBuf;
use std::time::Duration;

use tokio::time::Instant;

use bytes::Bytes;
use reqwest::{Method, Response, StatusCode, Url};
use serde::Serialize;
use serde::de::DeserializeOwned;
use vk_hub_proto::client::{
    CAPACITY_PATH, CancelMode, CancelRequest, Capacity, CapacityRequest, ClientError, ErrorCode,
    JOBS_PATH, JobSubmission, JobView, MAX_WAIT_SECS, OUTPUT_COMPLETE_HEADER, OUTPUT_LENGTH_HEADER,
    OUTPUT_OFFSET_HEADER, Placement, RESERVATIONS_PATH, RenewRequest, ReservationGrant,
    ReservationRequest,
};
use vk_hub_proto::dispatch::MAX_LEASE_SECS;
use vk_hub_proto::job::MAX_JOB_SPEC;
use vk_hub_proto::valid_id;

use crate::api::ClientError as SetupError;
use crate::backoff::Backoff;
use crate::dispatch::{
    DispatchError, DispatchResult, Dispatcher, ErrorKind, OutputChunk, Reservation, Submission,
};
use crate::secret::Secret;

/// How long a request may take beyond the long poll it asks for.
const REQUEST_SLACK: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest `retry_after_secs` (or `Retry-After`) honoured.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// How often a call is tried.
#[derive(Debug, Clone, Copy)]
enum Tries {
    /// Up to [`HubRetry::max_attempts`].
    Attempts,
    Once,
    /// Until a retry would start past the deadline.
    Until(Instant),
}

/// How hub calls are retried.
#[derive(Debug, Clone)]
pub struct HubRetry {
    /// Attempts in total, the first included.
    pub max_attempts: u32,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl Default for HubRetry {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            backoff_min: Duration::from_secs(1),
            backoff_max: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HubOptions {
    /// `https://…`, or `http://` to a loopback hub.
    pub url: String,
    /// `vkk_` and 64 hex digits.
    pub api_key: Secret,
    /// A PEM bundle the hub is verified against instead of the system roots.
    pub ca_file: Option<PathBuf>,
    pub retry: HubRetry,
}

/// Whether `key` has the shape of a hub API key.
pub fn valid_api_key(key: &str) -> bool {
    key.strip_prefix("vkk_").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub struct HubClient {
    http: reqwest::Client,
    base: Url,
    key: Secret,
    retry: HubRetry,
}

impl std::fmt::Debug for HubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubClient")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl HubClient {
    pub fn new(opts: HubOptions) -> Result<Self, SetupError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let base = Url::parse(&opts.url)
            .map_err(|e| SetupError::new(format!("hub url {:?}: {e}", opts.url)))?;
        match base.scheme() {
            "https" => {}
            "http" if is_loopback(&base) => {}
            _ => {
                return Err(SetupError::new(format!(
                    "hub url {:?}: https, or http to a loopback hub",
                    opts.url
                )));
            }
        }
        if !valid_api_key(opts.api_key.expose()) {
            return Err(SetupError::new(
                "the hub API key is not `vkk_` and 64 hex digits".to_owned(),
            ));
        }
        let mut builder = reqwest::Client::builder()
            .user_agent(format!("vk-gitlab {}", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .tls_version_min(reqwest::tls::Version::TLS_1_3);
        if let Some(ca) = &opts.ca_file {
            let pem = std::fs::read(ca)
                .map_err(|e| SetupError::new(format!("reading {}: {e}", ca.display())))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| SetupError::new(format!("parsing {}: {e}", ca.display())))?;
            builder = builder.tls_certs_only(certs);
        }
        let http = builder
            .build()
            .map_err(|e| SetupError::new(format!("building the hub client: {e}")))?;
        Ok(Self {
            http,
            base,
            key: opts.api_key,
            retry: opts.retry,
        })
    }

    fn url(&self, path: &str, query: &str) -> Result<Url, DispatchError> {
        let mut url = self
            .base
            .join(path)
            .map_err(|e| DispatchError::new(ErrorKind::Invalid, e.to_string()))?;
        if !query.is_empty() {
            url.set_query(Some(query));
        }
        Ok(url)
    }

    /// Retries a call according to `tries`. `read` decodes a successful response; its
    /// transport errors (a truncated body) are retried like request errors.
    /// `retry_no_capacity` is false when the caller waits for capacity itself.
    #[allow(clippy::too_many_arguments)]
    async fn call<T, F: Future<Output = DispatchResult<T>>>(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<Bytes>,
        timeout: Duration,
        retry_no_capacity: bool,
        tries: Tries,
        read: impl Fn(Response) -> F,
    ) -> DispatchResult<T> {
        let url = self.url(path, query)?;
        let mut backoff = Backoff::new(self.retry.backoff_min, self.retry.backoff_max, 2.0, true);
        let mut attempt = 0u32;
        loop {
            attempt = attempt.saturating_add(1);
            let mut rb = self
                .http
                .request(method.clone(), url.clone())
                .bearer_auth(self.key.expose())
                .timeout(timeout);
            if let Some(b) = &body {
                rb = rb
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .body(b.clone());
            }
            let err = match rb.send().await {
                Ok(resp) if resp.status().is_success() => match read(resp).await {
                    Err(e) if e.kind == ErrorKind::Transport => e,
                    done => return done,
                },
                Ok(resp) => error_of(resp).await,
                Err(e) => transport(e),
            };
            let retryable = match err.kind {
                ErrorKind::Transport | ErrorKind::Unavailable | ErrorKind::Internal => true,
                ErrorKind::NoCapacity => retry_no_capacity,
                _ => false,
            };
            let wait = err
                .retry_after
                .map_or_else(|| backoff.next_delay(), |d| d.min(MAX_RETRY_AFTER));
            let again = match tries {
                Tries::Attempts => attempt < self.retry.max_attempts,
                Tries::Once => false,
                Tries::Until(deadline) => Instant::now() + wait < deadline,
            };
            if !retryable || !again {
                return Err(err);
            }
            log::info!(
                path = path,
                attempt = attempt,
                wait_s = wait.as_secs_f64(),
                error = err.to_string().as_str();
                "Retrying the hub request"
            );
            tokio::time::sleep(wait).await;
        }
    }

    /// A call whose answer body does not matter.
    async fn call_empty(&self, method: Method, path: &str, tries: Tries) -> DispatchResult<()> {
        self.call(
            method,
            path,
            "",
            None,
            timeout_for(Duration::ZERO),
            true,
            tries,
            |resp| async move { resp.bytes().await.map(drop).map_err(transport) },
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn call_json<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<&impl Serialize>,
        timeout: Duration,
        retry_no_capacity: bool,
        tries: Tries,
    ) -> DispatchResult<T> {
        let body = match body {
            Some(b) => {
                Some(Bytes::from(serde_json::to_vec(b).map_err(|e| {
                    DispatchError::new(ErrorKind::Invalid, e.to_string())
                })?))
            }
            None => None,
        };
        self.call(
            method,
            path,
            query,
            body,
            timeout,
            retry_no_capacity,
            tries,
            |resp| async move {
                let bytes = resp.bytes().await.map_err(transport)?;
                serde_json::from_slice(&bytes).map_err(|e| {
                    DispatchError::new(
                        ErrorKind::Other,
                        format!("the hub's answer does not parse: {e}"),
                    )
                })
            },
        )
        .await
    }
}

fn transport(e: reqwest::Error) -> DispatchError {
    DispatchError::new(ErrorKind::Transport, e.without_url().to_string())
}

fn is_loopback(url: &Url) -> bool {
    match url.host_str() {
        Some("localhost") => true,
        Some(h) => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback()),
        None => false,
    }
}

/// A failed answer as an error: the body's code when it has one, else the status's.
async fn error_of(resp: Response) -> DispatchError {
    let status = resp.status();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
    };
    let retry_header = header("retry-after");
    let length = header(OUTPUT_LENGTH_HEADER);
    let body = resp.bytes().await.unwrap_or_default();
    let parsed = serde_json::from_slice::<ClientError>(&body).ok();
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        return DispatchError::new(
            ErrorKind::OutputRange {
                length: length.unwrap_or(0),
            },
            parsed.map_or_else(|| status.to_string(), |p| p.error),
        );
    }
    let kind = match parsed.as_ref().map(|p| p.code) {
        Some(ErrorCode::Unauthorized) => ErrorKind::Unauthorized,
        Some(ErrorCode::Forbidden) => ErrorKind::Forbidden,
        Some(ErrorCode::NotFound) => ErrorKind::NotFound,
        Some(ErrorCode::Invalid) => ErrorKind::Invalid,
        Some(ErrorCode::Conflict) => ErrorKind::Conflict,
        Some(ErrorCode::NoCapacity) => ErrorKind::NoCapacity,
        Some(ErrorCode::ReservationGone) => ErrorKind::ReservationGone,
        Some(ErrorCode::TooLarge) => ErrorKind::TooLarge,
        Some(ErrorCode::Unavailable) => ErrorKind::Unavailable,
        Some(ErrorCode::Internal) => ErrorKind::Internal,
        Some(ErrorCode::Other) | None => match status.as_u16() {
            400 => ErrorKind::Invalid,
            401 => ErrorKind::Unauthorized,
            403 => ErrorKind::Forbidden,
            404 => ErrorKind::NotFound,
            409 => ErrorKind::Conflict,
            410 => ErrorKind::ReservationGone,
            413 => ErrorKind::TooLarge,
            503 => ErrorKind::Unavailable,
            500..=599 => ErrorKind::Internal,
            _ => ErrorKind::Other,
        },
    };
    let retry_after = parsed
        .as_ref()
        .and_then(|p| p.retry_after_secs)
        .map(u64::from)
        .or(retry_header)
        .map(Duration::from_secs);
    DispatchError {
        kind,
        message: parsed.map_or_else(|| status.to_string(), |p| p.error),
        retry_after,
    }
}

fn wait_secs(wait: Duration) -> u32 {
    u32::try_from(wait.as_secs())
        .unwrap_or(u32::MAX)
        .min(MAX_WAIT_SECS)
}

fn checked_id(id: &str) -> DispatchResult<&str> {
    if valid_id(id) {
        Ok(id)
    } else {
        Err(DispatchError::new(
            ErrorKind::Invalid,
            format!("{id:?} is not a hub ID"),
        ))
    }
}

/// A plain request's bound: the long poll it asks for, plus slack.
fn timeout_for(wait: Duration) -> Duration {
    wait.min(Duration::from_secs(u64::from(MAX_WAIT_SECS))) + REQUEST_SLACK
}

impl Dispatcher for HubClient {
    async fn capacity(
        &self,
        placement: &Placement,
        after: Option<u64>,
        wait: Duration,
    ) -> DispatchResult<Capacity> {
        let body = CapacityRequest {
            placement: placement.clone(),
            after,
            wait_secs: wait_secs(wait),
        };
        self.call_json(
            Method::POST,
            CAPACITY_PATH,
            "",
            Some(&body),
            timeout_for(wait),
            true,
            Tries::Attempts,
        )
        .await
    }

    async fn reserve(
        &self,
        request_id: &str,
        placement: &Placement,
        lease: Duration,
        wait: Duration,
    ) -> DispatchResult<Reservation> {
        let body = ReservationRequest {
            request_id: request_id.to_owned(),
            placement: placement.clone(),
            lease_secs: lease_secs(lease),
            wait_secs: wait_secs(wait),
        };
        let grant: ReservationGrant = self
            .call_json(
                Method::POST,
                RESERVATIONS_PATH,
                "",
                Some(&body),
                timeout_for(wait),
                false,
                Tries::Attempts,
            )
            .await?;
        Ok(Reservation {
            id: grant.reservation,
            node: grant.node,
            envelope: grant.envelope,
            lease: Duration::from_secs(u64::from(grant.lease_secs)),
        })
    }

    async fn renew(&self, reservation: &str, lease: Duration) -> DispatchResult<Duration> {
        let path = format!("{RESERVATIONS_PATH}/{}/renew", checked_id(reservation)?);
        let grant: ReservationGrant = self
            .call_json(
                Method::POST,
                &path,
                "",
                Some(&RenewRequest {
                    lease_secs: lease_secs(lease),
                }),
                timeout_for(Duration::ZERO),
                true,
                Tries::Once,
            )
            .await?;
        Ok(Duration::from_secs(u64::from(grant.lease_secs)))
    }

    async fn release(&self, reservation: &str) -> DispatchResult<()> {
        let path = format!("{RESERVATIONS_PATH}/{}", checked_id(reservation)?);
        self.call_empty(Method::DELETE, &path, Tries::Attempts)
            .await
    }

    async fn submit(&self, submission: Submission) -> DispatchResult<JobView> {
        let spec_len = serde_json::to_vec(&submission.spec)
            .map(|v| v.len())
            .unwrap_or(usize::MAX);
        if spec_len > MAX_JOB_SPEC {
            return Err(DispatchError::new(
                ErrorKind::TooLarge,
                format!("the job spec is {spec_len} bytes, past {MAX_JOB_SPEC}"),
            ));
        }
        let body = JobSubmission {
            request_id: submission.request_id,
            placement: submission.placement,
            reservation: submission.reservation,
            place_within_secs: u32::try_from(submission.place_within.as_secs()).unwrap_or(u32::MAX),
            spec: submission.spec,
        };
        self.call_json(
            Method::POST,
            JOBS_PATH,
            "",
            Some(&body),
            timeout_for(Duration::ZERO),
            true,
            Tries::Until(Instant::now() + submission.place_within),
        )
        .await
    }

    async fn job(&self, id: &str, after: Option<u64>, wait: Duration) -> DispatchResult<JobView> {
        let path = format!("{JOBS_PATH}/{}", checked_id(id)?);
        let mut query = format!("wait={}", wait_secs(wait));
        if let Some(a) = after {
            query.push_str(&format!("&after={a}"));
        }
        self.call_json(
            Method::GET,
            &path,
            &query,
            None::<&()>,
            timeout_for(wait),
            true,
            Tries::Attempts,
        )
        .await
    }

    async fn output(&self, id: &str, offset: u64, wait: Duration) -> DispatchResult<OutputChunk> {
        let path = format!("{JOBS_PATH}/{}/output", checked_id(id)?);
        let query = format!("offset={offset}&wait={}", wait_secs(wait));
        self.call(
            Method::GET,
            &path,
            &query,
            None,
            timeout_for(wait),
            true,
            Tries::Attempts,
            |resp| async move {
                let header = |name: &str| {
                    resp.headers()
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                };
                let chunk_offset = header(OUTPUT_OFFSET_HEADER)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(offset);
                let length = header(OUTPUT_LENGTH_HEADER).and_then(|v| v.parse().ok());
                let complete = header(OUTPUT_COMPLETE_HEADER).as_deref() == Some("true");
                let data = resp.bytes().await.map_err(transport)?;
                Ok(OutputChunk {
                    offset: chunk_offset,
                    length: length.unwrap_or(chunk_offset.saturating_add(data.len() as u64)),
                    complete,
                    data,
                })
            },
        )
        .await
    }

    async fn cancel(&self, id: &str, mode: CancelMode) -> DispatchResult<JobView> {
        let path = format!("{JOBS_PATH}/{}/cancel", checked_id(id)?);
        self.call_json(
            Method::POST,
            &path,
            "",
            Some(&CancelRequest { mode }),
            timeout_for(Duration::ZERO),
            true,
            Tries::Attempts,
        )
        .await
    }

    async fn settle(&self, id: &str) -> DispatchResult<()> {
        let path = format!("{JOBS_PATH}/{}/settle", checked_id(id)?);
        self.call_empty(Method::POST, &path, Tries::Attempts).await
    }
}

fn lease_secs(lease: Duration) -> u32 {
    u32::try_from(lease.as_secs())
        .unwrap_or(u32::MAX)
        .clamp(1, MAX_LEASE_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_keys() {
        assert!(valid_api_key(&format!("vkk_{}", "0f".repeat(32))));
        assert!(!valid_api_key(&format!("vkk_{}", "0F".repeat(32))));
        assert!(!valid_api_key(&"0f".repeat(32)));
        assert!(!valid_api_key("vkk_abc"));
    }

    #[test]
    fn urls() {
        let key = Secret::new(format!("vkk_{}", "0f".repeat(32)));
        let mk = |url: &str| {
            HubClient::new(HubOptions {
                url: url.to_owned(),
                api_key: key.clone(),
                ca_file: None,
                retry: HubRetry::default(),
            })
        };
        assert!(mk("https://hub.example.com:8443").is_ok());
        assert!(mk("http://127.0.0.1:8443").is_ok());
        assert!(mk("http://[::1]:8443").is_ok());
        assert!(mk("http://localhost:8443").is_ok());
        assert!(mk("http://hub.example.com").is_err());
        assert!(mk("ftp://hub").is_err());
    }
}
