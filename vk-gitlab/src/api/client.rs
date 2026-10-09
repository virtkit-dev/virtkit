//! The runner API client. Port of gitlab-runner's `network/gitlab.go`, `network/client.go`
//! and `network/retry_requester.go`: one client per configured runner, its token and TLS
//! settings fixed at construction.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use bytes::Bytes;
use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, Response, StatusCode, Url};
use serde::Serialize;

use super::types::*;
use crate::backoff::{Backoff, hex, random_bytes};
use crate::failure::{FailureReason, JobState};
use crate::job::Job;
use crate::secret::{Secret, is_created_runner_token};

pub const RUNNER_TOKEN_HEADER: &str = "RUNNER-TOKEN";
pub const JOB_TOKEN_HEADER: &str = "JOB-TOKEN";
pub const PRIVATE_TOKEN_HEADER: &str = "PRIVATE-TOKEN";
pub const CORRELATION_ID_HEADER: &str = "X-Request-Id";
pub const LAST_UPDATE_HEADER: &str = "X-GitLab-Last-Update";
pub const UPDATE_INTERVAL_HEADER: &str = "X-GitLab-Trace-Update-Interval";
pub const JOB_STATUS_HEADER: &str = "Job-Status";
pub const RETRY_AFTER_HEADER: &str = "Retry-After";
pub const RATE_LIMIT_RESET_HEADER: &str = "RateLimit-ResetTime";

/// gitlab-runner's `DefaultNetworkClientTimeout`: the bound on a whole request.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// gitlab-runner's transport `ResponseHeaderTimeout`; here the bound on each read.
const READ_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 10;
/// The bound on one job request's long poll (virtkit's `docs/gitlab-dispatch.md`, kept
/// inside a reservation's lease); Workhorse answers a held request before it.
const JOB_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// How a request answered with a retriable status (408, 429, 500, 502–504, ≥512) is retried.
/// The defaults are gitlab-runner's.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Attempts in total, the first included.
    pub max_attempts: u32,
    pub backoff_min: Duration,
    pub backoff_max: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            backoff_min: Duration::from_millis(100),
            backoff_max: Duration::from_secs(60),
        }
    }
}

/// What a [`GitLabClient`] is built from.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// The GitLab instance URL; a trailing `/` or `/ci` is ignored.
    pub url: String,
    pub token: Secret,
    /// PEM CA bundle trusted on top of the system roots.
    pub tls_ca_file: Option<PathBuf>,
    /// PEM client certificate and key, for GitLab instances that require TLS client auth.
    pub tls_cert_file: Option<PathBuf>,
    pub tls_key_file: Option<PathBuf>,
    pub system_id: String,
    pub info: Info,
    pub retry: RetryPolicy,
}

#[derive(Debug)]
pub struct ClientError(String);

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ClientError {}

/// A request that never got an HTTP status.
#[derive(Debug)]
pub enum HttpError {
    Url(String),
    /// Connection, TLS, timeout or body error. Built without the URL, which can be a
    /// presigned object-storage URL carrying a signature.
    Transport(reqwest::Error),
    TooManyRedirects,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpError::Url(e) => write!(f, "invalid URL: {e}"),
            HttpError::Transport(e) => f.write_str(&error_chain(e)),
            HttpError::TooManyRedirects => f.write_str("stopped after 10 redirects"),
        }
    }
}

impl std::error::Error for HttpError {}

/// `POST /api/v4/runners/verify` failed for another reason than the token being refused.
#[derive(Debug)]
pub struct VerifyError(pub String);

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verifying runner: {}", self.0)
    }
}

impl std::error::Error for VerifyError {}

/// A request body that can be produced again for a retry or a redirect.
#[derive(Clone)]
enum Body {
    Empty,
    Bytes(Bytes, &'static str),
}

struct Req {
    method: Method,
    uri: String,
    headers: HeaderMap,
    body: Body,
    /// Retry a 429 too, not only the other retriable statuses.
    retry_rate_limited: bool,
    /// A bound on each attempt, below the client's.
    timeout: Option<Duration>,
}

impl Req {
    fn new(method: Method, uri: impl Into<String>) -> Self {
        Self {
            method,
            uri: uri.into(),
            headers: HeaderMap::new(),
            body: Body::Empty,
            retry_rate_limited: true,
            timeout: None,
        }
    }

    /// Sets header `name`. A value that is not a valid header value (a token from a job
    /// payload can hold anything) is left out with a warning; the value itself is not logged.
    fn header(mut self, name: &str, value: &str) -> Self {
        // `from_bytes` lowercases the name; HTTP header names are case-insensitive.
        match (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            (Ok(n), Ok(v)) => {
                self.headers.insert(n, v);
            }
            _ => {
                log::warn!(header = name, uri = self.uri.as_str(); "Leaving out a header whose value is not valid in HTTP");
            }
        }
        self
    }

    fn json<T: Serialize>(mut self, body: &T) -> Self {
        // Serializing these plain structs cannot fail; an empty body would be refused by
        // GitLab rather than silently accepted.
        let data = serde_json::to_vec(body).unwrap_or_default();
        self.body = Body::Bytes(Bytes::from(data), "application/json");
        self
    }
}

/// `200 OK`, as Go's `Response.Status` prints a status.
pub fn status_text(status: StatusCode) -> String {
    format!(
        "{} {}",
        status.as_u16(),
        status.canonical_reason().unwrap_or("")
    )
}

fn header_str<'a>(resp: &'a Response, name: &str) -> &'a str {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// A new correlation ID (`X-Request-Id`): 32 hex digits, as gitlab-runner's dash-less UUID.
fn new_correlation_id() -> String {
    hex(&random_bytes::<16>())
}

/// gitlab-runner's `retryStatuses` plus every status from 512 up.
fn should_retry(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504) || status.as_u16() >= 512
}

/// The wait a retriable response asks for: `RateLimit-ResetTime` (an HTTP date) first, then
/// `Retry-After` (seconds); `None` when neither gives a positive wait.
fn requested_wait(resp: &Response) -> Option<Duration> {
    let reset = header_str(resp, RATE_LIMIT_RESET_HEADER);
    if !reset.is_empty() {
        match httpdate::parse_http_date(reset) {
            Ok(at) => {
                if let Ok(d) = at.duration_since(std::time::SystemTime::now())
                    && !d.is_zero()
                {
                    return Some(d);
                }
            }
            Err(_) => {
                log::warn!(header = RATE_LIMIT_RESET_HEADER, value = reset; "Couldn't parse rate limit header")
            }
        }
    }
    let retry_after = header_str(resp, RETRY_AFTER_HEADER);
    if !retry_after.is_empty() {
        match retry_after.parse::<i64>() {
            Ok(secs) if secs > 0 => return Some(Duration::from_secs(secs.unsigned_abs())),
            Ok(_) => {}
            Err(_) => {
                log::warn!(header = RETRY_AFTER_HEADER, value = retry_after; "Couldn't parse retry after header")
            }
        }
    }
    None
}

/// `scheme://host:port` equality, the boundary across which a redirect drops credentials.
fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme()
        && a.host_str() == b.host_str()
        && a.port_or_known_default() == b.port_or_known_default()
}

/// gitlab-runner's `parseGitLabURL`: `<url>/api/v4/`, after dropping a trailing `/` and `/ci`.
pub fn api_base_url(url: &str) -> Result<Url, ClientError> {
    let trimmed = url.trim_end_matches('/');
    let trimmed = trimmed.strip_suffix("/ci").unwrap_or(trimmed);
    let api = Url::parse(&format!("{trimmed}/api/v4/"))
        .map_err(|_| ClientError("only http or https scheme supported".to_owned()))?;
    if api.scheme() != "http" && api.scheme() != "https" {
        return Err(ClientError(
            "only http or https scheme supported".to_owned(),
        ));
    }
    Ok(api)
}

/// The state GitLab reports for a job in a job update or trace patch response. Port of
/// `network.RemoteJobStateResponse` and `TracePatchResponse`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteJobState {
    pub status: u16,
    /// `Job-Status`: `running`, `canceling`, `canceled` or `failed`.
    pub state: String,
    pub update_interval: i64,
    /// `Range` of a trace patch response: the length GitLab holds, as `0-<len>`.
    pub range: String,
}

impl RemoteJobState {
    pub fn from_response(resp: &Response) -> Self {
        let raw = header_str(resp, UPDATE_INTERVAL_HEADER);
        let update_interval = if raw.is_empty() {
            0
        } else {
            raw.parse::<i64>().unwrap_or_else(|_| {
                log::warn!(header_value = raw; "Failed to parse \"{UPDATE_INTERVAL_HEADER}\" header");
                0
            })
        };
        Self {
            status: resp.status().as_u16(),
            state: header_str(resp, JOB_STATUS_HEADER).to_owned(),
            update_interval,
            range: header_str(resp, "Range").to_owned(),
        }
    }

    /// The job is over on GitLab's side (canceled, failed, or no longer ours): stop.
    pub fn is_failed(&self) -> bool {
        self.state == "canceled" || self.state == "failed" || self.status == 403
    }

    /// GitLab asks for a graceful cancel.
    pub fn is_canceling(&self) -> bool {
        self.state == "canceling"
    }

    /// The offset a 416 tells the runner to resume from.
    pub fn range_end(&self) -> usize {
        let parts: Vec<&str> = self.range.split('-').collect();
        match parts.as_slice() {
            [_, end] => end.parse().unwrap_or(0),
            _ => 0,
        }
    }
}

/// The client for one runner.
pub struct GitLabClient {
    http: reqwest::Client,
    api: Url,
    token: Secret,
    system_id: String,
    info: Info,
    retry: RetryPolicy,
    last_update: Mutex<String>,
}

impl std::fmt::Debug for GitLabClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitLabClient")
            .field("api", &self.api.as_str())
            .field("token", &self.token)
            .finish_non_exhaustive()
    }
}

fn read_file(path: &Path, what: &str) -> Result<Vec<u8>, ClientError> {
    std::fs::read(path).map_err(|e| ClientError(format!("reading {what} {}: {e}", path.display())))
}

impl GitLabClient {
    pub fn new(opts: ClientOptions) -> Result<Self, ClientError> {
        // reqwest is built without a default crypto provider; ring is the one this binary
        // links. Installing it again is a no-op error, ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let api = api_base_url(&opts.url)?;
        let user_agent = format!(
            "{} {} ({}; {}/{})",
            opts.info.name,
            opts.info.version,
            opts.info.revision,
            opts.info.platform,
            opts.info.architecture
        );
        let mut builder = reqwest::Client::builder()
            .user_agent(user_agent)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(CLIENT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .tcp_keepalive(Duration::from_secs(30));
        if let Some(ca) = &opts.tls_ca_file {
            let pem = read_file(ca, "tls-ca-file")?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| ClientError(format!("parsing {}: {e}", ca.display())))?;
            builder = builder.tls_certs_merge(certs);
        }
        match (&opts.tls_cert_file, &opts.tls_key_file) {
            (Some(cert), Some(key)) => {
                let mut pem = read_file(cert, "tls-cert-file")?;
                pem.push(b'\n');
                pem.extend(read_file(key, "tls-key-file")?);
                let identity = reqwest::Identity::from_pem(&pem)
                    .map_err(|e| ClientError(format!("loading the TLS client certificate: {e}")))?;
                builder = builder.identity(identity);
            }
            (None, None) => {}
            _ => {
                return Err(ClientError(
                    "tls-cert-file and tls-key-file go together".to_owned(),
                ));
            }
        }
        let http = builder
            .build()
            .map_err(|e| ClientError(format!("building the HTTP client: {}", error_chain(&e))))?;
        Ok(Self {
            http,
            api,
            token: opts.token,
            system_id: opts.system_id,
            info: opts.info,
            retry: opts.retry,
            last_update: Mutex::new(String::new()),
        })
    }

    pub fn api_url(&self) -> &Url {
        &self.api
    }

    pub fn info(&self) -> &Info {
        &self.info
    }

    /// The runner token, shortened for logs.
    pub fn short_token(&self) -> String {
        self.token.short()
    }

    /// The queue version GitLab last reported (`X-GitLab-Last-Update`), echoed as
    /// `last_update` in the next job request so Workhorse can long-poll it.
    pub fn last_update(&self) -> String {
        self.last_update
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn set_last_update(&self, value: &str) {
        if value.is_empty() {
            return;
        }
        if let Ok(mut g) = self.last_update.lock() {
            value.clone_into(&mut g);
        }
    }

    fn record_last_update(&self, resp: &Response) {
        self.set_last_update(header_str(resp, LAST_UPDATE_HEADER));
    }

    async fn send_once(
        &self,
        method: &Method,
        url: &Url,
        headers: &HeaderMap,
        body: &Body,
        timeout: Option<Duration>,
    ) -> Result<Response, HttpError> {
        let mut rb = self
            .http
            .request(method.clone(), url.clone())
            .headers(headers.clone());
        if let Some(t) = timeout {
            rb = rb.timeout(t);
        }
        match body {
            Body::Empty => {}
            Body::Bytes(data, ctype) => {
                rb = rb.header(header::CONTENT_TYPE, *ctype).body(data.clone());
            }
        }
        rb.send()
            .await
            .map_err(|e| HttpError::Transport(e.without_url()))
    }

    /// One attempt, following redirects as Go's `http.Client` does: 307/308 repeat the
    /// request, 301–303 turn it into a GET without body. Divergence from upstream: a redirect
    /// to another origin also drops the GitLab token headers, which Go forwards.
    async fn send_following(
        &self,
        req: &Req,
        url: Url,
        headers: HeaderMap,
    ) -> Result<Response, HttpError> {
        let mut method = req.method.clone();
        let mut url = url;
        let mut headers = headers;
        let mut body = req.body.clone();
        for _ in 0..=MAX_REDIRECTS {
            let resp = self
                .send_once(&method, &url, &headers, &body, req.timeout)
                .await?;
            let code = resp.status().as_u16();
            if !matches!(code, 301 | 302 | 303 | 307 | 308) {
                return Ok(resp);
            }
            let location = header_str(&resp, "Location");
            if location.is_empty() {
                return Ok(resp);
            }
            let next = url
                .join(location)
                .map_err(|e| HttpError::Url(e.to_string()))?;
            if matches!(code, 301..=303) && method != Method::GET && method != Method::HEAD {
                method = Method::GET;
                body = Body::Empty;
            }
            if !same_origin(&url, &next) {
                for name in [
                    JOB_TOKEN_HEADER,
                    RUNNER_TOKEN_HEADER,
                    PRIVATE_TOKEN_HEADER,
                    "authorization",
                    "cookie",
                ] {
                    headers.remove(name);
                }
            }
            url = next;
        }
        Err(HttpError::TooManyRedirects)
    }

    /// Sends `req` relative to the API base (or to an absolute URL), retrying retriable
    /// statuses. Port of `retryRequester.Do`: a transport error is not retried, and the last
    /// retriable response is returned as is once attempts run out. Returns the correlation ID
    /// sent with it.
    async fn send(&self, mut req: Req) -> (Result<Response, HttpError>, String) {
        let correlation_id = new_correlation_id();
        req = req.header(CORRELATION_ID_HEADER, &correlation_id);
        let url = match self.api.join(&req.uri) {
            Ok(u) => u,
            Err(e) => return (Err(HttpError::Url(e.to_string())), correlation_id),
        };
        let mut backoff = Backoff::new(self.retry.backoff_min, self.retry.backoff_max, 2.0, true);
        let mut attempts = 0u32;
        loop {
            let resp = match self
                .send_following(&req, url.clone(), req.headers.clone())
                .await
            {
                Ok(r) => r,
                Err(e) => return (Err(e), correlation_id),
            };
            attempts = attempts.saturating_add(1);
            let status = resp.status();
            let rate_limited_final =
                status == StatusCode::TOO_MANY_REQUESTS && !req.retry_rate_limited;
            if !should_retry(status) || attempts >= self.retry.max_attempts || rate_limited_final {
                return (Ok(resp), correlation_id);
            }
            // A server-requested wait is honored up to the backoff ceiling.
            let wait = requested_wait(&resp)
                .map(|d| d.min(self.retry.backoff_max))
                .unwrap_or_else(|| backoff.next_delay());
            log::info!(
                url = url.path(),
                method = req.method.as_str(),
                status = status.as_u16(),
                attempt = attempts,
                max_attempts = self.retry.max_attempts,
                correlation_id = correlation_id.as_str(),
                retry_after = header_str(&resp, RETRY_AFTER_HEADER),
                ratelimit_reset_time = header_str(&resp, RATE_LIMIT_RESET_HEADER),
                duration_s = wait.as_secs_f64();
                "Waiting before making the next call"
            );
            drop(resp);
            tokio::time::sleep(wait).await;
        }
    }

    /// `POST /api/v4/runners/verify`. `Ok(None)` when GitLab refuses the token (403).
    pub async fn verify(&self) -> Result<Option<VerifyRunnerResponse>, VerifyError> {
        let body = VerifyRunnerRequest {
            info: &self.info,
            token: self.token.expose(),
            system_id: &self.system_id,
        };
        let req = Req::new(Method::POST, "runners/verify")
            .header(RUNNER_TOKEN_HEADER, self.token.expose())
            .header("Accept", "application/json")
            .json(&body);
        let (resp, cid) = self.send(req).await;
        let runner = self.token.short();
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                log::error!(runner = runner.as_str(), correlation_id = cid.as_str(), status = e.to_string().as_str(); "Verifying runner... client error");
                return Err(VerifyError(format!("client error: {e}")));
            }
        };
        self.record_last_update(&resp);
        let cid = correlation_from(&resp, cid);
        let created = is_created_runner_token(self.token.expose());
        match resp.status().as_u16() {
            200 => {
                let parsed = if is_json(&resp) {
                    let body = resp.bytes().await.unwrap_or_default();
                    match serde_json::from_slice::<VerifyRunnerResponse>(&body) {
                        Ok(v) => v,
                        Err(e) => {
                            log::warn!(runner = runner.as_str(), error = e.to_string().as_str(); "Verifying runner... unexpected response body");
                            VerifyRunnerResponse::default()
                        }
                    }
                } else {
                    // A legacy server answers with no JSON body.
                    VerifyRunnerResponse::default()
                };
                let what = if created { "is valid" } else { "is alive" };
                log::info!(runner = runner.as_str(), correlation_id = cid.as_str(); "Verifying runner... {what}");
                Ok(Some(parsed))
            }
            403 => {
                if created {
                    log::info!(runner = runner.as_str(), correlation_id = cid.as_str(); "Verifying runner... is not valid");
                } else {
                    log::error!(runner = runner.as_str(), correlation_id = cid.as_str(), status = "403 Forbidden"; "Verifying runner... is removed");
                }
                Ok(None)
            }
            _ => {
                let status = status_message(resp, &Method::POST).await;
                log::error!(runner = runner.as_str(), correlation_id = cid.as_str(), status = status.as_str(); "Verifying runner... failed");
                Err(VerifyError(status))
            }
        }
    }

    /// `POST /api/v4/jobs/request`: one long poll for a job. A 429 is not retried here; the
    /// poll loop's own interval paces the next request.
    pub async fn request_job(&self) -> JobRequestResult {
        let last_update = self.last_update();
        let body = JobRequest {
            info: &self.info,
            token: self.token.expose(),
            system_id: &self.system_id,
            last_update: &last_update,
        };
        let mut req = Req::new(Method::POST, "jobs/request")
            .header(RUNNER_TOKEN_HEADER, self.token.expose())
            .header("Accept", "application/json")
            .json(&body);
        req.retry_rate_limited = false;
        req.timeout = Some(JOB_REQUEST_TIMEOUT);
        let (resp, cid) = self.send(req).await;
        let runner = self.token.short();
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                // Upstream counts a failed connection as a healthy runner: GitLab may be
                // down, the runner is not at fault. An unusable URL is the runner's own.
                log::warn!(runner = runner.as_str(), correlation_id = cid.as_str(), status = e.to_string().as_str(); "Checking for jobs... failed");
                return JobRequestResult {
                    job: None,
                    healthy: !matches!(e, HttpError::Url(_)),
                };
            }
        };
        let cid = correlation_from(&resp, cid);
        let status = resp.status();
        match status.as_u16() {
            201 => {
                if !is_json(&resp) {
                    let ctype = header_str(&resp, "Content-Type").to_owned();
                    log::warn!(runner = runner.as_str(), correlation_id = cid.as_str(), status = format!("response is not application/json: server should return application/json. Got: {ctype}").as_str(); "Checking for jobs... failed");
                    return JobRequestResult {
                        job: None,
                        healthy: true,
                    };
                }
                let last_update_header = header_str(&resp, LAST_UPDATE_HEADER).to_owned();
                let body = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        log::warn!(runner = runner.as_str(), correlation_id = cid.as_str(), status = e.without_url().to_string().as_str(); "Checking for jobs... failed");
                        return JobRequestResult {
                            job: None,
                            healthy: true,
                        };
                    }
                };
                match serde_json::from_slice::<Job>(&body) {
                    Ok(job) => {
                        self.set_last_update(&last_update_header);
                        log::info!(
                            runner = runner.as_str(),
                            correlation_id = cid.as_str(),
                            job = job.id,
                            job_name = job.job_info.name.as_str(),
                            repo_url = job.repo_clean_url().as_str();
                            "Checking for jobs... received"
                        );
                        JobRequestResult {
                            job: Some(Box::new(job)),
                            healthy: true,
                        }
                    }
                    Err(e) => {
                        // serde's message can quote the payload, secrets included: only
                        // the position is logged.
                        let at = format!("line {}, column {}", e.line(), e.column());
                        log::error!(runner = runner.as_str(), correlation_id = cid.as_str(), status = format!("decoding json payload at {at}").as_str(); "Checking for jobs... failed");
                        self.fail_undecodable_job(&body, &at).await;
                        JobRequestResult {
                            job: None,
                            healthy: true,
                        }
                    }
                }
            }
            204 => {
                self.record_last_update(&resp);
                log::debug!(runner = runner.as_str(), correlation_id = cid.as_str(), status = status_text(status).as_str(); "Checking for jobs... no content");
                JobRequestResult {
                    job: None,
                    healthy: true,
                }
            }
            403 => {
                self.record_last_update(&resp);
                log::error!(runner = runner.as_str(), correlation_id = cid.as_str(), status = status_text(status).as_str(); "Checking for jobs... forbidden");
                JobRequestResult {
                    job: None,
                    healthy: false,
                }
            }
            503 => {
                self.record_last_update(&resp);
                log::warn!(runner = runner.as_str(), correlation_id = cid.as_str(), status = status_text(status).as_str(); "Checking for jobs... GitLab instance currently unavailable");
                JobRequestResult {
                    job: None,
                    healthy: true,
                }
            }
            429 => {
                self.record_last_update(&resp);
                log::warn!(
                    runner = runner.as_str(),
                    correlation_id = cid.as_str(),
                    status = status_text(status).as_str(),
                    retry_after = header_str(&resp, RETRY_AFTER_HEADER),
                    ratelimit_reset_time = header_str(&resp, RATE_LIMIT_RESET_HEADER);
                    "Checking for jobs... rate limited"
                );
                JobRequestResult {
                    job: None,
                    healthy: true,
                }
            }
            _ => {
                self.record_last_update(&resp);
                let text = status_message(resp, &Method::POST).await;
                log::warn!(runner = runner.as_str(), correlation_id = cid.as_str(), status = text.as_str(); "Checking for jobs... failed");
                JobRequestResult {
                    job: None,
                    healthy: true,
                }
            }
        }
    }

    /// GitLab assigned a job whose payload does not decode. Upstream drops it, leaving it
    /// running until it times out; when its ID and token can still be read, fail it now.
    async fn fail_undecodable_job(&self, body: &[u8], at: &str) {
        let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
            return;
        };
        let (Some(id), Some(token)) = (
            value.get("id").and_then(serde_json::Value::as_i64),
            value.get("token").and_then(serde_json::Value::as_str),
        ) else {
            return;
        };
        let creds = JobCredentials {
            id,
            token: Secret::new(token),
        };
        let line = format!("ERROR: the runner could not decode this job (at {at})\n");
        let _ = self.patch_trace(&creds, line.as_bytes(), 0, false).await;
        let mut info = UpdateJobInfo::new(id, JobState::Failed);
        info.failure_reason = Some(FailureReason::runner_system_failure());
        let _ = self.update_job(&creds, &info).await;
    }

    /// `PUT /api/v4/jobs/:id`.
    pub async fn update_job(&self, job: &JobCredentials, info: &UpdateJobInfo) -> UpdateJobResult {
        let body = UpdateJobRequest {
            info: &self.info,
            token: job.token.expose(),
            state: info.state,
            failure_reason: info.failure_reason.as_ref(),
            checksum: &info.output.checksum,
            output: &info.output,
            exit_code: info.exit_code,
            runtime_environment_key: &info.runtime_environment_key,
        };
        let req = Req::new(Method::PUT, format!("jobs/{}", info.id))
            .header(JOB_TOKEN_HEADER, job.token.expose())
            .json(&body);
        log::info!(
            job = info.id,
            checksum = info.output.checksum.as_str(),
            bytesize = info.output.bytesize;
            "Updating job..."
        );
        let (resp, cid) = self.send(req).await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                log::warn!(job = info.id, correlation_id = cid.as_str(), status = e.to_string().as_str(); "Submitting job to coordinator... failed");
                return UpdateJobResult {
                    state: UpdateState::Failed,
                    cancel_requested: false,
                    new_update_interval: 0,
                };
            }
        };
        self.record_last_update(&resp);
        let cid = correlation_from(&resp, cid);
        let remote = RemoteJobState::from_response(&resp);
        let status = resp.status();
        let state = if remote.is_failed() {
            log::warn!(job = info.id, code = status.as_u16(), job_status = remote.state.as_str(), correlation_id = cid.as_str(), status = status_text(status).as_str(); "Submitting job to coordinator... job failed");
            UpdateState::Abort
        } else {
            match status.as_u16() {
                200 => {
                    log::info!(job = info.id, code = 200, job_status = remote.state.as_str(), correlation_id = cid.as_str(); "Submitting job to coordinator...ok");
                    UpdateState::Succeeded
                }
                202 => {
                    log::info!(job = info.id, code = 202, correlation_id = cid.as_str(); "Submitting job to coordinator...accepted, but not yet completed");
                    UpdateState::AcceptedButNotCompleted
                }
                412 => {
                    log::info!(job = info.id, code = 412, correlation_id = cid.as_str(); "Submitting job to coordinator...trace validation failed");
                    UpdateState::TraceValidationFailed
                }
                404 => {
                    log::warn!(job = info.id, code = 404, correlation_id = cid.as_str(), status = status_text(status).as_str(); "Submitting job to coordinator... not found");
                    UpdateState::Abort
                }
                _ => {
                    let text = status_message(resp, &Method::PUT).await;
                    log::warn!(job = info.id, code = status.as_u16(), correlation_id = cid.as_str(), status = text.as_str(); "Submitting job to coordinator... failed");
                    UpdateState::Failed
                }
            }
        };
        UpdateJobResult {
            state,
            cancel_requested: remote.is_canceling(),
            new_update_interval: remote.update_interval,
        }
    }

    /// `PATCH /api/v4/jobs/:id/trace`: append `content`, which starts at `start` in the log.
    pub async fn patch_trace(
        &self,
        job: &JobCredentials,
        content: &[u8],
        start: usize,
        debug_trace: bool,
    ) -> PatchTraceResult {
        if content.is_empty() {
            log::info!(job = job.id; "Appending trace to coordinator...skipped due to empty patch");
            return PatchTraceResult::new(start, PatchState::Succeeded, 0);
        }
        let end = start.saturating_add(content.len());
        let content_range = format!("{start}-{}", end.saturating_sub(1));
        let mut req = Req::new(
            Method::PATCH,
            format!("jobs/{}/trace?debug_trace={debug_trace}", job.id),
        )
        .header(JOB_TOKEN_HEADER, job.token.expose())
        .header("Content-Range", &content_range);
        req.body = Body::Bytes(Bytes::copy_from_slice(content), "text/plain");
        let (resp, cid) = self.send(req).await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                log::error!(job = job.id, error = e.to_string().as_str(); "Appending trace to coordinator... error");
                return PatchTraceResult::new(start, PatchState::Failed, 0);
            }
        };
        let cid = correlation_from(&resp, cid);
        let remote = RemoteJobState::from_response(&resp);
        let status = resp.status();
        let mut result = PatchTraceResult {
            sent_offset: start,
            cancel_requested: remote.is_canceling(),
            state: PatchState::Failed,
            new_update_interval: remote.update_interval,
        };
        let fields = |msg: &str, level: log::Level| {
            log::log!(
                level,
                job = job.id,
                sent_log = content_range.as_str(),
                job_log = remote.range.as_str(),
                job_status = remote.state.as_str(),
                code = status.as_u16(),
                update_interval = remote.update_interval,
                correlation_id = cid.as_str();
                "Appending trace to coordinator...{msg}"
            )
        };
        if remote.is_failed() {
            fields(" job failed", log::Level::Warn);
            result.state = PatchState::Abort;
            return result;
        }
        match status.as_u16() {
            202 => {
                fields("ok", log::Level::Info);
                result.sent_offset = end;
                result.state = PatchState::Succeeded;
            }
            404 => {
                fields(" not-found", log::Level::Warn);
                result.state = PatchState::NotFound;
            }
            416 => {
                fields(" range mismatch", log::Level::Warn);
                result.sent_offset = remote.range_end();
                result.state = PatchState::RangeMismatch;
            }
            _ => {
                fields(" failed", log::Level::Warn);
                result.state = PatchState::Failed;
            }
        }
        result
    }
}

/// `e` and its sources, `: `-separated.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut source = e.source();
    while let Some(s) = source {
        out.push_str(": ");
        out.push_str(&s.to_string());
        source = s.source();
    }
    out
}

fn correlation_from(resp: &Response, fallback: String) -> String {
    let echoed = header_str(resp, CORRELATION_ID_HEADER);
    if echoed.is_empty() {
        fallback
    } else {
        echoed.to_owned()
    }
}

fn mime_type(resp: &Response) -> String {
    header_str(resp, "Content-Type")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

fn is_json(resp: &Response) -> bool {
    mime_type(resp) == "application/json"
}

/// GitLab's `message` of an error response: a string, or a map of field to messages.
fn error_message(value: &serde_json::Value) -> Option<String> {
    match value.get("message")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Object(map) => {
            let parts: Vec<String> = map
                .iter()
                .map(|(k, v)| {
                    let msgs: Vec<String> = match v {
                        serde_json::Value::Array(items) => items
                            .iter()
                            .map(|i| i.as_str().map_or_else(|| i.to_string(), str::to_owned))
                            .collect(),
                        other => vec![other.to_string()],
                    };
                    format!("{k}: {}", msgs.join("; "))
                })
                .collect();
            Some(parts.join(", "))
        }
        _ => None,
    }
}

/// Port of `getMessageFromJSONResponse`: the status line, or for a JSON error body
/// `<METHOD> <url>: <status> (<message>)`.
pub async fn status_message(resp: Response, method: &Method) -> String {
    let status = resp.status();
    if status.is_success() || !is_json(&resp) {
        return status_text(status);
    }
    let url = crate::job::clean_url(resp.url().as_str());
    let Ok(body) = resp.bytes().await else {
        return status_text(status);
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return status_text(status);
    };
    let base = format!("{} {url}: {}", method.as_str(), status_text(status));
    match error_message(&value) {
        Some(m) if m != status_text(status) => format!("{base} ({m})"),
        _ => base,
    }
}

/// The job log reporter's API, allowing a scripted test double.
pub trait JobApi: Send + Sync + 'static {
    fn patch_trace(
        &self,
        job: &JobCredentials,
        content: &[u8],
        start: usize,
        debug_trace: bool,
    ) -> impl Future<Output = PatchTraceResult> + Send;

    fn update_job(
        &self,
        job: &JobCredentials,
        info: &UpdateJobInfo,
    ) -> impl Future<Output = UpdateJobResult> + Send;
}

impl JobApi for GitLabClient {
    fn patch_trace(
        &self,
        job: &JobCredentials,
        content: &[u8],
        start: usize,
        debug_trace: bool,
    ) -> impl Future<Output = PatchTraceResult> + Send {
        GitLabClient::patch_trace(self, job, content, start, debug_trace)
    }

    fn update_job(
        &self,
        job: &JobCredentials,
        info: &UpdateJobInfo,
    ) -> impl Future<Output = UpdateJobResult> + Send {
        GitLabClient::update_job(self, job, info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ported from gitlab-runner v19.5.0 network/client_test.go, TestUrlFixing, and
    // network/retry_requester_test.go, TestShouldRetryRequest (MIT, Copyright (c) 2015-2019
    // GitLab Inc.).
    #[test]
    fn url_fixing() {
        for (input, want) in [
            (
                "https://gitlab.example.com",
                "https://gitlab.example.com/api/v4/",
            ),
            (
                "https://gitlab.example.com/",
                "https://gitlab.example.com/api/v4/",
            ),
            (
                "https://gitlab.example.com/ci",
                "https://gitlab.example.com/api/v4/",
            ),
            (
                "https://gitlab.example.com/ci/",
                "https://gitlab.example.com/api/v4/",
            ),
            (
                "https://gitlab.example.com/sub/ci",
                "https://gitlab.example.com/sub/api/v4/",
            ),
        ] {
            assert_eq!(api_base_url(input).unwrap().as_str(), want, "{input}");
        }
        for bad in ["broken", "ftp://gitlab.example.com", ""] {
            assert!(api_base_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn retriable_statuses() {
        for (code, want) in [
            (200, false),
            (201, false),
            (400, false),
            (404, false),
            (408, true),
            (429, true),
            (500, true),
            (501, false),
            (502, true),
            (503, true),
            (504, true),
            (511, false),
            (512, true),
            (599, true),
        ] {
            assert_eq!(
                should_retry(StatusCode::from_u16(code).unwrap()),
                want,
                "{code}"
            );
        }
    }

    // network/patch_response.go NewOffset, via remote_job_state_response_test.go.
    #[test]
    fn range_end() {
        let r = |range: &str| {
            RemoteJobState {
                range: range.to_owned(),
                ..Default::default()
            }
            .range_end()
        };
        assert_eq!(r("0-10"), 10);
        assert_eq!(r("0-"), 0);
        assert_eq!(r("10"), 0);
        assert_eq!(r(""), 0);
        assert_eq!(r("a-b"), 0);
    }

    #[test]
    fn error_messages() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"message": "duplicate variables"}"#).unwrap();
        assert_eq!(error_message(&v).as_deref(), Some("duplicate variables"));
        let v: serde_json::Value =
            serde_json::from_str(r#"{"message": {"name": ["is too long", 3]}}"#).unwrap();
        assert_eq!(error_message(&v).as_deref(), Some("name: is too long; 3"));
    }

    #[test]
    fn correlation_ids_are_32_hex_digits() {
        let id = new_correlation_id();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(id, new_correlation_id());
    }
}
