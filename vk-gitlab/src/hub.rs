//! The hub client: [`Dispatcher`] over vk-hub's client API (HTTP/1.1 and JSON, TLS 1.3),
//! as `docs/gitlab-dispatch.md`, "Daemon ↔ hub", and vk-hub's `src/client.rs` define it.
//!
//! Each request is signed by the relay's key, as a node signs a release download: the
//! [`RELAY_HEADER`], [`TIME_HEADER`] and [`SIGNATURE_HEADER`] headers carry the relay's ID,
//! the time, and its signature over [`client_request_message`] — the method, path and query,
//! the body's SHA-256, the time and the TLS connection's exporter. A signature is good on its
//! own connection only, so each request opens a connection of its own, and a retry signs
//! again; a long poll then never holds a renewal up behind it.
//!
//! Transport errors and the retryable codes (`unavailable`, `internal`, and `no_capacity`
//! outside a reservation) are retried with backoff from 1 to 30 seconds and jitter, honouring
//! `retry_after_secs` up to a minute; any other 4xx is not. A create carries the
//! caller's `request_id`, which the hub keeps for a day, so a retried create answers the
//! first answer: a submission is retried until its `place_within` is up. An answer whose
//! body is cut short is retried as a request without one is. A renewal is tried once, and
//! its caller retries it within the lease.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use vk_hub_proto::client::{
    CAPACITY_PATH, CancelMode, CancelRequest, Capacity, CapacityRequest, ClientError, ErrorCode,
    JOBS_PATH, JobSubmission, JobView, MAX_OUTPUT_READ, MAX_WAIT_SECS, OUTPUT_COMPLETE_HEADER,
    OUTPUT_LENGTH_HEADER, OUTPUT_OFFSET_HEADER, Placement, RELAY_HEADER, RESERVATIONS_PATH,
    RenewRequest, ReservationGrant, ReservationRequest, client_request_message,
};
use vk_hub_proto::dispatch::MAX_LEASE_SECS;
use vk_hub_proto::job::MAX_JOB_SPEC;
use vk_hub_proto::{SIGNATURE_HEADER, TIME_HEADER, valid_id};
use vk_peer::identity::Identity;

use crate::backoff::Backoff;
use crate::dispatch::{
    DispatchError, DispatchResult, Dispatcher, ErrorKind, OutputChunk, Reservation, Submission,
};

/// How long a request may take beyond the long poll it asks for.
const REQUEST_SLACK: Duration = Duration::from_secs(30);
/// The longest `retry_after_secs` (or `Retry-After`) honoured.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);
/// The most an answer's body is read to: an output read, and room for its headers' worth.
const MAX_ANSWER: usize = MAX_OUTPUT_READ + (64 << 10);

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

/// The enrolled relay a client speaks as.
#[derive(Clone)]
pub struct HubOptions {
    /// The hub's base URL, as `join` checked it: `https://…`, or `http://` to a loopback hub.
    pub hub: String,
    /// The TLS the hub is reached with.
    pub tls: Arc<rustls::ClientConfig>,
    /// The relay's ID and key.
    pub relay_id: String,
    pub identity: Arc<Identity>,
    pub retry: HubRetry,
}

pub struct HubClient {
    opts: HubOptions,
}

impl std::fmt::Debug for HubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubClient")
            .field("hub", &self.opts.hub)
            .field("relay_id", &self.opts.relay_id)
            .finish_non_exhaustive()
    }
}

/// A successful answer, read whole.
struct Answer {
    headers: HeaderMap,
    body: Bytes,
}

impl Answer {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

impl HubClient {
    pub fn new(opts: HubOptions) -> Self {
        Self { opts }
    }

    /// One request on a connection of its own, signed for it, and its answer read whole,
    /// all within `timeout`. `Err` is a failed answer, or [`ErrorKind::Transport`] when none
    /// came whole.
    async fn send(
        &self,
        method: &Method,
        path_and_query: &str,
        body: &Bytes,
        timeout: Duration,
    ) -> DispatchResult<Answer> {
        let exchange = async {
            let transport = |what: &str, e: &dyn std::fmt::Display| {
                DispatchError::new(ErrorKind::Transport, format!("{what}: {e}"))
            };
            let (io, exported, authority) = vk_peer::session::dial(&self.opts.hub, &self.opts.tls)
                .await
                .map_err(|e| transport("reaching the hub", &format!("{e:#}")))?;
            let channel = match &exported {
                Some(e) => vk_hub_proto::Channel::Tls(e),
                None => vk_hub_proto::Channel::Plaintext,
            };
            let at = vk_peer::now_secs();
            let digest: [u8; vk_hub_proto::SHA256_LEN] =
                ring::digest::digest(&ring::digest::SHA256, body)
                    .as_ref()
                    .try_into()
                    .map_err(|_| DispatchError::new(ErrorKind::Other, "a SHA-256 of 32 bytes"))?;
            let signature = self.opts.identity.sign(&client_request_message(
                &self.opts.relay_id,
                method.as_str(),
                path_and_query,
                &digest,
                at,
                channel,
            ));
            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(io))
                    .await
                    .map_err(|e| transport("opening the request", &e))?;
            let driver = tokio::spawn(conn);
            let mut request = hyper::Request::builder()
                .method(method.clone())
                .uri(path_and_query)
                .header(hyper::header::HOST, authority)
                .header(
                    hyper::header::USER_AGENT,
                    concat!("vk-gitlab ", env!("CARGO_PKG_VERSION")),
                )
                .header(RELAY_HEADER, &self.opts.relay_id)
                .header(TIME_HEADER, at.to_string())
                .header(SIGNATURE_HEADER, signature);
            if !body.is_empty() {
                request = request.header(
                    hyper::header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
            }
            let request = request
                .body(http_body_util::Full::new(body.clone()))
                .map_err(|e| DispatchError::new(ErrorKind::Invalid, e.to_string()))?;
            let answer = async {
                let resp = sender
                    .send_request(request)
                    .await
                    .map_err(|e| transport("sending the request", &e))?;
                let (parts, incoming) = resp.into_parts();
                let body = http_body_util::Limited::new(incoming, MAX_ANSWER)
                    .collect()
                    .await
                    .map_err(|e| transport("reading the answer", &e))?
                    .to_bytes();
                Ok((parts.status, parts.headers, body))
            }
            .await;
            driver.abort();
            let (status, headers, body) = answer?;
            if status.is_success() {
                Ok(Answer { headers, body })
            } else {
                Err(error_of(status, &headers, &body))
            }
        };
        tokio::time::timeout(timeout, exchange)
            .await
            .unwrap_or_else(|_| {
                Err(DispatchError::new(
                    ErrorKind::Transport,
                    format!("the hub did not answer within {}s", timeout.as_secs()),
                ))
            })
    }

    /// Retries a call according to `tries`, and decodes a successful answer with `read`.
    /// `retry_no_capacity` is false when the caller waits for capacity itself.
    #[allow(clippy::too_many_arguments)]
    async fn call<T>(
        &self,
        method: Method,
        path: &str,
        query: &str,
        body: Option<Bytes>,
        timeout: Duration,
        retry_no_capacity: bool,
        tries: Tries,
        read: impl Fn(Answer) -> DispatchResult<T>,
    ) -> DispatchResult<T> {
        let path_and_query = if query.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{query}")
        };
        let body = body.unwrap_or_default();
        let mut backoff = Backoff::new(
            self.opts.retry.backoff_min,
            self.opts.retry.backoff_max,
            2.0,
            true,
        );
        let mut attempt = 0u32;
        loop {
            attempt = attempt.saturating_add(1);
            let err = match self.send(&method, &path_and_query, &body, timeout).await {
                Ok(answer) => return read(answer),
                Err(e) => e,
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
                Tries::Attempts => attempt < self.opts.retry.max_attempts,
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
    async fn call_empty(
        &self,
        method: Method,
        path: &str,
        body: Option<Bytes>,
        tries: Tries,
    ) -> DispatchResult<()> {
        self.call(
            method,
            path,
            "",
            body,
            timeout_for(Duration::ZERO),
            true,
            tries,
            |_| Ok(()),
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
            |answer| {
                serde_json::from_slice(&answer.body).map_err(|e| {
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

/// A failed answer as an error: the body's code when it has one, else the status's.
fn error_of(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> DispatchError {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
    };
    let retry_header = header("retry-after");
    let length = header(OUTPUT_LENGTH_HEADER);
    let parsed = serde_json::from_slice::<ClientError>(body).ok();
    if status == StatusCode::RANGE_NOT_SATISFIABLE {
        return DispatchError {
            status: Some(status.as_u16()),
            coded: parsed.is_some(),
            ..DispatchError::new(
                ErrorKind::OutputRange {
                    length: length.unwrap_or(0),
                },
                parsed.map_or_else(|| status.to_string(), |p| p.error),
            )
        };
    }
    let kind = match parsed.as_ref().map(|p| p.code) {
        Some(ErrorCode::Unauthorized) => ErrorKind::Unauthorized,
        // Told apart once the relay fails a job refused for approval.
        Some(ErrorCode::Forbidden | ErrorCode::ApprovalPending | ErrorCode::ProjectRejected) => {
            ErrorKind::Forbidden
        }
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
        coded: parsed.is_some(),
        message: parsed.map_or_else(|| status.to_string(), |p| p.error),
        retry_after,
        status: Some(status.as_u16()),
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
        self.call_empty(Method::DELETE, &path, None, Tries::Attempts)
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
            |answer| {
                let chunk_offset = answer
                    .header(OUTPUT_OFFSET_HEADER)
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(offset);
                let length = answer
                    .header(OUTPUT_LENGTH_HEADER)
                    .and_then(|v| v.parse().ok());
                let complete = answer.header(OUTPUT_COMPLETE_HEADER) == Some("true");
                let data = answer.body;
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
        self.call_empty(Method::POST, &path, None, Tries::Attempts)
            .await
    }
}

fn lease_secs(lease: Duration) -> u32 {
    u32::try_from(lease.as_secs())
        .unwrap_or(u32::MAX)
        .clamp(1, MAX_LEASE_SECS)
}
