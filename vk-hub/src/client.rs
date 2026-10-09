//! The client API on the node listener (`vk_hub_proto::client`): `vk-gitlab` requests and
//! reserves capacity, submits jobs and follows them using an API key in `authorization: Bearer`.
//! This module handles HTTP paths, bodies, long polls, idempotent creates and error codes;
//! [`crate::jobs`] handles the work.
//!
//! A request is authenticated before its body is read, and its body is read capped and timed:
//! [`MAX_BODY`], or [`MAX_JOB_BODY`] for a job. A long poll holds its request for at most
//! [`MAX_WAIT_SECS`].

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{self, HeaderMap, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use vk_hub_proto::client::{
    AUTHORIZATION, CAPACITY_PATH, CancelRequest, CapacityRequest, ClientError, ErrorCode,
    JOBS_PATH, JobState, JobSubmission, MAX_OUTPUT_READ, MAX_WAIT_SECS, OUTPUT_COMPLETE_HEADER,
    OUTPUT_LENGTH_HEADER, OUTPUT_OFFSET_HEADER, Placement, RESERVATIONS_PATH, RenewRequest,
    ReservationGrant, ReservationRequest,
};
use vk_hub_proto::job::{JobSpec, MAX_JOB_SPEC};

use crate::jobs::{self, OutputError};
use crate::server::{Body, Hub, full};
use crate::store::{ApiPrincipal, JobRow, RequestRow, Scope, Submitted, valid_name};

/// The largest non-job request body: a placement and a few numbers.
const MAX_BODY: usize = 64 * 1024;

/// The largest job submission: its spec, and the rest of the body around it.
const MAX_JOB_BODY: usize = MAX_JOB_SPEC + MAX_BODY;

/// How long a body may take to arrive.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// The most labels a placement names.
const MAX_LABELS: usize = 32;

/// The longest a job may wait to be placed.
const MAX_PLACE_WITHIN_SECS: u32 = 86_400;

/// A failed request: its status, and the body [`ClientError`] it answers with.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: ErrorCode,
    pub message: String,
    pub retry_after: Option<u32>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        ApiError {
            status,
            code,
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn retry_after(mut self, secs: u32) -> Self {
        self.retry_after = Some(secs);
        self
    }

    fn invalid(message: impl Into<String>) -> Self {
        ApiError::new(StatusCode::BAD_REQUEST, ErrorCode::Invalid, message)
    }

    pub fn response(&self) -> Response<Body> {
        let mut resp = json(
            self.status,
            &ClientError {
                error: self.message.clone(),
                code: self.code,
                retry_after_secs: self.retry_after,
            },
        );
        if let Some(secs) = self.retry_after {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        resp
    }
}

/// Log hub failures and return `internal` without exposing their details.
impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        eprintln!("vk-hub: client API: {e:#}");
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ErrorCode::Internal,
            "internal error",
        )
        .retry_after(1)
    }
}

/// Whether `path` is the client API's.
pub fn is_client_path(path: &str) -> bool {
    path == CAPACITY_PATH
        || path == RESERVATIONS_PATH
        || path.starts_with(&format!("{RESERVATIONS_PATH}/"))
        || path == JOBS_PATH
        || path.starts_with(&format!("{JOBS_PATH}/"))
}

/// The key the request carries, if the hub knows it and it still works.
pub async fn authenticate(headers: &HeaderMap, hub: &Hub) -> Result<ApiPrincipal, ApiError> {
    let unauthorized = || {
        ApiError::new(
            StatusCode::UNAUTHORIZED,
            ErrorCode::Unauthorized,
            "an API key the hub knows is required, as authorization: Bearer",
        )
    };
    let key = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or_else(unauthorized)?
        .to_string();
    let db = hub.db.clone();
    let found = tokio::task::spawn_blocking(move || db.api_key(&key, crate::now_secs()))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    found.ok_or_else(unauthorized)
}

/// Serve an authenticated request.
pub async fn serve(
    req: Request<Incoming>,
    hub: &Arc<Hub>,
    principal: ApiPrincipal,
) -> Response<Body> {
    route(req, hub, &principal)
        .await
        .unwrap_or_else(|e| e.response())
}

async fn route(
    req: Request<Incoming>,
    hub: &Arc<Hub>,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or_default().to_string();
    let method = req.method().clone();
    let wanted = if path == CAPACITY_PATH {
        [Scope::Capacity, Scope::Jobs].as_slice()
    } else {
        [Scope::Jobs].as_slice()
    };
    if !wanted.iter().any(|s| principal.has(*s)) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            "this key's scopes do not allow this request",
        ));
    }
    let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let id = |s: &str| -> Result<String, ApiError> {
        if vk_hub_proto::valid_id(s) {
            Ok(s.to_string())
        } else {
            Err(ApiError::invalid(format!("{s:?} is not an ID")))
        }
    };
    match (method, segments.as_slice()) {
        (Method::POST, ["v1", "capacity"]) => capacity(req, hub, principal).await,
        (Method::POST, ["v1", "reservations"]) => reserve(req, hub, principal).await,
        (Method::POST, ["v1", "reservations", r, "renew"]) => {
            let r = id(r)?;
            let ask: RenewRequest = read_json(req, MAX_BODY).await?.0;
            let grant = jobs::renew(hub, principal, &r, ask.lease_secs).await?;
            Ok(json(StatusCode::OK, &grant))
        }
        (Method::DELETE, ["v1", "reservations", r]) => {
            jobs::release(hub, principal, &id(r)?)?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        (Method::POST, ["v1", "jobs"]) => submit(req, hub, principal).await,
        (Method::GET, ["v1", "jobs", j]) => job(hub, principal, &id(j)?, &query).await,
        (Method::GET, ["v1", "jobs", j, "output"]) => output(hub, principal, &id(j)?, &query).await,
        (Method::POST, ["v1", "jobs", j, "cancel"]) => {
            let j = id(j)?;
            let ask: CancelRequest = read_json(req, MAX_BODY).await?.0;
            let view = jobs::cancel(hub, principal, &j, ask.mode).await?;
            Ok(json(StatusCode::ACCEPTED, &view))
        }
        (Method::POST, ["v1", "jobs", j, "settle"]) => {
            jobs::settle(hub, principal, &id(j)?).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        _ => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "no such endpoint",
        )),
    }
}

/// Read a JSON body of at most `limit` bytes, timed: the value, and its canonical JSON for
/// telling a retry from another request.
async fn read_json<T: serde::de::DeserializeOwned + serde::Serialize>(
    req: Request<Incoming>,
    limit: usize,
) -> Result<(T, Vec<u8>), ApiError> {
    let too_large = || {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::TooLarge,
            format!("the body is larger than {limit} bytes"),
        )
    };
    let declared = req
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    let body = match tokio::time::timeout(
        BODY_TIMEOUT,
        http_body_util::Limited::new(req.into_body(), limit).collect(),
    )
    .await
    {
        Ok(Ok(b)) => b.to_bytes(),
        Ok(Err(_)) => return Err(too_large()),
        Err(_) => {
            return Err(ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                ErrorCode::Invalid,
                "the body was too slow to arrive",
            ));
        }
    };
    let value: T = serde_json::from_slice(&body)
        .map_err(|e| ApiError::invalid(format!("the body does not parse: {e}")))?;
    let canonical = serde_json::to_vec(&value).map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
    Ok((value, canonical))
}

/// Refuse a placement that is malformed, or outside `principal`'s policy.
fn check_placement(placement: &Placement, principal: &ApiPrincipal) -> Result<(), ApiError> {
    if !valid_name(&placement.pool) {
        return Err(ApiError::invalid(format!(
            "{:?} is not a pool's name",
            placement.pool
        )));
    }
    if placement.labels.len() > MAX_LABELS || placement.labels.iter().any(|l| !valid_name(l)) {
        return Err(ApiError::invalid(format!(
            "a placement names at most {MAX_LABELS} labels, each a name"
        )));
    }
    let e = placement.envelope;
    if e.mem_mib == 0 || e.cpus == 0 {
        return Err(ApiError::invalid(
            "an envelope has at least 1 MiB of memory and 1 CPU",
        ));
    }
    if let Some(why) = principal.refuses(placement) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            why,
        ));
    }
    Ok(())
}

fn request_id(id: &str) -> Result<(), ApiError> {
    if vk_hub_proto::valid_id(id) {
        Ok(())
    } else {
        Err(ApiError::invalid(
            "request_id is 16 random bytes as lowercase hex",
        ))
    }
}

/// `wait`, or `wait_secs`, capped.
fn wait_for(secs: u32) -> Duration {
    Duration::from_secs(u64::from(secs.min(MAX_WAIT_SECS)))
}

/// `name`'s value in `query`, as a number.
fn query_number(query: &str, name: &str) -> Result<Option<u64>, ApiError> {
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            return v
                .parse()
                .map(Some)
                .map_err(|_| ApiError::invalid(format!("{name} is not a number")));
        }
    }
    Ok(None)
}

async fn capacity(
    req: Request<Incoming>,
    hub: &Hub,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    let (ask, _) = read_json::<CapacityRequest>(req, MAX_BODY).await?;
    check_placement(&ask.placement, principal)?;
    let deadline = Instant::now() + wait_for(ask.wait_secs);
    loop {
        let mut changed = hub.dispatch.subscribe();
        let mut node_changed = hub.subscribe();
        let answer = jobs::capacity(hub, &ask.placement).await?;
        if ask.after.is_none_or(|after| answer.revision > after) || Instant::now() >= deadline {
            return Ok(json(StatusCode::OK, &answer));
        }
        tokio::select! {
            _ = changed.changed() => {}
            _ = node_changed.changed() => {}
            () = tokio::time::sleep_until(deadline) => {}
        }
    }
}

async fn reserve(
    req: Request<Incoming>,
    hub: &Hub,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    let (ask, canonical) = read_json::<ReservationRequest>(req, MAX_BODY).await?;
    request_id(&ask.request_id)?;
    check_placement(&ask.placement, principal)?;
    let digest = vk_hub_proto::to_hex(&Sha256::digest(&canonical));
    let _serving = jobs::begin_request(hub, &format!("{}/{}", principal.id, ask.request_id))?;
    let (key, rid) = (principal.id.clone(), ask.request_id.clone());
    let db = hub.db.clone();
    let before = tokio::task::spawn_blocking(move || db.request(&key, &rid, crate::now_secs()))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    if let Some(before) = before {
        let grant = (before.digest == digest)
            .then(|| serde_json::from_value::<ReservationGrant>(before.answer).ok())
            .flatten();
        return match grant {
            Some(grant) => Ok(json(StatusCode::CREATED, &grant)),
            None => Err(conflict()),
        };
    }
    let grant = jobs::reserve(
        hub,
        principal,
        &ask.placement,
        ask.lease_secs,
        wait_for(ask.wait_secs),
    )
    .await?;
    // Unrecorded, a retry would reserve a second envelope: until the request is recorded,
    // this one goes back, also when the client hangs up and the handler is dropped.
    let unrecorded = Unrecorded {
        hub,
        principal,
        reservation: Some(&grant.reservation),
    };
    let row = RequestRow {
        at: crate::now_secs(),
        digest,
        answer: serde_json::to_value(&grant).map_err(|e| ApiError::from(anyhow::anyhow!(e)))?,
    };
    let actor = principal.actor();
    let event = format!(
        "{actor} reserved {} on node {} for {}s (reservation {})",
        crate::store::envelope_text(grant.envelope),
        grant.node,
        grant.lease_secs,
        grant.reservation
    );
    let (db, key, rid, node) = (
        hub.db.clone(),
        principal.id.clone(),
        ask.request_id.clone(),
        grant.node.clone(),
    );
    let recorded = tokio::task::spawn_blocking(move || {
        db.record_request(&key, &rid, &row, Some(&node), &actor, &event, row.at)
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))
    .and_then(|r| r);
    recorded?;
    unrecorded.disarm();
    Ok(json(StatusCode::CREATED, &grant))
}

/// Releases a granted reservation whose request was not recorded, when dropped armed.
struct Unrecorded<'a> {
    hub: &'a Hub,
    principal: &'a ApiPrincipal,
    reservation: Option<&'a str>,
}

impl Unrecorded<'_> {
    fn disarm(mut self) {
        self.reservation = None;
    }
}

impl Drop for Unrecorded<'_> {
    fn drop(&mut self) {
        if let Some(r) = self.reservation {
            let _ = jobs::release(self.hub, self.principal, r);
        }
    }
}

fn conflict() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        ErrorCode::Conflict,
        "this request_id was used before with another body",
    )
}

/// What a job is, for its record and the audit log.
fn title(spec: &JobSpec) -> String {
    match spec {
        JobSpec::GitlabCi(ci) => vk_hub_proto::display_safe(&format!(
            "GitLab job {} of {} ({})",
            ci.job.id, ci.job.project_path, ci.job.name
        )),
    }
}

async fn submit(
    req: Request<Incoming>,
    hub: &Hub,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    let (ask, canonical) = read_json::<JobSubmission>(req, MAX_JOB_BODY).await?;
    request_id(&ask.request_id)?;
    if ask
        .reservation
        .as_ref()
        .is_some_and(|r| !vk_hub_proto::valid_id(r))
    {
        return Err(ApiError::invalid("reservation is not an ID"));
    }
    check_placement(&ask.placement, principal)?;
    let spec_len = serde_json::to_vec(&ask.spec)
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))?
        .len();
    if spec_len > MAX_JOB_SPEC {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::TooLarge,
            format!("the spec is {spec_len} bytes, past {MAX_JOB_SPEC}"),
        ));
    }
    jobs::accepting(hub)?;
    let digest = vk_hub_proto::to_hex(&Sha256::digest(&canonical));
    let _serving = jobs::begin_request(hub, &format!("{}/{}", principal.id, ask.request_id))?;
    // Capped for a new job only: a request made before is answered with its job. No other
    // attempt of this request runs meanwhile, so it stays new until submitted.
    let (db, key, rid) = (hub.db.clone(), principal.id.clone(), ask.request_id.clone());
    let seen = tokio::task::spawn_blocking(move || db.request(&key, &rid, crate::now_secs()))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    if seen.is_none() {
        jobs::room_for_job(hub)?;
    }
    let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
    let row = JobRow {
        key: principal.id.clone(),
        key_name: principal.row.name.clone(),
        request_id: ask.request_id.clone(),
        placement: ask.placement.clone(),
        title: title(&ask.spec),
        job_url: match &ask.spec {
            JobSpec::GitlabCi(ci) => ci.job_url(),
        },
        created_at: crate::now_secs(),
        state: JobState::Queued,
        revision: 1,
        node: None,
        stage: None,
        cancel: None,
        result: None,
        output_len: 0,
        finished_at: None,
        settled_at: None,
    };
    let redacted = match &ask.spec {
        JobSpec::GitlabCi(ci) => JobSpec::GitlabCi(ci.redacted()),
    };
    let redacted = serde_json::to_vec(&redacted).map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
    let (db, job, stored, actor) = (hub.db.clone(), id.clone(), row.clone(), principal.actor());
    let submitted = tokio::task::spawn_blocking(move || {
        db.submit_job(&job, &stored, &digest, &redacted, &actor, stored.created_at)
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    match submitted {
        Submitted::New => {
            let place_within =
                Duration::from_secs(u64::from(ask.place_within_secs.min(MAX_PLACE_WITHIN_SECS)));
            let view = row.view(&id, 0);
            jobs::admit(hub, &id, row, ask.spec, ask.reservation, place_within);
            hub.touch();
            Ok(json(StatusCode::CREATED, &view))
        }
        Submitted::Again(id) => {
            let (view, _) = jobs::view(hub, principal, &id).await?;
            Ok(json(StatusCode::CREATED, &view))
        }
        Submitted::Conflict => Err(conflict()),
    }
}

async fn job(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
    query: &str,
) -> Result<Response<Body>, ApiError> {
    let after = query_number(query, "after")?;
    let wait = query_number(query, "wait")?.unwrap_or(0);
    let deadline = Instant::now() + wait_for(u32::try_from(wait).unwrap_or(u32::MAX));
    loop {
        let mut changed = hub.dispatch.subscribe();
        let (view, _) = jobs::view(hub, principal, id).await?;
        if after.is_none_or(|after| view.revision > after) || Instant::now() >= deadline {
            return Ok(json(StatusCode::OK, &view));
        }
        tokio::select! {
            _ = changed.changed() => {}
            () = tokio::time::sleep_until(deadline) => {}
        }
    }
}

async fn output(
    hub: &Hub,
    principal: &ApiPrincipal,
    id: &str,
    query: &str,
) -> Result<Response<Body>, ApiError> {
    let offset = query_number(query, "offset")?.unwrap_or(0);
    let wait = query_number(query, "wait")?.unwrap_or(0);
    let deadline = Instant::now() + wait_for(u32::try_from(wait).unwrap_or(u32::MAX));
    loop {
        let mut changed = hub.dispatch.subscribe();
        let (bytes, len, finished) =
            match jobs::output(hub, principal, id, offset, MAX_OUTPUT_READ).await {
                Ok(read) => read,
                Err(OutputError::Api(e)) => return Err(e),
                Err(OutputError::PastEnd(len)) => {
                    let mut resp = ApiError::new(
                        StatusCode::RANGE_NOT_SATISFIABLE,
                        ErrorCode::Invalid,
                        format!("offset {offset} is past the output's end, {len}"),
                    )
                    .response();
                    resp.headers_mut()
                        .insert(OUTPUT_LENGTH_HEADER, HeaderValue::from(len));
                    return Ok(resp);
                }
            };
        if !bytes.is_empty() || finished || Instant::now() >= deadline {
            let end = offset.saturating_add(bytes.len() as u64);
            let mut resp = Response::new(full(Bytes::from(bytes)));
            let h = resp.headers_mut();
            h.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            h.insert(OUTPUT_OFFSET_HEADER, HeaderValue::from(offset));
            h.insert(OUTPUT_LENGTH_HEADER, HeaderValue::from(len));
            if finished && end == len {
                h.insert(OUTPUT_COMPLETE_HEADER, HeaderValue::from_static("true"));
            }
            return Ok(resp);
        }
        tokio::select! {
            _ = changed.changed() => {}
            () = tokio::time::sleep_until(deadline) => {}
        }
    }
}

fn json<T: serde::Serialize>(status: StatusCode, value: &T) -> Response<Body> {
    // The protocol's own types, which always serialize.
    let body = serde_json::to_vec(value).unwrap_or_default();
    let mut resp = Response::new(full(body));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

fn empty(status: StatusCode) -> Response<Body> {
    let mut resp = Response::new(full(Bytes::new()));
    *resp.status_mut() = status;
    resp
}
