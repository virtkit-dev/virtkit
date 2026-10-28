//! The client API on the node listener (`vk_hub_proto::client`): an enrolled GitLab relay
//! (`vk-gitlab`) signing each request with its key, or a client holding an API key in
//! `authorization: Bearer`, requests and reserves capacity, submits jobs and follows them. Only
//! a relay submits GitLab jobs, each through the approval gate ([`Db::gate_job`]). This module
//! handles HTTP paths, bodies, long polls, idempotent creates and error codes; [`crate::jobs`]
//! handles the work.
//!
//! A request's key, or the relay it names and its signed time, is checked before its body is
//! read; a relay's signature, over the body's digest, once it is, before the connection counts
//! among the clients'. The body is read capped and timed: [`MAX_BODY`], or [`MAX_JOB_BODY`] for a job. A long poll holds its request for at most
//! [`MAX_WAIT_SECS`].
//!
//! [`Db::gate_job`]: crate::store::Db::gate_job

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
    AUTHORIZATION, CAPACITY_PATH, CLIENTS_PATH, CancelRequest, CapacityRequest, ClientError,
    ClientHello, ErrorCode, INSTANCE_HEADER, JOBS_PATH, JobState, JobSubmission,
    MAX_CLIENT_RUNNER_LABELS, MAX_CLIENT_RUNNERS, MAX_INSTANCE_LEN, MAX_OUTPUT_READ, MAX_WAIT_SECS,
    OUTPUT_COMPLETE_HEADER, OUTPUT_LENGTH_HEADER, OUTPUT_OFFSET_HEADER, Placement, RELAY_HEADER,
    RESERVATIONS_PATH, RenewRequest, ReservationGrant, ReservationRequest, valid_instance,
};
use vk_hub_proto::job::{JobSpec, MAX_JOB_SPEC};
use vk_hub_proto::{PUBLIC_KEY_LEN, SIGNATURE_LEN, from_hex_lower};

use crate::jobs::{self, OutputError};
use crate::server::{Body, Exported, Hub, full};
use crate::store::{
    ApiPrincipal, Gate, GateJob, JobRow, PrincipalKind, Refusal, RequestRow, Scope, Submitted,
    valid_name,
};

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
        || path == CLIENTS_PATH
}

/// The client instance `headers` name, if well-formed.
fn instance(headers: &HeaderMap) -> Option<String> {
    headers
        .get(INSTANCE_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| valid_instance(v))
        .map(str::to_string)
}

/// Who a request says it comes from, checked as far as its headers go.
pub enum Claimed {
    Key(ApiPrincipal),
    /// A relay, its signature still to check against the body.
    Relay {
        principal: ApiPrincipal,
        public_key: [u8; PUBLIC_KEY_LEN],
        at: u64,
        signature: [u8; SIGNATURE_LEN],
    },
}

fn unauthorized(message: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, message)
}

/// Who the request comes from: an enrolled relay naming itself in [`RELAY_HEADER`], its
/// signed time within [`DOWNLOAD_SKEW_SECS`](vk_hub_proto::DOWNLOAD_SKEW_SECS) of the hub's
/// clock, or else the key it carries, if the hub knows it and it still works, with the
/// instance the request names.
pub async fn authenticate(headers: &HeaderMap, hub: &Hub) -> Result<Claimed, ApiError> {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    if let Some(relay) = header(RELAY_HEADER) {
        let signed = || {
            unauthorized(format!(
                "a relay's request carries its ID, {} and {}",
                vk_hub_proto::TIME_HEADER,
                vk_hub_proto::SIGNATURE_HEADER
            ))
        };
        if !vk_hub_proto::valid_id(relay) {
            return Err(signed());
        }
        let at = header(vk_hub_proto::TIME_HEADER)
            .and_then(|t| t.parse::<u64>().ok())
            .ok_or_else(signed)?;
        let signature = header(vk_hub_proto::SIGNATURE_HEADER)
            .and_then(from_hex_lower::<SIGNATURE_LEN>)
            .ok_or_else(signed)?;
        if crate::now_secs().abs_diff(at) > vk_hub_proto::DOWNLOAD_SKEW_SECS {
            return Err(unauthorized(
                "the signed time is too far from the hub's clock",
            ));
        }
        let (db, id) = (hub.db.clone(), relay.to_string());
        let row = tokio::task::spawn_blocking(move || db.relay(&id))
            .await
            .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??
            .ok_or_else(|| unauthorized("no such relay: it was removed, or never enrolled"))?;
        let public_key = from_hex_lower::<PUBLIC_KEY_LEN>(&row.public_key).ok_or_else(|| {
            ApiError::from(anyhow::anyhow!("relay {relay} has a corrupt pinned key"))
        })?;
        return Ok(Claimed::Relay {
            principal: ApiPrincipal {
                id: relay.to_string(),
                name: row.hostname,
                instance: None,
                kind: PrincipalKind::Relay,
            },
            public_key,
            at,
            signature,
        });
    }
    let key = header(AUTHORIZATION)
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .ok_or_else(|| {
            unauthorized(
                "an API key the hub knows is required, as authorization: Bearer, or a relay's \
                 signature",
            )
        })?
        .to_string();
    let db = hub.db.clone();
    let found = tokio::task::spawn_blocking(move || db.api_key(&key, crate::now_secs()))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    let principal = found.ok_or_else(|| {
        unauthorized("an API key the hub knows is required, as authorization: Bearer")
    })?;
    Ok(Claimed::Key(ApiPrincipal {
        instance: instance(headers),
        ..principal
    }))
}

/// A request authenticated, its body read.
pub struct Admitted {
    parts: hyper::http::request::Parts,
    body: Bytes,
    pub principal: ApiPrincipal,
}

/// Read the body of a request whose headers [`authenticate`]d it, and check a relay's
/// signature over it: until then, the request has proved nothing.
pub async fn admit(
    req: Request<Incoming>,
    claimed: Claimed,
    exported: Exported,
) -> Result<Admitted, ApiError> {
    let (parts, body) = req.into_parts();
    let limit = if parts.method == Method::POST && parts.uri.path() == JOBS_PATH {
        MAX_JOB_BODY
    } else {
        MAX_BODY
    };
    let body = read_body(&parts.headers, body, limit).await?;
    let principal = match claimed {
        Claimed::Key(p) => p,
        Claimed::Relay {
            principal,
            public_key,
            at,
            signature,
        } => {
            let channel = match &exported {
                Some(exported) => vk_hub_proto::Channel::Tls(exported),
                None => vk_hub_proto::Channel::Plaintext,
            };
            let digest: [u8; vk_hub_proto::SHA256_LEN] = Sha256::digest(&body).into();
            let message = vk_hub_proto::client::client_request_message(
                &principal.id,
                parts.method.as_str(),
                parts
                    .uri
                    .path_and_query()
                    .map_or(parts.uri.path(), |p| p.as_str()),
                &digest,
                at,
                channel,
            );
            if !crate::verify(&public_key, &message, &signature) {
                return Err(unauthorized(
                    "the signature does not match the relay's pinned key; a proxy terminating \
                     TLS in front of the hub breaks its binding to the connection: pass TLS \
                     through",
                ));
            }
            principal
        }
    };
    Ok(Admitted {
        parts,
        body,
        principal,
    })
}

/// Serve an [`admit`]ted request.
pub async fn serve(admitted: Admitted, hub: &Arc<Hub>) -> Response<Body> {
    let Admitted {
        parts,
        body,
        principal,
    } = admitted;
    route(&parts, body, hub, &principal)
        .await
        .unwrap_or_else(|e| e.response())
}

async fn route(
    parts: &hyper::http::request::Parts,
    body: Bytes,
    hub: &Arc<Hub>,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    let path = parts.uri.path();
    let query = parts.uri.query().unwrap_or_default();
    let method = parts.method.clone();
    let wanted = if path == CAPACITY_PATH || path == CLIENTS_PATH {
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
        (Method::POST, ["v1", "capacity"]) => capacity(&body, hub, principal).await,
        (Method::POST, ["v1", "reservations"]) => reserve(&body, hub, principal).await,
        (Method::POST, ["v1", "reservations", r, "renew"]) => {
            let r = id(r)?;
            let ask: RenewRequest = parse_json(&body)?.0;
            let grant = jobs::renew(hub, principal, &r, ask.lease_secs).await?;
            Ok(json(StatusCode::OK, &grant))
        }
        (Method::DELETE, ["v1", "reservations", r]) => {
            jobs::release(hub, principal, &id(r)?)?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        (Method::POST, ["v1", "jobs"]) => submit(&body, hub, principal).await,
        (Method::GET, ["v1", "jobs", j]) => job(hub, principal, &id(j)?, query).await,
        (Method::GET, ["v1", "jobs", j, "output"]) => output(hub, principal, &id(j)?, query).await,
        (Method::POST, ["v1", "jobs", j, "cancel"]) => {
            let j = id(j)?;
            let ask: CancelRequest = parse_json(&body)?.0;
            let view = jobs::cancel(hub, principal, &j, ask.mode).await?;
            Ok(json(StatusCode::ACCEPTED, &view))
        }
        (Method::POST, ["v1", "jobs", j, "settle"]) => {
            jobs::settle(hub, principal, &id(j)?).await?;
            Ok(empty(StatusCode::NO_CONTENT))
        }
        (Method::POST, ["v1", "clients"]) => hello(&body, hub, principal).await,
        _ => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            ErrorCode::NotFound,
            "no such endpoint",
        )),
    }
}

/// Read a body of at most `limit` bytes, timed.
async fn read_body(headers: &HeaderMap, body: Incoming, limit: usize) -> Result<Bytes, ApiError> {
    let too_large = || {
        ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::TooLarge,
            format!("the body is larger than {limit} bytes"),
        )
    };
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|n| n > limit as u64) {
        return Err(too_large());
    }
    match tokio::time::timeout(
        BODY_TIMEOUT,
        http_body_util::Limited::new(body, limit).collect(),
    )
    .await
    {
        Ok(Ok(b)) => Ok(b.to_bytes()),
        Ok(Err(_)) => Err(too_large()),
        Err(_) => Err(ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            ErrorCode::Invalid,
            "the body was too slow to arrive",
        )),
    }
}

/// A JSON body: the value, and its canonical JSON for telling a retry from another request.
fn parse_json<T: serde::de::DeserializeOwned + serde::Serialize>(
    body: &[u8],
) -> Result<(T, Vec<u8>), ApiError> {
    let value: T = serde_json::from_slice(body)
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

/// Who a relay's request schedules for: the GitLab runner it names, as its relay's inventory
/// verified it, and the tenant the capacity policy maps that runner to.
#[derive(Clone)]
struct SchedulingIdentity {
    tenant: String,
    class: crate::policy::Class,
    gitlab: String,
    runner_id: u64,
    /// The policy used to resolve this identity and check its jobs.
    policy: Arc<crate::policy::Policy>,
}

fn identity_refused(message: &str) -> ApiError {
    ApiError::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden, message)
}

/// Log each identity refusal once per relay to avoid repeating it every check interval.
/// Messages can contain runner names; clear the remembered refusals at the bound.
fn say_refused_once(relay: &str, error: &ApiError) {
    const MAX_SAID: usize = 1024;
    static SAID: std::sync::Mutex<std::collections::BTreeSet<(String, String)>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());
    let mut said = SAID.lock().unwrap_or_else(|p| p.into_inner());
    if said.len() >= MAX_SAID {
        said.clear();
    }
    if said.insert((relay.to_owned(), error.message.clone())) {
        eprintln!("vk-hub: relay {relay}: {}", error.message);
    }
}

/// The identity a request schedules under: `None` for an API key, which names no runner; for
/// a relay, the runner it names, refused unless that runner is in its inventory once,
/// verified with a GitLab ID, of the request's placement, and mapped to a tenant.
async fn resolve_identity(
    hub: &Hub,
    principal: &ApiPrincipal,
    runner: Option<&str>,
    placement: &Placement,
) -> Result<Option<SchedulingIdentity>, ApiError> {
    if !principal.is_relay() {
        return if runner.is_some() {
            Err(identity_refused("an API key cannot name a relay runner"))
        } else {
            Ok(None)
        };
    }
    let (db, id, runner, placement) = (
        hub.db.clone(),
        principal.id.clone(),
        runner.map(str::to_owned),
        placement.clone(),
    );
    let relay = id.clone();
    let resolved = tokio::task::spawn_blocking(move || {
        let runner = runner.ok_or_else(|| {
            identity_refused("a relay must name its runner: upgrade vk-gitlab on the relay")
        })?;
        let (row, status) = db
            .relay_with_status(&id)?
            .ok_or_else(|| identity_refused("the relay is no longer enrolled"))?;
        let gitlab = status
            .filter(|s| s.state.approved())
            .and_then(|s| s.name)
            .ok_or_else(|| identity_refused("the relay's GitLab server is not approved"))?;
        let inventory = row
            .inventory
            .ok_or_else(|| identity_refused("the relay has no inventory"))?;
        let mut matching = inventory.runners.iter().filter(|r| r.name == runner);
        let found = matching.next().ok_or_else(|| {
            identity_refused(&format!(
                "runner {runner:?} is absent from the relay's inventory"
            ))
        })?;
        if matching.next().is_some() {
            return Err(identity_refused(&format!(
                "runner {runner:?} appears more than once in the relay's inventory"
            )));
        }
        if !found.verified {
            return Err(identity_refused(&format!(
                "runner {runner:?} is not verified with GitLab"
            )));
        }
        if found.placement != placement {
            return Err(identity_refused(&format!(
                "runner {runner:?}'s placement differs from the request's"
            )));
        }
        let runner_id = found.runner_id.filter(|id| *id != 0).ok_or_else(|| {
            identity_refused(&format!("runner {runner:?} has no GitLab runner ID"))
        })?;
        let policy = db.capacity_policy()?;
        let mapping = policy
            .runners
            .iter()
            .find(|r| r.gitlab == gitlab && r.runner_id == runner_id)
            .ok_or_else(|| {
                identity_refused(&format!(
                    "runner {gitlab}/{runner_id} is mapped to no capacity tenant: add it to \
                     the capacity policy"
                ))
            })?;
        let (tenant, class) = (mapping.tenant.clone(), mapping.class);
        Ok(Some(SchedulingIdentity {
            tenant,
            class,
            gitlab,
            runner_id,
            policy: Arc::new(policy),
        }))
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!(e)))?;
    if let Err(e) = &resolved
        && e.status == StatusCode::FORBIDDEN
    {
        say_refused_once(&relay, e);
    }
    resolved
}

/// Check that `spec` belongs to `identity`'s runner and a project listed for its tenant.
/// Production runners also require a pipeline of one of the project's production branches.
fn check_job_identity(identity: &SchedulingIdentity, spec: &JobSpec) -> Result<(), ApiError> {
    let JobSpec::GitlabCi(ci) = spec;
    if ci.job.project_id == 0 {
        return Err(ApiError::invalid("job project ID is missing"));
    }
    if identity.runner_id != ci.job.runner_id {
        return Err(identity_refused(
            "job runner does not match the relay runner",
        ));
    }
    let project = identity
        .policy
        .tenants
        .get(&identity.tenant)
        .and_then(|t| {
            t.projects
                .iter()
                .find(|p| p.gitlab == identity.gitlab && p.id == ci.job.project_id)
        })
        .ok_or_else(|| {
            identity_refused(&format!(
                "project {}/{} is not one of tenant {:?}'s projects",
                identity.gitlab, ci.job.project_id, identity.tenant
            ))
        })?;
    if identity.class == crate::policy::Class::Production
        && !crate::policy::branch_name(&ci.sources).is_some_and(|branch| {
            project
                .production_branches
                .iter()
                .any(|p| crate::subject::glob_match(p, branch))
        })
    {
        return Err(identity_refused(
            "job is not an approved production branch pipeline",
        ));
    }
    Ok(())
}

async fn capacity(
    body: &[u8],
    hub: &Hub,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    let (ask, _) = parse_json::<CapacityRequest>(body)?;
    check_placement(&ask.placement, principal)?;
    resolve_identity(hub, principal, ask.runner.as_deref(), &ask.placement).await?;
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

async fn hello(
    body: &[u8],
    hub: &Hub,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    if principal.is_relay() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            "a relay says what it is in its session, not in a hello",
        ));
    }
    let (hello, _) = parse_json::<ClientHello>(body)?;
    if !valid_instance(&hello.instance) {
        return Err(ApiError::invalid(format!(
            "instance is 1 to {MAX_INSTANCE_LEN} letters, digits, '.', '_' or '-', starting \
             with a letter or digit"
        )));
    }
    if principal
        .instance
        .as_ref()
        .is_some_and(|i| *i != hello.instance)
    {
        return Err(ApiError::invalid(format!(
            "the hello's instance is not the one {INSTANCE_HEADER} names"
        )));
    }
    if hello.runners.len() > MAX_CLIENT_RUNNERS
        || hello
            .runners
            .iter()
            .any(|r| r.labels.len() > MAX_CLIENT_RUNNER_LABELS)
    {
        return Err(ApiError::invalid(format!(
            "a hello lists at most {MAX_CLIENT_RUNNERS} runners, each with at most \
             {MAX_CLIENT_RUNNER_LABELS} labels"
        )));
    }
    crate::clients::hello(hub, principal, hello).await?;
    Ok(empty(StatusCode::NO_CONTENT))
}

async fn reserve(
    body: &[u8],
    hub: &Hub,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    let (ask, canonical) = parse_json::<ReservationRequest>(body)?;
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
    resolve_identity(hub, principal, ask.runner.as_deref(), &ask.placement).await?;
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
    let (db, key, rid) = (hub.db.clone(), principal.id.clone(), ask.request_id.clone());
    let recorded = tokio::task::spawn_blocking(move || db.record_request(&key, &rid, &row))
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

/// The commit `sha` names, as lowercase hex of at most 64 characters (a SHA-256), or `None`.
/// Restricted to hex for display in a tooltip.
pub(crate) fn commit(sha: &str) -> Option<String> {
    Some(sha.to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
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
    body: &[u8],
    hub: &Hub,
    principal: &ApiPrincipal,
) -> Result<Response<Body>, ApiError> {
    let (ask, canonical) = parse_json::<JobSubmission>(body)?;
    request_id(&ask.request_id)?;
    if !principal.is_relay() {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            ErrorCode::Forbidden,
            "only an enrolled relay submits GitLab jobs (vk-gitlab join), not an API key",
        ));
    }
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
    // Gated and capped for a new job only: a request made before is answered with what it
    // came to, so a relay recovering an accepted job is not refused by a later rejection. No
    // other attempt of this request runs meanwhile, so it stays new until submitted.
    // One time for the lookup and the record: a request seen is still seen when its job is.
    let now = crate::now_secs();
    let (db, key, rid) = (hub.db.clone(), principal.id.clone(), ask.request_id.clone());
    let seen = tokio::task::spawn_blocking(move || db.request(&key, &rid, now))
        .await
        .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    let gitlab = match &seen {
        Some(before) => match before.refusal() {
            Some(_) if before.digest != digest => return Err(conflict()),
            Some(refusal) => return Err(refused(refusal)),
            None => {
                let (db, relay) = (hub.db.clone(), principal.id.clone());
                tokio::task::spawn_blocking(move || db.relay_gitlab(&relay))
                    .await
                    .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??
            }
        },
        None => {
            let identity = resolve_identity(hub, principal, ask.runner.as_deref(), &ask.placement)
                .await?
                .ok_or_else(|| identity_refused("job has no relay runner"))?;
            check_job_identity(&identity, &ask.spec)?;
            let gitlab = gate(hub, principal, &ask, &digest, now).await?;
            jobs::room_for_job(hub)?;
            gitlab
        }
    };
    let id = crate::random_hex(vk_hub_proto::ID_BYTES)?;
    let row = JobRow {
        key: principal.id.clone(),
        key_name: principal.name.clone(),
        instance: principal.instance.clone(),
        request_id: ask.request_id.clone(),
        scheduling: None,
        admission: None,
        placement: ask.placement.clone(),
        title: title(&ask.spec),
        job_url: match &ask.spec {
            JobSpec::GitlabCi(ci) => ci.job_url(),
        },
        project: match &ask.spec {
            JobSpec::GitlabCi(ci) => Some(vk_hub_proto::display_safe(&ci.job.project_path)),
        },
        name: match &ask.spec {
            JobSpec::GitlabCi(ci) => Some(vk_hub_proto::display_safe(&ci.job.name)),
        },
        git_ref: match &ask.spec {
            JobSpec::GitlabCi(ci) => {
                Some(vk_hub_proto::display_safe(&ci.sources.git_ref)).filter(|r| !r.is_empty())
            }
        },
        pipeline: match &ask.spec {
            JobSpec::GitlabCi(ci) => Some(ci.job.pipeline_id).filter(|&p| p > 0),
        },
        commit: match &ask.spec {
            JobSpec::GitlabCi(ci) => commit(&ci.sources.sha),
        },
        created_at: now,
        state: JobState::Queued,
        revision: 1,
        node: None,
        stage: None,
        cancel: None,
        result: None,
        egress: None,
        output_len: 0,
        started_at: None,
        finished_at: None,
        settled_at: None,
        expired_at: None,
        activity: None,
        prepared_at: None,
        guest: None,
        registry_access: None,
        gitlab,
        project_id: match &ask.spec {
            JobSpec::GitlabCi(ci) => Some(ci.job.project_id).filter(|&p| p > 0),
        },
        protected: match &ask.spec {
            JobSpec::GitlabCi(ci) => ci.sources.protected,
        },
        egress_rules: None,
        egress_caps: None,
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
            jobs::admit(
                hub,
                &id,
                row,
                ask.spec,
                ask.reservation,
                place_within,
                Some(principal.id.clone()),
            );
            hub.touch();
            Ok(json(StatusCode::CREATED, &view))
        }
        Submitted::Again(id) => match jobs::view(hub, principal, &id).await {
            Ok((view, _)) => Ok(json(StatusCode::CREATED, &view)),
            // The request's answer outlives the job's record.
            Err(e) if e.status == StatusCode::NOT_FOUND => Err(ApiError::new(
                StatusCode::GONE,
                ErrorCode::NotFound,
                format!("job {id} was dropped from the history"),
            )),
            Err(e) => Err(e),
        },
        Submitted::Conflict => Err(conflict()),
        Submitted::AdmissionTaken => Err(ApiError::new(
            StatusCode::CONFLICT,
            ErrorCode::Conflict,
            "this admission was already used by another job",
        )),
    }
}

/// Pass `ask`, a new job of relay `principal` with a body hashing to `digest`, through the
/// approval gate at `now`: the name of its GitLab instance, or the refusal. `None` when another
/// attempt of the request was answered meanwhile, which recording the job then finds.
async fn gate(
    hub: &Hub,
    principal: &ApiPrincipal,
    ask: &JobSubmission,
    digest: &str,
    now: u64,
) -> Result<Option<String>, ApiError> {
    let JobSpec::GitlabCi(ci) = &ask.spec;
    let (db, relay, ci, rid, digest) = (
        hub.db.clone(),
        principal.id.clone(),
        ci.clone(),
        ask.request_id.clone(),
        digest.to_string(),
    );
    let gate = tokio::task::spawn_blocking(move || {
        let url = ci.job_url();
        let job = GateJob {
            server_url: &ci.server_url,
            project_id: ci.job.project_id,
            project_path: &ci.job.project_path,
            job_id: ci.job.id,
            job_url: url.as_deref(),
        };
        db.gate_job(&relay, &job, (&rid, &digest), now)
    })
    .await
    .map_err(|e| ApiError::from(anyhow::anyhow!(e)))??;
    match gate {
        Gate::Pass(gitlab) => Ok(Some(gitlab)),
        Gate::Seen => Ok(None),
        Gate::Refused(refusal) => {
            if matches!(
                refusal.code,
                ErrorCode::ApprovalPending | ErrorCode::ProjectRejected
            ) {
                hub.touch();
                hub.clients_changed();
            }
            Err(refused(refusal))
        }
    }
}

/// The approval gate's refusal as the client API answers it.
fn refused(refusal: Refusal) -> ApiError {
    let status = match refusal.code {
        ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
        ErrorCode::Invalid => StatusCode::BAD_REQUEST,
        ErrorCode::Conflict => StatusCode::CONFLICT,
        _ => StatusCode::FORBIDDEN,
    };
    ApiError::new(status, refusal.code, refusal.error)
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
