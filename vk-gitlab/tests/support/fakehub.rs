//! vk-hub's client API over HTTP (`vk-hub/src/client.rs`: paths,
//! statuses, error bodies, output headers), served from the in-memory `FakeDispatcher`, so
//! the real hub client is tested on the wire. A relay enrolls at `/v1/gitlab/enroll`, and
//! every request after must carry its signature, checked as the hub checks it; a request
//! without one is answered 401.

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{HeaderMap, Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use vk_gitlab::dispatch::{DispatchError, Dispatcher, ErrorKind, FakeDispatcher, Submission};
use vk_hub_proto::client::{
    CancelRequest, CapacityRequest, ClientError, ErrorCode, JobSubmission, RenewRequest,
    ReservationGrant, ReservationRequest,
};

/// The ID the fake hub gives the relay that enrolls.
pub const TEST_RELAY_ID: &str = "0123456789abcdef0123456789abcdef";

/// An injected failure: the next matching requests are answered this way.
#[derive(Clone, Debug)]
pub struct Fault {
    pub path_prefix: String,
    pub status: u16,
    pub code: ErrorCode,
    pub retry_after_secs: Option<u32>,
}

/// A request as the fake hub received it.
#[derive(Clone, Debug)]
pub struct HubRequest {
    pub method: String,
    pub path: String,
    pub headers: HeaderMap,
}

pub struct FakeHub {
    pub url: String,
    pub requests: Arc<Mutex<Vec<HubRequest>>>,
    /// The enrolled relay's public key.
    relay_key: Arc<Mutex<Option<Vec<u8>>>>,
    faults: Arc<Mutex<VecDeque<Fault>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeHub {
    fn drop(&mut self) {
        self.task.abort();
    }
}

type Resp = Response<Full<Bytes>>;

fn json<T: serde::Serialize>(status: u16, value: &T) -> Resp {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(value).unwrap())))
        .unwrap()
}

fn empty(status: u16) -> Resp {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn error(status: u16, code: ErrorCode, msg: &str, retry_after_secs: Option<u32>) -> Resp {
    json(
        status,
        &ClientError {
            error: msg.to_owned(),
            code,
            retry_after_secs,
        },
    )
}

fn dispatch_error(e: DispatchError) -> Resp {
    let retry = e
        .retry_after
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(1));
    let (status, code) = match e.kind {
        ErrorKind::NotFound => (404, ErrorCode::NotFound),
        ErrorKind::Conflict => (409, ErrorCode::Conflict),
        ErrorKind::ReservationGone => (410, ErrorCode::ReservationGone),
        ErrorKind::TooLarge => (413, ErrorCode::TooLarge),
        ErrorKind::NoCapacity => (503, ErrorCode::NoCapacity),
        ErrorKind::Unavailable => (503, ErrorCode::Unavailable),
        ErrorKind::Forbidden => (403, ErrorCode::Forbidden),
        ErrorKind::OutputRange { length } => {
            let mut r = error(416, ErrorCode::Invalid, &e.message, None);
            r.headers_mut()
                .insert("vk-output-length", length.to_string().parse().unwrap());
            return r;
        }
        _ => (500, ErrorCode::Internal),
    };
    error(status, code, &e.message, retry)
}

fn query(q: &str, name: &str) -> Option<u64> {
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == name)
        .and_then(|(_, v)| v.parse().ok())
}

/// Whether the request is signed by the relay whose key is `key`, as `vk-hub/src/client.rs`
/// checks it (over plain TCP: no TLS exporter).
fn signed(
    key: &[u8],
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> bool {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let (Some(relay), Some(at), Some(signature)) = (
        header("vk-relay"),
        header("vk-time").and_then(|t| t.parse::<u64>().ok()),
        header("vk-signature")
            .and_then(vk_hub_proto::from_hex_lower::<{ vk_hub_proto::SIGNATURE_LEN }>),
    ) else {
        return false;
    };
    if relay != TEST_RELAY_ID || headers.contains_key("authorization") {
        return false;
    }
    let digest: [u8; 32] = ring::digest::digest(&ring::digest::SHA256, body)
        .as_ref()
        .try_into()
        .unwrap();
    let message = vk_hub_proto::client::client_request_message(
        relay,
        method,
        path_and_query,
        &digest,
        at,
        vk_hub_proto::Channel::Plaintext,
    );
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(&message, &signature)
        .is_ok()
}

async fn serve(
    hub: FakeDispatcher,
    method: hyper::Method,
    path: String,
    q: String,
    body: Bytes,
) -> Resp {
    let segs: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let wait = Duration::from_secs(query(&q, "wait").unwrap_or(0).min(60));
    macro_rules! parse {
        ($t:ty) => {
            match serde_json::from_slice::<$t>(&body) {
                Ok(v) => v,
                Err(e) => return error(400, ErrorCode::Invalid, &e.to_string(), None),
            }
        };
    }
    match (method.as_str(), segs.as_slice()) {
        ("POST", ["v1", "capacity"]) => {
            let ask = parse!(CapacityRequest);
            let wait = Duration::from_secs(u64::from(ask.wait_secs.min(60)));
            match hub.capacity(&ask.placement, ask.after, wait).await {
                Ok(c) => json(200, &c),
                Err(e) => dispatch_error(e),
            }
        }
        ("POST", ["v1", "reservations"]) => {
            let ask = parse!(ReservationRequest);
            let lease = Duration::from_secs(u64::from(ask.lease_secs));
            match hub
                .reserve(&ask.request_id, &ask.placement, lease, wait)
                .await
            {
                Ok(r) => json(
                    201,
                    &ReservationGrant {
                        reservation: r.id,
                        node: r.node,
                        envelope: r.envelope,
                        lease_secs: u32::try_from(r.lease.as_secs()).unwrap(),
                    },
                ),
                Err(e) => dispatch_error(e),
            }
        }
        ("POST", ["v1", "reservations", id, "renew"]) => {
            let ask = parse!(RenewRequest);
            match hub
                .renew(id, Duration::from_secs(u64::from(ask.lease_secs)))
                .await
            {
                Ok(lease) => json(
                    200,
                    &ReservationGrant {
                        reservation: (*id).to_owned(),
                        node: "node-1".to_owned(),
                        envelope: Default::default(),
                        lease_secs: u32::try_from(lease.as_secs()).unwrap(),
                    },
                ),
                Err(e) => dispatch_error(e),
            }
        }
        ("DELETE", ["v1", "reservations", id]) => match hub.release(id).await {
            Ok(()) => empty(204),
            Err(e) => dispatch_error(e),
        },
        ("POST", ["v1", "jobs"]) => {
            let ask = parse!(JobSubmission);
            let vk_hub_proto::job::JobSpec::GitlabCi(ci) = &ask.spec;
            let sub = Submission {
                request_id: ask.request_id,
                placement: ask.placement,
                reservation: ask.reservation,
                place_within: Duration::from_secs(u64::from(ask.place_within_secs)),
                gitlab_job: i64::try_from(ci.job.id).unwrap(),
                spec: ask.spec,
            };
            match hub.submit(sub).await {
                Ok(v) => json(201, &v),
                Err(e) => dispatch_error(e),
            }
        }
        ("GET", ["v1", "jobs", id]) => match hub.job(id, query(&q, "after"), wait).await {
            Ok(v) => json(200, &v),
            Err(e) => dispatch_error(e),
        },
        ("GET", ["v1", "jobs", id, "output"]) => {
            match hub.output(id, query(&q, "offset").unwrap_or(0), wait).await {
                Ok(c) => {
                    let mut r = Response::builder()
                        .status(200)
                        .header("content-type", "application/octet-stream")
                        .header("vk-output-offset", c.offset.to_string())
                        .header("vk-output-length", c.length.to_string());
                    if c.complete {
                        r = r.header("vk-output-complete", "true");
                    }
                    r.body(Full::new(c.data)).unwrap()
                }
                Err(e) => dispatch_error(e),
            }
        }
        ("POST", ["v1", "jobs", id, "cancel"]) => {
            let ask = parse!(CancelRequest);
            match hub.cancel(id, ask.mode).await {
                Ok(v) => json(202, &v),
                Err(e) => dispatch_error(e),
            }
        }
        ("POST", ["v1", "jobs", id, "settle"]) => match hub.settle(id).await {
            Ok(()) => empty(204),
            Err(e) => dispatch_error(e),
        },
        _ => error(404, ErrorCode::NotFound, "no such endpoint", None),
    }
}

impl FakeHub {
    pub async fn start(hub: FakeDispatcher) -> FakeHub {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let relay_key = Arc::new(Mutex::new(None));
        let faults: Arc<Mutex<VecDeque<Fault>>> = Arc::new(Mutex::new(VecDeque::new()));
        let state = (
            Arc::clone(&requests),
            Arc::clone(&relay_key),
            Arc::clone(&faults),
        );
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let (hub, state) = (hub.clone(), state.clone());
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let (hub, (recs, key, flts)) = (hub.clone(), state.clone());
                        async move {
                            let (parts, body) = req.into_parts();
                            let path = parts.uri.path().to_owned();
                            let q = parts.uri.query().unwrap_or("").to_owned();
                            let body = body.collect().await.unwrap().to_bytes();
                            recs.lock().unwrap().push(HubRequest {
                                method: parts.method.to_string(),
                                path: path.clone(),
                                headers: parts.headers.clone(),
                            });
                            if parts.method == "POST" && path == "/v1/gitlab/enroll" {
                                let ask: vk_hub_proto::EnrollRequest =
                                    serde_json::from_slice(&body).unwrap();
                                *key.lock().unwrap() =
                                    Some(vk_hub_proto::from_hex(&ask.public_key).unwrap());
                                return Ok::<_, Infallible>(json(
                                    200,
                                    &vk_hub_proto::gitlab::EnrollResponse {
                                        relay_id: TEST_RELAY_ID.to_owned(),
                                    },
                                ));
                            }
                            let path_and_query =
                                parts.uri.path_and_query().map_or("", |p| p.as_str());
                            let known = key.lock().unwrap().clone();
                            if !known.is_some_and(|k| {
                                signed(
                                    &k,
                                    &parts.headers,
                                    parts.method.as_str(),
                                    path_and_query,
                                    &body,
                                )
                            }) {
                                return Ok(error(
                                    401,
                                    ErrorCode::Unauthorized,
                                    "a request signed by an enrolled relay is required",
                                    None,
                                ));
                            }
                            let fault = {
                                let mut f = flts.lock().unwrap();
                                match f.front() {
                                    Some(fault) if path.starts_with(&fault.path_prefix) => {
                                        f.pop_front()
                                    }
                                    _ => None,
                                }
                            };
                            if let Some(f) = fault {
                                let mut r = error(f.status, f.code, "injected", f.retry_after_secs);
                                if let Some(s) = f.retry_after_secs {
                                    r.headers_mut()
                                        .insert("retry-after", s.to_string().parse().unwrap());
                                }
                                return Ok(r);
                            }
                            Ok(serve(hub, parts.method, path, q, body).await)
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        FakeHub {
            url: format!("http://{addr}"),
            requests,
            relay_key,
            faults,
            task,
        }
    }

    /// Answers the next `n` requests under `path_prefix` with `status` and `code`.
    pub fn fail_next(
        &self,
        n: usize,
        path_prefix: &str,
        status: u16,
        code: ErrorCode,
        retry_after_secs: Option<u32>,
    ) {
        let mut f = self.faults.lock().unwrap();
        for _ in 0..n {
            f.push_back(Fault {
                path_prefix: path_prefix.to_owned(),
                status,
                code,
                retry_after_secs,
            });
        }
    }

    /// Drops the failures not yet answered.
    pub fn clear_faults(&self) {
        self.faults.lock().unwrap().clear();
    }

    pub fn requests_to(&self, prefix: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.path.starts_with(prefix))
            .count()
    }
}
