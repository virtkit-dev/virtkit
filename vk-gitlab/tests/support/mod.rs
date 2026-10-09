//! A fake GitLab: an in-process HTTP server answering from a handler or a script of
//! expected requests, and recording every request it receives.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use vk_gitlab::api::{ClientOptions, GitLabClient, Info, RetryPolicy};
use vk_gitlab::secret::Secret;

/// A request as the fake received it.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: hyper::HeaderMap,
    pub body: Bytes,
}

impl Recorded {
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }

    /// A query parameter, `""` when absent.
    pub fn query_param(&self, name: &str) -> String {
        self.query
            .split('&')
            .filter_map(|kv| kv.split_once('='))
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.to_owned())
            .unwrap_or_default()
    }
}

/// The fake's answer to a request.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    pub delay: Option<Duration>,
}

impl Reply {
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
            delay: None,
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }

    pub fn json(self, body: &str) -> Self {
        self.header("Content-Type", "application/json")
            .body(body.to_owned())
    }

    /// Answers after `d`, as a long poll does.
    pub fn after(mut self, d: Duration) -> Self {
        self.delay = Some(d);
        self
    }
}

type Handler = Arc<dyn Fn(&Recorded) -> Reply + Send + Sync>;

type Check = Box<dyn Fn(&Recorded) + Send + Sync>;

/// One scripted exchange: the request expected next and the reply to it.
pub struct Expect {
    pub method: &'static str,
    pub path: String,
    pub check: Option<Check>,
    pub reply: Reply,
}

impl Expect {
    pub fn new(method: &'static str, path: impl Into<String>, reply: Reply) -> Self {
        Self {
            method,
            path: path.into(),
            check: None,
            reply,
        }
    }

    pub fn check(mut self, f: impl Fn(&Recorded) + Send + Sync + 'static) -> Self {
        self.check = Some(Box::new(f));
        self
    }
}

pub struct FakeGitLab {
    pub url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
    script: Option<Arc<Mutex<VecDeque<Expect>>>>,
    errors: Arc<Mutex<Vec<String>>>,
    task: JoinHandle<()>,
}

impl Drop for FakeGitLab {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeGitLab {
    /// Answers every request with `handler`.
    pub async fn start(handler: impl Fn(&Recorded) -> Reply + Send + Sync + 'static) -> Self {
        Self::serve(Arc::new(handler), None).await
    }

    /// Answers the requests in order from `script`; a request that does not match the next
    /// expectation, or comes after the last, is answered 599 and recorded as an error.
    pub async fn scripted(script: Vec<Expect>) -> Self {
        let queue = Arc::new(Mutex::new(VecDeque::from(script)));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let q = Arc::clone(&queue);
        let errs = Arc::clone(&errors);
        let handler: Handler = Arc::new(move |r: &Recorded| {
            let next = q.lock().unwrap().pop_front();
            match next {
                Some(e) if e.method == r.method && e.path == r.path => {
                    if let Some(check) = &e.check {
                        check(r);
                    }
                    e.reply
                }
                Some(e) => {
                    errs.lock().unwrap().push(format!(
                        "expected {} {}, got {} {}",
                        e.method, e.path, r.method, r.path
                    ));
                    Reply::status(599)
                }
                None => {
                    errs.lock()
                        .unwrap()
                        .push(format!("unexpected {} {}", r.method, r.path));
                    Reply::status(599)
                }
            }
        });
        let mut fake = Self::serve(handler, Some(queue)).await;
        fake.errors = errors;
        fake
    }

    async fn serve(handler: Handler, script: Option<Arc<Mutex<VecDeque<Expect>>>>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recs = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let handler = Arc::clone(&handler);
                let recs = Arc::clone(&recs);
                tokio::spawn(async move {
                    let service = service_fn(move |req: Request<Incoming>| {
                        let handler = Arc::clone(&handler);
                        let recs = Arc::clone(&recs);
                        async move {
                            let (parts, body) = req.into_parts();
                            let body = body
                                .collect()
                                .await
                                .map(|b| b.to_bytes())
                                .unwrap_or_default();
                            let rec = Recorded {
                                method: parts.method.to_string(),
                                path: parts.uri.path().to_owned(),
                                query: parts.uri.query().unwrap_or("").to_owned(),
                                headers: parts.headers,
                                body,
                            };
                            recs.lock().unwrap().push(rec.clone());
                            let reply = handler(&rec);
                            if let Some(d) = reply.delay {
                                tokio::time::sleep(d).await;
                            }
                            let mut resp = Response::builder().status(reply.status);
                            for (k, v) in &reply.headers {
                                resp = resp.header(k, v);
                            }
                            Ok::<_, Infallible>(resp.body(Full::new(reply.body)).unwrap())
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        Self {
            url: format!("http://{addr}"),
            requests,
            script,
            errors: Arc::new(Mutex::new(Vec::new())),
            task,
        }
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }

    /// Requests to `path`, in order.
    pub fn requests_to(&self, path: &str) -> Vec<Recorded> {
        self.requests()
            .into_iter()
            .filter(|r| r.path == path)
            .collect()
    }

    /// Panics if a scripted exchange went wrong or is still pending.
    pub fn assert_script_done(&self) {
        let errors = self.errors.lock().unwrap().clone();
        assert!(errors.is_empty(), "fake GitLab: {errors:#?}");
        if let Some(q) = &self.script {
            let left: Vec<String> = q
                .lock()
                .unwrap()
                .iter()
                .map(|e| format!("{} {}", e.method, e.path))
                .collect();
            assert!(
                left.is_empty(),
                "fake GitLab: expected but not received: {left:#?}"
            );
        }
    }
}

pub const TEST_SYSTEM_ID: &str = "s_0123456789ab";

/// A client for `url` with `token`; `max_attempts` bounds retries so tests stay fast.
pub fn client(url: &str, token: &str, max_attempts: u32) -> GitLabClient {
    client_with_retry(
        url,
        token,
        RetryPolicy {
            max_attempts,
            ..RetryPolicy::default()
        },
    )
}

pub fn client_with_retry(url: &str, token: &str, retry: RetryPolicy) -> GitLabClient {
    GitLabClient::new(options(url, token, retry)).unwrap()
}

pub fn options(url: &str, token: &str, retry: RetryPolicy) -> ClientOptions {
    ClientOptions {
        url: url.to_owned(),
        token: Secret::new(token),
        tls_ca_file: None,
        tls_cert_file: None,
        tls_key_file: None,
        system_id: TEST_SYSTEM_ID.to_owned(),
        info: Info::this_runner(),
        retry,
    }
}
