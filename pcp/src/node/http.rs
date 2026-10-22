//! The HTTP binding of the wire (feature `http`, SPEC 5.5).
//!
//! The seller is the only server; the buyer is a client and needs no public
//! address. Two endpoints carry the protocol, one tells strangers what is
//! sold:
//!
//! ```text
//! POST /pcp/v0/request   Request -> 200 Offer | 422 Refused | 503 busy
//! POST /pcp/v0/accept    Accept  -> 200 {bundle, binding} | 202 no answer yet | 422 Refused | 503 busy
//! GET  /pcp/v0/info      -> 200 {job, price, backend, node, mandate} (unsigned; the offer is what counts)
//! ```
//!
//! The signed Accept is also the poll: the bundle and the invoice go only to
//! a valid Accept from the agent that sent the request, so there is nothing
//! else to authenticate.
//!
//! [`HttpSeller`] puts each request into the seller loop's inbox and waits
//! up to [`REPLY_WAIT`] for the loop's answer. If the loop is proving it does
//! not answer in time: a request gets 503 (`Retry-After`), an accept 202 (no
//! answer yet; it says nothing about validity), and the buyer asks again. A
//! message identical to one still queued is not queued twice: its waiter
//! joins. The seller loop itself is the same as over the directory wire.
//!
//! [`HttpBuyer`] posts each message and turns the answer into received
//! messages. A refused connection, a timeout or a 503 is "ask again later",
//! so a seller that is down or restarting is just slow.
//!
//! The server listens on loopback only unless told otherwise: put a TLS
//! reverse proxy in front (SPEC 5.2: the bundle needs a confidential
//! channel). The buyer refuses `http://` unless told otherwise.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::encoding::Hash32;
use crate::protocol::{Accept, Request};

use super::store::StoreError;
use super::wire::{Inbox, Wire, WireMsg};

/// Largest request or accept body accepted (a sudoku request is about 1 KB).
pub const MAX_BODY: usize = 64 * 1024;
/// How long a handler waits for the seller loop's answer.
pub const REPLY_WAIT: Duration = Duration::from_secs(3);
/// Messages waiting for the seller loop at most; beyond, 503 at once.
pub const MAX_QUEUE: usize = 64;

type Matcher = Box<dyn Fn(&WireMsg) -> bool + Send>;

struct Waiter {
    id: u64,
    matches: Matcher,
    tx: tokio::sync::oneshot::Sender<WireMsg>,
}

#[derive(Default)]
struct Shared {
    inbox: Mutex<VecDeque<(String, WireMsg)>>,
    waiters: Mutex<Vec<Waiter>>,
    info: Mutex<Value>,
    next_id: AtomicU64,
}

/// The seller's side: an HTTP server feeding the seller loop.
pub struct HttpSeller {
    shared: Arc<Shared>,
    addr: SocketAddr,
}

impl HttpSeller {
    /// Start serving on `addr` in a background thread. Refuses a
    /// non-loopback address unless `allow_public` (a TLS proxy should face
    /// the network, not this server).
    pub fn start(addr: SocketAddr, allow_public: bool) -> Result<HttpSeller, String> {
        if !addr.ip().is_loopback() && !allow_public {
            return Err(format!(
                "{addr} is not a loopback address: serve on 127.0.0.1 behind a TLS proxy, \
                 or pass --allow-public-bind"
            ));
        }
        let shared = Arc::new(Shared::default());
        let std_listener =
            std::net::TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| format!("{addr}: {e}"))?;
        let bound = std_listener
            .local_addr()
            .map_err(|e| format!("{addr}: {e}"))?;
        let app = Router::new()
            .route("/pcp/v0/request", post(handle_request))
            .route("/pcp/v0/accept", post(handle_accept))
            .route("/pcp/v0/info", get(handle_info))
            .layer(DefaultBodyLimit::max(MAX_BODY))
            .with_state(shared.clone());
        std::thread::Builder::new()
            .name("pcp-http".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                let r = rt.block_on(async move {
                    let listener = tokio::net::TcpListener::from_std(std_listener)?;
                    axum::serve(listener, app).await
                });
                // The seller loop would keep running deaf: stop the process.
                eprintln!("HTTP server stopped: {r:?}");
                std::process::exit(1);
            })
            .map_err(|e| format!("thread: {e}"))?;
        Ok(HttpSeller {
            shared,
            addr: bound,
        })
    }

    /// The address actually bound (useful with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Wire for HttpSeller {
    /// Hand the loop's answer to the request waiting for it, if any.
    /// Answers nobody waits for (the bundle after a long proof) are
    /// dropped: the buyer's next accept gets them again.
    fn send(&self, msg: &WireMsg) -> Result<(), StoreError> {
        let mut ws = self.shared.waiters.lock().expect("waiters");
        // A client that hung up leaves a waiter nobody reads.
        ws.retain(|w| !w.tx.is_closed());
        if let Some(i) = ws.iter().position(|w| (w.matches)(msg)) {
            let w = ws.swap_remove(i);
            let _ = w.tx.send(msg.clone());
        }
        Ok(())
    }

    fn receive(&self) -> Result<Inbox, StoreError> {
        let mut q = self.shared.inbox.lock().expect("inbox");
        Ok(q.drain(..).map(|(n, m)| (n, Ok(m))).collect())
    }

    fn ack(&self, _name: &str) -> Result<(), StoreError> {
        Ok(())
    }

    fn set_info(&self, info: Value) {
        *self.shared.info.lock().expect("info") = info;
    }
}

// Short-lived, one per waiting handler: boxing the answer gains nothing.
#[allow(clippy::large_enum_variant)]
enum Asked {
    Answer(WireMsg),
    /// The loop did not answer within [`REPLY_WAIT`].
    NoAnswer,
    /// [`MAX_QUEUE`] messages are already waiting.
    Full,
}

/// Queue a message for the seller loop (unless an identical one is still
/// queued) and wait for an answer that `matches`.
async fn ask(shared: &Arc<Shared>, msg: WireMsg, matches: Matcher) -> Asked {
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = tokio::sync::oneshot::channel();
    {
        let mut q = shared.inbox.lock().expect("inbox");
        let queued = q.iter().any(|(_, m)| *m == msg);
        if !queued && q.len() >= MAX_QUEUE {
            return Asked::Full;
        }
        let mut ws = shared.waiters.lock().expect("waiters");
        ws.retain(|w| !w.tx.is_closed());
        ws.push(Waiter { id, matches, tx });
        if !queued {
            q.push_back((msg.name(), msg));
        }
    }
    match tokio::time::timeout(REPLY_WAIT, rx).await {
        Ok(Ok(m)) => Asked::Answer(m),
        _ => {
            shared
                .waiters
                .lock()
                .expect("waiters")
                .retain(|w| w.id != id);
            Asked::NoAnswer
        }
    }
}

fn refused(subject_id: &Hash32, reason: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({ "subject_id": hex::encode(subject_id), "reason": reason })),
    )
        .into_response()
}

fn busy() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(header::RETRY_AFTER, "5")],
        Json(json!({ "status": "busy" })),
    )
        .into_response()
}

fn bad(e: impl std::fmt::Display) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": e.to_string() })),
    )
        .into_response()
}

async fn handle_request(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    let req: Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return bad(e),
    };
    let rid = req.request_id();
    let nonce = req.buyer_nonce;
    let matches: Matcher = Box::new(move |m| match m {
        WireMsg::Offer { offer } => offer.buyer_nonce == nonce,
        WireMsg::Refused { subject_id, .. } => *subject_id == rid,
        _ => false,
    });
    match ask(&shared, WireMsg::Request { request: req }, matches).await {
        Asked::Answer(WireMsg::Offer { offer }) => (StatusCode::OK, Json(offer)).into_response(),
        Asked::Answer(WireMsg::Refused { subject_id, reason }) => refused(&subject_id, &reason),
        _ => busy(),
    }
}

async fn handle_accept(State(shared): State<Arc<Shared>>, body: Bytes) -> Response {
    let acc: Accept = match serde_json::from_slice(&body) {
        Ok(a) => a,
        Err(e) => return bad(e),
    };
    let oid = acc.offer_id;
    let matches: Matcher = Box::new(move |m| match m {
        WireMsg::Bundle { binding, .. } => binding.offer_id == oid,
        WireMsg::Refused { subject_id, .. } => *subject_id == oid,
        _ => false,
    });
    match ask(&shared, WireMsg::Accept { accept: acc }, matches).await {
        Asked::Answer(WireMsg::Bundle { bundle, binding }) => (
            StatusCode::OK,
            Json(json!({ "bundle": bundle, "binding": binding })),
        )
            .into_response(),
        Asked::Answer(WireMsg::Refused { subject_id, reason }) => refused(&subject_id, &reason),
        Asked::Full => busy(),
        // No answer yet: the loop is proving, or this Accept waits its
        // turn. Says nothing about validity. Ask again.
        _ => (StatusCode::ACCEPTED, Json(json!({ "status": "pending" }))).into_response(),
    }
}

async fn handle_info(State(shared): State<Arc<Shared>>) -> Response {
    let info = shared.info.lock().expect("info").clone();
    (StatusCode::OK, Json(info)).into_response()
}

// ---------------------------------------------------------------------------
// Buyer

/// The buyer's side: posts each message to the seller and queues the
/// answers as received messages.
pub struct HttpBuyer {
    base: String,
    http: reqwest::blocking::Client,
    received: Mutex<VecDeque<WireMsg>>,
    seq: AtomicU64,
    /// Final-looking answers in a row (see [`FATAL_IN_A_ROW`]).
    final_answers: AtomicU64,
}

impl HttpBuyer {
    /// A client for the seller at `base` (e.g. `https://seller.example`).
    /// Refuses `http://` unless `allow_insecure` (tests on loopback): the
    /// bundle must not cross the network in the clear (SPEC 5.2, T6).
    /// `ca_pem` adds a root certificate the seller's TLS certificate may
    /// chain to (a self-hosted CA), next to the system roots.
    pub fn new(
        base: &str,
        allow_insecure: bool,
        ca_pem: Option<&[u8]>,
    ) -> Result<HttpBuyer, String> {
        let base = base.trim_end_matches('/').to_string();
        if !base.starts_with("https://") && !(allow_insecure && base.starts_with("http://")) {
            return Err(format!(
                "{base}: the seller URL must be https:// (--allow-insecure-transport for tests)"
            ));
        }
        let mut builder = reqwest::blocking::Client::builder().timeout(Duration::from_secs(15));
        if let Some(pem) = ca_pem {
            let cert = reqwest::Certificate::from_pem(pem)
                .map_err(|e| format!("seller CA certificate: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
        let http = builder.build().map_err(|e| format!("http client: {e}"))?;
        Ok(HttpBuyer {
            base,
            http,
            received: Mutex::new(VecDeque::new()),
            seq: AtomicU64::new(0),
            final_answers: AtomicU64::new(0),
        })
    }

    fn post(&self, path: &str, body: &impl serde::Serialize) -> Option<(u16, Vec<u8>)> {
        let url = format!("{}{path}", self.base);
        match self.http.post(&url).json(body).send() {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let bytes = resp.bytes().map(|b| b.to_vec()).unwrap_or_default();
                Some((status, bytes))
            }
            Err(e) => {
                // The whole chain: "error sending request" alone hides a
                // certificate problem a stranger has to see.
                let mut msg = e.to_string();
                let mut src = std::error::Error::source(&e);
                while let Some(c) = src {
                    msg.push_str(&format!(": {c}"));
                    src = c.source();
                }
                eprintln!("POST {url}: {msg} (will ask again)");
                None
            }
        }
    }

    fn push(&self, m: WireMsg) {
        self.received.lock().expect("received").push_back(m);
    }

    fn push_refused(&self, body: &[u8]) {
        let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let subject = v["subject_id"]
            .as_str()
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <Hash32>::try_from(b).ok());
        match (subject, v["reason"].as_str()) {
            (Some(subject_id), Some(reason)) => self.push(WireMsg::Refused {
                subject_id,
                reason: reason.to_string(),
            }),
            _ => eprintln!("a refusal without subject or reason: ignored"),
        }
    }
}

/// A 4xx answer other than 408 (timeout), 421 and 425 (a proxy's routing
/// or early-data hiccup), 422 (refusal) and 429 (slow down) looks final: the
/// seller cannot read this message (another version, a wrong URL, too
/// large). The buyer stops only after this many in a row, so one stray
/// answer from a proxy whose route is changing does not end a purchase.
/// The buyer sends only before paying, and a restart resumes.
pub const FATAL_IN_A_ROW: u64 = 3;

fn looks_final(status: u16) -> bool {
    (400..500).contains(&status) && ![408, 421, 422, 425, 429].contains(&status)
}

impl HttpBuyer {
    /// Count a non-2xx, non-422 answer; `Err` once [`FATAL_IN_A_ROW`]
    /// final-looking answers came in a row.
    fn other_status(&self, what: &str, status: u16, body: &[u8]) -> Result<(), StoreError> {
        if !looks_final(status) {
            self.final_answers.store(0, Ordering::Relaxed);
            eprintln!("{what}: HTTP {status} (will ask again)");
            return Ok(());
        }
        let n = self.final_answers.fetch_add(1, Ordering::Relaxed) + 1;
        let b = String::from_utf8_lossy(&body[..body.len().min(200)]).into_owned();
        if n >= FATAL_IN_A_ROW {
            return Err(StoreError::Peer(format!(
                "{what}: the seller answered HTTP {status} ({b}) {n} times in a row; not asking again"
            )));
        }
        eprintln!("{what}: HTTP {status} ({b}); {n} of {FATAL_IN_A_ROW} before giving up");
        Ok(())
    }

    fn answered(&self) {
        self.final_answers.store(0, Ordering::Relaxed);
    }
}

impl Wire for HttpBuyer {
    fn send(&self, msg: &WireMsg) -> Result<(), StoreError> {
        match msg {
            WireMsg::Request { request } => match self.post("/pcp/v0/request", request) {
                Some((200, b)) => {
                    self.answered();
                    match serde_json::from_slice(&b) {
                        Ok(offer) => self.push(WireMsg::Offer { offer }),
                        Err(e) => eprintln!("offer does not parse: {e}"),
                    }
                }
                Some((422, b)) => {
                    self.answered();
                    self.push_refused(&b)
                }
                Some((s, b)) => self.other_status("request", s, &b)?,
                None => {}
            },
            WireMsg::Accept { accept } => match self.post("/pcp/v0/accept", accept) {
                Some((200, b)) => {
                    self.answered();
                    let v: Result<Value, _> = serde_json::from_slice(&b);
                    let parsed = v.ok().and_then(|v| {
                        Some(WireMsg::Bundle {
                            bundle: serde_json::from_value(v["bundle"].clone()).ok()?,
                            binding: serde_json::from_value(v["binding"].clone()).ok()?,
                        })
                    });
                    match parsed {
                        Some(m) => self.push(m),
                        None => eprintln!("bundle does not parse"),
                    }
                }
                Some((202, _)) => self.answered(),
                Some((422, b)) => {
                    self.answered();
                    self.push_refused(&b)
                }
                Some((s, b)) => self.other_status("accept", s, &b)?,
                None => {}
            },
            // The buyer only sends requests and accepts.
            _ => {}
        }
        Ok(())
    }

    fn receive(&self) -> Result<Inbox, StoreError> {
        let mut q = self.received.lock().expect("received");
        Ok(q.drain(..)
            .map(|m| {
                let n = self.seq.fetch_add(1, Ordering::Relaxed);
                (format!("{n}-{}", m.name()), Ok(m))
            })
            .collect())
    }

    fn ack(&self, _name: &str) -> Result<(), StoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::TestSuiteJob;
    use crate::mandate::{Agent, Mandate, MandateTerms, Role, SecretKey};
    use crate::proof::InsecureDevTransparentBackend;
    use crate::protocol::{Buyer, BuyerPolicy};
    use rand::rngs::OsRng;

    fn request() -> Request {
        let principal = SecretKey::generate(&mut OsRng);
        let key = SecretKey::generate(&mut OsRng);
        let m = Mandate::sign(
            &principal,
            key.public_key(),
            MandateTerms {
                role: Role::Buyer,
                scope: vec![crate::job::JobClass::spec_hash(&TestSuiteJob)],
                cap_msat: 10_000_000,
                per_deal_max_msat: 10_000_000,
                payout_node: "b".into(),
                expires_at: 1_000_000,
            },
            &mut OsRng,
        );
        let agent = Agent::new(key, m).unwrap();
        let (_b, req) = Buyer::new(
            &agent,
            Box::new(TestSuiteJob),
            Box::new(InsecureDevTransparentBackend),
            BuyerPolicy::default(),
            TestSuiteJob::encode_suite(&[(1, 1)]),
            1_000_000,
            0,
            &mut OsRng,
        )
        .unwrap();
        req
    }

    fn server() -> (HttpSeller, String) {
        let s = HttpSeller::start("127.0.0.1:0".parse().unwrap(), false).unwrap();
        let base = format!("http://{}", s.local_addr());
        (s, base)
    }

    fn post(url: &str, body: Vec<u8>) -> (u16, String) {
        let r = reqwest::blocking::Client::new()
            .post(url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .unwrap();
        (r.status().as_u16(), r.text().unwrap())
    }

    #[test]
    fn transport_safety_defaults() {
        assert!(HttpBuyer::new("http://example.org", false, None).is_err());
        assert!(HttpBuyer::new("http://127.0.0.1:1", true, None).is_ok());
        assert!(HttpBuyer::new("https://example.org", false, None).is_ok());
        assert!(HttpBuyer::new("https://example.org", false, Some(b"not a pem")).is_err());
        assert!(HttpSeller::start("0.0.0.0:0".parse().unwrap(), false).is_err());
    }

    #[test]
    fn only_answers_a_retry_can_cure_are_retried() {
        for s in [400, 403, 404, 413, 415] {
            assert!(looks_final(s), "{s}");
        }
        for s in [408, 421, 422, 425, 429, 500, 502, 503, 504] {
            assert!(!looks_final(s), "{s}");
        }
        // Three final-looking answers in a row end it; anything else between
        // them starts the count again.
        let b = HttpBuyer::new("https://example.org", false, None).unwrap();
        assert!(b.other_status("accept", 404, b"").is_ok());
        assert!(b.other_status("accept", 404, b"").is_ok());
        assert!(b.other_status("accept", 502, b"").is_ok());
        assert!(b.other_status("accept", 404, b"").is_ok());
        assert!(b.other_status("accept", 404, b"").is_ok());
        assert!(b.other_status("accept", 404, b"").is_err());
    }

    #[test]
    fn oversize_and_malformed_bodies_are_refused_at_the_door() {
        let (s, base) = server();
        let (code, _) = post(&format!("{base}/pcp/v0/request"), vec![b' '; MAX_BODY + 1]);
        assert_eq!(code, 413);
        let (code, _) = post(&format!("{base}/pcp/v0/accept"), b"{not json".to_vec());
        assert_eq!(code, 400);
        // Nothing reached the seller loop.
        assert!(s.receive().unwrap().is_empty());
    }

    #[test]
    fn info_is_what_the_seller_set() {
        let (s, base) = server();
        s.set_info(json!({ "price_msat": 1000 }));
        let v: Value = reqwest::blocking::get(format!("{base}/pcp/v0/info"))
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(v["price_msat"], 1000);
    }

    #[test]
    fn a_seller_loop_that_does_not_answer_means_busy_or_pending() {
        // The loop is proving (here: not running). A request is 503 with
        // Retry-After; an accept is 202. Both reached the inbox.
        let (s, base) = server();
        let req = request();
        let r = reqwest::blocking::Client::new()
            .post(format!("{base}/pcp/v0/request"))
            .json(&req)
            .send()
            .unwrap();
        assert_eq!(r.status().as_u16(), 503);
        assert_eq!(r.headers()["retry-after"], "5");
        let acc = Accept {
            version: crate::encoding::VERSION.into(),
            offer_id: [1u8; 32],
            mandate: None,
            agent_sig: None,
        };
        let (code, _) = post(
            &format!("{base}/pcp/v0/accept"),
            serde_json::to_vec(&acc).unwrap(),
        );
        assert_eq!(code, 202);
        let got = s.receive().unwrap();
        assert_eq!(got.len(), 2);
    }

    #[test]
    fn identical_messages_queue_once_and_a_dead_waiter_does_not_swallow_the_answer() {
        let (s, _base) = server();
        let shared = s.shared.clone();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let req = request();
        let rid = req.request_id();
        let m = move |w: &WireMsg| matches!(w, WireMsg::Refused { subject_id, .. } if *subject_id == rid);
        rt.block_on(async {
            // A client that hangs up: its ask is dropped mid-wait.
            let dead = ask(
                &shared,
                WireMsg::Request {
                    request: req.clone(),
                },
                Box::new(m),
            );
            let _ = tokio::time::timeout(Duration::from_millis(50), dead).await;
        });
        assert_eq!(shared.waiters.lock().unwrap().len(), 1);
        let live = {
            let shared = shared.clone();
            let req = req.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(ask(&shared, WireMsg::Request { request: req }, Box::new(m)))
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        // The same request was not queued twice.
        assert_eq!(s.receive().unwrap().len(), 1);
        s.send(&WireMsg::Refused {
            subject_id: rid,
            reason: "seller_busy".into(),
        })
        .unwrap();
        match live.join().unwrap() {
            Asked::Answer(WireMsg::Refused { subject_id, .. }) => assert_eq!(subject_id, rid),
            _ => panic!("the live waiter did not get the answer"),
        }
        assert!(shared.waiters.lock().unwrap().is_empty());
    }

    #[test]
    fn the_loops_answer_reaches_the_request_that_waits_for_it() {
        // A stand-in seller loop refuses whatever request arrives; the
        // client sees 422 naming its request, and the HttpBuyer turns it
        // into a Refused message for the buyer loop.
        let (s, base) = server();
        let s = Arc::new(s);
        let loop_side = s.clone();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop2 = stop.clone();
        let t = std::thread::spawn(move || {
            while !stop2.load(Ordering::Relaxed) {
                for (_n, m) in loop_side.receive().unwrap() {
                    if let Ok(WireMsg::Request { request }) = m {
                        loop_side
                            .send(&WireMsg::Refused {
                                subject_id: request.request_id(),
                                reason: "seller_busy".into(),
                            })
                            .unwrap();
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let req = request();
        let buyer = HttpBuyer::new(&base, true, None).unwrap();
        buyer
            .send(&WireMsg::Request {
                request: req.clone(),
            })
            .unwrap();
        let got = buyer.receive().unwrap();
        stop.store(true, Ordering::Relaxed);
        t.join().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(
            got[0].1.as_ref().unwrap(),
            &WireMsg::Refused {
                subject_id: req.request_id(),
                reason: "seller_busy".into()
            }
        );
    }
}
