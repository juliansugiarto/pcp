//! LND REST rail (feature `lnd`, off by default): one LND node, hold
//! invoices, `lightning-bolt11/0`.
//!
//! **Status: run against real LND nodes on regtest** (LND v0.19.3-beta and
//! v0.21.4-beta in Docker, `.github/workflows/lnd-regtest.yml`): a whole
//! sale settles, and `tests/lnd_regtest.rs` checks a reused hash, a
//! mismatching presented invoice and a cancelled hold invoice. The JSON
//! field names and shapes below match what those nodes returned; the raw
//! output is kept on the `ci-results-lnd` branch.
//!
//! | Rail method | LND REST call |
//! |---|---|
//! | `create_invoice` | `POST /v2/invoices/hodl` (AddHoldInvoice), then `GET /v1/payreq/{bolt11}` to read it back |
//! | `pay_invoice` | `GET /v1/payreq/{bolt11}` (the payer's own node decodes), then `POST /v2/router/send` (SendPaymentV2, streaming; returns once an HTLC attempt is `IN_FLIGHT`) |
//! | `settle_invoice` | `POST /v2/invoices/settle` (SettleInvoice) |
//! | `lookup_invoice` | `GET /v1/invoice/{hash_hex}` (LookupInvoice) and `GET /v1/getinfo` for the block height |
//! | `lookup_payment` | `GET /v1/payments?include_incomplete=true` (ListPayments) |
//!
//! Why hold invoices: an ordinary LND invoice is created with its preimage
//! and settles by itself. PCP needs the seller to keep `k` until the
//! seller's own checks pass (SPEC 9, S4), so the invoice is created with
//! only `H` and settled explicitly.
//!
//! Units: BOLT11 timelocks are in blocks. This rail converts with
//! `secs_per_block` (600 by default): `min_htlc_secs` = `cltv_expiry *
//! secs_per_block`. LND refuses a hold invoice whose final CLTV delta is
//! below its minimum: 18 blocks up to v0.19, 24 blocks in v0.21 ("CLTV
//! delta of 18 must be greater than minimum of 24"). This rail asks for at
//! least 24, so on this rail a seller's `min_htlc_secs` is at least
//! 24 * 600 = 14 400 s, and the buyer's `BuyerPolicy::htlc_secs` must be
//! raised to match (RUN-ON-MAC.md uses 24 000).
//!
//! Authentication: the macaroon is sent as the `Grpc-Metadata-macaroon`
//! header (hex). TLS: LND's self-signed `tls.cert` is the only trusted root
//! (native TLS; on macOS the Security framework). Use a macaroon with the
//! least rights the role needs (seller: invoices; buyer: offchain), not
//! `admin.macaroon`, beyond regtest.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use serde_json::{json, Value};

use super::{
    IncomingHtlc, IncomingState, InvoiceRequest, PaymentStatus, Rail, RailError, RAIL_BOLT11,
};
use crate::encoding::{sha256, Hash32};
use crate::lightning::{Invoice, LedgerError};

/// LND refuses final CLTV deltas below this many blocks (24 in LND v0.21;
/// v0.19 accepted 18).
pub const LND_MIN_FINAL_CLTV: u64 = 24;

/// How to reach one LND node.
#[derive(Clone)]
pub struct LndConfig {
    /// REST endpoint, e.g. `https://127.0.0.1:8081` (Polar shows it on the
    /// node's "Connect" tab).
    pub rest_url: String,
    /// Macaroon bytes, hex-encoded.
    pub macaroon_hex: String,
    /// The node's `tls.cert` in PEM.
    pub tls_cert_pem: Vec<u8>,
    /// Routing fee limit for payments, in sat.
    pub fee_limit_sat: u64,
    /// SendPaymentV2 `timeout_seconds`: how long LND tries to find a route.
    pub payment_timeout_secs: u32,
    /// Seconds per block for timelock conversion.
    pub secs_per_block: u64,
}

impl std::fmt::Debug for LndConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LndConfig")
            .field("rest_url", &self.rest_url)
            .field("macaroon_hex", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl LndConfig {
    /// Read the macaroon and the TLS certificate from files, with default
    /// fee limit (10 sat), payment timeout (60 s) and 600 s per block.
    pub fn from_files(
        rest_url: &str,
        macaroon_path: impl AsRef<Path>,
        tls_cert_path: impl AsRef<Path>,
    ) -> std::io::Result<LndConfig> {
        Ok(LndConfig {
            rest_url: rest_url.trim_end_matches('/').to_string(),
            macaroon_hex: hex::encode(std::fs::read(macaroon_path)?),
            tls_cert_pem: std::fs::read(tls_cert_path)?,
            fee_limit_sat: 10,
            payment_timeout_secs: 60,
            secs_per_block: 600,
        })
    }

    /// Read `PCP_LND_REST_URL`, `PCP_LND_MACAROON` (path) and
    /// `PCP_LND_TLS_CERT` (path) from the environment.
    pub fn from_env(prefix: &str) -> Result<LndConfig, String> {
        let var = |name: &str| {
            let key = format!("{prefix}{name}");
            std::env::var(&key).map_err(|_| format!("{key} is not set"))
        };
        LndConfig::from_files(&var("REST_URL")?, var("MACAROON")?, var("TLS_CERT")?)
            .map_err(|e| e.to_string())
    }
}

/// One LND node as a PCP settlement rail.
pub struct LndRail {
    http: reqwest::blocking::Client,
    cfg: LndConfig,
    node_id: String,
}

impl LndRail {
    /// Connect and read the node's identity (`GET /v1/getinfo`). This is the
    /// only call that happens without being asked for.
    pub fn connect(cfg: LndConfig) -> Result<LndRail, RailError> {
        let cert = reqwest::Certificate::from_pem(&cfg.tls_cert_pem)
            .map_err(|e| RailError::Node(format!("tls.cert: {e}")))?;
        let http = reqwest::blocking::Client::builder()
            .add_root_certificate(cert)
            .timeout(Duration::from_secs(
                u64::from(cfg.payment_timeout_secs) + 30,
            ))
            .build()
            .map_err(|e| RailError::Node(format!("http client: {e}")))?;
        let mut rail = LndRail {
            http,
            cfg,
            node_id: String::new(),
        };
        let info = rail.get("/v1/getinfo")?;
        rail.node_id = info["identity_pubkey"]
            .as_str()
            .ok_or_else(|| RailError::Node("getinfo: no identity_pubkey".into()))?
            .to_string();
        Ok(rail)
    }

    /// The node's public key (hex). In PCP this is the `payout_node` the
    /// principal writes into the mandate.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Decode a BOLT11 string with this node (`GET /v1/payreq/{bolt11}`).
    /// The payer trusts its own node's decoding, not the payee's word.
    pub fn decode(&self, bolt11: &str) -> Result<Invoice, RailError> {
        let v = self.get(&format!("/v1/payreq/{bolt11}"))?;
        invoice_from_payreq(&v, bolt11, self.cfg.secs_per_block)
    }

    /// Cancel a hold invoice and fail any HTLC held for it
    /// (`POST /v2/invoices/cancel`). Not used by the protocol; for a seller
    /// that decides not to settle and wants to free the buyer's funds
    /// before the timeout.
    pub fn cancel_invoice(&self, payment_hash: &Hash32) -> Result<(), RailError> {
        self.post(
            "/v2/invoices/cancel",
            &json!({ "payment_hash": B64.encode(payment_hash) }),
        )
        .map(|_| ())
    }

    fn block_height(&self) -> Result<u64, RailError> {
        let info = self.get("/v1/getinfo")?;
        num(&info["block_height"]).ok_or_else(|| RailError::Node("getinfo: no block_height".into()))
    }

    fn check_node(&self, node: &str) -> Result<(), RailError> {
        if node == self.node_id {
            Ok(())
        } else {
            Err(RailError::NotThisNode)
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.cfg.rest_url, path)
    }

    fn get(&self, path: &str) -> Result<Value, RailError> {
        let resp = self
            .http
            .get(self.url(path))
            .header("Grpc-Metadata-macaroon", &self.cfg.macaroon_hex)
            .send()
            .map_err(|e| RailError::Node(format!("GET {path}: {e}")))?;
        json_body(path, resp)
    }

    fn get_opt(&self, path: &str) -> Result<Option<Value>, RailError> {
        let resp = self
            .http
            .get(self.url(path))
            .header("Grpc-Metadata-macaroon", &self.cfg.macaroon_hex)
            .send()
            .map_err(|e| RailError::Node(format!("GET {path}: {e}")))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        json_body(path, resp).map(Some)
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, RailError> {
        let resp = self
            .http
            .post(self.url(path))
            .header("Grpc-Metadata-macaroon", &self.cfg.macaroon_hex)
            .json(body)
            .send()
            .map_err(|e| RailError::Node(format!("POST {path}: {e}")))?;
        json_body(path, resp)
    }
}

fn json_body(path: &str, resp: reqwest::blocking::Response) -> Result<Value, RailError> {
    let status = resp.status();
    let text = resp
        .text()
        .map_err(|e| RailError::Node(format!("{path}: {e}")))?;
    if !status.is_success() {
        return Err(RailError::Node(format!("{path}: HTTP {status}: {text}")));
    }
    serde_json::from_str(&text).map_err(|e| RailError::Node(format!("{path}: bad JSON: {e}")))
}

impl Rail for LndRail {
    fn rail_id(&self) -> &'static str {
        RAIL_BOLT11
    }

    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn create_invoice(&mut self, req: &InvoiceRequest) -> Result<Invoice, RailError> {
        self.check_node(&req.payee)?;
        let cltv =
            secs_to_blocks(req.min_htlc_secs, self.cfg.secs_per_block).max(LND_MIN_FINAL_CLTV);
        let resp = self.post(
            "/v2/invoices/hodl",
            &json!({
                "hash": B64.encode(req.payment_hash),
                "value_msat": req.amount_msat.to_string(),
                "description_hash": B64.encode(req.description_hash),
                "expiry": req.expiry_secs.to_string(),
                "cltv_expiry": cltv.to_string(),
            }),
        )?;
        let bolt11 = resp["payment_request"]
            .as_str()
            .ok_or_else(|| RailError::Node("hodl: no payment_request".into()))?;
        let inv = self.decode(bolt11)?;
        // Read back what the node actually issued.
        let mismatch = if inv.payment_hash != req.payment_hash {
            Some("payment_hash")
        } else if inv.amount_msat != req.amount_msat {
            Some("amount_msat")
        } else if inv.description_hash != req.description_hash {
            Some("description_hash")
        } else if inv.payee != self.node_id {
            Some("payee")
        } else {
            None
        };
        match mismatch {
            Some(f) => Err(RailError::InvoiceMismatch(f)),
            None => Ok(inv),
        }
    }

    fn pay_invoice(
        &mut self,
        payer: &str,
        invoice: &Invoice,
        max_htlc_secs: u64,
    ) -> Result<(), RailError> {
        self.check_node(payer)?;
        let bolt11 = invoice.bolt11.as_deref().ok_or(RailError::InvoiceMissing)?;
        let decoded = self.decode(bolt11)?;
        if let Some(field) = invoice_mismatch(&decoded, invoice) {
            return Err(RailError::InvoiceMismatch(field));
        }
        if self.now() >= decoded.expires_at() {
            return Err(RailError::Ledger(LedgerError::InvoiceExpired));
        }
        let path = "/v2/router/send";
        let resp = self
            .http
            .post(self.url(path))
            .header("Grpc-Metadata-macaroon", &self.cfg.macaroon_hex)
            .json(&json!({
                "payment_request": bolt11,
                "timeout_seconds": self.cfg.payment_timeout_secs,
                "fee_limit_sat": self.cfg.fee_limit_sat.to_string(),
                "cltv_limit": secs_to_blocks(max_htlc_secs, self.cfg.secs_per_block),
            }))
            .send()
            .map_err(|e| RailError::Node(format!("POST {path}: {e}")))?;
        if !resp.status().is_success() {
            return Err(json_body(path, resp)
                .err()
                .unwrap_or(RailError::Node(format!("{path}: unexpected success body"))));
        }
        // A stream of JSON objects, one per line. A hold invoice keeps the
        // payment IN_FLIGHT until the seller settles, so return at the first
        // update that shows an HTLC out (or that the payment failed). LND
        // reports the payment IN_FLIGHT before any HTLC is sent (first line,
        // `htlcs: []`), so the status alone is not enough. Dropping the
        // stream does not cancel the payment (checked on regtest).
        for line in BufReader::new(resp).lines() {
            let line = line.map_err(|e| RailError::Node(format!("{path}: {e}")))?;
            if line.trim().is_empty() {
                continue;
            }
            match send_update(&line)? {
                SendUpdate::Pending => continue,
                SendUpdate::Out => return Ok(()),
                SendUpdate::Failed(reason) => {
                    return Err(RailError::Node(format!("payment failed: {reason}")))
                }
            }
        }
        Err(RailError::Node(format!(
            "{path}: stream ended without a status"
        )))
    }

    fn settle_invoice(
        &mut self,
        payee: &str,
        payment_hash: &Hash32,
        preimage: [u8; 32],
    ) -> Result<(), RailError> {
        self.check_node(payee)?;
        if sha256(&preimage) != *payment_hash {
            return Err(RailError::Ledger(LedgerError::PreimageMismatch));
        }
        self.post(
            "/v2/invoices/settle",
            &json!({ "preimage": B64.encode(preimage) }),
        )
        .map(|_| ())
    }

    fn lookup_invoice(&mut self, payment_hash: &Hash32) -> Result<Option<IncomingHtlc>, RailError> {
        let Some(v) = self.get_opt(&format!("/v1/invoice/{}", hex::encode(payment_hash)))? else {
            return Ok(None);
        };
        let height = self.block_height()?;
        Ok(incoming_from_invoice(
            &v,
            &self.node_id,
            height,
            self.now(),
            self.cfg.secs_per_block,
        ))
    }

    fn lookup_payment(
        &mut self,
        payer: &str,
        payment_hash: &Hash32,
    ) -> Result<PaymentStatus, RailError> {
        self.check_node(payer)?;
        let v = self.get("/v1/payments?include_incomplete=true&reversed=true&max_payments=1000")?;
        Ok(payment_status(&v, payment_hash, self.now()))
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (unit-tested without a node)

/// An LND JSON integer: grpc-gateway writes 64-bit integers as strings.
fn num(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn hex32(v: &Value) -> Option<Hash32> {
    hex::decode(v.as_str()?).ok()?.try_into().ok()
}

fn secs_to_blocks(secs: u64, secs_per_block: u64) -> u64 {
    secs.div_ceil(secs_per_block.max(1))
}

/// `PayReq` JSON (from `GET /v1/payreq/{bolt11}`) to the protocol's invoice.
fn invoice_from_payreq(v: &Value, bolt11: &str, secs_per_block: u64) -> Result<Invoice, RailError> {
    let bad = |f: &str| RailError::Node(format!("payreq: missing or bad {f}"));
    Ok(Invoice {
        payee: v["destination"]
            .as_str()
            .ok_or_else(|| bad("destination"))?
            .to_string(),
        payment_hash: hex32(&v["payment_hash"]).ok_or_else(|| bad("payment_hash"))?,
        amount_msat: num(&v["num_msat"]).ok_or_else(|| bad("num_msat"))?,
        created_at: num(&v["timestamp"]).ok_or_else(|| bad("timestamp"))?,
        expiry_secs: num(&v["expiry"]).ok_or_else(|| bad("expiry"))?,
        min_htlc_secs: num(&v["cltv_expiry"])
            .ok_or_else(|| bad("cltv_expiry"))?
            .saturating_mul(secs_per_block),
        description_hash: hex32(&v["description_hash"]).ok_or_else(|| bad("description_hash"))?,
        bolt11: Some(bolt11.to_string()),
    })
}

/// The first field where what the payer's node decoded differs from the
/// invoice the payer checked (SPEC 9, V5 to V8 were run on `presented`).
fn invoice_mismatch(decoded: &Invoice, presented: &Invoice) -> Option<&'static str> {
    if decoded.payment_hash != presented.payment_hash {
        Some("payment_hash")
    } else if decoded.amount_msat != presented.amount_msat {
        Some("amount_msat")
    } else if decoded.payee != presented.payee {
        Some("payee")
    } else if decoded.description_hash != presented.description_hash {
        Some("description_hash")
    } else if decoded.created_at != presented.created_at
        || decoded.expiry_secs != presented.expiry_secs
    {
        Some("expiry")
    } else if decoded.min_htlc_secs != presented.min_htlc_secs {
        Some("min_htlc_secs")
    } else {
        None
    }
}

/// `Invoice` JSON (from `GET /v1/invoice/{hash}`) to the payee's view of
/// the HTLC. `OPEN` (nothing paid yet) is `None`.
fn incoming_from_invoice(
    v: &Value,
    node_id: &str,
    height: u64,
    now: u64,
    secs_per_block: u64,
) -> Option<IncomingHtlc> {
    let state = match v["state"].as_str()? {
        "ACCEPTED" => IncomingState::Held,
        "SETTLED" => IncomingState::Settled,
        "CANCELED" => IncomingState::Canceled,
        _ => return None,
    };
    let live: Vec<&Value> = v["htlcs"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|h| match state {
                    IncomingState::Held => h["state"].as_str() == Some("ACCEPTED"),
                    IncomingState::Settled => h["state"].as_str() == Some("SETTLED"),
                    IncomingState::Canceled => true,
                })
                .collect()
        })
        .unwrap_or_default();
    let amount_msat = live.iter().filter_map(|h| num(&h["amt_msat"])).sum();
    let expiry_height = live
        .iter()
        .filter_map(|h| num(&h["expiry_height"]))
        .min()
        .unwrap_or(height);
    Some(IncomingHtlc {
        payee: node_id.to_string(),
        amount_msat,
        timeout_at: now.saturating_add(
            expiry_height
                .saturating_sub(height)
                .saturating_mul(secs_per_block),
        ),
        state,
    })
}

/// `ListPaymentsResponse` JSON to the payer's view of the latest payment to
/// `payment_hash`.
fn payment_status(v: &Value, payment_hash: &Hash32, now: u64) -> PaymentStatus {
    let want = hex::encode(payment_hash);
    let latest = v["payments"].as_array().and_then(|ps| {
        ps.iter()
            .filter(|p| p["payment_hash"].as_str() == Some(want.as_str()))
            .max_by_key(|p| num(&p["creation_time_ns"]).unwrap_or(0))
    });
    let Some(p) = latest else {
        return PaymentStatus::Unknown;
    };
    match p["status"].as_str() {
        Some("SUCCEEDED") => match hex32(&p["payment_preimage"]) {
            Some(preimage) => {
                let at = p["htlcs"]
                    .as_array()
                    .and_then(|hs| hs.iter().filter_map(|h| num(&h["resolve_time_ns"])).max())
                    .map(|ns| ns / 1_000_000_000)
                    .unwrap_or(now);
                PaymentStatus::Settled { preimage, at }
            }
            None => PaymentStatus::InFlight,
        },
        Some("FAILED") => PaymentStatus::Failed { at: now },
        _ => PaymentStatus::InFlight,
    }
}

enum SendUpdate {
    Pending,
    Out,
    Failed(String),
}

/// One line of the SendPaymentV2 stream: `{"result": Payment}` or
/// `{"error": {...}}`. `Out` once an HTLC attempt is in flight (or the
/// payment succeeded).
fn send_update(line: &str) -> Result<SendUpdate, RailError> {
    let v: Value = serde_json::from_str(line)
        .map_err(|e| RailError::Node(format!("router/send: bad JSON: {e}")))?;
    if let Some(err) = v.get("error") {
        return Err(RailError::Node(format!("router/send: {err}")));
    }
    let p = v.get("result").unwrap_or(&v);
    let htlc_out = p["htlcs"].as_array().is_some_and(|hs| {
        hs.iter()
            .any(|h| matches!(h["status"].as_str(), Some("IN_FLIGHT") | Some("SUCCEEDED")))
    });
    Ok(match p["status"].as_str() {
        Some("SUCCEEDED") => SendUpdate::Out,
        Some("IN_FLIGHT") if htlc_out => SendUpdate::Out,
        Some("FAILED") => SendUpdate::Failed(
            p["failure_reason"]
                .as_str()
                .unwrap_or("FAILURE_REASON_UNKNOWN")
                .to_string(),
        ),
        _ => SendUpdate::Pending,
    })
}

#[cfg(test)]
mod tests {
    //! The JSON below is written by hand from LND's REST documentation, not
    //! captured from a node. It checks this module's parsing, not LND.
    use super::*;

    const H: &str = "02d449a31fbb267c8f352e9968a79e3e5fc95c1bbeaa502fd6454ebde5a4bedc";
    const D: &str = "48b2ecc5eccf1ec9f13e74019ff6a45aa7aae444a3cae5f4338f28aff28e39b8";
    const NODE: &str = "03aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn h() -> Hash32 {
        hex32(&json!(H)).unwrap()
    }

    fn payreq() -> Value {
        json!({
            "destination": NODE,
            "payment_hash": H,
            "num_satoshis": "1000",
            "timestamp": "1700000000",
            "expiry": "600",
            "description": "",
            "description_hash": D,
            "cltv_expiry": "18",
            "num_msat": "1000000"
        })
    }

    #[test]
    fn payreq_decodes_to_the_protocol_invoice() {
        let inv = invoice_from_payreq(&payreq(), "lnbcrt1...", 600).unwrap();
        assert_eq!(inv.payee, NODE);
        assert_eq!(inv.payment_hash, h());
        assert_eq!(inv.amount_msat, 1_000_000);
        assert_eq!(inv.created_at, 1_700_000_000);
        assert_eq!(inv.expires_at(), 1_700_000_600);
        assert_eq!(inv.min_htlc_secs, 18 * 600);
        assert_eq!(hex::encode(inv.description_hash), D);
        assert_eq!(inv.bolt11.as_deref(), Some("lnbcrt1..."));
        let mut v = payreq();
        v["payment_hash"] = json!("zz");
        assert!(invoice_from_payreq(&v, "x", 600).is_err());
    }

    #[test]
    fn a_bolt11_that_decodes_to_other_terms_is_refused() {
        let inv = invoice_from_payreq(&payreq(), "lnbcrt1...", 600).unwrap();
        assert_eq!(invoice_mismatch(&inv, &inv), None);
        let mut claimed = inv.clone();
        claimed.amount_msat -= 1;
        assert_eq!(invoice_mismatch(&inv, &claimed), Some("amount_msat"));
        let mut claimed = inv.clone();
        claimed.payee = "03bb".into();
        assert_eq!(invoice_mismatch(&inv, &claimed), Some("payee"));
        let mut claimed = inv.clone();
        claimed.description_hash = [0; 32];
        assert_eq!(invoice_mismatch(&inv, &claimed), Some("description_hash"));
        let mut claimed = inv.clone();
        claimed.payment_hash = [0; 32];
        assert_eq!(invoice_mismatch(&inv, &claimed), Some("payment_hash"));
        let mut claimed = inv;
        claimed.min_htlc_secs = 600;
        assert_eq!(
            invoice_mismatch(&inv_again(), &claimed),
            Some("min_htlc_secs")
        );
    }

    fn inv_again() -> Invoice {
        invoice_from_payreq(&payreq(), "lnbcrt1...", 600).unwrap()
    }

    #[test]
    fn held_invoice_is_an_incoming_htlc_with_a_timeout() {
        let v = json!({
            "r_hash": "AtRJox+7JnyPNS6ZaKeePl/JXBu+qlAv1kVOveWkvtw=",
            "state": "ACCEPTED",
            "value_msat": "1000000",
            "htlcs": [
                {"amt_msat": "1000000", "expiry_height": "140", "state": "ACCEPTED"}
            ]
        });
        let got = incoming_from_invoice(&v, NODE, 120, 1_000, 600).unwrap();
        assert_eq!(got.state, IncomingState::Held);
        assert_eq!(got.amount_msat, 1_000_000);
        assert_eq!(got.timeout_at, 1_000 + 20 * 600);
        assert_eq!(got.payee, NODE);
        let open = json!({"state": "OPEN", "htlcs": []});
        assert_eq!(incoming_from_invoice(&open, NODE, 120, 0, 600), None);
        let settled = json!({"state": "SETTLED", "htlcs": [
            {"amt_msat": "1000000", "expiry_height": "140", "state": "SETTLED"}]});
        assert_eq!(
            incoming_from_invoice(&settled, NODE, 120, 0, 600)
                .unwrap()
                .state,
            IncomingState::Settled
        );
    }

    #[test]
    fn payments_list_gives_the_preimage() {
        let k = "1111111111111111111111111111111111111111111111111111111111111111";
        let v = json!({"payments": [
            {"payment_hash": H, "status": "FAILED", "creation_time_ns": "1"},
            {"payment_hash": H, "status": "SUCCEEDED", "payment_preimage": k,
             "creation_time_ns": "2",
             "htlcs": [{"resolve_time_ns": "1700000123000000000"}]},
            {"payment_hash": D, "status": "IN_FLIGHT", "creation_time_ns": "3"}
        ]});
        assert_eq!(
            payment_status(&v, &h(), 5),
            PaymentStatus::Settled {
                preimage: [0x11; 32],
                at: 1_700_000_123
            }
        );
        let inflight = json!({"payments": [
            {"payment_hash": H, "status": "IN_FLIGHT", "payment_preimage":
             "0000000000000000000000000000000000000000000000000000000000000000",
             "creation_time_ns": "9"}]});
        assert_eq!(payment_status(&inflight, &h(), 5), PaymentStatus::InFlight);
        let failed = json!({"payments": [
            {"payment_hash": H, "status": "FAILED", "creation_time_ns": "9"}]});
        assert_eq!(
            payment_status(&failed, &h(), 5),
            PaymentStatus::Failed { at: 5 }
        );
        assert_eq!(payment_status(&json!({}), &h(), 5), PaymentStatus::Unknown);
    }

    #[test]
    fn send_stream_returns_at_first_htlc_in_flight() {
        assert!(matches!(
            send_update(r#"{"result":{"status":"INITIATED"}}"#),
            Ok(SendUpdate::Pending)
        ));
        // LND v0.19.3, first two lines for a hold invoice (trimmed): the
        // payment is IN_FLIGHT before any HTLC is out.
        assert!(matches!(
            send_update(
                r#"{"result":{"status":"IN_FLIGHT","htlcs":[],"failure_reason":"FAILURE_REASON_NONE"}}"#
            ),
            Ok(SendUpdate::Pending)
        ));
        assert!(matches!(
            send_update(
                r#"{"result":{"status":"IN_FLIGHT","htlcs":[{"attempt_id":"4","status":"IN_FLIGHT","route":{"total_time_lock":134},"resolve_time_ns":"0","failure":null}],"failure_reason":"FAILURE_REASON_NONE"}}"#
            ),
            Ok(SendUpdate::Out)
        ));
        assert!(matches!(
            send_update(r#"{"result":{"status":"IN_FLIGHT","htlcs":[{"status":"FAILED"}]}}"#),
            Ok(SendUpdate::Pending)
        ));
        assert!(matches!(
            send_update(r#"{"result":{"status":"SUCCEEDED","htlcs":[]}}"#),
            Ok(SendUpdate::Out)
        ));
        assert!(matches!(
            send_update(r#"{"result":{"status":"FAILED","htlcs":[],"failure_reason":"FAILURE_REASON_INSUFFICIENT_BALANCE"}}"#),
            Ok(SendUpdate::Failed(r)) if r == "FAILURE_REASON_INSUFFICIENT_BALANCE"
        ));
        assert!(matches!(
            send_update(r#"{"result":{"status":"FAILED","failure_reason":"FAILURE_REASON_NO_ROUTE"}}"#),
            Ok(SendUpdate::Failed(r)) if r == "FAILURE_REASON_NO_ROUTE"
        ));
        assert!(send_update(r#"{"error":{"code":2,"message":"invoice expired"}}"#).is_err());
        assert!(send_update("not json").is_err());
    }

    #[test]
    fn timelocks_round_up_to_blocks() {
        assert_eq!(secs_to_blocks(0, 600), 0);
        assert_eq!(secs_to_blocks(1, 600), 1);
        assert_eq!(secs_to_blocks(10_800, 600), 18);
        assert_eq!(secs_to_blocks(24_000, 600), 40);
        assert_eq!(num(&json!("18")), Some(18));
        assert_eq!(num(&json!(18)), Some(18));
        assert_eq!(num(&json!("x")), None);
    }

    #[test]
    fn config_debug_hides_the_macaroon() {
        let c = LndConfig {
            rest_url: "https://127.0.0.1:8081".into(),
            macaroon_hex: "0201036c6e64".into(),
            tls_cert_pem: vec![],
            fee_limit_sat: 10,
            payment_timeout_secs: 60,
            secs_per_block: 600,
        };
        assert!(!format!("{c:?}").contains("0201036c6e64"));
    }
}
