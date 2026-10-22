//! The wire between buyer and seller: SPEC section 5 messages as JSON files
//! in the receiver's inbox directory.
//!
//! A sender writes `<name>.json.tmp`, flushes it, and renames it to
//! `<name>.json`, so a receiver never reads half a message. Names are
//! deterministic (`offer-<offer_id>` and so on), so a sender that resends
//! after a crash overwrites its earlier copy instead of adding one. A
//! receiver deletes a message only after it has saved the state the
//! message led to; a message read twice is harmless, because every step
//! is idempotent or returns `WrongState`, which the loops drop.
//!
//! The transport is dumb on purpose: it carries bytes and authenticates
//! nothing. Requests, offers and accepts are agent-signed; bundles and
//! invoices are checked against the buyer's own state.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::encoding::Hash32;
use crate::mandate::PublicKey;
use crate::proof::ProofBundle;
use crate::protocol::{Accept, InvoiceBinding, Offer, Request};

use super::store::{write_atomic, StoreError};

/// One message on the wire.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum WireMsg {
    Request {
        request: Request,
    },
    Offer {
        offer: Offer,
    },
    Accept {
        accept: Accept,
    },
    /// Proof bundle and invoice binding, sent together.
    Bundle {
        bundle: ProofBundle,
        binding: InvoiceBinding,
    },
    /// The counterparty refused a request or an accept (its reason code).
    Refused {
        #[serde(with = "crate::encoding::hex32")]
        subject_id: Hash32,
        reason: String,
    },
}

impl WireMsg {
    /// The file name the message is sent under: one per message kind and
    /// subject, so a resend replaces the earlier copy.
    pub fn name(&self) -> String {
        match self {
            WireMsg::Request { request } => {
                format!("request-{}", hex::encode(request.request_id()))
            }
            WireMsg::Offer { offer } => format!("offer-{}", hex::encode(offer.offer_id())),
            WireMsg::Accept { accept } => format!("accept-{}", hex::encode(accept.offer_id)),
            WireMsg::Bundle { binding, .. } => format!("bundle-{}", hex::encode(binding.offer_id)),
            WireMsg::Refused { subject_id, .. } => format!("refused-{}", hex::encode(subject_id)),
        }
    }
}

/// How a role exchanges SPEC 5 messages: send one, read what arrived,
/// and acknowledge a message once the state it led to is saved. The loops
/// in `node` use only this, so the directory wire and the HTTP binding
/// (`node::http`, feature `http`) are interchangeable.
pub trait Wire {
    /// Send (or resend) a message. Transport failures that a resend will
    /// cure (peer down, busy) are not errors here.
    fn send(&self, msg: &WireMsg) -> Result<(), StoreError>;
    /// Messages that arrived, with a name for [`Wire::ack`].
    fn receive(&self) -> Result<Inbox, StoreError>;
    /// The message is handled and its effect saved.
    fn ack(&self, name: &str) -> Result<(), StoreError>;
    /// What the seller publishes about itself (`GET /pcp/v0/info` on HTTP).
    fn set_info(&self, _info: serde_json::Value) {}
    /// The seller's principal list (`None`: everyone). A transport that
    /// queues (HTTP) refuses a request from anyone else before queueing it,
    /// so strangers cannot fill the queue while the loop is proving.
    fn set_principals(&self, _principals: Option<Vec<Hash32>>) {}
    /// Offers the seller has issued, with the buyer mandate each was
    /// issued under. A queueing transport refuses, before queueing, an
    /// Accept for any other offer or not signed by that mandate's agent.
    fn know_offers(&self, _offers: &[KnownOffer]) {}
    /// Messages a queueing transport refused before the loop saw them.
    fn refused_before_queue(&self) -> u64 {
        0
    }
}

/// An issued offer as the transport's gate needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownOffer {
    pub offer_id: Hash32,
    /// `mandate_id` of the buyer mandate the request came with.
    pub mandate_id: Hash32,
    pub agent_key: PublicKey,
}

impl KnownOffer {
    /// From an issued offer (None if its request had no mandate, which a
    /// seller never issues an offer for).
    pub fn of(o: &crate::protocol::IssuedOffer) -> Option<KnownOffer> {
        let m = o.request.mandate.as_ref()?;
        Some(KnownOffer {
            offer_id: o.offer.offer_id(),
            mandate_id: m.mandate_id(),
            agent_key: m.agent_key,
        })
    }
}

impl Wire for DirTransport {
    fn send(&self, msg: &WireMsg) -> Result<(), StoreError> {
        DirTransport::send(self, msg)
    }
    fn receive(&self) -> Result<Inbox, StoreError> {
        DirTransport::receive(self)
    }
    fn ack(&self, name: &str) -> Result<(), StoreError> {
        DirTransport::ack(self, name)
    }
}

/// Messages read from an inbox: file name, and the message or why it did
/// not parse.
pub type Inbox = Vec<(String, Result<WireMsg, String>)>;

/// A directory transport: read from our inbox, write to the peer's.
pub struct DirTransport {
    inbox: PathBuf,
    peer_inbox: PathBuf,
}

impl DirTransport {
    pub fn new(inbox: &Path, peer_inbox: &Path) -> Result<DirTransport, StoreError> {
        for d in [inbox, peer_inbox] {
            fs::create_dir_all(d).map_err(|e| StoreError::Io(d.to_path_buf(), e))?;
        }
        Ok(DirTransport {
            inbox: inbox.to_path_buf(),
            peer_inbox: peer_inbox.to_path_buf(),
        })
    }

    /// Send (or resend) a message.
    pub fn send(&self, msg: &WireMsg) -> Result<(), StoreError> {
        let p = self.peer_inbox.join(format!("{}.json", msg.name()));
        let json = serde_json::to_vec(msg).map_err(|e| StoreError::Json(p.clone(), e))?;
        write_atomic(&p, &json)
    }

    /// Messages waiting in the inbox, oldest name first. A file that does
    /// not parse is returned as an error entry and left for inspection.
    pub fn receive(&self) -> Result<Inbox, StoreError> {
        let mut names: Vec<String> = fs::read_dir(&self.inbox)
            .map_err(|e| StoreError::Io(self.inbox.clone(), e))?
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".json"))
            .collect();
        names.sort();
        let mut out = Vec::new();
        for n in names {
            let p = self.inbox.join(&n);
            let parsed = fs::read(&p)
                .map_err(|e| e.to_string())
                .and_then(|b| serde_json::from_slice::<WireMsg>(&b).map_err(|e| e.to_string()));
            out.push((n, parsed));
        }
        Ok(out)
    }

    /// Delete a handled message.
    pub fn ack(&self, name: &str) -> Result<(), StoreError> {
        let p = self.inbox.join(name);
        match fs::remove_file(&p) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(p, e)),
        }
    }
}
