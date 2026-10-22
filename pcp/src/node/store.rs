//! A role's state directory: the agent key, the mandate, and one state file
//! holding both the protocol state and the principal log.
//!
//! Layout:
//!
//! ```text
//! <dir>/lock           advisory lock: one process per directory
//! <dir>/agent.key      agent secret key seed, hex (mode 0600)
//! <dir>/mandate.json   the mandate the principal signed for that key
//! <dir>/state.json     protocol state + principal log (mode 0600), replaced
//!                      atomically after every step
//! <dir>/log.jsonl      the principal log, exported after every step (a
//!                      copy for the principal; state.json is authoritative)
//! ```
//!
//! State and log live in one file so they can never disagree: a crash
//! leaves either the old file or the new one, never a sale recorded in one
//! and not the other. The state file contains `k` (seller) or the result
//! `R` (buyer): treat the directory like a Lightning node's macaroons.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::mandate::{Agent, LogEntry, Mandate, PrincipalLog, SecretKey};

/// Errors from the state directory.
#[derive(Debug)]
pub enum StoreError {
    Io(PathBuf, std::io::Error),
    Json(PathBuf, serde_json::Error),
    /// Another process holds this directory.
    Locked(PathBuf),
    /// A file is missing or malformed (agent key, mandate).
    Bad(PathBuf, String),
    /// The peer refused the message in a way asking again cannot cure
    /// (HTTP 4xx other than 408, 422 and 429).
    Peer(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            StoreError::Json(p, e) => write!(f, "{}: {e}", p.display()),
            StoreError::Locked(p) => write!(f, "{}: in use by another process", p.display()),
            StoreError::Bad(p, m) => write!(f, "{}: {m}", p.display()),
            StoreError::Peer(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for StoreError {}

fn io(p: &Path) -> impl FnOnce(std::io::Error) -> StoreError + '_ {
    move |e| StoreError::Io(p.to_path_buf(), e)
}

/// Write `bytes` to `path` atomically: a temporary file in the same
/// directory, flushed to disk, renamed over `path`, then the directory
/// flushed so the rename itself survives a crash.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = path.with_extension("tmp");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(io(&tmp))?;
        restrict(&f);
        f.write_all(bytes).map_err(io(&tmp))?;
        f.sync_all().map_err(io(&tmp))?;
    }
    fs::rename(&tmp, path).map_err(io(path))?;
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io(dir))?;
    Ok(())
}

#[cfg(unix)]
fn restrict(f: &File) {
    use std::os::unix::fs::PermissionsExt;
    let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict(_: &File) {}

/// A role's state directory, locked for this process.
pub struct StateDir {
    dir: PathBuf,
    /// Held for the life of the value; the OS drops the lock when the
    /// process dies, so a killed process never blocks its restart.
    _lock: File,
}

impl StateDir {
    /// Open (creating it if needed) and lock a state directory. Fails if
    /// another live process holds the lock.
    pub fn open(dir: &Path) -> Result<StateDir, StoreError> {
        fs::create_dir_all(dir).map_err(io(dir))?;
        let lock_path = dir.join("lock");
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(io(&lock_path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(StoreError::Locked(dir.to_path_buf()))
            }
            Err(std::fs::TryLockError::Error(e)) => return Err(StoreError::Io(lock_path, e)),
        }
        Ok(StateDir {
            dir: dir.to_path_buf(),
            _lock: lock,
        })
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }

    /// Store the agent key and its mandate (setup, once).
    pub fn init_agent(&self, key: &SecretKey, mandate: &Mandate) -> Result<(), StoreError> {
        write_atomic(
            &self.dir.join("agent.key"),
            format!("{}\n", hex::encode(key.to_seed())).as_bytes(),
        )?;
        let m = self.dir.join("mandate.json");
        let json =
            serde_json::to_vec_pretty(mandate).map_err(|e| StoreError::Json(m.clone(), e))?;
        write_atomic(&m, &json)
    }

    /// The agent key and mandate stored by [`StateDir::init_agent`].
    pub fn agent_key_and_mandate(&self) -> Result<(SecretKey, Mandate), StoreError> {
        let kp = self.dir.join("agent.key");
        let text = fs::read_to_string(&kp).map_err(io(&kp))?;
        let seed: [u8; 32] = hex::decode(text.trim())
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| StoreError::Bad(kp.clone(), "not a 32-byte hex seed".into()))?;
        let mp = self.dir.join("mandate.json");
        let mandate: Mandate =
            read_json(&mp)?.ok_or_else(|| StoreError::Bad(mp.clone(), "missing".into()))?;
        Ok((SecretKey::from_seed(seed), mandate))
    }

    /// The saved state, if any.
    pub fn load<T: DeserializeOwned>(&self) -> Result<Option<Saved<T>>, StoreError> {
        read_json(&self.dir.join("state.json"))
    }

    /// Replace the saved state, then export the log for the principal.
    pub fn save<T: Serialize>(&self, state: &T, agent: &Agent) -> Result<(), StoreError> {
        let log = agent.log();
        let saved = SavedRef {
            schema: STATE_SCHEMA,
            agent_key: hex::encode(agent.public_key()),
            mandate_id: hex::encode(agent.mandate_id()),
            state,
            log: log.entries(),
        };
        let p = self.dir.join("state.json");
        let json = serde_json::to_vec(&saved).map_err(|e| StoreError::Json(p.clone(), e))?;
        write_atomic(&p, &json)?;
        write_atomic(&self.dir.join("log.jsonl"), log.to_jsonl().as_bytes())
    }
}

/// Version of `state.json`.
pub const STATE_SCHEMA: u32 = 1;

/// What `state.json` holds.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Saved<T> {
    pub schema: u32,
    /// The agent this state belongs to (hex), checked on load.
    pub agent_key: String,
    pub mandate_id: String,
    pub state: T,
    pub log: Vec<LogEntry>,
}

#[derive(Serialize)]
struct SavedRef<'a, T> {
    schema: u32,
    agent_key: String,
    mandate_id: String,
    state: &'a T,
    log: &'a [LogEntry],
}

impl<T> Saved<T> {
    /// Refuse a state written by another agent or under another mandate, or
    /// in another schema (the files were mixed up or restored wrongly).
    pub fn check(&self, key: &SecretKey, mandate: &Mandate) -> Result<(), String> {
        if self.schema != STATE_SCHEMA {
            return Err(format!(
                "state schema {} (expected {STATE_SCHEMA})",
                self.schema
            ));
        }
        if self.agent_key != hex::encode(key.public_key()) {
            return Err("state belongs to another agent key".into());
        }
        if self.mandate_id != hex::encode(mandate.mandate_id()) {
            return Err("state belongs to another mandate".into());
        }
        Ok(())
    }

    pub fn log(&self) -> PrincipalLog {
        PrincipalLog::from_entries(self.log.clone())
    }
}

fn read_json<T: DeserializeOwned>(p: &Path) -> Result<Option<T>, StoreError> {
    match fs::read(p) {
        Ok(b) => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| StoreError::Json(p.to_path_buf(), e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError::Io(p.to_path_buf(), e)),
    }
}

/// Write a JSON value atomically (results, reports).
pub fn write_json<T: Serialize>(p: &Path, v: &T) -> Result<(), StoreError> {
    let json = serde_json::to_vec_pretty(v).map_err(|e| StoreError::Json(p.to_path_buf(), e))?;
    write_atomic(p, &json)
}
