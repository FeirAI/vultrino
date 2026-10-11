//! The vault's write-ahead log and per-record change tracking (P3-VAULT).
//!
//! Before v10 every admin write re-serialized, re-encrypted and fsynced the WHOLE vault, and every
//! dispatch fence read decrypted the whole vault under the exclusive lock. v10 keeps the vault file
//! as a snapshot and records each committed mutation as one small encrypted record appended to a
//! sidecar log (`<vault>.wal`), so a write costs the records it changed and a read costs only the
//! records appended since this process last looked.
//!
//! ## Format
//!
//! One line per committed mutation: `{"seq":N,"nonce":"..","ct":".."}\n`. `seq` is cleartext so a
//! record already folded into the snapshot (`seq <= applied_seq`) is skipped without being
//! decrypted (a re-keyed vault can leave old-key records in the log); it is repeated inside the
//! authenticated plaintext and the two must agree. The plaintext is `{"seq":N,"ops":[..]}` where each
//! op puts or deletes one record of one collection, sets the kill epoch, or replaces the small
//! "misc" block (the intent-staging queue and the legacy v6 outbox fields).
//!
//! ## Commit and recovery rules
//!
//! * A mutation is committed when its line has been written and the log file fsynced, under the
//!   exclusive cross-process lock. Readers hold the lock too, so they never see a half-written line
//!   except after a crash.
//! * Sequence numbers are contiguous. A gap, a duplicate or an out-of-order record is corruption and
//!   fails the open closed.
//! * An unterminated final fragment is a torn append from a crash (it was never acknowledged). A
//!   reader ignores it; the next exclusive writer truncates it before appending. A newline-
//!   terminated line that fails to parse or authenticate is NOT treated as torn: it fails closed.
//! * Compaction writes a new snapshot (tmp, fsync, rename, directory fsync) stamped with the last
//!   sequence it folded in, then replaces the log with an empty one. A crash between the two leaves
//!   a log whose records are all `<= applied_seq`, which replay skips.

use super::StorageError;
use crate::crypto::{decrypt, encrypt, EncryptedData, MasterKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::Deref;

/// Collection name of the kill-fence marks in the log (the other names are the cache field names).
pub(super) const KILL_MARKS: &str = "kill_marks";

/// A map of records that remembers which keys were touched since the last commit, and what each
/// held before the first touch, so a commit can write only the changed records and an aborted
/// mutation can be rolled back without cloning the whole collection.
///
/// Reads go through `Deref<Target = HashMap>`. There is deliberately no `DerefMut`: every mutation
/// goes through a method here that records the touch.
#[derive(Debug, Serialize, Deserialize)]
#[serde(
    transparent,
    bound(serialize = "V: Serialize", deserialize = "V: Deserialize<'de>")
)]
pub(super) struct Tracked<V> {
    map: HashMap<String, V>,
    #[serde(skip)]
    touched: HashMap<String, Option<V>>,
}

impl<V> Default for Tracked<V> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            touched: HashMap::new(),
        }
    }
}

impl<V> Deref for Tracked<V> {
    type Target = HashMap<String, V>;
    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<'a, V> IntoIterator for &'a Tracked<V> {
    type Item = (&'a String, &'a V);
    type IntoIter = std::collections::hash_map::Iter<'a, String, V>;
    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

impl<V> Tracked<V> {
    /// Wrap an existing map with no changes recorded (legacy-format load).
    pub(super) fn from_map(map: HashMap<String, V>) -> Self {
        Self {
            map,
            touched: HashMap::new(),
        }
    }
}

impl<V: Clone> Tracked<V> {
    fn touch(&mut self, key: &str) {
        if !self.touched.contains_key(key) {
            let pre = self.map.get(key).cloned();
            self.touched.insert(key.to_string(), pre);
        }
    }

    pub(super) fn insert(&mut self, key: String, value: V) -> Option<V> {
        self.touch(&key);
        self.map.insert(key, value)
    }

    pub(super) fn remove(&mut self, key: &str) -> Option<V> {
        self.touch(key);
        self.map.remove(key)
    }

    pub(super) fn get_mut(&mut self, key: &str) -> Option<&mut V> {
        if self.map.contains_key(key) {
            self.touch(key);
        }
        self.map.get_mut(key)
    }

    /// Remove every record `keep` rejects, touching only those.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&String, &V) -> bool) {
        let doomed: Vec<String> = self
            .map
            .iter()
            .filter(|(k, v)| !keep(k, v))
            .map(|(k, _)| k.clone())
            .collect();
        for k in doomed {
            self.remove(&k);
        }
    }

    /// Insert without recording a touch: applying a record that is already durable.
    pub(super) fn insert_clean(&mut self, key: String, value: V) {
        self.map.insert(key, value);
    }

    /// Remove without recording a touch: applying a record that is already durable.
    pub(super) fn remove_clean(&mut self, key: &str) {
        self.map.remove(key);
    }

    /// The records this mutation changed: `Some(value)` to put, `None` to delete. A key that was
    /// absent before and is absent now (inserted then removed) is not a change.
    pub(super) fn changes(&self) -> Vec<(&String, Option<&V>)> {
        let mut out = Vec::new();
        for (k, pre) in &self.touched {
            let cur = self.map.get(k);
            if cur.is_none() && pre.is_none() {
                continue;
            }
            out.push((k, cur));
        }
        out
    }

    /// Forget the touch record: the changes are durable.
    pub(super) fn commit(&mut self) {
        self.touched.clear();
    }

    /// Undo every change since the last commit.
    pub(super) fn rollback(&mut self) {
        for (k, pre) in self.touched.drain() {
            match pre {
                Some(v) => {
                    self.map.insert(k, v);
                }
                None => {
                    self.map.remove(&k);
                }
            }
        }
    }
}

/// One change to the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub(super) enum Op {
    Put {
        c: String,
        k: String,
        v: serde_json::Value,
    },
    Del {
        c: String,
        k: String,
    },
    KillEpoch {
        epoch: u64,
    },
    Misc {
        v: serde_json::Value,
    },
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    seq: u64,
    nonce: String,
    ct: String,
}

#[derive(Serialize, Deserialize)]
struct Plain {
    seq: u64,
    ops: Vec<Op>,
}

/// Encode one committed mutation as a log line (newline-terminated).
pub(super) fn encode_record(
    seq: u64,
    ops: Vec<Op>,
    key: &MasterKey,
) -> Result<Vec<u8>, StorageError> {
    let plain = crate::with_vault_secret_serialization(|| serde_json::to_vec(&Plain { seq, ops }))
        .map_err(|e| StorageError::Serialization(e.to_string()))?;
    let enc = encrypt(&plain, key)?;
    let env = Envelope {
        seq,
        nonce: enc.nonce,
        ct: enc.ciphertext,
    };
    let mut line =
        serde_json::to_vec(&env).map_err(|e| StorageError::Serialization(e.to_string()))?;
    line.push(b'\n');
    Ok(line)
}

/// The records read from a log region.
pub(super) struct ParsedLog {
    /// `(seq, ops)` for every record newer than the floor, in order.
    pub records: Vec<(u64, Vec<Op>)>,
    /// Bytes of the region consumed by complete lines (including skipped ones).
    pub consumed: usize,
    /// The region ends in an unterminated fragment (a torn append).
    pub torn_tail: bool,
    /// Plaintext bytes decrypted, for the I/O accounting.
    pub decrypted_bytes: u64,
    /// How many records were decrypted.
    pub decrypts: u64,
}

fn corrupt(msg: impl Into<String>) -> StorageError {
    StorageError::Serialization(format!("vault log is corrupt: {}", msg.into()))
}

/// Parse a log region. `applied_seq` is the last sequence already reflected in the caller's state:
/// lines at or below it are skipped undecrypted, and the first newer one must be `applied_seq + 1`.
pub(super) fn parse_log(
    region: &[u8],
    applied_seq: u64,
    key: &MasterKey,
) -> Result<ParsedLog, StorageError> {
    let mut out = ParsedLog {
        records: Vec::new(),
        consumed: 0,
        torn_tail: false,
        decrypted_bytes: 0,
        decrypts: 0,
    };
    let mut next = applied_seq + 1;
    let mut pos = 0usize;
    while pos < region.len() {
        let Some(nl) = region[pos..].iter().position(|b| *b == b'\n') else {
            out.torn_tail = true;
            break;
        };
        let line = &region[pos..pos + nl];
        let env: Envelope = serde_json::from_slice(line)
            .map_err(|e| corrupt(format!("unparseable record at byte {pos}: {e}")))?;
        pos += nl + 1;
        out.consumed = pos;
        if env.seq <= applied_seq {
            continue;
        }
        if env.seq != next {
            return Err(corrupt(format!(
                "expected record {next}, found {} (gap, duplicate or reorder)",
                env.seq
            )));
        }
        let plain = decrypt(
            &EncryptedData {
                nonce: env.nonce,
                ciphertext: env.ct,
            },
            key,
        )?;
        out.decrypts += 1;
        out.decrypted_bytes += plain.len() as u64;
        let p: Plain = serde_json::from_slice(&plain)
            .map_err(|e| corrupt(format!("record {} plaintext: {e}", env.seq)))?;
        if p.seq != env.seq {
            return Err(corrupt(format!(
                "record {} carries inner sequence {}",
                env.seq, p.seq
            )));
        }
        out.records.push((env.seq, p.ops));
        next += 1;
    }
    Ok(out)
}
