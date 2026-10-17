//! The priced-model set, read from the rate-card file the metering plane (leria) prices with.
//!
//! A model that no rate-card entry covers books `$0` in leria (the event is rejected as
//! unpriced), so a budget cap would never trip for it. `[llm_proxy] require_priced_model`
//! therefore refuses such a request before any upstream call. The gateway learns the
//! priced set from the SAME file leria reads (`rate_card_path`), not from a runtime call to
//! leria, and reports the file's sha256 fingerprint in `/api/v1/posture` so a deploy check
//! can compare the two planes.
//!
//! Only what coverage needs is parsed from the file (the format is leria's
//! `ratecardconfig`): a card object, or an array of cards, whose `entries` are
//!
//! - `{"model_ref": "<id>", "asset": "tokens", ...prices}`: covers exactly that id;
//! - `{"model_ref_prefix": "<p>", "asset": "tokens", ...prices}`: covers a DATED id, the
//!   prefix followed by `-` or `@` and more text (`claude-haiku-4-5-20251001`,
//!   `model@20251001`). A dated id matches no other way. The prefix itself is not covered
//!   by its own prefix entry (that is an exact entry's job), and `claude-haiku-4-50` is not
//!   `claude-haiku-4-5` plus a date.
//!
//! Entries of any asset other than tokens do not price a model. A token price of zero is
//! refused when the file is read (it would book `$0` for real spend), exactly as leria
//! refuses it, so the two planes cannot disagree about which models are covered.
//!
//! Fail closed: a file that cannot be read or parsed at start is an error (the process
//! does not start with a half-read card); a later change that cannot be parsed keeps the
//! last good card and is reported in posture as `last_error`. With no card configured no
//! model is covered.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::RwLock;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// One parsed card file: the coverage sets and the file's fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateCard {
    exact: Vec<String>,
    prefixes: Vec<String>,
    /// Lower-case hex sha256 of the exact bytes of the file.
    sha256: String,
}

#[derive(Deserialize)]
struct WireCard {
    #[serde(default)]
    entries: Vec<WireEntry>,
}

#[derive(Deserialize)]
struct WireEntry {
    #[serde(default)]
    model_ref: Option<String>,
    #[serde(default)]
    model_ref_prefix: Option<String>,
    #[serde(default)]
    asset: Option<String>,
    #[serde(default)]
    price_micros_per_unit: Option<i64>,
    #[serde(default)]
    input_price_micros_per_unit: Option<i64>,
    #[serde(default)]
    output_price_micros_per_unit: Option<i64>,
}

/// Why a rate-card file was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rate card: {0}")]
pub struct RateCardError(pub String);

impl RateCard {
    /// Parse the bytes of a card file (a card object or an array of cards).
    pub fn parse(bytes: &[u8]) -> Result<Self, RateCardError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| RateCardError("not valid UTF-8".to_string()))?
            .trim();
        if text.is_empty() {
            return Err(RateCardError("the file is empty".to_string()));
        }
        let cards: Vec<WireCard> = if text.starts_with('[') {
            serde_json::from_str(text).map_err(|e| RateCardError(format!("bad JSON: {e}")))?
        } else {
            vec![serde_json::from_str(text).map_err(|e| RateCardError(format!("bad JSON: {e}")))?]
        };
        let mut card = RateCard {
            sha256: hex::encode(Sha256::digest(bytes)),
            ..Self::default()
        };
        for wire in cards {
            for entry in wire.entries {
                card.add(entry)?;
            }
        }
        if card.exact.is_empty() && card.prefixes.is_empty() {
            return Err(RateCardError(
                "no token-priced entries: every model would be refused".to_string(),
            ));
        }
        card.exact.sort();
        card.prefixes.sort();
        Ok(card)
    }

    fn add(&mut self, entry: WireEntry) -> Result<(), RateCardError> {
        let name = match (&entry.model_ref, &entry.model_ref_prefix) {
            (Some(m), None) if !m.is_empty() => m.clone(),
            (None, Some(p)) if !p.is_empty() => p.clone(),
            _ => {
                return Err(RateCardError(
                    "each entry needs exactly one non-empty model_ref or model_ref_prefix"
                        .to_string(),
                ))
            }
        };
        // Only a token price prices an LLM call. Leria rejects a non-token asset on an
        // input/output entry; either way such an entry never covers a model here.
        if entry.asset.as_deref().is_some_and(|a| a != "tokens") {
            return Ok(());
        }
        let prices = [
            entry.price_micros_per_unit,
            entry.input_price_micros_per_unit,
            entry.output_price_micros_per_unit,
        ];
        if prices.iter().flatten().any(|p| *p <= 0) {
            return Err(RateCardError(format!(
                "entry {name:?}: a token price of zero or less would book $0 for real spend"
            )));
        }
        if prices.iter().all(Option::is_none) {
            return Err(RateCardError(format!("entry {name:?} carries no price")));
        }
        if entry.model_ref_prefix.is_some() {
            self.prefixes.push(name);
        } else {
            self.exact.push(name);
        }
        Ok(())
    }

    /// Whether `model` is priced: an exact entry, or a dated id under an explicit prefix.
    pub fn covers(&self, model: &str) -> bool {
        if self.exact.iter().any(|m| m == model) {
            return true;
        }
        self.prefixes.iter().any(|p| dated_under(p, model))
    }

    /// The fingerprint of the file this card was read from.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Number of priced entries (exact and prefix).
    pub fn entries(&self) -> usize {
        self.exact.len() + self.prefixes.len()
    }
}

/// `model` is `prefix` followed by a version boundary (`-` or `@`) and at least one more
/// character.
fn dated_under(prefix: &str, model: &str) -> bool {
    let Some(rest) = model.strip_prefix(prefix) else {
        return false;
    };
    let mut chars = rest.chars();
    matches!(chars.next(), Some('-' | '@')) && chars.next().is_some()
}

/// The model a token meter event is booked under: when a card is configured, the model the
/// provider served if the card prices it, else the model the request named if the card
/// prices that, else (neither covered, or no card) the served model, then the request's, as
/// before. Never `None` when either was known.
pub fn pick_meter_model(
    card: Option<&RateCard>,
    served: Option<&str>,
    requested: Option<&str>,
) -> Option<String> {
    if let Some(card) = card {
        for m in [served, requested].into_iter().flatten() {
            if card.covers(m) {
                return Some(m.to_string());
            }
        }
    }
    served.or(requested).map(str::to_string)
}

#[derive(Debug, Default)]
struct HandleState {
    card: Option<Arc<RateCard>>,
    /// (modified time, length) of the file the card was read from; a change re-reads it.
    stamp: Option<(SystemTime, u64)>,
    last_error: Option<String>,
}

/// The configured rate-card file and the card last read from it, re-read when the file
/// changes. Cheap to clone and share: clones see the same card.
#[derive(Debug, Clone, Default)]
pub struct RateCardHandle {
    path: Option<PathBuf>,
    state: Arc<RwLock<HandleState>>,
}

/// A point-in-time view for the posture report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateCardStatus {
    pub configured: bool,
    pub sha256: Option<String>,
    pub entries: usize,
    pub last_error: Option<String>,
}

impl RateCardHandle {
    /// No card configured: no model is covered.
    pub fn unconfigured() -> Self {
        Self::default()
    }

    /// Read the card at `path`. An unreadable or invalid file is an error: the gateway
    /// must not start with a half-read pricing table.
    pub fn open(path: &Path) -> Result<Self, RateCardError> {
        let (card, stamp) = read_card(path)?;
        Ok(Self {
            path: Some(path.to_path_buf()),
            state: Arc::new(RwLock::new(HandleState {
                card: Some(Arc::new(card)),
                stamp,
                last_error: None,
            })),
        })
    }

    /// Whether a card file is configured (it may still have failed to re-read).
    pub fn is_configured(&self) -> bool {
        self.path.is_some()
    }

    /// The current card, re-read first when the file changed. `None` when no card is
    /// configured. A change that cannot be read or parsed keeps the last good card and is
    /// recorded in [`Self::status`].
    pub fn current(&self) -> Option<Arc<RateCard>> {
        let path = self.path.as_ref()?;
        let now = file_stamp(path);
        {
            let state = self.state.read();
            if state.stamp == now {
                return state.card.clone();
            }
        }
        let mut state = self.state.write();
        if state.stamp != now {
            match read_card(path) {
                Ok((card, stamp)) => {
                    state.card = Some(Arc::new(card));
                    state.stamp = stamp;
                    state.last_error = None;
                }
                Err(e) => {
                    // Keep serving the last good card; remember what is wrong.
                    tracing::error!(error = %e, path = %path.display(), "rate card changed but cannot be used; keeping the previous card");
                    state.last_error = Some(e.0);
                    state.stamp = now;
                }
            }
        }
        state.card.clone()
    }

    /// Whether the current card prices `model`.
    pub fn covers(&self, model: &str) -> bool {
        self.current().is_some_and(|c| c.covers(model))
    }

    pub fn status(&self) -> RateCardStatus {
        let card = self.current();
        let state = self.state.read();
        RateCardStatus {
            configured: self.path.is_some(),
            sha256: card.as_ref().map(|c| c.sha256().to_string()),
            entries: card.as_ref().map_or(0, |c| c.entries()),
            last_error: state.last_error.clone(),
        }
    }
}

fn file_stamp(path: &Path) -> Option<(SystemTime, u64)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

fn read_card(path: &Path) -> Result<(RateCard, Option<(SystemTime, u64)>), RateCardError> {
    // Stamp first: a write that lands between the stamp and the read is picked up on the
    // next check instead of being hidden behind a newer stamp.
    let stamp = file_stamp(path);
    let bytes = std::fs::read(path)
        .map_err(|e| RateCardError(format!("cannot read {}: {e}", path.display())))?;
    Ok((RateCard::parse(&bytes)?, stamp))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD: &str = r#"[{"rate_card_version":"v1","entries":[
        {"model_ref":"claude-opus-5","asset":"tokens","input_price_micros_per_unit":5,"output_price_micros_per_unit":25},
        {"model_ref":"claude-haiku-4-5","asset":"tokens","input_price_micros_per_unit":1,"output_price_micros_per_unit":5},
        {"model_ref_prefix":"claude-haiku-4-5","asset":"tokens","input_price_micros_per_unit":1,"output_price_micros_per_unit":5},
        {"model_ref":"flat","asset":"tokens","price_micros_per_unit":2},
        {"model_ref":"calls","asset":"api-calls","price_micros_per_unit":7}
    ]}]"#;

    fn card() -> RateCard {
        RateCard::parse(CARD.as_bytes()).unwrap()
    }

    #[test]
    fn an_exact_entry_covers_only_that_id() {
        let c = card();
        assert!(c.covers("claude-opus-5"));
        assert!(c.covers("flat"));
        assert!(
            !c.covers("claude-opus-5-20251001"),
            "no prefix entry for opus"
        );
        assert!(!c.covers("claude-opus"));
        assert!(!c.covers("claude-sonnet-5"));
        assert!(!c.covers(""));
    }

    #[test]
    fn a_dated_id_matches_only_through_an_explicit_prefix_entry() {
        let c = card();
        assert!(c.covers("claude-haiku-4-5-20251001"));
        assert!(c.covers("claude-haiku-4-5@20251001"));
        // Not a version boundary, not a longer name of the same model.
        assert!(!c.covers("claude-haiku-4-50"));
        assert!(!c.covers("claude-haiku-4-5x"));
        // The boundary alone is not a dated id.
        assert!(!c.covers("claude-haiku-4-5-"));
        assert!(!c.covers("claude-haiku-4-5@"));
        // A prefix of the prefix is not covered.
        assert!(!c.covers("claude-haiku-4"));
    }

    #[test]
    fn a_prefix_entry_does_not_cover_other_families() {
        let only_prefix = RateCard::parse(
            br#"{"rate_card_version":"p","entries":[{"model_ref_prefix":"m","asset":"tokens","price_micros_per_unit":1}]}"#,
        )
        .unwrap();
        assert!(only_prefix.covers("m-1"));
        assert!(
            !only_prefix.covers("m"),
            "the prefix itself is an exact entry's job"
        );
        assert!(!only_prefix.covers("model-1"));
    }

    #[test]
    fn a_non_token_entry_prices_no_model() {
        assert!(!card().covers("calls"));
    }

    #[test]
    fn a_zero_or_negative_token_price_is_refused() {
        for price in [
            r#""price_micros_per_unit":0"#,
            r#""input_price_micros_per_unit":0,"output_price_micros_per_unit":3"#,
            r#""input_price_micros_per_unit":1,"output_price_micros_per_unit":0"#,
            r#""price_micros_per_unit":-1"#,
        ] {
            let doc = format!(
                r#"{{"rate_card_version":"z","entries":[{{"model_ref":"m","asset":"tokens",{price}}}]}}"#
            );
            assert!(RateCard::parse(doc.as_bytes()).is_err(), "{price}");
        }
    }

    #[test]
    fn a_card_that_prices_nothing_or_is_malformed_is_refused() {
        for doc in [
            "",
            "   ",
            "not json",
            "[]",
            r#"{"rate_card_version":"e","entries":[]}"#,
            r#"[{"rate_card_version":"e","entries":[{"model_ref":"c","asset":"api-calls","price_micros_per_unit":1}]}]"#,
            r#"{"entries":[{"asset":"tokens","price_micros_per_unit":1}]}"#,
            r#"{"entries":[{"model_ref":"a","model_ref_prefix":"a","asset":"tokens","price_micros_per_unit":1}]}"#,
            r#"{"entries":[{"model_ref":"a","asset":"tokens"}]}"#,
        ] {
            assert!(RateCard::parse(doc.as_bytes()).is_err(), "{doc:?}");
        }
    }

    #[test]
    fn the_fingerprint_is_the_sha256_of_the_exact_file_bytes() {
        // Computed independently: `printf %s '<doc>' | sha256sum`.
        let doc = br#"{"entries":[{"model_ref":"a","asset":"tokens","price_micros_per_unit":1}]}"#;
        let c = RateCard::parse(doc).unwrap();
        assert_eq!(c.sha256(), hex::encode(Sha256::digest(doc)));
        assert_eq!(c.sha256().len(), 64);
        // One byte of whitespace changes it: it is the bytes, not the meaning.
        let spaced =
            br#"{"entries":[{"model_ref":"a","asset":"tokens","price_micros_per_unit":1}] }"#;
        assert_ne!(RateCard::parse(spaced).unwrap().sha256(), c.sha256());
    }

    #[test]
    fn pick_prefers_a_priced_served_model_then_a_priced_requested_one() {
        let c = card();
        // Served and priced: the served one.
        assert_eq!(
            pick_meter_model(
                Some(&c),
                Some("claude-haiku-4-5-20251001"),
                Some("claude-opus-5")
            ),
            Some("claude-haiku-4-5-20251001".to_string())
        );
        // Served is not priced: the requested model, which the gate priced.
        assert_eq!(
            pick_meter_model(
                Some(&c),
                Some("claude-opus-5-20251001"),
                Some("claude-opus-5")
            ),
            Some("claude-opus-5".to_string())
        );
        // Neither priced, or no card: the served model, then the requested one, as before.
        assert_eq!(
            pick_meter_model(Some(&c), Some("zzz"), Some("yyy")),
            Some("zzz".to_string())
        );
        assert_eq!(
            pick_meter_model(None, None, Some("yyy")),
            Some("yyy".to_string())
        );
        assert_eq!(pick_meter_model(Some(&c), None, None), None);
    }

    fn write(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
    }

    #[test]
    fn an_unconfigured_handle_covers_nothing() {
        let h = RateCardHandle::unconfigured();
        assert!(!h.is_configured());
        assert!(!h.covers("claude-opus-5"));
        let s = h.status();
        assert!(!s.configured);
        assert_eq!(s.sha256, None);
    }

    #[test]
    fn a_missing_or_invalid_file_is_a_startup_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(RateCardHandle::open(&dir.path().join("nope.json")).is_err());
        let bad = dir.path().join("bad.json");
        write(&bad, "{");
        assert!(RateCardHandle::open(&bad).is_err());
    }

    #[test]
    fn a_changed_file_is_picked_up_and_a_broken_change_keeps_the_last_good_card() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("card.json");
        write(&path, CARD);
        let h = RateCardHandle::open(&path).unwrap();
        assert!(h.covers("claude-opus-5"));
        let first = h.status().sha256.unwrap();

        // A new card with a different set (a longer file, so the stamp differs even when the
        // filesystem's mtime is coarse).
        let next = r#"{"rate_card_version":"v2","entries":[
            {"model_ref":"claude-sonnet-5","asset":"tokens","price_micros_per_unit":3},
            {"model_ref":"claude-sonnet-5-5","asset":"tokens","price_micros_per_unit":3}]}"#;
        write(&path, next);
        assert!(h.covers("claude-sonnet-5"));
        assert!(!h.covers("claude-opus-5"));
        assert_ne!(h.status().sha256.unwrap(), first);
        assert_eq!(h.status().last_error, None);

        // A broken edit: the previous good card keeps serving and the error is reported.
        write(
            &path,
            "{ this is not json at all, and longer than before ......",
        );
        assert!(h.covers("claude-sonnet-5"), "last good card still serves");
        assert!(h.status().last_error.is_some());

        // Fixed again: the error clears.
        write(&path, CARD);
        assert!(h.covers("claude-opus-5"));
        assert_eq!(h.status().last_error, None);
    }
}
