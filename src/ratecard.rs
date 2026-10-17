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
//! refused when the file is read (it would book `$0` for real spend), as leria refuses it.
//!
//! The parser mirrors leria's `ratecardconfig` strictness: an unknown field (a typo such as
//! `output_price_micros_per_unti`) is an error, `rate_card_version` is required and unique,
//! an entry that uses the input/output form needs both prices, and so on. A file one plane
//! refuses the other refuses too, except that this parser is the stricter where the two
//! differ (it refuses, never accepts, more).
//!
//! The two planes read the file at different times, so they CAN disagree about coverage for
//! a while: leria reads it only at start, this gateway also re-reads it when it changes. A
//! model added to the file after leria started is covered here but unpriced there, and every
//! call for it would book `$0`. So a change may only NARROW coverage: the gateway serves the
//! intersection of the card it read at start (what leria loaded at the same time, when both
//! started from one file) and the latest good file, until it restarts. `sha256` stays the
//! start card's fingerprint (what the posture comparison with leria needs) and
//! `file_sha256` reports the file as it is now, so a drift is visible. Narrowing is the safe
//! direction: a model dropped from the file is refused here at once; a model added is refused
//! until both planes restart on the new file.
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
    /// When set, a model is covered only if this card covers it too (a reloaded card is
    /// narrowed by the card read at start; see the module doc).
    limit: Option<Box<RateCard>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCard {
    #[serde(default)]
    rate_card_version: String,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    entries: Vec<WireEntry>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    stale_after_s: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
        let mut versions = std::collections::HashSet::new();
        for wire in cards {
            let version = wire.rate_card_version.clone();
            if version.is_empty() {
                return Err(RateCardError(
                    "a rate card is missing rate_card_version".to_string(),
                ));
            }
            if !versions.insert(version.clone()) {
                return Err(RateCardError(format!(
                    "rate card version {version:?} appears twice (versions are immutable)"
                )));
            }
            if wire.entries.is_empty() {
                return Err(RateCardError(format!(
                    "rate card {version:?} has no entries"
                )));
            }
            if let Some(created) = wire.created_at.as_deref().map(str::trim) {
                if !created.is_empty() && chrono::DateTime::parse_from_rfc3339(created).is_err() {
                    return Err(RateCardError(format!(
                        "rate card {version:?}: created_at {created:?} is not RFC3339"
                    )));
                }
            }
            let _ = (&wire.provider, wire.stale_after_s);
            // As leria: an entry that uses the input/output form, or a prefix, makes the
            // whole card the per-direction kind, which is tokens-only.
            let per_direction = wire.entries.iter().any(|e| {
                e.input_price_micros_per_unit.is_some()
                    || e.output_price_micros_per_unit.is_some()
                    || e.model_ref_prefix.as_deref().is_some_and(|p| !p.is_empty())
            });
            let mut seen = std::collections::HashSet::new();
            for entry in wire.entries {
                card.add(&version, per_direction, &mut seen, entry)?;
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

    fn add(
        &mut self,
        version: &str,
        per_direction: bool,
        seen: &mut std::collections::HashSet<(bool, String)>,
        entry: WireEntry,
    ) -> Result<(), RateCardError> {
        let model_ref = entry.model_ref.as_deref().filter(|m| !m.is_empty());
        let prefix = entry.model_ref_prefix.as_deref().filter(|p| !p.is_empty());
        let (is_prefix, name) = match (model_ref, prefix) {
            (Some(m), None) => (false, m.to_string()),
            (None, Some(p)) => (true, p.to_string()),
            _ => {
                return Err(RateCardError(
                    "each entry needs exactly one non-empty model_ref or model_ref_prefix"
                        .to_string(),
                ))
            }
        };
        if !seen.insert((is_prefix, name.clone())) {
            return Err(RateCardError(format!(
                "rate card {version:?}: duplicate entry for {name:?}"
            )));
        }
        let is_tokens = entry
            .asset
            .as_deref()
            .is_none_or(|a| a == "tokens" || a.is_empty());
        if per_direction {
            if !is_tokens {
                return Err(RateCardError(format!(
                    "rate card {version:?} entry {name:?}: input/output pricing is tokens-only (asset={:?})",
                    entry.asset.as_deref().unwrap_or("")
                )));
            }
            // Both directions, or a single price and no direction (leria's rule); a
            // one-sided input/output price is an error.
            let both = entry.input_price_micros_per_unit.is_some()
                && entry.output_price_micros_per_unit.is_some();
            let single = entry.price_micros_per_unit.is_some()
                && entry.input_price_micros_per_unit.is_none()
                && entry.output_price_micros_per_unit.is_none();
            if !both && !single {
                return Err(RateCardError(format!(
                    "rate card {version:?} entry {name:?}: needs BOTH input_price_micros_per_unit and output_price_micros_per_unit, or a single price_micros_per_unit"
                )));
            }
        } else if entry.price_micros_per_unit.is_none() {
            return Err(RateCardError(format!(
                "rate card {version:?} entry {name:?}: price_micros_per_unit is required (or use input_/output_price_micros_per_unit)"
            )));
        }
        // Only a token price prices an LLM call: a symmetric entry of another asset is
        // valid in the file but never covers a model here.
        if !is_tokens {
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
        if is_prefix {
            self.prefixes.push(name);
        } else {
            self.exact.push(name);
        }
        Ok(())
    }

    /// Whether `model` is priced: an exact entry, or a dated id under an explicit prefix.
    pub fn covers(&self, model: &str) -> bool {
        if self.limit.as_ref().is_some_and(|l| !l.covers(model)) {
            return false;
        }
        if self.exact.iter().any(|m| m == model) {
            return true;
        }
        self.prefixes.iter().any(|p| dated_under(p, model))
    }

    /// This card narrowed by `start`: covers only what both cover. Keeps `start`'s
    /// fingerprint (the card the metering plane loaded), see the module doc.
    fn narrowed_by(&self, start: &RateCard) -> RateCard {
        RateCard {
            exact: self.exact.clone(),
            prefixes: self.prefixes.clone(),
            sha256: start.sha256.clone(),
            limit: Some(Box::new(start.clone())),
        }
    }

    /// The fingerprint of the file this card was read from.
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Number of priced entries (exact and prefix).
    pub fn entries(&self) -> usize {
        match &self.limit {
            Some(start) => start.entries(),
            None => self.exact.len() + self.prefixes.len(),
        }
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

/// The model a token meter event is booked under. The model the provider served is what
/// is billed, so it is booked whenever the card prices it. The requested id stands in only
/// when the served id is a DATED form of it (`requested` followed by `-` or `@` and more
/// text) and the card prices the requested one: that is the alias-to-snapshot case. A served
/// model that is some other model (an upstream that ignored or overrode the requested one)
/// is booked under its own id even when the card does not price it, so leria counts it as
/// unpriced and holds its watermark instead of booking the requested model's price. With no
/// card the served model, then the requested one. Never `None` when either was known.
pub fn pick_meter_model(
    card: Option<&RateCard>,
    served: Option<&str>,
    requested: Option<&str>,
) -> Option<String> {
    let (Some(card), Some(served)) = (card, served) else {
        return served.or(requested).map(str::to_string);
    };
    if card.covers(served) {
        return Some(served.to_string());
    }
    if let Some(req) = requested {
        if dated_under(req, served) && card.covers(req) {
            return Some(req.to_string());
        }
    }
    Some(served.to_string())
}

#[derive(Debug, Default)]
struct HandleState {
    /// The card read when the handle was opened, never replaced.
    start: Option<Arc<RateCard>>,
    /// What is served: the start card, or the latest good file narrowed by it.
    card: Option<Arc<RateCard>>,
    /// Fingerprint of the latest good file (the start card's until the file changes).
    file_sha256: Option<String>,
    /// (modified time, length) of the file the card was read from; a change re-reads it.
    stamp: Option<(SystemTime, u64)>,
    last_error: Option<String>,
}

/// The configured rate-card file and the card last read from it, re-read when the file
/// changes. A change can only narrow what is covered (see the module doc). Cheap to clone
/// and share: clones see the same card.
#[derive(Debug, Clone, Default)]
pub struct RateCardHandle {
    path: Option<PathBuf>,
    state: Arc<RwLock<HandleState>>,
}

/// A point-in-time view for the posture report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateCardStatus {
    pub configured: bool,
    /// Fingerprint of the card read at start (what the metering plane loaded).
    pub sha256: Option<String>,
    /// Fingerprint of the file as last read successfully; differs from `sha256` after the
    /// file changed, when coverage is the intersection of the two.
    pub file_sha256: Option<String>,
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
        let card = Arc::new(card);
        Ok(Self {
            path: Some(path.to_path_buf()),
            state: Arc::new(RwLock::new(HandleState {
                start: Some(Arc::clone(&card)),
                file_sha256: Some(card.sha256().to_string()),
                card: Some(card),
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
    /// configured. A change that cannot be read or parsed keeps the previous card and is
    /// recorded in [`Self::status`]. A readable change never widens coverage past the card
    /// read at start.
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
                Ok((latest, stamp)) => {
                    let start = state.start.clone();
                    state.file_sha256 = Some(latest.sha256().to_string());
                    state.card = Some(match start {
                        Some(start) if start.sha256() != latest.sha256() => {
                            Arc::new(latest.narrowed_by(&start))
                        }
                        Some(start) => start,
                        None => Arc::new(latest),
                    });
                    state.stamp = stamp;
                    state.last_error = None;
                }
                Err(e) => {
                    // Keep serving the previous card; remember what is wrong.
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
            file_sha256: state.file_sha256.clone(),
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
        {"model_ref":"flat","asset":"tokens","price_micros_per_unit":2}
    ]},
    {"rate_card_version":"v1-calls","entries":[
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
        let doc = br#"{"rate_card_version":"f","entries":[{"model_ref":"a","asset":"tokens","price_micros_per_unit":1}]}"#;
        let c = RateCard::parse(doc).unwrap();
        assert_eq!(c.sha256(), hex::encode(Sha256::digest(doc)));
        assert_eq!(c.sha256().len(), 64);
        // One byte of whitespace changes it: it is the bytes, not the meaning.
        let spaced =
            br#"{"rate_card_version":"f","entries":[{"model_ref":"a","asset":"tokens","price_micros_per_unit":1}] }"#;
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

    #[test]
    fn a_different_served_model_is_booked_under_its_own_id_not_the_requested_ones() {
        let c = card();
        // The upstream served Opus (not on the card) for a request that named Haiku: it is
        // booked under the served id, so leria counts it unpriced and holds its watermark,
        // instead of booking Haiku's price for Opus spend.
        assert_eq!(
            pick_meter_model(
                Some(&c),
                Some("claude-opus-4-1-20250805"),
                Some("claude-haiku-4-5")
            ),
            Some("claude-opus-4-1-20250805".to_string())
        );
        // A name that merely starts with the requested id is not a dated form of it.
        assert_eq!(
            pick_meter_model(Some(&c), Some("claude-opus-5x"), Some("claude-opus-5")),
            Some("claude-opus-5x".to_string())
        );
        // A dated form whose requested id the card does not price stays under the served id.
        assert_eq!(
            pick_meter_model(Some(&c), Some("zzz-20250101"), Some("zzz")),
            Some("zzz-20250101".to_string())
        );
        // The `@` boundary is a dated form too.
        assert_eq!(
            pick_meter_model(
                Some(&c),
                Some("claude-opus-5@20251001"),
                Some("claude-opus-5")
            ),
            Some("claude-opus-5".to_string())
        );
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

    const WIDER: &str = r#"[{"rate_card_version":"v2","entries":[
        {"model_ref":"claude-opus-5","asset":"tokens","input_price_micros_per_unit":5,"output_price_micros_per_unit":25},
        {"model_ref":"claude-haiku-4-5","asset":"tokens","input_price_micros_per_unit":1,"output_price_micros_per_unit":5},
        {"model_ref_prefix":"claude-haiku-4-5","asset":"tokens","input_price_micros_per_unit":1,"output_price_micros_per_unit":5},
        {"model_ref":"flat","asset":"tokens","price_micros_per_unit":2},
        {"model_ref":"claude-sonnet-5","asset":"tokens","price_micros_per_unit":3}]}]"#;

    const NARROWER: &str = r#"{"rate_card_version":"v3","entries":[
        {"model_ref":"claude-haiku-4-5","asset":"tokens","price_micros_per_unit":3}]}"#;

    #[test]
    fn a_reloaded_card_can_only_narrow_what_the_start_card_covered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("card.json");
        write(&path, CARD);
        let h = RateCardHandle::open(&path).unwrap();
        let start = h.status().sha256.unwrap();
        assert!(h.covers("claude-opus-5"));
        assert!(!h.covers("claude-sonnet-5"));

        // A model ADDED to the file is not covered: the metering plane loaded the start
        // card and cannot price it, so every call for it would book $0.
        write(&path, WIDER);
        assert!(!h.covers("claude-sonnet-5"), "an added model stays refused");
        assert!(h.covers("claude-opus-5"));
        assert!(h.covers("claude-haiku-4-5-20251001"));
        let s = h.status();
        assert_eq!(
            s.sha256.as_deref(),
            Some(start.as_str()),
            "start fingerprint"
        );
        assert_ne!(
            s.file_sha256.as_deref(),
            Some(start.as_str()),
            "file fingerprint"
        );
        assert_eq!(s.last_error, None);

        // A model REMOVED is refused at once.
        write(&path, NARROWER);
        assert!(h.covers("claude-haiku-4-5"));
        assert!(!h.covers("claude-opus-5"), "a removed model is refused");
        assert!(
            !h.covers("claude-haiku-4-5-20251001"),
            "its prefix entry went too"
        );
        assert!(!h.covers("claude-sonnet-5"));
        assert_eq!(h.status().sha256.as_deref(), Some(start.as_str()));

        // The file back to the start content: the start coverage again, one fingerprint.
        write(&path, CARD);
        assert!(h.covers("claude-opus-5"));
        assert!(h.covers("flat"));
        assert!(!h.covers("claude-sonnet-5"));
        let s = h.status();
        assert_eq!(s.file_sha256.as_deref(), Some(start.as_str()));
    }

    #[test]
    fn a_broken_change_keeps_the_previous_card_and_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("card.json");
        write(&path, CARD);
        let h = RateCardHandle::open(&path).unwrap();
        write(&path, NARROWER);
        assert!(!h.covers("claude-opus-5"));

        // A broken edit: the previous card keeps serving and the error is reported.
        write(
            &path,
            "{ this is not json at all, and longer than before ......",
        );
        assert!(h.covers("claude-haiku-4-5"), "previous card still serves");
        assert!(!h.covers("claude-opus-5"), "and stays narrowed");
        assert!(h.status().last_error.is_some());

        // Fixed again: the error clears.
        write(&path, CARD);
        assert!(h.covers("claude-opus-5"));
        assert_eq!(h.status().last_error, None);
    }

    #[test]
    fn the_parser_refuses_what_leria_refuses() {
        let entry = r#"{"model_ref":"m","asset":"tokens","price_micros_per_unit":1}"#;
        let bad = [
            // An unknown field (a typo of a price field), on an entry and on the card.
            r#"{"rate_card_version":"a","entries":[{"model_ref":"m","asset":"tokens","input_price_micros_per_unit":1,"output_price_micros_per_unti":5}]}"#,
            r#"{"rate_card_version":"a","entires":[],"entries":[{"model_ref":"m","asset":"tokens","price_micros_per_unit":1}]}"#,
            // A missing or empty version.
            r#"{"entries":[{"model_ref":"m","asset":"tokens","price_micros_per_unit":1}]}"#,
            r#"{"rate_card_version":"","entries":[{"model_ref":"m","asset":"tokens","price_micros_per_unit":1}]}"#,
            // A one-sided asymmetric price.
            r#"{"rate_card_version":"a","entries":[{"model_ref":"m","asset":"tokens","input_price_micros_per_unit":1}]}"#,
            r#"{"rate_card_version":"a","entries":[{"model_ref":"m","asset":"tokens","output_price_micros_per_unit":1}]}"#,
            // An entry with no price in a symmetric card.
            r#"{"rate_card_version":"a","entries":[{"model_ref":"m","asset":"tokens"}]}"#,
            // A non-token entry in a card that uses the per-direction form or a prefix.
            r#"{"rate_card_version":"a","entries":[{"model_ref":"m","asset":"tokens","input_price_micros_per_unit":1,"output_price_micros_per_unit":2},{"model_ref":"c","asset":"api-calls","price_micros_per_unit":1}]}"#,
            r#"{"rate_card_version":"a","entries":[{"model_ref_prefix":"m","asset":"tokens","price_micros_per_unit":1},{"model_ref":"c","asset":"api-calls","price_micros_per_unit":1}]}"#,
            // A duplicate entry, and a version used twice.
            r#"{"rate_card_version":"a","entries":[{"model_ref":"m","asset":"tokens","price_micros_per_unit":1},{"model_ref":"m","asset":"tokens","price_micros_per_unit":2}]}"#,
            // A created_at that is not RFC3339.
            r#"{"rate_card_version":"a","created_at":"yesterday","entries":[{"model_ref":"m","asset":"tokens","price_micros_per_unit":1}]}"#,
        ];
        for doc in bad {
            assert!(RateCard::parse(doc.as_bytes()).is_err(), "{doc}");
        }
        let twice = format!(
            r#"[{{"rate_card_version":"a","entries":[{entry}]}},{{"rate_card_version":"a","entries":[{entry}]}}]"#
        );
        assert!(RateCard::parse(twice.as_bytes()).is_err());
        // The optional fields leria knows are accepted.
        let ok = r#"{"rate_card_version":"a","provider":"anthropic","created_at":"2026-10-17T00:00:00Z","stale_after_s":3600,"entries":[{"model_ref":"m","asset":"tokens","price_micros_per_unit":1}]}"#;
        assert!(RateCard::parse(ok.as_bytes()).is_ok());
    }
}
