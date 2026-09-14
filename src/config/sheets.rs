//! Operator-pinned Google Sheets targets (plan 106 gate G1b).
//!
//! The typed `sheets` plugin refuses every spreadsheet id and A1 range that is
//! not declared here. These pins are OPERATOR authority parsed from
//! `[[sheets_pins]]` in the vultrino TOML; a request (or a capability schema
//! the model is shown) can only select among them, never widen them.
//!
//! Range spelling is deliberately strict so that comparison is exact:
//! `Sheet!A1:Z100` (cell span) or `Sheet!A:Z` (whole columns). Sheet names are
//! `[A-Za-z0-9_-]` and unquoted; column letters are uppercase; rows are decimal
//! with no leading zero. Everything else (lowercase letters, whitespace, `$`
//! absolute refs, quoted sheet names, a second `!`, R1C1 notation, a bare
//! sheet name, single cells, row-only spans, percent-encoding) is refused.
//! Google Sheets resolves sheet names case-insensitively, so a case-variant
//! spelling is refused rather than normalized.

use std::fmt;

/// Largest row index Google Sheets addresses.
pub const MAX_SHEETS_ROW: u32 = 10_000_000;
const MAX_SHEET_NAME_LEN: usize = 100;
const MAX_SPREADSHEET_ID_LEN: usize = 128;
const MAX_RANGE_LEN: usize = 256;

/// A strictly parsed A1 range on one named sheet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct A1Range {
    sheet: String,
    start_col: u32,
    end_col: u32,
    /// `None` = whole columns (`A:Z`), i.e. rows `1..=MAX_SHEETS_ROW`.
    rows: Option<(u32, u32)>,
}

impl A1Range {
    /// Parse the strict spelling described in the module docs.
    pub fn parse_strict(raw: &str) -> Result<Self, String> {
        if raw.is_empty() || raw.len() > MAX_RANGE_LEN || !raw.is_ascii() {
            return Err("A1 range must be 1-256 ASCII characters".to_string());
        }
        let (sheet, reference) = raw
            .split_once('!')
            .ok_or_else(|| "A1 range must name a sheet as Sheet!A1:B2".to_string())?;
        if sheet.is_empty()
            || sheet.len() > MAX_SHEET_NAME_LEN
            || !sheet
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("A1 range sheet name must be unquoted [A-Za-z0-9_-]".to_string());
        }
        let (start, end) = reference
            .split_once(':')
            .ok_or_else(|| "A1 range must be a span Start:End".to_string())?;
        let (start_col, start_row) = parse_endpoint(start)?;
        let (end_col, end_row) = parse_endpoint(end)?;
        let rows = match (start_row, end_row) {
            (Some(a), Some(b)) => Some((a, b)),
            (None, None) => None,
            _ => {
                return Err(
                    "A1 range must be a cell span (A1:B2) or a column span (A:B)".to_string(),
                )
            }
        };
        if start_col > end_col || rows.is_some_and(|(a, b)| a > b) {
            return Err("A1 range start must not be after its end".to_string());
        }
        Ok(Self {
            sheet: sheet.to_string(),
            start_col,
            end_col,
            rows,
        })
    }

    /// A single-row cell span on `sheet`, used for adapter-derived writes.
    pub fn row_span(sheet: &str, start_col: u32, end_col: u32, row: u32) -> Self {
        Self {
            sheet: sheet.to_string(),
            start_col,
            end_col,
            rows: Some((row, row)),
        }
    }

    pub fn sheet(&self) -> &str {
        &self.sheet
    }

    pub fn first_row(&self) -> u32 {
        self.rows.map_or(1, |(a, _)| a)
    }

    pub fn last_row(&self) -> u32 {
        self.rows.map_or(MAX_SHEETS_ROW, |(_, b)| b)
    }

    pub fn first_col(&self) -> u32 {
        self.start_col
    }

    /// Whether `other` lies entirely inside `self` (same sheet, byte-exact).
    pub fn contains(&self, other: &A1Range) -> bool {
        self.sheet == other.sheet
            && self.start_col <= other.start_col
            && other.end_col <= self.end_col
            && self.first_row() <= other.first_row()
            && other.last_row() <= self.last_row()
    }
}

impl fmt::Display for A1Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let start = column_letters(self.start_col);
        let end = column_letters(self.end_col);
        match self.rows {
            Some((a, b)) => write!(f, "{}!{start}{a}:{end}{b}", self.sheet),
            None => write!(f, "{}!{start}:{end}", self.sheet),
        }
    }
}

fn parse_endpoint(raw: &str) -> Result<(u32, Option<u32>), String> {
    let letters = raw.bytes().take_while(u8::is_ascii_uppercase).count();
    if letters == 0 || letters > 3 {
        return Err("A1 range endpoint must start with 1-3 uppercase column letters".to_string());
    }
    let col = raw[..letters]
        .bytes()
        .fold(0u32, |acc, b| acc * 26 + u32::from(b - b'A' + 1));
    let digits = &raw[letters..];
    if digits.is_empty() {
        return Ok((col, None));
    }
    if !digits.bytes().all(|b| b.is_ascii_digit()) || digits.starts_with('0') {
        return Err("A1 range row must be a decimal number with no leading zero".to_string());
    }
    let row = digits
        .parse::<u32>()
        .ok()
        .filter(|row| (1..=MAX_SHEETS_ROW).contains(row))
        .ok_or_else(|| "A1 range row is out of bounds".to_string())?;
    Ok((col, Some(row)))
}

fn column_letters(mut col: u32) -> String {
    let mut out = Vec::new();
    while col > 0 {
        let rem = (col - 1) % 26;
        out.push(b'A' + rem as u8);
        col = (col - 1) / 26;
    }
    out.reverse();
    String::from_utf8(out).expect("column letters are ASCII")
}

/// One operator-pinned spreadsheet and the exact ranges each action class may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SheetsPin {
    /// Exact spreadsheet id, `[A-Za-z0-9_-]{1,128}`, compared byte-for-byte.
    pub spreadsheet_id: String,
    /// Ranges `sheets.read` may name (exact match). Adapter-internal reads
    /// (the append lineage read of `Sources`) must lie inside one of these.
    pub read_ranges: Vec<A1Range>,
    /// Ranges `sheets.append_draft` / `sheets.revise_draft` may name (exact
    /// match). A revision's derived row write must lie inside the named range.
    pub write_ranges: Vec<A1Range>,
}

impl SheetsPin {
    /// Validate one pin. Fail-closed: an unusable pin is an operator error.
    pub fn parse(
        spreadsheet_id: &str,
        read_ranges: &[&str],
        write_ranges: &[&str],
    ) -> Result<Self, String> {
        if spreadsheet_id.is_empty()
            || spreadsheet_id.len() > MAX_SPREADSHEET_ID_LEN
            || !spreadsheet_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(
                "sheets_pins: spreadsheet_id must be [A-Za-z0-9_-], 1-128 characters".to_string(),
            );
        }
        let parse_all = |kind: &str, raw: &[&str]| -> Result<Vec<A1Range>, String> {
            let mut out: Vec<A1Range> = Vec::with_capacity(raw.len());
            for entry in raw {
                let range = A1Range::parse_strict(entry).map_err(|e| {
                    format!("sheets_pins '{spreadsheet_id}': {kind} entry {entry:?}: {e}")
                })?;
                if out.contains(&range) {
                    return Err(format!(
                        "sheets_pins '{spreadsheet_id}': duplicate {kind} entry {entry:?}"
                    ));
                }
                out.push(range);
            }
            Ok(out)
        };
        let read_ranges = parse_all("read_ranges", read_ranges)?;
        let write_ranges = parse_all("write_ranges", write_ranges)?;
        if read_ranges.is_empty() && write_ranges.is_empty() {
            return Err(format!(
                "sheets_pins '{spreadsheet_id}': declare at least one read_ranges or write_ranges entry"
            ));
        }
        Ok(Self {
            spreadsheet_id: spreadsheet_id.to_string(),
            read_ranges,
            write_ranges,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parser_accepts_only_canonical_spellings() {
        for ok in [
            "Pipeline!A1:Z100",
            "Pipeline!A:Z",
            "Brand_2-x!AA10:ZZZ20",
            "S!A1:A1",
        ] {
            let range = A1Range::parse_strict(ok).unwrap();
            assert_eq!(range.to_string(), ok, "canonical round-trip");
        }
        for bad in [
            "",
            "Pipeline",
            "pipeline!a1:z100",
            "Pipeline!a:z",
            " Pipeline!A1:Z100",
            "Pipeline!A1:Z100 ",
            "Pipeline!A1: Z100",
            "'Pipeline'!A1:Z100",
            "Pipe line!A1:Z100",
            "Pipeline!$A$1:$Z$100",
            "Pipeline!A1:Z100!X",
            "A!B!C1:D2",
            "Pipeline!R1C1:R100C26",
            "Pipeline!A1",
            "Pipeline!1:100",
            "Pipeline!A1:Z",
            "Pipeline!A01:Z100",
            "Pipeline!Z1:A100",
            "Pipeline!A100:Z1",
            "Pipeline!AAAA1:Z2",
            "Pipeline!A0:Z1",
            "Pipeline!A1:Z10000001",
            "Pipeline!A1:Z100:AA200",
            "Pipeline%21A1%3AZ100",
            "Pipelin\u{e9}!A1:Z1",
        ] {
            assert!(
                A1Range::parse_strict(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn containment_is_sheet_exact_and_bounded() {
        let columns = A1Range::parse_strict("Pipeline!A:Z").unwrap();
        assert!(columns.contains(&A1Range::row_span("Pipeline", 1, 23, 9_999)));
        assert!(!columns.contains(&A1Range::row_span("pipeline", 1, 23, 2)));
        assert!(!columns.contains(&A1Range::parse_strict("Pipeline!A:AA").unwrap()));
        let cells = A1Range::parse_strict("Sources!A1:Z100").unwrap();
        assert!(cells.contains(&A1Range::parse_strict("Sources!A1:F100").unwrap()));
        assert!(!cells.contains(&A1Range::parse_strict("Sources!A1:F101").unwrap()));
        assert!(!cells.contains(&A1Range::parse_strict("Sources!A:F").unwrap()));
    }

    #[test]
    fn pin_validation_fails_closed() {
        let none: [&str; 0] = [];
        assert!(SheetsPin::parse("", &["S!A:B"], &none).is_err());
        assert!(SheetsPin::parse("id/../x", &["S!A:B"], &none).is_err());
        assert!(SheetsPin::parse("id", &none, &none).is_err());
        assert!(SheetsPin::parse("id", &["s!a:b"], &none).is_err());
        assert!(SheetsPin::parse("id", &["S!A:B", "S!A:B"], &none).is_err());
        assert!(SheetsPin::parse("id", &none, &["S!A:B"]).is_ok());
    }

    #[test]
    fn config_load_rejects_bad_pins_and_defaults_to_no_pins() {
        use crate::config::Config;
        assert!(Config::parse("").unwrap().sheets_pins.is_empty());
        for bad in [
            "[[sheets_pins]]\nspreadsheet_id = \"\"\nread_ranges = [\"S!A:B\"]\n",
            "[[sheets_pins]]\nspreadsheet_id = \"id\"\n",
            "[[sheets_pins]]\nspreadsheet_id = \"id\"\nread_ranges = [\" S!A:B\"]\n",
            "[[sheets_pins]]\nspreadsheet_id = \"id\"\nwrite_ranges = [\"S!R1C1:R2C2\"]\n",
            "[[sheets_pins]]\nspreadsheet_id = \"id\"\nread_ranges = [\"S!A:B\"]\nranges = [\"S!A:Z\"]\n",
            "[[sheets_pins]]\nspreadsheet_id = \"id\"\nread_ranges = [\"S!A:B\"]\n\
             [[sheets_pins]]\nspreadsheet_id = \"id\"\nread_ranges = [\"S!A:C\"]\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad:?} must fail config load");
        }
        let ok = Config::parse(
            "[[sheets_pins]]\nspreadsheet_id = \"id\"\nread_ranges = [\"S!A1:B2\"]\nwrite_ranges = [\"P!A:Z\"]\n",
        )
        .unwrap();
        assert_eq!(ok.sheets_pins.len(), 1);
        assert_eq!(ok.sheets_pins[0].write_ranges[0].to_string(), "P!A:Z");
    }
}
