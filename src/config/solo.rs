//! Operator-pinned Google targets for the typed `solo` plugin.
//!
//! The `solo` adapter already pins its Sheets A1 ranges to compiled constants
//! (Cohorts, Learners, Attendance, Knowledge). These pins close the other half:
//! the spreadsheet id and Calendar id a request may name. They are OPERATOR
//! authority parsed from `[solo_pins]` in the vultrino TOML; a request can only
//! select among them, never widen them.
//!
//! This section is deliberately separate from `[[sheets_pins]]` (the marketing
//! `sheets` plugin): a marketing pin never authorizes a solo call and a solo pin
//! never authorizes a marketing call, even when both name the same spreadsheet.
//! Learner spreadsheet ids and Calendar ids are also separate lists, so a
//! spreadsheet pin never authorizes a Calendar id (or the reverse).
//!
//! Comparison is byte-exact; values are validated at load with no trimming and
//! no case folding. Empty lists (the default) refuse every call of that family.

/// Maximum pinned spreadsheet id length (matches `[[sheets_pins]]`).
const MAX_SPREADSHEET_ID_LEN: usize = 128;
/// Maximum pinned Calendar id length (matches the adapter's request bound).
const MAX_CALENDAR_ID_LEN: usize = 512;

/// Validated solo pins. `Default` = nothing pinned = every Sheets and Calendar
/// call through the `solo` plugin is refused.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SoloPins {
    /// Spreadsheet ids `solo.learner_read` / `solo.attendance_update` may name.
    pub learner_spreadsheet_ids: Vec<String>,
    /// Calendar ids the `solo.session_*` / `solo.availability_check` actions may name.
    pub calendar_ids: Vec<String>,
}

impl SoloPins {
    /// Validate operator pins. Fail-closed: an unusable pin is a load error.
    pub fn parse(
        learner_spreadsheet_ids: &[String],
        calendar_ids: &[String],
    ) -> Result<Self, String> {
        let mut spreadsheets: Vec<String> = Vec::with_capacity(learner_spreadsheet_ids.len());
        for id in learner_spreadsheet_ids {
            if id.is_empty()
                || id.len() > MAX_SPREADSHEET_ID_LEN
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(format!(
                    "solo_pins: learner_spreadsheet_ids entry {id:?} must be [A-Za-z0-9_-], 1-128 characters"
                ));
            }
            if spreadsheets.contains(id) {
                return Err(format!(
                    "solo_pins: duplicate learner_spreadsheet_ids entry {id:?}"
                ));
            }
            spreadsheets.push(id.clone());
        }
        let mut calendars: Vec<String> = Vec::with_capacity(calendar_ids.len());
        for id in calendar_ids {
            if id.is_empty()
                || id.len() > MAX_CALENDAR_ID_LEN
                || !id.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'@' | b'+')
                })
            {
                return Err(format!(
                    "solo_pins: calendar_ids entry {id:?} must be [A-Za-z0-9_.@+-], 1-512 characters"
                ));
            }
            if calendars.contains(id) {
                return Err(format!("solo_pins: duplicate calendar_ids entry {id:?}"));
            }
            calendars.push(id.clone());
        }
        Ok(Self {
            learner_spreadsheet_ids: spreadsheets,
            calendar_ids: calendars,
        })
    }

    /// Byte-exact membership of a learner spreadsheet id.
    pub fn allows_learner_spreadsheet(&self, spreadsheet_id: &str) -> bool {
        self.learner_spreadsheet_ids
            .iter()
            .any(|pinned| pinned.as_bytes() == spreadsheet_id.as_bytes())
    }

    /// Byte-exact membership of a Calendar id.
    pub fn allows_calendar(&self, calendar_id: &str) -> bool {
        self.calendar_ids
            .iter()
            .any(|pinned| pinned.as_bytes() == calendar_id.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| (*v).to_string()).collect()
    }

    #[test]
    fn pin_validation_fails_closed_and_matches_byte_exact() {
        for bad in ["", "id/../x", "id ", " id", "id%2F", "id\u{e9}"] {
            assert!(
                SoloPins::parse(&strings(&[bad]), &[]).is_err(),
                "spreadsheet {bad:?} must be refused"
            );
        }
        for bad in [
            "",
            "cal id",
            "cal/events",
            "cal?x",
            "cal#x",
            "cal%40x",
            "cal\0",
        ] {
            assert!(
                SoloPins::parse(&[], &strings(&[bad])).is_err(),
                "calendar {bad:?} must be refused"
            );
        }
        assert!(SoloPins::parse(&strings(&["a", "a"]), &[]).is_err());
        assert!(SoloPins::parse(&[], &strings(&["c@x", "c@x"])).is_err());

        let pins = SoloPins::parse(
            &strings(&["solo-learner-fixture"]),
            &strings(&["team.cal+1@group.calendar.google.com"]),
        )
        .unwrap();
        assert!(pins.allows_learner_spreadsheet("solo-learner-fixture"));
        assert!(!pins.allows_learner_spreadsheet("Solo-learner-fixture"));
        assert!(!pins.allows_learner_spreadsheet("solo-learner-fixture "));
        assert!(!pins.allows_calendar("solo-learner-fixture"));
        assert!(pins.allows_calendar("team.cal+1@group.calendar.google.com"));
        assert!(!pins.allows_learner_spreadsheet("team.cal+1@group.calendar.google.com"));
        assert!(!SoloPins::default().allows_learner_spreadsheet("solo-learner-fixture"));
        assert!(!SoloPins::default().allows_calendar(""));
    }

    #[test]
    fn config_load_rejects_bad_solo_pins_and_defaults_to_none() {
        assert_eq!(Config::parse("").unwrap().solo_pins, SoloPins::default());
        for bad in [
            "[solo_pins]\nlearner_spreadsheet_ids = [\"\"]\n",
            "[solo_pins]\nlearner_spreadsheet_ids = [\" id\"]\n",
            "[solo_pins]\ncalendar_ids = [\"a b\"]\n",
            "[solo_pins]\ncalendar_ids = [\"c@x\", \"c@x\"]\n",
            "[solo_pins]\nspreadsheet_ids = [\"id\"]\n",
            "[solo_pins]\nlearner_spreadsheet_ids = \"id\"\n",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad:?} must fail config load");
        }
        let ok = Config::parse(
            "[solo_pins]\nlearner_spreadsheet_ids = [\"solo-learner-fixture\"]\ncalendar_ids = [\"solo-calendar-fixture\"]\n",
        )
        .unwrap();
        assert_eq!(
            ok.solo_pins.learner_spreadsheet_ids,
            ["solo-learner-fixture"]
        );
        assert_eq!(ok.solo_pins.calendar_ids, ["solo-calendar-fixture"]);
    }
}
