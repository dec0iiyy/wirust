//! UTC wall-clock formatting without a date-time dependency.

use std::time::{SystemTime, UNIX_EPOCH};

/// A UTC calendar date and time of day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Utc {
    pub(crate) year: i64,
    pub(crate) month: u32,
    pub(crate) day: u32,
    pub(crate) hour: u32,
    pub(crate) minute: u32,
    pub(crate) second: u32,
    pub(crate) millis: u32,
}

impl Utc {
    pub(crate) fn now() -> Self {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = i64::try_from(since.as_secs()).unwrap_or(i64::MAX);
        Self::from_unix(secs, since.subsec_millis())
    }

    /// Converts seconds since the Unix epoch, using Howard Hinnant's `civil_from_days`.
    pub(crate) fn from_unix(secs: i64, millis: u32) -> Self {
        let days = secs.div_euclid(86_400);
        let of_day = u32::try_from(secs.rem_euclid(86_400)).unwrap_or(0);
        let z = days + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z.rem_euclid(146_097);
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
        let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
        let year = yoe + era * 400 + i64::from(month <= 2);
        Self {
            year,
            month,
            day,
            hour: of_day / 3600,
            minute: of_day / 60 % 60,
            second: of_day % 60,
            millis,
        }
    }

    /// The same time of day on the previous calendar day.
    pub(crate) fn day_before(self) -> Self {
        let (year, month, day) = match (self.month, self.day) {
            (1, 1) => (self.year - 1, 12, 31),
            (month, 1) => (self.year, month - 1, days_in_month(self.year, month - 1)),
            (month, day) => (self.year, month, day - 1),
        };
        Self {
            year,
            month,
            day,
            ..self
        }
    }

    /// `2026-11-21T12:01:02.345Z`.
    pub(crate) fn rfc3339(self) -> String {
        let Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            millis,
        } = self;
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
    }
}

/// Days in `month` (1 to 12) of `year`, Gregorian.
fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_known_instants() {
        assert_eq!(Utc::from_unix(0, 0).rfc3339(), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            Utc::from_unix(1_709_210_096, 7).rfc3339(),
            "2024-02-29T12:34:56.007Z"
        );
    }
}
