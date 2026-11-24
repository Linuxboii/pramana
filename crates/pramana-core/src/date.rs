//! §7.6 — Dates become integers.
//!
//! A date of birth is encoded as `D = days since 1900-01-01` (proleptic Gregorian).
//! Arithmetic uses Howard Hinnant's `days_from_civil` / `civil_from_days`
//! algorithms, which are exact for all representable years and have no
//! dependence on locale or system time zone.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Days between 1970-01-01 and 1900-01-01 (negative): `days_from_civil(1900,1,1)`.
const EPOCH_1900_FROM_UNIX: i64 = -25_567;

/// A calendar date (proleptic Gregorian), years 1..=9999.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Date {
    y: i32,
    m: u8,
    d: u8,
}

/// Error from constructing or parsing a [`Date`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid date: {0}")]
pub struct DateError(pub String);

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(y) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Days since 1970-01-01 for a civil date (Hinnant).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m as i64 + 9) % 12; // March = 0
    let doy = (153 * mp + 2) / 5 + d as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// Civil date for a count of days since 1970-01-01 (Hinnant).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

impl Date {
    /// Construct and validate a date.
    pub fn new(y: i32, m: u32, d: u32) -> Result<Self, DateError> {
        if !(1..=9999).contains(&y) {
            return Err(DateError(format!("year {y} out of range 1..=9999")));
        }
        if !(1..=12).contains(&m) {
            return Err(DateError(format!("month {m} out of range")));
        }
        if d == 0 || d > days_in_month(y as i64, m) {
            return Err(DateError(format!("day {d} invalid for {y:04}-{m:02}")));
        }
        Ok(Date {
            y,
            m: m as u8,
            d: d as u8,
        })
    }

    /// Parse strict ISO-8601 `YYYY-MM-DD`.
    pub fn parse(s: &str) -> Result<Self, DateError> {
        let b = s.as_bytes();
        if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
            return Err(DateError(format!("expected YYYY-MM-DD, got {s:?}")));
        }
        let num = |r: std::ops::Range<usize>| -> Result<u32, DateError> {
            let part = &s[r];
            if !part.bytes().all(|c| c.is_ascii_digit()) {
                return Err(DateError(format!("non-digit in {s:?}")));
            }
            part.parse::<u32>()
                .map_err(|_| DateError(format!("bad number in {s:?}")))
        };
        Date::new(num(0..4)? as i32, num(5..7)?, num(8..10)?)
    }

    /// Year.
    pub fn year(&self) -> i32 {
        self.y
    }
    /// Month 1..=12.
    pub fn month(&self) -> u32 {
        self.m as u32
    }
    /// Day of month.
    pub fn day(&self) -> u32 {
        self.d as u32
    }

    /// `D`: days since the 1900-01-01 epoch (negative before it).
    pub fn days_since_epoch(&self) -> i64 {
        days_from_civil(self.y as i64, self.m as u32, self.d as u32) - EPOCH_1900_FROM_UNIX
    }

    /// Inverse of [`Date::days_since_epoch`].
    pub fn from_days_since_epoch(n: i64) -> Result<Self, DateError> {
        let (y, m, d) = civil_from_days(n + EPOCH_1900_FROM_UNIX);
        if !(1..=9999).contains(&y) {
            return Err(DateError(format!("day count {n} out of range")));
        }
        Date::new(y as i32, m, d)
    }

    /// The UTC calendar date containing the given Unix timestamp.
    pub fn from_unix_seconds(secs: u64) -> Self {
        let days = (secs / 86_400) as i64;
        let (y, m, d) = civil_from_days(days);
        Date::new(y as i32, m, d).expect("unix timestamps map to valid dates")
    }

    /// The same calendar day `years` years earlier. 29 February maps to 28 February
    /// in non-leap years. Consequence for age cutoffs: on 2026-02-28 the 18-year cutoff
    /// is 2008-02-28, so someone born on 29 Feb 2008 reaches 18 on 1 March 2026 (the
    /// common legal convention; see docs/PROTOCOL.md).
    pub fn minus_years(&self, years: u32) -> Self {
        let y = (self.y as i64 - years as i64).max(1);
        let d = (self.d as u32).min(days_in_month(y, self.m as u32));
        Date::new(y as i32, self.m as u32, d).expect("clamped date is valid")
    }
}

impl fmt::Display for Date {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04}-{:02}-{:02}", self.y, self.m, self.d)
    }
}

impl std::str::FromStr for Date {
    type Err = DateError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Date::parse(s)
    }
}

impl Serialize for Date {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Date {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Date::parse(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_zero() {
        assert_eq!(Date::new(1900, 1, 1).unwrap().days_since_epoch(), 0);
        assert_eq!(Date::new(1900, 1, 2).unwrap().days_since_epoch(), 1);
        assert_eq!(Date::new(1970, 1, 1).unwrap().days_since_epoch(), 25_567);
    }

    #[test]
    fn known_values() {
        // 1900 is not a leap year; 2000 is.
        assert_eq!(Date::new(1901, 1, 1).unwrap().days_since_epoch(), 365);
        assert_eq!(
            Date::new(2001, 1, 1).unwrap().days_since_epoch()
                - Date::new(2000, 1, 1).unwrap().days_since_epoch(),
            366
        );
    }

    #[test]
    fn roundtrip_many() {
        for n in (-1000..80_000).step_by(7) {
            let d = Date::from_days_since_epoch(n).unwrap();
            assert_eq!(d.days_since_epoch(), n, "{d}");
            assert_eq!(Date::parse(&d.to_string()).unwrap(), d);
        }
    }

    #[test]
    fn parse_rejects_garbage() {
        for s in [
            "2001-02-30",
            "2001-13-01",
            "2001-1-01",
            "20010101",
            "abcd-ef-gh",
            "2001-02-29",
            "0000-01-01",
            "+001-01-01",
        ] {
            assert!(Date::parse(s).is_err(), "{s}");
        }
        assert!(Date::parse("2000-02-29").is_ok());
    }

    #[test]
    fn minus_years_leap_day() {
        let d = Date::parse("2026-02-28").unwrap();
        assert_eq!(d.minus_years(18).to_string(), "2008-02-28");
        let leap = Date::parse("2028-02-29").unwrap();
        assert_eq!(leap.minus_years(18).to_string(), "2010-02-28");
        assert_eq!(leap.minus_years(4).to_string(), "2024-02-29");
    }

    #[test]
    fn from_unix() {
        assert_eq!(Date::from_unix_seconds(0).to_string(), "1970-01-01");
        assert_eq!(
            Date::from_unix_seconds(1_795_564_800).to_string(),
            "2026-11-25"
        );
    }
}
