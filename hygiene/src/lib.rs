//! Credential hygiene for one machine: which credentials are reused, and
//! which have gone unrotated too long — without storing or printing any.
//!
//! See `fingerprint` for exactly what "zero knowledge" does and does not
//! mean here.

pub mod audit;
pub mod extract;
pub mod fingerprint;
pub mod state;

/// `YYYY-MM-DD` for a Unix timestamp, without a date crate.
/// (Howard Hinnant's civil-from-days.)
#[must_use]
pub fn ymd(unix: u64) -> String {
    let z = (unix / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    #[test]
    fn dates_are_right_across_leap_years() {
        assert_eq!(super::ymd(0), "1970-01-01");
        assert_eq!(super::ymd(951_782_400), "2000-02-29");
        assert_eq!(super::ymd(1_790_208_000), "2026-09-24");
    }
}
