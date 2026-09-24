//! What the scanner remembers between runs: where each credential lives,
//! its keyed fingerprint, and since when that fingerprint has held.
//!
//! This is how "has this been rotated?" gets an answer without anyone
//! recording a rotation. When a location's fingerprint changes, the secret
//! there was replaced, and the date of the change is a real rotation date.
//! Until one is seen, the scanner only knows a lower bound — "unchanged for
//! AT LEAST this long" — and says so rather than inventing a date.
//!
//! Format: one line per location, tab-separated,
//! `location  fingerprint  since  exact`, written 0600 via a rename so a
//! crash never leaves half a file.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub fingerprint: String,
    /// Unix seconds this fingerprint was first seen at this location.
    pub since: u64,
    /// True when `since` is an OBSERVED rotation. False when it is merely
    /// the day tracking began, so it only bounds the age from below.
    pub exact: bool,
}

#[derive(Debug, Default)]
pub struct State {
    pub entries: BTreeMap<String, Entry>,
}

impl State {
    /// Load, treating a missing file as a first run. A corrupt line is
    /// dropped rather than trusted — at worst that location's history
    /// restarts, which under-reports age; it never over-reports it.
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        let mut entries = BTreeMap::new();
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 4 || f[1].len() != 64 {
                continue;
            }
            let Ok(since) = f[2].parse() else { continue };
            entries.insert(
                f[0].to_owned(),
                Entry {
                    fingerprint: f[1].to_owned(),
                    since,
                    exact: f[3] == "1",
                },
            );
        }
        Self { entries }
    }

    /// Record what a location holds now, and return its entry.
    ///
    /// Same fingerprint as before: history continues untouched. A new
    /// fingerprint at a known location is a rotation, dated now and marked
    /// exact. A location never seen before starts a lower-bound record.
    pub fn observe(&mut self, location: &str, fingerprint: &str, now: u64) -> Entry {
        let entry = match self.entries.get(location) {
            Some(e) if e.fingerprint == fingerprint => e.clone(),
            Some(_) => Entry {
                fingerprint: fingerprint.to_owned(),
                since: now,
                exact: true,
            },
            None => Entry {
                fingerprint: fingerprint.to_owned(),
                since: now,
                exact: false,
            },
        };
        self.entries.insert(location.to_owned(), entry.clone());
        entry
    }

    /// Keep only the locations `keep` accepts. The caller decides what is
    /// really gone: a deleted file should stop lingering, but a location
    /// that simply could not be seen this run must keep its history.
    pub fn retain(&mut self, keep: impl Fn(&str) -> bool) {
        self.entries.retain(|k, _| keep(k));
    }

    /// Write atomically, owner-only.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let tmp = path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        for (loc, e) in &self.entries {
            writeln!(
                f,
                "{loc}\t{}\t{}\t{}",
                e.fingerprint,
                e.since,
                u8::from(e.exact)
            )
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        }
        f.sync_all()
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    #[test]
    fn a_first_sighting_is_a_lower_bound_not_a_rotation() {
        let mut s = State::default();
        let e = s.observe("env:/x#K", FP_A, 1000);
        assert_eq!((e.since, e.exact), (1000, false));
    }

    #[test]
    fn an_unchanged_secret_keeps_its_history() {
        let mut s = State::default();
        s.observe("env:/x#K", FP_A, 1000);
        let e = s.observe("env:/x#K", FP_A, 9000);
        assert_eq!(
            (e.since, e.exact),
            (1000, false),
            "must not reset on a re-scan"
        );
    }

    #[test]
    fn a_changed_fingerprint_is_an_observed_rotation() {
        let mut s = State::default();
        s.observe("env:/x#K", FP_A, 1000);
        let e = s.observe("env:/x#K", FP_B, 5000);
        assert_eq!((e.since, e.exact), (5000, true));
    }

    #[test]
    fn state_round_trips_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("hyg-st-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("state");
        let mut s = State::default();
        s.observe("env:/x#K", FP_A, 1000);
        s.observe("file:/y", FP_B, 2000);
        s.save(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let back = State::load(&p);
        assert_eq!(back.entries, s.entries);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_line_is_dropped_not_trusted() {
        let dir = std::env::temp_dir().join(format!("hyg-cor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("state");
        std::fs::write(
            &p,
            format!("good\t{FP_A}\t1000\t0\nbad-line\nshort\tabc\t1\t0\n"),
        )
        .unwrap();
        let s = State::load(&p);
        assert_eq!(s.entries.len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
