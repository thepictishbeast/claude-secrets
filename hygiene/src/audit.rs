//! Reuse and age, from fingerprints and dates alone.

use crate::extract::{extract, Kind};
use crate::fingerprint::Pepper;
use crate::state::State;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const DAY: u64 = 86_400;

/// What to scan, read from a small config file.
///
/// ```text
/// # kind    path     (a * is allowed in the last path component only)
/// env       /srv/secrets/*.env
/// file      /srv/secrets/*.token
/// ini       /etc/asterisk/pjsip.conf
/// wg        /etc/wireguard/*.conf
/// shadow    /etc/shadow
/// stale-days 180
/// same      wg:/etc/wireguard/wg0.conf#PrivateKey file:/etc/wireguard/server.key
/// ```
#[derive(Debug)]
pub struct Config {
    pub sources: Vec<(Kind, String)>,
    pub shadow: Option<PathBuf>,
    pub stale_days: u64,
    /// Locations that hold one credential on purpose: a key file and the
    /// config that embeds it, or both ends of one API key. A reuse group
    /// inside one of these is expected; the group falling out of step is
    /// a half-finished rotation, and that is what gets reported.
    pub same: Vec<Vec<String>>,
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut cfg = Self {
            sources: Vec::new(),
            shadow: None,
            stale_days: 180,
            same: Vec::new(),
        };
        for (n, line) in text.lines().enumerate() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let mut it = l.split_whitespace();
            let (Some(kind), Some(arg)) = (it.next(), it.next()) else {
                return Err(format!("line {}: expected `<kind> <path>`", n + 1));
            };
            if kind == "same" {
                let group: Vec<String> =
                    std::iter::once(arg).chain(it).map(str::to_owned).collect();
                if group.len() < 2 {
                    return Err(format!(
                        "line {}: `same` needs at least two locations",
                        n + 1
                    ));
                }
                cfg.same.push(group);
                continue;
            }
            if it.next().is_some() {
                return Err(format!("line {}: unexpected text after the path", n + 1));
            }
            match kind {
                "env" => cfg.sources.push((Kind::Env, arg.to_owned())),
                "file" => cfg.sources.push((Kind::File, arg.to_owned())),
                "ini" => cfg.sources.push((Kind::IniPassword, arg.to_owned())),
                "wg" => cfg.sources.push((Kind::WireGuard, arg.to_owned())),
                "shadow" => cfg.shadow = Some(PathBuf::from(arg)),
                "stale-days" => {
                    cfg.stale_days = arg
                        .parse()
                        .map_err(|_| format!("line {}: stale-days needs a number", n + 1))?;
                }
                other => return Err(format!("line {}: unknown kind `{other}`", n + 1)),
            }
        }
        Ok(cfg)
    }
}

/// Whether `pattern` (a path whose LAST component may hold one `*`) names
/// `path`. The one matcher behind both `expand` and pruning, so what a scan
/// looks at and what it may forget cannot disagree.
fn names(pattern: &str, path: &Path) -> bool {
    let p = Path::new(pattern);
    if p.parent() != path.parent() {
        return false;
    }
    let (Some(want), Some(got)) = (
        p.file_name().and_then(|n| n.to_str()),
        path.file_name().and_then(|n| n.to_str()),
    ) else {
        return false;
    };
    match want.split_once('*') {
        None => got == want,
        Some((pre, post)) => {
            got.len() >= pre.len() + post.len() && got.starts_with(pre) && got.ends_with(post)
        }
    }
}

/// Expand a path whose LAST component may contain one `*`.
#[must_use]
pub fn expand(pattern: &str) -> Vec<PathBuf> {
    let p = Path::new(pattern);
    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if !name.contains('*') {
        return if p.is_file() {
            vec![p.to_path_buf()]
        } else {
            Vec::new()
        };
    }
    let dir = p.parent().unwrap_or(Path::new("/"));
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = rd
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|path| path.is_file() && names(pattern, path))
        .collect();
    out.sort();
    out
}

/// Whether this run could actually look where `pattern` points.
///
/// "Matched nothing" alone cannot tell a deleted file from a place that
/// is not there right now. The directory can: absent or unreadable means a
/// pool still locked at boot; EMPTY means an unmounted dataset's bare
/// mountpoint. A directory holding other files, but not this one, means the
/// file really is gone.
fn could_look(pattern: &str) -> bool {
    let dir = Path::new(pattern).parent().unwrap_or(Path::new("/"));
    std::fs::read_dir(dir).is_ok_and(|mut entries| entries.next().is_some())
}

/// `(kind word, file path)` of a location such as `env:/p/.env#KEY`.
fn location_file(loc: &str) -> Option<(&str, &Path)> {
    let (kind, rest) = loc.split_once(':')?;
    Some((kind, Path::new(rest.split('#').next()?)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// One credential found in more than one place.
    Reused {
        label: String,
        locations: Vec<String>,
    },
    /// Not rotated within the limit. `exact` means the date is an observed
    /// rotation; otherwise `days` is only a lower bound.
    Stale {
        location: String,
        days: u64,
        exact: bool,
    },
    /// A system account whose password is older than the limit.
    ShadowStale { user: String, days: u64 },
    /// Locations declared `same` that no longer hold one credential:
    /// changed in one place and not the others. `(label, location)` pairs,
    /// so the report shows which copies still agree.
    Drift { copies: Vec<(String, String)> },
    /// A location named in a `same` line that holds no credential now.
    Missing { location: String },
    /// A configured source that matched nothing, so the report is blind
    /// to it. Reported, because a moved directory otherwise shrinks the
    /// audit without anyone noticing.
    Uncovered { source: String },
    /// Several different secrets found under one location name, so none
    /// of them can be tracked. A reader bug, surfaced rather than absorbed.
    Ambiguous { location: String },
}

impl Finding {
    /// What makes a finding the same finding tomorrow: everything except
    /// an age, which grows daily and would otherwise re-notify every day.
    #[must_use]
    pub fn identity(&self) -> String {
        match self {
            Self::Stale {
                location, exact, ..
            } => format!("stale {location} {exact}"),
            Self::ShadowStale { user, .. } => format!("shadow {user}"),
            other => format!("{other:?}"),
        }
    }
}

/// What one configured source actually reached.
#[derive(Debug)]
pub struct Coverage {
    pub source: String,
    pub files: usize,
    pub secrets: usize,
    /// Names of matched files that yielded nothing. Usually a placeholder,
    /// sometimes a format the reader does not understand -- which is how a
    /// whole `KEY: value` file once went unscanned without a word.
    pub empty: Vec<String>,
}

#[derive(Debug)]
pub struct Outcome {
    pub findings: Vec<Finding>,
    pub credentials: usize,
    pub locations: usize,
    /// Reuse groups that sit inside a `same` declaration.
    pub declared: usize,
    pub coverage: Vec<Coverage>,
}

fn kind_word(kind: &Kind) -> &'static str {
    match kind {
        Kind::Env => "env",
        Kind::File => "file",
        Kind::IniPassword => "ini",
        Kind::WireGuard => "wg",
    }
}

/// Run the whole audit. `now` is injected so ages are testable.
pub fn run(cfg: &Config, pepper: &Pepper, state: &mut State, now: u64) -> Outcome {
    let mut by_fp: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut fp_at: BTreeMap<String, String> = BTreeMap::new();
    let mut present = BTreeSet::new();
    let mut stale = Vec::new();
    let mut blind = Vec::new();
    let mut ambiguous = BTreeSet::new();
    let mut coverage = Vec::new();
    let mut unseen: Vec<(&str, &str)> = Vec::new();

    for (kind, pattern) in &cfg.sources {
        let source = format!("{} {pattern}", kind_word(kind));
        let files = expand(pattern);
        if files.is_empty() {
            if !could_look(pattern) {
                unseen.push((kind_word(kind), pattern));
            }
            blind.push(Finding::Uncovered {
                source: source.clone(),
            });
        }
        let mut secrets = 0;
        let mut empty = Vec::new();
        for path in &files {
            let found = extract(kind, path);
            if found.is_empty() {
                empty.push(
                    path.file_name()
                        .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
                );
            }
            for cand in found {
                // The one place a secret is used: reduced to a fingerprint,
                // then `cand.secret` drops and is zeroized.
                let fp = pepper.fingerprint(&cand.secret);
                // One name, one secret. Two config lines reaching the same
                // file give the same pair twice: counted once. Two DIFFERENT
                // secrets under one name is a reader bug, and recording it
                // would make every scan look like a rotation -- so the name
                // is reported instead of tracked.
                if let Some(prev) = fp_at.get(&cand.location) {
                    if *prev != fp {
                        ambiguous.insert(cand.location.clone());
                    }
                    continue;
                }
                secrets += 1;
                let entry = state.observe(&cand.location, &fp, now);
                present.insert(cand.location.clone());
                fp_at.insert(cand.location.clone(), fp.clone());
                by_fp.entry(fp).or_default().push(cand.location.clone());

                // Age: an observed rotation is exact. Otherwise take the
                // larger of two lower bounds -- how long we have watched it
                // unchanged, and how long its file has been unmodified.
                let watched = now.saturating_sub(entry.since) / DAY;
                let (days, exact) = if entry.exact {
                    (watched, true)
                } else {
                    let untouched = cand.modified.map_or(0, |m| now.saturating_sub(m) / DAY);
                    (watched.max(untouched), false)
                };
                if days >= cfg.stale_days {
                    stale.push(Finding::Stale {
                        location: cand.location,
                        days,
                        exact,
                    });
                }
            }
        }
        coverage.push(Coverage {
            source,
            files: files.len(),
            secrets,
            empty,
        });
    }
    // Forget locations that are really gone -- but only where this run could
    // look. A source that matched nothing (a pool not yet unlocked at boot)
    // says nothing about what it holds: its locations keep their history,
    // or one reboot would silently restart every age this tool tracks.
    let under_unseen = |loc: &str| {
        location_file(loc).is_some_and(|(k, path)| {
            unseen
                .iter()
                .any(|(uk, pattern)| *uk == k && names(pattern, path))
        })
    };
    state.retain(|loc| present.contains(loc) || under_unseen(loc));
    blind.extend(
        ambiguous
            .into_iter()
            .map(|location| Finding::Ambiguous { location }),
    );

    // Declared copies: a reuse group wholly inside one `same` line is
    // expected. Anything wider -- even one extra location -- is reported.
    let inside_declared =
        |locs: &[String]| cfg.same.iter().any(|g| locs.iter().all(|l| g.contains(l)));
    let credentials = by_fp.len();
    let mut declared = 0;
    let mut reused = Vec::new();
    for (fp, locs) in by_fp.iter().filter(|(_, locs)| locs.len() > 1) {
        if inside_declared(locs) {
            declared += 1;
        } else {
            reused.push(Finding::Reused {
                label: pepper.label(fp),
                locations: locs.clone(),
            });
        }
    }
    let mut drift = Vec::new();
    for group in &cfg.same {
        let mut copies = Vec::new();
        for l in group {
            match fp_at.get(l) {
                Some(fp) => copies.push((pepper.label(fp), l.clone())),
                // Under a blind source it is unseen, not missing; the BLIND
                // line already says so.
                None if under_unseen(l) => {}
                None => blind.push(Finding::Missing {
                    location: l.clone(),
                }),
            }
        }
        let distinct: BTreeSet<&String> = copies.iter().map(|(label, _)| label).collect();
        if distinct.len() > 1 {
            drift.push(Finding::Drift { copies });
        }
    }

    stale.sort_by(|a, b| match (a, b) {
        (Finding::Stale { days: x, .. }, Finding::Stale { days: y, .. }) => y.cmp(x),
        _ => std::cmp::Ordering::Equal,
    });
    // The instrument first: a blind spot qualifies everything below it.
    let mut findings = blind;
    findings.extend(drift);
    findings.extend(reused);
    findings.extend(stale);
    if let Some(shadow) = &cfg.shadow {
        match shadow_stale(shadow, now, cfg.stale_days) {
            Some((accounts, found)) => {
                coverage.push(Coverage {
                    source: format!("shadow {}", shadow.display()),
                    files: 1,
                    secrets: accounts,
                    empty: Vec::new(),
                });
                findings.extend(found);
            }
            None => findings.push(Finding::Uncovered {
                source: format!("shadow {}", shadow.display()),
            }),
        }
    }
    Outcome {
        findings,
        credentials,
        locations: present.len(),
        declared,
        coverage,
    }
}

/// System account password ages, from `/etc/shadow`'s last-change field.
/// Returns how many accounts have a password, and the stale ones; `None`
/// if the file cannot be read, so an unreadable shadow is a blind spot,
/// not a clean bill.
///
/// Only field 1 (user) and field 3 (days since epoch of the last change)
/// are used. Field 2 is looked at for one thing — whether it starts with
/// `$`, meaning a password is set — and is never kept, compared or shown.
/// These hashes are salted per account, so they could not reveal reuse
/// anyway without cracking them, and this tool does not do that.
#[must_use]
pub fn shadow_stale(path: &Path, now: u64, limit: u64) -> Option<(usize, Vec<Finding>)> {
    let raw = Zeroizing::new(std::fs::read_to_string(path).ok()?);
    let today = now / DAY;
    let mut accounts = 0;
    let mut out = Vec::new();
    for line in raw.lines() {
        let f: Vec<&str> = line.splitn(4, ':').collect();
        if f.len() < 3 || !f[1].starts_with('$') {
            continue;
        }
        accounts += 1;
        let Ok(changed) = f[2].parse::<u64>() else {
            continue;
        };
        if changed == 0 {
            continue; // "must change at next login" -- not an age
        }
        let days = today.saturating_sub(changed);
        if days >= limit {
            out.push(Finding::ShadowStale {
                user: f[0].to_owned(),
                days,
            });
        }
    }
    Some((accounts, out))
}

/// The human report. Contains no credential and no fingerprint.
#[must_use]
pub fn render(o: &Outcome, stale_days: u64, date: &str) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "===== credential hygiene — {date}\n");
    let (mut reused, mut stale, mut other) = (0, 0, 0);
    for f in &o.findings {
        match f {
            Finding::Uncovered { source } => {
                other += 1;
                let _ = writeln!(
                    s,
                    "BLIND   {source} — matched nothing; this report does not cover it"
                );
            }
            Finding::Ambiguous { location } => {
                other += 1;
                let _ = writeln!(
                    s,
                    "BLIND   {location} — several different secrets under one name; none can be tracked"
                );
            }
            Finding::Missing { location } => {
                other += 1;
                let _ = writeln!(s, "MISSING declared copy holds no credential: {location}");
            }
            Finding::Drift { copies } => {
                other += 1;
                let _ = writeln!(
                    s,
                    "DRIFT   declared copies no longer match — changed in one place, not the others:"
                );
                for (label, l) in copies {
                    let _ = writeln!(s, "          {label}  {l}");
                }
            }
            Finding::Reused { label, locations } => {
                reused += 1;
                let _ = writeln!(
                    s,
                    "REUSED  {label} — one credential in {} places:",
                    locations.len()
                );
                for l in locations {
                    let _ = writeln!(s, "          {l}");
                }
            }
            Finding::Stale {
                location,
                days,
                exact,
            } => {
                stale += 1;
                let when = if *exact {
                    format!("rotated {days} days ago")
                } else {
                    format!("unchanged for at least {days} days")
                };
                let _ = writeln!(s, "STALE   {location} — {when} (limit {stale_days})");
            }
            Finding::ShadowStale { user, days } => {
                stale += 1;
                let _ = writeln!(
                    s,
                    "STALE   system account '{user}' — password last changed {days} days ago (limit {stale_days})"
                );
            }
        }
    }
    if o.findings.is_empty() {
        let _ = writeln!(s, "nothing reused, nothing older than {stale_days} days");
    }
    let _ = writeln!(
        s,
        "\n----- {} credentials in {} locations; {reused} reused; {stale} stale; {other} other; {} declared copies",
        o.credentials, o.locations, o.declared
    );
    let _ = writeln!(s, "\ncoverage:");
    for c in &o.coverage {
        let note = if c.files > 0 && c.secrets == 0 {
            "  (nothing secret found)".to_owned()
        } else if c.empty.is_empty() {
            String::new()
        } else {
            format!("  (none in: {})", c.empty.join(", "))
        };
        let _ = writeln!(
            s,
            "  {:<52} {:>3} files {:>4} secrets{note}",
            c.source, c.files, c.secrets
        );
    }
    let _ = writeln!(
        s,
        "\nThis report contains no credential and no fingerprint of one."
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        dir: PathBuf,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    // Fake credentials used across the end-to-end tests. Built at runtime
    // from parts so no source line holds a credential-shaped literal.
    fn shared() -> String {
        ["shared", "cred", "4471", "zq"].join("-")
    }
    fn unique() -> String {
        ["only", "here", "9083", "wx"].join("-")
    }

    fn fixture(tag: &str) -> Fixture {
        let dir = std::env::temp_dir().join(format!("hyg-e2e-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (sh, un) = (shared(), unique());
        std::fs::write(
            dir.join("app.env"),
            format!("APP_USER=admin\nAPP_PASSWORD={sh}\nAPI_TOKEN={un}\n"),
        )
        .unwrap();
        std::fs::write(dir.join("deploy.token"), format!("{sh}\n")).unwrap();
        std::fs::write(
            dir.join("pjsip.conf"),
            format!("[phone-auth]\ntype=auth\npassword={sh}\n"),
        )
        .unwrap();
        Fixture { dir }
    }

    fn cfg(f: &Fixture) -> Config {
        let d = f.dir.display();
        Config::parse(&format!(
            "env {d}/*.env\nfile {d}/*.token\nini {d}/pjsip.conf\nstale-days 180\n"
        ))
        .unwrap()
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn one_credential_in_three_formats_is_found_as_reuse() {
        let f = fixture("reuse");
        let p = Pepper::from_bytes(&[5; 32]);
        let mut st = State::default();
        let o = run(&cfg(&f), &p, &mut st, now());
        let reused: Vec<&Finding> = o
            .findings
            .iter()
            .filter(|x| matches!(x, Finding::Reused { .. }))
            .collect();
        assert_eq!(reused.len(), 1, "{:?}", o.findings);
        let Finding::Reused { locations, .. } = reused[0] else {
            unreachable!()
        };
        assert_eq!(locations.len(), 3, "{locations:?}");
        assert!(locations.iter().any(|l| l.starts_with("env:")));
        assert!(locations.iter().any(|l| l.starts_with("file:")));
        assert!(locations.iter().any(|l| l.starts_with("ini:")));
        assert_eq!(
            o.credentials, 2,
            "shared + unique; APP_USER is not a secret"
        );
    }

    #[test]
    fn no_credential_and_no_fingerprint_reaches_the_report_or_the_state() {
        // The promise of the whole tool, checked against its actual outputs.
        let f = fixture("leak");
        let p = Pepper::from_bytes(&[6; 32]);
        let mut st = State::default();
        let o = run(&cfg(&f), &p, &mut st, now());
        let report = render(&o, 180, "2026-09-24");
        let state_path = f.dir.join("state");
        st.save(&state_path).unwrap();
        let state_text = std::fs::read_to_string(&state_path).unwrap();
        for secret in [shared(), unique()] {
            assert!(
                !report.contains(&secret),
                "credential leaked into the report"
            );
            assert!(
                !state_text.contains(&secret),
                "credential leaked into the state"
            );
        }
        for e in st.entries.values() {
            assert!(
                !report.contains(&e.fingerprint),
                "fingerprint leaked into the report"
            );
        }
    }

    #[test]
    fn an_old_untouched_credential_is_stale_as_a_lower_bound() {
        let f = fixture("old");
        let p = Pepper::from_bytes(&[7; 32]);
        let mut st = State::default();
        // Look 200 days ahead: every file is now "unchanged for at least 200".
        let o = run(&cfg(&f), &p, &mut st, now() + 200 * DAY);
        let stale: Vec<&Finding> = o
            .findings
            .iter()
            .filter(|x| matches!(x, Finding::Stale { .. }))
            .collect();
        assert!(!stale.is_empty());
        for s in stale {
            let Finding::Stale { days, exact, .. } = s else {
                unreachable!()
            };
            assert!(*days >= 200);
            assert!(
                !exact,
                "never observed a rotation, so this is a bound, not a date"
            );
        }
    }

    #[test]
    fn a_rotation_is_observed_and_resets_the_age() {
        let f = fixture("rot");
        let p = Pepper::from_bytes(&[8; 32]);
        let mut st = State::default();
        let t0 = now();
        run(&cfg(&f), &p, &mut st, t0);
        std::fs::write(f.dir.join("deploy.token"), "a-brand-new-token-551\n").unwrap();
        let loc = format!("file:{}/deploy.token", f.dir.display());
        run(&cfg(&f), &p, &mut st, t0 + 10 * DAY);
        let e = &st.entries[&loc];
        assert!(e.exact, "a changed fingerprint is a real rotation");
        assert_eq!(e.since, t0 + 10 * DAY);
        let o = run(&cfg(&f), &p, &mut st, t0 + 50 * DAY);
        assert!(
            !o.findings
                .iter()
                .any(|x| matches!(x, Finding::Stale { location, .. } if *location == loc)),
            "40 days after a rotation is not stale"
        );
    }

    #[test]
    fn a_source_that_is_unavailable_keeps_its_history() {
        // /tank is unlocked by hand after a reboot, and the timer's catch-up
        // run fires at boot, before that. Nothing under it can be seen, and
        // "cannot see" must not be recorded as "deleted": pruning there would
        // silently restart every age the tool exists to track.
        let f = fixture("unmounted");
        let [a, b, c] = shared_locations(&f);
        let cfg = cfg_with(&f, &format!("same {a} {b} {c}\n"));
        let p = Pepper::from_bytes(&[18; 32]);
        let mut st = State::default();
        let t0 = now();
        run(&cfg, &p, &mut st, t0);
        let before = st.entries.clone();
        assert!(!before.is_empty());

        // A pool not yet imported: nothing there at all.
        let away = f.dir.with_extension("away");
        std::fs::rename(&f.dir, &away).unwrap();
        let o = run(&cfg, &p, &mut st, t0 + DAY);
        // A dataset not yet mounted: an empty mountpoint left behind.
        std::fs::create_dir(&f.dir).unwrap();
        run(&cfg, &p, &mut st, t0 + DAY);
        let after_empty_mountpoint = st.entries.clone();
        std::fs::remove_dir(&f.dir).unwrap();
        std::fs::rename(&away, &f.dir).unwrap();
        assert_eq!(
            after_empty_mountpoint, before,
            "an empty mountpoint is not a deletion"
        );
        assert!(o
            .findings
            .iter()
            .any(|x| matches!(x, Finding::Uncovered { .. })));
        assert!(
            !o.findings
                .iter()
                .any(|x| matches!(x, Finding::Missing { .. })),
            "unseen is not missing: {:?}",
            o.findings
        );
        assert_eq!(st.entries, before, "history kept while its source is blind");

        run(&cfg, &p, &mut st, t0 + 2 * DAY);
        for (loc, e) in &before {
            assert_eq!(st.entries[loc].since, e.since, "{loc}: age continues");
        }
    }

    #[test]
    fn a_removed_credential_stops_being_tracked() {
        let f = fixture("gone");
        let p = Pepper::from_bytes(&[9; 32]);
        let mut st = State::default();
        run(&cfg(&f), &p, &mut st, now());
        std::fs::remove_file(f.dir.join("deploy.token")).unwrap();
        run(&cfg(&f), &p, &mut st, now());
        assert!(!st.entries.keys().any(|k| k.contains("deploy.token")));
    }

    #[test]
    fn shadow_ages_come_from_the_date_field_and_never_the_hash() {
        let dir = std::env::temp_dir().join(format!("hyg-sh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("shadow");
        let today = now() / DAY;
        let hash = ["$6$saltsalt$", "fakehashvalue"].concat();
        std::fs::write(
            &p,
            format!(
                "root:*:{today}:0:99999:7:::\nold:{hash}:{}:0:99999:7:::\nfresh:{hash}:{today}:0:99999:7:::\nforce:{hash}:0:0:99999:7:::\n",
                today - 400
            ),
        )
        .unwrap();
        let (accounts, got) = shadow_stale(&p, now(), 180).unwrap();
        assert_eq!(accounts, 3, "root has no password; the other three do");
        assert_eq!(
            got,
            vec![Finding::ShadowStale {
                user: "old".into(),
                days: 400
            }]
        );
        let report = render(
            &Outcome {
                findings: got,
                credentials: 0,
                locations: 0,
                declared: 0,
                coverage: Vec::new(),
            },
            180,
            "d",
        );
        assert!(!report.contains("fakehashvalue") && !report.contains("saltsalt"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn globs_match_only_the_last_component() {
        let f = fixture("glob");
        let got = expand(&format!("{}/*.env", f.dir.display()));
        assert_eq!(got.len(), 1);
        assert!(expand(&format!("{}/*.nothing", f.dir.display())).is_empty());
    }

    #[test]
    fn a_bad_config_line_is_an_error_not_a_skip() {
        assert!(Config::parse("bogus /x\n").is_err());
        assert!(Config::parse("stale-days soon\n").is_err());
        assert!(Config::parse("env /x /y\n").is_err(), "trailing text");
        assert!(Config::parse("same file:/only-one\n").is_err());
    }

    // The three locations the fixture's shared credential lives in.
    fn shared_locations(f: &Fixture) -> [String; 3] {
        let d = f.dir.display();
        [
            format!("env:{d}/app.env#APP_PASSWORD"),
            format!("file:{d}/deploy.token"),
            format!("ini:{d}/pjsip.conf#[phone-auth]"),
        ]
    }

    fn cfg_with(f: &Fixture, extra: &str) -> Config {
        let d = f.dir.display();
        Config::parse(&format!(
            "env {d}/*.env\nfile {d}/*.token\nini {d}/pjsip.conf\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn declared_copies_are_not_reported_as_reuse() {
        let f = fixture("decl");
        let [a, b, c] = shared_locations(&f);
        let p = Pepper::from_bytes(&[10; 32]);
        let o = run(
            &cfg_with(&f, &format!("same {a} {b} {c}\n")),
            &p,
            &mut State::default(),
            now(),
        );
        assert!(o.findings.is_empty(), "{:?}", o.findings);
        assert_eq!(o.declared, 1);
    }

    #[test]
    fn reuse_wider_than_the_declaration_is_still_reported() {
        // Declaring two of the three places must not excuse the third:
        // that third place is exactly the reuse nobody planned.
        let f = fixture("wide");
        let [a, b, _] = shared_locations(&f);
        let p = Pepper::from_bytes(&[11; 32]);
        let o = run(
            &cfg_with(&f, &format!("same {a} {b}\n")),
            &p,
            &mut State::default(),
            now(),
        );
        assert!(
            o.findings
                .iter()
                .any(|x| matches!(x, Finding::Reused { locations, .. } if locations.len() == 3)),
            "{:?}",
            o.findings
        );
        assert_eq!(o.declared, 0);
    }

    #[test]
    fn a_half_finished_rotation_is_drift() {
        let f = fixture("drift");
        let [a, b, c] = shared_locations(&f);
        let cfg = cfg_with(&f, &format!("same {a} {b} {c}\n"));
        let p = Pepper::from_bytes(&[12; 32]);
        let mut st = State::default();
        run(&cfg, &p, &mut st, now());
        // Rotate the token file only; the other two copies are forgotten.
        std::fs::write(f.dir.join("deploy.token"), "rotated-in-one-place-77\n").unwrap();
        let o = run(&cfg, &p, &mut st, now());
        let drift: Vec<&Finding> = o
            .findings
            .iter()
            .filter(|x| matches!(x, Finding::Drift { .. }))
            .collect();
        assert_eq!(drift.len(), 1, "{:?}", o.findings);
        let Finding::Drift { copies } = drift[0] else {
            unreachable!()
        };
        let labels: BTreeSet<&String> = copies.iter().map(|(l, _)| l).collect();
        assert_eq!(labels.len(), 2, "two copies still agree, one moved on");
        assert!(!o
            .findings
            .iter()
            .any(|x| matches!(x, Finding::Reused { .. })));
    }

    #[test]
    fn a_declared_location_that_vanished_is_reported() {
        let f = fixture("miss");
        let [a, b, _] = shared_locations(&f);
        let typo = format!("file:{}/no-such.token", f.dir.display());
        let p = Pepper::from_bytes(&[13; 32]);
        let o = run(
            &cfg_with(&f, &format!("same {a} {b} {typo}\n")),
            &p,
            &mut State::default(),
            now(),
        );
        assert!(o
            .findings
            .iter()
            .any(|x| matches!(x, Finding::Missing { location } if *location == typo)));
    }

    #[test]
    fn a_source_that_matches_nothing_is_a_blind_spot_not_a_clean_bill() {
        let f = fixture("blind");
        let gone = format!("{}/moved-away/*.env", f.dir.display());
        let p = Pepper::from_bytes(&[14; 32]);
        let o = run(
            &cfg_with(&f, &format!("env {gone}\nshadow /nonexistent/shadow\n")),
            &p,
            &mut State::default(),
            now(),
        );
        let blind: Vec<&String> = o
            .findings
            .iter()
            .filter_map(|x| match x {
                Finding::Uncovered { source } => Some(source),
                _ => None,
            })
            .collect();
        assert_eq!(blind.len(), 2, "{:?}", o.findings);
        assert!(blind.iter().any(|s| s.contains("moved-away")));
        assert!(blind.iter().any(|s| s.starts_with("shadow ")));
        let report = render(&o, 180, "d");
        assert!(report.contains("BLIND"), "{report}");
    }

    #[test]
    fn two_secrets_under_one_name_are_reported_not_tracked() {
        let f = fixture("ambig");
        let d = f.dir.display();
        std::fs::write(
            f.dir.join("dup.conf"),
            format!("[trunk]\npassword={}\npassword={}\n", shared(), unique()),
        )
        .unwrap();
        let cfg = Config::parse(&format!("ini {d}/dup.conf\n")).unwrap();
        let p = Pepper::from_bytes(&[16; 32]);
        let mut st = State::default();
        let o = run(&cfg, &p, &mut st, now());
        assert!(
            o.findings.iter().any(
                |x| matches!(x, Finding::Ambiguous { location } if location.ends_with("#[trunk]"))
            ),
            "{:?}",
            o.findings
        );
        // And the history does not flip-flop between the two values.
        let before = st.entries.clone();
        run(&cfg, &p, &mut st, now() + DAY);
        assert_eq!(
            st.entries, before,
            "a re-scan must not look like a rotation"
        );
    }

    #[test]
    fn a_file_reached_by_two_config_lines_is_counted_once() {
        let f = fixture("overlap");
        let d = f.dir.display();
        let cfg = Config::parse(&format!("file {d}/*.token\nfile {d}/deploy.token\n")).unwrap();
        let p = Pepper::from_bytes(&[17; 32]);
        let o = run(&cfg, &p, &mut State::default(), now());
        assert!(
            o.findings.is_empty(),
            "not reuse of itself: {:?}",
            o.findings
        );
        assert_eq!(o.locations, 1);
    }

    #[test]
    fn a_finding_keeps_its_identity_as_it_ages() {
        // Otherwise a stale credential re-notifies every single day.
        let a = Finding::Stale {
            location: "file:/x".into(),
            days: 200,
            exact: false,
        };
        let b = Finding::Stale {
            location: "file:/x".into(),
            days: 201,
            exact: false,
        };
        assert_eq!(a.identity(), b.identity());
        let c = Finding::Stale {
            location: "file:/y".into(),
            days: 200,
            exact: false,
        };
        assert_ne!(a.identity(), c.identity());
    }

    #[test]
    fn no_credential_reaches_a_drift_report_either() {
        let f = fixture("dleak");
        let [a, b, c] = shared_locations(&f);
        let cfg = cfg_with(&f, &format!("same {a} {b} {c}\n"));
        let p = Pepper::from_bytes(&[15; 32]);
        let mut st = State::default();
        run(&cfg, &p, &mut st, now());
        let rotated = "rotated-value-for-leak-check-31";
        std::fs::write(f.dir.join("deploy.token"), format!("{rotated}\n")).unwrap();
        let o = run(&cfg, &p, &mut st, now());
        let report = render(&o, 180, "d");
        assert!(report.contains("DRIFT"), "{report}");
        for secret in [shared(), unique(), rotated.to_owned()] {
            assert!(
                !report.contains(&secret),
                "credential leaked into the report"
            );
        }
        for e in st.entries.values() {
            assert!(!report.contains(&e.fingerprint), "fingerprint leaked");
        }
    }
}
