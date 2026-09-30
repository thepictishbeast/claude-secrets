//! Finding the secrets inside a file, without keeping them.
//!
//! Every extractor hands back `Zeroizing` buffers, so a secret's bytes are
//! wiped when the fingerprint has been taken and the candidate drops. The
//! location string names WHERE a secret is — a path and, where there is
//! one, a key or section — and never contains any part of it.

use std::path::Path;
use std::time::UNIX_EPOCH;
use zeroize::Zeroizing;

/// One secret found at one place.
pub struct Candidate {
    /// Where it is: `env:/path#KEY`, `file:/path`, `ini:/path#[section]`.
    pub location: String,
    pub secret: Zeroizing<Vec<u8>>,
    /// Unix seconds the containing file last changed.
    pub modified: Option<u64>,
}

/// A kind of place secrets live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// The whole file is one secret: a token, a private key.
    File,
    /// `KEY=VALUE` lines; only secret-looking keys are taken.
    Env,
    /// `password=` lines inside `[section]`s, as in pjsip.conf.
    IniPassword,
    /// `PrivateKey =` lines in a WireGuard config.
    WireGuard,
}

fn mtime(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Read a file into a buffer that is wiped on drop.
fn read_secret_file(path: &Path) -> Option<Zeroizing<Vec<u8>>> {
    std::fs::read(path).ok().map(Zeroizing::new)
}

/// Whether an env key names a secret.
///
/// Name-based on purpose. A value-entropy guess would fingerprint random
/// IDs and hashes that are not credentials, and miss short passwords that
/// are. The exclusions matter as much as the inclusions: `DB_PASSWORD_FILE`
/// is a path and `API_KEY_ID` is an identifier, and fingerprinting either
/// would report "reuse" of things that are not secret.
#[must_use]
pub fn is_secret_key(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    const NOT_SECRET: &[&str] = &[
        "_USER",
        "_USERNAME",
        "_URL",
        "_URI",
        "_HOST",
        "_DOMAIN",
        "_PORT",
        "_EMAIL",
        "_ID",
        "_NAME",
        "_PATH",
        "_FILE",
        "_DIR",
        "_ENABLED",
        "_TTL",
        "_EXPIRY",
        "_EXPIRES",
        "_TYPE",
        "_ALGORITHM",
        "_LENGTH",
        "_MODE",
    ];
    if NOT_SECRET.iter().any(|s| n.ends_with(s)) {
        return false;
    }
    const SECRET: &[&str] = &[
        "PASS",
        "SECRET",
        "TOKEN",
        "KEY",
        "PAT",
        "AUTH",
        "CREDENTIAL",
        "PRIVATE",
        "SALT",
        "SIGNING",
        "COOKIE",
        "SESSION",
    ];
    SECRET.iter().any(|s| n.contains(s))
}

/// A value too short, empty, or indirect to be a real secret.
fn is_real_value(v: &str) -> bool {
    let v = v.trim();
    v.len() >= 8 && !v.starts_with("${") && !v.starts_with('$') && v != "changeme"
}

/// Split an env-style line into `(key, value)`: `KEY=value`, `export
/// KEY=value`, or `KEY: value`.
///
/// The key is matched POSITIVELY as an identifier, rather than taken as
/// "everything before the delimiter". A line that is not a key/value pair
/// then yields nothing, instead of yielding a "key" that is really the
/// whole line -- secret included.
fn env_pair(line: &str) -> Option<(&str, &str)> {
    let l = line.trim();
    let l = l.strip_prefix("export ").map_or(l, str::trim_start);
    let end = l
        .char_indices()
        .find(|&(i, c)| !(c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit())))
        .map_or(l.len(), |(i, _)| i);
    if end == 0 {
        return None;
    }
    let (key, rest) = l.split_at(end);
    let rest = rest.trim_start();
    let value = if let Some(v) = rest.strip_prefix('=') {
        v
    } else {
        // YAML-ish `KEY: value` needs the space, so `KEY:x` is not taken.
        let v = rest.strip_prefix(':')?;
        if !(v.is_empty() || v.starts_with(char::is_whitespace)) {
            return None;
        }
        v
    };
    Some((key, strip_quotes(value)))
}

/// The password inside `scheme://user:password@host...`, if there is one.
/// `DATABASE_URL`-style keys are not secret by name, but this part is.
fn url_password(v: &str) -> Option<&str> {
    let (scheme, rest) = v.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+.-".contains(c))
    {
        return None;
    }
    let authority = rest.split('/').next()?;
    let (userinfo, _host) = authority.rsplit_once('@')?;
    let (_user, password) = userinfo.split_once(':')?;
    (!password.is_empty()).then_some(password)
}

fn strip_quotes(v: &str) -> &str {
    let v = v.trim();
    if v.len() >= 2
        && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\'')))
    {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

/// Everything secret in one file.
#[must_use]
pub fn extract(kind: &Kind, path: &Path) -> Vec<Candidate> {
    let modified = mtime(path);
    let Some(raw) = read_secret_file(path) else {
        return Vec::new();
    };
    let p = path.display();
    match kind {
        Kind::File => {
            // Trim surrounding whitespace so a trailing newline does not make
            // an otherwise identical token look different.
            let start = raw
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .unwrap_or(raw.len());
            let end = raw
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map_or(start, |i| i + 1);
            if end <= start {
                return Vec::new();
            }
            vec![Candidate {
                location: format!("file:{p}"),
                secret: Zeroizing::new(raw[start..end].to_vec()),
                modified,
            }]
        }
        Kind::Env => {
            let Ok(text) = std::str::from_utf8(&raw) else {
                return Vec::new();
            };
            let mut out: Vec<Candidate> = Vec::new();
            for line in text.lines() {
                if line.trim_start().starts_with('#') {
                    continue;
                }
                let Some((k, v)) = env_pair(line) else {
                    continue;
                };
                // A password inside a URL counts whatever the key is called.
                let secret = match url_password(v) {
                    Some(pw) => pw,
                    None if is_secret_key(k) => v,
                    None => continue,
                };
                if !is_real_value(secret) {
                    continue;
                }
                let location = format!("env:{p}#{k}");
                // A key set twice: the last one wins, as every loader has it.
                // Two candidates under one name would make each scan look
                // like a rotation, and the credential could never age.
                out.retain(|c| c.location != location);
                out.push(Candidate {
                    location,
                    secret: Zeroizing::new(secret.as_bytes().to_vec()),
                    modified,
                });
            }
            out
        }
        Kind::IniPassword => {
            let Ok(text) = std::str::from_utf8(&raw) else {
                return Vec::new();
            };
            let mut section = String::new();
            let mut out = Vec::new();
            for line in text.lines() {
                let l = line.trim();
                if l.starts_with(';') || l.starts_with('#') {
                    continue;
                }
                if l.starts_with('[') && l.contains(']') {
                    section = l[1..l.find(']').unwrap_or(l.len())].to_owned();
                    continue;
                }
                // `password=` and `secret=`, with or without `=>`.
                let Some((k, v)) = l.split_once('=') else {
                    continue;
                };
                let k = k.trim().to_ascii_lowercase();
                if k != "password" && k != "secret" {
                    continue;
                }
                let v = strip_quotes(v.trim_start_matches('>'));
                if is_real_value(v) {
                    out.push(Candidate {
                        location: format!("ini:{p}#[{section}]"),
                        secret: Zeroizing::new(v.as_bytes().to_vec()),
                        modified,
                    });
                }
            }
            out
        }
        Kind::WireGuard => {
            let Ok(text) = std::str::from_utf8(&raw) else {
                return Vec::new();
            };
            // A server config holds one PresharedKey per peer, so the key
            // name alone is ambiguous. Each [Peer]'s keys are named by its
            // first AllowedIPs entry -- stable, readable, and not secret --
            // or by its position when it has none. That means a section's
            // keys can only be named once the whole section has been read.
            let mut out = Vec::new();
            let mut peers = 0;
            let mut sec = WgSection::default();
            for line in text.lines() {
                let l = line.trim();
                if l.starts_with('[') {
                    sec.flush(&p.to_string(), modified, &mut out);
                    let is_peer = l.eq_ignore_ascii_case("[peer]");
                    if is_peer {
                        peers += 1;
                    }
                    sec = WgSection {
                        peer: is_peer.then_some(peers),
                        ..WgSection::default()
                    };
                    continue;
                }
                // Base64 keys end in '=', so split on the FIRST '=' only.
                let Some((k, v)) = l.split_once('=') else {
                    continue;
                };
                let (k, v) = (k.trim(), v.trim());
                match k {
                    "AllowedIPs" => {
                        sec.allowed = v.split(',').next().map(|s| s.trim().to_owned());
                    }
                    "PrivateKey" | "PresharedKey" if !v.is_empty() => {
                        sec.keys
                            .push((k.to_owned(), Zeroizing::new(v.as_bytes().to_vec())));
                    }
                    _ => {}
                }
            }
            sec.flush(&p.to_string(), modified, &mut out);
            out
        }
    }
}

/// One `[Interface]` or `[Peer]` section of a WireGuard config, held until
/// its end so its keys can be named by the peer they belong to.
#[derive(Default)]
struct WgSection {
    /// `Some(n)` for the n-th `[Peer]`; `None` for `[Interface]`.
    peer: Option<usize>,
    allowed: Option<String>,
    keys: Vec<(String, Zeroizing<Vec<u8>>)>,
}

impl WgSection {
    fn flush(&mut self, path: &str, modified: Option<u64>, out: &mut Vec<Candidate>) {
        let prefix = match (self.peer, &self.allowed) {
            (None, _) => String::new(),
            (Some(_), Some(ip)) if !ip.is_empty() => format!("Peer({ip})."),
            (Some(n), _) => format!("Peer(#{n})."),
        };
        for (k, secret) in self.keys.drain(..) {
            out.push(Candidate {
                location: format!("wg:{path}#{prefix}{k}"),
                secret,
                modified,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str, body: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("hyg-ext-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn secret_keys_are_taken_and_non_secrets_are_not() {
        assert!(is_secret_key("FUB_API_KEY"));
        assert!(is_secret_key("DB_PASSWORD"));
        assert!(is_secret_key("GODADDY_PAT"));
        assert!(is_secret_key("session_secret"));
        // Look secret by name, are not secret by nature.
        assert!(!is_secret_key("DB_PASSWORD_FILE"));
        assert!(!is_secret_key("API_KEY_ID"));
        assert!(!is_secret_key("SMTP_USER"));
        assert!(!is_secret_key("AUTH_URL"));
        // A hostname, found holding "auth.<domain>" in a real .env.
        assert!(!is_secret_key("AUTH_DOMAIN"));
        assert!(!is_secret_key("DB_HOST"));
    }

    #[test]
    fn env_extraction_takes_only_real_secret_values() {
        // One fixture line per entry so each fake credential can carry its own
        // gitleaks:allow marker -- scoped to the line, not the whole file.
        let body = [
            "# comment KEY=ignored",
            "DB_USER=admin",
            "DB_PASSWORD=\"s3cret-value-1\"", // gitleaks:allow -- test fixture
            "export API_TOKEN='tok-abcdef123'", // gitleaks:allow -- test fixture
            "PORT=8080",
            "SHORT_KEY=abc",
            "REF_SECRET=${OTHER}",
        ]
        .join("\n");
        let p = tmp("a.env", &body);
        let got: Vec<String> = extract(&Kind::Env, &p)
            .into_iter()
            .map(|c| c.location)
            .collect();
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[0].ends_with("#DB_PASSWORD"));
        assert!(got[1].ends_with("#API_TOKEN"));
    }

    #[test]
    fn quotes_and_trailing_newlines_do_not_change_identity() {
        let a = tmp("q.env", "A_PASSWORD=\"same-secret-99\"\n");
        let b = tmp("q.token", "same-secret-99\n\n");
        let ea = extract(&Kind::Env, &a);
        let eb = extract(&Kind::File, &b);
        assert_eq!(ea[0].secret.as_slice(), eb[0].secret.as_slice());
    }

    #[test]
    fn ini_passwords_are_named_by_section() {
        let p = tmp(
            "pjsip.conf",
            "[global]\ntype=global\n[phone-auth]\ntype=auth\nusername=phone\npassword=ini-pass-12345\n\
             ; password=commented-out-123\n",
        );
        let got = extract(&Kind::IniPassword, &p);
        assert_eq!(got.len(), 1);
        assert!(
            got[0].location.ends_with("#[phone-auth]"),
            "{}",
            got[0].location
        );
    }

    #[test]
    fn wireguard_keys_keep_their_base64_padding() {
        let body = format!(
            "[Interface]\nPrivateKey = {}=\nListenPort = 51820\n",
            fake("wg-pad")
        );
        let got = extract(&Kind::WireGuard, &tmp("wg0.conf", &body));
        assert_eq!(got.len(), 1);
        assert!(
            got[0].secret.ends_with(b"="),
            "padding must survive the split"
        );
    }

    #[test]
    fn a_location_never_contains_the_secret() {
        let p = tmp("leak.env", "LEAK_PASSWORD=do-not-print-me-7\n");
        for c in extract(&Kind::Env, &p) {
            assert!(!c.location.contains("do-not-print-me-7"), "{}", c.location);
        }
    }

    // Fake values assembled at runtime so no source line is credential-shaped.
    fn fake(tag: &str) -> String {
        ["fake", tag, "0451", "qv"].join("-")
    }

    fn locations(kind: &Kind, p: &Path) -> Vec<String> {
        extract(kind, p).into_iter().map(|c| c.location).collect()
    }

    #[test]
    fn colon_style_env_files_are_read_not_skipped() {
        // One vendor env file here is written `KEY: value`. Reading only `=`
        // made the whole file invisible: 0 secrets, no error.
        let body = format!(
            "EMAIL: someone@example.com\nPASSWORD: {}\nAPI_KEY: {}\nTIGHT_TOKEN:{}\n",
            fake("colon-pw"),
            fake("colon-key"),
            fake("no-space"),
        );
        let got = locations(&Kind::Env, &tmp("colon.env", &body));
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got[0].ends_with("#PASSWORD") && got[1].ends_with("#API_KEY"));
    }

    #[test]
    fn a_line_that_is_not_a_pair_yields_nothing_at_all() {
        // Not "a key made of the whole line" -- that is how a value leaks
        // into a location.
        let secret = fake("free-text");
        let body = format!("some notes PASSWORD={secret}\n= {secret}\n{secret}\n");
        let p = tmp("notes.env", &body);
        assert!(locations(&Kind::Env, &p).is_empty());
    }

    #[test]
    fn a_key_set_twice_is_one_location_and_the_last_value_wins() {
        let (old, new) = (fake("first"), fake("second"));
        let p = tmp(
            "twice.env",
            &format!("DB_PASSWORD={old}\nDB_PASSWORD={new}\n"),
        );
        let got = extract(&Kind::Env, &p);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].secret.as_slice(), new.as_bytes());
    }

    #[test]
    fn a_password_inside_a_url_is_taken_whatever_the_key_is_called() {
        let pw = fake("url-pw");
        let body = format!(
            "SCRAPER_PRIVATE_URL=https://scraper:{pw}@scraper.local/\nREDIS_URL=redis://redis:6379/0\nPUBLIC_URL=https://example.com\n"
        );
        let got = extract(&Kind::Env, &tmp("url.env", &body));
        assert_eq!(got.len(), 1, "only the URL that carries a password");
        assert_eq!(
            got[0].secret.as_slice(),
            pw.as_bytes(),
            "the password, not the URL"
        );
        assert!(got[0].location.ends_with("#SCRAPER_PRIVATE_URL"));
        assert!(!got[0].location.contains(&pw));
    }

    #[test]
    fn each_wireguard_peer_gets_its_own_location() {
        // Three peers, three PresharedKeys. Under one shared name each scan
        // saw three "rotations" and those keys could never be reported old.
        let k = |t: &str| format!("{}=", fake(t));
        let body = format!(
            "[Interface]\nPrivateKey = {}\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 10.0.0.2/32, fd00::2/128\n\n\
             [Peer]\nPresharedKey = {}\nAllowedIPs = 10.0.0.3/32\n\n[Peer]\nPresharedKey = {}\n",
            k("iface"),
            k("pub"),
            k("psk-a"),
            k("psk-b"),
            k("psk-c"),
        );
        let got = locations(&Kind::WireGuard, &tmp("multi.conf", &body));
        let tails: Vec<&str> = got.iter().map(|l| &l[l.find('#').unwrap()..]).collect();
        assert_eq!(
            tails,
            [
                "#PrivateKey",
                "#Peer(10.0.0.2/32).PresharedKey",
                "#Peer(10.0.0.3/32).PresharedKey",
                "#Peer(#3).PresharedKey",
            ]
        );
        let unique: std::collections::BTreeSet<&String> = got.iter().collect();
        assert_eq!(unique.len(), got.len(), "every location distinct");
    }
}
