//! Finding known credentials inside other files -- transcripts, archives,
//! logs -- and replacing them, without printing any.
//!
//! The dictionary is every secret the configured sources hold, read exactly
//! as `scan` reads them. Each one is searched for in the forms it takes when
//! it leaks: as written, JSON-escaped (a transcript line), percent-encoded (a
//! URL), inside base64 at any alignment (an `Authorization: Basic` header),
//! and, for a multi-line secret such as a private key, line by line.
//!
//! Output names a credential only by its report label, never by value and
//! never by location: where the credentials live is itself worth protecting.

use crate::audit::{expand, Config};
use crate::extract::extract;
use crate::fingerprint::Pepper;
use std::collections::{BTreeMap, HashMap};
use zeroize::Zeroizing;

/// Shorter secrets are not searched. At seven bytes a match is as likely to
/// be an ordinary word as a leak. They are counted instead, so a clean result
/// can say what it did not cover.
pub const MIN_LEN: usize = 8;

/// A secret that reads like an ordinary word or a short number. Searching
/// for it flags ordinary text, and replacing every occurrence would give it
/// away by context, so it is counted as weak instead.
///
/// Shape alone is not enough: a random 11-letter token is one character
/// class too, and must still be searched. A word has vowels in a normal
/// proportion and no long consonant run; random letters rarely do.
fn word_like(s: &[u8]) -> bool {
    if s.len() >= 12 {
        return false;
    }
    if s.iter().all(u8::is_ascii_digit) {
        return true;
    }
    let one_case = s.iter().all(u8::is_ascii_lowercase) || s.iter().all(u8::is_ascii_uppercase);
    if !one_case {
        return false;
    }
    let vowel = |b: &u8| b"aeiouy".contains(&b.to_ascii_lowercase());
    let vowels = s.iter().filter(|b| vowel(b)).count();
    let mut run = 0;
    let mut longest = 0;
    for b in s {
        run = if vowel(b) { 0 } else { run + 1 };
        longest = longest.max(run);
    }
    vowels * 4 >= s.len() && longest <= 3
}

/// A line of a multi-line secret is searched on its own only when it is
/// this long: shorter lines (headers, short fields) are not distinctive.
const MIN_LINE: usize = 20;

const FILTER_BITS: u32 = 20;

struct Needle {
    bytes: Zeroizing<Vec<u8>>,
    label: String,
}

/// Every searchable form of every known credential.
pub struct Dictionary {
    needles: Vec<Needle>,
    /// First eight bytes of a needle -> the needles that start with them,
    /// longest first.
    by_prefix: HashMap<u64, Vec<usize>>,
    /// A bitset over a hash of those prefixes. Nearly every position in a
    /// file fails this test, which is what keeps one pass fast.
    filter: Vec<u64>,
    credentials: usize,
    too_short: usize,
    weak: usize,
    uncovered: Vec<String>,
}

/// One occurrence: where it starts, how long it is, and which credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub start: usize,
    pub len: usize,
    pub label: String,
}

fn prefix(b: &[u8]) -> u64 {
    let mut k = [0u8; 8];
    k.copy_from_slice(&b[..8]);
    u64::from_le_bytes(k)
}

fn slot(key: u64) -> usize {
    (key.wrapping_mul(0x9E37_79B9_7F4A_7C15) >> (64 - FILTER_BITS)) as usize
}

fn json_escape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0..=0x1f => out.extend_from_slice(format!("\\u{b:04x}").as_bytes()),
            _ => out.push(b),
        }
    }
    out
}

fn percent_encode(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for &b in s {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

/// The part of a base64 encoding that depends only on `s`, for each of the
/// three byte offsets `s` can sit at inside a longer encoded string.
///
/// Base64 turns 3 bytes into 4 characters, so the characters that carry
/// `s` differ with its offset mod 3. Encoding it behind 0, 1 and 2 filler
/// bytes, then keeping only the characters built entirely from `s`'s bits,
/// gives three substrings; any base64 text containing `s` contains one.
fn base64_cores(s: &[u8], alphabet: &[u8; 64]) -> Vec<Vec<u8>> {
    let mut cores = Vec::new();
    for o in 0..3usize {
        let mut p = vec![0u8; o];
        p.extend_from_slice(s);
        let bits = p.len() * 8;
        let chars = bits.div_ceil(6);
        let first = (8 * o).div_ceil(6);
        let last = bits / 6; // exclusive: the final partial character is dropped
        let mut enc = Vec::with_capacity(chars);
        for j in 0..chars {
            let mut v = 0u32;
            for bit in 0..6 {
                let at = j * 6 + bit;
                let byte = p.get(at / 8).copied().unwrap_or(0);
                v = (v << 1) | u32::from((byte >> (7 - at % 8)) & 1);
            }
            enc.push(alphabet[v as usize]);
        }
        if last > first {
            cores.push(enc[first..last].to_vec());
        }
    }
    cores
}

const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Every form of one secret worth searching for.
fn forms(secret: &[u8]) -> Vec<Vec<u8>> {
    let mut out = vec![secret.to_vec(), json_escape(secret), percent_encode(secret)];
    out.extend(base64_cores(secret, STD));
    out.extend(base64_cores(secret, URL));
    if secret.contains(&b'\n') {
        for line in secret.split(|&b| b == b'\n') {
            let line = line.trim_ascii();
            if line.len() >= MIN_LINE && !line.starts_with(b"-----") {
                out.push(line.to_vec());
            }
        }
    }
    out.retain(|f| f.len() >= MIN_LEN);
    out.sort();
    out.dedup();
    out
}

impl Dictionary {
    /// Every credential the configured sources hold.
    #[must_use]
    pub fn load(cfg: &Config, pepper: &Pepper) -> Self {
        let mut secrets: Vec<Zeroizing<Vec<u8>>> = Vec::new();
        let mut uncovered = Vec::new();
        for (kind, pattern) in &cfg.sources {
            let files = expand(pattern);
            if files.is_empty() {
                uncovered.push(pattern.clone());
            }
            for path in files {
                secrets.extend(extract(kind, &path).into_iter().map(|c| c.secret));
            }
        }
        let mut d = Self::from_secrets(&secrets, pepper);
        d.uncovered = uncovered;
        d
    }

    /// Configured sources that matched no file this run. The dictionary is
    /// missing whatever they hold, so a clean search cannot be trusted.
    #[must_use]
    pub fn uncovered(&self) -> &[String] {
        &self.uncovered
    }

    /// Build from secrets already in hand.
    #[must_use]
    pub fn from_secrets(secrets: &[Zeroizing<Vec<u8>>], pepper: &Pepper) -> Self {
        let mut d = Self {
            needles: Vec::new(),
            by_prefix: HashMap::new(),
            filter: vec![0; (1usize << FILTER_BITS) / 64],
            credentials: 0,
            too_short: 0,
            weak: 0,
            uncovered: Vec::new(),
        };
        let mut seen = std::collections::BTreeSet::new();
        for s in secrets {
            let s = s.trim_ascii();
            let fp = pepper.fingerprint(s);
            if !seen.insert(fp.clone()) {
                continue; // one credential in several places is one credential
            }
            if s.len() < MIN_LEN {
                d.too_short += 1;
                continue;
            }
            if word_like(s) {
                d.weak += 1;
                continue;
            }
            d.credentials += 1;
            let label = pepper.label(&fp);
            for f in forms(s) {
                d.needles.push(Needle {
                    bytes: Zeroizing::new(f),
                    label: label.clone(),
                });
            }
        }
        for (i, n) in d.needles.iter().enumerate() {
            let key = prefix(&n.bytes);
            d.filter[slot(key) / 64] |= 1 << (slot(key) % 64);
            d.by_prefix.entry(key).or_default().push(i);
        }
        for list in d.by_prefix.values_mut() {
            list.sort_by_key(|&i| std::cmp::Reverse(d.needles[i].bytes.len()));
        }
        d
    }

    /// Distinct credentials searched for.
    #[must_use]
    pub fn credentials(&self) -> usize {
        self.credentials
    }

    /// Credentials too short to search for without false alarms.
    #[must_use]
    pub fn too_short(&self) -> usize {
        self.too_short
    }

    /// Credentials that look like ordinary words or numbers: not searched,
    /// and weak enough to rotate.
    #[must_use]
    pub fn weak(&self) -> usize {
        self.weak
    }

    /// Every occurrence, leftmost first, longest at each position, never
    /// overlapping.
    #[must_use]
    pub fn find(&self, hay: &[u8]) -> Vec<Hit> {
        // Every position is tried, even inside an earlier match: skipping
        // ahead would miss a second credential that overlaps the first, and
        // redaction would then leave most of it behind. Overlapping matches
        // are merged into one span, named by the first credential in it.
        let mut hits: Vec<Hit> = Vec::new();
        for i in 0..hay.len().saturating_sub(MIN_LEN - 1) {
            let key = prefix(&hay[i..]);
            let s = slot(key);
            if self.filter[s / 64] & (1 << (s % 64)) == 0 {
                continue;
            }
            let Some(n) = self.by_prefix.get(&key).and_then(|list| {
                list.iter()
                    .map(|&k| &self.needles[k])
                    .find(|n| hay[i..].starts_with(&n.bytes))
            }) else {
                continue;
            };
            let end = i + n.bytes.len();
            match hits.last_mut() {
                Some(last) if i < last.start + last.len => {
                    last.len = end.max(last.start + last.len) - last.start;
                }
                _ => hits.push(Hit {
                    start: i,
                    len: n.bytes.len(),
                    label: n.label.clone(),
                }),
            }
        }
        hits
    }

    /// Hits per credential label.
    #[must_use]
    pub fn count(&self, hay: &[u8]) -> BTreeMap<String, usize> {
        let mut by = BTreeMap::new();
        for h in self.find(hay) {
            *by.entry(h.label).or_insert(0) += 1;
        }
        by
    }

    /// `hay` with every occurrence replaced by `[REDACTED:<label>]`, and how
    /// many were replaced.
    #[must_use]
    pub fn redact(&self, hay: &[u8]) -> (Vec<u8>, usize) {
        let hits = self.find(hay);
        let mut out = Vec::with_capacity(hay.len());
        let mut at = 0;
        for h in &hits {
            out.extend_from_slice(&hay[at..h.start]);
            out.extend_from_slice(format!("[REDACTED:{}]", h.label).as_bytes());
            at = h.start + h.len;
        }
        out.extend_from_slice(&hay[at..]);
        (out, hits.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dict(secrets: &[&[u8]]) -> Dictionary {
        let s: Vec<Zeroizing<Vec<u8>>> =
            secrets.iter().map(|b| Zeroizing::new(b.to_vec())).collect();
        Dictionary::from_secrets(&s, &Pepper::from_bytes(&[7u8; 32]))
    }

    fn b64(s: &[u8]) -> String {
        // Independent reference encoder (padding and all), so the cores are
        // checked against real base64 rather than against themselves.
        let mut out = String::new();
        for chunk in s.chunks(3) {
            let n = chunk.len();
            let v = (u32::from(chunk[0]) << 16)
                | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
                | u32::from(*chunk.get(2).unwrap_or(&0));
            for k in 0..4 {
                if k <= n {
                    out.push(STD[((v >> (18 - 6 * k)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    const SECRET: &[u8] = b"hunter2-correct-horse-9Q";

    #[test]
    fn a_plain_occurrence_is_found_and_named_by_label_only() {
        let d = dict(&[SECRET]);
        let text = [b"password is ".as_slice(), SECRET, b" ok"].concat();
        let hits = d.find(&text);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].start, 12);
        assert!(hits[0].label.starts_with("cred-"));
        assert!(!hits[0]
            .label
            .as_bytes()
            .windows(4)
            .any(|w| SECRET.windows(4).any(|x| x == w)));
    }

    #[test]
    fn a_secret_inside_basic_auth_is_found_at_every_alignment() {
        let d = dict(&[SECRET]);
        // Prefix lengths 15, 4, 2: the secret starts at offset 0, 1 and 2 mod 3.
        for prefix in ["x-access-token:", "abc:", "u:"] {
            let header = format!(
                "Authorization: Basic {}",
                b64(&[prefix.as_bytes(), SECRET].concat())
            );
            assert_eq!(d.find(header.as_bytes()).len(), 1, "prefix {prefix:?}");
        }
    }

    #[test]
    fn json_escaped_and_url_encoded_forms_are_found() {
        let s: &[u8] = b"pa\"ss\\word/with spaces&more";
        let d = dict(&[s]);
        assert_eq!(d.find(&json_escape(s)).len(), 1);
        assert_eq!(d.find(&percent_encode(s)).len(), 1);
    }

    #[test]
    fn one_line_of_a_private_key_is_found_on_its_own() {
        // Assembled at run time: a literal armor block, even a fake one,
        // would (rightly) trip the repository's own secret scan.
        let armor = |edge: &str| format!("-----{edge} OPENSSH {} KEY-----", "PRIVATE");
        let key = format!(
            "{}\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\nQyNTUxOQAAACBa1b2c3d4e5f6g7h8i9j0k1l2m3n4o\n{}",
            armor("BEGIN"),
            armor("END")
        );
        let d = dict(&[key.as_bytes()]);
        let leak = b"...it printed QyNTUxOQAAACBa1b2c3d4e5f6g7h8i9j0k1l2m3n4o and stopped";
        assert_eq!(d.find(leak).len(), 1);
        // The armor line is public text and must not count as a leak.
        assert!(d.find(armor("BEGIN").as_bytes()).is_empty());
    }

    #[test]
    fn short_secrets_are_counted_not_searched() {
        let d = dict(&[b"1234567", SECRET]);
        assert_eq!(d.too_short(), 1);
        assert_eq!(d.credentials(), 1);
        assert!(d.find(b"pin 1234567").is_empty());
    }

    #[test]
    fn word_like_secrets_are_counted_as_weak_not_searched() {
        let d = dict(&[b"sunshine", b"12345678901", SECRET]);
        assert_eq!(d.weak(), 2);
        assert_eq!(d.credentials(), 1);
        // Otherwise every "sunshine" in ordinary prose would be a "leak", and
        // redacting them all would spell the password out by context.
        assert!(d.find(b"a sunshine day, call 12345678901").is_empty());
    }

    #[test]
    fn a_random_single_case_token_is_still_searched() {
        // One character class, under 12 bytes, but not a word.
        let d = dict(&[b"qzkxvbnmwpt"]);
        assert_eq!(d.weak(), 0);
        assert_eq!(d.find(b"token=qzkxvbnmwpt").len(), 1);
    }

    #[test]
    fn overlapping_credentials_are_both_removed() {
        let a: &[u8] = b"abcdefgh12345";
        let b: &[u8] = b"12345zyxwvuts";
        let d = dict(&[a, b]);
        let (out, n) = d.redact(b"x abcdefgh12345zyxwvuts y");
        assert_eq!(n, 1, "one merged span");
        let s = String::from_utf8(out).unwrap();
        assert!(
            s.starts_with("x [REDACTED:cred-") && s.ends_with("] y"),
            "{s}"
        );
        assert!(!s.contains("zyxw") && !s.contains("abcdefgh"));
    }

    #[test]
    fn the_same_secret_in_two_places_is_one_credential() {
        let d = dict(&[SECRET, SECRET, b"  hunter2-correct-horse-9Q\n"]);
        assert_eq!(d.credentials(), 1);
    }

    #[test]
    fn the_longer_of_two_overlapping_secrets_wins() {
        let short: &[u8] = b"abcdefgh12";
        let long: &[u8] = b"abcdefgh12345678";
        let d = dict(&[short, long]);
        let hits = d.find(b"x abcdefgh12345678 y");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].len, long.len());
    }

    #[test]
    fn redaction_removes_every_byte_of_the_secret_and_keeps_the_rest() {
        let d = dict(&[SECRET]);
        let text = [b"a ".as_slice(), SECRET, b" b ", SECRET, b" c"].concat();
        let (out, n) = d.redact(&text);
        assert_eq!(n, 2);
        assert!(d.find(&out).is_empty());
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with("a [REDACTED:cred-") && s.ends_with(" c"));
        assert!(!s.contains("hunter2"));
    }

    #[test]
    fn unrelated_text_is_left_alone() {
        let d = dict(&[SECRET]);
        let text = b"hunter2 correct horse, a git sha 0123456789abcdef0123456789abcdef01234567";
        assert!(d.find(text).is_empty());
        assert_eq!(d.redact(text), (text.to_vec(), 0));
    }
}
