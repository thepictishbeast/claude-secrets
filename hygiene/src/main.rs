//! claude-secrets-hygiene — find reused and unrotated credentials without
//! ever storing or printing one.
//!
//!   claude-secrets-hygiene init              create the pepper (once)
//!   claude-secrets-hygiene scan [--notify A] update history, write the report
//!   claude-secrets-hygiene check             same audit, read-only
//!   claude-secrets-hygiene find-in PATH...   count known credentials in files
//!   claude-secrets-hygiene redact-in PATH... replace them, in place
//!
//! `find-in` reads directories recursively, `.gz` files through gzip, and
//! `-` as stdin. Both name a credential only by its report label.
//!
//! Exit status: 0 nothing found, 1 findings, 2 could not run.

use claude_secrets_hygiene::audit::{render, run, Config, Finding};
use claude_secrets_hygiene::fingerprint::Pepper;
use claude_secrets_hygiene::known::{Dictionary, MIN_LEN};
use claude_secrets_hygiene::state::State;
use claude_secrets_hygiene::ymd;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

const PEPPER: &str = "/etc/claude-secrets/hygiene.pepper";
const CONFIG: &str = "/etc/claude-secrets/hygiene.conf";
const STATE: &str = "/var/lib/claude-secrets/hygiene.state";
// Root-only by default: a list of where every credential lives is itself
// worth protecting, even with no credential in it.
const REPORT: &str = "/var/lib/claude-secrets/hygiene-report.txt";

fn flag(args: &[String], name: &str, default: &str) -> PathBuf {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map_or_else(|| PathBuf::from(default), PathBuf::from)
}

fn die(msg: &str) -> ! {
    eprintln!("claude-secrets-hygiene: {msg}");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map_or("", String::as_str);
    let pepper_path = flag(&args, "--pepper", PEPPER);

    match cmd {
        "init" => match Pepper::generate(&pepper_path) {
            Ok(()) => println!(
                "pepper created at {} (0400); keep it off backups that leave this machine",
                pepper_path.display()
            ),
            Err(e) => die(&e),
        },
        "scan" | "check" => {
            let read_only = cmd == "check";
            let cfg_path = flag(&args, "--config", CONFIG);
            let state_path = flag(&args, "--state", STATE);
            let report_path = flag(&args, "--report", REPORT);
            let pepper = Pepper::load(&pepper_path).unwrap_or_else(|e| die(&e));
            let cfg_text = std::fs::read_to_string(&cfg_path)
                .unwrap_or_else(|e| die(&format!("{}: {e}", cfg_path.display())));
            let cfg = Config::parse(&cfg_text)
                .unwrap_or_else(|e| die(&format!("{}: {e}", cfg_path.display())));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());

            // `check` audits against a copy, so a dry run never resets anyone's
            // rotation history or starts a lower-bound clock it should not.
            let mut state = State::load(&state_path);
            let outcome = run(&cfg, &pepper, &mut state, now);
            let report = render(&outcome, cfg.stale_days, &ymd(now));
            print!("{report}");

            if !read_only {
                state.save(&state_path).unwrap_or_else(|e| die(&e));
                write_private(&report_path, &report).unwrap_or_else(|e| die(&e));
                if let Some(addr) = args
                    .iter()
                    .position(|a| a == "--notify")
                    .and_then(|i| args.get(i + 1))
                {
                    notify_on_change(addr, &state_path, &outcome.findings, &report);
                }
            }
            if !outcome.findings.is_empty() {
                std::process::exit(1);
            }
        }
        "labels" => {
            // Which location each label stands for, and the SHAPE of the
            // secret (length, character classes) -- enough to judge whether a
            // value is too common to search for, without showing it.
            let cfg_path = flag(&args, "--config", CONFIG);
            let pepper = Pepper::load(&pepper_path).unwrap_or_else(|e| die(&e));
            let cfg_text = std::fs::read_to_string(&cfg_path)
                .unwrap_or_else(|e| die(&format!("{}: {e}", cfg_path.display())));
            let cfg = Config::parse(&cfg_text)
                .unwrap_or_else(|e| die(&format!("{}: {e}", cfg_path.display())));
            for (kind, pattern) in &cfg.sources {
                for path in claude_secrets_hygiene::audit::expand(pattern) {
                    for c in claude_secrets_hygiene::extract::extract(kind, &path) {
                        let s = c.secret.trim_ascii();
                        let class = |f: fn(&u8) -> bool, name: &'static str| {
                            s.iter().any(f).then_some(name)
                        };
                        let classes: Vec<&str> = [
                            class(u8::is_ascii_lowercase, "lower"),
                            class(u8::is_ascii_uppercase, "upper"),
                            class(u8::is_ascii_digit, "digit"),
                            class(|b| b.is_ascii_punctuation(), "punct"),
                            class(|b| !b.is_ascii(), "non-ascii"),
                        ]
                        .into_iter()
                        .flatten()
                        .collect();
                        println!(
                            "{}  len={:<4} {:<24} {}",
                            pepper.label(&pepper.fingerprint(s)),
                            s.len(),
                            classes.join("+"),
                            c.location
                        );
                    }
                }
            }
        }
        "find-in" | "redact-in" => {
            let cfg_path = flag(&args, "--config", CONFIG);
            let pepper = Pepper::load(&pepper_path).unwrap_or_else(|e| die(&e));
            let cfg_text = std::fs::read_to_string(&cfg_path)
                .unwrap_or_else(|e| die(&format!("{}: {e}", cfg_path.display())));
            let cfg = Config::parse(&cfg_text)
                .unwrap_or_else(|e| die(&format!("{}: {e}", cfg_path.display())));
            let dict = Dictionary::load(&cfg, &pepper);
            let targets = operands(&args);
            if targets.is_empty() {
                die("name at least one file, directory, or - for stdin");
            }
            let hits = if cmd == "find-in" {
                find_in(&dict, &targets)
            } else {
                redact_in(&dict, &targets)
            };
            if hits > 0 {
                std::process::exit(1);
            }
        }
        _ => {
            eprintln!("usage: claude-secrets-hygiene init | scan [--notify ADDR] | check | find-in PATH... | redact-in PATH...\n  [--config C] [--pepper P] [--state S] [--report R]");
            std::process::exit(2);
        }
    }
}

/// The non-flag arguments after the subcommand.
fn operands(args: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter().skip(1);
    while let Some(a) = it.next() {
        if a.starts_with("--") {
            it.next(); // every flag here takes a value
        } else {
            out.push(a.clone());
        }
    }
    out
}

/// Regular files under `target`, recursively; `-` stands for stdin.
fn files_under(target: &str) -> Vec<PathBuf> {
    let p = PathBuf::from(target);
    if target == "-" || !p.is_dir() {
        return vec![p];
    }
    let mut out = Vec::new();
    let mut stack = vec![p];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            die(&format!("{}: cannot read directory", dir.display()));
        };
        for e in rd.filter_map(Result::ok) {
            let path = e.path();
            match e.file_type() {
                Ok(t) if t.is_dir() => stack.push(path),
                Ok(t) if t.is_file() => out.push(path),
                _ => {}
            }
        }
    }
    out.sort();
    out
}

fn read_all(path: &PathBuf) -> Vec<u8> {
    use std::io::Read;
    if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .unwrap_or_else(|e| die(&format!("stdin: {e}")));
        return buf;
    }
    if path.extension().is_some_and(|x| x == "gz") {
        let out = std::process::Command::new("gzip")
            .arg("-dc")
            .arg(path)
            .output()
            .unwrap_or_else(|e| die(&format!("gzip: {e}")));
        if !out.status.success() {
            die(&format!("{}: gzip could not read it", path.display()));
        }
        return out.stdout;
    }
    std::fs::read(path).unwrap_or_else(|e| die(&format!("{}: {e}", path.display())))
}

fn coverage_line(dict: &Dictionary, files: usize, hits: usize, with_hits: usize) -> String {
    let mut unsearched = Vec::new();
    if dict.too_short() > 0 {
        unsearched.push(format!("{} shorter than {MIN_LEN} bytes", dict.too_short()));
    }
    if dict.weak() > 0 {
        unsearched.push(format!("{} word-like (weak: rotate)", dict.weak()));
    }
    let short = if unsearched.is_empty() {
        String::new()
    } else {
        format!(" (not searchable: {})", unsearched.join(", "))
    };
    format!(
        "searched {files} file(s) for {} known credential(s){short}: {hits} occurrence(s) in {with_hits} file(s)",
        dict.credentials()
    )
}

/// Count occurrences per file. Never prints a value or a location.
fn find_in(dict: &Dictionary, targets: &[String]) -> usize {
    let (mut files, mut total, mut with_hits) = (0, 0, 0);
    for t in targets {
        for path in files_under(t) {
            files += 1;
            let by = dict.count(&read_all(&path));
            let n: usize = by.values().sum();
            if n > 0 {
                with_hits += 1;
                total += n;
                let labels: Vec<String> = by.iter().map(|(l, c)| format!("{l}×{c}")).collect();
                println!("{}: {n} ({})", path.display(), labels.join(", "));
            }
        }
    }
    println!("{}", coverage_line(dict, files, total, with_hits));
    total
}

/// Replace occurrences in place. Refuses stdin and compressed files: a
/// redacted copy must land where the caller expects it, atomically.
fn redact_in(dict: &Dictionary, targets: &[String]) -> usize {
    use std::os::unix::fs::PermissionsExt;
    let (mut files, mut total, mut with_hits) = (0, 0, 0);
    for t in targets {
        for path in files_under(t) {
            if path.as_os_str() == "-" || path.extension().is_some_and(|x| x == "gz") {
                die(&format!(
                    "{}: redact-in only rewrites plain files",
                    path.display()
                ));
            }
            files += 1;
            let (out, n) = dict.redact(&read_all(&path));
            if n == 0 {
                continue;
            }
            with_hits += 1;
            total += n;
            let mode = std::fs::metadata(&path).map_or(0o600, |m| m.permissions().mode() & 0o777);
            let tmp = path.with_extension("redact-tmp");
            let _ = std::fs::remove_file(&tmp);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .open(&tmp)
                .unwrap_or_else(|e| die(&format!("{}: {e}", tmp.display())));
            f.write_all(&out)
                .and_then(|()| f.sync_all())
                .unwrap_or_else(|e| die(&format!("{}: {e}", tmp.display())));
            std::fs::rename(&tmp, &path)
                .unwrap_or_else(|e| die(&format!("{}: {e}", path.display())));
            println!("{}: {n} replaced", path.display());
        }
    }
    println!("{}", coverage_line(dict, files, total, with_hits));
    total
}

fn write_private(path: &PathBuf, body: &str) -> Result<(), String> {
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
    f.write_all(body.as_bytes())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Mail the report only when the set of findings changes. The digest is
/// over each finding's identity, which leaves out ages, so an unchanged
/// situation is one message, not one a day nobody reads.
fn notify_on_change(addr: &str, state_path: &std::path::Path, findings: &[Finding], report: &str) {
    let ids: Vec<String> = findings.iter().map(Finding::identity).collect();
    let digest: String = Sha256::digest(ids.join("\n").as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let sig_path = state_path.with_extension("notified");
    if std::fs::read_to_string(&sig_path)
        .map(|s| s.trim() == digest)
        .unwrap_or(false)
    {
        return;
    }
    let _ = write_private(&sig_path.to_path_buf(), &digest);
    if ids.is_empty() {
        return;
    }
    let host = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_owned())
        .unwrap_or_default();
    let Ok(mut child) = std::process::Command::new("/usr/sbin/sendmail")
        .arg("-t")
        .stdin(std::process::Stdio::piped())
        .spawn()
    else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = write!(
            stdin,
            "To: {addr}\nFrom: credential-hygiene <root@{host}>\nSubject: [credential-hygiene] findings changed on {host}\n\
             Content-Type: text/plain; charset=utf-8\n\n{report}"
        );
    }
    let _ = child.wait();
}
