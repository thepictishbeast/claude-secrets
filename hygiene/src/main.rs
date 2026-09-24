//! claude-secrets-hygiene — find reused and unrotated credentials without
//! ever storing or printing one.
//!
//!   claude-secrets-hygiene init              create the pepper (once)
//!   claude-secrets-hygiene scan [--notify A] update history, write the report
//!   claude-secrets-hygiene check             same audit, read-only
//!
//! Exit status: 0 nothing found, 1 findings, 2 could not run.

use claude_secrets_hygiene::audit::{render, run, Config, Finding};
use claude_secrets_hygiene::fingerprint::Pepper;
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
        _ => {
            eprintln!("usage: claude-secrets-hygiene init | scan [--notify ADDR] | check\n  [--config C] [--pepper P] [--state S] [--report R]");
            std::process::exit(2);
        }
    }
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
