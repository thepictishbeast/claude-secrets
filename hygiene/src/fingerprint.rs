//! Keyed fingerprints: the only form a credential is ever kept in.
//!
//! "Zero knowledge" here means something precise, and it is worth being
//! honest about what it is not. This is not a zk-SNARK. The scanner does
//! read each secret, transiently, in memory — there is no way to notice
//! that two plaintext secrets are equal without looking at them. What it
//! guarantees is that nothing it *keeps* or *prints* reveals one:
//!
//! * A secret is reduced to `HMAC-SHA256(pepper, secret)` the moment it is
//!   read, and the plaintext buffer is zeroized when it drops.
//! * The pepper lives in its own file, root-only. The fingerprints in the
//!   state file are therefore useless on their own: without the pepper
//!   you cannot test a guess against them, so a leaked state file cannot
//!   be dictionary-attacked the way a plain SHA-256 of a password could.
//! * Two locations sharing a fingerprint proves they share a credential.
//!   That equality is the only fact the fingerprints encode.
//!
//! Reports never carry fingerprints at all — only a short label derived
//! from one under the same pepper, so a label is stable between reports
//! but cannot be correlated with anything outside this machine.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Minimum pepper length. 32 bytes is the HMAC-SHA256 block-size-safe
/// choice and the size `init` generates.
const PEPPER_LEN: usize = 32;

/// The key every fingerprint is taken under.
pub struct Pepper(Zeroizing<Vec<u8>>);

impl Pepper {
    /// Load the pepper, refusing anything that would weaken the promise.
    ///
    /// There is deliberately no fallback to unkeyed hashing. A missing or
    /// exposed pepper is an error, because silently degrading to plain
    /// SHA-256 would produce a state file that *looks* the same and can
    /// be brute-forced offline.
    pub fn load(path: &Path) -> Result<Self, String> {
        let meta = std::fs::metadata(path).map_err(|e| {
            let hint = match e.kind() {
                std::io::ErrorKind::NotFound => " (run `init` first)",
                std::io::ErrorKind::PermissionDenied => " (the scan runs as root)",
                _ => "",
            };
            format!("pepper {}: {e}{hint}", path.display())
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "pepper {} is mode {mode:o}; it must be readable by its owner only (0400/0600)",
                path.display()
            ));
        }
        if meta.uid() != unsafe { geteuid() } {
            return Err(format!(
                "pepper {} is not owned by the user running the scan",
                path.display()
            ));
        }
        let mut buf = Zeroizing::new(Vec::with_capacity(PEPPER_LEN));
        std::fs::File::open(path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .map_err(|e| format!("pepper {}: {e}", path.display()))?;
        if buf.len() < PEPPER_LEN {
            return Err(format!(
                "pepper {} is {} bytes; it must be at least {PEPPER_LEN}",
                path.display(),
                buf.len()
            ));
        }
        Ok(Self(buf))
    }

    /// Create a new pepper. Refuses to overwrite: replacing the pepper
    /// silently resets every age the state file has accumulated.
    pub fn generate(path: &Path) -> Result<(), String> {
        if path.exists() {
            return Err(format!(
                "pepper {} already exists; refusing to replace it (that would reset all history)",
                path.display()
            ));
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        let mut key = Zeroizing::new(vec![0u8; PEPPER_LEN]);
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut key))
            .map_err(|e| format!("/dev/urandom: {e}"))?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        std::io::Write::write_all(&mut f, &key).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Build a pepper from bytes. Tests only.
    #[cfg(test)]
    pub fn from_bytes(b: &[u8]) -> Self {
        Self(Zeroizing::new(b.to_vec()))
    }

    fn mac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m =
            <HmacSha256 as KeyInit>::new_from_slice(&self.0).expect("HMAC takes any key length");
        for p in parts {
            m.update(p);
        }
        m.finalize().into_bytes().into()
    }

    /// The fingerprint of a secret, as hex. Domain-separated so a
    /// fingerprint can never collide with a label.
    #[must_use]
    pub fn fingerprint(&self, secret: &[u8]) -> String {
        hex(&self.mac(&[b"fp\0", secret]))
    }

    /// A short, report-safe label for a fingerprint.
    #[must_use]
    pub fn label(&self, fingerprint: &str) -> String {
        format!(
            "cred-{}",
            &hex(&self.mac(&[b"label\0", fingerprint.as_bytes()]))[..6]
        )
    }
}

fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

extern "C" {
    fn geteuid() -> u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fingerprint_is_keyed_so_a_leaked_state_file_is_useless_alone() {
        // The same secret under two peppers must give unrelated values.
        // If it did not, the state file could be attacked offline by
        // hashing guesses -- exactly what a pepper exists to prevent.
        let a = Pepper::from_bytes(&[1; 32]);
        let b = Pepper::from_bytes(&[2; 32]);
        assert_ne!(a.fingerprint(b"hunter2"), b.fingerprint(b"hunter2"));
        assert_eq!(a.fingerprint(b"hunter2"), a.fingerprint(b"hunter2"));
    }

    #[test]
    fn a_fingerprint_does_not_contain_the_secret() {
        let p = Pepper::from_bytes(&[7; 32]);
        let secret = "correct-horse-battery-staple";
        let fp = p.fingerprint(secret.as_bytes());
        assert!(!fp.contains(secret));
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn a_label_cannot_be_mistaken_for_a_fingerprint() {
        let p = Pepper::from_bytes(&[9; 32]);
        let fp = p.fingerprint(b"x");
        let label = p.label(&fp);
        assert!(label.starts_with("cred-") && label.len() == 11);
        assert!(
            !fp.contains(&label[5..]),
            "label must not be a substring of the fingerprint"
        );
    }

    #[test]
    fn an_exposed_pepper_is_refused_rather_than_used() {
        let dir = std::env::temp_dir().join(format!("hyg-pep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pepper");
        std::fs::write(&p, [3u8; 32]).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = Pepper::load(&p)
            .err()
            .expect("world-readable pepper must be refused");
        assert!(err.contains("owner only"), "{err}");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Pepper::load(&p).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_pepper_is_an_error_never_a_fallback() {
        let err = Pepper::load(Path::new("/nonexistent/pepper"))
            .err()
            .unwrap();
        assert!(err.contains("run `init` first"), "{err}");
    }

    #[test]
    fn generate_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("hyg-gen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let p = dir.join("pepper");
        Pepper::generate(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400);
        assert!(Pepper::generate(&p).is_err(), "a second init must refuse");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
