use crate::algorithms::{bcrypt, md5, ntlm, sha};
use pwhash::{md5_crypt, sha256_crypt, sha512_crypt};
use std::panic::{catch_unwind, AssertUnwindSafe};

pub fn is_supported_algorithm(algo: &str) -> bool {
    matches!(
        algo,
        "md5"
            | "md5_or_ntlm"
            | "sha1"
            | "sha256"
            | "sha512"
            | "ntlm"
            | "bcrypt"
            | "md5crypt"
            | "sha256crypt"
            | "sha512crypt"
    )
}

pub fn normalize_target_hash(algo: &str, hash: &str) -> String {
    if matches!(algo, "bcrypt" | "md5crypt" | "sha256crypt" | "sha512crypt") {
        hash.to_string()
    } else {
        hash.to_lowercase()
    }
}

pub fn candidate_matches(algo: &str, candidate: &str, target: &str) -> bool {
    match algo {
        "bcrypt" => bcrypt::verify(candidate, target),
        "md5" | "md5_or_ntlm" => md5::hash(candidate) == target,
        "sha1" => sha::sha1(candidate) == target,
        "sha256" => sha::sha256(candidate) == target,
        "sha512" => sha::sha512(candidate) == target,
        "ntlm" => ntlm::hash(candidate) == target,
        "md5crypt" => safe_verify(|| md5_crypt::verify(candidate, target)),
        "sha256crypt" => safe_verify(|| sha256_crypt::verify(candidate, target)),
        "sha512crypt" => safe_verify(|| sha512_crypt::verify(candidate, target)),
        _ => false,
    }
}

fn safe_verify<F>(verify_fn: F) -> bool
where
    F: FnOnce() -> bool,
{
    catch_unwind(AssertUnwindSafe(verify_fn)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_md5crypt_vector() {
        let hash = "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0";
        assert!(candidate_matches("md5crypt", "password", hash));
        assert!(!candidate_matches("md5crypt", "wrong", hash));
    }

    #[test]
    fn test_verify_sha256crypt_vector() {
        let hash = "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1";
        assert!(candidate_matches("sha256crypt", "test", hash));
        assert!(!candidate_matches("sha256crypt", "wrong", hash));
    }

    #[test]
    fn test_verify_sha512crypt_vector() {
        let hash = "$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1";
        assert!(candidate_matches("sha512crypt", "test", hash));
        assert!(!candidate_matches("sha512crypt", "wrong", hash));
    }
}
