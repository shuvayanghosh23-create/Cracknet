use digest::Digest;
use hex::encode;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// Compute SHA-1 of input, returning a lowercase hex string.
pub fn sha1(input: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(input.as_bytes());
    encode(hasher.finalize())
}

/// Compute SHA-256 of input, returning a lowercase hex string.
pub fn sha256(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    encode(hasher.finalize())
}

/// Compute SHA-512 of input, returning a lowercase hex string.
pub fn sha512(input: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_password() {
        assert_eq!(sha1("password"), "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
    }

    #[test]
    fn test_sha256_password() {
        assert_eq!(
            sha256("password"),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
    }

    #[test]
    fn test_sha512_password() {
        // SHA-512 produces 128 hex characters
        let result = sha512("password");
        assert_eq!(result.len(), 128);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
        // Known SHA-512 of "password"
        assert_eq!(
            result,
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
        );
    }
}
