/// Detect the hash type based on length, prefix, and charset.
/// Returns (algorithm_name, confidence_percentage, difficulty_level)
pub fn detect_hash_type(hash: &str) -> (String, f32, String) {
    let h = hash.trim();

    // Prefix-based detection (most specific)
    if h.starts_with("$2y$") || h.starts_with("$2b$") || h.starts_with("$2a$") {
        return ("bcrypt".to_string(), 99.0, "very_hard".to_string());
    }
    if h.starts_with("$6$") {
        return ("sha512crypt".to_string(), 99.0, "hard".to_string());
    }
    if h.starts_with("$1$") {
        return ("md5crypt".to_string(), 99.0, "medium".to_string());
    }
    if h.starts_with("$5$") {
        return ("sha256crypt".to_string(), 99.0, "hard".to_string());
    }

    // Length + charset based detection
    let len = h.len();
    let all_hex = h.chars().all(|c| c.is_ascii_hexdigit());

    match (len, all_hex) {
        (32, true) => ("md5".to_string(), 95.0, "easy".to_string()),
        (32, false) => ("md5".to_string(), 60.0, "easy".to_string()),
        (40, true) => ("sha1".to_string(), 95.0, "medium".to_string()),
        (40, false) => ("sha1".to_string(), 60.0, "medium".to_string()),
        (64, true) => ("sha256".to_string(), 95.0, "hard".to_string()),
        (64, false) => ("sha256".to_string(), 60.0, "hard".to_string()),
        (128, true) => ("sha512".to_string(), 95.0, "very_hard".to_string()),
        (128, false) => ("sha512".to_string(), 60.0, "very_hard".to_string()),
        // NTLM is also 32 hex chars, same as MD5, lower confidence
        _ => {
            if len == 32 && all_hex {
                ("md5_or_ntlm".to_string(), 80.0, "easy".to_string())
            } else {
                ("unknown".to_string(), 0.0, "unknown".to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_md5() {
        let (algo, conf, _) = detect_hash_type("5f4dcc3b5aa765d61d8327deb882cf99");
        assert_eq!(algo, "md5");
        assert!(conf >= 90.0);
    }

    #[test]
    fn test_detect_sha1() {
        let (algo, conf, _) = detect_hash_type("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8");
        assert_eq!(algo, "sha1");
        assert!(conf >= 90.0);
    }

    #[test]
    fn test_detect_sha256() {
        let (algo, conf, _) =
            detect_hash_type("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8");
        assert_eq!(algo, "sha256");
        assert!(conf >= 90.0);
    }

    #[test]
    fn test_detect_bcrypt() {
        let (algo, conf, _) =
            detect_hash_type("$2b$12$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgK");
        assert_eq!(algo, "bcrypt");
        assert!(conf >= 99.0);
    }

    #[test]
    fn test_detect_sha512crypt() {
        let (algo, conf, _) = detect_hash_type(
            "$6$rounds=5000$usesomesillysalt$D4ILAMEZknRRQlNvpnMYjWB/O78RCgJlQTTmFzFVoOZmOh.2PJkOyBkFZFLNT68x8cEiDRpbfzHJEkXyqT1u.",
        );
        assert_eq!(algo, "sha512crypt");
        assert!(conf >= 99.0);
    }

    #[test]
    fn test_detect_unknown() {
        let (algo, _, _) = detect_hash_type("notahash");
        assert_eq!(algo, "unknown");
    }
}
