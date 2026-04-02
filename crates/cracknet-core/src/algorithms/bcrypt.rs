/// Verify a plaintext against a bcrypt hash.
pub fn verify(plaintext: &str, hash: &str) -> bool {
    bcrypt::verify(plaintext, hash).unwrap_or(false)
}

/// Extract the cost factor from a bcrypt hash prefix.
pub fn cost_factor(hash: &str) -> Option<u32> {
    // bcrypt hashes look like: $2b$12$...
    let parts: Vec<&str> = hash.split('$').collect();
    if parts.len() >= 3 {
        parts[2].parse::<u32>().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bcrypt_verify() {
        // Generate and verify a fresh bcrypt hash
        let hash = bcrypt::hash("password", 4).unwrap();
        assert!(verify("password", &hash));
        assert!(!verify("wrong_password", &hash));
    }

    #[test]
    fn test_cost_factor() {
        let hash = bcrypt::hash("password", 12).unwrap();
        assert_eq!(cost_factor(&hash), Some(12));
    }
}
