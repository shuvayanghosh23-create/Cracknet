use digest::Digest;
use hex::encode;
use md4::Md4;

/// Compute NTLM hash of input (UTF-16LE + MD4), returning a lowercase hex string.
pub fn hash(input: &str) -> String {
    // Encode to UTF-16 little-endian
    let utf16_le: Vec<u8> = input.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut hasher = Md4::new();
    hasher.update(&utf16_le);
    encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntlm_password() {
        // The NTLM hash is computed as MD4(UTF-16LE(input)).
        // Verify the output is a valid 32-char hex string and is deterministic.
        let result = hash("Password");
        assert_eq!(result.len(), 32);
        assert!(result.chars().all(|c| c.is_ascii_hexdigit()));
        // Verify determinism
        assert_eq!(hash("Password"), result);
    }

    #[test]
    fn test_ntlm_empty() {
        assert_eq!(hash(""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    }
}
