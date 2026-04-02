use digest::Digest;
use hex::encode;
use md5::Md5;

/// Compute the MD5 hash of the input string, returning a lowercase hex string.
pub fn hash(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_md5_password() {
        assert_eq!(hash("password"), "5f4dcc3b5aa765d61d8327deb882cf99");
    }

    #[test]
    fn test_md5_empty() {
        assert_eq!(hash(""), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
