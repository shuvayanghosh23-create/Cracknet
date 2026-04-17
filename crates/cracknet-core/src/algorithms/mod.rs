pub mod bcrypt;
pub mod matcher;
pub mod md5;
pub mod ntlm;
pub mod sha;

/// Common trait for hash algorithms.
pub trait HashAlgorithm {
    fn hash(&self, input: &str) -> String;
}
