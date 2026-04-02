pub mod dictionary;

use serde::{Deserialize, Serialize};

/// Describes a cracking job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackJob {
    pub hash: String,
    pub wordlist_path: String,
    pub algorithm: String,
    pub threads: usize,
}
