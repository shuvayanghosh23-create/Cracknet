use serde::{Deserialize, Serialize};

use crate::attack::{dictionary::run_dictionary_attack, AttackJob};

/// A cracking job specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub hash: String,
    pub wordlist: String,
    pub algorithm: String,
    pub threads: usize,
}

/// The result of a cracking job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub cracked: bool,
    pub plaintext: Option<String>,
    pub elapsed_ms: u64,
}

/// Execute a cracking job and return the result.
pub fn execute_job(job: Job) -> Result<JobResult, String> {
    let start = std::time::Instant::now();

    let attack_job = AttackJob {
        hash: job.hash.clone(),
        wordlist_path: job.wordlist.clone(),
        algorithm: job.algorithm.clone(),
        threads: job.threads,
    };

    let plaintext = run_dictionary_attack(attack_job, None)?;
    let elapsed_ms = start.elapsed().as_millis() as u64;

    Ok(JobResult {
        cracked: plaintext.is_some(),
        plaintext,
        elapsed_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_execute_job_found() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "password").unwrap();
        writeln!(f, "hello").unwrap();

        let job = Job {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            wordlist: f.path().to_str().unwrap().to_string(),
            algorithm: "md5".to_string(),
            threads: 2,
        };

        let result = execute_job(job).unwrap();
        assert!(result.cracked);
        assert_eq!(result.plaintext, Some("password".to_string()));
    }

    #[test]
    fn test_execute_job_not_found() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(f, "nottheword").unwrap();

        let job = Job {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            wordlist: f.path().to_str().unwrap().to_string(),
            algorithm: "md5".to_string(),
            threads: 1,
        };

        let result = execute_job(job).unwrap();
        assert!(!result.cracked);
        assert_eq!(result.plaintext, None);
    }
}
