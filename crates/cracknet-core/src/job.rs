use serde::{Deserialize, Serialize};
use std::sync::mpsc::Sender;

use crate::attack::{
    bruteforce::{run_bruteforce_attack, BruteforceJob},
    dictionary::run_dictionary_attack,
    hybrid::{run_hybrid_attack, HybridJob},
    AttackJob,
};
use crate::progress::Progress;

/// A cracking job specification (Phase 2 extended).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub hash: String,
    /// Wordlist path – required for dictionary and hybrid modes.
    #[serde(default)]
    pub wordlist: Option<String>,
    pub algorithm: String,
    #[serde(default = "default_threads")]
    pub threads: usize,
    /// Mask string (e.g. `pass?d?d`) – required for bruteforce and hybrid modes.
    #[serde(default)]
    pub mask: Option<String>,
    /// Attack mode: `dictionary`, `bruteforce`, `hybrid`, or `auto`.
    /// `auto` picks based on the presence of wordlist/mask.
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_threads() -> usize {
    4
}

fn default_mode() -> String {
    "auto".to_string()
}

/// The result of a cracking job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub cracked: bool,
    pub plaintext: Option<String>,
    pub elapsed_ms: u64,
}

/// Resolve the effective attack mode from `auto`.
fn resolve_mode(mode: &str, has_wordlist: bool, has_mask: bool) -> &'static str {
    match mode {
        "dictionary" => "dictionary",
        "bruteforce" => "bruteforce",
        "hybrid" => "hybrid",
        // auto: pick based on what's provided
        _ => match (has_wordlist, has_mask) {
            (true, true) => "hybrid",
            (false, true) => "bruteforce",
            _ => "dictionary",
        },
    }
}

/// Execute a cracking job with an optional progress sender and return the result.
pub fn execute_job_with_progress(
    job: Job,
    tx: Option<Sender<Progress>>,
) -> Result<JobResult, String> {
    let start = std::time::Instant::now();

    let has_wordlist = job.wordlist.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
    let has_mask = job.mask.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
    let effective_mode = resolve_mode(&job.mode, has_wordlist, has_mask);

    let plaintext = match effective_mode {
        "bruteforce" => {
            let mask = job
                .mask
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or("bruteforce mode requires --mask")?;
            run_bruteforce_attack(
                BruteforceJob {
                    hash: job.hash.clone(),
                    mask: mask.to_string(),
                    algorithm: job.algorithm.clone(),
                    threads: job.threads,
                },
                tx,
            )?
        }
        "hybrid" => {
            let wordlist = job
                .wordlist
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or("hybrid mode requires --wordlist")?;
            let mask = job
                .mask
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or("hybrid mode requires --mask")?;
            run_hybrid_attack(
                HybridJob {
                    hash: job.hash.clone(),
                    wordlist_path: wordlist.to_string(),
                    mask: mask.to_string(),
                    algorithm: job.algorithm.clone(),
                    threads: job.threads,
                },
                tx,
            )?
        }
        // "dictionary" and fallback
        _ => {
            let wordlist = job
                .wordlist
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or("dictionary mode requires --wordlist")?;
            run_dictionary_attack(
                AttackJob {
                    hash: job.hash.clone(),
                    wordlist_path: wordlist.to_string(),
                    algorithm: job.algorithm.clone(),
                    threads: job.threads,
                },
                tx,
            )?
        }
    };

    let elapsed_ms = start.elapsed().as_millis() as u64;

    Ok(JobResult {
        cracked: plaintext.is_some(),
        plaintext,
        elapsed_ms,
    })
}

/// Execute a cracking job and return the result.
pub fn execute_job(job: Job) -> Result<JobResult, String> {
    execute_job_with_progress(job, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_wordlist(words: &[&str]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for w in words {
            writeln!(f, "{}", w).unwrap();
        }
        f
    }

    #[test]
    fn test_execute_job_dictionary_found() {
        let f = make_wordlist(&["password", "hello"]);

        let job = Job {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            wordlist: Some(f.path().to_str().unwrap().to_string()),
            algorithm: "md5".to_string(),
            threads: 2,
            mask: None,
            mode: "dictionary".to_string(),
        };

        let result = execute_job(job).unwrap();
        assert!(result.cracked);
        assert_eq!(result.plaintext, Some("password".to_string()));
    }

    #[test]
    fn test_execute_job_dictionary_not_found() {
        let f = make_wordlist(&["nottheword"]);

        let job = Job {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            wordlist: Some(f.path().to_str().unwrap().to_string()),
            algorithm: "md5".to_string(),
            threads: 1,
            mask: None,
            mode: "dictionary".to_string(),
        };

        let result = execute_job(job).unwrap();
        assert!(!result.cracked);
        assert_eq!(result.plaintext, None);
    }

    #[test]
    fn test_execute_job_bruteforce() {
        use crate::algorithms::md5;
        let target = md5::hash("42");
        let job = Job {
            hash: target,
            wordlist: None,
            algorithm: "md5".to_string(),
            threads: 2,
            mask: Some("?d?d".to_string()),
            mode: "bruteforce".to_string(),
        };
        let result = execute_job(job).unwrap();
        assert!(result.cracked);
        assert_eq!(result.plaintext, Some("42".to_string()));
    }

    #[test]
    fn test_execute_job_auto_picks_dictionary() {
        let f = make_wordlist(&["password"]);
        let job = Job {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            wordlist: Some(f.path().to_str().unwrap().to_string()),
            algorithm: "md5".to_string(),
            threads: 1,
            mask: None,
            mode: "auto".to_string(),
        };
        let result = execute_job(job).unwrap();
        assert!(result.cracked);
    }

    #[test]
    fn test_execute_job_auto_picks_bruteforce() {
        use crate::algorithms::md5;
        let target = md5::hash("z");
        let job = Job {
            hash: target,
            wordlist: None,
            algorithm: "md5".to_string(),
            threads: 1,
            mask: Some("?l".to_string()),
            mode: "auto".to_string(),
        };
        let result = execute_job(job).unwrap();
        assert!(result.cracked);
        assert_eq!(result.plaintext, Some("z".to_string()));
    }
}

