use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

use rayon::prelude::*;

use crate::algorithms::{bcrypt, md5, ntlm, sha};
use crate::attack::bruteforce::{generate_candidates, parse_mask};
use crate::progress::Progress;

/// Job description for a hybrid attack (wordlist + mask).
#[derive(Debug, Clone)]
pub struct HybridJob {
    pub hash: String,
    pub wordlist_path: String,
    /// Mask appended to each word. E.g. `?d?d` tries `word00..word99`.
    pub mask: String,
    pub algorithm: String,
    pub threads: usize,
}

fn candidate_matches(algo: &str, word: &str, target: &str) -> bool {
    if algo == "bcrypt" {
        return bcrypt::verify(word, target);
    }
    let hash = match algo {
        "md5" | "md5_or_ntlm" => md5::hash(word),
        "sha1" => sha::sha1(word),
        "sha256" => sha::sha256(word),
        "sha512" => sha::sha512(word),
        "ntlm" => ntlm::hash(word),
        _ => md5::hash(word),
    };
    hash == target
}

/// Run a hybrid attack: for each word in the wordlist, expand `mask` and
/// combine with the word as a prefix.  Returns the plaintext if found.
pub fn run_hybrid_attack(
    job: HybridJob,
    tx: Option<std::sync::mpsc::Sender<Progress>>,
) -> Result<Option<String>, String> {
    let file = File::open(&job.wordlist_path)
        .map_err(|e| format!("Cannot open wordlist '{}': {}", job.wordlist_path, e))?;

    let reader = BufReader::new(file);
    let words: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .map(|l| l.trim_end_matches('\r').to_string())
        .collect();

    let mask_segments = parse_mask(&job.mask)?;

    let algo = job.algorithm.to_lowercase();
    let target = if algo == "bcrypt" {
        job.hash.clone()
    } else {
        job.hash.to_lowercase()
    };
    let found = Arc::new(Mutex::new(None::<String>));
    let stop = Arc::new(AtomicBool::new(false));
    let tried = Arc::new(AtomicU64::new(0));
    let last_progress_emit_ms = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(job.threads.max(1))
        .build()
        .map_err(|e| format!("Thread pool error: {e}"))?;

    pool.install(|| {
        words.par_iter().for_each(|word| {
            if stop.load(Ordering::Relaxed) {
                return;
            }

            if mask_segments.is_empty() {
                // No mask – just hash the word directly
                let matched = candidate_matches(&algo, word, &target);
                let _current = tried.fetch_add(1, Ordering::Relaxed) + 1;
                if matched {
                    stop.store(true, Ordering::Relaxed);
                    *found.lock().unwrap() = Some(word.clone());
                }
                if let Some(ref sender) = tx {
                    let elapsed = start.elapsed().as_millis() as u64;
                    let last = last_progress_emit_ms.load(Ordering::Relaxed);
                    if elapsed.saturating_sub(last) >= 100
                        && last_progress_emit_ms
                            .compare_exchange(last, elapsed, Ordering::Relaxed, Ordering::Relaxed)
                            .is_ok()
                    {
                        let total = tried.load(Ordering::Relaxed);
                        let elapsed_ms = if total > 0 && elapsed == 0 {
                            1
                        } else {
                            elapsed
                        };
                        let speed = total as f64 / (elapsed_ms as f64 / 1000.0);
                        let _ = sender.send(Progress {
                            tried: total,
                            speed,
                            elapsed_ms: elapsed_ms as u128,
                        });
                    }
                }
                return;
            }

            // Use word bytes as initial buffer prefix then expand mask
            let buf_prefix = word.as_bytes().to_vec();
            let mut buf = buf_prefix;
            generate_candidates(
                &mask_segments,
                &mut buf,
                &target,
                &algo,
                &found,
                &stop,
                &tried,
                &last_progress_emit_ms,
                &start,
                &tx,
            );
        });
    });

    // Final progress update
    if let Some(ref sender) = tx {
        let elapsed = start.elapsed().as_millis() as u64;
        let total = tried.load(Ordering::Relaxed);
        let elapsed_ms = if total > 0 && elapsed == 0 {
            1
        } else {
            elapsed
        };
        let speed = total as f64 / (elapsed_ms as f64 / 1000.0);
        let _ = sender.send(Progress {
            tried: total,
            speed,
            elapsed_ms: elapsed_ms as u128,
        });
    }

    let result = found.lock().unwrap().clone();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithms::md5;
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
    fn test_hybrid_found() {
        // target is MD5 of "pass" + "42" = MD5("pass42")
        let target = md5::hash("pass42");
        let wl = make_wordlist(&["pass", "word", "hello"]);
        let job = HybridJob {
            hash: target,
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            mask: "?d?d".to_string(),
            algorithm: "md5".to_string(),
            threads: 2,
        };
        let result = run_hybrid_attack(job, None).unwrap();
        assert_eq!(result, Some("pass42".to_string()));
    }

    #[test]
    fn test_hybrid_not_found() {
        let wl = make_wordlist(&["foo", "bar"]);
        let job = HybridJob {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(), // MD5("password")
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            mask: "?d?d".to_string(),
            algorithm: "md5".to_string(),
            threads: 1,
        };
        let result = run_hybrid_attack(job, None).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_hybrid_bcrypt_found() {
        let target = ::bcrypt::hash("pass4", 4).unwrap();
        let wl = make_wordlist(&["pass", "word"]);
        let job = HybridJob {
            hash: target,
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            mask: "?d".to_string(),
            algorithm: "bcrypt".to_string(),
            threads: 1,
        };
        let result = run_hybrid_attack(job, None).unwrap();
        assert_eq!(result, Some("pass4".to_string()));
    }
}
