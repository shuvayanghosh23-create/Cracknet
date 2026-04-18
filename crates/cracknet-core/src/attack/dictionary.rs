use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

use rayon::prelude::*;

use crate::algorithms::matcher;
use crate::attack::AttackJob;
use crate::progress::Progress;

/// Run a dictionary attack on the given job.
/// Returns the plaintext if found, or None.
/// Sends progress updates every 100 ms via the optional sender.
pub fn run_dictionary_attack(
    job: AttackJob,
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

    let found = Arc::new(std::sync::Mutex::new(None::<String>));
    let stop = Arc::new(AtomicBool::new(false));

    let tried = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let last_progress_emit_ms = Arc::new(AtomicU64::new(0));
    let start = Instant::now();

    // Build thread pool respecting the requested thread count
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(job.threads.max(1))
        .build()
        .map_err(|e| format!("Thread pool error: {e}"))?;

    let algo = job.algorithm.to_lowercase();
    let target = matcher::normalize_target_hash(&algo, &job.hash);

    pool.install(|| {
        words.par_iter().for_each(|word| {
            if stop.load(Ordering::Relaxed) {
                return;
            }

            let matched = matcher::candidate_matches(&algo, word, &target);

            let _current = tried.fetch_add(1, Ordering::Relaxed) + 1;

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

            if matched {
                stop.store(true, Ordering::Relaxed);
                let mut guard = found.lock().unwrap();
                *guard = Some(word.clone());
            }
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
    fn test_dictionary_md5_found() {
        let wl = make_wordlist(&["hello", "world", "password", "test"]);
        let job = AttackJob {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            algorithm: "md5".to_string(),
            threads: 2,
        };
        let result = run_dictionary_attack(job, None).unwrap();
        assert_eq!(result, Some("password".to_string()));
    }

    #[test]
    fn test_dictionary_md5_not_found() {
        let wl = make_wordlist(&["hello", "world"]);
        let job = AttackJob {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(), // MD5 of "password"
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            algorithm: "md5".to_string(),
            threads: 1,
        };
        let result = run_dictionary_attack(job, None).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_dictionary_bcrypt_found() {
        let wl = make_wordlist(&["hello", "password", "world"]);
        let bcrypt_hash = ::bcrypt::hash("password", 4).unwrap();
        let job = AttackJob {
            hash: bcrypt_hash,
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            algorithm: "bcrypt".to_string(),
            threads: 1,
        };
        let result = run_dictionary_attack(job, None).unwrap();
        assert_eq!(result, Some("password".to_string()));
    }

    #[test]
    fn test_dictionary_md5crypt_found() {
        let wl = make_wordlist(&["hello", "password", "world"]);
        let job = AttackJob {
            hash: "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0".to_string(),
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            algorithm: "md5crypt".to_string(),
            threads: 1,
        };
        let result = run_dictionary_attack(job, None).unwrap();
        assert_eq!(result, Some("password".to_string()));
    }

    #[test]
    fn test_dictionary_sha256crypt_found() {
        let wl = make_wordlist(&["hello", "test", "world"]);
        let job = AttackJob {
            hash: "$5$rounds=11858$WH1ABM5sKhxbkgCK$aTQsjPkz0rBsH3lQlJxw9HDTDXPKBxC0LlVeV69P.t1"
                .to_string(),
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            algorithm: "sha256crypt".to_string(),
            threads: 1,
        };
        let result = run_dictionary_attack(job, None).unwrap();
        assert_eq!(result, Some("test".to_string()));
    }

    #[test]
    fn test_dictionary_sha512crypt_found() {
        let wl = make_wordlist(&["hello", "test", "world"]);
        let job = AttackJob {
            hash: "$6$rounds=11531$G/gkPn17kHYo0gTF$Kq.uZBHlSBXyzsOJXtxJruOOH4yc0Is13uY7yK0PvAvXxbvc1w8DO1RzREMhKsc82K/Jh8OquV8FZUlreYPJk1"
                .to_string(),
            wordlist_path: wl.path().to_str().unwrap().to_string(),
            algorithm: "sha512crypt".to_string(),
            threads: 1,
        };
        let result = run_dictionary_attack(job, None).unwrap();
        assert_eq!(result, Some("test".to_string()));
    }
}
