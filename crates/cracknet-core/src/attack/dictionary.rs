use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

use rayon::prelude::*;

use crate::algorithms::{md5, ntlm, sha};
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

    let target = job.hash.to_lowercase();
    let found = Arc::new(std::sync::Mutex::new(None::<String>));
    let stop = Arc::new(AtomicBool::new(false));

    let tried = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let start = Instant::now();

    // Build thread pool respecting the requested thread count
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(job.threads.max(1))
        .build()
        .map_err(|e| format!("Thread pool error: {e}"))?;

    let algo = job.algorithm.to_lowercase();

    pool.install(|| {
        words.par_iter().for_each(|word| {
            if stop.load(Ordering::Relaxed) {
                return;
            }

            let candidate = match algo.as_str() {
                "md5" => md5::hash(word),
                "sha1" => sha::sha1(word),
                "sha256" => sha::sha256(word),
                "sha512" => sha::sha512(word),
                "ntlm" => ntlm::hash(word),
                _ => md5::hash(word),
            };

            let current = tried.fetch_add(1, Ordering::Relaxed) + 1;

            // Send progress every 100 k words (roughly every ~100 ms at high speed)
            if let Some(ref sender) = tx {
                if current % 100_000 == 0 {
                    let elapsed = start.elapsed().as_millis();
                    let speed = if elapsed > 0 {
                        current as f64 / (elapsed as f64 / 1000.0)
                    } else {
                        0.0
                    };
                    let _ = sender.send(Progress {
                        tried: current,
                        speed,
                        elapsed_ms: elapsed,
                    });
                }
            }

            if candidate == target {
                stop.store(true, Ordering::Relaxed);
                let mut guard = found.lock().unwrap();
                *guard = Some(word.clone());
            }
        });
    });

    // Final progress update
    if let Some(ref sender) = tx {
        let elapsed = start.elapsed().as_millis();
        let total = tried.load(Ordering::Relaxed);
        let speed = if elapsed > 0 {
            total as f64 / (elapsed as f64 / 1000.0)
        } else {
            0.0
        };
        let _ = sender.send(Progress {
            tried: total,
            speed,
            elapsed_ms: elapsed,
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
}
