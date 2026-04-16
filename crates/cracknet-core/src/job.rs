use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

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

/// A batch cracking job for a single algorithm group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchJob {
    pub hashes: Vec<String>,
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
    #[serde(default = "default_mode")]
    pub mode: String,
}

/// The result of a cracking job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobResult {
    pub cracked: bool,
    pub plaintext: Option<String>,
    pub elapsed_ms: u64,
}

/// Progress for a batch cracking job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchProgress {
    pub processed_hashes: usize,
    pub total_hashes: usize,
    pub cracked_hashes: usize,
    pub tried: u64,
    pub speed: f64,
    pub elapsed_ms: u64,
    pub current_hash: Option<String>,
}

/// Per-hash result streamed from batch cracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResultItem {
    pub hash: String,
    pub cracked: bool,
    pub plaintext: Option<String>,
    pub elapsed_ms: u64,
}

/// Final result summary of a batch cracking job.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchJobResult {
    pub total_hashes: usize,
    pub processed_hashes: usize,
    pub cracked_hashes: usize,
    pub tried: u64,
    pub elapsed_ms: u64,
    pub results: Vec<BatchResultItem>,
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

    let has_wordlist = job
        .wordlist
        .as_ref()
        .map(|s| !s.is_empty())
        .unwrap_or(false);
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

fn emit_batch_progress(
    tx: &Option<Sender<BatchProgress>>,
    start: &Instant,
    total_hashes: usize,
    processed_hashes: &AtomicUsize,
    cracked_hashes: &AtomicUsize,
    total_tried: &AtomicU64,
    current_hash: Option<String>,
) {
    if let Some(sender) = tx {
        let elapsed = start.elapsed().as_millis() as u64;
        let tried = total_tried.load(Ordering::Relaxed);
        let elapsed_nonzero = if elapsed == 0 { 1 } else { elapsed };
        let speed = tried as f64 / (elapsed_nonzero as f64 / 1000.0);
        let _ = sender.send(BatchProgress {
            processed_hashes: processed_hashes.load(Ordering::Relaxed),
            total_hashes,
            cracked_hashes: cracked_hashes.load(Ordering::Relaxed),
            tried,
            speed,
            elapsed_ms: elapsed_nonzero,
            current_hash,
        });
    }
}

fn run_single_hash_for_batch(
    hash: String,
    base_job: &BatchJob,
    hash_threads: usize,
    start: &Instant,
    total_hashes: usize,
    processed_hashes: Arc<AtomicUsize>,
    cracked_hashes: Arc<AtomicUsize>,
    total_tried: Arc<AtomicU64>,
    progress_tx: &Option<Sender<BatchProgress>>,
    result_tx: &Option<Sender<BatchResultItem>>,
) -> Result<BatchResultItem, String> {
    emit_batch_progress(
        progress_tx,
        start,
        total_hashes,
        &processed_hashes,
        &cracked_hashes,
        &total_tried,
        Some(hash.clone()),
    );

    let (single_progress_tx, single_progress_rx) = std::sync::mpsc::channel::<Progress>();
    let progress_forwarder = thread::spawn({
        let hash_clone = hash.clone();
        let progress_tx_clone = progress_tx.clone();
        let start_copy = *start;
        let total_tried_ref = Arc::clone(&total_tried);
        let processed_ref = Arc::clone(&processed_hashes);
        let cracked_ref = Arc::clone(&cracked_hashes);
        move || {
            let mut last_tried = 0u64;
            for p in single_progress_rx {
                let delta = p.tried.saturating_sub(last_tried);
                last_tried = p.tried;
                total_tried_ref.fetch_add(delta, Ordering::Relaxed);
                emit_batch_progress(
                    &progress_tx_clone,
                    &start_copy,
                    total_hashes,
                    &processed_ref,
                    &cracked_ref,
                    &total_tried_ref,
                    Some(hash_clone.clone()),
                );
            }
        }
    });

    let result = execute_job_with_progress(
        Job {
            hash: hash.clone(),
            wordlist: base_job.wordlist.clone(),
            algorithm: base_job.algorithm.clone(),
            threads: hash_threads,
            mask: base_job.mask.clone(),
            mode: base_job.mode.clone(),
        },
        Some(single_progress_tx),
    )?;

    let _ = progress_forwarder.join();

    if result.cracked {
        cracked_hashes.fetch_add(1, Ordering::Relaxed);
    }
    processed_hashes.fetch_add(1, Ordering::Relaxed);

    let item = BatchResultItem {
        hash: hash.clone(),
        cracked: result.cracked,
        plaintext: result.plaintext,
        elapsed_ms: result.elapsed_ms,
    };
    if let Some(tx) = result_tx {
        let _ = tx.send(item.clone());
    }

    emit_batch_progress(
        progress_tx,
        start,
        total_hashes,
        &processed_hashes,
        &cracked_hashes,
        &total_tried,
        Some(hash),
    );

    Ok(item)
}

/// Execute a batch cracking job and stream aggregated progress and per-hash results.
pub fn execute_batch_job_with_progress(
    job: BatchJob,
    progress_tx: Option<Sender<BatchProgress>>,
    result_tx: Option<Sender<BatchResultItem>>,
) -> Result<BatchJobResult, String> {
    let start = Instant::now();
    let total_hashes = job.hashes.len();
    if total_hashes == 0 {
        return Ok(BatchJobResult {
            total_hashes: 0,
            processed_hashes: 0,
            cracked_hashes: 0,
            tried: 0,
            elapsed_ms: 0,
            results: Vec::new(),
        });
    }

    let processed_hashes = Arc::new(AtomicUsize::new(0));
    let cracked_hashes = Arc::new(AtomicUsize::new(0));
    let total_tried = Arc::new(AtomicU64::new(0));
    let results = Arc::new(Mutex::new(Vec::<BatchResultItem>::with_capacity(
        total_hashes,
    )));

    let algorithm = job.algorithm.to_lowercase();
    if algorithm == "bcrypt" {
        let cpu_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let worker_count = total_hashes.min(job.threads.max(1)).min(cpu_cores).max(1);
        let next_idx = Arc::new(AtomicUsize::new(0));
        let hashes = Arc::new(job.hashes.clone());
        let mut handles = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let next_idx = Arc::clone(&next_idx);
            let hashes = Arc::clone(&hashes);
            let processed = Arc::clone(&processed_hashes);
            let cracked = Arc::clone(&cracked_hashes);
            let tried = Arc::clone(&total_tried);
            let results_ref = Arc::clone(&results);
            let progress_tx_ref = progress_tx.clone();
            let result_tx_ref = result_tx.clone();
            let batch_job = job.clone();
            let start_copy = start;
            let handle = thread::spawn(move || -> Result<(), String> {
                loop {
                    let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    if idx >= hashes.len() {
                        break;
                    }
                    let hash = hashes[idx].clone();
                    let item = run_single_hash_for_batch(
                        hash,
                        &batch_job,
                        1,
                        &start_copy,
                        hashes.len(),
                        Arc::clone(&processed),
                        Arc::clone(&cracked),
                        Arc::clone(&tried),
                        &progress_tx_ref,
                        &result_tx_ref,
                    )?;
                    results_ref.lock().unwrap().push(item);
                }
                Ok(())
            });
            handles.push(handle);
        }

        for h in handles {
            h.join()
                .map_err(|_| "bcrypt batch worker thread panicked".to_string())??;
        }
    } else {
        for hash in job.hashes.clone() {
            let item = run_single_hash_for_batch(
                hash,
                &job,
                job.threads.max(1),
                &start,
                total_hashes,
                Arc::clone(&processed_hashes),
                Arc::clone(&cracked_hashes),
                Arc::clone(&total_tried),
                &progress_tx,
                &result_tx,
            )?;
            results.lock().unwrap().push(item);
        }
    }

    emit_batch_progress(
        &progress_tx,
        &start,
        total_hashes,
        &processed_hashes,
        &cracked_hashes,
        &total_tried,
        None,
    );

    let final_results = results.lock().unwrap().clone();
    Ok(BatchJobResult {
        total_hashes,
        processed_hashes: processed_hashes.load(Ordering::Relaxed),
        cracked_hashes: cracked_hashes.load(Ordering::Relaxed),
        tried: total_tried.load(Ordering::Relaxed),
        elapsed_ms: start.elapsed().as_millis() as u64,
        results: final_results,
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

    #[test]
    fn test_execute_batch_job_bcrypt_cracks_multiple_hashes() {
        let f = make_wordlist(&["hello", "password", "admin123", "letmein"]);
        let hashes = vec![
            ::bcrypt::hash("password", 4).unwrap(),
            ::bcrypt::hash("admin123", 4).unwrap(),
            ::bcrypt::hash("missing", 4).unwrap(),
        ];
        let batch = BatchJob {
            hashes: hashes.clone(),
            wordlist: Some(f.path().to_str().unwrap().to_string()),
            algorithm: "bcrypt".to_string(),
            threads: 3,
            mask: None,
            mode: "dictionary".to_string(),
        };

        let result = execute_batch_job_with_progress(batch, None, None).unwrap();
        assert_eq!(result.total_hashes, 3);
        assert_eq!(result.processed_hashes, 3);
        assert_eq!(result.cracked_hashes, 2);

        let mut found = 0usize;
        for item in result.results {
            if item.cracked {
                found += 1;
            }
        }
        assert_eq!(found, 2);
    }

    #[test]
    fn test_execute_batch_job_progress_aggregates() {
        let f = make_wordlist(&["foo", "bar", "password"]);
        let batch = BatchJob {
            hashes: vec![
                "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
                "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            ],
            wordlist: Some(f.path().to_str().unwrap().to_string()),
            algorithm: "md5".to_string(),
            threads: 2,
            mask: None,
            mode: "dictionary".to_string(),
        };
        let (tx, rx) = std::sync::mpsc::channel::<BatchProgress>();

        let result = execute_batch_job_with_progress(batch, Some(tx), None).unwrap();
        assert_eq!(result.total_hashes, 2);
        assert_eq!(result.processed_hashes, 2);
        assert_eq!(result.cracked_hashes, 2);
        assert!(result.tried >= 2);

        let progress: Vec<BatchProgress> = rx.into_iter().collect();
        assert!(!progress.is_empty());
        let last = progress.last().unwrap();
        assert_eq!(last.total_hashes, 2);
        assert_eq!(last.processed_hashes, 2);
        assert_eq!(last.cracked_hashes, 2);
        assert!(last.tried >= 2);
    }
}
