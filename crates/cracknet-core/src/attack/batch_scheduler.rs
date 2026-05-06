use std::io::Write;
use std::sync::mpsc;
use std::time::Instant;

use rayon::prelude::*;
use serde::Serialize;

use crate::algorithms::matcher;
use crate::attack::{
    bruteforce::{run_bruteforce_attack, BruteforceJob},
    dictionary::run_dictionary_attack,
    hybrid::{run_hybrid_attack, HybridJob},
    AttackJob,
};

/// Attack mode for batch cracking.
#[derive(Debug, Clone, PartialEq)]
pub enum BatchAttackMode {
    Dictionary,
    Bruteforce,
    Hybrid,
}

impl BatchAttackMode {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "bruteforce" => Self::Bruteforce,
            "hybrid" => Self::Hybrid,
            _ => Self::Dictionary,
        }
    }
}

/// A per-worker result sent over the internal channel.
#[derive(Debug, Clone, Serialize)]
pub struct WorkerResult {
    pub job_id: String,
    pub worker_id: usize,
    pub hash: String,
    pub found: bool,
    pub plaintext: Option<String>,
    pub elapsed: f64,
}

/// Final batch summary.
#[derive(Debug, Clone, Serialize)]
pub struct BatchDone {
    pub job_id: String,
    pub total: usize,
    pub cracked: usize,
    pub elapsed: f64,
}

/// Run a parallel batch crack job, writing JSON-lines to stdout.
///
/// Pool size = min(threads, hashes.len()).  Each hash is processed by exactly
/// one Rayon thread.  Results are streamed to stdout via a writer thread.
pub fn run_batch(
    hashes: Vec<String>,
    algorithm: &str,
    mode: BatchAttackMode,
    wordlist: Option<&str>,
    mask: Option<&str>,
    threads: usize,
    job_id: &str,
) {
    let total = hashes.len();
    if total == 0 {
        emit_json(&BatchDone {
            job_id: job_id.to_string(),
            total: 0,
            cracked: 0,
            elapsed: 0.0,
        });
        return;
    }

    let algo = algorithm.to_lowercase();
    let pool_size = threads.max(1).min(total);

    let pool = match rayon::ThreadPoolBuilder::new()
        .num_threads(pool_size)
        .build()
    {
        Ok(p) => p,
        Err(e) => {
            emit_error(&format!("Failed to build thread pool: {e}"));
            return;
        }
    };

    let (tx, rx) = mpsc::channel::<WorkerResult>();
    let job_id_str = job_id.to_string();

    let start = Instant::now();

    // Writer thread — reads from the channel and prints JSON lines.
    let writer_handle = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for wr in rx {
            let line = serde_json::to_string(&serde_json::json!({
                "type": "worker_result",
                "job_id": wr.job_id,
                "worker_id": wr.worker_id,
                "hash": wr.hash,
                "found": wr.found,
                "plaintext": wr.plaintext,
                "elapsed": wr.elapsed,
            }))
            .unwrap_or_default();
            let _ = writeln!(out, "{}", line);
        }
    });

    let wordlist_owned: Option<String> = wordlist.map(|s| s.to_string());
    let mask_owned: Option<String> = mask.map(|s| s.to_string());

    pool.install(|| {
        hashes
            .par_iter()
            .enumerate()
            .for_each(|(worker_id, hash)| {
                let hash_start = Instant::now();
                let wl_ref: Option<&str> = wordlist_owned.as_deref();
                let mask_ref: Option<&str> = mask_owned.as_deref();

                // Validate algorithm.
                if !matcher::is_supported_algorithm(&algo) {
                    let elapsed = hash_start.elapsed().as_secs_f64();
                    let _ = tx.send(WorkerResult {
                        job_id: job_id.to_string(),
                        worker_id,
                        hash: hash.clone(),
                        found: false,
                        plaintext: None,
                        elapsed,
                    });
                    return;
                }

                let result = match mode {
                    BatchAttackMode::Bruteforce => {
                        let mask_str = mask_ref.unwrap_or("").to_string();
                        run_bruteforce_attack(
                            BruteforceJob {
                                hash: hash.clone(),
                                mask: mask_str,
                                algorithm: algo.clone(),
                                threads: 1,
                            },
                            None,
                        )
                    }
                    BatchAttackMode::Hybrid => {
                        let wl = wl_ref.unwrap_or("").to_string();
                        let mask_str = mask_ref.unwrap_or("").to_string();
                        run_hybrid_attack(
                            HybridJob {
                                hash: hash.clone(),
                                wordlist_path: wl,
                                mask: mask_str,
                                algorithm: algo.clone(),
                                threads: 1,
                            },
                            None,
                        )
                    }
                    BatchAttackMode::Dictionary => {
                        let wl = wl_ref.unwrap_or("").to_string();
                        run_dictionary_attack(
                            AttackJob {
                                hash: hash.clone(),
                                wordlist_path: wl,
                                algorithm: algo.clone(),
                                threads: 1,
                            },
                            None,
                        )
                    }
                };

                let elapsed = hash_start.elapsed().as_secs_f64();
                let (found, plaintext) = match result {
                    Ok(Some(pt)) => (true, Some(pt)),
                    Ok(None) => (false, None),
                    Err(_) => (false, None),
                };

                let _ = tx.send(WorkerResult {
                    job_id: job_id.to_string(),
                    worker_id,
                    hash: hash.clone(),
                    found,
                    plaintext,
                    elapsed,
                });
            });
    });

    // Drop tx so the writer thread can finish.
    drop(tx);
    let _ = writer_handle.join();

    let total_elapsed = start.elapsed().as_secs_f64();
    emit_json(&serde_json::json!({
        "type": "batch_done",
        "job_id": job_id,
        "total": total,
        "elapsed": total_elapsed,
    }));
}

fn emit_json<T: serde::Serialize>(v: &T) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let line = serde_json::to_string(v).unwrap_or_default();
    let _ = writeln!(out, "{}", line);
}

fn emit_error(msg: &str) {
    emit_json(&serde_json::json!({ "type": "error", "message": msg }));
}
