use serde::Serialize;
use serde_json::Value;
use std::io::{self, BufRead, Write};
use std::sync::mpsc;

use cracknet_core::{
    analyze::detect_hash_type,
    job::{execute_job_with_progress, Job},
    progress::Progress,
};

/// Output message types sent back to Go CLI.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutputMessage {
    HashInfo {
        algorithm: String,
        confidence: f32,
        difficulty: String,
    },
    Progress {
        tried: u64,
        speed: f64,
        elapsed_ms: u128,
    },
    Result {
        cracked: bool,
        plaintext: Option<String>,
        elapsed_ms: u64,
    },
    Error {
        message: String,
    },
}

fn main() {
    let stdin = io::stdin();
    let stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                emit(&stdout, &OutputMessage::Error {
                    message: format!("Read error: {e}"),
                });
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let value: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                emit(&stdout, &OutputMessage::Error {
                    message: format!("JSON parse error: {e}"),
                });
                continue;
            }
        };

        // Determine type field
        let msg_type = value
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        match msg_type.as_str() {
            "analyze" => {
                let hash = value
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let (algorithm, confidence, difficulty) = detect_hash_type(&hash);
                emit(&stdout, &OutputMessage::HashInfo {
                    algorithm,
                    confidence,
                    difficulty,
                });
            }
            "crack" => {
                let job: Job = match serde_json::from_value(value.clone()) {
                    Ok(j) => j,
                    Err(e) => {
                        emit(&stdout, &OutputMessage::Error {
                            message: format!("Invalid crack job: {e}"),
                        });
                        continue;
                    }
                };

                // Set up a progress channel so attack progress is streamed to stdout
                let (tx, rx) = mpsc::channel::<Progress>();
                let stdout_clone = io::stdout();

                // Spawn a thread to forward progress messages
                let progress_thread = std::thread::spawn(move || {
                    for p in rx {
                        emit(&stdout_clone, &OutputMessage::Progress {
                            tried: p.tried,
                            speed: p.speed,
                            elapsed_ms: p.elapsed_ms,
                        });
                    }
                });

                // Run the job with the progress sender
                let result = execute_job_with_progress(job, Some(tx));

                // Wait for progress thread to finish
                let _ = progress_thread.join();

                match result {
                    Ok(result) => {
                        emit(&stdout, &OutputMessage::Result {
                            cracked: result.cracked,
                            plaintext: result.plaintext,
                            elapsed_ms: result.elapsed_ms,
                        });
                    }
                    Err(e) => {
                        emit(&stdout, &OutputMessage::Error { message: e });
                    }
                }
            }
            other => {
                emit(&stdout, &OutputMessage::Error {
                    message: format!("Unknown message type: '{other}'"),
                });
            }
        }
    }
}

fn emit(stdout: &io::Stdout, msg: &OutputMessage) {
    let mut out = stdout.lock();
    let _ = writeln!(out, "{}", serde_json::to_string(msg).unwrap_or_default());
}
