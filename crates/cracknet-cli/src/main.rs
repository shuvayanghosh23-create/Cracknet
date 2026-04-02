use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{self, BufRead, Write};

use cracknet_core::{
    analyze::detect_hash_type,
    job::{execute_job, Job},
};

/// Input message types from Go CLI (for documentation).
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum InputMessage {
    Analyze { hash: String },
    Crack(Job),
}

/// Output message types sent back to Go CLI.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum OutputMessage {
    HashInfo {
        algorithm: String,
        confidence: f32,
        difficulty: String,
    },
    #[allow(dead_code)]
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

                match execute_job(job) {
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
