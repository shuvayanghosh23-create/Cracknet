use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::Instant;

use rayon::prelude::*;

use crate::algorithms::{bcrypt, md5, ntlm, sha};
use crate::progress::Progress;

/// Charsets for mask tokens (Phase 2: no custom charsets).
pub const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &[u8] = b"0123456789";
pub const SPECIAL: &[u8] = b" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
pub const HEX: &[u8] = b"0123456789abcdef";

/// Return the charset for `?a` (all printable: lower + upper + digits + special).
fn all_charset() -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    v.extend_from_slice(LOWER);
    v.extend_from_slice(UPPER);
    v.extend_from_slice(DIGITS);
    v.extend_from_slice(SPECIAL);
    v
}

/// A parsed segment of a mask string.
#[derive(Debug, Clone)]
pub enum MaskSegment {
    /// Fixed literal bytes.
    Fixed(Vec<u8>),
    /// Expandable charset for one character position.
    Token(Vec<u8>),
}

/// Parse a mask string such as `pass?d?d` into segments.
/// Supported tokens: `?l ?u ?d ?s ?a ?h`.
/// Returns an error if an unknown `?X` token is encountered.
pub fn parse_mask(mask: &str) -> Result<Vec<MaskSegment>, String> {
    let bytes = mask.as_bytes();
    let mut segments: Vec<MaskSegment> = Vec::new();
    let mut i = 0;
    let mut literal: Vec<u8> = Vec::new();

    while i < bytes.len() {
        if bytes[i] == b'?' && i + 1 < bytes.len() {
            let token = bytes[i + 1] as char;
            let charset: Vec<u8> = match token {
                'l' => LOWER.to_vec(),
                'u' => UPPER.to_vec(),
                'd' => DIGITS.to_vec(),
                's' => SPECIAL.to_vec(),
                'a' => all_charset(),
                'h' => HEX.to_vec(),
                '?' => {
                    // Escaped '?'
                    literal.push(b'?');
                    i += 2;
                    continue;
                }
                other => {
                    return Err(format!(
                        "Unknown mask token '?{other}'. \
                         Supported: ?l ?u ?d ?s ?a ?h"
                    ))
                }
            };
            if !literal.is_empty() {
                segments.push(MaskSegment::Fixed(literal.clone()));
                literal.clear();
            }
            segments.push(MaskSegment::Token(charset));
            i += 2;
        } else {
            literal.push(bytes[i]);
            i += 1;
        }
    }
    if !literal.is_empty() {
        segments.push(MaskSegment::Fixed(literal));
    }
    Ok(segments)
}

/// Return the total number of candidates the mask expands to.
pub fn keyspace_size(segments: &[MaskSegment]) -> u64 {
    segments.iter().fold(1u64, |acc, seg| match seg {
        MaskSegment::Fixed(_) => acc,
        MaskSegment::Token(cs) => acc.saturating_mul(cs.len() as u64),
    })
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

/// Generate all candidates from `segments` recursively,
/// calling `visit` on each complete candidate.
/// Returns early when `stop` is set.
pub fn generate_candidates(
    segments: &[MaskSegment],
    buf: &mut Vec<u8>,
    target: &str,
    algo: &str,
    found: &Mutex<Option<String>>,
    stop: &AtomicBool,
    tried: &AtomicU64,
    last_progress_emit_ms: &AtomicU64,
    start: &Instant,
    tx: &Option<std::sync::mpsc::Sender<Progress>>,
) {
    if stop.load(Ordering::Relaxed) {
        return;
    }

    if segments.is_empty() {
        let candidate = match std::str::from_utf8(buf) {
            Ok(s) => s,
            Err(_) => return,
        };
        let matched = candidate_matches(algo, candidate, target);
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
            *guard = Some(candidate.to_string());
        }
        return;
    }

    match &segments[0] {
        MaskSegment::Fixed(bytes) => {
            let orig_len = buf.len();
            buf.extend_from_slice(bytes);
            generate_candidates(
                &segments[1..],
                buf,
                target,
                algo,
                found,
                stop,
                tried,
                last_progress_emit_ms,
                start,
                tx,
            );
            buf.truncate(orig_len);
        }
        MaskSegment::Token(charset) => {
            for &byte in charset.iter() {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                buf.push(byte);
                generate_candidates(
                    &segments[1..],
                    buf,
                    target,
                    algo,
                    found,
                    stop,
                    tried,
                    last_progress_emit_ms,
                    start,
                    tx,
                );
                buf.pop();
            }
        }
    }
}

/// Job description for a bruteforce attack.
#[derive(Debug, Clone)]
pub struct BruteforceJob {
    pub hash: String,
    pub mask: String,
    pub algorithm: String,
    pub threads: usize,
}

/// Run a mask-based bruteforce attack.
/// Returns the plaintext if found, or None.
pub fn run_bruteforce_attack(
    job: BruteforceJob,
    tx: Option<std::sync::mpsc::Sender<Progress>>,
) -> Result<Option<String>, String> {
    let segments = parse_mask(&job.mask)?;

    if segments.is_empty() {
        return Ok(None);
    }

    let target = if job.algorithm.eq_ignore_ascii_case("bcrypt") {
        job.hash.clone()
    } else {
        job.hash.to_lowercase()
    };
    let found = Arc::new(Mutex::new(None::<String>));
    let stop = Arc::new(AtomicBool::new(false));
    let tried = Arc::new(AtomicU64::new(0));
    let last_progress_emit_ms = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let algo = job.algorithm.to_lowercase();

    // Parallelize over the first Token segment's charset,
    // keeping the remaining segments for sequential inner expansion.
    // Find the first Token segment.
    let first_token_idx = segments
        .iter()
        .position(|s| matches!(s, MaskSegment::Token(_)));

    match first_token_idx {
        None => {
            // No tokens - single fixed candidate
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .map_err(|e| format!("Thread pool error: {e}"))?;
            pool.install(|| {
                let mut buf: Vec<u8> = Vec::new();
                generate_candidates(
                    &segments,
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
        }
        Some(idx) => {
            // Split into: prefix segments, first token charset, suffix segments
            let prefix = &segments[..idx];
            let suffix = segments[idx + 1..].to_vec();
            let charset = match &segments[idx] {
                MaskSegment::Token(cs) => cs.clone(),
                _ => unreachable!(),
            };

            // Prefix bytes (all Fixed)
            let prefix_bytes: Vec<u8> = prefix
                .iter()
                .flat_map(|s| match s {
                    MaskSegment::Fixed(b) => b.clone(),
                    MaskSegment::Token(_) => vec![],
                })
                .collect();

            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(job.threads.max(1))
                .build()
                .map_err(|e| format!("Thread pool error: {e}"))?;

            pool.install(|| {
                charset.par_iter().for_each(|&byte| {
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut buf = prefix_bytes.clone();
                    buf.push(byte);
                    generate_candidates(
                        &suffix,
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
        }
    }

    // Final progress
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

    #[test]
    fn test_parse_mask_only_tokens() {
        let segs = parse_mask("?d?d").unwrap();
        assert_eq!(segs.len(), 2);
        assert!(matches!(&segs[0], MaskSegment::Token(cs) if cs == DIGITS));
        assert!(matches!(&segs[1], MaskSegment::Token(cs) if cs == DIGITS));
    }

    #[test]
    fn test_parse_mask_mixed() {
        let segs = parse_mask("pass?d?d").unwrap();
        assert_eq!(segs.len(), 3);
        assert!(matches!(&segs[0], MaskSegment::Fixed(b) if b == b"pass"));
        assert!(matches!(&segs[1], MaskSegment::Token(_)));
        assert!(matches!(&segs[2], MaskSegment::Token(_)));
    }

    #[test]
    fn test_parse_mask_unknown_token() {
        assert!(parse_mask("?z").is_err());
    }

    #[test]
    fn test_keyspace_size_digits() {
        let segs = parse_mask("?d?d").unwrap();
        assert_eq!(keyspace_size(&segs), 100);
    }

    #[test]
    fn test_keyspace_size_fixed() {
        let segs = parse_mask("abc").unwrap();
        assert_eq!(keyspace_size(&segs), 1);
    }

    #[test]
    fn test_keyspace_size_mixed() {
        let segs = parse_mask("pass?d?d").unwrap();
        // 1 (fixed) * 10 * 10
        assert_eq!(keyspace_size(&segs), 100);
    }

    #[test]
    fn test_bruteforce_found_two_lower() {
        // Find MD5("ab") with mask ?l?l
        let target = md5::hash("ab");
        let job = BruteforceJob {
            hash: target,
            mask: "?l?l".to_string(),
            algorithm: "md5".to_string(),
            threads: 2,
        };
        let result = run_bruteforce_attack(job, None).unwrap();
        assert_eq!(result, Some("ab".to_string()));
    }

    #[test]
    fn test_bruteforce_fixed_prefix() {
        // Find MD5("a5") with mask a?d
        let target = md5::hash("a5");
        let job = BruteforceJob {
            hash: target,
            mask: "a?d".to_string(),
            algorithm: "md5".to_string(),
            threads: 2,
        };
        let result = run_bruteforce_attack(job, None).unwrap();
        assert_eq!(result, Some("a5".to_string()));
    }

    #[test]
    fn test_bruteforce_not_found() {
        // MD5("password") cannot be found with mask ?d?d
        let job = BruteforceJob {
            hash: "5f4dcc3b5aa765d61d8327deb882cf99".to_string(),
            mask: "?d?d".to_string(),
            algorithm: "md5".to_string(),
            threads: 2,
        };
        let result = run_bruteforce_attack(job, None).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_bruteforce_bcrypt_found() {
        let target = ::bcrypt::hash("ab", 4).unwrap();
        let job = BruteforceJob {
            hash: target,
            mask: "a?l".to_string(),
            algorithm: "bcrypt".to_string(),
            threads: 1,
        };
        let result = run_bruteforce_attack(job, None).unwrap();
        assert_eq!(result, Some("ab".to_string()));
    }
}
