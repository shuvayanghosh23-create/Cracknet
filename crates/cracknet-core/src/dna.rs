/// Pattern classification for cracked plaintext passwords.

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternClass {
    WordOnly,    // letters only, no digits/specials (e.g. "password")
    WordDigits,  // word followed by digits (e.g. "password123")
    WordSpecial, // word with special chars (e.g. "p@ssword")
    NameYear,    // name + 4-digit year (e.g. "alice2021")
    DigitsOnly,  // all digits (e.g. "123456")
    Complex,     // mixed upper/lower/digit/special, length >= 8
    Other,       // anything else
}

/// Classify a single plaintext into a PatternClass.
pub fn classify_pattern(plaintext: &str) -> PatternClass {
    let has_upper = plaintext.chars().any(|c| c.is_uppercase());
    let has_lower = plaintext.chars().any(|c| c.is_lowercase());
    let has_digit = plaintext.chars().any(|c| c.is_ascii_digit());
    let has_special = plaintext.chars().any(|c| !c.is_alphanumeric());
    let all_digits = plaintext.chars().all(|c| c.is_ascii_digit());
    let all_alpha = plaintext.chars().all(|c| c.is_alphabetic());
    let len = plaintext.len();

    if len == 0 {
        return PatternClass::Other;
    }
    if all_digits {
        return PatternClass::DigitsOnly;
    }
    if all_alpha {
        return PatternClass::WordOnly;
    }
    // Check name+year: letters followed by exactly 4 digits
    let alpha_part: String = plaintext.chars().take_while(|c| c.is_alphabetic()).collect();
    let rest: &str = &plaintext[alpha_part.len()..];
    if !alpha_part.is_empty() && rest.len() == 4 && rest.chars().all(|c| c.is_ascii_digit()) {
        let year: u32 = rest.parse().unwrap_or(0);
        if year >= 1950 && year <= 2030 {
            return PatternClass::NameYear;
        }
    }
    // Complex: has upper+lower+digit+special or long enough with 3 char classes
    let classes = [has_upper, has_lower, has_digit, has_special]
        .iter()
        .filter(|&&v| v)
        .count();
    if classes >= 3 && len >= 8 {
        return PatternClass::Complex;
    }
    if has_special {
        return PatternClass::WordSpecial;
    }
    if has_digit {
        return PatternClass::WordDigits;
    }
    PatternClass::Other
}

#[derive(Debug, serde::Serialize)]
pub struct DnaReport {
    pub total: usize,
    pub classes: std::collections::HashMap<String, usize>,
    pub percentages: std::collections::HashMap<String, f64>,
    pub key_findings: Vec<String>,
}

pub fn analyze_patterns(plaintexts: &[&str]) -> DnaReport {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    let total = plaintexts.len();
    for p in plaintexts {
        let class = classify_pattern(p);
        let key = format!("{:?}", class).to_lowercase();
        *counts.entry(key).or_insert(0) += 1;
    }
    let percentages: HashMap<String, f64> = counts
        .iter()
        .map(|(k, &v)| {
            (
                k.clone(),
                if total > 0 {
                    v as f64 * 100.0 / total as f64
                } else {
                    0.0
                },
            )
        })
        .collect();
    let mut findings = Vec::new();
    if let Some(&n) = counts.get("digitsonly") {
        if n as f64 / total.max(1) as f64 > 0.2 {
            findings.push(format!(
                "{:.0}% of passwords are digits-only — very weak",
                n as f64 * 100.0 / total.max(1) as f64
            ));
        }
    }
    if let Some(&n) = counts.get("wordonly") {
        if n as f64 / total.max(1) as f64 > 0.3 {
            findings.push(format!(
                "{:.0}% are plain words — weak, no complexity",
                n as f64 * 100.0 / total.max(1) as f64
            ));
        }
    }
    if let Some(&n) = counts.get("complex") {
        if n as f64 / total.max(1) as f64 > 0.3 {
            findings.push(format!(
                "{:.0}% meet complexity requirements",
                n as f64 * 100.0 / total.max(1) as f64
            ));
        }
    }
    DnaReport {
        total,
        classes: counts,
        percentages,
        key_findings: findings,
    }
}

/// Policy bypass detected in a plaintext password.
#[derive(Debug, serde::Serialize)]
pub struct PolicyBypass {
    pub bypass_type: String,
    pub description: String,
}

pub fn detect_policy_bypasses(plaintext: &str) -> Vec<PolicyBypass> {
    let mut bypasses = Vec::new();
    let chars: Vec<char> = plaintext.chars().collect();
    let len = chars.len();
    if len == 0 {
        return bypasses;
    }

    // Capitalize first letter only
    if chars[0].is_uppercase()
        && chars[1..]
            .iter()
            .all(|c| c.is_lowercase() || !c.is_alphabetic())
    {
        bypasses.push(PolicyBypass {
            bypass_type: "first_cap".into(),
            description: "Only first letter capitalised".into(),
        });
    }

    // Append 1! or trailing digit pattern
    if plaintext.ends_with("1!") || plaintext.ends_with('1') {
        bypasses.push(PolicyBypass {
            bypass_type: "append_digit".into(),
            description: "Digit appended to satisfy number requirement".into(),
        });
    }

    // Year suffix (last 4 chars are a year)
    if len >= 5 {
        let tail = &plaintext[len - 4..];
        if tail.chars().all(|c| c.is_ascii_digit()) {
            let year: u32 = tail.parse().unwrap_or(0);
            if year >= 1950 && year <= 2030 {
                bypasses.push(PolicyBypass {
                    bypass_type: "year_suffix".into(),
                    description: format!("Year suffix {} appended", tail),
                });
            }
        }
    }

    // Leet substitutions (simple check)
    let leet = plaintext
        .to_lowercase()
        .replace('4', "a")
        .replace('3', "e")
        .replace('1', "i")
        .replace('0', "o")
        .replace('5', "s")
        .replace('7', "t");
    if leet != plaintext.to_lowercase() && leet.chars().all(|c| c.is_alphabetic()) {
        bypasses.push(PolicyBypass {
            bypass_type: "leetspeak".into(),
            description: "Leetspeak substitutions detected".into(),
        });
    }

    bypasses
}

/// Crack difficulty prediction for a given algorithm.
#[derive(Debug, serde::Serialize)]
pub struct PredictorResult {
    pub difficulty: String,
    pub recommended_mode: String,
    pub recommended_mask: Option<String>,
    pub notes: Vec<String>,
}

pub fn predict_crack_difficulty(algorithm: &str) -> PredictorResult {
    let (difficulty, recommended_mode, mask, notes) = match algorithm {
        "md5" | "sha1" => (
            "easy",
            "dictionary",
            None,
            vec!["Fast algorithm — dictionary attack is most effective".to_string()],
        ),
        "sha256" | "sha512" | "ntlm" => (
            "medium",
            "hybrid",
            Some("?d?d?d?d".to_string()),
            vec!["Consider hybrid attack: wordlist + digit mask".to_string()],
        ),
        "sha512crypt" | "sha256crypt" | "md5crypt" => (
            "hard",
            "dictionary",
            None,
            vec!["Iterated hash — slow to crack, prioritise dictionary".to_string()],
        ),
        "bcrypt" => (
            "very_hard",
            "dictionary",
            None,
            vec![
                "bcrypt is intentionally slow — only common passwords will crack".to_string(),
                "Reduce threads per hash to avoid CPU saturation".to_string(),
            ],
        ),
        _ => (
            "unknown",
            "dictionary",
            None,
            vec!["Unknown algorithm — defaulting to dictionary".to_string()],
        ),
    };
    PredictorResult {
        difficulty: difficulty.to_string(),
        recommended_mode: recommended_mode.to_string(),
        recommended_mask: mask,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digits_only() {
        assert_eq!(classify_pattern("123456"), PatternClass::DigitsOnly);
    }

    #[test]
    fn test_word_only() {
        assert_eq!(classify_pattern("password"), PatternClass::WordOnly);
    }

    #[test]
    fn test_word_digits() {
        assert_eq!(classify_pattern("password123"), PatternClass::WordDigits);
    }

    #[test]
    fn test_name_year() {
        assert_eq!(classify_pattern("alice2021"), PatternClass::NameYear);
    }

    #[test]
    fn test_complex() {
        assert_eq!(classify_pattern("P@ssw0rd!"), PatternClass::Complex);
    }

    #[test]
    fn test_word_special() {
        assert_eq!(classify_pattern("p@ssword"), PatternClass::WordSpecial);
    }

    #[test]
    fn test_policy_bypass_first_cap() {
        let bypasses = detect_policy_bypasses("Password123");
        assert!(
            bypasses.iter().any(|b| b.bypass_type == "first_cap"),
            "should detect first_cap"
        );
    }

    #[test]
    fn test_analyze_patterns() {
        let plaintexts = ["password", "123456", "alice2021", "P@ssw0rd!"];
        let report = analyze_patterns(&plaintexts);
        assert_eq!(report.total, 4);
    }

    #[test]
    fn test_predict_md5() {
        let r = predict_crack_difficulty("md5");
        assert_eq!(r.difficulty, "easy");
    }

    #[test]
    fn test_predict_bcrypt() {
        let r = predict_crack_difficulty("bcrypt");
        assert_eq!(r.difficulty, "very_hard");
    }
}
