//! Verification code generation.

use rand::Rng;

/// Generate a cryptographically secure 6-digit verification code.
///
/// Returns a string of exactly 6 digits (000000-999999).
pub fn generate_verification_code() -> String {
    let mut rng = rand::rng();
    let code: u32 = rng.random_range(0..1_000_000);
    format!("{:06}", code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_is_6_digits() {
        for _ in 0..100 {
            let code = generate_verification_code();
            assert_eq!(code.len(), 6);
        }
    }

    #[test]
    fn test_code_is_numeric() {
        for _ in 0..100 {
            let code = generate_verification_code();
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_code_can_start_with_zero() {
        // Generate many codes until we find one starting with 0
        // With 1M possibilities and 10% starting with 0, this should happen quickly
        let mut found_zero_start = false;
        for _ in 0..1000 {
            let code = generate_verification_code();
            if code.starts_with('0') {
                found_zero_start = true;
                break;
            }
        }
        assert!(
            found_zero_start,
            "Should be able to generate codes starting with 0"
        );
    }

    #[test]
    fn test_code_randomness() {
        use std::collections::HashSet;
        // Generate 100 codes - with 1M possibilities, duplicates are extremely unlikely
        let codes: HashSet<String> = (0..100).map(|_| generate_verification_code()).collect();
        assert!(codes.len() > 95, "Should generate mostly unique codes");
    }
}
