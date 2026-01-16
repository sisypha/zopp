//! EFF wordlist passphrase generator
//!
//! Uses the EFF large wordlist (7776 words) to generate secure passphrases.
//! Each word provides ~12.9 bits of entropy (log2(7776) ≈ 12.925).
//!
//! Default 6 words = ~77.5 bits of entropy, suitable for protecting exported principals.

use rand::prelude::IndexedRandom;
use rand::rng;
use std::sync::LazyLock;

/// The EFF large wordlist embedded at compile time
static EFF_WORDLIST: &str = include_str!("eff_large_wordlist.txt");

/// Parsed wordlist (lazily initialized on first access, then cached)
static WORDS: LazyLock<Vec<&'static str>> =
    LazyLock::new(|| EFF_WORDLIST.lines().filter(|s| !s.is_empty()).collect());

/// Get the cached wordlist
fn get_words() -> &'static [&'static str] {
    &WORDS
}

/// Generate a passphrase with the specified number of words.
///
/// Default separator is a single space. Words are randomly selected from
/// the EFF large wordlist using cryptographically secure randomness.
///
/// # Arguments
/// * `word_count` - Number of words in the passphrase (default 6 for ~77 bits)
///
/// # Returns
/// A passphrase string with words separated by spaces.
pub fn generate_passphrase(word_count: usize) -> String {
    let words = get_words();
    let mut rng = rng();

    (0..word_count)
        .map(|_| *words.choose(&mut rng).expect("wordlist not empty"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generate a passphrase with a custom separator.
#[allow(dead_code)]
pub fn generate_passphrase_with_separator(word_count: usize, separator: &str) -> String {
    let words = get_words();
    let mut rng = rng();

    (0..word_count)
        .map(|_| *words.choose(&mut rng).expect("wordlist not empty"))
        .collect::<Vec<_>>()
        .join(separator)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wordlist_loaded() {
        let words = get_words();
        assert_eq!(
            words.len(),
            7776,
            "EFF large wordlist should have 7776 words"
        );
    }

    #[test]
    fn test_generate_passphrase_word_count() {
        let passphrase = generate_passphrase(6);
        let word_count = passphrase.split(' ').count();
        assert_eq!(word_count, 6);
    }

    #[test]
    fn test_generate_passphrase_uniqueness() {
        // Generate two passphrases - they should (almost certainly) be different
        let p1 = generate_passphrase(6);
        let p2 = generate_passphrase(6);
        // With 7776^6 possibilities, collision is astronomically unlikely
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_custom_separator() {
        let passphrase = generate_passphrase_with_separator(3, "-");
        let parts: Vec<_> = passphrase.split('-').collect();
        assert_eq!(parts.len(), 3);
    }
}
