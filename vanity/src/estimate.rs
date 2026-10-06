use alloc::{format, string::String};

use crate::{encode_pkh, Prefix, BASE58_ALPHABET, GOLDILOCKS_P};

impl Prefix {
    /// Expected trials for a uniform PKH, including canonical Base58's leading
    /// digit bias and this prefix's case and letter/digit matching rules.
    pub fn expected_attempts(&self) -> f64 {
        let maximum = encode_pkh([GOLDILOCKS_P - 1; 5]);
        let max_digits = maximum.as_str().as_bytes();
        let masks = self.digit_masks();
        let mut matches = 0.0;
        // Count matching numerals at each length. `equal` follows the upper
        // bound; `less` counts numerals already below it. Floating point is
        // sufficient for an estimate, including the full 320-bit address space.
        for length in self.len..=max_digits.len() {
            let mut equal = 1.0;
            let mut less = 0.0;
            for position in 0..length {
                let limit = if length == max_digits.len() {
                    BASE58_ALPHABET
                        .iter()
                        .position(|&b| b == max_digits[position])
                        .unwrap()
                } else {
                    57
                };
                let mut allowed = 0;
                let mut below = 0;
                let mut at_limit = false;
                for digit in 0..58 {
                    if position == 0 && length > 1 && digit == 0 {
                        continue;
                    }
                    if position < self.len && masks[position][digit / 32] & (1 << (digit % 32)) == 0
                    {
                        continue;
                    }
                    allowed += 1;
                    below += usize::from(digit < limit);
                    at_limit |= digit == limit;
                }
                less = less * allowed as f64 + equal * below as f64;
                if !at_limit {
                    equal = 0.0;
                }
            }
            matches += less + equal;
        }
        let mut space = 1.0;
        for _ in 0..5 {
            space *= GOLDILOCKS_P as f64;
        }
        space / matches
    }
}

/// Human-readable average search duration at a measured candidate rate.
pub fn format_vanity_duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds < 0.0 {
        return String::from("unavailable");
    }
    if seconds < 1.0 {
        return String::from("less than a second");
    }
    for (size, unit) in [
        (365.25 * 86400.0, "years"),
        (86400.0, "days"),
        (3600.0, "hours"),
        (60.0, "minutes"),
        (1.0, "seconds"),
    ] {
        if seconds >= size {
            let count = seconds / size;
            return if count >= 1e6 {
                format!("about {count:.1e} {unit}")
            } else {
                format!("about {count:.1} {unit}")
            };
        }
    }
    unreachable!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MatchMode;

    #[test]
    fn estimates_match_canonical_base58_reference_counts() {
        for (text, mode, expected) in [
            ("Reid", MatchMode::Exact, 141463955.05244663),
            ("Reid", MatchMode::Insensitive, 5894331.46051861),
            ("nock", MatchMode::Insensitive, 17682994.38155583),
            ("i", MatchMode::Insensitive, 725.0397466708692),
            ("l", MatchMode::Insensitive, 725.0397466708692),
            ("1", MatchMode::Insensitive, 362.5198733354346),
        ] {
            let actual = Prefix::with_mode(text, mode).unwrap().expected_attempts();
            assert!((actual / expected - 1.0).abs() < 1e-12, "{text}: {actual}");
        }
        let zero = Prefix::new("1").unwrap().expected_attempts();
        let full = Prefix::new(encode_pkh([GOLDILOCKS_P - 1; 5]).as_str())
            .unwrap()
            .expected_attempts();
        assert!((zero / full - 1.0).abs() < 1e-12);
        let probability: f64 = BASE58_ALPHABET
            .iter()
            .map(|&b| {
                1.0 / Prefix::new(core::str::from_utf8(&[b]).unwrap())
                    .unwrap()
                    .expected_attempts()
            })
            .sum();
        assert!((probability - 1.0).abs() < 1e-12);
    }
}
