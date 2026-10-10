#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

use subtle::{ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
use zeroize::Zeroize;

use crate::error::EngineError;

/// A secret of [`Credential::BYTE_LEN`] bytes whose storage is zeroized on drop.
///
/// Debug output is redacted. Caller-owned copies and encodings need their own
/// cleanup.
pub struct Credential([u8; Credential::BYTE_LEN]);

impl Credential {
    /// Credential length in bytes.
    pub const BYTE_LEN: usize = 32;
    /// Credential length in ASCII hexadecimal digits.
    pub const HEX_LEN: usize = 2 * Self::BYTE_LEN;

    pub const fn from_bytes(bytes: [u8; Self::BYTE_LEN]) -> Self {
        Self(bytes)
    }

    /// Decode exactly [`Self::HEX_LEN`] ASCII hex digits in either letter case.
    /// Invalid width or digits return `InvalidConfig` and zeroize `out`.
    /// Input and output contain the secret. The caller must clear both after use.
    pub fn decode_hex(text: &[u8], out: &mut [u8; Self::BYTE_LEN]) -> Result<(), EngineError> {
        let result = if text.len() == Self::HEX_LEN {
            text.chunks_exact(2)
                .zip(out.iter_mut())
                .try_for_each(|(pair, byte)| {
                    *byte = decode_hex_digit(pair[0])? << 4 | decode_hex_digit(pair[1])?;
                    Ok(())
                })
        } else {
            Err(EngineError::InvalidConfig)
        };
        if result.is_err() {
            out.zeroize();
        }
        result
    }

    /// Compare all credential bytes using `subtle`'s constant-time equality.
    #[must_use]
    pub fn verify(&self, candidate: &Credential) -> bool {
        bool::from(self.0.ct_eq(&candidate.0))
    }

    /// Write [`Self::HEX_LEN`] lowercase hexadecimal digits into `out`.
    ///
    /// The output contains the secret. The caller must clear it after use.
    pub fn write_hex(&self, out: &mut [u8; Self::HEX_LEN]) {
        for (index, byte) in self.0.iter().enumerate() {
            out[index * 2] = hex_digit(byte >> 4);
            out[index * 2 + 1] = hex_digit(byte & 0x0f);
        }
    }
}

fn decode_hex_digit(byte: u8) -> Result<u8, EngineError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(EngineError::InvalidConfig),
    }
}

#[inline]
fn hex_digit(nibble: u8) -> u8 {
    let nibble = nibble & 0x0f;
    let digit = b'0'.wrapping_add(nibble);
    // The unselected letter candidate is also computed below ten, so its
    // subtraction must wrap.
    let letter = b'a'.wrapping_add(nibble.wrapping_sub(10));
    u8::conditional_select(&digit, &letter, nibble.ct_gt(&9u8))
}

impl Drop for Credential {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Credential([redacted])")
    }
}

/// Result supplied by a host authorizer.
///
/// Constructing this value does not validate its fields or start an expiry timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthzDecision {
    pub principal: u64,
    pub quota_class: u32,

    /// Host-supplied validity duration used to cap target opening.
    pub valid_for: Duration,
}

#[cfg(test)]
mod tests {
    use super::{Credential, EngineError};

    #[test]
    fn decode_hex_accepts_lowercase_uppercase_and_mixed_case() {
        let expected: [u8; 32] = std::array::from_fn(|index| u8::try_from(index).unwrap());
        for text in [
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".as_slice(),
            b"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F".as_slice(),
            b"000102030405060708090a0B0c0D0e0F101112131415161718191A1b1C1d1E1f".as_slice(),
        ] {
            let mut out = [0xff; Credential::BYTE_LEN];
            Credential::decode_hex(text, &mut out).unwrap();
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn decode_hex_clears_output_on_invalid_width_or_digits() {
        let valid = b"ab".repeat(Credential::BYTE_LEN);
        let mut invalid = vec![
            Vec::new(),
            valid[..Credential::HEX_LEN - 1].to_vec(),
            [valid.as_slice(), b"0"].concat(),
        ];
        for (index, byte) in [(0, b'g'), (1, b'/'), (63, b'z'), (62, 0xff), (63, b' ')] {
            let mut text = valid.clone();
            text[index] = byte;
            invalid.push(text);
        }
        for text in invalid {
            let mut out = [0xa5; Credential::BYTE_LEN];
            assert_eq!(
                Credential::decode_hex(&text, &mut out),
                Err(EngineError::InvalidConfig)
            );
            assert_eq!(out, [0; Credential::BYTE_LEN]);
        }
    }

    #[test]
    fn verify_accepts_equal_secrets() {
        let left = Credential::from_bytes([0x41; 32]);
        let right = Credential::from_bytes([0x41; 32]);
        assert!(left.verify(&right));
        assert!(right.verify(&left));
    }

    #[test]
    fn verify_rejects_unequal_secrets() {
        let left = Credential::from_bytes([0x41; 32]);
        let mut bytes = [0x41; 32];
        bytes[0] = 0x40;
        assert!(!left.verify(&Credential::from_bytes(bytes)));

        bytes[0] = 0x41;
        bytes[15] ^= 0x01;
        assert!(!left.verify(&Credential::from_bytes(bytes)));

        bytes[15] = 0x41;
        bytes[31] = 0x42;
        assert!(!left.verify(&Credential::from_bytes(bytes)));
    }

    #[test]
    fn write_hex_emits_lowercase_digits() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x0a;
        bytes[1] = 0x41;
        bytes[31] = 0xff;
        let mut out = [0u8; 64];
        Credential::from_bytes(bytes).write_hex(&mut out);
        let mut expected = [b'0'; 64];
        expected[..4].copy_from_slice(b"0a41");
        expected[62..].copy_from_slice(b"ff");
        assert_eq!(out, expected);
    }
}
