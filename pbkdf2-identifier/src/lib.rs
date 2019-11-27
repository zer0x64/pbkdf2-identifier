use std::cmp::min;

use hmac::crypto_mac::generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
use hmac::digest::{BlockInput, FixedOutput, Input, Reset};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// A list of the hash algorithms to try
pub static PRIMITIVES: &'static [HashPrimitive] = &[
    HashPrimitive::HMACSHA1,
    HashPrimitive::HMACSHA256,
    HashPrimitive::HMACSHA512,
];

/// A wrapper around various common primitives used for PBKDF2.
/// Implements a name and the closure to compute the values.
/// This will later on be a userful abstraction when differentiating between webassembly and multithreaded code.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashPrimitive {
    HMACSHA1,
    HMACSHA256,
    HMACSHA512,
}

impl HashPrimitive {
    /// Returns a readable name for the primitive.
    pub fn name(&self) -> &'static str {
        match self {
            HashPrimitive::HMACSHA1 => "HMAC-SHA1",
            HashPrimitive::HMACSHA256 => "HMAC-SHA256",
            HashPrimitive::HMACSHA512 => "HMAC-SHA512",
        }
    }

    /// Returns a closure for identifying the iteration count for this specific algorithm.
    pub fn get_identifier(&self) -> Box<dyn Fn(&[u8], &[u8], &[u8], usize) -> usize> {
        match self {
            HashPrimitive::HMACSHA1 => Box::new(|password, hash, salt, max| {
                identify_iterations::<Sha1>(password, hash, salt, max)
            }),
            HashPrimitive::HMACSHA256 => Box::new(|password, hash, salt, max| {
                identify_iterations::<Sha256>(password, hash, salt, max)
            }),
            HashPrimitive::HMACSHA512 => Box::new(|password, hash, salt, max| {
                identify_iterations::<Sha512>(password, hash, salt, max)
            }),
        }
    }
}

/// Tries to find the iteration count and the hash algorithm of the hash.
/// password - The password of the hash
/// hash - The hash itself
/// salt - The salt used in the derivation
/// max - The maximum number of iteration to try. Use 0 to try until aborted.
pub fn identify_all(
    password: &[u8],
    hash: &[u8],
    salt: &[u8],
    max: usize,
) -> (HashPrimitive, usize) {
    for primitive in PRIMITIVES {
        match primitive.get_identifier()(password, hash, salt, max) {
            0 => continue,
            iteration_count => return (*primitive, iteration_count),
        }
    }
    (HashPrimitive::HMACSHA1, 0)
}

/// Tries to find the iteration count of the hash knowing its algorithm.
/// password - The password of the hash
/// hash - The hash itself
/// salt - The salt used in the derivation
/// max - The maximum number of iteration to try. Use 0 to try until aborted.
pub fn identify_iterations<T>(password: &[u8], hash: &[u8], salt: &[u8], mut max: usize) -> usize
where
    T: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    T::BlockSize: ArrayLength<u8>,
    T::OutputSize: ArrayLength<u8>,
{
    // The accumulator is XORed after each iteration and compared to the value expected
    let mut accumulator = GenericArray::<u8, T::OutputSize>::generate(|_| 0);

    // The key is always the password, so we can instanciate it once and clone it.
    let prf = Hmac::<T>::new_varkey(&password).expect("HMAC accepts all key sizes");

    // First iteration
    // Only the first block needs to be validated, so we'll only need to use Salt | int(1)
    let mut data = salt.to_vec();
    data.extend_from_slice(&[0, 0, 0, 1]);

    if max == 0 {
        max = std::usize::MAX;
    }

    for i in 1..max {
        // HMAC the previous result with the hash as the key.
        let mut prf = prf.clone();
        prf.input(&data);
        data = prf.result().code().to_vec();

        // XOR the result into the accumulator
        for j in 0..min(accumulator.len(), data.len()) {
            accumulator[j] ^= data[j];
        }

        // Checks if the data is equal
        let mut is_equal = true;
        for j in 0..min(accumulator.len(), hash.len()) {
            if accumulator[j] != hash[j] {
                is_equal = false;
                break;
            }
        }

        // Returns the iteration count if found
        if is_equal {
            return i;
        }
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_iterations_shorter_block_size() {
        use base64;

        let iterations = identify_iterations::<Sha1>(
            "password".as_bytes(),
            &base64::decode("EVeVmsezinX2Nv+J36elk6UA3mJFmJ4Nk2BWHnpbBCg=").unwrap(),
            &base64::decode("akL5xcl1RwlmlfAxkGp1NA==").unwrap(),
            1000,
        );
        assert_eq!(iterations, 123);
    }

    #[test]
    fn test_identify_iterations_longer_block_size() {
        use base64;

        let iterations = identify_iterations::<Sha512>(
            "password".as_bytes(),
            &base64::decode("oElyEp3GgQxwdfE6uKfLqz40XB9CTF3iP003JhLPCuc=").unwrap(),
            &base64::decode("RtTNd9YXr4vQxiPQXooELA==").unwrap(),
            1000,
        );
        assert_eq!(iterations, 123);
    }

    #[test]
    fn test_identify_all() {
        use base64;

        let (primitive, iterations) = identify_all(
            "password".as_bytes(),
            &base64::decode("Qp+q3JTY/2gnTSRHRNgn3g==").unwrap(),
            &base64::decode("al9TeCB42U/chevUbuaG1w==").unwrap(),
            200,
        );

        assert_eq!(primitive, HashPrimitive::HMACSHA256);
        assert_eq!(iterations, 125);
    }
}
