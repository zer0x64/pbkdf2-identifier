use std::cmp::min;

#[cfg(feature = "parallel")]
use std::thread;

use hmac::crypto_mac::generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
use hmac::digest::{BlockInput, FixedOutput, Input, Reset};
use hmac::{Hmac, Mac};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::hash_primitive::{HashPrimitive, PRIMITIVES};

/// Tries to find the iteration count and the hash algorithm of the hash.
/// password - The password of the hash
/// hash - The hash itself
/// salt - The salt used in the derivation
/// max - The maximum number of iteration to try. Use 0 to try until aborted.
pub fn identify_all(
    password: &[u8],
    hash: &[u8],
    salt: &[u8],
    max: Option<usize>,
) -> Option<(HashPrimitive, usize)> {
    identify_algorithms(password, hash, salt, max, PRIMITIVES.to_vec())
}

pub fn identify_algorithms(
    password: &[u8],
    hash: &[u8],
    salt: &[u8],
    max: Option<usize>,
    algorithms: Vec<HashPrimitive>,
) -> Option<(HashPrimitive, usize)> {
    let found = Arc::new(AtomicBool::new(false));

    #[cfg(feature = "parallel")]
    {
        let password = Arc::new(password.to_vec());
        let hash = Arc::new(hash.to_vec());
        let salt = Arc::new(salt.to_vec());

        let threads_handles: Vec<_> = algorithms
            .into_iter()
            .map(|primitive| {
                let password = password.clone();
                let hash = hash.clone();
                let salt = salt.clone();
                let found = found.clone();
                thread::spawn(move || {
                    Some((
                        primitive,
                        primitive.get_identifier_threaded()(&password, &hash, &salt, max, &found)?,
                    ))
                })
            })
            .collect();

        let mut result = None;
        for t in threads_handles {
            match t.join() {
                Ok(Some(x)) => result = Some(x),
                _ => {}
            };
        }

        result
    }

    #[cfg(not(feature = "parallel"))]
    {
        for p in PRIMITIVES {
            match p.get_identifier_threaded()(&password, &hash, &salt, max, &found) {
                Some(x) => return Some((*p, x)),
                _ => {}
            }
        }

        None
    }
}

/// Tries to find the iteration count of the hash knowing its algorithm.
/// password - The password of the hash
/// hash - The hash itself
/// salt - The salt used in the derivation
/// max - The maximum number of iteration to try. Use 0 to try until aborted.
pub fn identify_iterations<T>(
    password: &[u8],
    hash: &[u8],
    salt: &[u8],
    max: Option<usize>,
) -> Option<usize>
where
    T: Input + BlockInput + FixedOutput + Reset + Default + Clone,
    T::BlockSize: ArrayLength<u8>,
    T::OutputSize: ArrayLength<u8>,
{
    let found = Arc::new(AtomicBool::new(false));
    identify_iterations_threaded::<T>(password, hash, salt, max, &found)
}

/// Tries to find the iteration count of the hash knowing its algorithm. Takes an shared variable to know when to stop searching.
/// password - The password of the hash
/// hash - The hash itself
/// salt - The salt used in the derivation
/// max - The maximum number of iteration to try. Use 0 to try until aborted.
/// found - Shared variable to notify other threads if the hash has been identified.
pub fn identify_iterations_threaded<T>(
    password: &[u8],
    hash: &[u8],
    salt: &[u8],
    max: Option<usize>,
    found: &AtomicBool,
) -> Option<usize>
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

    let max = max.unwrap_or(std::usize::MAX);

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
            found.store(true, Ordering::Relaxed);
            return Some(i);
        }

        if found.load(Ordering::Relaxed) {
            return None;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identify_iterations_shorter_block_size() {
        use base64;
        use sha1::Sha1;

        let iterations = identify_iterations::<Sha1>(
            "password".as_bytes(),
            &base64::decode("EVeVmsezinX2Nv+J36elk6UA3mJFmJ4Nk2BWHnpbBCg=").unwrap(),
            &base64::decode("akL5xcl1RwlmlfAxkGp1NA==").unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(iterations, 123);
    }

    #[test]
    fn test_identify_iterations_longer_block_size() {
        use base64;
        use sha2::Sha512;

        let iterations = identify_iterations::<Sha512>(
            "password".as_bytes(),
            &base64::decode("oElyEp3GgQxwdfE6uKfLqz40XB9CTF3iP003JhLPCuc=").unwrap(),
            &base64::decode("RtTNd9YXr4vQxiPQXooELA==").unwrap(),
            None,
        )
        .unwrap();
        assert_eq!(iterations, 123);
    }

    #[test]
    fn test_identify_all() {
        use base64;

        let (primitive, iterations) = identify_all(
            "password".as_bytes(),
            &base64::decode("Qp+q3JTY/2gnTSRHRNgn3g==").unwrap(),
            &base64::decode("al9TeCB42U/chevUbuaG1w==").unwrap(),
            None,
        )
        .unwrap();

        assert_eq!(primitive, HashPrimitive::HMACSHA256);
        assert_eq!(iterations, 125);
    }
}
