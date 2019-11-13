use std::cmp::min;

use hmac::crypto_mac::generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
use hmac::digest::{BlockInput, FixedOutput, Input, Reset};
use hmac::{Hmac, Mac};

/// Tries to find the iteration count of the hash knowing it's algorithm.
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

#[test]
fn test() {
    use base64;
    use sha2::Sha256;

    let iterations = identify_iterations::<Sha256>(
        "password".as_bytes(),
        &base64::decode("rPfCAKgEnO/PJdkV7BP/1fTYZTzEiwHpXbO8VfYsLSk=").unwrap(),
        &base64::decode("ScjYXMzBrWvaNypcuYYHoA==").unwrap(),
        100000,
    );
    assert_eq!(iterations, 12345);
}
