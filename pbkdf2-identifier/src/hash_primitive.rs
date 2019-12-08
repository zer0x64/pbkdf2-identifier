use std::sync::atomic::AtomicBool;

use sha1::Sha1;
use sha2::{Sha224, Sha256, Sha384, Sha512};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use super::{ identify_iterations, identify_iterations_threaded };

/// A list of the hash algorithms to try
pub static PRIMITIVES: &'static [HashPrimitive] = &[
    HashPrimitive::HMACSHA1,
    HashPrimitive::HMACSHA224,
    HashPrimitive::HMACSHA256,
    HashPrimitive::HMACSHA384,
    HashPrimitive::HMACSHA512,
];

/// A wrapper around various common primitives used for PBKDF2.
/// Implements a name and the closure to compute the values.
/// This will later on be a userful abstraction when differentiating between webassembly and multithreaded code.
#[cfg_attr(target_arch = "wasm32",wasm_bindgen)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashPrimitive {
    HMACSHA1,
    HMACSHA224,
    HMACSHA256,
    HMACSHA384,
    HMACSHA512,
}

impl HashPrimitive {
    /// Returns a readable name for the primitive.
    pub fn name(&self) -> &'static str {
        match self {
            HashPrimitive::HMACSHA1 => "HMAC-SHA1",
            HashPrimitive::HMACSHA224 => "HMAC-SHA224",
            HashPrimitive::HMACSHA256 => "HMAC-SHA256",
            HashPrimitive::HMACSHA384 => "HMAC-SHA384",
            HashPrimitive::HMACSHA512 => "HMAC-SHA512",
        }
    }

    /// Returns a closure for identifying the iteration count for this specific algorithm.
    pub fn get_identifier(
        &self,
    ) -> Box<dyn Fn(&[u8], &[u8], &[u8], Option<usize>) -> Option<usize>> {
        match self {
            HashPrimitive::HMACSHA1 => Box::new(|password, hash, salt, max| {
                identify_iterations::<Sha1>(password, hash, salt, max)
            }),
            HashPrimitive::HMACSHA224 => Box::new(|password, hash, salt, max| {
                identify_iterations::<Sha224>(password, hash, salt, max)
            }),
            HashPrimitive::HMACSHA256 => Box::new(|password, hash, salt, max| {
                identify_iterations::<Sha256>(password, hash, salt, max)
            }),
            HashPrimitive::HMACSHA384 => Box::new(|password, hash, salt, max| {
                identify_iterations::<Sha384>(password, hash, salt, max)
            }),
            HashPrimitive::HMACSHA512 => Box::new(|password, hash, salt, max| {
                identify_iterations::<Sha512>(password, hash, salt, max)
            }),
        }
    }

    /// Returns a closure for identifying the iteration count for this specific algorithm.
    pub fn get_identifier_threaded(
        &self,
    ) -> Box<dyn Fn(&[u8], &[u8], &[u8], Option<usize>, &AtomicBool) -> Option<usize>> {
        match self {
            HashPrimitive::HMACSHA1 => Box::new(|password, hash, salt, max, found| {
                identify_iterations_threaded::<Sha1>(password, hash, salt, max, found)
            }),
            HashPrimitive::HMACSHA224 => Box::new(|password, hash, salt, max, found| {
                identify_iterations_threaded::<Sha224>(password, hash, salt, max, found)
            }),
            HashPrimitive::HMACSHA256 => Box::new(|password, hash, salt, max, found| {
                identify_iterations_threaded::<Sha256>(password, hash, salt, max, found)
            }),
            HashPrimitive::HMACSHA384 => Box::new(|password, hash, salt, max, found| {
                identify_iterations_threaded::<Sha384>(password, hash, salt, max, found)
            }),
            HashPrimitive::HMACSHA512 => Box::new(|password, hash, salt, max, found| {
                identify_iterations_threaded::<Sha512>(password, hash, salt, max, found)
            }),
        }
    }
}
