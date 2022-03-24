use wasm_bindgen::prelude::*;

use crate::hash_primitive::HashPrimitive;

static MAX_DEFAULT: usize = 1000000;

#[wasm_bindgen]
pub struct Pbkdf2Parameters {
    pub primitive: HashPrimitive,
    pub iterations: usize,
}

#[wasm_bindgen]
pub fn primitive_name(p: HashPrimitive) -> String {
    String::from(p.name())
}

#[wasm_bindgen]
pub fn identify_iterations(
    password: &[u8],
    hash: &[u8],
    salt: &[u8],
    primitive: HashPrimitive,
    max: Option<usize>,
) -> Option<usize> {
    primitive.get_identifier()(password, hash, salt, max)
}
