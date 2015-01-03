/* An MT19937 stream cipher
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate libc;
extern crate serialize;
extern crate mersenne_twister;

#[cfg(not(test))]
use std::rand::random;
use std::iter::range_step;
use std::ptr;
use libc::time_t;

use serialize::hex::{FromHex, ToHex};

use mersenne_twister::{MersenneTwister, MersenneTwisterSeed};


static TOKEN_LEN: uint = 8;

extern {
    fn time(tloc: *const time_t) -> time_t;
}

fn timestamp() -> time_t {
    unsafe {time(ptr::null())}
}

struct KeyStream {
    prng: MersenneTwister,
    buffer: Vec<u8>
}

impl KeyStream {
    fn new<S: MersenneTwisterSeed>(seed: S) -> Self {
        let prng = MersenneTwister::new(seed);
        let buffer = Vec::with_capacity(4);
        KeyStream{prng: prng, buffer: buffer}
    }
}

impl Iterator<u8> for KeyStream {
    fn next(&mut self) -> Option<u8> {
        if self.buffer.is_empty() {
            let rnd = self.prng.rand_u32();
            let buf = range_step(0, 32, 8).map(|shift| {(rnd >> shift) as u8});
            self.buffer.extend(buf);
        }
        self.buffer.pop()
    }
}

fn encrypt(data: &[u8], key: u16) -> Vec<u8> {
    let ks = KeyStream::new(key);
    data.iter().zip(ks).map(|(&d, k)| d ^ k).collect()
}

fn decrypt(data: &[u8], key: u16) -> Vec<u8> {
    encrypt(data, key)
}

#[cfg(not(test))]
fn guess_key(encrypted: &[u8], known_suffix: &[u8]) -> Option<u16> {
    let sfx_pos = encrypted.len() - known_suffix.len();
    let suffix_s = known_suffix.as_slice();
    // Brute force key search
    for key in range(0u32, 0x10000) {
        let dec = decrypt(encrypted, key as u16);
        if dec.slice_from(sfx_pos) == suffix_s {
            return Some(key as u16);
        }
    }
    None
}

#[cfg(not(test))]
fn random_bytes(len: uint) -> Vec<u8> {
    range(0, len).map(|_| random::<u8>()).collect()
}

#[cfg(not(test))]
fn update_text(suffix: &[u8]) -> Vec<u8> {
    random_bytes(random::<u8>() as uint) + suffix
}

fn create_token() -> String {
    let ks = KeyStream::new(timestamp());
    ks.take(TOKEN_LEN).collect::<Vec<u8>>().to_hex()
}

fn find_token_seed(token: &str) -> Option<time_t> {
    let mut now = timestamp();
    let bytes = token.from_hex().unwrap();
    let token_s = bytes.as_slice();
    for _ in range(0u64, 1000000) {
        let ks = KeyStream::new(now);
        let data = ks.take(TOKEN_LEN).collect::<Vec<u8>>();
        if data.as_slice() == token_s {
            return Some(now);
        }
        now -= 1;
    }
    None
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let suffix = String::from_str("AAAAAAAAAAAAAA").into_bytes();
    let key = random::<u16>();
    let enc = encrypt(update_text(suffix.as_slice()).as_slice(), key);
    assert_eq!(guess_key(enc.as_slice(), suffix.as_slice()), Some(key));
    println!("1. Recovered key: {}", key);

    let token = create_token();
    print!("2. A password reset token: {}", token);
    match find_token_seed(token.as_slice()) {
        Some(_) => println!(" (generated from the current time)"),
        None => panic!("Token wasn't generated from the current time")
    }
}

#[cfg(test)]
mod tests {
    use std::rand::random;
    use super::{KeyStream, encrypt, decrypt};

    #[test]
    fn test_key_stream() {
        let ks: Vec<u8> = KeyStream::new(0u32).take(100).collect();
        let ks2: Vec<u8> = KeyStream::new(0u32).take(100).collect();
        let ks3: Vec<u8> = KeyStream::new(100u32).take(100).collect();
        assert_eq!(ks.as_slice(), ks2.as_slice());
        assert!(ks.as_slice() != ks3.as_slice());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let data = String::from_str("Hello, new cipher!").into_bytes();
        let key = random::<u16>();
        let enc = encrypt(data.as_slice(), key);
        assert_eq!(decrypt(enc.as_slice(), key), data.as_slice());
    }
}
