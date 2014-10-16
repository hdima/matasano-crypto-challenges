/* AES ECB/CBC mode oracle
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use std::str;
use std::rand::{random, Rng, Rand};
use std::fmt::{Show, Formatter, FormatError};
use std::collections::{HashSet};
use serialize::base64::FromBase64;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ecb};

#[deriving(PartialEq, Eq)]
enum Mode {
    ECB,
    CBC
}

impl Rand for Mode {
    fn rand<R: Rng>(rng: &mut R) -> Mode {
        match rng.gen() {
            true => ECB,
            false => CBC
        }
    }
}

impl Show for Mode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        match *self {
            ECB => write!(f, "ECB"),
            CBC => write!(f, "CBC"),
        }
    }
}

#[inline]
fn random_byte() -> u8 {
    random::<u8>()
}

#[inline]
fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random_byte())
}

#[inline]
fn encrypt(string: &[u8], unknown: &[u8], key: &[u8]) -> Vec<u8> {
    encrypt_aes_ecb((string.to_vec() + unknown.to_vec()).as_slice(), key)
}

fn guess_aes_mode(unknown: &[u8], key: &[u8], block_size: uint) -> Mode {
    let s = Vec::from_fn(block_size * 2, |_| 'A' as u8);
    let enc = encrypt(s.as_slice(), unknown, key);
    let mut blocks = HashSet::new();
    for block in enc.as_slice().chunks(block_size) {
        if !blocks.insert(block) {
            return ECB;
        }
    }
    CBC
}

fn unknown_string() -> Vec<u8> {
    let data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";
    data.from_base64().unwrap()
}

fn guess_block_size(unknown: &[u8], key: &[u8]) -> Option<uint> {
    let mut prev = encrypt(['A' as u8].as_slice(), unknown, key);
    for len in range(1, 50) {
        let s = Vec::from_fn(len + 1, |_| 'A' as u8);
        let enc = encrypt(s.as_slice(), unknown, key);
        if prev.slice_to(len) == enc.slice_to(len) {
            return Some(len);
        }
        prev = enc;
    }
    None
}

fn make_dict(key: &[u8], block_size: uint) -> Vec<u8> {
    let mut dict = Vec::from_fn(256, |_| 0);
    let mut input = Vec::from_fn(block_size, |_| 'A' as u8);
    for c in range(0, 255) {
        *input.last_mut().unwrap() = c;
        let enc = encrypt_aes_ecb(input.as_slice(), key);
        *dict.get_mut(*enc.last().unwrap() as uint) = c;
    }
    dict
}

fn decrypt(unknown: &[u8], key: &[u8], dict: Vec<u8>,
           block_size: uint) -> Vec<u8> {
    let mut input = Vec::from_fn(block_size, |_| 'A' as u8);
    Vec::from_fn(unknown.len(), |i| {
        *input.last_mut().unwrap() = *unknown.get(i).unwrap();
        let enc = encrypt_aes_ecb(input.as_slice(), key);
        dict[*enc.last().unwrap() as uint]
        })
}

fn main() {
    let unknown = unknown_string();
    let key = random_bytes(AES_BLOCK_SIZE);
    let block_size = guess_block_size(unknown.as_slice(),
                                      key.as_slice()).unwrap();
    println!("Block size: {}", block_size);
    let mode = guess_aes_mode(unknown.as_slice(), key.as_slice(), block_size);
    println!("AES mode: {}", mode);
    let dict = make_dict(key.as_slice(), block_size);
    let dec = decrypt(unknown.as_slice(), key.as_slice(), dict, block_size);
    println!("Text: {}", str::from_utf8_lossy(dec.as_slice()));
}
