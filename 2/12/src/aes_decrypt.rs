/* Byte at a time AES ECB decryption (Simple)
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use std::rand::random;
use std::fmt;
use std::iter::repeat;
use std::collections::HashMap;
use serialize::base64::FromBase64;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ecb};


type Dict = HashMap<Vec<u8>, u8>;

#[deriving(PartialEq, Eq)]
enum Mode {
    ECB,
    CBC
}

impl fmt::Show for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Mode::ECB => write!(f, "ECB"),
            Mode::CBC => write!(f, "CBC"),
        }
    }
}

struct Decryptor {
    unknown: Vec<u8>,
    key: Vec<u8>,
}

impl Decryptor {
    fn new() -> Decryptor {
        let unknown = unknown_string();
        let key = random_bytes(AES_BLOCK_SIZE);
        Decryptor{unknown: unknown, key: key}
    }

    #[inline]
    fn encrypt(&self, string: &[u8]) -> Vec<u8> {
        let data = string.to_vec() + self.unknown.as_slice();
        encrypt_aes_ecb(data.as_slice(), self.key.as_slice())
    }

    fn guess_block_size(&self) -> Option<uint> {
        static MAX_KEY_SIZE: uint = 256;
        let data: Vec<u8> = repeat(0u8).take(MAX_KEY_SIZE - 1).collect();
        let mut prev = self.encrypt(data.slice_to(1));
        for len in range(1, MAX_KEY_SIZE) {
            let enc = self.encrypt(data.slice_to(len + 1));
            if prev.slice_to(len) == enc.slice_to(len) {
                return Some(len);
            }
            prev = enc;
        }
        None
    }

    fn guess_aes_mode(&self, block_size: uint) -> Mode {
        let s: Vec<u8> = repeat(0u8).take(block_size * 2).collect();
        let e = self.encrypt(s.as_slice());
        match e.slice_to(block_size) == e.slice(block_size, block_size * 2) {
            true => Mode::ECB,
            false => Mode::CBC
        }
    }

    fn make_dict(&self, block_size: uint) -> Dict {
        let mut input: Vec<u8> = repeat(0u8).take(block_size).collect();
        range(0, 255).map(|c| {
            *input.last_mut().unwrap() = c;
            let enc = self.encrypt(input.as_slice());
            (enc.slice_to(block_size).to_vec(), c)
        }).collect()
    }

    fn decrypt(&self, block_size: uint) -> Vec<u8> {
        let dict = self.make_dict(block_size);
        let mut input: Vec<u8> = repeat(0u8).take(block_size).collect();
        self.unknown.iter().map(|&c| {
            *input.last_mut().unwrap() = c;
            let enc = self.encrypt(input.as_slice());
            dict[enc.slice_to(block_size).to_vec()]
        }).collect()
    }
}

fn random_bytes(len: uint) -> Vec<u8> {
    range(0, len).map(|_| random::<u8>()).collect()
}

fn unknown_string() -> Vec<u8> {
    "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK".from_base64().unwrap()
}

fn main() {
    let decryptor = Decryptor::new();
    let block_size = decryptor.guess_block_size().unwrap();
    println!("Block size: {}", block_size);
    let mode = decryptor.guess_aes_mode(block_size);
    println!("AES mode: {}", mode);
    let dec = decryptor.decrypt(block_size);
    println!("Text: {}", String::from_utf8(dec).unwrap());
}
