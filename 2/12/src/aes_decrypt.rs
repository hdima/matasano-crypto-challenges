/* AES ECB/CBC mode oracle
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use std::str;
use std::rand::random;
use std::fmt;
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
            ECB => write!(f, "ECB"),
            CBC => write!(f, "CBC"),
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
        let data = string.to_vec() + self.unknown;
        encrypt_aes_ecb(data.as_slice(), self.key.as_slice())
    }

    fn guess_block_size(&self) -> Option<uint> {
        let mut prev = self.encrypt(['A' as u8].as_slice());
        for len in range(1, 256) {
            let s = Vec::from_elem(len + 1, 'A' as u8);
            let enc = self.encrypt(s.as_slice());
            if prev.slice_to(len) == enc.slice_to(len) {
                return Some(len);
            }
            prev = enc;
        }
        None
    }

    fn guess_aes_mode(&self, block_size: uint) -> Mode {
        let s = Vec::from_elem(block_size * 2, 'A' as u8);
        let enc = self.encrypt(s.as_slice());
        if enc.slice_to(block_size) == enc.slice(block_size, block_size * 2) {
            ECB
        } else {
            CBC
        }
    }

    fn make_dict(&self, block_size: uint) -> Dict {
        let mut dict = HashMap::with_capacity(256);
        let mut input = Vec::from_elem(block_size, 'A' as u8);
        for c in range(0, 255) {
            *input.last_mut().unwrap() = c;
            let enc = self.encrypt(input.as_slice());
            dict.insert(enc.slice_to(block_size).to_vec(), c);
        }
        dict
    }

    fn decrypt(&self, block_size: uint) -> Vec<u8> {
        let dict = self.make_dict(block_size);
        let mut input = Vec::from_elem(block_size, 'A' as u8);
        self.unknown.iter().map(|&c| {
            *input.last_mut().unwrap() = c;
            let enc = self.encrypt(input.as_slice());
            dict[enc.slice_to(block_size).to_vec()]
            }).collect()
    }
}

fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random::<u8>())
}

fn unknown_string() -> Vec<u8> {
    let data = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK";
    data.from_base64().unwrap()
}

fn main() {
    let decryptor = Decryptor::new();
    let block_size = decryptor.guess_block_size().unwrap();
    println!("Block size: {}", block_size);
    let mode = decryptor.guess_aes_mode(block_size);
    println!("AES mode: {}", mode);
    let dec = decryptor.decrypt(block_size);
    println!("Text: {}", str::from_utf8_lossy(dec.as_slice()));
}
