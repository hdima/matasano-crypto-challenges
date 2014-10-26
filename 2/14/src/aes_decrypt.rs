/* Byte at a time AES ECB decryption (Harder)
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use std::rand::random;
use std::collections::HashMap;
use serialize::base64::FromBase64;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ecb};


type Dict = HashMap<Vec<u8>, u8>;

struct Decryptor {
    unknown: Vec<u8>,
    prefix: Vec<u8>,
    key: Vec<u8>,
}

impl Decryptor {
    fn new() -> Decryptor {
        let unknown = unknown_string();
        let prefix = random_bytes(random::<u8>() as uint);
        let key = random_bytes(AES_BLOCK_SIZE);
        Decryptor{unknown: unknown, key: key, prefix: prefix}
    }

    #[inline]
    fn encrypt(&self, string: &[u8]) -> Vec<u8> {
        let data = self.prefix + string.to_vec() + self.unknown;
        encrypt_aes_ecb(data.as_slice(), self.key.as_slice())
    }

    // Return start position for the first AES block after the prefix and
    // difference between the start position and the end of the prefix
    fn find_start_pos(&self) -> (uint, uint) {
        // Start from 2 AES blocks so we can find duplicates
        let mut data = Vec::from_elem(AES_BLOCK_SIZE * 2, 'A' as u8);
        loop {
            let enc = self.encrypt(data.as_slice());
            let chunks = enc.as_slice().chunks(AES_BLOCK_SIZE);
            let tail = enc.slice_from(AES_BLOCK_SIZE);
            let pairs = chunks.zip(tail.chunks(AES_BLOCK_SIZE));
            for (i, (first, second)) in pairs.enumerate() {
                if first == second {
                    return (i * AES_BLOCK_SIZE,
                            data.len() - AES_BLOCK_SIZE * 2);
                }
            }
            // Extend test blocks by one character
            data.push('A' as u8);
        }
    }

    fn make_dict(&self, start: uint, diff: uint) -> Dict {
        let mut dict = HashMap::with_capacity(256);
        let mut input = Vec::from_elem(AES_BLOCK_SIZE + diff, 'A' as u8);
        for c in range(0, 255) {
            *input.last_mut().unwrap() = c;
            let enc = self.encrypt(input.as_slice());
            dict.insert(enc.slice(start, start + AES_BLOCK_SIZE).to_vec(), c);
        }
        dict
    }

    fn decrypt(&self) -> Vec<u8> {
        let (start, diff) = self.find_start_pos();
        let dict = self.make_dict(start, diff);
        let mut input = Vec::from_elem(AES_BLOCK_SIZE + diff, 'A' as u8);
        self.unknown.iter().map(|&c| {
            *input.last_mut().unwrap() = c;
            let enc = self.encrypt(input.as_slice());
            dict[enc.slice(start, start + AES_BLOCK_SIZE).to_vec()]
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
    let dec = decryptor.decrypt();
    println!("Text: {}", String::from_utf8(dec).unwrap());
}
