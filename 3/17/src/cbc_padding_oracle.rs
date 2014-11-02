/* AES CBC padding oracle
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use serialize::base64::FromBase64;
use std::rand::random;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_cbc, decrypt_aes_cbc_raw};


static LINES: [&'static str, ..10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93 ",
    ];

struct State {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl State {
    fn new() -> State {
        let key = random_bytes(AES_BLOCK_SIZE);
        let iv = random_bytes(AES_BLOCK_SIZE);
        State{key: key, iv: iv}
    }

    fn encrypt(&self) -> Vec<u8> {
        let i = random::<u8>() % LINES.len() as u8;
        let line = LINES[i as uint].from_base64().unwrap();
        encrypt_aes_cbc(line.as_slice(), self.key.as_slice(),
                        self.iv.as_slice())
    }

    fn is_padding_valid(&self, encrypted: &[u8]) -> bool {
        let dec = decrypt_aes_cbc_raw(encrypted, self.key.as_slice(),
                                      self.iv.as_slice());
        match dec.last() {
            Some(&last) if (last as uint) < AES_BLOCK_SIZE => {
                let data_len = dec.len() - last as uint;
                dec.slice_from(data_len).iter().all(|&c| c == last)
            }
            _ => false
        }
    }
}

fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random::<u8>())
}

fn main() {
    let state = State::new();
    let enc = state.encrypt();
    println!("Encrypted: {}", String::from_utf8_lossy(enc.as_slice()));
}
