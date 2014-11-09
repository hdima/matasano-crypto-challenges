/* AES CBC padding oracle
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use serialize::base64::FromBase64;
use std::rand::random;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_cbc, decrypt_aes_cbc_raw,
    remove_pkcs7_padding};


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
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
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
            Some(&last) if last > 0 && (last as uint) <= AES_BLOCK_SIZE => {
                let data_len = dec.len() - last as uint;
                dec.slice_from(data_len).iter().all(|&c| c == last)
            }
            _ => false
        }
    }

    fn decrypt(&self, enc: &[u8]) -> Vec<u8> {
        let blocks: Vec<Vec<u8>> = enc.chunks(AES_BLOCK_SIZE).map(
            |block| self.decrypt_block(block)).collect();
        let enc_it = self.iv.iter().chain(enc.iter());
        let dec_it = blocks.iter().flat_map(|block| block.iter());
        let dec = enc_it.zip(dec_it).map(|(&c1, &c2)| c1 ^ c2).collect();
        remove_pkcs7_padding(dec)
    }

    fn decrypt_block(&self, block: &[u8]) -> Vec<u8> {
        let mut dec = Vec::from_elem(AES_BLOCK_SIZE, 0);
        let mut tmp = Vec::from_elem(AES_BLOCK_SIZE, 0) + block;
        let mut i = 1;
        for c in range(0u16, 256) {
            tmp[AES_BLOCK_SIZE - i] = c as u8;
            if self.is_padding_valid(tmp.as_slice()) {
                break;
            }
        }
        while i < AES_BLOCK_SIZE {
            let is_padding_longer = range(0u16, 256).any(|c| {
                tmp[AES_BLOCK_SIZE - i - 1] = c as u8;
                !self.is_padding_valid(tmp.as_slice())
                });
            tmp[AES_BLOCK_SIZE - i - 1] = 0;
            if !is_padding_longer {
                break;
            }
            i += 1;
        }
        for j in range(1, i + 1) {
            dec[AES_BLOCK_SIZE - j] = i as u8 ^ tmp[AES_BLOCK_SIZE - j];
        }
        for j in range(i, AES_BLOCK_SIZE) {
            let next = j + 1;
            for k in range(1, next) {
                let c = tmp[AES_BLOCK_SIZE - k];
                tmp[AES_BLOCK_SIZE - k] = c ^ j as u8 ^ next as u8;
            }
            for c in range(0u16, 256) {
                tmp[AES_BLOCK_SIZE - next] = c as u8;
                if self.is_padding_valid(tmp.as_slice()) {
                    dec[AES_BLOCK_SIZE - next] = next as u8 ^ c as u8;
                    break;
                }
            }
        }
        dec
    }
}

fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random::<u8>())
}

fn main() {
    let state = State::new();
    let enc = state.encrypt();
    let dec = state.decrypt(enc.as_slice());
    println!("Encrypted: {}", String::from_utf8_lossy(dec.as_slice()));
}
