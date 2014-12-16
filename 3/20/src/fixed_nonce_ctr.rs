/* Breaking fixed nonce CTR statistically
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;
extern crate single_char_xor_lib;

use std::io::BufferedReader;
use std::io::File;
use std::rand::random;
use serialize::base64::FromBase64;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ctr};
use single_char_xor_lib::{decrypt, SingleCharKey};


fn encrypt_texts() -> Vec<Vec<u8>> {
    let key = random_bytes(AES_BLOCK_SIZE);
    let path = Path::new("texts.txt");
    let mut file = BufferedReader::new(File::open(&path));
    let texts: Vec<Vec<u8>> = file.lines().map(|line| {
        line.unwrap().from_base64().unwrap()
    }).collect();
    // Truncate all the encrypted texts to the same length
    let min_len = texts.iter().map(|t| t.len()).min().unwrap();
    texts.map_in_place(|line| {
        encrypt_aes_ctr(line.slice_to(min_len), key.as_slice(), 0)
    })
}

fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random::<u8>())
}

fn find_key(texts: &[Vec<u8>]) -> Vec<u8> {
    range(0, texts[0].len()).map(|i| {
        let buffer: Vec<u8> = texts.iter().map(|text| {
            text[i]
        }).collect();
        match decrypt(buffer.as_slice()) {
            SingleCharKey::Found(k, _) => k,
            SingleCharKey::NotFound => panic!("Key not found")
        }
    }).collect()
}

fn decrypt_texts(texts: &[Vec<u8>], key: &[u8]) -> Vec<Vec<u8>> {
    texts.iter().map(|text| {
        text.iter().zip(key.iter()).map(|(&c, &k)| c ^ k).collect()
    }).collect()
}

fn main() {
    let encrypted = encrypt_texts();
    let key = find_key(encrypted.as_slice());
    let decrypted = decrypt_texts(encrypted.as_slice(), key.as_slice());
    for (i, text) in decrypted.iter().enumerate() {
        println!("{:02}: \"{}\"", i + 1,
                 String::from_utf8_lossy(text.as_slice()));
    }
}
