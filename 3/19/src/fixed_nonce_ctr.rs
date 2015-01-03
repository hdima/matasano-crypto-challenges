/* Breaking fixed nonce CTR mode
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use std::io::BufferedReader;
use std::io::File;
use std::rand::random;
use std::iter::AdditiveIterator;
use serialize::base64::FromBase64;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ctr};


fn encrypt_texts() -> Vec<Vec<u8>> {
    let key = random_bytes(AES_BLOCK_SIZE);
    let path = Path::new("texts.txt");
    let mut file = BufferedReader::new(File::open(&path));
    file.lines().map(|line| {
        let text = line.unwrap().from_base64().unwrap();
        encrypt_aes_ctr(text.as_slice(), key.as_slice(), 0)
    }).collect()
}

fn random_bytes(len: uint) -> Vec<u8> {
    range(0, len).map(|_| random::<u8>()).collect()
}

/* Convert array of texts to array of columns
 */
fn get_text_columns(texts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let max = texts.iter().map(|t| t.len()).max().unwrap();
    range(0, max).map(|i| {
        texts.iter().filter_map(|text| {
            text.get(i).cloned()
        }).collect()
    }).collect()
}

/* Number of lowercase or uppercase ASCII letters when we XOR current character
 * with all the other characters in the same column
 */
fn char_score(c: u8, col: &[u8]) -> uint {
    col.iter().map(|&c2|
        match (c ^ c2) as char {
            'a'...'z' | 'A'...'Z' => 1,
            _ => 0
        }
    ).sum()
}

/* Return index of the possible space character
 */
fn space_col_index(col: &[u8]) -> uint {
    col.iter().enumerate().map(|(i, &c)| {
        (char_score(c, col), i)
    }).max().unwrap().1
}

/* As the key is the same XOR between two encrypted texts is equal to XOR of
 * the plain texts.
 *
 * Also if we XOR an ASCII letter with the space character it will switch the
 * letter between lowercase and uppercase.
 *
 * So if we XOR a byte with other bytes in the same column and get lots of
 * lowercase or uppercase ASCII letters then probably current byte is the space
 * character.
 */
fn find_key(texts: &[Vec<u8>]) -> Vec<u8> {
    let cols = get_text_columns(texts);
    let mut key: Vec<u8> = cols.iter().map(|col| {
        col[space_col_index(col.as_slice())] ^ ' ' as u8
    }).collect();
    // We don't have spaces as first characters but we can guess it from the
    // context
    key[0] = texts[0][0] ^ 'i' as u8;
    key
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
        println!("{}: \"{}\"", i + 1,
                 String::from_utf8_lossy(text.as_slice()));
    }
}
