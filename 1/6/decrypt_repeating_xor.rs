// Repeating-key XOR decrypter
//
// Dmitry Vasiliev <dima@hlabs.org>
//

extern mod single_xor_lib;

extern mod extra;

#[cfg(not(test))]
use std::path::Path;
#[cfg(not(test))]
use std::io::fs::File;
#[cfg(not(test))]
use std::str;

use std::iter::AdditiveIterator;

#[cfg(not(test))]
use extra::base64::FromBase64;

use single_xor_lib::{decrypt, Found, NotFound};

fn hamming_distance(s1: &[u8], s2: &[u8]) -> uint {
    static n_bits: [u8, ..256] =
            [0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3,
             3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4,
             3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2,
             2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5,
             3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5,
             5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3,
             2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4,
             4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
             3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 2, 3, 3, 4, 3, 4,
             4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6,
             5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5,
             5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8];
    let iter = s1.iter().zip(s2.iter());
    iter.map(|(&c1, &c2)| -> uint n_bits[c1 ^ c2] as uint).sum()
}

fn guess_keysize(buffer: &[u8]) -> Option<uint> {
    let len = buffer.len();
    let mut min_dist = -1f32;
    let mut keysize = None;
    for s in range(2, 50) {
        let size = s as uint;
        if len < size * 4 {
            break;
        }
        let dist1 = hamming_distance(buffer.slice(0, size),
                                     buffer.slice(size, size * 2));
        let dist2 = hamming_distance(buffer.slice(size * 2, size * 3),
                                     buffer.slice(size * 3, size * 4));
        let dist: f32 = (dist1 + dist2) as f32 / (2 * size) as f32;
        if min_dist < 0f32 || dist < min_dist {
            min_dist = dist;
            keysize = Some(size);
        }
    }
    keysize
}

#[cfg(not(test))]
fn decrypt_with_keysize(encrypted: &[u8], keysize: uint) -> Option<~[u8]> {
    // TODO:
    //  - Split buffer to single key buffers
    //  - Find keys and decrypt every single key buffer
    //  - Compile bytes of key and decryped text
    //  - Return key and the decrypted text
}

#[cfg(not(test))]
fn decrypt_repeating_xor(encrypted: &[u8]) -> Option<~[u8]> {
    match guess_keysize(encrypted) {
        Some(keysize) => decrypt_with_keysize(encrypted, keysize),
        None => return None
    }
}

#[cfg(not(test))]
fn decrypt_repeating_xor_file(mut file: File) -> Option<~[u8]> {
    let data = file.read_to_end();
    let encrypted = str::from_utf8(data).from_base64().unwrap();
    decrypt_repeating_xor(encrypted)
}

#[cfg(not(test))]
fn main() {
    let path = Path::new("buffer.txt");
    let decrypted = match File::open(&path) {
        Some(file) => decrypt_repeating_xor_file(file),
        None => fail!("Unable to open buffer.txt")
    };
    match decrypted {
        Some(text) => println!("Decrypted => {}", str::from_utf8(decrypted)),
        None => println!("ERROR: No key found")
    }
}

#[test]
fn test_hamming_distance() {
    let s1 = ~"this is a test";
    let s2 = ~"wokka wokka!!!";
    assert_eq!(hamming_distance(s1.into_bytes(), s2.into_bytes()), 37);
}

#[test]
fn test_guess_keysize() {
    let buffer1 = ~"123456";
    assert_eq!(guess_keysize(buffer1.into_bytes()), None);

    let buffer2 = ~"1234567890123456789012345678901234567890";
    assert_eq!(guess_keysize(buffer2.into_bytes()), Some(10));
}
