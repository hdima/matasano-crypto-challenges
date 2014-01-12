/* Repeating-key XOR decrypter
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern mod single_xor_lib;

extern mod extra;

#[cfg(not(test))]
use std::path::Path;
#[cfg(not(test))]
use std::io::fs::File;
#[cfg(not(test))]
use std::str;
#[cfg(not(test))]
use std::vec;

use std::iter::AdditiveIterator;

#[cfg(not(test))]
use extra::base64::FromBase64;

use single_xor_lib::decrypt;

// TODO: Rename it or rename the corresponding type in single_xor_lib
enum DecryptionResult {
    Found(~[u8], ~[u8]),
    NotFound
}

/*
 * Calculate Hamming distance between two binary vectors.
 * If vectors have different lengths the smallest length will be used.
 */
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
    // Iteration will stop once one of the iterators will stop
    let iter = s1.iter().zip(s2.iter());
    iter.map(|(&c1, &c2)| -> uint n_bits[c1 ^ c2] as uint).sum()
}

/*
 * Guess possible key size for the binary buffer
 */
fn guess_keysize(buffer: &[u8]) -> Option<uint> {
    static max_key_size: uint = 50;

    let len = buffer.len();
    // Set to maximal possible unnormalized Hamming distance
    let mut min_dist = (max_key_size * 8) as f32;
    let mut keysize = None;

    for s in range(2, max_key_size + 1) {
        let size = s as uint;
        // We're not trying too hard here
        if len < size * 4 {
            break;
        }
        // Calculate average Hamming distance between two pairs of consecutive
        // parts of encrypted text of the expected size
        let dist1 = hamming_distance(buffer.slice(0, size),
                                     buffer.slice(size, size * 2));
        let dist2 = hamming_distance(buffer.slice(size * 2, size * 3),
                                     buffer.slice(size * 3, size * 4));
        let dist: f32 = (dist1 + dist2) as f32 / (2 * size) as f32;
        // Save the new key size if Hamming distance is lower than the old one
        if dist < min_dist {
            min_dist = dist;
            keysize = Some(size);
        }
    }
    keysize
}

#[cfg(not(test))]
fn decrypt_with_keysize(encrypted: &[u8], keysize: uint) -> DecryptionResult {
    let len = encrypted.len();
    let line_len = (len / keysize) + 1;
    let mut buffers: ~[~[u8]] = vec::from_fn(keysize,
        |_| -> ~[u8] vec::with_capacity(line_len));
    for block in encrypted.chunks(keysize) {
        for (i, &c) in block.iter().enumerate() {
            buffers[i].push(c);
        }
    }
    let mut key: ~[u8] = vec::with_capacity(keysize);
    let mut decrypted: ~[u8] = vec::from_elem(len, 0u8);
    for (i, block) in buffers.iter().enumerate() {
        match decrypt(*block) {
            single_xor_lib::Found(k, text) => {
                key.push(k);
                for (j, &c) in text.iter().enumerate() {
                    decrypted[i + j * keysize] = c;
                }
            },
            single_xor_lib::NotFound => return NotFound
        }
    }
    Found(key, decrypted)
}

#[cfg(not(test))]
fn decrypt_repeating_xor(encrypted: &[u8]) -> DecryptionResult {
    match guess_keysize(encrypted) {
        Some(keysize) => decrypt_with_keysize(encrypted, keysize),
        None => return NotFound
    }
}

#[cfg(not(test))]
fn decrypt_repeating_xor_file(mut file: File) -> DecryptionResult {
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
        Found(key, text) => println!("Decrypted => {}, {}",
            str::from_utf8(key), str::from_utf8(text)),
        NotFound => println!("ERROR: No key found")
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
