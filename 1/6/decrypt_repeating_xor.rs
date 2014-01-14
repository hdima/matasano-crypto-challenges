/* Repeating-key XOR decrypter
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern mod single_char_xor_lib;

extern mod extra;

#[cfg(not(test))]
use std::path::Path;
#[cfg(not(test))]
use std::io::fs::File;
#[cfg(not(test))]
use std::str;
use std::vec;

use std::iter::AdditiveIterator;

#[cfg(not(test))]
use extra::base64::FromBase64;

use single_char_xor_lib::{decrypt, SingleCharKeyFound, SingleCharKeyNotFound};

// Result of the decryption
enum RepeatingKeyResult {
    RepeatingKeyFound(~[u8], ~[u8]),
    RepeatingKeyNotFound
}

/*
 * Calculate Hamming distance between two binary vectors.
 * If vectors have different lengths the smallest length will be used.
 */
fn hamming_distance(s1: &[u8], s2: &[u8]) -> uint {
    static n_bits: [uint, ..256] =
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
    s1.iter().zip(s2.iter()).map(|(&c1, &c2)| n_bits[c1 ^ c2]).sum()
}

/*
 * Return list of key sizes sorted by probability
 */
fn guess_keysize(buffer: &[u8]) -> ~[uint] {
    static min_block_size: uint = 2;
    static max_block_size: uint = 50;

    let max = match buffer.len() / 4 {
        block_size if block_size <= min_block_size =>
            // Make sure max block size is greater than min block size
            return ~[],
        block_size if block_size > max_block_size =>
            max_block_size,
        block_size =>
            // We're not trying too hard here
            block_size
    };
    let mut keysizes = vec::with_capacity(max - min_block_size);

    for size in range(min_block_size, max + 1) {
        // Calculate average Hamming distance between four consecutive parts of
        // encrypted text
        let s1 = buffer.slice(0, size);
        let s2 = buffer.slice(size, size * 2);
        let s3 = buffer.slice(size * 2, size * 3);
        let s4 = buffer.slice(size * 3, size * 4);
        let d1 = hamming_distance(s1, s2);
        let d2 = hamming_distance(s2, s3);
        let d3 = hamming_distance(s1, s4);
        let d4 = hamming_distance(s3, s4);
        // Calculate average and normalized value of the distance
        let dist: uint = ((d1 + d2 + d3 + d4) * 1000) / (4 * size);
        keysizes.push((dist, size));
    }
    keysizes.sort();
    keysizes.iter().map(|&(_, s)| s).collect()
}

fn decrypt_with_keysize(encrypted: &[u8], keysize: uint) -> RepeatingKeyResult {
    let len = encrypted.len();
    let line_len = (len / keysize) + 1;
    let mut buffers: ~[~[u8]] = vec::from_fn(keysize,
        |_| vec::with_capacity(line_len));
    for block in encrypted.chunks(keysize) {
        for (i, &c) in block.iter().enumerate() {
            buffers[i].push(c);
        }
    }
    let mut key: ~[u8] = vec::with_capacity(keysize);
    let mut decrypted: ~[u8] = vec::from_elem(len, 0u8);
    for (i, block) in buffers.iter().enumerate() {
        match decrypt(*block) {
            SingleCharKeyFound(k, text) => {
                key.push(k);
                for (j, &c) in text.iter().enumerate() {
                    decrypted[i + j * keysize] = c;
                }
            },
            SingleCharKeyNotFound => return RepeatingKeyNotFound
        }
    }
    RepeatingKeyFound(key, decrypted)
}

fn decrypt_repeating_xor(encrypted: &[u8]) -> RepeatingKeyResult {
    match guess_keysize(encrypted) {
        [] => return RepeatingKeyNotFound,
        keysizes => {
            for &keysize in keysizes.iter() {
                let found = decrypt_with_keysize(encrypted, keysize);
                match found {
                    RepeatingKeyFound(..) => return found,
                    RepeatingKeyNotFound => ()
                }
            }
        }
    }
    RepeatingKeyNotFound
}

#[cfg(not(test))]
fn decrypt_repeating_xor_file(mut file: File) -> RepeatingKeyResult {
    let data = file.read_to_end();
    let encrypted = str::from_utf8(data).from_base64().unwrap();
    decrypt_repeating_xor(encrypted)
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let path = Path::new("buffer.txt");
    let decrypted = match File::open(&path) {
        Some(file) => decrypt_repeating_xor_file(file),
        None => fail!("Unable to open buffer.txt")
    };
    match decrypted {
        RepeatingKeyFound(key, text) => println!(
            "Key       => \"{}\"\n\
             Decrypted => \"{}\"",
            str::from_utf8(key), str::from_utf8(text)),
        RepeatingKeyNotFound => println!("ERROR: No key found")
    }
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use std::str;
    use extra::hex::FromHex;
    use super::{hamming_distance, guess_keysize};
    use super::{decrypt_repeating_xor, RepeatingKeyFound, RepeatingKeyNotFound};

    #[test]
    fn test_hamming_distance() {
        let s1 = ~"this is a test";
        let s2 = ~"wokka wokka!!!";
        assert_eq!(hamming_distance(s1.into_bytes(), s2.into_bytes()), 37);
    }

    #[test]
    fn test_guess_keysize() {
        let buffer1 = ~"123456";
        assert_eq!(guess_keysize(buffer1.into_bytes()), ~[]);

        let buffer2 = ~"1234567890123456789012345678901234567890";
        assert_eq!(guess_keysize(buffer2.into_bytes()),
                   ~[10u, 4u, 6u, 8u, 2u, 9u, 3u, 7u, 5u]);
    }

    #[test]
    fn test_decrypt_repeating_xor() {
        let buffer = ~"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d633\
                       43c2a26226324272765272a282b2f20430a652e2c652a3124333a\
                       653e2b2027630c692b20283165286326302e27282f";
        let binary = buffer.from_hex().unwrap();
        let (key, text) = match decrypt_repeating_xor(binary) {
            RepeatingKeyFound(key, text) => (key, text),
            RepeatingKeyNotFound => fail!("Key not found")
        };
        assert_eq!(str::from_utf8(key), "ICE");
        assert_eq!(str::from_utf8(text),
                   "Burning 'em, if you ain't quick and nimble\n\
                    I go crazy when I hear a cymbal");
    }
}
