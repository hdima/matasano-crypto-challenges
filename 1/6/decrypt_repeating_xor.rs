/* Repeating-key XOR decrypter
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate single_char_xor_lib;

extern crate serialize;

#[cfg(not(test))]
use std::path::Path;
#[cfg(not(test))]
use std::io::fs::File;
#[cfg(not(test))]
use std::str;

use std::iter::AdditiveIterator;

#[cfg(not(test))]
use serialize::base64::FromBase64;

#[cfg(not(test))]
use single_char_xor_lib::{decrypt, SingleCharKeyFound, SingleCharKeyNotFound};

// Result of the decryption
#[cfg(not(test))]
enum RepeatingKeyResult {
    RepeatingKeyFound(Vec<u8>, Vec<u8>),
    RepeatingKeyNotFound
}

/*
 * Calculate Hamming distance between two equal-length buffers.
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
    if s1.len() != s2.len() {
        fail!("Not equal length buffers");
    }
    s1.iter().zip(s2.iter()).map(|(&c1, &c2)| n_bits[(c1 ^ c2) as uint]).sum()
}

/*
 * Return list of key sizes sorted by probability
 */
fn guess_keysize(buffer: &[u8]) -> Vec<uint> {
    static min_block_size: uint = 2;
    static max_block_size: uint = 50;

    let max = match buffer.len() / 2 {
        block_size if block_size <= min_block_size =>
            // Make sure max block size is greater than min block size
            return Vec::new(),
        block_size if block_size > max_block_size =>
            max_block_size,
        block_size =>
            // We're not trying too hard here
            block_size
    };
    let mut keysizes = Vec::with_capacity(max - min_block_size);

    for size in range(min_block_size, max + 1) {
        /* Calculate average Hamming distance between dynamic number of samples
         *
         * It seems for smaller block sizes we need to collect more samples to
         * achieve better results. But see also comments for
         * decrypt_repeating_xor() function.
         */
        let samples: uint = (max * 2) / size - 1;
        let mut dist = 0u;
        for i in range(0, samples) {
            let start = i * size;
            let s1 = buffer.slice(start, start + size);
            let s2 = buffer.slice(start + size, start + size * 2);
            dist += hamming_distance(s1, s2);
        }
        // Average Hamming distance for current block size
        dist = (dist * 1000) / (samples * size);
        keysizes.push((dist, size));
    }
    keysizes.sort();
    keysizes.iter().map(|&(_, s)| s).collect()
}

#[cfg(not(test))]
fn decrypt_with_keysize(encrypted: &[u8], keysize: uint) -> RepeatingKeyResult {
    let len = encrypted.len();
    let line_len = (len / keysize) + 1;
    let mut buffers: Vec<Vec<u8>> = Vec::from_fn(keysize,
        |_| Vec::with_capacity(line_len));
    for block in encrypted.chunks(keysize) {
        for (i, &c) in block.iter().enumerate() {
            buffers.get_mut(i).push(c);
        }
    }
    let mut key: Vec<u8> = Vec::with_capacity(keysize);
    let mut decrypted: Vec<u8> = Vec::from_elem(len, 0u8);
    for (i, block) in buffers.iter().enumerate() {
        match decrypt((*block).as_slice()) {
            SingleCharKeyFound(k, text) => {
                key.push(k);
                for (j, &c) in text.iter().enumerate() {
                    *decrypted.get_mut(i + j * keysize) = c;
                }
            },
            SingleCharKeyNotFound => return RepeatingKeyNotFound
        }
    }
    RepeatingKeyFound(key, decrypted)
}

#[cfg(not(test))]
fn decrypt_repeating_xor(encrypted: &[u8]) -> RepeatingKeyResult {
    let keysizes =  guess_keysize(encrypted);
    if keysizes.len() != 0 {
        /* It seems it's harder to get the correct order of key sizes if
         * length of the real key or length of the text is small. So
         * probably better results can be achieved if we collect multiple
         * number of decrypted texts and then select the correct one based
         * on n-grams model for example.
         */
        for &keysize in keysizes.iter() {
            let found = decrypt_with_keysize(encrypted, keysize);
            match found {
                RepeatingKeyFound(..) => return found,
                RepeatingKeyNotFound => ()
            }
        }
    }
    RepeatingKeyNotFound
}

#[cfg(not(test))]
fn decrypt_repeating_xor_file(mut file: File) -> RepeatingKeyResult {
    let data = file.read_to_end().unwrap();
    let text = str::from_utf8(data.as_slice()).unwrap();
    let encrypted = text.from_base64().unwrap();
    decrypt_repeating_xor(encrypted.as_slice())
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let path = Path::new("buffer.txt");
    let decrypted = match File::open(&path) {
        Ok(file) => decrypt_repeating_xor_file(file),
        Err(err) => fail!("Unable to open {}: {}", path.as_str(), err)
    };
    match decrypted {
        RepeatingKeyFound(key, text) => println!(
            "Key       => \"{}\"\n\
             Decrypted => \"{}\"",
            str::from_utf8(key.as_slice()).unwrap(),
            str::from_utf8(text.as_slice()).unwrap()),
        RepeatingKeyNotFound => println!("ERROR: No key found")
    }
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::{hamming_distance, guess_keysize};

    #[test]
    fn test_hamming_distance() {
        let s1 = "this is a test".to_string();
        let s2 = "wokka wokka!!!".to_string();
        assert_eq!(hamming_distance(s1.into_bytes().as_slice(),
                                    s2.into_bytes().as_slice()), 37);
    }

    #[test]
    fn test_guess_keysize() {
        let buffer1 = "123".to_string();
        assert_eq!(guess_keysize(buffer1.into_bytes().as_slice()).as_slice(),
                   [].as_slice());

        let buffer2 = "1234512345".to_string();
        assert_eq!(guess_keysize(buffer2.into_bytes().as_slice()).as_slice(),
                   [5u, 4u, 2u, 3u].as_slice());
    }
}
