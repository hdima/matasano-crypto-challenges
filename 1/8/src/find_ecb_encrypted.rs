/* Find ECB encrypted string
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

use std::collections::HashSet;
#[cfg(not(test))]
use std::path::Path;
#[cfg(not(test))]
use std::io::fs::File;
#[cfg(not(test))]
use std::io::BufferedReader;

#[cfg(not(test))]
use serialize::hex::FromHex;

#[cfg(not(test))]
enum ECBEncryptedLine {
    Found(uint, String),
    NotFound
}

/*
 * Find 128 bit ECB encrypted line in a file
 */
#[cfg(not(test))]
fn find_ecb_encrypted_line(file: File) -> ECBEncryptedLine {
    let mut reader = BufferedReader::new(file);
    for (line_num, result) in reader.lines().enumerate() {
        let line = result.unwrap();
        let bin = line.as_slice().from_hex().unwrap();
        if is_buffer_ecb_encrypted(bin.as_slice()) {
            // Return the first found line.
            return ECBEncryptedLine::Found(line_num + 1, line);
        }
    }
    ECBEncryptedLine::NotFound
}

/*
 * Is buffer ECB encrypted?
 */
#[inline]
fn is_buffer_ecb_encrypted(buffer: &[u8]) -> bool {
    static ECB_BLOCK_SIZE: uint = 16;
    let mut blocks = HashSet::new();
    buffer.chunks(ECB_BLOCK_SIZE).any(|b| !blocks.insert(b))
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let path = Path::new("ciphertexts.txt");
    let result = match File::open(&path) {
        Ok(file) => find_ecb_encrypted_line(file),
        Err(err) => panic!("Unable to open {}: {}", path.display(), err)
    };
    match result {
        ECBEncryptedLine::Found(line_num, text) =>
            println!("Found ECB encrypted text at line {}: {}",
                     line_num, text),
        ECBEncryptedLine::NotFound => println!("No ECB encrypted text found")
    }
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::is_buffer_ecb_encrypted;
    use serialize::hex::FromHex;

    #[test]
    fn test_is_buffer_ecb_encrypted() {
        let buffer = "000102030405060708090a0b0c0d0e0f\
                      101112131415161718191a1b1c1d1e1f\
                      202122232425262728292a2b2c2d2e2f";
        let bin = buffer.as_slice().from_hex().unwrap();
        assert_eq!(is_buffer_ecb_encrypted(bin.as_slice()), false);

        let buffer = "000102030405060708090a0b0c0d0e0f\
                      101112131415161718191a1b1c1d1e1f\
                      000102030405060708090a0b0c0d0e0f";
        let bin = buffer.as_slice().from_hex().unwrap();
        assert_eq!(is_buffer_ecb_encrypted(bin.as_slice()), true);
    }
}
