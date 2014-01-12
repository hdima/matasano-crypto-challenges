/* Find ECB encrypted string
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern mod extra;

use std::hashmap::HashSet;
#[cfg(not(test))]
use std::path::Path;
#[cfg(not(test))]
use std::io::fs::File;
#[cfg(not(test))]
use std::io::buffered::BufferedReader;

#[cfg(not(test))]
use extra::hex::FromHex;

#[cfg(not(test))]
enum ECBEncryptedLine {
    Found(uint, ~str),
    NotFound
}

/*
 * Find 128 bit ECB encrypted line in a file
 */
#[cfg(not(test))]
fn find_ecb_encrypted_line(file: File) -> ECBEncryptedLine {

    let mut reader = BufferedReader::new(file);
    for (line_num, line) in reader.lines().enumerate() {
        if is_buffer_ecb_encrypted(line.from_hex().unwrap()) {
            // Return the first found line.
            // Also convert 0-based line number to 1-based
            return Found(line_num + 1, line);
        }
    }
    NotFound
}

/*
 * Is buffer ECB encrypted?
 */
#[inline]
fn is_buffer_ecb_encrypted(buffer: &[u8]) -> bool {
    // 128 bit encryption
    static ecb_block_size: uint = 16;

    let mut blocks = HashSet::new();
    for block in buffer.chunks(ecb_block_size) {
        if !blocks.insert(block) {
            return true;
        }
    }
    false
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let path = Path::new("ciphertexts.txt");
    let result = match File::open(&path) {
        Some(file) => find_ecb_encrypted_line(file),
        None => fail!("Unable to open ciphertexts.txt")
    };
    match result {
        Found(line_num, text) => println!("Found ECB encrypted text at \
                                           line {}: {}", line_num, text),
        NotFound => println("No ECB encrypted text found")
    }
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::is_buffer_ecb_encrypted;
    use extra::hex::FromHex;

    #[test]
    fn test_is_buffer_ecb_encrypted() {
        let buffer = ~"000102030405060708090a0b0c0d0e0f\
                       101112131415161718191a1b1c1d1e1f\
                       202122232425262728292a2b2c2d2e2f";
        assert_eq!(is_buffer_ecb_encrypted(buffer.from_hex().unwrap()), false);

        let buffer = ~"000102030405060708090a0b0c0d0e0f\
                       101112131415161718191a1b1c1d1e1f\
                       000102030405060708090a0b0c0d0e0f";
        assert_eq!(is_buffer_ecb_encrypted(buffer.from_hex().unwrap()), true);
    }
}
