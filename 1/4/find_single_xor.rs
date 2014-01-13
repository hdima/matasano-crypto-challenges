/* Find a string encrypted with single-character XOR cipher
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern mod single_xor_lib;

extern mod extra;

use std::str;
use std::path::Path;
use std::io::fs::File;
use std::io::buffered::BufferedReader;
use extra::hex::FromHex;
use single_xor_lib::{decrypt, Found, NotFound};

/*
 * Find a line encrypted with single-character XOR cipher
 */
fn find_encrypted_line(file: File) {
    let mut reader = BufferedReader::new(file);
    for (n, line) in reader.lines().enumerate() {
        let encrypted = line.from_hex().unwrap();
        match decrypt(encrypted) {
            Found(key, decrypted) => {
                    println!("Found encrypted string at line {}:\n\
                             Key  => '{}' ({})\n\
                             Text => \"{}\"", n + 1, key as char, key,
                             str::from_utf8(decrypted));
                }
            NotFound => ()
        }
    }
}

/*
 * Main entry point
 */
fn main() {
    let path = Path::new("strings.txt");
    match File::open(&path) {
        Some(file) => find_encrypted_line(file),
        None => fail!("Unable to open strings.txt")
    }
}
