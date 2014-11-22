/* Find a string encrypted with single-character XOR cipher
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate single_char_xor_lib;

use std::path::Path;
use std::io::fs::File;
use std::io::BufferedReader;
use serialize::hex::FromHex;
use single_char_xor_lib::{decrypt, SingleCharKey};

/*
 * Find a line encrypted with single-character XOR cipher
 */
fn find_encrypted_line(file: File) {
    let mut reader = BufferedReader::new(file);
    for (n, line) in reader.lines().enumerate() {
        let encrypted = line.unwrap().from_hex().unwrap();
        match decrypt(encrypted.as_slice()) {
            SingleCharKey::Found(key, decrypted) => {
                println!("Found encrypted string at line {}:\n\
                         Key  => '{}' ({})\n\
                         Text => \"{}\"", n + 1, key as char, key,
                         String::from_utf8(decrypted).unwrap());
            }
            SingleCharKey::NotFound => ()
        }
    }
}

/*
 * Main entry point
 */
fn main() {
    let path = Path::new("strings.txt");
    match File::open(&path) {
        Ok(file) => find_encrypted_line(file),
        Err(err) => panic!("Unable to open strings.txt: {}", err)
    }
}
