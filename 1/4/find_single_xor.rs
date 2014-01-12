/* Find a string encrypted with single-character XOR cipher
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern mod single_xor_lib;

extern mod extra;

use std::path::Path;
use std::io::fs::File;
use std::io::buffered::BufferedReader;
use extra::hex::FromHex;
use single_xor_lib::{decrypt, Found, NotFound};

fn find_encrypted(file: File) {
    use std::str;

    let mut reader = BufferedReader::new(file);
    for line in reader.lines() {
        let encrypted = line.from_hex().unwrap();
        match decrypt(encrypted) {
            Found(key, decrypted) => {
                    println!("Key        => {}", key);
                    println!("Decrypted  => {}", str::from_utf8(decrypted));
                    //println!("Decrypted  => {:?}", decrypted);
                }
            NotFound => ()
        }
    }
}

#[cfg(not(test))]
fn main() {
    let path = Path::new("strings.txt");
    match File::open(&path) {
        Some(file) => find_encrypted(file),
        None => fail!("Unable to open strings.txt")
    }
}
