/* Single-character XOR cipher guesser
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate single_char_xor_lib;

use single_char_xor_lib::{decrypt, SingleCharKey};
use serialize::hex::FromHex;

/*
 * Main entry point
 */
fn main() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c\
                 78373e783a393b3736";
    let encrypted = input.from_hex().unwrap();
    println!("Input        => \"{}\"\n\
              Binary input => {:?}",
             input, encrypted);
    match decrypt(encrypted.as_slice()) {
        SingleCharKey::Found(key, decrypted) => {
            println!("Key  => '{}', ({})\n\
                      Text => \"{}\"",
                     key as char, key, String::from_utf8(decrypted).unwrap());
        }
        SingleCharKey::NotFound => panic!("No decryption key found")
    }
}
