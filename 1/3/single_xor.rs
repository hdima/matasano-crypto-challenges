/* Single-character XOR cipher guesser
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern mod single_xor_lib;

extern mod extra;

use std::str;

use single_xor_lib::{decrypt, Found, NotFound};
use extra::hex::FromHex;

/*
 * Main entry point
 */
fn main() {
    let input = ~"1b37373331363f78151b7f2b783431333d78397828372d363c\
                  78373e783a393b3736";
    let encrypted = input.from_hex().unwrap();

    println!("Input        => \"{}\"\n\
              Binary input => {:?}\n",
             input, encrypted);
    match decrypt(encrypted) {
        Found(key, decrypted) => {
                println!("Key  => '{}', ({})\n\
                          Text => \"{}\"",
                         key as char, key, str::from_utf8(decrypted));
            }
        NotFound => fail!("No decryption key found")
    }
}
