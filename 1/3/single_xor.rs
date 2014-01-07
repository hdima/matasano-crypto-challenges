// Single-character XOR cipher guesser
//
// Dmitry Vasiliev <dima@hlabs.org>
//

extern mod single_xor_lib;

extern mod extra;

use single_xor_lib::{decrypt, Found, NotFound};
use extra::hex::FromHex;

#[cfg(not(test))]
fn main() {
    use std::str;

    let input = ~"1b37373331363f78151b7f2b783431333d78397828372d363c\
                  78373e783a393b3736";
    let encrypted = input.from_hex().unwrap();

    println!("Input      => {}", input);
    println!("Encrypted  => {:?}", encrypted);
    match decrypt(encrypted) {
        Found(key, decrypted) => {
                println!("Key        => {}", key);
                println!("Decrypted  => {}", str::from_utf8(decrypted));
            }
        NotFound => fail!("No decryption key found")
    }
}
