/* AES-128 ECB mode decrypter
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use std::path::Path;
use std::io::fs::File;

use serialize::base64::FromBase64;

use aes_lib::decrypt_aes_ecb;

fn decrypt_aes_ecb_file(mut file: File, key: &[u8]) -> Vec<u8> {
    let data = file.read_to_end().unwrap();
    let text = String::from_utf8(data).unwrap();
    let encrypted = text.from_base64().unwrap();
    decrypt_aes_ecb(encrypted.as_slice(), key)
}

/*
 * Main entry point
 */
fn main() {
    let key = b"YELLOW SUBMARINE";
    let path = Path::new("aes_ecb_encrypted.txt");
    let decrypted = match File::open(&path) {
        Ok(file) => decrypt_aes_ecb_file(file, key),
        Err(err) => panic!("Unable to open aes_ecb_encrypted.txt: {}", err)
    };
    println!("Decrypted => \"{}\"", String::from_utf8(decrypted).unwrap());
}
