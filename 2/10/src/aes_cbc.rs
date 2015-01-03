/* AES-128 CBC mode
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use std::path::Path;
use std::io::fs::File;
use std::iter::repeat;

use serialize::base64::FromBase64;

use aes_lib::{decrypt_aes_cbc, encrypt_aes_cbc};

fn read_hex_file(path: &Path) -> Vec<u8> {
    match File::open(path) {
        Ok(mut file) => {
            let data = file.read_to_end().unwrap();
            let text = String::from_utf8(data).unwrap();
            text.from_base64().unwrap()
        },
        Err(err) => panic!("Unable to open {}: {}", path.display(), err)
    }
}

/*
 * Main entry point
 */
fn main() {
    let path = Path::new("10.txt");
    let data = read_hex_file(&path);
    let key = b"YELLOW SUBMARINE";
    let iv: Vec<u8> = repeat(0u8).take(16).collect();
    let decrypted = decrypt_aes_cbc(data.as_slice(), key.as_slice(),
                                    iv.as_slice());
    println!("Decrypted => \"{}\"",
             String::from_utf8(decrypted.clone()).unwrap());
    assert_eq!(data, encrypt_aes_cbc(decrypted.as_slice(), key.as_slice(),
                                     iv.as_slice()));
    println!("Encryption OK!");
}
