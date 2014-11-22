/* AES CTR mode
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

extern crate aes_lib;

use serialize::base64::FromBase64;

use aes_lib::{decrypt_aes_ctr, encrypt_aes_ctr};


static ENCODED: &'static str =
    "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";

fn main() {
    let encrypted = ENCODED.from_base64().unwrap();
    let key = b"YELLOW SUBMARINE";
    let nonce = 0u64;
    let dec = decrypt_aes_ctr(encrypted.as_slice(), key, nonce);
    println!("Decrypted: {}", String::from_utf8_lossy(dec.as_slice()));
    let enc = encrypt_aes_ctr(dec.as_slice(), key, nonce);
    assert_eq!(enc, encrypted);
    println!("Successfully encrypted!");
}
