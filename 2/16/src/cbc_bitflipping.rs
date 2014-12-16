/* AES CBC bitflipping attack
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate aes_lib;

use std::rand::random;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_cbc, decrypt_aes_cbc};

struct State {
    key: Vec<u8>,
    iv: Vec<u8>,
}

impl State {
    fn new() -> State {
        let key = random_bytes(AES_BLOCK_SIZE);
        let iv = random_bytes(AES_BLOCK_SIZE);
        State{key: key, iv: iv}
    }

    fn encrypt(&self, data: &str) -> Vec<u8> {
        let quoted = data.replace(";", "%3B").replace("=", "%3D");
        let prepend = "comment1=cooking%20MCs;userdata=";
        let append = ";comment2=%20like%20a%20pound%20of%20bacon";
        let to_enc = prepend.into_string() + quoted.as_slice() + append;
        encrypt_aes_cbc(to_enc.into_bytes().as_slice(), self.key.as_slice(),
                        self.iv.as_slice())
    }

    fn decrypt(&self, encrypted: &[u8]) -> Vec<u8> {
        decrypt_aes_cbc(encrypted, self.key.as_slice(), self.iv.as_slice())
    }

    fn is_admin(&self, dec: &[u8]) -> bool {
        let s = String::from_utf8_lossy(dec);
        s.as_slice().contains(";admin=true;")
    }
}

fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random::<u8>())
}

fn add_admin(state: &State) -> Vec<u8> {
    let mut enc = state.encrypt("1234567890123456?admin?true");
    // Replace first '?' (0x3f) with ';' (0x3b)
    enc[32] ^= 4;
    // Replace second '?' (0x3f) with '=' (0x3d)
    enc[38] ^= 2;
    enc
}

fn main() {
    let state = State::new();
    let enc = add_admin(&state);
    let dec = state.decrypt(enc.as_slice());
    println!("Decrypted: {}", String::from_utf8_lossy(dec.as_slice()));
    println!("Is admin? {}", state.is_admin(dec.as_slice()));
}
