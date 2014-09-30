/* AES-128 ECB mode decrypter
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate libc;
extern crate serialize;

#[cfg(not(test))]
use std::path::Path;
#[cfg(not(test))]
use std::io::fs::File;
#[cfg(not(test))]
use std::str;

use libc::{c_int, c_uint};

#[cfg(not(test))]
use serialize::base64::FromBase64;

static AES_BLOCK_SIZE: uint = 16u;
static RD_KEY_SIZE: uint = 4 * (14 + 1); // 4 * (AEX_MAXNR + 1)

#[repr(C)]
struct AesKey {
    rd_key: [c_uint, ..RD_KEY_SIZE],
    rounds: c_int,
}

#[link(name="crypto")]
extern {
    fn AES_set_decrypt_key(userKey: *const u8, bits: c_int,
                           key: *mut AesKey) -> c_int;
    fn AES_decrypt(input: *const u8, out: *mut u8, key: *const AesKey);

}

/*
 * Initialize AES key structure
 */
fn init_aes_key(key: &[u8]) -> AesKey {
    if key.len() != AES_BLOCK_SIZE {
        fail!("Invalid key size");
    }
    let mut aes_key = AesKey{rd_key: [0, ..RD_KEY_SIZE], rounds: 0};
    let bits = 8 * AES_BLOCK_SIZE as c_int;
    let res = unsafe {AES_set_decrypt_key(key.as_ptr(), bits, &mut aes_key)};
    if res != 0 {
        fail!("Unable to init AES key. AES_set_decrypt_key() -> {}", res);
    }
    aes_key
}

/*
 * Remove PKCS-7 padding
 */
fn remove_pkcs7_padding(mut data: Vec<u8>) -> Vec<u8> {
    let len = data.len();
    match data.last() {
        Some(&c) if (c as uint) < AES_BLOCK_SIZE =>
            data.truncate(len - c as uint),
        _ => ()
    }
    data
}

/*
 * Decrypt AES-128 ECB
 */
fn decrypt_aes_ecb(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let aes_key = init_aes_key(key);
    let mut data = encrypted.to_vec();
    for block in data.as_mut_slice().chunks_mut(AES_BLOCK_SIZE) {
        // Decrypt in-place
        unsafe {AES_decrypt(block.as_ptr(), block.as_mut_ptr(), &aes_key)};
    }
    remove_pkcs7_padding(data)
}

#[cfg(not(test))]
fn decrypt_aes_ecb_file(mut file: File, key_str: &str) -> Vec<u8> {
    let key = key_str.into_string().into_bytes();
    let data = file.read_to_end().unwrap();
    let text = str::from_utf8(data.as_slice()).unwrap();
    let encrypted = text.from_base64().unwrap();
    decrypt_aes_ecb(encrypted.as_slice(), key.as_slice())
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let key = "YELLOW SUBMARINE";
    let path = Path::new("aes_ecb_encrypted.txt");
    let decrypted = match File::open(&path) {
        Ok(file) => decrypt_aes_ecb_file(file, key),
        Err(err) => fail!("Unable to open aes_ecb_encrypted.txt: {}", err)
    };
    println!("Decrypted => \"{}\"",
             str::from_utf8(decrypted.as_slice()).unwrap());
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use serialize::hex::FromHex;
    use super::decrypt_aes_ecb;

    #[test]
    fn test_aes_ecb_decrypt() {
        let key = "00000000000000000000000000000000".from_hex().unwrap();
        let ciphertext = "0336763e966d92595a567cc9ce537f5e".from_hex().unwrap();
        assert_eq!(decrypt_aes_ecb(ciphertext.as_slice(), key.as_slice()),
            "f34481ec3cc627bacd5dc3fb08f273e6".from_hex().unwrap());

        let key2 = "10a58869d74be5a374cf867cfb473859".from_hex().unwrap();
        let ciphertext2 = "6d251e6944b051e04eaa6fb4dbf78465".from_hex().unwrap();
        assert_eq!(decrypt_aes_ecb(ciphertext2.as_slice(), key2.as_slice()),
            "00000000000000000000000000000000".from_hex().unwrap());

        let key3 = "80000000000000000000000000000000".from_hex().unwrap();
        let ciphertext3 = "0edd33d3c621e546455bd8ba1418bec8".from_hex().unwrap();
        assert_eq!(decrypt_aes_ecb(ciphertext3.as_slice(), key3.as_slice()),
            "00000000000000000000000000000000".from_hex().unwrap());

        let key4 = "00000000000000000000000000000000".from_hex().unwrap();
        let ciphertext4 = "3ad78e726c1ec02b7ebfe92b23d9ec34".from_hex().unwrap();
        assert_eq!(decrypt_aes_ecb(ciphertext4.as_slice(), key4.as_slice()),
            "80000000000000000000000000000000".from_hex().unwrap());

    }
}
