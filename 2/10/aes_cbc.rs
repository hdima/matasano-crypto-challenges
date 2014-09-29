/* AES-128 CBC mode
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
    fn AES_set_encrypt_key(userKey: *const u8, bits: c_int,
                           key: *mut AesKey) -> c_int;
    fn AES_decrypt(input: *const u8, out: *mut u8, key: *const AesKey);
    fn AES_encrypt(input: *const u8, out: *mut u8, key: *const AesKey);

}

/*
 * Initialize AES key structure
 */
#[inline]
fn init_aes_key(key: &[u8], set_key: |*const u8, c_int, *mut AesKey| -> c_int)
        -> AesKey {
    if key.len() != AES_BLOCK_SIZE {
        fail!("Invalid key size");
    }
    let mut aes_key = AesKey{rd_key: [0, ..RD_KEY_SIZE], rounds: 0};
    let bits = 8 * AES_BLOCK_SIZE as c_int;
    let res = set_key(key.as_ptr(), bits, &mut aes_key);
    if res != 0 {
        fail!("Unable to init AES key -> {}", res);
    }
    aes_key
}

/*
 * Initialize AES decryption key
 */
fn init_aes_decrypt_key(key: &[u8]) -> AesKey {
    init_aes_key(key, |user_key, bits, aes_key| unsafe {
        AES_set_decrypt_key(user_key, bits, aes_key)
        })
}

/*
 * Initialize AES encryption key
 */
fn init_aes_encrypt_key(key: &[u8]) -> AesKey {
    init_aes_key(key, |user_key, bits, aes_key| unsafe {
        AES_set_encrypt_key(user_key, bits, aes_key)
        })
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
 * AES CBC decryption
 */
fn decrypt_aes_cbc(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    if iv.len() != AES_BLOCK_SIZE {
        fail!("Invlaid IV size");
    }
    let len = encrypted.len();
    if len % AES_BLOCK_SIZE != 0 {
        fail!("Invalid size of encrypted data");
    }
    let mut result: Vec<u8> = Vec::with_capacity(len);
    if len > 0 {
        let aes_key = init_aes_decrypt_key(key);
        let mut dec = [0u8, ..AES_BLOCK_SIZE];
        encrypted.chunks(AES_BLOCK_SIZE).fold(iv, |prev, block| {
            unsafe {AES_decrypt(block.as_ptr(), dec.as_mut_ptr(), &aes_key)};
            // XOR ECB decripted block with the previous encrypted block
            let dblk = prev.iter().zip(dec.iter()).map(|(&c1, &c2)| c1 ^ c2);
            result.extend(dblk);
            block
        });
    }
    remove_pkcs7_padding(result)
}

/*
 * PKCS-7 padding
 */
fn pkcs7_padding(data: &[u8]) -> Vec<u8> {
    match data.len() % AES_BLOCK_SIZE {
        0 => data.into_vec(),
        size => {
            let pad = AES_BLOCK_SIZE - size;
            data.into_vec() + Vec::from_elem(pad, pad as u8)
        }
    }
}

/*
 * AES CBC encryption
 */
fn encrypt_aes_cbc(orig_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    if iv.len() != AES_BLOCK_SIZE {
        fail!("Invlaid IV size");
    }
    let data = pkcs7_padding(orig_data);
    let len = data.len();
    let mut result: Vec<u8> = Vec::with_capacity(len);
    if len > 0 {
        let aes_key = init_aes_encrypt_key(key);
        let mut enc = [0u8, ..AES_BLOCK_SIZE];
        data.as_slice().chunks(AES_BLOCK_SIZE).fold(iv, |prev, block| {
            // XOR block with the previous encrypted block
            let eblk: Vec<u8> = prev.iter().zip(block.iter()).map(
                                            |(&c1, &c2)| c1 ^ c2).collect();
            unsafe {AES_encrypt(eblk.as_ptr(), enc.as_mut_ptr(), &aes_key)};
            result.extend(enc.iter().map(|c| *c));
            enc
        });
    }
    result
}

#[cfg(not(test))]
fn read_hex_file(path: &Path) -> Vec<u8> {
    match File::open(path) {
        Ok(mut file) => {
            let data = file.read_to_end().unwrap();
            let text = str::from_utf8(data.as_slice()).unwrap();
            text.from_base64().unwrap()
        },
        Err(error) => fail!("Unable to open {}: {}", path.as_str(), error)
    }
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let path = Path::new("10.txt");
    let data = read_hex_file(&path);
    let key = "YELLOW SUBMARINE".into_string().into_bytes();
    let iv = Vec::from_elem(16u, 0u8);
    let decrypted = decrypt_aes_cbc(data.as_slice(), key.as_slice(),
                                    iv.as_slice());
    println!("Decrypted => \"{}\"",
             String::from_utf8_lossy(decrypted.as_slice()));
    assert_eq!(data, encrypt_aes_cbc(decrypted.as_slice(), key.as_slice(),
                                     iv.as_slice()));
    println!("Encryption OK!");
}
