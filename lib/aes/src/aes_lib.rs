/* AES-128 ECB/CBC/CTR library
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

#![crate_name="aes_lib"]
#![crate_type="lib"]

extern crate libc;
extern crate serialize;

use std::iter::repeat;
use libc::{c_int, c_uint};


pub static AES_BLOCK_SIZE: usize = 16;

#[repr(C)]
struct AesKey {
    // 4 * (AES_MAXNR + 1)
    rd_key: [c_uint; 4 * (14 + 1)],
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
 * AES ECB decryption
 */
pub fn decrypt_aes_ecb(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let mut data = encrypted.to_vec();
    if !data.is_empty() {
        let aes_key = init_aes_decrypt_key(key);
        for block in data.as_mut_slice().chunks_mut(AES_BLOCK_SIZE) {
            // Decrypt in-place
            unsafe {AES_decrypt(block.as_ptr(), block.as_mut_ptr(), &aes_key)};
        }
    }
    remove_pkcs7_padding(data)
}

/*
 * AES ECB encryption
 */
pub fn encrypt_aes_ecb(orig_data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut data = pkcs7_padding(orig_data);
    if !data.is_empty() {
        let aes_key = init_aes_encrypt_key(key);
        for block in data.as_mut_slice().chunks_mut(AES_BLOCK_SIZE) {
            // Encrypt in-place
            unsafe {AES_encrypt(block.as_ptr(), block.as_mut_ptr(), &aes_key)};
        }
    }
    data
}

/*
 * AES CBC decryption
 */
pub fn decrypt_aes_cbc(encrypted: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    remove_pkcs7_padding(decrypt_aes_cbc_raw(encrypted, key, iv))
}

/*
 * AES CBC decryption without PKCS#7 padding removal
 */
pub fn decrypt_aes_cbc_raw(encrypted: &[u8], key: &[u8], iv: &[u8])
        -> Vec<u8> {
    if iv.len() != AES_BLOCK_SIZE {
        panic!("Invalid IV size");
    }
    if encrypted.len() % AES_BLOCK_SIZE != 0 {
        panic!("Invalid size of encrypted data");
    }
    let mut data = encrypted.to_vec();
    if !data.is_empty() {
        let aes_key = init_aes_decrypt_key(key);
        let chunks = data.as_mut_slice().chunks_mut(AES_BLOCK_SIZE);
        let combined_chunks = encrypted.chunks(AES_BLOCK_SIZE).zip(chunks);
        combined_chunks.fold(iv, |prev, (enc_block, block)| {
            // Decrypt in-place
            unsafe {AES_decrypt(block.as_ptr(), block.as_mut_ptr(), &aes_key)};
            // XOR decrypted block with the previous encrypted block in-place
            for (&c1, c2) in prev.iter().zip(block.iter_mut()) {
                *c2 ^= c1
            }
            enc_block
        });
    }
    data
}

/*
 * AES CBC encryption
 */
pub fn encrypt_aes_cbc(orig_data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    if iv.len() != AES_BLOCK_SIZE {
        panic!("Invalid IV size");
    }
    let mut data = pkcs7_padding(orig_data);
    if !data.is_empty() {
        let aes_key = init_aes_encrypt_key(key);
        let chunks = data.as_mut_slice().chunks_mut(AES_BLOCK_SIZE);
        chunks.fold(iv, |prev, block| {
            // XOR block with the previous encrypted block in-place
            for (&c1, c2) in prev.iter().zip(block.iter_mut()) {
                *c2 ^= c1
            }
            // Encrypt in-place
            unsafe {AES_encrypt(block.as_ptr(), block.as_mut_ptr(), &aes_key)};
            block
        });
    }
    data
}

/*
 * AES CTR encryption
 */
pub fn encrypt_aes_ctr(orig_data: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    // Encryption is the same as decryption
    decrypt_aes_ctr(orig_data, key, nonce)
}

/*
 * AES CTR decryption
 */
pub fn decrypt_aes_ctr(encrypted: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    let mut data = encrypted.to_vec();
    if !data.is_empty() {
        let aes_key = init_aes_encrypt_key(key);
        let nonce_str = u64_to_vec(nonce);
        let blocks = data.as_mut_slice().chunks_mut(AES_BLOCK_SIZE);
        for (i, block) in blocks.enumerate() {
            let mut input = nonce_str.clone() + u64_to_vec(i as u64).as_slice();
            // Encrypt in-place
            unsafe {AES_encrypt(input.as_ptr(), input.as_mut_ptr(), &aes_key)};
            // XOR encrypted nonce/counter with the encrypted block in-place
            for (&c1, c2) in input.iter().zip(block.iter_mut()) {
                *c2 ^= c1
            }
        }
    }
    data
}

#[inline]
fn u64_to_vec(value: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8);
    match buf.write_le_u64(value) {
        Ok(()) => buf,
        Err(err) => panic!("Memory write error: {}", err)
    }
}

/*
 * Initialize AES key structure
 */
#[inline]
fn init_aes_key<Set: Fn(*const u8, c_int, *mut AesKey) -> c_int>(
        key: &[u8], set_key: Set) -> AesKey {
    if key.len() != AES_BLOCK_SIZE {
        panic!("Invalid key size");
    }
    // 4 * (AES_MAXNR + 1)
    let mut aes_key = AesKey{rd_key: [0; 4 * (14 + 1)], rounds: 0};
    let bits = 8 * AES_BLOCK_SIZE as c_int;
    match set_key(key.as_ptr(), bits, &mut aes_key) {
        0 => aes_key,
        err => panic!("Unable to init AES key -> {}", err)
    }
}

/*
 * Initialize AES decryption key
 */
#[inline]
fn init_aes_decrypt_key(key: &[u8]) -> AesKey {
    init_aes_key(key, |user_key, bits, aes_key| unsafe {
        AES_set_decrypt_key(user_key, bits, aes_key)
        })
}

/*
 * Initialize AES encryption key
 */
#[inline]
fn init_aes_encrypt_key(key: &[u8]) -> AesKey {
    init_aes_key(key, |user_key, bits, aes_key| unsafe {
        AES_set_encrypt_key(user_key, bits, aes_key)
        })
}

/*
 * Remove PKCS-7 padding
 */
#[inline]
pub fn remove_pkcs7_padding(mut data: Vec<u8>) -> Vec<u8> {
    match data.last() {
        Some(&last) if last > 0 && (last as usize) < AES_BLOCK_SIZE => {
            let data_len = data.len() - last as usize;
            if data.slice_from(data_len).iter().all(|&c| c == last) {
                data.truncate(data_len);
            }
            data
        }
        _ => data
    }
}

/*
 * PKCS-7 padding
 */
#[inline]
fn pkcs7_padding(data: &[u8]) -> Vec<u8> {
    let mut r = data.to_vec();
    match data.len() % AES_BLOCK_SIZE {
        0 => r,
        size => {
            let pad = AES_BLOCK_SIZE - size;
            r.extend(repeat(pad as u8).take(pad));
            r
        }
    }
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use serialize::hex::FromHex;
    use super::{encrypt_aes_ecb, decrypt_aes_ecb};
    use super::{encrypt_aes_cbc, decrypt_aes_cbc};
    use super::{encrypt_aes_ctr, decrypt_aes_ctr};

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

    #[test]
    fn test_aes_ecb() {
        let key = b"1234567890123456";
        let data = b"test test test test test test test test test";
        let encrypted = encrypt_aes_ecb(data, key);
        assert_eq!(data,
                   decrypt_aes_ecb(encrypted.as_slice(), key).as_slice());
    }

    #[test]
    fn test_aes_cbc() {
        let key = b"1234567890123456";
        let iv = b"6543210987654321";
        let data = b"test test test test test test test test test";
        let encrypted = encrypt_aes_cbc(data, key, iv);
        assert_eq!(data,
                   decrypt_aes_cbc(encrypted.as_slice(), key, iv).as_slice());
    }

    #[test]
    fn test_aes_ctr() {
        let key = b"1234567890123456";
        let nonce = 12345u64;
        let data = b"test test test test test test test test test";
        let encrypted = encrypt_aes_ctr(data, key, nonce);
        assert_eq!(data, decrypt_aes_ctr(encrypted.as_slice(),
                                         key, nonce).as_slice());
    }
}
