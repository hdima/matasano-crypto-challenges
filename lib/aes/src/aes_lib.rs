/* AES-128 ECB/CBC library
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

#![crate_name="aes_lib"]
#![crate_type="lib"]

extern crate libc;

use libc::{c_int, c_uint};


pub static AES_BLOCK_SIZE: uint = 16u;

#[repr(C)]
struct AesKey {
    // 4 * (AES_MAXNR + 1)
    rd_key: [c_uint, ..(4 * (14 + 1))],
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
    if data.len() > 0 {
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
    if data.len() > 0 {
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
    let len = encrypted.len();
    if len % AES_BLOCK_SIZE != 0 {
        panic!("Invalid size of encrypted data");
    }
    let mut data = encrypted.to_vec();
    if len > 0 {
        let aes_key = init_aes_decrypt_key(key);
        let chunks = data.as_mut_slice().chunks_mut(AES_BLOCK_SIZE);
        let mut combined_chunks = encrypted.chunks(AES_BLOCK_SIZE).zip(chunks);
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
    if data.len() > 0 {
        let aes_key = init_aes_encrypt_key(key);
        let mut chunks = data.as_mut_slice().chunks_mut(AES_BLOCK_SIZE);
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
 * Initialize AES key structure
 */
#[inline]
fn init_aes_key(key: &[u8], set_key: |*const u8, c_int, *mut AesKey| -> c_int)
        -> AesKey {
    if key.len() != AES_BLOCK_SIZE {
        panic!("Invalid key size");
    }
    // 4 * (AES_MAXNR + 1)
    let mut aes_key = AesKey{rd_key: [0, ..(4 * (14 + 1))], rounds: 0};
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
fn remove_pkcs7_padding(mut data: Vec<u8>) -> Vec<u8> {
    match data.last() {
        Some(&last) if last > 0 && (last as uint) < AES_BLOCK_SIZE => {
            let data_len = data.len() - last as uint;
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
    match data.len() % AES_BLOCK_SIZE {
        0 => data.to_vec(),
        size => {
            let pad = AES_BLOCK_SIZE - size;
            data.to_vec() + Vec::from_elem(pad, pad as u8)
        }
    }
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::{encrypt_aes_ecb, decrypt_aes_ecb};
    use super::{encrypt_aes_cbc, decrypt_aes_cbc};

    #[test]
    fn test_aes_ecb() {
        let key = "1234567890123456".into_string().into_bytes();
        let data = "Test data".into_string().into_bytes();
        let encrypted = encrypt_aes_ecb(data.as_slice(), key.as_slice());
        assert_eq!(data.as_slice(),
                   decrypt_aes_ecb(encrypted.as_slice(),
                                   key.as_slice()).as_slice());
    }

    #[test]
    fn test_aes_cbc() {
        let key = "1234567890123456".into_string().into_bytes();
        let iv = "6543210987654321".into_string().into_bytes();
        let data = "Test data".into_string().into_bytes();
        let encrypted = encrypt_aes_cbc(data.as_slice(), key.as_slice(),
                                        iv.as_slice());
        assert_eq!(data.as_slice(),
                   decrypt_aes_cbc(encrypted.as_slice(),
                                   key.as_slice(), iv.as_slice()).as_slice());
    }
}
