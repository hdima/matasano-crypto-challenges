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

use libc::{c_int, c_void};

#[cfg(not(test))]
use serialize::base64::FromBase64;

#[allow(non_camel_case_types)]
type EVP_CIPHER_CTX = *const c_void;
#[allow(non_camel_case_types)]
type EVP_CIPHER = *const c_void;

#[link(name="crypto")]
extern {
    fn EVP_CIPHER_CTX_new() -> EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_set_padding(ctx: EVP_CIPHER_CTX, padding: c_int);
    fn EVP_CIPHER_CTX_free(ctx: EVP_CIPHER_CTX);

    fn EVP_aes_128_ecb() -> EVP_CIPHER;

    fn EVP_DecryptInit(ctx: EVP_CIPHER_CTX, evp: EVP_CIPHER,
                       key: *const u8, iv: *const u8);
    fn EVP_DecryptUpdate(ctx: EVP_CIPHER_CTX, outbuf: *mut u8,
                         outlen: &mut c_int, inbuf: *const u8, inlen: c_int);
    fn EVP_DecryptFinal(ctx: EVP_CIPHER_CTX, res: *mut u8, len: &mut c_int);
}

/*
 * Decrypt AES_128 ECB
 */
fn decrypt_aes_ecb(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let blocksize = 16u;
    if key.len() != blocksize {
        fail!("Invalid key length");
    }

    unsafe {
        let iv = [];
        let ctx = EVP_CIPHER_CTX_new();
        let evp = EVP_aes_128_ecb();

        EVP_DecryptInit(ctx, evp, key.as_ptr(), iv.as_ptr());
        EVP_CIPHER_CTX_set_padding(ctx, 0 as c_int);

        let mut bodylen = (encrypted.len() + blocksize) as c_int;
        let mut body = Vec::from_elem(bodylen as uint, 0u8);
        EVP_DecryptUpdate(ctx, body.as_mut_ptr(), &mut bodylen,
                          encrypted.as_ptr(), encrypted.len() as c_int);

        let mut taillen = blocksize as c_int;
        let mut tail = Vec::from_elem(taillen as uint, 0u8);
        EVP_DecryptFinal(ctx, tail.as_mut_ptr(), &mut taillen);
        EVP_CIPHER_CTX_free(ctx);

        body.slice_to(bodylen as uint).into_vec()
            + tail.slice_to(taillen as uint).into_vec()
    }
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
