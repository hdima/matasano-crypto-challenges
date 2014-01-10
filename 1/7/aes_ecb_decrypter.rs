// AES-128 ECB mode decrypter
//
// Dmitry Vasiliev <dima@hlabs.org>
//

extern mod extra;

// TODO: Do we have a garbage at the end of the decrypted text?
// TODO: Refactor decryption as a type

#[cfg(not(test))]
use std::path::Path;
#[cfg(not(test))]
use std::io::fs::File;
#[cfg(not(test))]
use std::str;

use std::libc::{c_int, c_uint};
use std::libc;
use std::vec;

#[cfg(not(test))]
use extra::base64::FromBase64;

#[allow(non_camel_case_types)]
pub type EVP_CIPHER_CTX = *libc::c_void;

#[allow(non_camel_case_types)]
pub type EVP_CIPHER = *libc::c_void;

#[link(name="crypto")]
extern {
    fn EVP_CIPHER_CTX_new() -> EVP_CIPHER_CTX;
    fn EVP_CIPHER_CTX_set_padding(ctx: EVP_CIPHER_CTX, padding: c_int);
    fn EVP_CIPHER_CTX_free(ctx: EVP_CIPHER_CTX);

    fn EVP_aes_128_ecb() -> EVP_CIPHER;

    fn EVP_CipherInit(ctx: EVP_CIPHER_CTX, evp: EVP_CIPHER,
                      key: *u8, iv: *u8, mode: c_int);
    fn EVP_CipherUpdate(ctx: EVP_CIPHER_CTX, outbuf: *mut u8,
                        outlen: &mut c_uint, inbuf: *u8, inlen: c_int);
    fn EVP_CipherFinal(ctx: EVP_CIPHER_CTX, res: *mut u8, len: &mut c_int);
}

fn decrypt_aes_ecb(encrypted: &[u8], key: &[u8]) -> ~[u8] {
    if key.len() != 16u {
        fail!("Invalid key length");
    }

    let iv = [];
    let blocksize = 16u;

    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        let evp = EVP_aes_128_ecb();

        EVP_CipherInit(ctx, evp, key.as_ptr(), iv.as_ptr(), 0 as c_int);
        EVP_CIPHER_CTX_set_padding(ctx, 0 as c_int);

        let mut reslen = (encrypted.len() + blocksize) as u32;
        let mut res = vec::from_elem(reslen as uint, 0u8);
        EVP_CipherUpdate(ctx, res.as_mut_ptr(), &mut reslen,
            encrypted.as_ptr(), encrypted.len() as c_int);
        res.truncate(reslen as uint);

        let mut reslen2 = blocksize as c_int;
        let mut res2 = vec::from_elem(blocksize as uint, 0u8);
        EVP_CipherFinal(ctx, res2.as_mut_ptr(), &mut reslen2);
        EVP_CIPHER_CTX_free(ctx);
        res2.truncate(reslen2 as uint);
        res + res2
    }
}

#[cfg(not(test))]
fn decrypt_aes_ecb_file(mut file: File, key_str: &str) -> ~[u8] {
    let key = key_str.into_owned().into_bytes();
    let data = file.read_to_end();
    let encrypted = str::from_utf8(data).from_base64().unwrap();
    decrypt_aes_ecb(encrypted, key)
}

#[cfg(not(test))]
fn main() {
    let key = ~"YELLOW SUBMARINE";
    let path = Path::new("aes_ecb_encrypted.txt");
    let decrypted = match File::open(&path) {
        Some(file) => decrypt_aes_ecb_file(file, key),
        None => fail!("Unable to open aes_ecb_encrypted.txt")
    };
    println!("Decrypted => {}", str::from_utf8(decrypted));
}

#[test]
fn test_aes_ecb_decrypt() {
    use extra::hex::FromHex;

    let key = "00000000000000000000000000000000".from_hex().unwrap();
    let ciphertext = "0336763e966d92595a567cc9ce537f5e".from_hex().unwrap();
    assert_eq!(decrypt_aes_ecb(ciphertext, key),
        "f34481ec3cc627bacd5dc3fb08f273e6".from_hex().unwrap());

    let key2 = "10a58869d74be5a374cf867cfb473859".from_hex().unwrap();
    let ciphertext2 = "6d251e6944b051e04eaa6fb4dbf78465".from_hex().unwrap();
    assert_eq!(decrypt_aes_ecb(ciphertext2, key2),
        "00000000000000000000000000000000".from_hex().unwrap());

    let key3 = "80000000000000000000000000000000".from_hex().unwrap();
    let ciphertext3 = "0edd33d3c621e546455bd8ba1418bec8".from_hex().unwrap();
    assert_eq!(decrypt_aes_ecb(ciphertext3, key3),
        "00000000000000000000000000000000".from_hex().unwrap());

    let key4 = "00000000000000000000000000000000".from_hex().unwrap();
    let ciphertext4 = "3ad78e726c1ec02b7ebfe92b23d9ec34".from_hex().unwrap();
    assert_eq!(decrypt_aes_ecb(ciphertext4, key4),
        "80000000000000000000000000000000".from_hex().unwrap());

}
