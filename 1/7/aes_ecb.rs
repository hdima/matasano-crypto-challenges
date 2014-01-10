// AES-128 ECB mode decrypter
//
// Dmitry Vasiliev <dima@hlabs.org>
//

extern mod extra;

// TODO: Do we have a garbage at the end of the decrypted text?
// TODO: Refactor decryption as a type

use std::path::Path;
use std::io::fs::File;
use std::str;

use std::libc::{c_int, c_uint};
use std::libc;
use std::vec;

use extra::base64::FromBase64;

#[allow(non_camel_case_types)]
pub type EVP_CIPHER_CTX = *libc::c_void;

#[allow(non_camel_case_types)]
pub type EVP_CIPHER = *libc::c_void;

#[link(name = "crypto")]
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

fn aes_ecb_decrypt(mut file: File, key_str: &str) -> ~[u8] {
    let keylen = 16u;
    if key_str.len() != keylen {
        fail!("Invalid key length");
    }
    let key = key_str.into_owned().into_bytes();
    let data = file.read_to_end();
    let encrypted = str::from_utf8(data).from_base64().unwrap();

    let iv = [];
    let blocksize = 16u;

    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        let evp = EVP_aes_128_ecb();

        EVP_CipherInit(ctx, evp, key.as_ptr(), iv.as_ptr(), 0 as c_int);
        EVP_CIPHER_CTX_set_padding(ctx, 0 as c_int);

        let mut reslen = (encrypted.len() + blocksize) as u32;
        let mut res = vec::from_elem(encrypted.len() + blocksize, 0u8);
        EVP_CipherUpdate(ctx, res.as_mut_ptr(), &mut reslen,
            encrypted.as_ptr(), encrypted.len() as c_int);
        res.truncate(reslen as uint);

        let mut reslen2 = blocksize as c_int;
        let mut res2 = vec::from_elem(blocksize, 0u8);
        EVP_CipherFinal(ctx, res2.as_mut_ptr(), &mut reslen2);
        EVP_CIPHER_CTX_free(ctx);
        res2.truncate(reslen2 as uint);
        res + res2
    }
}

#[cfg(not(test))]
fn main() {
    let key = ~"YELLOW SUBMARINE";
    let path = Path::new("aes_ecb_encrypted.txt");
    let decrypted = match File::open(&path) {
        Some(file) => aes_ecb_decrypt(file, key),
        None => fail!("Unable to open aes_ecb_encrypted.txt")
    };
    println!("Decrypted => {}", str::from_utf8(decrypted));
}
