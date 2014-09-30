/* AES ECB/CBC mode oracle
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate aes_lib;

use std::rand;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ecb, encrypt_aes_cbc};


fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| rand::random::<u8>())
}

fn random_uint(low: uint, high: uint) -> uint {
    // FIXME: Why rand::task_rng().gen_range::<uint>(low, high) doesn't work?
    (rand::random::<uint>() % (high - low)) + low
}

fn random_bool() -> bool {
    rand::random::<bool>()
}

fn aes_encrypt() -> (Vec<u8>, bool) {
    let key = random_bytes(AES_BLOCK_SIZE);
    let data = random_bytes(AES_BLOCK_SIZE * random_uint(20, 60)
                            + random_uint(0, AES_BLOCK_SIZE));
    let use_ecb = random_bool();
    let encrypted = if use_ecb {
        encrypt_aes_ecb(data.as_slice(), key.as_slice())
    } else {
        let iv = random_bytes(AES_BLOCK_SIZE);
        encrypt_aes_cbc(data.as_slice(), key.as_slice(), iv.as_slice())
    };
    (encrypted, use_ecb)
}

fn main() {
    let (encrypted, use_ecb) = aes_encrypt();
    let mode = if use_ecb {"ECB"} else {"CBC"};
    println!("Mode: {} Enc: {}", mode, encrypted);
}
