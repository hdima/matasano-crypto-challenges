/* AES ECB/CBC mode oracle
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate aes_lib;

use std::rand::{random, task_rng, Rng, Rand};
use std::fmt::{Show, Formatter, FormatError};

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ecb, encrypt_aes_cbc};


enum Mode {
    ECB,
    CBC
}

impl Rand for Mode {
    fn rand<R: Rng>(rng: &mut R) -> Mode {
        match rng.gen() {
            true => ECB,
            false => CBC
        }
    }
}

impl Show for Mode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FormatError> {
        match *self {
            ECB => f.pad("ECB"),
            CBC => f.pad("CBC")
        }
    }
}

fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random::<u8>())
}

fn random_uint(low: uint, high: uint) -> uint {
    task_rng().gen_range(low, high)
}

fn aes_encrypt() -> (Vec<u8>, Mode) {
    let key = random_bytes(AES_BLOCK_SIZE);
    let data = random_bytes(AES_BLOCK_SIZE * random_uint(30, 80)
                            + random_uint(0, AES_BLOCK_SIZE));
    match random::<Mode>() {
        ECB => (encrypt_aes_ecb(data.as_slice(), key.as_slice()), ECB),
        CBC => {
            let iv = random_bytes(AES_BLOCK_SIZE);
            (encrypt_aes_cbc(data.as_slice(), key.as_slice(),
                             iv.as_slice()), CBC)
        }
    }
}

fn main() {
    let (encrypted, mode) = aes_encrypt();
    println!("Mode: {}", mode);
}
