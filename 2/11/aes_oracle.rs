/* AES ECB/CBC mode oracle
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate aes_lib;

use std::rand::{random, task_rng, Rng, Rand};
use std::fmt::{Show, Formatter, FormatError};
use std::collections::HashSet;
use std::io::File;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ecb, encrypt_aes_cbc};

#[deriving(PartialEq, Eq)]
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
            ECB => write!(f, "ECB"),
            CBC => write!(f, "CBC"),
        }
    }
}

#[inline]
fn random_byte() -> u8 {
    random::<u8>()
}

#[inline]
fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random_byte())
}

#[inline]
fn random_uint(low: uint, high: uint) -> uint {
    task_rng().gen_range(low, high)
}

fn aes_oracle(input: &[u8]) -> (Vec<u8>, Mode) {
    let key = random_bytes(AES_BLOCK_SIZE);
    let prepend = random_uint(5, 10);
    let append = random_uint(5, 10);
    let mut data = input.to_vec();
    data.reserve_additional(prepend + append);
    for _ in range(0, prepend) {
        data.insert(0, random_byte());
    }
    data.grow_fn(append, |_| random_byte());
    match random::<Mode>() {
        ECB => (encrypt_aes_ecb(data.as_slice(), key.as_slice()), ECB),
        CBC => {
            let iv = random_bytes(AES_BLOCK_SIZE);
            (encrypt_aes_cbc(data.as_slice(), key.as_slice(),
                             iv.as_slice()), CBC)
        }
    }
}

fn guess_aes_mode(buffer: &[u8]) -> Mode {
    let mut blocks = HashSet::new();
    for block in buffer.chunks(AES_BLOCK_SIZE) {
        if !blocks.insert(block) {
            return ECB;
        }
    }
    CBC
}

fn read_example_text() -> Vec<u8> {
    File::open(&Path::new("text.txt")).read_to_end().unwrap()
}

fn main() {
    let data = read_example_text();
    let (encrypted, mode) = aes_oracle(data.as_slice());
    print!("Mode: {} - ", mode);
    match guess_aes_mode(encrypted.as_slice()) {
        m if m == mode => println!("Matched"),
        _ => println!("Not matched")
    }
}
