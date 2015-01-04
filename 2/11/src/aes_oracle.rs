/* AES ECB/CBC mode oracle
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate aes_lib;

use std::rand::{random, thread_rng, Rng, Rand};
use std::fmt;
use std::fmt::{Show, Formatter};
use std::collections::HashSet;
use std::io::File;

use aes_lib::{AES_BLOCK_SIZE, encrypt_aes_ecb, encrypt_aes_cbc};

#[derive(PartialEq, Eq)]
enum Mode {
    ECB,
    CBC
}

impl Rand for Mode {
    fn rand<R: Rng>(rng: &mut R) -> Mode {
        match rng.gen() {
            true => Mode::ECB,
            false => Mode::CBC
        }
    }
}

impl Show for Mode {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match *self {
            Mode::ECB => write!(f, "ECB"),
            Mode::CBC => write!(f, "CBC"),
        }
    }
}

#[inline]
fn random_bytes(len: uint) -> Vec<u8> {
    range(0, len).map(|_| random::<u8>()).collect()
}

#[inline]
fn random_uint(low: uint, high: uint) -> uint {
    thread_rng().gen_range(low, high)
}

fn aes_oracle(input: &[u8]) -> (Vec<u8>, Mode) {
    let key = random_bytes(AES_BLOCK_SIZE);
    let prepend = random_bytes(random_uint(5, 10));
    let append = random_bytes(random_uint(5, 10));
    let data = prepend + input + append.as_slice();
    match random::<Mode>() {
        Mode::ECB =>
            (encrypt_aes_ecb(data.as_slice(), key.as_slice()), Mode::ECB),
        Mode::CBC => {
            let iv = random_bytes(AES_BLOCK_SIZE);
            (encrypt_aes_cbc(data.as_slice(), key.as_slice(),
                             iv.as_slice()), Mode::CBC)
        }
    }
}

fn guess_aes_mode(buffer: &[u8]) -> Mode {
    let mut blocks = HashSet::new();
    match buffer.chunks(AES_BLOCK_SIZE).any(|b| !blocks.insert(b)) {
        true => Mode::ECB,
        false => Mode::CBC
    }
}

fn read_example_text() -> Vec<u8> {
    File::open(&Path::new("text.txt")).read_to_end().unwrap()
}

fn main() {
    let data = read_example_text();
    let (encrypted, mode) = aes_oracle(data.as_slice());
    print!("Mode: {} - ", mode);
    if guess_aes_mode(encrypted.as_slice()) == mode {
        println!("Matched");
    } else {
        println!("Not matched");
    }
}
