// Single-character XOR cipher guesser library
//
// Dmitry Vasiliev <dima@hlabs.org>
//

// TODO:
//  - Tests
//  - Can we use letters frequency in is_english() function? Or just
//    implement trigram algorithm?

#[crate_id="single_xor_lib#0.1"];
#[crate_type="lib"];

use std::vec;

static ENGLISH_CHARS_BY_FREQ: &'static[u8] = bytes!(
    " eEtTaAiInNoOsSrRlLdDhHcCuUmMfFpPyYgGwWvVbBkKxXjJqQzZ");

pub enum DecryptionResult {
    Found(u8, ~[u8]),
    NotFound
}

struct ByteStat {
    byte: u8,
    num: uint
}

// XOR buffer with the key and return the result
fn xor_by_key(buffer: &[u8], key: u8) -> ~[u8] {
    buffer.iter().map(|c| c ^ key).collect()
}

// Return most frequent character from the buffer
fn get_most_freq_char(buffer: &[u8]) -> u8 {
    if buffer.is_empty() {
        fail!("Buffer is empty");
    }
    let mut chars = vec::from_fn(256, |i| ByteStat{byte: i as u8, num: 0});
    for &c in buffer.iter() {
        chars[c].num += 1;
    }
    // Reverse sorting
    chars.sort_by(|first, second| second.num.cmp(&first.num));
    // Most frequent character is the first one now
    chars[0].byte
}

// Is text in the buffer looks like an English text?
fn is_english(buffer: &[u8]) -> bool {
    // Here we just check that number of non letters in the text is lower than
    // 30%. More robust implementation can use most common English language
    // trigrams.
    let mut allowed = (buffer.len() * 30u) / 100u;
    for &c in buffer.iter() {
        match c as char {
            'a'..'z' | 'A'..'Z' => (),
            _ => {
                allowed -= 1u;
                if allowed <= 0 {
                    return false;
                }
            }
        }
    }
    true
}

// Try to decrypt encrypted text in the buffer
pub fn decrypt(buffer: &[u8]) -> DecryptionResult {
    if buffer.is_empty() {
        fail!("Buffer is empty");
    }
    let first = get_most_freq_char(buffer);
    for &c in ENGLISH_CHARS_BY_FREQ.iter() {
        // Most frequent letter in the encrypted text probably should
        // correspond to the most frequent letter in English
        let key = first ^ c;
        let decrypted = xor_by_key(buffer, key);
        if is_english(decrypted) {
            return Found(key, decrypted);
        }
    }
    NotFound
}
