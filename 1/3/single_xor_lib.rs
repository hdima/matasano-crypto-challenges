// Single-character XOR cipher guesser library
//
// Dmitry Vasiliev <dima@hlabs.org>
//

// TODO:
//  - Tests

#[crate_id="single_xor_lib#0.1"];
#[crate_type="lib"];

use std::vec;
use std::str;

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
    // TODO: We can't use trigrams or bigrams here because this library
    // also used to decrypt repeating key XOR in which case it's trying
    // to guess slices of text.
    // FIXME: Example implementation with trigrams. Should be tuned because it
    // can also catch a gibberish with a correct trigram inside.
    // Also strings with mixed case should be considered.
    // Can we also use letters frequency?
    let string = match str::from_utf8_opt(buffer) {
        Some(string) => string,
        None => return false
    };
    let len = string.char_len() - 3;
    if len >= 0 {
        for i in range(0, len) {
            match string.slice(i, i + 3) {
                &"the" | &"and" | &"tha" | &"ent" | &"ing" | &"ion"
                | &"tio" | &"for" | &"nde" | &"has" | &"nce" | &"edt"
                | &"tis" | &"oft" | &"sth" | &"men" => return true,
                _ => ()
            }
        }
    }
    false
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
