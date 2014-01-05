// Single-character XOR cipher guesser
//
// Dmitry Vasiliev <dima@hlabs.org>
//

// TODO:
//  - Tests
//  - Extract all main functions to a library

extern mod extra;

use std::vec;
use extra::hex::FromHex;

static ENGLISH_CHARS_BY_FREQ: &'static[u8] = bytes!(
    " eEtTaAiInNoOsSrRlLdDhHcCuUmMfFpPyYgGwWvVbBkKxXjJqQzZ");

enum DecryptionResult {
    Found(u8, ~[u8]),
    NotFound
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
    let mut map = vec::from_elem(256, 0u);
    for &c in buffer.iter() {
        map[c] += 1u;
    }
    let mut numchars = map.iter().enumerate().map(|(c, &n)| (n, c as u8));
    let mut chars: ~[(uint, u8)] = numchars.collect();
    // Reverse sorting
    chars.sort_by(|f, s| s.cmp(f));
    // Most frequent character is the first one now
    chars[0].n1()
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
fn decrypt(buffer: &[u8]) -> DecryptionResult {
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

#[cfg(not(test))]
fn main() {
    use std::str;

    let input = ~"1b37373331363f78151b7f2b783431333d78397828372d363c\
                  78373e783a393b3736";
    let encrypted = input.from_hex().unwrap();

    println!("Input      => {}", input);
    println!("Encrypted  => {:?}", encrypted);
    match decrypt(encrypted) {
        Found(key, decrypted) => {
                println!("Key        => {}", key);
                println!("Decrypted  => {}", str::from_utf8(decrypted));
            }
        NotFound => fail!("No decryption key found")
    }
}
