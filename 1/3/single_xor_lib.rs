/* Single-character XOR cipher guesser library
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

#[crate_id="single_xor_lib#0.1"];
#[crate_type="lib"];

extern mod extra;

use std::vec;

// English characters sorted by frequency
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

/*
 * XOR buffer by the key and return the result
 */
fn xor_by_key(buffer: &[u8], key: u8) -> ~[u8] {
    buffer.iter().map(|c| c ^ key).collect()
}

/*
 * Return most frequent character from the buffer
 */
fn get_most_freq_char(buffer: &[u8]) -> u8 {
    if buffer.is_empty() {
        fail!("Buffer is empty");
    }
    // Statistics map for every possible byte value
    let mut chars = vec::from_fn(256, |i| ByteStat{byte: i as u8, num: 0});
    for &c in buffer.iter() {
        chars[c].num += 1;
    }
    // Sort in reverse order so most frequent character will be the first one
    chars.sort_by(|first, second| second.num.cmp(&first.num));
    chars[0].byte
}

/*
 * Is text in the buffer looks like an English text?
 */
fn is_english(buffer: &[u8]) -> bool {
    /* The check is very simple here, we basically expect only printable
     * characters. But it should work in most of the cases.
     *
     * And we can't use for example n-grams with size greater than 1 here
     * because this library also used for slices of text.
     */
    for &c in buffer.iter() {
        match c as char {
            'a'..'z' | 'A'..'Z' | '0'..'9' => (),
            ' ' | '.' | ',' | '!' | '?' | '\'' | '-' | '"' | '&' | '%' => (),
            '#' | '(' | ')' | '\n' | '\r' | '\t' => (),
            _ => return false
        }
    }
    true
}

/*
 * Try to decrypt XOR encrypted text in the buffer
 */
pub fn decrypt(buffer: &[u8]) -> DecryptionResult {
    if buffer.is_empty() {
        fail!("Buffer is empty");
    }
    let first = get_most_freq_char(buffer);
    for &c in ENGLISH_CHARS_BY_FREQ.iter() {
        // Most frequent characters in the encrypted text probably should
        // correspond to the most frequent characters in English
        let key = first ^ c;
        let decrypted = xor_by_key(buffer, key);
        if is_english(decrypted) {
            return Found(key, decrypted);
        }
    }
    NotFound
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use std::str;
    use extra::hex::FromHex;
    use super::{xor_by_key, get_most_freq_char, is_english};
    use super::{decrypt, Found};

    #[test]
    fn test_xor_by_key() {
        let buffer = ~[0xafu8, 0xafu8, 0xafu8, 0xafu8];
        let key = 0xfau8;
        assert_eq!(xor_by_key(buffer, key), ~[0x55u8, 0x55u8, 0x55u8, 0x55u8]);
    }

    #[test]
    fn test_get_most_freq_char() {
        let buffer = ~[1u8, 1u8, 2u8, 2u8, 2u8, 3u8, 3u8, 3u8, 3u8];
        assert_eq!(get_most_freq_char(buffer), 3u8);
    }

    #[test]
    fn test_is_english() {
        assert_eq!(is_english(['t' as u8, 'e' as u8, 's' as u8, 't' as u8]),
                   true);
        assert_eq!(is_english([1u8, 2u8, 3u8]), false);
    }

    #[test]
    fn test_decrypt() {
        let buffer = ~"1b37373331363f78151b7f2b783431333d78397828372d363c78\
                       373e783a393b3736";
        let (key, decrypted) = match decrypt(buffer.from_hex().unwrap()) {
            Found(key, decrypted) => (key, decrypted),
            NotFound => fail!("Key not found")
        };
        assert_eq!('X', key as char);
        assert_eq!("Cooking MC's like a pound of bacon",
                   str::from_utf8(decrypted));
    }
}
