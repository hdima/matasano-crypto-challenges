/* Single-character XOR cipher decryption library
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

#![crate_name="single_char_xor_lib"]
#![crate_type="lib"]

extern crate serialize;

// English characters sorted by frequency
static ENGLISH_CHARS_BY_FREQ: &'static[u8] =
    b" eEtTaAiInNoOsSrRlLdDhHcCuUmMfFpPyYgGwWvVbBkKxXjJqQzZ";

// Result of the decryption
pub enum SingleCharKey {
    Found(u8, Vec<u8>),
    NotFound
}

// Bytes statistics
struct ByteStat {
    byte: u8,
    num: u64,
}

/*
 * Try to decrypt XOR encrypted text in the buffer
 */
pub fn decrypt(buffer: &[u8]) -> SingleCharKey {
    if buffer.is_empty() {
        return SingleCharKey::NotFound;
    }
    let first = get_most_freq_char(buffer);
    for &c in ENGLISH_CHARS_BY_FREQ.iter() {
        // Most frequent characters in the encrypted text probably should
        // correspond to the most frequent characters in English
        let key = first ^ c;
        let decrypted = xor_by_key(buffer, key);
        if is_english(decrypted.as_slice()) {
            return SingleCharKey::Found(key, decrypted);
        }
    }
    SingleCharKey::NotFound
}

/*
 * XOR buffer by the key and return the result
 */
#[inline]
fn xor_by_key(buffer: &[u8], key: u8) -> Vec<u8> {
    buffer.iter().map(|&c| c ^ key).collect()
}

/*
 * Return most frequent character from the buffer
 */
fn get_most_freq_char(buffer: &[u8]) -> u8 {
    // Statistics map for every possible byte value
    let mut chars: Vec<ByteStat> = range(0u16, 256).map(|i| {
            ByteStat{byte: i as u8, num: 0}
        }).collect();
    for &c in buffer.iter() {
        chars[c as uint].num += 1;
    }
    // Sort in reverse order so most frequent character will be the first one
    chars.sort_by(|first, second| second.num.cmp(&first.num));
    chars[0].byte
}

/*
 * Is text in the buffer looks like an English text?
 */
#[inline]
fn is_english(buffer: &[u8]) -> bool {
    /* The check is very simple here, we basically expect only printable
     * characters. But it should work in most of the cases.
     *
     * And we can't use for example n-grams because this library also used for
     * slices of text.
     */
    buffer.iter().all(|&c| is_english_char(c as char))
}

#[inline]
fn is_english_char(c: char) -> bool {
    match c {
        'a'...'z' | 'A'...'Z' | '0'...'9'
        | ' ' | '.' | ',' | '!' | '?' | '\'' | '-' | '"' | '&' | '%'
        | '#' | '(' | ')' | '\n' | '\r' | '\t' | '/' | ':' => true,
        _ => false
    }
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use std::str;
    use serialize::hex::FromHex;
    use super::{xor_by_key, get_most_freq_char, is_english};
    use super::{decrypt, SingleCharKey};

    #[test]
    fn test_xor_by_key() {
        let buffer = [0xafu8, 0xafu8, 0xafu8, 0xafu8];
        let key = 0xfau8;
        assert_eq!(xor_by_key(buffer.as_slice(), key),
                   vec![0x55u8, 0x55u8, 0x55u8, 0x55u8]);
    }

    #[test]
    fn test_get_most_freq_char() {
        let buffer = [1u8, 1u8, 2u8, 2u8, 2u8, 3u8, 3u8, 3u8, 3u8];
        assert_eq!(get_most_freq_char(buffer.as_slice()), 3u8);
    }

    #[test]
    fn test_is_english() {
        let buffer = ['t' as u8, 'e' as u8, 's' as u8, 't' as u8];
        assert_eq!(is_english(buffer.as_slice()), true);
        assert_eq!(is_english([1u8, 2u8, 3u8].as_slice()), false);
    }

    #[test]
    fn test_decrypt() {
        let buffer = "1b37373331363f78151b7f2b783431333d78397828372d363c78\
                      373e783a393b3736";
        let buf = buffer.from_hex().unwrap();
        let (key, decrypted) = match decrypt(buf.as_slice()) {
            SingleCharKey::Found(key, decrypted) => (key, decrypted),
            SingleCharKey::NotFound => panic!("Key not found")
        };
        assert_eq!('X', key as char);
        assert_eq!("Cooking MC's like a pound of bacon".as_slice(),
                   str::from_utf8(decrypted.as_slice()).unwrap());
    }
}
