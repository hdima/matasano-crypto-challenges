/* AES ECB cut and paste
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate aes_lib;

#[cfg(not(test))]
use std::rand::random;
use std::collections::HashMap;

#[cfg(not(test))]
use aes_lib::{AES_BLOCK_SIZE, decrypt_aes_ecb, encrypt_aes_ecb};


#[cfg(not(test))]
struct Profile {
    key: Vec<u8>,
}

#[cfg(not(test))]
impl Profile {
    fn new() -> Profile {
        let key = random_bytes(AES_BLOCK_SIZE);
        Profile{key: key}
    }

    fn profile_for(&self, email: &str) -> Vec<u8> {
        if email.contains("&") || email.contains("=") {
            fail!("Invalid character in email: {}", email);
        }
        let mut map = HashMap::with_capacity(3);
        map.insert("email".into_string(), email.to_string());
        map.insert("uid".into_string(), "10".into_string());
        map.insert("role".into_string(), "user".into_string());
        let encoded = encode_kv(map);
        encrypt_aes_ecb(encoded.as_slice(), self.key.as_slice())
    }

    fn decrypt(&self, encrypted: &[u8]) -> HashMap<String, String> {
        let encoded = decrypt_aes_ecb(encrypted, self.key.as_slice());
        parse_kv(encoded.as_slice())
    }
}

#[cfg(not(test))]
fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random::<u8>())
}

fn parse_kv(string: &[u8]) -> HashMap<String, String> {
    let kv = string.split(|&c| c == b'&');
    let mut pairs = kv.map(|kv| kv.split(|&c| c == b'='));
    let mut map = HashMap::new();
    for mut it in pairs {
        let pair: Vec<&[u8]> = it.collect();
        map.insert(String::from_utf8(pair[0].to_vec()).unwrap(),
                   String::from_utf8(pair[1].to_vec()).unwrap());
    }
    map
}

fn encode_kv(map: HashMap<String, String>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (k, v) in map.iter() {
        bytes.push_all(k.clone().into_bytes().as_slice());
        bytes.push(b'=');
        bytes.push_all(v.clone().into_bytes().as_slice());
        bytes.push(b'&');
    }
    bytes.pop();
    bytes
}

#[cfg(not(test))]
fn main() {
    let profile = Profile::new();
    let encrypted = profile.profile_for("bob@microsoft.com".as_slice());
    println!("Decrypted: {}", profile.decrypt(encrypted.as_slice()));
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use super::{parse_kv, encode_kv};

    fn split_encoded(string: &[u8]) -> Vec<&[u8]> {
        let mut pairs: Vec<&[u8]> = string.split(|&c| c == b'&').collect();
        pairs.sort();
        pairs
    }

    #[test]
    fn test_parse_encode_kv() {
        let mut map: HashMap<String, String> = HashMap::new();
        let encoded: Vec<u8> = b"foo=bar&baz=qux&zap=zazzle".to_vec();
        map.insert("foo".into_string(), "bar".into_string());
        map.insert("baz".into_string(), "qux".into_string());
        map.insert("zap".into_string(), "zazzle".into_string());
        assert_eq!(map, parse_kv(encoded.as_slice()));
        assert_eq!(split_encoded(encode_kv(map).as_slice()),
                   split_encoded(encoded.as_slice()));
    }
}
