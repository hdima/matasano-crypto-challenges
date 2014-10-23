/* AES ECB cut and paste
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate aes_lib;

use std::rand::random;

use aes_lib::{AES_BLOCK_SIZE, decrypt_aes_ecb, encrypt_aes_ecb};


struct Profile {
    key: Vec<u8>,
}

impl Profile {
    fn new() -> Profile {
        let key = random_bytes(AES_BLOCK_SIZE);
        Profile{key: key}
    }

    fn profile_for(&self, email: &str) -> Vec<u8> {
        if email.contains("&") || email.contains("=") {
            fail!("Invalid character in email: {}", email);
        }
        let map = [("email".into_string(), email.to_string()),
                   ("uid".into_string(), "10".into_string()),
                   ("role".into_string(), "user".into_string())];
        let encoded = encode_kv(map);
        encrypt_aes_ecb(encoded.as_slice(), self.key.as_slice())
    }

    fn decrypt(&self, encrypted: &[u8]) -> Vec<(String, String)> {
        let encoded = decrypt_aes_ecb(encrypted, self.key.as_slice());
        parse_kv(encoded.as_slice())
    }
}

fn random_bytes(len: uint) -> Vec<u8> {
    Vec::from_fn(len, |_| random::<u8>())
}

fn parse_kv(string: &[u8]) -> Vec<(String, String)> {
    let kv = string.split(|&c| c == b'&');
    kv.map(|kv| {
        let pair: Vec<&[u8]> = kv.split(|&c| c == b'=').collect();
        (String::from_utf8(pair[0].to_vec()).unwrap(),
         String::from_utf8(pair[1].to_vec()).unwrap())
        }).collect()
}

fn encode_kv(map: &[(String, String)]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for item in map.iter() {
        bytes.push_all(item.ref0().clone().into_bytes().as_slice());
        bytes.push(b'=');
        bytes.push_all(item.ref1().clone().into_bytes().as_slice());
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
    use super::{Profile, parse_kv, encode_kv};

    #[test]
    fn test_parse_encode_kv() {
        let map = [("foo".into_string(), "bar".into_string()),
                   ("baz".into_string(), "qux".into_string()),
                   ("zap".into_string(), "zazzle".into_string())];
        let encoded: Vec<u8> = b"foo=bar&baz=qux&zap=zazzle".to_vec();
        assert_eq!(map.to_vec(), parse_kv(encoded.as_slice()));
        assert_eq!(encode_kv(map), encoded);
    }

    #[test]
    fn test_profile() {
        let profile = Profile::new();
        let email = "bob@microsoft.com";
        let encrypted = profile.profile_for(email.as_slice());
        assert_eq!(profile.decrypt(encrypted.as_slice()),
                   [("email".into_string(), email.into_string()),
                    ("uid".into_string(), "10".into_string()),
                    ("role".into_string(), "user".into_string())].to_vec());
    }
}
