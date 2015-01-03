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
            panic!("Invalid character in email: {}", email);
        }
        let map = [("email".to_string(), email.to_string()),
                   ("uid".to_string(), "10".to_string()),
                   ("role".to_string(), "user".to_string())];
        let encoded = encode_kv(&map);
        encrypt_aes_ecb(encoded.as_slice(), self.key.as_slice())
    }

    fn decrypt(&self, encrypted: &[u8]) -> Vec<(String, String)> {
        let encoded = decrypt_aes_ecb(encrypted, self.key.as_slice());
        parse_kv(encoded.as_slice())
    }

    #[cfg(not(test))]
    fn make_admin_profile(&self) -> Vec<u8> {
        let encrypted = self.profile_for("foooo@bar.com");
        let enc_admin = self.profile_for(concat!("f@bar.com.",
            "admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b"));
        encrypted.slice_to(32).to_vec() + enc_admin.slice(16, 32)
    }
}

fn random_bytes(len: uint) -> Vec<u8> {
    range(0, len).map(|_| random::<u8>()).collect()
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
        bytes.push_all(item.0.clone().into_bytes().as_slice());
        bytes.push(b'=');
        bytes.push_all(item.1.clone().into_bytes().as_slice());
        bytes.push(b'&');
    }
    // Remove last '&'
    bytes.pop();
    bytes
}

#[cfg(not(test))]
fn main() {
    let profile = Profile::new();
    let encrypted = profile.make_admin_profile();
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
        let map = [("foo".to_string(), "bar".to_string()),
                   ("baz".to_string(), "qux".to_string()),
                   ("zap".to_string(), "zazzle".to_string())];
        let encoded: Vec<u8> = b"foo=bar&baz=qux&zap=zazzle".to_vec();
        assert_eq!(map.to_vec(), parse_kv(encoded.as_slice()));
        assert_eq!(encode_kv(&map), encoded);
    }

    #[test]
    fn test_profile() {
        let profile = Profile::new();
        let email = "foo@bar.com";
        let encrypted = profile.profile_for(email.as_slice());
        assert_eq!(profile.decrypt(encrypted.as_slice()),
                   [("email".to_string(), email.to_string()),
                    ("uid".to_string(), "10".to_string()),
                    ("role".to_string(), "user".to_string())].to_vec());
    }
}
