/* Repeating-key XOR cipher
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

#[cfg(not(test))]
use serialize::hex::ToHex;

/*
 * Encrypt buffer with mult-character key
 */
fn xor_by_key(buffer: &[u8], key: &[u8]) -> Vec<u8> {
    buffer.iter().zip(key.iter().cycle()).map(|(&c, &k)| c ^ k).collect()
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let key = b"ICE";
    let input = b"Burning 'em, if you ain't quick and nimble\n\
                  I go crazy when I hear a cymbal";
    println!("Key   => {:?}\n\
              Input => {:?}",
              key, input);
    let encrypted = xor_by_key(input, key);
    println!("Encrypted => \"{}\"", encrypted.to_hex());
    let decrypted = xor_by_key(encrypted.as_slice(), key);
    println!("Decrypted => \"{}\"", String::from_utf8(decrypted).unwrap());
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::xor_by_key;
    use serialize::hex::ToHex;

    #[test]
    fn test_xor_by_key() {
        let key = b"ICE";
        let input = b"Burning 'em, if you ain't quick and nimble\n\
                      I go crazy when I hear a cymbal";
        let encrypted = xor_by_key(input, key);
        assert_eq!(encrypted.to_hex().as_slice(),
                   "0b3637272a2b2e63622c2e69692a23693a2a3c\
                    6324202d623d63343c2a26226324272765272a\
                    282b2f20430a652e2c652a3124333a653e2b20\
                    27630c692b20283165286326302e27282f");
    }
}
