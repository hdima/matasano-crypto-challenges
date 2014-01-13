/* Repeating-key XOR cipher
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern mod extra;

#[cfg(not(test))]
use extra::hex::ToHex;

/*
 * Encrypt buffer with mult-character key
 */
fn xor_by_key(buffer: &[u8], key: &[u8]) -> ~[u8] {
    buffer.iter().zip(key.iter().cycle()).map(|(&c, &k)| c ^ k).collect()
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let key = ~"ICE";
    let input = ~"Burning 'em, if you ain't quick and nimble\n\
                  I go crazy when I hear a cymbal";
    println!("Key   => \"{}\"\n\
              Input => \"{}\"\n",
              key, input);
    let encrypted = xor_by_key(input.into_bytes(), key.into_bytes());
    println!("Encrypted => \"{}\"", encrypted.to_hex());
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::xor_by_key;
    use extra::hex::ToHex;

    #[test]
    fn test_xor_by_key() {
        let key = ~"ICE";
        let input = ~"Burning 'em, if you ain't quick and nimble\n\
                      I go crazy when I hear a cymbal";
        let encrypted = xor_by_key(input.into_bytes(), key.into_bytes());
        assert_eq!(encrypted.to_hex(),
                   ~"0b3637272a2b2e63622c2e69692a23693a2a3c\
                     6324202d623d63343c2a26226324272765272a\
                     282b2f20430a652e2c652a3124333a653e2b20\
                     27630c692b20283165286326302e27282f");
    }
}
