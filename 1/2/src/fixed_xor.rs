/* Fixed XOR
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate serialize;

#[cfg(not(test))]
use serialize::hex::{FromHex, ToHex};

/*
 * XOR two equal-length buffers
 */
fn xor_buffers(s1: &[u8], s2: &[u8]) -> Vec<u8> {
    if s1.len() != s2.len() {
        panic!("Not equal length of input buffers")
    }
    s1.iter().zip(s2.iter()).map(|(&c1, &c2)| c1 ^ c2).collect()
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    use std::str;

    let key = "1c0111001f010100061a024b53535009181c";
    let input = "686974207468652062756c6c277320657965";
    println!("Key           => {}", key);
    println!("Input         => {}", input);
    let key_bytes = key.from_hex().unwrap();
    let input_bytes = input.from_hex().unwrap();
    println!("Key bytes     => {}", key_bytes);
    let input_str = str::from_utf8(input_bytes.as_slice()).unwrap();
    println!("Input bytes   => {}", input_str);
    let output = xor_buffers(input_bytes.as_slice(), key_bytes.as_slice());
    println!("Output        => {}", output.as_slice().to_hex());
    let output_str = str::from_utf8(output.as_slice()).unwrap();
    println!("Output bytes  => {}", output_str);
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::xor_buffers;
    use serialize::hex::{FromHex, ToHex};

    #[test]
    fn test_xor_buffers() {
        let key = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
        let input = "686974207468652062756c6c277320657965".from_hex().unwrap();
        let output = xor_buffers(input.as_slice(), key.as_slice());
        assert_eq!(output.as_slice().to_hex().as_slice(),
                   "746865206b696420646f6e277420706c6179");
    }
}
