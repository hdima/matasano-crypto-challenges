/* Converting between Hex and Base64 encodings
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

extern crate "rustc-serialize" as serialize;

use serialize::hex::{FromHex, ToHex};
use serialize::base64::{STANDARD, FromBase64, ToBase64};


fn hex_to_bytes(hex: &str) -> Vec<u8> {
    match hex.from_hex() {
        Ok(bytes) => bytes,
        Err(error) => panic!("Error converting from Hex: {:?}", error)
    }
}

fn bytes_to_base64(bytes: &[u8]) -> String {
    bytes.to_base64(STANDARD)
}

fn base64_to_bytes(base64: &str) -> Vec<u8> {
    match base64.from_base64() {
        Ok(bytes) => bytes,
        Err(error) => panic!("Error converting from Base64: {:?}", error)
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.to_hex()
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120\
               706f69736f6e6f7573206d757368726f6f6d";
    println!("Hex     => {}", hex);
    let bytes = hex_to_bytes(hex);
    let base64 = bytes_to_base64(bytes.as_slice());
    println!("Bytes   => {}", String::from_utf8(bytes).unwrap());
    println!("Base64  => {}", base64);
    let bytes2 = base64_to_bytes(base64.as_slice());
    let hex2 = bytes_to_hex(bytes2.as_slice());
    println!("Bytes 2 => {}", String::from_utf8(bytes2).unwrap());
    println!("Hex 2   => {}", hex2);
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::{bytes_to_base64, base64_to_bytes};
    use super::{hex_to_bytes, bytes_to_hex};

    #[test]
    fn test_base64_hex() {
        let ex_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65\
                      206120706f69736f6e6f7573206d757368726f6f6d";
        let ex_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3V\
                         zIG11c2hyb29t";
        let base64 = bytes_to_base64(hex_to_bytes(ex_hex).as_slice());
        let hex = bytes_to_hex(base64_to_bytes(ex_base64).as_slice());
        assert_eq!(base64.as_slice(), ex_base64);
        assert_eq!(hex.as_slice(), ex_hex);
    }
}
