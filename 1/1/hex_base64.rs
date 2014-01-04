// Converting between Hex and Base64 encodings
//
// Dmitry Vasiliev <dima@hlabs.org>
//

extern mod extra;

use extra::hex::{FromHex, ToHex};
use extra::base64::{STANDARD, FromBase64, ToBase64};


fn hex_to_bytes(hex: ~str) -> ~[u8] {
    match hex.from_hex() {
        Ok(bytes) => bytes,
        Err(error) => fail!("Error converting from Hex: {}", error)
    }
}

fn bytes_to_base64(bytes: ~[u8]) -> ~str {
    bytes.to_base64(STANDARD)
}

fn base64_to_bytes(base64: ~str) -> ~[u8] {
    match base64.from_base64() {
        Ok(bytes) => bytes,
        Err(error) => fail!("Error converting from Base64: {}", error)
    }
}

fn bytes_to_hex(bytes: ~[u8]) -> ~str {
    bytes.to_hex()
}

#[cfg(not(test))]
fn main() {
    use std::str;

    let hex = ~"49276d206b696c6c696e6720796f757220627261696e206c696b65206120\
                706f69736f6e6f7573206d757368726f6f6d";
    println!("Hex     => {}", hex);
    let bytes = hex_to_bytes(hex);
    println!("Bytes   => {}", str::from_utf8(bytes));
    let base64 = bytes_to_base64(bytes);
    println!("Base64  => {}", base64);
    let bytes2 = base64_to_bytes(base64);
    println!("Bytes 2 => {}", str::from_utf8(bytes2));
    let hex2 = bytes_to_hex(bytes2);
    println!("Hex 2   => {}", hex2);
}

#[test]
fn test_base64_hex() {
    let hex = ~"49276d206b696c6c696e6720796f757220627261696e206c696b65206120\
                706f69736f6e6f7573206d757368726f6f6d";
    let base64 = ~"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3V\
                   zIG11c2hyb29t";
    assert_eq!(bytes_to_base64(hex_to_bytes(hex.clone())), base64);
    assert_eq!(bytes_to_hex(base64_to_bytes(base64)), hex);
}
