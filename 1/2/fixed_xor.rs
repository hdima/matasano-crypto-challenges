// Fixed XOR
//
// Dmitry Vasiliev <dima@hlabs.org>
//

extern mod extra;

use extra::hex::{FromHex, ToHex};

fn xor_buffers(s1: &[u8], s2: &[u8]) -> ~[u8] {
    if s1.len() != s2.len() {
        fail!("Not equal length of input buffers")
    }
    s1.iter().zip(s2.iter()).map(|(&c1, &c2)| c1 ^ c2).collect()
}

#[cfg(not(test))]
fn main() {
    use std::str;

    let key = ~"1c0111001f010100061a024b53535009181c";
    let input = ~"686974207468652062756c6c277320657965";
    println!("Key           => {}", key);
    println!("Input         => {}", input);
    let key_bytes = key.from_hex().unwrap();
    let input_bytes = input.from_hex().unwrap();
    println!("Key bytes     => {:?}", key_bytes);
    println!("Input bytes   => {}", str::from_utf8(input_bytes));
    let output = xor_buffers(input_bytes, key_bytes);
    println!("Output        => {}", output.to_hex());
    println!("Output bytes  => {}", str::from_utf8(output));
}

#[test]
fn test_xor_buffers() {
    let key = "1c0111001f010100061a024b53535009181c".from_hex().unwrap();
    let input = "686974207468652062756c6c277320657965".from_hex().unwrap();
    let output = xor_buffers(input, key);
    assert_eq!(output.to_hex(), ~"746865206b696420646f6e277420706c6179");
}
