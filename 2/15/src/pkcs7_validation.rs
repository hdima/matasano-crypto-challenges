/* PKCS#7 validation
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

static AES_BLOCK_SIZE: u8 = 16;

fn remove_pkcs7_padding(data: &[u8]) -> Option<&[u8]> {
    let len = data.len();
    if (len == 0) || (len % AES_BLOCK_SIZE as uint != 0) {
        return None;
    }
    match data.last() {
        Some(&last) if last > 0 && last < AES_BLOCK_SIZE => {
            let data_len = len - last as uint;
            match data.slice_from(data_len).iter().all(|&c| c == last) {
                true => Some(data.slice_to(data_len)),
                false => None
            }
        }
        _ => None
    }
}

fn main() {
    let strings = [
        b"ICE ICE BABY\x04\x04\x04\x04",
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x01\x02\x03\x04",
    ];
    for &string in strings.iter() {
        print!("Input: {}, ", string);
        match remove_pkcs7_padding(string) {
            Some(stripped) => println!("Stripped: \"{}\"",
                String::from_utf8(stripped.to_vec()).unwrap()),
            None => println!("Invalid PKCS#7 padding")
        }
    }
}
