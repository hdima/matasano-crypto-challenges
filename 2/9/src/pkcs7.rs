/* PKCS#7 padding
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */


fn pkcs7(data: &[u8], size: u8) -> Vec<u8> {
    let len = data.len();
    if len > size as uint {
        panic!("Invalid block size: {}", size);
    } else if len == size as uint {
        data.to_vec()
    } else {
        let pad = size - len as u8;
        data.to_vec() + Vec::from_elem(pad as uint, pad)
    }
}

/*
 * Main entry point
 */
#[cfg(not(test))]
fn main() {
    let input = b"YELLOW SUBMARINE";
    println!("Input     => {}", input);
    println!("PKCS#7    => {}", pkcs7(input, 20));
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use super::pkcs7;

    #[test]
    fn test_pkcs7() {
        let input = b"YELLOW SUBMARINE";
        assert_eq!(b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec(),
                   pkcs7(input, 20));
    }
}
