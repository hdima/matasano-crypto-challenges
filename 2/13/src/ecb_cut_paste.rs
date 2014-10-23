/* AES ECB cut and paste
 *
 * Dmitry Vasiliev <dima@hlabs.org>
 */

use std::collections::HashMap;


fn parse_kv(string: &[u8]) -> HashMap<String, String> {
    let kv = string.split(|&c| c == b'&');
    let mut pairs = kv.map(|kv| kv.split(|&c| c == b'='));
    let mut map = HashMap::new();
    for mut it in pairs {
        let pair: Vec<&[u8]> = it.collect();
        map.insert(String::from_utf8(pair[0].to_vec()).unwrap(),
                   String::from_utf8(pair[1].to_vec()).unwrap());
    }
    map
}

fn encode_kv(map: HashMap<String, String>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (k, v) in map.iter() {
        bytes.push_all(k.clone().into_bytes().as_slice());
        bytes.push(b'=');
        bytes.push_all(v.clone().into_bytes().as_slice());
        bytes.push(b'&');
    }
    bytes.pop();
    bytes
}

#[cfg(not(test))]
fn main() {
    let obj = parse_kv(b"foo=bar&baz=qux&zap=zazzle");
    println!("Obj: {}", obj);
    let s = encode_kv(obj);
    println!("String: {}", String::from_utf8_lossy(s.as_slice()));
}

/*
 * Tests
 */
#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use super::{parse_kv, encode_kv};

    fn split_encoded(string: &[u8]) -> Vec<&[u8]> {
        let mut pairs: Vec<&[u8]> = string.split(|&c| c == b'&').collect();
        pairs.sort();
        pairs
    }

    #[test]
    fn test_parse_encode_kv() {
        let mut map: HashMap<String, String> = HashMap::new();
        let encoded: Vec<u8> = b"foo=bar&baz=qux&zap=zazzle".to_vec();
        map.insert("foo".into_string(), "bar".into_string());
        map.insert("baz".into_string(), "qux".into_string());
        map.insert("zap".into_string(), "zazzle".into_string());
        assert_eq!(map, parse_kv(encoded.as_slice()));
        assert_eq!(split_encoded(encode_kv(map).as_slice()),
                   split_encoded(encoded.as_slice()));
    }
}
