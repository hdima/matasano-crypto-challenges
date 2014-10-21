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

fn main() {
    let obj = parse_kv(b"foo=bar&baz=qux&zap=zazzle");
    println!("Obj: {}", obj);
    let s = encode_kv(obj);
    println!("String: {}", String::from_utf8_lossy(s.as_slice()));
}
