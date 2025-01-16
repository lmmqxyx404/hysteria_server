mod codec;

use bytes::BytesMut;

pub fn bytes_to_ascii_characters(bytes: &BytesMut) -> String {
    bytes
        .iter()
        .map(|&byte| {
            if byte.is_ascii() {
                byte as char
            } else {
                panic!("can not transfer"); // '.' // 替换非 ASCII 字符为 '.'
            }
        })
        .collect()
}

#[test]
fn test_ascii() {
    let initial_str = "Hello, world!".to_string();
    let mut bytes = BytesMut::from(initial_str.as_bytes()); // 包含非 ASCII 字符
    let ascii_characters = bytes_to_ascii_characters(&bytes);
    println!("ASCII Characters: {}", ascii_characters);
    assert_eq!(initial_str, ascii_characters);
    // 输出: ASCII Characters: Hello, world! .
}
