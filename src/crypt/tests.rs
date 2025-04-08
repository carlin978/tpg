use super::*;

#[test]
fn generate_key() {
    let key = gen_key("Test", "test@example.com").unwrap();
}

#[test]
fn encrypt_text_without_armor() {
    let key_data = include_bytes!("../../tests/key.pgp");
    let key = read_priv_key(key_data.into()).unwrap();

    let text = include_str!("../../tests/test.txt");
    let encrypted = encrypt_to_binary(key.into(), text.as_bytes().into()).unwrap();
}

#[test]
fn encrypt_text_with_armor() {
    let key_data = include_bytes!("../../tests/key.asc");
    let key = read_armored_priv_key(key_data.into()).unwrap();

    let text = include_str!("../../tests/test.txt");
    let encrypted = encrypt_to_binary(key.into(), text.as_bytes().into()).unwrap();
}

#[test]
fn decrypt_text() {
    let key_data = include_bytes!("../../tests/key.asc");
    let key = read_armored_priv_key(key_data.into()).unwrap();

    let encrypted_bytes = include_bytes!("../../tests/test.asc");
    let decrypted_bytes = decrypt_from_binary(key, encrypted_bytes.into()).unwrap();

    let decrypted = String::from_utf8(decrypted_bytes).unwrap();

    assert_eq!(decrypted.as_str(), include_str!("../../tests/test.txt"));
}
