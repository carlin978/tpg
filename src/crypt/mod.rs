use std::io::{Cursor, Read};

use anyhow::anyhow;
use pgp::composed::{
    key::SecretKeyParamsBuilder, KeyType, Message, SignedPublicKey, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::ser::Serialize;
use pgp::types::{CompressionAlgorithm, EskType, PkeskBytes, PublicKeyTrait};
use pgp::{Deserializable, SignedPublicSubKey};
use rand::thread_rng;
use smallvec::*;

mod helpers;
use helpers::*;

#[cfg(test)]
mod tests;

pub fn gen_key(name: &str, email: &str) -> anyhow::Result<SignedSecretKey> {
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id(format!("{} <{}>", name, email))
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::X25519)
                .can_encrypt(true)
                .build()?,
        )
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256])
        .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB]);

    let secret_key_params = key_params.build()?;

    let secret_key = secret_key_params.generate(thread_rng())?;

    let signed_secret_key = secret_key.sign(&mut thread_rng(), || String::new())?;

    Ok(signed_secret_key)
}

pub fn read_priv_key(data: Vec<u8>) -> anyhow::Result<SignedSecretKey> {
    Ok(SignedSecretKey::from_bytes(data.as_slice())?)
}

pub fn read_armored_priv_key(data: Vec<u8>) -> anyhow::Result<SignedSecretKey> {
    let (key, _) = SignedSecretKey::from_armor_single(data.as_slice())?;
    Ok(key)
}

pub fn read_pub_key(data: Vec<u8>) -> anyhow::Result<SignedPublicKey> {
    Ok(SignedPublicKey::from_bytes(data.as_slice())?)
}

pub fn read_armored_pub_key(data: Vec<u8>) -> anyhow::Result<SignedPublicKey> {
    let (key, _) = SignedPublicKey::from_armor_single(data.as_slice())?;
    Ok(key)
}

pub fn encrypt_to_binary(key: SignedPublicKey, data: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let encryption_key =
        get_encryption_key(&key).ok_or(anyhow!("Key doesn't have encryption key"))?;

    let msg = Message::new_literal_bytes("", data.as_slice());

    let encrypted_msg = msg.encrypt_to_keys_seipdv1(
        thread_rng(),
        SymmetricKeyAlgorithm::AES256,
        &[&encryption_key],
    )?;

    let encrypted_bytes = encrypted_msg.to_armored_bytes(Default::default())?;

    Ok(encrypted_bytes)
}

pub fn decrypt_from_binary(key: SignedSecretKey, encrypted: Vec<u8>) -> anyhow::Result<Vec<u8>> {
    let cursor = Cursor::new(encrypted);

    let (msg, _) = Message::from_armor_single(cursor)?;

    let (decrypted_msg, key_id) = msg.decrypt(|| String::new(), &[&key])?;

    let decrypted_bytes = decrypted_msg
        .get_content()?
        .ok_or(anyhow!("bytes are empty"))?;

    Ok(decrypted_bytes)
}
