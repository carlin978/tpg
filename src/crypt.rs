use std::io::Read;

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

pub fn gen_key(name: &str, email: &str) -> SignedSecretKey {
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Ed25519)
        .can_certify(false)
        .can_sign(true)
        .can_encrypt(false)
        .primary_user_id(format!("{} <{}>", name, email))
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH(ECCCurve::Curve25519))
                .can_encrypt(true)
                .build()
                .expect("Failed to create subkey"),
        )
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256])
        .preferred_hash_algorithms(smallvec![HashAlgorithm::SHA2_256])
        .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB]);

    let secret_key_params = key_params
        .build()
        .expect("Must be able to create secret key params");

    let secret_key = secret_key_params
        .generate(thread_rng())
        .expect("Failed to generate a plain key.");

    let passwd_fn = || String::new();

    let signed_secret_key = secret_key
        .sign(&mut thread_rng(), passwd_fn)
        .expect("Must be able to sign its own metadata");
    signed_secret_key
}

pub fn read_priv_key(data: Vec<u8>) -> Result<SignedSecretKey, pgp::errors::Error> {
    SignedSecretKey::from_bytes(data.as_slice())
}

pub fn read_pub_key(data: Vec<u8>) -> Result<SignedPublicKey, pgp::errors::Error> {
    SignedPublicKey::from_bytes(data.as_slice())
}

pub fn encrypt_to_binary(key: SignedPublicKey, data: Vec<u8>) -> Result<Vec<u8>, String> {
    let msg = Message::new_literal_bytes("", data.as_slice());
    let encrypted_msg = match msg.encrypt_to_keys_seipdv2(
        thread_rng(),
        SymmetricKeyAlgorithm::AES256,
        pgp::crypto::aead::AeadAlgorithm::None,
        64, //TODO: figure out a chunk_size that works
        &[&key
            .public_subkeys
            .iter()
            .find(|pk| pk.is_encryption_key())
            .expect("expected encryption subkey")],
    ) {
        Ok(msg) => msg,
        Err(err) => return Err(err.to_string().into()),
    };
    Ok(encrypted_msg
        .to_bytes()
        .expect("Failed to convert message to bytes"))
}

// pub fn encrypt_bytes_to_binary(key: SignedPublicKey, bytes: Vec<u8>) -> Result<Vec<u8>, String> {
//     let encrypted_result = key.encrypt(thread_rng(), bytes.as_slice(), EskType::V6);
//     if let Ok(encrypted) = encrypted_result {
//         match encrypted {
//             PkeskBytes::Rsa { mpi } => Ok(mpi.as_bytes().into()),
//             _ => Err("Unknown/Non-supported encryption method".into()),
//         }
//     } else {
//         Err(format!(
//             "Failed to Encrypt: {}",
//             encrypted_result.unwrap_err().to_string()
//         ))
//     }
// }
