use std::io::Read;

use pgp::composed::{key::SecretKeyParamsBuilder, KeyType, SignedSecretKey};
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::types::CompressionAlgorithm;
use pgp::Deserializable;
use rand::thread_rng;
use smallvec::*;

pub fn gen_priv_key(name: &str, email: &str) -> SignedSecretKey {
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Rsa(2048))
        .can_certify(false)
        .can_sign(true)
        .primary_user_id(format!("{} <{}>", name, email).into())
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
