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
        .key_type(KeyType::EdDSALegacy)
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

#[derive(Debug)]
enum SignedPublicKeyOrSubkey<'a> {
    Key(&'a SignedPublicKey),
    SubKey(&'a SignedPublicSubKey),
}
impl PublicKeyTrait for SignedPublicKeyOrSubkey<'_> {
    fn version(&self) -> pgp::types::KeyVersion {
        match self {
            Self::Key(key) => key.version(),
            Self::SubKey(subkey) => subkey.version(),
        }
    }

    fn fingerprint(&self) -> pgp::types::Fingerprint {
        match self {
            Self::Key(key) => key.fingerprint(),
            Self::SubKey(subkey) => subkey.fingerprint(),
        }
    }

    fn key_id(&self) -> pgp::types::KeyId {
        match self {
            Self::Key(key) => key.key_id(),
            Self::SubKey(subkey) => subkey.key_id(),
        }
    }

    fn algorithm(&self) -> pgp::crypto::public_key::PublicKeyAlgorithm {
        match self {
            Self::Key(key) => key.algorithm(),
            Self::SubKey(subkey) => subkey.algorithm(),
        }
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        match self {
            Self::Key(key) => key.created_at(),
            Self::SubKey(subkey) => subkey.created_at(),
        }
    }

    fn expiration(&self) -> Option<u16> {
        match self {
            Self::Key(key) => key.expiration(),
            Self::SubKey(subkey) => subkey.expiration(),
        }
    }

    fn verify_signature(
        &self,
        hash: HashAlgorithm,
        data: &[u8],
        sig: &pgp::types::SignatureBytes,
    ) -> pgp::errors::Result<()> {
        match self {
            Self::Key(key) => key.verify_signature(hash, data, sig),
            Self::SubKey(subkey) => subkey.verify_signature(hash, data, sig),
        }
    }

    fn encrypt<R: rand::CryptoRng + rand::Rng>(
        &self,
        rng: R,
        plain: &[u8],
        typ: EskType,
    ) -> pgp::errors::Result<PkeskBytes> {
        match self {
            Self::Key(key) => key.encrypt(rng, plain, typ),
            Self::SubKey(subkey) => subkey.encrypt(rng, plain, typ),
        }
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> pgp::errors::Result<()> {
        match self {
            Self::Key(key) => key.serialize_for_hashing(writer),
            Self::SubKey(subkey) => subkey.serialize_for_hashing(writer),
        }
    }

    fn public_params(&self) -> &pgp::types::PublicParams {
        match self {
            Self::Key(key) => key.public_params(),
            Self::SubKey(subkey) => subkey.public_params(),
        }
    }
}

fn get_encryption_key(key: &SignedPublicKey) -> Option<SignedPublicKeyOrSubkey> {
    if key.is_encryption_key() {
        Some(SignedPublicKeyOrSubkey::Key(&key))
    } else {
        key.public_subkeys
            .iter()
            .find(|subkey| subkey.is_encryption_key())
            .map_or_else(
                || None,
                |subkey| Some(SignedPublicKeyOrSubkey::SubKey(subkey)),
            )
    }
}

pub fn encrypt_to_binary(key: SignedPublicKey, data: Vec<u8>) -> Result<Vec<u8>, String> {
    let encryption_key = match get_encryption_key(&key) {
        Some(key) => key,
        None => return Err("Key doesn't have encryption key".into()),
    };
    let msg = Message::new_literal_bytes("", data.as_slice());
    let encrypted_msg = match msg.encrypt_to_keys_seipdv2(
        thread_rng(),
        SymmetricKeyAlgorithm::AES256,
        pgp::crypto::aead::AeadAlgorithm::None,
        64, //TODO: figure out a chunk_size that works
        &[&encryption_key],
    ) {
        Ok(msg) => msg,
        Err(err) => return Err(err.to_string().into()),
    };
    Ok(encrypted_msg
        .to_bytes()
        .expect("Failed to convert message to bytes"))
}
