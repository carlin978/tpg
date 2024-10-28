use pgp::{
    crypto::hash::HashAlgorithm,
    types::{EskType, PkeskBytes, PublicKeyTrait},
    SignedPublicKey, SignedPublicSubKey,
};

#[derive(Debug)]
pub enum SignedPublicKeyOrSubkey<'a> {
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

pub fn get_encryption_key(key: &SignedPublicKey) -> Option<SignedPublicKeyOrSubkey> {
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
