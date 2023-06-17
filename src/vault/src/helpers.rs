use std::borrow::Borrow;

use crate::{abstractions::VaultError, cipher, VaultResult};
use password_hash::Encoding;

pub(crate) fn encode_b64(buf: &[u8]) -> VaultResult<String> {
    let len = Encoding::B64.encoded_len(buf);
    let mut dest = vec![0u8; len];
    let rst = Encoding::B64
        .encode(buf, &mut dest)
        .map_err(|e| VaultError::create(e.to_string()))?;
    let rst = rst.to_owned();
    Ok(rst)
}

pub(crate) fn decode_b64(buf: &str) -> VaultResult<Vec<u8>> {
    let len = buf.len();
    let mut dest = vec![0u8; len];
    let rst = Encoding::B64
        .decode(buf, &mut dest)
        .map_err(|e| VaultError::create(e.to_string()))?;
    let rst = rst.to_owned();
    Ok(rst)
}

/// Generates a system key based in the source
pub(crate) fn try_prepare_system_key(source_hash: &[u8]) -> VaultResult<Vec<u8>> {
    let system_key = crate::cipher::try_generate_user_system_key(source_hash)?;
    let system_key_sha3 = crate::cipher::try_hash_with_sha3_256(system_key.as_ref());
    system_key_sha3
}

pub(crate) fn try_serialize_and_cipher<T: serde::Serialize>(
    content: T,
    cipher_key: &str,
    nonce: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, VaultError> {
    let profile_serialized =
        bincode::serialize::<T>(&content).map_err(|e| VaultError::from(e.to_string()))?;
    let cipher_profile = cipher::try_encrypt(
        &cipher_key.as_bytes(),
        &nonce,
        &profile_serialized,
        Some(&aad),
    )?;
    Ok(cipher_profile)
}

// pub(crate) fn decipher_and_deserialize<'a, T>(
//     content: &'a [u8],
//     cipher_key: &str,
//     nonce: &[u8],
//     aad: &[u8],
// ) -> VaultResult<T>
// where
//     T: serde::de::Deserialize<'a>,
// {
//     let profile = cipher::try_decrypt(&cipher_key.as_bytes(), &nonce, &content, Some(&aad))?;
//     let profile = bincode::deserialize::<T>(&profile).map_err(|e| VaultError::from(e.to_string()))?;
//     todo!()
//     //Ok(profile)

// }

