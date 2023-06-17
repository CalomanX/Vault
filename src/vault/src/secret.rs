
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

use crate::{abstractions::{VaultResult, VaultEmptyResult, VaultError}, cipher::{try_hash_with_sha3_256, self}, helpers, authentication, store::{store_manager::{self, CURRRENT_STORE}, self}};

const SECRET_KEY_LEN: usize = 24;


#[derive(Debug, Clone)]
pub(crate) struct SecretContainer {
    /// The key that identifies the Profile
    pub(crate) key: String,

    pub(crate) owner_profile_key: String,
    pub(crate) owner_scope_key: String,
    /// The ciphered version of the Profile
    pub(crate) secure_info: Vec<u8>,

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub(crate) key: String,
    pub(crate) owner_profile_key: String,
    pub(crate) owner_scope_key: String,
    pub(crate) value: String,
    pub(crate) created: String,
    pub(crate) expirable: bool,
    pub(crate) expire: Option<String>
}



impl Secret {
    pub(crate) fn new(profile_key: &str, scope_key: &str, auth_key: &str, password: &str, value: &str, expire_date: Option<DateTime<Utc>>) -> VaultResult<String> {

        authentication::ensure_user_is_owner(profile_key, auth_key, password)?;

        let (secret_key, secret_key_hash) = new_secret_key()?;
        
        let (cipher_key, system_key) = try_get_cipher_key(auth_key, &secret_key_hash)?;

        let nonce = cipher::try_generate_nonce(&secret_key_hash, &system_key)?;

        let secret = Secret {
            key: secret_key.to_string(),
            owner_profile_key: profile_key.to_string(),
            owner_scope_key: scope_key.to_string(),
            created: Utc::now().to_string(),
            expirable: expire_date.is_some(),
            expire: match expire_date {
                Some(e) => Some(e.to_string()),
                None => None,
            },
            value: value.to_string(), 
        };

        let secret_encoded = helpers::try_serialize_and_cipher::<Secret>(secret, &cipher_key, &nonce, &system_key)?;
        
        let secret_container = SecretContainer {
            key: secret_key.to_string(),
            owner_profile_key: profile_key.to_string(),
            owner_scope_key: scope_key.to_string(),
            secure_info: secret_encoded
        };
        
        try_save_secret(&secret_container)?;

        Ok(secret_key)
    }

    pub(crate) fn get_with_key(profile_key: &str, scope_key: &str, auth_key: &str, secret_key: &str) -> VaultResult<Self> {

        let secret_key_hash = try_hash_with_sha3_256(secret_key.as_bytes())?;
        let (cipher_key, system_key) = try_get_cipher_key(auth_key, &secret_key_hash)?;
        let nonce = cipher::try_generate_nonce(&secret_key_hash, &system_key)?;       


        let store_manager = store_manager::CURRRENT_STORE.get();
        let container = store_manager.try_get_secret(secret_key)?;

        let bytes = cipher::try_decrypt(&cipher_key.as_bytes(), &nonce, &container.secure_info, Some(&system_key))?;
        let secret = bincode::deserialize::<Secret>(&bytes).map_err(|e| VaultError::from(e.to_string()))?;

        if secret.owner_profile_key != profile_key {
            return Err(VaultError::from("Invalid profile!"));
        } else if secret.owner_scope_key != scope_key {
            return Err(VaultError::from("Invalid scope!"));
        }
        Ok(secret)
    }


    pub fn key(&self) -> &str {
        self.key.as_ref()
    }

    pub fn value(&self) -> &str {
        self.value.as_ref()
    }

    pub fn created(&self) -> &str {
        self.created.as_ref()
    }

    pub fn expirable(&self) -> bool {
        self.expirable
    }

    pub fn expire(&self) -> Option<&String> {
        self.expire.as_ref()
    }

    pub(crate) fn try_delete(profile_key: &str, secret_key: &str, auth_key: &str, password: &str) -> VaultEmptyResult {
        authentication::ensure_user_is_owner(profile_key, auth_key, password)?;
        let sm = CURRRENT_STORE.get();   
        sm.try_delete_secret(secret_key)
    }

    pub(crate) fn try_get_all_scoped_secrets(&self, profile_key:&str, scope_key:&str, auth_key: &str, password: &str) -> VaultResult<Vec<SecretContainer>> {

        authentication::ensure_user_is_owner(profile_key, auth_key, password)?;
        let sm = CURRRENT_STORE.get();
        let secrets = sm.try_get_all_scope_secrets(profile_key, scope_key)?;
        Ok(secrets)
    }

}

fn try_save_secret(secret_container: &SecretContainer) -> VaultEmptyResult {
    let store_manager = store_manager::CURRRENT_STORE.get();
    store_manager.try_add_secret(secret_container)
}

fn new_secret_key() -> VaultResult<(String, Vec<u8>)> {
    let key = cipher::generate_random_bytes(24);
    let key = helpers::encode_b64(&key)?;
    let key_hash = try_hash_with_sha3_256(key.as_bytes())?;
    Ok((key, key_hash))
}

fn try_get_cipher_key(auth_key: &str, secret_key_hash: &[u8]) -> VaultResult<(String, Vec<u8>)> {
    let auth_key_bytes = helpers::decode_b64(auth_key)?;
    let key_merged = cipher::merge_key(&auth_key_bytes, secret_key_hash);
    let cipher_key = helpers::encode_b64(&key_merged)?;
    let system_key = helpers::try_prepare_system_key(secret_key_hash)?;
    Ok((cipher_key, system_key))
}