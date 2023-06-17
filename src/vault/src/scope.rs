use std::thread::current;

use serde::{Serialize, Deserialize};

use crate::{abstractions::{VaultResult, VaultEmptyResult, VaultError}, helpers, cipher::{self, try_hash_with_sha3_256}, authentication, store::{store_manager::{CURRRENT_STORE, self, StoreManager}, self}};


const SCOPE_KEY_LEN: usize = 6;

/// Container
///
#[derive(Debug, Clone)]
pub(crate) struct ScopeContainer {
    /// The key that identifies the Profile
    pub(crate) key: String,

    pub(crate) owner_profile_key: String,

    /// The ciphered version of the Profile
    pub(crate) secure_info: Vec<u8>,

}



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Scope {
    /// The key that identifies the scope
    pub(crate) key: String,

    pub(crate) owner_profile_key: String,

    /// The name of the Profile
    pub(crate) name: String,

}

impl Scope {
    pub(crate) fn new(profile_key: &str, auth_key: &str, password: &str, name: &str) -> VaultResult<String> {
        
        authentication::ensure_user_is_owner(profile_key, auth_key, password)?;

        let (scope_key, scope_key_hash) = new_scope_key()?;

        let system_key = helpers::try_prepare_system_key(&scope_key_hash)?;

        let (cipher_key, system_key) = try_get_cipher_key(auth_key, &scope_key_hash)?;
        let nonce = cipher::try_generate_nonce(&scope_key_hash, &system_key)?;
        
        let scope = Scope {
            key: scope_key.clone(),
            owner_profile_key: profile_key.to_string(),
            name: name.to_string(),
        };

        let scope_sec = helpers::try_serialize_and_cipher(scope, &cipher_key, &nonce, &system_key)?;
        let scope_container = ScopeContainer {
            key: scope_key.to_owned(),
            owner_profile_key: profile_key.to_string(),
            secure_info: scope_sec
        };

        save_scope(&scope_container)?;

        Ok(scope_key)
    }

    pub(crate) fn get_with_key(profile_key: &str, auth_key: &str, scope_key: &str) -> VaultResult<Self> {

        let scope_key_hash = try_hash_with_sha3_256(scope_key.as_bytes())?;

        let (cipher_key, system_key) = try_get_cipher_key(auth_key, &scope_key_hash)?;
        let nonce = cipher::try_generate_nonce(&scope_key_hash, &system_key)?;

        let sm:&StoreManager = store_manager::CURRRENT_STORE.get();
        let container = sm.try_get_scope(&scope_key)?;

        let bytes = cipher::try_decrypt(&cipher_key.as_bytes(), &nonce, &container.secure_info, Some(&system_key))?;
        let scope = bincode::deserialize::<Scope>(&bytes).map_err(|e| VaultError::from(e.to_string()))?;

        if scope.owner_profile_key != profile_key {
            return Err(VaultError::from("Invalid profile!"));
        }

        Ok(scope)
    }


    pub fn key(&self) -> &str {
        self.key.as_ref()
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub(crate) fn try_delete(profile_key: &str, scope_key: &str, auth_key: &str, password: &str) -> VaultEmptyResult {
        authentication::ensure_user_is_owner(profile_key, auth_key, password)?;
        let sm = CURRRENT_STORE.get();
        sm.try_delete_scope(scope_key)
    }

    pub(crate) fn try_list(profile_key: &str, auth_key: &str, password: &str) -> VaultResult<Vec<ScopeContainer>> {
        authentication::ensure_user_is_owner(profile_key, auth_key, password)?;

        let sm = CURRRENT_STORE.get();
        let scopes = sm.try_get_profile_scopes(profile_key)?;
        Ok(scopes)
    }


}

fn try_get_cipher_key(auth_key: &str, scope_key_hash: &[u8]) -> VaultResult<(String, Vec<u8>)> {
    let auth_key_bytes = helpers::decode_b64(auth_key)?;
    let key_merged = cipher::merge_key(&auth_key_bytes, scope_key_hash);
    let cipher_key = helpers::encode_b64(&key_merged)?;
    let system_key = helpers::try_prepare_system_key(scope_key_hash)?;
    Ok((cipher_key, system_key))
}

fn save_scope(scope: &ScopeContainer) -> VaultEmptyResult {

    let store_m = CURRRENT_STORE.get();
    store_m.try_add_scope(scope)?;
    Ok(())
}

fn new_scope_key() -> VaultResult<(String, Vec<u8>)> {
    let scope_key = cipher::generate_random_bytes(SCOPE_KEY_LEN);
    let scope_key = helpers::encode_b64(&scope_key)?;
    let scope_key_hash = try_hash_with_sha3_256(&scope_key.as_bytes())?;
    Ok((scope_key, scope_key_hash))
}
