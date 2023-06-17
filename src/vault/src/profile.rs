use std::str;

use password_hash::SaltString;
use serde::{Deserialize, Serialize};
use uuid::{NoContext, Uuid};

use crate::{
    abstractions::{B64String, VaultEmptyResult, VaultError, VaultResult},
    authentication,
    cipher::{self, try_derive_password},
    helpers::{self, try_serialize_and_cipher},
    store::{store_manager::CURRRENT_STORE}, profile,
};

/// Container
///
#[derive(Debug, Clone)]
pub(crate) struct ProfileContainer {
    /// The key that identifies the Profile
    pub(crate) key: String,

    pub(crate) auth_key_phc: String,

    pub(crate) is_active: bool,

    /// The ciphered version of the Profile
    pub(crate) secure_info: Vec<u8>,
}

pub(crate) const PROFILE_AUTH_KEY_LEN: usize = 24;

/// Profile
///
/// Represents a Profile
///
/// key - The profile key (or id)
/// source_key - The source key is the base key for all keys that derive from it
/// source_key_phc - The phc for the source key to allow matching the profile with the authentication password
/// name - the profile's name
/// is_master - indicates if the profile is the master profile
/// is_active - indicates if the profile is active (Note the master profile can not be inactive)
/// scopes - A collection of all the profile's scopes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Profile {
    /// The key that identifies the profile
    pub(crate) key: String,

    /// PHC of the password
    pub(crate) password_phc: String,

    /// The name of the Profile
    pub(crate) name: String,

    /// Identifies if the Profile is active.
    /// NOTE: A Master profile can not be inactive
    pub(crate) is_master: bool,
}

impl Profile {

    pub(crate) fn new(
        admin_profile_key: &str,
        admin_auth_key: &str,
        admin_password: &str,
        profile_name: &str,
        profile_password: &str,
    ) -> VaultResult<(String, String)> {
        new_core(
            Some(admin_profile_key),
            Some(admin_auth_key),
            Some(admin_password),
            profile_name,
            profile_password,
            false,
        )
    }

    pub(crate) fn new_master(password: &str) -> VaultResult<(String, String)> {
        new_core(None, None, None, "Admin", password, true)
    }

    pub(crate) fn get_with_key(key: &str, auth_key: &str) -> VaultResult<Self> {
        if key.is_empty() || key.contains(char::is_whitespace) {
            return Err(VaultError::create("Key is invalid.".to_string()));
        }
        if auth_key.is_empty() || auth_key.contains(char::is_whitespace) {
            return Err(VaultError::create("auth_key is invalid.".to_string()));
        }

        let store_manager = CURRRENT_STORE.get();
        let container = store_manager.try_get_profile(&key)?;

        if !container.is_active {
            return Err(VaultError::from("No such profile."));
        }

        let profile_key_hash = cipher::try_hash_with_sha3_256(key.as_bytes())?;
        let system_key = helpers::try_prepare_system_key(&profile_key_hash.as_ref())?;

        let auth_key_bytes = auth_key.as_bytes();

        let nonce = cipher::try_derive_key_with_size(
            &system_key,
            &auth_key_bytes,
            cipher::CHACHAPOLY1305_NONCE_SIZE_IN_BYTES,
        )?;

        let cipher_profile = cipher::try_decrypt(
            &auth_key_bytes,
            &nonce,
            &container.secure_info,
            Some(&system_key),
        )?;
        let profile = bincode::deserialize::<Profile>(&cipher_profile)
            .map_err(|e| VaultError::from(e.to_string()))?;

        Ok(profile)
    }

    pub(crate) fn delete(profile_key: &str, auth_key: &str, password: &str) -> VaultEmptyResult {

        authentication::ensure_user_is_owner(profile_key, auth_key, password)?;

        let store_manager = CURRRENT_STORE.get();
        store_manager.try_delete_profile(&profile_key)
    }

    pub(crate) fn key(&self) -> &str {
        self.key.as_ref()
    }

    pub(crate) fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub(crate) fn try_list(admin_profile_key: &str, admin_auth_key: &str, password: &str) -> VaultResult<Vec<ProfileContainer>> {
        authentication::ensure_user_is_admin(&admin_profile_key, &admin_auth_key, &password)?;
        let store_manager = CURRRENT_STORE.get();
        store_manager.try_get_all_profiles()
    }


}




/// Create a new Profile
///
/// Will create a new profile and return the Authentication Key
///
fn new_core(
    maybe_admin_profile_key: Option<&str>,
    maybe_admin_auth_key: Option<&str>,
    maybe_admin_password: Option<&str>,
    name: &str,
    clear_password: &str,
    is_master: bool,
) -> VaultResult<(String, String)> {

    let (profile_key, profile_key_hash) = new_profile_key()?;

    let system_key_bytes = helpers::try_prepare_system_key(&profile_key_hash)?;
    let password_key = try_derive_password(clear_password, &system_key_bytes)?;

    if !is_master {
        let admin_password = maybe_admin_password.unwrap();
        let admin_profile_key = maybe_admin_profile_key.unwrap();
        let admin_auth_key = maybe_admin_auth_key.unwrap();
        authentication::ensure_user_is_admin(
            admin_profile_key,
            admin_auth_key,
            &admin_password,
        )?;
    }

    let password_phc = get_password_phc(&password_key, &system_key_bytes)?;

    let auth_key = get_auth_key()?;

    let auth_key_phc = get_auth_key_phc(&auth_key, &system_key_bytes)?;

    let nonce = cipher::try_generate_nonce(&system_key_bytes, &auth_key.as_bytes())?;

    let profile = Profile {
        key: profile_key.to_owned(),
        password_phc: password_phc,
        name: name.to_string(),
        is_master: is_master,
    };

    let cipher_profile = try_serialize_and_cipher(profile, &auth_key, &nonce, &system_key_bytes)?;

    let container = create_profile_container(
        &profile_key.to_owned(),
        auth_key_phc.to_string(),
        true,
        &cipher_profile,
    )?;

    save_profile(&container)?;

    Ok((profile_key, auth_key))
}

fn get_auth_key_phc(
    password_bytes: &String,
    system_key_bytes: &Vec<u8>,
) -> Result<String, VaultError> {
    let salt = new_salt(&system_key_bytes.clone())?;
    let auth_key_phc =
        cipher::try_default_password_hash(&password_bytes.as_bytes(), &salt)?.to_string();
    Ok(auth_key_phc)
}

fn get_auth_key() -> Result<String, VaultError> {
    let auth_key_bytes = cipher::generate_random_bytes(PROFILE_AUTH_KEY_LEN);
    let auth_key = helpers::encode_b64(&auth_key_bytes)?;
    Ok(auth_key)
}

fn get_password_phc<'a>(
    password: &str,
    system_key_bytes: &'a Vec<u8>,
) -> Result<String, VaultError> {
    let password_key_salt = new_salt(&system_key_bytes)?;
    let password_phc =
        cipher::try_default_password_hash(password.as_ref(), &password_key_salt)?.to_string();
    Ok(password_phc)
}

fn new_salt(key_to_hash: &[u8]) -> VaultResult<SaltString> {
    let key_salt = helpers::encode_b64(key_to_hash)?;
    let key_salt =
        SaltString::from_b64(&key_salt).map_err(|e| VaultError::create(e.to_string()))?;
    Ok(key_salt)
}

fn create_profile_container(
    profile_key: &String,
    auth_key_phc: String,
    is_active: bool,
    profile: &Vec<u8>,
) -> VaultResult<ProfileContainer> {
    let container = ProfileContainer {
        key: profile_key.to_owned(),
        auth_key_phc: auth_key_phc,
        is_active: is_active,
        secure_info: profile.to_owned(),
    };
    Ok(container)
}

fn save_profile(container: &ProfileContainer) -> VaultEmptyResult {
    let store_manager = CURRRENT_STORE.get();
    store_manager.try_add_profile(&container)?;

    Ok(())
}

fn new_profile_key() -> VaultResult<(String, Vec<u8>)> {
    let profile_key = Uuid::new_v4().to_string();
    //let profile_key = uuid::uuid!("67e55044-10b1-426f-9247-bb680e5fe0c8").to_string();
    let hash = cipher::try_hash_with_sha3_256(profile_key.as_bytes())?;
    Ok((profile_key, hash))
}
