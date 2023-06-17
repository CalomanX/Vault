use crate::{
    abstractions::{VaultEmptyResult, VaultError},
    cipher::{self, try_derive_password, try_hash_with_sha3_256},
    helpers,
    profile::{Profile},
};

pub(crate) fn ensure_user_is_admin(
    admin_profile_key: &str,
    admin_auth_key: &str,
    admin_password: &str
) -> VaultEmptyResult {
    let profile_key_hash = cipher::try_hash_with_sha3_256(admin_profile_key.as_bytes())?;
    let system_key = helpers::try_prepare_system_key(&profile_key_hash)?;
    let password = try_derive_password(admin_password, &system_key.as_slice())?;

    match Profile::get_with_key(admin_profile_key, admin_auth_key) {
        Ok(p) => {
            if admin_profile_key == p.key && p.is_master {
                if cipher::password_is_valid(&password, &system_key, &p.password_phc) {
                    return Ok(());
                }
            }
        }
        Err(_) => (),
    };
    Err(VaultError::from("Invalid credentials."))
}

pub(crate) fn ensure_user_is_owner(
    profile_key: &str,
    auth_key: &str,
    clear_password: &str
) -> VaultEmptyResult {

    let key_hash = try_hash_with_sha3_256(profile_key.as_bytes())?;
    let system_key = helpers::try_prepare_system_key(&key_hash)?;    
    let normalized_password = try_derive_password(clear_password, &system_key)?;

    match Profile::get_with_key(profile_key, auth_key) {
        Ok(p) => {
            if profile_key == p.key {
                if cipher::password_is_valid(&normalized_password, &system_key, &p.password_phc) {
                    return Ok(());
                }
            }
        }
        Err(_) => (),
    };
    Err(VaultError::from("Invalid credentials."))
}
