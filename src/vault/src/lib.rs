#[unit_tests("lib.rs")]

use abstractions::{VaultResult, VaultEmptyResult, VaultError};


use chrono::{Utc, DateTime};

use profile::{Profile, ProfileContainer};
use secret::Secret;
use store::{abstractions::{StoreType, StoreProperties, IStore}, store_manager::{StoreManager, CURRRENT_STORE}};

use tests_bin::unit_tests;

use crate::scope::Scope;

pub mod abstractions;
pub mod store;
mod cipher;
pub mod profile;
pub mod scope;
pub mod helpers;
mod authentication;
mod secret;
mod information_sources;


pub fn init_vault(password: &str, store_type:crate::store::abstractions::StoreType, target: Option<&str>) -> VaultResult<(String, String)>  {

    if password.is_empty() || password.contains(char::is_whitespace) {
        return Err(VaultError::create("Password is invalid.".to_string()));
    }

    if !crate::store::store_manager::StoreManager::ensure_no_Store(store_type, target) {
        return  Err(VaultError::create("A new store is not possible for the target.".to_string()));
    }

    let store_props = StoreProperties {
        default_store: StoreType::default(),
        store_type: store_type,
        target: match target {
            Some(t) => Some(t.to_string()),
            None => None,
        },
        date_created: Utc::now()
    };

    StoreManager::try_init(store_props)?;


    let key_auth = profile::Profile::new_master(password)?;


    Ok(key_auth)
}


pub fn new_profile(admin_profile_key: &str, admin_auth_key: &str, admin_password: &str, profile_name: &str, profile_password: &str) -> VaultResult<(String, String)> {
    profile::Profile::new(admin_profile_key, admin_auth_key, admin_password, profile_name, profile_password)
}

pub fn get_profile_with_key(key: &str, auth_key: &str) -> VaultResult<Profile> {
    Profile::get_with_key(key, auth_key)
}

fn delete_profile(profile_key: &str, auth_key: &str, password:&str) -> VaultEmptyResult {
    Profile::delete(profile_key, auth_key, password)
}

pub fn new_scope(profile_key: &str, auth_key: &str, profile_password: &str) -> VaultResult<String> {
    Scope::new(profile_key, auth_key, profile_password, "Scope1")
}

fn delete_scope(profile_key: &str, scope_key: &str, auth_key: &str, password: &str) -> VaultEmptyResult {
    Scope::try_delete(profile_key, scope_key, auth_key, password)
}

pub fn new_secret(profile_key: &str, scope_key: &str, auth_key: &str, password: &str, value: &str, expire_date: Option<DateTime<Utc>>) -> VaultResult<String> {
    Secret::new(profile_key, scope_key, auth_key, password, value, expire_date)
}

pub fn get_secret_with_key(profile_key: &str, scope_key: &str, auth_key: &str, secret_key: &str) -> VaultResult<Secret> {
    Secret::get_with_key(profile_key, scope_key, auth_key, secret_key)
}

pub fn try_delete_secret(profile_key: &str, secret_key: &str, auth_key: &str, password:&str) -> VaultEmptyResult {
    Secret::try_delete(profile_key, secret_key, auth_key, password)
}

pub fn try_list_profiles(admin_profile_key: &str, admin_auth_key: &str, password: &str) -> VaultResult<Vec<String>> {
    let list = Profile::try_list(admin_profile_key, admin_auth_key, password)?;
    let list: Vec<String> = list.iter()
        .map(| pc | pc.key.clone())
        .collect();

    Ok(list)
}

pub fn try_list_profile_scopes(profile_key: &str, auth_key: &str, password: &str) -> VaultResult<Vec<String>> {
    let list = Scope::try_list(profile_key, auth_key, password)?;
    let list: Vec<String> = list.iter()
        .map(|scope| scope.key.to_string())
        .collect();

    Ok(list)
}










