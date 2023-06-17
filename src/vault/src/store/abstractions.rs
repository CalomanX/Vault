
use crate::{VaultResult, profile::{ProfileContainer}, scope::ScopeContainer, secret::SecretContainer,};
use chrono::{DateTime, Utc};

use crate::VaultEmptyResult;

use super::memory_store::MemoryStore;


pub(crate) trait IStoreInitializer {
    fn ensure_no_store(target: Option<&str>) -> bool;
    fn try_init(properties: &StoreProperties) -> VaultResult<MemoryStore>;
}


pub(crate) trait IStore: Send + Sync + 'static {


    fn try_add_profile(&mut self, profile_container: &ProfileContainer) -> VaultEmptyResult;

    fn try_get_profile(&self, key: &str) -> VaultResult<ProfileContainer>;

    fn try_get_all_profiles(&self) -> VaultResult<Vec<ProfileContainer>>;

    fn try_delete_profile(&mut self, key: &str) -> VaultEmptyResult;
    
    fn try_get_password_phc(&self, key: &str) -> VaultResult<String>;

    fn try_add_scope(&mut self, scope: &crate::scope::ScopeContainer) -> VaultEmptyResult;

    fn try_get_scope(&self, key: &str) -> VaultResult<ScopeContainer>;

    fn try_get_all_profile_scopes(&self, profile_key: &str) -> VaultResult<Vec<ScopeContainer>>;

    fn try_delete_scope(&mut self, key: &str) -> VaultEmptyResult;

    fn try_add_secret(&mut self, secret: &crate::secret::SecretContainer) -> VaultEmptyResult;

    fn try_get_secret(&self, secret_key: &str) -> VaultResult<SecretContainer>; 

    fn try_delete_secret(&mut self, key: &str) -> VaultEmptyResult;

    fn try_get_all_scope_secrets(&self, profile_key:&str, scope_key:&str) -> VaultResult<Vec<SecretContainer>>;

}




#[derive(Debug, Clone)]
pub(crate) struct StoreProperties {
    pub(crate) default_store: StoreType,
    pub(crate) store_type: StoreType,
    pub(crate) target: Option<String>,
    pub(crate) date_created: DateTime<Utc>
}




#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreType {
    Memory,
    Disk,
}

impl From<&String> for StoreType {
    fn from(value: &String) -> Self {
        match value.to_lowercase().as_str() {
            "disk" => StoreType::Disk,
            _=> StoreType::Memory
        }
    }
}

impl Default for StoreType {
    fn default() -> Self {
        StoreType::Memory
    }
}


