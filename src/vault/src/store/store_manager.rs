use std::sync::RwLock;

use crate::{
    abstractions::{VaultEmptyResult, VaultError, VaultResult},
    profile::ProfileContainer,
    scope::ScopeContainer, secret::SecretContainer,
};

use super::{
    abstractions::{IStore, IStoreInitializer, StoreProperties, StoreType},
    memory_store::{self, MemoryStore},
};

pub(crate) static CURRRENT_STORE: state::Storage<StoreManager> = state::Storage::new();

pub(crate) struct StoreManager {
    pub(crate) store_provider: RwLock<StoreProvider>,
    pub(crate) properties: StoreProperties,
    pub(crate) is_initialized: bool,

    pub(crate) cache: Option<RwLock<Box<dyn IStore>>>,
}

impl StoreManager {
    pub(crate) fn try_init<'a>(mut properties: StoreProperties) -> VaultResult<&'a StoreManager> {
        let mut sm = CURRRENT_STORE.try_get();
        if sm.is_none() {
            properties.date_created = chrono::Utc::now();
            let store = match properties.store_type {
                super::abstractions::StoreType::Memory => {
                    memory_store::MemoryStore::try_init(&properties)?
                }
                super::abstractions::StoreType::Disk => todo!(),
            };
            let store_provider = match properties.store_type {
                StoreType::Memory => StoreProvider::Memory(MemoryStore::try_init(&properties)?),
                StoreType::Disk => todo!(),
            };
            let manager = StoreManager {
                properties: properties,
                store_provider: RwLock::<StoreProvider>::new(store_provider),
                cache: None,
                is_initialized: true,
            };
            CURRRENT_STORE.set(manager);
            sm = Some(CURRRENT_STORE.get());
        }
        let manager = sm.unwrap();

        Ok(manager)
    }

    pub(crate) fn ensure_no_Store(store_type: StoreType, target: Option<&str>) -> bool {
        let no_store = match store_type {
            StoreType::Memory => MemoryStore::ensure_no_store(target),
            StoreType::Disk => todo!(),
        };

        no_store
    }

    fn get_target<'a>() -> &'a Option<String> {
        let store = unsafe { CURRRENT_STORE.get() };
        let info = &store.properties.target;
        info
    }

    fn get_creation_date() -> Option<chrono::NaiveDateTime> {
        todo!()
    }

    pub(crate) fn try_add_profile(&self, profile_container: &ProfileContainer) -> VaultEmptyResult {
        let mut store_provider = self.store_provider.try_write().map_err(|e| VaultError::from(e.to_string()))?;
        let store = store_provider.get_mut_store();
        store.try_add_profile(profile_container)
    }



    pub(crate) fn try_get_profile(&self, key: &str) -> VaultResult<ProfileContainer> {
        let store_provider = self.store_provider.try_read().map_err(|e| VaultError::from(e.to_string()))?;
        let store = store_provider.get_store();
        let container = store.try_get_profile(key);
        container
    }

    // pub(crate) fn try_get_profile_password_phc(&self, key: &str) -> VaultResult<String> {
    //     let store_provider = self.store_provider.try_read().map_err(|e| VaultError::from(e.to_string()))?;
    //     let store = store_provider.get_store();
    //     let container = store.try_get_profile(key)?;
    //     Ok(container.auth_key_phc)
    // }

    pub(crate) fn try_add_scope(&self, scope: &crate::scope::ScopeContainer) -> VaultEmptyResult {
        let mut store_provider = self
            .store_provider
            .try_write()
            .map_err(|e| VaultError::from(e.to_string()))?;
        let store = store_provider.get_mut_store();
        store.try_add_scope(&scope)
    }

    pub(crate) fn try_get_scope(&self, scope_key: &str) -> VaultResult<ScopeContainer> {
        let store_provider = self
            .store_provider
            .try_read()
            .map_err(|e| VaultError::from(e.to_string()))?;
        let store = store_provider.get_store();
        store.try_get_scope(scope_key)
    }

    pub(crate) fn try_delete_scope(&self, scope_key: &str) -> VaultEmptyResult {
        let mut store_provider = self
            .store_provider
            .try_write()
            .map_err(|e| VaultError::from(e.to_string()))?;
        let store = store_provider.get_mut_store();
        store.try_delete_scope(scope_key)
    }



    pub(crate) fn try_add_secret(&self, secret: &crate::secret::SecretContainer) -> VaultEmptyResult {

        let mut store_provider = self
            .store_provider
            .try_write()
            .map_err(|e| VaultError::from(e.to_string()))?;

        let store = store_provider.get_mut_store();
        store.try_add_secret(secret)

    }

    pub(crate) fn try_get_secret(&self, secret_key: &str) -> VaultResult<SecretContainer> {
        let store_provider = self.store_provider.try_read().map_err(|e| VaultError::from(e.to_string()))?;
        let store = store_provider.get_store();
        store.try_get_secret(secret_key)
    }

    pub(crate) fn try_delete_profile(&self, profile_key: &str) -> VaultEmptyResult {
        let mut store_provider = self.store_provider.try_write().map_err(|e| VaultError::from(e.to_string()))?;
        let store = store_provider.get_mut_store();
        store.try_delete_profile(profile_key)
    }

    pub(crate) fn try_get_all_profiles(&self) -> VaultResult<Vec<ProfileContainer>> {
        let store_provider = self.store_provider.try_read().map_err(|e| VaultError::from(e.to_string()))?;
        let store = store_provider.get_store();
        store.try_get_all_profiles()
    }

    pub(crate) fn try_get_profile_scopes(&self, profile_key: &str) -> VaultResult<Vec<ScopeContainer>> {
        let sp = self.store_provider.try_read().map_err(|e| VaultError::from(e.to_string()))?;
        let store = sp.get_store();
        let scopes = store.try_get_all_profile_scopes(profile_key)?;
        Ok(scopes)
    }

    pub(crate) fn try_get_all_scope_secrets(&self, profile_key:&str, scope_key:&str) -> VaultResult<Vec<SecretContainer>> {
        let sp = self.store_provider.try_read().map_err(|e| VaultError::from(e.to_string()))?;
        let store = sp.get_store();
        store.try_get_all_scope_secrets(profile_key, scope_key)
    }
    pub fn try_delete_secret(&self, secret_key: &str) -> VaultEmptyResult {
        let mut sp = self.store_provider.try_write().map_err(|e| VaultError::from(e.to_string()))?;
        let mut store = sp.get_mut_store();    
        store.try_delete_secret(secret_key)
    }

}

pub(crate) enum StoreProvider {
    Memory(MemoryStore),
}

impl StoreProvider {
    pub(crate) fn get_mut_store(&mut self) -> &mut dyn IStore {
        match self {
            StoreProvider::Memory(m) => m,
        }
    }
    pub(crate) fn get_store(&self) -> &dyn IStore {
        match self {
            StoreProvider::Memory(m) => m,
        }
    }

    pub(crate) fn get_memory_store(&self) -> Option<&MemoryStore> {
        match self {
            StoreProvider::Memory(m) => Some(m),
            _ => None,
        }
    }
}
