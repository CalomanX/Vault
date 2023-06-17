use std::{collections::HashMap, iter::FilterMap};
use super::{abstractions::{IStore, IStoreInitializer, StoreProperties}, store_manager::CURRRENT_STORE};
use crate::{abstractions::{VaultResult, VaultEmptyResult, VaultError,}, profile::ProfileContainer, scope::ScopeContainer, secret::{SecretContainer, Secret}};


// #[derive(Debug, Clone)]
// pub(crate) struct Scope {
//     pub(crate) key: String,
//     pub(crate) name: String,
//     pub(crate) is_active: bool
// }
// #[derive(Debug, Clone)]
// pub(crate) struct ScopeContainer
// {
//     pub(crate) owner : Option<Scope>,
//     pub(crate) owner_as_cipher: Vec<u8>,
//     pub(crate) childreen: std::collections::HashMap<String, SecretContainer>
// }    


// #[derive(Debug, Clone)]
// pub(crate) struct Secret {
//     pub(crate) key: String,
//     pub(crate) is_active: bool,
//     pub(crate) secret: Vec<u8>
// }
// #[derive(Debug, Clone)]
// pub(crate) struct SecretContainer
// {
//     pub(crate) owner : Option<Secret>,
//     pub(crate) owner_as_cipher: Vec<u8>
// }    





#[derive(Debug, Clone)]
pub(crate) struct MemoryStore {

    pub(self) profiles: HashMap<String, ProfileContainer>,
    pub(self) scopes: HashMap<String, ScopeContainer>,
    pub(self) secrets: HashMap<String, SecretContainer>
}

impl MemoryStore {

    // pub(self) fn try_add_profile_internal(&mut self, profile_container: &ProfileContainer) -> VaultEmptyResult {
    //     let container = profile_container.to_owned();
    //     self.profiles.insert(container.key.clone(), container);
    //     Ok(())
    // }

}


impl IStore for MemoryStore {

    fn try_add_profile(&mut self, profile_container: &ProfileContainer) -> VaultEmptyResult {
        let container = profile_container.to_owned();
        let key = container.key.clone();      
        self.profiles.insert(key, container);
        Ok(())
    }


    fn try_get_profile(&self, key: &str) -> VaultResult<ProfileContainer> {
        let container = match self.profiles.get(key){
            Some(c) => c,
            None => return Err(VaultError::from("No profile found.")),
        };
        Ok(container.to_owned())
    }

    fn try_delete_profile(&mut self, key: &str) -> VaultEmptyResult {

        let filtered: Vec<String> = self.secrets.iter()
            .filter_map(| (_, value) | match value.owner_profile_key.as_str() == key {
                true => Some(value.key.clone()),
                false => None,
            }).collect();
        for item in filtered {
            self.secrets.remove(&item);
        }

        let filtered: Vec<String> = self.scopes.iter()
            .filter_map(| (_, value) | match value.owner_profile_key.as_str() == key {
                true => Some(value.key.clone()),
                false => None,
            }).collect();
            for item in filtered {
                self.scopes.remove(&item);
            }
        self.profiles.remove(key);

        Ok(())
    }    
    
    fn try_get_password_phc(&self, key: &str) -> VaultResult<String> {
        let profile = self.try_get_profile(key)?;
        Ok(profile.auth_key_phc)
    }

    fn try_add_scope(&mut self, scope: &crate::scope::ScopeContainer) -> VaultEmptyResult {
        let container = scope.to_owned();
        self.scopes.insert(scope.key.clone(), container);
        Ok(())
    }

    fn try_get_scope(&self, key: &str) -> VaultResult<ScopeContainer> { 
        let scope_container = match self.scopes.get(key) {
            Some(sc) => sc,
            None => return Err(VaultError::from("No scope found.")), 
        };
        Ok(scope_container.to_owned())
    }

    fn try_delete_scope(&mut self, key: &str) -> VaultEmptyResult {

        let filtered: Vec<String> = self.scopes.iter()
            .filter_map(| (_, value) | match value.owner_profile_key.as_str() == key {
                true => Some(value.key.clone()),
                false => None,
            })
            .collect();

            for item in filtered 
            { 
                self.scopes.remove(&item); 
            }

        self.scopes.remove(key);

        Ok(())
    }

    fn try_add_secret(&mut self, secret: &crate::secret::SecretContainer) -> VaultEmptyResult {
        let container = secret.to_owned();
        self.secrets.insert(secret.key.to_string(), container);
        Ok(())
    }

    fn try_get_secret(&self, secret_key: &str) -> VaultResult<SecretContainer> {
        let secret_container = match self.secrets.get(secret_key) {
            Some(sc) => sc,
            None => return Err(VaultError::from("No secret found.")), 
        };
        Ok(secret_container.to_owned())   
    }

    fn try_delete_secret(&mut self, key: &str) -> VaultEmptyResult {
        self.secrets.remove(key);
        Ok(())
    }

    fn try_get_all_profiles(&self) -> VaultResult<Vec<ProfileContainer>> {
        let profiles= self.profiles
            .values()
            .map(| pc | pc.clone())
            .collect();
        Ok(profiles)
    }

    fn try_get_all_profile_scopes(&self, profile_key: &str) -> VaultResult<Vec<ScopeContainer>> {
        let scopes: Vec<ScopeContainer> = self.scopes
            .values()
            .filter_map(| sc | match &sc.owner_profile_key == profile_key {
                true => Some(sc.clone()),
                false => None,
            })
            .collect();
        Ok(scopes)
    }

    fn try_get_all_scope_secrets(&self, profile_key:&str, scope_key:&str) -> VaultResult<Vec<SecretContainer>> {
        let secrets: Vec<SecretContainer> = self.secrets.values()
            .filter_map(| sec | match sec.owner_profile_key == profile_key && sec.owner_scope_key == scope_key {
                true => Some(sec.to_owned()),
                false => None,
            })
            .collect();
        Ok(secrets)
    }


    // fn try_get_all_profile_scopes(&self, profile_key: &str) -> VaultResult<Vec<ScopeContainer>> {
    //     todo!()
    // }




}

impl IStoreInitializer for MemoryStore {

    fn try_init(properties: &StoreProperties) -> VaultResult<Self> {
        let store = MemoryStore { 
            profiles: HashMap::new(),
            scopes: HashMap::new(),
            secrets: HashMap::new()
         };

        Ok(store)
    }
    fn ensure_no_store(_target: Option<&str>) -> bool {
        true
    }
}

