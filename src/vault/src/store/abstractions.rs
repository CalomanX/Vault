use std::path::PathBuf;

use crate::abstractions::{Result, EmptyResult};

use super::memory_store::MemoryStore;



pub(crate) trait IStore: Sized {
    fn ensure_init(&self) -> EmptyResult;

    // fn try_open(&self) -> EmptyResult;

    // fn try_close(&self) -> EmptyResult;

    // fn try_read(&self, key: &str) -> Result<Option<Vec<u8>>>;

    // fn try_write(&self, key: &String, record: &Vec<u8>) -> EmptyResult;

    // fn try_remove(&self, key: &str) -> EmptyResult;

    // fn try_init_vault(&self, root_value: &str) -> EmptyResult;

    // fn try_add_profile(&self, profile: &Profile) -> EmptyResult;

    // fn try_list_profiles(&self) -> Result<Vec<Profile>>;

    // fn try_get_profile_with_key(&self, profile_key: &str) -> Result<Option<Profile>>;

    // fn try_get_root_key(&self) -> Result<Option<Vec<u8>>>;

    // fn try_update_profile_with_key(&self, profile_key: &str, data: &Vec<u8>) -> EmptyResult;
}





#[derive(Debug, Clone)]
pub(crate) struct StoreProperties {
    pub(crate) default_store: StoreType,
    pub(crate) path: PathBuf
}

impl Default for StoreContainer {
    fn default() -> Self {
        let properties = StoreProperties { default_store: StoreType::Memory, path: PathBuf::default()};
        let store = MemoryStore { properties };
        Self::Memory(store)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StoreType {
    Memory,
    Disk,
}


#[derive(Debug, Clone)]
pub(crate) enum StoreContainer {
    Memory(MemoryStore),
    // Disk(DiskStore),
}

