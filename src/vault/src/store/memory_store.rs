use state::Storage;

use super::abstractions::{IStore, StoreProperties};

#[derive(Debug, Clone)]
pub(crate) struct MemoryStore {
    pub(crate) properties: StoreProperties,
}

impl IStore for MemoryStore {
    fn ensure_init(&self) -> crate::abstractions::EmptyResult {
        todo!()
    }
}

pub(crate) fn init(properties: StoreProperties) -> MemoryStore {
    let store = MemoryStore { properties };
    store
}
