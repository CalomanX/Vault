mod abstractions;
mod memory_store;
use state::Storage;

use self::{abstractions::{IStore, StoreProperties, StoreContainer}, memory_store::MemoryStore};

static CURRENT: Storage<StoreContainer> = Storage::new();

fn init(properties: StoreProperties) {
    let store = match properties.default_store {
        abstractions::StoreType::Memory => StoreContainer::Memory(memory_store::init(properties)),
        abstractions::StoreType::Disk => todo!(),
    };

    CURRENT.set(store);

} 


