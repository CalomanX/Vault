pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub type EmptyResult = Result<()>;

use chrono::NaiveDateTime;

struct Secret {
    created: NaiveDateTime,
    last_access: NaiveDateTime,
    payload: Vec<u8>
}

struct Scope {
    created: NaiveDateTime,
    last_access: NaiveDateTime,
    secrets: Vec<Secret>
}

struct Profile {
    created: NaiveDateTime,
    last_access: NaiveDateTime,
    secrets: Vec<Scope>
}

struct Vault {
    created: NaiveDateTime,
    last_access: NaiveDateTime,
    profiles: Vec<Scope>    
}


