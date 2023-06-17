# Data Structures

```plantuml
struct Vault {

}


struct Locker {
    keys: Map<access_key, Lock>
}
note right of Locker::keys
    Accesskey is the profile 
    access key provided by the user
end note

struct CipherKey<T> {
    nonce: byte[],
    T: Target
}

struct Lock {
    access_key: string
    is_active: bool
    profile_key: CipherKey<Profile>
}

struct Profile {
    access_key: string
    name: string    
    scopes: Map<access_key, CipherKey<Scope>>
    is_admin: bool
}
note right of Profile::is_admin
When true signals as the administrative profile
end note

struct Scope {
    access_key: string
    name: string 
    secrets: Map<access_key, CipherKey<Secret>>
}
note right of Scope::secrets 
    The string mapping will match
    the accesskey on every Secret
end note

struct Secret {
    access_key: string
    data: string
}

note right of Secret::data 
    JSON representation of an object
end note

Vault "1" *-- "*" Profile
Vault *-- Locker
Locker "1" *-- "*" Lock
Profile "1" *-- "*" Scope : scopes:access_key <-> access_key
Lock "1" -- "1" Profile : profile_access_key <-> access_key
Scope "1" *-- "*" Secret : secrets:access_key <-> access_key
```
