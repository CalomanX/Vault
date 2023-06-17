# How to create a new Vault

```plantuml
start
:input **AdminPassword**, VaultType and Target;/
if (params are invalid?) then (yes)
    #red: error;
    stop
endif
if (vault exists) then (yes)
    #red:error;
    stop
endif
:Generate the **Salt** from the **AdminPassword**;
:Use Argon2 to PasswordHash(key:**AdminPassword**, salt:**Salt**) into **AdminKey**;
:Generate the **UserSystemKey** from the **AdminKey**;
:Generate a Random Byte[] as **nonce**;
:Create a AdminProfile = new Profile(
    access_key: **AdminKey**,
    nome: "Adminsitrative Profile",
    is_admin: true
    );
:Cipher the AdminProfile with (Key=**AdminKey**, nonce=**nonce** 
and aead=**UserSystemKey**);
:Store the AdminProfile<
:Create a new Lock(
    access_key: **AdminKey**,
    is_active: true,
    profile_key = new CipherKey<Profile>(
        nonce: **nonce**, 
        profile: AdminProfile
    );

:Store the lock<
end
```
