#[cfg(test)]
mod tests {
    use crate::{store::abstractions::StoreType, profile::{Profile}, scope::Scope, abstractions::VaultResult};

    fn get_new_vault_internal() -> (String, String) {
        let (admin_profile_key, admin_auth_key) = match crate::init_vault("abracadabra", StoreType::Memory, None) {
            Ok(v) => v,
            Err(e) => {
                println!("Error {:?}", e);
                panic!("Crap!");
            },
        };
        (admin_profile_key, admin_auth_key)
    }

    fn get_new_profile_internal(admin_profile_key: &String, admin_auth_key: &String) -> (String, String, VaultResult<Profile>) {
        let (profile_key, auth_key) = crate::new_profile(admin_profile_key, admin_auth_key, "abracadabra", "Profile1", "profile1password").unwrap_or_default();
        let profile = Profile::get_with_key(&profile_key, &auth_key);
        (profile_key, auth_key, profile)
    }

    fn get_new_scope_internal(profile_key: &String, auth_key: &String) -> (String, VaultResult<Scope>) {
        let scope_key = crate::new_scope(profile_key.as_str(), auth_key.as_str(), "profile1password").unwrap();
        
        let scope = Scope::get_with_key(profile_key, auth_key, &scope_key);
        (scope_key, scope)
    }


    #[test]
    fn init_a_new_vault() {
        let r = crate::init_vault("abracadabra", StoreType::Memory, None);
    
        let keys = match r {
            Ok(v) => v,
            Err(e) => return assert!(e.get_message().is_none(), "DAMM"),
        };    
  

        let p = Profile::get_with_key(&keys.0, &keys.1).unwrap();

        // println!("Profile name is {:?}", p.name);

        assert_eq!(p.name, "Admin");
    }



    #[test]
    fn create_new_profile() {

        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();
        
        let (profile_key, auth_key) = crate::new_profile(&admin_profile_key, &admin_auth_key, "abracadabra", "Profile1", "profile1password").unwrap_or_default();
        
        let profile = Profile::get_with_key(&profile_key, &auth_key);

        assert!(profile.is_ok());
        
        let profile = profile.unwrap();

        assert_eq!(profile.key, profile_key, "Profile key is different!");
    }

    #[test]
    fn list_profiles() {
        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();
        
        let (profile1_key, auth_key1) = crate::new_profile(&admin_profile_key, &admin_auth_key, "abracadabra", "Profile1", "profile1password").unwrap_or_default();
        let (profile_key2, auth_key2) = crate::new_profile(&admin_profile_key, &admin_auth_key, "abracadabra", "Profile2", "profile2password").unwrap_or_default();
        
        let profiles = crate::try_list_profiles(&admin_profile_key, &admin_auth_key, "abracadabra");
        assert!(profiles.is_ok());
        let profiles = profiles.unwrap();
        
        // println!("{:?}", profiles);
    }

    


    #[test]
    fn delete_profile() {
        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();


        let (profile_key, auth_key, profile) = get_new_profile_internal(&admin_profile_key, &admin_auth_key);

        crate::delete_profile(&profile_key, &auth_key, "profile1password").unwrap();
        
        let profile = Profile::get_with_key(&profile_key, &auth_key);

        assert!(profile.is_err());
        
    }


    #[test]
    fn create_new_scope() {

        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();

        let (profile_key, auth_key, profile) = get_new_profile_internal(&admin_profile_key, &admin_auth_key);

        let scope_key = crate::new_scope(profile_key.as_str(), auth_key.as_str(), "profile1password");

        assert!(scope_key.is_ok());
        
        let scope_key = scope_key.unwrap();

        // assert_eq!(profile.key, profile_key, "Profile key is different!");
    }


    #[test]
    fn get_scope() {
        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();

        let (profile_key, auth_key, profile) = get_new_profile_internal(&admin_profile_key, &admin_auth_key);

        let scope_key = crate::new_scope(profile_key.as_str(), auth_key.as_str(), "profile1password").unwrap();
        
        let scope = Scope::get_with_key(&profile_key, &auth_key, &scope_key);

        assert!(scope.is_ok());
        let scope = scope.unwrap();
        assert_eq!(scope.key, scope_key, "Scope keys are different.");
    }


    #[test]
    fn list_scopes() {
        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();

        let (profile_key, auth_key, profile) = get_new_profile_internal(&admin_profile_key, &admin_auth_key);

        let scope_key1 = crate::new_scope(profile_key.as_str(), auth_key.as_str(), "profile1password").unwrap();
        let scope_key2 = crate::new_scope(profile_key.as_str(), auth_key.as_str(), "profile1password").unwrap();
        
        let scopes = crate::try_list_profile_scopes(&profile_key, &auth_key, "profile1password");

        assert!(scopes.is_ok());
        let mut scopes = scopes.unwrap();

        // println!("{:?}", scopes);                
        
        let sk2 = scopes.pop().unwrap();
        let sk1 = scopes.pop().unwrap();
        // println!("{:?} = {:?}; {:?} = {:?}", sk2, scope_key2, sk1, scope_key1);   
        assert_eq!(sk2, scope_key2, "Scope keys are different.");
        assert_eq!(sk1, scope_key1, "Scope keys are different.");

    }


    #[test]
    fn delete_scope() {
        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();

        let (profile_key, auth_key, profile) = get_new_profile_internal(&admin_profile_key, &admin_auth_key);

        let scope_key = crate::new_scope(profile_key.as_str(), auth_key.as_str(), "profile1password").unwrap();
        
        let scope = Scope::get_with_key(&profile_key, &auth_key, &scope_key);

        crate::delete_scope(&profile_key, &scope_key, &auth_key, "profile1password").unwrap();
        
        let r = Scope::get_with_key(&profile_key, &auth_key, &scope_key);

        assert!(r.is_err());
        
    }

    #[test]
    fn create_new_secret() {

        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();

        let (profile_key, auth_key, profile) = get_new_profile_internal(&admin_profile_key, &admin_auth_key);

        let (scope_key, scope) = get_new_scope_internal(&profile_key, &auth_key);

        let secret_key = crate::new_secret(&profile_key, &scope_key, &auth_key, "profile1password", "my secret!", None);

        assert!(secret_key.is_ok());

        let secret_key = secret_key.unwrap();
        
    }


    #[test]    
    fn get_secret() {

        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();

        let (profile_key, auth_key, profile) = get_new_profile_internal(&admin_profile_key, &admin_auth_key);

        let (scope_key, scope) = get_new_scope_internal(&profile_key, &auth_key);

        let secret_key = crate::new_secret(&profile_key, &scope_key, &auth_key, "profile1password", "my secret!", None).unwrap();

        let secret = crate::get_secret_with_key(&profile_key, &scope_key, &auth_key, &secret_key);

        assert!(secret.is_ok());

        let secret = secret.unwrap();
        assert!(profile_key == secret.owner_profile_key, "Profile keys are different.");
        assert!(scope_key == secret.owner_scope_key, "Scope keys are different.");
        assert!(secret_key == secret.key, "Keys keys are different.");
        assert!("my secret!" == secret.value, "Secre value do not match!");
       
    }

    #[test]    
    fn delete_secret() {

        let (admin_profile_key, admin_auth_key) = get_new_vault_internal();

        let (profile_key, auth_key, profile) = get_new_profile_internal(&admin_profile_key, &admin_auth_key);

        let (scope_key, scope) = get_new_scope_internal(&profile_key, &auth_key);

        let secret_key = crate::new_secret(&profile_key, &scope_key, &auth_key, "profile1password", "my secret!", None).unwrap();


        let r = crate::try_delete_secret(&profile_key, &secret_key, &auth_key, "profile1password");
        assert!(r.is_ok());        
        
        let r = crate::get_secret_with_key(&profile_key, &scope_key, &auth_key, &secret_key);
        assert!(r.is_err());      

       
    }



}