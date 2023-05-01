pub mod abstractions;
pub(crate) mod store;

/// Initializes a new Vault
/// 
/// Will initialize a new Vault for a specific machine/path
/// 
/// ### Use Case
/// 
/// #### Args
/// 
/// | Arg | Type | R | Comment |
/// |---|---|---|---|
/// | secret    | &str | X  | A secret password|
/// | store_type| &str | X  | The type of store to create |
/// | target    | &str |    | The path and file name for the target vault or other form
///  
/// 1. If the user is NOT an administrator of the local machine or there is already a vault at target or the secret is empty, should throw error and terminate;
/// 2. Generate the SystemKey = Hash(Environment)
/// 3. Generate the AdminKey = KeyDerivate(secret)
/// 4. Create the AdminProfile and Store the AdminKey;
/// 5. Cipher the AdminProfile with the SystemKey;  
pub fn init_vault(secret: &str, storeType:&str, target: &str) {

}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_a_new_vault() {



    }
}
