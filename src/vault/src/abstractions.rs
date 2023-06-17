use core::fmt;

pub type VaultResult<T> = std::result::Result<T, VaultError>;
pub type VaultEmptyResult = VaultResult<()>;
pub type B64String = String; 

#[derive(Debug)]
pub struct VaultError {
    message: Option<String>
}

impl From<Box<dyn std::error::Error>> for VaultError {


    fn from(value: Box<dyn std::error::Error>) -> Self {
        let msg = value.to_string();
        let ve = VaultError::create(msg);
        ve
    }
}

impl VaultError {

    pub fn new() -> VaultError {
        let ve = VaultError {
            message: None
        };
        ve
    }

    pub fn create(message: String) -> VaultError {
        let ve = VaultError {
            message: Some(message)
        };
        ve
    }

    pub fn get_message(self) -> Option<String> {
        self.message
    }

    pub fn set_message(mut self, message: String) {
        self.message = Some(message);
    }
}


impl From<&str> for VaultError {
    fn from(value: &str) -> Self {
        VaultError::create(value.to_string())
    }
}
impl From<String> for VaultError {
    fn from(value: String) -> Self {
        VaultError::create(value)
    }
}
impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         write!(f, "Vault Error is '{:?}'", self.message)
     }
 }

impl std::error::Error for VaultError {
}



