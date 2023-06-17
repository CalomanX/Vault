use std::{str::{self}};

use crate::information_sources::{
        abstractions::{CpuInfo, SysInfo},
        sys_information_souce,
    };
use crate::{
    store::store_manager::CURRRENT_STORE, abstractions::{VaultResult, VaultError}, helpers::{encode_b64, self},
};

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, Salt},
    Argon2, ParamsBuilder,
};
use chacha20poly1305::{
    aead::{rand_core::RngCore, Aead, KeyInit, OsRng, Payload},
    ChaCha20Poly1305, Nonce,
};
use password_hash::{SaltString, PasswordVerifier};
use sha3::{Digest, Sha3_256};
use sysinfo::SystemExt;

pub const DEFAULT_KEY_SIZE_IN_BYTES: usize = 32;
pub const CHACHAPOLY1305_NONCE_SIZE_IN_BYTES: usize = 12;
pub const CHACHAPOLY1305_KEY_SIZE_IN_BYTES: usize = 32;
pub const ARGON2_SALT_RECOMENDED_LEN: usize = Salt::RECOMMENDED_LENGTH;

macro_rules! enum_from_u8 {
    ($(#[$meta:meta])* $vis:vis enum $name:ident {
        $($(#[$vmeta:meta])* $vname:ident $(= $val:expr)?,)*
    }) => {
        $(#[$meta])*
        $vis enum $name {
            $($(#[$vmeta])* $vname $(= $val)?,)*
        }

        impl std::convert::TryFrom<u8> for $name {
            type Error = ();

            fn try_from(v: u8) -> core::result::Result<Self, Self::Error> {
                match v {
                    $(x if x == $name::$vname as u8 => Ok($name::$vname),)*
                    _ => Err(()),
                }
            }
        }
    }
}

impl TryFrom<SystemKeyOptions> for i32 {
    type Error = ();

    fn try_from(value: SystemKeyOptions) -> std::result::Result<Self, Self::Error> {
        Ok(value as i32)
    }
}

enum_from_u8! {
    enum SystemKeyOptions {
        PathFileName  = 0,
        DateCreation   ,
        CpuName        ,
        CpuVendorId   ,
        CpuBrand       ,
        CpuFrequency   ,
        SystemName     ,
        SystemHostname ,
    }

}

/// Make a key ciphered by merging ato keys
pub(crate) fn merge_key(key1: &[u8], key2: &[u8]) -> Vec<u8> {
    let mut m_key1 = key1.to_vec();
    let mut m_key2 = key2.to_vec();

    let len = m_key1.len();
    let sklen = m_key2.len();
    let rlen = len.abs_diff(sklen);

    if len < sklen {
        m_key2.remove(rlen);
    } else if len > sklen {
        m_key2.append(&mut vec![1u8; rlen]);
    }

    m_key1.rotate_left(len / 3);

    m_key1 = m_key1
        .iter()
        .zip(m_key2.iter())
        .map(|(x1, x2)| x1 ^ x2)
        .collect();
    m_key1
}

/// Hash a plain text using SHA3-256
pub(crate) fn try_hash_with_sha3_256(plainText: &[u8]) -> VaultResult<Vec<u8>> {
    let mut hasher = Sha3_256::new();

    // write input message
    hasher.update(plainText);

    // read hash digest
    let result = hasher.finalize();

    let hash = result.to_vec();
    Ok(hash)
}




pub(crate) fn try_default_password_hash<'a>(password_bytes: &[u8], salt: impl Into<Salt<'a>>) -> VaultResult<PasswordHash<'a>> {
    
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password_bytes, salt).map_err(|e| VaultError::create(e.to_string()))?;
    Ok(password_hash)
}

pub(crate) fn try_password_hash<'a>(password_bytes: &[u8], salt: impl Into<Salt<'a>>, len: usize) -> VaultResult<PasswordHash<'a>> {
    
    let mut paramsBuilder = ParamsBuilder::default();
    paramsBuilder.output_len(len);
    let params = paramsBuilder.build().map_err(|e| VaultError::from("Could no build the cipher algorithm."))?;
    
    let argon2 = Argon2::new(argon2::Algorithm::default(), argon2::Version::default(), params);
    let password_hash = argon2.hash_password(password_bytes, salt).map_err(|e| VaultError::create(e.to_string()))?;
    Ok(password_hash)
}

pub(crate) fn password_is_valid(password: &str, system_key:&[u8], password_hash: &str) -> bool {
    
    match try_derive_key(password.as_ref(), system_key) {
        Ok(passw) => {
            match encode_b64(passw.as_slice()) {
                Ok(passw) => {
                    match PasswordHash::new(password_hash.as_ref()) {
                        Ok(hash) => Argon2::default().verify_password(password.as_bytes(), &hash).is_ok(),
                        Err(e) => {
                            return false;
                        } ,
                    }                    
                },
                Err(_) => false,
            }
        },
        Err(_) => false,
    }

}

pub(crate) fn try_derive_key(key: &[u8], salt: &[u8]) -> VaultResult<Vec<u8>> {

    let argon2 = Argon2::default();
    let mut buf = vec![0u8; DEFAULT_KEY_SIZE_IN_BYTES];
    argon2.hash_password_into(key, salt, &mut buf).map_err(|e| VaultError::create(e.to_string()))?;

    Ok(buf.to_vec())
}

pub(crate) fn try_derive_key_with_size<'a>(key: &[u8], salt: &[u8], size: usize) -> VaultResult<Vec<u8>> {

    let argon2 = Argon2::default();
    let mut buf = vec![0u8; size];
    argon2.hash_password_into(key, salt, &mut buf).map_err(|e| VaultError::create(e.to_string()))?;

    Ok(buf.to_vec())
}

/// Generates a random array of size bytes
pub(crate) fn generate_random_bytes<'a>(size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Encrypts the plain text plain text using ChaChaPoly1205 with a 256b key, a 92b nonce and a aead
pub(crate) fn try_encrypt(key: &[u8], nonce: &[u8], plain: &[u8], aad: Option<&[u8]>) -> crate::VaultResult<Vec<u8>> {
    let nonce = Nonce::from_slice(nonce);
    let empty_aad = b"".to_vec();
    let payload = Payload {
        msg: plain,
        aad: aad.unwrap_or(&empty_aad),
    };
    let ccp = ChaCha20Poly1305::new_from_slice(key).map_err(|e| VaultError::create(e.to_string()))?;

    let result = ccp.encrypt(&nonce, payload).map_err(|e| VaultError::create(e.to_string()))?;

    Ok(result)
}

/// Decrypts the ciphered text using ChaChaPoly1205 with a 256b key, a 92b nonce and a aead
pub(crate) fn try_decrypt( key: &[u8], nonce: &[u8], cipher_text: &[u8], aad: Option<&[u8]>) -> crate::VaultResult<Vec<u8>> {
    let ccp = ChaCha20Poly1305::new_from_slice(&key).map_err(|e| VaultError::create(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce);
    let empty_aad = b"".to_vec();
    let payload = Payload {
        msg: &cipher_text,
        aad: aad.unwrap_or(&empty_aad),
    };
    let result = ccp.decrypt(&nonce, payload).map_err(|e| VaultError::create(e.to_string()));

    result
}

pub(crate) fn try_generate_user_system_key<'a>(source: &[u8]) -> VaultResult<Vec<u8>> {
    let mut m_source = source.to_owned();
    let mut index = 0;
    let mut chosenCount = 0;


    let v = source.get(0).unwrap().to_owned();
    let base = usize::from(v % 7);

    let range = m_source[base..].to_vec();

    let system = sysinfo::System::new();
    for byte in range {
        if byte % 2 == 1 {
            let sys_key_index = byte % 7;
            let opt = SystemKeyOptions::try_from(sys_key_index as u8).unwrap();
            m_source = try_parse_option(&system, opt, m_source, &mut chosenCount)?;
        }
        if chosenCount == 3 {
            break;
        }
    }
    m_source = try_parse_option(
        &system,
        SystemKeyOptions::PathFileName,
        m_source,
        &mut chosenCount,
    )?;

    if chosenCount < 2 {
        return Err( VaultError::create("Key is not sufficient.".to_string()));
    }

    let m_source = try_hash_with_sha3_256(&m_source);
    
    m_source
}

fn try_parse_option( system: &sysinfo::System, mut opt: SystemKeyOptions, m_source: Vec<u8>, mut chosenCount: &mut i32) -> VaultResult<Vec<u8>> {
    let code = match opt {
        SystemKeyOptions::PathFileName => {
            let store = CURRRENT_STORE.try_get();
            match store {
                Some(sto) => {
                    let pn = sto.properties.target.to_owned();
                    let pn = match pn {
                        Some(s) => s,
                        None => match std::env::current_dir().map_err(|e| VaultError::create(e.to_string()))?.to_str() {
                            Some(s) => s.to_string(),
                            None => panic!("There is a problem!"),
                        },
                    };
                    let ret = pn.as_bytes().to_vec();
                    *chosenCount += 1;
                    ret
                }
                None => vec![0u8; 0],
            }
        }
        SystemKeyOptions::DateCreation => {
            let store = CURRRENT_STORE.try_get();
            match store {
                Some(sto) => {
                    let date_created = store.unwrap().properties.date_created;
                    *chosenCount += 1;
                    date_created.to_string().as_bytes().to_vec()
                }
                None => vec![0u8; 0],
            }
        }
        SystemKeyOptions::CpuName => try_get_info_from_cpu(&system, &mut chosenCount, &|cpu| {
            cpu.name.as_bytes().to_vec()
        })?,
        SystemKeyOptions::CpuVendorId => try_get_info_from_cpu(&system, &mut chosenCount, &|cpu| {
            cpu.vendor_id.as_bytes().to_vec()
        })?,
        SystemKeyOptions::CpuBrand => try_get_info_from_cpu(&system, &mut chosenCount, &|cpu| {
            cpu.brand.as_bytes().to_vec()
        })?,
        SystemKeyOptions::CpuFrequency => try_get_info_from_cpu(&system, &mut chosenCount, &|cpu| {
            cpu.frequency.to_be_bytes().to_vec()
        })?,
        SystemKeyOptions::SystemName => {
            try_get_info_from_sys(&system, &mut chosenCount, &|sys| match sys.name {
                Some(n) => n.as_bytes().to_vec(),
                None => b"".to_vec(),
            })?
        }
        SystemKeyOptions::SystemHostname => {
            try_get_info_from_sys(&system, &mut chosenCount, &|sys| match sys.name {
                Some(n) => n.as_bytes().to_vec(),
                None => b"".to_vec(),
            })?
        }
    };
    let cypher_k = merge_key(&code, &m_source);

    Ok(cypher_k)
}

pub(crate) fn try_generate_salt_from_password(password: &str) -> VaultResult<Vec<u8>> {
    let bytes = password.as_bytes();
    let salt = try_generate_user_system_key(bytes)?;
    Ok(salt)
}

fn try_get_info_from_cpu(system: &sysinfo::System, chosenCount: &mut i32, f: &dyn Fn(CpuInfo) -> Vec<u8>) -> VaultResult<Vec<u8>> {
    let mut cpus: Vec<CpuInfo> = sys_information_souce::cpu_info();
    let return_value = vec![0u8; 0];
    let cpu = cpus.pop().unwrap();
    let mut value = f(cpu);

    if value.len() > 0 {
        value.resize(DEFAULT_KEY_SIZE_IN_BYTES, 0u8);
        if value.len() > DEFAULT_KEY_SIZE_IN_BYTES {
            value.truncate(DEFAULT_KEY_SIZE_IN_BYTES);
        }

        *chosenCount += 1;
        return Ok(value);
    }

    Ok(return_value)
}

fn try_get_info_from_sys( system: &sysinfo::System, chosenCount: &mut i32, f: &dyn Fn(SysInfo) -> Vec<u8>) -> VaultResult<Vec<u8>> {
    let sys = sys_information_souce::sys_info();
    let return_value = vec![0u8; 0];

    let mut value = f(sys);

    if value.len() > 0 {
        value.resize(DEFAULT_KEY_SIZE_IN_BYTES, 0u8);
        if value.len() > DEFAULT_KEY_SIZE_IN_BYTES {
            value.truncate(DEFAULT_KEY_SIZE_IN_BYTES);
        }

        *chosenCount += 1;

        return Ok(value);
    }

    Ok(return_value)
}

/// Generate a Nonce by hashing the key with the Salt
 pub(crate) fn try_generate_nonce(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, VaultError> {

    let salt = helpers::encode_b64(salt)?;    
    let salt = SaltString::from_b64(&salt).map_err(|e| VaultError::from(e.to_string()))?;
    
    let nonce = try_password_hash(
        &password,
        &salt,
        CHACHAPOLY1305_NONCE_SIZE_IN_BYTES,
    )?
    .hash;
    let nonce = match nonce {
        Some(k) => k,
        None => return Err(VaultError::from("Ups!")),
    };
    let nonce = helpers::decode_b64(&nonce.to_string())?;
    Ok(nonce)
}



/// Try to normalize a password by deriving and encoding in B64
pub(crate) fn try_derive_password(password: &str, system_key: &[u8]) -> VaultResult<crate::abstractions::B64String> {
    let derived_key = try_derive_key(password.as_bytes(), &system_key)?;
    let dk_string = helpers::encode_b64(&derived_key)?;
    Ok(dk_string)
}





