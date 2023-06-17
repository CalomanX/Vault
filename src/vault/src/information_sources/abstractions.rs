use chrono::NaiveDateTime;
use sysinfo::{Uid, Gid};



#[derive(Debug, Clone)]
pub(crate) struct CpuInfo {
    pub(crate) name: String,
    pub(crate) vendor_id: String,
    pub(crate) brand: String,
    pub(crate) frequency: u64,
}

#[derive(Debug, Clone)]
pub(crate)  struct UserInfo {
    pub(crate) uid: Uid,
    pub(crate) group_id: Gid,
    pub(crate) name: String
}

#[derive(Debug, Clone)]
pub struct SysInfo {
    pub(crate) name: Option<String>,
    pub(crate) host_name: Option<String>
}


#[derive(Debug, Clone)]
pub(crate) struct SystemInfo {
    pub(crate) sys: Option<SysInfo>,
    pub(crate) user: Option<UserInfo>,
    pub(crate) cpus: Option<Vec<CpuInfo>>
}

pub(crate) trait StoreInformationSource {
    fn target<'a>()-> &'a Option<String>;
    fn creation_date() -> Option<NaiveDateTime>;

}


pub(crate) trait SystemInformationSource {
    
}