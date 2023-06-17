use std::{sync::RwLock};

use super::abstractions::{CpuInfo, SystemInfo, SysInfo};


use sysinfo::{
    CpuExt, CpuRefreshKind, RefreshKind, SystemExt
};


static mut CACHE: RwLock<SystemInfo> = RwLock::new(SystemInfo { cpus: Option::None, user: Option::None, sys: None });


pub(crate) fn cpu_info() -> Vec<CpuInfo> {

    let cache = unsafe { CACHE.read().unwrap() };

    let cached_cpus = cache.cpus.to_owned();

    let cpus = match cached_cpus {
        Some(v) => v,
        None => {

            let sinfo = sysinfo::System::new_with_specifics(RefreshKind::new().with_cpu(CpuRefreshKind::everything().without_cpu_usage()));

            let sys_cpus = sinfo.cpus();

            let cpus: Vec<CpuInfo> = sys_cpus.iter().map(|scpu| CpuInfo {
                brand: scpu.brand().to_owned(),
                frequency: scpu.frequency().to_owned(),
                name: scpu.name().to_owned(),
                vendor_id: scpu.vendor_id().to_owned()
                })
                .collect();
        
            let cache = unsafe { CACHE.get_mut().unwrap() };
            cache.cpus = Some(cpus.clone());      
            
            cpus
        },
    };


    cpus.to_vec()

}


pub(crate) fn sys_info() -> SysInfo {

    let cache = unsafe { CACHE.read().unwrap() };

    let cached_sys = cache.sys.to_owned();

    let sys = match cached_sys {
        Some(v) => v,
        None => {

            let sinfo = sysinfo::System::new();

            let sys_name = sinfo.name();
            let host_name = sinfo.host_name();
    
            let cache = unsafe { CACHE.get_mut().unwrap() };

            let sys = SysInfo {
                name: sys_name,
                host_name: host_name,
            };

            cache.sys = Some(sys.clone());   
            sys
        },
    };

    sys
}



// pub(crate) fn get_System_Info() -> Result<SystemInfo> {
//     let sysinfo = unsafe { SYSINFO.read() }.unwrap();
//     let cpu_info = cpu_info(*sysinfo).unwrap();
    

//     todo!()
// }





