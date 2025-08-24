use windows_sys::Win32::{
    Foundation::{HMODULE, TRUE},
    System::{
        LibraryLoader::DisableThreadLibraryCalls,
        SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
        Console::{AllocConsole, FreeConsole},
        Threading::CreateThread,
    },
};

mod logging;
use log::info;

fn dumper_thread() {
    info!("\n\nUE Dumper thread started.\n\n");
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    h_module: HMODULE,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> i32 {
    match reason {
        DLL_PROCESS_ATTACH => {
            DisableThreadLibraryCalls(h_module);
            AllocConsole();
            crate::logging::init_logger();

            info!("\n\nUE Dumper injected successfully!\n\n");
            
            // Запуск дампера в отдельном потоке
            let mut thread_id = 0u32;
            std::thread::spawn(|| {
                dumper_thread();
            });
            
            TRUE as i32
        }
        DLL_PROCESS_DETACH => {
            info!("UE Dumper detached.");
            FreeConsole();
            TRUE as i32
        }
        _ => TRUE as i32,
    }
}