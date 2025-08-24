use windows_sys::Win32::{
    Foundation::{HMODULE, TRUE},
    System::{
        LibraryLoader::DisableThreadLibraryCalls,
        SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH},
        Console::{AllocConsole, FreeConsole},
    },
};

mod logging;
mod offsets;
use log::{info, error};
use offsets::offset_finder::{OffsetFinder, export_offsets_to_json};

fn dumper_thread() {
    info!("\n\nUE Dumper thread started.\n\n");
    
    // Обработка паники для предотвращения краша игры
    let result = std::panic::catch_unwind(|| {
        // Создаем поисковик оффсетов для текущего процесса
        let mut finder = OffsetFinder::new();
        info!("Offset finder initialized for current process");
        
        // Поиск всех оффсетов
        let offsets = finder.find_all_offsets();
        info!("Found offsets: {:?}", offsets);
        
        // Экспорт в JSON
        let filename = format!("ue_offsets_{}.json", chrono::Utc::now().timestamp());
        if let Err(e) = export_offsets_to_json(&offsets, &filename) {
            error!("Failed to export offsets: {}", e);
        } else {
            info!("Offsets successfully exported to: {}", filename);
        }
    });
    
    match result {
        Ok(_) => info!("Offset finding completed successfully"),
        Err(e) => {
            error!("Offset finding failed with panic: {:?}", e);
            error!("Game should continue running normally");
        }
    }
}

#[no_mangle]
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