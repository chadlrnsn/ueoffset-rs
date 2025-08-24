use serde::{Serialize, Deserialize};
use log::{info, warn};
use windows_sys::Win32::Foundation::{HANDLE, CloseHandle};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UEOffsets {
    pub gnames: Option<u64>,
    pub gobjects: Option<u64>,
    pub gworld: Option<u64>,
    pub process_event: Option<u64>,
    pub fname_append_string: Option<u64>,
    pub create_default_object: Option<u64>,
    pub timestamp: String,
    pub module_base: u64,
}

impl UEOffsets {
    pub fn new(module_base: u64) -> Self {
        Self {
            gnames: None,
            gobjects: None,
            gworld: None,
            process_event: None,
            fname_append_string: None,
            create_default_object: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            module_base,
        }
    }
}

pub struct OffsetFinder {
    module_base: u64,
    process_handle: HANDLE,
}

impl OffsetFinder {
    pub fn new() -> Self {
        let module_base = Self::get_module_base();
        info!("Module base address: 0x{:X}", module_base);
        
        // Получаем handle текущего процесса
        let process_handle = unsafe { GetCurrentProcess() };
        
        Self { module_base, process_handle }
    }

    fn get_module_base() -> u64 {
        // Получаем базовый адрес текущего модуля через GetModuleHandle(NULL)
        unsafe {
            let module_handle = windows_sys::Win32::System::LibraryLoader::GetModuleHandleA(std::ptr::null());
            if module_handle.is_null() {
                0x140000000 // Fallback адрес
            } else {
                module_handle as u64
            }
        }
    }

    pub fn find_all_offsets(&mut self) -> UEOffsets {
        let mut offsets = UEOffsets::new(self.module_base);
        
        info!("Starting UE offset search in current process...");
        
        // Поиск GNames через анализ FName структур
        if let Ok(addr) = self.find_gnames_advanced() {
            offsets.gnames = Some(addr);
            info!("GNames found at: 0x{:X}", addr);
        } else {
            warn!("GNames not found");
        }
        
        // Поиск GObjects через анализ UObject структур
        if let Ok(addr) = self.find_gobjects_advanced() {
            offsets.gobjects = Some(addr);
            info!("GObjects found at: 0x{:X}", addr);
        } else {
            warn!("GObjects not found");
        }
        
        // Поиск GWorld через анализ World объектов
        if let Ok(addr) = self.find_gworld_advanced() {
            offsets.gworld = Some(addr);
            info!("GWorld found at: 0x{:X}", addr);
        } else {
            warn!("GWorld not found");
        }
        
        // Поиск ProcessEvent через анализ UFunction структур
        if let Ok(addr) = self.find_process_event_advanced() {
            offsets.process_event = Some(addr);
            info!("ProcessEvent found at: 0x{:X}", addr);
        } else {
            warn!("ProcessEvent not found");
        }
        
        // Поиск FName::AppendString через анализ строк
        if let Ok(addr) = self.find_fname_append_string_advanced() {
            offsets.fname_append_string = Some(addr);
            info!("FName::AppendString found at: 0x{:X}", addr);
        } else {
            warn!("FName::AppendString not found");
        }
        
        // Поиск CreateDefaultObject через анализ UClass структур
        if let Ok(addr) = self.find_create_default_object_advanced() {
            offsets.create_default_object = Some(addr);
            info!("CreateDefaultObject found at: 0x{:X}", addr);
        } else {
            warn!("CreateDefaultObject not found");
        }
        
        info!("Offset search completed. Found {} offsets", 
            [offsets.gnames, offsets.gobjects, offsets.gworld, 
             offsets.process_event, offsets.fname_append_string, offsets.create_default_object]
            .iter().filter(|&&x| x.is_some()).count());
        
        offsets
    }

    // Продвинутый поиск GNames через анализ FName структур
    fn find_gnames_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Ищем строки, которые обычно находятся рядом с GNames
        let strings_to_find = [
            "%d.%d.%d.%d.%d.%s",
            "Invalid name index",
            "FName::GetDisplayNameEntry",
        ];
        
        for string in &strings_to_find {
            if let Some(addr) = self.find_string_reference(string) {
                // Ищем выше по коду инструкции загрузки адреса
                if let Some(gnames_addr) = self.find_gnames_above_string_advanced(addr) {
                    return Ok(gnames_addr);
                }
            }
        }
        
        // Альтернативный поиск через сигнатуры
        let signatures = [
            (vec![0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8], "xxx????x"),
            (vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0xC8], "xxx????xxx"),
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                let offset = self.read_memory::<i32>(addr + 3)? as u64;
                let target_addr = addr + 7 + offset;
                return Ok(target_addr);
            }
        }
        
        Err("GNames not found".into())
    }

    // Продвинутый поиск GObjects через анализ UObject структур
    fn find_gobjects_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Ищем строки, связанные с GObjects
        let strings_to_find = [
            "Invalid object index in reference chain",
            "UObject::Serialize",
            "Garbage collection",
        ];
        
        for string in &strings_to_find {
            if let Some(addr) = self.find_string_reference(string) {
                if let Some(gobjects_addr) = self.find_gobjects_above_string_advanced(addr) {
                    return Ok(gobjects_addr);
                }
            }
        }
        
        // Поиск через сигнатуры доступа к GObjects
        let signatures = [
            (vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0xC8], "xxx????xxx"),
            (vec![0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x04, 0xC8], "xxx????xxx"),
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                let offset = self.read_memory::<i32>(addr + 3)? as u64;
                let target_addr = addr + 7 + offset;
                return Ok(target_addr);
            }
        }
        
        Err("GObjects not found".into())
    }

    // Продвинутый поиск GWorld через анализ World объектов
    fn find_gworld_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Ищем строки, связанные с World
        let strings_to_find = [
            "SeamlessTravel FlushLevelStreaming",
            "World::Tick",
            "UWorld::BeginPlay",
        ];
        
        for string in &strings_to_find {
            if let Some(addr) = self.find_string_reference(string) {
                if let Some(gworld_addr) = self.find_gworld_above_string_advanced(addr) {
                    return Ok(gworld_addr);
                }
            }
        }
        
        // Поиск через сигнатуры записи в GWorld
        let signatures = [
            (vec![0x48, 0x89, 0x15, 0x00, 0x00, 0x00, 0x00], "xxx????"),
            (vec![0x48, 0x89, 0x0D, 0x00, 0x00, 0x00, 0x00], "xxx????"),
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                let offset = self.read_memory::<i32>(addr + 3)? as u64;
                let target_addr = addr + 7 + offset;
                return Ok(target_addr);
            }
        }
        
        Err("GWorld not found".into())
    }

    // Продвинутый поиск ProcessEvent через анализ UFunction структур
    fn find_process_event_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Ищем строки, связанные с ProcessEvent
        let strings_to_find = [
            "Bad or missing property",
            "AccessNoneNoContext",
            "ProcessEvent",
        ];
        
        for string in &strings_to_find {
            if let Some(addr) = self.find_string_reference(string) {
                if let Some(process_event_addr) = self.find_process_event_above_string_advanced(addr) {
                    return Ok(process_event_addr);
                }
            }
        }
        
        // Поиск через сигнатуры вызова ProcessEvent
        let signatures = [
            (vec![0xFF, 0x50, 0x38], "xxx"), // call qword ptr [rax+38h]
            (vec![0x48, 0x8B, 0x40, 0x38, 0xFF, 0x50, 0x38], "xxxxxxx"), // mov rax, [rax+38h]; call qword ptr [rax+38h]
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                return Ok(addr);
            }
        }
        
        Err("ProcessEvent not found".into())
    }

    // Продвинутый поиск FName::AppendString
    fn find_fname_append_string_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Ищем строки, связанные с FName
        let strings_to_find = [
            "Skeleton",
            "FName::AppendString",
            "Name collision",
        ];
        
        for string in &strings_to_find {
            if let Some(addr) = self.find_string_reference(string) {
                if let Some(fname_addr) = self.find_fname_above_string_advanced(addr) {
                    return Ok(fname_addr);
                }
            }
        }
        
        // Поиск через сигнатуры функции FName::AppendString
        let signatures = [
            (vec![0x48, 0x89, 0x5C, 0x24, 0x00, 0x56, 0x48, 0x83, 0xEC], "xxxx?xxxx"),
            (vec![0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B, 0xD9], "xxxxxxxxx"),
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                return Ok(addr);
            }
        }
        
        Err("FName::AppendString not found".into())
    }

    // Продвинутый поиск CreateDefaultObject
    fn find_create_default_object_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Ищем строки, связанные с CreateDefaultObject
        let strings_to_find = [
            "CanvasRenderTarget2DCanvas",
            "CreateDefaultObject",
            "Default__",
        ];
        
        for string in &strings_to_find {
            if let Some(addr) = self.find_string_reference(string) {
                if let Some(create_default_addr) = self.find_create_default_above_string_advanced(addr) {
                    return Ok(create_default_addr);
                }
            }
        }
        
        // Поиск через сигнатуры функции CreateDefaultObject
        let signatures = [
            (vec![0x4C, 0x8B, 0xDC, 0x48, 0x83, 0xEC, 0x48], "xxxxxxx"),
            (vec![0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0x48, 0x83, 0xEC, 0x20], "xxxxxxxxxx"),
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                return Ok(addr);
            }
        }
        
        Err("CreateDefaultObject not found".into())
    }

    // Продвинутое сканирование сигнатур с ограничениями по памяти
    fn scan_signature_advanced(&self, signature: &[u8], mask: &str) -> Option<u64> {
        let mut current_address = self.module_base;
        let max_address = self.module_base + 0x20000000; // Максимум 512MB от базового адреса
        
        while current_address < max_address {
            match self.read_memory_buffer_safe(current_address, 1024 * 1024) {
                Ok(buffer) => {
                    if let Some(offset) = self.find_pattern_in_buffer(&buffer, signature, mask) {
                        return Some(current_address + offset as u64);
                    }
                }
                Err(_) => {
                    // Пропускаем недоступные блоки памяти
                    current_address += 1024 * 1024;
                    continue;
                }
            }
            
            current_address += 1024 * 1024;
        }
        
        None
    }

    // Безопасное чтение блока памяти с проверкой валидности
    fn read_memory_buffer_safe(&self, address: u64, size: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if address == 0 || address > 0x7FFFFFFFFFFF {
            return Err("Invalid address".into());
        }
        
        if size == 0 || size > 1024 * 1024 {
            return Err("Invalid buffer size".into());
        }
        
        let mut buffer = vec![0u8; size];
        let mut bytes_read = 0usize;
        
        let result = unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const core::ffi::c_void,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                size,
                &mut bytes_read
            )
        };
        
        if result == 0 || bytes_read != size {
            return Err("Failed to read memory buffer".into());
        }
        
        Ok(buffer)
    }

    // Продвинутый поиск GNames выше строки
    fn find_gnames_above_string_advanced(&self, string_addr: u64) -> Option<u64> {
        // Ищем выше по коду инструкции загрузки адреса GNames
        for offset in 1..2000 {
            let addr = string_addr.saturating_sub(offset);
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0x48 { // mov rax/rcx
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x8D || next_byte == 0x8B { // lea/mov
                            if let Ok(third_byte) = self.read_memory::<u8>(addr + 2) {
                                if third_byte == 0x0D || third_byte == 0x05 { // rcx/rax
                                    if let Ok(offset_bytes) = self.read_memory::<i32>(addr + 3) {
                                        let target_addr = addr + 7 + offset_bytes as u64;
                                        return Some(target_addr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // Продвинутый поиск GObjects выше строки
    fn find_gobjects_above_string_advanced(&self, string_addr: u64) -> Option<u64> {
        for offset in 1..2000 {
            let addr = string_addr.saturating_sub(offset);
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0x48 { // mov rax
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x8B { // mov
                            if let Ok(third_byte) = self.read_memory::<u8>(addr + 2) {
                                if third_byte == 0x05 { // mov rax, [rip+offset]
                                    if let Ok(offset_bytes) = self.read_memory::<i32>(addr + 3) {
                                        let target_addr = addr + 7 + offset_bytes as u64;
                                        return Some(target_addr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // Продвинутый поиск GWorld выше строки
    fn find_gworld_above_string_advanced(&self, string_addr: u64) -> Option<u64> {
        for offset in 1..2000 {
            let addr = string_addr.saturating_sub(offset);
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0x48 { // mov
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x89 { // mov [rip+offset], rax
                            if let Ok(third_byte) = self.read_memory::<u8>(addr + 2) {
                                if third_byte == 0x15 { // mov [rip+offset], rdx
                                    if let Ok(offset_bytes) = self.read_memory::<i32>(addr + 3) {
                                        let target_addr = addr + 7 + offset_bytes as u64;
                                        return Some(target_addr);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // Продвинутый поиск ProcessEvent выше строки
    fn find_process_event_above_string_advanced(&self, string_addr: u64) -> Option<u64> {
        for offset in 1..2000 {
            let addr = string_addr.saturating_sub(offset);
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0xFF { // call
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x50 { // call qword ptr [rax+...]
                            if let Ok(offset_bytes) = self.read_memory::<u8>(addr + 2) {
                                if offset_bytes == 0x38 { // +38h
                                    return Some(addr);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // Продвинутый поиск FName выше строки
    fn find_fname_above_string_advanced(&self, string_addr: u64) -> Option<u64> {
        for offset in 1..2000 {
            let addr = string_addr.saturating_sub(offset);
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0x48 { // mov rsp, rbp
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x89 { // mov
                            if let Ok(third_byte) = self.read_memory::<u8>(addr + 2) {
                                if third_byte == 0xE5 { // mov rsp, rbp
                                    return Some(addr);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // Продвинутый поиск CreateDefault выше строки
    fn find_create_default_above_string_advanced(&self, string_addr: u64) -> Option<u64> {
        for offset in 1..2000 {
            let addr = string_addr.saturating_sub(offset);
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0x4C { // mov r11, rsp
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x8B { // mov
                            if let Ok(third_byte) = self.read_memory::<u8>(addr + 2) {
                                if third_byte == 0xDC { // mov r11, rsp
                                    return Some(addr);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    // Поиск строки в памяти
    fn find_string_reference(&self, string: &str) -> Option<u64> {
        let mut current_address = self.module_base;
        let max_address = self.module_base + 0x20000000; // Максимум 512MB
        
        while current_address < max_address {
            match self.read_memory_buffer_safe(current_address, 1024 * 1024) {
                Ok(buffer) => {
                    if let Some(offset) = buffer.windows(string.len()).position(|window| window == string.as_bytes()) {
                        return Some(current_address + offset as u64);
                    }
                }
                Err(_) => {
                    current_address += 1024 * 1024;
                    continue;
                }
            }
            
            current_address += 1024 * 1024;
        }
        
        None
    }

    // Поиск паттерна в буфере
    fn find_pattern_in_buffer(&self, buffer: &[u8], signature: &[u8], mask: &str) -> Option<usize> {
        'outer: for i in 0..=buffer.len().saturating_sub(signature.len()) {
            for j in 0..signature.len() {
                let mask_char = mask.chars().nth(j).unwrap_or('x');
                if mask_char == 'x' && buffer[i + j] != signature[j] {
                    continue 'outer;
                }
            }
            return Some(i);
        }
        None
    }

    // Чтение памяти с проверками
    fn read_memory<T>(&self, address: u64) -> Result<T, Box<dyn std::error::Error>> {
        if address == 0 || address > 0x7FFFFFFFFFFF {
            return Err("Invalid address".into());
        }
        
        if address % std::mem::align_of::<T>() as u64 != 0 {
            return Err("Unaligned address".into());
        }
        
        let mut buffer = std::mem::MaybeUninit::<T>::uninit();
        let mut bytes_read = 0usize;
        
        let result = unsafe {
            ReadProcessMemory(
                self.process_handle,
                address as *const core::ffi::c_void,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                std::mem::size_of::<T>(),
                &mut bytes_read
            )
        };
        
        if result == 0 || bytes_read != std::mem::size_of::<T>() {
            return Err("Failed to read memory".into());
        }
        
        Ok(unsafe { buffer.assume_init() })
    }
}

impl Drop for OffsetFinder {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_handle);
        }
    }
}

pub fn export_offsets_to_json(offsets: &UEOffsets, filename: &str) -> Result<(), Box<dyn std::error::Error>> {
    let json = serde_json::to_string_pretty(offsets)?;
    std::fs::write(filename, json)?;
    info!("Offsets exported to: {}", filename);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ue_offsets_new() {
        let offsets = UEOffsets::new(0x140000000);
        assert_eq!(offsets.module_base, 0x140000000);
        assert!(offsets.gnames.is_none());
        assert!(offsets.gobjects.is_none());
        assert!(offsets.gworld.is_none());
        assert!(offsets.process_event.is_none());
        assert!(offsets.fname_append_string.is_none());
        assert!(offsets.create_default_object.is_none());
        assert!(!offsets.timestamp.is_empty());
    }

    #[test]
    fn test_find_pattern_in_buffer() {
        let finder = OffsetFinder { module_base: 0, process_handle: 0 as HANDLE };
        
        let buffer = vec![0x48, 0x8D, 0x0D, 0x12, 0x34, 0x56, 0x78, 0xE8];
        let signature = vec![0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8];
        let mask = "xxx????x";
        
        let result = finder.find_pattern_in_buffer(&buffer, &signature, mask);
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_find_pattern_in_buffer_no_match() {
        let finder = OffsetFinder { module_base: 0, process_handle: 0 as HANDLE };
        
        let buffer = vec![0x48, 0x8D, 0x0C, 0x12, 0x34, 0x56, 0x78, 0xE8];
        let signature = vec![0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, 0xE8];
        let mask = "xxx????x";
        
        let result = finder.find_pattern_in_buffer(&buffer, &signature, mask);
        assert_eq!(result, None);
    }

    #[test]
    fn test_export_offsets_to_json() {
        let offsets = UEOffsets::new(0x140000000);
        let temp_file = "test_offsets.json";
        
        let result = export_offsets_to_json(&offsets, temp_file);
        assert!(result.is_ok());
        
        if let Ok(content) = std::fs::read_to_string(temp_file) {
            assert!(content.contains("module_base"));
            assert!(content.contains("gnames"));
            assert!(content.contains("gobjects"));
        }
        
        let _ = std::fs::remove_file(temp_file);
    }
}
