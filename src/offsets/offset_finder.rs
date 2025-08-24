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

    // Продвинутый поиск GNames через анализ FName структур (методика @Engine/)
    fn find_gnames_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Методика из @Engine/ - ищем через EnterCriticalSection и ByteProperty
        if let Some(addr) = self.find_gnames_via_entercritical_advanced() {
            return Ok(addr);
        }
        
        // Альтернативный поиск через другие строки
        let strings_to_find = [
            "Invalid name index",
            "FName::StaticInit",
            "GetNames",
            "ByteProperty",
        ];
        
        for string in &strings_to_find {
            if let Some(addr) = self.find_string_reference(string) {
                if let Some(gnames_addr) = self.find_gnames_above_string_advanced(addr) {
                    return Ok(gnames_addr);
                }
            }
        }
        
        // Поиск через сигнатуры
        let signatures = [
            (vec![0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00], "xxx????"),
            (vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00], "xxx????"),
            (vec![0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00], "xxx????"),
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                let offset = self.read_memory::<i32>(addr + 3)? as u64;
                let target_addr = addr + 7 + offset;
                if self.is_valid_gnames_address(target_addr) {
                    return Ok(target_addr);
                }
            }
        }
        
        Err("GNames not found".into())
    }

    // Поиск GNames через EnterCriticalSection (методика @Engine/)
    fn find_gnames_via_entercritical_advanced(&self) -> Option<u64> {
        // Ищем строку "ByteProperty" и анализируем код выше
        if let Some(byte_property_addr) = self.find_string_reference("ByteProperty") {
            info!("Found ByteProperty string at: 0x{:X}", byte_property_addr);
            
            // Ищем выше по коду EnterCriticalSection
            for offset in 1..0x150 {
                let addr = byte_property_addr.saturating_sub(offset);
                
                // Проверяем EnterCriticalSection call
                if let Ok(byte) = self.read_memory::<u8>(addr) {
                    if byte == 0xFF { // call
                        if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                            if next_byte == 0x15 { // call [rip+offset]
                                // Это может быть EnterCriticalSection, ищем выше GetNames
                                if let Some(gnames_addr) = self.find_gnames_via_getnames_advanced(addr) {
                                    return Some(gnames_addr);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        None
    }

    // Поиск GNames через GetNames (методика @Engine/)
    fn find_gnames_via_getnames_advanced(&self, call_addr: u64) -> Option<u64> {
        // Ищем выше по коду функцию GetNames
        for offset in 1..0x100 {
            let addr = call_addr.saturating_sub(offset);
            
            // Проверяем начало функции GetNames
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0x48 { // mov
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x89 { // mov
                            if let Ok(third_byte) = self.read_memory::<u8>(addr + 2) {
                                if third_byte == 0xE5 { // mov rsp, rbp
                                    // Нашли начало функции GetNames, ищем возврат GNames
                                    if let Some(gnames_addr) = self.find_gnames_in_getnames_advanced(addr) {
                                        return Some(gnames_addr);
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

    // Поиск GNames в функции GetNames (методика @Engine/)
    fn find_gnames_in_getnames_advanced(&self, func_start: u64) -> Option<u64> {
        // Сканируем функцию GetNames в поисках доступа к GNames
        for offset in 0..0x100 {
            let addr = func_start + offset;
            
            // Проверяем инструкции mov rax, [rip+offset]
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0x48 { // mov
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x8B { // mov rax, [rip+offset]
                            if let Ok(third_byte) = self.read_memory::<u8>(addr + 2) {
                                if third_byte == 0x05 { // mov rax, [rip+offset]
                                    if let Ok(offset_bytes) = self.read_memory::<i32>(addr + 3) {
                                        let target_addr = addr + 7 + offset_bytes as u64;
                                        if self.is_valid_gnames_address(target_addr) {
                                            return Some(target_addr);
                                        }
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

    // Проверка валидности адреса GNames
    fn is_valid_gnames_address(&self, addr: u64) -> bool {
        // Простая проверка - адрес должен быть в пределах модуля
        if addr < self.module_base || addr > self.module_base + 0x10000000 {
            return false;
        }
        
        // Пытаемся прочитать первые байты
        if let Ok(first_bytes) = self.read_memory::<u64>(addr) {
            // GNames обычно содержит валидные указатели
            return first_bytes != 0 && first_bytes < 0x7FFFFFFFFFFF;
        }
        
        false
    }

    // Продвинутый поиск GObjects через анализ UObject структур
    fn find_gobjects_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Методика из @Engine/ - сканируем .data секцию
        if let Some(addr) = self.find_gobjects_via_data_section() {
            return Ok(addr);
        }
        
        // Альтернативный поиск через строки
        let strings_to_find = [
            "Invalid object index in reference chain",
            "UObject::Serialize",
            "Garbage collection",
            "FUObjectArray",
        ];
        
        for string in &strings_to_find {
            if let Some(addr) = self.find_string_reference(string) {
                if let Some(gobjects_addr) = self.find_gobjects_above_string_advanced(addr) {
                    return Ok(gobjects_addr);
                }
            }
        }
        
        let signatures = [
            (vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x0C, 0xC8], "xxx????xxx"),
            (vec![0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x04, 0xC8], "xxx????xxx"),
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                let offset = self.read_memory::<i32>(addr + 3)? as u64;
                let target_addr = addr + 7 + offset;
                if self.is_valid_gobjects_address(target_addr) {
                    return Ok(target_addr);
                }
            }
        }
        
        Err("GObjects not found".into())
    }

    fn find_gobjects_via_data_section(&self) -> Option<u64> {
        let mut current_address = self.module_base;
        let max_address = self.module_base + 0x10000000; // 256MB
        
        while current_address < max_address {
            // Проверяем структуру FUObjectArray
            if self.is_valid_fuobject_array(current_address) {
                return Some(current_address);
            }
            
            current_address += 0x4; // Выравнивание по 4 байта
        }
        
        None
    }

    // Проверка валидности структуры FUObjectArray
    fn is_valid_fuobject_array(&self, addr: u64) -> bool {
        // Читаем первые поля структуры
        if let Ok(objects_offset) = self.read_memory::<u32>(addr) {
            if let Ok(max_objects_offset) = self.read_memory::<u32>(addr + 4) {
                if let Ok(num_objects_offset) = self.read_memory::<u32>(addr + 8) {
                    // Проверяем валидность оффсетов
                    if objects_offset > 0 && objects_offset < 0x1000 &&
                       max_objects_offset > 0 && max_objects_offset < 0x1000 &&
                       num_objects_offset > 0 && num_objects_offset < 0x1000 {
                        
                        // Проверяем указатель на объекты
                        let objects_ptr = addr + objects_offset as u64;
                        if let Ok(first_item_ptr) = self.read_memory::<u64>(objects_ptr) {
                            return first_item_ptr != 0 && first_item_ptr < 0x7FFFFFFFFFFF;
                        }
                    }
                }
            }
        }
        
        false
    }

    // Проверка валидности адреса GObjects
    fn is_valid_gobjects_address(&self, addr: u64) -> bool {
        if addr < self.module_base || addr > self.module_base + 0x10000000 {
            return false;
        }
        
        // Проверяем структуру FUObjectArray
        self.is_valid_fuobject_array(addr)
    }

    // Продвинутый поиск GWorld через анализ World объектов (методика @Engine/)
    fn find_gworld_advanced(&self) -> Result<u64, Box<dyn std::error::Error>> {
        // Методика из @Engine/ - ищем через UWorld объекты
        if let Some(addr) = self.find_gworld_via_world_objects() {
            return Ok(addr);
        }
        
        // Ищем строки, связанные с World
        let strings_to_find = [
            "SeamlessTravel FlushLevelStreaming",
            "World::Tick",
            "UWorld::BeginPlay",
            "GetWorld",
            "UWorld::GetWorld",
            "GWorld",
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
            (vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00], "xxx????"),
        ];
        
        for (signature, mask) in &signatures {
            if let Some(addr) = self.scan_signature_advanced(signature, mask) {
                let offset = self.read_memory::<i32>(addr + 3)? as u64;
                let target_addr = addr + 7 + offset;
                if self.is_valid_gworld_address(target_addr) {
                    return Ok(target_addr);
                }
            }
        }
        
        Err("GWorld not found".into())
    }

    // Поиск GWorld через UWorld объекты (методика @Engine/)
    fn find_gworld_via_world_objects(&self) -> Option<u64> {
        // Сканируем память в поисках указателей на UWorld объекты
        let mut current_address = self.module_base;
        let max_address = self.module_base + 0x10000000; // 256MB
        
        while current_address < max_address {
            // Проверяем валидность указателя
            if let Ok(ptr_value) = self.read_memory::<u64>(current_address) {
                if ptr_value != 0 && ptr_value < 0x7FFFFFFFFFFF {
                    // Проверяем, что это может быть указатель на UWorld
                    if self.is_valid_world_object(ptr_value) {
                        // Ищем выше по коду инструкции записи в GWorld
                        if let Some(gworld_addr) = self.find_gworld_write_instruction(current_address) {
                            return Some(gworld_addr);
                        }
                    }
                }
            }
            
            current_address += 0x8; // Выравнивание по 8 байт
        }
        
        None
    }

    // Проверка валидности World объекта
    fn is_valid_world_object(&self, addr: u64) -> bool {
        // Простая проверка - адрес должен быть в пределах модуля
        if addr < self.module_base || addr > self.module_base + 0x10000000 {
            return false;
        }
        
        // Пытаемся прочитать первые байты
        if let Ok(first_bytes) = self.read_memory::<u64>(addr) {
            return first_bytes != 0 && first_bytes < 0x7FFFFFFFFFFF;
        }
        
        false
    }

    // Поиск инструкции записи в GWorld
    fn find_gworld_write_instruction(&self, world_ptr_addr: u64) -> Option<u64> {
        // Ищем выше по коду инструкции записи в GWorld
        for offset in 1..0x1000 {
            let addr = world_ptr_addr.saturating_sub(offset);
            
            // Проверяем инструкции mov [rip+offset], rax
            if let Ok(byte) = self.read_memory::<u8>(addr) {
                if byte == 0x48 { // mov
                    if let Ok(next_byte) = self.read_memory::<u8>(addr + 1) {
                        if next_byte == 0x89 { // mov [rip+offset], rax
                            if let Ok(third_byte) = self.read_memory::<u8>(addr + 2) {
                                if third_byte == 0x15 { // mov [rip+offset], rdx
                                    if let Ok(offset_bytes) = self.read_memory::<i32>(addr + 3) {
                                        let target_addr = addr + 7 + offset_bytes as u64;
                                        if self.is_valid_gworld_address(target_addr) {
                                            return Some(target_addr);
                                        }
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

    // Проверка валидности адреса GWorld
    fn is_valid_gworld_address(&self, addr: u64) -> bool {
        if addr < self.module_base || addr > self.module_base + 0x10000000 {
            return false;
        }
        
        // Пытаемся прочитать указатель на UWorld
        if let Ok(world_ptr) = self.read_memory::<u64>(addr) {
            return world_ptr != 0 && world_ptr < 0x7FFFFFFFFFFF;
        }
        
        false
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
