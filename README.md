# UE Offset Finder

Модульный инструмент для поиска оффсетов Unreal Engine и экспорта их в JSON формат. **Работает как DLL, инжектируемый в игру.**

## Возможности

- **Поиск GNames** - через сигнатуры и строки
- **Поиск GObjects** - через сигнатуры и строки  
- **Поиск GWorld** - через сигнатуры и строки
- **Поиск ProcessEvent** - через строки и анализ кода
- **Поиск FName::AppendString** - через сигнатуры и строки
- **Поиск CreateDefaultObject** - через строки и анализ кода
- **Экспорт в JSON** - структурированный вывод результатов

## Архитектура

```
src/
├── lib.rs              # DLL entry point
├── logging.rs          # Система логирования
└── offsets/
    ├── mod.rs          # Модуль оффсетов
    └── offset_finder.rs # Основная логика поиска
```

**Ключевая особенность**: DLL работает **внутри** целевого процесса, используя прямое чтение памяти без Windows API.

## Использование

### 1. Сборка

```bash
cargo build --release
```

### 2. Инъекция в процесс

```bash
# Инжектируйте DLL в процесс UE игры
# (используйте любой инжектор DLL)
```

### 3. Автоматический поиск

После инъекции DLL автоматически:
1. Определит базовый адрес модуля
2. Найдет все доступные оффсеты
3. Экспортирует результаты в JSON файл
4. Выведет информацию в консоль

## Алгоритмы поиска

### GNames
- **Сигнатура**: `48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 8B 50`
- **Строка**: `%d.%d.%d.%d.%d.%s`
- **Анализ**: Поиск выше по коду `mov rax, cs:qword ptr [...]`

### GObjects  
- **Сигнатура**: `48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1 48 85 C0`
- **Строка**: `Invalid object index in reference chain`
- **Анализ**: Поиск выше по коду `mov rax, cs:qword ptr [...]`

### GWorld
- **Сигнатура**: `48 89 15 ?? ?? ?? ?? 8B DA`
- **Строка**: `SeamlessTravel FlushLevelStreaming`
- **Анализ**: Поиск выше по коду `mov cs:qword ptr [...], rax`

### ProcessEvent
- **Строка**: `Bad or missing property` или `AccessNoneNoContext`
- **Анализ**: Поиск выше по коду `call qword ptr [rax+138h]`

### FName::AppendString
- **Сигнатура**: `48 89 5C 24 ?? 56 48 83 EC ?? 80 3D ?? ?? ?? ?? ?? 48 8B DA`
- **Строка**: `Skeleton`
- **Анализ**: Поиск выше по коду начала функции

### CreateDefaultObject
- **Строка**: `CanvasRenderTarget2DCanvas`
- **Анализ**: Поиск выше по коду начала функции

## Формат JSON

```json
{
  "gnames": 140737488355328,
  "gobjects": 140737488355840,
  "gworld": 140737488356352,
  "process_event": 140737488356864,
  "fname_append_string": 140737488357376,
  "create_default_object": 140737488357888,
  "timestamp": "2024-01-01T12:00:00Z",
  "module_base": 140737488355328
}
```

## Тестирование

```bash
cargo test
```

Тесты покрывают:
- Создание структуры оффсетов
- Поиск паттернов в буферах
- Экспорт в JSON
- Обработку ошибок

## Требования

- Windows 10/11
- Rust 1.70+
- Целевой процесс должен быть доступен для инъекции DLL
- Права администратора для инъекции DLL

## Безопасность

- **НЕ использует Windows API** для чтения памяти
- **Прямой доступ** к памяти текущего процесса
- **Автоматическое определение** базового адреса модуля
- Graceful degradation при ошибках

## Технические детали

### Прямое чтение памяти
```rust
fn read_memory<T>(&self, address: u64) -> Result<T, Box<dyn std::error::Error>> {
    let ptr = address as *const T;
    let value = unsafe { ptr.read_volatile() };
    Ok(value)
}
```

### Определение базового адреса
```rust
fn get_module_base() -> u64 {
    // Получаем из PEB (Process Environment Block)
    unsafe {
        let peb = std::ptr::read_volatile(0x60 as *const u64);
        let ldr = std::ptr::read_volatile((peb + 0x18) as *const u64);
        let flink = std::ptr::read_volatile((ldr + 0x10) as *const u64);
        let module_base = std::ptr::read_volatile((flink + 0x30) as *const u64);
        module_base
    }
}
```

## Расширение

Для добавления новых оффсетов:

1. Добавьте поле в структуру `UEOffsets`
2. Реализуйте метод поиска в `OffsetFinder`
3. Добавьте вызов в `find_all_offsets()`
4. Напишите тесты

## Лицензия

MIT License
