# UE Offset Finder

> [!IMPORTANT]
> ⚠️ This repository is under heavy development. Structure and other stuff may change daily.

Modular tool for finding Unreal Engine offsets and exporting them to JSON format. **Works as a DLL injectable into the game.**

## Features

- **GNames Search** - via signatures and strings
- **GObjects Search** - via signatures and strings  
- **GWorld Search** - via signatures and strings
- **ProcessEvent Search** - via strings and code analysis
- **FName::AppendString Search** - via signatures and strings
- **CreateDefaultObject Search** - via strings and code analysis
- **JSON Export** - structured output of results

## Architecture

```
src/
├── lib.rs              # DLL entry point
├── logging.rs          # Logging system
└── offsets/
    ├── mod.rs          # Offsets module
    └── offset_finder.rs # Main search logic
```

**Key feature**: DLL works **inside** the target process, using direct memory reading without Windows API.

## Usage

### 1. Build

```bash
cargo build --release
```

### 2. Inject into process

```bash
# Inject DLL into UE game process
# (use any DLL injector)
```

### 3. Automatic search

After injection, DLL automatically:
1. Determines module base address
2. Finds all available offsets
3. Exports results to JSON file
4. Outputs information to console

## Search algorithms

### GNames
- **Signature**: `48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05 ?? ?? ?? ?? ?? 8B 50`
- **String**: `%d.%d.%d.%d.%d.%s`
- **Analysis**: Search above in code for `mov rax, cs:qword ptr [...]`

### GObjects  
- **Signature**: `48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1 48 85 C0`
- **String**: `Invalid object index in reference chain`
- **Analysis**: Search above in code for `mov rax, cs:qword ptr [...]`

### GWorld
- **Signature**: `48 89 15 ?? ?? ?? ?? 8B DA`
- **String**: `SeamlessTravel FlushLevelStreaming`
- **Analysis**: Search above in code for `mov cs:qword ptr [...], rax`

### ProcessEvent
- **String**: `Bad or missing property` or `AccessNoneNoContext`
- **Analysis**: Search above in code for `call qword ptr [rax+138h]`

### FName::AppendString
- **Signature**: `48 89 5C 24 ?? 56 48 83 EC ?? 80 3D ?? ?? ?? ?? ?? 48 8B DA`
- **String**: `Skeleton`
- **Analysis**: Search above in code for function start

### CreateDefaultObject
- **String**: `CanvasRenderTarget2DCanvas`
- **Analysis**: Search above in code for function start

## JSON Format

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

## Testing

```bash
cargo test
```

Tests cover:
- Creating offset structure
- Pattern search in buffers
- JSON export
- Error handling

## Requirements

- Windows 10/11
- Rust 1.70+
- Target process must be accessible for DLL injection
- Administrator rights for DLL injection

## Security

- **Does NOT use Windows API** for memory reading
- **Direct access** to current process memory
- **Automatic detection** of module base address
- Graceful degradation on errors

## Technical details

### Direct memory reading
```rust
fn read_memory<T>(&self, address: u64) -> Result<T, Box<dyn std::error::Error>> {
    let ptr = address as *const T;
    let value = unsafe { ptr.read_volatile() };
    Ok(value)
}
```

### Base address determination
```rust
fn get_module_base() -> u64 {
    // Get from PEB (Process Environment Block)
    unsafe {
        let peb = std::ptr::read_volatile(0x60 as *const u64);
        let ldr = std::ptr::read_volatile((peb + 0x18) as *const u64);
        let flink = std::ptr::read_volatile((ldr + 0x10) as *const u64);
        let module_base = std::ptr::read_volatile((flink + 0x30) as *const u64);
        module_base
    }
}
```

## Extension

To add new offsets:

1. Add field to `UEOffsets` structure
2. Implement search method in `OffsetFinder`
3. Add call to `find_all_offsets()`
4. Write tests

## License

MIT License
