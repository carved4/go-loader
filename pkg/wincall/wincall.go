package wincall

import (
	"fmt"
	"unsafe"
	"go-loader/pkg/obf"
	"go-loader/pkg/resolve"
	"sync"
)

var (
	loadLibraryWAddr   uintptr
	getProcAddressAddr uintptr
	wincallOnce        sync.Once
)

func initAddresses() {
	kernel32Hash := obf.DBJ2HashStr("kernel32.dll")
	kernel32Base := resolve.GetModuleBase(kernel32Hash)
	if kernel32Base == 0 {
		return
	}
	loadLibraryWHash := obf.DBJ2HashStr("LoadLibraryW")
	loadLibraryWAddr = resolve.GetFunctionAddress(kernel32Base, loadLibraryWHash)

	getProcAddressHash := obf.DBJ2HashStr("GetProcAddress")
	getProcAddressAddr = resolve.GetFunctionAddress(kernel32Base, getProcAddressHash)
}

type libcall struct {
	fn   uintptr
	n    uintptr
	args uintptr
	r1   uintptr
	r2   uintptr
	err  uintptr
}

func wincall(libcall *libcall)

func LoadLibraryW(name string) uintptr {
	namePtr, _ := UTF16PtrFromString(name)
	args := []uintptr{uintptr(unsafe.Pointer(namePtr))}
	lc := &libcall{
		fn:   getLoadLibraryWAddr(),
		n:    1,
		args: uintptr(unsafe.Pointer(&args[0])),
	}

	wincall(lc)
	return lc.r1
}

func GetProcAddress(moduleHandle uintptr, proc unsafe.Pointer) uintptr {
	lc := &libcall{
		fn:   getGetProcAddressAddr(),
		n:    2,
		args: uintptr(unsafe.Pointer(&[]uintptr{moduleHandle, uintptr(proc)}[0])),
	}
	wincall(lc)
	return lc.r1
}

func getLoadLibraryWAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return loadLibraryWAddr
}

func getGetProcAddressAddr() uintptr {
	wincallOnce.Do(initAddresses)
	return getProcAddressAddr
}

func IsDebuggerPresent() bool {
	kernel32Hash := obf.DBJ2HashStr("kernel32.dll")
	kernel32Base := resolve.GetModuleBase(kernel32Hash)
	procName, _ := BytePtrFromString("IsDebuggerPresent")
	isDebuggerPresentAddr := GetProcAddress(kernel32Base, unsafe.Pointer(procName))
	if isDebuggerPresentAddr == 0 {
		return false
	}
	lc := &libcall{
		fn:   isDebuggerPresentAddr,
		n:    0,
		args: uintptr(0),
	}
	wincall(lc)
	return lc.r1 != 0
}

func CheckRemoteDebuggerPresent(hProcess uintptr, pbDebuggerPresent *bool) error {
	kernel32Hash := obf.DBJ2HashStr("kernel32.dll")
	kernel32Base := resolve.GetModuleBase(kernel32Hash)
	procName, _ := BytePtrFromString("CheckRemoteDebuggerPresent")
	checkRemoteDebuggerPresentAddr := GetProcAddress(kernel32Base, unsafe.Pointer(procName))
	if checkRemoteDebuggerPresentAddr == 0 {
		return fmt.Errorf("could not find CheckRemoteDebuggerPresent")
	}
	var isPresent uint32
	args := []uintptr{hProcess, uintptr(unsafe.Pointer(&isPresent))}
	lc := &libcall{
		fn:   checkRemoteDebuggerPresentAddr,
		n:    2,
		args: uintptr(unsafe.Pointer(&args[0])),
	}
	wincall(lc)
	*pbDebuggerPresent = (isPresent != 0)
	if lc.r1 == 0 {
		return fmt.Errorf("CheckRemoteDebuggerPresent failed")
	}
	return nil
}

func Call(proc uintptr, args ...uintptr) (r1, r2, err uintptr) {
	lc := &libcall{
		fn: proc,
		n:  uintptr(len(args)),
	}
	if len(args) > 0 {
		lc.args = uintptr(unsafe.Pointer(&args[0]))
	} else {
		lc.args = uintptr(0)
	}
	wincall(lc)
	return lc.r1, lc.r2, lc.err
}

func UTF16PtrFromString(s string) (*uint16, error) {
	runes := []rune(s)
	buf := make([]uint16, len(runes)+1)
	for i, r := range runes {
		if r <= 0xFFFF {
			buf[i] = uint16(r)
		} else {
			// surrogate pair
			r -= 0x10000
			buf[i] = 0xD800 + uint16(r>>10)
			i++
			buf[i] = 0xDC00 + uint16(r&0x3FF)
		}
	}
	return &buf[0], nil
}

func BytePtrFromString(s string) (*byte, error) {
	bytes := append([]byte(s), 0)
	return &bytes[0], nil
}

// UTF16ToString converts a UTF16 string to a Go string
func UTF16ToString(ptr *uint16) string {
	if ptr == nil {
		return ""
	}

	// Find the length by searching for null terminator
	length := 0
	for tmp := ptr; *tmp != 0; tmp = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(tmp)) + 2)) {
		length++
	}

	// Create a slice of uint16 values
	slice := make([]uint16, length)
	for i := 0; i < length; i++ {
		slice[i] = *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i*2)))
	}

	// Convert to a Go string
	return string(utf16BytesToString(slice))
}

// utf16BytesToString converts UTF-16 bytes to string
func utf16BytesToString(b []uint16) string {
	// Decode UTF-16 to runes
	runes := make([]rune, 0, len(b))
	for i := 0; i < len(b); i++ {
		r := rune(b[i])
		// Handle surrogate pairs
		if r >= 0xD800 && r <= 0xDBFF && i+1 < len(b) {
			r2 := rune(b[i+1])
			if r2 >= 0xDC00 && r2 <= 0xDFFF {
				r = (r-0xD800)<<10 + (r2 - 0xDC00) + 0x10000
				i++
			}
		}
		runes = append(runes, r)
	}
	return string(runes)
}
