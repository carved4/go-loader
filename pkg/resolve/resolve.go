// taken from my go-native-syscall/syscallresolve pkg
package resolve

import (
	"fmt"
	"log"
	"sync"
	"time"
	"unsafe"
	"sort"
	"strings"
	"github.com/Binject/debug/pe"
	"loader/pkg/obf"
)

// Windows structures needed for PEB access
type LIST_ENTRY struct {
	Flink *LIST_ENTRY
	Blink *LIST_ENTRY
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LDR_DATA_TABLE_ENTRY struct {
	InLoadOrderLinks       LIST_ENTRY
	InMemoryOrderLinks     LIST_ENTRY
	InInitializationOrderLinks LIST_ENTRY
	DllBase                uintptr
	EntryPoint             uintptr
	SizeOfImage            uintptr
	FullDllName            UNICODE_STRING
	BaseDllName            UNICODE_STRING
}

type PEB_LDR_DATA struct {
	Length                          uint32
	Initialized                     uint32
	SsHandle                        uintptr
	InLoadOrderModuleList           LIST_ENTRY
	InMemoryOrderModuleList         LIST_ENTRY
	InInitializationOrderModuleList LIST_ENTRY
}

type PEB struct {
	Reserved1              [2]byte
	BeingDebugged          byte
	Reserved2              byte
	Reserved3              [2]uintptr
	Ldr                    *PEB_LDR_DATA
	ProcessParameters      uintptr
	Reserved4              [3]uintptr
	AtlThunkSListPtr       uintptr
	Reserved5              uintptr
	Reserved6              uint32
	Reserved7              uintptr
	Reserved8              uint32
	AtlThunkSListPtr32     uint32
	Reserved9              [45]uintptr
	Reserved10             [96]byte
	PostProcessInitRoutine uintptr
	Reserved11             [128]byte
	Reserved12             [1]uintptr
	SessionId              uint32
}

// GetPEB directly using assembly (Windows x64)
//
//go:nosplit
//go:noinline
func GetPEB() uintptr

// The x64 implementation is kept in assembly in pkg/syscallresolve/peb_windows_amd64.s
// Using the following:
/*
// Assembly for peb_windows_amd64.s:
TEXT ·GetPEB(SB), $0-8
    MOVQ 0x60(GS), AX  // Access PEB from GS register (x64)
    MOVQ AX, ret+0(FP)
    RET
*/

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

// GetCurrentProcessPEB retrieves a pointer to the PEB of the current process
// This uses a direct assembly approach without any Windows API calls
func GetCurrentProcessPEB() *PEB {
	// Using direct assembly to get PEB
	pebAddr := GetPEB()
	if pebAddr == 0 {
		log.Printf("Failed to get PEB address via assembly\n")
		return nil
	}
	
	// Add some retry attempts to ensure stability
	maxRetries := 5
	var peb *PEB
	
	for i := 0; i < maxRetries; i++ {
		peb = (*PEB)(unsafe.Pointer(pebAddr))
		
		// Validate PEB pointer
		if peb != nil && peb.Ldr != nil {
			return peb
		}
		
		log.Printf("PEB validation failed (retry %d/%d), waiting...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	return peb
}

// GetModuleBase retrieves the base address of a module by its name hash
func GetModuleBase(moduleHash uint32) uintptr {
	// Add retry mechanism for GetModuleBase
	maxRetries := 5
	var moduleBase uintptr
	
	for i := 0; i < maxRetries; i++ {
		peb := GetCurrentProcessPEB()
		if peb == nil {
			log.Printf("Failed to get PEB, retrying (%d/%d)...\n", i+1, maxRetries)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		if peb.Ldr == nil {
			log.Printf("PEB.Ldr is nil, retrying (%d/%d)...\n", i+1, maxRetries)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		
		// Try all three module lists for better reliability
		// Sometimes a DLL might be in one list but not the others
		lists := []struct {
			name string
			entry *LIST_ENTRY
		}{
			{"InLoadOrderModuleList", &peb.Ldr.InLoadOrderModuleList},
			{"InMemoryOrderModuleList", &peb.Ldr.InMemoryOrderModuleList},
			{"InInitializationOrderModuleList", &peb.Ldr.InInitializationOrderModuleList},
		}
		
		for _, list := range lists {
			// Get the head of the module list
			entry := list.entry
			currentEntry := entry.Flink
		
			// Ensure the linked list is valid
			if currentEntry == nil {
				log.Printf("Module list %s is invalid (nil), skipping\n", list.name)
				continue
			}
		
			// Iterate through the module list
			var offset uintptr
			var dataTableEntry *LDR_DATA_TABLE_ENTRY
			
			// Different lists have different offsets to LDR_DATA_TABLE_ENTRY
			switch list.name {
			case "InLoadOrderModuleList":
				offset = 0 // No offset needed
			case "InMemoryOrderModuleList":
				offset = unsafe.Offsetof(LDR_DATA_TABLE_ENTRY{}.InMemoryOrderLinks)
			case "InInitializationOrderModuleList":
				offset = unsafe.Offsetof(LDR_DATA_TABLE_ENTRY{}.InInitializationOrderLinks)
			}
			
			for currentEntry != entry {
				if offset == 0 {
					// For InLoadOrderModuleList
					dataTableEntry = (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(currentEntry))
				} else {
					// For other lists, adjust the pointer
					dataTableEntry = (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(currentEntry)) - offset))
				}
		
				// Get the module name
				baseName := UTF16ToString(dataTableEntry.BaseDllName.Buffer)
				
				// Skip if empty name (shouldn't happen but a safety check)
				if baseName == "" {
					currentEntry = currentEntry.Flink
					continue
				}
				
				// Normalize to lowercase for case-insensitive comparison
				baseName = strings.ToLower(baseName)
				
				// Calculate the hash of the module name
				currentHash := obf.DBJ2HashStr(baseName)
				
				// Debug output to check the found modules
				// log.Printf("Found module: %s with hash 0x%X\n", baseName, currentHash)
				
				// If the hash matches, return the module base
				if currentHash == moduleHash {
					moduleBase = dataTableEntry.DllBase
					break
				}
		
				// Move to the next entry
				currentEntry = currentEntry.Flink
				
				// Safety check to prevent infinite loops
				if currentEntry == nil {
					break
				}
			}
			
			if moduleBase != 0 {
				// log.Printf("Found module base 0x%X in list %s\n", moduleBase, list.name)
				break
			}
		}
		
		if moduleBase != 0 {
			break
		}
		
		// Wait before retrying
		time.Sleep(100 * time.Millisecond)
	}

	return moduleBase
}

// GetFunctionAddress retrieves the address of a function in a module by its name hash using Binject PE parser
func GetFunctionAddress(moduleBase uintptr, functionHash uint32) uintptr {
	if moduleBase == 0 {
		return 0
	}

	// Read the PE header to get the actual size of the image
	dosHeader := (*[64]byte)(unsafe.Pointer(moduleBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		log.Printf("Invalid DOS signature\n")
		return 0
	}
	
	// Get the offset to the PE header
	peOffset := *(*uint32)(unsafe.Pointer(moduleBase + 60))
	if peOffset >= 1024 {
		log.Printf("PE offset too large: %d\n", peOffset)
		return 0
	}
	
	// Read the PE header to get the SizeOfImage
	peHeader := (*[1024]byte)(unsafe.Pointer(moduleBase + uintptr(peOffset)))
	if peHeader[0] != 'P' || peHeader[1] != 'E' {
		log.Printf("Invalid PE signature\n")
		return 0
	}
	
	// SizeOfImage is at offset 56 from the start of the OptionalHeader
	// OptionalHeader starts at offset 24 from PE signature
	sizeOfImage := *(*uint32)(unsafe.Pointer(moduleBase + uintptr(peOffset) + 24 + 56))
	
	// Create a memory reader for the PE file with the correct size
	dataSlice := unsafe.Slice((*byte)(unsafe.Pointer(moduleBase)), sizeOfImage)
	
	// Parse the PE file from memory
	file, err := pe.NewFileFromMemory(&memoryReaderAt{data: dataSlice})
	if err != nil {
		log.Printf("Failed to parse PE file: %v\n", err)
		return 0
	}
	defer file.Close()

	// Get the exports
	exports, err := file.Exports()
	if err != nil {
		log.Printf("Failed to get exports: %v\n", err)
		return 0
	}

	// Search for the function by hash
	for _, export := range exports {
		if export.Name != "" {
			currentHash := obf.DBJ2HashStr(export.Name)
			if currentHash == functionHash {
				// Return the function address (module base + RVA)
				return moduleBase + uintptr(export.VirtualAddress)
			}
		}
	}

	return 0
}

// memoryReaderAt implements io.ReaderAt for in-memory data
type memoryReaderAt struct {
	data []byte
}

func (r *memoryReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || off >= int64(len(r.data)) {
		return 0, fmt.Errorf("offset out of range")
	}
	n = copy(p, r.data[off:])
	if n < len(p) {
		err = fmt.Errorf("EOF")
	}
	return n, err
}

// GetSyscallNumber extracts the syscall number from a NTDLL syscall function
// This function uses ONLY manual PE parsing and PEB walking - NO Windows API calls
func GetSyscallNumber(functionHash uint32) uint16 {
	// Try cache first for performance
	if cached := getSyscallFromCache(functionHash); cached != 0 {
		return cached
	}

	// Get the base address of ntdll.dll using PEB walking (no LoadLibrary)
	ntdllHash := obf.GetHash("ntdll.dll")
	
	// Add retry mechanism with exponential backoff
	var ntdllBase uintptr
	maxRetries := 8
	baseDelay := 50 * time.Millisecond
	
	for i := 0; i < maxRetries; i++ {
		ntdllBase = GetModuleBase(ntdllHash)
		if ntdllBase != 0 {
			break
		}
		
		// Exponential backoff
		delay := baseDelay * time.Duration(1<<uint(i))
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		
		log.Printf("Failed to get ntdll.dll base address, retrying (%d/%d) after %v...\n", i+1, maxRetries, delay)
		time.Sleep(delay)
	}
	
	if ntdllBase == 0 {
		log.Printf("Failed to get ntdll.dll base address after %d retries\n", maxRetries)
		return 0
	}
	
	// Get the address of the syscall function using PE parsing (no GetProcAddress)
	var funcAddr uintptr
	
	for i := 0; i < maxRetries; i++ {
		funcAddr = GetFunctionAddress(ntdllBase, functionHash)
		if funcAddr != 0 {
			break
		}
		
		// Exponential backoff
		delay := baseDelay * time.Duration(1<<uint(i))
		if delay > 2*time.Second {
			delay = 2 * time.Second
		}
		
		log.Printf("Failed to get function address, retrying (%d/%d) after %v...\n", i+1, maxRetries, delay)
		time.Sleep(delay)
	}
	
	if funcAddr == 0 {
		log.Printf("Failed to get function address for hash: 0x%X after %d retries\n", functionHash, maxRetries)
		return 0
	}

	// Enhanced syscall stub validation and extraction
	syscallNumber := extractSyscallNumberWithValidation(funcAddr, functionHash)
	
	// Cache the result if valid
	if syscallNumber != 0 {
		cacheSyscallNumber(functionHash, syscallNumber)
	}
	
	return syscallNumber
}

// Helper function to map function hashes to their string names (for debugging/testing)
func getFunctionNameFromHash(functionHash uint32) string {
	// Map common function hashes to their names
	commonFunctions := map[uint32]string{
		obf.GetHash("NtAllocateVirtualMemory"): "NtAllocateVirtualMemory",
		obf.GetHash("NtWriteVirtualMemory"):    "NtWriteVirtualMemory", 
		obf.GetHash("NtCreateThreadEx"):        "NtCreateThreadEx",
		obf.GetHash("NtProtectVirtualMemory"):  "NtProtectVirtualMemory",
		obf.GetHash("NtCreateProcess"):         "NtCreateProcess",
		obf.GetHash("NtCreateThread"):          "NtCreateThread",
		obf.GetHash("NtOpenProcess"):           "NtOpenProcess",
		obf.GetHash("NtClose"):                 "NtClose",
	}
	
	return commonFunctions[functionHash]
}

// GetSyscallAndAddress returns both the syscall number and the address of the syscall instruction
func GetSyscallAndAddress(functionHash uint32) (uint16, uintptr) {
	// Get the base address of ntdll.dll using PEB walking (no LoadLibrary)
	ntdllHash := obf.GetHash("ntdll.dll")
	
	// Add retry mechanism
	var ntdllBase uintptr
	maxRetries := 5
	
	for i := 0; i < maxRetries; i++ {
		ntdllBase = GetModuleBase(ntdllHash)
		if ntdllBase != 0 {
			break
		}
		log.Printf("Failed to get ntdll.dll base address, retrying (%d/%d)...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	if ntdllBase == 0 {
		log.Printf("Failed to get ntdll.dll base address after %d retries\n", maxRetries)
		return 0, 0
	}

	// Get the address of the syscall function using PE parsing (no GetProcAddress)
	var funcAddr uintptr
	
	for i := 0; i < maxRetries; i++ {
		funcAddr = GetFunctionAddress(ntdllBase, functionHash)
		if funcAddr != 0 {
			break
		}
		log.Printf("Failed to get function address, retrying (%d/%d)...\n", i+1, maxRetries)
		time.Sleep(100 * time.Millisecond)
	}
	
	if funcAddr == 0 {
		log.Printf("Failed to get function address for hash: 0x%X after %d retries\n", functionHash, maxRetries)
		return 0, 0
	}

	// The syscall number is at offset 4 in the syscall stub
	syscallNumber := *(*uint16)(unsafe.Pointer(funcAddr + 4))
	
	// The syscall instruction is at offset 0x12 for x64
	syscallInstructionAddr := funcAddr + 0x12
	
	return syscallNumber, syscallInstructionAddr
}

// Helper function to dump memory for debugging
func dumpMemory(addr uintptr, size int) {
	log.Printf("Memory dump at 0x%X:\n", addr)
	for i := 0; i < size; i++ {
		if i%16 == 0 {
			log.Printf("%08X: ", i)
		}
		b := *(*byte)(unsafe.Pointer(addr + uintptr(i)))
		log.Printf("%02X ", b)
		if i%16 == 15 || i == size-1 {
			log.Printf("\n")
		}
	}
}

// SyscallCache provides thread-safe caching for resolved syscall numbers
type SyscallCache struct {
	cache map[uint32]uint16
	mutex sync.RWMutex
}

var globalSyscallCache = &SyscallCache{
	cache: make(map[uint32]uint16),
}

// getSyscallFromCache retrieves a cached syscall number
func getSyscallFromCache(functionHash uint32) uint16 {
	globalSyscallCache.mutex.RLock()
	defer globalSyscallCache.mutex.RUnlock()
	
	if syscallNum, exists := globalSyscallCache.cache[functionHash]; exists {
		return syscallNum
	}
	return 0
}

// cacheSyscallNumber stores a syscall number in the cache
func cacheSyscallNumber(functionHash uint32, syscallNumber uint16) {
	globalSyscallCache.mutex.Lock()
	defer globalSyscallCache.mutex.Unlock()
	
	globalSyscallCache.cache[functionHash] = syscallNumber
}

// clearSyscallCache clears all cached syscall numbers (useful for testing)
func clearSyscallCache() {
	globalSyscallCache.mutex.Lock()
	defer globalSyscallCache.mutex.Unlock()
	
	globalSyscallCache.cache = make(map[uint32]uint16)
}

// GetSyscallCacheSize returns the number of cached syscalls
func GetSyscallCacheSize() int {
	globalSyscallCache.mutex.RLock()
	defer globalSyscallCache.mutex.RUnlock()
	
	return len(globalSyscallCache.cache)
}

// extractSyscallNumberWithValidation performs enhanced validation and extraction
func extractSyscallNumberWithValidation(funcAddr uintptr, functionHash uint32) uint16 {
	if funcAddr == 0 {
		return 0
	}

	// Read enough bytes to analyze the function
	const maxBytes = 32
	funcBytes := make([]byte, maxBytes)
	
	// Safely read memory with bounds checking
	for i := 0; i < maxBytes; i++ {
		funcBytes[i] = *(*byte)(unsafe.Pointer(funcAddr + uintptr(i)))
	}

	// Try multiple syscall stub patterns for robustness
	syscallNumber := tryExtractSyscallNumber(funcBytes, funcAddr, functionHash)
	
	// Validate the extracted syscall number
	if syscallNumber > 0 && validateSyscallNumber(syscallNumber, functionHash) {
		return syscallNumber
	}

	// Fallback: try alternative extraction methods
	return tryAlternativeExtractionMethods(funcBytes, funcAddr, functionHash)
}

// tryExtractSyscallNumber attempts to extract syscall number using multiple patterns
func tryExtractSyscallNumber(funcBytes []byte, funcAddr uintptr, functionHash uint32) uint16 {
	if len(funcBytes) < 16 {
		return 0
	}

	// Pattern 1: Standard x64 syscall stub
	// 0: 4c 8b d1             mov r10, rcx
	// 3: b8 XX XX 00 00       mov eax, XXXX
	// 8: f6 04 25 08 03 fe 7f test byte ptr [0x7ffe0308], 1
	if len(funcBytes) >= 8 &&
		funcBytes[0] == 0x4c && funcBytes[1] == 0x8b && funcBytes[2] == 0xd1 &&
		funcBytes[3] == 0xb8 {
		
		syscallNum := uint16(funcBytes[4]) | (uint16(funcBytes[5]) << 8)
		if syscallNum > 0 && syscallNum < 2000 { // Reasonable range check
			return syscallNum
		}
	}

	// Pattern 2: Alternative syscall stub (some Windows versions)
	// 0: b8 XX XX 00 00       mov eax, XXXX
	// 5: 4c 8b d1             mov r10, rcx
	if len(funcBytes) >= 8 &&
		funcBytes[0] == 0xb8 &&
		funcBytes[5] == 0x4c && funcBytes[6] == 0x8b && funcBytes[7] == 0xd1 {
		
		syscallNum := uint16(funcBytes[1]) | (uint16(funcBytes[2]) << 8)
		if syscallNum > 0 && syscallNum < 2000 {
			return syscallNum
		}
	}

	// Pattern 3: Hooked syscall detection (look for JMP instruction)
	// If we find a JMP at the beginning, the function might be hooked
	if funcBytes[0] == 0xe9 || funcBytes[0] == 0xeb || funcBytes[0] == 0xff {
		log.Printf("Warning: Function at 0x%X appears to be hooked (starts with JMP: 0x%02X)\n", 
			funcAddr, funcBytes[0])
		return 0
	}

	return 0
}

// validateSyscallNumber performs additional validation on extracted syscall numbers
func validateSyscallNumber(syscallNumber uint16, functionHash uint32) bool {
	// Basic range validation
	if syscallNumber == 0 || syscallNumber >= 2000 {
		return false
	}

	// Check against known invalid ranges
	// Syscall numbers should be reasonable for NT kernel functions
	if syscallNumber < 2 {
		// Only syscall numbers 0 and 1 are truly suspicious
		log.Printf("Warning: Unusually low syscall number %d for hash 0x%X\n", 
			syscallNumber, functionHash)
	}

	// Additional validation could include (if you want to submit a PR)
	// - Cross-referencing with known good syscall numbers
	// - Checking if the syscall number fits expected patterns
	// - Validating against syscall tables from different Windows versions

	return true
}

// tryAlternativeExtractionMethods provides fallback extraction when standard methods fail
func tryAlternativeExtractionMethods(funcBytes []byte, funcAddr uintptr, functionHash uint32) uint16 {
	// Method 1: Scan for MOV EAX instructions in the first 32 bytes
	for i := 0; i < len(funcBytes)-4; i++ {
		if funcBytes[i] == 0xb8 { // MOV EAX, imm32
			syscallNum := uint16(funcBytes[i+1]) | (uint16(funcBytes[i+2]) << 8)
			if syscallNum > 0 && syscallNum < 2000 {
				log.Printf("Alternative extraction found syscall %d at offset %d for hash 0x%X\n", 
					syscallNum, i, functionHash)
				return syscallNum
			}
		}
	}

	// Method 2: Look for syscall instruction and backtrack
	for i := 0; i < len(funcBytes)-1; i++ {
		if funcBytes[i] == 0x0f && funcBytes[i+1] == 0x05 { // SYSCALL instruction
			// Found syscall instruction, now look backwards for MOV EAX
			for j := i; j >= 4; j-- {
				if funcBytes[j-4] == 0xb8 { // MOV EAX, imm32
					syscallNum := uint16(funcBytes[j-3]) | (uint16(funcBytes[j-2]) << 8)
					if syscallNum > 0 && syscallNum < 2000 {
						log.Printf("Backtrack extraction found syscall %d for hash 0x%X\n", 
							syscallNum, functionHash)
						return syscallNum
					}
				}
			}
			break
		}
	}

	// Method 3: Try reading at different offsets (handle potential hooks/patches)
	alternativeOffsets := []int{8, 12, 16, 20}
	for _, offset := range alternativeOffsets {
		if offset+1 < len(funcBytes) {
			if funcBytes[offset] == 0xb8 { // MOV EAX
				syscallNum := uint16(funcBytes[offset+1]) | (uint16(funcBytes[offset+2]) << 8)
				if syscallNum > 0 && syscallNum < 2000 {
					log.Printf("Offset extraction found syscall %d at offset %d for hash 0x%X\n", 
						syscallNum, offset, functionHash)
					return syscallNum
				}
			}
		}
	}

	log.Printf("All extraction methods failed for hash 0x%X\n", functionHash)
	return 0
}

// GetSyscallWithValidation provides additional metadata and validation
func GetSyscallWithValidation(functionHash uint32) (uint16, bool, error) {
	syscallNum := GetSyscallNumber(functionHash)
	
	if syscallNum == 0 {
		return 0, false, fmt.Errorf("failed to resolve syscall for hash 0x%X", functionHash)
	}

	// Additional validation
	isValid := validateSyscallNumber(syscallNum, functionHash)
	
	return syscallNum, isValid, nil
}

// GuessSyscallNumber attempts to infer a syscall number for a hooked function
// by finding clean left and right neighbors and interpolating the missing number.
func GuessSyscallNumber(targetHash uint32) uint16 {
	ntdllBase := GetModuleBase(obf.GetHash("ntdll.dll"))
	if ntdllBase == 0 {
		log.Printf("Failed to get ntdll.dll base for delta guessing\n")
		return 0
	}

	// Parse exports from NTDLL
	dosHeader := (*[2]byte)(unsafe.Pointer(ntdllBase))
	if dosHeader[0] != 'M' || dosHeader[1] != 'Z' {
		log.Printf("Invalid DOS signature in NTDLL\n")
		return 0
	}

	peOffset := *(*uint32)(unsafe.Pointer(ntdllBase + 0x3C))
	file := (*[1024]byte)(unsafe.Pointer(ntdllBase + uintptr(peOffset)))
	if file[0] != 'P' || file[1] != 'E' {
		log.Printf("Invalid PE signature\n")
		return 0
	}

	sizeOfImage := *(*uint32)(unsafe.Pointer(ntdllBase + uintptr(peOffset) + 24 + 56))
	slice := unsafe.Slice((*byte)(unsafe.Pointer(ntdllBase)), sizeOfImage)
	peFile, err := pe.NewFileFromMemory(&memoryReaderAt{data: slice})
	if err != nil {
		log.Printf("Failed to parse NTDLL PE: %v\n", err)
		return 0
	}
	exports, err := peFile.Exports()
	if err != nil {
		log.Printf("Failed to list NTDLL exports: %v\n", err)
		return 0
	}

	// Sort exports by address
	sort.Slice(exports, func(i, j int) bool {
		return exports[i].VirtualAddress < exports[j].VirtualAddress
	})

	// Find the target function
	targetIndex := -1
	for i, exp := range exports {
		if obf.GetHash(exp.Name) == targetHash {
			targetIndex = i
			break
		}
	}

	if targetIndex == -1 {
		log.Printf("Target function not found for hash 0x%X\n", targetHash)
		return 0
	}

	// Helper function to check if a function is hooked
	isCleanSyscall := func(addr uintptr) (bool, uint16) {
		bytes := *(*[8]byte)(unsafe.Pointer(addr))
		// Check for standard syscall stub pattern
		if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
			syscallNum := uint16(bytes[4]) | uint16(bytes[5])<<8
			return true, syscallNum
		}
		return false, 0
	}

	// Helper function to check if two function names are NT/ZW pairs
	isNtZwPair := func(name1, name2 string) bool {
		if len(name1) < 2 || len(name2) < 2 {
			return false
		}
		// Check if one starts with Nt and other with Zw, and rest is same
		if (name1[:2] == "Nt" && name2[:2] == "Zw" && name1[2:] == name2[2:]) ||
		   (name1[:2] == "Zw" && name2[:2] == "Nt" && name1[2:] == name2[2:]) {
			return true
		}
		return false
	}

	// First, check if there's a ZW/NT pair nearby (they have identical syscall numbers)
	for offset := -5; offset <= 5; offset++ {
		if offset == 0 {
			continue
		}
		
		pairIdx := targetIndex + offset
		if pairIdx < 0 || pairIdx >= len(exports) {
			continue
		}

		if isNtZwPair(exports[targetIndex].Name, exports[pairIdx].Name) {
			pairAddr := ntdllBase + uintptr(exports[pairIdx].VirtualAddress)
			if clean, syscallNum := isCleanSyscall(pairAddr); clean {
				log.Printf("Found NT/ZW pair %s with syscall %d for target %s\n", 
					exports[pairIdx].Name, syscallNum, exports[targetIndex].Name)
				return syscallNum
			}
		}
	}

	// Find clean left neighbor
	var leftSyscall uint16
	var leftIndex int = -1
	for i := targetIndex - 1; i >= 0 && i >= targetIndex-10; i-- {
		addr := ntdllBase + uintptr(exports[i].VirtualAddress)
		if clean, syscallNum := isCleanSyscall(addr); clean {
			leftSyscall = syscallNum
			leftIndex = i
			break
		}
	}

	// Find clean right neighbor  
	var rightSyscall uint16
	var rightIndex int = -1
	for i := targetIndex + 1; i < len(exports) && i <= targetIndex+10; i++ {
		addr := ntdllBase + uintptr(exports[i].VirtualAddress)
		if clean, syscallNum := isCleanSyscall(addr); clean {
			rightSyscall = syscallNum
			rightIndex = i
			break
		}
	}

	// If we have both neighbors, interpolate
	if leftIndex != -1 && rightIndex != -1 {
		// Calculate the expected syscall number based on position
		positionDiff := targetIndex - leftIndex
		syscallDiff := rightSyscall - leftSyscall
		indexDiff := rightIndex - leftIndex
		
		if indexDiff > 0 {
			interpolated := leftSyscall + uint16((syscallDiff*uint16(positionDiff))/uint16(indexDiff))
			log.Printf("Interpolated syscall %d for hash 0x%X between %s(%d) and %s(%d)\n", 
				interpolated, targetHash, exports[leftIndex].Name, leftSyscall, exports[rightIndex].Name, rightSyscall)
			return interpolated
		}
	}

	// Fallback: use single neighbor with small offset
	if leftIndex != -1 {
		offset := targetIndex - leftIndex
		guessed := leftSyscall + uint16(offset)
		log.Printf("Guessed syscall %d for hash 0x%X using left neighbor %s(%d) + %d\n", 
			guessed, targetHash, exports[leftIndex].Name, leftSyscall, offset)
		return guessed
	}

	if rightIndex != -1 {
		offset := rightIndex - targetIndex
		guessed := rightSyscall - uint16(offset)
		log.Printf("Guessed syscall %d for hash 0x%X using right neighbor %s(%d) - %d\n", 
			guessed, targetHash, exports[rightIndex].Name, rightSyscall, offset)
		return guessed
	}

	log.Printf("Failed to find clean neighbors for hash 0x%X\n", targetHash)
	return 0
}


// hgSyscall is implemented in syscall_windows_amd64.s
// It executes a raw syscall using the assembly implementation
func hgSyscall(callid uint16, argh ...uintptr) uint32

// Syscall executes a syscall with the given number and arguments.
// This function acts as a wrapper around the assembly implementation.
func Syscall(syscallNum uint16, args ...uintptr) (uintptr, error) {
	ret := hgSyscall(syscallNum, args...)
	return uintptr(ret), nil
}

// DebugListAllModules prints all modules loaded in the PEB for debugging purposes
func DebugListAllModules() {
	peb := GetCurrentProcessPEB()
	if peb == nil {
		log.Printf("[DEBUG] Failed to get PEB\n")
		return
	}
	
	if peb.Ldr == nil {
		log.Printf("[DEBUG] PEB.Ldr is nil\n")
		return
	}
	
	// Try all three module lists for better visibility
	lists := []struct {
		name string
		entry *LIST_ENTRY
	}{
		{"InLoadOrderModuleList", &peb.Ldr.InLoadOrderModuleList},
		{"InMemoryOrderModuleList", &peb.Ldr.InMemoryOrderModuleList},
		{"InInitializationOrderModuleList", &peb.Ldr.InInitializationOrderModuleList},
	}
	
	for _, list := range lists {
		// Get the head of the module list
		entry := list.entry
		currentEntry := entry.Flink
		
		// Ensure the linked list is valid
		if currentEntry == nil {
			log.Printf("[DEBUG] Module list %s is invalid (nil)\n", list.name)
			continue
		}
		
		log.Printf("[DEBUG] Module summary for %s:\n", list.name)
		
		// Iterate through the module list
		var offset uintptr
		var dataTableEntry *LDR_DATA_TABLE_ENTRY
		
		// Different lists have different offsets to LDR_DATA_TABLE_ENTRY
		switch list.name {
		case "InLoadOrderModuleList":
			offset = 0 // No offset needed
		case "InMemoryOrderModuleList":
			offset = unsafe.Offsetof(LDR_DATA_TABLE_ENTRY{}.InMemoryOrderLinks)
		case "InInitializationOrderModuleList":
			offset = unsafe.Offsetof(LDR_DATA_TABLE_ENTRY{}.InInitializationOrderLinks)
		}
		
		for currentEntry != entry {
			if offset == 0 {
				// For InLoadOrderModuleList
				dataTableEntry = (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(currentEntry))
			} else {
				// For other lists, adjust the pointer
				dataTableEntry = (*LDR_DATA_TABLE_ENTRY)(unsafe.Pointer(uintptr(unsafe.Pointer(currentEntry)) - offset))
			}
			
			// Get the module name
			baseName := UTF16ToString(dataTableEntry.BaseDllName.Buffer)
			
			// Skip if empty name
			if baseName == "" {
				currentEntry = currentEntry.Flink
				continue
			}
			
			// Normalize to lowercase for case-insensitive comparison
			baseName = strings.ToLower(baseName)
			
			// Calculate the hash of the module name
			currentHash := obf.DBJ2HashStr(baseName)
			
			// Print module information
			log.Printf("[DEBUG]   - %s: 0x%X\n", baseName, currentHash)
			
			// Move to the next entry
			currentEntry = currentEntry.Flink
			
			// Safety check to prevent infinite loops
			if currentEntry == nil {
				break
			}
		}
	}
	
	// Also specifically check for amsi.dll
	amsiHash := obf.GetHash("amsi.dll")
	log.Printf("[DEBUG] Looking for module with hash 0x%X (amsi.dll)\n", amsiHash)
	amsiBase := GetModuleBase(amsiHash)
	if amsiBase == 0 {
		log.Printf("[DEBUG] Failed to find module with hash 0x%X (amsi.dll)\n", amsiHash)
		log.Printf("[DEBUG-AMSI] AMSI module not loaded or not found in PEB\n")
	} else {
		log.Printf("[DEBUG] Found amsi.dll at base address: 0x%X\n", amsiBase)
	}
}

