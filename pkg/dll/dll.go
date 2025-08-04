package dll

import (
	"encoding/binary"
	"log"
	"strconv"
	"unsafe"
	api "github.com/carved4/go-wincall"
	types "loader/pkg/types"
)


func uintptrToBytes(ptr uintptr) []byte {
	ptrPtr := unsafe.Pointer(&ptr)

	byteSlice := make([]byte, unsafe.Sizeof(ptr))
	for i := 0; i < int(unsafe.Sizeof(ptr)); i++ {
		byteSlice[i] = *(*byte)(unsafe.Pointer(uintptr(ptrPtr) + uintptr(i)))
	}

	return byteSlice
}

// bytePtrToString converts a null-terminated byte pointer to a string
func bytePtrToString(ptr *byte) string {
	if ptr == nil {
		return ""
	}
	
	var result []byte
	for i := uintptr(0); ; i++ {
		b := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + i))
		if b == 0 {
			break
		}
		result = append(result, b)
	}
	
	return string(result)
}



func LoadDLL(dllBytes []byte, functionIdentifier interface{}) error {
	dllPtr := uintptr(unsafe.Pointer(&dllBytes[0]))

	e_lfanew := *((*uint32)(unsafe.Pointer(dllPtr + 0x3c)))
	nt_header := (*types.IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(e_lfanew)))

	dllBase := uintptr(nt_header.OptionalHeader.ImageBase)
	regionSize := uintptr(nt_header.OptionalHeader.SizeOfImage)
	status, err := api.NtAllocateVirtualMemory(^uintptr(0), &dllBase, 0, &regionSize, 
		types.MEM_RESERVE|types.MEM_COMMIT, types.PAGE_READWRITE)
	if err != nil || status != 0 {
		log.Fatalf("[ERROR] NtAllocateVirtualMemory Failed: status=0x%X, err=%v", status, err)
	}

	deltaImageBase := dllBase - uintptr(nt_header.OptionalHeader.ImageBase)
	var numberOfBytesWritten uintptr
	status, err = api.NtWriteVirtualMemory(^uintptr(0), dllBase, uintptr(unsafe.Pointer(&dllBytes[0])), uintptr(nt_header.OptionalHeader.SizeOfHeaders), &numberOfBytesWritten)
	if err != nil || status != 0 {
		log.Fatalf("[ERROR] NtWriteVirtualMemory Failed: status=0x%X, err=%v", status, err)
	}
	numberOfSections := int(nt_header.FileHeader.NumberOfSections)

	var sectionAddr uintptr
	sectionAddr = dllPtr + uintptr(e_lfanew) + unsafe.Sizeof(nt_header.Signature) + unsafe.Sizeof(nt_header.OptionalHeader) + unsafe.Sizeof(nt_header.FileHeader)

	for i := 0; i < numberOfSections; i++ {
		section := (*types.IMAGE_SECTION_HEADER)(unsafe.Pointer(sectionAddr))
		sectionDestination := dllBase + uintptr(section.VirtualAddress)
		sectionBytes := (*byte)(unsafe.Pointer(dllPtr + uintptr(section.PointerToRawData)))

		status, err = api.NtWriteVirtualMemory(^uintptr(0), sectionDestination, uintptr(unsafe.Pointer(sectionBytes)), uintptr(section.SizeOfRawData), &numberOfBytesWritten)
		if err != nil || status != 0 {
			log.Fatalf("[ERROR] NtWriteVirtualMemory Failed: status=0x%X, err=%v", status, err)
		}
		sectionAddr += unsafe.Sizeof(*section)
	}

	relocations := nt_header.OptionalHeader.DataDirectory[types.IMAGE_DIRECTORY_ENTRY_BASERELOC]
	relocation_table := uintptr(relocations.VirtualAddress) + dllBase

	var relocations_processed int = 0
	for {

		relocation_block := *(*types.BASE_RELOCATION_BLOCK)(unsafe.Pointer(uintptr(relocation_table + uintptr(relocations_processed))))
		relocEntry := relocation_table + uintptr(relocations_processed) + 8
		if relocation_block.BlockSize == 0 && relocation_block.PageAddress == 0 {
			break
		}
		relocationsCount := (relocation_block.BlockSize - 8) / 2

		relocationEntries := make([]types.BASE_RELOCATION_ENTRY, relocationsCount)

		for i := 0; i < int(relocationsCount); i++ {
			relocationEntries[i] = *(*types.BASE_RELOCATION_ENTRY)(unsafe.Pointer(relocEntry + uintptr(i*2)))
		}
		for _, relocationEntry := range relocationEntries {
			if relocationEntry.Type() == 0 {
				continue
			}
			var size uintptr
			byteSlice := make([]byte, unsafe.Sizeof(size))
			relocationRVA := relocation_block.PageAddress + uint32(relocationEntry.Offset())

			status, err = api.NtReadVirtualMemory(^uintptr(0), dllBase+uintptr(relocationRVA), uintptr(unsafe.Pointer(&byteSlice[0])), unsafe.Sizeof(size), nil)
			if err != nil || status != 0 {
				log.Fatalf("[ERROR] Failed to NtReadVirtualMemory: status=0x%X, err=%v", status, err)
			}
			addressToPatch := uintptr(binary.LittleEndian.Uint64(byteSlice))
			addressToPatch += deltaImageBase
			a2Patch := uintptrToBytes(addressToPatch)
			status, err = api.NtWriteVirtualMemory(^uintptr(0), dllBase+uintptr(relocationRVA), uintptr(unsafe.Pointer(&a2Patch[0])), uintptr(len(a2Patch)), nil)
			if err != nil || status != 0 {
				log.Fatalf("[ERROR] Failed to NtWriteVirtualMemory: status=0x%X, err=%v", status, err)
			}

		}
		relocations_processed += int(relocation_block.BlockSize)

	}

	importsDirectory := nt_header.OptionalHeader.DataDirectory[types.IMAGE_DIRECTORY_ENTRY_IMPORT]
	importDescriptorAddr := dllBase + uintptr(importsDirectory.VirtualAddress)

	for {
		importDescriptor := *(*types.IMAGE_IMPORT_DESCRIPTOR)(unsafe.Pointer(importDescriptorAddr))
		if importDescriptor.Name == 0 {
			break
		}
		libraryName := uintptr(importDescriptor.Name) + dllBase
		dllName := bytePtrToString((*byte)(unsafe.Pointer(libraryName)))
		hLibrary := api.LoadLibraryW(dllName)
		if hLibrary == 0 {
			log.Fatalf("[ERROR] LoadLibrary Failed for: %s", dllName)
		}
		addr := dllBase + uintptr(importDescriptor.FirstThunk)
		for {
			thunk := *(*uint16)(unsafe.Pointer(addr))
			if thunk == 0 {
				break
			}
			functionNameAddr := dllBase + uintptr(thunk+2)

			functionName := bytePtrToString((*byte)(unsafe.Pointer(functionNameAddr)))
			functionNameBytes := append([]byte(functionName), 0) // null-terminated
			proc, err := api.Call("kernel32.dll", "GetProcAddress", hLibrary, uintptr(unsafe.Pointer(&functionNameBytes[0])))
			if err != nil || proc == 0 {
				log.Fatalf("[ERROR] Failed to GetProcAddress for %s: %v", functionName, err)
			}
			procBytes := uintptrToBytes(proc)
			var numberOfBytesWritten uintptr
			status, err := api.NtWriteVirtualMemory(^uintptr(0), addr, uintptr(unsafe.Pointer(&procBytes[0])), uintptr(len(procBytes)), &numberOfBytesWritten)
			if err != nil || status != 0 {
				log.Fatalf("[ERROR] Failed to NtWriteVirtualMemory: status=0x%X, err=%v", status, err)
			}
			addr += 0x8

		}
		importDescriptorAddr += 0x14
	}

	// Change memory protection from RW to RX now that we're done writing
	baseAddr := dllBase
	regionSize = uintptr(nt_header.OptionalHeader.SizeOfImage)
	var oldProtect uintptr
	status, err = api.NtProtectVirtualMemory(^uintptr(0), &baseAddr, &regionSize, types.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil || status != 0 {
		log.Fatalf("[ERROR] NtProtectVirtualMemory Failed: status=0x%X, err=%v", status, err)
	}

	exportsDirectory := nt_header.OptionalHeader.DataDirectory[types.IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportsDirectory.VirtualAddress != 0 {
		exportTable := (*types.IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(dllBase + uintptr(exportsDirectory.VirtualAddress)))
		
		functionRVAs := (*[1000]uint32)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfFunctions)))
		nameRVAs := (*[1000]uint32)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfNames)))
		nameOrdinals := (*[1000]uint16)(unsafe.Pointer(dllBase + uintptr(exportTable.AddressOfNameOrdinals)))
		
		
		var functionRVA uint32
		var found bool

		switch v := functionIdentifier.(type) {
		case string:
			for i := uint32(0); i < exportTable.NumberOfNames; i++ {
				nameAddr := dllBase + uintptr(nameRVAs[i])
				funcName := bytePtrToString((*byte)(unsafe.Pointer(nameAddr)))
				if funcName == v {
					functionRVA = functionRVAs[nameOrdinals[i]]
					found = true
					break
				}
			}
		case int:
			ordinalIndex := uint32(v) - exportTable.Base
			if ordinalIndex < exportTable.NumberOfFunctions {
				functionRVA = functionRVAs[ordinalIndex]
				found = true
			}
		default:
			if str, ok := functionIdentifier.(string); ok {
				if num, err := strconv.Atoi(str); err == nil {
					ordinalIndex := uint32(num) - exportTable.Base
					if ordinalIndex < exportTable.NumberOfFunctions {
						functionRVA = functionRVAs[ordinalIndex]
						found = true
					}
				} else {
					for i := uint32(0); i < exportTable.NumberOfNames; i++ {
						nameAddr := dllBase + uintptr(nameRVAs[i])
						funcName := bytePtrToString((*byte)(unsafe.Pointer(nameAddr)))
						if funcName == str {
							functionRVA = functionRVAs[nameOrdinals[i]]
							found = true
							break
						}
					}
				}
			}
		}
		
		if found && functionRVA != 0 {
			api.CallWorker(dllBase+uintptr(functionRVA))
		} else {
		}
	} else {
		api.CallWorker(dllBase+uintptr(nt_header.OptionalHeader.AddressOfEntryPoint), dllBase, types.DLL_PROCESS_ATTACH, 0)
	}

	baseAddr = dllBase
	regionSize = 0
	// Note: NtFreeVirtualMemory may not be available in wincall, memory will be freed on process exit
	// status, err = api.NtFreeVirtualMemory(^uintptr(0), &baseAddr, &regionSize, types.MEM_RELEASE)
	// if err != nil || status != 0 {
	//     log.Fatalf("[ERROR] NtFreeVirtualMemory Failed: status=0x%X, err=%v", status, err)
	// }
	return nil
}