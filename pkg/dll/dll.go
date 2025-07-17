package dll

import (
	"encoding/binary"
	"log"
	"strconv"
	"syscall"
	"unsafe"
	types "loader/pkg/types"
	"loader/pkg/wrappers"
	"golang.org/x/sys/windows"
)


func uintptrToBytes(ptr uintptr) []byte {
	ptrPtr := unsafe.Pointer(&ptr)

	byteSlice := make([]byte, unsafe.Sizeof(ptr))
	for i := 0; i < int(unsafe.Sizeof(ptr)); i++ {
		byteSlice[i] = *(*byte)(unsafe.Pointer(uintptr(ptrPtr) + uintptr(i)))
	}

	return byteSlice
}

func LoadDLL(dllBytes []byte, functionIdentifier interface{}) error {
	dllPtr := uintptr(unsafe.Pointer(&dllBytes[0]))

	e_lfanew := *((*uint32)(unsafe.Pointer(dllPtr + 0x3c)))
	nt_header := (*types.IMAGE_NT_HEADERS64)(unsafe.Pointer(dllPtr + uintptr(e_lfanew)))

	dllBase := uintptr(nt_header.OptionalHeader.ImageBase)
	regionSize := uintptr(nt_header.OptionalHeader.SizeOfImage)
	status, err := wrappers.NtAllocateVirtualMemory(^uintptr(0), &dllBase, 0, &regionSize, 
		types.MEM_RESERVE|types.MEM_COMMIT, types.PAGE_READWRITE)
	if err != nil || status != 0 {
		log.Fatalf("[ERROR] NtAllocateVirtualMemory Failed: status=0x%X, err=%v", status, err)
	}

	deltaImageBase := dllBase - uintptr(nt_header.OptionalHeader.ImageBase)
	var numberOfBytesWritten uintptr
	status, err = wrappers.NtWriteVirtualMemory(^uintptr(0), dllBase, &dllBytes[0], uintptr(nt_header.OptionalHeader.SizeOfHeaders), &numberOfBytesWritten)
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

		status, err = wrappers.NtWriteVirtualMemory(^uintptr(0), sectionDestination, sectionBytes, uintptr(section.SizeOfRawData), &numberOfBytesWritten)
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

			status, err = wrappers.NtReadVirtualMemory(^uintptr(0), dllBase+uintptr(relocationRVA), &byteSlice[0], unsafe.Sizeof(size), nil)
			if err != nil || status != 0 {
				log.Fatalf("[ERROR] Failed to NtReadVirtualMemory: status=0x%X, err=%v", status, err)
			}
			addressToPatch := uintptr(binary.LittleEndian.Uint64(byteSlice))
			addressToPatch += deltaImageBase
			a2Patch := uintptrToBytes(addressToPatch)
			status, err = wrappers.NtWriteVirtualMemory(^uintptr(0), dllBase+uintptr(relocationRVA), &a2Patch[0], uintptr(len(a2Patch)), nil)
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
		dllName := windows.BytePtrToString((*byte)(unsafe.Pointer(libraryName)))
		hLibrary, err := windows.LoadLibrary(dllName)
		if err != nil {
			log.Fatalln("[ERROR] LoadLibrary Failed: %v", err)
		}
		addr := dllBase + uintptr(importDescriptor.FirstThunk)
		for {
			thunk := *(*uint16)(unsafe.Pointer(addr))
			if thunk == 0 {
				break
			}
			functionNameAddr := dllBase + uintptr(thunk+2)

			functionName := windows.BytePtrToString((*byte)(unsafe.Pointer(functionNameAddr)))
			proc, err := windows.GetProcAddress(hLibrary, functionName)
			if err != nil {
				log.Fatalln("[ERROR] Failed to GetProcAddress: %v", err)
			}
			procBytes := uintptrToBytes(proc)
			var numberOfBytesWritten uintptr
			status, err = wrappers.NtWriteVirtualMemory(^uintptr(0), addr, &procBytes[0], uintptr(len(procBytes)), &numberOfBytesWritten)
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
	var oldProtect uint32
	status, err = wrappers.NtProtectVirtualMemory(^uintptr(0), &baseAddr, &regionSize, types.PAGE_EXECUTE_READ, &oldProtect)
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
				funcName := windows.BytePtrToString((*byte)(unsafe.Pointer(nameAddr)))
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
						funcName := windows.BytePtrToString((*byte)(unsafe.Pointer(nameAddr)))
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
			syscall.SyscallN(dllBase+uintptr(functionRVA))
		} else {
		}
	} else {
		syscall.SyscallN(dllBase+uintptr(nt_header.OptionalHeader.AddressOfEntryPoint), dllBase, types.DLL_PROCESS_ATTACH, 0)
	}

	baseAddr = dllBase
	regionSize = 0
	status, err = wrappers.NtFreeVirtualMemory(^uintptr(0), &baseAddr, &regionSize, types.MEM_RELEASE)
	if err != nil || status != 0 {
		log.Fatalf("[ERROR] NtFreeVirtualMemory Failed: status=0x%X, err=%v", status, err)
	}
	return nil
}