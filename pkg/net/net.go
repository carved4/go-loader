package net

import (
	"net/http"
	"fmt"
	"io/ioutil"
	"runtime"
	"unsafe"
)

// Global buffer to prevent GC during execution
var globalBuffer []byte

func DownloadFile(url string) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download file: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}
	// more hacks to get around go garbage collector evil 
	globalBuffer = make([]byte, len(body))
	copy(globalBuffer, body)
	ptr := unsafe.Pointer(&globalBuffer[0])
	runtime.KeepAlive(ptr)
	runtime.KeepAlive(globalBuffer)
	result := make([]byte, len(body))
	copy((*[1 << 30]byte)(unsafe.Pointer(&result[0]))[:len(body)], globalBuffer)
	return result, nil
}