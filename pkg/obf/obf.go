// Package obf provides string hashing and obfuscation utilities.
package obf

import (
	"log"
	"sync"
)

// DBJ2HashStr calculates a hash for a string using the DBJ2 algorithm.
func DBJ2HashStr(s string) uint32 {
	return DBJ2Hash([]byte(s))
}

// DBJ2Hash calculates a hash for a byte slice using the DBJ2 algorithm.
func DBJ2Hash(buffer []byte) uint32 {
	hash := uint32(5381)
	
	for _, b := range buffer {
		if b == 0 {
			continue
		}
		if b >= 'a' {
			b -= 0x20
		}
		
		hash = ((hash << 5) + hash) + uint32(b)
	}
	
	return hash
}

// HashCache is a map to store precomputed hashes for performance
var HashCache = make(map[string]uint32)
var hashCacheMutex sync.RWMutex
var collisionDetector = make(map[uint32]string)
var collisionMutex sync.RWMutex

// GetHash returns the hash for a string, using the cache if available
func GetHash(s string) uint32 {
	hashCacheMutex.RLock()
	if hash, ok := HashCache[s]; ok {
		hashCacheMutex.RUnlock()
		return hash
	}
	hashCacheMutex.RUnlock()
	
	hash := DBJ2HashStr(s)
	
	// Store in cache with collision detection
	hashCacheMutex.Lock()
	HashCache[s] = hash
	hashCacheMutex.Unlock()
	
	// Check for hash collisions
	detectHashCollision(hash, s)
	
	return hash
}

// detectHashCollision checks for and logs hash collisions
func detectHashCollision(hash uint32, newString string) {
	collisionMutex.Lock()
	defer collisionMutex.Unlock()
	
	if existingString, exists := collisionDetector[hash]; exists {
		if existingString != newString {
			log.Printf("Warning: Hash collision detected!")
			log.Printf("  Hash:", hash)
			log.Printf("  Existing string:", existingString)
			log.Printf("  New string:", newString)
		}
	} else {
		collisionDetector[hash] = newString
	}
}

// FNV1AHash provides an alternative hash algorithm for better collision resistance
func FNV1AHash(buffer []byte) uint32 {
	const (
		fnv1aOffset = 2166136261
		fnv1aPrime  = 16777619
	)
	
	hash := uint32(fnv1aOffset)
	
	for _, b := range buffer {
		if b == 0 {
			continue
		}
		
		// Convert lowercase to uppercase for consistency
		if b >= 'a' {
			b -= 0x20
		}
		
		hash ^= uint32(b)
		hash *= fnv1aPrime
	}
	
	return hash
}

// GetHashWithAlgorithm allows choosing the hash algorithm
func GetHashWithAlgorithm(s string, algorithm string) uint32 {
	switch algorithm {
	case "fnv1a":
		return FNV1AHash([]byte(s))
	case "dbj2":
		fallthrough
	default:
		return DBJ2HashStr(s)
	}
}

// ClearHashCache clears all cached hashes (useful for testing)
func ClearHashCache() {
	hashCacheMutex.Lock()
	defer hashCacheMutex.Unlock()
	
	collisionMutex.Lock()
	defer collisionMutex.Unlock()
	
	HashCache = make(map[string]uint32)
	collisionDetector = make(map[uint32]string)
}

// GetHashCacheStats returns statistics about the hash cache
func GetHashCacheStats() map[string]interface{} {
	hashCacheMutex.RLock()
	defer hashCacheMutex.RUnlock()
	
	collisionMutex.RLock()
	defer collisionMutex.RUnlock()
	
	collisions := 0
	uniqueHashes := len(collisionDetector)
	totalEntries := len(HashCache)
	
	if totalEntries > uniqueHashes {
		collisions = totalEntries - uniqueHashes
	}
	
	return map[string]interface{}{
		"total_entries":  totalEntries,
		"unique_hashes":  uniqueHashes,
		"collisions":     collisions,
		"cache_hit_ratio": 0.0, // Could implement hit counting if needed
	}
}

// EncodingCache stores encoded string mappings for reversible encoding
var EncodingCache = make(map[uint32]string)
var encodingCacheMutex sync.RWMutex

// Simple XOR key for encoding/decoding
const encodeKey = uint32(0xDEADBEEF)

// Encode converts a string to a reversible encoded uint32 value
func Encode(s string) uint32 {
	// Use a simple hash as the key, but store the original string
	key := DBJ2HashStr(s)
	
	// Store the mapping for decoding
	encodingCacheMutex.Lock()
	EncodingCache[key] = s
	encodingCacheMutex.Unlock()
	
	return key
}

// Decode converts an encoded uint32 value back to the original string
func Decode(encoded uint32) string {
	encodingCacheMutex.RLock()
	defer encodingCacheMutex.RUnlock()
	
	if original, exists := EncodingCache[encoded]; exists {
		return original
	}
	
	// If not found, return empty string
	return ""
}

// PreloadEncodings allows preloading string->encoded mappings at init time
func PreloadEncodings(strings []string) []uint32 {
	encoded := make([]uint32, len(strings))
	for i, s := range strings {
		encoded[i] = Encode(s)
	}
	return encoded
}

// ClearEncodingCache clears the encoding cache
func ClearEncodingCache() {
	encodingCacheMutex.Lock()
	defer encodingCacheMutex.Unlock()
	EncodingCache = make(map[uint32]string)
}
