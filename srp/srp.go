package srp

import (
	"crypto"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
)

// Params represents SRP protocol parameters
// n - large safe prime number
// g - generator modulo n
// k - multiplier parameter
// hashFunc - cryptographic hash function to use
// lenSalt - length of salt in bytes
type Params struct {
	n        *big.Int
	g        *big.Int
	k        *big.Int
	abLen    int
	hashFunc crypto.Hash
	lenSalt  int16
}

// NewParams creates new SRP parameters with specified security level
// secure - bit size of the prime (2048, 3072, 4096, 6144, 8192)
// hashFunc - hash function to use (crypto.SHA1, crypto.SHA256, etc.)
// lenSalt - salt length in bytes (minimum 8 recommended)
// Returns configured SRP parameters or error if validation fails
func NewParams(secure int16, hashFunc crypto.Hash, lenSalt int16) (*Params, error) {
	// Ensure hash function implementations are linked by using them
	// This prevents "hash function not available" errors in some environments
	_ = md5.New()
	_ = sha1.New()
	_ = sha256.New()
	_ = sha512.New()

	// Validate salt length - minimum 8 bytes for security
	if lenSalt < 8 {
		return nil, errors.New("salt length must be at least 8 bytes")
	}

	// Check if the requested hash function is available in the current environment
	if !hashFunc.Available() {
		return nil, errors.New("requested hash function is not available")
	}

	var N, G *big.Int
	var abLen int

	// Select predefined N and G values based on security level
	// These are standard SRP group parameters from RFC 5054
	switch secure {
	case 2048:
		N = N_2048
		G = G_2048
		abLen = ab_2048_len
	case 3072:
		N = N_3072
		G = G_3072
		abLen = ab_3072_len
	case 4096:
		N = N_4096
		G = G_4096
		abLen = ab_4096_len
	case 6144:
		N = N_6144
		G = G_6144
		abLen = ab_6144_len
	case 8192:
		N = N_8192
		G = G_8192
		abLen = ab_8192_len
	default:
		return nil, errors.New("invalid security level - supported values: 2048, 3072, 4096, 6144, 8192")
	}

	// Calculate k parameter: k = H(N | G)
	K, err := calculateK(N, G, hashFunc)
	if err != nil {
		return nil, err
	}

	// Return configured SRP parameters
	return &Params{
		n:        N,
		g:        G,
		k:        K,
		abLen:    abLen,
		hashFunc: hashFunc,
		lenSalt:  lenSalt,
	}, nil
}

// calculateK computes the SRP multiplier parameter k
// k = H(N | G) where N and G are padded to the same length
// Follows RFC 5054 specification for parameter encoding
// n - large safe prime
// g - generator modulo n
// hashFunc - hash function to use for calculation
// Returns k parameter or error if validation fails
func calculateK(n *big.Int, g *big.Int, hashFunc crypto.Hash) (*big.Int, error) {
	// Create new hash instance
	h := hashFunc.New()

	// Get byte representations of n and g
	nBytes := n.Bytes()
	gBytes := g.Bytes()

	nLen := len(nBytes)
	gLen := len(gBytes)

	// If 'g' is less than 'n', the length is aligned using the zero byte addition method according to RFC 5054.
	if nLen > gLen {
		// The highest byte of 'g' must not be zero according to RFC 5054
		if len(gBytes) > 0 && gBytes[0] == 0x00 {
			return nil, errors.New("highest byte of generator cannot be zero")
		}

		// Pad gBytes with leading zeros to match the length of nBytes
		padding := make([]byte, nLen-gLen)
		gBytes = append(padding, gBytes...)
	}

	// Compute hash: H(N | G)
	h.Write(nBytes)
	h.Write(gBytes)

	// Convert hash result to big integer
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}
