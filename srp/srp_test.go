package srp

import (
	"crypto"
	"crypto/rand"
	"testing"
)

func TestNewParams(t *testing.T) {
	tests := []struct {
		name      string
		secure    int16
		hashFunc  crypto.Hash
		lenSalt   int16
		wantError bool
	}{
		{
			name:      "Valid 2048-bit with SHA256",
			secure:    2048,
			hashFunc:  crypto.SHA256,
			lenSalt:   16,
			wantError: false,
		},
		{
			name:      "Valid 3072-bit with SHA512",
			secure:    3072,
			hashFunc:  crypto.SHA512,
			lenSalt:   32,
			wantError: false,
		},
		{
			name:      "Invalid security level",
			secure:    1024,
			hashFunc:  crypto.SHA256,
			lenSalt:   16,
			wantError: true,
		},
		{
			name:      "Salt too short",
			secure:    2048,
			hashFunc:  crypto.SHA256,
			lenSalt:   4,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, err := NewParams(tt.secure, tt.hashFunc, tt.lenSalt)

			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if params == nil {
				t.Error("Expected params but got nil")
			}

			// Verify parameters are set correctly
			if params.n == nil || params.g == nil || params.k == nil {
				t.Error("SRP parameters not properly initialized")
			}

			if params.hashFunc != tt.hashFunc {
				t.Errorf("Expected hash function %v, got %v", tt.hashFunc, params.hashFunc)
			}

			if params.lenSalt != tt.lenSalt {
				t.Errorf("Expected salt length %d, got %d", tt.lenSalt, params.lenSalt)
			}
		})
	}
}

func TestPadToLength(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		targetLen int
		expected  int
	}{
		{
			name:      "Pad short input",
			input:     []byte{0x01, 0x02},
			targetLen: 5,
			expected:  5,
		},
		{
			name:      "No padding needed",
			input:     []byte{0x01, 0x02, 0x03, 0x04},
			targetLen: 4,
			expected:  4,
		},
		{
			name:      "Input longer than target",
			input:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			targetLen: 3,
			expected:  5,
		},
		{
			name:      "Empty input",
			input:     []byte{},
			targetLen: 5,
			expected:  5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := padToLength(tt.input, tt.targetLen)

			if len(result) != tt.expected {
				t.Errorf("Expected length %d, got %d", tt.expected, len(result))
			}

			// Verify padding is zeros
			paddingLen := tt.targetLen - len(tt.input)
			if paddingLen > 0 {
				for i := 0; i < paddingLen; i++ {
					if result[i] != 0x00 {
						t.Errorf("Expected zero padding at position %d, got %x", i, result[i])
					}
				}

				// Verify original data is preserved
				for i := 0; i < len(tt.input); i++ {
					if result[paddingLen+i] != tt.input[i] {
						t.Errorf("Original data corrupted at position %d", i)
					}
				}
			}
		})
	}
}

func TestCalculateK(t *testing.T) {
	params, err := NewParams(2048, crypto.SHA256, 16)
	if err != nil {
		t.Fatalf("Failed to create params: %v", err)
	}

	k, err := calculateK(params.n, params.g, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to calculate k: %v", err)
	}

	if k == nil {
		t.Error("Expected k value but got nil")
	}

	if k.Sign() == 0 {
		t.Error("k should not be zero")
	}

	// k should be consistent for same parameters
	k2, err := calculateK(params.n, params.g, crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to calculate k second time: %v", err)
	}

	if k.Cmp(k2) != 0 {
		t.Error("k calculation should be deterministic")
	}
}

func TestGeneratorX(t *testing.T) {
	username := "testuser"
	password := "testpassword"
	lenSalt := int16(16)

	x1, salt1, err := generatorX(username, password, lenSalt, crypto.SHA256, nil)
	if err != nil {
		t.Fatalf("Failed to generate x: %v", err)
	}

	if len(salt1) != int(lenSalt) {
		t.Errorf("Expected salt length %d, got %d", lenSalt, len(salt1))
	}

	if len(x1) == 0 {
		t.Error("Expected non-empty x value")
	}

	// Same input with same salt should produce same x
	x2, salt2, err := generatorX(username, password, 0, crypto.SHA256, salt1)
	if err != nil {
		t.Fatalf("Failed to generate x with provided salt: %v", err)
	}

	if len(salt2) != len(salt1) {
		t.Error("Salt length mismatch")
	}

	for i := range salt1 {
		if salt1[i] != salt2[i] {
			t.Error("Salts should be identical")
			break
		}
	}

	for i := range x1 {
		if x1[i] != x2[i] {
			t.Error("x values should be identical with same salt")
			break
		}
	}

	// Different salt should produce different x
	differentSalt := make([]byte, lenSalt)
	rand.Read(differentSalt)

	x3, _, err := generatorX(username, password, 0, crypto.SHA256, differentSalt)
	if err != nil {
		t.Fatalf("Failed to generate x with different salt: %v", err)
	}

	// Very high probability that x1 != x3
	equal := true
	for i := 0; i < len(x1) && i < len(x3); i++ {
		if x1[i] != x3[i] {
			equal = false
			break
		}
	}

	if equal {
		t.Error("Different salts should produce different x values")
	}
}
