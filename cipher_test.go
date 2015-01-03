package skein

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	k := make([]byte, 64) // blank key
	p := make([]byte, 64) // plaintext
	q := make([]byte, 64) // decrypted plaintext
	c := make([]byte, 64) // ciphertext
	z := make([]byte, 64) // 0
	b := NewCipher(k)
	// Set p to sequential integers
	for i := range p {
		p[i] = byte(i)
	}
	b.Encrypt(c, p)
	if bytes.Equal(c, z) {
		t.Fatalf("encrypt failed: c is empty")
	}
	if bytes.Equal(c, p) {
		t.Fatalf("encrypt failed: c == p: %x", c)
	}
	b.Decrypt(q, c)
	if !bytes.Equal(p, q) {
		t.Fatalf("decrypt failed: p != q: got %x, want %x", q, p)
	}
}

var blockTests = []struct {
	key   []byte
	tweak []byte
	p     []byte
	c     []byte
}{
	{
		key:   make([]byte, 64),
		tweak: make([]byte, 16),
		p:     make([]byte, 64),
		c: []byte{
			0xB1, 0xA2, 0xBB, 0xC6, 0xEF, 0x60, 0x25, 0xBC,
			0x40, 0xEB, 0x38, 0x22, 0x16, 0x1F, 0x36, 0xE3,
			0x75, 0xD1, 0xBB, 0x0A, 0xEE, 0x31, 0x86, 0xFB,
			0xD1, 0x9E, 0x47, 0xC5, 0xD4, 0x79, 0x94, 0x7B,
			0x7B, 0xC2, 0xF8, 0x58, 0x6E, 0x35, 0xF0, 0xCF,
			0xF7, 0xE7, 0xF0, 0x30, 0x84, 0xB0, 0xB7, 0xB1,
			0xF1, 0xAB, 0x39, 0x61, 0xA5, 0x80, 0xA3, 0xE9,
			0x7E, 0xB4, 0x1E, 0xA1, 0x4A, 0x6D, 0x7B, 0xBE,
		},
	},
	{
		key: []byte{
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
			0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
			0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F,
		},
		tweak: []byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		},
		p: []byte{
			0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
			0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0,
			0xEF, 0xEE, 0xED, 0xEC, 0xEB, 0xEA, 0xE9, 0xE8,
			0xE7, 0xE6, 0xE5, 0xE4, 0xE3, 0xE2, 0xE1, 0xE0,
			0xDF, 0xDE, 0xDD, 0xDC, 0xDB, 0xDA, 0xD9, 0xD8,
			0xD7, 0xD6, 0xD5, 0xD4, 0xD3, 0xD2, 0xD1, 0xD0,
			0xCF, 0xCE, 0xCD, 0xCC, 0xCB, 0xCA, 0xC9, 0xC8,
			0xC7, 0xC6, 0xC5, 0xC4, 0xC3, 0xC2, 0xC1, 0xC0,
		},
		c: []byte{
			0xE3, 0x04, 0x43, 0x96, 0x26, 0xD4, 0x5A, 0x2C,
			0xB4, 0x01, 0xCA, 0xD8, 0xD6, 0x36, 0x24, 0x9A,
			0x63, 0x38, 0x33, 0x0E, 0xB0, 0x6D, 0x45, 0xDD,
			0x8B, 0x36, 0xB9, 0x0E, 0x97, 0x25, 0x47, 0x79,
			0x27, 0x2A, 0x0A, 0x8D, 0x99, 0x46, 0x35, 0x04,
			0x78, 0x44, 0x20, 0xEA, 0x18, 0xC9, 0xA7, 0x25,
			0xAF, 0x11, 0xDF, 0xFE, 0xA1, 0x01, 0x62, 0x34,
			0x89, 0x27, 0x67, 0x3D, 0x5C, 0x1C, 0xAF, 0x3D,
		},
	},
}

func TestEncrypt(t *testing.T) {
	var pad [64]byte
	for _, tt := range blockTests {
		b := NewCipher(tt.key)
		b.SetTweak(tt.tweak)
		b.Encrypt(pad[:], tt.p)
		if !bytes.Equal(pad[:], tt.c) {
			t.Errorf("Encrypt(%x): want %x, got %x", tt.p, tt.c, pad[:])
		}
	}
}

func TestDecrypt(t *testing.T) {
	var pad [64]byte
	for _, tt := range blockTests {
		b := NewCipher(tt.key)
		b.SetTweak(tt.tweak)
		b.Decrypt(pad[:], tt.c)
		if !bytes.Equal(pad[:], tt.p) {
			t.Errorf("Decrypt(%x): want %x, got %x", tt.c, tt.p, pad[:])
		}
	}
}
