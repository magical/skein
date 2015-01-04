package skein

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHash(t *testing.T) {
	h := New()
	out := h.Sum(nil)
	vector, err := hex.DecodeString("bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, vector) {
		t.Errorf("Skein(%q) = %x, want %x", "", out, vector)
	}
}

func benchmark(b *testing.B, size int64) {
	var buf [8192]byte
	var out [64]byte
	h := New()
	b.ResetTimer()
	b.SetBytes(size)
	for i := 0; i < b.N; i++ {
		h.Reset()
		h.Write(buf[:size])
		h.Sum(out[:0])
	}
}

func BenchmarkHash_8(b *testing.B) { benchmark(b, 8) }
func BenchmarkHash_1k(b *testing.B) { benchmark(b, 1024) }
func BenchmarkHash_8k(b *testing.B) { benchmark(b, 8192) }
