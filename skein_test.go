package skein

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

var hashTests = []struct {
	text string
	hash string
}{
	{
		text: "",
		hash: "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af41fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a",
	},
	{
		text: strings.Repeat("\x00", 256),
		hash: "D74F3B946A59D16A50FED34786ACB23AEB6069A1567BDCC2442A54C74A4D41A24A62F3F1A76C6BB44BD54AEDF94B40F53D9335154530986CD4F5AA16F93D2D24",
	},
	{
		text: "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8\xF7\xF6\xF5\xF4\xF3\xF2\xF1\xF0\xEF\xEE\xED\xEC\xEB\xEA\xE9\xE8\xE7\xE6\xE5\xE4\xE3\xE2\xE1\xE0",
		hash: "0B7FD053AE635EE8E519646EB41EA0CF7EA340152378062FB2440AA0250FF195FE32D9A0691E68A0FEB17DC285AA6756CEF19404E4DB92BF836C4AE65381504A",
	},
}

func TestHash(t *testing.T) {
	for _, tt := range hashTests {
		want, err := hex.DecodeString(tt.hash)
		if err != nil {
			t.Fatal(err)
		}
		got := Sum([]byte(tt.text))
		if !bytes.Equal(got[:], want) {
			t.Errorf("Skein(%q) = %x, want %x", tt.text, got, want)
		}
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

func BenchmarkHash_8(b *testing.B)  { benchmark(b, 8) }
func BenchmarkHash_1k(b *testing.B) { benchmark(b, 1024) }
func BenchmarkHash_8k(b *testing.B) { benchmark(b, 8192) }
