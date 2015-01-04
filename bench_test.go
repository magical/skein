package skein

import "testing"

func BenchmarkEncrypt512(b *testing.B) {
	var p [8]uint64
	var k = [8]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	var t = [2]uint64{9, 10}
	b.ResetTimer()
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		encrypt512(&p, &p, &k, &t)
	}
}

func BenchmarkDecrypt512(b *testing.B) {
	var p [8]uint64
	var k = [8]uint64{1, 2, 3, 4, 5, 6, 7, 8}
	var t = [2]uint64{9, 10}
	b.ResetTimer()
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		decrypt512(&p, &p, &k, &t)
	}
}
