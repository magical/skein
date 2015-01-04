// This file implements the Threefish block cipher which Skein is built on.

package skein

import "crypto/cipher"

var _ cipher.Block = &Threefish{}

// Threefish implements the Threefish-512 block encryption primitive.
type Threefish struct {
	k [8]uint64
	t [2]uint64
}

// NewCipher returns a Threefish object with the given key.
func NewCipher(key []byte) *Threefish {
	if len(key) != 64 {
		panic("invalid key length")
	}
	var b Threefish
	for i := 0; i < 8; i++ {
		b.k[i] = le64dec(key[i*8:])
	}
	return &b
}

// SetTweak sets the cipher tweak to the given 16 bytes.
func (b *Threefish) SetTweak(t []byte) {
	if len(t) != 16 {
		panic("invalid tweak length")
	}
	b.t[0] = le64dec(t[0:])
	b.t[1] = le64dec(t[8:])
}

func (*Threefish) BlockSize() int { return 512 / 8 }

func (b *Threefish) Encrypt(dst, src []byte) {
	if len(src) < b.BlockSize() {
		panic("src too short")
	}
	if len(dst) < b.BlockSize() {
		panic("dst too short")
	}
	var p [8]uint64
	for i := range p {
		p[i] = le64dec(src[i*8:])
	}
	encrypt512(&p, &p, &b.k, &b.t)
	for i, x := range p {
		le64enc(dst[i*8:][:0], x)
	}
}

func (b *Threefish) Decrypt(dst, src []byte) {
	if len(src) < b.BlockSize() {
		panic("src too short")
	}
	if len(dst) < b.BlockSize() {
		panic("dst too short")
	}
	var p [8]uint64
	for i := range p {
		p[i] = le64dec(src[i*8:])
	}
	decrypt512(&p, &p, &b.k, &b.t)
	for i, x := range p {
		le64enc(dst[i*8:][:0], x)
	}
}

func le64dec(b []byte) uint64 {
	return uint64(b[0])<<0 | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func le64enc(b []byte, x uint64) []byte {
	return append(b, byte(x), byte(x>>8), byte(x>>16), byte(x>>24), byte(x>>32), byte(x>>40), byte(x>>48), byte(x>>56))
}
