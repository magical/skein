package skein

import "hash"

var _ hash.Hash = &digest{}

type digest struct {
	g   [8]uint64
	t   [2]uint64
	buf [64]byte
	len int   // bytes in buf
	pos int64 // bytes hashed so far
}

func (d *digest) Size() int      { return 512 / 8 }
func (d *digest) BlockSize() int { return 512 / 8 }

func New() hash.Hash {
	var d digest
	d.Reset()
	return &d
}

// Types for UBI
const (
	typeCfg = 4
	typeMsg = 48
	typeOut = 63
)

// The maximum number of bytes that can be hashed.
const maxLen = 1<<96 - 1

func (d *digest) Reset() {
	var key [8]uint64
	var cfg [8]uint64
	var pad [8]uint64
	var t [2]uint64
	cfg[0] = le64dec([]byte("SHA3\x01\x00\x00\x00")) // schema & version
	cfg[1] = 512                                     // output length
	t[0] = 32                                      // cfg length
	t[1] = typeCfg << 56
	t[1] |= 3 << 62 // first and final block
	encrypt512(&pad, &cfg, &key, &t)
	for i := range key {
		d.g[i] = pad[i] ^ cfg[i]
	}
	d.len = 0
}

func (d *digest) Write(b []byte) (int, error) {
	written := len(b)
	for len(b) > 0 {
		// Flush if the buffer is full.
		// We can't flush before this because the last block needs to
		// be handled specially.
		if d.len == len(d.buf) {
			d.flush(false)
		}
		// Copy bytes into the buffer
		n := copy(d.buf[d.len:], b)
		b = b[n:]
		d.len += n
	}
	return written, nil
}

func (d *digest) flush(end bool) {
	var m, out [8]uint64
	var t [2]uint64
	// Pad the buffer
	for i := d.len; i < len(d.buf); i++ {
		d.buf[i] = 0
	}
	// Convert to uint64
	for i := range m {
		m[i] = le64dec(d.buf[i*8:])
	}
	// Add length to total
	d.pos += int64(d.len)
	d.len = 0
	// Initialize tweak
	t[0] = uint64(d.pos)
	t[1] = typeMsg << 56
	if d.pos <= 64 {
		t[1] |= 1 << 62 // first block
	}
	if end {
		t[1] |= 1 << 63 // final block
	}
	// Encrypt buf with the output of the previous block.
	encrypt512(&out, &m, &d.g, &t)
	for i := range d.g {
		d.g[i] = m[i] ^ out[i]
	}
}

func (d0 *digest) Sum(b []byte) []byte {
	d := *d0
	// Flush last block. If there are no blocks, flush an empty block.
	d.flush(true)
	// Initialize tweak.
	var t [2]uint64
	t[0] = 8
	t[1] = typeOut << 56
	t[1] |= 3 << 62
	// Encrypt the zero block.
	var msg [8]uint64
	encrypt512(&msg, &msg, &d.g, &t)
	// Append output
	var out [64]byte
	for i := range msg {
		le64enc(out[i*8:], msg[i])
	}
	return append(b, out[:]...)
}
