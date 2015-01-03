package skein

//import "fmt"

// Encrypt encrypts a block p with the given subkeys.
func encrypt512(p *[8]uint64, s *[19][8]uint64) {
	//fmt.Printf("Initial state: %x\n", p)
	//fmt.Printf("Key schedule: %x\n", s[0])
	var p0, p1, p2, p3, p4, p5, p6, p7 = p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]
	for i := 0; i < 72; i += 8 {

		p0 += s[uint(i)/4+0/4][0]

		p1 += s[uint(i)/4+0/4][1]

		p2 += s[uint(i)/4+0/4][2]

		p3 += s[uint(i)/4+0/4][3]

		p4 += s[uint(i)/4+0/4][4]

		p5 += s[uint(i)/4+0/4][5]

		p6 += s[uint(i)/4+0/4][6]

		p7 += s[uint(i)/4+0/4][7]

		//fmt.Printf("State after key injection: %x\n", p)

		p0 += p1
		p1 = p1<<46 | p1>>(64-46)
		p1 ^= p0

		p2 += p3
		p3 = p3<<36 | p3>>(64-36)
		p3 ^= p2

		p4 += p5
		p5 = p5<<19 | p5>>(64-19)
		p5 ^= p4

		p6 += p7
		p7 = p7<<37 | p7>>(64-37)
		p7 ^= p6

		//fmt.Printf("State after round %d: %x\n", i+0+1, p)

		p2 += p1
		p1 = p1<<33 | p1>>(64-33)
		p1 ^= p2

		p4 += p7
		p7 = p7<<27 | p7>>(64-27)
		p7 ^= p4

		p6 += p5
		p5 = p5<<14 | p5>>(64-14)
		p5 ^= p6

		p0 += p3
		p3 = p3<<42 | p3>>(64-42)
		p3 ^= p0

		//fmt.Printf("State after round %d: %x\n", i+1+1, p)

		p4 += p1
		p1 = p1<<17 | p1>>(64-17)
		p1 ^= p4

		p6 += p3
		p3 = p3<<49 | p3>>(64-49)
		p3 ^= p6

		p0 += p5
		p5 = p5<<36 | p5>>(64-36)
		p5 ^= p0

		p2 += p7
		p7 = p7<<39 | p7>>(64-39)
		p7 ^= p2

		//fmt.Printf("State after round %d: %x\n", i+2+1, p)

		p6 += p1
		p1 = p1<<44 | p1>>(64-44)
		p1 ^= p6

		p0 += p7
		p7 = p7<<9 | p7>>(64-9)
		p7 ^= p0

		p2 += p5
		p5 = p5<<54 | p5>>(64-54)
		p5 ^= p2

		p4 += p3
		p3 = p3<<56 | p3>>(64-56)
		p3 ^= p4

		//fmt.Printf("State after round %d: %x\n", i+3+1, p)

		p0 += s[uint(i)/4+4/4][0]

		p1 += s[uint(i)/4+4/4][1]

		p2 += s[uint(i)/4+4/4][2]

		p3 += s[uint(i)/4+4/4][3]

		p4 += s[uint(i)/4+4/4][4]

		p5 += s[uint(i)/4+4/4][5]

		p6 += s[uint(i)/4+4/4][6]

		p7 += s[uint(i)/4+4/4][7]

		//fmt.Printf("State after key injection: %x\n", p)

		p0 += p1
		p1 = p1<<39 | p1>>(64-39)
		p1 ^= p0

		p2 += p3
		p3 = p3<<30 | p3>>(64-30)
		p3 ^= p2

		p4 += p5
		p5 = p5<<34 | p5>>(64-34)
		p5 ^= p4

		p6 += p7
		p7 = p7<<24 | p7>>(64-24)
		p7 ^= p6

		//fmt.Printf("State after round %d: %x\n", i+4+1, p)

		p2 += p1
		p1 = p1<<13 | p1>>(64-13)
		p1 ^= p2

		p4 += p7
		p7 = p7<<50 | p7>>(64-50)
		p7 ^= p4

		p6 += p5
		p5 = p5<<10 | p5>>(64-10)
		p5 ^= p6

		p0 += p3
		p3 = p3<<17 | p3>>(64-17)
		p3 ^= p0

		//fmt.Printf("State after round %d: %x\n", i+5+1, p)

		p4 += p1
		p1 = p1<<25 | p1>>(64-25)
		p1 ^= p4

		p6 += p3
		p3 = p3<<29 | p3>>(64-29)
		p3 ^= p6

		p0 += p5
		p5 = p5<<39 | p5>>(64-39)
		p5 ^= p0

		p2 += p7
		p7 = p7<<43 | p7>>(64-43)
		p7 ^= p2

		//fmt.Printf("State after round %d: %x\n", i+6+1, p)

		p6 += p1
		p1 = p1<<8 | p1>>(64-8)
		p1 ^= p6

		p0 += p7
		p7 = p7<<35 | p7>>(64-35)
		p7 ^= p0

		p2 += p5
		p5 = p5<<56 | p5>>(64-56)
		p5 ^= p2

		p4 += p3
		p3 = p3<<22 | p3>>(64-22)
		p3 ^= p4

		//fmt.Printf("State after round %d: %x\n", i+7+1, p)

	}

	p[0] = p0 + s[len(s)-1][0]

	p[1] = p1 + s[len(s)-1][1]

	p[2] = p2 + s[len(s)-1][2]

	p[3] = p3 + s[len(s)-1][3]

	p[4] = p4 + s[len(s)-1][4]

	p[5] = p5 + s[len(s)-1][5]

	p[6] = p6 + s[len(s)-1][6]

	p[7] = p7 + s[len(s)-1][7]

}

// Decrypt decrypts a block p using the given subkeys.
func decrypt512(p *[8]uint64, s *[19][8]uint64) {
	var p0, p1, p2, p3, p4, p5, p6, p7 uint64

	p0 = p[0] - s[len(s)-1][0]

	p1 = p[1] - s[len(s)-1][1]

	p2 = p[2] - s[len(s)-1][2]

	p3 = p[3] - s[len(s)-1][3]

	p4 = p[4] - s[len(s)-1][4]

	p5 = p[5] - s[len(s)-1][5]

	p6 = p[6] - s[len(s)-1][6]

	p7 = p[7] - s[len(s)-1][7]

	for i := 72 - 8; i >= 0; i -= 8 {

		p3 ^= p4
		p3 = p3<<(64-22) | p3>>22
		p4 -= p3

		p5 ^= p2
		p5 = p5<<(64-56) | p5>>56
		p2 -= p5

		p7 ^= p0
		p7 = p7<<(64-35) | p7>>35
		p0 -= p7

		p1 ^= p6
		p1 = p1<<(64-8) | p1>>8
		p6 -= p1

		p7 ^= p2
		p7 = p7<<(64-43) | p7>>43
		p2 -= p7

		p5 ^= p0
		p5 = p5<<(64-39) | p5>>39
		p0 -= p5

		p3 ^= p6
		p3 = p3<<(64-29) | p3>>29
		p6 -= p3

		p1 ^= p4
		p1 = p1<<(64-25) | p1>>25
		p4 -= p1

		p3 ^= p0
		p3 = p3<<(64-17) | p3>>17
		p0 -= p3

		p5 ^= p6
		p5 = p5<<(64-10) | p5>>10
		p6 -= p5

		p7 ^= p4
		p7 = p7<<(64-50) | p7>>50
		p4 -= p7

		p1 ^= p2
		p1 = p1<<(64-13) | p1>>13
		p2 -= p1

		p7 ^= p6
		p7 = p7<<(64-24) | p7>>24
		p6 -= p7

		p5 ^= p4
		p5 = p5<<(64-34) | p5>>34
		p4 -= p5

		p3 ^= p2
		p3 = p3<<(64-30) | p3>>30
		p2 -= p3

		p1 ^= p0
		p1 = p1<<(64-39) | p1>>39
		p0 -= p1

		p0 -= s[uint(i)/4+4/4][0]

		p1 -= s[uint(i)/4+4/4][1]

		p2 -= s[uint(i)/4+4/4][2]

		p3 -= s[uint(i)/4+4/4][3]

		p4 -= s[uint(i)/4+4/4][4]

		p5 -= s[uint(i)/4+4/4][5]

		p6 -= s[uint(i)/4+4/4][6]

		p7 -= s[uint(i)/4+4/4][7]

		p3 ^= p4
		p3 = p3<<(64-56) | p3>>56
		p4 -= p3

		p5 ^= p2
		p5 = p5<<(64-54) | p5>>54
		p2 -= p5

		p7 ^= p0
		p7 = p7<<(64-9) | p7>>9
		p0 -= p7

		p1 ^= p6
		p1 = p1<<(64-44) | p1>>44
		p6 -= p1

		p7 ^= p2
		p7 = p7<<(64-39) | p7>>39
		p2 -= p7

		p5 ^= p0
		p5 = p5<<(64-36) | p5>>36
		p0 -= p5

		p3 ^= p6
		p3 = p3<<(64-49) | p3>>49
		p6 -= p3

		p1 ^= p4
		p1 = p1<<(64-17) | p1>>17
		p4 -= p1

		p3 ^= p0
		p3 = p3<<(64-42) | p3>>42
		p0 -= p3

		p5 ^= p6
		p5 = p5<<(64-14) | p5>>14
		p6 -= p5

		p7 ^= p4
		p7 = p7<<(64-27) | p7>>27
		p4 -= p7

		p1 ^= p2
		p1 = p1<<(64-33) | p1>>33
		p2 -= p1

		p7 ^= p6
		p7 = p7<<(64-37) | p7>>37
		p6 -= p7

		p5 ^= p4
		p5 = p5<<(64-19) | p5>>19
		p4 -= p5

		p3 ^= p2
		p3 = p3<<(64-36) | p3>>36
		p2 -= p3

		p1 ^= p0
		p1 = p1<<(64-46) | p1>>46
		p0 -= p1

		p0 -= s[uint(i)/4+0/4][0]

		p1 -= s[uint(i)/4+0/4][1]

		p2 -= s[uint(i)/4+0/4][2]

		p3 -= s[uint(i)/4+0/4][3]

		p4 -= s[uint(i)/4+0/4][4]

		p5 -= s[uint(i)/4+0/4][5]

		p6 -= s[uint(i)/4+0/4][6]

		p7 -= s[uint(i)/4+0/4][7]

	}
	p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7] = p0, p1, p2, p3, p4, p5, p6, p7
}

// Expand expands a key and tweak into subkeys.
func expand(s *[19][8]uint64, k *[9]uint64, t *[3]uint64) {
	t[2] = t[0] ^ t[1]
	k[8] = c240 ^ k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4] ^ k[5] ^ k[6] ^ k[7]
	for i := 0; i < len(*s); i++ {

		s[i][0] = k[(i+0)%9]

		s[i][1] = k[(i+1)%9]

		s[i][2] = k[(i+2)%9]

		s[i][3] = k[(i+3)%9]

		s[i][4] = k[(i+4)%9]

		s[i][5] = k[(i+5)%9]

		s[i][6] = k[(i+6)%9]

		s[i][7] = k[(i+7)%9]

		s[i][5] += t[(i+0)%3]
		s[i][6] += t[(i+1)%3]
		s[i][7] += uint64(i)
	}
}
