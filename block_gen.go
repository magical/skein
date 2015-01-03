package skein

//import "fmt"

// Encrypt encrypts a block p with the given key and tweak.
func encrypt512(p *[8]uint64, k *[9]uint64, t *[3]uint64) {
	//fmt.Printf("Initial state: %x\n", p)
	//fmt.Printf("Key schedule: %x\n", s[0])
	var p0, p1, p2, p3, p4, p5, p6, p7 = p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]
	//var k0, k1, k2, k3, k4, k5, k6, k7 = k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]
	//var t0, t1, t2 = t[0], t[1], t[0] ^ t[1]
	//k8 := c240 ^ k0 ^ k1 ^ k2 ^ k3 ^ k4 ^ k5 ^ k6 ^ k7
	t[2] = t[0] ^ t[1]
	k[8] = c240 ^ k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4] ^ k[5] ^ k[6] ^ k[7]

	p0 += k[0]

	p1 += k[1]

	p2 += k[2]

	p3 += k[3]

	p4 += k[4]

	p5 += k[5] + t[0]

	p6 += k[6] + t[1]

	p7 += k[7] + 0

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

	p0 += k[1]

	p1 += k[2]

	p2 += k[3]

	p3 += k[4]

	p4 += k[5]

	p5 += k[6] + t[1]

	p6 += k[7] + t[2]

	p7 += k[8] + 1

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

	p0 += k[2]

	p1 += k[3]

	p2 += k[4]

	p3 += k[5]

	p4 += k[6]

	p5 += k[7] + t[2]

	p6 += k[8] + t[0]

	p7 += k[0] + 2

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

	//fmt.Printf("State after round %d: %x\n", i+8+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+9+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+10+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+11+1, p)

	p0 += k[3]

	p1 += k[4]

	p2 += k[5]

	p3 += k[6]

	p4 += k[7]

	p5 += k[8] + t[0]

	p6 += k[0] + t[1]

	p7 += k[1] + 3

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

	//fmt.Printf("State after round %d: %x\n", i+12+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+13+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+14+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+15+1, p)

	p0 += k[4]

	p1 += k[5]

	p2 += k[6]

	p3 += k[7]

	p4 += k[8]

	p5 += k[0] + t[1]

	p6 += k[1] + t[2]

	p7 += k[2] + 4

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

	//fmt.Printf("State after round %d: %x\n", i+16+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+17+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+18+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+19+1, p)

	p0 += k[5]

	p1 += k[6]

	p2 += k[7]

	p3 += k[8]

	p4 += k[0]

	p5 += k[1] + t[2]

	p6 += k[2] + t[0]

	p7 += k[3] + 5

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

	//fmt.Printf("State after round %d: %x\n", i+20+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+21+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+22+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+23+1, p)

	p0 += k[6]

	p1 += k[7]

	p2 += k[8]

	p3 += k[0]

	p4 += k[1]

	p5 += k[2] + t[0]

	p6 += k[3] + t[1]

	p7 += k[4] + 6

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

	//fmt.Printf("State after round %d: %x\n", i+24+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+25+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+26+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+27+1, p)

	p0 += k[7]

	p1 += k[8]

	p2 += k[0]

	p3 += k[1]

	p4 += k[2]

	p5 += k[3] + t[1]

	p6 += k[4] + t[2]

	p7 += k[5] + 7

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

	//fmt.Printf("State after round %d: %x\n", i+28+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+29+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+30+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+31+1, p)

	p0 += k[8]

	p1 += k[0]

	p2 += k[1]

	p3 += k[2]

	p4 += k[3]

	p5 += k[4] + t[2]

	p6 += k[5] + t[0]

	p7 += k[6] + 8

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

	//fmt.Printf("State after round %d: %x\n", i+32+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+33+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+34+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+35+1, p)

	p0 += k[0]

	p1 += k[1]

	p2 += k[2]

	p3 += k[3]

	p4 += k[4]

	p5 += k[5] + t[0]

	p6 += k[6] + t[1]

	p7 += k[7] + 9

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

	//fmt.Printf("State after round %d: %x\n", i+36+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+37+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+38+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+39+1, p)

	p0 += k[1]

	p1 += k[2]

	p2 += k[3]

	p3 += k[4]

	p4 += k[5]

	p5 += k[6] + t[1]

	p6 += k[7] + t[2]

	p7 += k[8] + 10

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

	//fmt.Printf("State after round %d: %x\n", i+40+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+41+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+42+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+43+1, p)

	p0 += k[2]

	p1 += k[3]

	p2 += k[4]

	p3 += k[5]

	p4 += k[6]

	p5 += k[7] + t[2]

	p6 += k[8] + t[0]

	p7 += k[0] + 11

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

	//fmt.Printf("State after round %d: %x\n", i+44+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+45+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+46+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+47+1, p)

	p0 += k[3]

	p1 += k[4]

	p2 += k[5]

	p3 += k[6]

	p4 += k[7]

	p5 += k[8] + t[0]

	p6 += k[0] + t[1]

	p7 += k[1] + 12

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

	//fmt.Printf("State after round %d: %x\n", i+48+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+49+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+50+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+51+1, p)

	p0 += k[4]

	p1 += k[5]

	p2 += k[6]

	p3 += k[7]

	p4 += k[8]

	p5 += k[0] + t[1]

	p6 += k[1] + t[2]

	p7 += k[2] + 13

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

	//fmt.Printf("State after round %d: %x\n", i+52+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+53+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+54+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+55+1, p)

	p0 += k[5]

	p1 += k[6]

	p2 += k[7]

	p3 += k[8]

	p4 += k[0]

	p5 += k[1] + t[2]

	p6 += k[2] + t[0]

	p7 += k[3] + 14

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

	//fmt.Printf("State after round %d: %x\n", i+56+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+57+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+58+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+59+1, p)

	p0 += k[6]

	p1 += k[7]

	p2 += k[8]

	p3 += k[0]

	p4 += k[1]

	p5 += k[2] + t[0]

	p6 += k[3] + t[1]

	p7 += k[4] + 15

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

	//fmt.Printf("State after round %d: %x\n", i+60+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+61+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+62+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+63+1, p)

	p0 += k[7]

	p1 += k[8]

	p2 += k[0]

	p3 += k[1]

	p4 += k[2]

	p5 += k[3] + t[1]

	p6 += k[4] + t[2]

	p7 += k[5] + 16

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

	//fmt.Printf("State after round %d: %x\n", i+64+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+65+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+66+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+67+1, p)

	p0 += k[8]

	p1 += k[0]

	p2 += k[1]

	p3 += k[2]

	p4 += k[3]

	p5 += k[4] + t[2]

	p6 += k[5] + t[0]

	p7 += k[6] + 17

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

	//fmt.Printf("State after round %d: %x\n", i+68+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+69+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+70+1, p)

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

	//fmt.Printf("State after round %d: %x\n", i+71+1, p)

	p0 += k[0]

	p1 += k[1]

	p2 += k[2]

	p3 += k[3]

	p4 += k[4]

	p5 += k[5] + t[0]

	p6 += k[6] + t[1]

	p7 += k[7] + 18

	//fmt.Printf("State after key injection: %x\n", p)

	p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7] = p0, p1, p2, p3, p4, p5, p6, p7
}

// Decrypt decrypts a block p using the given subkeys.
func decrypt512(p *[8]uint64, k *[9]uint64, t *[3]uint64) {
	var p0, p1, p2, p3, p4, p5, p6, p7 = p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]
	//var k0, k1, k2, k3, k4, k5, k6, k7 = k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]
	//var t0, t1, t2 = t[0], t[1], t[0] ^ t[1]
	//k8 := c240 ^ k0 ^ k1 ^ k2 ^ k3 ^ k4 ^ k5 ^ k6 ^ k7
	t[2] = t[0] ^ t[1]
	k[8] = c240 ^ k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4] ^ k[5] ^ k[6] ^ k[7]

	p0 -= k[0]

	p1 -= k[1]

	p2 -= k[2]

	p3 -= k[3]

	p4 -= k[4]

	p5 -= k[5] + t[0]

	p6 -= k[6] + t[1]

	p7 -= k[7] + 18

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[8]

	p1 -= k[0]

	p2 -= k[1]

	p3 -= k[2]

	p4 -= k[3]

	p5 -= k[4] + t[2]

	p6 -= k[5] + t[0]

	p7 -= k[6] + 17

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[7]

	p1 -= k[8]

	p2 -= k[0]

	p3 -= k[1]

	p4 -= k[2]

	p5 -= k[3] + t[1]

	p6 -= k[4] + t[2]

	p7 -= k[5] + 16

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[6]

	p1 -= k[7]

	p2 -= k[8]

	p3 -= k[0]

	p4 -= k[1]

	p5 -= k[2] + t[0]

	p6 -= k[3] + t[1]

	p7 -= k[4] + 15

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[5]

	p1 -= k[6]

	p2 -= k[7]

	p3 -= k[8]

	p4 -= k[0]

	p5 -= k[1] + t[2]

	p6 -= k[2] + t[0]

	p7 -= k[3] + 14

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[4]

	p1 -= k[5]

	p2 -= k[6]

	p3 -= k[7]

	p4 -= k[8]

	p5 -= k[0] + t[1]

	p6 -= k[1] + t[2]

	p7 -= k[2] + 13

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[3]

	p1 -= k[4]

	p2 -= k[5]

	p3 -= k[6]

	p4 -= k[7]

	p5 -= k[8] + t[0]

	p6 -= k[0] + t[1]

	p7 -= k[1] + 12

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[2]

	p1 -= k[3]

	p2 -= k[4]

	p3 -= k[5]

	p4 -= k[6]

	p5 -= k[7] + t[2]

	p6 -= k[8] + t[0]

	p7 -= k[0] + 11

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[1]

	p1 -= k[2]

	p2 -= k[3]

	p3 -= k[4]

	p4 -= k[5]

	p5 -= k[6] + t[1]

	p6 -= k[7] + t[2]

	p7 -= k[8] + 10

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[0]

	p1 -= k[1]

	p2 -= k[2]

	p3 -= k[3]

	p4 -= k[4]

	p5 -= k[5] + t[0]

	p6 -= k[6] + t[1]

	p7 -= k[7] + 9

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[8]

	p1 -= k[0]

	p2 -= k[1]

	p3 -= k[2]

	p4 -= k[3]

	p5 -= k[4] + t[2]

	p6 -= k[5] + t[0]

	p7 -= k[6] + 8

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[7]

	p1 -= k[8]

	p2 -= k[0]

	p3 -= k[1]

	p4 -= k[2]

	p5 -= k[3] + t[1]

	p6 -= k[4] + t[2]

	p7 -= k[5] + 7

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[6]

	p1 -= k[7]

	p2 -= k[8]

	p3 -= k[0]

	p4 -= k[1]

	p5 -= k[2] + t[0]

	p6 -= k[3] + t[1]

	p7 -= k[4] + 6

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[5]

	p1 -= k[6]

	p2 -= k[7]

	p3 -= k[8]

	p4 -= k[0]

	p5 -= k[1] + t[2]

	p6 -= k[2] + t[0]

	p7 -= k[3] + 5

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[4]

	p1 -= k[5]

	p2 -= k[6]

	p3 -= k[7]

	p4 -= k[8]

	p5 -= k[0] + t[1]

	p6 -= k[1] + t[2]

	p7 -= k[2] + 4

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[3]

	p1 -= k[4]

	p2 -= k[5]

	p3 -= k[6]

	p4 -= k[7]

	p5 -= k[8] + t[0]

	p6 -= k[0] + t[1]

	p7 -= k[1] + 3

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[2]

	p1 -= k[3]

	p2 -= k[4]

	p3 -= k[5]

	p4 -= k[6]

	p5 -= k[7] + t[2]

	p6 -= k[8] + t[0]

	p7 -= k[0] + 2

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[1]

	p1 -= k[2]

	p2 -= k[3]

	p3 -= k[4]

	p4 -= k[5]

	p5 -= k[6] + t[1]

	p6 -= k[7] + t[2]

	p7 -= k[8] + 1

	//fmt.Printf("State after key injection: %x\n", p)

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

	p0 -= k[0]

	p1 -= k[1]

	p2 -= k[2]

	p3 -= k[3]

	p4 -= k[4]

	p5 -= k[5] + t[0]

	p6 -= k[6] + t[1]

	p7 -= k[7] + 0

	//fmt.Printf("State after key injection: %x\n", p)

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
