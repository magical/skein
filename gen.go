// +build ignore

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"reflect"
	"text/template"
)

var perm512 = [4][8]uint8{
	{0, 1, 2, 3, 4, 5, 6, 7},
	{2, 1, 4, 7, 6, 5, 0, 3},
	{4, 1, 6, 3, 0, 5, 2, 7},
	{6, 1, 0, 7, 2, 5, 4, 3},
}

// Rotation constants for Threefish-512.
var rot512 = [8][4]uint8{
	{46, 36, 19, 37},
	{33, 27, 14, 42},
	{17, 49, 36, 39},
	{44, 9, 54, 56},
	{39, 30, 34, 24},
	{13, 50, 10, 17},
	{25, 29, 39, 43},
	{8, 35, 56, 22},
}

func main() {
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	io.Copy(os.Stdout, &buf)
}

var funcs = template.FuncMap{
	"count":   count,
	"round":   round,
	"reverse": reverse,
	"p":       pfunc,
	"subkey":  subkey,
	"mod":     mod,
}

func count(n int) []int {
	s := make([]int, n)
	for i := range s {
		s[i] = i
	}
	return s
}

func reverse(iface interface{}) interface{} {
	v := reflect.ValueOf(iface)
	tmp := reflect.New(v.Type().Elem()).Elem()
	for i, j := 0, v.Len()-1; i < j; i, j = i+1, j-1 {
		x := v.Index(i)
		y := v.Index(j)
		tmp.Set(x)
		x.Set(y)
		y.Set(tmp)
	}
	return iface
}

func pfunc(i int) string {
	return fmt.Sprintf("p%d", i)
}

type subround struct {
	X, Y, R int
}

// Returns the indexes and rotation constants for the given round.
func round(i int) []subround {
	p := &perm512[i%4]
	r := &rot512[i%8]
	return []subround{
		{int(p[0]), int(p[1]), int(r[0])},
		{int(p[2]), int(p[3]), int(r[1])},
		{int(p[4]), int(p[5]), int(r[2])},
		{int(p[6]), int(p[7]), int(r[3])},
	}
}

func subkey(i, j int) string {
	k := (i/4 + j) % 9
	switch j {
	default:
		return fmt.Sprintf("k[%d]", k)
	case 5:
		return fmt.Sprintf("k[%d] + t[%d]", k, i/4%3)
	case 6:
		return fmt.Sprintf("k[%d] + t[%d]", k, (i/4+1)%3)
	case 7:
		return fmt.Sprintf("k[%d] + %d", k, i/4)
	}
}

func mod(x, y int) int {
	return x % y
}

// mix:   x += y; y <<<= r; y ^= x
// unmix: y ^= x; y >>>= r; x -= y

// Skein-512 has 72 rounds.
// Each round consists of four parallel MIX operations and a permutation.
// Subkeys are injected every four rounds.

var tmpl = template.Must(template.New("skein").Funcs(funcs).Parse(`
package skein

//import "fmt"

{{ define "inject" }}
	{{ $i := . }}
	{{ range $j := count 8 }}
		{{p $j}} += {{subkey $i $j}}
	{{ end }}
	//fmt.Printf("State after key injection: %x\n", p)
{{ end }}

// Encrypt encrypts a block p with the given key and tweak.
func encrypt512(p *[8]uint64, k *[9]uint64, t *[3]uint64) {
	//fmt.Printf("Initial state: %x\n", p)
	//fmt.Printf("Key schedule: %x\n", s[0])
	var p0, p1, p2, p3, p4, p5, p6, p7 = p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]
	t[2] = t[0] ^ t[1]
	k[8] = c240 ^ k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4] ^ k[5] ^ k[6] ^ k[7]
	{{ range $i := count 72 }}
		{{ if eq (mod $i 4) 0 }}
			{{ template "inject" $i }}
		{{ end }}
		{{ range round $i }}
			{{p .X}} += {{p .Y}}
			{{p .Y}} = {{p .Y}}<<{{.R}} | {{p .Y}}>>(64-{{.R}})
			{{p .Y}} ^= {{p .X}}
		{{ end }}
		//fmt.Printf("State after round %d: %x\n", i+{{$i}}+1, p)
	{{ end }}
	{{ template "inject" 72 }}
	p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7] = p0, p1, p2, p3, p4, p5, p6, p7
}

{{ define "uninject" }}
	{{ $i := . }}
	{{ range $j := count 8 }}
		{{p $j}} -= {{subkey $i $j}}
	{{ end }}
	//fmt.Printf("State after key injection: %x\n", p)
{{ end }}

// Decrypt decrypts a block p using the given subkeys.
func decrypt512(p *[8]uint64, k *[9]uint64, t *[3]uint64) {
	var p0, p1, p2, p3, p4, p5, p6, p7 = p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]
	t[2] = t[0] ^ t[1]
	k[8] = c240 ^ k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4] ^ k[5] ^ k[6] ^ k[7]
	{{ template "uninject" 72 }}
	{{ range $i := count 72 | reverse }}
		{{ range round $i | reverse }}
			{{p .Y}} ^= {{p .X}}
			{{p .Y}} = {{p .Y}}<<(64-{{.R}}) | {{p .Y}}>>{{.R}}
			{{p .X}} -= {{p .Y}}
		{{ end }}
		{{ if eq (mod $i 4) 0 }}
			{{ template "uninject" $i }}
		{{ end }}
	{{ end }}
	p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7] = p0, p1, p2, p3, p4, p5, p6, p7
}

// Expand expands a key and tweak into subkeys.
func expand(s *[19][8]uint64, k *[9]uint64, t *[3]uint64) {
	t[2] = t[0] ^ t[1]
	k[8] = c240 ^ k[0] ^ k[1] ^ k[2] ^ k[3] ^ k[4] ^ k[5] ^ k[6] ^ k[7]
	for i := 0; i < len(*s); i++ {
		{{ range $j := count 8 }}
			s[i][ {{$j}} ] = k[ (i + {{$j}})%9 ]
		{{ end }}
		s[i][5] += t[ (i + 0)%3 ]
		s[i][6] += t[ (i + 1)%3 ]
		s[i][7] += uint64(i)
	}
}
`))
