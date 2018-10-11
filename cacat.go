package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
)

const (
	caduHeaderLen = 14
	caduCheckLen  = 2
	caduPacketLen = 1024
	caduBodyLen   = caduPacketLen - caduHeaderLen - caduCheckLen
)

var (
	empty = make([]byte, caduBodyLen)
	Word  = []byte{0xf8, 0x2e, 0x35, 0x53}
)

type Coze struct {
	Count int
	Size  int
	Bad   int
	Error int
}

type Counter struct {
	Missing uint32
	First uint32
	Last  uint32
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	hrdfe := flag.Bool("hrdfe", false, "hrdfe packet")
	flag.Parse()

	var rs []io.Reader
	for _, a := range flag.Args() {
		r, err := os.Open(a)
		if err != nil {
			log.Println(err)
		}
		defer r.Close()
		rs = append(rs, r)
	}
	z, err := reassemble(io.MultiReader(rs...), *hrdfe)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("%d VMU packets (%d bad, %dKB)", z.Count, z.Bad, z.Size>>10)
}

func reassemble(r io.Reader, hrdfe bool) (*Coze, error) {
	rs := NewReader(r, hrdfe)

	var z Coze
	counts := make(map[byte]*Coze)
	origins := make(map[byte]*Counter)
	channels := make(map[byte]*Counter)

	xs := make([]byte, 8<<20)
	for i := 1; ; i++ {
		n, err := rs.Read(xs)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 || err == io.EOF {
			break
		}
		vs := xs[:n]
		if !bytes.Equal(vs[:len(Word)], Word) {
			return nil, fmt.Errorf("missing sync word")
		}
		if i := bytes.Index(vs, Word); i >= len(Word) {
			return nil, fmt.Errorf("multiple vmu packets")
		}
		z.Count++
		z.Size += n

		// count per origin
		c, ok := counts[vs[47]]
		if !ok {
			c = &Coze{}
		}
		c.Count++
		c.Size += n

		var sum uint32
		for i := 8; i < len(vs)-4; i++ {
			sum += uint32(vs[i])
		}
		if sum != binary.LittleEndian.Uint32(vs[len(vs)-4:]) {
			c.Bad++
			z.Bad++
		}
		if z := binary.LittleEndian.Uint32(vs[4:]); int(z) != len(vs)-12 {
			c.Error++
		}

		counts[vs[47]] = c

		// check missing vmu packets
		v, ok := channels[vs[8]]
		vmuseq := uint32(binary.LittleEndian.Uint16(vs[12:]))
		if !ok {
			v = &Counter{First: vmuseq, Last: vmuseq}
		} else {
			if vmuseq != v.Last+1 {
				v.Missing += vmuseq - v.Last
			}
			v.Last = vmuseq
		}
		channels[vs[8]] = v

		// check missing hrd packets by orgins
		o, ok := origins[vs[47]]
		oriseq := binary.LittleEndian.Uint32(vs[27:])
		if !ok {
			o = &Counter{First: oriseq, Last: oriseq}
		} else {
			if oriseq != o.Last+1 {
				o.Missing += oriseq - o.Last
			}
			o.Last = oriseq
		}
		origins[vs[47]] = o
	}
	log.Println("count packets by origin")
	for b, c := range counts {
		log.Printf("origin %02x = %8d: %6d bad, %8d length error, %9dKB", b, c.Count, c.Bad, c.Error, c.Size>>10)
	}
	log.Println()
	log.Println("sequence check by origin")
	for b, c := range origins {
		log.Printf("origin %02x: first: %10d - last: %10d - missing: %10d", b, c.First, c.Last, c.Missing)
	}
	log.Println()
	log.Println("sequence check by channel")
	for b, c := range channels {
		log.Printf("channel %02x: first: %10d - last: %10d - missing: %10d", b, c.First, c.Last, c.Missing)
	}
	return &z, nil
}

type reader struct {
	inner *bufio.Reader
	rest  *bytes.Buffer
	skip  int
}

func NewReader(r io.Reader, hrdfe bool) io.Reader {
	rs := &reader{
		inner: bufio.NewReaderSize(r, 1<<20),
		rest:  new(bytes.Buffer),
	}
	if hrdfe {
		rs.skip = 8
	}
	return rs
}

const defaultOffset = caduBodyLen + 4

func (r *reader) Read(bs []byte) (int, error) {
	xs := r.rest.Bytes()
	r.rest.Reset()
	if len(xs) > 8 && bytes.Equal(xs[:len(Word)], Word) {
		if ix := bytes.Index(xs[len(Word):], Word); ix >= 0 {
			n := copy(bs, xs[:ix+len(Word)])
			r.rest.Write(xs[ix+len(Word):])
			return n, nil
		}
	}
	for {
		vs, err := r.readCadu()
		if err != nil {
			return 0, err
		}
		xs = append(xs, vs...)
		if ix := bytes.Index(xs, Word); ix >= 0 {
			xs = xs[ix:]
			break
		}
	}
	for {
		offset := len(xs) - defaultOffset
		if offset <= 0 {
			offset = len(Word)
		}
		if ix := bytes.Index(xs[offset:], Word); ix >= 0 {
			// z := binary.LittleEndian.Uint32(xs[len(Word):])
			// log.Printf("hrdl: %x %8d - vmu: %x - rest: %x", xs[:8], z, xs[8:24], xs[24:48])
			// if int(z) >= len(xs) {
			// 	xs = xs[offset+ix:]
			// 	continue
			// }
			n := copy(bs, xs[:offset+ix])
			r.rest.Write(xs[offset+ix:])
			return n, nil
		}
		vs, err := r.readCadu()
		if err != nil {
			return 0, err
		}
		xs = append(xs, vs...)
	}
}

func (r *reader) readCadu() ([]byte, error) {
	vs := make([]byte, caduPacketLen+r.skip)
	if _, err := io.ReadFull(r.inner, vs); err != nil {
		return nil, err
	}
	return vs[r.skip+caduHeaderLen : caduPacketLen-caduCheckLen], nil
}
