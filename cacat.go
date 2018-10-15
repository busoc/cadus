package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"os"
	"time"
)

const (
	caduHeaderLen = 14
	caduCheckLen  = 2
	caduPacketLen = 1024
	caduBodyLen   = caduPacketLen - caduHeaderLen - caduCheckLen
)

var (
	GPS   = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
	UNIX  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	Delta = GPS.Sub(UNIX)
)

var (
	empty = make([]byte, caduBodyLen)
	Word  = []byte{0xf8, 0x2e, 0x35, 0x53}
	Stuff = []byte{0xf8, 0x2e, 0x35, 0xaa}
)

type hookFunc func(int, []byte)

type byFunc func([]byte) (uint16, int)

type Coze struct {
	Count   int
	Size    int
	Bad     int
	Bigger  int
	Smaller int
}

type Counter struct {
	Count   uint64
	Size    uint64
	Missing uint64
	First   uint32
	Last    uint32
}

const (
	rawPattern    = "%6d | %x | %x | %x | %x | %12d | %12d"
	fieldsPattern = "%6d | %7d | %02x | %s | %9d | %6d | %s | %s | %02x | %02x | %7d | %2d | %2d | %s"
)

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	kind := flag.String("by", "channel", "report by channel or origin")
	debug := flag.String("debug", "", "dump packet headers")
	hrdfe := flag.Bool("hrdfe", false, "hrdfe packet")
	flag.Parse()

	var hook hookFunc
	switch *debug {
	case "raw":
		hook = debugRaw
	case "header":
		hook = debugHeaders(false)
	default:
	}
	var by byFunc
	switch *kind {
	case "channel":
		by = func(vs []byte) (uint16, int) {
			return uint16(vs[8]), 12
		}
	case "origin":
		by = func(vs []byte) (uint16, int) {
			return uint16(vs[9]) << 8 | uint16(vs[47]), 27
		}
	default:
		log.Fatalln("%s unsupported", *kind)
	}

	var rs []io.Reader
	for _, a := range flag.Args() {
		r, err := os.Open(a)
		if err != nil {
			log.Println(err)
		}
		defer r.Close()
		rs = append(rs, r)
	}
	status, reports, err := reassemble(io.MultiReader(rs...), *hrdfe, by, hook)
	if err != nil {
		log.Fatalln(err)
	}
	printReports(*kind, status, reports)
}

func printReports(kind string, status map[uint16]*Coze, reports map[uint16]*Counter) {
	log.Printf("status by %s(s):", kind)
	var z Coze
	for b, c := range status {
		z.Count += c.Count
		z.Bad += c.Bad
		z.Size += c.Size

		mode := "rt"
		if m := b>>8; m >= 0x61 && m <= 0x66 {
			mode = "pb"
		}

		log.Printf("%s(%s) %02x = %8d: %6d bad, %8d length error (big: %6d, small: %6d), %9dKB", kind, mode, b&0xFF, c.Count, c.Bad, c.Bigger+c.Smaller, c.Bigger, c.Smaller, c.Size>>10)
	}

	log.Println()
	log.Printf("sequence check by %s(s):", kind)
	for b, c := range reports {
		mode := "rt"
		if m := b>>8; m >= 0x61 && m <= 0x66 {
			mode = "pb"
		}
		log.Printf("%s(%s) %02x: first: %10d - last: %10d - missing: %10d", kind, mode, b&0xFF, c.First, c.Last, c.Missing)
	}
	log.Println()
	log.Printf("%d VMU packets (%d bad, %dKB)", z.Count, z.Bad, z.Size>>10)
}

func debugRaw(i int, vs []byte) {
	z := binary.LittleEndian.Uint32(vs[4:])
	sum := vs[len(vs)-4:]
	log.Printf(rawPattern, i, vs[:8], vs[8:24], vs[24:48], sum, z, len(vs)-12)
}

func debugHeaders(hrd bool) hookFunc {
	deltas := make(map[uint8]uint32)
	return func(i int, vs []byte) {
		// HRDL Frame Header
		var (
			sync     uint32
			size     uint32
			channel  uint8
			source   uint8
			sequence uint32
			coarse   uint32
			fine     uint16
			spare    uint16
			property uint8
			stream   uint16
			counter  uint32
			acqtime  time.Duration
			auxtime  time.Duration
			origin   uint8
		)

		r := bytes.NewReader(vs)
		binary.Read(r, binary.BigEndian, &sync)
		binary.Read(r, binary.LittleEndian, &size)
		binary.Read(r, binary.LittleEndian, &channel)
		binary.Read(r, binary.LittleEndian, &source)
		binary.Read(r, binary.LittleEndian, &spare)
		binary.Read(r, binary.LittleEndian, &sequence)
		binary.Read(r, binary.LittleEndian, &coarse)
		binary.Read(r, binary.LittleEndian, &fine)
		binary.Read(r, binary.LittleEndian, &spare)
		binary.Read(r, binary.LittleEndian, &property)
		binary.Read(r, binary.LittleEndian, &stream)
		binary.Read(r, binary.LittleEndian, &counter)
		binary.Read(r, binary.LittleEndian, &acqtime)
		binary.Read(r, binary.LittleEndian, &auxtime)
		binary.Read(r, binary.LittleEndian, &origin)

		at := GPS.Add(acqtime).Format("2006-01-02 15:04:05.000")
		xt := GPS.Add(auxtime).Format("15:04:05.000")
		vt := readTime6(coarse, fine).Add(Delta).Format("2006-01-02 15:04:05.000")

		tp, st := property>>4, property&0xF
		var upi string
		switch bs := make([]byte, 32); tp {
		case 1:
			io.ReadFull(r, bs)
			upi = string(bytes.Trim(bs, "\x00"))
		case 2:
			io.ReadFull(r, make([]byte, 20))
			io.ReadFull(r, bs)
			upi = string(bytes.Trim(bs, "\x00"))
		default:
			upi = "UNKNOWN"
		}
		k, s := channel, sequence
		if hrd {
			k, s = origin, counter
		}
		var delta uint64
		if last, ok := deltas[k]; ok && last+1 != s {
			delta = sequenceDelta(s, last)
		}
		deltas[k] = s

		log.Printf(fieldsPattern, i, size, channel, vt, sequence, delta, at, xt, source, origin, counter, tp, st, upi)
	}
}

func readTime6(coarse uint32, fine uint16) time.Time {
	t := time.Unix(int64(coarse), 0).UTC()

	fs := float64(fine) / 65536.0 * 1000.0
	ms := time.Duration(fs) * time.Millisecond
	return t.Add(ms).UTC()
}

var (
	ErrSyncword = errors.New("missing syncword")
	ErrMultiple = errors.New("multiple syncword")
)

func reassemble(r io.Reader, hrdfe bool, by byFunc, hook hookFunc) (map[uint16]*Coze, map[uint16]*Counter, error) {
	rs := NewReader(r, hrdfe)

	status := make(map[uint16]*Coze)
	reports := make(map[uint16]*Counter)

	xs := make([]byte, 8<<20)
	for i := 1; ; i++ {
		n, err := rs.Read(xs)
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		if n == 0 || err == io.EOF {
			break
		}
		vs := xs[:n]
		if !bytes.Equal(vs[:len(Word)], Word) {
			return nil, nil, ErrSyncword
		}
		if i := bytes.Index(vs, Word); i >= len(Word) {
			return nil, nil, ErrMultiple
		}
		if hook != nil {
			hook(i, vs)
		}

		k, six := by(vs)
		c, ok := status[k]
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
		}
		switch z, n := binary.LittleEndian.Uint32(vs[4:]), len(vs)-12; {
		default:
		case int(z) > n:
			c.Smaller++
		case int(z) < n:
			c.Bigger++
		}
		status[k] = c

		v, ok := reports[k]
		if seq := binary.LittleEndian.Uint32(vs[six:]); !ok {
			v = &Counter{First: seq, Last: seq}
		} else {
			v.Missing += sequenceDelta(seq, v.Last)
			v.Last = seq
		}
		v.Count++
		reports[k] = v
	}
	return status, reports, nil
}

func sequenceDelta(current, last uint32) uint64 {
	if current == last+1 {
		return 0
	}
	if current > last {
		return uint64(current) - uint64(last)
	}
	return 0
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
	xs := make([]byte, r.rest.Len(), len(bs))
	if _, err := io.ReadFull(r.rest, xs); err != nil {
		return 0, err
	}
	if n := r.copyHRDL(xs, bs); n > 0 {
		return n, nil
	}
	for {
		vs, err := r.readCadu()
		if err != nil {
			return 0, err
		}
		xs = append(xs, vs...)
		if ix := bytes.Index(xs, Word); ix >= 0 {
			xs = bytes.Replace(xs[ix:], Stuff, Word[:3], -1)
			// xs = xs[ix:]
			break
		}
	}
	for {
		if n := r.copyHRDL(xs, bs); n > 0 {
			return n, nil
		}
		vs, err := r.readCadu()
		if err != nil {
			return 0, err
		}
		xs = append(xs, vs...)
		offset := len(xs) - caduPacketLen
		if offset < 0 {
			offset = 0
		}
		copy(xs[offset:], bytes.Replace(xs[offset:], Stuff, Word[:3], -1))
	}
}

func (r *reader) copyHRDL(xs, bs []byte) int {
	if len(xs) < 8 || !bytes.Equal(xs[:len(Word)], Word) {
		return 0
	}
	offset := len(xs) - defaultOffset
	if offset <= 0 {
		offset = len(Word)
	}
	ix := bytes.Index(xs[offset:], Word)
	if ix < 0 {
		return 0
	}
	z := ix + offset
	s := int(binary.LittleEndian.Uint32(xs[len(Word):])) + 12
	if s > z {
		s = z
	}
	// ns := bytes.Replace(xs[:s], []byte{0xf8, 0x2e, 0x35, 0xaa}, []byte{0xf8, 0x2e, 0x35}, -1)
	n := copy(bs, xs[:s])
	r.rest.Write(xs[z:])
	return n
}

func (r *reader) readCadu() ([]byte, error) {
	vs := make([]byte, caduPacketLen+r.skip)
	if _, err := io.ReadFull(r.inner, vs); err != nil {
		return nil, err
	}
	return vs[r.skip+caduHeaderLen : r.skip+caduPacketLen-caduCheckLen], nil
}
