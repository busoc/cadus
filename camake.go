package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"time"
)

const (
	DefaultSpacecraft = 23
	DefaultChannel    = 7
	DefaultVersion    = 1
	DefaultSyncword   = 0x1acffc1d
	DefaultLength     = 1008
	DefaultReplay     = 0
	DefaultPointer    = 0x3fff
	DefaultControl    = 0xfdc3
	CaduHeaderLen     = 14
	CaduCRCLen        = 2
	CaduLen           = CaduHeaderLen + CaduCRCLen + DefaultLength
)

const MaxSequenceCounter = uint32(1 << 24)

type badconn struct {
	net.Conn
	threshold int
	limit     uint32
	curr      uint32
	with      bool

	writer io.Writer
}

func WithGap(c net.Conn, t int) net.Conn {
	rand.Seed(time.Now().Unix())
	return &badconn{
		Conn:      c,
		writer:    c,
		threshold: t,
		limit:     uint32(rand.Intn(t)),
	}
}

func (b *badconn) Write(bs []byte) (int, error) {
	b.curr++
	if b.curr >= b.limit {
		b.limit, b.curr = uint32(rand.Intn(b.threshold)), 0
		b.with = !b.with
	}
	if b.with {
		b.writer = ioutil.Discard
	} else {
		b.writer = b.Conn
	}
	return b.writer.Write(bs)
}

func init() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
}

func main() {
	threshold := flag.Int("t", 0, "threhold")
	count := flag.Int("c", 0, "count")
	rate := flag.Duration("r", time.Millisecond*500, "rate")
	file := flag.String("f", "", "file")
	proto := flag.String("p", "udp", "protocol")
	flag.Parse()

	cs := make([]io.Writer, flag.NArg())
	for i, a := range flag.Args() {
		scheme, addr := *proto, a
		if u, err := url.Parse(a); err == nil {
			scheme, addr = u.Scheme, u.Host
		}
		c, err := net.Dial(scheme, addr)
		if err != nil {
			log.Fatalln(err)
		}
		defer c.Close()
		if *threshold > 0 {
			c = WithGap(c, *threshold)
		}
		cs[i] = c
	}
	r, err := os.Open(*file)
	if err != nil {
		log.Fatalln(err)
	}
	defer r.Close()

	b, c := Build(r, *count, *rate), io.MultiWriter(cs...)
	if _, err := io.Copy(c, b); err != nil {
		log.Fatalln(err)
	}
	time.Sleep(*rate)
}

func DebugW(w io.Writer) io.Writer {
	g, err := ioutil.TempFile("", "camake-w.raw-")
	if err != nil {
		return w
	}
	return io.MultiWriter(w, g)
}

func DebugR(r io.Reader) io.Reader {
	w, err := ioutil.TempFile("", "camake-r.raw-")
	if err != nil {
		return r
	}
	return io.TeeReader(r, w)
}

type Builder struct {
	inner io.Reader

	sleep   time.Duration
	limit   uint32
	counter uint32
}

func Build(r io.Reader, c int, s time.Duration) io.Reader {
	return &Builder{inner: r, limit: uint32(c), sleep: s}
}

func (b *Builder) Read(bs []byte) (int, error) {
	if b.limit > 0 && b.counter >= b.limit {
		return 0, io.EOF
	}
	if len(bs) < CaduLen {
		return 0, io.ErrShortBuffer
	}
	var body, sum bytes.Buffer

	pid := uint16(DefaultVersion)<<14 | uint16(DefaultSpacecraft)<<6 | uint16(DefaultChannel)
	fragment := ((b.counter % MaxSequenceCounter) << 8) | uint32(DefaultReplay)

	binary.Write(&body, binary.BigEndian, uint32(DefaultSyncword))

	w := io.MultiWriter(&body, &sum)
	binary.Write(w, binary.BigEndian, uint16(pid))
	binary.Write(w, binary.BigEndian, uint32(fragment))
	binary.Write(w, binary.BigEndian, uint16(DefaultControl))
	binary.Write(w, binary.BigEndian, uint16(DefaultPointer))

	switch n, err := io.CopyN(w, b.inner, int64(DefaultLength)); {
	case err != nil:
		return int(n), err
	case n < DefaultLength:
		return int(n), io.ErrShortWrite
	default:
		b.counter++
	}
	binary.Write(&body, binary.BigEndian, calculateCRC(sum.Bytes()))
	time.Sleep(b.sleep)

	return body.Read(bs)
}

const (
	CCITT = uint16(0xFFFF)
	POLY  = uint16(0x1021)
)

func calculateCRC(bs []byte) uint16 {
	crc := CCITT
	for i := 0; i < len(bs); i++ {
		crc ^= uint16(bs[i]) << 8
		for j := 0; j < 8; j++ {
			if (crc & 0x8000) > 0 {
				crc = (crc << 1) ^ POLY
			} else {
				crc = crc << 1
			}
		}
	}
	return crc
}
