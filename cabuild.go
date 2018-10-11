package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
)

var (
	CaduMagic = []byte{0x1a, 0xcf, 0xfc, 0x1d}
	HRDLMagic = []byte{0xf8, 0x2e, 0x35, 0x53}
)

var (
	UNIX  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	GPS   = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
	Delta = GPS.Sub(UNIX)
)

const caduBodyLen = 1008

const (
	VMURowPattern = "%10d | %08x | %8d | %d | %02x | %8d | %s | %t"
	TimePattern   = "2006-01-02 15:04:05.000"
)

type LengthError struct {
	Want int
	Got  int
}

func (e LengthError) Error() string {
	return fmt.Sprintf("invalid length: want %d, got %d", e.Want, e.Got)
}

type ChecksumError struct {
	Want uint16
	Got  uint16
}

func (e ChecksumError) Error() string {
	return fmt.Sprintf("invalid checksum: want %04x, got %04x", e.Want, e.Got)
}

type vmuSum struct {
	sum uint32
}

func Sum() hash.Hash32 {
	return &vmuSum{}
}

func (v *vmuSum) Size() int      { return 4 }
func (v *vmuSum) BlockSize() int { return 32 }
func (v *vmuSum) Reset()         { v.sum = 0 }

func (v *vmuSum) Sum(bs []byte) []byte {
	v.Write(bs)
	vs := make([]byte, v.Size())
	binary.LittleEndian.PutUint32(vs, v.sum)

	return vs
}

func (v *vmuSum) Write(bs []byte) (int, error) {
	for i := 0; i < len(bs); i++ {
		v.sum += uint32(bs[i])
	}
	return len(bs), nil
}

func (v *vmuSum) Sum32() uint32 {
	return v.sum
}

type Header struct {
	Word     uint32
	Version  uint8
	Space    uint8
	Channel  uint8
	Sequence uint32
	Replay   bool
	Control  uint16
	Data     uint16
}

type Cadu struct {
	*Header
	Payload []byte
	Control uint16
	Error   error
}

func (c *Cadu) Missing(p *Cadu) uint32 {
	if p == nil {
		return 0
	}
	if p.Sequence > c.Sequence {
		return p.Missing(c)
	}
	if p.Sequence+1 != c.Sequence {
		return c.Sequence - p.Sequence
	}
	return 0
}

func init() {
	log.SetFlags(0)
}

var (
	Hadock  = 0
	Version = 2
	Mode    = 255
)

func main() {
	flag.IntVar(&Hadock, "k", Hadock, "hadock version")
	flag.IntVar(&Version, "u", Version, "VMU version")
	flag.IntVar(&Mode, "m", Mode, "mode")
	flag.Parse()
	queue, err := decodeFromUDP(flag.Arg(0))
	if err != nil {
		log.Fatalln(err)
	}
	logger := log.New(os.Stderr, "[main] ", 0)
	for vs := range reassemble(queue) {
		for {
			rs, err := debugHRDLHeaders(vs)
			if err != nil {
				logger.Println(err)
			}
			if len(rs) == 0 || err != nil {
				break
			}
			vs = rs
		}
	}
}

func reassemble(queue <-chan *Cadu) <-chan []byte {
	q := make(chan []byte)
	go func() {
		defer close(q)
		var (
			prev *Cadu
			pos  int
		)

		bs := make([]byte, 0, 8<<20)
		for c := range queue {
			back := pos
			switch delta := int(c.Missing(prev)); {
			default:
				pos += caduBodyLen
			case delta > 0:
				pos += (delta * caduBodyLen)
			case delta < 0:
				pos = pos + (delta * caduBodyLen)
			}
			switch p := pos - caduBodyLen; {
			case p == len(bs):
				bs = append(bs, c.Payload...)
			case p > len(bs):
				zs := make([]byte, p-len(bs))
				bs = append(bs, zs...)
				bs = append(bs, c.Payload...)
			case p < len(bs):
				if p >= 0 {
					copy(bs[p:], c.Payload)
				} else {
					zs := make([]byte, -pos-len(c.Payload))
					vs := make([]byte, len(c.Payload)+len(zs)+len(bs))

					copy(vs[:len(c.Payload)], c.Payload)
					copy(vs[len(c.Payload):len(c.Payload)+len(zs)], zs)
					copy(vs[len(c.Payload)+len(zs):], bs)
					bs = vs
					pos = back
				}
			}
			offset := len(bs) - len(c.Payload) - len(HRDLMagic)
			if offset < 0 {
				continue
			}
			if ix := bytes.Index(bs[offset:], HRDLMagic); len(bs) > 0 && ix >= 0 {
				if bytes.HasPrefix(bs, HRDLMagic) {
					vs := make([]byte, offset+ix)
					copy(vs, bs[:offset+ix])
					q <- vs
				}
				bs, pos = bs[offset+ix:], len(bs)-(offset+ix)
			}
			prev = c
		}
	}()
	return q
}

func debugHRDLHeaders(bs []byte) ([]byte, error) {
	var (
		sync    uint32
		length  uint32
		channel uint8
		origin  uint8
		counter uint32
		coarse  uint32
		fine    uint16
		spare   uint16
		digest  uint32
	)
	r := bytes.NewReader(bs)
	binary.Read(r, binary.BigEndian, &sync)
	if sync != binary.BigEndian.Uint32(HRDLMagic) {
		return nil, fmt.Errorf("invalid sync word found %08x", sync)
	}
	binary.Read(r, binary.LittleEndian, &length)

	sum := Sum()
	rs := io.TeeReader(r, sum)
	binary.Read(rs, binary.LittleEndian, &channel)
	binary.Read(rs, binary.LittleEndian, &origin)
	binary.Read(rs, binary.LittleEndian, &spare)
	binary.Read(rs, binary.LittleEndian, &counter)
	binary.Read(rs, binary.LittleEndian, &coarse)
	binary.Read(rs, binary.LittleEndian, &fine)
	binary.Read(rs, binary.LittleEndian, &spare)

	when := readTime6(coarse, fine).Add(Delta)
	if n, err := io.CopyN(ioutil.Discard, rs, int64(length-16)); err != nil {
		return nil, LengthError{Want: int(length), Got: int(n)}
	}
	binary.Read(r, binary.LittleEndian, &digest)

	log.Printf(VMURowPattern, len(bs), sync, length, channel, origin, counter, when.Format(TimePattern), sum.Sum32() == digest)

	var vs []byte
	if n := r.Len(); n > 0 {
		vs = make([]byte, n)
		io.ReadFull(r, vs)
	}
	return vs, nil
}

func decodeFromUDP(addr string) (<-chan *Cadu, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	var r *net.UDPConn
	if a.IP.IsMulticast() {
		r, err = net.ListenMulticastUDP("udp", nil, a)
	} else {
		r, err = net.ListenUDP("udp", a)
	}
	q := make(chan *Cadu, 100)
	go func() {
		defer func() {
			close(q)
			r.Close()
		}()
		rs := bufio.NewReaderSize(r, 4<<20)
		for {
			c, err := decodeCadu(rs)
			if err != nil {
				return
			}
			q <- c
		}
	}()
	return q, nil
}

func decodeCadu(r io.Reader) (*Cadu, error) {
	var (
		h   Header
		pid uint16
		seq uint32
	)
	if err := binary.Read(r, binary.BigEndian, &h.Word); err != nil {
		return nil, err
	}

	var sum bytes.Buffer
	r = io.TeeReader(r, &sum)

	binary.Read(r, binary.BigEndian, &pid)
	h.Version = uint8((pid & 0xC000) >> 14)
	h.Space = uint8((pid & 0x3FC0) >> 6)
	h.Channel = uint8(pid & 0x003F)

	binary.Read(r, binary.BigEndian, &seq)
	h.Sequence = seq >> 8
	h.Replay = (seq >> 7) == 1

	binary.Read(r, binary.BigEndian, &h.Control)
	binary.Read(r, binary.BigEndian, &h.Data)

	c := Cadu{
		Header:  &h,
		Payload: make([]byte, caduBodyLen),
	}
	if _, err := io.ReadFull(r, c.Payload); err != nil {
		return nil, err
	}
	s := calculateCRC(sum.Bytes())
	binary.Read(r, binary.BigEndian, &c.Control)
	if s != c.Control {
		c.Error = ChecksumError{Want: c.Control, Got: s}
	}

	return &c, nil
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

func readTime6(coarse uint32, fine uint16) time.Time {
	t := time.Unix(int64(coarse), 0).UTC()

	fs := float64(fine) / 65536.0 * 1000.0
	ms := time.Duration(fs) * time.Millisecond
	return t.Add(ms).UTC()
}
