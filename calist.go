package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"time"
)

const (
	pcapHeaderLen   = 24
	pktHeaderLen    = 16
	cookedHeaderLen = 14
	ipHeaderLen     = 20
	udpHeaderLen    = 8
	tcpHeaderLen    = 32
	// tcpHeaderLen    = 20
	caduLen       = 1024
	caduHeaderLen = 14
	caduBodyLen   = 1008
	caduPacketLen = caduBodyLen + caduHeaderLen + 2
	blockLen      = cookedHeaderLen + ipHeaderLen
	// blockLen = pktHeaderLen + cookedHeaderLen + ipHeaderLen + udpHeaderLen
)

var (
	CaduMagic = []byte{0x1a, 0xcf, 0xfc, 0x1d}
	HRDLMagic = []byte{0xf8, 0x2e, 0x35, 0x53}
)

var (
	GPS   = time.Date(1980, 1, 6, 0, 0, 0, 0, time.UTC)
	UNIX  = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	Delta = GPS.Sub(UNIX)
)

const TimeFormat = "2006-01-02 15:04:05.000"

type ChecksumError struct {
	Want uint16
	Got  uint16
}

func (c ChecksumError) Error() string {
	return fmt.Sprintf("invalid checksum: want %04x, got %04x", c.Want, c.Got)
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
	if delta := (c.Sequence - p.Sequence) & 0xFFFFFF; delta > 1 {
		return delta
	}
	return 0
}

type TimeCadu struct {
	*Cadu
	Reception time.Time
}

func (t *TimeCadu) Missing(p *TimeCadu) uint32 {
	if p == nil {
		return 0
	}
	return t.Cadu.Missing(p.Cadu)
}

func (t *TimeCadu) Elapsed(p *TimeCadu) time.Duration {
	if p == nil {
		return 0
	}
	if p.Reception.After(t.Reception) {
		return p.Elapsed(t)
	}
	return t.Reception.Sub(p.Reception)
}

func init() {
	log.SetFlags(0)
	log.SetOutput(os.Stdout)
}

func main() {
	proto := flag.String("p", "udp", "protocol")
	mode := flag.String("m", "", "mode")
	hrdfe := flag.Bool("hrdfe", false, "skip byte")
	flag.Parse()

	var (
		queue <-chan *TimeCadu
		err   error
	)
	switch *proto {
	case "udp":
		queue, err = decodeFromUDP(flag.Arg(0))
	case "tcp":
		queue, err = decodeFromTCP(flag.Arg(0))
	case "pcap+udp":
		queue, err = decodeFromPCAP(flag.Args(), udpHeaderLen)
	case "pcap+tcp":
		queue, err = decodeFromPCAP(flag.Args(), tcpHeaderLen)
	case "file", "":
		queue, err = decodeFromFile(flag.Args(), *hrdfe)
	default:
		err = fmt.Errorf("unsupported protocol %s", *proto)
	}

	if err != nil {
		log.Fatalln(err)
	}

	switch *mode {
	case "", "list":
		printCadus(queue)
	case "gaps":
		printGaps(queue)
	default:
		log.Fatalln("unknown working mode %q", *mode)
	}
}

func printGaps(queue <-chan *TimeCadu) {
	const line = "%s | %s | %8d | %8d | %4d | %s"

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Kill, os.Interrupt)

	var (
		prev  *TimeCadu
		count int
		gaps  uint32
		total time.Duration
	)
	now := time.Now()
Loop:
	for {
		select {
		case c, ok := <-queue:
			if !ok {
				break Loop
			}
			delta, elapsed := c.Missing(prev), c.Elapsed(prev)
			count++
			if delta != 0 {
				gaps += delta
				total += elapsed
				log.Printf(line, prev.Reception.Format(TimeFormat), c.Reception.Format(TimeFormat), prev.Sequence, c.Sequence, delta, elapsed)
			}
			prev = c
		case <-sig:
			break Loop
		}
	}
	log.Println()
	log.Printf("%d/%d missing cadus (%s/%s)", gaps, count, total, time.Since(now))
}

func printCadus(queue <-chan *TimeCadu) {
	var (
		prev      *TimeCadu
		count     int
		corrupted int
		missing   int
		total     time.Duration
	)
	for c := range queue {
		delta, elapsed := c.Missing(prev), c.Elapsed(prev)
		total += elapsed
		err := "-"
		if c.Error != nil {
			err = c.Error.Error()
			corrupted++
		}
		missing += int(delta)
		count++

		log.Printf("%8d | %s | %18s | %18s | %04x | %-3d | %-3d | %-3d | %-12d | %6t | %04x | %04x | %04x | %4d | %s",
			count,
			c.Reception.Format("2006-01-02 15:05:04.000"),
			elapsed,
			total,
			c.Header.Word,
			c.Header.Version,
			c.Header.Space,
			c.Header.Channel,
			c.Header.Sequence,
			c.Header.Replay,
			c.Header.Control,
			c.Header.Data,
			c.Control,
			delta,
			err,
		)
		prev = c
	}
	log.Printf("%d cadus found (%d missing, %d corrupted - total time %s)", count, missing, corrupted, total)
}

func decodeFromTCP(addr string) (<-chan *TimeCadu, error) {
	c, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	q := make(chan *TimeCadu, 100)
	go func() {
		defer func() {
			close(q)
			q = nil
			c.Close()
		}()
		for {
			c, err := c.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rs := bufio.NewReaderSize(c, 4096)
				for {
					c, err := decodeCadu(rs)
					if err != nil {
						return
					}
					select {
					case q <- &TimeCadu{Reception: time.Now(), Cadu: c}:
					default:
					}
				}
			}(c)
		}
	}()
	return q, nil
}

func decodeFromUDP(addr string) (<-chan *TimeCadu, error) {
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
	q := make(chan *TimeCadu, 100)
	go func(r io.ReadCloser) {
		defer func() {
			close(q)
			r.Close()
		}()
		rs := bufio.NewReaderSize(r, 4096)
		for {
			c, err := decodeCadu(rs)
			if err != nil {
				return
			}
			q <- &TimeCadu{Reception: time.Now(), Cadu: c}
		}
	}(r)
	return q, nil
}

func decodeFromFile(paths []string, hrdfe bool) (<-chan *TimeCadu, error) {
	q := make(chan *TimeCadu, 100)
	go func() {
		var rs []io.Reader
		for _, p := range paths {
			r, err := os.Open(p)
			if err != nil {
				return
			}
			defer r.Close()
			rs = append(rs, r)
		}
		r := io.MultiReader(rs...)
		defer close(q)
		for {
			n := time.Now()
			if hrdfe {
				var (
					coarse uint32
					fine   uint32
				)
				binary.Read(r, binary.LittleEndian, &coarse)
				binary.Read(r, binary.LittleEndian, &fine)

				n = time.Unix(int64(coarse), int64(fine)*1000).Add(Delta)
			}
			c, err := decodeCadu(r)
			if err != nil {
				break
			}
			q <- &TimeCadu{Reception: n, Cadu: c}
		}
	}()
	return q, nil
}

func decodeFromPCAP(paths []string, cutLen int) (<-chan *TimeCadu, error) {
	q := make(chan *TimeCadu, 100)
	go func() {
		defer close(q)
		for _, p := range paths {
			r, err := os.Open(p)
			if err != nil {
				continue
			}
			r.Seek(pcapHeaderLen, io.SeekStart)
			for {
				var (
					sec, ms uint32
					length  uint32
					spare   uint32
				)
				binary.Read(r, binary.LittleEndian, &sec)
				binary.Read(r, binary.LittleEndian, &ms)
				binary.Read(r, binary.LittleEndian, &length)
				binary.Read(r, binary.LittleEndian, &spare)
				if length == 0 {
					r.Close()
					break
				}
				if length < caduPacketLen {
					r.Seek(int64(length), io.SeekCurrent)
					continue
				}
				r.Seek(int64(blockLen+cutLen), io.SeekCurrent)

				c, err := decodeCadu(r)
				if err != nil {
					r.Close()
					break
				}
				when := time.Unix(int64(sec), 0).Add(time.Duration(ms) * time.Microsecond).UTC()
				q <- &TimeCadu{Reception: when, Cadu: c}
			}
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

	sum := Sum()
	rs := io.TeeReader(r, sum)

	binary.Read(rs, binary.BigEndian, &pid)
	h.Version = uint8((pid & 0xC000) >> 14)
	h.Space = uint8((pid & 0x3FC0) >> 6)
	h.Channel = uint8(pid & 0x003F)

	binary.Read(rs, binary.BigEndian, &seq)
	h.Sequence = seq >> 8
	h.Replay = (seq >> 7) == 1

	binary.Read(rs, binary.BigEndian, &h.Control)
	binary.Read(rs, binary.BigEndian, &h.Data)

	c := Cadu{
		Header:  &h,
		Payload: make([]byte, caduBodyLen),
	}
	if _, err := io.ReadFull(rs, c.Payload); err != nil {
		return nil, err
	}
	binary.Read(r, binary.BigEndian, &c.Control)
	if s := sum.Sum32(); uint16(s) != c.Control {
		c.Error = ChecksumError{Want: c.Control, Got: uint16(s)}
	}

	return &c, nil
}

type ccittSum struct {
	sum uint16
}

func Sum() hash.Hash32 {
	return &ccittSum{sum: CCITT}
}

func (c *ccittSum) Size() int      { return 2 }
func (c *ccittSum) BlockSize() int { return 32 }
func (c *ccittSum) Reset()         { c.sum = 0 }

func (c *ccittSum) Write(bs []byte) (int, error) {
	for i := 0; i < len(bs); i++ {
		c.sum ^= uint16(bs[i]) << 8
		for j := 0; j < 8; j++ {
			if (c.sum & 0x8000) > 0 {
				c.sum = (c.sum << 1) ^ POLY
			} else {
				c.sum = c.sum << 1
			}
		}
	}
	return len(bs), nil
}

func (c *ccittSum) Sum(bs []byte) []byte {
	c.Write(bs)

	vs := make([]byte, 4)
	binary.BigEndian.PutUint32(vs, c.Sum32())
	return vs
}

func (c *ccittSum) Sum32() uint32 {
	return uint32(c.sum)
}

const (
	CCITT = uint16(0xFFFF)
	POLY  = uint16(0x1021)
)

// func calculateCRC(bs []byte) uint16 {
// 	crc := CCITT
// 	for i := 0; i < len(bs); i++ {
// 		crc ^= uint16(bs[i]) << 8
// 		for j := 0; j < 8; j++ {
// 			if (crc & 0x8000) > 0 {
// 				crc = (crc << 1) ^ POLY
// 			} else {
// 				crc = crc << 1
// 			}
// 		}
// 	}
// 	return crc
// }
