package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/kinvolk/gobpf-elf-loader/bpf"
	"github.com/vishvananda/netns"
)

type EventType uint32

const (
	_ EventType = iota
	EventConnect
	EventAccept
	EventClose
)

func (e EventType) String() string {
	switch e {
	case EventConnect:
		return "connect"
	case EventAccept:
		return "accept"
	case EventClose:
		return "close"
	default:
		return "unknown"
	}
}

type tcpEventV4 struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	Cpu   uint64
	Type  uint32
	Pid   uint32
	Comm  [16]byte
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	NetNS uint32
}

type tcpEventV6 struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	Cpu    uint64
	Type   uint32
	Pid    uint32
	Comm   [16]byte
	SAddrH uint64
	SAddrL uint64
	DAddrH uint64
	DAddrL uint64
	SPort  uint16
	DPort  uint16
	NetNS  uint32
}

var byteOrder binary.ByteOrder

// In lack of binary.HostEndian ...
func init() {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		byteOrder = binary.LittleEndian
	} else {
		byteOrder = binary.BigEndian
	}
}

var lastTimestampV4 uint64
var lastTimestampV6 uint64

func tcpEventCbV4(event tcpEventV4) {
	timestamp := uint64(event.Timestamp)
	cpu := event.Cpu
	typ := EventType(event.Type)
	pid := event.Pid & 0xffffffff
	comm := string(event.Comm[:bytes.IndexByte(event.Comm[:], 0)])

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(event.SAddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(event.DAddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := event.SPort
	dport := event.DPort
	netns := event.NetNS

	fmt.Printf("%v cpu#%d %s %v %q %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, comm, sIP, sport, dIP, dport, netns)

	if lastTimestampV4 > timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	lastTimestampV4 = timestamp
}

func tcpEventCbV6(event tcpEventV6) {
	timestamp := uint64(event.Timestamp)
	cpu := event.Cpu
	typ := EventType(event.Type)
	pid := event.Pid & 0xffffffff

	saddrbuf := make([]byte, 16)
	daddrbuf := make([]byte, 16)

	binary.LittleEndian.PutUint64(saddrbuf, event.SAddrH)
	binary.LittleEndian.PutUint64(saddrbuf[4:], event.SAddrL)
	binary.LittleEndian.PutUint64(daddrbuf, event.DAddrH)
	binary.LittleEndian.PutUint64(daddrbuf[4:], event.DAddrL)

	sIP := net.IP(saddrbuf)
	dIP := net.IP(daddrbuf)

	sport := event.SPort
	dport := event.DPort
	netns := event.NetNS

	fmt.Printf("%v cpu#%d %s %v %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, sIP, sport, dIP, dport, netns)

	if lastTimestampV6 > timestamp {
		fmt.Printf("ERROR: late event!\n")
		os.Exit(1)
	}

	lastTimestampV6 = timestamp
}

type tcpTracerState uint64

const (
	Uninitialized tcpTracerState = iota
	Checking
	Checked
	Ready
)

type What uint64

const (
	GuessSaddr What = iota
	GuessDaddr
	GuessSport
	GuessDport
	GuessNetns
	GuessFamily
	GuessDaddrIPv6
)

type tcpTracerStatus struct {
	status tcpTracerState

	pidTgid         uint64
	what            What
	offsetSaddr     uint64
	offsetDaddr     uint64
	offsetSport     uint64
	offsetDport     uint64
	offsetNetns     uint64
	offsetIno       uint64
	offsetFamily    uint64
	offsetDaddrIPv6 uint64

	saddr     uint32
	daddr     uint32
	sport     uint16
	dport     uint16
	netns     uint32
	family    uint16
	daddrIPv6 [4]uint32
}

func listen(url, netType string) {
	l, err := net.Listen(netType, url)
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		os.Exit(1)
	}
	fmt.Println("Listening on " + url)
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println("Error accepting: ", err.Error())
			os.Exit(1)
		}
		conn.Close()
	}
}

func compareThings(a, b [4]uint32) bool {
	for i := 2; i < 4; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func guessWhat(b *bpf.BPFKProbePerf) error {
	go listen("127.0.0.2:9091", "tcp4")
	time.Sleep(300 * time.Millisecond)

	currentNetns, err := netns.Get()
	if err != nil {
		return fmt.Errorf("error getting current netns: %v", err)
		os.Exit(1)
	}
	var s syscall.Stat_t
	if err := syscall.Fstat(int(currentNetns), &s); err != nil {
		return fmt.Errorf("NS(%d: unknown)", currentNetns)
	}

	mp := b.Map("tcptracer_status")

	var pidTgid uint64
	pidTgid = uint64(os.Getpid()<<32 | syscall.Gettid())

	var zero uint64
	zero = 0

	status := tcpTracerStatus{
		status:       Checking,
		pidTgid:      pidTgid,
		what:         0,
		offsetSaddr:  0,
		offsetDaddr:  0,
		offsetSport:  0,
		offsetDport:  0,
		offsetNetns:  45,
		offsetIno:    135,
		offsetFamily: 0,
		saddr:        0,
		daddr:        0,
		sport:        0,
		dport:        0,
		netns:        0,
		family:       0,
	}

	for {
		// 127.0.0.1
		saddr := 0x0100007F
		// 127.0.0.2
		daddr := 0x0200007F
		// 9091 (net endianness)
		dport := 0x8323
		// will be set later
		sport := 0
		netns := uint32(s.Ino)
		// AF_INET
		family := 2

		var daddrIPv6 [4]uint32

		daddrIPv6[0] = 0xaddeefbe
		daddrIPv6[1] = 0xaddefec0

		daddrIPv6[2] = 0x67452301
		daddrIPv6[3] = 0xefcdab89

		err = b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status))
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		if status.what != GuessDaddrIPv6 {
			conn, err := net.Dial("tcp4", "127.0.0.2:9091")
			if err != nil {
				fmt.Printf("error: %v\n", err)
			}

			sport, err = strconv.Atoi(strings.Split(conn.LocalAddr().String(), ":")[1])
			if err != nil {
				return fmt.Errorf("error: %v", err)
			}

			conn.Close()
		} else {
			conn, err := net.Dial("tcp6", "[dead:c0fe:dead:beef:0123:4567:89ab:cdef]:9092")
			if err == nil {
				conn.Close()
			}
		}

		err = b.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status))
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		if status.status == Checked {
			switch status.what {
			case GuessSaddr:
				if status.saddr == uint32(saddr) {
					fmt.Println("offsetSaddr found:", status.offsetSaddr)
					status.what++
					status.status = Checking
				} else {
					status.offsetSaddr++
					status.status = Checking
					status.saddr = uint32(saddr)
				}
			case GuessDaddr:
				if status.daddr == uint32(daddr) {
					fmt.Println("offsetDaddr found:", status.offsetDaddr)
					status.what++
					status.status = Checking
				} else {
					status.offsetDaddr++
					status.status = Checking
					status.daddr = uint32(daddr)
				}
			case GuessSport:
				if status.sport == uint16(sport) {
					fmt.Println("offsetSport found:", status.offsetSport)
					status.what++
					status.status = Checking
				} else {
					status.offsetSport++
					status.status = Checking
				}
			case GuessDport:
				if status.dport == uint16(dport) {
					fmt.Println("offsetDport found:", status.offsetDport)
					status.what++
					status.status = Checking
				} else {
					status.offsetDport++
					status.status = Checking
				}
			case GuessNetns:
				if status.netns == netns {
					fmt.Println("offsetNetns found:", status.offsetNetns)
					fmt.Println("offsetIno found:", status.offsetIno)
					status.what++
					status.status = Checking
				} else {
					status.offsetIno++
					if status.offsetIno >= 200 {
						status.offsetIno = 15
						status.offsetNetns++
					}
					status.status = Checking
				}
			case GuessFamily:
				if status.family == uint16(family) {
					fmt.Println("offsetFamily found:", status.offsetFamily)
					status.what++
					status.status = Checking
				} else {
					status.offsetFamily++
					status.status = Checking
				}
			case GuessDaddrIPv6:
				if compareThings(status.daddrIPv6, daddrIPv6) {
					fmt.Println("offsetDaddrIPv6 found:", status.offsetDaddrIPv6)
					status.what++
					status.status = Ready
					break
				} else {
					status.offsetDaddrIPv6++
					status.status = Checking
				}
			default:
				return fmt.Errorf("Uh, oh!")
			}
		}

		if status.offsetSaddr >= 50 ||
			status.offsetDaddr >= 50 ||
			status.offsetSport >= 50 ||
			status.offsetDport >= 50 ||
			status.offsetNetns >= 100 ||
			status.offsetFamily >= 50 ||
			status.offsetDaddrIPv6 >= 100 {
			fmt.Println("overflow!")
			os.Exit(1)
		}

		if status.status == Ready {
			break
		}
	}

	err = b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status))
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s ${GOPATH}/src/github.com/kinvolk/tcptracer-bpf/ebpf/${DISTRO}/x86_64/$(uname -r)/ebpf.o\n", os.Args[0])
		os.Exit(1)
	}
	fileName := os.Args[1]
	b := bpf.NewBpfPerfEvent(fileName)
	if b == nil {
		fmt.Fprintf(os.Stderr, "System doesn't support BPF\n")
		os.Exit(1)
	}

	err := b.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if err := guessWhat(b); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ready.\n")

	channelV4 := make(chan []byte)
	channelV6 := make(chan []byte)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event tcpEventV4
		for {
			data := <-channelV4
			err := binary.Read(bytes.NewBuffer(data), byteOrder, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCbV4(event)
		}
	}()

	go func() {
		var event tcpEventV6
		for {
			data := <-channelV6
			err := binary.Read(bytes.NewBuffer(data), byteOrder, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCbV6(event)
		}
	}()

	b.PollStart("tcp_event_ipv4", channelV4)
	b.PollStart("tcp_event_ipv6", channelV6)
	<-sig
	b.PollStop("tcp_event_ipv4")
	b.PollStop("tcp_event_ipv6")
}
