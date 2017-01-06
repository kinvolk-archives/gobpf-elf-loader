package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/kinvolk/gobpf-elf-loader/bpf"
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
	binary.LittleEndian.PutUint64(saddrbuf[8:], event.SAddrL)
	binary.LittleEndian.PutUint64(daddrbuf, event.DAddrH)
	binary.LittleEndian.PutUint64(daddrbuf[8:], event.DAddrL)

	sIP := net.IP(saddrbuf)
	dIP := net.IP(daddrbuf)

	sport := event.SPort
	dport := event.DPort
	netns := event.NetNS

	fmt.Printf("%v cpu#%d %s %v [%v]:%v [%v]:%v %v\n", timestamp, cpu, typ, pid, sIP, sport, dIP, dport, netns)

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

type GuessWhat uint64

const (
	GuessSaddr GuessWhat = iota
	GuessDaddr
	GuessSport
	GuessDport
	GuessNetns
	GuessFamily
	GuessDaddrIPv6
)

type tcpTracerStatus struct {
	status          tcpTracerState
	pidTgid         uint64
	what            GuessWhat
	offsetSaddr     uint64
	offsetDaddr     uint64
	offsetSport     uint64
	offsetDport     uint64
	offsetNetns     uint64
	offsetIno       uint64
	offsetFamily    uint64
	offsetDaddrIPv6 uint64
	err             byte
	saddr           uint32
	daddr           uint32
	sport           uint16
	dport           uint16
	netns           uint32
	family          uint16
	daddrIPv6       [4]uint32
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

func compareIPv6(a, b [4]uint32) bool {
	for i := 0; i < 4; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func ownNetNS() (uint64, error) {
	var s syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &s); err != nil {
		return 0, err
	}
	return s.Ino, nil
}

func IPFromUint32Arr(ipv6Addr [4]uint32) net.IP {
	buf := make([]byte, 16)
	for i := 0; i < 16; i++ {
		buf[i] = *(*byte)(unsafe.Pointer((uintptr(unsafe.Pointer(&ipv6Addr[0])) + uintptr(i))))
	}
	return net.IP(buf)
}

func guessOffsets(b *bpf.BPFKProbePerf) error {
	listenIP := "127.0.0.2"
	listenPort := uint16(9091)
	bindAddress := fmt.Sprintf("%s:%d", listenIP, listenPort)

	go listen(bindAddress, "tcp4")
	time.Sleep(300 * time.Millisecond)

	currentNetns, err := ownNetNS()
	if err != nil {
		return fmt.Errorf("error getting current netns: %v", err)
		os.Exit(1)
	}

	mp := b.Map("tcptracer_status")

	var zero uint64
	pidTgid := uint64(os.Getpid()<<32 | syscall.Gettid())

	status := tcpTracerStatus{
		status:  Checking,
		pidTgid: pidTgid,
	}

	err = b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status))
	if err != nil {
		return fmt.Errorf("error: %v", err)
	}

	// convert to network endianness
	arr := make([]byte, 2)
	binary.BigEndian.PutUint16(arr, listenPort)
	dport := byteOrder.Uint16(arr)

	// 127.0.0.1
	saddr := 0x0100007F
	// 127.0.0.2
	daddr := 0x0200007F
	// will be set later
	sport := 0
	netns := uint32(currentNetns)
	family := syscall.AF_INET

	for status.status != Ready {
		var daddrIPv6 [4]uint32

		daddrIPv6[0] = rand.Uint32()
		daddrIPv6[1] = rand.Uint32()
		daddrIPv6[2] = rand.Uint32()
		daddrIPv6[3] = rand.Uint32()

		ip := IPFromUint32Arr(daddrIPv6)

		if status.what != GuessDaddrIPv6 {
			conn, err := net.Dial("tcp4", bindAddress)
			if err != nil {
				fmt.Printf("error: %v\n", err)
			}

			sport, err = strconv.Atoi(strings.Split(conn.LocalAddr().String(), ":")[1])
			if err != nil {
				return fmt.Errorf("error: %v", err)
			}

			// set SO_LINGER to 0 so the connection state after closing is
			// CLOSE instead of TIME_WAIT. In this way, they will disappear
			// from the conntrack table after around 10 seconds instead of 2
			// minutes
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetLinger(0)
			} else {
				panic("not a tcp connection")
			}

			conn.Close()
		} else {
			conn, err := net.Dial("tcp6", fmt.Sprintf("[%s]:9092", ip))
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
				if status.dport == dport {
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
					// go to the next offsetNetns if we get an error
					if status.err != 0 || status.offsetIno >= 200 {
						status.offsetIno = 0
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
				if compareIPv6(status.daddrIPv6, daddrIPv6) {
					fmt.Println("offsetDaddrIPv6 found:", status.offsetDaddrIPv6)
					status.what++
					status.status = Ready
				} else {
					status.offsetDaddrIPv6++
					status.status = Checking
				}
			default:
				return fmt.Errorf("Uh, oh!")
			}
		}

		err = b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status))
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		if status.offsetSaddr >= 200 || status.offsetDaddr >= 200 ||
			status.offsetSport >= 200 || status.offsetDport >= 200 ||
			status.offsetNetns >= 200 || status.offsetFamily >= 200 ||
			status.offsetDaddrIPv6 >= 200 {
			fmt.Fprintf(os.Stderr, "overflow, bailing out!\n")
			os.Exit(1)
		}
	}

	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s ${GOPATH}/src/github.com/kinvolk/tcptracer-bpf/ebpf/ebpf.o\n", os.Args[0])
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

	if err := guessOffsets(b); err != nil {
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
