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

type tcpTracerState uint64

const (
	Uninitialized tcpTracerState = iota
	Checking
	Checked
	Ready
)

type tcpTracerStatus struct {
	status tcpTracerState

	pid_tgid     uint64
	what         uint64
	offset_saddr uint64
	offset_daddr uint64
	offset_sport uint64
	offset_dport uint64
	offset_netns uint64

	saddr uint32
	daddr uint32
	sport uint16
	dport uint16
	netns uint32
}

func listen(url string) {
	l, err := net.Listen("tcp4", url)
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

func guessWhat(b *bpf.BPFKProbePerf) error {
	go listen("127.0.0.2:9091")
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

	var pid_tgid uint64
	pid_tgid = uint64(os.Getpid()<<32 | syscall.Gettid())

	var zero uint64
	zero = 0

	status := tcpTracerStatus{
		status:       tcpTracerState(Checking),
		pid_tgid:     pid_tgid,
		what:         0,
		offset_saddr: 0,
		offset_daddr: 0,
		offset_sport: 0,
		offset_dport: 0,
		offset_netns: 0,
		saddr:        0x0100007F,
		daddr:        0x0200007F,
		sport:        65535,
		dport:        0x2383,
		netns:        uint32(s.Ino),
	}

	for {
		// net endianness
		dport := 0x8323
		netns := uint32(s.Ino)
		status.netns = netns
		status.dport = uint16(dport)

		err = b.UpdateElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status))
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		conn, err := net.Dial("tcp4", "127.0.0.2:9091")
		if err != nil {
			fmt.Printf("error: %v\n", err)
		}

		sport, err := strconv.Atoi(strings.Split(conn.LocalAddr().String(), ":")[1])
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		status.sport = uint16(sport)

		err = b.LookupElement(mp, unsafe.Pointer(&zero), unsafe.Pointer(&status))
		if err != nil {
			return fmt.Errorf("error: %v", err)
		}

		if status.status == tcpTracerState(Checked) {
			switch status.what {
			case 0:
				//				fmt.Printf("%x\n", status.saddr)
				if status.saddr == 0x0100007F {
					fmt.Println("offset_saddr found:", status.offset_saddr)
					status.what++
					status.status = tcpTracerState(Checking)
				} else {
					status.offset_saddr++
					status.status = tcpTracerState(Checking)
					status.saddr = 0x0100007F
				}
			case 1:
				//				fmt.Printf("%x\n", status.daddr)
				if status.daddr == 0x0200007F {
					fmt.Println("offset_daddr found:", status.offset_daddr)
					status.what++
					status.status = tcpTracerState(Checking)
				} else {
					status.offset_daddr++
					status.status = tcpTracerState(Checking)
					status.daddr = 0x0200007F
				}
			case 2:
				//				fmt.Printf("%d\n", status.sport)
				if uint16(sport) == status.sport {
					fmt.Println("offset_sport found:", status.offset_sport)
					status.what++
					status.status = tcpTracerState(Checking)
				} else {
					status.offset_sport++
					status.status = tcpTracerState(Checking)
				}
			case 3:
				//				fmt.Printf("%d\n", status.dport)
				if uint16(dport) == status.dport {
					fmt.Println("offset_dport found:", status.offset_dport)
					status.what++
					status.status = tcpTracerState(Checking)
				} else {
					status.offset_dport++
					status.status = tcpTracerState(Checking)
				}
			case 4:
				//				fmt.Printf("%d\n", status.netns)
				if netns == status.netns {
					fmt.Println("offset_netns found:", status.offset_netns)
					status.what++
					status.status = tcpTracerState(Ready)
					break
				} else {
					status.offset_netns++
					status.status = tcpTracerState(Checking)
				}
			default:
				return fmt.Errorf("Uh, oh!")
			}
		}

		if status.offset_saddr >= 50 ||
			status.offset_daddr >= 50 ||
			status.offset_sport >= 50 ||
			status.offset_dport >= 50 ||
			status.offset_netns >= 50 {
			fmt.Println("overflow!")
			os.Exit(1)
		}

		if status.status == tcpTracerState(Ready) {
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

	b.PollStart("tcp_event_v4", channelV4)
	<-sig
	b.PollStop("tcp_event_v4")
}
