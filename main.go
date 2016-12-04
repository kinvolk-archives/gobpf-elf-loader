package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"unsafe"

	bpf "github.com/kinvolk/go-ebpf-kprobe-example/bpf"
)

import "C"

type tcpEvent struct {
	// Timestamp must be the first field, the sorting depends on it
	Timestamp uint64

	Cpu   uint64
	Type  [12]C.char
	Pid   uint32
	Comm  [16]C.char
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

var lastTimestamp uint64

func tcpEventCb(event tcpEvent) {
	timestamp := uint64(event.Timestamp)
	cpu := event.Cpu
	typ := C.GoString(&event.Type[0])
	pid := event.Pid & 0xffffffff

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(event.SAddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(event.DAddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := event.SPort
	dport := event.DPort
	netns := event.NetNS

	fmt.Printf("%v cpu#%d %s %v %v:%v %v:%v %v\n", timestamp, cpu, typ, pid, sIP, sport, dIP, dport, netns)

	if lastTimestamp > timestamp {
		fmt.Printf("WARNING: late event!\n")
		os.Exit(1)
	}

	lastTimestamp = timestamp
}

func main() {
	b := bpf.NewBpfPerfEvent("kernel/trace_output_kern.o")

	err := b.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ready.\n")

	channel := make(chan []byte)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event tcpEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), byteOrder, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			tcpEventCb(event)
		}
	}()

	b.PollStart("tcp_event", channel)
	<-sig
	b.PollStop("tcp_event")
}
