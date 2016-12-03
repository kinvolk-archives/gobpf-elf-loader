package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"unsafe"

	bpf "github.com/kinvolk/go-ebpf-kprobe-example/bpf"
)

/*
#cgo CFLAGS: -Wall -Wno-unused-variable

#include <stdlib.h>
#include <stdint.h>
//#include <sys/ioctl.h>
//#include <linux/perf_event.h>
#include <poll.h>
#include <errno.h>
//#include <linux/bpf.h>

#define TASK_COMM_LEN 16

struct tcp_event_t {
    char ev_type[12];
    uint32_t pid;
    char comm[TASK_COMM_LEN];
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint32_t netns;
};
*/
import "C"

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

//export tcpEventCb
func tcpEventCb(data []byte) {
	tcpEvent := (*C.struct_tcp_event_t)(unsafe.Pointer(&data[0]))

	typ := C.GoString(&tcpEvent.ev_type[0])
	pid := tcpEvent.pid & 0xffffffff

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	byteOrder.PutUint32(saddrbuf, uint32(tcpEvent.saddr))
	byteOrder.PutUint32(daddrbuf, uint32(tcpEvent.daddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := tcpEvent.sport
	dport := tcpEvent.dport
	netns := tcpEvent.netns

	fmt.Printf("%s %v %v:%v %v:%v %v\n", typ, pid, sIP, sport, dIP, dport, netns)
}

func main() {
	b := bpf.NewBpfPerfEvent("kernel/trace_output_kern.o")

	err := b.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Ready.\n")
	b.Poll("tcp_event", tcpEventCb)

	select {}
}
