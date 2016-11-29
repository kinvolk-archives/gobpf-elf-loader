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
#cgo LDFLAGS: -lelf

#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <errno.h>
#include <linux/bpf.h>

#define TASK_COMM_LEN 16

struct tcp_event_t {
    char ev_type[12];
    __u32 pid;
    char comm[TASK_COMM_LEN];
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u32 netns;
};
*/
import "C"

//export tcpEventCb
func tcpEventCb(data []byte) {
	tcpEvent := (*C.struct_tcp_event_t)(unsafe.Pointer(&data[0]))

	typ := C.GoString(&tcpEvent.ev_type[0])
	pid := tcpEvent.pid & 0xffffffff

	saddrbuf := make([]byte, 4)
	daddrbuf := make([]byte, 4)

	binary.LittleEndian.PutUint32(saddrbuf, uint32(tcpEvent.saddr))
	binary.LittleEndian.PutUint32(daddrbuf, uint32(tcpEvent.daddr))

	sIP := net.IPv4(saddrbuf[0], saddrbuf[1], saddrbuf[2], saddrbuf[3])
	dIP := net.IPv4(daddrbuf[0], daddrbuf[1], daddrbuf[2], daddrbuf[3])

	sport := tcpEvent.sport
	dport := tcpEvent.dport
	netns := tcpEvent.netns

	fmt.Println(typ)
	fmt.Println(pid)
	fmt.Println(sIP)
	fmt.Println(dIP)
	fmt.Println(sport)
	fmt.Println(dport)
	fmt.Println(netns)
	fmt.Println()
}

func main() {
	fmt.Println("Ready.\n")

	b, err := bpf.NewBpfPerfEvent("kernel/trace_output_kern.o")
	if err != nil {
		fmt.Fprintf(os.Stderr, "perf error: %v\n", err)
		os.Exit(1)
	}

	b.Poll(tcpEventCb)

	select {}
}
