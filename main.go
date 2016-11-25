package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"unsafe"
)

/*
#cgo CFLAGS: -Wall -Wno-unused-variable
#cgo LDFLAGS: -lelf

#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <errno.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include "perf_utils.h"

extern void tcpEventCb();

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

var (
	pmuFD C.int
)

/*
type tcpEvent struct {
	pid   uint32
	sIP   net.IP
	dIP   net.IP
	sPort uint16
	dPort uint16
	netns uint32
	comm  [16]byte
}
*/

//export tcpEventCb
func tcpEventCb(data unsafe.Pointer, size int) {
	tcpEvent := (*C.struct_tcp_event_t)(data)

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

func perfEventMmap(fd int) error {
	pageSize := os.Getpagesize()
	mmapSize := pageSize * (C.PAGE_COUNT + 1)

	base, err := syscall.Mmap(fd, 0, mmapSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap error: %v", err)
	}

	C.header = (*C.struct_perf_event_mmap_page)(unsafe.Pointer(&base[0]))

	return nil
}

func perfEventPoll(fd int) error {
	var pfd C.struct_pollfd

	pfd.fd = C.int(fd)
	pfd.events = C.POLLIN

	_, err := C.poll(&pfd, 1, 20)
	if err != nil {
		return fmt.Errorf("error polling: %v", err.(syscall.Errno))
	}

	return nil
}

func testBpfPerfEvent() {
	var attr C.struct_perf_event_attr

	attr.sample_type = C.PERF_SAMPLE_RAW
	attr._type = C.PERF_TYPE_SOFTWARE
	attr.config = C.PERF_COUNT_SW_BPF_OUTPUT

	key := 0

	pmuFD = C.perf_event_open(&attr, -1 /* pid */, 0 /* cpu */, -1 /* group_fd */, 0)

	ret := C.bpf_update_elem(C.map_fd[0], unsafe.Pointer(&key), unsafe.Pointer(&pmuFD), C.BPF_ANY)
	if ret != 0 {
		log.Fatal("bpf_update_elem error: %d", syscall.Errno(ret))
	}

	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(pmuFD), C.PERF_EVENT_IOC_ENABLE, 0)
	if err != 0 {
		log.Fatal("error enabling perf event: %v", err)
	}
}

func main() {
	fmt.Println("Ready.\n")

	bpfObjectFile := C.CString("kernel/trace_output_kern.o")
	defer C.free(unsafe.Pointer(bpfObjectFile))

	ret := C.load_bpf_file(bpfObjectFile)
	if ret != 0 {
		fmt.Fprintf(os.Stderr, "load_bpf_file error: %v\n", syscall.Errno(ret))
		os.Exit(1)
	}

	testBpfPerfEvent()

	if err := perfEventMmap(int(pmuFD)); err != nil {
		fmt.Fprintf(os.Stderr, "perfEventMmap error: %v\n", ret)
		os.Exit(1)
	}

	for {
		perfEventPoll(int(pmuFD))
		C.perf_event_read((*[0]byte)(C.tcpEventCb))
	}
}
