package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

/*
#cgo CFLAGS: -Wall -Wno-unused-variable -I.
#cgo LDFLAGS: -lelf

#include <stdlib.h>
#include <stropts.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <errno.h>
#include <linux/bpf.h>
#include "libbpf.h"
#include "bpf_load.h"
#include "perf_utils.h"
*/
import "C"

var (
	pmuFD C.int
)

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

	pmuFD = C.perf_event_open(&attr, -1, 0, -1, 0)

	ret := C.bpf_update_elem(C.map_fd[0], unsafe.Pointer(&key), unsafe.Pointer(&pmuFD), C.BPF_ANY)
	if ret != 0 {
		log.Fatal("bpf_update_elem error: %d", syscall.Errno(ret))
	}

	_, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(pmuFD), C.PERF_EVENT_IOC_ENABLE, 0)
	if err != 0 {
		log.Fatal("lol error")
	}
}

func main() {
	fmt.Println("hello world")

	bpfObjectFile := C.CString("../trace_output_kern.o")
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
		C.perf_event_read((*[0]byte)(C.print_bpf_output))
	}
}
