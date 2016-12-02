package bpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

/*
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <sys/socket.h>
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <poll.h>
#include <linux/perf_event.h>

#include "libbpf.h"

// from https://github.com/safchain/goebpf
// Apache License

typedef struct bpf_map {
	int         fd;
	bpf_map_def def;
} bpf_map;

static __u64 ptr_to_u64(void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static void bpf_apply_relocation(int fd, struct bpf_insn *insn)
{
	insn->src_reg = BPF_PSEUDO_MAP_FD;
	insn->imm = fd;
}

static int bpf_create_map(enum bpf_map_type map_type, int key_size,
	int value_size, int max_entries)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;

	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static bpf_map *bpf_load_map(bpf_map_def *map_def)
{
	bpf_map *map;

	map = calloc(1, sizeof(bpf_map));
	if (map == NULL)
		return NULL;

	memcpy(&map->def, map_def, sizeof(bpf_map_def));

	map->fd = bpf_create_map(map_def->type,
		map_def->key_size,
		map_def->value_size,
		map_def->max_entries
	);

	if (map->fd < 0)
		return 0;

	return map;
}

static int bpf_prog_load(enum bpf_prog_type prog_type,
	const struct bpf_insn *insns, int prog_len,
	const char *license, int kern_version,
	char *log_buf, int log_size)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.prog_type = prog_type;
	attr.insn_cnt = prog_len / sizeof(struct bpf_insn);
	attr.insns = ptr_to_u64((void *) insns);
	attr.license = ptr_to_u64((void *) license);
	attr.log_buf = ptr_to_u64(log_buf);
	attr.log_size = log_size;
	attr.log_level = 1;
	attr.kern_version = kern_version;

	return syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
}

// from samples

#define PAGE_COUNT 8

typedef void (*print_fn)(void *data, int size);

struct perf_event_sample {
	struct perf_event_header header;
	__u32 size;
	char data[];
};

static void perf_event_read(volatile struct perf_event_mmap_page *header, print_fn fn)
{
	int page_size;
	page_size = getpagesize();

	__u64 data_tail = header->data_tail;
	__u64 data_head = header->data_head;
	__u64 buffer_size = PAGE_COUNT * page_size;
	void *base, *begin, *end;
	char buf[256];

	asm volatile("" ::: "memory"); // in real code it should be smp_rmb()
	if (data_head == data_tail)
		return;

	base = ((char *)header) + page_size;

	begin = base + data_tail % buffer_size;
	end = base + data_head % buffer_size;

	while (begin != end) {
		struct perf_event_sample *e;

		e = begin;
		if (begin + e->header.size > base + buffer_size) {
			long len = base + buffer_size - begin;

			assert(len < e->header.size);
			memcpy(buf, begin, len);
			memcpy(buf + len, base, e->header.size - len);
			e = (void *) buf;
			begin = base + e->header.size - len;
		} else if (begin + e->header.size == base + buffer_size) {
			begin = base;
		} else {
			begin += e->header.size;
		}

		if (e->header.type == PERF_RECORD_SAMPLE) {
			fn(e->data, e->size);
		} else if (e->header.type == PERF_RECORD_LOST) {
			struct {
				struct perf_event_header header;
				__u64 id;
				__u64 lost;
			} *lost = (void *) e;
			printf("lost %lld events\n", lost->lost);
		} else {
			printf("unknown event type=%d size=%d\n",
			       e->header.type, e->header.size);
		}
	}

	__sync_synchronize(); // smp_mb()
	header->data_tail = data_head;
}


extern void eventCb();
*/
import "C"

type EventCb func([]byte)

var myEventCb EventCb

// BPFMap represents a eBPF map. An eBPF map has to be declared in the C file
type BPFMap struct {
	Name       string
	SectionIdx int
	Idx        int
	m          *C.bpf_map
}

// BPFKProbe represents a kprobe or kretprobe. they have to be declared in the C file
type BPFKProbe struct {
	Name string
	fd   int
}

type BPFMapIterator struct {
	key interface{}
	m   *BPFMap
}

type BPFKProbePerf struct {
	fileName string
	file     *elf.File

	log    []byte
	maps   map[string]*BPFMap
	probes map[string]*BPFKProbe

	pmuFDs  []C.int
	headers []*C.struct_perf_event_mmap_page
}

func perfEventPoll(fd int) error {
	var pfd C.struct_pollfd

	pfd.fd = C.int(fd)
	pfd.events = C.POLLIN

	_, err := C.poll(&pfd, 1, 1000)
	if err != nil {
		return fmt.Errorf("error polling: %v", err.(syscall.Errno))
	}

	return nil
}

//export eventCb
func eventCb(data unsafe.Pointer, size C.int) {
	b := C.GoBytes(data, size)

	myEventCb(b)
}

func NewBpfPerfEvent(fileName string) *BPFKProbePerf {
	return &BPFKProbePerf{
		fileName: fileName,
		maps:     make(map[string]*BPFMap),
		probes:   make(map[string]*BPFKProbe),
		log:      make([]byte, 65536),
	}
}

// from https://github.com/safchain/goebpf
// Apache License

func (b *BPFKProbePerf) readLicense() (string, error) {
	if lsec := b.file.Section("license"); lsec != nil {
		data, err := lsec.Data()
		if err != nil {
			return "", err
		}
		return string(data), nil
	}

	return "", nil
}

func (b *BPFKProbePerf) readVersion() (int, error) {
	if vsec := b.file.Section("version"); vsec != nil {
		data, err := vsec.Data()
		if err != nil {
			return 0, err
		}
		if len(data) != 4 {
			return 0, errors.New("version is not a __u32")
		}
		version := *(*C.uint32_t)(unsafe.Pointer(&data[0]))
		if err != nil {
			return 0, err
		}
		return int(version), nil
	}

	return 0, nil
}

func (b *BPFKProbePerf) readMaps() error {
	for sectionIdx, section := range b.file.Sections {
		fmt.Printf("searching maps: %d: %s\n", sectionIdx, section.Name)
		if strings.HasPrefix(section.Name, "maps/") {
			data, err := section.Data()
			if err != nil {
				return err
			}

			name := strings.TrimPrefix(section.Name, "maps/")

			mapCount := len(data) / C.sizeof_struct_bpf_map_def
			for i := 0; i < mapCount; i++ {
				pos := i * C.sizeof_struct_bpf_map_def
				cm := C.bpf_load_map((*C.bpf_map_def)(unsafe.Pointer(&data[pos])))
				if cm == nil {
					return fmt.Errorf("Error while loading map %s", section.Name)
				}

				m := &BPFMap{
					Name:       name,
					SectionIdx: sectionIdx,
					Idx:        i,
					m:          cm,
				}

				if oldMap, ok := b.maps[name]; ok {
					return fmt.Errorf("duplicate map: %q (section %q) and %q (section %q)",
						oldMap.Name, b.file.Sections[oldMap.SectionIdx].Name,
						name, section.Name)
				}
				b.maps[name] = m
			}
		}
	}

	return nil
}

func (b *BPFKProbePerf) relocate(data []byte, rdata []byte) error {
	var symbol elf.Symbol
	var offset uint64

	symbols, err := b.file.Symbols()
	if err != nil {
		return err
	}

	br := bytes.NewReader(data)

	for {
		switch b.file.Class {
		case elf.ELFCLASS64:
			var rel elf.Rel64
			err := binary.Read(br, b.file.ByteOrder, &rel)
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}

			symNo := rel.Info >> 32
			symbol = symbols[symNo-1]

			offset = rel.Off
		case elf.ELFCLASS32:
			var rel elf.Rel32
			err := binary.Read(br, b.file.ByteOrder, &rel)
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}

			symNo := rel.Info >> 8
			symbol = symbols[symNo-1]

			offset = uint64(rel.Off)
		default:
			return errors.New("Architecture not supported")
		}

		rinsn := (*C.struct_bpf_insn)(unsafe.Pointer(&rdata[offset]))
		if rinsn.code != (C.BPF_LD | C.BPF_IMM | C.BPF_DW) {
			return errors.New("Invalid relocation")
		}

		symbolSec := b.file.Sections[symbol.Section]
		if !strings.HasPrefix(symbolSec.Name, "maps/") {
			return fmt.Errorf("map location not supported: map %q is in section %q instead of \"maps/%s\"",
				symbol.Name, symbolSec.Name, symbol.Name)
		}
		name := strings.TrimPrefix(symbolSec.Name, "maps/")

		m := b.Map(name)
		if m == nil {
			return fmt.Errorf("relocation error, symbol %q not found in section %q",
				symbol.Name, symbolSec.Name)
		}

		fmt.Printf("symbol: %v\n", symbol)
		C.bpf_apply_relocation(m.m.fd, rinsn)
	}
}

func (b *BPFKProbePerf) Load() error {
	fileReader, err := os.Open(b.fileName)
	if err != nil {
		return err
	}

	b.file, err = elf.NewFile(fileReader)
	if err != nil {
		return err
	}

	license, err := b.readLicense()
	if err != nil {
		return err
	}

	lp := unsafe.Pointer(C.CString(license))
	defer C.free(lp)

	version, err := b.readVersion()
	if err != nil {
		return err
	}

	err = b.readMaps()
	if err != nil {
		return err
	}

	processed := make([]bool, len(b.file.Sections))
	for i, section := range b.file.Sections {
		if processed[i] {
			continue
		}

		data, err := section.Data()
		if err != nil {
			return err
		}

		if len(data) == 0 {
			continue
		}

		if section.Type == elf.SHT_REL {
			rsection := b.file.Sections[section.Info]

			processed[i] = true
			processed[section.Info] = true

			if strings.HasPrefix(rsection.Name, "kprobe/") || strings.HasPrefix(rsection.Name, "kretprobe/") {
				rdata, err := rsection.Data()
				if err != nil {
					return err
				}

				if len(rdata) == 0 {
					continue
				}

				err = b.relocate(data, rdata)
				if err != nil {
					return err
				}

				insns := (*C.struct_bpf_insn)(unsafe.Pointer(&rdata[0]))

				fd := C.bpf_prog_load(C.BPF_PROG_TYPE_KPROBE,
					insns, C.int(rsection.Size),
					(*C.char)(lp), C.int(version),
					(*C.char)(unsafe.Pointer(&b.log[0])), C.int(len(b.log)))
				if fd < 0 {
					return fmt.Errorf("error while loading %q:\n%s", rsection.Name, b.log)
				}
				b.probes[rsection.Name] = &BPFKProbe{
					Name: rsection.Name,
					fd:   int(fd),
				}
			}
		}
	}

	for i, section := range b.file.Sections {
		if processed[i] {
			continue
		}

		if strings.HasPrefix(section.Name, "kprobe/") || strings.HasPrefix(section.Name, "kretprobe/") {
			data, err := section.Data()
			if err != nil {
				panic(err)
			}

			if len(data) == 0 {
				continue
			}

			insns := (*C.struct_bpf_insn)(unsafe.Pointer(&data[0]))

			fd := C.bpf_prog_load(C.BPF_PROG_TYPE_KPROBE,
				insns, C.int(section.Size),
				(*C.char)(lp), C.int(version),
				(*C.char)(unsafe.Pointer(&b.log[0])), C.int(len(b.log)))
			if fd < 0 {
				return fmt.Errorf("error while loading %q:\n%s", section.Name, b.log)
			}
			b.probes[section.Name] = &BPFKProbe{
				Name: section.Name,
				fd:   int(fd),
			}
		}
	}

	return nil
}

// Map returns the BPFMap for the given name. The name is the name used for
// the map declaration with the MAP macro is the eBPF C file.
func (b *BPFKProbePerf) Map(name string) *BPFMap {
	return b.maps[name]
}

//func foo() {
//	bpfObjectFile := C.CString(fileName)
//	defer C.free(unsafe.Pointer(bpfObjectFile))
//
//	mapFds, _, _, err := loadBpfFile(fileName)
//	if err != nil {
//		return nil, err
//	}
//
//	var attr C.struct_perf_event_attr
//	var cpu C.int = 0
//	var pmuFDs []C.int
//	var headers []*C.struct_perf_event_mmap_page
//
//	attr.size = C.sizeof_struct_perf_event_attr
//	attr.config = 10 // PERF_COUNT_SW_BPF_OUTPUT
//	attr._type = C.PERF_TYPE_SOFTWARE
//	attr.sample_type = C.PERF_SAMPLE_RAW
//
//	for {
//		pmuFD := C.perf_event_open(&attr, -1 /* pid */, cpu /* cpu */, -1 /* group_fd */, C.PERF_FLAG_FD_CLOEXEC)
//		if pmuFD < 0 {
//			break
//		}
//
//		// mmap
//		pageSize := os.Getpagesize()
//		mmapSize := pageSize * (C.PAGE_COUNT + 1)
//
//		base, err := syscall.Mmap(int(pmuFD), 0, mmapSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
//		if err != nil {
//			return nil, fmt.Errorf("mmap error: %v", err)
//		}
//
//		// enable
//		_, _, err2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(pmuFD), C.PERF_EVENT_IOC_ENABLE, 0)
//		if err2 != 0 {
//			log.Fatal("error enabling perf event: %v", err2)
//		}
//
//		// assign perf fd tp map
//		ret := C.bpf_update_elem(C.int(mapFds[0]), unsafe.Pointer(&cpu), unsafe.Pointer(&pmuFD), C.BPF_ANY)
//		if ret != 0 {
//			log.Fatal("bpf_update_elem error: %d", syscall.Errno(ret))
//			break
//		}
//
//		pmuFDs = append(pmuFDs, pmuFD)
//		headers = append(headers, (*C.struct_perf_event_mmap_page)(unsafe.Pointer(&base[0])))
//
//		cpu++
//		if cpu == 4 {
//			break
//		}
//	}
//
//	return &BPFKProbePerf{
//		pmuFDs:  pmuFDs,
//		headers: headers,
//	}, nil
//}

func (b *BPFKProbePerf) Poll(cb EventCb) {
	// TODO: do something like
	// https://github.com/iovisor/gobpf/pull/2/files#diff-51d172d4e15a1a9ddb788f8eb973a93fR70
	myEventCb = cb

	for i, _ := range b.pmuFDs {
		go func(cpu int) {
			for {
				perfEventPoll(int(b.pmuFDs[cpu]))
				C.perf_event_read(b.headers[cpu], (*[0]byte)(C.eventCb))
			}
		}(i)
	}
}
