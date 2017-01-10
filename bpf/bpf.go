//+build linux

package bpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

/*
#include <sys/types.h>
#include <errno.h>
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
#include <sys/resource.h>

// from https://github.com/safchain/goebpf
// Apache License, Version 2.0

// bpf map structure used by C program to define maps and
// used by elf loader.
typedef struct bpf_map_def {
  unsigned int type;
  unsigned int key_size;
  unsigned int value_size;
  unsigned int max_entries;
} bpf_map_def;

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
	int ret;
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.map_type = map_type;
	attr.key_size = key_size;
	attr.value_size = value_size;
	attr.max_entries = max_entries;

	ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	if (ret < 0 && errno == EPERM) {
		// When EPERM is returned, two reasons are possible:
		// 1. user has no permissions for bpf()
		// 2. user has insufficent rlimit for locked memory
		// Unfortunately, there is no api to inspect the current usage of locked
		// mem for the user, so an accurate calculation of how much memory to lock
		// for this new program is difficult to calculate. As a hack, bump the limit
		// to unlimited. If program load fails again, return the error.

		struct rlimit rl = {};
		if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
			rl.rlim_max = RLIM_INFINITY;
			rl.rlim_cur = rl.rlim_max;
			if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
				ret = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
			}
			else {
				printf("setrlimit() failed with errno=%d\n", errno);
				return -1;
			}
		}
	}

	return ret;
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
	int ret;
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

	ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (ret < 0 && errno == EPERM) {
		// When EPERM is returned, two reasons are possible:
		// 1. user has no permissions for bpf()
		// 2. user has insufficent rlimit for locked memory
		// Unfortunately, there is no api to inspect the current usage of locked
		// mem for the user, so an accurate calculation of how much memory to lock
		// for this new program is difficult to calculate. As a hack, bump the limit
		// to unlimited. If program load fails again, return the error.

		struct rlimit rl = {};
		if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
			rl.rlim_max = RLIM_INFINITY;
			rl.rlim_cur = rl.rlim_max;
			if (setrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
				ret = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
			}
			else {
				printf("setrlimit() failed with errno=%d\n", errno);
				return -1;
			}
		}
	}

	return ret;
}

static int bpf_update_element(int fd, void *key, void *value, unsigned long long flags)
{
	union bpf_attr attr = {
		.map_fd = fd,
		.key = ptr_to_u64(key),
		.value = ptr_to_u64(value),
		.flags = flags,
	};

	return syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}


static int perf_event_open_map(int pid, int cpu, int group_fd, unsigned long flags)
{
	struct perf_event_attr attr = {0,};
	attr.type = PERF_TYPE_SOFTWARE;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.wakeup_events = 1;

	attr.size = sizeof(struct perf_event_attr);
	attr.config = 10; // PERF_COUNT_SW_BPF_OUTPUT

       return syscall(__NR_perf_event_open, &attr, pid, cpu,
                      group_fd, flags);
}

static int perf_event_open_tracepoint(int tracepoint_id, int pid, int cpu,
                           int group_fd, unsigned long flags)
{
	struct perf_event_attr attr = {0,};
	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;
	attr.config = tracepoint_id;

	return syscall(__NR_perf_event_open, &attr, pid, cpu,
                      group_fd, flags);
}

// from https://github.com/cilium/cilium/blob/master/pkg/bpf/perf.go
// Apache License, Version 2.0

struct event_sample {
	struct perf_event_header header;
	uint32_t size;
	uint8_t data[];
};

struct read_state {
	void *buf;
	int buf_len;
};

static int perf_event_read(int page_count, int page_size, void *_state,
		    void *_header, void *_sample_ptr, void *_lost_ptr)
{
	volatile struct perf_event_mmap_page *header = _header;
	uint64_t data_head = *((volatile uint64_t *) &header->data_head);
	uint64_t data_tail = header->data_tail;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	void *base  = ((uint8_t *)header) + page_size;
	struct read_state *state = _state;
	struct event_sample *e;
	void *begin, *end;
	void **sample_ptr = (void **) _sample_ptr;
	void **lost_ptr = (void **) _lost_ptr;

	// No data to read on this ring
	__sync_synchronize();
	if (data_head == data_tail)
		return 0;

	begin = base + data_tail % raw_size;
	e = begin;
	end = base + (data_tail + e->header.size) % raw_size;

	if (state->buf_len < e->header.size || !state->buf) {
		state->buf = realloc(state->buf, e->header.size);
		state->buf_len = e->header.size;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;

		memcpy(state->buf, begin, len);
		memcpy((char *) state->buf + len, base, e->header.size - len);

		e = state->buf;
	} else {
		memcpy(state->buf, begin, e->header.size);
	}

	switch (e->header.type) {
	case PERF_RECORD_SAMPLE:
		*sample_ptr = state->buf;
		break;
	case PERF_RECORD_LOST:
		*lost_ptr = state->buf;
		break;
	}

	__sync_synchronize();
	header->data_tail += e->header.size;

	return e->header.type;
}

static void create_bpf_update_elem(int fd, void *key, void *value,
			    unsigned long long flags, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
	ptr_bpf_attr->map_fd = fd;
	ptr_bpf_attr->key = ptr_to_u64(key);
	ptr_bpf_attr->value = ptr_to_u64(value);
	ptr_bpf_attr->flags = flags;
}

static void create_bpf_lookup_elem(int fd, void *key, void *value, void *attr)
{
	union bpf_attr* ptr_bpf_attr;
	ptr_bpf_attr = (union bpf_attr*)attr;
	ptr_bpf_attr->map_fd = fd;
	ptr_bpf_attr->key = ptr_to_u64(key);
	ptr_bpf_attr->value = ptr_to_u64(value);
}
*/
import "C"

type EventCb func([]byte)

var myEventCb EventCb

const useCurrentKernelVersion = 0xFFFFFFFE

// BPFMap represents a eBPF map. An eBPF map has to be declared in the C file
type BPFMap struct {
	Name       string
	SectionIdx int
	Idx        int
	m          *C.bpf_map

	// only for perf maps
	pmuFDs  []C.int
	headers []*C.struct_perf_event_mmap_page
}

// BPFKProbe represents a kprobe or kretprobe. they have to be declared in the C file
type BPFKProbe struct {
	Name string
	fd   int
	efd  int
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
}

func NewBpfPerfEvent(fileName string) *BPFKProbePerf {
	return &BPFKProbePerf{
		fileName: fileName,
		maps:     make(map[string]*BPFMap),
		probes:   make(map[string]*BPFKProbe),
		log:      make([]byte, 65536),
	}
}

func UpdateElementReal(fd int, key, value unsafe.Pointer, flags uint64) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_update_elem(
		C.int(fd),
		key,
		value,
		C.ulonglong(flags),
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_UPDATE_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to update element: %s", err)
	}

	return nil
}

func (b *BPFKProbePerf) UpdateElement(mp *BPFMap, key, value unsafe.Pointer) error {
	return UpdateElementReal(int(mp.m.fd), key, value, 0)
}

// LookupElementReal looks up for the map value stored in fd with the given key. The value
// is stored in the value unsafe.Pointer.
func LookupElementReal(fd int, key, value unsafe.Pointer) error {
	uba := C.union_bpf_attr{}
	C.create_bpf_lookup_elem(
		C.int(fd),
		key,
		value,
		unsafe.Pointer(&uba),
	)
	ret, _, err := syscall.Syscall(
		C.__NR_bpf,
		C.BPF_MAP_LOOKUP_ELEM,
		uintptr(unsafe.Pointer(&uba)),
		unsafe.Sizeof(uba),
	)

	if ret != 0 || err != 0 {
		return fmt.Errorf("Unable to lookup element: %s", err)
	}

	return nil
}

func (b *BPFKProbePerf) LookupElement(mp *BPFMap, key, value unsafe.Pointer) error {
	return LookupElementReal(int(mp.m.fd), key, value)
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

func utsnameStr(in []int8) string {
	out := make([]byte, len(in))

	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			break
		}
		out = append(out, byte(in[i]))
	}

	return string(out)
}

func currentVersion() (int, error) {
	var buf syscall.Utsname
	if err := syscall.Uname(&buf); err != nil {
		return -1, err
	}

	releaseStr := strings.Trim(utsnameStr(buf.Release[:]), "\x00")

	kernelVersionStr := strings.Split(releaseStr, "-")[0]

	kernelVersionParts := strings.Split(kernelVersionStr, ".")
	if len(kernelVersionParts) != 3 {
		return -1, errors.New("not enough version information")
	}

	major, err := strconv.Atoi(kernelVersionParts[0])
	if err != nil {
		return -1, err
	}

	minor, err := strconv.Atoi(kernelVersionParts[1])
	if err != nil {
		return -1, err
	}

	patch, err := strconv.Atoi(kernelVersionParts[2])
	if err != nil {
		return -1, err
	}

	out := major*256*256 + minor*256 + patch

	return out, nil
}

func (b *BPFKProbePerf) readMaps() error {
	for sectionIdx, section := range b.file.Sections {
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
			fmt.Printf("https://gist.github.com/alban/161ec3c254f05854aeb3ad90730b3fb5\n")
			return fmt.Errorf("map location not supported: map %q is in section %q instead of \"maps/%s\"",
				symbol.Name, symbolSec.Name, symbol.Name)
		}
		name := strings.TrimPrefix(symbolSec.Name, "maps/")

		m := b.Map(name)
		if m == nil {
			return fmt.Errorf("relocation error, symbol %q not found in section %q",
				symbol.Name, symbolSec.Name)
		}

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
	if version == useCurrentKernelVersion {
		version, err = currentVersion()
		if err != nil {
			return err
		}
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

			secName := rsection.Name
			isKprobe := strings.HasPrefix(secName, "kprobe/")
			isKretprobe := strings.HasPrefix(secName, "kretprobe/")

			if isKprobe || isKretprobe {
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

				progFd := C.bpf_prog_load(C.BPF_PROG_TYPE_KPROBE,
					insns, C.int(rsection.Size),
					(*C.char)(lp), C.int(version),
					(*C.char)(unsafe.Pointer(&b.log[0])), C.int(len(b.log)))
				if progFd < 0 {
					return fmt.Errorf("error while loading %q:\n%s", secName, b.log)
				}

				efd, err := b.EnableKprobe(int(progFd), secName, isKretprobe)
				if err != nil {
					return err
				}

				b.probes[secName] = &BPFKProbe{
					Name: secName,
					fd:   int(progFd),
					efd:  efd,
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

	for name, _ := range b.maps {
		var cpu C.int = 0

		for {
			pmuFD := C.perf_event_open_map(-1 /* pid */, cpu /* cpu */, -1 /* group_fd */, C.PERF_FLAG_FD_CLOEXEC)
			if pmuFD < 0 {
				if cpu == 0 {
					return fmt.Errorf("perf_event_open for map error: %v", err)
				}
				break
			}

			// mmap
			pageSize := os.Getpagesize()
			pageCount := 8
			mmapSize := pageSize * (pageCount + 1)

			base, err := syscall.Mmap(int(pmuFD), 0, mmapSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
			if err != nil {
				return fmt.Errorf("mmap error: %v", err)
			}

			// enable
			_, _, err2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(pmuFD), C.PERF_EVENT_IOC_ENABLE, 0)
			if err2 != 0 {
				return fmt.Errorf("error enabling perf event: %v", err2)
			}

			// assign perf fd tp map
			_, err = C.bpf_update_element(C.int(b.maps[name].m.fd), unsafe.Pointer(&cpu), unsafe.Pointer(&pmuFD), C.BPF_ANY)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: cannot assign perf fd to map %q: %s (cpu %d)\n", name, err, cpu)
			}

			b.maps[name].pmuFDs = append(b.maps[name].pmuFDs, pmuFD)
			b.maps[name].headers = append(b.maps[name].headers, (*C.struct_perf_event_mmap_page)(unsafe.Pointer(&base[0])))

			cpu++
		}
	}

	return nil
}

func (b *BPFKProbePerf) EnableKprobe(progFd int, secName string, isKretprobe bool) (int, error) {
	var probeType, funcName string
	if isKretprobe {
		probeType = "r"
		funcName = strings.TrimPrefix(secName, "kretprobe/")
	} else {
		probeType = "p"
		funcName = strings.TrimPrefix(secName, "kprobe/")
	}
	eventName := probeType + funcName

	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return 0, fmt.Errorf("cannot open kprobe_events: %v\n", err)
	}
	defer f.Close()

	cmd := fmt.Sprintf("%s:%s %s\n", probeType, eventName, funcName)
	_, err = f.WriteString(cmd)
	if err != nil {
		return 0, fmt.Errorf("cannot write %q to kprobe_events: %v\n", cmd, err)
	}

	kprobeIdFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", eventName)
	kprobeIdBytes, err := ioutil.ReadFile(kprobeIdFile)
	if err != nil {
		return 0, fmt.Errorf("cannot read kprobe id: %v\n", err)
	}
	kprobeId, err := strconv.Atoi(strings.TrimSpace(string(kprobeIdBytes)))
	if err != nil {
		return 0, fmt.Errorf("invalid kprobe id): %v\n", err)
	}

	efd := C.perf_event_open_tracepoint(C.int(kprobeId), -1 /* pid */, 0 /* cpu */, -1 /* group_fd */, C.PERF_FLAG_FD_CLOEXEC)
	if efd < 0 {
		return 0, fmt.Errorf("perf_event_open for kprobe error")
	}

	_, _, err2 := syscall.Syscall(syscall.SYS_IOCTL, uintptr(efd), C.PERF_EVENT_IOC_ENABLE, 0)
	if err2 != 0 {
		return 0, fmt.Errorf("error enabling perf event: %v", err2)
	}

	_, _, err2 = syscall.Syscall(syscall.SYS_IOCTL, uintptr(efd), C.PERF_EVENT_IOC_SET_BPF, uintptr(progFd))
	if err2 != 0 {
		return 0, fmt.Errorf("error enabling perf event: %v", err2)
	}
	return int(efd), nil
}

// Map returns the BPFMap for the given name. The name is the name used for
// the map declaration with the MAP macro is the eBPF C file.
func (b *BPFKProbePerf) Map(name string) *BPFMap {
	return b.maps[name]
}

func perfEventPoll(fds []C.int) error {
	var pfds []C.struct_pollfd

	for i, _ := range fds {
		var pfd C.struct_pollfd

		pfd.fd = fds[i]
		pfd.events = C.POLLIN

		pfds = append(pfds, pfd)
	}
	_, err := C.poll(&pfds[0], C.nfds_t(len(fds)), -1)
	if err != nil {
		return fmt.Errorf("error polling: %v", err.(syscall.Errno))
	}

	return nil
}

// Assume the timestamp is at the beginning of the user struct
type BytesWithTimestamp [][]byte

func (a BytesWithTimestamp) Len() int      { return len(a) }
func (a BytesWithTimestamp) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a BytesWithTimestamp) Less(i, j int) bool {
	return *(*C.uint64_t)(unsafe.Pointer(&a[i][0])) < *(*C.uint64_t)(unsafe.Pointer(&a[j][0]))
}

// Matching 'struct perf_event_header in <linux/perf_event.h>
type PerfEventHeader struct {
	Type      uint32
	Misc      uint16
	TotalSize uint16
}

// Matching 'struct perf_event_sample in kernel sources
type PerfEventSample struct {
	PerfEventHeader
	Size uint32
	data byte // Size bytes of data
}

// Matching 'struct perf_event_lost in kernel sources
type PerfEventLost struct {
	PerfEventHeader
	Id   uint64
	Lost uint64
}

// nowNanoseconds returns a time that can be compared to bpf_ktime_get_ns()
func nowNanoseconds() uint64 {
	var ts syscall.Timespec
	syscall.Syscall(syscall.SYS_CLOCK_GETTIME, 1 /* CLOCK_MONOTONIC */, uintptr(unsafe.Pointer(&ts)), 0)
	sec, nsec := ts.Unix()
	return 1000*1000*1000*uint64(sec) + uint64(nsec)
}

func (b *BPFKProbePerf) PollStart(mapName string, receiverChan chan []byte) {
	var incoming BytesWithTimestamp

	if _, ok := b.maps[mapName]; !ok {
		fmt.Fprintf(os.Stderr, "Cannot find map %q. List of found maps:\n", mapName)
		for key, _ := range b.maps {
			fmt.Fprintf(os.Stderr, "%q\n", key)
		}
		os.Exit(1)
	}

	go func() {
		cpuCount := len(b.maps[mapName].pmuFDs)
		pageSize := os.Getpagesize()
		pageCount := 8
		state := C.struct_read_state{}

		for {
			perfEventPoll(b.maps[mapName].pmuFDs)

			for {
				var harvestCount C.int
				beforeHarvest := nowNanoseconds()
				for cpu := 0; cpu < cpuCount; cpu++ {
					for {
						var sample *PerfEventSample
						var lost *PerfEventLost

						ok := C.perf_event_read(C.int(pageCount), C.int(pageSize),
							unsafe.Pointer(&state), unsafe.Pointer(b.maps[mapName].headers[cpu]),
							unsafe.Pointer(&sample), unsafe.Pointer(&lost))

						switch ok {
						case 0:
							break // nothing to read
						case C.PERF_RECORD_SAMPLE:
							size := sample.Size - 4
							b := C.GoBytes(unsafe.Pointer(&sample.data), C.int(size))
							incoming = append(incoming, b)
							harvestCount++
							if *(*uint64)(unsafe.Pointer(&b[0])) > beforeHarvest {
								break
							} else {
								continue
							}
						case C.PERF_RECORD_LOST:
							fmt.Printf("lost event on cpu %d\n", cpu)
						default:
							fmt.Printf("unknown event on cpu %d\n", cpu)
						}
						break
					}

				}

				sort.Sort(incoming)

				for i := 0; i < len(incoming); i++ {
					if *(*uint64)(unsafe.Pointer(&incoming[0][0])) > beforeHarvest {
						// This record has been sent after the beginning of the harvest. Stop
						// processing here to keep the order. "incoming" is sorted, so the next
						// elements also must not be processed now.
						break
					}
					receiverChan <- incoming[0]
					// remove first element
					incoming = incoming[1:]
				}
				if harvestCount == 0 && len(incoming) == 0 {
					break
				}
			}
		}
	}()
}

func (b *BPFKProbePerf) PollStop(mapName string) {
	// TODO
}
