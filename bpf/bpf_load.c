#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <ctype.h>
#include "libbpf.h"
#include "bpf_helpers.h"

#define DEBUGFS "/sys/kernel/debug/tracing/"

static bool processed_sec[128];
int map_fd[32];
int prog_fd[32];
int event_fd[32];
int prog_cnt;
int prog_array_fd = -1;

int load_and_attach(const char *event, struct bpf_insn *prog, int size, const char *license, int kern_version)
{
	bool is_kprobe = strncmp(event, "kprobe/", 7) == 0;
	bool is_kretprobe = strncmp(event, "kretprobe/", 10) == 0;
	bool is_tracepoint = strncmp(event, "tracepoint/", 11) == 0;
	bool is_xdp = strncmp(event, "xdp", 3) == 0;
	bool is_perf_event = strncmp(event, "perf_event", 10) == 0;
	enum bpf_prog_type prog_type;
	char buf[256];
	int fd, efd, err, id;
	struct perf_event_attr attr = {};

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.sample_type = PERF_SAMPLE_RAW;
	attr.sample_period = 1;
	attr.wakeup_events = 1;

	if (is_kprobe || is_kretprobe) {
		prog_type = BPF_PROG_TYPE_KPROBE;
	} else {
		printf("Unknown event '%s'\n", event);
		return -1;
	}

	fd = bpf_prog_load(prog_type, prog, size, license, kern_version);
	if (fd < 0) {
		printf("bpf_prog_load() err=%d\n%s", errno, bpf_log_buf);
		return -1;
	}

	prog_fd[prog_cnt++] = fd;

	if (is_xdp || is_perf_event)
		return 0;

	if (is_kprobe || is_kretprobe) {
		if (is_kprobe)
			event += 7;
		else
			event += 10;

		if (*event == 0) {
			printf("event name cannot be empty\n");
			return -1;
		}

		snprintf(buf, sizeof(buf),
			 "echo '%c:%c%s %s' >> /sys/kernel/debug/tracing/kprobe_events",
			 is_kprobe ? 'p' : 'r',
			 is_kprobe ? 'p' : 'r',
			 event, event);
		err = system(buf);
		if (err < 0) {
			printf("failed to create kprobe '%s' error '%s'\n",
			       event, strerror(errno));
			return -1;
		}

		strcpy(buf, DEBUGFS);
		strcat(buf, "events/kprobes/");
		if (is_kprobe)
			strcat(buf, "p");
		else
			strcat(buf, "r");
		strcat(buf, event);
		strcat(buf, "/id");
	} else if (is_tracepoint) {
		event += 11;

		if (*event == 0) {
			printf("event name cannot be empty\n");
			return -1;
		}
		strcpy(buf, DEBUGFS);
		strcat(buf, "events/");
		strcat(buf, event);
		strcat(buf, "/id");
	}

	efd = open(buf, O_RDONLY, 0);
	if (efd < 0) {
		printf("failed to open event %s\n", event);
		return -1;
	}

	err = read(efd, buf, sizeof(buf));
	if (err < 0 || err >= sizeof(buf)) {
		printf("read from '%s' failed '%s'\n", event, strerror(errno));
		return -1;
	}

	close(efd);

	buf[err] = 0;
	id = atoi(buf);
	attr.config = id;

	efd = perf_event_open(&attr, -1/*pid*/, 0/*cpu*/, -1/*group_fd*/, 0);
	if (efd < 0) {
		printf("event %d fd %d err %s\n", id, efd, strerror(errno));
		return -1;
	}
	event_fd[prog_cnt - 1] = efd;
	ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
	ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);

	return 0;
}

void relocate_map(struct bpf_insn *insn, int fd)
{
	insn->src_reg = BPF_PSEUDO_MAP_FD;
	insn->imm = fd;
}
