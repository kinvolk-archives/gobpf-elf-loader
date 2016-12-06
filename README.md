# gobpf-elf-loader

gobpf-elf-loader is a Golang library to load a BPF kprobes/kretprobes compiled to an ELF object file.
It has helper functions to get events from perf maps reordered in the chronological order.

It can be used with [tcptracer-bpf](https://github.com/kinvolk/tcptracer-bpf):
```
sudo ./gobpf-elf-loader $GOPATH/src/github.com/kinvolk/tcptracer-bpf/ebpf/fedora-24/x86_64/4.8.10-200.fc24/ebpf.o
```

