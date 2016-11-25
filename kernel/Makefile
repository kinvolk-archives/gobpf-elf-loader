KERNEL_HEADERS=/lib/modules/$(shell uname -r)/build

all: trace_output_kern.o

trace_output_kern.o: trace_output_kern.c
	clang -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types \
		-O2 -emit-llvm -c $< \
		-I $(KERNEL_HEADERS)/arch/x86/include \
		-I $(KERNEL_HEADERS)/arch/x86/include/generated \
		-I $(KERNEL_HEADERS)/include \
		-I $(KERNEL_HEADERS)/include/generated/uapi \
		-o - | llc -march=bpf -filetype=obj -o $@

clean:
	/bin/rm -f trace_output_user trace_output_kern.o
