#!/bin/bash
set -xe

RKT_IMAGE=quay.io/alban/rkt:ebpf
docker pull ${RKT_IMAGE}
CONTAINER_ID=$(docker run -d ${RKT_IMAGE} /bin/false 2>/dev/null || true)
docker export -o rkt.tgz ${CONTAINER_ID}
mkdir -p rkt
tar xvf rkt.tgz -C rkt/

EBPF_IMAGE=kinvolk/tcptracer-bpf:iaguis-guess-offsets
docker pull ${EBPF_IMAGE}
CONTAINER_ID=$(docker run -d ${EBPF_IMAGE} /bin/false 2>/dev/null || true)
docker export -o ebpf.tgz ${CONTAINER_ID}
mkdir -p ebpf
tar xvf ebpf.tgz -C ebpf/

sudo docker build -t gobpf-elf-loader-builder -f Dockerfile.builder .
sudo docker run --rm \
	-v $PWD:/src \
	--entrypoint=/bin/bash \
	gobpf-elf-loader-builder \
	-c 'go build -o gobpf-elf-loader'
sudo chown -R $UID:$UID gobpf-elf-loader

sudo timeout --foreground --kill-after=10 5m \
	./rkt/rkt \
        run --interactive \
        --insecure-options=image,all-run \
        --dns=8.8.8.8 \
        --stage1-path=./rkt/stage1-kvm.aci \
        --volume=ebpf,kind=host,source=$PWD \
        docker://debian \
        --mount=volume=ebpf,target=/ebpf \
        --exec=/bin/sh -- -c \
        'cd /ebpf ; \
                mount -t tmpfs tmpfs /tmp ; \
                mount -t debugfs debugfs /sys/kernel/debug/ ; \
                ./gobpf-elf-loader ./ebpf/ebpf/fedora/x86_64/4.8.13-200.fc24.x86_64/ebpf.o'

