FROM fedora:24

RUN dnf install -y llvm clang kernel-devel make golang

RUN mkdir -p /src /go/src/github.com/kinvolk/
RUN ln -s /src /go/src/github.com/kinvolk/gobpf-elf-loader
ENV GOPATH=/go

WORKDIR /src

