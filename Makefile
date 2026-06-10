CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= cc
ARCH    := $(shell uname -m)

# Debian/Ubuntu keep <asm/*.h> in a multiarch directory.
BPF_CFLAGS := -O2 -g -target bpf -Wall -Werror -Ibpf -I/usr/include/$(ARCH)-linux-gnu
CFLAGS     ?= -O2 -g
CFLAGS     += -Wall -Wextra -Werror -std=gnu11 -Ibpf -Isrc -Ibuild
LDLIBS     := -lbpf

.PHONY: all test clean

all: build/xdp_lb.skel.h

build/xdp_lb.bpf.o: bpf/xdp_lb.bpf.c bpf/lb_common.h
	@mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

build/xdp_lb.skel.h: build/xdp_lb.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build/test_lb: tests/test_lb.c src/maglev.c src/balancer.c src/*.h bpf/lb_common.h
	@mkdir -p build
	$(CC) $(CFLAGS) tests/test_lb.c src/maglev.c src/balancer.c -o $@

test: build/test_lb
	./build/test_lb

clean:
	rm -rf build
