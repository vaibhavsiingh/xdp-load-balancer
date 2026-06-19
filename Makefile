CLANG   ?= clang
BPFTOOL ?= bpftool
CC      ?= cc
ARCH    := $(shell uname -m)

# Debian/Ubuntu keep <asm/*.h> in a multiarch directory.
BPF_CFLAGS := -O2 -g -target bpf -Wall -Werror -Ibpf -I/usr/include/$(ARCH)-linux-gnu
CFLAGS     ?= -O2 -g
CFLAGS     += -Wall -Wextra -Werror -std=gnu11 -Ibpf -Isrc -Ibuild
LDLIBS     := -lbpf

SRCS := src/lbctl.c src/maglev.c src/balancer.c

.PHONY: all test clean

all: build/lbctl

build/xdp_lb.bpf.o: bpf/xdp_lb.bpf.c bpf/lb_common.h
	@mkdir -p build
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# The BPF object is embedded in the skeleton, so lbctl is a single binary.
build/xdp_lb.skel.h: build/xdp_lb.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

build/lbctl: $(SRCS) src/*.h bpf/lb_common.h build/xdp_lb.skel.h
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDLIBS)

build/test_lb: tests/test_lb.c src/maglev.c src/balancer.c src/*.h bpf/lb_common.h
	@mkdir -p build
	$(CC) $(CFLAGS) tests/test_lb.c src/maglev.c src/balancer.c -o $@

test: build/test_lb
	./build/test_lb

# build/demo may hold root-owned files from scripts/demo.sh
clean:
	find build -mindepth 1 -maxdepth 1 ! -name demo -exec rm -rf {} +
