# Project paths
SRC_DIR := ./src
INCLUDE_DIR := ./include
OBJ_DIR := ./obj
BPF_DIR := ./bpf

# Source files
BPF_PROG := $(BPF_DIR)/rtds.bpf.c
BPF_OBJ := $(OBJ_DIR)/rtds.bpf.o
BPF_SKEL := $(INCLUDE_DIR)/rtds.skel.h

C_MAIN_SRC := agent.c
C_MAIN_OBJ := $(OBJ_DIR)/agent.o
C_MAIN_BIN := agent

# Tools

CC := clang
CXX := clang++
BPFTOOL := bpftool

# Architecture
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
	BPF_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
	BPF_ARCH := arm64
else
	$(error "Unsupported architecture: $(UNAME_M) \n Defaulting to x86")
	BPF_ARCH := x86
endif

LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LDLIBS := $(shell pkg-config --libs   libbpf 2>/dev/null)
# libbpf typically also needs z & elf:
LIBBPF_LDLIBS += -lelf -lz

# Compiler flags
CFLAGS := -O2 -g -Wall -Wextra -I$(INCLUDE_DIR)
CXXFLAGS  := -O2 -g -Wall -Wextra -std=c++20 -I$(INCLUDE_DIR)

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types
BPF_CFLAGS += -I$(INCLUDE_DIR)


.PHONY: all
all: $(C_MAIN_BIN)

# Ensure obj directory exists
$(OBJ_DIR):
	mkdir -p $@

# Ensure include directory exists
$(INCLUDE_DIR):
	mkdir -p $@

# Generate vmlinux.h if it doesn't exist
$(INCLUDE_DIR)/vmlinux.h : $(INCLUDE_DIR)
	@echo "[*] Generating vmlinux.h"
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build BPF object file
$(BPF_OBJ): $(SRC_DIR)/$(BPF_PROG) $(INCLUDE_DIR)/vmlinux.h | $(OBJ_DIR)
	@echo "[*] Building BPF object file"
	$(CC) $(BPF_CFLAGS) -c $< -o $@

# Generate BPF skeleton header
$(BPF_SKEL): $(BPF_OBJ) | $(INCLUDE_DIR)
	@echo "[*] Generating BPF skeleton header"
	$(BPFTOOL) gen skeleton $< > $@

# Userspace program
$(C_MAIN_OBJ): $(SRC_DIR)/$(C_MAIN_SRC) $(BPF_SKEL) | $(OBJ_DIR)
	@echo "[*] Compiling userspace program"
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -c	 $< -o $@

# Link userspace program
$(C_MAIN_BIN): $(C_MAIN_OBJ)
	@echo "[*] Linking userspace program"
	$(CC) $^ $(LIBBPF_LDLIBS) -o $@

.PHONY: clean
clean:
	@echo "[*] Cleaning up"
	rm -rf $(OBJ_DIR) $(C_MAIN_BIN) $(BPF_SKEL) $(INCLUDE_DIR)/vmlinux.h
