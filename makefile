# Project paths
SRC_DIR := ./src
INCLUDE_DIR := ./include
OBJ_DIR := ./obj
BPF_DIR := ./bpf

# Source files
BPF_PROG := $(BPF_DIR)/rtds.bpf.c
BPF_OBJ := $(OBJ_DIR)/rtds.bpf.o
BPF_SKEL := $(INCLUDE_DIR)/rtds.skel.h

# C_MAIN_SRC := agent.c
# C_MAIN_OBJ := $(OBJ_DIR)/agent.o
# C_MAIN_BIN := agent

AGENT_SRCS := \
  $(SRC_DIR)/agent/main.c \
  $(SRC_DIR)/agent/log.c \
  $(SRC_DIR)/agent/handlers_events.c \
  $(SRC_DIR)/agent/handlers_syscalls.c \
  $(SRC_DIR)/agent/cgroups.c 

AGENT_OBJS := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(AGENT_SRCS))
AGENT_BIN  := agent

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
all: $(AGENT_BIN)

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

# # Userspace program
# $(C_MAIN_OBJ): $(SRC_DIR)/$(C_MAIN_SRC) $(BPF_SKEL) | $(OBJ_DIR)
# 	@echo "[*] Compiling userspace program"
# 	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -c	 $< -o $@
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c $(BPF_SKEL) | $(OBJ_DIR)
	@mkdir -p $(dir $@)
	@echo "[*] Compiling userspace program"
	$(CC) $(CFLAGS) -c $< -o $@

# # Link userspace program
# $(C_MAIN_BIN): $(C_MAIN_OBJ)
# 	@echo "[*] Linking userspace program"
# 	$(CC) $^ $(LIBBPF_LDLIBS) -o $@
$(AGENT_BIN): $(AGENT_OBJS)
	@echo "[*] Linking userspace program"
	$(CC) $^ $(LIBBPF_LDLIBS) -o $@

.PHONY: clean
clean:
	@echo "[*] Cleaning up"
	rm -rf $(OBJ_DIR) $(AGENT_BIN) $(BPF_SKEL) $(INCLUDE_DIR)/vmlinux.h

# .PHONY: clean
# clean:
# 	@echo "[*] Cleaning up"
# 	rm -rf $(OBJ_DIR) $(AGENT_BIN) $(BPF_SKEL) $(VMLINUX)


# ======================================================================
#                        R S Y S L O G   S H I P P E R
# ======================================================================

HOST_IP       ?= 192.168.56.1     # host reachable from VM
LOGSTASH_CN   ?= logstash.local   # must match Logstash cert CN
LOGSTASH_PORT ?= 2514
RTDST_LOG     ?= /var/log/rtdst/events.ndjson

.PHONY: ship-install ship-reload ship-uninstall smoke

ship-install:
	@id -u | grep -q ^0$$ || { echo "Run as root: sudo make ship-install"; exit 1; }
	@if [ ! -f /tmp/logstash.crt ]; then echo "Missing /tmp/logstash.crt (scp from host: elk-siem/logstash/certs/logstash.crt)"; exit 2; fi
	apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y rsyslog rsyslog-relp
	install -o root -g root -m 0644 /tmp/logstash.crt /etc/rsyslog.d/ca.crt
	mkdir -p $$(dirname $(RTDST_LOG)); touch $(RTDST_LOG); chown syslog:adm $(RTDST_LOG); chmod 0644 $(RTDST_LOG)
	printf '%s\n' \
'module(load="imfile")' \
'module(load="omrelp")' \
'module(load="gtls")' \
'' \
'$$MaxMessageSize 64k' \
'$$EscapeControlCharactersOnReceive off' \
'template(name="jsononly" type="string" string="%msg%\n")' \
'' \
'ruleset(name="send2siem") {' \
'  queue.type="LinkedList"' \
'  queue.size="10000"' \
'  queue.dequeueBatchSize="1000"' \
'  queue.maxdiskspace="1g"' \
'  queue.filename="rtdst_relp"' \
'  queue.saveonshutdown="on"' \
'  queue.discardMark="9500"' \
'  queue.highWatermark="8000"' \
'  action(type="omrelp" target="$(HOST_IP)" port="$(LOGSTASH_PORT)" tls="on" tls.caCert="/etc/rsyslog.d/ca.crt" tls.permittedPeer="$(LOGSTASH_CN)" template="jsononly" action.resumeRetryCount="-1" action.resumeInterval="10" ratelimit.interval="0")' \
'}' \
'' \
'input(type="imfile" File="$(RTDST_LOG)" Tag="rtdst:" ruleset="send2siem" addMetadata="on" readMode="2")' \
> /etc/rsyslog.d/30-rtdst.conf
	printf '%s\n' \
'$(RTDST_LOG) {' \
'  daily' \
'  rotate 7' \
'  compress' \
'  delaycompress' \
'  missingok' \
'  notifempty' \
'  copytruncate' \
'}' > /etc/logrotate.d/rtdst
	systemctl restart rsyslog || true
	$(MAKE) smoke

ship-reload:
	sudo systemctl restart rsyslog

ship-uninstall:
	sudo rm -f /etc/rsyslog.d/30-rtdst.conf /etc/rsyslog.d/ca.crt /etc/logrotate.d/rtdst || true
	sudo systemctl restart rsyslog || true

smoke:
	@echo '{"@timestamp":"'"`date -u +%Y-%m-%dT%H:%M:%SZ`"'","host":{"hostname":"'"`hostname`"'"},"rtds":{"event_type":"PING","event_id":1}}' | sudo tee -a $(RTDST_LOG) >/dev/null
	@echo "[victim] wrote PING to $(RTDST_LOG)"