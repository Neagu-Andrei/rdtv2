#pragma once

#if defined(__TARGET_ARCH_x86)  || defined(__TARGET_ARCH_x86_64) || \
    defined(__TARGET_ARCH_arm64) || defined(__TARGET_ARCH_arm)    || \
    defined(__TARGET_ARCH_riscv) || defined(__BPF__)              || \
    defined(__BPF_TRACING__)
    /* BPF-side: assume vmlinux.h is included by the .bpf.c TU before this header.
       Do not add typedefs or include linux/types.h. */
#else
  /* Userspace: bring in kernel-style typedefs if available, else stdint. */
  #if __has_include(<linux/types.h>)
    #include <linux/types.h>   /* defines __u8/__u16/__u32/__u64/__s64 */
  #else
    #include <stdint.h>
    typedef uint8_t  __u8;
    typedef uint16_t __u16;
    typedef uint32_t __u32;
    typedef uint64_t __u64;
    typedef int64_t  __s64;
  #endif
#endif

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 128
#define MAX_NUMBER_OF_ROOT_PIDS 16000
#define MAX_CANARY_INODES 2048


#define F_DUPFD            0
#define F_DUPFD_CLOEXEC  1030
#define SIGKILL 9
#define SIGTERM 15
#define SIGSTOP 19

#define AF_UNIX 1   /* aka AF_LOCAL */
#define INPL_NBINS 12  


/*
We do need a Map for the configs for each event that has
INPL_MIN_WRITES_CAP
#define INPL_NBINS 12  
if(opens_window->distinct_inodes >= 200 && opens_window->distinct_dirs >= 50)

#ifndef INPL_MIN_WRITES_FLOOR
#define INPL_MIN_WRITES_FLOOR 8u       // floor for tiny files
#endif
#ifndef INPL_MIN_WRITES_CAP
#define INPL_MIN_WRITES_CAP   4096u    // cap for huge files
#endif
#ifndef INPL_MIN_TOTAL_BYTES
#define INPL_MIN_TOTAL_BYTES  (4ULL*1024*1024) // 4 MiB bytes floor before firing
#endif
*/

enum event_type {
    // EVENT_EXEC = 30,
    // EVENT_BPF_OP = 31,
    // EVENT_MAP_OP = 32,
    // EVENT_RNG_OPEN = 33,
    // // Guardrails
    // EVENT_CANARY_HIT = 200,
    // EVENT_QUARANTINE_SET = 201,
    // EVENT_QUARANTINE_DENY = 202,
    //
    EVENT_SYSINFO_DISCOVERY = 100,
    EVENT_PROCESS_DISCOVERY = 101,
    EVENT_SERVICE_STOP = 102,
    EVENT_OPEN_HOST_DATA = 103,
    EVENT_MASS_WRITE = 104,
    EVENT_DATA_FOR_IMPACT = 105,
    EVENT_CGROUP_MOVE = 108,
    EVENT_ESCALATE_ROOT = 109,
}; 

enum cgroup_move{
    FLAG_MOVED_TO_WHITELISTED_CGROUP = (1u << 0),
    FLAG_FIRST_TIME_MOVED_TO_CGROUP = (1u << 1),
};

enum pattern_flag_system_discovery{
    // FLAGS FOR PROCESS DISCOVERY
    PF_OS_VERSION = (1u << 0),
    PF_USER_ENUM = (1u << 1),
    PF_VM_PROBE = (1u << 2),
    PF_HW_ENUM = (1u << 3),
    PF_DISK_ENUM = (1u << 4),
    PF_TOOL_EXEC = (1u << 5),
};

enum service_stop_channel{
    CHANNEL_DIRECT_SIGNAL   = (1u << 1), // kill/tgkill to PID/PGID/TID
    CHANNEL_EXEC_SERVICE    = (1u << 2), // systemctl/service/initctl/rc-service/sv/supervisorctl
    CHANNEL_ORCHESTRATOR    = (1u << 3), // docker/podman/ctr/crictl (daemon will signal)
    CHANNEL_HYPERVISOR      = (1u << 4), // esxcli/vim-cmd/virsh/qm (mgmt plane will signal)
    CHANNEL_DBUS_PID1       = (1u << 5), // connect/send to /run/systemd/private
    CHANNEL_CGROUP_CONTROL  = (1u << 6), // writes to cgroup.freeze (v2) / freezer.state (v1)
};

enum service_stop_effect {
  EFFECT_STOP      = (1u << 7),  // graceful stop (TERM/restart job)
  EFFECT_KILL      = (1u << 8),  // force kill (KILL or destroy)
  EFFECT_DISABLE   = (1u << 9),  // disable unit (won’t start at boot)
  EFFECT_MASK      = (1u << 10),  // mask unit (bind to /dev/null)
  EFFECT_RESTART   = (1u << 11),  // restart (often part of stop/start playbooks)
  EFFECT_RELOAD    = (1u << 12),  // reload (sometimes used to disrupt logging)
  EFFECT_FREEZE    = (1u << 13),  // cgroup freezer engaged
  EFFECT_PROBEONLY = (1u << 14),  // pkill -0 / systemctl is-active (no stop yet)
  EFFECT_FANOUT    = (1u << 15),  // group/regex fanout (many PIDs, e.g., -pgid or pkill pattern)
};

enum service_stop_target {
  TARGET_LOGGING_AUDIT   = (1u << 16), // rsyslogd, journald, auditd
  TARGET_CONTAINER_RT    = (1u << 17), // dockerd, containerd, crio, kubelet
  TARGET_VMM_HYPERVISOR  = (1u << 18), // qemu-system-*, libvirtd, vmx-*, vmware-hostd, vpxa, hostd
  TARGET_DATABASE        = (1u << 19), // mysqld, postgres, mongod, redis, etc.
  TARGET_BACKUP_AGENT    = (1u << 20), // veeam*, rsnapshot, restic, bacula, etc.
  TARGET_SECURITY_AGENT  = (1u << 21), // your agent/edr/av
  TARGET_NETWORKING      = (1u << 22), // networkd, NetworkManager (optional)
  TARGET_OTHER_CRITICAL  = (1u << 23), // fallback for hand-curated list
};


enum drop_index{
    DROP_BUFFER_EVENT  = 0,
    DROP_BUFFER_SYSCALL = 1,   
};

struct proc_ids {
    __u32 root_tgid;  /* lineage root (from root_pid_of map) */
    __u32 tgid;       /* process (thread-group) id */
    __u32 tid;        /* thread id */
    __u64 cgroup_id;  /* cgroup id */
    __u32 _pad;       /* explicit pad -> struct size 16B, 8B-aligned embedding */
};

struct file_id{
    __u32 device_id;
    __u64 inode;
};

struct pattern {
    __u32 writes;
    __u32 fsyncs;
    __u32 renames;
    __u32 unlinks;
    __u32 distinct_files;   /* approximate via small LRU below */
    __u32 flags;            /* recon bits: rng_used, esxi_probe, etc. */
    __u64 last_tick_ns;
};

/*  ---- Uniform event record (48 bytes on most ABIs) ---- */
struct event_t {
    __u64 ts_ns;           /* monotonic timestamp from bpf_ktime_get_ns() */

    struct proc_ids p;      /* root, tgid, pid */

    __u8 _pad8;             //padding
    __u8  type;             /* evt_type */
    __u32  event_flags;     /* flags based on the events */

    /* Small op-specific integers (don’t bloat the record) */
    __u64 arg0;            /* e.g., bytes (write), flags (renameat2), prot (mmap/mprotect), bpf cmd */
    __u64 arg1;            /* e.g., fd (write), dir-hash, msync/sfr flags, etc. */
};

struct syscall_t {
    __u64 ts_ns;
    __u64 duration_ns;

    struct proc_ids p;  /* nested process identity */

    __u32 sys_nr;          /* syscall number (or tp id) */
    __s64 ret;            /* from sys_exit; 0 on enter if used there */
    __u16 path0_len;
    __u16 path1_len;

    __u8  arg_count;      // number of arguments
    __u64 a0;
    __u64 a1;
    __u64 a2;
    __u64 a3;
    char  path0[MAX_PATH_LEN];
    char  path1[MAX_PATH_LEN];


    char comm[TASK_COMM_LEN];        /* short task name */

};

struct pid_fd { __u32 pid; __s32 fd; };

struct proc_opens { __u32 opens; __u64 first_tick; };

struct argstash_t {
    __u64 enter_ts_ns;
    __u16 sys_nr;
    __u16 path0_len;
    __u16 path1_len;
    __u16 _pad16;
    __u64 args[6];
    char  path0[MAX_PATH_LEN];
    char  path1[MAX_PATH_LEN];
};

struct argstash_raw {
    __u64 enter_ts_ns;
    __u16 sys_nr;
    __u16 path0_len;
    __u16 path1_len;
    __u16 _pad16;
    __u64 args[6];
    char  path0[MAX_PATH_LEN];
    char  path1[MAX_PATH_LEN];
};

// TO RESOLVE pidfd_send_signal syscall
struct tgid_fd { __u32 tgid; __s32 fd; };

// Mass writes and all heuristic
struct root_file_id_key {
    __u32 root;
    struct file_id id;
};
struct dir_seen_key { __u32 root; __u64 dir; };
// FOR CHECKING IF THE PROCESS OPENED MANY FILES FROM DIFFERENTE DIRECTORIES IN A GIVEN TIME FRAME
struct opens_window{
    __u64 window_ms;
    __u32 opens;
    __u32 distinct_inodes;
    __u32 distinct_dirs;
};

struct write_stats {
    __u64 first_ns;
    __u64 last_ns;
    __u64 window_start_ns;
    __u64 window_bytes;
    __u32 window_calls;

    __u64 total_bytes;
    __u64 total_calls;
    __u32 distinct_files;
};

// A struct for write on files with a minimal histogram
struct inpl_stats {
    __u64 total_bytes;
    __u32 total_writes;

    __u32 bins[INPL_NBINS];  // histogram
    __u8  fired;             // emit-once latch
};


// A root state in case we need to escalade to raw syscalls
enum rt_escalation_state {
    RT_NOT_ESCALATED = 0,
    RT_ESCALATED     = 1,
};

enum suspicious_events {
    BIT_SYSINFO_DISCOVERY           = (1u << 0),
    BIT_PROCESS_DISCOVERY           = (1u << 1),
    BIT_SERVICE_STOP                = (1u << 2),
    BIT_OPEN_HOST_DATA              = (1u << 3),
    BIT_MOVED_TO_WHITELISTED_CGROUP = (1u << 4),
};

struct root_state{
    __u8 escalated; //if the process escalated or not
    __u8 cat_bits;  //events that triggered escalation
    __u16 _pad;     //padding for consistency
    __u64 first_event_ns;   //first time seen event
    __u64 last_event_ns;    //last time seen event
};


