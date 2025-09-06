#pragma once


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
    // //File Operations
    // EVENT_OPEN = 1,
    // EVENT_RENAME = 2,
    // EVENT_UNLINK = 3,
    // EVENT_LINK = 4,
    // EVENT_TRUNC = 5,
    // // IO
    // EVENT_WRITE = 10,
    // EVENT_FSYNC = 11,
    // EVENT_FDATASYNC = 12,
    // EVENT_MSYNC = 13,
    // EVENT_SYNC_FILE_RANGE = 14,
    // // Memory Map
    // EVENT_MMAP = 20,
    // EVENT_MPROTECT = 21,
    // //
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
    EVENT_ENCRYPT_INPLACE_DOMBIN = 107,
}; 


/* ---- Small aux flags to explain "why this mattered" ---- */
// enum evt_aux_bits{
//     AUX_DENIED       = 1u << 0,  /* we returned -EPERM in LSM */
//     AUX_OVERWRITE    = 1u << 1,  /* rename/link replaced existing */
//     AUX_EXCHANGE     = 1u << 2,  /* renameat2 RENAME_EXCHANGE */
//     AUX_NOREPLACE    = 1u << 3,  /* renameat2 RENAME_NOREPLACE */
//     AUX_TMPFILE      = 1u << 4,  /* open with O_TMPFILE */
//     AUX_TRUNCATE     = 1u << 5,  /* O_TRUNC or ATTR_SIZE set */
//     AUX_PROT_DIR     = 1u << 6,  /* op hit a protected directory */
// };

// enum pattern_flags{
//     PF_NONE                = 0,

//     /* Crypto / preparation */
//     PF_RNG_USED            = (1u << 0),  /* /dev/urandom or getrandom() */
//     PF_OPENSSL_LIKE_LOAD   = (1u << 1),  /* e.g., loads of reads from /proc/sys/ * /random or libcrypto files (optional) */

//     /* Staging / stealthy file creation */
//     PF_TMP_USED            = (1u << 2),  /* O_TMPFILE or writes in /tmp,/var/tmp,/dev/shm */
//     PF_TMPFS_WRITE         = (1u << 3),  /* writes on tmpfs/ramfs mounts (fast staging) */

//     /* Write mechanics */
//     PF_MMAP_WRITE          = (1u << 4),  /* mmap(PROT_WRITE) + actual dirtying */
//     PF_MSYNC_USED          = (1u << 5),  /* msync/sync_file_range after mmaps */
//     PF_FALLOCATE_USED      = (1u << 6),  /* preallocate target size */
//     PF_FTRUNCATE_USED      = (1u << 7),  /* truncate to target size */

//     /* Rename/link tricks */
//     PF_RENAME_EXCHANGE     = (1u << 8),  /* renameat2(..., RENAME_EXCHANGE) */
//     PF_RENAME_NOREPLACE    = (1u << 9),  /* renameat2(..., RENAME_NOREPLACE) */
//     PF_LINK_TRICKS         = (1u << 10), /* hardlink/linkat patterns around encrypt/swap */

//     /* Volume/shape signals */
//     PF_PARALLEL_ENCRYPT    = (1u << 11), /* concurrent writes to many distinct files */
//     PF_NEW_EXTENSIONS      = (1u << 12), /* sudden creation of unknown extensions (.lock, .bert, etc.) */
//     PF_SYSCALL_FLOOD       = (1u << 13), /* high-rate syscalls causing drops/backpressure */

//     /* Reconnaissance / environment manipulation */
//     PF_PROC_ENUM           = (1u << 14), /* scanning /proc, /proc/ * /maps, procfs scraping */
//     PF_PROC_KILL_ATTEMPT   = (1u << 15), /* signals to other processes (SIGKILL/SIGTERM bursts) */
//     PF_ESXI_PROBE          = (1u << 16), /* probing for ESXi/VMware paths or services */
//     PF_NET_SHARE_TOUCH     = (1u << 17), /* SMB/NFS paths (//host/share, /mnt/nfs, cifs mounts) */

//     /* Tamper with defenses / persistence */
//     PF_BPF_OPS_ATTEMPT     = (1u << 18), /* bpf() syscalls (load/attach/map ops) by unknown lineage */
//     PF_MOUNT_TAMPER        = (1u << 19), /* remounts, bind mounts to bypass protections */
//     PF_CANARY_TOUCHED      = (1u << 20), /* interacted with a planted canary */

//     /* Reserve some headroom for future signals */
//     PF_VM_PROBE          = (1u << 21), /* probing to check for VM artifacts */
//     PF_HW_PROBE          = (1u << 22), /*hardware reads (/proc/cpuinfo, /proc/meminfo, /sys/class/dmi/id/*)*/
//     PF_HOSTNAME_CHECK    = (1u << 23), /**/
// };

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
    __u32 _pad;       /* explicit pad -> struct size 16B, 8B-aligned embedding */
};

struct file_id{
    __u32 device_id;
    __u64 inode;
};

// struct bucket{
//     __s64 count;
//     __u64 last_refill;
// };

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
    __u32 arg0;            /* e.g., bytes (write), flags (renameat2), prot (mmap/mprotect), bpf cmd */
    __u32 arg1;            /* e.g., fd (write), dir-hash, msync/sfr flags, etc. */
};

// struct syscall_t {
//     __u64 ts_ns;

//     struct proc_ids p;  /* nested process identity */

//     __s32 nr;             /* syscall number (or tp id) */
//     __s32 ret;            /* from sys_exit; 0 on enter if used there */

//     __s32 fd;             /* -1 if N/A */
//     __u32 flags;          /* OR’d flags (open/mmap/mprotect/msync/renameat2) */
//     __u64 len;            /* write/read/mmap length etc. */

//     char comm[16];        /* short task name */
// };


struct pid_fd { __u32 pid; __s32 fd; };

struct proc_opens { __u32 opens; __u64 first_tick; };

struct argstash_t {
    __u64 args[6];
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
