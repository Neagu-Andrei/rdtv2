#pragma once

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../rdts_uapi.h"

/* Typically 80B; fine for ringbuf */

// Ring buffer for events
// 16MB buffer size
struct {
    __uint (type, BPF_MAP_TYPE_RINGBUF);
    __uint (max_entries, 1 << 24); // 16MB  ~350k events of 48bytes
} events SEC (".maps");


// Ring buffer for syscalls
// 8MB buffer size
struct {
    __uint (type, BPF_MAP_TYPE_RINGBUF);
    __uint (max_entries, 1 << 23); // 8MB
} syscalls SEC (".maps");


// Map to store root PIDs of containers
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u32);
} root_pid_of SEC(".maps");

// Map to store dropped events count per CPU
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} dropped SEC(".maps");

// Map to store canary inodes
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, MAX_CANARY_INODES);
//     __type(key, struct file_id);
//     __type(value, __u8);

// } canary_id SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, MAX_NUMBER_OF_ROOT_PIDS);
//     __type(key, struct file_id); //exec file id
//     __type(value, __u8);    // 1 == benign

// } benign_exec SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, MAX_NUMBER_OF_ROOT_PIDS);
//     __type(key, __u32);   // root_tgid
//     __type(value, __u8);  // 1 = watched
// } watched_roots SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, MAX_NUMBER_OF_ROOT_PIDS);
//     __type(key, __u32);   // root_tgid
//     __type(value, __u8);  // 1 = quarantined
// } quarantine_roots SEC(".maps");


// struct dir_permissions { __u32 agent_root_pid; };
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, 65536);
//     __type(key, struct file_id);
//     __type(value, struct dir_permissions);  
// }protected_dirs SEC(".maps");


/*  FOR DETECTION    S*/
// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __uint(max_entries, MAX_NUMBER_OF_ROOT_PIDS);
//     __type(key, __u32);         /* root_tgid */
//     __type(value, struct bucket);
// } bucket_by_root SEC(".maps");

// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __uint(max_entries, MAX_NUMBER_OF_ROOT_PIDS);
//     __type(key, __u32);            /* root_tgid */
//     __type(value, struct pattern_t);
// } pattern_by_root SEC(".maps");

/* Small per-root LRU of recently touched file ids to estimate distinctness */
// struct {
//     __uint(type, BPF_MAP_TYPE_LRU_HASH);
//     __uint(max_entries, 65536);
//     __type(key, struct root_file_key);
//     __type(value, __u8); /* presence only */
// } recent_files SEC(".maps");

/*
not needed if you observe writes at vfs_write/fop (you already have struct file *). 
Needed if you only have tracepoint args (fd) and still want {mount,ino} per write.
*/
/* If using sys_enter_write*, map (pid,fd) → file_id (updated on open/close) */

//NOT SURE IF I NEED THIS
/* Current policy/config revision hash (single entry) */
// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, 1);
//     __type(key, __u32);
//     __type(value, __u64); /* e.g., truncated 64-bit hash */
// } policy_rev SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);         //root_pid
    __type(value, struct proc_opens);
} proc_touch_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, u32);                   /* thread id */
    __type(value, struct argstash_t);   /* __u64 argv[6] */
} argstash SEC(".maps");

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32); //root_pid
    __type(value, __u32);    //stored flags
} sys_discovery_flags SEC(".maps");

/*
    To resolve pidfd_send_signal we need to map out pidfd to pid.
    We need additional hooks on: pidfd_open, dup, dup2 (not sure since newer kernels implement dup2 from dup3), dup3, fcntl and close.
    When process = x calls pidfd_open on process y we get a pidfd = 2 (supposetly it's still an integer)
    When dup is called both the newfd and the oldfd could refrence the same pid, however these fd are accesible to x (makes sense)
    For dup3 if the newfd was already open, the kernel closes the newfd first, then makes a duplicate of oldfd.

    WHY LRU? Because we want to evict the last pidfd that are created through fcntl with F_DUPFD_CLOEXEC because those close after exec
    without calling close. That is an edge case though and we don't expect it to happen
*/
struct{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32768);
    __type(key, struct tgid_fd); // { __u32 tgid; __s32 fd;}
    __type(value, __u32);       // pid
} pidfd_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);  //root_pid
    __type(value, struct opens_window);
} opens_window_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct root_file_id_key); // { __u32 root; __u64 inode;}
    __type(value, __u8);       // dummy data
} inodes_seen SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct dir_seen_key); // { __u32 root; __u64 dir;}
    __type(value, __u8);       // dummy data
} dirs_seen SEC(".maps");


// for write encryption
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 131072);
    __type(key, struct root_file_id_key);
    __type(value, struct inpl_stats);
} inpl_map SEC(".maps");
