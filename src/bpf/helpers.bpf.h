#pragma once

#include <bpf/bpf_core_read.h>

#include "../../include/vmlinux.h"

#include "maps.bpf.h"
#include "../rdts_uapi.h"
/* --- Access mode / open flags (kernel side). Keep here (BPF only). --- */
#ifndef O_RDONLY
#define O_RDONLY        00000000
#endif
#ifndef O_WRONLY
#define O_WRONLY        00000001
#endif
#ifndef O_RDWR
#define O_RDWR          00000002
#endif
#ifndef O_ACCMODE
#define O_ACCMODE       00000003
#endif
#ifndef O_CREAT
#define O_CREAT         00000100
#endif
#ifndef O_EXCL
#define O_EXCL          00000200
#endif
#ifndef O_NOCTTY
#define O_NOCTTY        00000400
#endif
#ifndef O_TRUNC
#define O_TRUNC         00001000
#endif
#ifndef O_APPEND
#define O_APPEND        00002000
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK      00004000
#endif
#ifndef O_DSYNC
#define O_DSYNC         00010000
#endif
#ifndef O_DIRECT
#define O_DIRECT        00040000
#endif
#ifndef O_LARGEFILE
#define O_LARGEFILE     00100000
#endif
#ifndef O_DIRECTORY
#define O_DIRECTORY     00200000
#endif
#ifndef O_NOFOLLOW
#define O_NOFOLLOW      00400000
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC       02000000
#endif
#ifndef O_SYNC
#define O_SYNC          04010000
#endif
#ifndef O_PATH
#define O_PATH          010000000
#endif
#ifndef O_TMPFILE
#define O_TMPFILE       020200000
#endif

/* --- mmap / permission bits (BPF uses these; agent does not need them). --- */
#ifndef PROT_EXEC
#define PROT_EXEC  0x4
#endif
#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif
#ifndef PROT_READ
#define PROT_READ  0x1
#endif

#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif
#ifndef MAP_PRIVATE
#define MAP_PRIVATE 0x02
#endif
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

#ifndef MAY_READ
#define MAY_READ  0x4
#endif
#ifndef MAY_WRITE
#define MAY_WRITE 0x2
#endif

#ifndef S_IXUSR
#define S_IXUSR  0x40
#endif
#ifndef S_IXGRP
#define S_IXGRP 0x08
#endif
#ifndef S_IXOTH
#define S_IXOTH  0x01
#endif
#ifndef S_IFMT
#define S_IFMT 0170000
#endif
#ifndef S_IFREG
#define S_IFREG  0100000
#endif
/* --- Filesystem magics used in classifiers. Keep here (BPF only). --- */
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC   0x9fa0UL
#endif
#ifndef SYSFS_MAGIC
#define SYSFS_MAGIC        0x62656572UL
#endif
/* /dev is typically devtmpfs (not tmpfs). Define if you rely on it in classifiers. */
#ifndef DEVTMPFS_MAGIC
#define DEVTMPFS_MAGIC     0x1cd1UL   /* value may differ on very old kernels */
#endif
#ifndef TMPFS_MAGIC
#define TMPFS_MAGIC        0x01021994UL
#endif
#ifndef EXT4_SUPER_MAGIC
#define EXT4_SUPER_MAGIC   0xEF53
#endif
#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC    0x58465342
#endif
#ifndef BTRFS_SUPER_MAGIC
#define BTRFS_SUPER_MAGIC  0x9123683E
#endif
#ifndef CGROUP_SUPER_MAGIC
#define CGROUP_SUPER_MAGIC     0x27e0eb
#endif
#ifndef DEVPTS_SUPER_MAGIC
#define DEVPTS_SUPER_MAGIC     0x1cd1
#endif
#ifndef DEBUGFS_MAGIC
#define DEBUGFS_MAGIC          0x64626720
#endif
#ifndef TRACEFS_MAGIC
#define TRACEFS_MAGIC          0x74726163
#endif
#ifndef SELINUX_MAGIC
#define SELINUX_MAGIC          0xf97cff8c
#endif
#ifndef SECURITYFS_MAGIC
#define SECURITYFS_MAGIC       0x73636673
#endif
#ifndef RAMFS_MAGIC
#define RAMFS_MAGIC            0x858458f6
#endif
#ifndef BPF_FS_MAGIC
#define BPF_FS_MAGIC           0xcafe4a11
#endif
#ifndef F2FS_SUPER_MAGIC
#define F2FS_SUPER_MAGIC       0xf2f52010
#endif
#ifndef EXFAT_SUPER_MAGIC
#define EXFAT_SUPER_MAGIC      0x2011BAB0
#endif
#ifndef NTFS3_SUPER_MAGIC
#define NTFS3_SUPER_MAGIC      0x5346544e
#endif
#ifndef NFS_SUPER_MAGIC
#define NFS_SUPER_MAGIC        0x6969
#endif
#ifndef CIFS_SUPER_MAGIC
#define CIFS_SUPER_MAGIC       0xff534d42
#endif
#ifndef FUSE_SUPER_MAGIC
#define FUSE_SUPER_MAGIC       0x65735546
#endif

/* --- Small utilities --- */
#ifndef LITLEN
#define LITLEN(lit) ((int)sizeof(lit)-1)
#endif

#ifdef HAVE_KFUNC_BPF_TASK_FROM_PID
extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *task) __ksym;
#endif

#ifndef INPL_MIN_WRITES_FLOOR
#define INPL_MIN_WRITES_FLOOR 8u       // floor for tiny files
#endif
#ifndef INPL_MIN_WRITES_CAP
#define INPL_MIN_WRITES_CAP   4096u    // cap for huge files
#endif
#ifndef INPL_MIN_TOTAL_BYTES
#define INPL_MIN_TOTAL_BYTES  (4ULL*1024*1024) // 4 MiB bytes floor before firing
#endif

#define LITLEN(lit) ((int)sizeof(lit)-1)

// Get current task's Thread Group ID (TGID)
static __always_inline __u32 get_tgid (void) {
    return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

// Get current task's Thread ID (TID)
static __always_inline __u32 get_tid (void) {
    return (__u32)bpf_get_current_pid_tgid();
}

// Get root pid for current process (if in container, get container root pid)
static __always_inline __u32 get_root_pid (void) {
    __u32 pid = get_tgid();
    __u32 *root_pid =  bpf_map_lookup_elem(&root_pid_of, &pid);
    if (root_pid) {
        return *root_pid;
    }
    return pid;
}

// Setter for process id
static __always_inline void fill_proc_ids(struct proc_ids *out)
{
    out->tgid = get_tgid();
    out->tid  = get_tid();
    out->root_tgid = get_root_pid();
    out->_pad = 0;
}


// static __always_inline bool is_watched_root(void){
//     __u32 root = get_root_pid();
//     __u8 *p = bpf_map_lookup_elem(&watched_roots, &root);
//     return p && *p;
// }

// static __always_inline bool is_quarantined_root(void){
//     __u32 root = get_root_pid();
//     __u8 *p = bpf_map_lookup_elem(&quarantine_roots, &root);
//     return p && *p;
// }

/* SAFE RESERVE FOR RING BUFFERS*/


static __always_inline void bump_drop(__u32 idx){
    __u64 *c = bpf_map_lookup_elem(&dropped, &idx);
    if (c) __sync_fetch_and_add(c, 1);
}

/*
We created a wrapper around bpf_ringbuf_reserve so that we can detect drops when the buffer is full
We need a macro to evaluate sizeof() which should be around 48B for events and 80B for syscalls
*/
#define RINGBUF_RESERVE_OR_DROP(rb, type, rb_index)({          \
    type *__rec = bpf_ringbuf_reserve(&rb, sizeof(type), 0);   \
    if(!__rec) bump_drop(rb_index);                            \
    __rec;                                                     \
})                                                             


/*MOUNT IDENTITY*/

/* Prefer sb->s_dev if present; else sb->s_bdev->bd_dev; else hash sb pointer. */
static __always_inline __u32 device_id_from_superblock(const struct super_block *sb)
{
#if __has_builtin(__builtin_preserve_access_index)
    if (bpf_core_field_exists(((struct super_block *)0)->s_dev)) {
        dev_t dev = BPF_CORE_READ(sb, s_dev); // the device id
        return (__u32)dev;
    }
    if (bpf_core_field_exists(((struct super_block *)0)->s_bdev) &&
        bpf_core_field_exists(((struct block_device *)0)->bd_dev)) {
        dev_t dev = BPF_CORE_READ(sb, s_bdev, bd_dev);
        return (__u32)dev;
    }
#endif
    return (__u32)((__u64)sb & 0xffffffffu);
}


static __always_inline struct file_id file_id_from_inode_sb(const struct inode *in, const struct super_block *sb)
{
    struct file_id id = {};
    if (sb) id.device_id = device_id_from_superblock(sb);
    if (in) id.inode = BPF_CORE_READ(in, i_ino);
    return id;
}

static __always_inline struct file_id file_id_from_dentry(const struct dentry *dentry)
{
    const struct inode *in = BPF_CORE_READ(dentry, d_inode);
    const struct super_block *sb = BPF_CORE_READ(dentry, d_sb);
    return file_id_from_inode_sb(in, sb);
}

static __always_inline struct file_id file_id_from_file(const struct file *file)
{
    const struct inode *in = BPF_CORE_READ(file, f_inode);
    const struct super_block *sb = BPF_CORE_READ(file, f_inode, i_sb);
    return file_id_from_inode_sb(in, sb);
}

static __always_inline struct file_id file_id_from_path(const struct path *path) {
    const struct dentry *dentry = BPF_CORE_READ(path, dentry);
    const struct super_block *sb = BPF_CORE_READ(path, mnt, mnt_sb);
    const struct inode *in = dentry ? BPF_CORE_READ(dentry, d_inode) : NULL;
    return file_id_from_inode_sb(in, sb);
}


/* 
Checks if the first slen bits of s are the same as lit
*/
static __always_inline bool str_start_with(const char *s, int slen, const char* lit)
{
    int lit_len = LITLEN(lit);
    if (slen < lit_len) return false;
    return __builtin_memcmp(s, lit, lit_len) == 0;
}

/*
Checks if the last slen bits of s are the same as lit
*/
static __always_inline bool str_ends_with(const char *s, int slen, const char* lit)
{
    int lit_len = LITLEN(lit);
    if (slen < lit_len) return false;
    return __builtin_memcmp(s + (slen - lit_len), lit,  lit_len) == 0;
}

/*
Checks if slen is the same as lit
*/
static __always_inline bool str_equals( const char* s, int slen, const char* lit)
{
    int lit_len = LITLEN(lit);
    if (slen != lit_len) return false;
    return __builtin_memcmp(s, lit,  lit_len) == 0;
}



// // Check if a file_id is a canary
// static __always_inline bool is_canary(struct file_id *fid){
//     __u8 *val = bpf_map_lookup_elem(&canary_id, fid);
//     return val && *val;
// }

// static __always_inline bool is_under_protected_dir(struct dentry *d, struct super_block *sb)
// {
//     if (!d || !sb) return false;
//     __u32 dev = device_id_from_superblock(sb);

// #pragma unroll
//     for (int i = 0; i < 32; i++) {
//         struct inode *in = BPF_CORE_READ(d, d_inode);
//         __u64 ino = in ? BPF_CORE_READ(in, i_ino) : 0;

//         struct file_id key = {.device_id = dev, .inode = ino};
//         if (bpf_map_lookup_elem(&protected_dirs, &key))
//             return true;

//         struct dentry *parent = BPF_CORE_READ(d, d_parent);
//         if (!parent || parent == d) break;
//         d = parent;
//     }
//     return false;
// }

/* EMITS*/

static __always_inline void emit_event(__u8 type, __u32 flags,  __u32 a0, __u32 a1)
{
    struct event_t *e = RINGBUF_RESERVE_OR_DROP(events, struct event_t, DROP_BUFFER_EVENT);
    if (!e) return;

    e->ts_ns = bpf_ktime_get_ns();
    fill_proc_ids(&e->p);
    e->type = type;
    e->event_flags = flags;
    e->_pad8 = 0;
    e->arg0 = a0;
    e->arg1 = a1;

    bpf_ringbuf_submit(e, 0);
}

// static __always_inline void emit_syscalls( __s32 nr, __s32 ret, __s32 fd, __u32 flags, __u64 len)
// {
//     if (!is_watched_root()) return;

//     struct syscall_t *s = RINGBUF_RESERVE_OR_DROP(syscalls, struct syscall_t, DROP_BUFFER_SYSCALL);
//     if(!s) return;

//     s->ts_ns = bpf_ktime_get_ns();
//     fill_proc_ids(&s->p);
//     s->nr = nr;
//     s->ret = ret;
//     s->fd = fd;
//     s->flags = flags;
//     s->len = len;


//     struct task_struct *task = (struct task_struct *)bpf_get_current_task();
//     const char *task_comm = BPF_CORE_READ(task, comm);
//     bpf_core_read_str(&s->comm, sizeof(s->comm), task_comm);
    
//     bpf_ringbuf_submit(s, 0);

// }

// /* LSM GUARDS*/

// static __always_inline int lsm_guard_destructive_dentry(struct dentry *d, __u8 event_type, __u8 event_aux)
// {
//     if(!d) return 0;

//     if (is_quarantined_root())
//     {
//         emit_event_dentry((__u8)EVENT_QUARANTINE_DENY, (AUX_DENIED| event_aux), d, 0, 0);
//         return -1;
//     }
//     struct file_id fid = file_id_from_dentry(d);
//     if (is_canary(&fid))
//     {
//         emit_event_dentry((__u8)EVENT_CANARY_HIT, (AUX_DENIED | event_aux), d, 0, 0);
//         return -1;
//     }
//     struct dir_permissions *dv = bpf_map_lookup_elem(&protected_dirs, &fid);
//     bool under = false;
//     if (!dv)
//     {
//         struct super_block *sb = BPF_CORE_READ(d, d_sb);
//         if (sb && is_under_protected_dir(d, sb))
//         {
//             under = true;
//         }
        
//     }
//     if (dv || under)
//     {
//         __u32 root = get_root_pid();
//         if (root != dv->agent_root_pid)
//         {
//             emit_event_dentry(event_type, (AUX_PROT_DIR | AUX_DENIED | event_aux), d, 0, 0);
//             return -1;
//         }
        
//     }
//     return 0;
// }

static __always_inline const struct dentry *dentry_of(const struct file *f) {
    return BPF_CORE_READ(f, f_path.dentry);
}

static __always_inline const struct dentry *parent_of(const struct dentry *d) {
    return d ? BPF_CORE_READ(d, d_parent) : 0;
}

static __always_inline unsigned long sb_magic(const struct file *f) {
    return BPF_CORE_READ(f, f_inode, i_sb, s_magic);
}

static __always_inline bool dentry_is(const struct dentry *d, const char *lit, int n) {
    if (!d) return false;
    const struct qstr name = BPF_CORE_READ(d, d_name);
    // exact match on len then bytes; very cheap (names like "os-release", "cpuinfo", etc.)
    __u32 len = BPF_CORE_READ(&name, len);
    if (len != (__u32)n) return false;
    const char *s = BPF_CORE_READ(&name, name);
    char buf[32]; // enough for all our literals
    if (n > (int)sizeof(buf)) return false;
    bpf_core_read(buf, n, s);
    return __builtin_memcmp(buf, lit, n) == 0;
}

/* FOR PROCESS DISCOVERY
    IF THE OPEN("/proc/[pid]/status") or OPEN("/proc/[pid]/status") is grater than 100 trigger an event
*/
static __always_inline bool is_proc_pid_discovery_file(const struct file *f)
{
    /* only care about files in procfs */
    if (sb_magic(f) != PROC_SUPER_MAGIC) return false;

    const struct dentry *leaf  = dentry_of(f);
    if (!leaf) return false;

    /* match stat, statm, cmdline or status */
    if (!(dentry_is(leaf, "stat",   LITLEN("stat"))   ||
          dentry_is(leaf, "statm",  LITLEN("statm"))  ||
          dentry_is(leaf, "cmdline",LITLEN("cmdline"))||
          dentry_is(leaf, "status", LITLEN("status"))))
        return false;

    return true;
}


static __always_inline void proc_map_bump (__u32 root)
{
    struct proc_opens *count = bpf_map_lookup_elem(&proc_touch_map, &root);
    if(!count){
        struct proc_opens init = {.opens = 1, .first_tick =  bpf_ktime_get_ns()};
        bpf_map_update_elem(&proc_touch_map, &root, &init, BPF_ANY);
        return;
    } 
    __u32 opens = count->opens + 1;
     struct proc_opens update = {.opens = opens, .first_tick = count->first_tick};
     bpf_map_update_elem(&proc_touch_map, &root, &update, BPF_ANY);
    if (opens == 100)   //hard coded might need modifications
    {
        emit_event((__u8)EVENT_PROCESS_DISCOVERY, 0, 0, 0);
        return;
    }
    
}

static __always_inline void mitigate_process_discovery_file(const struct file *file)
{
    if (!file) return;
    if (!is_proc_pid_discovery_file(file)) return;

    __u32 root = get_root_pid();  // or get_tgid() if you don’t maintain lineage
    proc_map_bump(root);
}

/*

Detect System Information Discovery

*/

static __always_inline bool is_os_version_file(const struct file *f)
{
    const struct dentry *d = dentry_of(f);
    unsigned long sm = sb_magic(f);

    if (sm == PROC_SUPER_MAGIC) {
        // /proc/version
        if (dentry_is(d, "version", LITLEN("version")) &&
            dentry_is(parent_of(d), "proc", LITLEN("proc")) == false) // parent exists; not required
            return true;

        // /proc/self/auxv
        const struct dentry *p = parent_of(d);
        if (dentry_is(d, "auxv", LITLEN("auxv")) &&
            p && dentry_is(p, "self", LITLEN("self")))
            return true;

        // /proc/sys/kernel/{ostype,osrelease,version}
        const struct dentry *k = parent_of(d);
        const struct dentry *sys = k ? parent_of(k) : 0;
        if (k && sys &&
            dentry_is(k, "kernel", LITLEN("kernel")) &&
            dentry_is(sys, "sys", LITLEN("sys")) &&
            ( dentry_is(d, "ostype",    LITLEN("ostype"))
           || dentry_is(d, "osrelease", LITLEN("osrelease"))
           || dentry_is(d, "version",   LITLEN("version"))))
            return true;
    } else {
        // /etc/os-release or /usr/lib/os-release
        const struct dentry *p1 = parent_of(d);
        const struct dentry *p2 = p1 ? parent_of(p1) : 0;
        if (dentry_is(d, "os-release", LITLEN("os-release")) &&
            ((p1 && dentry_is(p1, "etc", LITLEN("etc")))
          || (p1 && p2 && dentry_is(p1, "lib", LITLEN("lib")) && dentry_is(p2, "usr", LITLEN("usr")))))
            return true;
    }
    return false;
}

static __always_inline bool is_user_enum_file(const struct file *f)
{
    const struct dentry *d = dentry_of(f);
    unsigned long sm = sb_magic(f);

    if (sm == PROC_SUPER_MAGIC) {
        const struct dentry *k = parent_of(d);
        const struct dentry *sys = k ? parent_of(k) : 0;
        if (k && sys &&
            dentry_is(k, "kernel", LITLEN("kernel")) &&
            dentry_is(sys, "sys", LITLEN("sys")) &&
            ( dentry_is(d, "hostname",   LITLEN("hostname"))
           || dentry_is(d, "domainname", LITLEN("domainname"))))
            return true;
    } else {
        const struct dentry *p1 = parent_of(d);
        const struct dentry *p2 = p1 ? parent_of(p1) : 0;

        if (p1 && dentry_is(p1, "etc", LITLEN("etc")) &&
            ( dentry_is(d, "hostname", LITLEN("hostname"))
           || dentry_is(d, "passwd",   LITLEN("passwd"))
           || dentry_is(d, "group",    LITLEN("group"))))
            return true;

        if (p2 && dentry_is(p2, "var", LITLEN("var")) &&
            ((dentry_is(p1, "run", LITLEN("run")) && dentry_is(d, "utmp", LITLEN("utmp"))) ||
             (dentry_is(p1, "log", LITLEN("log")) && dentry_is(d, "wtmp", LITLEN("wtmp")))))
            return true;
    }
    return false;
}

static __always_inline bool is_vm_probe_file(const struct file *f)
{
    const struct dentry *d = dentry_of(f);
    unsigned long sm = sb_magic(f);

    if (sm == SYSFS_MAGIC) {
        const struct dentry *id = parent_of(d);
        const struct dentry *dmi = id ? parent_of(id) : 0;
        const struct dentry *classd = dmi ? parent_of(dmi) : 0;

        if (id && dmi && classd &&
            dentry_is(id, "id", LITLEN("id")) &&
            dentry_is(dmi, "dmi", LITLEN("dmi")) &&
            dentry_is(classd, "class", LITLEN("class")) &&
            ( dentry_is(d, "sys_vendor",   LITLEN("sys_vendor"))
           || dentry_is(d, "bios_vendor",  LITLEN("bios_vendor"))
           || dentry_is(d, "product_name", LITLEN("product_name"))
           || dentry_is(d, "board_vendor", LITLEN("board_vendor"))))
            return true;

        // /sys/hypervisor/*  (prefix check via parent name)
        const struct dentry *p = parent_of(d);
        if (p && dentry_is(p, "hypervisor", LITLEN("hypervisor")))
            return true;
    }

    if (sm == PROC_SUPER_MAGIC) {
        const struct dentry *p = parent_of(d);
        if (p && ( dentry_is(p, "xen",  LITLEN("xen"))
               || dentry_is(p, "scsi", LITLEN("scsi"))))
            return true;
    }
    return false;
}

static __always_inline bool is_hw_enum_file(const struct file *f)
{
    const struct dentry *d = dentry_of(f);
    unsigned long sm = sb_magic(f);

    if (sm == PROC_SUPER_MAGIC) {
        if (dentry_is(d, "cpuinfo", LITLEN("cpuinfo")) ||
            dentry_is(d, "meminfo", LITLEN("meminfo")))
            return true;
    }

    if (sm == SYSFS_MAGIC) {
        const struct dentry *p1 = parent_of(d);
        const struct dentry *p2 = p1 ? parent_of(p1) : 0;
        const struct dentry *p3 = p2 ? parent_of(p2) : 0;

        // /sys/devices/system/cpu/*
        if (p3 &&
            dentry_is(p2, "system",  LITLEN("system")) &&
            dentry_is(p1, "cpu",     LITLEN("cpu")) &&
            dentry_is(p3, "devices", LITLEN("devices")))
            return true;

        // /sys/firmware/dmi/tables/*
        if (p2 &&
            dentry_is(p2, "dmi",      LITLEN("dmi")) &&
            dentry_is(p1, "tables",   LITLEN("tables")) &&
            dentry_is(parent_of(p2), "firmware", LITLEN("firmware")))
            return true;
    }
    return false;
}

static __always_inline bool is_disk_enum_file(const struct file *f)
{
    const struct dentry *d = dentry_of(f);
    unsigned long sm = sb_magic(f);

    if (sm == PROC_SUPER_MAGIC) {
        if (dentry_is(d, "partitions", LITLEN("partitions")) ||
            dentry_is(d, "mounts",     LITLEN("mounts")))
            return true;
    }

    // /etc/fstab on normal FS
    if (dentry_is(d, "fstab", LITLEN("fstab")) &&
        dentry_is(parent_of(d), "etc", LITLEN("etc")))
        return true;

    if (sm == SYSFS_MAGIC) {
        const struct dentry *p = parent_of(d);
        const struct dentry *pp = p ? parent_of(p) : 0;
        if ((p && dentry_is(p,  "block", LITLEN("block"))) ||
            (pp && dentry_is(pp, "class", LITLEN("class")) && dentry_is(p, "block", LITLEN("block"))))
            return true;
    }

    // /dev/disk/by-*
    if (sm == DEVTMPFS_MAGIC) {
        const struct dentry *p1 = parent_of(d);
        const struct dentry *p2 = p1 ? parent_of(p1) : 0;
        if (p2 &&
            dentry_is(p2, "dev",  LITLEN("dev")) &&
            dentry_is(p1, "disk", LITLEN("disk")) &&
            // leaf starts with "by-": cheap 3-byte compare if len>=3
            ({ const struct qstr name = BPF_CORE_READ(d, d_name);
               __u32 len = BPF_CORE_READ(&name, len);
               const char *s = BPF_CORE_READ(&name, name);
               char b[3]; bpf_core_read(b, 3, s); len >= 3 &&
               b[0]=='b' && b[1]=='y' && b[2]=='-'; }))
            return true;
    }
    return false;
}


static __always_inline void set_sysinfo_flag(const struct file *f)
{
    __u32 root = get_root_pid();                // your lineage; or get_tgid()
    __u32 *oldp = bpf_map_lookup_elem(&sys_discovery_flags, &root);
    __u32 old = oldp ? *oldp : 0;

    __u32 bits = 0;
    if (is_os_version_file(f)) bits |= (__u32)PF_OS_VERSION;
    if (is_user_enum_file(f))  bits |= (__u32)PF_USER_ENUM;
    if (is_vm_probe_file(f))   bits |= (__u32)PF_VM_PROBE;
    if (is_hw_enum_file(f))    bits |= (__u32)PF_HW_ENUM;
    if (is_disk_enum_file(f))  bits |= (__u32)PF_DISK_ENUM;

    if (!bits) return;

    __u32 added = bits & ~old;
    if (added) {
        __u32 updated = old | bits;
        bpf_map_update_elem(&sys_discovery_flags, &root, &updated, BPF_ANY);
        emit_event((__u8)EVENT_SYSINFO_DISCOVERY, updated, added, 0);
    }
}

/*
TREATING EDGE CASE FOR SYSTEM DISCOVERY INFO:
1. WHEN THE PROCESS USES EXECVE("/BIN/SH")
2. WHEN THE PROCESS USES EXECVE("/BIN")
*/
static __always_inline bool is_regular_exec_file(const struct file *f)
{
    const struct inode *ino = BPF_CORE_READ(f, f_inode);
    umode_t mode = BPF_CORE_READ(ino, i_mode);
    bool is_reg = ((mode & S_IFMT) == S_IFREG);

    bool is_exec = (mode & (S_IXUSR | 00010 | S_IXOTH));

    return is_reg && is_exec;
}

static __always_inline bool is_bin_or_sbin_parent(const struct dentry *d)
{
    const struct dentry *p1 = parent_of(d);
    const struct dentry *p2 = p1 ? parent_of(p1) : 0;
    return (p1 && (dentry_is(p1,"bin",3) || dentry_is(p1,"sbin",4) || dentry_is(p1,"busybox",7))) ||
           (p2 && (dentry_is(p2,"bin",3) || dentry_is(p2,"sbin",4) ));
}

static __always_inline bool is_discovery_tool_execfile(const struct file *f)
{
    if (!is_regular_exec_file(f)) return false;

    const struct dentry *d = dentry_of(f);
    if (!is_bin_or_sbin_parent(d)) return false;

    // Keep this list tight and low-noise; expand as needed
    if (dentry_is(d,"uname",5)     ||
        dentry_is(d,"hostname",8)  ||
        dentry_is(d,"lsb_release",11) || dentry_is(d,"lsb-release",11) ||
        dentry_is(d,"dmidecode",9) ||
        dentry_is(d,"lscpu",5)     ||
        dentry_is(d,"lsblk",5)     ||
        dentry_is(d,"df",2))
        return true;

    // BusyBox via *symlink* (/bin/uname -> /bin/busybox) still shows d_name == "uname": caught above.
    // If they exec busybox directly, we won't match here.
    return false;
}

static __always_inline void bprm_check_set_sysinfo_flag(const struct file *f)
{
    if (!is_discovery_tool_execfile(f)) return;

    __u32 root = get_root_pid();
    __u32 old = 0, *oldp = bpf_map_lookup_elem(&sys_discovery_flags, &root);
    if (oldp) old = *oldp;

    __u32 add = (PF_TOOL_EXEC);
    __u32 updated = old | add;
    if ((add & ~old) != 0) {
        bpf_map_update_elem(&sys_discovery_flags, &root, &updated, BPF_ANY);
        emit_event((__u8)EVENT_SYSINFO_DISCOVERY, updated, add, 0);
    }
}



/*
    Reads the pointer value from the syscall argument at arg_index, copies a user string from that pointer into dst up to len
    and on success return the length of dst. Else 0
    We mainly use it on openat/rename (paths), on connect (AF_UNIX) (sun_path) or to snapshot argv[i] for execve
*/
static __always_inline int stash_path_args(const struct argstash_t *st, int arg_idx, char *dst, int len)
{
    __u64 raw = st->args[arg_idx];
    const char *up = (const char *)(unsigned long)raw;

    if (!up) {
        if (len) dst[0] = 0;
        return 0;
    }

    int n = bpf_probe_read_user_str(dst, len, up);
    if (n < 0) {
        if (len) dst[0] = 0;
        return 0;
    }
    return n;
}

// SERVICE STOP T1489


/* comm_len is always 16 when you read via bpf_get_current_comm() or bpf_core_read_str() into a 16-byte buffer */
static __always_inline __u32 classify_target_by_comm(const char comm[16]) {
    /* Logging / audit */
    if (str_equals(comm, 20, "systemd-journald")) return TARGET_LOGGING_AUDIT;
    if (str_equals(comm, 20, "rsyslogd"))         return TARGET_LOGGING_AUDIT;
    if (str_equals(comm, 20, "auditd"))           return TARGET_LOGGING_AUDIT;

    /* Container runtimes */
    if (str_equals(comm, 20, "dockerd"))          return TARGET_CONTAINER_RT;
    if (str_equals(comm, 20, "containerd"))       return TARGET_CONTAINER_RT;
    if (str_equals(comm, 20, "crio"))             return TARGET_CONTAINER_RT;   // aka cri-o
    if (str_equals(comm, 20, "kubelet"))          return TARGET_CONTAINER_RT;

    /* Hypervisor / VM mgmt / guests */
    if (str_start_with(comm, 20, "qemu-system-")) return TARGET_VMM_HYPERVISOR;
    if (str_equals(comm, 16, "libvirtd"))         return TARGET_VMM_HYPERVISOR;
    if (str_start_with(comm, 16, "vmx-"))         return TARGET_VMM_HYPERVISOR; // ESXi vmx-*
    if (str_equals(comm, 16, "hostd"))            return TARGET_VMM_HYPERVISOR; // ESXi mgmt
    if (str_equals(comm, 16, "vpxa"))             return TARGET_VMM_HYPERVISOR; // ESXi vCenter agent

    /* Databases */
    if (str_equals(comm, 16, "mysqld"))           return TARGET_DATABASE;
    if (str_equals(comm, 16, "postgres"))         return TARGET_DATABASE;       // postgres (master)
    if (str_equals(comm, 16, "mongod"))           return TARGET_DATABASE;
    if (str_start_with(comm, 16, "redis-"))       return TARGET_DATABASE;       // redis-server often “redis-…”
    if (str_equals(comm, 16, "redis-server"))     return TARGET_DATABASE;

    /* Security/EDR placeholder (your agent) */
    if (str_equals(comm, 16, "rtds-agent"))       return TARGET_SECURITY_AGENT;

    return TARGET_OTHER_CRITICAL;
}


/* Safe memcpy of a user C-string into fixed buffer; returns length (0 if fail). */
static __always_inline int read_user_str( char *dst, int dstsize, const char *uptr) {
    if (!uptr || !dst || dstsize <= 0) return 0;
    int n = bpf_probe_read_user_str(dst, dstsize, uptr);
    if (n < 0) return 0;
    if (n > dstsize) n = dstsize;
    return n - 1; // exclude trailing '\0'
}


// static __always_inline void service_stop_connect(const struct sockaddr *us)
// {
//      // Only AF_UNIX (local) sockets
//     __u16 family = 0;
//     bpf_probe_read_user(&family, sizeof(family), &us->sa_family);
//     if (family != AF_UNIX) return;

//     // Read sun_path
//     struct sockaddr_un sun = {};
//     bpf_probe_read_user(&sun, sizeof(sun), us);

//     // sun_path is not guaranteed NUL-terminated; bound it
//     char path[sizeof(sun.sun_path)+1] = {0};
//     __builtin_memcpy(path, sun.sun_path, sizeof(sun.sun_path));

//     int plen = 0;
//     // Find first NUL manually with bounded scan (no loops allowed → rely on strnlen-style helpers if you have one)
//     // Here we assume kernel added trailing NUL; otherwise direct compare still OK because we compare full literal length.
//     // Look for "/run/systemd/private"
//     if (startswith_lit(path, 108, "/run/systemd/private") ||
//         str_equals(path, 108, "/run/systemd/private")) {
//         __u32 bits = CH(CHANNEL_DBUS_PID1) | EFF(EFFECT_STOP);
//         emit_service_stop(bits, 0, (char[16]){"dbus"}, (char[16]){0});
//     }
// }


//1. DIRECT SYSCALLS

/*
We first must resolve the pidfd map in order to corectly get the process that is killed.
For this we must treat the dup/dup2/pidfd_open/dup3/close/fcntl syscalls
*/
static __always_inline void pidfd_map_set(__u32 tgid, int fd, __u32 pid) {
    if (fd < 0 || pid == 0) return;
    struct tgid_fd key = { .tgid = tgid, .fd = fd };
    bpf_map_update_elem(&pidfd_map, &key, &pid, BPF_ANY);
}
static __always_inline void pidfd_map_del(__u32 tgid, int fd) {
    if (fd < 0) return;
    struct tgid_fd key = { .tgid = tgid, .fd = fd };
    bpf_map_delete_elem(&pidfd_map, &key);
}
static __always_inline __u32 pidfd_map_get(__u32 tgid, int fd, bool *found) {
    struct tgid_fd key = { .tgid = tgid, .fd = fd };
    __u32 *pid = bpf_map_lookup_elem(&pidfd_map, &key);
    if (found) *found = (pid != 0);
    return pid ? *pid : 0;
}

/*
For pidfd_send_signal and everything that has a signal we need to resolve what is the effect of that signal.
We do this with a helper function
*/
static __always_inline __u32 flag_from_sig(int sig)
{
    // if(sig == 0) return EFFECT_PROBEONLY;
    if(sig == SIGKILL) return EFFECT_KILL;
    if(sig == SIGSTOP) return EFFECT_FREEZE;
    if(sig == SIGTERM) return EFFECT_STOP;
    return 0;
}


static __always_inline __u32 flag_from_pid(__u32 pid)
{
#ifdef HAVE_KFUNC_BPF_TASK_FROM_PID
    if (!pid) return 0;
    struct task_struct *task = bpf_task_from_pid((s32)pid);
    if (!task) return 0;

    char comm[16];
    bpf_core_read_str(comm, sizeof(comm), &task->comm);
    bpf_task_release(task);
    return classify_target_by_comm(comm);
#else
    (void)pid;
    return 0;
#endif
}

/*

DATA ENCRYPTED FOR IMPACT T1486

*/


/*
EVENT_OPEN_HOST_DATA 
*/
static __always_inline bool is_pseudofs_magic(__u64 m)
{
    if(m == PROC_SUPER_MAGIC) return true;
    if(m == SYSFS_MAGIC) return true;
    if(m == TMPFS_MAGIC) return true;
    if(m == BPF_FS_MAGIC) return true;
    if(m == CGROUP_SUPER_MAGIC) return true;
    if(m == DEVPTS_SUPER_MAGIC) return true;
    if(m == DEBUGFS_MAGIC) return true;
    if(m == TRACEFS_MAGIC) return true;
    if(m == SELINUX_MAGIC) return true;
    if(m == SECURITYFS_MAGIC) return true;
    if(m == RAMFS_MAGIC) return true;
    return false;
}

static __always_inline bool is_user_data_fs_magic(__u64 m)
{
    if(m == EXT4_SUPER_MAGIC) return true;
    if(m == XFS_SUPER_MAGIC) return true;
    if(m == BTRFS_SUPER_MAGIC) return true;
    if(m == F2FS_SUPER_MAGIC) return true;
    if(m == EXFAT_SUPER_MAGIC) return true;
    if(m == NTFS3_SUPER_MAGIC) return true;
    if(m == NFS_SUPER_MAGIC) return true;
    if(m == CIFS_SUPER_MAGIC) return true;
    if(m == FUSE_SUPER_MAGIC) return true;
    return false;
}

static __always_inline bool path_has_allowed_prefix(const char *p, int len)
{
    if (len >= 5 && str_start_with(p, len, "/home") == 0) return true;
    if (len >= 4 && str_start_with(p, len, "/mnt") == 0)  return true;
    if (len >= 6 && str_start_with(p, len, "/media") == 0)  return true;
    if (len >= 4 && str_start_with(p, len, "/srv") == 0)  return true;
    return false;
}

static __always_inline __u64 get_dir_inode(const struct file *file)
{
    const struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
    const struct dentry *p = BPF_CORE_READ(d, d_parent);
    return BPF_CORE_READ(p, d_inode, i_ino);
}


static __always_inline bool is_regular_file_mode(umode_t mode)
{
    return (mode & 0170000) == 0100000;
}

static __always_inline bool is_host_data_tree(const struct file *file)
{
    umode_t mode = BPF_CORE_READ(file, f_inode, i_mode);
    if (!is_regular_file_mode(mode)) return false;

    __u64 magic = BPF_CORE_READ(file, f_inode, i_sb, s_magic);
    if(is_pseudofs_magic(magic)) return false;
    if(!is_user_data_fs_magic(magic)) return false;
    char path[256];
    int n = bpf_d_path((struct path*)&file->f_path, path, sizeof(path));
    if(n<0) return false;
    int eff_len = 0;
    //bpf_d_path return a string that is NUL-terminated if fully written so for safety we cap at the buffer size -1
    if(n >= (int)sizeof(path)) eff_len = (int)sizeof(path) -1;
    else eff_len = n;

    if(!path_has_allowed_prefix(path, eff_len)) return false;
    return true;
}

static __always_inline void event_open_host_data(const struct file *file)
{
    if (!is_host_data_tree(file)) return;
    __u32 root = get_root_pid();
    __u64 dir_ino = get_dir_inode(file);
    struct file_id fid = file_id_from_file(file);

    struct root_file_id_key ik = {.root = root, .id = fid};
    struct dir_seen_key dk = {.root = root, .dir = dir_ino};
    __u8 dummy = 1;

    bool is_new_inode = false;
    bool is_new_dir = false;


    if (!bpf_map_lookup_elem(&inodes_seen, &ik)) {
        bpf_map_update_elem(&inodes_seen, &ik, &dummy, BPF_ANY);
        is_new_inode = true;
    }
    
    if (!bpf_map_lookup_elem(&dirs_seen, &dk)) {
        bpf_map_update_elem(&dirs_seen, &dk, &dummy, BPF_ANY);
        is_new_dir = true;
    }

    struct opens_window *opens_window = bpf_map_lookup_elem(&opens_window_map, &root);
    if (!opens_window)
    {
        struct opens_window op = {};
        bpf_map_update_elem(&opens_window_map, &root, &op, BPF_ANY);
        opens_window = bpf_map_lookup_elem(&opens_window_map, &root);
        if (!opens_window) return;
    }

    __sync_fetch_and_add(&opens_window->opens, 1);
    if (is_new_inode) __sync_fetch_and_add(&opens_window->distinct_inodes, 1);
    if (is_new_dir)   __sync_fetch_and_add(&opens_window->distinct_dirs, 1);

    if(opens_window->distinct_inodes >= 200 && opens_window->distinct_dirs >= 50)
    {
        emit_event((__u8)EVENT_OPEN_HOST_DATA, 0, 0, 0); // to add flags and arguments
        // we need to implement so we don't trigger the event every time it exceeds the treshlod
    }
}

/*

DETECTING MASS WRITES


*/

static __always_inline void mmap_called(const struct file *file)
{
    __u32 root = get_root_pid();
    struct file_id fid = file_id_from_file(file);
    struct root_file_id_key ik = {.root = root, .id = fid};
    __u64 now = bpf_ktime_get_ns();

    struct mmap_mark_val *v = bpf_map_lookup_elem(&mmap_marks, &ik);
    if (!v) {
        struct mmap_mark_val init = {
            .first_ns = now,
            .maps = 1,
            .fired = 0,
        };
        bpf_map_update_elem(&mmap_marks, &ik, &init, BPF_ANY);
    } else {
        __sync_fetch_and_add(&v->maps, 1);  // atomic increment
    }
}


static __always_inline void event_mmap_commit(const struct file *file, int datasync)
{
    __u32 root = get_root_pid();
    struct file_id fid = file_id_from_file(file);
    struct root_file_id_key ik = {.root = root, .id = fid};
    struct mmap_mark_val *v = bpf_map_lookup_elem(&mmap_marks, &ik);
    if (!v) return;

    if (!v->fired) {
        v->fired = 1;
        emit_event((__u8)EVENT_MMAP_COMMIT, v->maps, (unsigned int)datasync, 0);
    }
}

// For write encryption
static __always_inline int size_bin(__u64 n)
{
    if (n == 0) return 0;
    if (n <=   512) return 0;
    if (n <=  1024) return 1;
    if (n <=  2048) return 2;
    if (n <=  4096) return 3;
    if (n <=  8192) return 4;
    if (n <= 16384) return 5;
    if (n <= 32768) return 6;
    if (n <= 65536) return 7;
    if (n <= 131072) return 8;
    if (n <= 262144) return 9;
    if (n <= 524288) return 10;
    return 11; // > 512 KiB, includes 1 MiB blocks (very common for ransomware)
}

static __always_inline __u64 bin_width_bytes(int bin)
{
    switch (bin) {
    case 0:  return 512ULL;
    case 1:  return 1024ULL;
    case 2:  return 2048ULL;
    case 3:  return 4096ULL;
    case 4:  return 8192ULL;
    case 5:  return 16384ULL;
    case 6:  return 32768ULL;
    case 7:  return 65536ULL;
    case 8:  return 131072ULL;
    case 9:  return 262144ULL;
    case 10: return 524288ULL;
    case 11: return 1048576ULL; // treat “>512KiB” as ~1MiB
    default: return 4096ULL;
    }
}

static __always_inline void inpl_update_on_write(const struct file *file, ssize_t ret_bytes)
{
    if (ret_bytes <= 0 || !file) return;

    __u32 root = get_root_pid();
    struct file_id fid = file_id_from_file(file);
    struct root_file_id_key ik = {.root = root, .id = fid};

    struct inpl_stats *st = bpf_map_lookup_elem(&inpl_map, &ik);
    if (!st) {
        struct inpl_stats init = {};
        init.total_bytes  = (unsigned long)ret_bytes;
        init.total_writes = 1;
        int b0 = size_bin((__u64)ret_bytes);
        if (b0 >= 0 && b0 < INPL_NBINS) init.bins[b0] = 1;
        init.fired = 0;
        bpf_map_update_elem(&inpl_map, &ik, &init, BPF_ANY);
        return;
    }

    // Update (benign races acceptable for heuristics)
    st->total_bytes  += (unsigned long)ret_bytes;
    st->total_writes += 1;
    {
        int b = size_bin((__u64)ret_bytes);
        if (b >= 0 && b < INPL_NBINS) st->bins[b] += 1;
    }

    if (st->fired) return;

    // Bytes floor: avoid firing on trivial I/O
    if (st->total_bytes < INPL_MIN_TOTAL_BYTES) return;

    // Find dominant bin and count
    __u32 maxc = 0;
    __u32 dom_idx = 0;
#pragma unroll
    for (int i = 0; i < INPL_NBINS; i++) {
        __u32 c = st->bins[i];
        if (c > maxc) { maxc = c; dom_idx = (__u32)i; }
    }

    // Adaptive minimum writes: ceil(i_size / bin_width)
    __u64 isize = BPF_CORE_READ(file, f_inode, i_size);
    __u64 bw    = bin_width_bytes((int)dom_idx);
    __u64 min_required64 = bw ? (isize + bw - 1) / bw : 0;
    __u32 min_required = 0;
    if(min_required64 > INPL_MIN_WRITES_CAP)
    {
       min_required =  INPL_MIN_WRITES_CAP;
    }else
    {
        if(min_required64 < INPL_MIN_WRITES_FLOOR)  min_required = INPL_MIN_WRITES_FLOOR;
        else min_required = (__u32)min_required64;
    }

    __u32 N = st->total_writes;
    if (N < min_required) return;

    // Dominance: maxc / N > 0.5  <=>  2*maxc > N
    if ((maxc << 1) > N) {
        st->fired = 1;
        emit_event((__u8)EVENT_ENCRYPT_INPLACE_DOMBIN,
                   N, maxc, (dom_idx << 16) | INPL_NBINS);
    }
}


