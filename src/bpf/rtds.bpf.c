#include "../../include/vmlinux.h"
#include "bpf/bpf_core_read.h"

#include "maps.bpf.h"
#include "helpers.bpf.h"


char LICENSE[] SEC("license") = "Dual BSD/GPL";


SEC("tp_btf/sched_process_fork")
int BPF_PROG(tpbtf_fork, struct task_struct *parent, struct task_struct *child)
{
    __u32 p_tgid = BPF_CORE_READ(parent, tgid);
    __u32 c_tgid = BPF_CORE_READ(child,  tgid);

    // record lineage edge
    (void)bpf_map_update_elem(&ppid_map, &c_tgid, &p_tgid, BPF_ANY);

    // inherit root
    __u32 *pr = bpf_map_lookup_elem(&root_pid_of, &p_tgid);
    __u32 root = pr ? *pr : p_tgid;
    (void)bpf_map_update_elem(&root_pid_of, &c_tgid, &root, BPF_ANY);

    return 0;
}

// Exec: DO NOT reset root. If missing (late attach / missed fork), repair via ppid_map.
SEC("tp_btf/sched_process_exec")
int BPF_PROG(tpbtf_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    __u32 tgid = BPF_CORE_READ(p, tgid);

    // if (!bpf_map_lookup_elem(&root_pid_of, &tgid)) {
    //     // We might be attaching late; try cheap repair from ppid_map chain.
    //     repair_root_via_ppid(tgid);
    // }

    // Optional: you can stash exec-specific context here if needed.
    (void)bpf_map_update_elem(&root_pid_of, &tgid, &tgid, BPF_ANY);
    return 0;
}

// Exit: cleanup both maps for this TGID (prevents PID reuse ghosts).
SEC("tp_btf/sched_process_exit")
int BPF_PROG(tpbtf_exit, struct task_struct *p, long code)
{
    __u32 tgid = BPF_CORE_READ(p, tgid);
    (void)bpf_map_delete_elem(&root_pid_of, &tgid);
    (void)bpf_map_delete_elem(&ppid_map, &tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_pidfd_open")
int enter_pidfd_open(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = get_tid();
    struct argstash_t st = {};
    st.args[0] = ctx->args[0];  // pid
    st.args[1] = ctx->args[1];  // flags
    bpf_map_update_elem(&argstash, &tid, &st, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pidfd_open")
int exit_pidfd_open(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid  = get_tid();
    __u32 tgid = get_tgid();

    struct argstash_t *st = bpf_map_lookup_elem(&argstash, &tid);
    if (!st) return 0;

    int   retfd = (int)ctx->ret;       // new pidfd on success
    __u32 pid   = (__u32)st->args[0];  // pid argument

    if (retfd >= 0 && pid > 0)
        pidfd_map_set(tgid, retfd, pid);

    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}

// =============================== dup ===============================

SEC("tracepoint/syscalls/sys_enter_dup")
int enter_dup(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = get_tid();
    struct argstash_t st = {};
    st.args[0] = ctx->args[0];  // oldfd
    bpf_map_update_elem(&argstash, &tid, &st, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_dup")
int exit_dup(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid  = get_tid();
    __u32 tgid = get_tgid();

    struct argstash_t *st = bpf_map_lookup_elem(&argstash, &tid);
    if (!st) return 0;

    int retfd = (int)ctx->ret;
    if (retfd >= 0) {
        int   oldfd = (int)st->args[0];
        bool  found = false;
        __u32 pid   = pidfd_map_get(tgid, oldfd, &found);
        if (found) pidfd_map_set(tgid, retfd, pid);
    }
    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}

// ============================== dup2 ===============================

SEC("?tracepoint/syscalls/sys_enter_dup2")
int enter_dup2(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = get_tid();
    struct argstash_t st = {};
    st.args[0] = ctx->args[0];  // oldfd
    st.args[1] = ctx->args[1];  // newfd
    bpf_map_update_elem(&argstash, &tid, &st, BPF_ANY);
    return 0;
}

SEC("?tracepoint/syscalls/sys_exit_dup2")
int exit_dup2(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid  = get_tid();
    __u32 tgid = get_tgid();

    struct argstash_t *st = bpf_map_lookup_elem(&argstash, &tid);
    if (!st) return 0;

    int ret = (int)ctx->ret;
    if (ret >= 0) {
        int oldfd = (int)st->args[0];
        int newfd = (int)st->args[1];

        // dup2 allows oldfd == newfd (no-op on success)
        if (oldfd != newfd) {
            pidfd_map_del(tgid, newfd);                // closed/overwritten
            bool  found = false;
            __u32 pid   = pidfd_map_get(tgid, oldfd, &found);
            if (found) pidfd_map_set(tgid, newfd, pid);
        }
    }
    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}

// ============================== dup3 ===============================

SEC("?tracepoint/syscalls/sys_enter_dup3")
int enter_dup3(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = get_tid();
    struct argstash_t st = {};
    st.args[0] = ctx->args[0];  // oldfd
    st.args[1] = ctx->args[1];  // newfd
    bpf_map_update_elem(&argstash, &tid, &st, BPF_ANY);
    return 0;
}

SEC("?tracepoint/syscalls/sys_exit_dup3")
int exit_dup3(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid  = get_tid();
    __u32 tgid = get_tgid();

    struct argstash_t *st = bpf_map_lookup_elem(&argstash, &tid);
    if (!st) return 0;

    int ret = (int)ctx->ret;
    if (ret >= 0) {
        int oldfd = (int)st->args[0];
        int newfd = (int)st->args[1];

        // dup3 forbids oldfd == newfd; on success they differ
        pidfd_map_del(tgid, newfd);                    // closed/overwritten
        bool  found = false;
        __u32 pid   = pidfd_map_get(tgid, oldfd, &found);
        if (found) pidfd_map_set(tgid, newfd, pid);
    }
    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}

// ============================== fcntl ==============================

SEC("tracepoint/syscalls/sys_enter_fcntl")
int enter_fcntl(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = get_tid();
    struct argstash_t st = {};
    st.args[0] = ctx->args[0];  // fd
    st.args[1] = ctx->args[1];  // cmd
    bpf_map_update_elem(&argstash, &tid, &st, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_fcntl")
int exit_fcntl(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid  = get_tid();
    __u32 tgid = get_tgid();

    struct argstash_t *st = bpf_map_lookup_elem(&argstash, &tid);
    if (!st) return 0;

    int retfd = (int)ctx->ret;
    if (retfd >= 0) {
        int fd  = (int)st->args[0];
        int cmd = (int)st->args[1];
        if (cmd == F_DUPFD || cmd == F_DUPFD_CLOEXEC) {
            bool  found = false;
            __u32 pid   = pidfd_map_get(tgid, fd, &found);
            if (found) pidfd_map_set(tgid, retfd, pid);
        }
    }
    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}

// ============================== close ==============================

SEC("tracepoint/syscalls/sys_enter_close")
int enter_close(struct trace_event_raw_sys_enter *ctx) {
    __u32 tid = get_tid();
    struct argstash_t st = {};
    st.args[0] = ctx->args[0];  // fd
    bpf_map_update_elem(&argstash, &tid, &st, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_close")
int exit_close(struct trace_event_raw_sys_exit *ctx) {
    __u32 tid  = get_tid();
    __u32 tgid = get_tgid();

    struct argstash_t *st = bpf_map_lookup_elem(&argstash, &tid);
    if (!st) return 0;

    if ((int)ctx->ret == 0) {
        int fd = (int)st->args[0];
        pidfd_map_del(tgid, fd);
    }
    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}

// =========================== pidfd_send_signal ============================

SEC("tracepoint/syscalls/sys_enter_pidfd_send_signal")
int enter_pidfd_send_signal(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tid = get_tid();
    struct argstash_t st = {};
    st.args[0] = ctx->args[0];  //pidfd
    st.args[1] = ctx->args[1];  //sig
    bpf_map_update_elem(&argstash, &tid, &st, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_pidfd_send_signal")
int exit_pidfd_send_signal(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = get_tid();
    __u32 tgid = get_tgid();

    struct argstash_t *st = bpf_map_lookup_elem(&argstash, &tid);
    if(!st) return 0;

    int ret = (int)ctx->ret;
    int pidfd = (int)st->args[0];
    int sig = (int)st->args[1];

    if(ret == 0)
    {
        bool found = false;
        __u32 pid = pidfd_map_get(tgid, pidfd, &found);
        __u32 flags = CHANNEL_DIRECT_SIGNAL | flag_from_sig(sig);
        if (found)
        {
            __u32 target_flag = flag_from_pid(pid);
            if (target_flag) flags |= target_flag;
        }
        if ((flags & (EFFECT_KILL | EFFECT_STOP | EFFECT_FREEZE | EFFECT_PROBEONLY)) != 0) {
            emit_event(EVENT_SERVICE_STOP, flags, pid, 0);
        } 
    }

    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_kill")
int enter_kill(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tid = get_tid();
    struct argstash_t st = {};
    st.args[0] = ctx->args[0];  //pid
    st.args[1] = ctx->args[1];  //sig
    bpf_map_update_elem(&argstash, &tid, &st, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_kill")
int exit_kill(struct trace_event_raw_sys_exit *ctx)
{
    __u32 tid = get_tid();
    struct argstash_t *st = bpf_map_lookup_elem(&argstash, &tid);
    if (!st) return 0;

    int ret = (int)ctx->ret;
    if(ret == 0)
    {
        int pid = (int)st->args[0];
        int sig = (int)st->args[1];

        __u32 flags = CHANNEL_DIRECT_SIGNAL | flag_from_sig(sig);

        if (flags & (EFFECT_KILL | EFFECT_STOP | EFFECT_FREEZE | EFFECT_PROBEONLY))
        {
            if (pid <= 0) emit_event(EVENT_SERVICE_STOP, (flags | EFFECT_FANOUT),0,0);  
            else{
                __u32 target_flag =  flag_from_pid(pid);
                if (target_flag) flags |= target_flag;
                emit_event(EVENT_SERVICE_STOP, flags, pid, 0);
            }
        }
    }

    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}


SEC("fexit/security_file_open")
int BPF_PROG(exit_security_file_open, struct file *file, int ret)
{
    /* Only act on successful opens */
    if (ret) return 0;

    /* Access flags are in file->f_flags, just like in your LSM hook */
    __u64 flags = BPF_CORE_READ(file, f_flags);

    /* Ignore path opens */
    if (flags & O_PATH) return 0;

    /* Check for read‑only access */
    if ((flags & O_ACCMODE) == O_RDONLY) {
        /* replicate your original logic */
        set_sysinfo_flag(file);
        mitigate_process_discovery_file(file);
    }

    /* Always record the open if needed */
    event_open_host_data(file);
    return 0;
}

// SEC("lsm/mmap_file")
// int BPF_PROG(on_mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags, unsigned long addr, unsigned long addr_only)
// {
//     if (!file) return 0;

//     bool writable = (prot & PROT_WRITE) != 0;
//     bool shared   = (flags & MAP_SHARED) != 0;
//     if (!(writable && shared)) return 0;

//     mmap_called(file);
//     return 0;
// }

SEC("fexit/security_mmap_file")
int BPF_PROG(exit_security_mmap_file,
             struct file *file,
             unsigned long prot,
             unsigned long flags,
             int ret)
{
    /* Skip failed mmaps */
    if (ret) return 0;

    /* file can be NULL for anonymous mappings */
    if (!file) return 0;

    bool writable = (prot & PROT_WRITE) != 0;
    bool shared   = (flags & MAP_SHARED) != 0;
    if (!(writable && shared)) return 0;

    mmap_called(file);
    return 0;
}

// do_fsync(struct file *file, loff_t start, loff_t end, int datasync) -> int
SEC("fexit/do_fsync")
int BPF_PROG(x_do_fsync, struct file *file, int datasync, int ret)
{
    if (ret < 0 || !file) return 0;
    event_mmap_commit(file, datasync);
    return 0;
}

// fdatasync(struct file *) may route here on some kernels:
// fexit/fdatasync or fexit/vfs_fsync_range are also viable.
// vfs_fsync_range(file, start, end, datasync) -> int
SEC("fexit/vfs_fsync_range")
int BPF_PROG (x_vfs_fsync_range, struct file *file, loff_t start, loff_t end, int datasync, int ret)
{
    if (ret < 0 || !file) return 0;
    event_mmap_commit(file, datasync);
    return 0;
}

// vfs_write(file, buf, count, pos) -> ssize_t
SEC("fexit/vfs_write")
int BPF_PROG(exit_vfs_write,
             struct file *file,
             const char *buf,
             size_t count,
             loff_t *pos,
             long ret)
{
    if (ret > 0) inpl_update_on_write(file, ret);
    return 0;
}

// vfs_writev(file, iov, vlen, pos) -> ssize_t (prototype varies by kernel)
SEC("fexit/vfs_writev")
int BPF_PROG( exit_vfs_writev, struct file *file, const struct iovec *iov, unsigned long vlen, loff_t *pos, ssize_t ret)
{
    if (ret > 0) inpl_update_on_write(file, ret);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(x_bprm_check, struct linux_binprm *bprm)
{
    struct file *f = BPF_CORE_READ(bprm, file);
    if (!f) return 0;
    // bprm_check_set_sysinfo_flag(f);
    return 0;
}