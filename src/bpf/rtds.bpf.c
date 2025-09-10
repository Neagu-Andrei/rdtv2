#include "vmlinux.h"
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
    // (void)bpf_map_update_elem(&ppid_map, &c_tgid, &p_tgid, BPF_ANY);

    // inherit root
    __u32 *pr = bpf_map_lookup_elem(&root_pid_of, &p_tgid);
    __u32 root = pr ? *pr : p_tgid;
    (void)bpf_map_update_elem(&root_pid_of, &c_tgid, &root, BPF_ANY);

    return 0;
}

// Exec: DO NOT reset root.
SEC("tp_btf/sched_process_exec")
int BPF_PROG(tpbtf_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
    // __u32 tgid = BPF_CORE_READ(p, tgid);

    // // Optional: you can stash exec-specific context here if needed.
    // // (void)bpf_map_update_elem(&root_pid_of, &tgid, &tgid, BPF_ANY);
    // __u32 *pr   = bpf_map_lookup_elem(&root_pid_of, &tgid);
    // __u32 root  = pr ? *pr : tgid;

    // // Re-base attribution to this image ONLY if we are not already escalated.
    // // This preserves correct image attribution (away from the parent shell)
    // // while keeping monitoring continuity once escalation happens.
    // if (!root_is_escalated(root) && root != tgid) {
    //     (void)bpf_map_update_elem(&root_pid_of, &tgid, &tgid, BPF_ANY);
    // }
    return 0;
}

// Exit: cleanup both maps for this TGID (prevents PID reuse ghosts).
SEC("tracepoint/sched/sched_process_exit")
int tp_sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
    struct proc_ids id = {};
    fill_proc_ids(&id);
    (void)bpf_map_delete_elem(&root_pid_of, &id.tgid);
    (void)bpf_map_delete_elem(&last_cgroup_by_tgid, &id.tgid);
    bpf_map_delete_elem(&argstash, &id.tid);
    bpf_map_delete_elem(&argstash_raw, &id.tid);
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
    __u32 root = get_root_pid();

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
            mark_event_and_escalate(root, EVENT_SERVICE_STOP, 0);
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
    __u32 root = get_root_pid();
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
            if (pid <= 0) 
            {
                emit_event(EVENT_SERVICE_STOP, (flags | EFFECT_FANOUT),0,0);  
                mark_event_and_escalate(root, EVENT_SERVICE_STOP, 0);
            }
            else{
                __u32 target_flag =  flag_from_pid(pid);
                if (target_flag) flags |= target_flag;
                emit_event(EVENT_SERVICE_STOP, flags, pid, 0);
                mark_event_and_escalate(root, EVENT_SERVICE_STOP, 0);
            }
        }
    }

    bpf_map_delete_elem(&argstash, &tid);
    return 0;
}


SEC("fexit/security_file_open")
int BPF_PROG(exit_security_file_open, struct file *file, int ret)
{
    detect_cgroup_move();
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

// vfs_write(file, buf, count, pos) -> ssize_t
SEC("fexit/vfs_write")
int BPF_PROG(exit_vfs_write,
             struct file *file,
             const char *buf,
             size_t count,
             loff_t *pos,
             long ret)
{
    detect_cgroup_move();
    if (ret > 0) inpl_update_on_write(file, ret);
    return 0;
}

// vfs_writev(file, iov, vlen, pos) -> ssize_t (prototype varies by kernel)
SEC("fexit/vfs_writev")
int BPF_PROG( exit_vfs_writev, struct file *file, const struct iovec *iov, unsigned long vlen, loff_t *pos, ssize_t ret)
{
    detect_cgroup_move();
    if (ret > 0) inpl_update_on_write(file, ret);
    return 0;
}

SEC("fentry/cgroup_attach_task")
int BPF_PROG(fe_cgroup_attach_task, struct task_struct *task, struct cgroup *dst)
{
    __u32 tgid   = BPF_CORE_READ(task, tgid);
    __u32 pid    = BPF_CORE_READ(task, pid);
    __u32 root_p = get_root_pid_of(tgid);
    __u64 dstid  = cgroup_to_id(dst);
    if (!tgid || !dstid) return 0; // v1 or unexpected

    __u64 prev = 0;
    __u32 flag   = 0;
    if (detect_cgroup_move_for(tgid, dstid, &prev, &flag)) {
        struct event_t *e = RINGBUF_RESERVE_OR_DROP(events, struct event_t, DROP_BUFFER_EVENT);
        if (!e) return 0;

        e->ts_ns         = bpf_ktime_get_ns();
        e->p.tid         = pid;
        e->p.tgid        = tgid;
        e->p.root_tgid   = root_p;
        e->p.cgroup_id   = dstid;
        e->type          = EVENT_CGROUP_MOVE;
        e->event_flags   = flag;
        e->_pad8         = 0;
        e->arg0          = prev;           // previous cgroup id (0 if first seen)
        e->arg1          = dstid;          // new cgroup id

        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

/*

FOR EMITING RAW SYSCALLS
*/

// ---------- openat ----------
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, 1, -1);
}
SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct trace_event_raw_sys_exit *ctx)
{
    /* If kernel doesn’t support openat2, glibc falls back to openat.
       Don’t emit the v2 attempt so we don’t get double entries. */
    if ((long)ctx->ret == -38 /* -ENOSYS */) {
        __u32 tid = get_tid();
        bpf_map_delete_elem(&argstash_raw, &tid); // or your enter stash, if used
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

// ---------- openat2 ----------
SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_enter_openat2(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, 1, -1);
}
SEC("tracepoint/syscalls/sys_exit_openat2")
int tp_exit_openat2(struct trace_event_raw_sys_exit *ctx)
{
    /* If kernel doesn’t support openat2, glibc falls back to openat.
       Don’t emit the v2 attempt so we don’t get double entries. */
    if ((long)ctx->ret == -38 /* -ENOSYS */) {
        __u32 tid = get_tid();
        bpf_map_delete_elem(&argstash_raw, &tid); // or your enter stash, if used
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

// ---------- unlinkat ----------
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_enter_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, 1, -1);
}
SEC("tracepoint/syscalls/sys_exit_unlinkat")
int tp_exit_unlinkat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

// ---------- readlinkat ----------
SEC("tracepoint/syscalls/sys_enter_readlinkat")
int tp_enter_readlinkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, 1, -1);
}
SEC("tracepoint/syscalls/sys_exit_readlinkat")
int tp_exit_readlinkat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

// ---------- renameat / renameat2 ----------
SEC("tracepoint/syscalls/sys_enter_renameat")
int tp_enter_renameat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, 1, 3);
}
SEC("tracepoint/syscalls/sys_exit_renameat")
int tp_exit_renameat(struct trace_event_raw_sys_exit *ctx)
{
    /* If kernel doesn’t support openat2, glibc falls back to openat.
       Don’t emit the v2 attempt so we don’t get double entries. */
    if ((long)ctx->ret == -38 /* -ENOSYS */) {
        __u32 tid = get_tid();
        bpf_map_delete_elem(&argstash_raw, &tid); // or your enter stash, if used
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tp_enter_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, 1, 3);
}
SEC("tracepoint/syscalls/sys_exit_renameat2")
int tp_exit_renameat2(struct trace_event_raw_sys_exit *ctx)
{
    /* If kernel doesn’t support openat2, glibc falls back to openat.
       Don’t emit the v2 attempt so we don’t get double entries. */
    if ((long)ctx->ret == -38 /* -ENOSYS */) {
        __u32 tid = get_tid();
        bpf_map_delete_elem(&argstash_raw, &tid); // or your enter stash, if used
        return 0;
    }

    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

// ---------- linkat ----------
SEC("tracepoint/syscalls/sys_enter_linkat")
int tp_enter_linkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, 1, 3);
}
SEC("tracepoint/syscalls/sys_exit_linkat")
int tp_exit_linkat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

// ---------- symlinkat ----------
SEC("tracepoint/syscalls/sys_enter_symlinkat")
int tp_enter_symlinkat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, 0, 2);
}
SEC("tracepoint/syscalls/sys_exit_symlinkat")
int tp_exit_symlinkat(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

// ---------- execve / execveat ----------
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    // read ids
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 tid  = (__u32)id;

    // fast path: only if root is escalated (keep same gating as others if you use it)
    if (!root_is_escalated(get_root_pid_of(tgid)))
        return 0;

    struct syscall_t *e = bpf_ringbuf_reserve(&syscalls, sizeof(*e), 0);
    if (!e) return 0;

    // args (safe reads)
    __u64 a0 = BPF_CORE_READ(ctx, args[0]);
    __u64 a1 = BPF_CORE_READ(ctx, args[1]);
    __u64 a2 = BPF_CORE_READ(ctx, args[2]);
    __u64 a3 = BPF_CORE_READ(ctx, args[3]);

    // snapshot path (arg0)
    char path0[MAX_PATH_LEN] = {};
    __u16 p0len = (__u16)snap_user_str((const void *)a0, path0, MAX_PATH_LEN);

    // fill event
    e->ts_ns        = bpf_ktime_get_ns();
    e->duration_ns  = 0;
    e->p.cgroup_id  = bpf_get_current_cgroup_id();
    e->p.root_tgid  = get_root_pid_of(tgid);
    e->p.tgid       = tgid;
    e->p.tid        = tid;

    e->sys_nr       = BPF_CORE_READ(ctx, id);
    e->ret          = 0;
    e->arg_count    = 4;
    e->a0 = a0; e->a1 = a1; e->a2 = a2; e->a3 = a3;

    e->path0_len = p0len;
    e->path1_len = 0;
#pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) e->path0[i] = path0[i];
#pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) e->path1[i] = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execve")
int tp_exit_execve(struct trace_event_raw_sys_exit *ctx)
{
    // No-op: we didn’t stash on enter, so nothing to emit on exit.
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 tgid = id >> 32;
    __u32 tid  = (__u32)id;

    if (!root_is_escalated(get_root_pid_of(tgid)))
        return 0;

    struct syscall_t *e = bpf_ringbuf_reserve(&syscalls, sizeof(*e), 0);
    if (!e) return 0;

    __u64 a0 = BPF_CORE_READ(ctx, args[0]); // dirfd
    __u64 a1 = BPF_CORE_READ(ctx, args[1]); // pathname
    __u64 a2 = BPF_CORE_READ(ctx, args[2]); // argv
    __u64 a3 = BPF_CORE_READ(ctx, args[3]); // envp

    // snapshot path (arg1 for execveat)
    char path0[MAX_PATH_LEN] = {};
    __u16 p0len = (__u16)snap_user_str((const void *)a1, path0, MAX_PATH_LEN);

    e->ts_ns        = bpf_ktime_get_ns();
    e->duration_ns  = 0;
    e->p.cgroup_id  = bpf_get_current_cgroup_id();
    e->p.root_tgid  = get_root_pid_of(tgid);
    e->p.tgid       = tgid;
    e->p.tid        = tid;

    e->sys_nr       = BPF_CORE_READ(ctx, id);
    e->ret          = 0;
    e->arg_count    = 4;
    e->a0 = a0; e->a1 = a1; e->a2 = a2; e->a3 = a3;

    e->path0_len = p0len;
    e->path1_len = 0;
#pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) e->path0[i] = path0[i];
#pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) e->path1[i] = 0;

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_execveat")
int tp_exit_execveat(struct trace_event_raw_sys_exit *ctx)
{
    // No-op: same reason as execve.
    return 0;
}

// ---------- write-ish (no paths) ----------
SEC("tracepoint/syscalls/sys_enter_write")
int tp_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, -1, -1);
}
SEC("tracepoint/syscalls/sys_exit_write")
int tp_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

SEC("tracepoint/syscalls/sys_enter_pwrite64")
int tp_enter_pwrite64(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, -1, -1);
}
SEC("tracepoint/syscalls/sys_exit_pwrite64")
int tp_exit_pwrite64(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}

SEC("tracepoint/syscalls/sys_enter_fsync")
int tp_enter_fsync(struct trace_event_raw_sys_enter *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_enter_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id, -1, -1);
}
SEC("tracepoint/syscalls/sys_exit_fsync")
int tp_exit_fsync(struct trace_event_raw_sys_exit *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    return do_tp_exit_common(ctx, get_root_pid_of(id >> 32), id >> 32, (__u32)id);
}