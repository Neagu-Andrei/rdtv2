#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include<stdio.h> 
#include<stdlib.h> 
#include<signal.h> 
#include<errno.h> 
#include<sys/resource.h> 
#include<time.h> 
#include<unistd.h>

#include "../include/rtds.skel.h"

#include "rdts_uapi.h"

static volatile sig_atomic_t exiting = 0;

static void on_sigint(int sig) { (void)sig; exiting = 1; }

static void bump_memlock(void) {
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
    }
}

static int libbpf_print(enum libbpf_print_level level, const char *fmt, va_list args) {
    return vfprintf(stderr, fmt, args);
}

struct flag_desc {
    uint32_t bit;
    const char *name;
};

static const char *event_name(__u8 t)
{
    // Optional: map your EVENT_* ids to names
    switch (t) {
    case 100:  return "EVENT_SYSINFO_DISCOVERY";
    case 101:  return "EVENT_PROCESS_DISCOVERY";
    case 102:  return "EVENT_SERVICE_STOP";
    case 103:  return "EVENT_OPEN_HOST_DATA";
    case 104:  return "EVENT_MASS_WRITE";
    case 105:  return "EVENT_DATA_FOR_IMPACT";
    case 106:  return "EVENT_MMAP_COMMIT";
    case 107: return "EVENT_ENCRYPT_INPLACE_DOMBIN";
    case 108: return "EVENT_CGROUP_MOVE";
    default: return "EVENT";
    }
}

/* Returns a heap‑allocated string describing the flags. Caller must free. */
static char *event_flags_to_string(uint8_t type, uint32_t flags)
{
    /* Build up a comma‑separated string in a fixed buffer; if no bits are set,
       return "none".  Extend the switch as you add more event types. */
    static char buf[256];
    buf[0] = '\0';

    switch (type) {
    case EVENT_SYSINFO_DISCOVERY: {
        if (!flags) {
            snprintf(buf, sizeof buf, "none");
            break;
        }
        if (flags & PF_OS_VERSION)  strncat(buf, "OS version, ", sizeof buf - strlen(buf) - 1);
        if (flags & PF_USER_ENUM)   strncat(buf, "user enum, ", sizeof buf - strlen(buf) - 1);
        if (flags & PF_VM_PROBE)    strncat(buf, "VM probe, ", sizeof buf - strlen(buf) - 1);
        if (flags & PF_HW_ENUM)     strncat(buf, "HW enum, ", sizeof buf - strlen(buf) - 1);
        if (flags & PF_DISK_ENUM)   strncat(buf, "disk enum, ", sizeof buf - strlen(buf) - 1);
        break;
    }
    case EVENT_SERVICE_STOP: {
        if (!flags) {
            snprintf(buf, sizeof buf, "none");
            break;
        }
        /* channels */
        if (flags & CHANNEL_DIRECT_SIGNAL)  strncat(buf, "direct_signal, ", sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_EXEC_SERVICE)   strncat(buf, "exec_service, ", sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_ORCHESTRATOR)   strncat(buf, "orchestrator, ", sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_HYPERVISOR)     strncat(buf, "hypervisor, ", sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_DBUS_PID1)      strncat(buf, "dbus_pid1, ", sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_CGROUP_CONTROL) strncat(buf, "cgroup_control, ", sizeof buf - strlen(buf) - 1);
        /* effects */
        if (flags & EFFECT_STOP)      strncat(buf, "stop, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_KILL)      strncat(buf, "kill, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_DISABLE)   strncat(buf, "disable, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_MASK)      strncat(buf, "mask, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_RESTART)   strncat(buf, "restart, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_RELOAD)    strncat(buf, "reload, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_FREEZE)    strncat(buf, "freeze, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_PROBEONLY) strncat(buf, "probe_only, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_FANOUT)    strncat(buf, "fanout, ", sizeof buf - strlen(buf) - 1);
        /* targets */
        if (flags & TARGET_LOGGING_AUDIT)  strncat(buf, "logging/audit, ", sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_CONTAINER_RT)   strncat(buf, "container_rt, ", sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_VMM_HYPERVISOR) strncat(buf, "vmm/hypervisor, ", sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_DATABASE)       strncat(buf, "database, ", sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_BACKUP_AGENT)   strncat(buf, "backup, ", sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_SECURITY_AGENT) strncat(buf, "security, ", sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_NETWORKING)     strncat(buf, "networking, ", sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_OTHER_CRITICAL) strncat(buf, "other_critical, ", sizeof buf - strlen(buf) - 1);
        break;
    }
    case EVENT_CGROUP_MOVE: {
        if (!flags) {
            snprintf(buf, sizeof buf, "none");
            break;
        }
        /* channels */
        if (flags & FLAG_MOVED_TO_WHITELISTED_CGROUP)  strncat(buf, "to a whitelisted cgroup", sizeof buf - strlen(buf) - 1);
        if (flags & FLAG_FIRST_TIME_MOVED_TO_CGROUP)   strncat(buf, "first", sizeof buf - strlen(buf) - 1);
    }
    default:
        /* Unknown or unsupported event type: dump the raw value */
        snprintf(buf, sizeof buf, "0x%x", flags);
        break;
    }

    /* Remove trailing comma and space, if any */
    size_t len = strlen(buf);
    if (len >= 2 && buf[len-2] == ',' && buf[len-1] == ' ')
        buf[len-2] = '\0';
    return buf;
}

static void emit_sysinfo_discovery(const struct event_t *e)
{
    double ms = e->ts_ns / 1e6;
    /* e->event_flags: updated flags; e->arg0: newly added flags */
    printf("[%.3f ms] pid=%u tgid=%u root=%u event=%s flags=%s added=%s \n",
           ms,e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
           event_flags_to_string(e->type, e->event_flags),
           event_flags_to_string(e->type, e->arg0));
}

static void emit_process_discovery(const struct event_t *e)
{
    double ms = e->ts_ns / 1e6;
    /* No useful flags or args for this event. */
    printf("[%.3f ms] pid=%u tgid=%u root=%u event=%s flags=none\n",
           ms,e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type));
}

static void emit_service_stop(const struct event_t *e)
{
    double ms = e->ts_ns / 1e6;
    /* e->event_flags encodes channels/effects/targets; arg0 holds the PID we signalled. */
    printf("[%.3f ms] pid=%u tgid=%u root=%u event=%s flags=%s at pid %llu\n",
           ms, e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
           event_flags_to_string(e->type, e->event_flags),
           e->arg0);
}

static void emit_encrypt_inplace_dombin(const struct event_t *e)
{
    double ms = e->ts_ns / 1e6;
    /* flags = N (total writes); arg0 = maxc (writes in dominant bin);
       arg1: upper 16 bits = dom_idx, lower 16 bits = INPL_NBINS. */
    unsigned dom_idx = (e->arg1 >> 16) & 0xffffu;
    unsigned nbins   = e->arg1 & 0xffffu;
    printf("[%.3f ms] pid=%u tgid=%u root=%u event=%s flags=%u "
           "args=[writes=%u, max_bin=%llu, dom_idx=%u/%u]\n",
           ms,e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
           e->event_flags,
           e->event_flags, e->arg0, dom_idx, nbins);
}

static void emit_cgroup_change(const struct event_t *e)
{
    double ms = e->ts_ns / 1e6;
    printf("[%.3f ms] pid=%u tgid=%u root=%u event=%s context=[%s]"
           "from %llu to %llu\n",
           ms,e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),event_flags_to_string(e->type, e->event_flags), e->arg0, e->arg1);
}

static void emit_generic(const struct event_t *e)
{
    double ms = e->ts_ns / 1e6;
    printf("[%.3f ms] pid=%u tgid=%u root=%u event=%s flags=0x%x args=[%llu,%llu]\n",
           ms,e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
           e->event_flags, e->arg0, e->arg1);
}

/* Main dispatcher replaces the monolithic print in handle_event(). */
static void emit_event(const struct event_t *e)
{
    switch (e->type) {
    case EVENT_SYSINFO_DISCOVERY:
        emit_sysinfo_discovery(e);
        break;
    case EVENT_PROCESS_DISCOVERY:
        emit_process_discovery(e);
        break;
    case EVENT_SERVICE_STOP:
        emit_service_stop(e);
        break;
    case EVENT_ENCRYPT_INPLACE_DOMBIN:
        emit_encrypt_inplace_dombin(e);
        break;
    case EVENT_CGROUP_MOVE:
        emit_cgroup_change(e);
        break;
    default:
        /* Unknown or unimplemented event type */
        emit_generic(e);
        break;
    }
}

static int handle_sample(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct event_t)) {
        fprintf(stderr, "short event: %zu < %zu\n", size, sizeof(struct event_t));
        return 0;
    }
    const struct event_t *e = data;
    emit_event(e);  // dispatch to per‑type printer
    return 0;
}


int main(int argc, char **argv)
{
    (void)argc; (void)argv;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    // libbpf_set_print(libbpf_print);   // << add this

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    bump_memlock();

    struct rtds_bpf *skel = rtds_bpf__open();
    if (!skel) {
        fprintf(stderr, "failed to open skeleton\n");
        return 1;
    }

    // (Optional) Set map sizes/rodata here before load, e.g.:
    // *skel->rodata->INPL_MIN_TOTAL_BYTES = 4ULL*1024*1024;

    int err = rtds_bpf__load(skel);
    if (err) {
        fprintf(stderr, "failed to load skeleton: %d\n", err);
        goto cleanup;
    }

    err = rtds_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "failed to attach: %d\n", err);
        goto cleanup;
    }

    // Ring buffer to the map named "events" in your BPF object
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_sample, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "failed to create ring buffer: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("agent: running. Ctrl-C to stop.\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 200 /* ms */);
        if (err == -EINTR) break;
        if (err < 0) {
            fprintf(stderr, "ring_buffer__poll: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);

cleanup:
    rtds_bpf__destroy(skel);
    return err < 0 ? 1 : 0;
}