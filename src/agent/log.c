#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include "rdts_uapi.h"
#include "log.h"

static int SINK_SYSLOG          = 1;
static int SINK_STDOUT_EVENTS   = 0;
static int SINK_STDOUT_SYSCALLS = 0;

int rtds_log_syslog_enabled(void) { return SINK_SYSLOG; }

static int parse_facility(const char *s) {
    if (!s) return LOG_AUTHPRIV;
    if (!strcasecmp(s, "AUTH") || !strcasecmp(s, "AUTHPRIV")) return LOG_AUTHPRIV;
    if (!strcasecmp(s, "DAEMON")) return LOG_DAEMON;
    if (!strcasecmp(s, "LOCAL0")) return LOG_LOCAL0;
    if (!strcasecmp(s, "LOCAL1")) return LOG_LOCAL1;
    if (!strcasecmp(s, "LOCAL2")) return LOG_LOCAL2;
    if (!strcasecmp(s, "LOCAL3")) return LOG_LOCAL3;
    if (!strcasecmp(s, "LOCAL4")) return LOG_LOCAL4;
    if (!strcasecmp(s, "LOCAL5")) return LOG_LOCAL5;
    if (!strcasecmp(s, "LOCAL6")) return LOG_LOCAL6;
    if (!strcasecmp(s, "LOCAL7")) return LOG_LOCAL7;
    return LOG_AUTHPRIV;
}

/* pass enable_syslog=0 to avoid opening syslog at all */
void rtds_log_init(int enable_syslog) {
    SINK_SYSLOG = !!enable_syslog;
    if (SINK_SYSLOG) {
        const char *fac = getenv("RTDS_SYSLOG_FACILITY");
        openlog("rtds-agent", LOG_PID | LOG_NDELAY, parse_facility(fac));
        setlogmask(LOG_UPTO(LOG_INFO));
    }
}

void rtds_log_set_sinks(int to_syslog, int to_stdout_events, int to_stdout_syscalls)
{
    SINK_SYSLOG          = !!to_syslog;
    SINK_STDOUT_EVENTS   = !!to_stdout_events;
    SINK_STDOUT_SYSCALLS = !!to_stdout_syscalls;

    /* Ensure stdout is unbuffered when we plan to show live events/syscalls */
    if (SINK_STDOUT_EVENTS || SINK_STDOUT_SYSCALLS) {
        setvbuf(stdout, NULL, _IONBF, 0);
    }
}

int rtds_libbpf_vprint(enum libbpf_print_level lvl, const char *fmt, va_list ap) {
    (void)lvl; (void)fmt; (void)ap; return 0;
    // return vfprintf(stderr, fmt, ap);
}

/* ---------- status helper (DEFINITION) ---------- */
void rtds_log_statusf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    if (SINK_SYSLOG) syslog(LOG_INFO, "%s", buf);
    fprintf(stdout, "%s\n", buf);
}

/* ---------- event name (DEFINITION) ---------- */
static const char *event_name(__u8 t)
{
    switch (t) {
    case 100: return "EVENT_SYSINFO_DISCOVERY";
    case 101: return "EVENT_PROCESS_DISCOVERY";
    case 102: return "EVENT_SERVICE_STOP";
    case 103: return "EVENT_OPEN_HOST_DATA";
    case 104: return "EVENT_MASS_WRITE";
    case 105: return "EVENT_DATA_FOR_IMPACT";
    case 106: return "EVENT_MMAP_COMMIT";
    case 107: return "EVENT_ENCRYPT_INPLACE_DOMBIN";
    case 108: return "EVENT_CGROUP_MOVE";
    case 109: return "EVENT_ESCALATE_ROOT";
    default:  return "EVENT";
    }
}

static const char *flags_to_str(__u8 type, __u32 flags)
{
    static char buf[256]; buf[0] = 0;
    if (!flags) { snprintf(buf, sizeof buf, "none"); return buf; }

    switch (type) {
    case EVENT_SYSINFO_DISCOVERY:
        if (flags & PF_OS_VERSION)  strncat(buf, "OS version, ",  sizeof buf - strlen(buf) - 1);
        if (flags & PF_USER_ENUM)   strncat(buf, "user enum, ",   sizeof buf - strlen(buf) - 1);
        if (flags & PF_VM_PROBE)    strncat(buf, "VM probe, ",    sizeof buf - strlen(buf) - 1);
        if (flags & PF_HW_ENUM)     strncat(buf, "HW enum, ",     sizeof buf - strlen(buf) - 1);
        if (flags & PF_DISK_ENUM)   strncat(buf, "disk enum, ",   sizeof buf - strlen(buf) - 1);
        break;
    case EVENT_SERVICE_STOP:
        if (flags & CHANNEL_DIRECT_SIGNAL)  strncat(buf, "direct_signal, ",  sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_EXEC_SERVICE)   strncat(buf, "exec_service, ",   sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_ORCHESTRATOR)   strncat(buf, "orchestrator, ",   sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_HYPERVISOR)     strncat(buf, "hypervisor, ",     sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_DBUS_PID1)      strncat(buf, "dbus_pid1, ",      sizeof buf - strlen(buf) - 1);
        if (flags & CHANNEL_CGROUP_CONTROL) strncat(buf, "cgroup_control, ", sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_STOP)      strncat(buf, "stop, ",      sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_KILL)      strncat(buf, "kill, ",      sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_DISABLE)   strncat(buf, "disable, ",   sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_MASK)      strncat(buf, "mask, ",      sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_RESTART)   strncat(buf, "restart, ",   sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_RELOAD)    strncat(buf, "reload, ",    sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_FREEZE)    strncat(buf, "freeze, ",    sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_PROBEONLY) strncat(buf, "probe_only, ",sizeof buf - strlen(buf) - 1);
        if (flags & EFFECT_FANOUT)    strncat(buf, "fanout, ",    sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_LOGGING_AUDIT)  strncat(buf, "logging/audit, ", sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_CONTAINER_RT)   strncat(buf, "container_rt, ",  sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_VMM_HYPERVISOR) strncat(buf, "vmm/hypervisor, ",sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_DATABASE)       strncat(buf, "database, ",      sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_BACKUP_AGENT)   strncat(buf, "backup, ",        sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_SECURITY_AGENT) strncat(buf, "security, ",      sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_NETWORKING)     strncat(buf, "networking, ",    sizeof buf - strlen(buf) - 1);
        if (flags & TARGET_OTHER_CRITICAL) strncat(buf, "other_critical, ",sizeof buf - strlen(buf) - 1);
        break;
    case EVENT_CGROUP_MOVE:
        if (flags & FLAG_MOVED_TO_WHITELISTED_CGROUP) strncat(buf, "to_whitelisted, ", sizeof buf - strlen(buf) - 1);
        if (flags & FLAG_FIRST_TIME_MOVED_TO_CGROUP)  strncat(buf, "first_move, ",     sizeof buf - strlen(buf) - 1);
        break;
    case EVENT_ESCALATE_ROOT:
        if (flags & BIT_SYSINFO_DISCOVERY)           strncat(buf, "sysinfo, ", sizeof buf - strlen(buf) - 1);
        if (flags & BIT_PROCESS_DISCOVERY)           strncat(buf, "procdisc, ", sizeof buf - strlen(buf) - 1);
        if (flags & BIT_SERVICE_STOP)                strncat(buf, "servicestop, ", sizeof buf - strlen(buf) - 1);
        if (flags & BIT_OPEN_HOST_DATA)              strncat(buf, "openhost, ", sizeof buf - strlen(buf) - 1);
        if (flags & BIT_MOVED_TO_WHITELISTED_CGROUP) strncat(buf, "whitelist_cgrp, ", sizeof buf - strlen(buf) - 1);
        break;
    default: snprintf(buf, sizeof buf, "0x%x", flags); break;
    }
    size_t L = strlen(buf);
    if (L >= 2 && buf[L-2] == ',' && buf[L-1] == ' ') buf[L-2] = 0;
    return buf;
}

/* tiny JSON helpers … (unchanged) */
/* event_name() … (unchanged) */

/* ---------------- JSON emitters ---------------- */
void rtds_log_event(const struct event_t *e)
{
    /* compact JSON for SIEM/journald */
    char line[512];
    int n = snprintf(line, sizeof line,
        "{"
          "\"ts_ns\":%llu,"
          "\"root\":%u,"
          "\"tgid\":%u,"
          "\"pid\":%u,"
          "\"type\":\"%s\","
          "\"flags\":%s,"
          "\"arg0\":%llu,"
          "\"arg1\":%llu"
        "}",
        (unsigned long long)e->ts_ns,
        e->p.root_tgid,
        e->p.tgid,
        e->p.tid,
        /* if you want numeric id instead: replace event_name(e->type) with "%u" and (unsigned)e->type */
        event_name(e->type),
        flags_to_str(e->type, e->event_flags),
        (unsigned long long)e->arg0,
        (unsigned long long)e->arg1);

    if (n < 0) return; /* snprintf error */

    if (rtds_log_syslog_enabled())
        syslog(LOG_INFO, "%s", line);
    /* Do NOT print to stdout here; CLI uses rtds_cli_print_event() */
}

void rtds_log_syscall(const struct syscall_t *s)
{
    // Build compact JSON; keep it small to avoid syslog truncation
    char line[2048];
    int w = 0;

    // header
    w += snprintf(line + w, sizeof(line) - w,
                  "{\"ts_ns\":%llu,"
                  "\"dur_ns\":%llu,"
                  "\"root\":%u,\"tgid\":%u,\"pid\":%u,"
                  "\"sys\":%u,\"ret\":%lld,"
                  "\"argc\":%u,",
                  (unsigned long long)s->ts_ns,
                  (unsigned long long)s->duration_ns,
                  s->p.root_tgid, s->p.tgid, s->p.tid,
                  (unsigned)s->sys_nr,
                  (long long)s->ret,
                  (unsigned)s->arg_count);

    // args (always present as u64 fields for uniformity)
    w += snprintf(line + w, sizeof(line) - w,
                  "\"a0\":%llu,\"a1\":%llu,\"a2\":%llu,\"a3\":%llu,",
                  (unsigned long long)s->a0,
                  (unsigned long long)s->a1,
                  (unsigned long long)s->a2,
                  (unsigned long long)s->a3);

    // task name
    w += snprintf(line + w, sizeof(line) - w, "\"comm\":\"%.*s\",",
                  TASK_COMM_LEN, s->comm);

    // cgroup id for correlation
    w += snprintf(line + w, sizeof(line) - w,
                  "\"cgroup_id\":%llu,",
                  (unsigned long long)s->p.cgroup_id);

    // optional paths (truncate to reported length)
    w += snprintf(line + w, sizeof(line) - w, "\"path0\":\"");
    for (int i = 0; i < s->path0_len && i < MAX_PATH_LEN && w + 4 < (int)sizeof(line); i++) {
        unsigned char c = (unsigned char)s->path0[i];
        // escape quotes and backslashes
        if (c == '\\' || c == '"') { if (w+2 < (int)sizeof(line)) line[w++]='\\', line[w++]=c; }
        else if (c >= 32 && c < 127) line[w++] = c;
        else { // hex escape
            if (w+4 < (int)sizeof(line)) w += snprintf(line + w, sizeof(line) - w, "\\x%02x", c);
        }
    }
    w += snprintf(line + w, sizeof(line) - w, "\",\"path1\":\"");
    for (int i = 0; i < s->path1_len && i < MAX_PATH_LEN && w + 4 < (int)sizeof(line); i++) {
        unsigned char c = (unsigned char)s->path1[i];
        if (c == '\\' || c == '"') { if (w+2 < (int)sizeof(line)) line[w++]='\\', line[w++]=c; }
        else if (c >= 32 && c < 127) line[w++] = c;
        else { if (w+4 < (int)sizeof(line)) w += snprintf(line + w, sizeof(line) - w, "\\x%02x", c); }
    }
    w += snprintf(line + w, sizeof(line) - w, "\"}");

    // sinks
    if (rtds_log_syslog_enabled()) syslog(LOG_INFO, "%s", line);
    if (SINK_STDOUT_SYSCALLS) { fputs(line, stdout); fputc('\n', stdout); }
}

/* ---------------- CLI pretty printer for events ---------------- */
/* Your original “pre-processing of flags & args”, only to stdout. */
static const char *event_name(__u8); /* already defined above */


void rtds_cli_print_event(const struct event_t *e)
{
    double ms = e->ts_ns / 1e6;
    switch (e->type) {
    case EVENT_SYSINFO_DISCOVERY:
        printf("[%.3f ms] pid=%u tgid=%u root=%u %s flags=%s added=%s\n",
            ms, e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
            flags_to_str(e->type, e->event_flags),
            flags_to_str(e->type, (unsigned)e->arg0));
        break;
    case EVENT_PROCESS_DISCOVERY:
        printf("[%.3f ms] pid=%u tgid=%u root=%u %s\n",
            ms, e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type));
        break;
    case EVENT_SERVICE_STOP:
        printf("[%.3f ms] pid=%u tgid=%u root=%u %s flags=%s target=%llu\n",
            ms, e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
            flags_to_str(e->type, e->event_flags), e->arg0);
        break;
    case EVENT_CGROUP_MOVE:
        printf("[%.3f ms] pid=%u tgid=%u root=%u %s ctx=[%s] from %llu to %llu\n",
            ms, e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
            flags_to_str(e->type, e->event_flags), e->arg0, e->arg1);
        break;
    case EVENT_ESCALATE_ROOT:
        printf("[%.3f ms] pid=%u tgid=%u root=%u %s ctx=[%s] from %llu to %llu\n",
            ms, e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
            flags_to_str(e->type, e->event_flags), e->arg0, e->arg1);
        break;
    default:
        printf("[%.3f ms] pid=%u tgid=%u root=%u %s flags=0x%x args=[%llu,%llu]\n",
            ms, e->p.tid, e->p.tgid, e->p.root_tgid, event_name(e->type),
            e->event_flags, e->arg0, e->arg1);
        break;
    }
}