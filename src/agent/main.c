#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>  
#include <syslog.h>

#include "rtds.skel.h"
#include "rdts_uapi.h"

#include "cgroups.h"
#include "log.h"
#include "handlers.h"

static volatile sig_atomic_t exiting = 0;
static void on_sigint(int sig) { (void)sig; exiting = 1; }

static void bump_memlock(void) {
    struct rlimit r = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &r) != 0) perror("setrlimit(RLIMIT_MEMLOCK)");
}

static void usage(const char *arg0) {
    fprintf(stderr,
        "Usage: %s [--stdout-events] [--stdout-syscalls] [--no-syslog] [--cgroup]\n"
        "       By default, logs go to syslog only.\n", arg0);
}

int main(int argc, char **argv)
{
    int to_syslog = 1, to_stdout_events = 0, to_stdout_syscalls = 0, list_cgroups_mode = 0;

    /* simple argv parsing */
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--stdout-events"))   to_stdout_events = 1;
        else if (!strcmp(argv[i], "--stdout-syscalls")) to_stdout_syscalls = 1;
        else if (!strcmp(argv[i], "--no-syslog"))  to_syslog = 0;
        else if (!strcmp(argv[i], "--cgroup"))  list_cgroups_mode= 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) { usage(argv[0]); return 0; }
        else { fprintf(stderr, "unknown arg: %s\n", argv[i]); usage(argv[0]); return 2; }
    }

    rtds_log_init(to_syslog);
    rtds_log_set_sinks(to_syslog, to_stdout_events, to_stdout_syscalls);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(rtds_libbpf_vprint);

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);
    bump_memlock();

    struct rtds_bpf *skel = rtds_bpf__open();
    if (!skel) { rtds_log_statusf("agent: open skeleton failed"); return 1; }

    int err = rtds_bpf__load(skel);
    if (err) { rtds_log_statusf("agent: load failed rc=%d", err); goto out_destroy; }

    // policy: set tracked syscalls before attach
    // int tfd = bpf_map__fd(skel->maps.tracked_syscalls);
    // if (tfd < 0) { syslog(LOG_ERR, "{\"err\":\"tracked_syscalls_fd\",\"errno\":%d}", errno); goto out_destroy; }
    // int rc = populate_tracked_syscalls_array(tfd);
    // if (rc) syslog(LOG_WARNING, "{\"warn\":\"populate_tracked\",\"rc\":%d}", rc);

    if (list_cgroups_mode) {
        int map_fd = bpf_map__fd(skel->maps.cgroup_whitelist);
        if (map_fd < 0) {
            rtds_log_statusf("agent: cg_whitelist map fd error");
            goto out_destroy;
        }
        rtds_log_statusf("agent: cgroup whitelist toggler");
        cg_cli_list_and_toggle(map_fd);
    }

    err = rtds_bpf__attach(skel);
    if (err) { rtds_log_statusf("agent: attach failed rc=%d", err); goto out_destroy; }

    // ring buffers
    int ev_fd = bpf_map__fd(skel->maps.events);
    int sc_fd = bpf_map__fd(skel->maps.syscalls);

    if (ev_fd < 0 || sc_fd < 0) {
    rtds_log_statusf("agent: map fd error (events=%d, syscalls=%d)", ev_fd, sc_fd);
    goto out_detach;
    }

    // create ONE ring buffer and add both maps
    struct ring_buffer *rb = ring_buffer__new(ev_fd, handle_event_sample, NULL, NULL);
    if (!rb) {
        syslog(LOG_ERR, "{\"err\":\"ringbuf_events\",\"errno\":%d}", errno);
        rtds_log_statusf("agent: ringbuf events failed");
        goto out_detach;
    }
    if (ring_buffer__add(rb, sc_fd, handle_syscall_sample, NULL)) {
        syslog(LOG_ERR, "{\"err\":\"ringbuf_syscalls\",\"errno\":%d}", errno);
        rtds_log_statusf("agent: ringbuf syscalls failed");
        ring_buffer__free(rb);
        goto out_detach;
    }


    rtds_log_statusf("agent: running%s%s%s",
        to_syslog ? " [syslog]" : "",
        to_stdout_events ? " [stdout-events]" : "",
        to_stdout_syscalls ? " [stdout-syscalls]" : "");

    while (!exiting) {
        int err = ring_buffer__poll(rb, 200);   // just poll the one rb
        if (err == -EINTR) break;
        if (err < 0) {
            syslog(LOG_ERR, "{\"err\":\"rb_poll\",\"rc\":%d}", err);
            rtds_log_statusf("agent: ringbuf poll error rc=%d", err);
            break;
        }
    }
    ring_buffer__free(rb);

out_detach:
    rtds_bpf__detach(skel);
out_destroy:
    rtds_bpf__destroy(skel);
    rtds_log_statusf("agent: stopped");
    if (rtds_log_syslog_enabled()) closelog();
    return err < 0 ? 1 : 0;
}