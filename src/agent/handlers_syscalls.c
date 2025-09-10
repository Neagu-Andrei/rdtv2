#include <syslog.h>
#include <stdio.h>
#include "rdts_uapi.h"
#include "log.h"
#include "handlers.h"

static unsigned long g_syscall_seen = 0;

int handle_syscall_sample(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct syscall_t)) {
        // log BOTH to syslog (if enabled) and stderr so it’s visible
        if (rtds_log_syslog_enabled())
            syslog(LOG_WARNING, "{\"warn\":\"short_syscall\",\"size\":%zu,\"need\":%zu}", size, sizeof(struct syscall_t));
        fprintf(stderr, "short_syscall: got %zu need %zu\n", size, sizeof(struct syscall_t));
        g_syscall_seen++;
        if ((g_syscall_seen % 1000) == 1)  // every ~1000, print one line
            fprintf(stderr, "[dbg] syscall samples seen: %lu\n", g_syscall_seen);
        return 0;
    }
    rtds_log_syscall((const struct syscall_t*)data);
    return 0;
}