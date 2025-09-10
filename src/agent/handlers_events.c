#include <syslog.h>
#include <stdio.h>
#include "rdts_uapi.h"
#include "log.h"
#include "handlers.h"

int handle_event_sample(void *ctx, void *data, size_t size)
{
    (void)ctx;
    if (size < sizeof(struct event_t)) {
        if (rtds_log_syslog_enabled())
            syslog(LOG_WARNING, "{\"warn\":\"short_event\",\"size\":%zu}", size);
        return 0;
    }
    const struct event_t *e = data;

    /* Always send JSON to the selected sinks */
    rtds_log_event(e);

    /* Additionally, print the human-readable CLI line */
    rtds_cli_print_event(e);

    return 0;
}