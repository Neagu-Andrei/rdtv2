#pragma once
#include <stdarg.h>
#include <bpf/libbpf.h>

#ifdef __cplusplus
extern "C" {
#endif

void rtds_log_init(int enable_syslog);     // pass 0/1
int  rtds_libbpf_vprint(enum libbpf_print_level lvl, const char *fmt, va_list ap);

void rtds_log_set_sinks(int to_syslog, int to_stdout_events, int to_stdout_syscalls);
int  rtds_log_syslog_enabled(void);

void rtds_log_statusf(const char *fmt, ...);   // <-- ensure this is declared

struct event_t;
struct syscall_t;

void rtds_log_event(const struct event_t *e);
void rtds_log_syscall(const struct syscall_t *s);

/* CLI-only pretty printer */
void rtds_cli_print_event(const struct event_t *e);

#ifdef __cplusplus
}
#endif