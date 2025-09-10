#pragma once
#include <stddef.h>

int handle_event_sample(void *ctx, void *data, size_t size);
int handle_syscall_sample(void *ctx, void *data, size_t size);