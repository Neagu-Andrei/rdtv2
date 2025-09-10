#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct cg_entry {
    char     path[512];  // full path under /sys/fs/cgroup
    uint64_t id;         // st_ino (cgroup id)
    int      whitelisted;
};

struct cg_list {
    struct cg_entry *v;
    int count;
};

int cg_enumerate(struct cg_list *out);      // allocates out->v; caller frees
void cg_free(struct cg_list *lst);

int cg_whitelist_set(int map_fd, uint64_t id, int enable); // 1=add, 0=remove
int cg_is_whitelisted_map(int map_fd, uint64_t id);        // 1/0

int cg_cli_list_and_toggle(int map_fd);     // simple interactive toggle UI

#ifdef __cplusplus
}
#endif