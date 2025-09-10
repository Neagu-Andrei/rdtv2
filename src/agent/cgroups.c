#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include "cgroups.h"

static const char *CG_ROOT = "/sys/fs/cgroup";

static int is_dir(const char *p) {
    struct stat st;
    if (stat(p, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

static int get_cg_id(const char *p, uint64_t *out)
{
    struct stat st;
    if (stat(p, &st) != 0) return -errno;
    *out = (uint64_t)st.st_ino;
    return 0;
}

static int append_entry(struct cg_list *lst, const char *path, uint64_t id)
{
    int newc = lst->count + 1;
    struct cg_entry *nv = realloc(lst->v, newc * sizeof(*nv));
    if (!nv) return -ENOMEM;
    lst->v = nv;
    struct cg_entry *e = &lst->v[lst->count];
    snprintf(e->path, sizeof e->path, "%s", path);
    e->id = id;
    e->whitelisted = 0;
    lst->count = newc;
    return 0;
}

static int walk_dir(struct cg_list *lst, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) return -errno;

    // include the directory itself
    uint64_t id;
    if (get_cg_id(dir, &id) == 0)
        append_entry(lst, dir, id);

    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        char child[PATH_MAX];
        snprintf(child, sizeof child, "%s/%s", dir, de->d_name);
        if (is_dir(child))
            walk_dir(lst, child);
    }
    closedir(d);
    return 0;
}

int cg_enumerate(struct cg_list *out)
{
    memset(out, 0, sizeof(*out));
    if (!is_dir(CG_ROOT)) return -ENOENT;
    return walk_dir(out, CG_ROOT);
}

void cg_free(struct cg_list *lst)
{
    free(lst->v);
    lst->v = NULL;
    lst->count = 0;
}

int cg_whitelist_set(int map_fd, uint64_t id, int enable)
{
    if (enable) {
        __u8 one = 1;
        return bpf_map_update_elem(map_fd, &id, &one, BPF_ANY);
    } else {
        return bpf_map_delete_elem(map_fd, &id);
    }
}

int cg_is_whitelisted_map(int map_fd, uint64_t id)
{
    __u8 val = 0;
    int rc = bpf_map_lookup_elem(map_fd, &id, &val);
    return rc == 0 && val == 1;
}

/* ---------- range parsing helpers (toggle only) ---------- */

static int parse_range_token(const char *tok, int *lo, int *hi)
{
    while (*tok == ' ') tok++;

    char *dash = strchr(tok, '-');
    if (!dash) {
        char *endp = NULL;
        long v = strtol(tok, &endp, 10);
        if (!endp || *endp != '\0') return -1;
        *lo = *hi = (int)v;
        return 0;
    }

    char left[64], right[64];
    size_t L = (size_t)(dash - tok);
    if (L >= sizeof(left)) return -1;
    memcpy(left, tok, L);
    left[L] = 0;

    const char *r = dash + 1;
    while (*r == ' ') r++;
    snprintf(right, sizeof right, "%s", r);

    // trim trailing spaces from left
    for (int i = (int)strlen(left) - 1; i >= 0 && left[i] == ' '; i--) left[i] = 0;

    char *endp1 = NULL, *endp2 = NULL;
    long a = strtol(left, &endp1, 10);
    long b = strtol(right, &endp2, 10);
    if (!endp1 || *endp1 != '\0') return -1;
    if (!endp2 || *endp2 != '\0') return -1;

    if (a <= b) { *lo = (int)a; *hi = (int)b; }
    else        { *lo = (int)b; *hi = (int)a; }
    return 0;
}

static int apply_range_toggle(int map_fd, struct cg_list *lst, int lo, int hi)
{
    if (lo < 0) lo = 0;
    if (hi >= lst->count) hi = lst->count - 1;
    if (hi < lo) return 0;

    int failures = 0;
    for (int i = lo; i <= hi; i++) {
        struct cg_entry *e = &lst->v[i];
        int cur = cg_is_whitelisted_map(map_fd, e->id);
        if (cg_whitelist_set(map_fd, e->id, !cur) != 0)
            failures++;
    }
    return failures ? -1 : 0;
}

static int apply_index_list_toggle(int map_fd, struct cg_list *lst, const char *list)
{
    char buf[1024];
    snprintf(buf, sizeof buf, "%s", list);

    int rc_all = 0;
    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        // trim spaces
        while (*tok == ' ') tok++;
        char *end = tok + strlen(tok) - 1;
        while (end >= tok && *end == ' ') *end-- = 0;

        int lo = 0, hi = 0;
        if (parse_range_token(tok, &lo, &hi) != 0) {
            fprintf(stderr, "bad range token: '%s'\n", tok);
            rc_all = -1;
            continue;
        }
        if (apply_range_toggle(map_fd, lst, lo, hi) != 0)
            rc_all = -1;
    }
    return rc_all;
}

/* ---------- UI ---------- */

static void print_table(struct cg_list *lst, int map_fd)
{
    printf("%-5s %-18s  %s\n", "Idx", "CGroupID", "Path");
    for (int i = 0; i < lst->count; i++) {
        struct cg_entry *e = &lst->v[i];
        int wl = cg_is_whitelisted_map(map_fd, e->id);
        printf("%-5d %c%-18lu  %s\n",
               i, wl ? '*' : ' ',
               (unsigned long)e->id, e->path);
    }
    printf("\n");
    printf("  q                     quit editor and continue agent\n");
    printf("  <idx>                 toggle one index (e.g., 12)\n");
    printf("  <idx-list>            toggle list/ranges (e.g., 0-5, 10-12)\n");
    printf("\n[*] '*' means whitelisted. Example: '0-100' to toggle a batch\n");
}

int cg_cli_list_and_toggle(int map_fd)
{
    struct cg_list lst = {};
    int rc = cg_enumerate(&lst);
    if (rc) { fprintf(stderr, "enumerate cgroups: %s\n", strerror(-rc)); return rc; }

    char buf[1024];
    for (;;) {
        print_table(&lst, map_fd);
        printf("> ");
        fflush(stdout);
        if (!fgets(buf, sizeof buf, stdin)) break;

        // trim
        char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
        if (buf[0] == 0) continue;
        if (buf[0] == 'q' || buf[0] == 'Q') break;

        // decide if it's a list/range (only digits, ',', '-', spaces)
        int numbers_only = 1;
        for (const char *p = buf; *p; p++) {
            if (!((*p >= '0' && *p <= '9') || *p == '-' || *p == ',' || *p == ' ')) {
                numbers_only = 0; break;
            }
        }
        if (numbers_only) {
            if (apply_index_list_toggle(map_fd, &lst, buf) != 0)
                fprintf(stderr, "one or more toggles failed\n");
            continue;
        }

        // try single index
        char *endp = NULL;
        long idx = strtol(buf, &endp, 10);
        if (endp && *endp == '\0') {
            if (idx < 0 || idx >= lst.count) { fprintf(stderr, "bad index\n"); continue; }
            struct cg_entry *e = &lst.v[idx];
            int cur = cg_is_whitelisted_map(map_fd, e->id);
            rc = cg_whitelist_set(map_fd, e->id, !cur);
            if (rc) fprintf(stderr, "toggle failed: %s\n", strerror(errno));
            continue;
        }

        // treat as path
        char path[PATH_MAX];
        if (buf[0] == '/') snprintf(path, sizeof path, "%s", buf);
        else               snprintf(path, sizeof path, "%s/%s", CG_ROOT, buf);

        uint64_t id;
        rc = get_cg_id(path, &id);
        if (rc) { fprintf(stderr, "stat %s: %s\n", path, strerror(-rc)); continue; }

        int cur = cg_is_whitelisted_map(map_fd, id);
        rc = cg_whitelist_set(map_fd, id, !cur);
        if (rc) fprintf(stderr, "toggle failed: %s\n", strerror(errno));
    }

    cg_free(&lst);
    return 0;
}