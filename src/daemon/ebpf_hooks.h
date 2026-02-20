/* ebpf_hooks.h — eBPF program management for claw-daemon */
#pragma once
#ifndef CLAW_EBPF_HOOKS_H
#define CLAW_EBPF_HOOKS_H

#include <stdbool.h>
#include <stdint.h>

/* ── Event types emitted by eBPF hooks ───────────────────────────── */
typedef enum {
    CLAW_EVENT_FILE_OPEN  = 1,
    CLAW_EVENT_FILE_WRITE = 2,
    CLAW_EVENT_NET_CONN   = 3,
    CLAW_EVENT_PROC_EXEC  = 4,
    CLAW_EVENT_PROC_EXIT  = 5,
} claw_event_type_t;

/* Matches the struct in eBPF programs (must be kept in sync) */
typedef struct {
    uint32_t          pid;
    uint32_t          uid;
    claw_event_type_t type;
    char              comm[16];
    char              path[256];
    int64_t           ts_ns;
} claw_ebpf_event_t;

/* ── Callback ─────────────────────────────────────────────────────── */
typedef void (*claw_event_cb)(const claw_ebpf_event_t *ev, void *userdata);

/* ── Handle ───────────────────────────────────────────────────────── */
typedef struct claw_ebpf_ctx claw_ebpf_ctx_t;

/* Load all eBPF programs from bpf_obj_dir (e.g. /usr/lib/claw/bpf/).
 * Returns NULL on failure (eBPF unavailable → gracefully disabled). */
claw_ebpf_ctx_t *claw_ebpf_init(const char *bpf_obj_dir,
                                  claw_event_cb callback,
                                  void *userdata);

/* Poll the ring-buffer for events (timeout_ms = -1 → block). */
int claw_ebpf_poll(claw_ebpf_ctx_t *ctx, int timeout_ms);

/* Returns the perf/ring-buffer fd for use in epoll */
int claw_ebpf_fd(const claw_ebpf_ctx_t *ctx);

/* Cleanup */
void claw_ebpf_destroy(claw_ebpf_ctx_t *ctx);

/* Check kernel BPF capability (CAP_BPF / CAP_SYS_ADMIN) */
bool claw_ebpf_capable(void);

#endif /* CLAW_EBPF_HOOKS_H */
