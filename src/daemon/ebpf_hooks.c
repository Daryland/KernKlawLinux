/* ebpf_hooks.c — eBPF program loader using libbpf ring-buffer API
 *
 * We load pre-compiled BPF object files (.bpf.o) produced by clang.
 * If eBPF is unavailable (non-root, old kernel, no CAP_BPF) we log a
 * warning and return NULL so the daemon continues without eBPF.
 */
#define _GNU_SOURCE
#include "ebpf_hooks.h"
#include "../common/log.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>
#include <errno.h>
#include <stdio.h>

/* ── Internal context ─────────────────────────────────────────────── */
struct claw_ebpf_ctx {
    struct bpf_object    *obj_file;    /* file_watch.bpf.o      */
    struct bpf_object    *obj_exec;    /* skill_trigger.bpf.o   */
    struct ring_buffer   *rb;          /* ring-buffer consumer  */
    int                   rb_fd;       /* map fd for epoll      */
    claw_event_cb         callback;
    void                 *userdata;
};

/* ── Capability check ─────────────────────────────────────────────── */
bool claw_ebpf_capable(void)
{
    return geteuid() == 0;   /* simplified: root = capable */
}

/* ── Ring-buffer callback ─────────────────────────────────────────── */
static int rb_handle_event(void *ctx_ptr, void *data, size_t size)
{
    struct claw_ebpf_ctx *ctx = (struct claw_ebpf_ctx *)ctx_ptr;
    if (size < sizeof(claw_ebpf_event_t)) return 0;
    const claw_ebpf_event_t *ev = (const claw_ebpf_event_t *)data;
    if (ctx->callback)
        ctx->callback(ev, ctx->userdata);
    return 0;
}

/* ── Loader ───────────────────────────────────────────────────────── */
static struct bpf_object *load_bpf_obj(const char *path)
{
    struct bpf_object *obj = bpf_object__open(path);
    if (!obj || IS_ERR(obj)) {
        log_warn("bpf_object__open(%s) failed: %ld", path, PTR_ERR(obj));
        return NULL;
    }
    if (bpf_object__load(obj) != 0) {
        log_warn("bpf_object__load(%s) failed: %m", path);
        bpf_object__close(obj);
        return NULL;
    }
    return obj;
}

/* Attach all programs in an object file */
static int attach_all(struct bpf_object *obj)
{
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *link = bpf_program__attach(prog);
        if (!link || IS_ERR(link)) {
            log_warn("bpf attach %s failed", bpf_program__name(prog));
            /* non-fatal: keep going */
        } else {
            log_debug("attached eBPF program: %s", bpf_program__name(prog));
        }
    }
    return 0;
}

claw_ebpf_ctx_t *claw_ebpf_init(const char *bpf_obj_dir,
                                   claw_event_cb callback,
                                   void *userdata)
{
    if (!claw_ebpf_capable()) {
        log_warn("eBPF hooks disabled (need root / CAP_BPF)");
        return NULL;
    }

    struct claw_ebpf_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->callback = callback;
    ctx->userdata = userdata;

    /* Silence libbpf chatty log — redirect to our own logger */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* Load file-watch object */
    char fw_path[512], st_path[512];
    snprintf(fw_path, sizeof(fw_path), "%s/file_watch.bpf.o", bpf_obj_dir);
    snprintf(st_path, sizeof(st_path), "%s/skill_trigger.bpf.o", bpf_obj_dir);

    ctx->obj_file = load_bpf_obj(fw_path);
    ctx->obj_exec = load_bpf_obj(st_path);

    if (!ctx->obj_file && !ctx->obj_exec) {
        log_warn("no eBPF objects loaded from %s — eBPF disabled", bpf_obj_dir);
        free(ctx);
        return NULL;
    }

    /* Attach programs */
    if (ctx->obj_file) attach_all(ctx->obj_file);
    if (ctx->obj_exec) attach_all(ctx->obj_exec);

    /* Find a ring-buffer map named "events" in first loaded object */
    struct bpf_object *rb_src = ctx->obj_file ? ctx->obj_file : ctx->obj_exec;
    struct bpf_map *rb_map = bpf_object__find_map_by_name(rb_src, "events");
    if (!rb_map) {
        log_warn("ring-buffer map 'events' not found; eBPF events won't be delivered");
        /* Don't fail — tracing still happens, just no callbacks */
        return ctx;
    }

    ctx->rb_fd = bpf_map__fd(rb_map);
    ctx->rb = ring_buffer__new(ctx->rb_fd, rb_handle_event, ctx, NULL);
    if (!ctx->rb) {
        log_warn("ring_buffer__new failed: %m");
        /* non-fatal */
    }

    log_info("eBPF hooks initialised (ring-buffer fd=%d)", ctx->rb_fd);
    return ctx;
}

int claw_ebpf_poll(claw_ebpf_ctx_t *ctx, int timeout_ms)
{
    if (!ctx || !ctx->rb) return 0;
    int n = ring_buffer__poll(ctx->rb, timeout_ms);
    if (n < 0 && n != -EINTR) log_warn("ring_buffer__poll: %d", n);
    return n;
}

int claw_ebpf_fd(const claw_ebpf_ctx_t *ctx)
{
    return (ctx && ctx->rb) ? ctx->rb_fd : -1;
}

void claw_ebpf_destroy(claw_ebpf_ctx_t *ctx)
{
    if (!ctx) return;
    if (ctx->rb)       ring_buffer__free(ctx->rb);
    if (ctx->obj_file) bpf_object__close(ctx->obj_file);
    if (ctx->obj_exec) bpf_object__close(ctx->obj_exec);
    free(ctx);
}
