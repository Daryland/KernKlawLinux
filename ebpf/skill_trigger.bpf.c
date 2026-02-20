/* skill_trigger.bpf.c — eBPF program: monitor exec events for skill triggers
 *
 * Watches process executions (execve/execveat) and process exits.
 * The daemon uses these events to auto-trigger skills when configured
 * programs are run (e.g., trigger "git-hook" skill on git commit).
 *
 * Compiled with:
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *         -I/usr/include/bpf \
 *         -c skill_trigger.bpf.c -o skill_trigger.bpf.o
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/* ── Event types (matches ebpf_hooks.h) ──────────────────────────── */
#define CLAW_EVENT_PROC_EXEC  4
#define CLAW_EVENT_PROC_EXIT  5

struct claw_event {
    __u32  pid;
    __u32  uid;
    __s32  type;
    char   comm[16];
    char   path[256];
    __s64  ts_ns;
};

/* ── Shared ring-buffer (same map name as file_watch) ─────────────── */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* ── PID allowlist map (userspace adds/removes entries) ───────────── */
/* key=pid (u32), value=1 (u8) — used for ptrace-style monitoring */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key,   __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

/* ── tracepoint: sys_enter_execve ────────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct claw_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid   = bpf_get_current_pid_tgid() >> 32;
    ev->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->type  = CLAW_EVENT_PROC_EXEC;
    ev->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    /* ctx->args[0] = filename */
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(ev->path, sizeof(ev->path), filename);

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── tracepoint: sched_process_exit ──────────────────────────────── */
SEC("tracepoint/sched/sched_process_exit")
int tp_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    /* Only emit exit events for watched PIDs */
    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);
    if (!watched) return 0;

    struct claw_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid   = pid;
    ev->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->type  = CLAW_EVENT_PROC_EXIT;
    ev->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    ev->path[0] = '\0';

    bpf_map_delete_elem(&watched_pids, &pid);
    bpf_ringbuf_submit(ev, 0);
    return 0;
}

/* ── kprobe: tcp_connect (net connection monitoring) ─────────────── */
SEC("kprobe/tcp_connect")
int kp_tcp_connect(struct pt_regs *ctx)
{
    struct claw_event *ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev) return 0;

    ev->pid   = bpf_get_current_pid_tgid() >> 32;
    ev->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->type  = 3; /* CLAW_EVENT_NET_CONN */
    ev->ts_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));
    ev->path[0] = '\0';

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
