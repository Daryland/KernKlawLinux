/* claw-daemon.c — KernKlaw-Linux main daemon
 *
 * Architecture:
 *   - Epoll event loop (main thread)
 *   - Unix socket IPC (clients: claw-shell, scripts)
 *   - Ollama integration for AI inference
 *   - Skill registry (loaded from /etc/claw/skills)
 *   - Optional eBPF event hooks
 *   - Systemd sd_notify integration
 *
 * Privilege: should run as 'claw' user (root for eBPF hooks).
 * Drop privileges after binding socket with cap_net_bind_service.
 */
#define _GNU_SOURCE
#define CLAW_LOG_IMPL    /* define g_log_level here */
#define CLAW_LOG_SYSLOG  /* use syslog in daemon */

#include "../common/proto.h"
#include "../common/log.h"
#include "../common/json_utils.h"
#include "ipc.h"
#include "ollama.h"
#include "skill_loader.h"
#include "ebpf_hooks.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <pthread.h>
#include <sys/stat.h>
#include <systemd/sd-daemon.h>
#include <curl/curl.h>

/* ── Daemon state ─────────────────────────────────────────────────── */
typedef struct {
    claw_server_t     srv;
    ollama_cfg_t      ollama;
    skill_registry_t  skills;
    claw_ebpf_ctx_t  *ebpf;

    char  config_dir[256];
    char  skill_dir[256];
    char  bpf_dir[256];

    volatile int running;
    int          epoll_fd;     /* same as srv.epoll_fd */
} claw_daemon_t;

static claw_daemon_t g_daemon;

/* ── Signal handling ──────────────────────────────────────────────── */
static volatile sig_atomic_t g_sigterm = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_sigterm = 1;
    g_daemon.running = 0;
}

/* ── Streaming thread ─────────────────────────────────────────────── */
/* We offload Ollama streaming calls to a thread so the event loop
 * doesn't block.  When a token arrives we write it back to the client
 * over the Unix socket (thread-safe via send() which is async-signal-safe). */

typedef struct {
    int              client_fd;
    uint64_t         request_id;
    char             model[64];
    char            *prompt;       /* heap, thread owns it */
    ollama_cfg_t     ollama;
} query_thread_arg_t;

static void query_on_token(const char *token, void *ud)
{
    query_thread_arg_t *arg = (query_thread_arg_t *)ud;
    if (!token) return; /* stream done signal handled by on_done */

    struct json_object *chunk = json_object_new_object();
    json_object_object_add(chunk, CLAW_F_ID,      json_object_new_int64((int64_t)arg->request_id));
    json_object_object_add(chunk, CLAW_F_CONTENT, json_object_new_string(token));
    char *s = claw_json_to_str(chunk);
    json_object_put(chunk);

    claw_hdr_t hdr;
    claw_hdr_init(&hdr, CLAW_MSG_STREAM_CHUNK, (uint32_t)strlen(s));
    struct iovec iov[2] = {
        { &hdr, sizeof(hdr) },
        { s,    strlen(s)   },
    };
    struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };
    sendmsg(arg->client_fd, &msg, MSG_NOSIGNAL);
    free(s);
}

static void query_on_done(const char *full_text, int err, void *ud)
{
    query_thread_arg_t *arg = (query_thread_arg_t *)ud;
    struct json_object *end = json_object_new_object();
    json_object_object_add(end, CLAW_F_ID,       json_object_new_int64((int64_t)arg->request_id));
    json_object_object_add(end, CLAW_F_DONE,     json_object_new_boolean(1));
    json_object_object_add(end, CLAW_F_RESPONSE, json_object_new_string(full_text ? full_text : ""));
    if (err)
        json_object_object_add(end, CLAW_F_ERROR, json_object_new_int(err));
    char *s = claw_json_to_str(end);
    json_object_put(end);

    claw_hdr_t hdr;
    claw_hdr_init(&hdr, CLAW_MSG_STREAM_END, (uint32_t)strlen(s));
    struct iovec iov[2] = { { &hdr, sizeof(hdr) }, { s, strlen(s) } };
    struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };
    sendmsg(arg->client_fd, &msg, MSG_NOSIGNAL);
    free(s);
}

static void *query_thread(void *arg_ptr)
{
    query_thread_arg_t *arg = (query_thread_arg_t *)arg_ptr;
    ollama_generate_stream(&arg->ollama, arg->model, arg->prompt,
                           query_on_token, query_on_done, arg);
    free(arg->prompt);
    free(arg);
    return NULL;
}

/* ── IPC message handler ──────────────────────────────────────────── */
static int handle_message(claw_client_t *client,
                           claw_msg_type_t type,
                           const char *payload, size_t payload_len,
                           void *ud)
{
    claw_daemon_t *d = (claw_daemon_t *)ud;

    switch (type) {

    case CLAW_MSG_PING: {
        claw_server_send(client, CLAW_MSG_PONG, "{\"pong\":1}", 10);
        break;
    }

    case CLAW_MSG_STATUS: {
        struct json_object *s = json_object_new_object();
        json_object_object_add(s, "version",    json_object_new_string("0.1.0"));
        json_object_object_add(s, "skills",     json_object_new_int(d->skills.count));
        json_object_object_add(s, "ebpf",       json_object_new_boolean(d->ebpf != NULL));
        json_object_object_add(s, "ollama_url", json_object_new_string(d->ollama.base_url));
        json_object_object_add(s, "model",      json_object_new_string(d->ollama.default_model));
        char *str = claw_json_to_str(s);
        json_object_put(s);
        claw_server_send(client, CLAW_MSG_STATUS_RSP, str, strlen(str));
        free(str);
        break;
    }

    case CLAW_MSG_QUERY: {
        struct json_object *req = claw_json_from_buf(payload, payload_len);
        if (!req) {
            const char *err = "{\"error\":\"invalid JSON\"}";
            claw_server_send(client, CLAW_MSG_ERROR, err, strlen(err));
            break;
        }
        const char *prompt = claw_json_str(req, CLAW_F_PROMPT);
        const char *model  = claw_json_str(req, CLAW_F_MODEL);
        uint64_t    id     = (uint64_t)claw_json_int(req, CLAW_F_ID, 0);

        if (!prompt || !*prompt) {
            json_object_put(req);
            const char *err = "{\"error\":\"missing prompt\"}";
            claw_server_send(client, CLAW_MSG_ERROR, err, strlen(err));
            break;
        }

        /* Dispatch to streaming thread */
        query_thread_arg_t *arg = calloc(1, sizeof(*arg));
        arg->client_fd  = client->fd;
        arg->request_id = id;
        arg->ollama     = d->ollama;
        arg->prompt     = strdup(prompt);
        strncpy(arg->model,
                (model && *model) ? model : d->ollama.default_model,
                sizeof(arg->model)-1);
        json_object_put(req);

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, query_thread, arg);
        pthread_attr_destroy(&attr);
        break;
    }

    case CLAW_MSG_SKILL_LIST: {
        char *list = skill_list_json(&d->skills);
        claw_server_send(client, CLAW_MSG_SKILL_LIST_RSP, list, strlen(list));
        free(list);
        break;
    }

    case CLAW_MSG_SKILL_EXEC: {
        struct json_object *req = claw_json_from_buf(payload, payload_len);
        if (!req) {
            const char *err = "{\"error\":\"invalid JSON\"}";
            claw_server_send(client, CLAW_MSG_ERROR, err, strlen(err));
            break;
        }
        const char *skill_name = claw_json_str(req, CLAW_F_SKILL);
        uint64_t id = (uint64_t)claw_json_int(req, CLAW_F_ID, 0);

        struct json_object *args_obj = NULL;
        json_object_object_get_ex(req, CLAW_F_ARGS, &args_obj);
        char *args_json = args_obj
            ? strdup(json_object_to_json_string(args_obj))
            : strdup("{}");
        json_object_put(req);

        const skill_manifest_t *skill = skill_find(&d->skills, skill_name);
        if (!skill) {
            struct json_object *err = claw_json_error(id, "skill not found");
            char *s = claw_json_to_str(err);
            json_object_put(err);
            claw_server_send(client, CLAW_MSG_ERROR, s, strlen(s));
            free(s);
            free(args_json);
            break;
        }

        char *output = NULL;
        int rc = skill_exec(skill, args_json, &output);
        free(args_json);

        struct json_object *resp = json_object_new_object();
        json_object_object_add(resp, CLAW_F_ID, json_object_new_int64((int64_t)id));
        if (rc == 0) {
            json_object_object_add(resp, CLAW_F_RESULT,
                                   json_object_new_string(output ? output : ""));
        } else {
            json_object_object_add(resp, CLAW_F_ERROR,
                                   json_object_new_string("skill execution failed"));
        }
        free(output);
        char *s = claw_json_to_str(resp);
        json_object_put(resp);
        claw_server_send(client,
                         (rc == 0) ? CLAW_MSG_SKILL_RESULT : CLAW_MSG_ERROR,
                         s, strlen(s));
        free(s);
        break;
    }

    default:
        log_warn("unknown message type 0x%02x from client %lu",
                 type, (unsigned long)client->id);
        break;
    }

    return 0; /* keep client alive */
}

/* ── eBPF event handler ───────────────────────────────────────────── */
static void on_ebpf_event(const claw_ebpf_event_t *ev, void *ud)
{
    (void)ud;
    log_debug("eBPF event type=%d pid=%u comm=%s path=%s",
              ev->type, ev->pid, ev->comm, ev->path);
    /* TODO: match ev->path against skill trigger_event patterns */
}

/* ── Usage ────────────────────────────────────────────────────────── */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  -c <dir>    Config dir (default: " CLAW_CONFIG_DIR ")\n"
        "  -s <dir>    Skill dir  (default: " CLAW_SKILL_DIR ")\n"
        "  -m <model>  Default model (default: llama3.2)\n"
        "  -v          Increase verbosity\n"
        "  -h          Show this help\n",
        prog);
}

/* ── Entry point ──────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    claw_daemon_t *d = &g_daemon;
    memset(d, 0, sizeof(*d));

    strncpy(d->config_dir, CLAW_CONFIG_DIR, sizeof(d->config_dir)-1);
    strncpy(d->skill_dir,  CLAW_SKILL_DIR,  sizeof(d->skill_dir)-1);
    snprintf(d->bpf_dir, sizeof(d->bpf_dir), "/usr/lib/claw/bpf");

    openlog("claw-daemon", LOG_PID | LOG_NDELAY, LOG_DAEMON);

    int opt;
    while ((opt = getopt(argc, argv, "c:s:m:vh")) != -1) {
        switch (opt) {
        case 'c': strncpy(d->config_dir, optarg, sizeof(d->config_dir)-1); break;
        case 's': strncpy(d->skill_dir,  optarg, sizeof(d->skill_dir)-1);  break;
        case 'm': strncpy(d->ollama.default_model, optarg,
                          sizeof(d->ollama.default_model)-1); break;
        case 'v': g_log_level--; if (g_log_level < CLAW_LOG_TRACE) g_log_level = CLAW_LOG_TRACE; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    /* Signals */
    struct sigaction sa = { .sa_handler = on_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Ollama */
    ollama_cfg_init(&d->ollama);
    ollama_cfg_from_env(&d->ollama);
    log_info("Ollama endpoint: %s", d->ollama.base_url);

    if (!ollama_ping(&d->ollama))
        log_warn("Ollama not reachable at %s — queries will fail", d->ollama.base_url);

    /* Skills */
    skill_registry_init(&d->skills, d->skill_dir);
    skill_registry_scan(&d->skills);

    /* IPC server */
    if (claw_server_init(&d->srv) < 0) {
        log_fatal("Failed to start IPC server");
        return 1;
    }

    /* eBPF hooks (optional, fails gracefully) */
    d->ebpf = claw_ebpf_init(d->bpf_dir, on_ebpf_event, d);

    /* curl global init */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* Notify systemd we're ready */
    sd_notify(0, "READY=1\nSTATUS=KernKlaw-Linux daemon running");

    log_info("claw-daemon started (pid=%d)", getpid());
    d->running = 1;

    /* ── Main event loop ─────────────────────────────────────────── */
    while (d->running && !g_sigterm) {
        int rc = claw_server_poll(&d->srv, 1000 /* ms */, handle_message, d);
        if (rc < 0 && rc != -EINTR) {
            log_error("claw_server_poll: %d", rc);
            break;
        }

        /* Poll eBPF ring-buffer */
        if (d->ebpf)
            claw_ebpf_poll(d->ebpf, 0);
    }

    log_info("claw-daemon shutting down");
    sd_notify(0, "STOPPING=1");

    /* Cleanup */
    claw_ebpf_destroy(d->ebpf);
    claw_server_destroy(&d->srv);
    skill_registry_free(&d->skills);
    curl_global_cleanup();
    closelog();

    return 0;
}
