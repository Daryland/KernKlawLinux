/* claw-shell.c — KernKlaw-Linux interactive REPL
 *
 * Features:
 *   • Readline-based input with history
 *   • Direct AI queries to claw-daemon via Unix socket
 *   • Workflow DSL execution (inline or from file)
 *   • Skill listing / invocation
 *   • Streaming output (token-by-token)
 *   • Tab completion (skills, commands)
 *   • Offline mode when daemon is unavailable
 */
#define _GNU_SOURCE
#define CLAW_LOG_IMPL

#include "../common/proto.h"
#include "../common/log.h"
#include "../common/json_utils.h"
#include "../daemon/ipc.h"
#include "workflow.h"
#include "parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <readline/readline.h>
#include <readline/history.h>
#include <json-c/json.h>

/* ── Shell state ──────────────────────────────────────────────────── */
typedef struct {
    int        daemon_fd;
    wf_ctx_t   wf;
    uint64_t   req_id;
    char       model[64];
    int        verbose;
    char       history_file[256];
    int        running;
} shell_t;

static shell_t g_shell;

/* ── Readline completion ───────────────────────────────────────────── */
static const char *shell_commands[] = {
    "/ask", "/skill", "/skills", "/workflow", "/run", "/status",
    "/model", "/history", "/quit", "/exit", "/help",
    "ask", "skill", "let", "print", "loop", "if",
    NULL
};

static char *shell_completion_gen(const char *text, int state)
{
    static int idx;
    static size_t tlen;
    if (state == 0) { idx = 0; tlen = strlen(text); }
    while (shell_commands[idx]) {
        const char *cmd = shell_commands[idx++];
        if (strncmp(cmd, text, tlen) == 0) return strdup(cmd);
    }
    return NULL;
}

static char **shell_completion(const char *text, int start, int end)
{
    (void)start; (void)end;
    rl_attempted_completion_over = 1;
    return rl_completion_matches(text, shell_completion_gen);
}

/* ── Banner ───────────────────────────────────────────────────────── */
static void print_banner(void)
{
    printf("\n"
           "  ╔═══════════════════════════════════╗\n"
           "  ║  KernKlaw-Linux Shell v0.1.0      ║\n"
           "  ║  Type /help for commands           ║\n"
           "  ╚═══════════════════════════════════╝\n\n");
}

static void print_help(void)
{
    printf(
        "Shell commands:\n"
        "  /ask <question>        — Ask the AI a question\n"
        "  /skills                — List installed skills\n"
        "  /skill <name> [args]   — Run a skill\n"
        "  /workflow <file>       — Run a workflow file\n"
        "  /run <file>            — Alias for /workflow\n"
        "  /status                — Show daemon status\n"
        "  /model [name]          — Get/set default model\n"
        "  /verbose               — Toggle verbose mode\n"
        "  /quit, /exit           — Exit shell\n"
        "\n"
        "Inline DSL (multi-line, end with 'end'):\n"
        "  > ask \"What is Linux?\"\n"
        "  > let greeting = \"Hello\"\n"
        "  > skill echo msg=\"hi\"\n"
        "  > print greeting\n"
        "  > loop 3 { print \"iter \" + _i }\n"
        "  > ! ls -la\n"
        "\n"
        "Direct queries: just type your question and press Enter.\n"
    );
}

/* ── Send a query and stream the response ─────────────────────────── */
static void do_ask(shell_t *sh, const char *prompt)
{
    if (sh->daemon_fd < 0) {
        fprintf(stderr, "[offline] daemon not connected\n");
        return;
    }

    uint64_t id = sh->req_id++;
    struct json_object *q = claw_json_query(id, prompt, sh->model);
    char *qs = claw_json_to_str(q);
    json_object_put(q);

    if (claw_client_send(sh->daemon_fd, CLAW_MSG_QUERY, qs, strlen(qs)) < 0) {
        fprintf(stderr, "[error] send failed: %m\n");
        free(qs);
        return;
    }
    free(qs);

    printf("\n");
    for (;;) {
        claw_msg_type_t type;
        char  *payload = NULL;
        size_t plen    = 0;

        if (claw_client_recv(sh->daemon_fd, &type, &payload, &plen) < 0) {
            fprintf(stderr, "\n[error] recv failed\n");
            break;
        }

        if (type == CLAW_MSG_STREAM_CHUNK) {
            struct json_object *j = claw_json_from_buf(payload, plen);
            const char *chunk = claw_json_str(j, CLAW_F_CONTENT);
            if (chunk) { printf("%s", chunk); fflush(stdout); }
            if (j) json_object_put(j);
        } else if (type == CLAW_MSG_STREAM_END) {
            printf("\n");
            free(payload);
            break;
        } else if (type == CLAW_MSG_ERROR) {
            struct json_object *j = claw_json_from_buf(payload, plen);
            fprintf(stderr, "[error] %s\n", claw_json_str(j, CLAW_F_ERROR));
            if (j) json_object_put(j);
            free(payload);
            break;
        }
        free(payload);
    }
}

/* ── /skills ──────────────────────────────────────────────────────── */
static void do_list_skills(shell_t *sh)
{
    if (sh->daemon_fd < 0) { fprintf(stderr, "[offline]\n"); return; }
    if (claw_client_send(sh->daemon_fd, CLAW_MSG_SKILL_LIST, NULL, 0) < 0) return;

    claw_msg_type_t type;
    char *payload = NULL; size_t plen = 0;
    if (claw_client_recv(sh->daemon_fd, &type, &payload, &plen) < 0) return;

    struct json_object *arr = claw_json_from_buf(payload, plen);
    free(payload);
    if (!arr) { printf("[no skills]\n"); return; }

    int n = (int)json_object_array_length(arr);
    printf("%-20s %-8s %-40s\n", "NAME", "TYPE", "DESCRIPTION");
    printf("%-20s %-8s %-40s\n", "────────────────────",
           "────────", "────────────────────────────────────────");
    for (int i = 0; i < n; i++) {
        struct json_object *s = json_object_array_get_idx(arr, i);
        printf("%-20s %-8s %-40s\n",
               claw_json_str(s, "name"),
               claw_json_str(s, "type"),
               claw_json_str(s, "description"));
    }
    json_object_put(arr);
}

/* ── /status ──────────────────────────────────────────────────────── */
static void do_status(shell_t *sh)
{
    if (sh->daemon_fd < 0) { printf("daemon: disconnected\n"); return; }
    if (claw_client_send(sh->daemon_fd, CLAW_MSG_STATUS, NULL, 0) < 0) return;

    claw_msg_type_t type;
    char *payload = NULL; size_t plen = 0;
    if (claw_client_recv(sh->daemon_fd, &type, &payload, &plen) < 0) return;

    struct json_object *j = claw_json_from_buf(payload, plen);
    free(payload);
    if (!j) return;
    printf("daemon status:\n");
    printf("  version:  %s\n", claw_json_str(j, "version"));
    printf("  skills:   %lld\n", (long long)claw_json_int(j, "skills", 0));
    printf("  eBPF:     %s\n",   claw_json_bool(j, "ebpf", false) ? "yes" : "no");
    printf("  ollama:   %s\n",   claw_json_str(j, "ollama_url"));
    printf("  model:    %s\n",   claw_json_str(j, "model"));
    json_object_put(j);
}

/* ── /skill exec ──────────────────────────────────────────────────── */
static void do_skill(shell_t *sh, const char *line)
{
    /* line: "skill_name [key=val ...]" */
    if (sh->daemon_fd < 0) { fprintf(stderr, "[offline]\n"); return; }

    char name[64] = {0};
    const char *rest = line;
    while (*rest && !(*rest == ' ' || *rest == '\t')) rest++;
    size_t nlen = (size_t)(rest - line);
    if (nlen >= sizeof(name)) nlen = sizeof(name)-1;
    strncpy(name, line, nlen);
    while (*rest == ' ' || *rest == '\t') rest++;

    /* Build args JSON from key=val pairs */
    struct json_object *args = json_object_new_object();
    char *tmp = strdup(rest);
    char *tok = strtok(tmp, " \t");
    while (tok) {
        char *eq = strchr(tok, '=');
        if (eq) {
            *eq = '\0';
            json_object_object_add(args, tok, json_object_new_string(eq+1));
        }
        tok = strtok(NULL, " \t");
    }
    free(tmp);

    uint64_t rid = sh->req_id++;
    struct json_object *req = claw_json_skill_exec(rid, name, args);
    json_object_put(args);
    char *s = claw_json_to_str(req);
    json_object_put(req);
    claw_client_send(sh->daemon_fd, CLAW_MSG_SKILL_EXEC, s, strlen(s));
    free(s);

    claw_msg_type_t type;
    char *payload = NULL; size_t plen = 0;
    if (claw_client_recv(sh->daemon_fd, &type, &payload, &plen) < 0) return;
    struct json_object *j = claw_json_from_buf(payload, plen);
    free(payload);
    if (!j) return;
    if (type == CLAW_MSG_ERROR) printf("[error] %s\n", claw_json_str(j, CLAW_F_ERROR));
    else                         printf("%s\n",         claw_json_str(j, CLAW_F_RESULT));
    json_object_put(j);
}

/* ── Multi-line DSL collector ─────────────────────────────────────── */
static void do_dsl_repl(shell_t *sh)
{
    /* Collect lines until bare "end" or empty line after content */
    char *src = strdup("");
    size_t srclen = 0;

    for (;;) {
        char *line = readline("  ... ");
        if (!line) break;
        if (strcmp(line, "end") == 0) { free(line); break; }

        size_t llen = strlen(line);
        char *tmp = realloc(src, srclen + llen + 2);
        if (!tmp) { free(line); break; }
        src = tmp;
        memcpy(src + srclen, line, llen);
        src[srclen + llen]     = '\n';
        src[srclen + llen + 1] = '\0';
        srclen += llen + 1;
        free(line);
    }

    if (srclen > 0)
        wf_exec_str(&sh->wf, src, srclen);
    free(src);
}

/* ── Command dispatcher ───────────────────────────────────────────── */
static int dispatch(shell_t *sh, const char *line)
{
    /* Skip leading whitespace */
    while (*line == ' ' || *line == '\t') line++;
    if (!*line) return 0;

    /* Workflow DSL keywords → enter multi-line mode */
    if (strncmp(line, "ask ", 4)  == 0 ||
        strncmp(line, "let ", 4)  == 0 ||
        strncmp(line, "loop ", 5) == 0 ||
        strncmp(line, "print ", 6)== 0 ||
        strncmp(line, "skill ", 6)== 0 ||
        line[0] == '!') {
        wf_exec_str(&sh->wf, line, strlen(line));
        return 0;
    }

    if (strcmp(line, "workflow") == 0) {
        do_dsl_repl(sh);
        return 0;
    }

    if (!strncmp(line, "/ask ", 5) || !strncmp(line, "/ask\t", 5)) {
        do_ask(sh, line + 5);
        return 0;
    }
    if (strcmp(line, "/skills") == 0) { do_list_skills(sh); return 0; }
    if (strcmp(line, "/status") == 0) { do_status(sh); return 0; }
    if (!strncmp(line, "/skill ", 7)) { do_skill(sh, line + 7); return 0; }
    if (!strncmp(line, "/workflow ", 10) || !strncmp(line, "/run ", 5)) {
        const char *path = strchr(line, ' ') + 1;
        wf_exec_file(&sh->wf, path);
        return 0;
    }
    if (!strncmp(line, "/model", 6)) {
        if (line[6] == ' ') { strncpy(sh->model, line+7, sizeof(sh->model)-1); printf("model: %s\n", sh->model); }
        else                  printf("current model: %s\n", sh->model);
        return 0;
    }
    if (strcmp(line, "/verbose") == 0) {
        sh->wf.verbose ^= 1;
        printf("verbose: %s\n", sh->wf.verbose ? "on" : "off");
        return 0;
    }
    if (strcmp(line, "/help") == 0) { print_help(); return 0; }
    if (strcmp(line, "/quit") == 0 || strcmp(line, "/exit") == 0 ||
        strcmp(line, "quit")  == 0 || strcmp(line, "exit")  == 0)
        return -1; /* signal exit */

    /* Anything else → treat as a direct AI query */
    do_ask(sh, line);
    return 0;
}

/* ── Signal handling ──────────────────────────────────────────────── */
static void on_sigint(int sig) { (void)sig; printf("\n"); rl_on_new_line(); rl_replace_line("", 0); rl_redisplay(); }

/* ── Usage ────────────────────────────────────────────────────────── */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] [workflow.claw]\n"
        "  -s <socket>  Daemon socket (default: " CLAW_DAEMON_SOCK ")\n"
        "  -m <model>   Default AI model\n"
        "  -v           Verbose output\n"
        "  -h           Help\n",
        prog);
}

/* ── Entry point ──────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    shell_t *sh = &g_shell;
    memset(sh, 0, sizeof(*sh));
    sh->daemon_fd = -1;
    strncpy(sh->model, "llama3.2", sizeof(sh->model)-1);

    const char *sock_path = CLAW_DAEMON_SOCK;
    const char *workflow_file = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "s:m:vh")) != -1) {
        switch (opt) {
        case 's': sock_path = optarg; break;
        case 'm': strncpy(sh->model, optarg, sizeof(sh->model)-1); break;
        case 'v': sh->verbose = 1; g_log_level = CLAW_LOG_DEBUG; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }
    if (optind < argc) workflow_file = argv[optind];

    /* Connect to daemon */
    sh->daemon_fd = claw_client_connect(sock_path);
    if (sh->daemon_fd < 0)
        fprintf(stderr, "[warn] daemon not available (%s) — offline mode\n", sock_path);

    /* Init workflow context */
    wf_ctx_init(&sh->wf, sh->daemon_fd);
    sh->wf.verbose = sh->verbose;

    /* Run workflow file if given */
    if (workflow_file) {
        int rc = wf_exec_file(&sh->wf, workflow_file);
        wf_ctx_free(&sh->wf);
        if (sh->daemon_fd >= 0) close(sh->daemon_fd);
        return rc < 0 ? 1 : 0;
    }

    /* Readline setup */
    rl_attempted_completion_function = shell_completion;
    rl_bind_key('\t', rl_complete);

    const char *home = getenv("HOME");
    if (home) {
        snprintf(sh->history_file, sizeof(sh->history_file),
                 "%s/.claw_history", home);
        read_history(sh->history_file);
    }

    signal(SIGINT, on_sigint);
    signal(SIGPIPE, SIG_IGN);

    print_banner();
    if (sh->daemon_fd >= 0) do_status(sh);
    else printf("[offline mode]\n\n");

    /* ── REPL ───────────────────────────────────────────────────── */
    sh->running = 1;
    while (sh->running) {
        char *line = readline("\001\033[1;32m\002claw\001\033[0m\002> ");
        if (!line) { printf("\n"); break; }   /* Ctrl-D */

        if (*line) {
            add_history(line);
            if (dispatch(sh, line) < 0) {
                free(line);
                break;
            }
        }
        free(line);
    }

    /* Save history */
    if (sh->history_file[0])
        write_history(sh->history_file);

    wf_ctx_free(&sh->wf);
    if (sh->daemon_fd >= 0) close(sh->daemon_fd);
    printf("Goodbye.\n");
    return 0;
}
