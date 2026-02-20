/* workflow.c — Tree-walking interpreter for the Lobster DSL */
#define _GNU_SOURCE
#include "workflow.h"
#include "parser.h"
#include "../common/proto.h"
#include "../common/log.h"
#include "../daemon/ipc.h"
#include "../common/json_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

/* ── Context ──────────────────────────────────────────────────────── */

void wf_ctx_init(wf_ctx_t *ctx, int daemon_fd)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->daemon_fd   = daemon_fd;
    ctx->next_req_id = 1;
}

void wf_ctx_free(wf_ctx_t *ctx)
{
    for (int i = 0; i < ctx->nvars; i++) free(ctx->vars[i].sval);
    ctx->nvars = 0;
}

const char *wf_var_get(const wf_ctx_t *ctx, const char *name)
{
    for (int i = 0; i < ctx->nvars; i++)
        if (strcmp(ctx->vars[i].name, name) == 0)
            return ctx->vars[i].sval ? ctx->vars[i].sval : "";
    return NULL;
}

void wf_var_set(wf_ctx_t *ctx, const char *name, const char *val)
{
    /* Update existing */
    for (int i = 0; i < ctx->nvars; i++) {
        if (strcmp(ctx->vars[i].name, name) == 0) {
            free(ctx->vars[i].sval);
            ctx->vars[i].sval = val ? strdup(val) : NULL;
            ctx->vars[i].type = VAR_STR;
            return;
        }
    }
    /* Insert new */
    if (ctx->nvars >= WF_MAX_VARS) {
        log_warn("wf: variable table full, dropping '%s'", name);
        return;
    }
    wf_var_t *v = &ctx->vars[ctx->nvars++];
    strncpy(v->name, name, sizeof(v->name)-1);
    v->sval = val ? strdup(val) : NULL;
    v->type = VAR_STR;
}

/* ── Expression evaluator ─────────────────────────────────────────── */

/* Returns heap-alloc'd string (caller free()s) */
static char *eval_expr(wf_ctx_t *ctx, const ast_node_t *n)
{
    if (!n) return strdup("");

    switch (n->type) {
    case AST_STRING:
        return strdup(n->sval ? n->sval : "");

    case AST_NUMBER: {
        char buf[64];
        if (n->nval == (long long)n->nval)
            snprintf(buf, sizeof(buf), "%lld", (long long)n->nval);
        else
            snprintf(buf, sizeof(buf), "%.6g", n->nval);
        return strdup(buf);
    }

    case AST_IDENT: {
        const char *v = wf_var_get(ctx, n->sval ? n->sval : "");
        return strdup(v ? v : "");
    }

    case AST_BINOP: {
        if (n->sval && strcmp(n->sval, "+") == 0) {
            char *l = eval_expr(ctx, n->left);
            char *r = eval_expr(ctx, n->right);
            size_t len = strlen(l) + strlen(r) + 1;
            char *res = malloc(len);
            snprintf(res, len, "%s%s", l, r);
            free(l); free(r);
            return res;
        }
        return strdup("");
    }

    default:
        return strdup("");
    }
}

/* ── AI query via daemon socket ───────────────────────────────────── */
static char *query_daemon(wf_ctx_t *ctx, const char *prompt)
{
    if (ctx->daemon_fd < 0) {
        fprintf(stderr, "[offline] Would ask: %s\n", prompt);
        return strdup("[daemon not connected]");
    }

    uint64_t req_id = ctx->next_req_id++;
    struct json_object *q = claw_json_query(req_id, prompt, "");
    char *qstr = claw_json_to_str(q);
    json_object_put(q);

    if (claw_client_send(ctx->daemon_fd, CLAW_MSG_QUERY, qstr, strlen(qstr)) < 0) {
        free(qstr);
        return strdup("[send error]");
    }
    free(qstr);

    /* Accumulate streamed response */
    char *accum = strdup("");
    for (;;) {
        claw_msg_type_t type;
        char  *payload = NULL;
        size_t plen    = 0;

        if (claw_client_recv(ctx->daemon_fd, &type, &payload, &plen) < 0)
            break;

        if (type == CLAW_MSG_STREAM_CHUNK) {
            struct json_object *j = claw_json_from_buf(payload, plen);
            const char *chunk = claw_json_str(j, CLAW_F_CONTENT);
            if (chunk) {
                size_t newlen = strlen(accum) + strlen(chunk) + 1;
                char *tmp = realloc(accum, newlen);
                if (tmp) { accum = tmp; strcat(accum, chunk); }
            }
            if (j) json_object_put(j);
            if (ctx->verbose) { printf("%s", chunk ? chunk : ""); fflush(stdout); }
        } else if (type == CLAW_MSG_STREAM_END) {
            free(payload);
            break;
        }
        free(payload);
    }
    return accum;
}

/* ── Statement executor ───────────────────────────────────────────── */
static int exec_node(wf_ctx_t *ctx, const ast_node_t *n);

static int exec_block(wf_ctx_t *ctx, const ast_node_t *block)
{
    if (!block) return 0;
    for (int i = 0; i < block->nchildren; i++) {
        int rc = exec_node(ctx, block->children[i]);
        if (rc != 0) return rc;
    }
    return 0;
}

static int exec_node(wf_ctx_t *ctx, const ast_node_t *n)
{
    if (!n) return 0;

    switch (n->type) {

    case AST_ASK: {
        char *prompt = eval_expr(ctx, n->left);
        printf(">> %s\n", prompt);
        char *response = query_daemon(ctx, prompt);
        free(prompt);
        printf("%s\n", response);
        if (n->sval && *n->sval)          /* "into varname" */
            wf_var_set(ctx, n->sval, response);
        free(response);
        break;
    }

    case AST_SKILL: {
        if (ctx->daemon_fd < 0) {
            printf("[offline] Would run skill: %s\n", n->sval ? n->sval : "?");
            break;
        }
        /* Build args JSON from KV children */
        struct json_object *args = json_object_new_object();
        for (int i = 0; i < n->nchildren; i++) {
            const ast_node_t *kv = n->children[i];
            if (kv->type != AST_KVPAIR) continue;
            char *val = eval_expr(ctx, kv->left);
            json_object_object_add(args, kv->sval, json_object_new_string(val));
            free(val);
        }
        uint64_t rid = ctx->next_req_id++;
        struct json_object *req = claw_json_skill_exec(rid, n->sval, args);
        json_object_put(args);
        char *s = claw_json_to_str(req);
        json_object_put(req);
        claw_client_send(ctx->daemon_fd, CLAW_MSG_SKILL_EXEC, s, strlen(s));
        free(s);

        claw_msg_type_t type;
        char  *payload = NULL;
        size_t plen    = 0;
        if (claw_client_recv(ctx->daemon_fd, &type, &payload, &plen) == 0) {
            struct json_object *j = claw_json_from_buf(payload, plen);
            const char *result = claw_json_str(j, CLAW_F_RESULT);
            const char *err    = claw_json_str(j, CLAW_F_ERROR);
            if (err && *err)   printf("[skill error] %s\n", err);
            else if (result)   printf("%s\n", result);
            if (j) json_object_put(j);
            free(payload);
        }
        break;
    }

    case AST_LET: {
        char *val = eval_expr(ctx, n->left);
        wf_var_set(ctx, n->sval ? n->sval : "?", val);
        free(val);
        break;
    }

    case AST_IF: {
        /* Condition: non-empty string or non-zero number → truthy */
        char *cond_s = eval_expr(ctx, n->left);
        int truthy = (cond_s && *cond_s && strcmp(cond_s, "0") != 0 &&
                      strcmp(cond_s, "false") != 0);
        free(cond_s);
        if (truthy && n->nchildren >= 1)
            exec_block(ctx, n->children[0]);
        else if (!truthy && n->nchildren >= 2)
            exec_block(ctx, n->children[1]);
        break;
    }

    case AST_LOOP: {
        char *cnt_s = eval_expr(ctx, n->left);
        int cnt = cnt_s ? atoi(cnt_s) : 0;
        free(cnt_s);
        for (int i = 0; i < cnt; i++) {
            char ibuf[16]; snprintf(ibuf, sizeof(ibuf), "%d", i);
            wf_var_set(ctx, "_i", ibuf);
            if (n->nchildren >= 1) exec_block(ctx, n->children[0]);
        }
        break;
    }

    case AST_PRINT: {
        char *val = eval_expr(ctx, n->left);
        printf("%s\n", val);
        free(val);
        break;
    }

    case AST_SHELL: {
        char *cmd = eval_expr(ctx, n->left);
        int rc = system(cmd);
        free(cmd);
        (void)rc;
        break;
    }

    case AST_WORKFLOW:
        return exec_block(ctx, n);

    default:
        break;
    }
    return 0;
}

/* ── Public API ───────────────────────────────────────────────────── */

int wf_exec(wf_ctx_t *ctx, const ast_node_t *root)
{
    if (!root) return -EINVAL;
    return exec_node(ctx, root);
}

int wf_exec_str(wf_ctx_t *ctx, const char *src, size_t len)
{
    parser_t p;
    parser_init(&p, src, len);
    ast_node_t *root = parser_parse(&p);
    if (!root) {
        log_error("parse error: %s", p.errmsg);
        return -EINVAL;
    }
    int rc = wf_exec(ctx, root);
    ast_free(root);
    return rc;
}

int wf_exec_file(wf_ctx_t *ctx, const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { log_error("open %s: %m", path); return -errno; }

    off_t sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (sz <= 0) { close(fd); return -EINVAL; }

    char *buf = malloc((size_t)sz + 1);
    if (!buf) { close(fd); return -ENOMEM; }
    read(fd, buf, (size_t)sz);
    buf[sz] = '\0';
    close(fd);

    int rc = wf_exec_str(ctx, buf, (size_t)sz);
    free(buf);
    return rc;
}
