/* workflow.h — AST interpreter for Lobster-inspired workflow DSL */
#pragma once
#ifndef CLAW_WORKFLOW_H
#define CLAW_WORKFLOW_H

#include "parser.h"
#include <stddef.h>

#define WF_MAX_VARS   128
#define WF_VAR_MAXLEN 4096

/* ── Runtime variable ─────────────────────────────────────────────── */
typedef enum { VAR_STR, VAR_NUM } var_type_t;

typedef struct {
    char       name[64];
    var_type_t type;
    char      *sval;    /* heap */
    double     nval;
} wf_var_t;

/* ── Execution context ────────────────────────────────────────────── */
typedef struct {
    wf_var_t   vars[WF_MAX_VARS];
    int        nvars;
    int        daemon_fd;       /* connected Unix socket (-1 = offline)  */
    uint64_t   next_req_id;
    int        verbose;
} wf_ctx_t;

/* ── API ──────────────────────────────────────────────────────────── */

/* Initialise context; daemon_fd = -1 to run offline */
void wf_ctx_init(wf_ctx_t *ctx, int daemon_fd);
void wf_ctx_free(wf_ctx_t *ctx);

/* Get / set variables */
const char *wf_var_get(const wf_ctx_t *ctx, const char *name);
void        wf_var_set(wf_ctx_t *ctx, const char *name, const char *val);

/* Execute a workflow AST. Returns 0 on success. */
int wf_exec(wf_ctx_t *ctx, const ast_node_t *root);

/* Parse and execute a workflow file */
int wf_exec_file(wf_ctx_t *ctx, const char *path);

/* Parse and execute a workflow string */
int wf_exec_str(wf_ctx_t *ctx, const char *src, size_t len);

#endif /* CLAW_WORKFLOW_H */
