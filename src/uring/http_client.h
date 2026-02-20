/* http_client.h — io_uring-based async HTTP/1.1 client
 *
 * Provides a lightweight HTTP client using Linux io_uring for
 * zero-syscall-overhead async I/O.  Designed for talking to
 * local services (Ollama, ClawHub API) at high throughput.
 *
 * Requirements: liburing, kernel ≥ 5.6
 */
#pragma once
#ifndef CLAW_HTTP_CLIENT_H
#define CLAW_HTTP_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define URING_QUEUE_DEPTH  64
#define HTTP_MAX_HEADERS   32
#define HTTP_MAX_URL       512
#define HTTP_BUF_SIZE      (256 * 1024)  /* 256 KiB */

/* ── HTTP request ─────────────────────────────────────────────────── */
typedef struct {
    char        method[8];         /* GET, POST, etc. */
    char        url[HTTP_MAX_URL];
    char       *headers[HTTP_MAX_HEADERS];
    int         nheaders;
    const char *body;
    size_t      body_len;
    long        timeout_ms;
} http_req_t;

/* ── HTTP response ────────────────────────────────────────────────── */
typedef struct {
    int    status_code;
    char  *body;          /* heap-alloc'd, caller free()s */
    size_t body_len;
    int    error;         /* negative errno on failure   */
} http_resp_t;

/* ── Streaming callback ───────────────────────────────────────────── */
typedef void (*http_chunk_cb)(const char *data, size_t len, void *userdata);
typedef void (*http_done_cb)(int status, int error, void *userdata);

/* ── io_uring context ─────────────────────────────────────────────── */
typedef struct uring_http_ctx uring_http_ctx_t;

/* Create a context (one per thread is recommended) */
uring_http_ctx_t *uring_http_init(int queue_depth);
void               uring_http_destroy(uring_http_ctx_t *ctx);

/* ── Blocking request (wraps async internals) ─────────────────────── */
http_resp_t uring_http_request(uring_http_ctx_t *ctx,
                                const http_req_t *req);

/* ── Streaming POST ───────────────────────────────────────────────── */
int uring_http_post_stream(uring_http_ctx_t *ctx,
                            const char *url,
                            const char *body, size_t body_len,
                            http_chunk_cb on_chunk,
                            http_done_cb  on_done,
                            void *userdata);

/* ── Quick helpers ────────────────────────────────────────────────── */
http_resp_t uring_http_get(uring_http_ctx_t *ctx, const char *url);
http_resp_t uring_http_post_json(uring_http_ctx_t *ctx,
                                  const char *url,
                                  const char *json_body);

void http_resp_free(http_resp_t *r);

/* ── Capability check ─────────────────────────────────────────────── */
bool uring_available(void);   /* returns true if kernel supports io_uring */

#endif /* CLAW_HTTP_CLIENT_H */
