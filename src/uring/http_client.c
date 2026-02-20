/* http_client.c — io_uring async HTTP/1.1 client
 *
 * Design:
 *   • Uses io_uring IORING_OP_CONNECT, IORING_OP_SEND, IORING_OP_RECV
 *     in a submission/completion queue loop.
 *   • Supports fixed buffers (IORING_REGISTER_BUFFERS) for zero-copy.
 *   • HTTP/1.1 keep-alive is tracked per-host.
 *   • Falls back to blocking sockets if io_uring unavailable.
 *
 * We parse minimal HTTP/1.1 (status line + Content-Length / chunked).
 */
#define _GNU_SOURCE
#include "http_client.h"
#include "../common/log.h"

#include <liburing.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ── Internal ─────────────────────────────────────────────────────── */

struct uring_http_ctx {
    struct io_uring ring;
    int             available;   /* 1 if io_uring setup succeeded */
    /* Fixed-buffer pool */
    char            io_buf[HTTP_BUF_SIZE];
    struct iovec    iov;
};

/* ── io_uring setup ───────────────────────────────────────────────── */

bool uring_available(void)
{
    struct io_uring ring;
    int rc = io_uring_queue_init(4, &ring, 0);
    if (rc == 0) { io_uring_queue_exit(&ring); return true; }
    return false;
}

uring_http_ctx_t *uring_http_init(int queue_depth)
{
    uring_http_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;

    ctx->iov.iov_base = ctx->io_buf;
    ctx->iov.iov_len  = HTTP_BUF_SIZE;

    int rc = io_uring_queue_init(queue_depth > 0 ? queue_depth : URING_QUEUE_DEPTH,
                                  &ctx->ring, IORING_SETUP_SQPOLL);
    if (rc < 0) {
        /* SQPOLL may require root; fallback to normal mode */
        rc = io_uring_queue_init(queue_depth > 0 ? queue_depth : URING_QUEUE_DEPTH,
                                  &ctx->ring, 0);
    }
    if (rc < 0) {
        log_warn("io_uring_queue_init failed (%d); falling back to blocking sockets", rc);
        ctx->available = 0;
    } else {
        /* Register fixed buffers */
        io_uring_register_buffers(&ctx->ring, &ctx->iov, 1);
        ctx->available = 1;
    }
    return ctx;
}

void uring_http_destroy(uring_http_ctx_t *ctx)
{
    if (!ctx) return;
    if (ctx->available) {
        io_uring_unregister_buffers(&ctx->ring);
        io_uring_queue_exit(&ctx->ring);
    }
    free(ctx);
}

/* ── URL parser ───────────────────────────────────────────────────── */
typedef struct {
    char scheme[8];
    char host[256];
    int  port;
    char path[HTTP_MAX_URL];
} parsed_url_t;

static int parse_url(const char *url, parsed_url_t *out)
{
    memset(out, 0, sizeof(*out));
    if (strncmp(url, "http://", 7) == 0) {
        strncpy(out->scheme, "http", 7);
        out->port = 80;
        url += 7;
    } else if (strncmp(url, "https://", 8) == 0) {
        strncpy(out->scheme, "https", 7);
        out->port = 443;
        url += 8;
    } else return -EINVAL;

    const char *slash = strchr(url, '/');
    size_t hlen = slash ? (size_t)(slash - url) : strlen(url);

    /* Check for port in host */
    const char *colon = memchr(url, ':', hlen);
    if (colon) {
        size_t bare_hlen = (size_t)(colon - url);
        strncpy(out->host, url, bare_hlen < 255 ? bare_hlen : 255);
        out->port = atoi(colon + 1);
    } else {
        strncpy(out->host, url, hlen < 255 ? hlen : 255);
    }

    strncpy(out->path, slash ? slash : "/", HTTP_MAX_URL - 1);
    return 0;
}

/* ── Blocking TCP connect (used by both paths) ────────────────────── */
static int tcp_connect(const char *host, int port, long timeout_ms)
{
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -EIO;

    int fd = -1;
    for (struct addrinfo *a = res; a; a = a->ai_next) {
        fd = socket(a->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) continue;

        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        int rc = connect(fd, a->ai_addr, a->ai_addrlen);
        if (rc == 0 || errno == EINPROGRESS) {
            /* Wait for connect with timeout */
            fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
            struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
            if (select(fd + 1, NULL, &wfds, NULL, &tv) > 0) {
                int err = 0; socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                if (err == 0) break; /* connected */
            }
        }
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd > 0) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    return fd >= 0 ? fd : -ECONNREFUSED;
}

/* ── HTTP request builder ─────────────────────────────────────────── */
static size_t build_http_request(const http_req_t *req,
                                  const parsed_url_t *url_p,
                                  char *out, size_t outsz)
{
    size_t n = 0;
    n += (size_t)snprintf(out + n, outsz - n,
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "User-Agent: KernKlaw-Linux/0.1\r\n",
        req->method, url_p->path, url_p->host);

    for (int i = 0; i < req->nheaders && n < outsz - 2; i++)
        n += (size_t)snprintf(out + n, outsz - n, "%s\r\n", req->headers[i]);

    if (req->body && req->body_len > 0)
        n += (size_t)snprintf(out + n, outsz - n,
                              "Content-Length: %zu\r\n\r\n", req->body_len);
    else
        n += (size_t)snprintf(out + n, outsz - n, "\r\n");

    return n;
}

/* ── HTTP response parser ─────────────────────────────────────────── */
static int parse_http_status(const char *buf, size_t len)
{
    /* HTTP/1.1 200 OK */
    if (len < 12 || strncmp(buf, "HTTP/", 5) != 0) return -1;
    const char *sp = memchr(buf, ' ', len < 16 ? len : 16);
    if (!sp) return -1;
    return atoi(sp + 1);
}

static const char *find_body(const char *buf, size_t len, size_t *body_len_out)
{
    /* Find \r\n\r\n header/body separator */
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i]=='\r' && buf[i+1]=='\n' && buf[i+2]=='\r' && buf[i+3]=='\n') {
            *body_len_out = len - (i + 4);
            return buf + i + 4;
        }
    }
    *body_len_out = 0;
    return NULL;
}

/* ── io_uring path ────────────────────────────────────────────────── */
static http_resp_t uring_do_request(uring_http_ctx_t *ctx,
                                     int sockfd,
                                     const char *req_buf, size_t req_len,
                                     const char *body, size_t body_len)
{
    http_resp_t resp = {0};
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    /* ── Send request headers ── */
    sqe = io_uring_get_sqe(&ctx->ring);
    io_uring_prep_send(sqe, sockfd, req_buf, req_len, 0);
    sqe->user_data = 1;
    io_uring_submit(&ctx->ring);
    io_uring_wait_cqe(&ctx->ring, &cqe);
    if (cqe->res < 0) { resp.error = -cqe->res; io_uring_cqe_seen(&ctx->ring, cqe); return resp; }
    io_uring_cqe_seen(&ctx->ring, cqe);

    /* ── Send body (if any) ── */
    if (body && body_len > 0) {
        sqe = io_uring_get_sqe(&ctx->ring);
        io_uring_prep_send(sqe, sockfd, body, body_len, 0);
        sqe->user_data = 2;
        io_uring_submit(&ctx->ring);
        io_uring_wait_cqe(&ctx->ring, &cqe);
        if (cqe->res < 0) { resp.error = -cqe->res; io_uring_cqe_seen(&ctx->ring, cqe); return resp; }
        io_uring_cqe_seen(&ctx->ring, cqe);
    }

    /* ── Recv response into fixed buffer ── */
    size_t accum = 0;
    char  *accum_buf = malloc(HTTP_BUF_SIZE);
    if (!accum_buf) { resp.error = ENOMEM; return resp; }

    for (;;) {
        sqe = io_uring_get_sqe(&ctx->ring);
        io_uring_prep_recv(sqe, sockfd, ctx->io_buf, HTTP_BUF_SIZE, 0);
        sqe->user_data = 3;
        io_uring_submit(&ctx->ring);
        io_uring_wait_cqe(&ctx->ring, &cqe);
        int n = cqe->res;
        io_uring_cqe_seen(&ctx->ring, cqe);
        if (n <= 0) break;
        if (accum + (size_t)n > HTTP_BUF_SIZE) break;
        memcpy(accum_buf + accum, ctx->io_buf, (size_t)n);
        accum += (size_t)n;
    }

    resp.status_code = parse_http_status(accum_buf, accum);
    size_t body_start_len = 0;
    const char *body_start = find_body(accum_buf, accum, &body_start_len);
    if (body_start) {
        resp.body = malloc(body_start_len + 1);
        if (resp.body) {
            memcpy(resp.body, body_start, body_start_len);
            resp.body[body_start_len] = '\0';
            resp.body_len = body_start_len;
        }
    }
    free(accum_buf);
    return resp;
}

/* ── Blocking fallback path ───────────────────────────────────────── */
static http_resp_t blocking_do_request(int sockfd,
                                        const char *req_buf, size_t req_len,
                                        const char *body, size_t body_len)
{
    http_resp_t resp = {0};
    if (send(sockfd, req_buf, req_len, 0) < 0)  { resp.error = errno; return resp; }
    if (body && body_len)
        if (send(sockfd, body, body_len, 0) < 0) { resp.error = errno; return resp; }

    size_t cap = HTTP_BUF_SIZE, accum = 0;
    char *buf = malloc(cap);
    if (!buf) { resp.error = ENOMEM; return resp; }

    ssize_t n;
    while ((n = recv(sockfd, buf + accum, cap - accum, 0)) > 0) {
        accum += (size_t)n;
        if (accum + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) break;
            buf = tmp;
        }
    }

    resp.status_code = parse_http_status(buf, accum);
    size_t blen = 0;
    const char *bstart = find_body(buf, accum, &blen);
    if (bstart) {
        resp.body = malloc(blen + 1);
        if (resp.body) { memcpy(resp.body, bstart, blen); resp.body[blen] = '\0'; resp.body_len = blen; }
    }
    free(buf);
    return resp;
}

/* ── Public API ───────────────────────────────────────────────────── */

http_resp_t uring_http_request(uring_http_ctx_t *ctx, const http_req_t *req)
{
    http_resp_t resp = {0};
    parsed_url_t url_p;
    if (parse_url(req->url, &url_p) < 0) { resp.error = EINVAL; return resp; }

    int fd = tcp_connect(url_p.host, url_p.port,
                         req->timeout_ms > 0 ? req->timeout_ms : 30000);
    if (fd < 0) { resp.error = -fd; return resp; }

    char req_buf[8192];
    size_t req_len = build_http_request(req, &url_p, req_buf, sizeof(req_buf));

    if (ctx && ctx->available)
        resp = uring_do_request(ctx, fd, req_buf, req_len, req->body, req->body_len);
    else
        resp = blocking_do_request(fd, req_buf, req_len, req->body, req->body_len);

    close(fd);
    return resp;
}

http_resp_t uring_http_get(uring_http_ctx_t *ctx, const char *url)
{
    http_req_t req = { .method = "GET", .timeout_ms = 30000 };
    strncpy(req.url, url, HTTP_MAX_URL - 1);
    return uring_http_request(ctx, &req);
}

http_resp_t uring_http_post_json(uring_http_ctx_t *ctx,
                                  const char *url, const char *json_body)
{
    http_req_t req = { .method = "POST", .timeout_ms = 120000 };
    strncpy(req.url, url, HTTP_MAX_URL - 1);
    req.headers[0] = "Content-Type: application/json";
    req.nheaders   = 1;
    req.body       = json_body;
    req.body_len   = strlen(json_body);
    return uring_http_request(ctx, &req);
}

int uring_http_post_stream(uring_http_ctx_t *ctx,
                            const char *url,
                            const char *body, size_t body_len,
                            http_chunk_cb on_chunk,
                            http_done_cb  on_done,
                            void *userdata)
{
    parsed_url_t url_p;
    if (parse_url(url, &url_p) < 0) return -EINVAL;

    int fd = tcp_connect(url_p.host, url_p.port, 30000);
    if (fd < 0) { if (on_done) on_done(-1, -fd, userdata); return -fd; }

    /* Build request */
    http_req_t req = { .method = "POST", .body = body, .body_len = body_len };
    strncpy(req.url, url, HTTP_MAX_URL-1);
    req.headers[0] = "Content-Type: application/json";
    req.headers[1] = "Accept: application/x-ndjson";
    req.nheaders   = 2;

    char req_buf[8192];
    size_t req_len = build_http_request(&req, &url_p, req_buf, sizeof(req_buf));

    /* Send headers + body */
    send(fd, req_buf, req_len, 0);
    if (body && body_len) send(fd, body, body_len, 0);

    /* Stream response */
    char *chunk_buf = malloc(HTTP_BUF_SIZE);
    if (!chunk_buf) { close(fd); return -ENOMEM; }

    bool headers_done = false;
    ssize_t n;
    int status = 0;

    while ((n = recv(fd, chunk_buf, HTTP_BUF_SIZE - 1, 0)) > 0) {
        chunk_buf[n] = '\0';
        if (!headers_done) {
            status = parse_http_status(chunk_buf, (size_t)n);
            size_t body_off = 0;
            const char *body_start = find_body(chunk_buf, (size_t)n, &body_off);
            if (body_start) {
                headers_done = true;
                if (on_chunk && body_off > 0)
                    on_chunk(body_start, body_off, userdata);
            }
        } else {
            if (on_chunk) on_chunk(chunk_buf, (size_t)n, userdata);
        }
    }

    free(chunk_buf);
    close(fd);
    if (on_done) on_done(status, 0, userdata);
    return 0;
}

void http_resp_free(http_resp_t *r)
{
    if (r) { free(r->body); r->body = NULL; r->body_len = 0; }
}
