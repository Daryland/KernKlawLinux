/* ipc.c — Unix-socket IPC (epoll-based multi-client server + client stubs)
 *
 * Wire format: [claw_hdr_t (12 bytes)][payload bytes]
 * The server accumulates bytes per-client until a full message arrives,
 * then calls the user-supplied handler.
 */
#define _GNU_SOURCE
#include "ipc.h"
#include "../common/log.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

/* ── Helpers ──────────────────────────────────────────────────────── */

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -errno;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ? -errno : 0;
}

static int epoll_add(int epfd, int fd, uint32_t events, void *ptr)
{
    struct epoll_event ev = { .events = events, .data.ptr = ptr };
    return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0 ? -errno : 0;
}

static int epoll_del(int epfd, int fd)
{
    return epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL) < 0 ? -errno : 0;
}

/* ── Server ───────────────────────────────────────────────────────── */

int claw_server_init(claw_server_t *srv)
{
    memset(srv, 0, sizeof(*srv));

    /* Create state dir */
    mkdir(CLAW_STATE_DIR, 0755);

    /* Unlink stale socket */
    unlink(CLAW_DAEMON_SOCK);

    /* Create Unix domain socket */
    srv->listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (srv->listen_fd < 0) { log_error("socket: %m"); return -errno; }

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, CLAW_DAEMON_SOCK, sizeof(addr.sun_path)-1);

    if (bind(srv->listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("bind %s: %m", CLAW_DAEMON_SOCK);
        close(srv->listen_fd);
        return -errno;
    }
    chmod(CLAW_DAEMON_SOCK, 0660);

    if (listen(srv->listen_fd, 32) < 0) {
        log_error("listen: %m"); close(srv->listen_fd); return -errno;
    }
    set_nonblock(srv->listen_fd);

    /* epoll */
    srv->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->epoll_fd < 0) {
        log_error("epoll_create1: %m"); close(srv->listen_fd); return -errno;
    }

    /* Add listen socket; use NULL ptr as sentinel for "this is listener" */
    if (epoll_add(srv->epoll_fd, srv->listen_fd, EPOLLIN, NULL) < 0) {
        log_error("epoll_add listen: %m");
        close(srv->epoll_fd); close(srv->listen_fd); return -errno;
    }

    srv->next_id = 1;
    log_info("IPC server listening on %s", CLAW_DAEMON_SOCK);
    return 0;
}

static claw_client_t *client_new(claw_server_t *srv, int fd)
{
    if (srv->nclients >= CLAW_MAX_CLIENTS) return NULL;
    claw_client_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = fd;
    c->id = srv->next_id++;
    for (int i = 0; i < CLAW_MAX_CLIENTS; i++) {
        if (!srv->clients[i]) { srv->clients[i] = c; srv->nclients++; break; }
    }
    return c;
}

static void client_free(claw_server_t *srv, claw_client_t *c)
{
    for (int i = 0; i < CLAW_MAX_CLIENTS; i++) {
        if (srv->clients[i] == c) { srv->clients[i] = NULL; srv->nclients--; break; }
    }
    free(c);
}

void claw_server_drop_client(claw_server_t *srv, claw_client_t *c)
{
    log_debug("dropping client id=%lu fd=%d", (unsigned long)c->id, c->fd);
    epoll_del(srv->epoll_fd, c->fd);
    close(c->fd);
    client_free(srv, c);
}

/* Try to process all complete messages in client's receive buffer.
 * Returns number of messages dispatched, or <0 on fatal error. */
static int drain_client(claw_client_t *c,
                        claw_msg_handler_t handler, void *userdata)
{
    int dispatched = 0;
    for (;;) {
        if (c->recv_len < sizeof(claw_hdr_t)) break;

        claw_hdr_t *hdr = (claw_hdr_t *)c->recv_buf;
        if (hdr->magic != CLAW_MAGIC) {
            log_warn("client %lu bad magic %08x", (unsigned long)c->id, hdr->magic);
            return -EPROTO;
        }
        if (hdr->length > CLAW_MAX_PAYLOAD) {
            log_warn("client %lu payload too large %u", (unsigned long)c->id, hdr->length);
            return -EMSGSIZE;
        }
        size_t total = sizeof(claw_hdr_t) + hdr->length;
        if (c->recv_len < total) break; /* need more data */

        const char *payload = c->recv_buf + sizeof(claw_hdr_t);
        int rc = handler(c, (claw_msg_type_t)hdr->type, payload, hdr->length, userdata);
        if (rc < 0) return rc;
        dispatched++;

        /* Shift buffer */
        size_t remaining = c->recv_len - total;
        if (remaining)
            memmove(c->recv_buf, c->recv_buf + total, remaining);
        c->recv_len = remaining;
    }
    return dispatched;
}

int claw_server_poll(claw_server_t *srv, int timeout_ms,
                     claw_msg_handler_t handler, void *userdata)
{
    struct epoll_event events[64];
    int nev = epoll_wait(srv->epoll_fd, events, 64, timeout_ms);
    if (nev < 0) {
        if (errno == EINTR) return 0;
        log_error("epoll_wait: %m");
        return -errno;
    }

    for (int i = 0; i < nev; i++) {
        void *ptr = events[i].data.ptr;

        if (ptr == NULL) {
            /* Listener: accept new connection */
            int fd = accept4(srv->listen_fd, NULL, NULL,
                             SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    log_warn("accept4: %m");
                continue;
            }
            claw_client_t *c = client_new(srv, fd);
            if (!c) { close(fd); continue; }
            epoll_add(srv->epoll_fd, fd, EPOLLIN | EPOLLHUP | EPOLLERR, c);
            log_debug("new client id=%lu fd=%d", (unsigned long)c->id, fd);
            continue;
        }

        claw_client_t *c = (claw_client_t *)ptr;

        if (events[i].events & (EPOLLHUP | EPOLLERR)) {
            claw_server_drop_client(srv, c);
            continue;
        }

        if (events[i].events & EPOLLIN) {
            size_t space = sizeof(c->recv_buf) - c->recv_len;
            ssize_t n = recv(c->fd, c->recv_buf + c->recv_len, space, 0);
            if (n <= 0) {
                claw_server_drop_client(srv, c);
                continue;
            }
            c->recv_len += (size_t)n;
            int rc = drain_client(c, handler, userdata);
            if (rc < 0) {
                claw_server_drop_client(srv, c);
            }
        }
    }
    return 0;
}

int claw_server_send(claw_client_t *client,
                     claw_msg_type_t type,
                     const char *payload, size_t len)
{
    claw_hdr_t hdr;
    claw_hdr_init(&hdr, type, (uint32_t)len);

    struct iovec iov[2] = {
        { .iov_base = &hdr,          .iov_len = sizeof(hdr) },
        { .iov_base = (void*)payload, .iov_len = len         },
    };
    struct msghdr msg = { .msg_iov = iov, .msg_iovlen = (payload && len) ? 2 : 1 };

    ssize_t rc = sendmsg(client->fd, &msg, MSG_NOSIGNAL);
    if (rc < 0) { log_warn("sendmsg client %lu: %m", (unsigned long)client->id); return -errno; }
    return 0;
}

void claw_server_destroy(claw_server_t *srv)
{
    for (int i = 0; i < CLAW_MAX_CLIENTS; i++) {
        if (srv->clients[i]) {
            close(srv->clients[i]->fd);
            free(srv->clients[i]);
            srv->clients[i] = NULL;
        }
    }
    if (srv->epoll_fd >= 0) close(srv->epoll_fd);
    if (srv->listen_fd >= 0) close(srv->listen_fd);
    unlink(CLAW_DAEMON_SOCK);
}

/* ── Standalone client (shell-side) ──────────────────────────────── */

int claw_client_connect(const char *sock_path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -errno;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = errno;
        close(fd);
        return -err;
    }
    return fd;
}

int claw_client_send(int fd, claw_msg_type_t type,
                     const char *payload, size_t len)
{
    claw_hdr_t hdr;
    claw_hdr_init(&hdr, type, (uint32_t)len);

    if (send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL) != sizeof(hdr)) return -EIO;
    if (len && send(fd, payload, len, MSG_NOSIGNAL) != (ssize_t)len) return -EIO;
    return 0;
}

int claw_client_recv(int fd, claw_msg_type_t *type_out,
                     char **payload_out, size_t *len_out)
{
    claw_hdr_t hdr;
    ssize_t n = recv(fd, &hdr, sizeof(hdr), MSG_WAITALL);
    if (n != sizeof(hdr)) return -EIO;
    if (hdr.magic != CLAW_MAGIC) return -EPROTO;
    if (hdr.length > CLAW_MAX_PAYLOAD) return -EMSGSIZE;

    *type_out = (claw_msg_type_t)hdr.type;
    *len_out  = hdr.length;

    char *buf = malloc(hdr.length + 1);
    if (!buf) return -ENOMEM;

    if (hdr.length) {
        n = recv(fd, buf, hdr.length, MSG_WAITALL);
        if (n != (ssize_t)hdr.length) { free(buf); return -EIO; }
    }
    buf[hdr.length] = '\0';
    *payload_out = buf;   /* caller free()s */
    return 0;
}
