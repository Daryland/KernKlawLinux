/* ipc.h — Unix-socket IPC server helpers for claw-daemon */
#pragma once
#ifndef CLAW_IPC_H
#define CLAW_IPC_H

#include "../common/proto.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define CLAW_MAX_CLIENTS   64
#define CLAW_RECV_BUFSZ    (64 * 1024)

/* ── Client connection ────────────────────────────────────────────── */
typedef struct claw_client {
    int      fd;
    uint64_t id;               /* monotonic session id          */
    char     recv_buf[CLAW_RECV_BUFSZ];
    size_t   recv_len;
    bool     closing;
} claw_client_t;

/* ── Server handle ────────────────────────────────────────────────── */
typedef struct claw_server {
    int            listen_fd;
    int            epoll_fd;
    claw_client_t *clients[CLAW_MAX_CLIENTS];
    int            nclients;
    uint64_t       next_id;
} claw_server_t;

/* ── Message dispatch callback ────────────────────────────────────── */
/* Return 0 to keep client, <0 to drop */
typedef int (*claw_msg_handler_t)(claw_client_t *client,
                                   claw_msg_type_t type,
                                   const char *payload,
                                   size_t payload_len,
                                   void *userdata);

/* ── API ──────────────────────────────────────────────────────────── */

/* Create listening socket + epoll fd.  Binds to CLAW_DAEMON_SOCK. */
int claw_server_init(claw_server_t *srv);

/* Run one iteration of the event loop (timeout_ms = -1 → block forever).
 * Calls handler for every complete message received. */
int claw_server_poll(claw_server_t *srv, int timeout_ms,
                     claw_msg_handler_t handler, void *userdata);

/* Send a message to a specific client.
 * Payload is raw JSON bytes (not NUL-terminated required). */
int claw_server_send(claw_client_t *client,
                     claw_msg_type_t type,
                     const char *payload, size_t len);

/* Close and remove a client */
void claw_server_drop_client(claw_server_t *srv, claw_client_t *client);

/* Shutdown server */
void claw_server_destroy(claw_server_t *srv);

/* ── Standalone client (used by claw-shell) ───────────────────────── */
int  claw_client_connect(const char *sock_path);
int  claw_client_send(int fd, claw_msg_type_t type,
                      const char *payload, size_t len);
int  claw_client_recv(int fd, claw_msg_type_t *type_out,
                      char **payload_out, size_t *len_out);

#endif /* CLAW_IPC_H */
