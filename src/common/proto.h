/* proto.h — KernKlaw-Linux IPC wire protocol
 * All messages are length-prefixed JSON over Unix domain sockets.
 * Wire layout: [magic:4][type:4][length:4][payload:length]
 * All integers are little-endian.
 */
#pragma once
#ifndef CLAW_PROTO_H
#define CLAW_PROTO_H

#include <stdint.h>
#include <stddef.h>

/* ── Magic & versions ─────────────────────────────────────────────── */
#define CLAW_MAGIC        UINT32_C(0xC1A70001)
#define CLAW_PROTO_VER    1
#define CLAW_MAX_PAYLOAD  (4 * 1024 * 1024)   /* 4 MiB */

/* ── Socket paths ─────────────────────────────────────────────────── */
#define CLAW_DAEMON_SOCK  "/run/claw/daemon.sock"
#define CLAW_SKILL_SOCK   "/run/claw/skill.sock"
#define CLAW_STATE_DIR    "/run/claw"
#define CLAW_CONFIG_DIR   "/etc/claw"
#define CLAW_SKILL_DIR    "/etc/claw/skills"
#define CLAW_USER_DIR     ".config/claw"     /* relative to $HOME */

/* ── Message types ────────────────────────────────────────────────── */
typedef enum {
    CLAW_MSG_PING           = 0x01,
    CLAW_MSG_PONG           = 0x02,
    CLAW_MSG_QUERY          = 0x10,   /* client → daemon: free-form AI query */
    CLAW_MSG_RESPONSE       = 0x11,   /* daemon → client: complete AI reply   */
    CLAW_MSG_STREAM_CHUNK   = 0x12,   /* daemon → client: streaming token     */
    CLAW_MSG_STREAM_END     = 0x13,   /* daemon → client: streaming done      */
    CLAW_MSG_SKILL_LIST     = 0x20,   /* client → daemon: list skills         */
    CLAW_MSG_SKILL_LIST_RSP = 0x21,   /* daemon → client: skill list JSON     */
    CLAW_MSG_SKILL_EXEC     = 0x22,   /* client → daemon: run a skill         */
    CLAW_MSG_SKILL_RESULT   = 0x23,   /* daemon → client: skill output        */
    CLAW_MSG_WORKFLOW_RUN   = 0x30,   /* client → daemon: run workflow file   */
    CLAW_MSG_WORKFLOW_STEP  = 0x31,   /* daemon → client: workflow step event */
    CLAW_MSG_WORKFLOW_DONE  = 0x32,   /* daemon → client: workflow finished   */
    CLAW_MSG_STATUS         = 0x40,   /* client → daemon: daemon status query */
    CLAW_MSG_STATUS_RSP     = 0x41,   /* daemon → client: status JSON         */
    CLAW_MSG_ERROR          = 0xFF,   /* bidirectional: error payload         */
} claw_msg_type_t;

/* ── Wire header (12 bytes, packed) ───────────────────────────────── */
#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    uint32_t type;
    uint32_t length;   /* byte length of payload that follows */
} claw_hdr_t;
#pragma pack(pop)

/* ── Convenience ──────────────────────────────────────────────────── */
static inline void claw_hdr_init(claw_hdr_t *h, claw_msg_type_t t, uint32_t len)
{
    h->magic  = CLAW_MAGIC;
    h->type   = (uint32_t)t;
    h->length = len;
}

/* JSON field names used in payloads */
#define CLAW_F_ID        "id"
#define CLAW_F_MODEL     "model"
#define CLAW_F_PROMPT    "prompt"
#define CLAW_F_MESSAGES  "messages"
#define CLAW_F_ROLE      "role"
#define CLAW_F_CONTENT   "content"
#define CLAW_F_STREAM    "stream"
#define CLAW_F_SKILL     "skill"
#define CLAW_F_ARGS      "args"
#define CLAW_F_ENV       "env"
#define CLAW_F_RESULT    "result"
#define CLAW_F_STATUS    "status"
#define CLAW_F_ERROR     "error"
#define CLAW_F_DONE      "done"
#define CLAW_F_RESPONSE  "response"

#endif /* CLAW_PROTO_H */
