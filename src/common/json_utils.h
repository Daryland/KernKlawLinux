/* json_utils.h — Thin helpers over json-c for KernKlaw-Linux */
#pragma once
#ifndef CLAW_JSON_UTILS_H
#define CLAW_JSON_UTILS_H

#include <json-c/json.h>
#include <stdint.h>
#include <stdbool.h>

/* ── Constructors ─────────────────────────────────────────────────── */

/* Build a complete Ollama /api/generate payload */
struct json_object *claw_json_ollama_generate(
        const char *model,
        const char *prompt,
        bool stream);

/* Build a complete Ollama /api/chat payload */
struct json_object *claw_json_ollama_chat(
        const char *model,
        struct json_object *messages,   /* json array */
        bool stream);

/* Build an IPC QUERY message payload */
struct json_object *claw_json_query(
        uint64_t id,
        const char *prompt,
        const char *model);

/* Build an IPC SKILL_EXEC payload */
struct json_object *claw_json_skill_exec(
        uint64_t id,
        const char *skill_name,
        struct json_object *args);

/* Build an IPC ERROR payload */
struct json_object *claw_json_error(uint64_t id, const char *msg);

/* ── Accessors ────────────────────────────────────────────────────── */

/* Safe string getter (returns "" on missing key) */
const char *claw_json_str(struct json_object *obj, const char *key);

/* Safe int64 getter (returns def on missing key) */
int64_t claw_json_int(struct json_object *obj, const char *key, int64_t def);

/* Safe bool getter */
bool claw_json_bool(struct json_object *obj, const char *key, bool def);

/* ── Serialise / deserialise ──────────────────────────────────────── */

/* Returns heap-allocated string; caller must free() */
char *claw_json_to_str(struct json_object *obj);

/* Parse buffer; returns NULL on error */
struct json_object *claw_json_from_buf(const char *buf, size_t len);

#endif /* CLAW_JSON_UTILS_H */
