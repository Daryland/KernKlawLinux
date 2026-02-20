/* ollama.h — Blocking + streaming Ollama HTTP/1.1 client (libcurl) */
#pragma once
#ifndef CLAW_OLLAMA_H
#define CLAW_OLLAMA_H

#include <stddef.h>
#include <stdbool.h>

/* Default Ollama endpoint (overridden by OLLAMA_HOST env var) */
#define OLLAMA_DEFAULT_URL  "http://127.0.0.1:11434"
#define OLLAMA_GEN_PATH     "/api/generate"
#define OLLAMA_CHAT_PATH    "/api/chat"
#define OLLAMA_TAGS_PATH    "/api/tags"

/* ── Callback types ───────────────────────────────────────────────── */

/* Called for each streaming token (token=NULL signals done) */
typedef void (*ollama_token_cb)(const char *token, void *userdata);

/* Called with the final complete response text */
typedef void (*ollama_done_cb)(const char *full_text, int err, void *userdata);

/* ── Config ───────────────────────────────────────────────────────── */
typedef struct {
    char    base_url[256];
    char    default_model[64];
    long    timeout_ms;
    bool    verify_ssl;
} ollama_cfg_t;

void ollama_cfg_init(ollama_cfg_t *cfg);       /* set sane defaults */
void ollama_cfg_from_env(ollama_cfg_t *cfg);   /* override from env */

/* ── Blocking calls ───────────────────────────────────────────────── */

/* Returns heap-alloc'd response string; caller free()s. NULL on error. */
char *ollama_generate(const ollama_cfg_t *cfg,
                      const char *model,
                      const char *prompt);

/* List available models; returns heap-alloc'd JSON string */
char *ollama_list_models(const ollama_cfg_t *cfg);

/* ── Streaming calls ──────────────────────────────────────────────── */

/* Streams tokens to on_token; calls on_done when complete.
 * Runs synchronously (use from a thread for non-blocking behaviour).
 * Returns 0 on success, negative errno on error. */
int ollama_generate_stream(const ollama_cfg_t *cfg,
                           const char *model,
                           const char *prompt,
                           ollama_token_cb on_token,
                           ollama_done_cb  on_done,
                           void *userdata);

/* Chat (messages is a JSON array string like Ollama /api/chat expects) */
int ollama_chat_stream(const ollama_cfg_t *cfg,
                       const char *model,
                       const char *messages_json,
                       ollama_token_cb on_token,
                       ollama_done_cb  on_done,
                       void *userdata);

/* ── Health check ─────────────────────────────────────────────────── */
bool ollama_ping(const ollama_cfg_t *cfg);

#endif /* CLAW_OLLAMA_H */
