/* ollama.c — Ollama HTTP client using libcurl
 *
 * Streaming:  curl writes NDJSON lines into a growing buffer; we parse
 *             each complete line as a JSON object and extract "response".
 * Blocking:   same but accumulate all tokens then return.
 */
#define _GNU_SOURCE
#include "ollama.h"
#include "../common/log.h"
#include "../common/json_utils.h"

#include <curl/curl.h>
#include <json-c/json.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

/* ── Internal write-buffer ────────────────────────────────────────── */
typedef struct {
    char  *data;
    size_t len;
    size_t cap;
} wbuf_t;

static int wbuf_append(wbuf_t *b, const char *src, size_t n)
{
    if (b->len + n + 1 > b->cap) {
        size_t newcap = (b->cap ? b->cap : 4096);
        while (newcap < b->len + n + 1) newcap *= 2;
        char *tmp = realloc(b->data, newcap);
        if (!tmp) return -ENOMEM;
        b->data = tmp;
        b->cap  = newcap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    b->data[b->len] = '\0';
    return 0;
}

static void wbuf_free(wbuf_t *b) { free(b->data); b->data=NULL; b->len=b->cap=0; }

/* ── Stream context ───────────────────────────────────────────────── */
typedef struct {
    wbuf_t           line_buf;     /* accumulate partial line       */
    wbuf_t           full_text;    /* accumulate all response tokens*/
    ollama_token_cb  on_token;
    ollama_done_cb   on_done;
    void            *userdata;
    int              error;
} stream_ctx_t;

/* curl write callback for streaming */
static size_t stream_write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    size_t total = size * nmemb;
    stream_ctx_t *ctx = (stream_ctx_t *)ud;

    /* Append raw data to line buffer */
    if (wbuf_append(&ctx->line_buf, ptr, total) < 0) {
        ctx->error = ENOMEM;
        return 0;
    }

    /* Process complete lines (Ollama NDJSON: one JSON object per line) */
    char *start = ctx->line_buf.data;
    char *nl;
    while ((nl = memchr(start, '\n', ctx->line_buf.len - (size_t)(start - ctx->line_buf.data)))) {
        size_t linelen = (size_t)(nl - start);
        if (linelen > 0) {
            struct json_object *jobj = claw_json_from_buf(start, linelen);
            if (jobj) {
                const char *token = claw_json_str(jobj, "response");
                bool done         = claw_json_bool(jobj, "done", false);

                if (token && *token) {
                    wbuf_append(&ctx->full_text, token, strlen(token));
                    if (ctx->on_token)
                        ctx->on_token(token, ctx->userdata);
                }
                if (done) {
                    if (ctx->on_token) ctx->on_token(NULL, ctx->userdata);
                    if (ctx->on_done)
                        ctx->on_done(ctx->full_text.data ? ctx->full_text.data : "",
                                     0, ctx->userdata);
                }
                json_object_put(jobj);
            }
        }
        start = nl + 1;
    }

    /* Keep leftover data (partial line) */
    size_t remaining = ctx->line_buf.len - (size_t)(start - ctx->line_buf.data);
    if (remaining && start != ctx->line_buf.data)
        memmove(ctx->line_buf.data, start, remaining);
    ctx->line_buf.len = remaining;
    if (ctx->line_buf.data) ctx->line_buf.data[remaining] = '\0';

    return total;
}

/* curl write callback for blocking (just accumulate) */
static size_t blocking_write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
    wbuf_t *buf = (wbuf_t *)ud;
    size_t total = size * nmemb;
    if (wbuf_append(buf, ptr, total) < 0) return 0;
    return total;
}

/* ── Config ───────────────────────────────────────────────────────── */

void ollama_cfg_init(ollama_cfg_t *cfg)
{
    strncpy(cfg->base_url,       OLLAMA_DEFAULT_URL, sizeof(cfg->base_url)-1);
    strncpy(cfg->default_model,  "llama3.2",         sizeof(cfg->default_model)-1);
    cfg->timeout_ms = 120000;
    cfg->verify_ssl = false;
}

void ollama_cfg_from_env(ollama_cfg_t *cfg)
{
    const char *host = getenv("OLLAMA_HOST");
    if (host) strncpy(cfg->base_url, host, sizeof(cfg->base_url)-1);

    const char *model = getenv("CLAW_DEFAULT_MODEL");
    if (model) strncpy(cfg->default_model, model, sizeof(cfg->default_model)-1);
}

/* ── Internal: build URL ──────────────────────────────────────────── */
static void build_url(const ollama_cfg_t *cfg, const char *path,
                      char *out, size_t outsz)
{
    snprintf(out, outsz, "%s%s", cfg->base_url, path);
}

/* ── Internal: perform curl POST ─────────────────────────────────── */
static CURL *make_curl(const ollama_cfg_t *cfg, const char *url,
                       const char *body, struct curl_slist **hdrs_out)
{
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, "Content-Type: application/json");
    hdrs = curl_slist_append(hdrs, "Accept: application/x-ndjson");
    *hdrs_out = hdrs;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(body));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, cfg->timeout_ms);
    if (!cfg->verify_ssl)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    return curl;
}

/* ── Public API ───────────────────────────────────────────────────── */

bool ollama_ping(const ollama_cfg_t *cfg)
{
    char url[512];
    snprintf(url, sizeof(url), "%s/", cfg->base_url);
    CURL *curl = curl_easy_init();
    if (!curl) return false;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 3000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    return (rc == CURLE_OK);
}

char *ollama_list_models(const ollama_cfg_t *cfg)
{
    char url[512];
    build_url(cfg, OLLAMA_TAGS_PATH, url, sizeof(url));
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    wbuf_t buf = {0};
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, blocking_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, 10000L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    CURLcode rc = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) { wbuf_free(&buf); return NULL; }
    return buf.data; /* caller free()s */
}

char *ollama_generate(const ollama_cfg_t *cfg,
                      const char *model, const char *prompt)
{
    /* Build body with stream:false so we get one big JSON blob */
    struct json_object *req = claw_json_ollama_generate(model, prompt, false);
    char *body = claw_json_to_str(req);
    json_object_put(req);

    char url[512];
    build_url(cfg, OLLAMA_GEN_PATH, url, sizeof(url));

    struct curl_slist *hdrs = NULL;
    CURL *curl = make_curl(cfg, url, body, &hdrs);
    free(body);
    if (!curl) return NULL;

    wbuf_t buf = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, blocking_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK) { wbuf_free(&buf); return NULL; }

    /* Parse the single JSON object and extract "response" */
    struct json_object *jobj = claw_json_from_buf(buf.data, buf.len);
    wbuf_free(&buf);
    if (!jobj) return NULL;
    const char *resp = claw_json_str(jobj, "response");
    char *result = resp ? strdup(resp) : strdup("");
    json_object_put(jobj);
    return result;
}

int ollama_generate_stream(const ollama_cfg_t *cfg,
                           const char *model,
                           const char *prompt,
                           ollama_token_cb on_token,
                           ollama_done_cb  on_done,
                           void *userdata)
{
    struct json_object *req = claw_json_ollama_generate(model, prompt, true);
    char *body = claw_json_to_str(req);
    json_object_put(req);

    char url[512];
    build_url(cfg, OLLAMA_GEN_PATH, url, sizeof(url));

    struct curl_slist *hdrs = NULL;
    CURL *curl = make_curl(cfg, url, body, &hdrs);
    free(body);
    if (!curl) return -ENOMEM;

    stream_ctx_t ctx = {
        .on_token = on_token,
        .on_done  = on_done,
        .userdata = userdata,
    };
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    wbuf_free(&ctx.line_buf);
    wbuf_free(&ctx.full_text);

    if (rc != CURLE_OK) {
        log_error("curl: %s", curl_easy_strerror(rc));
        return -EIO;
    }
    return ctx.error ? -ctx.error : 0;
}

int ollama_chat_stream(const ollama_cfg_t *cfg,
                       const char *model,
                       const char *messages_json,
                       ollama_token_cb on_token,
                       ollama_done_cb  on_done,
                       void *userdata)
{
    struct json_object *msgs = claw_json_from_buf(messages_json,
                                                   strlen(messages_json));
    if (!msgs) return -EINVAL;

    struct json_object *req = claw_json_ollama_chat(model, msgs, true);
    json_object_put(msgs);
    char *body = claw_json_to_str(req);
    json_object_put(req);

    char url[512];
    build_url(cfg, OLLAMA_CHAT_PATH, url, sizeof(url));

    struct curl_slist *hdrs = NULL;
    CURL *curl = make_curl(cfg, url, body, &hdrs);
    free(body);
    if (!curl) return -ENOMEM;

    stream_ctx_t ctx = {
        .on_token = on_token,
        .on_done  = on_done,
        .userdata = userdata,
    };
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, stream_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &ctx);

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(curl);
    wbuf_free(&ctx.line_buf);
    wbuf_free(&ctx.full_text);

    return (rc == CURLE_OK) ? (ctx.error ? -ctx.error : 0) : -EIO;
}
