/* json_utils.c — json-c helpers for KernKlaw-Linux */
#include "json_utils.h"
#include <stdlib.h>
#include <string.h>

/* ── Constructors ─────────────────────────────────────────────────── */

struct json_object *claw_json_ollama_generate(
        const char *model, const char *prompt, bool stream)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "model",  json_object_new_string(model));
    json_object_object_add(obj, "prompt", json_object_new_string(prompt));
    json_object_object_add(obj, "stream", json_object_new_boolean(stream));
    return obj;
}

struct json_object *claw_json_ollama_chat(
        const char *model, struct json_object *messages, bool stream)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "model",    json_object_new_string(model));
    json_object_object_add(obj, "messages", json_object_get(messages));
    json_object_object_add(obj, "stream",   json_object_new_boolean(stream));
    return obj;
}

struct json_object *claw_json_query(
        uint64_t id, const char *prompt, const char *model)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "id",     json_object_new_int64((int64_t)id));
    json_object_object_add(obj, "prompt", json_object_new_string(prompt));
    json_object_object_add(obj, "model",  json_object_new_string(model));
    return obj;
}

struct json_object *claw_json_skill_exec(
        uint64_t id, const char *skill_name, struct json_object *args)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "id",    json_object_new_int64((int64_t)id));
    json_object_object_add(obj, "skill", json_object_new_string(skill_name));
    if (args)
        json_object_object_add(obj, "args", json_object_get(args));
    else
        json_object_object_add(obj, "args", json_object_new_object());
    return obj;
}

struct json_object *claw_json_error(uint64_t id, const char *msg)
{
    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "id",    json_object_new_int64((int64_t)id));
    json_object_object_add(obj, "error", json_object_new_string(msg));
    return obj;
}

/* ── Accessors ────────────────────────────────────────────────────── */

const char *claw_json_str(struct json_object *obj, const char *key)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v)) return "";
    return json_object_get_string(v);
}

int64_t claw_json_int(struct json_object *obj, const char *key, int64_t def)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v)) return def;
    return json_object_get_int64(v);
}

bool claw_json_bool(struct json_object *obj, const char *key, bool def)
{
    struct json_object *v = NULL;
    if (!obj || !json_object_object_get_ex(obj, key, &v)) return def;
    return json_object_get_boolean(v);
}

/* ── Serialise / deserialise ──────────────────────────────────────── */

char *claw_json_to_str(struct json_object *obj)
{
    if (!obj) return strdup("null");
    const char *s = json_object_to_json_string_ext(obj,
        JSON_C_TO_STRING_NOSLASHESCAPE);
    return strdup(s);
}

struct json_object *claw_json_from_buf(const char *buf, size_t len)
{
    struct json_tokener *tok = json_tokener_new();
    struct json_object  *obj = json_tokener_parse_ex(tok, buf, (int)len);
    json_tokener_free(tok);
    return obj;
}
