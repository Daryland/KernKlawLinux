/* skill_loader.c — Skill discovery and execution */
#define _GNU_SOURCE
#include "skill_loader.h"
#include "../common/log.h"
#include "../common/json_utils.h"

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* ── Registry ─────────────────────────────────────────────────────── */

void skill_registry_init(skill_registry_t *reg, const char *skill_dir)
{
    memset(reg, 0, sizeof(*reg));
    strncpy(reg->skill_dir, skill_dir, SKILL_MAX_PATH-1);
}

void skill_registry_free(skill_registry_t *reg)
{
    for (int i = 0; i < reg->count; i++) {
        free(reg->skills[i].schema_json);
        reg->skills[i].schema_json = NULL;
    }
    reg->count = 0;
}

/* Parse one skill.json file into a manifest */
static int parse_skill_manifest(const char *json_path, const char *base_dir,
                                  skill_manifest_t *out)
{
    FILE *f = fopen(json_path, "r");
    if (!f) return -errno;

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz <= 0 || fsz > 65536) { fclose(f); return -EINVAL; }

    char *buf = malloc((size_t)fsz + 1);
    if (!buf) { fclose(f); return -ENOMEM; }
    fread(buf, 1, (size_t)fsz, f);
    buf[fsz] = '\0';
    fclose(f);

    struct json_object *jobj = claw_json_from_buf(buf, (size_t)fsz);
    free(buf);
    if (!jobj) { log_warn("parse_skill_manifest: invalid JSON in %s", json_path); return -EINVAL; }

    const char *name    = claw_json_str(jobj, "name");
    const char *desc    = claw_json_str(jobj, "description");
    const char *version = claw_json_str(jobj, "version");
    const char *author  = claw_json_str(jobj, "author");
    const char *type_s  = claw_json_str(jobj, "type");
    const char *exec    = claw_json_str(jobj, "exec");
    const char *trigger = claw_json_str(jobj, "trigger_event");

    if (!name || !*name) { json_object_put(jobj); return -EINVAL; }

    strncpy(out->name,    name,    SKILL_MAX_NAME-1);
    strncpy(out->description, desc && *desc ? desc : "(no description)",
            SKILL_MAX_DESC-1);
    strncpy(out->version, version && *version ? version : "0.1.0", 31);
    strncpy(out->author,  author  && *author  ? author  : "unknown", 63);
    strncpy(out->trigger_event, trigger && *trigger ? trigger : "", 63);
    out->requires_root = claw_json_bool(jobj, "requires_root", false);
    out->enabled       = claw_json_bool(jobj, "enabled",       true);

    /* Determine type */
    if (!type_s || strcmp(type_s, "exec") == 0)   out->type = SKILL_TYPE_EXEC;
    else if (strcmp(type_s, "so") == 0)            out->type = SKILL_TYPE_SO;
    else if (strcmp(type_s, "script") == 0)        out->type = SKILL_TYPE_SCRIPT;
    else                                            out->type = SKILL_TYPE_EXEC;

    /* Build exec path: relative to skill dir if not absolute */
    if (exec && *exec) {
        if (exec[0] == '/') {
            strncpy(out->exec_path, exec, SKILL_MAX_PATH-1);
        } else {
            snprintf(out->exec_path, SKILL_MAX_PATH, "%s/%s", base_dir, exec);
        }
    }

    /* Schema */
    struct json_object *schema = NULL;
    if (json_object_object_get_ex(jobj, "args_schema", &schema)) {
        const char *sstr = json_object_to_json_string(schema);
        out->schema_json = strdup(sstr);
    }

    json_object_put(jobj);
    return 0;
}

int skill_registry_scan(skill_registry_t *reg)
{
    DIR *d = opendir(reg->skill_dir);
    if (!d) {
        log_warn("skill_dir %s: %m", reg->skill_dir);
        return -errno;
    }

    struct dirent *ent;
    while ((ent = readdir(d)) && reg->count < SKILL_MAX_COUNT) {
        if (ent->d_name[0] == '.') continue;

        char subdir[SKILL_MAX_PATH];
        snprintf(subdir, sizeof(subdir), "%s/%s", reg->skill_dir, ent->d_name);

        struct stat st;
        if (stat(subdir, &st) < 0 || !S_ISDIR(st.st_mode)) continue;

        char manifest_path[SKILL_MAX_PATH];
        snprintf(manifest_path, sizeof(manifest_path), "%s/skill.json", subdir);

        if (access(manifest_path, R_OK) != 0) continue;

        skill_manifest_t *m = &reg->skills[reg->count];
        if (parse_skill_manifest(manifest_path, subdir, m) == 0) {
            log_info("loaded skill: %s v%s (%s)",
                     m->name, m->version,
                     m->type == SKILL_TYPE_SO ? "so" :
                     m->type == SKILL_TYPE_SCRIPT ? "script" : "exec");
            reg->count++;
        }
    }
    closedir(d);
    log_info("skill registry: %d skills loaded from %s",
             reg->count, reg->skill_dir);
    return reg->count;
}

const skill_manifest_t *skill_find(const skill_registry_t *reg, const char *name)
{
    for (int i = 0; i < reg->count; i++) {
        if (strcmp(reg->skills[i].name, name) == 0)
            return &reg->skills[i];
    }
    return NULL;
}

/* ── Execution ────────────────────────────────────────────────────── */

/* Run an executable skill in a child process; capture stdout */
static int exec_skill_proc(const char *exec_path, const char *args_json,
                            char **out)
{
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC) < 0) return -errno;

    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -errno; }

    if (pid == 0) {
        /* child */
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execlp(exec_path, exec_path, args_json, NULL);
        _exit(127);
    }

    close(pipefd[1]);

    /* Read output */
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (!buf) { close(pipefd[0]); waitpid(pid, NULL, 0); return -ENOMEM; }

    ssize_t n;
    while ((n = read(pipefd[0], buf + len, cap - len)) > 0) {
        len += (size_t)n;
        if (len + 1 >= cap) {
            cap *= 2;
            char *tmp = realloc(buf, cap);
            if (!tmp) { free(buf); close(pipefd[0]); waitpid(pid, NULL, 0); return -ENOMEM; }
            buf = tmp;
        }
    }
    close(pipefd[0]);
    buf[len] = '\0';

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        log_warn("skill exec exited %d", WEXITSTATUS(status));
        free(buf);
        return -ECHILD;
    }

    *out = buf;
    return 0;
}

/* Run a shared-object skill via dlopen */
static int exec_skill_so(const char *so_path, const char *args_json, char **out)
{
    void *hdl = dlopen(so_path, RTLD_NOW | RTLD_LOCAL);
    if (!hdl) {
        log_error("dlopen %s: %s", so_path, dlerror());
        return -ELIBACC;
    }

    skill_so_init_fn    init_fn    = dlsym(hdl, "skill_init");
    skill_so_run_fn     run_fn     = dlsym(hdl, "skill_run");
    skill_so_destroy_fn destroy_fn = dlsym(hdl, "skill_destroy");

    if (!run_fn) {
        log_error("skill_run not found in %s", so_path);
        dlclose(hdl);
        return -ENOTSUP;
    }

    if (init_fn) init_fn();

    size_t outlen = 0;
    int rc = run_fn(args_json, out, &outlen);

    if (destroy_fn) destroy_fn();
    dlclose(hdl);
    return rc;
}

int skill_exec(const skill_manifest_t *skill, const char *args_json, char **out)
{
    if (!skill->enabled) return -EPERM;

    switch (skill->type) {
    case SKILL_TYPE_EXEC:
    case SKILL_TYPE_SCRIPT:
        return exec_skill_proc(skill->exec_path, args_json, out);
    case SKILL_TYPE_SO:
        return exec_skill_so(skill->exec_path, args_json, out);
    case SKILL_TYPE_BUILTIN:
        /* Builtins handled by the daemon directly */
        *out = strdup("{\"error\":\"builtin dispatch not implemented\"}");
        return -ENOTSUP;
    }
    return -EINVAL;
}

char *skill_list_json(const skill_registry_t *reg)
{
    struct json_object *arr = json_object_new_array();
    for (int i = 0; i < reg->count; i++) {
        const skill_manifest_t *m = &reg->skills[i];
        struct json_object *obj = json_object_new_object();
        json_object_object_add(obj, "name",        json_object_new_string(m->name));
        json_object_object_add(obj, "description", json_object_new_string(m->description));
        json_object_object_add(obj, "version",     json_object_new_string(m->version));
        json_object_object_add(obj, "author",      json_object_new_string(m->author));
        json_object_object_add(obj, "enabled",     json_object_new_boolean(m->enabled));
        const char *type_s = (m->type == SKILL_TYPE_SO) ? "so" :
                             (m->type == SKILL_TYPE_SCRIPT) ? "script" : "exec";
        json_object_object_add(obj, "type", json_object_new_string(type_s));
        json_object_array_add(arr, obj);
    }
    char *result = strdup(json_object_to_json_string_ext(arr,
                          JSON_C_TO_STRING_PRETTY));
    json_object_put(arr);
    return result;
}
