/* skill_loader.h — Skill discovery, manifest parsing, and execution */
#pragma once
#ifndef CLAW_SKILL_LOADER_H
#define CLAW_SKILL_LOADER_H

#include <stddef.h>
#include <stdbool.h>
#include <json-c/json.h>

#define SKILL_MAX_NAME   64
#define SKILL_MAX_DESC   256
#define SKILL_MAX_PATH   512
#define SKILL_MAX_COUNT  256

/* ── Skill types ──────────────────────────────────────────────────── */
typedef enum {
    SKILL_TYPE_EXEC    = 1,   /* external executable              */
    SKILL_TYPE_SO      = 2,   /* shared object (dlopen)           */
    SKILL_TYPE_SCRIPT  = 3,   /* shell script                     */
    SKILL_TYPE_BUILTIN = 4,   /* compiled-in skill                */
} skill_type_t;

/* ── Skill manifest (parsed from skill.json) ──────────────────────── */
typedef struct {
    char         name[SKILL_MAX_NAME];
    char         description[SKILL_MAX_DESC];
    char         version[32];
    char         author[64];
    skill_type_t type;
    char         exec_path[SKILL_MAX_PATH];   /* for EXEC/SO/SCRIPT  */
    char         trigger_event[64];           /* optional eBPF event */
    char        *schema_json;                 /* arg schema (heap)   */
    bool         requires_root;
    bool         enabled;
} skill_manifest_t;

/* ── Skill registry ───────────────────────────────────────────────── */
typedef struct {
    skill_manifest_t skills[SKILL_MAX_COUNT];
    int              count;
    char             skill_dir[SKILL_MAX_PATH];
} skill_registry_t;

/* ── Shared-object skill interface ───────────────────────────────────
 * Skills compiled as .so must export these symbols:
 *   int  skill_init(void);
 *   int  skill_run(const char *args_json, char **output, size_t *outlen);
 *   void skill_destroy(void);
 */
typedef int  (*skill_so_init_fn)(void);
typedef int  (*skill_so_run_fn)(const char *args_json,
                                 char **output, size_t *outlen);
typedef void (*skill_so_destroy_fn)(void);

/* ── API ──────────────────────────────────────────────────────────── */

void skill_registry_init(skill_registry_t *reg, const char *skill_dir);
void skill_registry_free(skill_registry_t *reg);

/* Scan skill_dir for subdirs containing skill.json; populate registry */
int  skill_registry_scan(skill_registry_t *reg);

/* Find skill by name; returns pointer into registry (don't free) */
const skill_manifest_t *skill_find(const skill_registry_t *reg,
                                    const char *name);

/* Execute a skill.
 * args_json:  JSON object string with skill arguments.
 * out:        heap-allocated output string (caller free()s).
 * Returns 0 on success, negative errno on error. */
int skill_exec(const skill_manifest_t *skill,
               const char *args_json,
               char **out);

/* Returns heap-alloc'd JSON array of all skill descriptors */
char *skill_list_json(const skill_registry_t *reg);

#endif /* CLAW_SKILL_LOADER_H */
