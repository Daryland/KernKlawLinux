/* skill-template.c — Template for shared-object (.so) skills
 *
 * Compile:
 *   gcc -O2 -shared -fPIC -o myskill.so skill-template.c -ljson-c
 *
 * Skill manifest (skill.json):
 *   { "type": "so", "exec": "myskill.so", ... }
 *
 * The claw-daemon loads this with dlopen() and calls:
 *   skill_init()            — once at load
 *   skill_run(args, &out)   — on each invocation
 *   skill_destroy()         — at unload
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

/* Called once when skill is loaded */
int skill_init(void)
{
    return 0;
}

/* Main skill entrypoint.
 * args_json: JSON string of invocation arguments
 * output:    heap-alloc'd result string (caller free()s)
 * outlen:    byte length of *output
 * Returns 0 on success, negative errno on error. */
int skill_run(const char *args_json, char **output, size_t *outlen)
{
    /* Parse args */
    struct json_object *args = json_tokener_parse(args_json);
    if (!args) {
        *output = strdup("{\"error\":\"invalid args JSON\"}");
        *outlen = strlen(*output);
        return -1;
    }

    /* Extract "msg" argument */
    struct json_object *msg_obj = NULL;
    const char *msg = "hello from .so skill";
    if (json_object_object_get_ex(args, "msg", &msg_obj))
        msg = json_object_get_string(msg_obj);

    /* Build result */
    struct json_object *result = json_object_new_object();
    json_object_object_add(result, "result",
                           json_object_new_string(msg));
    json_object_object_add(result, "skill",
                           json_object_new_string("example-so"));

    const char *str = json_object_to_json_string(result);
    *output = strdup(str);
    *outlen = strlen(*output);

    json_object_put(result);
    json_object_put(args);
    return 0;
}

/* Called once at unload */
void skill_destroy(void)
{
    /* cleanup here */
}
