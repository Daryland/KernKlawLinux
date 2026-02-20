#!/bin/sh
# Example skill: echo the args JSON back as a result
# Called by claw-skill-exec as: run.sh '<args-json>'
set -e
ARGS="${1:-{}}"
MSG=$(printf '%s' "$ARGS" | sed -n 's/.*"msg"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
printf '{"result": "echo: %s", "args": %s}\n' "${MSG:-<no msg>}" "$ARGS"
