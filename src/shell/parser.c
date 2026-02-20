/* parser.c — Lobster-inspired DSL lexer + recursive-descent parser */
#define _GNU_SOURCE
#include "parser.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>

/* ── Lexer ────────────────────────────────────────────────────────── */

void lexer_init(lexer_t *lex, const char *src, size_t len)
{
    lex->src  = src;
    lex->pos  = 0;
    lex->len  = len;
    lex->line = 1;
}

static char peek_char(const lexer_t *lex, size_t offset)
{
    size_t i = lex->pos + offset;
    return (i < lex->len) ? lex->src[i] : '\0';
}

static char next_char(lexer_t *lex)
{
    if (lex->pos >= lex->len) return '\0';
    char c = lex->src[lex->pos++];
    if (c == '\n') lex->line++;
    return c;
}

static void skip_ws_comments(lexer_t *lex)
{
    for (;;) {
        char c = peek_char(lex, 0);
        if (c == '#') { while (peek_char(lex, 0) && peek_char(lex, 0) != '\n') next_char(lex); continue; }
        if (isspace((unsigned char)c)) { next_char(lex); continue; }
        break;
    }
}

static token_t make_tok(token_type_t type, char *value, int line)
{
    return (token_t){ .type = type, .value = value, .line = line };
}

static const struct { const char *kw; token_type_t type; } keywords[] = {
    { "ask",      TOK_KW_ASK      },
    { "into",     TOK_KW_INTO     },
    { "skill",    TOK_KW_SKILL    },
    { "let",      TOK_KW_LET      },
    { "if",       TOK_KW_IF       },
    { "else",     TOK_KW_ELSE     },
    { "loop",     TOK_KW_LOOP     },
    { "print",    TOK_KW_PRINT    },
    { "workflow", TOK_KW_WORKFLOW },
    { "end",      TOK_KW_END      },
    { NULL,       TOK_EOF         },
};

token_t lexer_next(lexer_t *lex)
{
    skip_ws_comments(lex);
    int line = lex->line;

    if (lex->pos >= lex->len)
        return make_tok(TOK_EOF, NULL, line);

    char c = peek_char(lex, 0);

    /* Single-char tokens */
    switch (c) {
    case '{': next_char(lex); return make_tok(TOK_LBRACE, NULL, line);
    case '}': next_char(lex); return make_tok(TOK_RBRACE, NULL, line);
    case '(': next_char(lex); return make_tok(TOK_LPAREN, NULL, line);
    case ')': next_char(lex); return make_tok(TOK_RPAREN, NULL, line);
    case '=': next_char(lex); return make_tok(TOK_EQUALS, NULL, line);
    case '+': next_char(lex); return make_tok(TOK_PLUS,   NULL, line);
    case '!': next_char(lex); return make_tok(TOK_BANG,   NULL, line);
    }

    /* String literals: "..." or '...' */
    if (c == '"' || c == '\'') {
        char delim = next_char(lex);
        size_t start = lex->pos;
        while (lex->pos < lex->len && peek_char(lex, 0) != delim) {
            if (peek_char(lex, 0) == '\\') next_char(lex); /* skip escape */
            next_char(lex);
        }
        size_t slen = lex->pos - start;
        char *val = strndup(lex->src + start, slen);
        if (lex->pos < lex->len) next_char(lex); /* consume closing quote */
        return make_tok(TOK_STRING, val, line);
    }

    /* Numbers */
    if (isdigit((unsigned char)c) || (c == '-' && isdigit((unsigned char)peek_char(lex, 1)))) {
        size_t start = lex->pos;
        if (c == '-') next_char(lex);
        while (lex->pos < lex->len && (isdigit((unsigned char)peek_char(lex, 0)) || peek_char(lex, 0) == '.'))
            next_char(lex);
        char *val = strndup(lex->src + start, lex->pos - start);
        return make_tok(TOK_NUMBER, val, line);
    }

    /* Identifiers / keywords */
    if (isalpha((unsigned char)c) || c == '_') {
        size_t start = lex->pos;
        while (lex->pos < lex->len && (isalnum((unsigned char)peek_char(lex, 0)) || peek_char(lex, 0) == '_'))
            next_char(lex);
        char *val = strndup(lex->src + start, lex->pos - start);
        for (int i = 0; keywords[i].kw; i++) {
            if (strcmp(val, keywords[i].kw) == 0) {
                free(val);
                return make_tok(keywords[i].type, NULL, line);
            }
        }
        return make_tok(TOK_IDENT, val, line);
    }

    next_char(lex);
    return make_tok(TOK_ERR, NULL, line);
}

void token_free(token_t *tok)
{
    free(tok->value);
    tok->value = NULL;
}

/* ── AST helpers ──────────────────────────────────────────────────── */

static ast_node_t *ast_alloc(ast_type_t type, int line)
{
    ast_node_t *n = calloc(1, sizeof(*n));
    n->type = type;
    n->line = line;
    return n;
}

void ast_free(ast_node_t *n)
{
    if (!n) return;
    free(n->sval);
    ast_free(n->left);
    ast_free(n->right);
    for (int i = 0; i < n->nchildren; i++) ast_free(n->children[i]);
    free(n->children);
    free(n);
}

static void ast_add_child(ast_node_t *parent, ast_node_t *child)
{
    parent->children = realloc(parent->children,
                                sizeof(ast_node_t *) * (size_t)(parent->nchildren + 1));
    parent->children[parent->nchildren++] = child;
}

/* ── Parser internals ─────────────────────────────────────────────── */

static void p_advance(parser_t *p)
{
    token_free(&p->cur);
    p->cur  = p->peek;
    p->peek = lexer_next(&p->lex);
}

static int p_match(parser_t *p, token_type_t type)
{
    if (p->cur.type == type) { p_advance(p); return 1; }
    return 0;
}

static void p_expect(parser_t *p, token_type_t type, const char *ctx)
{
    if (p->cur.type != type) {
        snprintf(p->errmsg, sizeof(p->errmsg),
                 "line %d: expected token %d in %s", p->cur.line, type, ctx);
        p->had_error = 1;
    }
    p_advance(p);
}

static ast_node_t *parse_expr(parser_t *p);
static ast_node_t *parse_stmt(parser_t *p);
static ast_node_t *parse_block(parser_t *p);

static ast_node_t *parse_primary(parser_t *p)
{
    int line = p->cur.line;
    if (p->cur.type == TOK_STRING) {
        ast_node_t *n = ast_alloc(AST_STRING, line);
        n->sval = strdup(p->cur.value);
        p_advance(p);
        return n;
    }
    if (p->cur.type == TOK_IDENT) {
        ast_node_t *n = ast_alloc(AST_IDENT, line);
        n->sval = strdup(p->cur.value);
        p_advance(p);
        return n;
    }
    if (p->cur.type == TOK_NUMBER) {
        ast_node_t *n = ast_alloc(AST_NUMBER, line);
        n->nval = atof(p->cur.value);
        p_advance(p);
        return n;
    }
    /* Parenthesised expression */
    if (p->cur.type == TOK_LPAREN) {
        p_advance(p);
        ast_node_t *e = parse_expr(p);
        p_expect(p, TOK_RPAREN, "expr");
        return e;
    }
    snprintf(p->errmsg, sizeof(p->errmsg),
             "line %d: unexpected token in expression", p->cur.line);
    p->had_error = 1;
    p_advance(p);
    return ast_alloc(AST_STRING, line);
}

static ast_node_t *parse_expr(parser_t *p)
{
    ast_node_t *left = parse_primary(p);
    while (p->cur.type == TOK_PLUS) {
        int line = p->cur.line;
        p_advance(p);
        ast_node_t *right = parse_primary(p);
        ast_node_t *bin   = ast_alloc(AST_BINOP, line);
        bin->sval  = strdup("+");
        bin->left  = left;
        bin->right = right;
        left = bin;
    }
    return left;
}

static ast_node_t *parse_block(parser_t *p)
{
    int line = p->cur.line;
    p_expect(p, TOK_LBRACE, "block");
    ast_node_t *block = ast_alloc(AST_BLOCK, line);
    while (p->cur.type != TOK_RBRACE && p->cur.type != TOK_EOF && !p->had_error) {
        ast_node_t *s = parse_stmt(p);
        if (s) ast_add_child(block, s);
    }
    p_expect(p, TOK_RBRACE, "block end");
    return block;
}

static ast_node_t *parse_stmt(parser_t *p)
{
    int line = p->cur.line;

    /* ask "prompt" [into varname] */
    if (p->cur.type == TOK_KW_ASK) {
        p_advance(p);
        ast_node_t *n = ast_alloc(AST_ASK, line);
        n->left = parse_expr(p);
        if (p->cur.type == TOK_KW_INTO) {
            p_advance(p);
            n->sval = strdup(p->cur.value ? p->cur.value : "");
            p_advance(p);
        }
        return n;
    }

    /* skill name key=val key=val ... */
    if (p->cur.type == TOK_KW_SKILL) {
        p_advance(p);
        ast_node_t *n = ast_alloc(AST_SKILL, line);
        n->sval = strdup(p->cur.value ? p->cur.value : "");
        p_advance(p); /* consume skill name (IDENT) */
        /* Parse key=value pairs until end of line / next keyword */
        while (p->cur.type == TOK_IDENT && p->peek.type == TOK_EQUALS) {
            ast_node_t *kv = ast_alloc(AST_KVPAIR, p->cur.line);
            kv->sval = strdup(p->cur.value); p_advance(p); /* key  */
            p_advance(p);                                   /* '='  */
            kv->left = parse_expr(p);                       /* value */
            ast_add_child(n, kv);
        }
        return n;
    }

    /* let varname = expr */
    if (p->cur.type == TOK_KW_LET) {
        p_advance(p);
        ast_node_t *n = ast_alloc(AST_LET, line);
        n->sval = strdup(p->cur.value ? p->cur.value : "");
        p_advance(p); p_expect(p, TOK_EQUALS, "let");
        n->left = parse_expr(p);
        return n;
    }

    /* if expr block [else block] */
    if (p->cur.type == TOK_KW_IF) {
        p_advance(p);
        ast_node_t *n = ast_alloc(AST_IF, line);
        n->left = parse_expr(p);
        ast_add_child(n, parse_block(p));
        if (p->cur.type == TOK_KW_ELSE) {
            p_advance(p);
            ast_add_child(n, parse_block(p));
        }
        return n;
    }

    /* loop NUM block */
    if (p->cur.type == TOK_KW_LOOP) {
        p_advance(p);
        ast_node_t *n = ast_alloc(AST_LOOP, line);
        n->left = parse_expr(p); /* count */
        ast_add_child(n, parse_block(p));
        return n;
    }

    /* print expr */
    if (p->cur.type == TOK_KW_PRINT) {
        p_advance(p);
        ast_node_t *n = ast_alloc(AST_PRINT, line);
        n->left = parse_expr(p);
        return n;
    }

    /* ! "shell command" */
    if (p->cur.type == TOK_BANG) {
        p_advance(p);
        ast_node_t *n = ast_alloc(AST_SHELL, line);
        n->left = parse_expr(p);
        return n;
    }

    /* Unknown: skip token to avoid infinite loop */
    p_advance(p);
    return NULL;
}

/* ── Public API ───────────────────────────────────────────────────── */

void parser_init(parser_t *p, const char *src, size_t len)
{
    memset(p, 0, sizeof(*p));
    lexer_init(&p->lex, src, len);
    p->cur  = lexer_next(&p->lex);
    p->peek = lexer_next(&p->lex);
}

ast_node_t *parser_parse(parser_t *p)
{
    ast_node_t *root = ast_alloc(AST_WORKFLOW, 0);
    /* Optional "workflow" keyword at top level */
    if (p->cur.type == TOK_KW_WORKFLOW) p_advance(p);
    while (p->cur.type != TOK_EOF && !p->had_error) {
        if (p->cur.type == TOK_KW_END) { p_advance(p); break; }
        ast_node_t *s = parse_stmt(p);
        if (s) ast_add_child(root, s);
    }
    if (p->had_error) {
        ast_free(root);
        return NULL;
    }
    return root;
}

void ast_print(const ast_node_t *n, int indent)
{
    if (!n) return;
    static const char *names[] = {
        [AST_WORKFLOW]="WORKFLOW",[AST_BLOCK]="BLOCK",[AST_ASK]="ASK",
        [AST_SKILL]="SKILL",[AST_LET]="LET",[AST_IF]="IF",
        [AST_LOOP]="LOOP",[AST_PRINT]="PRINT",[AST_SHELL]="SHELL",
        [AST_STRING]="STRING",[AST_IDENT]="IDENT",[AST_NUMBER]="NUMBER",
        [AST_BINOP]="BINOP",[AST_KVPAIR]="KV",
    };
    for (int i = 0; i < indent; i++) printf("  ");
    printf("%s", names[n->type] ? names[n->type] : "?");
    if (n->sval) printf(" sval=%s", n->sval);
    if (n->type == AST_NUMBER) printf(" nval=%.6g", n->nval);
    printf("\n");
    ast_print(n->left, indent+1);
    ast_print(n->right, indent+1);
    for (int i = 0; i < n->nchildren; i++) ast_print(n->children[i], indent+1);
}
