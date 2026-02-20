/* parser.h — Lobster-inspired workflow DSL parser for claw-shell
 *
 * Grammar (simplified):
 *
 *   workflow   ::= stmt*
 *   stmt       ::= ask_stmt | skill_stmt | let_stmt | if_stmt
 *                | loop_stmt | print_stmt | shell_stmt
 *   ask_stmt   ::= "ask" STRING ("into" IDENT)?
 *   skill_stmt ::= "skill" IDENT (KEY "=" VALUE)*
 *   let_stmt   ::= "let" IDENT "=" expr
 *   if_stmt    ::= "if" expr block ("else" block)?
 *   loop_stmt  ::= "loop" NUM block
 *   print_stmt ::= "print" expr
 *   shell_stmt ::= "!" STRING
 *   block      ::= "{" stmt* "}"
 *   expr       ::= STRING | IDENT | NUMBER | expr "+" expr
 */
#pragma once
#ifndef CLAW_PARSER_H
#define CLAW_PARSER_H

#include <stddef.h>

/* ── Token types ──────────────────────────────────────────────────── */
typedef enum {
    TOK_EOF = 0,
    TOK_IDENT,
    TOK_STRING,
    TOK_NUMBER,
    TOK_LBRACE,
    TOK_RBRACE,
    TOK_LPAREN,
    TOK_RPAREN,
    TOK_EQUALS,
    TOK_PLUS,
    TOK_BANG,
    TOK_KW_ASK,
    TOK_KW_INTO,
    TOK_KW_SKILL,
    TOK_KW_LET,
    TOK_KW_IF,
    TOK_KW_ELSE,
    TOK_KW_LOOP,
    TOK_KW_PRINT,
    TOK_KW_WORKFLOW,
    TOK_KW_END,
    TOK_ERR,
} token_type_t;

typedef struct {
    token_type_t type;
    char        *value;   /* heap-alloc'd; NULL for single-char tokens */
    int          line;
} token_t;

/* ── Lexer ────────────────────────────────────────────────────────── */
typedef struct {
    const char *src;
    size_t      pos;
    size_t      len;
    int         line;
} lexer_t;

void    lexer_init(lexer_t *lex, const char *src, size_t len);
token_t lexer_next(lexer_t *lex);
void    token_free(token_t *tok);

/* ── AST node types ───────────────────────────────────────────────── */
typedef enum {
    AST_WORKFLOW,
    AST_BLOCK,
    AST_ASK,
    AST_SKILL,
    AST_LET,
    AST_IF,
    AST_LOOP,
    AST_PRINT,
    AST_SHELL,
    AST_STRING,
    AST_IDENT,
    AST_NUMBER,
    AST_BINOP,
    AST_KVPAIR,
} ast_type_t;

typedef struct ast_node ast_node_t;

struct ast_node {
    ast_type_t   type;
    char        *sval;        /* string / ident / operator value */
    double       nval;        /* numeric value */
    ast_node_t  *left;
    ast_node_t  *right;
    ast_node_t **children;    /* for BLOCK, WORKFLOW, SKILL args */
    int          nchildren;
    int          line;
};

/* ── Parser ───────────────────────────────────────────────────────── */
typedef struct {
    lexer_t  lex;
    token_t  cur;
    token_t  peek;
    char     errmsg[256];
    int      had_error;
} parser_t;

void        parser_init(parser_t *p, const char *src, size_t len);
ast_node_t *parser_parse(parser_t *p);    /* returns AST root (WORKFLOW) */
void        ast_free(ast_node_t *node);
void        ast_print(const ast_node_t *node, int indent);

#endif /* CLAW_PARSER_H */
