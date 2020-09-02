/*
 * We want a reentrant parser.
 * For now ignore the wdeprecated warning recommending
 * %define api.pure
 * https://code.wireshark.org/review/#/c/33771/
 * "This doesn't work with Berkeley YACC, and I'd *really* prefer not to require Bison."
 */
%pure-parser

/*
 * We also want a reentrant scanner, so we have to pass the
 * handle for the reentrant scanner to the parser, and the
 * parser has to pass it to the lexical analyzer.
 *
 * We use void * rather than yyscan_t because, at least with some
 * versions of Flex and Bison, if you use yyscan_t in %parse-param and
 * %lex-param, you have to include the protobuf_lang_scanner_lex.h before
 * protobuf_lang.h to get yyscan_t declared, and you have to include protobuf_lang.h
 * before protobuf_lang_scanner_lex.h to get YYSTYPE declared.  Using void *
 * breaks the cycle; the Flex documentation says yyscan_t is just a void *.
 */
%parse-param {void *yyscanner}
%lex-param {void *yyscanner}

/*
 * And we need to pass the parser/scanner state to the parser.
 */
%parse-param {protobuf_lang_state_t *state}

%{
/* protobuf_lang.y
 *
 * C Protocol Buffers Language (PBL) Parser (for *.proto files)
 * Copyright 2019, Huang Qiangxiong <qiangxiong.huang@qq.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This parser is mainly to get MESSAGE, ENUM, and FIELD information from *.proto files.
 * There are two formats of *.proto files:
 * 1) Protocol Buffers Version 3 Language Specification:
 *      https://developers.google.com/protocol-buffers/docs/reference/proto3-spec
 * 2) Protocol Buffers Version 2 Language Specification:
 *      https://developers.google.com/protocol-buffers/docs/reference/proto2-spec
 * There are some errors about 'proto', 'option' (value) and 'reserved' (fieldName) definitions on the site.
 * This parser is created because Wireshark is mainly implemented in plain ANSI C but the offical
 * Protocol Buffers Language parser is implemented in C++.
 */
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <glib.h>
#include <wsutil/file_util.h>
#include "protobuf_lang_tree.h"
DIAG_OFF_BYACC
#include "protobuf_lang.h"
#include "protobuf_lang_scanner_lex.h"
DIAG_ON_BYACC

#define NAME_TO_BE_SET "<NAME_TO_BE_SET>"
#define NEED_NOT_NAME "<NEED_NOT_NAME>"

/* Error handling function for bison */
void protobuf_langerror(void* yyscanner, protobuf_lang_state_t *state, const char *msg);

/* Extended error handling function */
void protobuf_langerrorv(void* yyscanner, protobuf_lang_state_t *state, const char *fmt, ...);

DIAG_OFF_BYACC
%}

%expect 23 /* suppress the warning about these conflicts */

%union {
    char* sval;
    pbl_node_t* node;
    int ival;
};

/* operations or symbols tokens */
%token PT_QUOTE PT_LPAREN PT_RPAREN PT_LBRACKET PT_RBRACKET PT_LCURLY PT_RCURLY PT_EQUAL PT_NOTEQUAL PT_NOTEQUAL2
%token PT_GEQUAL PT_LEQUAL PT_ASSIGN_PLUS PT_ASSIGN PT_PLUS PT_MINUS PT_MULTIPLY PT_DIV PT_LOGIC_OR PT_OR PT_LOGIC_AND
%token PT_AND PT_NOT PT_NEG PT_XOR PT_SHL PT_SHR PT_PERCENT PT_DOLLAR PT_COND PT_SEMICOLON PT_DOT PT_COMMA PT_COLON PT_LESS PT_GREATER

/* key words tokens */
%right <sval> PT_SYNTAX PT_IMPORT PT_WEAK PT_PUBLIC PT_PACKAGE PT_OPTION PT_REQUIRED PT_OPTIONAL
%right <sval> PT_REPEATED PT_ONEOF PT_MAP PT_RESERVED PT_ENUM PT_GROUP PT_EXTEND PT_EXTENSIONS
%right <sval> PT_MESSAGE PT_SERVICE PT_RPC PT_STREAM PT_RETURNS PT_TO PT_PROTO2 PT_PROTO3 PT_IDENT PT_STRLIT

%token <ival> PT_DECIMALLIT PT_OCTALLIT PT_HEXLIT

%type <sval> optionName label type keyType messageName enumName
%type <sval> streamName fieldName oneofName mapName serviceName rpcName messageType
%type <sval> groupName constant exIdent strLit

%type <node> protoBody topLevelDef message messageBody rpc rpcDecl field oneofField
%type <node> enum enumBody enumField service serviceBody stream streamDecl
%type <node> fieldOptions fieldOption oneof oneofBody mapField group extend extendBody

%type <ival> intLit fieldNumber

/* We don't care about following nodes:
syntax import package option enumValueOptions enumValueOption rpcBody streamBody
extensions reserved ranges range quoteFieldNames emptyStatement
*/

%start proto

%%

/* v2/v3: proto = syntax { import | package | option | topLevelDef | emptyStatement } */
/* Offical PBL bugfix: proto = { syntax } { import | package | option | topLevelDef | emptyStatement }
   The default syntax version is "proto2". */
proto:
  syntax wholeProtoBody
| wholeProtoBody
;

wholeProtoBody: protoBody
    {
        /* set real package name */
        pbl_set_node_name($1, state->file->package_name);
        /* use the allocate mem of the name of the package node */
        state->file->package_name = pbl_get_node_name($1);
        /* put this file data into package tables */
        pbl_node_t* packnode = (pbl_node_t*)g_hash_table_lookup(state->pool->packages, state->file->package_name);
        if (packnode) {
            pbl_merge_children(packnode, $1);
            pbl_free_node($1);
        } else {
            g_hash_table_insert(state->pool->packages, g_strdup(state->file->package_name), $1);
        }
    }
;

/* v2: syntax = "syntax" "=" quote "proto2" quote ";" */
/* v3: syntax = "syntax" "=" quote "proto3" quote ";" */
syntax:
  PT_SYNTAX PT_ASSIGN PT_PROTO2 PT_SEMICOLON  { state->file->syntax_version = 2; }
| PT_SYNTAX PT_ASSIGN PT_PROTO3 PT_SEMICOLON  { state->file->syntax_version = 3; }
;

protoBody:
  /* empty */ { $$ = pbl_create_node(state->file, PBL_PACKAGE, NAME_TO_BE_SET); } /* create am empty package node */
| protoBody import /* default action is { $$ = $1; } */
| protoBody package
| protoBody option
| protoBody topLevelDef  { $$ = $1; pbl_add_child($$, $2); }
| protoBody emptyStatement
;

/* v2/v3: import = "import" [ "weak" | "public" ] strLit ";" */
import:
  PT_IMPORT strLit PT_SEMICOLON { pbl_add_proto_file_to_be_parsed(state->pool, $2); } /* append file to todo list */
| PT_IMPORT PT_PUBLIC strLit PT_SEMICOLON { pbl_add_proto_file_to_be_parsed(state->pool, $3); }
| PT_IMPORT PT_WEAK strLit PT_SEMICOLON { pbl_add_proto_file_to_be_parsed(state->pool, $3); }
;

/* v2/v3: package = "package" fullIdent ";" */
package: PT_PACKAGE exIdent PT_SEMICOLON
    {   /* The memory of $2 will be freed after parsing, but the package_name will
           be replaced by the new-allocated name of package node late */
        state->file->package_name = $2;
    }
;

/* v2/v3: option = "option" optionName  "=" constant ";" */
/* Offical PBL bugfix: option = "option" optionName  "=" ( constant | customOptionValue ) ";" */
option:
  PT_OPTION optionName PT_ASSIGN constant PT_SEMICOLON
| PT_OPTION optionName PT_ASSIGN customOptionValue PT_SEMICOLON
;

/* v2/v3: optionName = ( ident | "(" fullIdent ")" ) { "." ident } */
optionName:
  exIdent
| PT_LPAREN exIdent PT_RPAREN  { $$ = pbl_store_string_token(state, g_strconcat("(", $2, ")", NULL)); }
| PT_LPAREN exIdent PT_RPAREN exIdent  { $$ = pbl_store_string_token(state, g_strconcat("(", $2, ")", $4, NULL)); } /* exIdent contains "." */
;

/* Allow format which not defined in offical PBL specification like:
    option (google.api.http) = { post: "/v3alpha/kv/put" body: "*" };
    option (google.api.http) = { post: "/v3alpha/kv/put", body: "*" };
    option (google.api.http) = { post: "/v3alpha/kv/put" { any format } body: "*" };
*/
customOptionValue: PT_LCURLY customOptionBody PT_RCURLY
;

customOptionBody:
  /* empty */
| customOptionBody exIdent
| customOptionBody strLit
| customOptionBody symbolsWithoutCurly
| customOptionBody intLit
| customOptionBody customOptionValue
;

symbolsWithoutCurly:
  PT_LPAREN | PT_RPAREN | PT_LBRACKET | PT_RBRACKET | PT_EQUAL | PT_NOTEQUAL | PT_NOTEQUAL2 | PT_GEQUAL
| PT_LEQUAL | PT_ASSIGN_PLUS | PT_ASSIGN | PT_PLUS | PT_MINUS | PT_MULTIPLY | PT_DIV | PT_LOGIC_OR | PT_OR
| PT_LOGIC_AND | PT_AND | PT_NOT | PT_NEG | PT_XOR | PT_SHL | PT_SHR | PT_PERCENT | PT_DOLLAR | PT_COND
| PT_SEMICOLON | PT_DOT | PT_COMMA | PT_COLON | PT_LESS | PT_GREATER
;

/* v2: topLevelDef = message | enum | extend | service */
/* v3: topLevelDef = message | enum | service */
topLevelDef:
  message
| enum
| extend /*v2 only */
| service
;

/* v2/v3: message = "message" messageName messageBody */
message: PT_MESSAGE messageName PT_LCURLY messageBody PT_RCURLY  { $$ = $4; pbl_set_node_name($$, $2); }
;

/* v2: messageBody = "{" { field | enum | message | extend | extensions | group | option | oneof | mapField | reserved | emptyStatement } "}" */
/* v3: messageBody = "{" { field | enum | message | option | oneof | mapField | reserved | emptyStatement } "}" */
messageBody:
  /* empty */  { $$ = pbl_create_node(state->file, PBL_MESSAGE, NAME_TO_BE_SET); }
| messageBody field  {  $$ = $1; pbl_add_child($$, $2); }
| messageBody enum  { $$ = $1; pbl_add_child($$, $2); }
| messageBody message  { $$ = $1; pbl_add_child($$, $2); }
| messageBody extend  /* v2 only */
| messageBody extensions /* v2 only */
| messageBody group /* v2 only */  { $$ = $1; pbl_add_child($$, $2); }
| messageBody option
| messageBody oneof  { $$ = $1; pbl_merge_children($$, $2); pbl_free_node($2); }
| messageBody mapField  { $$ = $1; pbl_add_child($$, $2); }
| messageBody reserved
| messageBody emptyStatement
;

/* v2/v3: enum = "enum" enumName enumBody */
/*        1       2        3        4         5  */
enum: PT_ENUM enumName PT_LCURLY enumBody PT_RCURLY  { $$ = $4; pbl_set_node_name($$, $2); }
;

/* v2/v3: enumBody = "{" { option | enumField | emptyStatement } "}" */
enumBody:
  /* empty */  { $$ = pbl_create_node(state->file, PBL_ENUM, NAME_TO_BE_SET); }
| enumBody option
| enumBody enumField  { $$ = $1; pbl_add_child($$, $2); }
| enumBody emptyStatement
;

/* v2/v3: enumField = ident "=" intLit [ "[" enumValueOption { ","  enumValueOption } "]" ]";" */
enumField:
  exIdent PT_ASSIGN intLit PT_LBRACKET enumValueOptions PT_RBRACKET PT_SEMICOLON
    { $$ = pbl_create_enum_value_node(state->file, $1, $3); }
| exIdent PT_ASSIGN intLit
    { $$ = pbl_create_enum_value_node(state->file, $1, $3); }
;

/* v2/v3: enumValueOption { ","  enumValueOption } */
enumValueOptions:
  enumValueOption
| enumValueOptions PT_COMMA enumValueOption

/* v2/v3: enumValueOption = optionName "=" constant */
enumValueOption: optionName PT_ASSIGN constant
;

/* v2: service = "service" serviceName "{" { option | rpc | stream | emptyStatement } "}" */
/* v3: service = "service" serviceName "{" { option | rpc | emptyStatement } "}" */
service: PT_SERVICE serviceName PT_LCURLY serviceBody PT_RCURLY  { $$ = $4; pbl_set_node_name($$, $2); }
;

serviceBody:
  /* empty */  { $$ = pbl_create_node(state->file, PBL_SERVICE, NAME_TO_BE_SET); }
| serviceBody option
| serviceBody rpc  { $$ = $1; pbl_add_child($$, $2); }
| serviceBody emptyStatement
| serviceBody stream /* v2 only */ { $$ = $1; pbl_add_child($$, $2); }
;

/* v2/v3: rpc = "rpc" rpcName "(" [ "stream" ] messageType ")" "returns" "(" [ "stream" ] messageType ")" (( "{" {option | emptyStatement } "}" ) | ";") */
rpc:
  rpcDecl PT_SEMICOLON
| rpcDecl PT_LCURLY rpcBody PT_RCURLY
;

/* "rpc" rpcName "(" [ "stream" ] messageType ")" "returns" "(" [ "stream" ] messageType ")" */
rpcDecl:
/*   1       2         3          4          5         6        7          8          9 */
  PT_RPC rpcName PT_LPAREN messageType PT_RPAREN PT_RETURNS PT_LPAREN messageType PT_RPAREN
    { $$ = pbl_create_method_node(state->file, $2, $4, FALSE, $8, FALSE); }
/*   1       2         3        4        5            6         7          8         9         10 */
| PT_RPC rpcName PT_LPAREN PT_STREAM messageType PT_RPAREN PT_RETURNS PT_LPAREN messageType PT_RPAREN
    { $$ = pbl_create_method_node(state->file, $2, $5, TRUE, $9, FALSE); }
/*   1      2        3          4          5          6         7          8         9         10 */
| PT_RPC rpcName PT_LPAREN messageType PT_RPAREN PT_RETURNS PT_LPAREN PT_STREAM messageType PT_RPAREN
    { $$ = pbl_create_method_node(state->file, $2, $4, FALSE, $9, TRUE); }
/*   1      2        3         4          5          6         7           8         9        10         11 */
| PT_RPC rpcName PT_LPAREN PT_STREAM messageType PT_RPAREN PT_RETURNS PT_LPAREN PT_STREAM messageType PT_RPAREN
    { $$ = pbl_create_method_node(state->file, $2, $5, TRUE, $10, TRUE); }
;

rpcBody:
  /* empty */
| rpcBody option
| rpcBody emptyStatement
;

/* v2: stream = "stream" streamName "(" messageType "," messageType ")" (( "{" { option | emptyStatement } "}") | ";" ) */
stream:
  streamDecl PT_SEMICOLON
| streamDecl PT_LCURLY streamBody PT_RCURLY
;

/* v2 only */
/*              1         2          3          4          5         6           7  */
streamDecl: PT_STREAM streamName PT_LPAREN messageType PT_COMMA messageType PT_RPAREN
    { $$ = pbl_create_method_node(state->file, $2, $4, TRUE, $6, TRUE); }
;

/* v2 only */
streamBody:
  /* empty */
| streamBody option
| streamBody emptyStatement
;

/* v2: label type fieldName "=" fieldNumber [ "[" fieldOptions "]" ] ";" */
/* v3: field = [ "repeated" ] type fieldName "=" fieldNumber [ "[" fieldOptions "]" ] ";" */
field:
/* 1      2           3         4           5   */
  type fieldName PT_ASSIGN fieldNumber PT_SEMICOLON
    { $$ = pbl_create_field_node(state->file, NULL, $1, $2, $4, NULL); }
/* 1      2           3         4           5           6            7           8   */
| type fieldName PT_ASSIGN fieldNumber PT_LBRACKET fieldOptions PT_RBRACKET PT_SEMICOLON
    { $$ = pbl_create_field_node(state->file, NULL, $1, $2, $4, $6); }
/* 1      2      3          4         5            6   */
| label type fieldName PT_ASSIGN fieldNumber PT_SEMICOLON
    { $$ = pbl_create_field_node(state->file, $1, $2, $3, $5, NULL); }
/* 1      2      3          4         5            6          7            8           9  */
| label type fieldName PT_ASSIGN fieldNumber PT_LBRACKET fieldOptions PT_RBRACKET PT_SEMICOLON
    { $$ = pbl_create_field_node(state->file, $1, $2, $3, $5, $7); }
;

/* v2: label = "required" | "optional" | "repeated" */
label: PT_REQUIRED | PT_OPTIONAL | PT_REPEATED;

/* v2/v3: type = "double" | "float" | "int32" | "int64" | "uint32" | "uint64"
      | "sint32" | "sint64" | "fixed32" | "fixed64" | "sfixed32" | "sfixed64"
      | "bool" | "string" | "bytes" | messageType | enumType
*/
type: exIdent;

fieldNumber: intLit;

/* v2/v3: fieldOptions = fieldOption { ","  fieldOption } */
fieldOptions:
  fieldOption
    { $$ = pbl_create_node(state->file, PBL_OPTIONS, NEED_NOT_NAME); pbl_add_child($$, $1); }
| fieldOptions PT_COMMA fieldOption
    { $$ = $1; pbl_add_child($$, $3); }
;

/* v2/v3: fieldOption = optionName "=" constant */
fieldOption: optionName PT_ASSIGN constant
    { $$ = pbl_create_option_node(state->file, $1, $3); }
;

/* v2 only: group = label "group" groupName "=" fieldNumber messageBody */
/*       1       2        3         4         5           6         7          8  */
group: label PT_GROUP groupName PT_ASSIGN fieldNumber PT_LCURLY messageBody PT_RCURLY
    { $$ = $7; pbl_set_node_name($$, $3); }
;

groupName: exIdent;

/* v2/v3: oneof = "oneof" oneofName "{" { oneofField | emptyStatement } "}" */
/*         1        2         3         4         5  */
oneof: PT_ONEOF oneofName PT_LCURLY oneofBody PT_RCURLY { $$ = $4; pbl_set_node_name($$, $2); }
;

oneofBody:
  /* empty */  { $$ = pbl_create_node(state->file, PBL_ONEOF, NAME_TO_BE_SET); }
| oneofBody oneofField { $$ = $1; pbl_add_child($$, $2); }
| oneofBody emptyStatement
;

/* v2/v3: oneofField = type fieldName "=" fieldNumber [ "[" fieldOptions "]" ] ";" */
oneofField:
/*  1      2          3         4           5           6            7           8   */
  type fieldName PT_ASSIGN fieldNumber PT_LBRACKET fieldOptions PT_RBRACKET PT_SEMICOLON
    { $$ = pbl_create_field_node(state->file, NULL, $1, $2, $4, $6); }
/*  1      2          3         4           5   */
| type fieldName PT_ASSIGN fieldNumber PT_SEMICOLON
    { $$ = pbl_create_field_node(state->file, NULL, $1, $2, $4, NULL); }
;

/* v2/v3: mapField = "map" "<" keyType "," type ">" mapName "=" fieldNumber [ "[" fieldOptions "]" ] ";" */
mapField:
/*   1      2       3        4      5       6        7        8         9            10          11          12          13  */
  PT_MAP PT_LESS keyType PT_COMMA type PT_GREATER mapName PT_ASSIGN fieldNumber PT_LBRACKET fieldOptions PT_RBRACKET PT_SEMICOLON
    {
        $$ = pbl_create_map_field_node(state->file, $7, $9, $11);
        pbl_add_child($$, pbl_create_field_node(state->file, NULL, $3, "key", 1, NULL)); /* add key field */
        pbl_add_child($$, pbl_create_field_node(state->file, NULL, $5, "value", 2, NULL)); /* add value field */
    }
/*   1      2       3        4      5       6        7        8         9            10   */
| PT_MAP PT_LESS keyType PT_COMMA type PT_GREATER mapName PT_ASSIGN fieldNumber PT_SEMICOLON
    {
        $$ = pbl_create_map_field_node(state->file, $7, $9, NULL);
        pbl_add_child($$, pbl_create_field_node(state->file, NULL, $3, "key", 1, NULL)); /* add key field */
        pbl_add_child($$, pbl_create_field_node(state->file, NULL, $5, "value", 2, NULL)); /* add value field */
    }
;

/* keyType = "int32" | "int64" | "uint32" | "uint64" | "sint32" | "sint64" |
          "fixed32" | "fixed64" | "sfixed32" | "sfixed64" | "bool" | "string" */
keyType: exIdent
;

/* v2 only: extensions = "extensions" ranges ";" */
extensions: PT_EXTENSIONS ranges PT_SEMICOLON
;

/* v2/v3: reserved = "reserved" ( ranges | fieldNames ) ";" */
reserved:
  PT_RESERVED ranges PT_SEMICOLON
| PT_RESERVED quoteFieldNames PT_SEMICOLON
;

/* v2/v3: ranges = range { "," range } */
ranges:
  range
| ranges PT_COMMA range
;

/* v2/v3: range =  intLit [ "to" ( intLit | "max" ) ] */
range:
  intLit
| intLit PT_TO intLit
| intLit PT_TO exIdent
;

/* v2/v3: fieldNames = fieldName { "," fieldName }
Note: There is an error in BNF definition about reserved fieldName. It's strLit not ident.
*/
quoteFieldNames:
  strLit
| quoteFieldNames PT_COMMA strLit
;

/* v2 only: extend = "extend" messageType "{" {field | group | emptyStatement} "}" */
/*          1           2         3          4         5 */
extend: PT_EXTEND messageType PT_LCURLY extendBody PT_RCURLY
    { $$ = $4; pbl_set_node_name($$, pbl_store_string_token(state, g_strconcat($2, "Extend", NULL))); }
;

/* v2 only */
extendBody:
  /* empty */ { $$ = pbl_create_node(state->file, PBL_MESSAGE, NAME_TO_BE_SET); }
| extendBody field { $$ = $1; pbl_add_child($$, $2); }
| extendBody group { $$ = $1; pbl_add_child($$, $2); }
| extendBody emptyStatement
;

messageName: exIdent;
enumName: exIdent;
streamName: exIdent;
fieldName: exIdent;
oneofName: exIdent;
mapName: exIdent;
serviceName: exIdent;
rpcName: exIdent;

/* messageType = [ "." ] { ident "." } messageName */
messageType: exIdent
;

/* enumType = [ "." ] { ident "." } enumName */
/*enumType: exIdent*/
;

/* intLit     = decimalLit | octalLit | hexLit */
intLit: PT_DECIMALLIT | PT_OCTALLIT | PT_HEXLIT
;

/* emptyStatement = ";" */
emptyStatement: PT_SEMICOLON;

/* constant = fullIdent | ( [ "-" | "+" ] intLit ) | ( [ "-" | "+" ] floatLit ) | strLit | boolLit */
constant: exIdent | strLit
;

exIdent: PT_IDENT
| PT_SYNTAX | PT_IMPORT | PT_WEAK | PT_PUBLIC | PT_PACKAGE | PT_OPTION
| PT_ONEOF | PT_MAP | PT_RESERVED | PT_ENUM | PT_GROUP | PT_EXTEND | PT_EXTENSIONS
| PT_MESSAGE | PT_SERVICE | PT_RPC | PT_STREAM | PT_RETURNS | PT_TO | label
;

strLit: PT_STRLIT | PT_PROTO2 | PT_PROTO3
;

%%

DIAG_ON_BYACC

int
pbl_get_current_lineno(void* scanner)
{
    return protobuf_langget_lineno(scanner);
}

void
protobuf_langerror(void* yyscanner, protobuf_lang_state_t *state, const char *msg)
{
    int lineno;
    void(*error_cb)(const char *format, ...);
    const char* filepath = (state && state->file) ?
                            state->file->filename : "UNKNOWN";

    error_cb = (state && state->pool->error_cb) ?
                state->pool->error_cb : pbl_printf;

    lineno = yyscanner ? protobuf_langget_lineno(yyscanner) : -1;

    if (lineno > -1) {
        error_cb("Protobuf: Parsing file [%s:%d] failed: %s\n", filepath, lineno, msg);
    } else {
        error_cb("Protobuf: Parsing file [%s] failed: %s\n", filepath, msg);
    }
}

void
protobuf_langerrorv(void* yyscanner, protobuf_lang_state_t *state, const char *fmt, ...)
{
    char* msg;
    va_list ap;
    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    protobuf_langerror(yyscanner, state, msg);
    va_end(ap);
    g_free(msg);
}

void
pbl_parser_error(protobuf_lang_state_t *state, const char *fmt, ...)
{
    char* msg;
    void* scanner;
    va_list ap;
    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    scanner = state ? state->scanner : NULL;
    protobuf_langerror(scanner, state, msg);
    va_end(ap);
    g_free(msg);
}

static void
pbl_clear_state(protobuf_lang_state_t *state, pbl_descriptor_pool_t* pool)
{
    if (state == NULL) {
        return;
    }

    state->pool = NULL;
    state->file = NULL;
    state->scanner = NULL;

    if (state->lex_string_tokens) {
        g_slist_free_full(state->lex_string_tokens, g_free);
    }
    state->lex_string_tokens = NULL;

    if (pool) {
        pool->parser_state = NULL;
    }
}

static void
pbl_reinit_state(protobuf_lang_state_t *state, pbl_descriptor_pool_t* pool, const char* filepath)
{
    if (state == NULL) {
        return;
    }
    pbl_clear_state(state, pool);

    state->pool = pool;
    state->file = (pbl_file_descriptor_t*) g_hash_table_lookup(pool->proto_files, filepath);

    if (pool) {
        pool->parser_state = state;
    }
}

int run_pbl_parser(pbl_descriptor_pool_t* pool)
{
    protobuf_lang_state_t state = {0};
    yyscan_t scanner;
    GSList* it;
    FILE * fp;
    int status;
    const char* filepath;

    it = pool->proto_files_to_be_parsed;
    while (it) {
        filepath = (const char*) it->data;
        /* reinit state and scanner */
        pbl_reinit_state(&state, pool, filepath);
        scanner = NULL;

        /* Note that filepath is absolute path in proto_files */
        fp = ws_fopen(filepath, "r");
        if (fp == NULL) {
            protobuf_langerrorv(NULL, &state, "File does not exists!");
            pbl_clear_state(&state, pool);
            return -1;
        }

        status = protobuf_langlex_init(&scanner);
        if (status != 0) {
            protobuf_langerrorv(NULL, &state, "Initialize Protocol Buffers Languange scanner failed!\n");
            fclose(fp);
            pbl_clear_state(&state, pool);
            return status;
        }

        /* associate the parser state with the lexical analyzer state */
        protobuf_langset_extra(&state, scanner);
        state.scanner = scanner;

        protobuf_langrestart(fp, scanner);
        status = protobuf_langparse(scanner, &state);
        fclose(fp);
        if (status != 0) {
            /* grammar errors should have been reported during parsing */
            pbl_clear_state(&state, pool);
            return status;
        }

        /* remove the parsed file from list */
        pool->proto_files_to_be_parsed = it = g_slist_delete_link(pool->proto_files_to_be_parsed, it);
    }

    return 0;
}

DIAG_OFF_BYACC
