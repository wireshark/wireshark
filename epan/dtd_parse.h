/* dtd_parse.h
 * an XML dissector for Wireshark
 * header file to declare functions defined in lexer and used in parser,
 * or vice versa
 *
 * Copyright 2004, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

extern void DtdParse(void*,int,dtd_token_data_t*,dtd_build_data_t*);
extern void *DtdParseAlloc(void *(*)(gsize));
extern void DtdParseFree( void*, void(*)(void*) );
extern void DtdParseTrace(FILE *TraceFILE, char *zTracePrompt);
