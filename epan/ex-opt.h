/** @file
 *
 * eXtension command line options
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _EX_OPT_H
#define _EX_OPT_H

#include <stdbool.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* will be called by main each time a -X option is found */
WS_DLL_PUBLIC bool ex_opt_add(const char* ws_optarg);

/* yields the number of arguments of a given key obviously returns 0 if there aren't */
WS_DLL_PUBLIC int ex_opt_count(const char* key);

/* fetches the nth argument of a given key returns NULL if there isn't */
WS_DLL_PUBLIC const char* ex_opt_get_nth(const char* key, unsigned key_index);

/* extracts the next value of a given key */
WS_DLL_PUBLIC const char* ex_opt_get_next(const char* key);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _EX_OPT_H */
