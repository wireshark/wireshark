/*
 *  ex-opt.h
 *
 * eXtension command line options
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis@ontanon.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _EX_OPT_H
#define _EX_OPT_H

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* will be called by main each time a -X option is found */
WS_DLL_PUBLIC gboolean ex_opt_add(const gchar* optarg);

/* yields the number of arguments of a given key obviously returns 0 if there aren't */
WS_DLL_PUBLIC gint ex_opt_count(const gchar* key);

/* fetches the nth argument of a given key returns NULL if there isn't */
WS_DLL_PUBLIC const gchar* ex_opt_get_nth(const gchar* key, guint key_index);

/* extracts the next value of a given key */
WS_DLL_PUBLIC const gchar* ex_opt_get_next(const gchar* key);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _EX_OPT_H */
