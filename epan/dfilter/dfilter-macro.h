/* dfilter-macro.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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

#ifndef _DFILTER_MACRO_H
#define _DFILTER_MACRO_H

#include "ws_symbol_export.h"


#define DFILTER_MACRO_FILENAME "dfilter_macros"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _dfilter_macro_t {
	gchar* name; /* the macro id */
	gchar* text; /* raw data from file */
	gboolean usable; /* macro is usable */
	gchar** parts; /* various segments of text between insertion targets */
	int* args_pos; /* what's to be inserted */
	int argc; /* the expected number of arguments */
	void* priv; /* a copy of text that contains every c-string in parts */
} dfilter_macro_t;

/* applies all macros to the given text and returns the resulting string or NULL on failure */
gchar* dfilter_macro_apply(const gchar* text, gchar** error);

void dfilter_macro_init(void);

struct epan_uat;

WS_DLL_PUBLIC
void dfilter_macro_get_uat(struct epan_uat **dfmu_ptr_ptr);

WS_DLL_PUBLIC
void dfilter_macro_build_ftv_cache(void* tree_root);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _DFILTER_MACRO_H */
