/* dfilter-macro.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

void dfilter_macro_cleanup(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _DFILTER_MACRO_H */
