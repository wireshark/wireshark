/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _DFILTER_MACRO_H
#define _DFILTER_MACRO_H

#include <wireshark.h>
#include "dfilter.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _dfilter_macro_t {
	char* name; /* the macro id */
	char* text; /* raw data from file */
	bool usable; /* macro is usable */
	char** parts; /* various segments of text between insertion targets */
	int* args_pos; /* what's to be inserted */
	int argc; /* the expected number of arguments */
	void* priv; /* a copy of text that contains every c-string in parts */
} dfilter_macro_t;

void macro_parse(dfilter_macro_t *m);

/* applies all macros to the given text and returns the resulting string or NULL on failure */
char* dfilter_macro_apply(const char* text, df_error_t** error);

void dfilter_macro_init(void);

WS_DLL_PUBLIC
void dfilter_macro_reload(void);

void dfilter_macro_cleanup(void);

struct dfilter_macro_table_iter {
	GHashTableIter iter;
};

WS_DLL_PUBLIC
size_t
dfilter_macro_table_count(void);

WS_DLL_PUBLIC
void
dfilter_macro_table_iter_init(struct dfilter_macro_table_iter *iter);

WS_DLL_PUBLIC
bool
dfilter_macro_table_iter_next(struct dfilter_macro_table_iter *iter,
				const char **name_ptr, const char **text_ptr);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _DFILTER_MACRO_H */
