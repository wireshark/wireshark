/** @file
 * Definitions for column handling routines
 * Column preference and format settings.
 *
 * For internal Wireshark useonly. Don't include this header in dissectors!
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __COLUMN_H__
#define __COLUMN_H__

#include "ws_symbol_export.h"
#include <epan/column-utils.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct _fmt_data {
  gchar *title;            /* title of the column */
  int fmt;                 /* format of column */
  gchar *custom_fields;    /* fields names for COL_CUSTOM */
  gint custom_occurrence;  /* optional ordinal of occurrence of that field */
  gboolean visible;        /* if FALSE, hide this column */
  gboolean resolved;       /* if TRUE, show a more human-readable name */
} fmt_data;

WS_DLL_PUBLIC
const gchar         *col_format_to_string(const gint);
WS_DLL_PUBLIC
const gchar         *col_format_desc(const gint);
WS_DLL_PUBLIC
gint                 get_column_format(const gint);
WS_DLL_PUBLIC
void                 set_column_format(const gint, const gint);
WS_DLL_PUBLIC
void                 get_column_format_matches(gboolean *, const gint);
WS_DLL_PUBLIC
gint                 get_column_format_from_str(const gchar *);
WS_DLL_PUBLIC
gchar               *get_column_title(const gint);
WS_DLL_PUBLIC
void                 set_column_title(const gint, const gchar *);
WS_DLL_PUBLIC
gboolean             get_column_visible(const gint);
WS_DLL_PUBLIC
void                 set_column_visible(const gint, gboolean);
WS_DLL_PUBLIC
gboolean             get_column_resolved(const gint);
WS_DLL_PUBLIC
void                 set_column_resolved(const gint, gboolean);
WS_DLL_PUBLIC
const gchar         *get_column_custom_fields(const gint);
WS_DLL_PUBLIC
void                 set_column_custom_fields(const gint, const char *);
WS_DLL_PUBLIC
gint                 get_column_custom_occurrence(const gint);
WS_DLL_PUBLIC
void                 set_column_custom_occurrence(const gint, const gint);
WS_DLL_PUBLIC
const gchar         *get_column_width_string(const gint, const gint);
WS_DLL_PUBLIC
gint                 get_column_char_width(const gint format);
WS_DLL_PUBLIC
gchar               *get_column_tooltip(const gint col);

/** Get the text of a column element. The string returned may
 * depend on whether the resolved member variable is set.
 * For internal Wireshark use, not to be called from dissectors.
 * Dissectors use col_get_text() in column-utils.h
 *
 * @param cinfo the column information
 * @param col the column index to use (not the format)
 *
 * @return the text string
 */
WS_DLL_PUBLIC
const gchar         *get_column_text(column_info *cinfo, const gint col);

WS_DLL_PUBLIC
void
col_finalize(column_info *cinfo);

WS_DLL_PUBLIC
void
build_column_format_array(column_info *cinfo, const gint num_cols, const gboolean reset_fences);

WS_DLL_PUBLIC
void                 column_dump_column_formats(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* column.h */
