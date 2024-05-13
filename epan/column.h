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
  char *title;            /* title of the column */
  int fmt;                 /* format of column */
  char *custom_fields;    /* fields names for COL_CUSTOM */
  int custom_occurrence;  /* optional ordinal of occurrence of that field */
  bool visible;            /* if false, hide this column */
  bool resolved;           /* if true, show a more human-readable name */
} fmt_data;

WS_DLL_PUBLIC
const char          *col_format_to_string(const int);
WS_DLL_PUBLIC
const char          *col_format_desc(const int);
WS_DLL_PUBLIC
const char          *col_format_abbrev(const int);
WS_DLL_PUBLIC
int                  get_column_format(const int);
WS_DLL_PUBLIC
void                 set_column_format(const int, const int);
WS_DLL_PUBLIC
void                 get_column_format_matches(bool *, const int);
WS_DLL_PUBLIC
int                  get_column_format_from_str(const char *);
WS_DLL_PUBLIC
char                *get_column_title(const int);
WS_DLL_PUBLIC
void                 set_column_title(const int, const char *);
WS_DLL_PUBLIC
bool                 get_column_visible(const int);
WS_DLL_PUBLIC
void                 set_column_visible(const int, bool);
WS_DLL_PUBLIC
bool                 get_column_resolved(const int);
WS_DLL_PUBLIC
void                 set_column_resolved(const int, bool);
WS_DLL_PUBLIC
const char          *get_column_custom_fields(const int);
WS_DLL_PUBLIC
void                 set_column_custom_fields(const int, const char *);
WS_DLL_PUBLIC
int                  get_column_custom_occurrence(const int);
WS_DLL_PUBLIC
void                 set_column_custom_occurrence(const int, const int);
WS_DLL_PUBLIC
const char          *get_column_longest_string(const int);
WS_DLL_PUBLIC
const char          *get_column_width_string(const int, const int);
WS_DLL_PUBLIC
int                  get_column_char_width(const int format);
WS_DLL_PUBLIC
char                *get_column_tooltip(const int col);

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
const char          *get_column_text(column_info *cinfo, const int col);

WS_DLL_PUBLIC
void
col_finalize(column_info *cinfo);

WS_DLL_PUBLIC
void
build_column_format_array(column_info *cinfo, const int num_cols, const bool reset_fences);

WS_DLL_PUBLIC
void                 column_dump_column_formats(void);

/** Parse a column format string into a fmt_data struct.
 * If the format string possibly can be that of a deprecated column
 * that has been migrated to a custom column (e.g., upon first being
 * read from a preference file), call try_convert_to_custom_column() first.
 *
 * @param[out] cfmt The parsed cfmt, still owned by the caller.
 * For custom columns, the caller is responsible for freeing
 * the custom_fields member as well.
 * @param[in] fmt The column format to parse.
 *
 * @return true if conversion was successful, false if unsuccessful
 */
WS_DLL_PUBLIC
bool parse_column_format(fmt_data *cfmt, const char *fmt);

/** Checks a column format string to see if it is a deprecated column
 * that has been migrated to a custom column, and converts the format
 * to the corresponding custom column format if so, otherwise leaving
 * it unchanged.
 *
 * @param[in,out] fmt The column format to check and possibly convert.
 */
WS_DLL_PUBLIC
void try_convert_to_custom_column(char **fmt);

/** Checks a column field string to see if it is a name of a filter
 * field created using a default column title (as used in tshark -e),
 * and alias it to the new column type based field.
 *
 * @param[in] field The old title based field, e.g. "_ws.col.Info"
 * @return The new field, e.g. "_ws.col.info", or NULL
 */
WS_DLL_PUBLIC
const char* try_convert_to_column_field(const char *field);

WS_DLL_PUBLIC
void column_register_fields(void);
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* column.h */
