/* value_string.h
 * Definitions for value_string structures and routines
 *
 * $Id$
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

#ifndef __VALUE_STRING_H__
#define __VALUE_STRING_H__

#include <glib.h>
#include "ws_symbol_export.h"

/* VALUE TO STRING MATCHING */

typedef struct _value_string {
  guint32  value;
  const gchar   *strptr;
} value_string;

WS_DLL_PUBLIC
const gchar*
val_to_str(const guint32 val, const value_string *vs, const char *fmt);

WS_DLL_PUBLIC
const gchar*
val_to_str_const(const guint32 val, const value_string *vs, const char *unknown_str);

WS_DLL_PUBLIC
const gchar*
try_val_to_str(const guint32 val, const value_string *vs);

WS_DLL_PUBLIC
const gchar*
try_val_to_str_idx(const guint32 val, const value_string *vs, gint *idx);

/* STRING TO VALUE MATCHING */

WS_DLL_PUBLIC
guint32
str_to_val(const gchar *val, const value_string *vs, const guint32 err_val);

WS_DLL_PUBLIC
gint
str_to_val_idx(const gchar *val, const value_string *vs);

/* EXTENDED VALUE TO STRING MATCHING */

struct _value_string_ext;
typedef const value_string *(*_value_string_match2_t)(const guint32, const struct _value_string_ext *);

typedef struct _value_string_ext {
  _value_string_match2_t _vs_match2;
  guint32 _vs_first_value;    /* first value of the value_string array       */
  guint   _vs_num_entries;    /* number of entries in the value_string array */
                              /*  (excluding final {0, NULL})                */
  const value_string *_vs_p;  /* the value string array address              */
  const gchar *_vs_name;      /* vse "Name" (for error messages)             */
} value_string_ext;

#define VALUE_STRING_EXT_VS_P(x) (x)->_vs_p
#define VALUE_STRING_EXT_VS_NUM_ENTRIES(x) (x)->_vs_num_entries
#define VALUE_STRING_EXT_VS_NAME(x) (x)->_vs_name

WS_DLL_PUBLIC
const value_string*
_try_val_to_str_ext_init(const guint32 val, const value_string_ext *vse);
#define VALUE_STRING_EXT_INIT(x) { _try_val_to_str_ext_init, 0, array_length(x)-1, x, #x }

WS_DLL_PUBLIC
value_string_ext*
value_string_ext_new(value_string *vs, guint vs_tot_num_entries, const gchar *vs_name);

WS_DLL_PUBLIC
const gchar*
val_to_str_ext(const guint32 val, const value_string_ext *vs, const char *fmt);

WS_DLL_PUBLIC
const gchar*
val_to_str_ext_const(const guint32 val, const value_string_ext *vs, const char *unknown_str);

WS_DLL_PUBLIC
const gchar*
try_val_to_str_ext(const guint32 val, const value_string_ext *vse);

WS_DLL_PUBLIC
const gchar*
try_val_to_str_idx_ext(const guint32 val, value_string_ext *vse, gint *idx);

/* STRING TO STRING MATCHING */

typedef struct _string_string {
  const gchar   *value;
  const gchar   *strptr;
} string_string;

WS_DLL_PUBLIC
const gchar*
str_to_str(const gchar *val, const string_string *vs, const char *fmt);

WS_DLL_PUBLIC
const gchar*
try_str_to_str(const gchar *val, const string_string *vs);

WS_DLL_PUBLIC
const gchar*
try_str_to_str_idx(const gchar *val, const string_string *vs, gint *idx);

/* RANGE TO STRING MATCHING */

typedef struct _range_string {
  guint32        value_min;
  guint32        value_max;
  const gchar   *strptr;
} range_string;

WS_DLL_PUBLIC
const gchar*
rval_to_str(const guint32 val, const range_string *rs, const char *fmt);

WS_DLL_PUBLIC
const gchar*
try_rval_to_str(const guint32 val, const range_string *rs);

WS_DLL_PUBLIC
const gchar*
try_rval_to_str_idx(const guint32 val, const range_string *rs, gint *idx);

/* MISC (generally do not use) */

WS_DLL_LOCAL
gboolean
value_string_ext_validate(const value_string_ext *vse);

WS_DLL_LOCAL
const gchar*
value_string_ext_match_type_str(const value_string_ext *vse);

#endif /* __VALUE_STRING_H__ */
