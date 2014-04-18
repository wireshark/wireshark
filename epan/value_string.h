/* value_string.h
 * Definitions for value_string structures and routines
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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include "ws_symbol_export.h"

/* VALUE TO STRING MATCHING */

typedef struct _value_string {
    guint32      value;
    const gchar *strptr;
} value_string;

#if 0
  /* -----  VALUE_STRING "Helper" macros ----- */

  /* Essentially: Provide the capability to define a list of value_strings once and
     then to expand the list as an enum and/or as a value_string array. */

  /* Usage: */

  /*- define list of value strings -*/
     #define foo_VALUE_STRING_LIST(XXX) \
        XXX( FOO_A, 1, "aaa" ) \
        XXX( FOO_B, 3, "bbb" )

  /*- gen enum -*/
     VALUE_STRING_ENUM(foo);      /* gen's 'enum {FOO_A=1, FOO_B=3};' */

  /*- gen value_string array -*/
     /* local */
     VALUE_STRING_ARRAY(foo);     /* gen's 'static const value_string foo[] = {{1,"aaa"}, {3,"bbb"}}; */

     /* global */
     VALUE_STRING_ARRAY_GLOBAL_DEF(foo); /* gen's 'const value_string foo[] = {{1,"aaa"}, {3,"bbb"}}; */
     VALUE_STRING_ARRAY_GLOBAL_DCL(foo); /* gen's 'const value_string foo[]; */

  /* Alternatively: */
     #define bar_VALUE_STRING_LIST(XXX) \
        XXX( BAR_A, 1) \
        XXX( BAR_B, 3)

     VALUE_STRING_ENUM2(bar);     /* gen's 'enum {BAR_A=1, BAR_B=3};' */
     VALUE_STRING_ARRAY2(bar);    /* gen's 'static const value_string bar[] = {{1,"BAR_A"}, {3,"BAR_B"}}; */
     ...
#endif

/* -- Public -- */
#define VALUE_STRING_ENUM(              array_name) _VS_ENUM_XXX( array_name, _VS_ENUM_ENTRY)
#define VALUE_STRING_ARRAY(             array_name) _VS_ARRAY_SC_XXX(array_name, _VS_ARRAY_ENTRY, static)
#define VALUE_STRING_ARRAY_GLOBAL_DEF(  array_name) _VS_ARRAY_XXX(array_name, _VS_ARRAY_ENTRY)
#define VALUE_STRING_ARRAY_GLOBAL_DCL(  array_name) _VS_ARRAY_SC_TYPE_NAME(array_name, extern)

#define VALUE_STRING_ENUM2(             array_name) _VS_ENUM_XXX( array_name, _VS_ENUM_ENTRY2)
#define VALUE_STRING_ARRAY2(            array_name) _VS_ARRAY_SC_XXX(array_name, _VS_ARRAY_ENTRY2, static)
#define VALUE_STRING_ARRAY2_GLOBAL_DEF( array_name) _VS_ARRAY_XXX(array_name, _VS_ARRAY_ENTRY2)
#define VALUE_STRING_ARRAY2_GLOBAL_DCL( array_name) _VS_ARRAY_SC_TYPE_NAME(array_name, extern)

/* -- Private -- */
#define _VS_ENUM_XXX(array_name, macro) \
enum { \
    array_name##_VALUE_STRING_LIST(macro) \
    _##array_name##_ENUM_DUMMY = 0 \
}

#define _VS_ARRAY_SC_XXX(array_name, macro, sc)  \
    _VS_ARRAY_SC_TYPE_NAME(array_name, sc) = { \
    array_name##_VALUE_STRING_LIST(macro) \
    { 0, NULL } \
}

#define _VS_ARRAY_XXX(array_name, macro)  \
    _VS_ARRAY_TYPE_NAME(array_name) = { \
    array_name##_VALUE_STRING_LIST(macro) \
    { 0, NULL } \
}

#define _VS_ARRAY_SC_TYPE_NAME(array_name, sc) sc const value_string array_name[]
#define _VS_ARRAY_TYPE_NAME(array_name) const value_string array_name[]

#define _VS_ENUM_ENTRY( name, value, string) name = value,
#define _VS_ARRAY_ENTRY(name, value, string) { value, string },

#define _VS_ENUM_ENTRY2( name, value) name = value,
#define _VS_ARRAY_ENTRY2(name, value) { value, #name },
/* ----- ----- */

WS_DLL_PUBLIC
const gchar *
val_to_str(const guint32 val, const value_string *vs, const char *fmt);

WS_DLL_PUBLIC
const gchar *
val_to_str_const(const guint32 val, const value_string *vs, const char *unknown_str);

WS_DLL_PUBLIC
const gchar *
try_val_to_str(const guint32 val, const value_string *vs);

WS_DLL_PUBLIC
const gchar *
try_val_to_str_idx(const guint32 val, const value_string *vs, gint *idx);

/* 64-BIT VALUE TO STRING MATCHING */

typedef struct _val64_string {
    guint64      value;
    const gchar *strptr;
} val64_string;

WS_DLL_PUBLIC
const gchar *
val64_to_str(const guint64 val, const val64_string *vs, const char *fmt);

WS_DLL_PUBLIC
const gchar *
val64_to_str_const(const guint64 val, const val64_string *vs, const char *unknown_str);

WS_DLL_PUBLIC
const gchar *
try_val64_to_str(const guint64 val, const val64_string *vs);

WS_DLL_PUBLIC
const gchar *
try_val64_to_str_idx(const guint64 val, const val64_string *vs, gint *idx);

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
    guint32                _vs_first_value; /* first value of the value_string array       */
    guint                  _vs_num_entries; /* number of entries in the value_string array */
                                            /*  (excluding final {0, NULL})                */
    const value_string    *_vs_p;           /* the value string array address              */
    const gchar           *_vs_name;        /* vse "Name" (for error messages)             */
} value_string_ext;

#define VALUE_STRING_EXT_VS_P(x)           (x)->_vs_p
#define VALUE_STRING_EXT_VS_NUM_ENTRIES(x) (x)->_vs_num_entries
#define VALUE_STRING_EXT_VS_NAME(x)        (x)->_vs_name

WS_DLL_PUBLIC
const value_string *
_try_val_to_str_ext_init(const guint32 val, const value_string_ext *vse);
#define VALUE_STRING_EXT_INIT(x) { _try_val_to_str_ext_init, 0, G_N_ELEMENTS(x)-1, x, #x }

WS_DLL_PUBLIC
const value_string_ext *
value_string_ext_new(const value_string *vs, guint vs_tot_num_entries, const gchar *vs_name);

WS_DLL_PUBLIC
void
value_string_ext_free(const value_string_ext *vse);

WS_DLL_PUBLIC
const gchar *
val_to_str_ext(const guint32 val, const value_string_ext *vs, const char *fmt);

WS_DLL_PUBLIC
const gchar *
val_to_str_ext_const(const guint32 val, const value_string_ext *vs, const char *unknown_str);

WS_DLL_PUBLIC
const gchar *
try_val_to_str_ext(const guint32 val, const value_string_ext *vse);

WS_DLL_PUBLIC
const gchar *
try_val_to_str_idx_ext(const guint32 val, const value_string_ext *vse, gint *idx);

/* STRING TO STRING MATCHING */

typedef struct _string_string {
    const gchar *value;
    const gchar *strptr;
} string_string;

WS_DLL_PUBLIC
const gchar *
str_to_str(const gchar *val, const string_string *vs, const char *fmt);

WS_DLL_PUBLIC
const gchar *
try_str_to_str(const gchar *val, const string_string *vs);

WS_DLL_PUBLIC
const gchar *
try_str_to_str_idx(const gchar *val, const string_string *vs, gint *idx);

/* RANGE TO STRING MATCHING */

typedef struct _range_string {
    guint32      value_min;
    guint32      value_max;
    const gchar *strptr;
} range_string;

WS_DLL_PUBLIC
const gchar *
rval_to_str(const guint32 val, const range_string *rs, const char *fmt);

WS_DLL_PUBLIC
const gchar *
rval_to_str_const(const guint32 val, const range_string *rs, const char *unknown_str);

WS_DLL_PUBLIC
const gchar *
try_rval_to_str(const guint32 val, const range_string *rs);

WS_DLL_PUBLIC
const gchar *
try_rval_to_str_idx(const guint32 val, const range_string *rs, gint *idx);

/* MISC (generally do not use) */

WS_DLL_LOCAL
gboolean
value_string_ext_validate(const value_string_ext *vse);

WS_DLL_LOCAL
const gchar *
value_string_ext_match_type_str(const value_string_ext *vse);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __VALUE_STRING_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
