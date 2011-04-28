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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __VALUE_STRING_H__
#define __VALUE_STRING_H__

#include <glib.h>

/* Struct for the val_to_str, match_strval_idx, and match_strval functions */

typedef struct _value_string {
  guint32  value;
  const gchar   *strptr;
} value_string;

/* Struct for the str_to_str, match_strstr_idx, and match_strstr functions */

typedef struct _string_string {
  const gchar   *value;
  const gchar   *strptr;
} string_string;

/* Struct for the rval_to_str, match_strrval_idx, and match_strrval functions */
typedef struct _range_string {
  guint32        value_min;
  guint32        value_max;
  const gchar   *strptr;
} range_string;

/* #define VS_DEF(x) { x, #x } */
/* #define VS_END    { 0, NULL } */

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
extern const gchar* match_strval_idx(const guint32 val, const value_string *vs, gint *idx);

/* Like match_strval_idx(), but doesn't return the index. */
extern const gchar* match_strval(const guint32 val, const value_string *vs);

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
extern const gchar* val_to_str(const guint32 val, const value_string *vs, const char *fmt);


/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Returns 'unknown_str', on failure. */
extern const gchar* val_to_str_const(const guint32 val, const value_string *vs, const char *unknown_str);

/* Tries to match val against each element in the string_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
extern const gchar* match_strstr_idx(const gchar *val, const string_string *vs, gint *idx);

/* Like match_strstr_idx(), but doesn't return the index. */
extern const gchar* match_strstr(const gchar *val, const string_string *vs);

/* Tries to match val against each element in the string_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
extern const gchar* str_to_str(const gchar *val, const string_string *vs, const char *fmt);

/* --------------------------------------------------------------------*/
/* value_string_ext functions
 *
 *   Extended value strings allow fast(er) value_string array lookups by
 *    using (if possible) direct access or a binary search of the array.
 *
 *    If the values in the value_string array are a contiguous range of values
 *    from min to max, the value will be used as as a direct index into the array.
 *
 *    If the values in the array are not contiguous (ie: there are "gaps"),
 *    but are in assending order a binary search will be used.
 *
 *    If direct access or binary search cannot be used, then a linear search
 *    is used.
 *
 *    Note that the value_string array used with VALUE_STRING_EXT_INIT
 *     *must* be terminated with {0, NULL}).
 *
 *    Extended value strings are defined at compile time as follows:
 *      static const value_string vs[] = { {value1, "string1"}, {value2, "string2"}, ..., {0, NULL}};
 *      static value_string_ext vse = VALUE_STRING_EXT_INIT(vs);
 *
 *    Extended value strings can be created at runtime by calling
 *      value_string_ext_new(<ptr to value_string array>,
 *                           <total number of entries in the value_string_array>,
 *                           <value_string_name>);
 *      Note: <total number of entries in the value_string_array> should include the {0, NULL} entry
 */
/* --------------------------------------------------------------------*/
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

/* "Acessors" */
#define VALUE_STRING_EXT_VS_P(x) (x)->_vs_p
#define VALUE_STRING_EXT_VS_NUM_ENTRIES(x) (x)->_vs_num_entries
#define VALUE_STRING_EXT_VS_NAME(x) (x)->_vs_name

/* (Fcns for use by proto_registrar_dump_values() [See proto.c]) */
gboolean value_string_ext_validate(const value_string_ext *vse);
const gchar *value_string_ext_match_type_str(const value_string_ext *vse);
/* --- --- */

extern const value_string *_match_strval_ext_init(const guint32 val, const value_string_ext *vse);
#define VALUE_STRING_EXT_INIT(x) { _match_strval_ext_init, 0, array_length(x)-1, x, #x }

/* Create a value_string_ext given a ptr to a value_string array and the total number of entries. */
/* Note: vs_tot_num_entries should include the required {0, NULL} terminating entry of the array. */
/* Return: a pointer to a gmalloc'd and initialized value_string_ext struct.                      */
extern value_string_ext *value_string_ext_new(value_string *vs, guint vs_tot_num_entries, gchar *vs_name);

/* Looks up val in a value_string array using access method (direct, binary search
 *  or linear) determined at rutime during the initial access); (see _match_strval_ext_init)
 * Returns the associated string ptr on a match or NULL on failure.
 */
extern const gchar* match_strval_ext(const guint32 val, const value_string_ext *vse);

/* Tries to match val against each element in the value_string array vs.
 *  Returns the associated string ptr, and sets "*idx" to the index in
 *  that table, on a match, and returns NULL, and sets "*idx" to -1,
 *  on failure.
 */
extern const gchar* match_strval_idx_ext(const guint32 val, value_string_ext *vse, gint *idx);

/* Similar to match_strval_ext except that on failure
 * Formats val with fmt, and returns the resulting string
 */
extern const gchar* val_to_str_ext(const guint32 val, const value_string_ext *vs, const char *fmt);

/* Similar to match_strval_ext except that on failure
 *  Returns 'unknown_str'
 */
extern const gchar* val_to_str_ext_const(const guint32 val, const value_string_ext *vs, const char *unknown_str);

/* ---- ---- */

/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
extern const char *decode_enumerated_bitfield(const guint32 val, const guint32 mask,
  const int width, const value_string *tab, const char *fmt);

/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
extern const char *decode_enumerated_bitfield_shifted(const guint32 val, const guint32 mask,
  const int width, const value_string *tab, const char *fmt);


/* ranges aware versions */

/* Tries to match val against each range in the range_string array rs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
extern const gchar* rval_to_str(const guint32 val, const range_string *rs, const char *fmt);

/* Tries to match val against each range in the range_string array rs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
extern const gchar *match_strrval_idx(const guint32 val, const range_string *rs, gint *idx);

/* Like match_strrval_idx(), but doesn't return the index. */
extern const gchar *match_strrval(const guint32 val, const range_string *rs);

#endif /* __VALUE_STRING_H__ */
