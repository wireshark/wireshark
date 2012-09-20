/* value_string.c
 * Routines for value_strings
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

#include "config.h"

#include <stdio.h>

#include "to_str.h"
#include "emem.h"
#include "value_string.h"
#include <string.h>

/* --------------------------------------------------------------------*/
/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
const gchar*
val_to_str(const guint32 val, const value_string *vs, const char *fmt) {
  const gchar *ret;

  g_assert(fmt != NULL);

  ret = match_strval(val, vs);
  if (ret != NULL)
    return ret;

  return ep_strdup_printf(fmt, val);
}

/* --------------------------------------------------------------------*/
/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Returns 'unknown_str', on failure. */
const gchar*
val_to_str_const(const guint32 val, const value_string *vs, const char *unknown_str) {
  const gchar *ret;

  g_assert(unknown_str != NULL);

  ret = match_strval(val, vs);
  if (ret != NULL)
    return ret;

  return unknown_str;
}

/* --------------------------------------------------------------------*/
/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
const gchar*
match_strval_idx(const guint32 val, const value_string *vs, gint *idx) {
  gint i = 0;

  if(vs) {
    while (vs[i].strptr) {
      if (vs[i].value == val) {
        *idx = i;
        return(vs[i].strptr);
      }
      i++;
    }
  }

  *idx = -1;
  return NULL;
}

/* Like match_strval_idx(), but doesn't return the index. */
const gchar*
match_strval(const guint32 val, const value_string *vs) {
    gint ignore_me;
    return match_strval_idx(val, vs, &ignore_me);
}

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
 *
 */

/* --------------------------------------------------------------------*/

/* Create a value_string_ext given a ptr to a value_string array and the total number of entries.           */
/* Note:  The total number of entries should include the required {0, NULL} terminating entry of the array. */
/* Return: a pointer to a g_malloc'd and initialized value_string_ext struct.                                */
value_string_ext *
value_string_ext_new(value_string *vs, guint vs_tot_num_entries, gchar *vs_name) {
    value_string_ext *vse;
    g_assert (vs_name != NULL);
    g_assert (vs_tot_num_entries > 0);
    g_assert (vs[vs_tot_num_entries-1].strptr == NULL); /* Null-terminated value-string ? */
    vse                  = g_malloc(sizeof (value_string_ext));
    vse->_vs_p           = vs;
    vse->_vs_num_entries = vs_tot_num_entries - 1; /* remember the actual number of entries */
    vse->_vs_first_value = 0;                      /* initialized in _match_strval_ext_init */
    vse->_vs_match2      = _match_strval_ext_init;
    vse->_vs_name        = vs_name;
    return vse;
}

/* Looks up val in a value_string array using access method (direct, binary search
 *  or linear) determined at rutime during the initial access); (see _match_strval_ext_init)
 * Returns the associated string ptr on a match, and returns NULL on failure.
 */
const gchar*
match_strval_ext(const guint32 val, const value_string_ext *vse) {
    if (vse) {
      const value_string *vs = vse->_vs_match2(val, vse);
      if (vs)
        return vs->strptr;
    }
    return NULL;
}

/* Tries to match val against each element in the value_string array vs.
 *  Returns the associated string ptr, and sets "*idx" to the index in
 *  that table, on a match, and returns NULL, and sets "*idx" to -1,
 *  on failure.
 */

const gchar*
match_strval_idx_ext(const guint32 val, value_string_ext *vse, gint *idx) {
    if (vse) {
      const value_string *vs = vse->_vs_match2(val, vse);
      if (vs) {
        *idx = (gint) (vs - vse->_vs_p);
        return vs->strptr;
      }
    }
    *idx = -1;
    return NULL;
}

/* Similar to match_strval_ext except that on failure
 * Formats val with fmt, and returns the resulting string
 */
const gchar*
val_to_str_ext(const guint32 val, const value_string_ext *vse, const char *fmt) {
  const gchar *ret;

  g_assert(fmt != NULL);

  ret = match_strval_ext(val, vse);
  if (ret != NULL)
    return ret;

  return ep_strdup_printf(fmt, val);
}

/* Similar to match_strval_ext except that on failure
 *  Returns 'unknown_str'
 */
const gchar*
val_to_str_ext_const(const guint32 val, const value_string_ext *vse, const char *unknown_str) {
  const gchar *ret;

  g_assert(unknown_str != NULL);

  ret = match_strval_ext(val, vse);
  if (ret != NULL)
    return ret;

  return unknown_str;
}

static const value_string *
_match_strval_linear(const guint32 val, const value_string_ext *vse)
{
  const value_string *vs_p = vse->_vs_p;
  guint i;
  for (i=0; i<vse->_vs_num_entries; i++) {
    if (vs_p[i].value == val)
      return &(vs_p[i]);
  }
  return NULL;
}

static const value_string *
_match_strval_index(const guint32 val, const value_string_ext *vse)
{
  guint i;

  i = val - vse->_vs_first_value;
  if (i < vse->_vs_num_entries) {
    g_assert (val == vse->_vs_p[i].value);
    return &(vse->_vs_p[i]);
  }
  return NULL;
}

static const value_string *
_match_strval_bsearch(const guint32 val, const value_string_ext *vse)
{
  guint low, i, max;
  guint32 item;

  for (low = 0, max = vse->_vs_num_entries; low < max; ) {
    i = (low + max) / 2;
    item = vse->_vs_p[i].value;

    if (val < item)
      max = i;
    else if (val > item)
      low = i + 1;
    else
      return &(vse->_vs_p[i]);
  }
  return NULL;
}

/* Init value_string_ext struct
   - Go thru the value_string array to determine whether indexed access
      or binary search access is possible;
   - Verify that the value_string array does not contain any
      NULL string pointers;
   - Verify that the value_string array is terminated
      by {0, NULL};
*/
const value_string *
_match_strval_ext_init(const guint32 val, const value_string_ext *a_vse)
{
  /*  Cast away the constness!
   *  It's better if the prototype for this function matches the other
   *  _match_strval_* functions (so we don't have to cast it when storing it
   *  in _match_strval so the compiler will notice if the prototypes get out
   *  of sync), but the init function is unique in that it does actually
   *  modify the vse.
   */
  value_string_ext    *vse            = (value_string_ext *)a_vse;

  const value_string *vs_p           = vse->_vs_p;
  const guint         vs_num_entries = vse->_vs_num_entries;

/* The way matching of value is done in a value_string:
 * 0 Sequential search (as in a normal value string)
 * 1 Binary search, the values MUST be in numerical order.
 * 2 The value used as an index(the value string MUST have all values between first and last defined in numerical order)
 */

/* Note: The value_string 'value' is *unsigned*.
 *
 *   Special case:
 *    { -3, -2, -1, 0, 1, 2 }                      will be treated as "ascending ordered" (altho not really such)
 *                                                  thus allowing as a 'direct' search.
 *
 *   Note:
 *    { -3, -2, 0, 1, 2 } and { -3, -2, -1, 0, 2 } will both be considered as "out-of-order with gaps"
 *                                                  thus requiring a 'linear' search.
 *    { 0, 1, 2, -3, -2 } and { 0, 2, -3, -2, -1 } will be considered "ascending ordered with gaps"
 *                                                  thus allowing a 'binary' search.
 */

  enum { VS_SEARCH = 0, VS_BIN_TREE, VS_INDEX } type = VS_INDEX;

  guint32 prev_value;
  guint   first_value;
  guint   i;

  g_assert((vs_p[vs_num_entries].value==0) && (vs_p[vs_num_entries].strptr==NULL));

  vse->_vs_first_value = vs_p[0].value;
  first_value          = vs_p[0].value;
  prev_value           = first_value;

  for (i = 0; i < vs_num_entries; i++) {
    g_assert(vs_p[i].strptr != NULL);
    if ((type == VS_INDEX) && (vs_p[i].value != (i + first_value))) {
      type = VS_BIN_TREE;
    }
    /* XXX: Should check for dups ?? */
    if ((type == VS_BIN_TREE) &&
        ((prev_value > vs_p[i].value) || (first_value > vs_p[i].value))) {
      type = VS_SEARCH;
      break;
    }

    prev_value = vs_p[i].value;
  }

  switch (type) {
  case VS_SEARCH:
    vse->_vs_match2 = _match_strval_linear;
    break;
  case VS_BIN_TREE:
    vse->_vs_match2 = _match_strval_bsearch;
    break;
  case VS_INDEX:
    vse->_vs_match2 = _match_strval_index;
    break;
  default:
    g_assert_not_reached();
    break;
  }

  return vse->_vs_match2(val, vse);
}

/* (Fcns for use by proto_registrar_dump_values() [See proto.c]) */
gboolean
value_string_ext_validate(const value_string_ext *vse) {
    if (vse == NULL)
        return FALSE;
    if ((vse->_vs_match2 == _match_strval_ext_init) ||
        (vse->_vs_match2 == _match_strval_linear)   ||
        (vse->_vs_match2 == _match_strval_bsearch)  ||
        (vse->_vs_match2 == _match_strval_index))
        return TRUE;
    return FALSE;
}

const gchar *
value_string_ext_match_type_str(const value_string_ext *vse) {
    if (vse->_vs_match2 == _match_strval_linear)
        return "[Linear Search]";
    if (vse->_vs_match2 == _match_strval_bsearch)
        return "[Binary Search]";
    if (vse->_vs_match2 == _match_strval_index)
        return "[Direct (indexed) Access]";
    return "[Match Type not initialized or invalid]";
}

/* ----------- */

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
const gchar*
str_to_str(const gchar *val, const string_string *vs, const char *fmt) {
  const gchar *ret;

  g_assert(fmt != NULL);

  ret = match_strstr(val, vs);
  if (ret != NULL)
    return ret;

  return ep_strdup_printf(fmt, val);
}

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
const gchar*
match_strstr_idx(const gchar *val, const string_string *vs, gint *idx) {
  gint i = 0;

  if(vs) {
    while (vs[i].strptr) {
      if (!strcmp(vs[i].value,val)) {
        *idx = i;
        return(vs[i].strptr);
      }
      i++;
    }
  }

  *idx = -1;
  return NULL;
}

/* Like match_strval_idx(), but doesn't return the index. */
const gchar*
match_strstr(const gchar *val, const string_string *vs) {
    gint ignore_me;
    return match_strstr_idx(val, vs, &ignore_me);
}

/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
const char *
decode_enumerated_bitfield(const guint32 val, const guint32 mask, const int width,
    const value_string *tab, const char *fmt)
{
  static char buf[1025];
  char *p;

  p = decode_bitfield_value(buf, val, mask, width);
  g_snprintf(p, (gulong) (1024-(p-buf)), fmt, val_to_str(val & mask, tab, "Unknown"));
  return buf;
}


/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
const char *
decode_enumerated_bitfield_shifted(const guint32 val, const guint32 mask, const int width,
    const value_string *tab, const char *fmt)
{
  static char buf[1025];
  char *p;
  int shift = 0;

  /* Compute the number of bits we have to shift the bitfield right
     to extract its value. */
  while ((mask & (1<<shift)) == 0)
    shift++;

  p = decode_bitfield_value(buf, val, mask, width);
  g_snprintf(p, (gulong) (1024-(p-buf)), fmt, val_to_str((val & mask) >> shift, tab, "Unknown"));
  return buf;
}


/* FF: ranges aware versions */

/* Tries to match val against each range in the range_string array rs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
const gchar *rval_to_str(const guint32 val, const range_string *rs, const char *fmt)
{
  const gchar *ret = NULL;

  g_assert(fmt != NULL);

  ret = match_strrval(val, rs);
  if(ret != NULL)
    return ret;

  return ep_strdup_printf(fmt, val);
}

/* Tries to match val against each range in the range_string array rs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
const gchar *match_strrval_idx(const guint32 val, const range_string *rs, gint *idx)
{
  gint i = 0;

  if(rs) {
    while(rs[i].strptr) {
      if( (val >= rs[i].value_min) && (val <= rs[i].value_max) ) {
        *idx = i;
        return (rs[i].strptr);
      }
      i++;
    }
  }

  *idx = -1;
  return NULL;
}

/* Like match_strrval_idx(), but doesn't return the index. */
const gchar *match_strrval(const guint32 val, const range_string *rs)
{
    gint ignore_me = 0;
    return match_strrval_idx(val, rs, &ignore_me);
}

