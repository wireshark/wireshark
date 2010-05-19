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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include "to_str.h"
#include "emem.h"
#include "value_string.h"
#include <string.h>

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

const gchar*
val_to_str_ext(const guint32 val, const value_string_ext *vs, const char *fmt) {
  const gchar *ret;

  g_assert(fmt != NULL);

  ret = match_strval_ext(val, vs);
  if (ret != NULL)
    return ret;

  return ep_strdup_printf(fmt, val);
}

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

const gchar*
val_to_str_ext_const(const guint32 val, const value_string_ext *vs, const char *unknown_str) {
  const gchar *ret;

  g_assert(unknown_str != NULL);

  ret = match_strval_ext(val, vs);
  if (ret != NULL)
    return ret;

  return unknown_str;
}

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

static const gchar *
_match_strval_linear(const guint32 val, const value_string_ext *vs)
{
  return match_strval(val, vs->vals);
}

static const gchar *
_match_strval_index(const guint32 val, const value_string_ext *vs)
{
  return (val < vs->length) ? vs->vals[val].strptr : NULL;
}

static const gchar *
_match_strval_bsearch(const guint32 val, const value_string_ext *vs)
{
  guint low, idx, max;
  guint32 item;

  for (low = 0, max = vs->length; low < max; ) {
    idx = (low + max) / 2;
    item = vs->vals[idx].value;

    if (val < item)
      max = idx;
    else if (val > item)
      low = idx + 1;
    else
      return vs->vals[idx].strptr;
  }
  return NULL;
}

const gchar *
match_strval_ext_init(const guint32 val, value_string_ext *vse)
{
  const value_string *vals = vse->vals;

/* The way matching of value is done in a value_string:
 * 0 default, value will be set in proto_register_field_init()
 * 1 Sequential search (as in a normal value string)
 * 2 The value used as an index(the value string MUST have all values 0-max defined)
 * 3 Binary search, the valuse MUST be in numerical order.
 */
  enum { VS_SEARCH = 0, VS_INDEX, VS_BIN_TREE } type = VS_INDEX;

  guint32 prev = 0;
  guint i;

  for (i = 0; i < vse->length; i++) {
    if (type == VS_INDEX && vals[i].value != i)
      type = VS_BIN_TREE;

    if (type == VS_BIN_TREE && prev > vals[i].value) {
      type = VS_SEARCH;
      break;
    }

    prev = vals[i].value;
  }
  
  switch (type) {
  case VS_SEARCH:
    vse->match = _match_strval_linear;
    break;
  case VS_INDEX:
    vse->match = _match_strval_index;
    break;
  case VS_BIN_TREE:
    vse->match = _match_strval_bsearch;
    break;
  default:
    g_assert_not_reached();
    break;
  }

  return vse->match(val, vse);
}

const gchar*
match_strval_ext(const guint32 val, const value_string_ext *vs) {
    if (vs)
      return vs->match(val, vs);
    return NULL;
}

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

