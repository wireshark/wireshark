/* value_string.c
 * Routines for value_strings
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
const gchar*
val_to_str(guint32 val, const value_string *vs, const char *fmt) {
  const gchar *ret;
  gchar *cur;

  g_assert(fmt != NULL);

  ret = match_strval(val, vs);
  if (ret != NULL)
    return ret;

  cur=ep_alloc(64);
  g_snprintf(cur, 64, fmt, val);
  return cur;
}

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
const gchar*
match_strval_idx(guint32 val, const value_string *vs, gint *idx) {
  gint i = 0;

  while (vs[i].strptr) {
    if (vs[i].value == val) {
      *idx = i;
      return(vs[i].strptr);
    }
    i++;
  }

  *idx = -1;
  return(NULL);
}

/* Like match_strval_idx(), but doesn't return the index. */
const gchar*
match_strval(guint32 val, const value_string *vs) {
    gint ignore_me;
    return match_strval_idx(val, vs, &ignore_me);
}

/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
const char *
decode_enumerated_bitfield(guint32 val, guint32 mask, int width,
    const value_string *tab, const char *fmt)
{
  static char buf[1025];
  char *p;

  p = decode_bitfield_value(buf, val, mask, width);
  sprintf(p, fmt, val_to_str(val & mask, tab, "Unknown"));
  return buf;
}


/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
const char *
decode_enumerated_bitfield_shifted(guint32 val, guint32 mask, int width,
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
  sprintf(p, fmt, val_to_str((val & mask) >> shift, tab, "Unknown"));
  return buf;
}
