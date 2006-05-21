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

/* #define VS_DEF(x) { x, #x } */
/* #define VS_END    { 0, NULL } */

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr, and sets "*idx" to the index in
   that table, on a match, and returns NULL, and sets "*idx" to -1,
   on failure. */
extern const gchar* match_strval_idx(guint32 val, const value_string *vs, gint *idx);

/* Like match_strval_idx(), but doesn't return the index. */
extern const gchar* match_strval(guint32 val, const value_string *vs);

/* Tries to match val against each element in the value_string array vs.
   Returns the associated string ptr on a match.
   Formats val with fmt, and returns the resulting string, on failure. */
extern const gchar* val_to_str(guint32 val, const value_string *vs, const char *fmt);

/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
extern const char *decode_enumerated_bitfield(guint32 val, guint32 mask,
  int width, const value_string *tab, const char *fmt);

/* Generate a string describing an enumerated bitfield (an N-bit field
   with various specific values having particular names). */
extern const char *decode_enumerated_bitfield_shifted(guint32 val, guint32 mask,
  int width, const value_string *tab, const char *fmt);

#endif /* __VALUE_STRING_H__ */
