/* value_string.h
 * Definitions for value_string structures and routines
 *
 * $Id: value_string.h,v 1.1 2001/04/01 03:18:41 hagbard Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

/* Struct for the match_strval function */

typedef struct _value_string {
  guint32  value;
  gchar   *strptr;
} value_string;

gchar*     match_strval(guint32, const value_string*);

gchar*     val_to_str(guint32, const value_string *, const char *);
const char *decode_enumerated_bitfield(guint32 val, guint32 mask, int width,
  const value_string *tab, const char *fmt);

#endif /* __VALUE_STRING_H__ */
