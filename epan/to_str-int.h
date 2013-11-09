/* to_str-int.h
 * Definitions for utilities to convert various other types to strings.
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

#ifndef __TO_STR_INT_H__
#define __TO_STR_INT_H__

#include <glib.h>

char *word_to_hex(char *out, guint16 word);
char *word_to_hex_npad(char *out, guint16 word);
char *dword_to_hex_punct(char *out, guint32 dword, char punct);
char *dword_to_hex(char *out, guint32 dword);
char *bytes_to_hexstr(char *out, const guint8 *ad, guint32 len);
char *bytes_to_hexstr_punct(char *out, const guint8 *ad, guint32 len, char punct);

char *oct_to_str_back(char *ptr, guint32 value);
char *hex_to_str_back(char *ptr, int pad, guint32 value);
char *uint_to_str_back(char *ptr, guint32 value);
char *int_to_str_back(char *ptr, gint32 value);

#endif /* __TO_STR_INT_H__ */
