/* asm_utils.c
 * Functions optionally implemented in assembler
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

#include <string.h>
#include <ctype.h>
#include <glib.h>

#include "asm_utils.h"

/* String comparison func for dfilter_token GTree */
gint
wrs_strcmp(gconstpointer a, gconstpointer b)
{
    return strcmp((const char*)a, (const char*)b);
}

gint
wrs_strcmp_with_data(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
    return strcmp((const char*)a, (const char*)b);
}

gboolean
wrs_str_equal(gconstpointer a, gconstpointer b)
{
    return !strcmp((const char*)a, (const char*)b);
}

guchar
wrs_check_charset(const guchar table[256], const char *str)
{
    const char *p = str;
    guchar c;

    do {
      c = *(p++);
    } while (table[c]);
    return c;
}

guint
wrs_str_hash(gconstpointer v)
{
  /* 31 bit hash function */
  const signed char *p = v;
  guint32 h = *p;
  if (h)
    for (p += 1; *p != '\0'; p++)
      h = (h << 5) - h + *p;
  return h;
}

