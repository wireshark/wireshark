/* ws_strsplit.c
 * String Split utility function
 * Code borrowed from GTK2 to override the GTK1 version of g_strsplit, which is
 * known to be buggy.
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

#if GLIB_MAJOR_VERSION < 2
#include <glib.h>
#include <string.h>

gchar** ws_strsplit ( const gchar *string,
		      const gchar *delimiter,
		      gint max_tokens)
{
  GSList *string_list = NULL, *slist;
  gchar **str_array, *s;
  guint n = 0;
  const gchar *remainder;

  g_return_val_if_fail (string != NULL, NULL);
  g_return_val_if_fail (delimiter != NULL, NULL);
  g_return_val_if_fail (delimiter[0] != '\0', NULL);

  if (max_tokens < 1)
    max_tokens = G_MAXINT;

  remainder = string;
  s = strstr (remainder, delimiter);
  if (s) {
    gsize delimiter_len = strlen (delimiter);

    while (--max_tokens && s) {
      gsize len;
      gchar *new_string;

      len = s - remainder;
      new_string = g_new (gchar, len + 1);
      strncpy (new_string, remainder, len);
      new_string[len] = 0;
      string_list = g_slist_prepend (string_list, new_string);
      n++;
      remainder = s + delimiter_len;
      s = strstr (remainder, delimiter);
    }
  }
  if (*string) {
    n++;
    string_list = g_slist_prepend (string_list, g_strdup (remainder));
  }

  str_array = g_new (gchar*, n + 1);

  str_array[n--] = NULL;
  for (slist = string_list; slist; slist = slist->next)
    str_array[n--] = slist->data;

  g_slist_free (string_list);

  return str_array;
}

#endif /* GLIB_MAJOR_VERSION */
