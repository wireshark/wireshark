/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "config.h"
#ifdef HAVE_GLIB10

#include <glib.h>
#include <stdarg.h>
#include <string.h>

gpointer
g_memdup (const gpointer mem,
	  guint         byte_size)
{
  gpointer new_mem;

  if (mem)
    {
      new_mem = g_malloc (byte_size);
      memcpy (new_mem, mem, byte_size);
    }
  else
    new_mem = NULL;

  return new_mem;
}

gchar*
g_strjoin (const gchar  *separator,
	   ...)
{
  gchar *string, *s;
  va_list args;
  guint len;
  guint separator_len;

  if(separator == NULL)
    separator = "";

  separator_len = strlen (separator);

  va_start(args, separator);

  s = va_arg(args, gchar *);

  if(s) {
    len = strlen(s) + 1;

    while((s = va_arg(args, gchar*)))
      {
	len += separator_len + strlen(s);
      }
    va_end(args);

    string = g_new (gchar, len);

    va_start(args, separator);

    *string = 0;
    s = va_arg(args, gchar*);
    strcat (string, s);

    while((s = va_arg(args, gchar*)))
      {
	strcat(string, separator);
	strcat(string, s);
      }

  } else
    string = g_strdup("");

  va_end(args);

  return string;
}

/* this was introduced sometime between glib-1.0.1 and glib-1.0.4 */
gpointer
g_slist_nth_data (GSList   *list,
		          guint     n)
{
	  while ((n-- > 0) && list)
		      list = list->next;

	    return list ? list->data : NULL;
}


#endif
