/* GLIB - Library of useful routines for C programming
 * Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/*
 * Modified by the GLib Team and others 1997-2000.  See the AUTHORS
 * file for a list of people on the GLib Team.  See the ChangeLog
 * files for a list of changes.  These files are distributed with
 * GLib at ftp://ftp.gtk.org/pub/gtk/. 
 */

/*
 * $Id$
 *
 * "g_ascii_strcasecmp()" and "g_ascii_strncasecmp()" extracted from
 * GLib 2.4.8, for use with GLibs that don't have it (e.g., GLib 1.2[.x]).
 */

#include "g_ascii_strcasecmp.h"

#define ISUPPER(c)		((c) >= 'A' && (c) <= 'Z')
#define ISLOWER(c)		((c) >= 'a' && (c) <= 'z')
#define	TOUPPER(c)		(ISLOWER (c) ? (c) - 'a' + 'A' : (c))
#define	TOLOWER(c)		(ISUPPER (c) ? (c) - 'A' + 'a' : (c))

/**
 * g_ascii_strcasecmp:
 * @s1: string to compare with @s2.
 * @s2: string to compare with @s1.
 * 
 * Compare two strings, ignoring the case of ASCII characters.
 *
 * Unlike the BSD strcasecmp() function, this only recognizes standard
 * ASCII letters and ignores the locale, treating all non-ASCII
 * characters as if they are not letters.
 * 
 * Return value: an integer less than, equal to, or greater than
 *               zero if @s1 is found, respectively, to be less than,
 *               to match, or to be greater than @s2.
 **/
gint
g_ascii_strcasecmp (const gchar *s1,
		    const gchar *s2)
{
  gint c1, c2;

  g_return_val_if_fail (s1 != NULL, 0);
  g_return_val_if_fail (s2 != NULL, 0);

  while (*s1 && *s2)
    {
      c1 = (gint)(guchar) TOLOWER (*s1);
      c2 = (gint)(guchar) TOLOWER (*s2);
      if (c1 != c2)
	return (c1 - c2);
      s1++; s2++;
    }

  return (((gint)(guchar) *s1) - ((gint)(guchar) *s2));
}

/**
 * g_ascii_strncasecmp:
 * @s1: string to compare with @s2.
 * @s2: string to compare with @s1.
 * @n:  number of characters to compare.
 * 
 * Compare @s1 and @s2, ignoring the case of ASCII characters and any
 * characters after the first @n in each string.
 *
 * Unlike the BSD strcasecmp() function, this only recognizes standard
 * ASCII letters and ignores the locale, treating all non-ASCII
 * characters as if they are not letters.
 * 
 * Return value: an integer less than, equal to, or greater than zero
 *               if the first @n bytes of @s1 is found, respectively,
 *               to be less than, to match, or to be greater than the
 *               first @n bytes of @s2.
 **/
gint
g_ascii_strncasecmp (const gchar *s1,
		     const gchar *s2,
		     gsize n)
{
  gint c1, c2;

  g_return_val_if_fail (s1 != NULL, 0);
  g_return_val_if_fail (s2 != NULL, 0);

  while (n && *s1 && *s2)
    {
      n -= 1;
      c1 = (gint)(guchar) TOLOWER (*s1);
      c2 = (gint)(guchar) TOLOWER (*s2);
      if (c1 != c2)
	return (c1 - c2);
      s1++; s2++;
    }

  if (n)
    return (((gint) (guchar) *s1) - ((gint) (guchar) *s2));
  else
    return 0;
}

