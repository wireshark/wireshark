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
 * "g_ascii_strtoull()" extracted from GLib 2.4.5, for use with GLibs
 * that don't have it (e.g., GLib 1.2[.x]).
 */

/*
 * MT safe
 */

#include <errno.h>

#include <glib.h>

#include "g_ascii_strtoull.h"

#ifndef G_MAXUINT64
#define G_MAXUINT64	((guint64)G_GINT64_CONSTANT(0xFFFFFFFFFFFFFFFFU))
#endif

/**
 * g_ascii_strtoull:
 * @nptr:    the string to convert to a numeric value.
 * @endptr:  if non-%NULL, it returns the character after
 *           the last character used in the conversion.
 * @base:    to be used for the conversion, 2..36 or 0
 *
 * Converts a string to a #guint64 value.
 * This function behaves like the standard strtoull() function
 * does in the C locale. It does this without actually
 * changing the current locale, since that would not be
 * thread-safe.
 *
 * This function is typically used when reading configuration
 * files or other non-user input that should be locale independent.
 * To handle input from the user you should normally use the
 * locale-sensitive system strtoull() function.
 *
 * If the correct value would cause overflow, %G_MAXUINT64
 * is returned, and %ERANGE is stored in %errno.
 *
 * Return value: the #guint64 value.
 *
 * Since: 2.2
 **/
guint64
g_ascii_strtoull (const gchar *nptr,
		  gchar      **endptr,
		  guint        base)
{
  /* this code is based on on the strtol(3) code from GNU libc released under
   * the GNU Lesser General Public License.
   *
   * Copyright (C) 1991,92,94,95,96,97,98,99,2000,01,02
   *        Free Software Foundation, Inc.
   */
#define ISSPACE(c)		((c) == ' ' || (c) == '\f' || (c) == '\n' || \
				 (c) == '\r' || (c) == '\t' || (c) == '\v')
#define ISUPPER(c)		((c) >= 'A' && (c) <= 'Z')
#define ISLOWER(c)		((c) >= 'a' && (c) <= 'z')
#define ISALPHA(c)		(ISUPPER (c) || ISLOWER (c))
#define	TOUPPER(c)		(ISLOWER (c) ? (c) - 'a' + 'A' : (c))
#define	TOLOWER(c)		(ISUPPER (c) ? (c) - 'A' + 'a' : (c))
  gboolean negative, overflow;
  guint64 cutoff;
  guint64 cutlim;
  guint64 ui64;
  const gchar *s, *save;
  guchar c;
  
  if (base == 1 || base > 36)
    {
      errno = EINVAL;
      return 0;
    }
  
  save = s = nptr;
  
  /* Skip white space.  */
  while (ISSPACE (*s))
    ++s;
  if (!*s)
    goto noconv;
  
  /* Check for a sign.  */
  negative = FALSE;
  if (*s == '-')
    {
      negative = TRUE;
      ++s;
    }
  else if (*s == '+')
    ++s;
  
  /* Recognize number prefix and if BASE is zero, figure it out ourselves.  */
  if (*s == '0')
    {
      if ((base == 0 || base == 16) && TOUPPER (s[1]) == 'X')
	{
	  s += 2;
	  base = 16;
	}
      else if (base == 0)
	base = 8;
    }
  else if (base == 0)
    base = 10;
  
  /* Save the pointer so we can check later if anything happened.  */
  save = s;
  cutoff = G_MAXUINT64 / base;
  cutlim = G_MAXUINT64 % base;
  
  overflow = FALSE;
  ui64 = 0;
  c = *s;
  for (; c; c = *++s)
    {
      if (c >= '0' && c <= '9')
	c -= '0';
      else if (ISALPHA (c))
	c = TOUPPER (c) - 'A' + 10;
      else
	break;
      if (c >= base)
	break;
      /* Check for overflow.  */
      if (ui64 > cutoff || (ui64 == cutoff && c > cutlim))
	overflow = TRUE;
      else
	{
	  ui64 *= base;
	  ui64 += c;
	}
    }
  
  /* Check if anything actually happened.  */
  if (s == save)
    goto noconv;
  
  /* Store in ENDPTR the address of one character
     past the last character we converted.  */
  if (endptr)
    *endptr = (gchar*) s;
  
  if (overflow)
    {
      errno = ERANGE;
      return G_MAXUINT64;
    }
  
  /* Return the result of the appropriate sign.  */
  return negative ? -ui64 : ui64;
  
 noconv:
  /* We must handle a special case here: the base is 0 or 16 and the
     first two characters are '0' and 'x', but the rest are no
     hexadecimal digits.  This is no error case.  We return 0 and
     ENDPTR points to the `x`.  */
  if (endptr)
    {
      if (save - nptr >= 2 && TOUPPER (save[-1]) == 'X'
	  && save[-2] == '0')
	*endptr = (gchar*) &save[-1];
      else
	/*  There was no number to convert.  */
	*endptr = (gchar*) nptr;
    }
  return 0;
}
