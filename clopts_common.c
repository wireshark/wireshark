/* clopts_common.c
 * Handle command-line arguments common to Wireshark and TShark
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
#include <string.h>

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#include "clopts_common.h"
#include "cmdarg_err.h"

int
get_natural_int(const char *string, const char *name)
{
  long number;
  char *p;

  number = strtol(string, &p, 10);
  if (p == string || *p != '\0') {
    cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
    exit(1);
  }
  if (number < 0) {
    cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
    exit(1);
  }
  if (number > INT_MAX) {
    cmdarg_err("The specified %s \"%s\" is too large (greater than %d)",
	       name, string, INT_MAX);
    exit(1);
  }
  return number;
}


int
get_positive_int(const char *string, const char *name)
{
  long number;

  number = get_natural_int(string, name);

  if (number == 0) {
    cmdarg_err("The specified %s is zero", name);
    exit(1);
  }

  return number;
}

gint64
get_natural_int64(const char *string, const char *name)
{
  gint64 number;
  char *p;

#if GLIB_CHECK_VERSION(2,12,0)
  number = g_ascii_strtoll(string, &p, 10);
#elif defined(HAVE_STRTOLL)
  number = strtoll(string, &p, 10);
#else
  /* Punt and grab a 32-bit value */
  number = strtol(string, &p, 10);
#endif

  if (p == string || *p != '\0') {
    cmdarg_err("The specified %s \"%s\" isn't a decimal number", name, string);
    exit(1);
  }
  if (number < 0) {
    cmdarg_err("The specified %s \"%s\" is a negative number", name, string);
    exit(1);
  }
  if (number > G_MAXINT64) { /* XXX - ??? */
    cmdarg_err("The specified %s \"%s\" is too large (greater than %" G_GINT64_MODIFIER "d)",
	       name, string, G_MAXINT64);
    exit(1);
  }
  return number;
}


gint64
get_positive_int64(const char *string, const char *name)
{
  gint64 number;

  number = get_natural_int64(string, name);

  if (number == 0) {
    cmdarg_err("The specified %s is zero", name);
    exit(1);
  }

  return number;
}
