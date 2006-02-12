/* util.c
 * Utility routines
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

#include <glib.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <epan/address.h>
#include <epan/addr_resolv.h>

#include "util.h"

/*
 * Collect command-line arguments as a string consisting of the arguments,
 * separated by spaces.
 */
char *
get_args_as_string(int argc, char **argv, int optind)
{
	int len;
	int i;
	char *argstring;

	/*
	 * Find out how long the string will be.
	 */
	len = 0;
	for (i = optind; i < argc; i++) {
		len += strlen(argv[i]);
		len++;	/* space, or '\0' if this is the last argument */
	}

	/*
	 * Allocate the buffer for the string.
	 */
	argstring = g_malloc(len);

	/*
	 * Now construct the string.
	 */
	strcpy(argstring, "");
	i = optind;
	for (;;) {
		strcat(argstring, argv[i]);
		i++;
		if (i == argc)
			break;
		strcat(argstring, " ");
	}
	return argstring;
}

/* Compute the difference between two seconds/microseconds time stamps. */
void
compute_timestamp_diff(gint *diffsec, gint *diffusec,
	guint32 sec1, guint32 usec1, guint32 sec2, guint32 usec2)
{
  if (sec1 == sec2) {
    /* The seconds part of the first time is the same as the seconds
       part of the second time, so if the microseconds part of the first
       time is less than the microseconds part of the second time, the
       first time is before the second time.  The microseconds part of
       the delta should just be the difference between the microseconds
       part of the first time and the microseconds part of the second
       time; don't adjust the seconds part of the delta, as it's OK if
       the microseconds part is negative. */

    *diffsec = sec1 - sec2;
    *diffusec = usec1 - usec2;
  } else if (sec1 <= sec2) {
    /* The seconds part of the first time is less than the seconds part
       of the second time, so the first time is before the second time.

       Both the "seconds" and "microseconds" value of the delta
       should have the same sign, so if the difference between the
       microseconds values would be *positive*, subtract 1,000,000
       from it, and add one to the seconds value. */
    *diffsec = sec1 - sec2;
    if (usec2 >= usec1) {
      *diffusec = usec1 - usec2;
    } else {
      *diffusec = (usec1 - 1000000) - usec2;
      (*diffsec)++;
    }
  } else {
    /* Oh, good, we're not caught in a chronosynclastic infindibulum. */
    *diffsec = sec1 - sec2;
    if (usec2 <= usec1) {
      *diffusec = usec1 - usec2;
    } else {
      *diffusec = (usec1 + 1000000) - usec2;
      (*diffsec)--;
    }
  }
}

/* Try to figure out if we're remotely connected, e.g. via ssh or
   Terminal Server, and create a capture filter that matches aspects of the
   connection.  We match the following environment variables:

   SSH_CONNECTION (ssh): <remote IP> <remote port> <local IP> <local port>
   SSH_CLIENT (ssh): <remote IP> <remote port> <local port>
   REMOTEHOST (tcsh, others?): <remote name>
   DISPLAY (x11): [remote name]:<display num>
   CLIENTNAME (terminal server): <remote name>
 */

const gchar *get_conn_cfilter(void) {
	static GString *filter_str = NULL;
	gchar *env, **tokens;

	if (filter_str == NULL) {
		filter_str = g_string_new("");
	}
	if ((env = getenv("SSH_CONNECTION")) != NULL) {
		tokens = g_strsplit(env, " ", 4);
		if (tokens[3]) {
			g_string_sprintf(filter_str, "not (tcp port %s and %s host %s "
							 "and tcp port %s and %s host %s)", tokens[1], host_ip_af(tokens[0]), tokens[0],
				tokens[3], host_ip_af(tokens[2]), tokens[2]);
			return filter_str->str;
		}
	} else if ((env = getenv("SSH_CLIENT")) != NULL) {
		tokens = g_strsplit(env, " ", 3);
		g_string_sprintf(filter_str, "not (tcp port %s and %s host %s "
			"and tcp port %s)", tokens[1], host_ip_af(tokens[0]), tokens[0], tokens[2]);
		return filter_str->str;
	} else if ((env = getenv("REMOTEHOST")) != NULL) {
		if (strcasecmp(env, "localhost") == 0 || strcmp(env, "127.0.0.1") == 0) {
			return "";
		}
		g_string_sprintf(filter_str, "not %s host %s", host_ip_af(env), env);
		return filter_str->str;
	} else if ((env = getenv("DISPLAY")) != NULL) {
		tokens = g_strsplit(env, ":", 2);
		if (tokens[0] && tokens[0][0] != 0) {
			if (strcasecmp(tokens[0], "localhost") == 0 ||
					strcmp(tokens[0], "127.0.0.1") == 0) {
				return "";
			}
			g_string_sprintf(filter_str, "not %s host %s",
				host_ip_af(tokens[0]), tokens[0]);
			return filter_str->str;
		}
	} else if ((env = getenv("CLIENTNAME")) != NULL) {
		g_string_sprintf(filter_str, "not tcp port 3389");
		return filter_str->str;
	}
	return "";
}
