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

#include "file_util.h"

#include <epan/address.h>
#include <epan/addr_resolv.h>

#if GLIB_MAJOR_VERSION > 2 || (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION >= 6)
#include <glib/gstdio.h>	/* available since GLib 2.6 only! */

/* GLib2.6 or above, using new wrapper functions */
#define eth_mkstemp g_mkstemp
#else
#define eth_mkstemp mkstemp
#endif

/*
 * This has to come after the include of <pcap.h>, as the include of
 * <pcap.h> might cause <winsock2.h> to be included, and if we've
 * already included <winsock.h> as a result of including <windows.h>,
 * we get a bunch of redefinitions.
 */
#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

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

static const char *
setup_tmpdir(const char *dir)
{
	size_t len = strlen(dir);
	char *newdir;

	/* Append path separator if necessary */
	if (len != 0 && dir[len - 1] == G_DIR_SEPARATOR) {
		return dir;
	}
	else {
		newdir = g_malloc(len + 2);
		strcpy(newdir, dir);
		strcat(newdir, G_DIR_SEPARATOR_S);
		return newdir;
	}
}

static int
try_tempfile(char *namebuf, int namebuflen, const char *dir, const char *pfx)
{
	static const char suffix[] = "XXXXXXXXXX";
	int namelen = strlen(dir) + strlen(pfx) + sizeof suffix;
	int old_umask;
	int tmp_fd;

	if (namebuflen < namelen) {
		/* Stick in a truncated name, so that if this error is
		   reported with the file name, you at least get
		   something. */
		g_snprintf(namebuf, namebuflen, "%s%s%s", dir, pfx, suffix);
		errno = ENAMETOOLONG;
		return -1;
	}
	strcpy(namebuf, dir);
	strcat(namebuf, pfx);
	strcat(namebuf, suffix);

	/* The Single UNIX Specification doesn't say that "mkstemp()"
	   creates the temporary file with mode rw-------, so we
	   won't assume that all UNIXes will do so; instead, we set
	   the umask to 0077 to take away all group and other
	   permissions, attempt to create the file, and then put
	   the umask back. */
	old_umask = umask(0077);
	tmp_fd = eth_mkstemp(namebuf);
	umask(old_umask);
	return tmp_fd;
}

static const char *tmpdir = NULL;
#ifdef _WIN32
static const char *temp = NULL;
#endif
static const char *E_tmpdir;

#ifndef P_tmpdir
#define P_tmpdir "/var/tmp"
#endif

int
create_tempfile(char *namebuf, int namebuflen, const char *pfx)
{
	char *dir;
	int fd;
	static gboolean initialized;

	if (!initialized) {
		if ((dir = getenv("TMPDIR")) != NULL)
			tmpdir = setup_tmpdir(dir);
#ifdef _WIN32
		if ((dir = getenv("TEMP")) != NULL)
			temp = setup_tmpdir(dir);
#endif

		E_tmpdir = setup_tmpdir(P_tmpdir);
		initialized = TRUE;
	}

	if (tmpdir != NULL) {
		fd = try_tempfile(namebuf, namebuflen, tmpdir, pfx);
		if (fd != -1)
			return fd;
	}

#ifdef _WIN32
	if (temp != NULL) {
		fd = try_tempfile(namebuf, namebuflen, temp, pfx);
		if (fd != -1)
			return fd;
	}
#endif

	fd = try_tempfile(namebuf, namebuflen, E_tmpdir, pfx);
	if (fd != -1)
		return fd;

	return try_tempfile(namebuf, namebuflen, G_DIR_SEPARATOR_S "tmp", pfx);
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
