/* tempfile.c
 * Routines to create temporary files
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

#include <glib.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#include "tempfile.h"
#include "mkstemp.h"
#include <wsutil/file_util.h>

#define INITIAL_PATH_SIZE 128
#define TMP_FILE_SUFFIX "XXXXXXXXXX"

/**
 * Create a tempfile with the given prefix (e.g. "wireshark").
 * 
 * @param namebuf If not NULL, receives the full path of the temp file.
 *                Should NOT be freed.
 * @param pfx A prefix for the temporary file.
 * @return The file descriptor of the new tempfile, from mkstemp().
 */
int
create_tempfile(char **namebuf, const char *pfx)
{
	static char *tf_path[3];
	static int tf_path_len[3];
	static int idx;
	const char *tmp_dir;
	int old_umask;
	int fd;

	idx = (idx + 1) % 3;
	
	/*
	 * Allocate the buffer if it's not already allocated.
	 */
	if (tf_path[idx] == NULL) {
		tf_path_len[idx] = INITIAL_PATH_SIZE;
		tf_path[idx] = g_malloc(tf_path_len[idx]);
	}

	/*
	 * We can't use get_tempfile_path here because we're called from dumpcap.c.
	 */
	tmp_dir = g_get_tmp_dir();

	while (g_snprintf(tf_path[idx], tf_path_len[idx], "%s%c%s" TMP_FILE_SUFFIX, tmp_dir, G_DIR_SEPARATOR, pfx) > tf_path_len[idx]) {
		tf_path_len[idx] *= 2;
		tf_path[idx] = g_realloc(tf_path[idx], tf_path_len[idx]);
	}

	if (namebuf) {
		*namebuf = tf_path[idx];
	}
	/* The Single UNIX Specification doesn't say that "mkstemp()"
	   creates the temporary file with mode rw-------, so we
	   won't assume that all UNIXes will do so; instead, we set
	   the umask to 0077 to take away all group and other
	   permissions, attempt to create the file, and then put
	   the umask back. */
	old_umask = umask(0077);
	fd = mkstemp(tf_path[idx]);
	umask(old_umask);
	return fd;
}
