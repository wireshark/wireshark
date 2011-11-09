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

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#ifdef _WIN32
#include <process.h>    /* For getpid() */
#endif

#include "tempfile.h"
#include <wsutil/file_util.h>

#ifndef __set_errno
#define __set_errno(x) errno=(x)
#endif

#define INITIAL_PATH_SIZE   128
#define TMP_FILE_SUFFIX     "XXXXXX"

#ifndef HAVE_MKSTEMP
/* Generate a unique temporary file name from TEMPLATE.
   The last six characters of TEMPLATE must be TMP_FILE_SUFFIX;
   they are replaced with a string that makes the filename unique.
   Returns a file descriptor open on the file for reading and writing.  */
static int
mkstemp (char *template)
{
  static const char letters[]
    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t len;
  size_t i;

  len = strlen (template);
  if (len < 6 || strcmp (&template[len - 6], TMP_FILE_SUFFIX))
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (g_snprintf (&template[len - 5], 6, "%.5u",
	       (unsigned int) getpid () % 100000) != 5)
    /* Inconceivable lossage.  */
    return -1;

  for (i = 0; i < sizeof (letters); ++i)
    {
      int fd;

      template[len - 6] = letters[i];

      fd = ws_open (template, O_RDWR|O_BINARY|O_CREAT|O_EXCL, 0600);
      if (fd >= 0)
	return fd;
    }

  /* We return the null string if we can't find a unique file name.  */

  template[0] = '\0';
  return -1;
}

#endif /* HAVE_MKSTEMP */

#ifndef HAVE_MKDTEMP
/* Generate a unique temporary directory name from TEMPLATE.
   The last six characters of TEMPLATE must be TMP_FILE_SUFFIX;
   they are replaced with a string that makes the filename unique.
   Returns 0 on success or -1 on error (from mkdir(2)).  */
char *
mkdtemp (char *template)
{
  static const char letters[]
    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t len;
  size_t i;

  len = strlen (template);
  if (len < 6 || strcmp (&template[len - 6], TMP_FILE_SUFFIX))
    {
      __set_errno (EINVAL);
      return NULL;
    }

  if (g_snprintf (&template[len - 5], 6, "%.5u",
	       (unsigned int) getpid () % 100000) != 5)
    /* Inconceivable lossage.  */
    return NULL;

  for (i = 0; i < sizeof (letters); ++i)
    {
      int ret;

      template[len - 6] = letters[i];

      ret = ws_mkdir(template, 0700);
      if (ret >= 0)
	return template;
    }

  /* We return the null string if we can't find a unique file name.  */

  template[0] = '\0';
  return NULL;
}

#endif /* HAVE_MKDTEMP */

#define MAX_TEMPFILES   3

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
	static struct _tf {
		char *path;
		unsigned long len;
	} tf[MAX_TEMPFILES];
	static int idx;

	const char *tmp_dir;
	int old_umask;
	int fd;
	time_t current_time;
	char timestr[14 + 1];
	gchar *tmp_file;
	gchar sep[2] = {0, 0};

	idx = (idx + 1) % MAX_TEMPFILES;
	
	/*
	 * Allocate the buffer if it's not already allocated.
	 */
	if (tf[idx].path == NULL) {
		tf[idx].len = INITIAL_PATH_SIZE;
		tf[idx].path = (char *)g_malloc(tf[idx].len);
	}

	/*
	 * We can't use get_tempfile_path here because we're called from dumpcap.c.
	 */
	tmp_dir = g_get_tmp_dir();

#ifdef _WIN32
	_tzset();
#endif
	current_time = time(NULL);
	strftime(timestr, sizeof(timestr), "%Y%m%d%H%M%S", localtime(&current_time));
	sep[0] = G_DIR_SEPARATOR;
	tmp_file = g_strconcat(tmp_dir, sep, pfx, "_", timestr, "_", TMP_FILE_SUFFIX, NULL);
	if (strlen(tmp_file) > tf[idx].len) {
		tf[idx].len = (int)strlen(tmp_file) + 1;
		tf[idx].path = (char *)g_realloc(tf[idx].path, tf[idx].len);
	}
	g_strlcpy(tf[idx].path, tmp_file, tf[idx].len);
	g_free(tmp_file);

	if (namebuf) {
		*namebuf = tf[idx].path;
	}
	/* The Single UNIX Specification doesn't say that "mkstemp()"
	   creates the temporary file with mode rw-------, so we
	   won't assume that all UNIXes will do so; instead, we set
	   the umask to 0077 to take away all group and other
	   permissions, attempt to create the file, and then put
	   the umask back. */
	old_umask = umask(0077);
	fd = mkstemp(tf[idx].path);
	umask(old_umask);
	return fd;
}

/**
 * Create a directory with the given prefix (e.g. "wireshark"). The path
 * is created using g_get_tmp_dir and mkdtemp.
 * 
 * @param namebuf 
 * @param pfx A prefix for the temporary directory.
 * @return The temporary directory path on success, or NULL on failure.
 *         Must NOT be freed.
 */
const char *
create_tempdir(char **namebuf, const char *pfx)
{
	static char *td_path[3];
	static int td_path_len[3];
	static int idx;
	const char *tmp_dir;

	idx = (idx + 1) % 3;
	
	/*
	 * Allocate the buffer if it's not already allocated.
	 */
	if (td_path[idx] == NULL) {
		td_path_len[idx] = INITIAL_PATH_SIZE;
		td_path[idx] = (char *)g_malloc(td_path_len[idx]);
	}

	/*
	 * We can't use get_tempfile_path here because we're called from dumpcap.c.
	 */
	tmp_dir = g_get_tmp_dir();

	while (g_snprintf(td_path[idx], td_path_len[idx], "%s%c%s" TMP_FILE_SUFFIX, tmp_dir, G_DIR_SEPARATOR, pfx) > td_path_len[idx]) {
		td_path_len[idx] *= 2;
		td_path[idx] = (char *)g_realloc(td_path[idx], td_path_len[idx]);
	}

	if (namebuf) {
		*namebuf = td_path[idx];
	}
	return mkdtemp(td_path[idx]);
}
