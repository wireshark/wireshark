/* tempfile.c
 * Routines to create temporary files
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
#include <stdlib.h>
#include <errno.h>

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

#ifndef HAVE_MKSTEMPS
/* Generate a unique temporary file name from TEMPLATE.
   The last six characters before the suffix length of TEMPLATE
   must be TMP_FILE_SUFFIX; they are replaced with a string that
   makes the filename unique.
   Returns a file descriptor open on the file for reading and writing.  */
static int
mkstemps(char *path_template, int suffixlen)
{
  static const char letters[]
    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  char uniqueness[6];
  size_t len;
  size_t i;

  len = strlen (path_template);
  if (len < 6 || strncmp (&path_template[len - 6 - suffixlen], TMP_FILE_SUFFIX, 6))
    {
      __set_errno (EINVAL);
      return -1;
    }

  if (g_snprintf (uniqueness, 6, "%.5u",
                  (unsigned int) ws_getpid () % 100000) != 5)
    /* Inconceivable lossage.  */
    return -1;

  memcpy(&path_template[len - 5 - suffixlen], uniqueness, 5);

  for (i = 0; i < sizeof (letters); ++i)
    {
      int fd;

      path_template[len - 6 - suffixlen] = letters[i];

      fd = ws_open (path_template, O_RDWR|O_BINARY|O_CREAT|O_EXCL, 0600);
      if (fd >= 0)
        return fd;
    }

  /* We return the null string if we can't find a unique file name.  */

  path_template[0] = '\0';
  return -1;
}

#endif /* HAVE_MKSTEMPS */

#ifndef HAVE_MKDTEMP
/* Generate a unique temporary directory name from TEMPLATE.
   The last six characters of TEMPLATE must be TMP_FILE_SUFFIX;
   they are replaced with a string that makes the filename unique.
   Returns 0 on success or -1 on error (from mkdir(2)).  */
char *
mkdtemp (char *path_template)
{
  static const char letters[]
    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  size_t len;
  size_t i;

  len = strlen (path_template);
  if (len < 6 || strcmp (&path_template[len - 6], TMP_FILE_SUFFIX))
    {
      __set_errno (EINVAL);
      return NULL;
    }

  if (g_snprintf (&path_template[len - 5], 6, "%.5u",
                  (unsigned int) ws_getpid () % 100000) != 5)
    /* Inconceivable lossage.  */
    return NULL;

  for (i = 0; i < sizeof (letters); ++i)
    {
      int ret;

      path_template[len - 6] = letters[i];

      ret = ws_mkdir(path_template, 0700);
      if (ret >= 0)
        return path_template;
    }

  /* We return the null string if we can't find a unique file name.  */

  path_template[0] = '\0';
  return NULL;
}

#endif /* HAVE_MKDTEMP */

/*
 * Construct and return the path name of a file in the
 * appropriate temporary file directory.
 */
char *get_tempfile_path(const char *filename)
{
  return g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", g_get_tmp_dir(), filename);
}

#define MAX_TEMPFILES   3

/**
 * Create a tempfile with the given prefix (e.g. "wireshark").
 *
 * @param namebuf If not NULL, receives the full path of the temp file.
 *                Should NOT be freed.
 * @param pfx A prefix for the temporary file.
 * @param sfx [in] A file extension for the temporary file. NULL can be passed
 *                 if no file extension is needed
 * @return The file descriptor of the new tempfile, from mkstemps().
 */
int
create_tempfile(char **namebuf, const char *pfx, const char *sfx)
{
  static struct _tf {
    char *path;
    size_t len;
  } tf[MAX_TEMPFILES];
  static int idx;

  const char *tmp_dir;
  int old_umask;
  int fd;
  time_t current_time;
  char timestr[14 + 1];
  gchar *tmp_file;
  gchar *safe_pfx;
  gchar sep[2] = {0, 0};

  /* The characters in "delimiters" come from:
   * http://msdn.microsoft.com/en-us/library/aa365247%28VS.85%29.aspx.
   * Add to the list as necessary for other OS's.
   */
  const gchar *delimiters = "<>:\"/\\|?*"
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
    "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";

  /* Sanitize the pfx to resolve bug 7877 */
  safe_pfx = g_strdup(pfx);
  safe_pfx = g_strdelimit(safe_pfx, delimiters, '-');

  idx = (idx + 1) % MAX_TEMPFILES;

  /*
   * Allocate the buffer if it's not already allocated.
   */
  if (tf[idx].path == NULL) {
    tf[idx].len = INITIAL_PATH_SIZE;
    tf[idx].path = (char *)g_malloc(tf[idx].len);
  }

  tmp_dir = g_get_tmp_dir();

#ifdef _WIN32
  _tzset();
#endif
  current_time = time(NULL);
  /* We trust the OS not to return a time before the Epoch. */
  strftime(timestr, sizeof(timestr), "%Y%m%d%H%M%S", localtime(&current_time));
  sep[0] = G_DIR_SEPARATOR;
  tmp_file = g_strconcat(tmp_dir, sep, safe_pfx, "_", timestr, "_", TMP_FILE_SUFFIX, sfx, NULL);
  g_free(safe_pfx);
  if (strlen(tmp_file) > tf[idx].len) {
    tf[idx].len = strlen(tmp_file) + 1;
    tf[idx].path = (char *)g_realloc(tf[idx].path, tf[idx].len);
  }
  g_strlcpy(tf[idx].path, tmp_file, tf[idx].len);
  g_free(tmp_file);

  if (namebuf) {
    *namebuf = tf[idx].path;
  }
  /* The Single UNIX Specification doesn't say that "mkstemps()"
     creates the temporary file with mode rw-------, so we
     won't assume that all UNIXes will do so; instead, we set
     the umask to 0077 to take away all group and other
     permissions, attempt to create the file, and then put
     the umask back. */
  old_umask = ws_umask(0077);
  fd = mkstemps(tf[idx].path, sfx ? (int) strlen(sfx) : 0);
  ws_umask(old_umask);
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
