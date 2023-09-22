/* tempfile.c
 * Routines to create temporary files
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "tempfile.h"

#include <errno.h>

#include "file_util.h"

static char *
sanitize_prefix(const char *prefix)
{
  if (!prefix) {
      return NULL;
  }

  /* The characters in "delimiters" come from:
   * https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions.
   * Add to the list as necessary for other OS's.
   */
  const char *delimiters = "<>:\"/\\|?*"
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
    "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";

  /* Sanitize the prefix to resolve bug 7877 */
  char *safe_prefx = g_strdup(prefix);
  safe_prefx = g_strdelimit(safe_prefx, delimiters, '-');
  return safe_prefx;
}

 /**
 * Create a tempfile with the given prefix (e.g. "wireshark"). The path
 * is created using g_file_open_tmp.
 *
 * @param tempdir [in] If not NULL, the directory in which to create the file.
 * @param namebuf [in,out] If not NULL, receives the full path of the temp file.
 *                Must be freed.
 * @param pfx [in] A prefix for the temporary file.
 * @param sfx [in] A file extension for the temporary file. NULL can be passed
 *                 if no file extension is needed
 * @param err [out] Any error returned by g_file_open_tmp. May be NULL
 * @return The file descriptor of the new tempfile, from mkstemps().
 */
int
create_tempfile(const char *tempdir, char **namebuf, const char *pfx, const char *sfx, GError **err)
{
  int fd;
  char *safe_pfx = sanitize_prefix(pfx);

  if (tempdir == NULL || tempdir[0] == '\0') {
    /* Use OS default tempdir behaviour */
    char* filetmpl = ws_strdup_printf("%sXXXXXX%s", safe_pfx ? safe_pfx : "", sfx ? sfx : "");
    g_free(safe_pfx);

    fd = g_file_open_tmp(filetmpl, namebuf, err);
    g_free(filetmpl);
  }
  else {
    /* User-specified tempdir.
     * We don't get libc's help generating a random name here.
     */
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
    const int32_t a_len = 64;
    char* filetmpl = NULL;

    while(1) {
      g_free(filetmpl);
      filetmpl = ws_strdup_printf("%s%c%s%c%c%c%c%c%c%s",
          tempdir,
          G_DIR_SEPARATOR,
          safe_pfx ? safe_pfx : "",
          alphabet[g_random_int_range(0, a_len)],
          alphabet[g_random_int_range(0, a_len)],
          alphabet[g_random_int_range(0, a_len)],
          alphabet[g_random_int_range(0, a_len)],
          alphabet[g_random_int_range(0, a_len)],
          alphabet[g_random_int_range(0, a_len)],
          sfx ? sfx : "");

      fd = ws_open(filetmpl, O_CREAT|O_EXCL|O_BINARY|O_WRONLY, 0600);
      if (fd >= 0) {
        break;
      }
      if (errno != EEXIST) {
        g_set_error_literal(err, G_FILE_ERROR,
            g_file_error_from_errno(errno), g_strerror(errno));
        g_free(filetmpl);
        filetmpl = NULL;
        break;
      }
      /* Loop continues if error was EEXIST, meaning the file we tried
       * to make already existed at the destination
       */
    }

    if (namebuf == NULL) {
      g_free(filetmpl);
    }
    else {
      *namebuf = filetmpl;
    }
    g_free(safe_pfx);
  }

  return fd;
}

char *
create_tempdir(const char *parent_dir, const char *tmpl, GError **err)
{
  if (parent_dir == NULL || parent_dir[0] == '\0') {
      parent_dir = g_get_tmp_dir();
  }

  char *safe_pfx = sanitize_prefix(tmpl);
  if (safe_pfx == NULL) {
    safe_pfx = g_strdup("wireshark_XXXXXX");
  }

  char *temp_subdir = g_build_path(G_DIR_SEPARATOR_S, parent_dir, safe_pfx, NULL);
  g_free(safe_pfx);
  if (g_mkdtemp(temp_subdir) == NULL)
  {
      g_free(temp_subdir);
      g_set_error_literal(err, G_FILE_ERROR,
          g_file_error_from_errno(errno), g_strerror(errno));
      return false;
  }

  return temp_subdir;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
