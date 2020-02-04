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

#include <glib.h>
#include "tempfile.h"

 /**
 * Create a tempfile with the given prefix (e.g. "wireshark"). The path
 * is created using g_file_open_tmp.
 *
 * @param namebuf [in,out] If not NULL, receives the full path of the temp file.
 *                Must be freed.
 * @param pfx [in] A prefix for the temporary file.
 * @param sfx [in] A file extension for the temporary file. NULL can be passed
 *                 if no file extension is needed
 * @param sfx [out] Any error returned by g_file_open_tmp. May be NULL.
 * @return The file descriptor of the new tempfile, from mkstemps().
 */
int
create_tempfile(gchar **namebuf, const char *pfx, const char *sfx, GError **err)
{
  int fd;
  gchar *safe_pfx = NULL;

  if (pfx) {
    /* The characters in "delimiters" come from:
     * https://docs.microsoft.com/en-us/windows/win32/fileio/naming-a-file#naming-conventions.
     * Add to the list as necessary for other OS's.
     */
    const gchar *delimiters = "<>:\"/\\|?*"
      "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
      "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
      "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";

    /* Sanitize the pfx to resolve bug 7877 */
    safe_pfx = g_strdup(pfx);
    safe_pfx = g_strdelimit(safe_pfx, delimiters, '-');
  }

  gchar* filetmpl = g_strdup_printf("%sXXXXXX%s", safe_pfx ? safe_pfx : "", sfx ? sfx : "");
  g_free(safe_pfx);

  fd = g_file_open_tmp(filetmpl, namebuf, err);

  g_free(filetmpl);
  return fd;
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
