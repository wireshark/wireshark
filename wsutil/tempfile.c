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

  gchar* filetmpl = g_strdup_printf("%sXXXXXX%s", pfx ? pfx : "", sfx ? sfx : "");

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
