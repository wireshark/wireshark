/* tempfile.h
 * Declarations of routines to create temporary files
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TEMPFILE_H__
#define __TEMPFILE_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Convenience function for temporary file creation.
 */

/**
 * Create a tempfile with the given prefix (e.g. "wireshark"). The path
 * is created using g_file_open_tmp.
 *
 * @param namebuf [in,out] If not NULL, receives the full path of the temp file.
 *                Must be freed.
 * @param pfx [in] A prefix for the temporary file.
 * @param sfx [in] A file extension for the temporary file. NULL can be passed
 *                 if no file extension is needed
 * @param err [out] Any error returned by g_file_open_tmp. May be NULL.
 * @return The file descriptor of the new tempfile, from mkstemps().
 */
WS_DLL_PUBLIC int create_tempfile(gchar **namebuf, const char *pfx, const char *sfx, GError **err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEMPFILE_H__ */
