/* tempfile.h
 * Declarations of routines to create temporary files
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
 * Construct the path name of a file in the appropriate temporary
 * file directory.
 *
 * @param filename the file name to be given to the file.
 * @return the pathname of the file, g_malloced so the caller
 * should g_free it.
 */
WS_DLL_PUBLIC char *get_tempfile_path(const char *filename);

/**
 * Create a tempfile with the given prefix (e.g. "wireshark"). The path
 * is created using g_get_tmp_dir and mkstemp.
 *
 * @param namebuf [in,out] If not NULL, receives the full path of the temp file.
 *                Must NOT be freed.
 * @param pfx [in] A prefix for the temporary file.
 * @param sfx [in] A file extension for the temporary file. NULL can be passed
 *                 if no file extension is needed
 * @return The file descriptor of the new tempfile, from mkstemps().
 */
WS_DLL_PUBLIC int create_tempfile(char **namebuf, const char *pfx, const char *sfx);

/**
 * Create a directory with the given prefix (e.g. "wireshark"). The path
 * is created using g_get_tmp_dir and mkdtemp.
 *
 * @param namebuf If not NULL, receives the full path of the temp directory.
 *                Must NOT be freed.
 * @param pfx A prefix for the temporary directory.
 * @return The temporary directory path on success, or NULL on failure.
 *         Must NOT be freed.
 */
WS_DLL_PUBLIC const char *create_tempdir(char **namebuf, const char *pfx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEMPFILE_H__ */
