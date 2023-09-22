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

#include <wireshark.h>

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
 * @param tempdir [in] If not NULL, the directory in which to create the file.
 * @param namebuf [in,out] If not NULL, receives the full path of the temp file.
 *                Must be g_freed.
 * @param pfx [in] A prefix for the temporary file.
 * @param sfx [in] A file extension for the temporary file. NULL can be passed
 *                 if no file extension is needed
 * @param err [out] Any error returned by g_file_open_tmp. May be NULL.
 * @return The file descriptor of the new tempfile, from mkstemps().
 */
WS_DLL_PUBLIC int create_tempfile(const char *tempdir, char **namebuf, const char *pfx, const char *sfx, GError **err);

/**
 * Create a tempfile with the given parent directory (e.g. "/my/private/tmp"). The path
 * is created using g_mkdtemp.
 *
 * @param parent_dir [in] If not NULL, the parent directory in which to create the subdirectory,
 *                        otherwise the system temporary directory is used.
 * @param tmpl [in] A template for the temporary directory.
 * @param err [out] Any error returned by g_mkdtemp. May be NULL.
 * @return The full path of the temporary directory or NULL on error. Must be g_freed.
 */
WS_DLL_PUBLIC char *create_tempdir(const char *parent_dir, const char *tmpl, GError **err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEMPFILE_H__ */
