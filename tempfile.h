/* tempfile.h
 * Declarations of routines to create temporary files
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __TEMPFILE_H__
#define __TEMPFILE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @file
 * Convenience function for temporary file creation.
 */


/**
 * Create a tempfile with the given prefix (e.g. "wireshark"). The path
 * is created using g_get_tmp_dir and mkstemp.
 * 
 * @param namebuf If not NULL, receives the full path of the temp file.
 *                Must NOT be freed.
 * @param pfx A prefix for the temporary file.
 * @return The file descriptor of the new tempfile, from mkstemp().
 */
int create_tempfile(char **namebuf, const char *pfx);

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
const char *create_tempdir(char **namebuf, const char *pfx);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEMPFILE_H__ */
