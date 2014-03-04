/* ft_file_wrappers.h
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifndef __FILE_H__
#define __FILE_H__

#include <glib.h>
#include <ftap.h>
#include <wsutil/file_util.h>
#include "ws_symbol_export.h"

extern FILE_F file_open(const char *path);
extern FILE_F file_fdopen(int fildes);
extern void file_set_random_access(FILE_F stream, gboolean random_flag, GPtrArray *seek);
WS_DLL_PUBLIC gint64 file_seek(FILE_F stream, gint64 offset, int whence, int *err);
extern gboolean file_skip(FILE_F file, gint64 delta, int *err);
WS_DLL_PUBLIC gint64 file_tell(FILE_F stream);
extern gint64 file_tell_raw(FILE_F stream);
extern int file_fstat(FILE_F stream, ws_statb64 *statb, int *err);
extern gboolean file_iscompressed(FILE_F stream);
WS_DLL_PUBLIC int file_read(void *buf, unsigned int count, FILE_F file);
WS_DLL_PUBLIC int file_getc(FILE_F stream);
WS_DLL_PUBLIC char *file_gets(char *buf, int len, FILE_F stream);
WS_DLL_PUBLIC int file_eof(FILE_F stream);
WS_DLL_PUBLIC int file_error(FILE_F fh, gchar **err_info);
extern void file_clearerr(FILE_F stream);
extern void file_fdclose(FILE_F file);
extern int file_fdreopen(FILE_F file, const char *path);
extern void file_close(FILE_F file);

#ifdef HAVE_LIBZ
typedef struct wtap_writer *GZWFILE_T;

extern GZWFILE_T gzwfile_open(const char *path);
extern GZWFILE_T gzwfile_fdopen(int fd);
extern guint gzwfile_write(GZWFILE_T state, const void *buf, guint len);
extern int gzwfile_flush(GZWFILE_T state);
extern int gzwfile_close(GZWFILE_T state);
extern int gzwfile_geterr(GZWFILE_T state);
#endif /* HAVE_LIBZ */

#endif /* __FILE_H__ */
