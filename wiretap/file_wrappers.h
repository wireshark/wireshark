/* file_wrappers.h
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

#ifndef __WTAP_FILE_WRAPPERS_H__
#define __WTAP_FILE_WRAPPERS_H__

#include <glib.h>
#include "wtap.h"
#include <wsutil/file_util.h>
#include "ws_symbol_export.h"

extern FILE_T file_open(const char *path);
extern FILE_T file_fdopen(int fildes);
extern void file_set_random_access(FILE_T stream, gboolean random_flag, GPtrArray *seek);
WS_DLL_PUBLIC gint64 file_seek(FILE_T stream, gint64 offset, int whence, int *err);
extern gboolean file_skip(FILE_T file, gint64 delta, int *err);
WS_DLL_PUBLIC gint64 file_tell(FILE_T stream);
extern gint64 file_tell_raw(FILE_T stream);
extern int file_fstat(FILE_T stream, ws_statb64 *statb, int *err);
WS_DLL_PUBLIC gboolean file_iscompressed(FILE_T stream);
WS_DLL_PUBLIC int file_read(void *buf, unsigned int count, FILE_T file);
WS_DLL_PUBLIC int file_peekc(FILE_T stream);
WS_DLL_PUBLIC int file_getc(FILE_T stream);
WS_DLL_PUBLIC char *file_gets(char *buf, int len, FILE_T stream);
WS_DLL_PUBLIC int file_eof(FILE_T stream);
WS_DLL_PUBLIC int file_error(FILE_T fh, gchar **err_info);
extern void file_clearerr(FILE_T stream);
extern void file_fdclose(FILE_T file);
extern int file_fdreopen(FILE_T file, const char *path);
extern void file_close(FILE_T file);

#ifdef HAVE_ZLIB
typedef struct wtap_writer *GZWFILE_T;

extern GZWFILE_T gzwfile_open(const char *path);
extern GZWFILE_T gzwfile_fdopen(int fd);
extern guint gzwfile_write(GZWFILE_T state, const void *buf, guint len);
extern int gzwfile_flush(GZWFILE_T state);
extern int gzwfile_close(GZWFILE_T state, gboolean is_stdout);
extern int gzwfile_geterr(GZWFILE_T state);
#endif /* HAVE_ZLIB */

#endif /* __FILE_H__ */
