/* file_wrappers.h
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifndef __FILE_H__
#define __FILE_H__

extern gint64 file_seek(FILE_T stream, gint64 offset, int whence, int *err);
extern gint64 file_tell(FILE_T stream);
extern int file_error(FILE_T fh);

extern FILE_T file_open(const char *path);
extern FILE_T filed_open(int fildes);
extern int file_read(void *buf, unsigned int count, FILE_T file);
extern int file_close(FILE_T file);
extern int file_getc(FILE_T stream);
extern char *file_gets(char *buf, int len, FILE_T stream);
extern int file_eof(FILE_T stream);
extern void file_clearerr(FILE_T stream);

#ifdef HAVE_LIBZ
typedef struct wtap_writer *GZWFILE_T;

extern GZWFILE_T gzwfile_open(const char *path);
extern GZWFILE_T gzwfile_fdopen(int fd);
extern unsigned gzwfile_write(GZWFILE_T state, const void *buf, unsigned len);
extern int gzwfile_flush(GZWFILE_T state);
extern int gzwfile_close(GZWFILE_T state);
extern int gzwfile_geterr(GZWFILE_T state);
#endif /* HAVE_LIBZ */

#endif /* __FILE_H__ */
