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

extern gint64 file_seek(void *stream, gint64 offset, int whence, int *err);
extern gint64 file_tell(void *stream);
extern int file_error(void *fh);

#ifdef HAVE_LIBZ

extern FILE_T file_open(const char *path);
#define filed_open(fildes) gzdopen(fildes, "rb")
#define file_read(buf, count, file) gzread((file),(buf),(unsigned)(count))
#define file_close gzclose
#define file_getc gzgetc
#define file_gets(buf, len, file) gzgets((file), (buf), (len))
#define file_eof gzeof

#else /* No zLib */

#define file_open(path) ws_fopen(path, "rb")
#define filed_open(fildes) fdopen(fildes, "rb")
#define file_read(buf, count, file) fread((buf), (1), (count), (file))
#define file_close fclose
#define file_getc fgetc
#define file_gets fgets
#define file_eof feof

#endif /* HAVE_LIBZ */

#endif /* __FILE_H__ */
