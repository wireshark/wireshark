/* file.h
 *
 * $Id: file.h,v 1.3 1999/09/24 05:49:50 guy Exp $
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@verdict.uthscsa.edu>
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

#ifdef HAVE_LIBZ
#define file_open gzopen
#define filed_open gzdopen
#define file_seek gzseek
#define file_read(buf, bsize, count, file) gzread((file),(buf),((count)*(bsize)))
#define file_write(buf, bsize, count, file) gzwrite((file),(buf),((count)*(bsize)))
#define file_close gzclose
#define file_tell gztell
#define file_getc gzgetc
static inline int file_error(void *fh) {
    int errnum;
    gzerror(fh, &errnum);
    if (errnum<0) return errnum;
    return 0;
}

#else /* No zLib */
#define file_open fopen
#define filed_open fdopen
#define file_seek fseek
#define file_read fread
#define file_write fwrite
#define file_close fclose
#define file_error ferror
#define file_tell ftell
#define file_getc fgetc
#endif /* HAVE_LIBZ */

#endif /* __FILE_H__ */
