/* file_wrappers.c
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/*
 * Do this now, to get close() defined, before we muck with the definition
 * of HAVE_UNISTD_H.  See below for the full sad story of why we do that.
 */
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

/*
 * OK, now this is tricky.
 *
 * At least on FreeBSD 3.2, "/usr/include/zlib.h" includes
 * "/usr/include/zconf.h", which, if HAVE_UNISTD_H is defined,
 * #defines "z_off_t" to be "off_t", and if HAVE_UNISTD_H is
 * not defined, #defines "z_off_t" to be "long" if it's not
 * already #defined.
 *
 * In 4.4-Lite-derived systems such as FreeBSD, "off_t" is
 * "long long int", not "long int", so the definition of "z_off_t" -
 * and therefore the types of the arguments to routines such as
 * "gzseek()", as declared, with prototypes, in "zlib.h" - depends
 * on whether HAVE_UNISTD_H is defined prior to including "zlib.h"!
 *
 * It's not defined in the FreeBSD 3.2 "zlib", so if we include "zlib.h"
 * after defining HAVE_UNISTD_H, we get a misdeclaration of "gzseek()",
 * and, if we're building with "zlib" support, anything that seeks
 * on a file may not work.
 *
 * Other BSDs may have the same problem, if they haven't done something
 * such as defining HAVE_UNISTD_H in "zconf.h".
 *
 * "config.h" defines HAVE_UNISTD_H, on all systems that have it, and all
 * 4.4-Lite-derived BSDs have it.  Therefore, given that "zlib.h" is included
 * by "file_wrappers.h", that means that unless we include "zlib.h" before
 * we include "config.h", we get a misdeclaration of "gzseek()".
 *
 * Unfortunately, it's "config.h" that tells us whether we have "zlib"
 * in the first place, so we don't know whether to include "zlib.h"
 * until we include "config.h"....
 *
 * A similar problem appears to occur with "gztell()", at least on
 * NetBSD.
 *
 * To add further complication, on recent versions, at least, of OpenBSD,
 * the Makefile for zlib defines HAVE_UNISTD_H.
 *
 * So what we do is, on all OSes other than OpenBSD, *undefine* HAVE_UNISTD_H
 * before including "wtap-int.h" (it handles including "zlib.h" if HAVE_ZLIB
 * is defined, and it includes "wtap.h", which we include to get the
 * WTAP_ERR_ZLIB values), and, if we have zlib, make "file_seek()" and
 * "file_tell()" subroutines, so that the only calls to "gzseek()" and
 * "gztell()" are in this file, which, by dint of the hackery described
 * above, manages to correctly declare "gzseek()" and "gztell()".
 *
 * On OpenBSD, we forcibly *define* HAVE_UNISTD_H if it's not defined.
 *
 * Hopefully, the BSDs will, over time, remove the test for HAVE_UNISTD_H
 * from "zconf.h", so that "gzseek()" and "gztell()" will be declared
 * with the correct signature regardless of whether HAVE_UNISTD_H is
 * defined, so that if they change the signature we don't have to worry
 * about making sure it's defined or not defined.
 *
 * DO NOT, UNDER ANY CIRCUMSTANCES, REMOVE THE FOLLOWING LINES, OR MOVE
 * THEM AFTER THE INCLUDE OF "wtap-int.h"!  Doing so will cause any program
 * using Wiretap to read capture files to fail miserably on a FreeBSD
 * 3.2 or 3.3 system - and possibly some other BSD systems - if zlib is
 * installed.  If you *must* have HAVE_UNISTD_H defined before including
 * "wtap-int.h", put "file_error()" into a file by itself, which can
 * cheerfully include "wtap.h" and get "gzseek()" misdeclared, and include
 * just "zlib.h" in this file - *after* undefining HAVE_UNISTD_H.
 */
#ifdef __OpenBSD__
#ifndef HAVE_UNISTD_H
#define HAVE_UNISTD_H
#endif /* HAVE_UNISTD_H */
#else /* __OpenBSD__ */
#undef HAVE_UNISTD_H
#endif /* __OpenBSD__ */

#include <errno.h>
#include <stdio.h>
#ifdef HAVE_LIBZ
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#include <string.h>
#endif /* HAVE_LIBZ */
#include "wtap-int.h"
#include "file_wrappers.h"
#include "file_util.h"


#ifdef HAVE_LIBZ

FILE_T
file_open(const char *path, const char *mode)
{
	int fd;
	FILE_T ft;
	int oflag;

	if (*mode == 'r') {
		if (strchr(mode + 1, '+') != NULL)
			oflag = O_RDWR;
		else
			oflag = O_RDONLY;
	} else if (*mode == 'w') {
		if (strchr(mode + 1, '+') != NULL)
			oflag = O_RDWR|O_CREAT|O_TRUNC;
		else
			oflag = O_RDONLY|O_CREAT|O_TRUNC;
	} else if (*mode == 'a') {
		if (strchr(mode + 1, '+') != NULL)
			oflag = O_RDWR|O_APPEND;
		else
			oflag = O_RDONLY|O_APPEND;
	} else {
		errno = EINVAL;
		return NULL;
	}
#ifdef _WIN32
	if (strchr(mode + 1, 'b') != NULL)
		oflag |= O_BINARY;
#endif
	/* open file and do correct filename conversions */
	if ((fd = eth_open(path, oflag, 0666)) == -1)
		return NULL;

	/* open zlib file handle */
	ft = gzdopen(fd, mode);
	if (ft == NULL) {
		eth_close(fd);
		return NULL;
	}

	return ft;
}

gint64
file_seek(void *stream, gint64 offset, int whence, int *err)
{
	gint64 ret;

	/* XXX - z_off_t is usually long, won't work >= 2GB! */
	ret = (gint64) gzseek(stream, (z_off_t)offset, whence);
	if (ret == -1) {
		/*
		 * XXX - "gzseek()", as of zlib 1.1.4, doesn't set
		 * "z_err" for the stream, so "gzerror()" could return
		 * a bogus Z_OK.
		 *
		 * As this call failed, we know "gzerror()" shouldn't
		 * return Z_OK; if it does, we assume that "errno" is
		 * the real error.
		 */
		*err = file_error(stream);
		if (*err == 0)
			*err = errno;
	}
	return ret;
}

gint64
file_tell(void *stream)
{
	/* XXX - z_off_t is usually long, won't work >= 2GB! */
	return (gint64)gztell(stream);
}

/*
 * Routine to return a Wiretap error code (0 for no error, an errno
 * for a file error, or a WTAP_ERR_ code for other errors) for an
 * I/O stream.
 */
int
file_error(void *fh)
{
	int errnum;

	gzerror(fh, &errnum);
	switch (errnum) {

	case Z_OK:		/* no error */
		return 0;

	case Z_STREAM_END:	/* EOF - not an error */
		return 0;

	case Z_ERRNO:		/* file I/O error */
		return errno;

	default:
		return WTAP_ERR_ZLIB + errnum;
	}
}

#else /* HAVE_LIBZ */

gint64
file_seek(void *stream, gint64 offset, int whence, int *err)
{
	gint64 ret;
#ifdef _WIN32
        gint64 pos;
#endif

#ifdef _WIN32
        /* Win32 version using fsetpos/fgetpos */
        /* XXX - using fsetpos/fgetpos this way is UNDOCUMENTED, but I don't see a any better way :-( */
        /* _lseeki64(_fileno(stream)) doesn't work as this will mangle the internal FILE handling data */
        switch(whence) {
        case(SEEK_SET):
            /* do nothing */
            break;
        case(SEEK_CUR):
            /* adjust offset */
            /* XXX - CURRENTLY UNTESTED!!! */
	    ret = fgetpos(stream, &pos);
            if(ret != 0) {
                *err = errno;
                return ret;
            }
            offset += pos;
            break;
        case(SEEK_END):
        default:
            g_assert_not_reached();
        }
	ret = fsetpos(stream, &offset);
	if(ret != 0) {
		*err = errno;
	}
	/* XXX - won't work >= 2GB! */
	/*ret = (gint64) fseek(stream, (long) offset, whence);
	if(ret == -1) {
		*err = errno;
	}*/
#else
        /* "basic" version using fseek */
	/* XXX - won't work >= 2GB! */
	ret = (gint64) fseek(stream, (long) offset, whence);
	if (ret == -1)
		*err = file_error(stream);
#endif
        /*g_warning("Seek %lld whence %u ret %lld size %u", offset, whence, ret, sizeof(fpos_t));*/
	return ret;
}

gint64
file_tell(void *stream)
{
#ifdef _WIN32
        /* Win32 version using _telli64 */
        /* XXX - CURRENTLY UNTESTED!!! */
	return _telli64(_fileno((FILE *)stream));
#else
        /* "basic" version using ftell */
	/* XXX - ftell returns a long - won't work >= 2GB! */
	return (gint64) ftell(stream);
#endif
}

int
file_error(void *fh)
{
	if (ferror((FILE *) fh))
		return errno;
	else
		return 0;
}

#endif /* HAVE_LIBZ */
