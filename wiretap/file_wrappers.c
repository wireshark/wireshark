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

/* file_access interface based heavily on zlib gzread.c and gzlib.c from zlib
 * Copyright (C) 1995-2010 Jean-loup Gailly and Mark Adler
 * under licence:
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty.  In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgment in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include <errno.h>
#include <stdio.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#include <string.h>
#include "wtap-int.h"
#include "file_wrappers.h"
#include <wsutil/file_util.h>

/* #define GZBUFSIZE 8192 */
#define GZBUFSIZE 4096

/* values for gz_state compression */
#define UNKNOWN 0      /* look for a gzip header */
#define UNCOMPRESSED 1      /* copy input directly */

#ifdef HAVE_LIBZ
#define ZLIB 2      /* decompress a zlib stream */
#endif

/* XXX, lseek64() instead of ws_lseek()? */

static int	/* gz_load */
raw_read(FILE_T state, unsigned char *buf, unsigned int count, unsigned *have)
{
	int ret;

	*have = 0;
	do {
		ret = read(state->fd, buf + *have, count - *have);
		if (ret <= 0)
			break;
		*have += ret;
	} while (*have < count);
	if (ret < 0) {
		state->err = errno;
		return -1;
	}
	if (ret == 0)
		state->eof = 1;
	return 0;
}

static int /* gz_avail */
fill_in_buffer(FILE_T state)
{
	if (state->err)
		return -1;
	if (state->eof == 0) {
		if (raw_read(state, state->in, state->size, (unsigned *)&(state->avail_in)) == -1)
			return -1;
		state->next_in = state->in;
	}
	return 0;
}

#ifdef HAVE_LIBZ

/* Get next byte from input, or -1 if end or error. */
#define NEXT() ((state->avail_in == 0 && fill_in_buffer(state) == -1) ? -1 : \
                (state->avail_in == 0 ? -1 : \
                 (state->avail_in--, *(state->next_in)++)))

/* Get a four-byte little-endian integer and return 0 on success and the value
   in *ret.  Otherwise -1 is returned and *ret is not modified. */
static int
gz_next4(FILE_T state, guint32 *ret)
{
	guint32 val;
	int ch;

	val = NEXT();
	val += (unsigned)NEXT() << 8;
	val += (guint32)NEXT() << 16;
	ch = NEXT();
	if (ch == -1)
		return -1;
	val += (guint32)ch << 24;
	*ret = val;
	return 0;
}

static int /* gz_decomp */
zlib_read(FILE_T state, unsigned char *buf, unsigned int count)
{
	int ret;
	guint32 crc, len;
	z_streamp strm = &(state->strm);

	strm->avail_out = count;
	strm->next_out = buf;

	/* fill output buffer up to end of deflate stream */
	do {
		/* get more input for inflate() */
		if (state->avail_in == 0 && fill_in_buffer(state) == -1)
			return -1;
		if (state->avail_in == 0) {
			state->err = WTAP_ERR_ZLIB + Z_DATA_ERROR;
			return -1;
		}

		strm->avail_in = state->avail_in;
		strm->next_in = state->next_in;
		/* decompress and handle errors */
		ret = inflate(strm, Z_NO_FLUSH);
		state->avail_in = strm->avail_in;
		state->next_in = strm->next_in;
		if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT) {
			state->err = WTAP_ERR_ZLIB + Z_STREAM_ERROR;
			return -1;
		}
		if (ret == Z_MEM_ERROR) {
			state->err = WTAP_ERR_ZLIB + Z_MEM_ERROR; /* ENOMEM? */
			return -1;
		}
		if (ret == Z_DATA_ERROR) {              /* deflate stream invalid */
			state->err = WTAP_ERR_ZLIB + Z_DATA_ERROR;
			return -1;
		}
	} while (strm->avail_out && ret != Z_STREAM_END);

	/* update available output and crc check value */
	state->next = buf;
	state->have = count - strm->avail_out;
	strm->adler = crc32(strm->adler, state->next, state->have);

	/* check gzip trailer if at end of deflate stream */
	if (ret == Z_STREAM_END) {
		if (gz_next4(state, &crc) == -1 || gz_next4(state, &len) == -1) {
			state->err = WTAP_ERR_ZLIB + Z_DATA_ERROR;
			return -1;
		}
		if (crc != strm->adler) {
			state->err = WTAP_ERR_ZLIB + Z_DATA_ERROR;
			return -1;
		}
		if (len != (strm->total_out & 0xffffffffL)) {
			state->err = WTAP_ERR_ZLIB + Z_DATA_ERROR;
			return -1;
		}
		state->compression = UNKNOWN;      /* ready for next stream, once have is 0 */
	}

	/* good decompression */
	return 0;
}
#endif

static int
gz_head(FILE_T state)
{
	/* get some data in the input buffer */
	if (state->avail_in == 0) {
		if (fill_in_buffer(state) == -1)
			return -1;
		if (state->avail_in == 0)
			return 0;
	}

	/* look for the gzip magic header bytes 31 and 139 */
#ifdef HAVE_LIBZ
	if (state->next_in[0] == 31) {
		state->avail_in--;
		state->next_in++;
		if (state->avail_in == 0 && fill_in_buffer(state) == -1)
			return -1;
		if (state->avail_in && state->next_in[0] == 139) {
			unsigned len;
			int flags;

			/* we have a gzip header, woo hoo! */
			state->avail_in--;
			state->next_in++;

			/* skip rest of header */
			if (NEXT() != 8) {      /* compression method */
				state->err = WTAP_ERR_ZLIB + Z_DATA_ERROR;
				return -1;
			}
			flags = NEXT();
			if (flags & 0xe0) {     /* reserved flag bits */
				state->err = WTAP_ERR_ZLIB + Z_DATA_ERROR;
				return -1;
			}
			NEXT();                 /* modification time */
			NEXT();
			NEXT();
			NEXT();
			NEXT();                 /* extra flags */
			NEXT();                 /* operating system */
			if (flags & 4) {        /* extra field */
				len = (unsigned)NEXT();
				len += (unsigned)NEXT() << 8;
				while (len--)
					if (NEXT() < 0)
						break;
			}
			if (flags & 8)          /* file name */
				while (NEXT() > 0)
					;
			if (flags & 16)         /* comment */
				while (NEXT() > 0)
					;
			if (flags & 2) {        /* header crc */
				NEXT();
				NEXT();
			}
			/* an unexpected end of file is not checked for here -- it will be
			   noticed on the first request for uncompressed data */

			/* set up for decompression */
			inflateReset(&(state->strm));
			state->strm.adler = crc32(0L, Z_NULL, 0);
			state->compression = ZLIB;
			return 0;
		}
		else {
			/* not a gzip file -- save first byte (31) and fall to raw i/o */
			state->out[0] = 31;
			state->have = 1;
		}
	}
#endif
#ifdef HAVE_LIBXZ
	/* { 0xFD, '7', 'z', 'X', 'Z', 0x00 } */
	/* FD 37 7A 58 5A 00 */
#endif

	/* doing raw i/o, save start of raw data for seeking, copy any leftover
	   input to output -- this assumes that the output buffer is larger than
	   the input buffer, which also assures space for gzungetc() */
	state->raw = state->pos;
	state->next = state->out;
	if (state->avail_in) {
		memcpy(state->next + state->have, state->next_in, state->avail_in);
		state->have += state->avail_in;
		state->avail_in = 0;
	}
	state->compression = UNCOMPRESSED;
	return 0;
}

static int /* gz_make */
fill_out_buffer(FILE_T state)
{
	if (state->compression == UNKNOWN) {           /* look for gzip header */
		if (gz_head(state) == -1)
			return -1;
		if (state->have)                /* got some data from gz_head() */
			return 0;
	}
	if (state->compression == UNCOMPRESSED) {           /* straight copy */
		if (raw_read(state, state->out, state->size /* << 1 */, &(state->have)) == -1)
			return -1;
		state->next = state->out;
	}
#ifdef HAVE_LIBZ
	else if (state->compression == ZLIB) {      /* decompress */
		if (zlib_read(state, state->out, state->size << 1) == -1)
			return -1;
	}
#endif
	return 0;
}

static int
gz_skip(FILE_T state, gint64 len)
{
	unsigned n;

	/* skip over len bytes or reach end-of-file, whichever comes first */
	while (len)
		/* skip over whatever is in output buffer */
		if (state->have) {
			n = (gint64)state->have > len ? (unsigned)len : state->have;
			state->have -= n;
			state->next += n;
			state->pos += n;
			len -= n;
		}

	/* output buffer empty -- return if we're at the end of the input */
		else if (state->eof && state->avail_in == 0)
			break;

	/* need more data to skip -- load up output buffer */
		else {
			/* get more output, looking for header if required */
			if (fill_out_buffer(state) == -1)
				return -1;
		}
	return 0;
}

static void
gz_reset(FILE_T state)
{
	state->have = 0;              /* no output data available */
	state->eof = 0;               /* not at end of file */
	state->compression = UNKNOWN; /* look for gzip header */

	state->seek = 0;              /* no seek request pending */
	state->err = 0;               /* clear error */
	state->pos = 0;               /* no uncompressed data yet */
	state->avail_in = 0;          /* no input data yet */
}

FILE_T
filed_open(int fd)
{
#ifdef _STATBUF_ST_BLKSIZE	/* XXX, _STATBUF_ST_BLKSIZE portable? */
	struct stat st;
#endif
	int want = GZBUFSIZE;
	FILE_T state;

	if (fd == -1)
		return NULL;

	/* allocate gzFile structure to return */
	state = g_try_malloc(sizeof(wtap_reader));
	if (state == NULL)
		return NULL;

	/* open the file with the appropriate mode (or just use fd) */
	state->fd = fd;

	/* save the current position for rewinding (only if reading) */
	state->start = ws_lseek(state->fd, 0, SEEK_CUR);
	if (state->start == -1) state->start = 0;

	/* initialize stream */
	gz_reset(state);

#ifdef _STATBUF_ST_BLKSIZE
	if (fstat(fd, &st) >= 0) {
		want = st.st_blksize;
		/* XXX, verify result? */
	}
#endif

	/* allocate buffers */
	state->in = g_try_malloc(want);
	state->out = g_try_malloc(want << 1);
	state->size = want;
	if (state->in == NULL || state->out == NULL) {
		g_free(state->out);
		g_free(state->in);
		g_free(state);
		errno = ENOMEM;
		return NULL;
	}

#ifdef HAVE_LIBZ
	/* allocate inflate memory */
	state->strm.zalloc = Z_NULL;
	state->strm.zfree = Z_NULL;
	state->strm.opaque = Z_NULL;
	state->strm.avail_in = 0;
	state->strm.next_in = Z_NULL;
	if (inflateInit2(&(state->strm), -15) != Z_OK) {    /* raw inflate */
		g_free(state->out);
		g_free(state->in);
		g_free(state);
		errno = ENOMEM;
		return NULL;
	}
#endif
	gz_head(state);	/* read first chunk */

	/* return stream */
	return state;
}

FILE_T
file_open(const char *path)
{
	int fd;
	FILE_T ft;
	int oflag;

	/* O_LARGEFILE? */
	oflag = O_RDONLY;
#ifdef _WIN32
	oflag |= O_BINARY;
#endif

	/* open file and do correct filename conversions */
	if ((fd = ws_open(path, oflag, 0666)) == -1)
		return NULL;

	/* open file handle */
	ft = filed_open(fd);
	if (ft == NULL) {
		ws_close(fd);
		return NULL;
	}

	return ft;
}

gint64
file_seek(FILE_T file, gint64 offset, int whence, int *err)
{
	unsigned n;

	/* check that there's no error */
	if (file->err) {
		*err = file->err;
		return -1;
	}

	/* can only seek from start or relative to current position */
	if (whence != SEEK_SET && whence != SEEK_CUR) {
		g_assert_not_reached();
/*
		*err = EINVAL;
		return -1;
 */
	}

	/* normalize offset to a SEEK_CUR specification */
	if (whence == SEEK_SET)
		offset -= file->pos;
	else if (file->seek)
		offset += file->skip;
	file->seek = 0;

	/* if within raw area while reading, just go there */
	if (file->compression == UNCOMPRESSED && file->pos + offset >= file->raw) {
		if (ws_lseek(file->fd, offset - file->have, SEEK_CUR) == -1) {
			*err = errno;
			return -1;
		}
		file->have = 0;
		file->eof = 0;
		file->seek = 0;
		file->err = 0;
		file->avail_in = 0;
		file->pos += offset;
		return file->pos;
	}

	/* calculate skip amount, rewinding if needed for back seek when reading */
	if (offset < 0) {
		offset += file->pos;
		if (offset < 0) {                    /* before start of file! */
			/* *err = ???; */
			return -1;
		}
		/* rewind, then skip to offset */

		/* back up and start over */
		if (ws_lseek(file->fd, file->start, SEEK_SET) == -1) {
			*err = errno;
			return -1;
		}
		gz_reset(file);
	}

	/* skip what's in output buffer (one less gzgetc() check) */
	n = (gint64)file->have > offset ? (unsigned)offset : file->have;
	file->have -= n;
	file->next += n;
	file->pos += n;
	offset -= n;

	/* request skip (if not zero) */
	if (offset) {
		file->seek = 1;
		file->skip = offset;
	}
	return file->pos + offset;
}

gint64
file_tell(FILE_T stream)
{
	/* return position */
	return stream->pos + (stream->seek ? stream->skip : 0);
}

int 
file_read(void *buf, unsigned int len, FILE_T file)
{
	unsigned got, n;

	/* check that we're reading and that there's no error */
	if (file->err)
		return -1;

	/* if len is zero, avoid unnecessary operations */
	if (len == 0)
		return 0;

	/* process a skip request */
	if (file->seek) {
		file->seek = 0;
		if (gz_skip(file, file->skip) == -1)
			return -1;
	}

	/* get len bytes to buf, or less than len if at the end */
	got = 0;
	do {
		/* first just try copying data from the output buffer */
		if (file->have) {
			n = file->have > len ? len : file->have;
			memcpy(buf, file->next, n);
			file->next += n;
			file->have -= n;
		}

		/* output buffer empty -- return if we're at the end of the input */
		else if (file->eof && file->avail_in == 0)
			break;

		/* need output data -- for small len or new stream load up our output buffer */
		else if (file->compression == UNKNOWN  || len < (file->size << 1)) {
			/* get more output, looking for header if required */
			if (fill_out_buffer(file) == -1)
				return -1;
			continue;       /* no progress yet -- go back to memcpy() above */

		} else if (file->compression == UNCOMPRESSED) {	/* large len -- read directly into user buffer */
			if (raw_read(file, buf, len, &n) == -1)
				return -1;
		}
#ifdef HAVE_LIBZ
		/* large len -- decompress directly into user buffer */
		else {  /* file->compression == ZLIB */
			if (zlib_read(file, buf, len) == -1)
				return -1;
			n = file->have;
			file->have = 0;
		}
#endif
		/* update progress */
		len -= n;
		buf = (char *)buf + n;
		got += n;
		file->pos += n;
	} while (len);

	return (int)got;
}

int
file_getc(FILE_T file)
{
	unsigned char buf[1];
	int ret;

	/* check that we're reading and that there's no error */
	if (file->err)
		return -1;

	/* try output buffer (no need to check for skip request) */
	if (file->have) {
		file->have--;
		file->pos++;
		return *(file->next)++;
	}

	ret = file_read(buf, 1, file);
	return ret < 1 ? -1 : buf[0];
}

char *
file_gets(char *buf, int len, FILE_T file)
{
	unsigned left, n;
	char *str;
	unsigned char *eol;

	/* check parameters */
	if (buf == NULL || len < 1)
		return NULL;

	/* check that there's no error */
	if (file->err)
		return NULL;

	/* process a skip request */
	if (file->seek) {
		file->seek = 0;
		if (gz_skip(file, file->skip) == -1)
			return NULL;
	}

	/* copy output bytes up to new line or len - 1, whichever comes first --
	   append a terminating zero to the string (we don't check for a zero in
	   the contents, let the user worry about that) */
	str = buf;
	left = (unsigned)len - 1;
	if (left) do {
		/* assure that something is in the output buffer */
		if (file->have == 0) {
			if (fill_out_buffer(file) == -1)
				return NULL;            /* error */
			if (file->have == 0)  {     /* end of file */
				if (buf == str)         /* got bupkus */
					return NULL;
				break;                  /* got something -- return it */
			}
		}

		/* look for end-of-line in current output buffer */
		n = file->have > left ? left : file->have;
		eol = memchr(file->next, '\n', n);
		if (eol != NULL)
			n = (unsigned)(eol - file->next) + 1;

		/* copy through end-of-line, or remainder if not found */
		memcpy(buf, file->next, n);
		file->have -= n;
		file->next += n;
		file->pos += n;
		left -= n;
		buf += n;
	} while (left && eol == NULL);

	/* found end-of-line or out of space -- terminate string and return it */
	buf[0] = 0;
	return str;
}

int 
file_eof(FILE_T file)
{
	/* return end-of-file state */
	return (file->eof && file->avail_in == 0 && file->have == 0);
}

/*
 * Routine to return a Wiretap error code (0 for no error, an errno
 * for a file error, or a WTAP_ERR_ code for other errors) for an
 * I/O stream.
 */
int
file_error(FILE_T fh)
{
	return fh->err;
}

void
file_clearerr(FILE_T stream)
{
	/* clear error and end-of-file */
	stream->err = 0;
	stream->eof = 0;
}

int 
file_close(FILE_T file)
{
	int fd = file->fd;

	/* free memory and close file */
	if (file->size) {
#ifdef HAVE_LIBZ
		inflateEnd(&(file->strm));
#endif
		g_free(file->out);
		g_free(file->in);
	}
	file->err = 0;
	g_free(file);
	return close(fd);
}

