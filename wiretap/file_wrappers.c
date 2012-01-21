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

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif /* HAVE_LIBZ */

/*
 * See RFC 1952 for a description of the gzip file format.
 *
 * Some other compressed file formats we might want to support:
 *
 *	XZ format: http://tukaani.org/xz/
 *
 *	Bzip2 format: http://bzip.org/
 */

/*
 * List of extensions for compressed files.
 * If we add support for more compressed file types, this table
 * might be expanded to include routines to handle the various
 * compression types.
 */
static const char *compressed_file_extensions[] = {
#ifdef HAVE_LIBZ
	"gz",
#endif
	NULL
};

/*
 * Return a GSList of all the compressed file extensions.
 * The data pointers all point to items in compressed_file_extensions[],
 * so the GSList can just be freed with g_slist_free().
 */
GSList *
wtap_get_compressed_file_extensions(void)
{
	const char **extension;
	GSList *extensions;

	extensions = NULL;
	for (extension = &compressed_file_extensions[0]; *extension != NULL;
	    extension++)
		extensions = g_slist_append(extensions, (gpointer)(*extension));
	return extensions;
}

/* #define GZBUFSIZE 8192 */
#define GZBUFSIZE 4096

struct wtap_reader {
	int fd;                 /* file descriptor */
	gint64 raw_pos;         /* current position in file (just to not call lseek()) */
	gint64 pos;             /* current position in uncompressed data */
	unsigned size;          /* buffer size */
	unsigned char *in;      /* input buffer */
	unsigned char *out;     /* output buffer (double-sized when reading) */
	unsigned char *next;    /* next output data to deliver or write */

	unsigned have;          /* amount of output data unused at next */
	int eof;                /* true if end of input file reached */
	gint64 start;           /* where the gzip data started, for rewinding */
	gint64 raw;             /* where the raw data started, for seeking */
	int compression;        /* 0: ?, 1: uncompressed, 2: zlib */
	/* seek request */
	gint64 skip;            /* amount to skip (already rewound if backwards) */
	int seek;               /* true if seek request pending */
	/* error information */
	int err;                /* error code */
	const char *err_info;   /* additional error information string for some errors */

	unsigned int  avail_in;  /* number of bytes available at next_in */
	unsigned char *next_in;  /* next input byte */
#ifdef HAVE_LIBZ
	/* zlib inflate stream */
	z_stream strm;          /* stream structure in-place (not a pointer) */
	int dont_check_crc;	/* 1 if we aren't supposed to check the CRC */
#endif
	/* fast seeking */
	GPtrArray *fast_seek;
	void *fast_seek_cur;
};

/* values for gz_state compression */
#define UNKNOWN		0	/* look for a gzip header */
#define UNCOMPRESSED	1	/* copy input directly */
#ifdef HAVE_LIBZ
#define ZLIB		2	/* decompress a zlib stream */
#define GZIP_AFTER_HEADER 3
#endif

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
		state->raw_pos += ret;
	} while (*have < count);
	if (ret < 0) {
		state->err = errno;
		state->err_info = NULL;
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

#define ZLIB_WINSIZE 32768

struct fast_seek_point {
	gint64 out; 	/* corresponding offset in uncompressed data */
	gint64 in;		/* offset in input file of first full byte */

	int compression;
	union {
		struct {
#ifdef HAVE_INFLATEPRIME
			int bits;		/* number of bits (1-7) from byte at in - 1, or 0 */
#endif
			unsigned char window[ZLIB_WINSIZE];	/* preceding 32K of uncompressed data */

			/* be gentle with Z_STREAM_END, 8 bytes more... Another solution would be to comment checks out */
			guint32 adler;
			guint32 total_out;
		} zlib;
	} data;
};

struct zlib_cur_seek_point {
	unsigned char window[ZLIB_WINSIZE];	/* preceding 32K of uncompressed data */
	unsigned int pos;
	unsigned int have;
};

#define SPAN G_GINT64_CONSTANT(1048576)
static struct fast_seek_point *
fast_seek_find(FILE_T file, gint64 pos)
{
	struct fast_seek_point *smallest = NULL;
	struct fast_seek_point *item;
	guint low, i, max;

	if (!file->fast_seek)
		return NULL;

	for (low = 0, max = file->fast_seek->len; low < max; ) {
		i = (low + max) / 2;
		item = file->fast_seek->pdata[i];

		if (pos < item->out)
			max = i;
		else if (pos > item->out) {
			smallest = item;
			low = i + 1;
		} else {
			return item;
		}
	}
	return smallest;
}

static void
fast_seek_header(FILE_T file, gint64 in_pos, gint64 out_pos, int compression)
{
	struct fast_seek_point *item = NULL;

	if (file->fast_seek->len != 0)
		item = file->fast_seek->pdata[file->fast_seek->len - 1];

	if (!item || item->out < out_pos) {
		struct fast_seek_point *val = g_malloc(sizeof(struct fast_seek_point));
		val->in = in_pos;
		val->out = out_pos;
		val->compression = compression;

		g_ptr_array_add(file->fast_seek, val);
	}
}

static void
fast_seek_reset(FILE_T state _U_)
{
#ifdef HAVE_LIBZ
	if (state->compression == ZLIB && state->fast_seek_cur) {
		struct zlib_cur_seek_point *cur = (struct zlib_cur_seek_point *) state->fast_seek_cur;

		cur->have = 0;
	}
#endif
}

#ifdef HAVE_LIBZ

/* Get next byte from input, or -1 if end or error.
 *
 * Note:
 *
 *	1) errors from raw_read(), and thus from fill_in_buffer(), are
 *	"sticky", and fill_in_buffer() won't do any reading if there's
 *	an error;
 *
 *	2) GZ_GETC() returns -1 on an EOF;
 *
 * so it's safe to make multiple GZ_GETC() calls and only check the
 * last one for an error. */
#define GZ_GETC() ((state->avail_in == 0 && fill_in_buffer(state) == -1) ? -1 : \
                (state->avail_in == 0 ? -1 : \
                 (state->avail_in--, *(state->next_in)++)))

/* Get a one-byte integer and return 0 on success and the value in *ret.
   Otherwise -1 is returned, state->err is set, and *ret is not modified. */
static int
gz_next1(FILE_T state, guint8 *ret)
{
	int ch;

	ch = GZ_GETC();
	if (ch == -1) {
		if (state->err == 0) {
			/* EOF */
			state->err = WTAP_ERR_SHORT_READ;
			state->err_info = NULL;
		}
		return -1;
	}
	*ret = ch;
	return 0;
}

/* Get a two-byte little-endian integer and return 0 on success and the value
   in *ret.  Otherwise -1 is returned, state->err is set, and *ret is not
   modified. */
static int
gz_next2(FILE_T state, guint16 *ret)
{
	guint16 val;
	int ch;

	val = GZ_GETC();
	ch = GZ_GETC();
	if (ch == -1) {
		if (state->err == 0) {
			/* EOF */
			state->err = WTAP_ERR_SHORT_READ;
			state->err_info = NULL;
		}
		return -1;
	}
	val += (guint16)ch << 8;
	*ret = val;
	return 0;
}

/* Get a four-byte little-endian integer and return 0 on success and the value
   in *ret.  Otherwise -1 is returned, state->err is set, and *ret is not
   modified. */
static int
gz_next4(FILE_T state, guint32 *ret)
{
	guint32 val;
	int ch;

	val = GZ_GETC();
	val += (unsigned)GZ_GETC() << 8;
	val += (guint32)GZ_GETC() << 16;
	ch = GZ_GETC();
	if (ch == -1) {
		if (state->err == 0) {
			/* EOF */
			state->err = WTAP_ERR_SHORT_READ;
			state->err_info = NULL;
		}
		return -1;
	}
	val += (guint32)ch << 24;
	*ret = val;
	return 0;
}

/* Skip the specified number of bytes and return 0 on success.  Otherwise -1
   is returned. */
static int
gz_skipn(FILE_T state, size_t n)
{
	while (n != 0) {
		if (GZ_GETC() == -1) {
			if (state->err == 0) {
				/* EOF */
				state->err = WTAP_ERR_SHORT_READ;
				state->err_info = NULL;
			}
			return -1;
		}
		n--;
	}
	return 0;
}

/* Skip a null-terminated string and return 0 on success.  Otherwise -1
   is returned. */
static int
gz_skipzstr(FILE_T state)
{
	int ch;

	/* It's null-terminated, so scan until we read a byte with
	   the value 0 or get an error. */
	while ((ch = GZ_GETC()) > 0)
		;
	if (ch == -1) {
		if (state->err == 0) {
			/* EOF */
			state->err = WTAP_ERR_SHORT_READ;
			state->err_info = NULL;
		}
		return -1;
	}
	return 0;
}

static void
zlib_fast_seek_add(FILE_T file, struct zlib_cur_seek_point *point, int bits, gint64 in_pos, gint64 out_pos)
{
	/* it's for sure after gzip header, so file->fast_seek->len != 0 */
	struct fast_seek_point *item = file->fast_seek->pdata[file->fast_seek->len - 1];;

#ifndef HAVE_INFLATEPRIME
	if (bits)
		return;
#endif

	/* Glib has got Balanced Binary Trees (GTree) but I couldn't find a way to do quick search for nearest (and smaller) value to seek (It's what fast_seek_find() do)
	 *      Inserting value in middle of sorted array is expensive, so we want to add only in the end.
	 *      It's not big deal, cause first-read don't usually invoke seeking
	 */
	if (item->out + SPAN < out_pos) {
		struct fast_seek_point *val = g_malloc(sizeof(struct fast_seek_point));
		val->in = in_pos;
		val->out = out_pos;
		val->compression = ZLIB;
#ifdef HAVE_INFLATEPRIME
		val->data.zlib.bits = bits;
#endif
		if (point->pos != 0) {
			unsigned int left = ZLIB_WINSIZE - point->pos;

			memcpy(val->data.zlib.window, point->window + point->pos, left);
			memcpy(val->data.zlib.window + left, point->window, point->pos);
		} else
			memcpy(val->data.zlib.window, point->window, ZLIB_WINSIZE);

		val->data.zlib.adler = file->strm.adler;
		val->data.zlib.total_out = file->strm.total_out;
		g_ptr_array_add(file->fast_seek, val);
	}
}

static void /* gz_decomp */
zlib_read(FILE_T state, unsigned char *buf, unsigned int count)
{
	int ret = 0;	/* XXX */
	guint32 crc, len;
	z_streamp strm = &(state->strm);

	unsigned char *buf2 = buf;
	unsigned int count2 = count;

	strm->avail_out = count;
	strm->next_out = buf;

	/* fill output buffer up to end of deflate stream or error */
	do {
		/* get more input for inflate() */
		if (state->avail_in == 0 && fill_in_buffer(state) == -1)
			break;
		if (state->avail_in == 0) {
			/* EOF */
			state->err = WTAP_ERR_SHORT_READ;
			state->err_info = NULL;
			break;
		}

		strm->avail_in = state->avail_in;
		strm->next_in = state->next_in;
		/* decompress and handle errors */
		/* ret = inflate(strm, Z_NO_FLUSH); */
		ret = inflate(strm, Z_BLOCK);
		state->avail_in = strm->avail_in;
		state->next_in = strm->next_in;
		if (ret == Z_STREAM_ERROR) {
			state->err = WTAP_ERR_DECOMPRESS;
			state->err_info = strm->msg;
			break;
		}
		if (ret == Z_NEED_DICT) {
			state->err = WTAP_ERR_DECOMPRESS;
			state->err_info = "preset dictionary needed";
			break;
		}
		if (ret == Z_MEM_ERROR) {
			/* This means "not enough memory". */
			state->err = ENOMEM;
			state->err_info = NULL;
			break;
		}
		if (ret == Z_DATA_ERROR) {              /* deflate stream invalid */
			state->err = WTAP_ERR_DECOMPRESS;
			state->err_info = strm->msg;
			break;
		}
		/*
		 * XXX - Z_BUF_ERROR?
		 */

		strm->adler = crc32(strm->adler, buf2, count2 - strm->avail_out);
		if (state->fast_seek_cur) {
			struct zlib_cur_seek_point *cur = (struct zlib_cur_seek_point *) state->fast_seek_cur;
			unsigned int ready = count2 - strm->avail_out;

			if (ready < ZLIB_WINSIZE) {
				unsigned left = ZLIB_WINSIZE - cur->pos;

				if (ready >= left) {
					memcpy(cur->window + cur->pos, buf2, left);
					if (ready != left)
						memcpy(cur->window, buf2 + left, ready - left);

					cur->pos = ready - left;
					cur->have += ready;
				} else {
					memcpy(cur->window + cur->pos, buf2, ready);
					cur->pos += ready;
					cur->have += ready;
				}

				if (cur->have >= ZLIB_WINSIZE)
					cur->have = ZLIB_WINSIZE;

			} else {
				memcpy(cur->window, buf2 + (ready - ZLIB_WINSIZE), ZLIB_WINSIZE);
				cur->pos = 0;
				cur->have = ZLIB_WINSIZE;
			}

			if (cur->have >= ZLIB_WINSIZE && ret != Z_STREAM_END && (strm->data_type & 128) && !(strm->data_type & 64))
				zlib_fast_seek_add(state, cur, (strm->data_type & 7), state->raw_pos - strm->avail_in, state->pos + (count - strm->avail_out));
		}
		buf2 = (buf2 + count2 - strm->avail_out);
		count2 = strm->avail_out;

	} while (strm->avail_out && ret != Z_STREAM_END);

	/* update available output and crc check value */
	state->next = buf;
	state->have = count - strm->avail_out;

	/* Check gzip trailer if at end of deflate stream.
	   We don't fail immediately here, we just set an error
	   indication, so that we try to process what data we
	   got before the error.  The next attempt to read
	   something past that data will get the error. */
	if (ret == Z_STREAM_END) {
		if (gz_next4(state, &crc) != -1 &&
		    gz_next4(state, &len) != -1) {
			/*
			 * XXX - compressed Windows Sniffer don't
			 * all have the same CRC value; is it just
			 * random crap, or are they running the
			 * CRC on a different set of data than
			 * you're supposed to (e.g., not CRCing
			 * some of the data), or something such
			 * as that?
			 */
			if (crc != strm->adler && !state->dont_check_crc) {
				state->err = WTAP_ERR_DECOMPRESS;
				state->err_info = "bad CRC";
			} else if (len != (strm->total_out & 0xffffffffL)) {
				state->err = WTAP_ERR_DECOMPRESS;
				state->err_info = "length field wrong";
			}
		}
		state->compression = UNKNOWN;      /* ready for next stream, once have is 0 */
		g_free(state->fast_seek_cur);
		state->fast_seek_cur = NULL;
	}
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
			guint8 cm;
			guint8 flags;
			guint16 len;
			guint16 hcrc;

			/* we have a gzip header, woo hoo! */
			state->avail_in--;
			state->next_in++;

			/* read rest of header */

			/* compression method (CM) */
			if (gz_next1(state, &cm) == -1)
				return -1;
			if (cm != 8) {
				state->err = WTAP_ERR_DECOMPRESS;
				state->err_info = "unknown compression method";
				return -1;
			}

			/* flags (FLG) */
			if (gz_next1(state, &flags) == -1)
				return -1;
			if (flags & 0xe0) {     /* reserved flag bits */
				state->err = WTAP_ERR_DECOMPRESS;
				state->err_info = "reserved flag bits set";
				return -1;
			}

			/* modification time (MTIME) */
			if (gz_skipn(state, 4) == -1)
				return -1;

			/* extra flags (XFL) */
			if (gz_skipn(state, 1) == -1)
				return -1;

			/* operating system (OS) */
			if (gz_skipn(state, 1) == -1)
				return -1;

			if (flags & 4) {
				/* extra field - get XLEN */
				if (gz_next2(state, &len) == -1)
					return -1;

				/* skip the extra field */
				if (gz_skipn(state, len) == -1)
					return -1;
			}
			if (flags & 8) {
				/* file name */
				if (gz_skipzstr(state) == -1)
					return -1;
			}
			if (flags & 16) {
				/* comment */
				if (gz_skipzstr(state) == -1)
					return -1;
			}
			if (flags & 2) {
				/* header crc */
				if (gz_next2(state, &hcrc) == -1)
					return -1;
				/* XXX - check the CRC? */
			}

			/* set up for decompression */
			inflateReset(&(state->strm));
			state->strm.adler = crc32(0L, Z_NULL, 0);
			state->compression = ZLIB;

			if (state->fast_seek) {
				struct zlib_cur_seek_point *cur = g_malloc(sizeof(struct zlib_cur_seek_point));

				cur->pos = cur->have = 0;
				g_free(state->fast_seek_cur);
				state->fast_seek_cur = cur;
				fast_seek_header(state, state->raw_pos - state->avail_in, state->pos, GZIP_AFTER_HEADER);
			}
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
	if (state->fast_seek)
		fast_seek_header(state, state->raw_pos - state->avail_in - state->have, state->pos, UNCOMPRESSED);

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
		zlib_read(state, state->out, state->size << 1);
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
		if (state->have) {
			/* We have stuff in the output buffer; skip over
			   it. */
			n = (gint64)state->have > len ? (unsigned)len : state->have;
			state->have -= n;
			state->next += n;
			state->pos += n;
			len -= n;
		} else if (state->err) {
			/* We have nothing in the output buffer, and
			   we have an error that may not have been
			   reported yet; that means we can't generate
			   any more data into the output buffer, so
			   return an error indication. */
			return -1;
		} else if (state->eof && state->avail_in == 0) {
			/* We have nothing in the output buffer, and
			   we're at the end of the input; just return. */
			break;
		} else {
			/* We have nothing in the output buffer, and
			   we can generate more data; get more output,
			   looking for header if required. */
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
	state->err_info = NULL;
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

	/* allocate FILE_T structure to return */
	state = g_try_malloc(sizeof *state);
	if (state == NULL)
		return NULL;

	state->fast_seek_cur = NULL;
	state->fast_seek = NULL;

	/* open the file with the appropriate mode (or just use fd) */
	state->fd = fd;

	/* save the current position for rewinding (only if reading) */
	state->start = ws_lseek64(state->fd, 0, SEEK_CUR);
	if (state->start == -1) state->start = 0;
	state->raw_pos = state->start;

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

	/* for now, assume we should check the crc */
	state->dont_check_crc = 0;
#endif
	/* return stream */
	return state;
}

FILE_T
file_open(const char *path)
{
	int fd;
	FILE_T ft;
#ifdef HAVE_LIBZ
	const char *suffixp;
#endif

	/* open file and do correct filename conversions.

	   XXX - do we need O_LARGEFILE?  On UN*X, if we need to do
	   something special to get large file support, the configure
	   script should have set us up with the appropriate #defines,
	   so we should be getting a large-file-enabled file descriptor
	   here.  Pre-Large File Summit UN*Xes, and possibly even some
	   post-LFS UN*Xes, might require O_LARGEFILE here, though.
	   If so, we should probably handle that in ws_open(). */
	if ((fd = ws_open(path, O_RDONLY|O_BINARY, 0000)) == -1)
		return NULL;

	/* open file handle */
	ft = filed_open(fd);
	if (ft == NULL) {
		ws_close(fd);
		return NULL;
	}

#ifdef HAVE_LIBZ
	/*
	 * If this file's name ends in ".caz", it's probably a compressed
	 * Windows Sniffer file.  The compression is gzip, but they don't
	 * bother filling in the CRC; we set a flag to ignore CRC errors.
	 */
	suffixp = strrchr(path, '.');
	if (suffixp != NULL) {
		if (g_ascii_strcasecmp(suffixp, ".caz") == 0)
			ft->dont_check_crc = 1;
	}
#endif

	return ft;
}

void 
file_set_random_access(FILE_T stream, gboolean random _U_, GPtrArray *seek)
{
	stream->fast_seek = seek;
}

gint64
file_seek(FILE_T file, gint64 offset, int whence, int *err)
{
	struct fast_seek_point *here;
	unsigned n;

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

	/* XXX, profile */
	if ((here = fast_seek_find(file, file->pos + offset)) && (offset < 0 || offset > SPAN || here->compression == UNCOMPRESSED)) {
		gint64 off, off2;

#ifdef HAVE_LIBZ
		if (here->compression == ZLIB) {
#ifdef HAVE_INFLATEPRIME
			off = here->in - (here->data.zlib.bits ? 1 : 0);
#else
			off = here->in;
#endif
			off2 = here->out;
		} else if (here->compression == GZIP_AFTER_HEADER) {
			off = here->in;
			off2 = here->out;
		} else
#endif
		{
			off2 = (file->pos + offset);
			off = here->in + (off2 - here->out);
		}

		if (ws_lseek64(file->fd, off, SEEK_SET) == -1) {
			*err = errno;
			return -1;
		}
		fast_seek_reset(file);

		file->raw_pos = off;
		file->have = 0;
		file->eof = 0;
		file->seek = 0;
		file->err = 0;
		file->err_info = NULL;
		file->avail_in = 0;

#ifdef HAVE_LIBZ
		if (here->compression == ZLIB) {
			z_stream *strm = &file->strm;

			inflateReset(strm);
			strm->adler = here->data.zlib.adler;
			strm->total_out = here->data.zlib.total_out;
#ifdef HAVE_INFLATEPRIME
			if (here->data.zlib.bits) {
				FILE_T state = file;
				int ret = GZ_GETC();

				if (ret == -1) {
					if (state->err == 0) {
						/* EOF */
						*err = WTAP_ERR_SHORT_READ;
					} else
						*err = state->err;
					return -1;
				}
				(void)inflatePrime(strm, here->data.zlib.bits, ret >> (8 - here->data.zlib.bits));
			}
#endif
			(void)inflateSetDictionary(strm, here->data.zlib.window, ZLIB_WINSIZE);
			file->compression = ZLIB;
		} else if (here->compression == GZIP_AFTER_HEADER) {
			z_stream *strm = &file->strm;

			inflateReset(strm);
			strm->adler = crc32(0L, Z_NULL, 0);
			file->compression = ZLIB;
		} else
#endif
			file->compression = here->compression;

		offset = (file->pos + offset) - off2;
		file->pos = off2;
		/* g_print("OK! %ld\n", offset); */

		if (offset) {
			file->seek = 1;
			file->skip = offset;
		}
		return file->pos + offset;
	}

	/* if within raw area while reading, just go there */
	if (file->compression == UNCOMPRESSED && file->pos + offset >= file->raw) {
		if (ws_lseek64(file->fd, offset - file->have, SEEK_CUR) == -1) {
			*err = errno;
			return -1;
		}
		file->raw_pos += (offset - file->have);
		file->have = 0;
		file->eof = 0;
		file->seek = 0;
		file->err = 0;
		file->err_info = NULL;
		file->avail_in = 0;
		file->pos += offset;
		return file->pos;
	}

	/* calculate skip amount, rewinding if needed for back seek when reading */
	if (offset < 0) {
		offset += file->pos;
		if (offset < 0) {                    /* before start of file! */
			*err = EINVAL;
			return -1;
		}
		/* rewind, then skip to offset */

		/* back up and start over */
		if (ws_lseek64(file->fd, file->start, SEEK_SET) == -1) {
			*err = errno;
			return -1;
		}
		fast_seek_reset(file);
		file->raw_pos = file->start;
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

gint64
file_tell_raw(FILE_T stream)
{
	return stream->raw_pos;
}

int
file_fstat(FILE_T stream, ws_statb64 *statb, int *err)
{
	if (ws_fstat64(stream->fd, statb) == -1) {
		if (err != NULL)
			*err = errno;
		return -1;
	}
	return 0;
}

int 
file_read(void *buf, unsigned int len, FILE_T file)
{
	unsigned got, n;

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
		if (file->have) {
			/* We have stuff in the output buffer; copy
			   what we have. */
			n = file->have > len ? len : file->have;
			memcpy(buf, file->next, n);
			file->next += n;
			file->have -= n;
		} else if (file->err) {
			/* We have nothing in the output buffer, and
			   we have an error that may not have been
			   reported yet; that means we can't generate
			   any more data into the output buffer, so
			   return an error indication. */
			return -1;
		} else if (file->eof && file->avail_in == 0) {
			/* We have nothing in the output buffer, and
			   we're at the end of the input; just return
			   with what we've gotten so far. */
			break;
		} else {
			/* We have nothing in the output buffer, and
			   we can generate more data; get more output,
			   looking for header if required, and
			   keep looping to process the new stuff
			   in the output buffer. */
			if (fill_out_buffer(file) == -1)
				return -1;
			continue;       /* no progress yet -- go back to memcpy() above */
		}
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
			/* We have nothing in the output buffer. */
			if (file->err) {
				/* We have an error that may not have
				   been reported yet; that means we
				   can't generate any more data into
				   the output buffer, so return an
				   error indication. */
				return NULL;
			}
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
 * I/O stream.  Also returns an error string for some errors.
 */
int
file_error(FILE_T fh, gchar **err_info)
{
	if (fh->err != 0) {
		*err_info = (fh->err_info == NULL) ? NULL : g_strdup(fh->err_info);
		return fh->err;
	}
	return 0;
}

void
file_clearerr(FILE_T stream)
{
	/* clear error and end-of-file */
	stream->err = 0;
	stream->err_info = NULL;
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
	g_free(file->fast_seek_cur);
	file->err = 0;
	file->err_info = NULL;
	g_free(file);
	return ws_close(fd);
}

#ifdef HAVE_LIBZ
/* internal gzip file state data structure for writing */
struct wtap_writer {
    int fd;                 /* file descriptor */
    gint64 pos;             /* current position in uncompressed data */
    unsigned size;          /* buffer size, zero if not allocated yet */
    unsigned want;          /* requested buffer size, default is GZBUFSIZE */
    unsigned char *in;      /* input buffer */
    unsigned char *out;     /* output buffer (double-sized when reading) */
    unsigned char *next;    /* next output data to deliver or write */
    int level;              /* compression level */
    int strategy;           /* compression strategy */
    int err;                /* error code */
	/* zlib deflate stream */
    z_stream strm;          /* stream structure in-place (not a pointer) */
};

GZWFILE_T
gzwfile_open(const char *path)
{
    int fd;
    GZWFILE_T state;
    int save_errno;

    fd = ws_open(path, O_BINARY|O_WRONLY|O_CREAT|O_TRUNC, 0666);
    if (fd == -1)
        return NULL;
    state = gzwfile_fdopen(fd);
    if (state == NULL) {
        save_errno = errno;
        close(fd);
        errno = save_errno;
    }
    return state;
}

GZWFILE_T
gzwfile_fdopen(int fd)
{
    GZWFILE_T state;

    /* allocate wtap_writer structure to return */
    state = g_try_malloc(sizeof *state);
    if (state == NULL)
        return NULL;
    state->fd = fd;
    state->size = 0;            /* no buffers allocated yet */
    state->want = GZBUFSIZE;    /* requested buffer size */

    state->level = Z_DEFAULT_COMPRESSION;
    state->strategy = Z_DEFAULT_STRATEGY;

    /* initialize stream */
    state->err = Z_OK;              /* clear error */
    state->pos = 0;                 /* no uncompressed data yet */
    state->strm.avail_in = 0;       /* no input data yet */

    /* return stream */
    return state;
}

/* Initialize state for writing a gzip file.  Mark initialization by setting
   state->size to non-zero.  Return -1, and set state->err, on failure;
   return 0 on success. */
static int
gz_init(GZWFILE_T state)
{
    int ret;
    z_streamp strm = &(state->strm);

    /* allocate input and output buffers */
    state->in = g_try_malloc(state->want);
    state->out = g_try_malloc(state->want);
    if (state->in == NULL || state->out == NULL) {
        g_free(state->out);
        g_free(state->in);
        state->err = ENOMEM;
        return -1;
    }

    /* allocate deflate memory, set up for gzip compression */
    strm->zalloc = Z_NULL;
    strm->zfree = Z_NULL;
    strm->opaque = Z_NULL;
    ret = deflateInit2(strm, state->level, Z_DEFLATED,
                       15 + 16, 8, state->strategy);
    if (ret != Z_OK) {
        g_free(state->out);
        g_free(state->in);
        if (ret == Z_MEM_ERROR) {
        	/* This means "not enough memory". */
        	state->err = ENOMEM;
        } else {
        	/* This "shouldn't happen". */
        	state->err = WTAP_ERR_INTERNAL;
        }
        return -1;
    }

    /* mark state as initialized */
    state->size = state->want;

    /* initialize write buffer */
    strm->avail_out = state->size;
    strm->next_out = state->out;
    state->next = strm->next_out;
    return 0;
}

/* Compress whatever is at avail_in and next_in and write to the output file.
   Return -1, and set state->err, if there is an error writing to the output
   file; return 0 on success.
   flush is assumed to be a valid deflate() flush value.  If flush is Z_FINISH,
   then the deflate() state is reset to start a new gzip stream. */
static int
gz_comp(GZWFILE_T state, int flush)
{
    int ret, got;
    unsigned have;
    z_streamp strm = &(state->strm);

    /* allocate memory if this is the first time through */
    if (state->size == 0 && gz_init(state) == -1)
        return -1;

    /* run deflate() on provided input until it produces no more output */
    ret = Z_OK;
    do {
        /* write out current buffer contents if full, or if flushing, but if
           doing Z_FINISH then don't write until we get to Z_STREAM_END */
        if (strm->avail_out == 0 || (flush != Z_NO_FLUSH &&
            (flush != Z_FINISH || ret == Z_STREAM_END))) {
            have = (unsigned)(strm->next_out - state->next);
            if (have) {
		got = write(state->fd, state->next, have);
		if (got < 0) {
                    state->err = errno;
                    return -1;
                }
                if ((unsigned)got != have) {
                    state->err = WTAP_ERR_SHORT_WRITE;
                    return -1;
                }
            }
            if (strm->avail_out == 0) {
                strm->avail_out = state->size;
                strm->next_out = state->out;
            }
            state->next = strm->next_out;
        }

        /* compress */
        have = strm->avail_out;
        ret = deflate(strm, flush);
        if (ret == Z_STREAM_ERROR) {
            /* This "shouldn't happen". */
            state->err = WTAP_ERR_INTERNAL;
            return -1;
        }
        have -= strm->avail_out;
    } while (have);

    /* if that completed a deflate stream, allow another to start */
    if (flush == Z_FINISH)
        deflateReset(strm);

    /* all done, no errors */
    return 0;
}

/* Write out len bytes from buf.  Return 0, and set state->err, on
   failure or on an attempt to write 0 bytes (in which case state->err
   is Z_OK); return the number of bytes written on success. */
unsigned
gzwfile_write(GZWFILE_T state, const void *buf, unsigned len)
{
    unsigned put = len;
    unsigned n;
    z_streamp strm;

    strm = &(state->strm);

    /* check that there's no error */
    if (state->err != Z_OK)
        return 0;

    /* if len is zero, avoid unnecessary operations */
    if (len == 0)
        return 0;

    /* allocate memory if this is the first time through */
    if (state->size == 0 && gz_init(state) == -1)
        return 0;

    /* for small len, copy to input buffer, otherwise compress directly */
    if (len < state->size) {
        /* copy to input buffer, compress when full */
        do {
            if (strm->avail_in == 0)
                strm->next_in = state->in;
            n = state->size - strm->avail_in;
            if (n > len)
                n = len;
            memcpy(strm->next_in + strm->avail_in, buf, n);
            strm->avail_in += n;
            state->pos += n;
            buf = (char *)buf + n;
            len -= n;
            if (len && gz_comp(state, Z_NO_FLUSH) == -1)
                return 0;
        } while (len);
    }
    else {
        /* consume whatever's left in the input buffer */
        if (strm->avail_in && gz_comp(state, Z_NO_FLUSH) == -1)
            return 0;

        /* directly compress user buffer to file */
        strm->avail_in = len;
        strm->next_in = (voidp)buf;
        state->pos += len;
        if (gz_comp(state, Z_NO_FLUSH) == -1)
            return 0;
    }

    /* input was all buffered or compressed (put will fit in int) */
    return (int)put;
}

/* Flush out what we've written so far.  Returns -1, and sets state->err,
   on failure; returns 0 on success. */
int
gzwfile_flush(GZWFILE_T state)
{
    /* check that there's no error */
    if (state->err != Z_OK)
        return -1;

    /* compress remaining data with Z_SYNC_FLUSH */
    gz_comp(state, Z_SYNC_FLUSH);
    if (state->err != Z_OK)
        return -1;
    return 0;
}

/* Flush out all data written, and close the file.  Returns a Wiretap
   error on failure; returns 0 on success. */
int
gzwfile_close(GZWFILE_T state)
{
    int ret = 0;

    /* flush, free memory, and close file */
    if (gz_comp(state, Z_FINISH) == -1 && ret == 0)
        ret = state->err;
    (void)deflateEnd(&(state->strm));
    g_free(state->out);
    g_free(state->in);
    state->err = Z_OK;
    if (close(state->fd) == -1 && ret == 0)
        ret = errno;
    g_free(state);
    return ret;
}

int
gzwfile_geterr(GZWFILE_T state)
{
    return state->err;
}
#endif
