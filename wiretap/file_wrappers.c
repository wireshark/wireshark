/* file_wrappers.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* file_access interface based heavily on zlib gzread.c and gzlib.c from zlib
 * Copyright (C) 1995-2010 Jean-loup Gailly and Mark Adler
 * under licence:
 *
 * SPDX-License-Identifier: Zlib
 *
 */

#include "config.h"
#include "file_wrappers.h"

#include <assert.h>
#include <errno.h>
#include <string.h>
#include "wtap-int.h"

#include <wsutil/file_util.h>

#if defined(HAVE_ZLIB) && !defined(HAVE_ZLIBNG)
#define USE_ZLIB_OR_ZLIBNG
#define ZLIB_CONST
#define ZLIB_PREFIX(x) x
#include <zlib.h>
typedef z_stream zlib_stream;
#endif /* defined(HAVE_ZLIB) && !defined(HAVE_ZLIBNG) */

#ifdef HAVE_ZLIBNG
#define USE_ZLIB_OR_ZLIBNG
#define HAVE_INFLATEPRIME 1
#define ZLIB_PREFIX(x) zng_ ## x
#include <zlib-ng.h>
typedef zng_stream zlib_stream;
#endif /* HAVE_ZLIBNG */

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif /* HAVE_ZSTD */

#ifdef HAVE_LZ4
#include <lz4.h>

#if LZ4_VERSION_NUMBER >= 10703
#define USE_LZ4
#include <lz4frame.h>
#endif /* LZ4_VERSION_NUMBER >= 10703 */
#endif /* HAVE_LZ4 */

/*
 * List of compression types supported.
 */
static struct compression_type {
    wtap_compression_type  type;
    const char            *extension;
    const char            *description;
} compression_types[] = {
#ifdef USE_ZLIB_OR_ZLIBNG
    { WTAP_GZIP_COMPRESSED, "gz", "gzip compressed" },
#endif /* USE_ZLIB_OR_ZLIBNG */
#ifdef HAVE_ZSTD
    { WTAP_ZSTD_COMPRESSED, "zst", "zstd compressed" },
#endif /* HAVE_ZSTD */
#ifdef USE_LZ4
    { WTAP_LZ4_COMPRESSED, "lz4", "lz4 compressed" },
#endif /* USE_LZ4 */
    { WTAP_UNCOMPRESSED, NULL, NULL }
};

static wtap_compression_type file_get_compression_type(FILE_T stream);

wtap_compression_type
wtap_get_compression_type(wtap *wth)
{
	return file_get_compression_type((wth->fh == NULL) ? wth->random_fh : wth->fh);
}

const char *
wtap_compression_type_description(wtap_compression_type compression_type)
{
	for (struct compression_type *p = compression_types;
	    p->type != WTAP_UNCOMPRESSED; p++) {
		if (p->type == compression_type)
			return p->description;
	}
	return NULL;
}

const char *
wtap_compression_type_extension(wtap_compression_type compression_type)
{
	for (struct compression_type *p = compression_types;
	    p->type != WTAP_UNCOMPRESSED; p++) {
		if (p->type == compression_type)
			return p->extension;
	}
	return NULL;
}

GSList *
wtap_get_all_compression_type_extensions_list(void)
{
	GSList *extensions;

	extensions = NULL;	/* empty list, to start with */

	for (struct compression_type *p = compression_types;
	    p->type != WTAP_UNCOMPRESSED; p++)
		extensions = g_slist_prepend(extensions, (void *)p->extension);

	return extensions;
}

/* #define GZBUFSIZE 8192 */
#define GZBUFSIZE 4096

/* values for wtap_reader compression */
typedef enum {
    UNKNOWN,       /* unknown - look for a compression header */
    UNCOMPRESSED,  /* uncompressed - copy input directly */
    ZLIB,          /* decompress a zlib stream */
    GZIP_AFTER_HEADER,
    ZSTD,
    LZ4,
} compression_t;

/*
 * We limit the size of our input and output buffers to 2^30 bytes,
 * because:
 *
 *    1) on Windows with MSVC, the return value of _read() is int,
 *       so the biggest read you can do is INT_MAX, and the biggest
 *       power of 2 below that is 2^30;
 *
 *    2) the "avail_in" and "avail_out" values in a z_stream structure
 *       in zlib are uInts, and those are unsigned ints, and that
 *       imposes a limit on the buffer size when we're reading a
 *       gzipped file.
 *
 * Thus, we use unsigned for the buffer sizes, offsets, amount available
 * from the buffer, etc.
 *
 * If we want an even bigger buffer for uncompressed data, or for
 * some other form of compression, then the unsigned-sized values should
 * be in structure values used only for reading gzipped files, and
 * other values should be used for uncompressed data or data
 * compressed using other algorithms (e.g., in a union).
 */
#define MAX_READ_BUF_SIZE	(1U << 30)

struct wtap_reader_buf {
    uint8_t *buf;  /* buffer */
    uint8_t *next; /* next byte to deliver from buffer */
    unsigned avail;  /* number of bytes available to deliver at next */
};

struct wtap_reader {
    int fd;                     /* file descriptor */
    int64_t raw_pos;            /* current position in file (just to not call lseek()) */
    int64_t pos;                /* current position in uncompressed data */
    unsigned size;              /* buffer size */

    struct wtap_reader_buf in;  /* input buffer, containing compressed data */
    struct wtap_reader_buf out; /* output buffer, containing uncompressed data */

    bool eof;                   /* true if end of input file reached */
    int64_t start;              /* where the gzip data started, for rewinding */
    int64_t raw;                /* where the raw data started, for seeking */
    compression_t compression;  /* type of compression, if any */
    compression_t last_compression; /* last known compression type */
    bool is_compressed;         /* false if completely uncompressed, true otherwise */

    /* seek request */
    int64_t skip;               /* amount to skip (already rewound if backwards) */
    bool seek_pending;          /* true if seek request pending */

    /* error information */
    int err;                    /* error code */
    const char *err_info;       /* additional error information string for some errors */

    /*
     * Decompression stream information.
     *
     * XXX - should this be a union?
     */
#ifdef USE_ZLIB_OR_ZLIBNG
    /* zlib inflate stream */
    zlib_stream strm;           /* stream structure in-place (not a pointer) */
    bool dont_check_crc;        /* true if we aren't supposed to check the CRC */
#endif /* USE_ZLIB_OR_ZLIBNG */
#ifdef HAVE_ZSTD
    ZSTD_DCtx *zstd_dctx;
#endif /* HAVE_ZSTD */
#ifdef USE_LZ4
    LZ4F_dctx *lz4_dctx;
#endif /* USE_LZ4 */

    /* fast seeking */
    GPtrArray *fast_seek;
    void *fast_seek_cur;
};

/* Current read offset within a buffer. */
static unsigned
offset_in_buffer(struct wtap_reader_buf *buf)
{
    /* buf->next points to the next byte to read, and buf->buf points
       to the first byte in the buffer, so the difference between them
       is the offset.

       This will fit in an unsigned int, because it can't be bigger
       than the size of the buffer, which is an unsigned int. */
    return (unsigned)(buf->next - buf->buf);
}

/* Number of bytes of data that are in a buffer. */
static unsigned
bytes_in_buffer(struct wtap_reader_buf *buf)
{
    /* buf->next + buf->avail points just past the last byte of data in
       the buffer.
       Thus, (buf->next + buf->avail) - buf->buf is the number of bytes
       of data in the buffer.

       This will fit in an unsigned, because it can't be bigger
       than the size of the buffer, which is a unsigned. */
    return (unsigned)((buf->next + buf->avail) - buf->buf);
}

/* Reset a buffer, discarding all data in the buffer, so we read into
   it starting at the beginning. */
static void
buf_reset(struct wtap_reader_buf *buf)
{
    buf->next = buf->buf;
    buf->avail = 0;
}

static int
buf_read(FILE_T state, struct wtap_reader_buf *buf)
{
    unsigned space_left, to_read;
    unsigned char *read_ptr;
    ssize_t ret;

    /* How much space is left at the end of the buffer?
       XXX - the output buffer actually has state->size * 2 bytes. */
    space_left = state->size - bytes_in_buffer(buf);
    if (space_left == 0) {
        /* There's no space left, so we start fresh at the beginning
           of the buffer. */
        buf_reset(buf);

        read_ptr = buf->buf;
        to_read = state->size;
    } else {
        /* There's some space left; try to read as much data as we
           can into that space.  We may get less than that if we're
           reading from a pipe or if we're near the end of the file. */
        read_ptr = buf->next + buf->avail;
        to_read = space_left;
    }

    ret = ws_read(state->fd, read_ptr, to_read);
    if (ret < 0) {
        state->err = errno;
        state->err_info = NULL;
        return -1;
    }
    if (ret == 0)
        state->eof = true;
    state->raw_pos += ret;
    buf->avail += (unsigned)ret;
    return 0;
}

static int /* gz_avail */
fill_in_buffer(FILE_T state)
{
    if (state->err != 0)
        return -1;
    if (!state->eof) {
        if (buf_read(state, &state->in) < 0)
            return -1;
    }
    return 0;
}

#define ZLIB_WINSIZE 32768

struct fast_seek_point {
    int64_t out;         /* corresponding offset in uncompressed data */
    int64_t in;          /* offset in input file of first full byte */

    compression_t compression;
    union {
        struct {
#ifdef HAVE_INFLATEPRIME
            int bits;   /* number of bits (1-7) from byte at in - 1, or 0 */
#endif /* HAVE_INFLATEPRIME */
            unsigned char window[ZLIB_WINSIZE]; /* preceding 32K of uncompressed data */

            /* be gentle with Z_STREAM_END, 8 bytes more... Another solution would be to comment checks out */
            uint32_t adler;
            uint32_t total_out;
        } zlib;
    } data;
};

struct zlib_cur_seek_point {
    unsigned char window[ZLIB_WINSIZE]; /* preceding 32K of uncompressed data */
    unsigned int pos;
    unsigned int have;
};

#define SPAN INT64_C(1048576)
static struct fast_seek_point *
fast_seek_find(FILE_T file, int64_t pos)
{
    struct fast_seek_point *smallest = NULL;
    struct fast_seek_point *item;
    unsigned low, i, max;

    if (!file->fast_seek)
        return NULL;

    for (low = 0, max = file->fast_seek->len; low < max; ) {
        i = (low + max) / 2;
        item = (struct fast_seek_point *)file->fast_seek->pdata[i];

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
fast_seek_header(FILE_T file, int64_t in_pos, int64_t out_pos,
                 compression_t compression)
{
    struct fast_seek_point *item = NULL;

    if (file->fast_seek->len != 0)
        item = (struct fast_seek_point *)file->fast_seek->pdata[file->fast_seek->len - 1];

    if (!item || item->out < out_pos) {
        struct fast_seek_point *val = g_new(struct fast_seek_point,1);
        val->in = in_pos;
        val->out = out_pos;
        val->compression = compression;

        g_ptr_array_add(file->fast_seek, val);
    }
}

static void
fast_seek_reset(
#ifdef HAVE_ZLIB
    FILE_T state)
#else /* HAVE_ZLIB */
    FILE_T state _U_)
#endif /* HAVE_ZLIB */
{
#ifdef HAVE_ZLIB
    if (state->compression == ZLIB && state->fast_seek_cur != NULL) {
        struct zlib_cur_seek_point *cur = (struct zlib_cur_seek_point *) state->fast_seek_cur;

        cur->have = 0;
    }
#endif /* HAVE_ZLIB */
}

static bool
uncompressed_fill_out_buffer(FILE_T state)
{
    if (buf_read(state, &state->out) < 0)
        return false;
    return true;
}

/*
 * Gzipped files, using compression from zlib or zlib-ng.
 *
 * https://tools.ietf.org/html/rfc1952 (RFC 1952)
 */
#ifdef USE_ZLIB_OR_ZLIBNG

/* Get next byte from input, or -1 if end or error.
 *
 * Note:
 *
 *      1) errors from buf_read(), and thus from fill_in_buffer(), are
 *      "sticky", and fill_in_buffer() won't do any reading if there's
 *      an error;
 *
 *      2) GZ_GETC() returns -1 on an EOF;
 *
 * so it's safe to make multiple GZ_GETC() calls and only check the
 * last one for an error. */
#define GZ_GETC() ((state->in.avail == 0 && fill_in_buffer(state) == -1) ? -1 : \
                   (state->in.avail == 0 ? -1 :                         \
                    (state->in.avail--, *(state->in.next)++)))

/* Get a one-byte integer and return 0 on success and the value in *ret.
   Otherwise -1 is returned, state->err is set, and *ret is not modified. */
static int
gz_next1(FILE_T state, uint8_t *ret)
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
gz_next2(FILE_T state, uint16_t *ret)
{
    uint16_t val;
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
    val += (uint16_t)ch << 8;
    *ret = val;
    return 0;
}

/* Get a four-byte little-endian integer and return 0 on success and the value
   in *ret.  Otherwise -1 is returned, state->err is set, and *ret is not
   modified. */
static int
gz_next4(FILE_T state, uint32_t *ret)
{
    uint32_t val;
    int ch;

    val = GZ_GETC();
    val += (unsigned)GZ_GETC() << 8;
    val += (uint32_t)GZ_GETC() << 16;
    ch = GZ_GETC();
    if (ch == -1) {
        if (state->err == 0) {
            /* EOF */
            state->err = WTAP_ERR_SHORT_READ;
            state->err_info = NULL;
        }
        return -1;
    }
    val += (uint32_t)ch << 24;
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
zlib_fast_seek_add(FILE_T file, struct zlib_cur_seek_point *point, int bits, int64_t in_pos, int64_t out_pos)
{
    /* it's for sure after gzip header, so file->fast_seek->len != 0 */
    struct fast_seek_point *item = (struct fast_seek_point *)file->fast_seek->pdata[file->fast_seek->len - 1];

#ifndef HAVE_INFLATEPRIME
    if (bits)
        return;
#endif /* HAVE_INFLATEPRIME */

    /* Glib has got Balanced Binary Trees (GTree) but I couldn't find a way to do quick search for nearest (and smaller) value to seek (It's what fast_seek_find() do)
     *      Inserting value in middle of sorted array is expensive, so we want to add only in the end.
     *      It's not big deal, cause first-read don't usually invoke seeking
     */
    if (item->out + SPAN < out_pos) {
        struct fast_seek_point *val = g_new(struct fast_seek_point,1);
        val->in = in_pos;
        val->out = out_pos;
        val->compression = ZLIB;
#ifdef HAVE_INFLATEPRIME
        val->data.zlib.bits = bits;
#endif /* HAVE_INFLATEPRIME */
        if (point->pos != 0) {
            unsigned int left = ZLIB_WINSIZE - point->pos;

            memcpy(val->data.zlib.window, point->window + point->pos, left);
            memcpy(val->data.zlib.window + left, point->window, point->pos);
        } else
            memcpy(val->data.zlib.window, point->window, ZLIB_WINSIZE);

        /*
         * XXX - strm.adler is a uLong in at least some versions
         * of zlib, and uLong is an unsigned long in at least
         * some of those versions, which means it's 64-bit
         * on LP64 platforms, even though the checksum is
         * 32-bit.  We assume the actual Adler checksum
         * is in the lower 32 bits of strm.adler; as the
         * checksum in the file is only 32 bits, we save only
         * those lower 32 bits, and cast away any additional
         * bits to squelch warnings.
         *
         * The same applies to strm.total_out.
         */
        val->data.zlib.adler = (uint32_t) file->strm.adler;
        val->data.zlib.total_out = (uint32_t) file->strm.total_out;
        g_ptr_array_add(file->fast_seek, val);
    }
}

/*
 * Based on what gz_decomp() in zlib does.
 */
static void
zlib_fill_out_buffer(FILE_T state)
{
    int ret = 0;        /* XXX */
    uint32_t crc, len;
#ifdef HAVE_ZLIBNG
    zng_streamp strm = &(state->strm);
#else /* HAVE_ZLIBNG */
    z_streamp strm = &(state->strm);
#endif /* HAVE_ZLIBNG */
    unsigned char *buf = state->out.buf;
    unsigned int count = state->size << 1;

    unsigned char *buf2 = buf;
    unsigned int count2 = count;

    strm->avail_out = count;
    strm->next_out = buf;

    /* fill output buffer up to end of deflate stream or error */
    do {
        /* get more input for inflate() */
        if (state->in.avail == 0 && fill_in_buffer(state) == -1)
            break;
        if (state->in.avail == 0) {
            /* EOF */
            state->err = WTAP_ERR_SHORT_READ;
            state->err_info = NULL;
            break;
        }

        strm->avail_in = state->in.avail;
        strm->next_in = state->in.next;
        /* decompress and handle errors */
#ifdef Z_BLOCK
        ret = ZLIB_PREFIX(inflate)(strm, Z_BLOCK);
#else /* Z_BLOCK */
        ret = ZLIB_PREFIX(inflate)(strm, Z_NO_FLUSH);
#endif /* Z_BLOCK */
        state->in.avail = strm->avail_in;
#ifdef z_const
DIAG_OFF(cast-qual)
        state->in.next = (unsigned char *)strm->next_in;
DIAG_ON(cast-qual)
#else /* z_const */
        state->in.next = strm->next_in;
#endif /* z_const */
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

        strm->adler = ZLIB_PREFIX(crc32)(strm->adler, buf2, count2 - strm->avail_out);
#ifdef Z_BLOCK
        if (state->fast_seek_cur != NULL) {
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
#endif /* Z_BLOCK */
        buf2 = (buf2 + count2 - strm->avail_out);
        count2 = strm->avail_out;

    } while (strm->avail_out && ret != Z_STREAM_END);

    /* update available output and crc check value */
    state->out.next = buf;
    state->out.avail = count - strm->avail_out;

    /* Check gzip trailer if at end of deflate stream.
       We don't fail immediately here, we just set an error
       indication, so that we try to process what data we
       got before the error.  The next attempt to read
       something past that data will get the error. */
    if (ret == Z_STREAM_END) {
        if (gz_next4(state, &crc) != -1 &&
            gz_next4(state, &len) != -1) {
            if (crc != strm->adler && !state->dont_check_crc) {
                state->err = WTAP_ERR_DECOMPRESS;
                state->err_info = "bad CRC";
            } else if (len != (strm->total_out & 0xffffffffUL)) {
                state->err = WTAP_ERR_DECOMPRESS;
                state->err_info = "length field wrong";
            }
        }
        state->last_compression = state->compression;
        state->compression = UNKNOWN;      /* ready for next stream, once have is 0 */
        g_free(state->fast_seek_cur);
        state->fast_seek_cur = NULL;
    }
}
#endif /* USE_ZLIB_OR_ZLIBNG */

/*
 * Check for a gzip header.
 *
 * Based on the gzip-specific stuff gz_head() from zlib does.
 */
static int
check_for_zlib_compression(FILE_T state)
{
    /*
     * Look for the gzip header.  The first two bytes are 31 and 139,
     * and if we find it, return success if we support gzip and an
     * error if we don't.
     */
    if (state->in.next[0] == 31) {
        state->in.avail--;
        state->in.next++;

        /* Make sure the byte after the first byte is present */
        if (state->in.avail == 0 && fill_in_buffer(state) == -1) {
            /* Read error. */
            return -1;
        }
        if (state->in.avail != 0) {
            if (state->in.next[0] == 139) {
                /*
                 * We have what looks like the ID1 and ID2 bytes of a gzip
                 * header.
                 * Continue processing the file.
                 *
                 * XXX - some capture file formats (I'M LOOKING AT YOU,
                 * ENDACE!) can have 31 in the first byte of the file
                 * and 139 in the second byte of the file.  For now, in
                 * those cases, you lose.
                 */
#ifdef USE_ZLIB_OR_ZLIBNG
                uint8_t cm;
                uint8_t flags;
                uint16_t len;
                uint16_t hcrc;

                state->in.avail--;
                state->in.next++;

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
                if (gz_next1(state, &flags) == -1) {
                    /* Read error. */
                    return -1;
                }
                if (flags & 0xe0) {     /* reserved flag bits */
                    state->err = WTAP_ERR_DECOMPRESS;
                    state->err_info = "reserved flag bits set";
                    return -1;
                }

                /* modification time (MTIME) */
                if (gz_skipn(state, 4) == -1) {
                    /* Read error. */
                    return -1;
                }

                /* extra flags (XFL) */
                if (gz_skipn(state, 1) == -1) {
                    /* Read error. */
                    return -1;
                }

                /* operating system (OS) */
                if (gz_skipn(state, 1) == -1) {
                    /* Read error. */
                    return -1;
                }

                if (flags & 4) {
                    /* extra field - get XLEN */
                    if (gz_next2(state, &len) == -1) {
                        /* Read error. */
                        return -1;
                    }

                    /* skip the extra field */
                    if (gz_skipn(state, len) == -1) {
                        /* Read error. */
                        return -1;
                    }
                }
                if (flags & 8) {
                    /* file name */
                    if (gz_skipzstr(state) == -1) {
                        /* Read error. */
                        return -1;
                    }
                }
                if (flags & 16) {
                    /* comment */
                    if (gz_skipzstr(state) == -1) {
                        /* Read error. */
                        return -1;
                    }
                }
                if (flags & 2) {
                    /* header crc */
                    if (gz_next2(state, &hcrc) == -1) {
                        /* Read error. */
                        return -1;
                    }
                    /* XXX - check the CRC? */
                }

                /* set up for decompression */
                ZLIB_PREFIX(inflateReset)(&(state->strm));
                state->strm.adler = ZLIB_PREFIX(crc32)(0L, Z_NULL, 0);
                state->compression = ZLIB;
                state->is_compressed = true;
#ifdef Z_BLOCK
                if (state->fast_seek) {
                    struct zlib_cur_seek_point *cur = g_new(struct zlib_cur_seek_point,1);

                    cur->pos = cur->have = 0;
                    g_free(state->fast_seek_cur);
                    state->fast_seek_cur = cur;
                    fast_seek_header(state, state->raw_pos - state->in.avail, state->pos, GZIP_AFTER_HEADER);
                }
#endif /* Z_BLOCK */
                return 1;
#else /* USE_ZLIB_OR_ZLIBNG */
                state->err = WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED;
                state->err_info = "reading gzip-compressed files isn't supported";
                return -1;
#endif /* USE_ZLIB_OR_ZLIBNG */
            }

            /*
             * Not a gzip file.  "Unget" the first character; either:
             *
             *    1) we read both of the first two bytes into the
             *    buffer with the first ws_read, so we can just back
             *    up by one byte;
             *
             *    2) we only read the first byte into the buffer with
             *    the first ws_read (e.g., because we're reading from
             *    a pipe and only the first byte had been written to
             *    the pipe at that point), and read the second byte
             *    into the buffer after the first byte in the
             *    fill_in_buffer call, so we now have two bytes in
             *    the buffer, and can just back up by one byte.
             */
            state->in.avail++;
            state->in.next--;
        }
    }
    return 0;
}


/*
 * Zstandard compression.
 *
 * https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md
 */
#ifdef HAVE_ZSTD
static bool
zstd_fill_out_buffer(FILE_T state)
{
    ws_assert(state->out.avail == 0);

    if (state->in.avail == 0 && fill_in_buffer(state) == -1)
        return false;

    ZSTD_outBuffer output = {state->out.buf, state->size << 1, 0};
    ZSTD_inBuffer input = {state->in.next, state->in.avail, 0};
    const size_t ret = ZSTD_decompressStream(state->zstd_dctx, &output, &input);
    if (ZSTD_isError(ret)) {
        state->err = WTAP_ERR_DECOMPRESS;
        state->err_info = ZSTD_getErrorName(ret);
        return false;
    }

    state->in.next = state->in.next + input.pos;
    state->in.avail -= (unsigned)input.pos;

    state->out.next = output.dst;
    state->out.avail = (unsigned)output.pos;

    if (ret == 0) {
        state->last_compression = state->compression;
        state->compression = UNKNOWN;
    }
    return true;
}
#endif /* HAVE_ZSTD */

/*
 * Check for a Zstandard header.
 */
static int
check_for_zstd_compression(FILE_T state)
{
    /*
     * Look for the Zstandard header, and, if we find it, return
     * success if we support Zstandard and an error if we don't.
     */
    if (state->in.avail >= 4
        && state->in.buf[0] == 0x28 && state->in.buf[1] == 0xb5
        && state->in.buf[2] == 0x2f && state->in.buf[3] == 0xfd) {
#ifdef HAVE_ZSTD
        const size_t ret = ZSTD_initDStream(state->zstd_dctx);
        if (ZSTD_isError(ret)) {
            state->err = WTAP_ERR_DECOMPRESS;
            state->err_info = ZSTD_getErrorName(ret);
            return -1;
        }

        state->compression = ZSTD;
        state->is_compressed = true;
        return 1;
#else /* HAVE_ZSTD */
        state->err = WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED;
        state->err_info = "reading zstd-compressed files isn't supported";
        return -1;
#endif /* HAVE_ZSTD */
    }
    return 0;
}

/*
 * lz4 compression.
 *
 * https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md
 */
#ifdef USE_LZ4
static bool
lz4_fill_out_buffer(FILE_T state)
{
    ws_assert(state->out.avail == 0);

    if (state->in.avail == 0 && fill_in_buffer(state) == -1)
        return false;

    size_t outBufSize = state->size << 1;
    size_t inBufSize = state->in.avail;
    const size_t ret = LZ4F_decompress(state->lz4_dctx, state->out.buf, &outBufSize, state->in.next, &inBufSize, NULL);
    if (LZ4F_isError(ret)) {
        state->err = WTAP_ERR_DECOMPRESS;
        state->err_info = LZ4F_getErrorName(ret);
        return false;
    }

    /*
     * We assume LZ4F_decompress() will not set inBufSize to a
     * value > state->in.avail.
     */
    state->in.next = state->in.next + inBufSize;
    state->in.avail -= (unsigned)inBufSize;

    state->out.next = state->out.buf;
    state->out.avail = (unsigned)outBufSize;

    if (ret == 0) {
        state->last_compression = state->compression;
        state->compression = UNKNOWN;
    }
    return true;
}
#endif /* USE_LZ4 */

/*
 * Check for an lz4 header.
 */
static int
check_for_lz4_compression(FILE_T state)
{
    /*
     * Look for the lz4 header, and, if we find it, return success
     * if we support lz4 and an error if we don't.
     */
    if (state->in.avail >= 4
        && state->in.buf[0] == 0x04 && state->in.buf[1] == 0x22
        && state->in.buf[2] == 0x4d && state->in.buf[3] == 0x18) {
#ifdef USE_LZ4
#if LZ4_VERSION_NUMBER >= 10800
        LZ4F_resetDecompressionContext(state->lz4_dctx);
#else /* LZ4_VERSION_NUMBER >= 10800 */
        LZ4F_freeDecompressionContext(state->lz4_dctx);
        const LZ4F_errorCode_t ret = LZ4F_createDecompressionContext(&state->lz4_dctx, LZ4F_VERSION);
        if (LZ4F_isError(ret)) {
            state->err = WTAP_ERR_INTERNAL;
            state->err_info = LZ4F_getErrorName(ret);
            return -1;
        }
#endif /* LZ4_VERSION_NUMBER >= 10800 */
        state->compression = LZ4;
        state->is_compressed = true;
        return 1;
#else /* USE_LZ4 */
        state->err = WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED;
        state->err_info = "reading lz4-compressed files isn't supported";
        return -1;
#endif /* USE_LZ4 */
    }
    return 0;
}

typedef int (*compression_type_test)(FILE_T);

static compression_type_test const compression_type_tests[] = {
    check_for_zlib_compression,
    check_for_zstd_compression,
    check_for_lz4_compression,
};

/*
 * Used when we haven't yet determined whether we have a compressed file
 * and, if we do, what sort of compressed file it is.
 *
 * Based on the non-gzip-specific stuff that gz_head() from zlib does.
 */
static int
check_for_compression(FILE_T state)
{
    unsigned already_read;

    /* get some data in the input buffer */
    if (state->in.avail == 0) {
        if (fill_in_buffer(state) == -1)
            return -1;
        if (state->in.avail == 0)
            return 0;
    }

    /*
     * Check for the compression types we support.
     */
    for (size_t i = 0; i < G_N_ELEMENTS(compression_type_tests); i++) {
        int ret;

        ret = compression_type_tests[i](state);
        if (ret == -1)
            return -1;    /* error */
        if (ret == 1)
            return 0;     /* found it */
    }

    /*
     * Some other compressed file formats we might want to support:
     *
     *   XZ format:
     *     https://tukaani.org/xz/
     *     https://github.com/tukaani-project/xz
     *     https://github.com/tukaani-project/xz/blob/master/doc/xz-file-format.txt
     *
     *    Bzip2 format:
     *      https://www.sourceware.org/bzip2/
     *      https://gitlab.com/bzip2/bzip2/
     *      https://github.com/dsnet/compress/blob/master/doc/bzip2-format.pdf
     *        (GitHub won't render it; download and open it)
     *
     *    Lzip format:
     *      https://www.nongnu.org/lzip/
     */

    /*
     * We didn't see anything that looks like a header for any type of
     * compressed file that we support, so just do uncompressed I/O.
     *
     * XXX - we don't need the fast seek stuff for that, as we don't
     * have any compression state to keep track of and don't need to
     * map between offsets in the uncompressed data and offsets in
     * the compressed file; what are we doing here?
     */
    if (state->fast_seek)
        fast_seek_header(state, state->raw_pos - state->in.avail - state->out.avail, state->pos, UNCOMPRESSED);

    /* doing raw i/o, save start of raw data for seeking, copy any leftover
       input to output -- this assumes that the output buffer is larger than
       the input buffer, which also assures space for gzungetc() */
    state->raw = state->pos;
    state->out.next = state->out.buf;
    /* not a compressed file -- copy everything we've read into the
       input buffer to the output buffer and fall to raw i/o */
    already_read = bytes_in_buffer(&state->in);
    if (already_read != 0) {
        memcpy(state->out.buf, state->in.buf, already_read);
        state->out.avail = already_read;

        /* Now discard everything in the input buffer */
        buf_reset(&state->in);
    }
    state->compression = UNCOMPRESSED;
    return 0;
}

/*
 * Based on what gz_make() in zlib does.
 */
static int
fill_out_buffer(FILE_T state)
{
    if (state->compression == UNKNOWN) {
        /*
         * We don't yet know whether the file is compressed,
         * so check for a compressed-file header.
         */
        if (check_for_compression(state) == -1)
            return -1;
        if (state->out.avail != 0)                /* got some data from check_for_compression() */
            return 0;
    }

    /*
     * We got no data from check_for_compression(), or we didn't call
     * it as we already know the compression type, so read some more
     * data.
     */
    switch (state->compression) {

    case UNCOMPRESSED:
        /* straight copy */
        if (!uncompressed_fill_out_buffer(state))
            return -1;
        break;

#ifdef USE_ZLIB_OR_ZLIBNG
    case ZLIB:
        /* zlib (gzip) decompress */
        zlib_fill_out_buffer(state);
        break;
#endif /* USE_ZLIB_OR_ZLIBNG */

#ifdef HAVE_ZSTD
    case ZSTD:
        /* zstd decompress */
        if (!zstd_fill_out_buffer(state))
            return -1;
        break;
#endif /* HAVE_ZSTD */

#ifdef USE_LZ4
    case LZ4:
        /* lz4 decompress */
        if (!lz4_fill_out_buffer(state))
            return -1;
        break;
#endif /* USE_LZ4 */

    default:
        /* Unknown compression type; keep reading */
        break;
    }
    return 0;
}

static int
gz_skip(FILE_T state, int64_t len)
{
    unsigned n;

    /* skip over len bytes or reach end-of-file, whichever comes first */
    while (len)
        if (state->out.avail != 0) {
            /* We have stuff in the output buffer; skip over
               it. */
            n = (int64_t)state->out.avail > len ? (unsigned)len : state->out.avail;
            state->out.avail -= n;
            state->out.next += n;
            state->pos += n;
            len -= n;
        } else if (state->err != 0) {
            /* We have nothing in the output buffer, and
               we have an error that may not have been
               reported yet; that means we can't generate
               any more data into the output buffer, so
               return an error indication. */
            return -1;
        } else if (state->eof && state->in.avail == 0) {
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
    buf_reset(&state->out);       /* no output data available */
    state->eof = false;           /* not at end of file */
    state->compression = UNKNOWN; /* look for compression header */

    state->seek_pending = false;  /* no seek request pending */
    state->err = 0;               /* clear error */
    state->err_info = NULL;
    state->pos = 0;               /* no uncompressed data yet */
    buf_reset(&state->in);        /* no input data yet */
}

FILE_T
file_fdopen(int fd)
{
    /*
     * XXX - we now check whether we have st_blksize in struct stat;
     * it's not available on all platforms.
     *
     * I'm not sure why we're testing _STATBUF_ST_BLKSIZE; it's not
     * set on all platforms that have st_blksize in struct stat.
     * (Not all platforms have st_blksize in struct stat.)
     *
     * Is there some reason *not* to make the buffer size the maximum
     * of GBUFSIZE and st_blksize?  On most UN*Xes, the standard I/O
     * library does I/O with st_blksize as the buffer size; on others,
     * and on Windows, it's a 4K buffer size.  If st_blksize is bigger
     * than GBUFSIZE (which is currently 4KB), that's probably a
     * hint that reading in st_blksize chunks is considered a good
     * idea (e.g., an 8K/1K Berkeley fast file system with st_blksize
     * being 8K, or APFS, where st_blksize is big on at least some
     * versions of macOS).
     */
#ifdef _STATBUF_ST_BLKSIZE
    ws_statb64 st;
#endif /* _STATBUF_ST_BLKSIZE */
#ifdef HAVE_ZSTD
    size_t zstd_buf_size;
#endif /* HAVE_ZSTD */
    unsigned want = GZBUFSIZE;
    FILE_T state;
#ifdef USE_LZ4
    size_t ret;
#endif /* USE_LZ4 */

    if (fd == -1)
        return NULL;

    /* allocate FILE_T structure to return */
    state = (FILE_T)g_try_malloc0(sizeof *state);
    if (state == NULL)
        return NULL;

    state->fast_seek_cur = NULL;
    state->fast_seek = NULL;

    /* open the file with the appropriate mode (or just use fd) */
    state->fd = fd;

    /* we don't yet know whether it's compressed */
    state->is_compressed = false;
    state->last_compression = UNKNOWN;

    /* save the current position for rewinding (only if reading) */
    state->start = ws_lseek64(state->fd, 0, SEEK_CUR);
    if (state->start == -1) state->start = 0;
    state->raw_pos = state->start;

    /* initialize stream */
    gz_reset(state);

#ifdef _STATBUF_ST_BLKSIZE
    /*
     * See what I/O size the file system recommends using, and if
     * it's bigger than what we're using and isn't too big, use
     * it.
     */
    if (ws_fstat64(fd, &st) >= 0) {
        /*
         * Yes, st_blksize can be bigger than an int; apparently,
         * it's a long on LP64 Linux, for example.
         *
         * If the value is too big to fit into a unsigned,
         * just use the maximum read buffer size.
         *
         * On top of that, the Single UNIX Speification says that
         * st_blksize is of type blksize_t, which is a *signed*
         * integer type, and, at minimum, macOS 11.6 and Linux 5.14.11's
         * include/uapi/asm-generic/stat.h define it as such.
         *
         * However, other OSes might make it unsigned, and older versions
         * of OSes that currently make it signed might make it unsigned,
         * so we try to avoid warnings from that.
         *
         * We cast MAX_READ_BUF_SIZE to long in order to avoid the
         * warning, although it might introduce warnings on platforms
         * where st_blocksize is unsigned; we'll deal with that if
         * it ever shows up as an issue.
         *
         * MAX_READ_BUF_SIZE is < the largest *signed* 32-bt integer,
         * so casting it to long won't turn it into a negative number.
         * (We only support 32-bit and 64-bit 2's-complement platforms.)
         */
        if (st.st_blksize <= (long)MAX_READ_BUF_SIZE)
            want = (unsigned)st.st_blksize;
        else
            want = MAX_READ_BUF_SIZE;
        /* XXX, verify result? */
    }
#endif /* _STATBUF_ST_BLKSIZE */
#ifdef HAVE_ZSTD
    /* we should have separate input and output buf sizes */
    zstd_buf_size = ZSTD_DStreamInSize();
    if (zstd_buf_size > want) {
        if (zstd_buf_size <= MAX_READ_BUF_SIZE)
            want = (unsigned)zstd_buf_size;
        else
            want = MAX_READ_BUF_SIZE;
    }
    zstd_buf_size = ZSTD_DStreamOutSize();
    if (zstd_buf_size > want) {
        if (zstd_buf_size <= MAX_READ_BUF_SIZE)
            want = (unsigned)zstd_buf_size;
        else
            want = MAX_READ_BUF_SIZE;
    }
#endif /* HAVE_ZSTD */
    /* allocate buffers */
    state->in.buf = (unsigned char *)g_try_malloc(want);
    state->in.next = state->in.buf;
    state->in.avail = 0;
    state->out.buf = (unsigned char *)g_try_malloc(want << 1);
    state->out.next = state->out.buf;
    state->out.avail = 0;
    state->size = want;
    if (state->in.buf == NULL || state->out.buf == NULL) {
       goto err;
    }

#ifdef USE_ZLIB_OR_ZLIBNG
    /* allocate inflate memory */
    state->strm.zalloc = Z_NULL;
    state->strm.zfree = Z_NULL;
    state->strm.opaque = Z_NULL;
    state->strm.avail_in = 0;
    state->strm.next_in = Z_NULL;
    if (ZLIB_PREFIX(inflateInit2)(&(state->strm), -15) != Z_OK) {    /* raw inflate */
        goto err;
    }

    /* for now, assume we should check the crc */
    state->dont_check_crc = false;
#endif /* USE_ZLIB_OR_ZLIBNG */

#ifdef HAVE_ZSTD
    state->zstd_dctx = ZSTD_createDCtx();
    if (state->zstd_dctx == NULL) {
        goto err;
    }
#endif /* HAVE_ZSTD */

#ifdef USE_LZ4
    ret = LZ4F_createDecompressionContext(&state->lz4_dctx, LZ4F_VERSION);
    if (LZ4F_isError(ret)) {
        goto err;
    }
#endif /* USE_LZ4 */

    /* return stream */
    return state;

err:
#ifdef USE_ZLIB_OR_ZLIBNG
    ZLIB_PREFIX(inflateEnd)(&state->strm);
#endif /* USE_ZLIB_OR_ZLIBNG */
#ifdef HAVE_ZSTD
    ZSTD_freeDCtx(state->zstd_dctx);
#endif /* HAVE_ZSTD */
#ifdef USE_LZ4
    LZ4F_freeDecompressionContext(state->lz4_dctx);
#endif /* USE_LZ4 */
    g_free(state->out.buf);
    g_free(state->in.buf);
    g_free(state);
    errno = ENOMEM;
    return NULL;
}

FILE_T
file_open(const char *path)
{
    int fd;
    FILE_T ft;
#ifdef USE_ZLIB_OR_ZLIBNG
    const char *suffixp;
#endif /* USE_ZLIB_OR_ZLIBNG */

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
    ft = file_fdopen(fd);
    if (ft == NULL) {
        ws_close(fd);
        return NULL;
    }

#ifdef USE_ZLIB_OR_ZLIBNG
    /*
     * If this file's name ends in ".caz", it's probably a compressed
     * Windows Sniffer file.  The compression is gzip, but if we
     * process the CRC as specified by RFC 1952, the computed CRC
     * doesn't match the stored CRC.
     *
     * Compressed Windows Sniffer files don't all have the same CRC
     * value; is it just random crap, or are they running the CRC on
     * a different set of data than you're supposed to (e.g., not
     * CRCing some of the data), or something such as that?
     *
     * For now, we just set a flag to ignore CRC errors.
     */
    suffixp = strrchr(path, '.');
    if (suffixp != NULL) {
        if (g_ascii_strcasecmp(suffixp, ".caz") == 0)
            ft->dont_check_crc = true;
    }
#endif /* USE_ZLIB_OR_ZLIBNG */

    return ft;
}

void
file_set_random_access(FILE_T stream, bool random_flag _U_, GPtrArray *seek)
{
    stream->fast_seek = seek;
}

int64_t
file_seek(FILE_T file, int64_t offset, int whence, int *err)
{
    struct fast_seek_point *here;
    unsigned n;

    if (whence != SEEK_SET && whence != SEEK_CUR && whence != SEEK_END) {
        ws_assert_not_reached();
/*
 *err = EINVAL;
 return -1;
*/
    }

    /* Normalize offset to a SEEK_CUR specification */
    if (whence == SEEK_END) {
        /* Seek relative to the end of the file; given that we might be
           reading from a compressed file, we do that by seeking to the
           end of the file, making an offset relative to the end of
           the file an offset relative to the current position.

           XXX - we don't actually use this yet, but, for uncompressed
           files, we could optimize it, if desired, by directly using
           ws_lseek64(). */
        if (gz_skip(file, INT64_MAX) == -1) {
            *err = file->err;
            return -1;
        }
        if (offset == 0) {
            /* We are done */
            return file->pos;
        }
    } else if (whence == SEEK_SET)
        offset -= file->pos;
    else if (file->seek_pending) {
        /* There's a forward-skip pending, so file->pos doesn't reflect
           the actual file position, it represents the position from
           which we're skipping; update the offset to include that. */
        offset += file->skip;
    }
    file->seek_pending = false;

    /*
     * Are we moving at all?
     */
    if (offset == 0) {
        /* No.  Just return the current position. */
        return file->pos;
    }

    /*
     * Are we seeking backwards?
     */
    if (offset < 0) {
        /*
         * Yes.
         *
         * Do we have enough data before the current position in the
         * buffer that we can seek backwards within the buffer?
         */
        if (-offset <= offset_in_buffer(&file->out)) {
            /*
             * Yes.  Adjust appropriately.
             *
             * offset is negative, so -offset is non-negative, and
             * -offset is <= an unsigned and thus fits in an unsigned.
             * Get that value and adjust appropriately.
             *
             * (Casting offset to unsigned makes it positive, which
             * is not what we would want, so we cast -offset instead.)
             *
             * XXX - this won't work with -offset = 2^63, as its
             * negative isn't a valid 64-bit integer, but we are
             * not at all likely to see files big enough to ever
             * see a negative offset that large.
             */
            unsigned adjustment = (unsigned)(-offset);

            file->out.avail += adjustment;
            file->out.next -= adjustment;
            file->pos -= adjustment;
            return file->pos;
        }
    } else {
        /*
         * No.  Offset is positive; we're seeking forwards.
         *
         * Do we have enough data after the current position in the
         * buffer that we can seek forwards within the buffer?
         */
        if (offset < file->out.avail) {
            /*
             * Yes.  Adjust appropriately.
             *
             * offset is < an unsigned and thus fits in an unsigned,
             * so we can cast it to unsigned safely.
             */
            file->out.avail -= (unsigned)offset;
            file->out.next += offset;
            file->pos += offset;
            return file->pos;
        }
    }

    /*
     * We're not seeking within the buffer.  Do we have "fast seek" data
     * for the location to which we will be seeking, and is the offset
     * outside the span for compressed files or is this an uncompressed
     * file?
     *
     * XXX, profile
     */
    if ((here = fast_seek_find(file, file->pos + offset)) &&
        (offset < 0 || offset > SPAN || here->compression == UNCOMPRESSED)) {
        int64_t off, off2;

        /*
         * Yes.  Use that data to do the seek.
         * Note that this will be true only if file_set_random_access()
         * has been called on this file, which should never be the case
         * for a pipe.
         */
#ifdef USE_ZLIB_OR_ZLIBNG
        if (here->compression == ZLIB) {
#ifdef HAVE_INFLATEPRIME
            off = here->in - (here->data.zlib.bits ? 1 : 0);
#else /* HAVE_INFLATEPRIME */
            off = here->in;
#endif /* HAVE_INFLATEPRIME */
            off2 = here->out;
        } else if (here->compression == GZIP_AFTER_HEADER) {
            off = here->in;
            off2 = here->out;
        } else
#endif /* USE_ZLIB_OR_ZLIBNG */
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
        buf_reset(&file->out);
        file->eof = false;
        file->seek_pending = false;
        file->err = 0;
        file->err_info = NULL;
        buf_reset(&file->in);

#ifdef USE_ZLIB_OR_ZLIBNG
        if (here->compression == ZLIB) {
            zlib_stream*strm = &file->strm;
            ZLIB_PREFIX(inflateReset)(strm);
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
                (void)ZLIB_PREFIX(inflatePrime)(strm, here->data.zlib.bits, ret >> (8 - here->data.zlib.bits));
            }
#endif /* HAVE_INFLATEPRIME */
            (void)ZLIB_PREFIX(inflateSetDictionary)(strm, here->data.zlib.window, ZLIB_WINSIZE);
            file->compression = ZLIB;
        } else if (here->compression == GZIP_AFTER_HEADER) {
            zlib_stream* strm = &file->strm;
            ZLIB_PREFIX(inflateReset)(strm);
            strm->adler = ZLIB_PREFIX(crc32)(0L, Z_NULL, 0);
            file->compression = ZLIB;
        } else
#endif /* USE_ZLIB_OR_ZLIBNG */
            file->compression = here->compression;

        offset = (file->pos + offset) - off2;
        file->pos = off2;
        /* g_print("OK! %ld\n", offset); */

        if (offset) {
            /* Don't skip forward yet, wait until we want to read from
               the file; that way, if we do multiple seeks in a row,
               all involving forward skips, they will be combined. */
            file->seek_pending = true;
            file->skip = offset;
        }
        return file->pos + offset;
    }

    /*
     * Is this an uncompressed file, are we within the raw area,
     * are we either seeking backwards or seeking past the end
     * of the buffer, and are we set up for random access with
     * file_set_random_access()?
     *
     * Again, note that this will never be true on a pipe, as
     * file_set_random_access() should never be called if we're
     * reading from a pipe.
     */
    if (file->compression == UNCOMPRESSED && file->pos + offset >= file->raw
        && (offset < 0 || offset >= file->out.avail)
        && (file->fast_seek != NULL))
    {
        /*
         * Yes.  Just seek there within the file.
         */
        if (ws_lseek64(file->fd, offset - file->out.avail, SEEK_CUR) == -1) {
            *err = errno;
            return -1;
        }
        file->raw_pos += (offset - file->out.avail);
        buf_reset(&file->out);
        file->eof = false;
        file->seek_pending = false;
        file->err = 0;
        file->err_info = NULL;
        buf_reset(&file->in);
        file->pos += offset;
        return file->pos;
    }

    /*
     * Are we seeking backwards?
     */
    if (offset < 0) {
        /*
         * Yes.  We have no fast seek data, so we have to rewind and
         * seek forward.
         * XXX - true only for compressed files.
         *
         * Calculate the amount to skip forward after rewinding.
         */
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

    /*
     * Either we're seeking backwards, but have rewound and now need to
     * skip forwards, or we're seeking forwards.
     *
     * Skip what's in output buffer (one less gzgetc() check).
     */
    n = (int64_t)file->out.avail > offset ? (unsigned)offset : file->out.avail;
    file->out.avail -= n;
    file->out.next += n;
    file->pos += n;
    offset -= n;

    /* request skip (if not zero) */
    if (offset) {
        /* Don't skip forward yet, wait until we want to read from
           the file; that way, if we do multiple seeks in a row,
           all involving forward skips, they will be combined. */
        file->seek_pending = true;
        file->skip = offset;
    }
    return file->pos + offset;
}

int64_t
file_tell(FILE_T stream)
{
    /* return position */
    return stream->pos + (stream->seek_pending ? stream->skip : 0);
}

int64_t
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

bool
file_iscompressed(FILE_T stream)
{
    return stream->is_compressed;
}

/* Returns a wtap compression type. If we don't know the compression type,
 * return WTAP_UNCOMPRESSED, but if our compression state is temporarily
 * UNKNOWN because we need to reread compression headers, return the last
 * known compression type.
 */
static wtap_compression_type
file_get_compression_type(FILE_T stream)
{
    if (stream->is_compressed) {
        switch ((stream->compression == UNKNOWN) ? stream->last_compression : stream->compression) {

        case ZLIB:
        case GZIP_AFTER_HEADER:
            return WTAP_GZIP_COMPRESSED;

        case ZSTD:
            return WTAP_ZSTD_COMPRESSED;

        case LZ4:
            return WTAP_LZ4_COMPRESSED;

        case UNCOMPRESSED:
            return WTAP_UNCOMPRESSED;

        default: /* UNKNOWN, should never happen if is_compressed is set */
            ws_assert_not_reached();
            return WTAP_UNCOMPRESSED;
        }
    }
    return WTAP_UNCOMPRESSED;
}

int
file_read(void *buf, unsigned int len, FILE_T file)
{
    unsigned got, n;

    /* if len is zero, avoid unnecessary operations */
    if (len == 0)
        return 0;

    /* process a skip request */
    if (file->seek_pending) {
        file->seek_pending = false;
        if (gz_skip(file, file->skip) == -1)
            return -1;
    }

    /*
     * Get len bytes to buf, or less than len if at the end;
     * if buf is null, just throw the bytes away.
     */
    got = 0;
    do {
        if (file->out.avail != 0) {
            /* We have stuff in the output buffer; copy
               what we have. */
            n = file->out.avail > len ? len : file->out.avail;
            if (buf != NULL) {
                memcpy(buf, file->out.next, n);
                buf = (char *)buf + n;
            }
            file->out.next += n;
            file->out.avail -= n;
            len -= n;
            got += n;
            file->pos += n;
        } else if (file->err != 0) {
            /* We have nothing in the output buffer, and
               we have an error that may not have been
               reported yet; that means we can't generate
               any more data into the output buffer, so
               return an error indication. */
            return -1;
        } else if (file->eof && file->in.avail == 0) {
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
        }
    } while (len);

    return (int)got;
}

/*
 * XXX - this *peeks* at next byte, not a character.
 */
int
file_peekc(FILE_T file)
{
    int ret = 0;

    /* check that we're reading and that there's no error */
    if (file->err != 0)
        return -1;

    /* try output buffer (no need to check for skip request) */
    if (file->out.avail != 0) {
        return *(file->out.next);
    }

    /* process a skip request */
    if (file->seek_pending) {
        file->seek_pending = false;
        if (gz_skip(file, file->skip) == -1)
            return -1;
    }
    /* if we processed a skip request, there may be data in the buffer,
     * or an error could have occurred; likewise if we didn't do seek but
     * now call fill_out_buffer, the errors can occur.  So we do this while
     * loop to check before and after - this is basically the logic from
     * file_read() but only for peeking not consuming a byte
     */
    while (1) {
        if (file->out.avail != 0) {
            return *(file->out.next);
        }
        else if (file->err != 0) {
            return -1;
        }
        else if (file->eof && file->in.avail == 0) {
            return -1;
        }
        else if (fill_out_buffer(file) == -1) {
            return -1;
        }
    }
    /* it's actually impossible to get here */
    return ret;
}

/*
 * XXX - this gets a byte, not a character.
 */
int
file_getc(FILE_T file)
{
    unsigned char buf[1];
    int ret;

    /* check that we're reading and that there's no error */
    if (file->err != 0)
        return -1;

    /* try output buffer (no need to check for skip request) */
    if (file->out.avail != 0) {
        file->out.avail--;
        file->pos++;
        return *(file->out.next)++;
    }

    ret = file_read(buf, 1, file);
    return ret < 1 ? -1 : buf[0];
}

/* Like file_gets, but returns a pointer to the terminating NUL. */
char *
file_getsp(char *buf, int len, FILE_T file)
{
    unsigned left, n;
    char *str;
    unsigned char *eol;

    /* check parameters */
    if (buf == NULL || len < 1)
        return NULL;

    /* check that there's no error */
    if (file->err != 0)
        return NULL;

    /* process a skip request */
    if (file->seek_pending) {
        file->seek_pending = false;
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
            if (file->out.avail == 0) {
                /* We have nothing in the output buffer. */
                if (file->err != 0) {
                    /* We have an error that may not have
                       been reported yet; that means we
                       can't generate any more data into
                       the output buffer, so return an
                       error indication. */
                    return NULL;
                }
                if (fill_out_buffer(file) == -1)
                    return NULL;            /* error */
                if (file->out.avail == 0)  {     /* end of file */
                    if (buf == str)         /* got bupkus */
                        return NULL;
                    break;                  /* got something -- return it */
                }
            }

            /* look for end-of-line in current output buffer */
            n = file->out.avail > left ? left : file->out.avail;
            eol = (unsigned char *)memchr(file->out.next, '\n', n);
            if (eol != NULL)
                n = (unsigned)(eol - file->out.next) + 1;

            /* copy through end-of-line, or remainder if not found */
            memcpy(buf, file->out.next, n);
            file->out.avail -= n;
            file->out.next += n;
            file->pos += n;
            left -= n;
            buf += n;
        } while (left && eol == NULL);

    /* found end-of-line or out of space -- add a terminator and return
       a pointer to it */
    buf[0] = 0;
    return buf;
}

char *
file_gets(char *buf, int len, FILE_T file)
{
    if (!file_getsp(buf, len, file)) return NULL;
    return buf;
}

int
file_eof(FILE_T file)
{
    /* return end-of-file state */
    return (file->eof && file->in.avail == 0 && file->out.avail == 0);
}

/*
 * Routine to return a Wiretap error code (0 for no error, an errno
 * for a file error, or a WTAP_ERR_ code for other errors) for an
 * I/O stream.  Also returns an error string for some errors.
 */
int
file_error(FILE_T fh, char **err_info)
{
    if (fh->err!=0 && err_info) {
        /* g_strdup() returns NULL for NULL argument */
        *err_info = g_strdup(fh->err_info);
    }
    return fh->err;
}

void
file_clearerr(FILE_T stream)
{
    /* clear error and end-of-file */
    stream->err = 0;
    stream->err_info = NULL;
    stream->eof = false;
}

void
file_fdclose(FILE_T file)
{
    if (file->fd != -1)
        ws_close(file->fd);
    file->fd = -1;
}

bool
file_fdreopen(FILE_T file, const char *path)
{
    int fd;

    if ((fd = ws_open(path, O_RDONLY|O_BINARY, 0000)) == -1)
        return false;
    file->fd = fd;
    return true;
}

void
file_close(FILE_T file)
{
    int fd = file->fd;

    /* free memory and close file */
    if (file->size) {
#ifdef USE_ZLIB_OR_ZLIBNG
        ZLIB_PREFIX(inflateEnd)(&(file->strm));
#endif /* USE_ZLIB_OR_ZLIBNG */
#ifdef HAVE_ZSTD
        ZSTD_freeDCtx(file->zstd_dctx);
#endif /* HAVE_ZSTD */
#ifdef USE_LZ4
        LZ4F_freeDecompressionContext(file->lz4_dctx);
#endif /* USE_LZ4 */
        g_free(file->out.buf);
        g_free(file->in.buf);
    }
    g_free(file->fast_seek_cur);
    file->err = 0;
    file->err_info = NULL;
    g_free(file);
    /*
     * If fd is -1, somebody's done a file_closefd() on us, so
     * we don't need to close the FD itself, and shouldn't do
     * so.
     */
    if (fd != -1)
        ws_close(fd);
}

#ifdef USE_ZLIB_OR_ZLIBNG
/* internal gzip file state data structure for writing */
struct wtap_writer {
    int fd;                 /* file descriptor */
    int64_t pos;            /* current position in uncompressed data */
    unsigned size;          /* buffer size, zero if not allocated yet */
    unsigned want;          /* requested buffer size, default is GZBUFSIZE */
    unsigned char *in;      /* input buffer */
    unsigned char *out;     /* output buffer (double-sized when reading) */
    unsigned char *next;    /* next output data to deliver or write */
    int level;              /* compression level */
    int strategy;           /* compression strategy */
    int err;                /* error code */
    const char *err_info;   /* additional error information string for some errors */
    /* zlib deflate stream */
    zlib_stream strm;          /* stream structure in-place (not a pointer) */
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
        ws_close(fd);
        errno = save_errno;
    }
    return state;
}

GZWFILE_T
gzwfile_fdopen(int fd)
{
    GZWFILE_T state;

    /* allocate wtap_writer structure to return */
    state = (GZWFILE_T)g_try_malloc(sizeof *state);
    if (state == NULL)
        return NULL;
    state->fd = fd;
    state->size = 0;            /* no buffers allocated yet */
    state->want = GZBUFSIZE;    /* requested buffer size */

    state->level = Z_DEFAULT_COMPRESSION;
    state->strategy = Z_DEFAULT_STRATEGY;

    /* initialize stream */
    state->err = Z_OK;              /* clear error */
    state->err_info = NULL;         /* clear additional error information */
    state->pos = 0;                 /* no uncompressed data yet */
    state->strm.avail_in = 0;       /* no input data yet */

    /* return stream */
    return state;
}

/* Initialize state for writing a gzip file.  Mark initialization by setting
   state->size to non-zero.  Return -1, and set state->err and possibly
   state->err_info, on failure; return 0 on success. */
static int
gz_init(GZWFILE_T state)
{
    int ret;
#ifdef HAVE_ZLIBNG
    zng_streamp strm = &(state->strm);
#else /* HAVE_ZLIBNG */
    z_streamp strm = &(state->strm);
#endif /* HAVE_ZLIBNG */

    /* allocate input and output buffers */
    state->in = (unsigned char *)g_try_malloc(state->want);
    state->out = (unsigned char *)g_try_malloc(state->want);
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
    ret = ZLIB_PREFIX(deflateInit2)(strm, state->level, Z_DEFLATED,
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
            state->err_info = "Unknown error from deflateInit2()";
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
   Return -1, and set state->err and possibly state->err_info, if there is
   an error writing to the output file; return 0 on success.
   flush is assumed to be a valid deflate() flush value.  If flush is Z_FINISH,
   then the deflate() state is reset to start a new gzip stream. */
static int
gz_comp(GZWFILE_T state, int flush)
{
    int ret;
    ssize_t got;
    ptrdiff_t have;
#ifdef HAVE_ZLIBNG
    zng_streamp strm = &(state->strm);
#else /* HAVE_ZLIBNG */
    z_streamp strm = &(state->strm);
#endif /* HAVE_ZLIBNG */
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
            have = strm->next_out - state->next;
            if (have) {
                got = ws_write(state->fd, state->next, (unsigned int)have);
                if (got < 0) {
                    state->err = errno;
                    return -1;
                }
                if ((ptrdiff_t)got != have) {
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
        ret = ZLIB_PREFIX(deflate)(strm, flush);
        if (ret == Z_STREAM_ERROR) {
            /* This "shouldn't happen". */
            state->err = WTAP_ERR_INTERNAL;
            state->err_info = "Z_STREAM_ERROR from deflate()";
            return -1;
        }
        have -= strm->avail_out;
    } while (have);

    /* if that completed a deflate stream, allow another to start */
    if (flush == Z_FINISH)
        ZLIB_PREFIX(deflateReset)(strm);

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
#ifdef HAVE_ZLIBNG
    zng_streamp strm;
#else /* HAVE_ZLIBNG */
    z_streamp strm;
#endif /* HAVE_ZLIBNG */

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
#ifdef z_const
DIAG_OFF(cast-qual)
            memcpy((Bytef *)strm->next_in + strm->avail_in, buf, n);
DIAG_ON(cast-qual)
#else /* z_const */
            memcpy(strm->next_in + strm->avail_in, buf, n);
#endif /* z_const */
            strm->avail_in += n;
            state->pos += n;
            buf = (const char *)buf + n;
            len -= n;
            if (len && gz_comp(state, Z_NO_FLUSH) == -1)
                return 0;
        } while (len);
    }
    else {
        /* consume whatever's left in the input buffer */
        if (strm->avail_in != 0 && gz_comp(state, Z_NO_FLUSH) == -1)
            return 0;

        /* directly compress user buffer to file */
        strm->avail_in = len;
#ifdef z_const
        strm->next_in = (z_const Bytef *)buf;
#else /* z_const */
DIAG_OFF(cast-qual)
        strm->next_in = (Bytef *)buf;
DIAG_ON(cast-qual)
#endif /* z_const */
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
    if (gz_comp(state, Z_FINISH) == -1)
        ret = state->err;
    (void)ZLIB_PREFIX(deflateEnd)(&(state->strm));
    g_free(state->out);
    g_free(state->in);
    state->err = Z_OK;
    if (ws_close(state->fd) == -1 && ret == 0)
        ret = errno;
    g_free(state);
    return ret;
}

int
gzwfile_geterr(GZWFILE_T state)
{
    return state->err;
}
#endif /* USE_ZLIB_OR_ZLIBNG */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
