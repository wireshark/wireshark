/* file_compressed.c
 * Code for writing compressed files.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Derived from code in the Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <wireshark.h>

#include <errno.h>

/*
 * XXX - this is included only to get some libwiretap error codes;
 * we should fix this to have its own error codes for those cases
 * and to have libwiretap use *those* error codes.
 */
#include <wiretap/wtap.h>

#include <wsutil/file_util.h>
#include <wsutil/zlib_compat.h>

#ifdef HAVE_LZ4FRAME_H
#include <lz4frame.h>
#endif /* HAVE_LZ4FRAME_H */

#include "file_compressed.h"

/*
 * List of compression types supported.
 * This includes compression types that can only be read, not written.
 */
static const struct compression_type {
    ws_compression_type  type;
    const char          *extension;
    const char          *description;
    const char          *name;
    const bool           can_write_compressed;
} compression_types[] = {
#ifdef USE_ZLIB_OR_ZLIBNG
    { WS_FILE_GZIP_COMPRESSED, "gz", "gzip compressed", "gzip", true },
#endif /* USE_ZLIB_OR_ZLIBNG */
#ifdef HAVE_ZSTD
    { WS_FILE_ZSTD_COMPRESSED, "zst", "zstd compressed", "zstd", false },
#endif /* HAVE_ZSTD */
#ifdef HAVE_LZ4FRAME_H
    { WS_FILE_LZ4_COMPRESSED, "lz4", "lz4 compressed", "lz4", true },
#endif /* HAVE_LZ4FRAME_H */
    { WS_FILE_UNCOMPRESSED, NULL, NULL, "none", true },
    { WS_FILE_UNKNOWN_COMPRESSION, NULL, NULL, NULL, false },
};

ws_compression_type
ws_name_to_compression_type(const char *name)
{
    for (const struct compression_type *p = compression_types;
	 p->type != WS_FILE_UNKNOWN_COMPRESSION; p++) {
        if (!g_strcmp0(name, p->name))
            return p->type;
    }
    return WS_FILE_UNKNOWN_COMPRESSION;
}

ws_compression_type
ws_extension_to_compression_type(const char *ext)
{
    for (const struct compression_type *p = compression_types;
         p->type != WS_FILE_UNKNOWN_COMPRESSION; p++) {
        if (g_strcmp0(ext, p->extension) == 0)
            return p->type;
    }
    return WS_FILE_UNKNOWN_COMPRESSION;
}

bool
ws_can_write_compression_type(ws_compression_type compression_type)
{
    for (const struct compression_type *p = compression_types;
         p->type != WS_FILE_UNKNOWN_COMPRESSION; p++) {
        if (compression_type == p->type)
            return p->can_write_compressed;
    }

    return false;
}

const char *
ws_compression_type_description(ws_compression_type compression_type)
{
    for (const struct compression_type *p = compression_types;
         p->type != WS_FILE_UNCOMPRESSED; p++) {
        if (p->type == compression_type)
            return p->description;
    }
    return NULL;
}

const char *
ws_compression_type_extension(ws_compression_type compression_type)
{
    for (const struct compression_type *p = compression_types;
         p->type != WS_FILE_UNCOMPRESSED; p++) {
        if (p->type == compression_type)
            return p->extension;
    }
    return NULL;
}

const char *
ws_compression_type_name(ws_compression_type compression_type)
{
    for (const struct compression_type *p = compression_types;
         p->type != WS_FILE_UNCOMPRESSED; p++) {
        if (p->type == compression_type)
            return p->name;
    }
    return NULL;
}

GSList *
ws_get_all_compression_type_extensions_list(void)
{
    GSList *extensions;

    extensions = NULL;	/* empty list, to start with */

    for (const struct compression_type *p = compression_types;
         p->type != WS_FILE_UNCOMPRESSED; p++)
        extensions = g_slist_prepend(extensions, (void *)p->extension);

    return extensions;
}

GSList *
ws_get_all_output_compression_type_names_list(void)
{
    GSList *names;

    names = NULL;	/* empty list, to start with */

    for (const struct compression_type *p = compression_types;
         p->type != WS_FILE_UNCOMPRESSED; p++) {
        if (p->can_write_compressed)
            names = g_slist_prepend(names, (void *)p->name);
    }

    return names;
}

typedef void* WFILE_T;

struct ws_cwstream {
    WFILE_T fh;
    char* io_buffer;
    ws_compression_type ctype;
};

static WFILE_T
writecap_file_open(ws_cwstream* pfile, const char *filename)
{
    WFILE_T fh;
    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WS_FILE_GZIP_COMPRESSED:
            return gzwfile_open(filename);
#endif /* defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG) */
#ifdef HAVE_LZ4FRAME_H
        case WS_FILE_LZ4_COMPRESSED:
            return lz4wfile_open(filename);
#endif /* HAVE_LZ4FRAME_H */
        default:
            fh = ws_fopen(filename, "wb");
            /* Increase the size of the IO buffer if uncompressed.
             * Compression has its own buffer that reduces writes.
             */
            if (fh != NULL) {
                size_t buffsize = IO_BUF_SIZE;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
                ws_statb64 statb;

                if (ws_stat64(filename, &statb) == 0) {
                    if (statb.st_blksize > IO_BUF_SIZE) {
                        buffsize = (size_t)statb.st_blksize;
                    }
                }
#endif
                pfile->io_buffer = (char *)g_malloc(buffsize);
                setvbuf(fh, pfile->io_buffer, _IOFBF, buffsize);
                //ws_debug("buffsize %zu", buffsize);
            }
            return fh;
    }
}

static WFILE_T
writecap_file_fdopen(ws_cwstream* pfile, int fd)
{
    WFILE_T fh;
    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WS_FILE_GZIP_COMPRESSED:
            return gzwfile_fdopen(fd);
#endif /* defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG) */
#ifdef HAVE_LZ4FRAME_H
        case WS_FILE_LZ4_COMPRESSED:
            return lz4wfile_fdopen(fd);
#endif /* HAVE_LZ4FRAME_H */
        default:
            fh = ws_fdopen(fd, "wb");
            /* Increase the size of the IO buffer if uncompressed.
             * Compression has its own buffer that reduces writes.
             */
            if (fh != NULL) {
                size_t buffsize = IO_BUF_SIZE;
#ifdef HAVE_STRUCT_STAT_ST_BLKSIZE
                ws_statb64 statb;

                if (ws_fstat64(fd, &statb) == 0) {
                    if (statb.st_blksize > IO_BUF_SIZE) {
                        buffsize = (size_t)statb.st_blksize;
                    }
                }
#endif
                pfile->io_buffer = (char *)g_malloc(buffsize);
                setvbuf(fh, pfile->io_buffer, _IOFBF, buffsize);
                //ws_debug("buffsize %zu", buffsize);
            }
            return fh;
    }
}

ws_cwstream*
ws_cwstream_open(const char *filename, ws_compression_type ctype, int *err)
{
    ws_cwstream* pfile;
    *err = 0;

    pfile = g_new0(struct ws_cwstream, 1);
    if (pfile == NULL) {
        *err = errno;
        return NULL;
    }
    pfile->ctype = ctype;
    errno = WTAP_ERR_CANT_OPEN;
    void* fh = writecap_file_open(pfile, filename);
    if (fh == NULL) {
        *err = errno;
	g_free(pfile);
	return NULL;
    }

    pfile->fh = fh;
    return pfile;
}

ws_cwstream*
ws_cwstream_fdopen(int fd, ws_compression_type ctype, int *err)
{
    ws_cwstream* pfile;
    *err = 0;

    pfile = g_new0(struct ws_cwstream, 1);
    if (pfile == NULL) {
        *err = errno;
        return NULL;
    }
    pfile->ctype = ctype;
    errno = WTAP_ERR_CANT_OPEN;
    WFILE_T fh = writecap_file_fdopen(pfile, fd);
    if (fh == NULL) {
        *err = errno;
        g_free(pfile);
        return NULL;
    }

    pfile->fh = fh;
    return pfile;
}

ws_cwstream*
ws_cwstream_open_stdout(ws_compression_type ctype, int *err)
{
    int new_fd;
    ws_cwstream* pfile;

    new_fd = ws_dup(1);
    if (new_fd == -1) {
        *err = errno;
        return NULL;
    }
#ifdef _WIN32
    /*
     * Put the new descriptor into binary mode.
     *
     * XXX - even if the file format we're writing is a text
     * format?
     */
    if (_setmode(new_fd, O_BINARY) == -1) {
        /* "Should not happen" */
        *err = errno;
        ws_close(new_fd);
        return NULL;
    }
#endif

    pfile = ws_cwstream_fdopen(new_fd, ctype, err);
    if (pfile == NULL) {
        /* Failed; close the new fd */
        ws_close(new_fd);
        return NULL;
    }
    return pfile;
}

/* Write to file */
bool
ws_cwstream_write(ws_cwstream* pfile, const uint8_t* data, size_t data_length,
                  uint64_t *bytes_written, int *err)
{
    size_t nwritten;

    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WS_FILE_GZIP_COMPRESSED:
            nwritten = gzwfile_write(pfile->fh, data, (unsigned)data_length);
            /*
             * gzwfile_write() returns 0 on error.
             */
            if (nwritten == 0) {
                *err = gzwfile_geterr(pfile->fh);
                return false;
            }
            break;
#endif
#ifdef HAVE_LZ4FRAME_H
        case WS_FILE_LZ4_COMPRESSED:
            nwritten = lz4wfile_write(pfile->fh, data, data_length);
            /*
             * lz4wfile_write() returns 0 on error.
             */
            if (nwritten == 0) {
                *err = lz4wfile_geterr(pfile->fh);
                return false;
            }
            break;
#endif /* HAVE_LZ4FRAME_H */
        default:
            nwritten = fwrite(data, data_length, 1, pfile->fh);
            if (nwritten != 1) {
                if (ferror((FILE *)pfile->fh)) {
                    *err = errno;
                } else {
                    *err = WTAP_ERR_SHORT_WRITE;
                }
                return false;
            }
            break;
    }

    (*bytes_written) += data_length;
    return true;
}

bool
ws_cwstream_flush(ws_cwstream* pfile, int *err)
{
    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WS_FILE_GZIP_COMPRESSED:
            if (gzwfile_flush((GZWFILE_T)pfile->fh) == -1) {
                if (err) {
                    *err = gzwfile_geterr((GZWFILE_T)pfile->fh);
                }
                return false;
            }
            break;
#endif
#ifdef HAVE_LZ4FRAME_H
        case WS_FILE_LZ4_COMPRESSED:
            if (lz4wfile_flush((LZ4WFILE_T)pfile->fh) == -1) {
                if (err) {
                    *err = lz4wfile_geterr((LZ4WFILE_T)pfile->fh);
                }
                return false;
            }
            break;
#endif /* HAVE_LZ4FRAME_H */
        default:
            if (fflush((FILE*)pfile->fh) == EOF) {
                if (err) {
                    *err = errno;
                }
                return false;
            }
    }
    return true;
}

bool
ws_cwstream_close(ws_cwstream* pfile, int *errp)
{
    int err = 0;

    errno = WTAP_ERR_CANT_CLOSE;
    switch (pfile->ctype) {
#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
        case WS_FILE_GZIP_COMPRESSED:
            err = gzwfile_close(pfile->fh);
            break;
#endif
#ifdef HAVE_LZ4FRAME_H
        case WS_FILE_LZ4_COMPRESSED:
            err = lz4wfile_close(pfile->fh);
            break;
#endif /* HAVE_LZ4FRAME_H */
        default:
            if (fclose(pfile->fh) == EOF) {
                err = errno;
            }
    }

    g_free(pfile->io_buffer);
    g_free(pfile);
    if (errp) {
        *errp = err;
    }
    return err == 0;
}

#ifdef USE_ZLIB_OR_ZLIBNG

#define GZBUFSIZE 4096

/* internal gzip file state data structure for writing */
struct gzip_writer {
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

    /* allocate zlib_writer structure to return */
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
    zlib_streamp strm = &(state->strm);

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
    zlib_streamp strm = &(state->strm);
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
    zlib_streamp strm;

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

    /* input was all buffered or compressed */
    return put;
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

#ifdef HAVE_LZ4FRAME_H

#define LZ4BUFSIZE 4194304 // 4MiB, maximum block size

/* internal lz4 file state data structure for writing */
struct lz4_writer {
    int fd;                 /* file descriptor */
    int64_t pos;            /* current position in uncompressed data */
    int64_t pos_out;
    size_t size_out;      /* buffer size, zero if not allocated yet */
    size_t want;          /* requested buffer size, default is LZ4BUFSIZE */
    size_t want_out;      /* requested output buffer size, determined from want */
    unsigned char *out; /* output buffer, containing uncompressed data */
    int err;                /* error code */
    const char *err_info;   /* additional error information string for some errors */
    LZ4F_preferences_t lz4_prefs;
    LZ4F_cctx *lz4_cctx;
};

LZ4WFILE_T
lz4wfile_open(const char *path)
{
    int fd;
    LZ4WFILE_T state;
    int save_errno;

    fd = ws_open(path, O_BINARY|O_WRONLY|O_CREAT|O_TRUNC, 0666);
    if (fd == -1)
        return NULL;
    state = lz4wfile_fdopen(fd);
    if (state == NULL) {
        save_errno = errno;
        ws_close(fd);
        errno = save_errno;
    }
    return state;
}

LZ4WFILE_T
lz4wfile_fdopen(int fd)
{
    LZ4WFILE_T state;

    /* allocate lz4_writer structure to return */
    state = (LZ4WFILE_T)g_try_malloc(sizeof *state);
    if (state == NULL)
        return NULL;
    state->fd = fd;
    state->size_out = 0;         /* no buffer allocated yet */
    state->want = LZ4BUFSIZE;    /* max input size (a block) */

    memset(&state->lz4_prefs, 0, sizeof(LZ4F_preferences_t));
    /* Use the same prefs as the lz4 command line utility defaults. */
    state->lz4_prefs.frameInfo.blockMode = LZ4F_blockIndependent; /* Allows fast seek */
    /* We could use LZ4F_blockLinked but start a new frame every so often
     * in order to allow fast seek. (Or implement fast seek for linked
     * blocks via dictionary loading.) Linked blocks have better compression
     * when blocks are small, as happens when flushing during live capture.
     */
    state->lz4_prefs.frameInfo.contentChecksumFlag = 1;
    state->lz4_prefs.frameInfo.blockSizeID = LZ4F_max4MB;
    /* XXX - What should we set state->lz4_prefs.compressionLevel to?
     * The command line utility uses 1, recommends 9 as another option, and
     * also there's 12 (max).
     *
     * We could provide an API call or perhaps two or three preset options.
     */
    state->lz4_prefs.compressionLevel = 1;

    state->want_out = LZ4F_compressBound(state->want, &state->lz4_prefs);
    /*
     * This size guarantees that we will always have enough room to
     * write the result of LZ4F_compressUpdate (or Flush or End),
     * so long as the output buffer is empty (i.e., we immediately
     * write to the output file anything the compressor hands back
     * instead of buffering.)
     */

    /* initialize stream */
    state->err = 0;              /* clear error */
    state->err_info = NULL;         /* clear additional error information */
    state->pos = 0;                 /* no uncompressed data yet */
    state->pos_out = 0;

    /* return stream */
    return state;
}

/* Writes len bytes from the output buffer to the file.
 * Return true on success; returns false and sets state->err on failure.
 */
static bool
lz4_write_out(LZ4WFILE_T state, size_t len)
{
    if (len > 0) {
        ssize_t got = ws_write(state->fd, state->out, (unsigned)len);
        if (got < 0) {
            state->err = errno;
            return false;
        }
        if ((unsigned)got != len) {
            state->err = WTAP_ERR_SHORT_WRITE;
            return false;
        }
        state->pos_out += got;
    }
    return true;
}

/* Initialize state for writing an lz4 file.  Mark initialization by setting
   state->size to non-zero.  Return -1, and set state->err and possibly
   state->err_info, on failure; return 0 on success. */
static int
lz4_init(LZ4WFILE_T state)
{
    LZ4F_errorCode_t ret;

    /* create Compression context */
    ret = LZ4F_createCompressionContext(&state->lz4_cctx, LZ4F_VERSION);
    if (LZ4F_isError(ret)) {
        state->err = WTAP_ERR_CANT_WRITE; // XXX - WTAP_ERR_COMPRESS?
        state->err_info = LZ4F_getErrorName(ret);
        return -1;
    }

    /* allocate buffer */
    state->out = (unsigned char *)g_try_malloc(state->want_out);
    if (state->out == NULL) {
        g_free(state->out);
        LZ4F_freeCompressionContext(state->lz4_cctx);
        state->err = ENOMEM;
        return -1;
    }

    ret = LZ4F_compressBegin(state->lz4_cctx, state->out, state->want_out, &state->lz4_prefs);
    if (LZ4F_isError(ret)) {
        state->err = WTAP_ERR_CANT_WRITE; // XXX - WTAP_ERR_COMPRESS?
        state->err_info = LZ4F_getErrorName(ret);
        return -1;
    }
    if (!lz4_write_out(state, ret)) {
        return -1;
    }

    /* mark state as initialized */
    state->size_out = state->want_out;

    return 0;
}

/* Write out len bytes from buf.  Return 0, and set state->err, on
   failure or on an attempt to write 0 bytes (in which case state->err
   is 0); return the number of bytes written on success. */
size_t
lz4wfile_write(LZ4WFILE_T state, const void *buf, size_t len)
{
    size_t to_write;
    size_t put = len;

    /* check that there's no error */
    if (state->err != 0)
        return 0;

    /* if len is zero, avoid unnecessary operations */
    if (len == 0)
        return 0;

    /* allocate memory if this is the first time through */
    if (state->size_out == 0 && lz4_init(state) == -1)
        return 0;

    do {
        to_write = MIN(len, state->want);
        size_t bytesWritten = LZ4F_compressUpdate(state->lz4_cctx, state->out, state->size_out,
            buf, to_write, NULL);
        if (LZ4F_isError(bytesWritten)) {
            state->err = WTAP_ERR_CANT_WRITE; // XXX - WTAP_ERR_COMPRESS?
            state->err_info = LZ4F_getErrorName(bytesWritten);
            return 0;
        }
        if (!lz4_write_out(state, bytesWritten)) {
            return 0;
        }
        state->pos += to_write;
        len -= to_write;
    } while (len);

    /* input was all buffered or compressed */
    return put;
}

/* Flush out what we've written so far.  Returns -1, and sets state->err,
   on failure; returns 0 on success. */
int
lz4wfile_flush(LZ4WFILE_T state)
{
    size_t bytesWritten;
    /* check that there's no error */
    if (state->err != 0)
        return -1;

    bytesWritten = LZ4F_flush(state->lz4_cctx, state->out, state->size_out, NULL);
    if (LZ4F_isError(bytesWritten)) {
        // Should never happen if size_out >= LZ4F_compressBound(0, prefsPtr)
        state->err = WTAP_ERR_INTERNAL;
        return -1;
    }
    if (!lz4_write_out(state, bytesWritten)) {
        return -1;
    }
    return 0;
}

/* Flush out all data written, and close the file.  Returns a Wiretap
   error on failure; returns 0 on success. */
int
lz4wfile_close(LZ4WFILE_T state)
{
    int ret = 0;

    /* flush, free memory, and close file */
    size_t bytesWritten = LZ4F_compressEnd(state->lz4_cctx, state->out, state->size_out, NULL);
    if (LZ4F_isError(bytesWritten)) {
        // Should never happen if size_out >= LZ4F_compressBound(0, prefsPtr)
        ret = WTAP_ERR_INTERNAL;
    }
    if (!lz4_write_out(state, bytesWritten)) {
        ret = state->err;
    }
    g_free(state->out);
    LZ4F_freeCompressionContext(state->lz4_cctx);
    if (ws_close(state->fd) == -1 && ret == 0)
        ret = errno;
    g_free(state);
    return ret;
}

int
lz4wfile_geterr(LZ4WFILE_T state)
{
    return state->err;
}
#endif /* HAVE_LZ4FRAME_H */
