/* tvbuff_zlib.c
 *
 * Copyright (c) 2000 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#define WS_LOG_DOMAIN LOG_DOMAIN_EPAN

#include <glib.h>

#include <string.h>
#include <wsutil/glib-compat.h>


#ifdef HAVE_ZLIBNG
#define ZLIB_PREFIX(x) zng_ ## x
#include <zlib-ng.h>
typedef zng_stream zlib_stream;
#else
#ifdef HAVE_ZLIB
#define ZLIB_CONST
#define ZLIB_PREFIX(x) x
#include <zlib.h>
typedef z_stream zlib_stream;
#endif /* HAVE_ZLIB */
#endif

#include "tvbuff.h"
#include <wsutil/wslog.h>

#if defined (HAVE_ZLIB) || defined (HAVE_ZLIBNG)
/*
 * Uncompresses a zlib compressed packet inside a message of tvb at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 */
#define TVB_Z_MIN_BUFSIZ 32768
#define TVB_Z_MAX_BUFSIZ 1048576 * 10

tvbuff_t *
tvb_uncompress_zlib(tvbuff_t *tvb, const int offset, int comprlen)
{
	int        err;
	unsigned   bytes_out      = 0;
	uint8_t   *compr;
	uint8_t   *uncompr        = NULL;
	tvbuff_t  *uncompr_tvb    = NULL;
#ifdef HAVE_ZLIBNG
	zng_streamp  strm;
#else
	z_streamp  strm;
#endif
	Bytef     *strmbuf;
	unsigned   inits_done     = 0;
	int        wbits          = MAX_WBITS;
	uint8_t   *next;
	unsigned   bufsiz;
	unsigned   inflate_passes = 0;
	unsigned   bytes_in       = tvb_captured_length_remaining(tvb, offset);

	if (tvb == NULL || comprlen <= 0) {
		return NULL;
	}

	compr = (uint8_t *)tvb_memdup(NULL, tvb, offset, comprlen);
	if (compr == NULL) {
		return NULL;
	}

	/*
	 * Assume that the uncompressed data is at least twice as big as
	 * the compressed size.
	 */
	bufsiz = tvb_captured_length_remaining(tvb, offset) * 2;
	bufsiz = CLAMP(bufsiz, TVB_Z_MIN_BUFSIZ, TVB_Z_MAX_BUFSIZ);

	ws_debug("bufsiz: %u bytes\n", bufsiz);

	next = compr;

	strm            = g_new0(zlib_stream, 1);
	strm->next_in   = next;
	strm->avail_in  = comprlen;

	strmbuf         = (Bytef *)g_malloc0(bufsiz);
	strm->next_out  = strmbuf;
	strm->avail_out = bufsiz;

	err = ZLIB_PREFIX(inflateInit2)(strm, wbits);
	inits_done = 1;
	if (err != Z_OK) {
		ZLIB_PREFIX(inflateEnd)(strm);
		g_free(strm);
		wmem_free(NULL, compr);
		g_free(strmbuf);
		return NULL;
	}

	while (1) {
		memset(strmbuf, '\0', bufsiz);
		strm->next_out  = strmbuf;
		strm->avail_out = bufsiz;

		err = ZLIB_PREFIX(inflate)(strm, Z_SYNC_FLUSH);

		if (err == Z_OK || err == Z_STREAM_END) {
			unsigned bytes_pass = bufsiz - strm->avail_out;

			++inflate_passes;

			if (uncompr == NULL) {
				/*
				 * This is ugly workaround for bug #6480
				 * (https://gitlab.com/wireshark/wireshark/-/issues/6480)
				 *
				 * g_memdup2(..., 0) returns NULL (g_malloc(0) also)
				 * when uncompr is NULL logic below doesn't create tvb
				 * which is later interpreted as decompression failed.
				 */
				uncompr = (uint8_t *)((bytes_pass || err != Z_STREAM_END) ?
						g_memdup2(strmbuf, bytes_pass) :
						g_strdup(""));
			} else {
				uncompr = (uint8_t *)g_realloc(uncompr, bytes_out + bytes_pass);
				memcpy(uncompr + bytes_out, strmbuf, bytes_pass);
			}

			bytes_out += bytes_pass;

			if (err == Z_STREAM_END) {
				ZLIB_PREFIX(inflateEnd)(strm);
				g_free(strm);
				g_free(strmbuf);
				break;
			}
		} else if (err == Z_BUF_ERROR) {
			/*
			 * It's possible that not enough frames were captured
			 * to decompress this fully, so return what we've done
			 * so far, if any.
			 */
			ZLIB_PREFIX(inflateEnd)(strm);
			g_free(strm);
			g_free(strmbuf);

			if (uncompr != NULL) {
				break;
			} else {
				wmem_free(NULL, compr);
				return NULL;
			}

		} else if (err == Z_DATA_ERROR && inits_done == 1
			&& uncompr == NULL && comprlen >= 2 &&
			(*compr  == 0x1f) && (*(compr + 1) == 0x8b)) {
			/*
			 * inflate() is supposed to handle both gzip and deflate
			 * streams automatically, but in reality it doesn't
			 * seem to handle either (at least not within the
			 * context of an HTTP response.)  We have to try
			 * several tweaks, depending on the type of data and
			 * version of the library installed.
			 */

			/*
			 * Gzip file format.  Skip past the header, since the
			 * fix to make it work (setting windowBits to 31)
			 * doesn't work with all versions of the library.
			 */
			Bytef *c = compr + 2;
			Bytef  flags = 0;

			/* we read two bytes already (0x1f, 0x8b) and
			   need at least Z_DEFLATED, 1 byte flags, 4
			   bytes MTIME, 1 byte XFL, 1 byte OS */
			if (comprlen < 10 || *c != Z_DEFLATED) {
				ZLIB_PREFIX(inflateEnd)(strm);
				g_free(strm);
				wmem_free(NULL, compr);
				g_free(strmbuf);
				return NULL;
			}

			c++;
			flags = *c;
			c++;

			/* Skip past the MTIME (4 bytes),
			   XFL, and OS fields (1 byte each). */
			c += 6;

			if (flags & (1 << 2)) {
				/* An Extra field is present. It
				   consists of 2 bytes xsize and xsize
				   bytes of data.
				   Read byte-by-byte (least significant
				   byte first) to make sure we abort
				   cleanly when the xsize is truncated
				   after the first byte. */
				uint16_t xsize = 0;

				if (c-compr < comprlen) {
					xsize += *c;
					c++;
				}
				if (c-compr < comprlen) {
					xsize += *c << 8;
					c++;
				}

				c += xsize;
			}

			if (flags & (1 << 3)) {
				/* A null terminated filename */

				while ((c - compr) < comprlen && *c != '\0') {
					c++;
				}

				c++;
			}

			if (flags & (1 << 4)) {
				/* A null terminated comment */

				while ((c - compr) < comprlen && *c != '\0') {
					c++;
				}

				c++;
			}


			if (c - compr > comprlen) {
				ZLIB_PREFIX(inflateEnd)(strm);
				g_free(strm);
				wmem_free(NULL, compr);
				g_free(strmbuf);
				return NULL;
			}
			/* Drop gzip header */
			comprlen -= (int) (c - compr);
			next = c;

			ZLIB_PREFIX(inflateReset)(strm);
			strm->next_in   = next;
			strm->avail_in  = comprlen;

			ZLIB_PREFIX(inflateEnd)(strm);
			ZLIB_PREFIX(inflateInit2)(strm, wbits);
			inits_done++;
		} else if (err == Z_DATA_ERROR && uncompr == NULL &&
			inits_done <= 3) {

			/*
			 * Re-init the stream with a negative
			 * MAX_WBITS. This is necessary due to
			 * some servers (Apache) not sending
			 * the deflate header with the
			 * content-encoded response.
			 */
			wbits = -MAX_WBITS;

			ZLIB_PREFIX(inflateReset)(strm);

			strm->next_in   = next;
			strm->avail_in  = comprlen;

			ZLIB_PREFIX(inflateEnd)(strm);
			memset(strmbuf, '\0', bufsiz);
			strm->next_out  = strmbuf;
			strm->avail_out = bufsiz;

			err = ZLIB_PREFIX(inflateInit2)(strm, wbits);

			inits_done++;

			if (err != Z_OK) {
				g_free(strm);
				g_free(strmbuf);
				wmem_free(NULL, compr);
				g_free(uncompr);

				return NULL;
			}
		} else {
			ZLIB_PREFIX(inflateEnd)(strm);
			g_free(strm);
			g_free(strmbuf);

			if (uncompr == NULL) {
				wmem_free(NULL, compr);
				return NULL;
			}

			break;
		}
	}

	ws_debug("inflate() total passes: %u\n", inflate_passes);
	ws_debug("bytes  in: %u\nbytes out: %u\n\n", bytes_in, bytes_out);

	if (uncompr != NULL) {
		uncompr_tvb =  tvb_new_real_data(uncompr, bytes_out, bytes_out);
		tvb_set_free_cb(uncompr_tvb, g_free);
	}
	wmem_free(NULL, compr);
	return uncompr_tvb;
}
#else
tvbuff_t *
tvb_uncompress_zlib(tvbuff_t *tvb _U_, const int offset _U_, int comprlen _U_)
{
	return NULL;
}
#endif

tvbuff_t *
tvb_child_uncompress_zlib(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int comprlen)
{
	tvbuff_t *new_tvb = tvb_uncompress_zlib(tvb, offset, comprlen);
	if (new_tvb)
		tvb_set_child_real_data_tvbuff (parent, new_tvb);
	return new_tvb;
}

tvbuff_t *
tvb_uncompress(tvbuff_t *tvb, const int offset, int comprlen)
{
	return tvb_uncompress_zlib(tvb, offset, comprlen);
}

tvbuff_t *
tvb_child_uncompress(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int comprlen)
{
	return tvb_child_uncompress_zlib(parent, tvb, offset, comprlen);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
