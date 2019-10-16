/* tvbuff_brotli.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <glib.h>

#include <string.h>

#ifdef HAVE_BROTLI
#include <brotli/decode.h>
#endif

#include "tvbuff.h"

#ifdef HAVE_BROTLI

/*
 * 512KiB is the buffer size used by the brotli tool, so we
 * use that too.
 */
#define TVB_BROTLI_BUFSIZ (1 << 19)

static void*
brotli_g_malloc_wrapper(void *opaque _U_, size_t size)
{
    return g_malloc(size);
}

static void
brotli_g_free_wrapper(void *opaque _U_, void *address)
{
    g_free(address);
}

/*
 * Uncompresses a brotli compressed packet inside a message of tvb at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 */

tvbuff_t *
tvb_uncompress_brotli(tvbuff_t *tvb, const int offset, int comprlen)
{
    guint8              *compr;
    guint8              *uncompr        = NULL;
    tvbuff_t            *uncompr_tvb;
    BrotliDecoderState  *decoder;
    guint8              *strmbuf;
    const size_t         bufsiz         = TVB_BROTLI_BUFSIZ;
    size_t               available_in;
    const guint8        *next_in;
    size_t               available_out;
    guint8              *next_out;
    size_t               total_out;
    guint                needs_more_output;
    guint                finished;

    if (tvb == NULL || comprlen <= 0) {
        return NULL;
    }

    compr = (guint8 *)tvb_memdup(NULL, tvb, offset, comprlen);
    if (compr == NULL) {
        return NULL;
    }

    decoder = BrotliDecoderCreateInstance(
      &brotli_g_malloc_wrapper /*alloc_func*/,
      &brotli_g_free_wrapper /*free_func*/,
      NULL /*opaque*/);
    if (decoder == NULL) {
        wmem_free(NULL, compr);
        return NULL;
    }
    strmbuf = (guint8 *)g_malloc(bufsiz);

    available_in = comprlen;
    next_in = compr;
    total_out = 0;
    needs_more_output = 0;
    finished = 0;
    while (available_in > 0 || needs_more_output) {
        needs_more_output = 0;
        available_out = bufsiz;
        next_out = strmbuf;

        BrotliDecoderResult result = BrotliDecoderDecompressStream(
          decoder, &available_in, &next_in, &available_out, &next_out, &total_out);
        switch (result) {
        case BROTLI_DECODER_RESULT_SUCCESS:
            if (available_in > 0) {
                goto cleanup;
            }
            finished = 1;
            break;
        case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
            needs_more_output = 1;
            break;
        case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
            /*
             * It's possible that not enough frames were captured
             * to decompress this fully, so return what we've done
             * so far, if any.
             */
            break;
        case BROTLI_DECODER_RESULT_ERROR:
        default:
            goto cleanup;
        }

        /*
         * Check if decompressed size is too large.
         */
        if (total_out > G_MAXINT) {
            goto cleanup;
        }

        /*
         * BrotliDecoderDecompressStream sets available_out to the number of bytes
         * left unused from the buffer. But we are interested in the bytes it wrote
         * to the buffer in this pass, so we calculate pass_out.
         */
        size_t pass_out = bufsiz - available_out;
        if (pass_out > 0) {
            uncompr = (guint8 *)g_realloc(uncompr, total_out);
            memcpy(uncompr + (total_out - pass_out), strmbuf, pass_out);
        }
    }

    if (uncompr == NULL) {
        /*
         * This is for the case when the validly decompressed
         * length is 0.
         */
        if (finished) {
            uncompr = (guint8 *)g_strdup("");
        } else {
            goto cleanup;
        }
    }

    uncompr_tvb = tvb_new_real_data((guint8 *)uncompr, (guint)total_out, (gint)total_out);
    tvb_set_free_cb(uncompr_tvb, g_free);

    g_free(strmbuf);
    wmem_free(NULL, compr);
    BrotliDecoderDestroyInstance(decoder);
    return uncompr_tvb;

cleanup:
    g_free(strmbuf);
    g_free(uncompr);
    wmem_free(NULL, compr);
    BrotliDecoderDestroyInstance(decoder);
    return NULL;
}
#else
tvbuff_t *
tvb_uncompress_brotli(tvbuff_t *tvb _U_, const int offset _U_, int comprlen _U_)
{
    return NULL;
}
#endif

tvbuff_t *
tvb_child_uncompress_brotli(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int comprlen)
{
    tvbuff_t *new_tvb = tvb_uncompress_brotli(tvb, offset, comprlen);
    if (new_tvb)
        tvb_set_child_real_data_tvbuff(parent, new_tvb);
    return new_tvb;
}

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
