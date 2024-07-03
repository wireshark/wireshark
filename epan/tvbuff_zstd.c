/* tvbuff_zstd.c
 * Copyright 2022, Kevin Albertson <kevin.eric.albertson [AT] gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Decompress ZSTD: http://facebook.github.io/zstd/
 */

#include "config.h"

#ifdef HAVE_ZSTD
#include <zstd.h>
#endif

#include "proto.h" // DISSECTOR_ASSERT_HINT
#include "tvbuff.h"

#include "tvbuff-int.h" // tvb_add_to_chain

#define MAX_LOOP_ITERATIONS 100

tvbuff_t *tvb_uncompress_zstd(tvbuff_t *tvb, const int offset, int comprlen)
{
#ifndef HAVE_ZSTD
    // Cast to void to silence unused warnings.
    (void)tvb;
    (void)offset;
    (void)comprlen;
    return NULL;
#else
    ZSTD_inBuffer input = {tvb_memdup(NULL, tvb, offset, comprlen), comprlen, 0};
    ZSTD_DStream *zds = ZSTD_createDStream();
    size_t rc = 0;
    uint8_t *uncompr = NULL;
    size_t uncompr_len = 0;
    bool ok = false;
    int count = 0;

    // ZSTD does not consume the last byte of the frame until it has flushed all of the decompressed data of the frame.
    // Therefore, loop while there is more input.
    ZSTD_outBuffer output = {g_malloc(ZSTD_DStreamOutSize()), ZSTD_DStreamOutSize(), 0};
    while (input.pos < input.size && count < MAX_LOOP_ITERATIONS)
    {
        rc = ZSTD_decompressStream(zds, &output, &input);
        if (ZSTD_isError(rc))
        {
            goto end;
        }

        if (output.pos > 0)
        {
            if (!uncompr)
            {
                DISSECTOR_ASSERT (uncompr_len == 0);
                uncompr = g_malloc(output.pos);
            } else {
                uncompr = g_realloc(uncompr, uncompr_len + output.pos);
            }
            memcpy (uncompr + uncompr_len, output.dst, output.pos);
            uncompr_len += output.pos;
            // Reset the output buffer.
            output.pos = 0;
        }
        count++;
        DISSECTOR_ASSERT_HINT(count < MAX_LOOP_ITERATIONS, "MAX_LOOP_ITERATIONS exceeded");
    }
    if (rc > 0)
    {
        // There is extra data that was not decompressed.
        goto end;
    }

    ok = true;
end:
    g_free((void *)output.dst);
    wmem_free(NULL, (void *)input.src);
    ZSTD_freeDStream(zds);
    if (ok)
    {
        tvbuff_t *uncompr_tvb;
        uncompr_tvb = tvb_new_real_data (uncompr, (unsigned)uncompr_len, (unsigned)uncompr_len);
        tvb_set_free_cb (uncompr_tvb, g_free);
        return uncompr_tvb;
    }

    if (uncompr)
    {
        g_free (uncompr);
    }

    return NULL;
#endif /* HAVE_ZSTD */
}

tvbuff_t *tvb_child_uncompress_zstd(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int comprlen)
{
    tvbuff_t *uncompressed = tvb_uncompress_zstd(tvb, offset, comprlen);
    if (!uncompressed)
    {
        return uncompressed;
    }
    tvb_add_to_chain(parent, uncompressed);
    return uncompressed;
}
