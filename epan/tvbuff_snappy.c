/* tvbuff_snappy.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#ifdef HAVE_SNAPPY
#include <snappy-c.h>
#endif

#include "tvbuff.h"

#ifdef HAVE_SNAPPY

/*
 * Uncompresses a snappy compressed packet inside a message of tvb at offset with
 * length comprlen.  Returns an uncompressed tvbuffer if uncompression
 * succeeded or NULL if uncompression failed.
 */

tvbuff_t *
tvb_uncompress_snappy(tvbuff_t *tvb, const int offset, int comprlen)
{
    tvbuff_t *uncompr_tvb = NULL;
    unsigned char *decompressed_buffer = NULL;
    size_t orig_size = 0;
    snappy_status ret;
    const void *compr_ptr;

    if (tvb == NULL || comprlen <= 0 || comprlen > tvb_captured_length_remaining(tvb, offset)) {
        return NULL;
    }

    compr_ptr = tvb_get_ptr(tvb, offset, comprlen);
    ret = snappy_uncompressed_length(compr_ptr, comprlen, &orig_size);

    if (ret == SNAPPY_OK) {
        decompressed_buffer = (unsigned char *)g_malloc(orig_size);

        ret = snappy_uncompress(compr_ptr, comprlen, decompressed_buffer, &orig_size);

        if (ret == SNAPPY_OK) {
            uncompr_tvb = tvb_new_real_data(decompressed_buffer, (uint32_t)orig_size, (uint32_t)orig_size);
            tvb_set_free_cb(uncompr_tvb, g_free);
        } else {
            g_free(decompressed_buffer);
        }
    }

    return uncompr_tvb;
}
#else
tvbuff_t *
tvb_uncompress_snappy(tvbuff_t *tvb _U_, const int offset _U_, int comprlen _U_)
{
    return NULL;
}
#endif

tvbuff_t *
tvb_child_uncompress_snappy(tvbuff_t *parent, tvbuff_t *tvb, const int offset, int comprlen)
{
    tvbuff_t *new_tvb = tvb_uncompress_snappy(tvb, offset, comprlen);
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
