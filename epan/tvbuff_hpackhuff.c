/* @file
 * Decompression of the Huffman encoding used for HTTP fields in HPACK (HTTP/2)
 * and QPACK (HTTP/3)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/tvbuff.h>
#include <epan/nghttp2_hd_huffman.h>

static wmem_strbuf_t *
get_hpack_huffman_strbuf(wmem_allocator_t *scope, const uint8_t *ptr, size_t len)
{
    wmem_strbuf_t *strbuf;
    strbuf = wmem_strbuf_new_sized(scope, len + 1);

    nghttp2_huff_decode node = {0, 0};
    const nghttp2_huff_decode *nodep = &node;

    while (len > 0) {
        uint8_t ch = *ptr++;

        nodep = &huff_decode_table[nodep->fstate & 0x1ff][ch >> 4];
        if (nodep->fstate & NGHTTP2_HUFF_SYM) {
            wmem_strbuf_append_c(strbuf, nodep->sym);
        }

        nodep = &huff_decode_table[nodep->fstate & 0x1ff][ch & 0xf];
        if (nodep->fstate & NGHTTP2_HUFF_SYM) {
            wmem_strbuf_append_c(strbuf, nodep->sym);
        }

        len--;
    }

    if (!(nodep->fstate & NGHTTP2_HUFF_ACCEPTED)) {
        wmem_strbuf_destroy(strbuf);
        return NULL;
    }

    return strbuf;
}

wmem_strbuf_t *
tvb_get_hpack_huffman_strbuf(wmem_allocator_t *scope, tvbuff_t *tvb, const int offset, const int len)
{
    return get_hpack_huffman_strbuf(scope, tvb_get_ptr(tvb, offset, len), len);
}

tvbuff_t*
tvb_child_uncompress_hpack_huff(tvbuff_t* parent, int offset, int length)
{
    tvbuff_t* tvb = NULL;
    wmem_strbuf_t *strbuf;
    char* data;
    size_t len;

    strbuf = tvb_get_hpack_huffman_strbuf(NULL, parent, offset, length);

    if (strbuf) {
        len = wmem_strbuf_get_len(strbuf);
        data = wmem_strbuf_finalize(strbuf);

        tvb = tvb_new_child_real_data(parent, (const uint8_t*)data, (unsigned)len, (int)len);

        tvb_set_free_cb(tvb, g_free);
    }

    return tvb;
}
