/** @file
 * Wireshark CBOR item encoding API.
 * References:
 *     RFC 8949: https://tools.ietf.org/html/rfc8949
 *
 * Copyright 2017, Malisa Vucinic <malishav@gmail.com>
 * Copyright 2019-2025, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

// Use typedefs from wscbor header
#include <epan/wscbor.h>
#include "wscbor_enc.h"

/** Encode a CBOR head using the same strategy as QCBOR double loop.
 */
static void wscbor_enc_head(GByteArray *buf, uint8_t type_major, uint64_t arg) {
    const uint8_t maj_mask = type_major << 5;

    if (arg <= 0x17 ) {
        const uint8_t tmp[1] = { maj_mask | (uint8_t)arg };
        g_byte_array_append(buf, tmp, sizeof(tmp));
    }
    else {
        static const unsigned inc_size[] = {1, 1, 2, 4};
        // buffer maximum possible head size and right-align
        uint8_t tmp[9];
        uint8_t *curs = tmp + 9;
        unsigned used = 0;

        uint8_t type_minor = 0x17;
        // Each inner loop trims the arg by one byte and its size is 8 bytes
        for (int ix = 0; arg; ++ix) {
            // write entire increment at each step
            const unsigned next = inc_size[ix];
            for (unsigned jx = 0; jx < next; ++jx) {
                *--curs = (uint8_t)(arg & 0xFF);
                arg >>= 8;
                ++used;
            }
            ++type_minor;
        }

        // leading octet
        *--curs = maj_mask | type_minor;
        ++used;

        g_byte_array_append(buf, curs, used);
    }
}

void wscbor_enc_undefined(GByteArray *buf) {
    wscbor_enc_head(buf, CBOR_TYPE_FLOAT_CTRL, CBOR_CTRL_UNDEF);
}

void wscbor_enc_null(GByteArray *buf) {
    wscbor_enc_head(buf, CBOR_TYPE_FLOAT_CTRL, CBOR_CTRL_NULL);
}

void wscbor_enc_boolean(GByteArray *buf, bool value) {
    wscbor_enc_head(buf, CBOR_TYPE_FLOAT_CTRL, value ? CBOR_CTRL_TRUE : CBOR_CTRL_FALSE);
}

void wscbor_enc_uint64(GByteArray *buf, uint64_t value) {
    wscbor_enc_head(buf, CBOR_TYPE_UINT, value);
}

void wscbor_enc_int64(GByteArray *buf, int64_t value) {
    if (value >= 0) {
        uint64_t arg = value;
        wscbor_enc_head(buf, CBOR_TYPE_UINT, arg);
    }
    else {
        uint64_t arg = -1 - value;
        wscbor_enc_head(buf, CBOR_TYPE_NEGINT, arg);
    }
}

void wscbor_enc_bstr(GByteArray *buf, const uint8_t *ptr, size_t len) {
    wscbor_enc_head(buf, CBOR_TYPE_BYTESTRING, len);
    if (len && (len < UINT_MAX)) {
        g_byte_array_append(buf, ptr, (unsigned)len);
    }
}

void wscbor_enc_bstr_bytearray(GByteArray *buf, GByteArray *src) {
    size_t len;
    uint8_t *ptr = g_byte_array_steal(src, &len);
    wscbor_enc_bstr(buf, ptr, len);
    g_free(ptr);
}

void wscbor_enc_tstr(GByteArray *buf, const char *ptr) {
    // exclude terminating null from CBOR
    const size_t len = ptr ? strlen(ptr) : 0;
    wscbor_enc_head(buf, CBOR_TYPE_STRING, len);
    if (len && (len < UINT_MAX)) {
        g_byte_array_append(buf, ptr, (unsigned)len);
    }
}

void wscbor_enc_array_head(GByteArray *buf, size_t len) {
    wscbor_enc_head(buf, CBOR_TYPE_ARRAY, len);
}

void wscbor_enc_map_head(GByteArray *buf, size_t len) {
    wscbor_enc_head(buf, CBOR_TYPE_MAP, len);
}
