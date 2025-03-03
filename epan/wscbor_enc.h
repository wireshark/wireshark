/** @file
 * Definitions for the Wireshark CBOR item encoding API.
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

#ifndef __WSCBOR_ENC_H__
#define __WSCBOR_ENC_H__

#include <ws_symbol_export.h>
#include <glib.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Add an item containing an undefined value.
 * @param[in,out] buf The buffer to append to.
 */
WS_DLL_PUBLIC
void wscbor_enc_undefined(GByteArray *buf);

/** Add an item containing a null value.
 * @param[in,out] buf The buffer to append to.
 */
WS_DLL_PUBLIC
void wscbor_enc_null(GByteArray *buf);

/** Add an item containing a bool value.
 * @param[in,out] buf The buffer to append to.
 * @param value The value to write.
 */
WS_DLL_PUBLIC
void wscbor_enc_boolean(GByteArray *buf, bool value);

/** Add an item containing an unsigned int.
 * @param[in,out] buf The buffer to append to.
 * @param value The value to write.
 */
WS_DLL_PUBLIC
void wscbor_enc_uint64(GByteArray *buf, uint64_t value);

/** Add an item containing an unsigned or negative int.
 * @param[in,out] buf The buffer to append to.
 * @param value The value to write.
 */
WS_DLL_PUBLIC
void wscbor_enc_int64(GByteArray *buf, int64_t value);

/** Add an item containing a definite length byte string.
 * @param[in,out] buf The buffer to append to.
 * @param[in] ptr The data to write.
 * @param len The length of the @c data to write.
 * This MUST be no longer than the actual size of data.
 */
WS_DLL_PUBLIC
void wscbor_enc_bstr(GByteArray *buf, const uint8_t *ptr, size_t len);

/** @overload
 * This is a shortcut to adding a byte string stolen from an existing array.
 * This can be useful to embed encoded CBOR into a byte string
 * (see CDDL operators ".cbor" and ".cborseq" from Section 3.8.4 of
 * RFC 8610).
 * @param[in,out] buf The buffer to append to.
 * @param[in,out] src The buffer to steal from.
 */
WS_DLL_PUBLIC
void wscbor_enc_bstr_bytearray(GByteArray *buf, GByteArray *src);

/** Add an item containing a definite length text string.
 * @param[in,out] buf The buffer to append to.
 * @param[in] ptr The null-terminated text to write.
 */
WS_DLL_PUBLIC
void wscbor_enc_tstr(GByteArray *buf, const char *ptr);

/** Add an array header with a definite length.
 * @note The items which follow this header must agree with the definite length.
 * @param[in,out] buf The buffer to append to.
 * @param len The number of items of the array.
 */
WS_DLL_PUBLIC
void wscbor_enc_array_head(GByteArray *buf, size_t len);

/** Add a map header with a definite length.
 * @note The items which follow this header must agree with the definite length.
 * @param[in,out] buf The buffer to append to.
 * @param len The number of pairs in the map.
 */
WS_DLL_PUBLIC
void wscbor_enc_map_head(GByteArray *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* __WSCBOR_ENC_H__ */
