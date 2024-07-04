/* packet-cose.h
 * Definitions for CBOR Object Signing and Encryption (COSE) dissection
 * References:
 *     RFC 9052: https://tools.ietf.org/html/rfc9052
 *
 * Copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef __PACKET_COSE_H__
#define __PACKET_COSE_H__

#include <glib.h>

/**
 * COSE message dissectors are registered multiple ways:
 * 1. The unit-keyed dissector table "cose.msgtag" with keys being
 *    IANA-registered CBOR tag values (e.g., 18 is COSE_Sign1).
 * 2. The string-keyed dissector table "media_type" with keys being
 *    IANA-registered media type IDs
 *    (e.g., application/cose; cose-type="cose-sign1" is COSE_Sign1).
 * 3. The registered dissectors for names "cose" and message names in
 *    all-lowercase form (e.g., "cose_sign1").
 * There is currently no CoAP dissector table to register with.
 *
 * COSE message dissectors use the tag (wscbor_tag_t *) value, if used to
 * discriminate the message type, as the user data pointer.
 *
 * COSE header label dissectors are registered with the dissector table
 * "cose.header" and key parameter dissectors with the table "cose.keyparam"
 * both with cose_param_key_t* keys.
 * The header/parameter dissectors use a cose_header_context_t* as the user
 * data pointer.
 *
 * An additional dissector "cose.msg.headers" will dissect an individual
 * header map structure outside of a COSE message.
 */

// A header parameter or key-type parameter key
typedef struct {
    /// The Algorithm or Key Type context or NULL for
    /// all-context keys.
    GVariant *principal;

    /// Label simple value (int or tstr) as variant.
    /// Object owned by this struct.
    GVariant *label;
} cose_param_key_t;

/** Compatible with GHashFunc signature.
 */
unsigned cose_param_key_hash(const void *ptr);

/** Compatible with GEqualFunc signature.
 */
gboolean cose_param_key_equal(const void *a, const void *b);

/** Compatible with GDestroyNotify signature.
 */
void cose_param_key_free(void *ptr);

/// User data for header/key-parameter dissectors
typedef struct {
    /// Principal value (alg or kty) of the map, if defined.
    GVariant *principal;
    /// Current label being processed
    GVariant *label;
} cose_header_context_t;

#endif /* __PACKET_COSE_H__ */
