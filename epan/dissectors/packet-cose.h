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

#include <ws_symbol_export.h>
#include <glib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * COSE message dissectors are registered multiple ways:
 * 1. The unit-keyed dissector table "cose.msgtag" with keys being
 *    IANA-registered CBOR tag values (e.g., 18 is COSE_Sign1).
 * 2. The string-keyed dissector table "media_type" with the IANA-registered
 *    key "application/cose" and subtypes registered in dissector table
 *    "cose.mediasub" (e.g., "cose-sign1" is COSE_Sign1).
 * 3. The registered dissectors for names "cose" and message names in
 *    all-lowercase form (e.g., "cose_sign1").
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
WS_DLL_PUBLIC
unsigned cose_param_key_hash(const void *ptr);

/** Compatible with GEqualFunc signature.
 */
WS_DLL_PUBLIC
gboolean cose_param_key_equal(const void *a, const void *b);

/** Compatible with GDestroyNotify signature.
 */
WS_DLL_PUBLIC
void cose_param_key_free(void *ptr);

/// User data for header/key-parameter dissectors
typedef struct {
    /// Principal value (alg or kty) of the map, if defined.
    GVariant *principal;
    /// Current label being processed
    GVariant *label;
} cose_header_context_t;

/// Derived properties of hash algorithm
typedef struct {
    /// The algorithm code point
    int64_t value;
    /// GCrypt hash enumeration
    int gcry_hash;
    /** Output length in bytes.
     * This can be shorter than the native output from the hash algorithm
     * to indicate truncated output.
     */
    unsigned out_len;
} cose_hash_props_t;

/** Get properties for a specific algorithm code point.
 *
 * @param alg The code point from "COSE Algorithms" IANA registry.
 * @return The algorithm properties, or NULL if not a hash code point.
 */
WS_DLL_PUBLIC
const cose_hash_props_t * cose_get_hash_props(int64_t alg);

/// Derived properties of AEAD encryption algorithm
typedef struct {
    /// The algorithm code point
    int64_t value;
    /// GCrypt cipher enumeration
    int gcry_cipher;
    /// GCrypt mode enumeration
    int gcry_mode;
    /// Key length in bytes
    unsigned key_len;
    /// IV length in bytes
    unsigned iv_len;
    /// Tag length in bytes
    unsigned tag_len;
} cose_aead_props_t;

/** Get properties for a specific algorithm code point.
 *
 * @param alg The code point from "COSE Algorithms" IANA registry.
 * @return The algorithm properties, or NULL if not an AEAD code point.
 */
WS_DLL_PUBLIC
const cose_aead_props_t * cose_get_aead_props(int64_t alg);

/// Derived properties of AEAD encryption algorithm
typedef struct {
    /// The algorithm code point
    int64_t value;
    /// Public key encoded size in bytes
    unsigned pubkey_len;
} cose_ecc_props_t;

/** Get properties for a specific algorithm code point.
 *
 * @param crv The code point from "COSE Elliptic Curves" IANA registry.
 * @return The curve properties, or NULL if not a known code point.
 */
WS_DLL_PUBLIC
const cose_ecc_props_t * cose_get_ecc_props(int64_t crv);

#ifdef __cplusplus
}
#endif

#endif /* __PACKET_COSE_H__ */
