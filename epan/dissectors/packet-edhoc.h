/* packet-cose.h
 * Definitions for Ephemeral Diffie-Hellman Over COSE (EDHOC) dissection
 * References:
 *     RFC 9528: https://tools.ietf.org/html/rfc9528
 *
 * Copyright 2024-2025, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#ifndef __PACKET_EDHOC_H__
#define __PACKET_EDHOC_H__

#include "packet-cose.h"
#include <epan/conversation.h>
#include <glib.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * The EDHOC message dissectors are expected to be used embedded within another
 * protocol, and are registered as media types defined RFC 9528 for
 * off-the-shelf use within HTTP and CoAP protocols.
 *
 * When embedding EDHOC, the outer protocol needs to:
 *  1. Construct a new EDHOC session state using edhoc_state_new()
 *  2. Call into the "edhoc" dissector using the state as user data.
 *  3. Inspect the session state to see which messages have been processed
 *     so far and take protocol-specific action.
 *  4. Allow the session state to expire when the capture file is closed,
 *     or call edhoc_state_free() as needed.
 *
 * Additionally, the External Authorization Data (EAD) labels can be registered
 * with the dissector table "edhoc.ead" using int64_t * keys (but only
 * non-negative values).
 * These registrations always use the unsigned form of the label, which
 * the EDHOC dissector computes by taking the absoute value of the actual label.
 * Each EAD sub-dissector will be passed the edhoc_session_t * as its user data.
 */

/// State of one or more sessions within a conversation
typedef struct edhoc_state_t {
    /// Parent conversation for these sessions
    conversation_t *conv;
    /// An indicator of whether a CID is expected to be prepended
    bool prepend_cid;

    /// Sessions in this state, values are edhoc_session_t *
    wmem_list_t *session_list;
    /// Sessions organized by frame number ranges which they cover.
    wmem_tree_t *session_map;
} edhoc_state_t;

/** State of a session across multiple messages.
 * A new session begins when a message 1 must be present, including after
 * an earlier session has an error or message 4.
 */
typedef struct {
    /// The parent protocol state
    edhoc_state_t *parent;
    /// The session index within the state, starting at zero
    uint64_t sess_idx;

    /// True if message 1 has been seen
    bool seen_msg1;
    /// The frame of message 1 if #seen_msg1 is true
    uint32_t frame_msg1;
    /// True if message 2 has been seen
    bool seen_msg2;
    /// The frame of message 2 if #seen_msg2 is true
    uint32_t frame_msg2;
    /// True if message 3 has been seen
    bool seen_msg3;
    /// The frame of message 3 if #seen_msg3 is true
    uint32_t frame_msg3;
    /// True if message 4 has been seen
    bool seen_msg4;
    /// The frame of message 4 if #seen_msg4 is true
    uint32_t frame_msg4;

    /* Errors can only be present after #seen_msg1 is true.
     * But they can be sent from either side of the session.
     */
    /// True if an EDHOC error message has been seen so far
    bool seen_error;
    /// The frame of the first error if #seen_error is true
    uint32_t frame_error;

    /// The selected method from message 1
    int64_t method;
    /// The selected cipher suite from message 1
    int64_t suite;
    /// Lookup into a static table for #suite
    const struct edhoc_cs_s *found_cs;
    /// Lookup into COSE table for AEAD properties
    const cose_aead_props_t *aead_props;
    /// Lookup into COSE table for hash properties
    const cose_hash_props_t *hash_props;
    /// Lookup into COSE table for ECC properties
    const cose_ecc_props_t *ecc_props;

    /// Pointer to extracted message 1 G_X owned by this session
    GBytes *gx_data;
    /// Pointer to external keyfile PRK data
    GBytes *prk_2e;
    /// Pointer to external keyfile PRK data
    GBytes *prk_3e2m;
    /// Pointer to external keyfile PRK data
    GBytes *prk_4e3m;
    /// Pointer to derived data owned by this session
    GBytes *prk_out;
    /// Pointer to derived data owned by this session
    GBytes *prk_exporter;

} edhoc_session_t;

/** Create a new external state.
 * The state will be freed when the capture is closed or edhoc_state_free()
 * is called before that.
 * @param[in] conv The parent conversation for the EDHOC session, which
 * can be used to correlate other protocol state.
 * @return Pointer to the state, which will have a lifetime no longer
 * than the capture file load.
 */
edhoc_state_t * edhoc_state_new(conversation_t *conv);

/** Free an allocated state.
 * @param[in] state Pointer to the instance.
 */
void edhoc_state_free(edhoc_state_t *state);

/** An application-visible exporter per Section 4.2 of RFC 9528.
 *
 * @param[in] sess The session being exported from.
 * @param label The exporter label from IANA registry.
 * @param[in] ctx The context byte string.
 * @param length The size of the output key material.
 * @return A new bytes instance for which ownership is taken by the caller
 * and can be freed with g_bytes_unref().
 * Errors are indicated by a null return value.
 */
GBytes * edhoc_exporter_kdf(const edhoc_session_t *sess, int64_t label, GBytes *ctx, size_t length);

#endif /* __PACKET_EDHOC_H__ */
