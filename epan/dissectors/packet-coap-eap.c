/* packet-coap-eap.c
 * Routines for CoAP-EAP (RFC 9820) dissection
 * References:
 *     RFC 9820: https://tools.ietf.org/html/rfc9820
 *     RFC 7252: https://tools.ietf.org/html/rfc7252
 *     RFC 3748: https://tools.ietf.org/html/rfc3748
 *     RFC 8949: https://tools.ietf.org/html/rfc8949
 *
 * Copyright 2025, Juan Carlos Valera Lopez <juancarlosvalera999@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "packet-coap-eap"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/wscbor.h>
#include <wsutil/value_string.h>
#include <wsutil/wmem/wmem_strbuf.h>
#include "packet-media-type.h"

/* ------------------------------------------------------------------ */
/* Forward declarations                                                */
/* ------------------------------------------------------------------ */

void proto_register_coap_eap(void);
void proto_reg_handoff_coap_eap(void);

static int dissect_coap_eap_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);  /* data: media_content_info_t* */
static int dissect_coap_eap_port(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_);
static int dissect_coap_eap_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_cbor_info(tvbuff_t *tvb, packet_info *pinfo, int offset, int len, proto_tree *tree);
static void coap_eap_prefs_apply(void);

/* ------------------------------------------------------------------ */
/* Protocol handle                                                     */
/* ------------------------------------------------------------------ */

static int proto_coap_eap;
static module_t *coap_eap_module;
static expert_module_t *expert_coap_eap;

/* Dissector handles */
static dissector_handle_t coap_eap_media_handle;
static dissector_handle_t coap_eap_port_handle;
static dissector_handle_t eap_handle;
static dissector_handle_t coap_handle;

/* Subtree handles */
static int ett_coap_eap;
static int ett_coap_eap_eap;
static int ett_coap_eap_cbor;

/* Header field handles */
static int hf_coap_eap_trigger_uri;
static int hf_coap_eap_eap;
static int hf_coap_eap_cbor_info;
static int hf_coap_eap_cipher_suites;
static int hf_coap_eap_rid_c;
static int hf_coap_eap_rid_i;
static int hf_coap_eap_lifetime;
static int hf_coap_eap_cbormap_key;

/* Expert info handles */
static expert_field ei_coap_eap_payload_too_short;
static expert_field ei_coap_eap_eap_length_invalid;
static expert_field ei_coap_eap_eap_length_exceeds;
static expert_field ei_coap_eap_cbor_malformed;
static expert_field ei_coap_eap_cbor_not_map;

/* Preferences */
static unsigned udp_port_pref = 0;
static unsigned current_udp_port = 0;

/* ------------------------------------------------------------------ */
/* Value strings                                                       */
/* ------------------------------------------------------------------ */

static const value_string cipher_suite_vals[] = {
    { 0, "AES-CCM-16-64-128, SHA-256" },
    { 1, "A128GCM, SHA-256" },
    { 2, "A256GCM, SHA-384" },
    { 3, "ChaCha20/Poly1305, SHA-256" },
    { 4, "ChaCha20/Poly1305, SHAKE256" },
    { 0, NULL }
};

static const value_string cbormap_key_vals[] = {
    { 1, "Cipher Suites" },
    { 2, "RID-C" },
    { 3, "RID-I" },
    { 4, "Session-Lifetime" },
    { 0, NULL }
};

/* ------------------------------------------------------------------ */
/* CBOR parser — uses Wireshark's wscbor library                       */
/* ------------------------------------------------------------------ */

/**
 * Parse a CoAP-EAP_Info CBOR map (RFC 9820 Section 5).
 *
 * Uses Wireshark's built-in wscbor API (same as packet-cbor.c and
 * packet-edhoc.c). The CBOR map structure is:
 *
 *   CoAP-EAP_Info = {
 *     ? 1 : [+ int],   ; Cipher Suites
 *     ? 2 : bstr,      ; RID-C
 *     ? 3 : bstr,      ; RID-I
 *     ? 4 : uint       ; Session-Lifetime
 *   }
 *
 * \param tvb    The tvbuff containing the CBOR data.
 * \param pinfo  Packet info for memory allocation and expert info.
 * \param offset Start offset within \p tvb.
 * \param len   Total bytes available (unused; wscbor reads via tvb bounds).
 * \param tree  Protocol tree to add items to.
 * \return Offset after the CBOR map, or -1 on error.
 */
static int
dissect_cbor_info(tvbuff_t *tvb, packet_info *pinfo, int offset, int len, proto_tree *tree)
{
    if (offset < 0 || offset >= len)
        return -1;

    wmem_allocator_t *alloc = pinfo->pool;
    int off = offset;
    int map_start = offset;

    /* Read the outer CBOR map header */
    wscbor_chunk_t *map_chunk = wscbor_chunk_read(alloc, tvb, &off);

    /* Add the CoAP-EAP_Info subtree (use standard proto_tree_add_item
     * with -1 length; corrected by proto_item_set_len at end) */
    proto_item *cbor_item = proto_tree_add_item(tree, hf_coap_eap_cbor_info,
        tvb, map_start, -1, ENC_NA);
    proto_tree *cbor_tree = proto_item_add_subtree(cbor_item, ett_coap_eap_cbor);

    /* Check for CBOR-level errors on the map header */
    if (wscbor_has_errors(map_chunk)) {
        wscbor_chunk_mark_errors(pinfo, cbor_item, map_chunk);
        wscbor_chunk_free(map_chunk);
        proto_item_set_len(cbor_item, off - map_start);
        return off;
    }

    /* Require the outer item to be a definite-length map */
    if (!wscbor_require_map(map_chunk) || map_chunk->type_minor == 31) {
        proto_tree_add_expert_format(cbor_tree, pinfo, &ei_coap_eap_cbor_not_map,
            tvb, map_chunk->start, map_chunk->head_length,
            "Expected definite CBOR map, got major type %u", map_chunk->type_major);
        wscbor_chunk_free(map_chunk);
        return -1;
    }

    uint64_t pair_count = map_chunk->head_value;

    /* Process each key-value pair */
    for (uint64_t i = 0; i < pair_count; i++) {
        if (off >= len)
            break;

        /* Read map key (must be unsigned integer per RFC 9820) */
        wscbor_chunk_t *key_chunk = wscbor_chunk_read(alloc, tvb, &off);
        uint64_t *key_val = wscbor_require_uint64(alloc, key_chunk);

        if (key_val == NULL || wscbor_has_errors(key_chunk)) {
            /* Non-integer or malformed key: skip value */
            wscbor_chunk_free(key_chunk);
            wscbor_skip_next_item(alloc, tvb, &off);
            continue;
        }

        /* Show the key in the tree */
        uint64_t k = *key_val;
        proto_tree_add_uint(cbor_tree, hf_coap_eap_cbormap_key,
            tvb, key_chunk->start, key_chunk->head_length, (uint32_t)k);
        wscbor_chunk_free(key_chunk);

        if (off >= len)
            break;

        switch (k) {
        case 1: {
            /* Cipher Suites: CBOR array of unsigned integers.
             * RFC 9820 uses a definite-length array; reject indefinite
             * arrays (type_minor == 31) the same way we reject them for
             * the outer map, so the value offset stays aligned. */
            wscbor_chunk_t *arr_chunk = wscbor_chunk_read(alloc, tvb, &off);
            int cs_start = arr_chunk->start;

            if (!wscbor_require_array(arr_chunk) || arr_chunk->type_minor == 31 ||
                wscbor_has_errors(arr_chunk)) {
                wscbor_chunk_free(arr_chunk);
                break;
            }

            uint64_t cs_count = arr_chunk->head_value;
            wmem_strbuf_t *buf = wmem_strbuf_new_sized(alloc, 128);

            for (uint64_t j = 0; j < cs_count; j++) {
                if (off >= len)
                    break;
                wscbor_chunk_t *cs_chunk = wscbor_chunk_read(alloc, tvb, &off);
                uint64_t *cs_val = wscbor_require_uint64(alloc, cs_chunk);

                if (cs_val != NULL && !wscbor_has_errors(cs_chunk)) {
                    if (j > 0)
                        wmem_strbuf_append_c(buf, ',');
                    wmem_strbuf_append_printf(buf, "%s (%u)",
                        val_to_str_const((uint32_t)*cs_val, cipher_suite_vals, "Unknown"),
                        (uint32_t)*cs_val);
                }
                wscbor_chunk_free(cs_chunk);
            }

            proto_tree_add_string(cbor_tree, hf_coap_eap_cipher_suites,
                tvb, cs_start, off - cs_start, wmem_strbuf_get_str(buf));
            wscbor_chunk_free(arr_chunk);
            break;
        }

        case 2:
        case 3: {
            /* RID-C (key=2) or RID-I (key=3): byte string */
            int hf_id = (k == 2) ? hf_coap_eap_rid_c : hf_coap_eap_rid_i;
            wscbor_chunk_t *rid_chunk = wscbor_chunk_read(alloc, tvb, &off);

            if (wscbor_require_major_type(rid_chunk, CBOR_TYPE_BYTESTRING) &&
                !wscbor_has_errors(rid_chunk)) {
                tvbuff_t *bstr_tvb = wscbor_require_bstr(alloc, rid_chunk);
                if (bstr_tvb) {
                    proto_tree_add_item(cbor_tree, hf_id,
                        bstr_tvb, 0, tvb_captured_length(bstr_tvb), ENC_NA);
                }
            }
            wscbor_chunk_free(rid_chunk);
            break;
        }

        case 4: {
            /* Session-Lifetime: unsigned integer */
            wscbor_chunk_t *lt_chunk = wscbor_chunk_read(alloc, tvb, &off);
            uint64_t *lt_val = wscbor_require_uint64(alloc, lt_chunk);

            if (lt_val != NULL && !wscbor_has_errors(lt_chunk)) {
                proto_tree_add_uint64(cbor_tree, hf_coap_eap_lifetime,
                    tvb, lt_chunk->start, lt_chunk->head_length, *lt_val);
            }
            wscbor_chunk_free(lt_chunk);
            break;
        }

        default:
            /* Unknown key: skip its value */
            wscbor_skip_next_item(alloc, tvb, &off);
            break;
        }
    }

    proto_item_set_len(cbor_item, off - map_start);
    wscbor_chunk_free(map_chunk);
    return off;
}

/* ------------------------------------------------------------------ */
/* CoAP context extraction (for UDP port path)                        */
/* ------------------------------------------------------------------ */

/**
 * Manually walk CoAP options to extract Content-Format and payload offset.
 *
 * This is needed only when the dissector is invoked via a manually
 * configured UDP port, where the CoAP dissector has not already parsed
 * the packet. In the primary registration path (media_type table),
 * the CoAP dissector handles all option parsing and reassembly.
 *
 * \param tvb  The tvbuff containing the full CoAP packet.
 * \param out_cf   [out] Content-Format value, or -1 if absent.
 * \param out_payload_offset [out] Byte offset of the payload, or -1.
 * \return true if CoAP context was extracted, false on error.
 */
static bool
get_coap_context(tvbuff_t *tvb, int *out_cf, int *out_payload_offset)
{
    *out_cf = -1;
    *out_payload_offset = -1;

    uint32_t len = tvb_captured_length(tvb);
    if (len < 4)
        return false;

    /* Skip 4-byte CoAP header + variable-length token (RFC 7252 Section 3) */
    uint8_t tkl = tvb_get_uint8(tvb, 0) & 0x0F;
    int offset = 4 + tkl;
    if (offset >= (int)len)
        return false;

    int opt_num = 0;

    while (offset < (int)len) {
        uint8_t byte = tvb_get_uint8(tvb, offset);

        if (byte == 0xFF) {
            *out_payload_offset = offset + 1;
            return true;
        }

        offset++;
        int delta = byte >> 4;
        int opt_len = byte & 0x0F;

        /* Extended delta (RFC 7252 Section 3.1) */
        if (delta == 13) {
            if (offset >= (int)len) return false;
            delta = tvb_get_uint8(tvb, offset) + 13;
            offset++;
        } else if (delta == 14) {
            if (offset + 2 > (int)len) return false;
            delta = tvb_get_ntohs(tvb, offset) + 269;
            offset += 2;
        } else if (delta == 15) {
            return false;
        }

        /* Extended length */
        if (opt_len == 13) {
            if (offset >= (int)len) return false;
            opt_len = tvb_get_uint8(tvb, offset) + 13;
            offset++;
        } else if (opt_len == 14) {
            if (offset + 2 > (int)len) return false;
            opt_len = tvb_get_ntohs(tvb, offset) + 269;
            offset += 2;
        } else if (opt_len == 15) {
            return false;
        }

        opt_num += delta;

        if (opt_num == 12) {
            /* Content-Format option */
            if (opt_len == 0)
                *out_cf = 0;
            else if (opt_len == 1)
                *out_cf = tvb_get_uint8(tvb, offset);
            else if (opt_len == 2)
                *out_cf = tvb_get_ntohs(tvb, offset);
        }

        offset += opt_len;
    }

    /* No payload marker found; options exhausted */
    return true;
}

/* ------------------------------------------------------------------ */
/* Common payload dissection                                           */
/* ------------------------------------------------------------------ */

/**
 * Dissect the CoAP-EAP payload (EAP packet + optional CBOR map).
 *
 * This function processes the payload after the CoAP 0xFF marker.
 * The payload starts with an EAP packet (RFC 3748); if there are
 * trailing bytes after the EAP packet, they are parsed as a
 * CoAP-EAP_Info CBOR map (RFC 9820 Section 5).
 *
 * If the first byte is not a valid EAP code (1-6), the payload is
 * treated as a Step 0 trigger URI (plain text).
 *
 * \param tvb   TVB containing only the CoAP payload (after 0xFF marker).
 * \param pinfo Packet info.
 * \param tree  Protocol tree.
 * \return Number of bytes consumed.
 */
static int
dissect_coap_eap_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    unsigned payload_len = tvb_captured_length(tvb);

    if (payload_len == 0)
        return 0;

    proto_item *ti = proto_tree_add_item(tree, proto_coap_eap, tvb, 0, -1, ENC_NA);
    proto_tree *coap_eap_tree = proto_item_add_subtree(ti, ett_coap_eap);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoAP-EAP");

    /*
     * Determine payload type:
     * - If first byte is a valid EAP code (1-6 per RFC 3748 §4.2)
     *   and payload >= 4 bytes, treat as EAP (Steps 1-6).
     * - If first byte looks like EAP but payload < 4 bytes, malformed.
     * - Otherwise, treat as a Step 0 trigger URI (plain text).
     */
    uint8_t first_byte = tvb_get_uint8(tvb, 0);
    if (first_byte >= 1 && first_byte <= 6) {
        if (payload_len < 4) {
            expert_add_info_format(pinfo, ti, &ei_coap_eap_payload_too_short,
                "Payload too short for EAP header (%u bytes, need 4)", payload_len);
            return tvb_captured_length(tvb);
        }
        /* Steps 1-6: EAP packet + optional CBOR */
        uint16_t eap_len = tvb_get_ntohs(tvb, 2);

        if (eap_len < 4) {
            expert_add_info_format(pinfo, ti, &ei_coap_eap_eap_length_invalid,
                "EAP Length %u < 4 (minimum EAP packet size)", eap_len);
            return tvb_captured_length(tvb);
        }

        if (eap_len > payload_len) {
            expert_add_info_format(pinfo, ti, &ei_coap_eap_eap_length_exceeds,
                "EAP Length %u exceeds payload length %u; clamping",
                eap_len, payload_len);
            eap_len = (uint16_t)payload_len;
        }

        /* Create EAP subset TVB and call the native EAP dissector */
        tvbuff_t *eap_tvb = tvb_new_subset_length(tvb, 0, eap_len);
        proto_item *eap_item = proto_tree_add_item(coap_eap_tree, hf_coap_eap_eap,
            eap_tvb, 0, -1, ENC_NA);
        proto_tree *eap_tree = proto_item_add_subtree(eap_item, ett_coap_eap_eap);

        if (eap_handle) {
            /* Save the info column before EAP call */
            const char *pre_eap_text = pinfo->cinfo ? col_get_text(pinfo->cinfo, COL_INFO) : NULL;
            const char *pre_eap = pre_eap_text ? wmem_strdup(pinfo->pool, pre_eap_text) : "";

            call_dissector(eap_handle, eap_tvb, pinfo, eap_tree);

            /* Merge CoAP info with EAP info if different */
            const char *post_eap_text = pinfo->cinfo ? col_get_text(pinfo->cinfo, COL_INFO) : NULL;
            const char *post_eap = post_eap_text ? wmem_strdup(pinfo->pool, post_eap_text) : "";

            if (post_eap[0] != '\0' && pre_eap[0] != '\0' &&
                strcmp(post_eap, pre_eap) != 0 &&
                strncmp(post_eap, pre_eap, (int)strlen(pre_eap)) != 0) {
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s | %s", pre_eap, post_eap);
            }
        }

        col_set_str(pinfo->cinfo, COL_PROTOCOL, "CoAP-EAP");

        /* Parse optional CoAP-EAP_Info CBOR map after EAP */
        if ((unsigned)eap_len < payload_len) {
            int cbor_offset = eap_len;
            volatile int next = -1;
            TRY {
                next = dissect_cbor_info(tvb, pinfo, cbor_offset, (int)payload_len, coap_eap_tree);
            }
            CATCH_BOUNDS_AND_DISSECTOR_ERRORS {
                next = -1;
            }
            ENDTRY;
            if (next < 0) {
                expert_add_info_format(pinfo, ti, &ei_coap_eap_cbor_malformed,
                    "CBOR parse error");
            }
        }
    } else {
        /* Step 0: trigger URI (plain text) */
        proto_tree_add_item(coap_eap_tree, hf_coap_eap_trigger_uri,
            tvb, 0, -1, ENC_ASCII);
        col_append_str(pinfo->cinfo, COL_INFO, " | CoAP-EAP Trigger");
    }

    return tvb_captured_length(tvb);
}

/* ------------------------------------------------------------------ */
/* Dissect entry point: media_type table (primary)                    */
/* ------------------------------------------------------------------ */

/**
 * Dissect CoAP-EAP payload called from the CoAP dissector via the
 * media_type dissector table for Content-Format 269.
 *
 * The \p tvb contains only the CoAP payload (after the 0xFF marker).
 * The \p data parameter is a media_content_info_t* provided by the
 * parent CoAP dissector.
 *
 * The parent CoAP dissector has already parsed the CoAP header and
 * options, including any Block-wise transfer reassembly (RFC 7959).
 * The payload may be a complete reassembled payload.
 */
static int
dissect_coap_eap_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    media_content_info_t *content_info = data;
    DISSECTOR_ASSERT(content_info);
    return dissect_coap_eap_payload(tvb, pinfo, tree);
}

/* ------------------------------------------------------------------ */
/* Dissect entry point: UDP port (manual configuration)               */
/* ------------------------------------------------------------------ */

/**
 * Dissect CoAP-EAP traffic on a user-configured UDP port.
 *
 * Delegates to the native CoAP dissector first, which populates the
 * CoAP tree and columns. If the packet carries Content-Format 269,
 * the CoAP dissector dispatches to our media_type handler automatically.
 *
 * This function exists as a convenience for deployments that use a
 * non-standard UDP port for CoAP-EAP. The CoAP dissector must be
 * available; if it is not, the packet is handed to the data dissector.
 */
static int
dissect_coap_eap_port(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /*
     * Try the CoAP dissector first. If the packet is valid CoAP and
     * carries Content-Format 269, the CoAP dissector will dispatch
     * to our media_type handler (dissect_coap_eap_media) automatically.
     */
    if (coap_handle) {
        call_dissector(coap_handle, tvb, pinfo, tree);

        /*
         * If CoAP did not dispatch to our media_type handler (e.g.,
         * the packet was not CF=269), we still return the full length.
         * The CoAP dissector will have handled the packet appropriately.
         *
         * If CoAP did dispatch to us, the columns and tree are already
         * populated by dissect_coap_eap_media, so we just return.
         */
        return tvb_captured_length(tvb);
    }

    /*
     * Fallback: if the CoAP dissector is unavailable (unlikely),
     * manually parse CoAP options to extract the payload.
     */
    int cf = -1;
    int payload_offset = -1;

    if (!get_coap_context(tvb, &cf, &payload_offset))
        return 0;

    if (cf != 269 || payload_offset < 0 || payload_offset >= (int)tvb_captured_length(tvb))
        return 0;

    tvbuff_t *payload_tvb = tvb_new_subset_remaining(tvb, payload_offset);
    return dissect_coap_eap_payload(payload_tvb, pinfo, tree);
}

/* ------------------------------------------------------------------ */
/* Protocol registration                                               */
/* ------------------------------------------------------------------ */

void
proto_register_coap_eap(void)
{
    static hf_register_info hf[] = {
        { &hf_coap_eap_trigger_uri,
            { "Next Resource URI", "coap_eap.trigger_uri",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Step 0 trigger: URI of the first EAP resource (RFC 9820 Section 4)", HFILL }
        },
        { &hf_coap_eap_eap,
            { "EAP Packet", "coap_eap.eap",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "EAP payload carried inside CoAP-EAP (RFC 3748)", HFILL }
        },
        { &hf_coap_eap_cbor_info,
            { "CoAP-EAP Info (CBOR)", "coap_eap.cbor_info",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "CBOR map containing CoAP-EAP_Info (RFC 9820 Section 5)", HFILL }
        },
        { &hf_coap_eap_cipher_suites,
            { "Cipher Suites", "coap_eap.cipher_suites",
              FT_STRING, BASE_NONE, NULL, 0x0,
              "Negotiated cipher suites (RFC 9820 Section 9.1)", HFILL }
        },
        { &hf_coap_eap_rid_c,
            { "RID-C", "coap_eap.rid_c",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Recipient ID of the EAP Authenticator (RFC 9820 Section 5)", HFILL }
        },
        { &hf_coap_eap_rid_i,
            { "RID-I", "coap_eap.rid_i",
              FT_BYTES, BASE_NONE, NULL, 0x0,
              "Recipient ID of the EAP Peer (RFC 9820 Section 5)", HFILL }
        },
        { &hf_coap_eap_lifetime,
            { "Session-Lifetime", "coap_eap.lifetime",
              FT_UINT64, BASE_DEC, NULL, 0x0,
              "Session lifetime in seconds (RFC 9820 Section 5)", HFILL }
        },
        { &hf_coap_eap_cbormap_key,
            { "CBOR Map Key", "coap_eap.cbormap_key",
              FT_UINT8, BASE_DEC, VALS(cbormap_key_vals), 0x0,
              "Key identifier in the CoAP-EAP_Info CBOR map", HFILL }
        },
    };

    static int *ett[] = {
        &ett_coap_eap,
        &ett_coap_eap_eap,
        &ett_coap_eap_cbor,
    };

    static ei_register_info ei[] = {
        { &ei_coap_eap_payload_too_short,
            { "coap_eap.payload_too_short", PI_MALFORMED, PI_ERROR,
              "Payload too short for EAP header (need 4 bytes)", EXPFILL }
        },
        { &ei_coap_eap_eap_length_invalid,
            { "coap_eap.eap_length_invalid", PI_MALFORMED, PI_ERROR,
              "EAP Length field is less than 4 (minimum EAP packet size)", EXPFILL }
        },
        { &ei_coap_eap_eap_length_exceeds,
            { "coap_eap.eap_length_exceeds", PI_MALFORMED, PI_WARN,
              "EAP Length exceeds available payload; clamping", EXPFILL }
        },
        { &ei_coap_eap_cbor_malformed,
            { "coap_eap.cbor_malformed", PI_MALFORMED, PI_WARN,
              "CBOR parse error in CoAP-EAP_Info", EXPFILL }
        },
        { &ei_coap_eap_cbor_not_map,
            { "coap_eap.cbor_not_map", PI_MALFORMED, PI_WARN,
              "Expected CBOR map for CoAP-EAP_Info", EXPFILL }
        },
    };

    proto_coap_eap = proto_register_protocol(
        "CoAP-EAP",
        "CoAP-EAP",
        "coap_eap"
    );

    proto_register_field_array(proto_coap_eap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_coap_eap = expert_register_protocol(proto_coap_eap);
    expert_register_field_array(expert_coap_eap, ei, array_length(ei));

    coap_eap_module = prefs_register_protocol(proto_coap_eap, coap_eap_prefs_apply);

    prefs_register_uint_preference(coap_eap_module, "udp_port",
         "CoAP-EAP UDP Port",
         "UDP port for non-standard CoAP-EAP deployments (0 = disabled). "
         "When set, the dissector registers on this UDP port and delegates "
         "to the native CoAP dissector for initial parsing.",
         10, &udp_port_pref);
}

/* ------------------------------------------------------------------ */
/* Preferences callback (called on initial load and on pref changes)   */
/* ------------------------------------------------------------------ */

/**
 * Apply the UDP port preference. Called once from proto_reg_handoff_coap_eap
 * for the initial value, and again whenever preferences are changed.
 * Only the UDP port registration is preference-driven; the static
 * registrations (handles, media_type table) are done once in the handoff.
 */
static void
coap_eap_prefs_apply(void)
{
    if (current_udp_port != 0) {
        dissector_delete_uint("udp.port", current_udp_port, coap_eap_port_handle);
    }
    current_udp_port = udp_port_pref;
    if (current_udp_port != 0) {
        dissector_add_uint("udp.port", current_udp_port, coap_eap_port_handle);
    }
}

/* ------------------------------------------------------------------ */
/* Handoff registration                                               */
/* ------------------------------------------------------------------ */

void
proto_reg_handoff_coap_eap(void)
{
    eap_handle = find_dissector_add_dependency("eap", proto_coap_eap);
    coap_handle = find_dissector_add_dependency("coap", proto_coap_eap);

    coap_eap_media_handle = create_dissector_handle_with_name_and_description(
        dissect_coap_eap_media, proto_coap_eap,
        "coap_eap.media", "CoAP-EAP (RFC 9820)");

    coap_eap_port_handle = register_dissector("coap_eap.port",
        dissect_coap_eap_port, proto_coap_eap);

    /*
     * Primary registration: Content-Format 269 via the media_type
     * dissector table. The CoAP dissector dispatches to us when it
     * encounters Content-Format 269 (application/coap-eap).
     *
     * Prerequisite: packet-coap.c must include the mapping
     *   { 269, "application/coap-eap" }
     * in its vals_ctype array. Without this mapping, CF 269 resolves
     * to "Unknown Type 269" and the media_type lookup will fail.
     */
    dissector_add_string("media_type", "application/coap-eap", coap_eap_media_handle);

    /* Apply the initial UDP port preference */
    coap_eap_prefs_apply();
}
