/* packet-edhoc.c
 * Routines for Ephemeral Diffie-Hellman Over COSE (EDHOC) dissection
 * References:
 *     RFC 9528: https://tools.ietf.org/html/rfc9528
 *     RFC 9053: https://tools.ietf.org/html/rfc9053
 *
 * Copyright 2024-2025, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#define WS_LOG_DOMAIN "packet-edhoc"
#define EDHOC_LOG_DATA 1

#include <config.h>
#include "packet-edhoc.h"
#include "packet-cbor.h"
#include "packet-media-type.h"
#include <epan/wscbor.h>
#include <epan/wscbor_enc.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/media_params.h>
#include <epan/strutil.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/uat.h>
#include <wsutil/array.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/str_util.h>
#include <wsutil/to_str.h>
#include <wsutil/wsgcrypt.h>
#include <wsutil/wslog.h>
#include <wsutil/wmem/wmem_list.h>
#include <wsutil/wmem/wmem_map.h>

#if EDHOC_LOG_DATA
/** Duplicate logic of packet-tls-util.c
 */
static void log_data_bytes(const packet_info *pinfo, const char *name, GBytes *data) {
    char *hexstr = "";
    if (data) {
        size_t len;
        const uint8_t *ptr = g_bytes_get_data(data, &len);
        hexstr = g_malloc(2 * len + 1);
        bytes_to_hexstr(hexstr, ptr, len);
        hexstr[2 * len] = '\0';
    }
    ws_debug("frame %d data %s: %s", pinfo->num, name, hexstr);
    if (data) {
        g_free(hexstr);
    }
}
#endif

/** Secrets for a single EDHOC session, indexed by its G_X bytes.
 */
typedef struct {
    /// Reference to PRK_2e
    GBytes *prk_2e;
    /// Reference to TH_2
    GBytes *th_2;
    /// Reference to PRK_3e2m
    GBytes *prk_3e2m;
    /// Reference to TH_3
    GBytes *th_3;
    /// Reference to PRK_4e3m
    GBytes *prk_4e3m;
    /// Reference to TH_4
    GBytes *th_4;
} edhoc_secrets_t;

/** File-scope index of secrets from an key log.
 * These correspond to inputs for Figure 6 from RFC 9528.
 */
typedef struct {
    /// Storage for map keys and values as GBytes *
    wmem_list_t *bytes_list;

    /// Map from G_X to secrets as GBytes * to edhoc_secrets_t *
    wmem_map_t *gx_secrets;
} edhoc_secrets_store_t;

static void edhoc_secrets_init(edhoc_secrets_store_t *obj, wmem_allocator_t *alloc) {
    obj->bytes_list = wmem_list_new(alloc);
    obj->gx_secrets = wmem_map_new(alloc, g_bytes_hash, g_bytes_equal);
}

static void edhoc_secrets_clear(edhoc_secrets_store_t *obj) {
    obj->gx_secrets = NULL;

    if (obj->bytes_list) {
        wmem_list_frame_t *it;
        for (it = wmem_list_head(obj->bytes_list); it; it = wmem_list_frame_next(it)) {
            GBytes *data = wmem_list_frame_data(it);
            g_bytes_unref(data);
        }
        obj->bytes_list = NULL;
    }
}

void proto_register_edhoc(void);
void proto_reg_handoff_edhoc(void);

/// Protocol column name
static const char *const proto_name_edhoc = "EDHOC";

// Protocol preferences and defaults
static bool edhoc_ead_try_heur = false;

// Protocol handles
static int proto_edhoc;
/// Dissect EAD items
static dissector_table_t table_edhoc_ead;

// Dissect opaque CBOR data
static dissector_handle_t handle_cbor;
// Dissect ID_CRED_x values
static dissector_handle_t handle_cose_hdrs;
// Dissector handles
static dissector_handle_t handle_edhoc_msg;
static dissector_handle_t handle_edhoc_media;
static dissector_handle_t handle_edhoc_media_cid;

/// Dissect extension items
//static dissector_table_t table_cose_msg_tag;

static const val64_string edhoc_method_vals[] = {
    // Methods from RFC 9528
    {0, "SIGN-SIGN"},
    {1, "SIGN-DH"},
    {2, "DH-SIGN"},
    {3, "DH-DH"},
    {23, "Reserved"},
    {0, NULL}
};

static const val64_string edhoc_cs_vals[] = {
    {-24, "Private Use"},
    {-23, "Private Use"},
    {-22, "Private Use"},
    {-21, "Private Use"},
    // Cipher Suites from RFC 9528
    {0, "AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA, AES‑CCM‑16‑64‑128, SHA-256"},
    {1, "AES-CCM-16-128-128, SHA‑256, 16, X25519, EdDSA, AES‑CCM‑16‑64‑128, SHA-256"},
    {2, "AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES‑CCM‑16‑64‑128, SHA-256"},
    {3, "AES-CCM-16-128-128, SHA‑256, 16, P-256, ES256, AES‑CCM‑16‑64‑128, SHA-256"},
    {4, "ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA, ChaCha20/Poly1305, SHA-256"},
    {5, "ChaCha20/Poly1305, SHA-256, 16, P-256, ES256, ChaCha20/⁠Poly1305, SHA-256"},
    {6, "A128GCM, SHA-256, 16, X25519, ES256, A128GCM, SHA-256"},
    {23, "Reserved"},
    {24, "A256GCM, SHA-384, 16, P-384, ES384, A256GCM, SHA-384"},
    {25, "ChaCha20/Poly1305, SHAKE256, 16, X448, EdDSA, ChaCha20/Poly1305, SHAKE256"},
    {0, NULL}
};

static const val64_string edhoc_err_code_vals[] = {
    {0, "Reserved"},
    {1, "Unspecified error"},
    {2, "Wrong selected cipher suite"},
    {3, "Unknown credential referenced"},
    {23, "Reserved"},
    {0, NULL}
};

/** Storage for cipher suite parameters per Section 3.6 of RFC 9528.
 */
typedef struct edhoc_cs_s {
    /// Identifier for this cipher suite
    int64_t value;

    /// COSE algorithm for AEAD
    int64_t edhoc_aead;
    /// COSE algorithm for hash
    int64_t edhoc_hash;
    /// MAC length for internal processing
    size_t edhoc_mac_length;
    /// COSE curve for key exchange
    int edhoc_ke_curve;
    /// COSE algorithm for signature
    int64_t edhoc_sign;

    /// COSE algorithm for AEAD
    int64_t app_aead;
    /// COSE algorithm for hash
    int64_t app_hash;
} edhoc_cs_t;

/// Defined suites
static edhoc_cs_t edhoc_cs_list[] = {
    // Cipher Suites from RFC 9528
    // 0: AES-CCM-16-64-128, SHA-256, 8, X25519, EdDSA, AES-CCM-16-64-128, SHA-256
    {0, 10, -16, 8, 4, -8, 10, -16},
    // 1: AES-CCM-16-128-128, SHA-256, 16, X25519, EdDSA, AES-CCM-16-64-128, SHA-256
    {1, 30, -16, 16, 4, -8, 10, -16},
    // 2: AES-CCM-16-64-128, SHA-256, 8, P-256, ES256, AES-CCM-16-64-128, SHA-256
    {2, 10, -16, 8, 1, -7, 10, -16},
    // 3: AES-CCM-16-128-128, SHA-256, 16, P-256, ES256, AES-CCM-16-64-128, SHA-256
    {3, 30, -16, 16, 1, -7, 10, -16},
    // 4: ChaCha20/Poly1305, SHA-256, 16, X25519, EdDSA, ChaCha20/Poly1305, SHA-256
    {4, 24, -16, 16, 4, -8, 24, -16},
    // 5: ChaCha20/Poly1305, SHA-256, 16, P-256, ES256, ChaCha20/⁠Poly1305, SHA-256
    {5, 24, -16, 16, 1, -7, 24, -16},
    // 6: A128GCM, SHA-256, 16, X25519, ES256, A128GCM, SHA-256
    {6, 1, -16, 16, 4, -7, 1, -16},
    // 24: A256GCM, SHA-384, 16, P-384, ES384, A256GCM, SHA-384
    {24, 3, -43, 16, 1, -35, 3, -43},
    // 25: ChaCha20/Poly1305, SHAKE256, 16, X448, EdDSA, ChaCha20/Poly1305, SHAKE256
    {25, 24, -45, 16, 5, -8, 24, -45},
};
/// Lookup table for ::edhoc_cs_t
static GHashTable *edhoc_cs_table = NULL;

/// Conversations in this file, pointers to edhoc_state_t
static wmem_list_t *edhoc_convos = NULL;

edhoc_state_t * edhoc_state_new(conversation_t *conv) {
    wmem_allocator_t *alloc = wmem_file_scope();

    edhoc_state_t *state = wmem_alloc0(alloc, sizeof(edhoc_state_t));
    state->conv = conv;
    state->session_list = wmem_list_new(alloc);
    state->session_map = wmem_tree_new(alloc);
    wmem_list_append(edhoc_convos, state);
    return state;
}

static void edhoc_state_free_internal(edhoc_state_t *state) {
    for (wmem_list_frame_t *it = wmem_list_head(state->session_list);
        it; it = wmem_list_frame_next(it)) {
        edhoc_session_t *sess = wmem_list_frame_data(it);
        g_bytes_unref(sess->gx_data);
        g_bytes_unref(sess->prk_out);
        g_bytes_unref(sess->prk_exporter);
    }
}

void edhoc_state_free(edhoc_state_t *state) {
    wmem_list_remove(edhoc_convos, state);
    edhoc_state_free_internal(state);
}

/** Implement a KDF for either EDHOC or application use.
 */
static GBytes * edhoc_any_kdf(int64_t algo, GBytes *prk, int64_t label, GBytes *ctx, size_t length) {
    if (!prk || !length || (length > UINT_MAX)) {
        return NULL;
    }

    const cose_hash_props_t *props = cose_get_hash_props(algo);
    if (!props) {
        return NULL;
    }

    GByteArray *info_buf = g_byte_array_new();
    wscbor_enc_int64(info_buf, label);
    if (ctx) {
        wscbor_enc_bstr(info_buf, g_bytes_get_data(ctx, NULL), g_bytes_get_size(ctx));
    }
    else {
        wscbor_enc_bstr(info_buf, NULL, 0);
    }
    wscbor_enc_uint64(info_buf, length);
    GBytes *info_data = g_byte_array_free_to_bytes(info_buf);

    uint8_t *out = NULL;
    switch (props->gcry_hash) {
        case GCRY_MD_SHA256:
        case GCRY_MD_SHA384:
        case GCRY_MD_SHA512: {
            out = g_malloc(length);
            gcry_error_t err = hkdf_expand(
                props->gcry_hash,
                g_bytes_get_data(prk, NULL), (unsigned)g_bytes_get_size(prk),
                g_bytes_get_data(info_data, NULL), (unsigned)g_bytes_get_size(info_data),
                out, (unsigned)length
            );
            if (err) {
                ws_error("HKDF error: %s", gcry_strerror(err));
            }
            break;
        }
        default:
            ws_error("unhandled KDF hash algo: %"PRId64, algo);
            break;
    }

    g_bytes_unref(info_data);
    // this may be treated as a truncation, but does not change allocation
    return g_bytes_new_take(out, length);
}

static GBytes * edhoc_kdf(const edhoc_session_t *sess, GBytes *prk, int64_t label, GBytes *ctx, size_t length) {
    if (!sess || !(sess->found_cs)) {
        return NULL;
    }
    return edhoc_any_kdf(sess->found_cs->edhoc_hash, prk, label, ctx, length);
}

GBytes * edhoc_exporter_kdf(const edhoc_session_t *sess, int64_t label, GBytes *ctx, size_t length) {
    if (!sess || !(sess->found_cs) || !(sess->prk_exporter)) {
        return NULL;
    }
    return edhoc_any_kdf(sess->found_cs->app_hash, sess->prk_exporter, label, ctx, length);
}

/// UAT secret lookup
static edhoc_secrets_store_t uat_secrets = {
    NULL,
    NULL
};

static int hf_connid_corr_true;
static int hf_connid_corr_bytes;
static int hf_method;
static int hf_suite_pref_list;
static int hf_suite_pref;
static int hf_suite_sel;
static int hf_pubkey_i;
static int hf_connid_i;
static int hf_error_code;
static int hf_error_info;
static int hf_ead_item;
static int hf_ead_label;
static int hf_ead_label_abs;
static int hf_ead_value;
static int hf_gy_ciphertext;
static int hf_pubkey_r;
static int hf_ciphertext;
static int hf_plaintext;
static int hf_connid_r;
static int hf_idcred_r;
static int hf_idcred_i;
static int hf_idcred_kid;
static int hf_sigmac;
static int hf_sess_idx;
static int hf_sess_msg1;
static int hf_sess_prev;
static int hf_sess_next;

static int ett_msg;
static int ett_suite_list;
static int ett_gyc;
static int ett_plain;
static int ett_idcred;
static int ett_ead_item;
static int ett_ead_value;
static int ett_error_info;

static expert_field ei_item_type;
static expert_field ei_missing_msg1;
static expert_field ei_pubkey_len;
static expert_field ei_no_decrypt;
static expert_field ei_ead_critical;
static expert_field ei_ead_partial_decode;
static expert_field ei_ead_embedded_bstr;
static expert_field ei_err_partial_decode;

/** Perform AEAD decryption in-place on a ciphertext scratchpad.
 *
 */
static int edhoc_decrypt(const edhoc_cs_t *suite, GBytes *key, GBytes *iv, GBytes *aad, uint8_t *scratch, size_t scratch_len) {
    if (!suite || !key || !iv|| !aad || !scratch) {
        return -1;
    }

    const cose_aead_props_t *aead_props = cose_get_aead_props(suite->edhoc_aead);
    if (!aead_props || (scratch_len < aead_props->tag_len)) {
        return -1;
    }
    // plaintext length
    int pt_len = (int)(scratch_len - aead_props->tag_len);

    // perform AEAD decryption
    gcry_error_t err;
    gcry_cipher_hd_t ghd;
    err = gcry_cipher_open(&ghd, aead_props->gcry_cipher, aead_props->gcry_mode, 0);
    if (err) {
        ws_warning("gcry_cipher_open error: %s", gcry_strerror(err));
    }
    err = gcry_cipher_setkey(ghd, g_bytes_get_data(key, NULL), g_bytes_get_size(key));
    if (err) {
        ws_warning("gcry_cipher_setkey error: %s", gcry_strerror(err));
    }
    err = gcry_cipher_setiv(ghd, g_bytes_get_data(iv, NULL), g_bytes_get_size(iv));
    if (err) {
        ws_warning("gcry_cipher_setiv error: %s", gcry_strerror(err));
    }

    if (aead_props->gcry_mode == GCRY_CIPHER_MODE_CCM) {
        // size of plaintext, AAD, and auth tag
        uint64_t lengths[3] = {
            pt_len,
            g_bytes_get_size(aad),
            aead_props->tag_len
        };
        gcry_cipher_ctl(ghd, GCRYCTL_SET_CCM_LENGTHS, lengths, sizeof(lengths));
    }
    err = gcry_cipher_authenticate(ghd, g_bytes_get_data(aad, NULL), g_bytes_get_size(aad));
    if (err) {
        ws_warning("gcry_cipher_authenticate error: %s", gcry_strerror(err));
    }

    // in-place decryption in the scratch buffer
    err = gcry_cipher_decrypt(ghd, scratch, pt_len, NULL, 0);
    if (err) {
        ws_warning("gcry_cipher_decrypt size %d error: %s", pt_len, gcry_strerror(err));
    }

    err = gcry_cipher_checktag(ghd, scratch + pt_len, aead_props->tag_len);
    if (err) {
        ws_warning("gcry_cipher_checktag error: %s", gcry_strerror(err));
    }

    gcry_cipher_close(ghd);
    return err ? -1 : pt_len;
}

/** Dissect connection ID, which can have a few different forms.
 *
 * @param[in,out] want_hex Non-null if the pointer should be set to a
 * hex string representation of the CID.
 * @return True if the CID itself is true.
 */
static bool dissect_connid(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, int *offset, char **want_hex) {
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    if (chunk->type_major == CBOR_TYPE_FLOAT_CTRL) {
        // special case for application/cid-edhoc prefix
        bool *val = wscbor_require_boolean(pinfo->pool, chunk);
        proto_tree_add_cbor_boolean(tree, hf_connid_corr_true, pinfo, tvb, chunk, val);
        return val ? *val == true : false;
    }
    else if ((chunk->type_major == CBOR_TYPE_UINT) || (chunk->type_major == CBOR_TYPE_NEGINT)) {
        // special case of encoded byte
        proto_tree_add_item(tree, hfindex, tvb, chunk->start, chunk->head_length, ENC_NA);
        if (want_hex) {
            *want_hex = tvb_bytes_to_str(pinfo->pool, tvb, chunk->start, chunk->head_length);
        }
    }
    else {
        // either a bstr or show the error
        tvbuff_t *data = wscbor_require_bstr(pinfo->pool, chunk);
        proto_tree_add_cbor_bstr(tree, hfindex, pinfo, tvb, chunk);
        if (want_hex) {
            *want_hex = tvb_bytes_to_str(pinfo->pool, data, 0, tvb_reported_length(data));
        }
    }
    return false;
}

/** Dissect credential ID, which can have a few different forms.
 */
static void dissect_idcred(proto_tree *tree, int hfindex, packet_info *pinfo, tvbuff_t *tvb, int *offset) {
    proto_item *item_idcred = proto_tree_add_item(tree, hfindex, tvb, *offset, -1, ENC_NA);
    proto_tree *tree_idcred = proto_item_add_subtree(item_idcred, ett_idcred);

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    if (chunk->type_major == CBOR_TYPE_MAP) {
        // a COSE header map
        *offset = chunk->start;
        tvbuff_t *tvb_idcred = tvb_new_subset_remaining(tvb, *offset);

        int sublen = call_dissector(handle_cose_hdrs, tvb_idcred, pinfo, tree_idcred);
        if (sublen > 0) {
            proto_item_set_len(item_idcred, sublen);
            *offset += sublen;
        }
    }
    else {
        // direct key ID, with connid compression
        *offset = chunk->start;
        dissect_connid(tree_idcred, hf_idcred_kid, pinfo, tvb, offset, NULL);
        proto_item_set_len(item_idcred, *offset - chunk->start);
    }
}

static void dissect_ead_list(proto_tree *tree_msg, packet_info *pinfo, tvbuff_t *tvb, int *offset, edhoc_session_t *sess) {
    const int replen = tvb_reported_length(tvb);
    int count = 0;
    while (*offset < replen) {
        proto_item *item_ead = proto_tree_add_item(tree_msg, hf_ead_item, tvb, *offset, -1, ENC_NA);
        proto_tree *tree_ead = proto_item_add_subtree(item_ead, ett_ead_item);

        wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
        int64_t *label = wscbor_require_int64(pinfo->pool, chunk);
        proto_tree_add_cbor_int64(tree_ead, hf_ead_label, pinfo, tvb, chunk, label);

        dissector_handle_t ead_dissector = NULL;
        if (label) {
            if (*label < 0) {
                expert_add_info(pinfo, item_ead, &ei_ead_critical);
            }

            // Show absolute value
            *label = llabs(*label);
            proto_item *item_abs = proto_tree_add_cbor_int64(tree_ead, hf_ead_label_abs, pinfo, tvb, chunk, label);
            proto_item_set_generated(item_abs);

            // Lookup by absolute values
            ead_dissector = dissector_get_custom_table_handle(table_edhoc_ead, label);
            const char *dis_name = dissector_handle_get_description(ead_dissector);
            if (item_abs && dis_name) {
                proto_item_set_text(item_abs, "%s: %s (%" PRId64 ")",
                                    PITEM_HFINFO(item_abs)->name, dis_name, *label);
            }
            if (item_ead && dis_name) {
                proto_item_append_text(item_ead, ": %s", dis_name);
            }
        }

        // peek ahead
        chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
        if (chunk->type_major == CBOR_TYPE_BYTESTRING) {
            tvbuff_t *tvb_data = wscbor_require_bstr(pinfo->pool, chunk);
            proto_item *item_ead_value = proto_tree_add_cbor_bstr(tree_ead, hf_ead_value, pinfo, tvb, chunk);
            proto_tree *tree_ead_value = proto_item_add_subtree(item_ead_value, ett_ead_value);

            if (ead_dissector) {
                int sublen = call_dissector_only(ead_dissector, tvb_data, pinfo, tree_ead_value, sess);
                if ((sublen < 0) ||
                    ((sublen > 0) && ((unsigned)sublen < tvb_reported_length(tvb_data)))) {
                    expert_add_info(pinfo, item_ead_value, &ei_ead_partial_decode);
                }
            }
            else if (edhoc_ead_try_heur) {
                bool valid = cbor_heuristic(tvb_data, pinfo, tree_ead_value, NULL);
                if (valid) {
                    expert_add_info(pinfo, item_ead_value, &ei_ead_embedded_bstr);
                }
            }
        }
        else {
            *offset = chunk->start;
        }

        proto_item_set_end(item_ead, tvb, *offset);
        ++count;
    }

    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "EAD=%d", count);
}

/** Inspect to check if error is present.
 * An error is a sequence of exactly two CBOR items.
 *
 * @return True if an error is present and not a message.
 */
static bool check_edhoc_error(tvbuff_t *tvb, packet_info *pinfo, int offset) {
    // error code
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    if ((chunk->type_major != CBOR_TYPE_UINT) && (chunk->type_major != CBOR_TYPE_NEGINT)) {
        return false;
    }

    // error detail
    if (!wscbor_skip_next_item(pinfo->pool, tvb, &offset)) {
        return false;
    }

    // only those two can be present
    return (offset == (int)tvb_reported_length(tvb));
}

/** Inspect to check if message 1 is present.
 * This message is a sequence of at least 4 CBOR items.
 *
 * @return True if an error is present and not a message.
 */
static bool check_edhoc_msg1(tvbuff_t *tvb, packet_info *pinfo, int offset) {
    // method: int
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    if ((chunk->type_major != CBOR_TYPE_UINT) && (chunk->type_major != CBOR_TYPE_NEGINT)) {
        return false;
    }

    // suites: array or int
    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    if ((chunk->type_major != CBOR_TYPE_UINT) && (chunk->type_major != CBOR_TYPE_NEGINT)
        && (chunk->type_major != CBOR_TYPE_ARRAY)) {
        return false;
    }
    if (chunk->type_major == CBOR_TYPE_ARRAY) {
        offset = chunk->start;
        if (!wscbor_skip_next_item(pinfo->pool, tvb, &offset)) {
            return false;
        }
    }

    // G_X: bstr
    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    if (chunk->type_major != CBOR_TYPE_BYTESTRING) {
        return false;
    }

    // C_I: bstr or int
    chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    if ((chunk->type_major != CBOR_TYPE_UINT) && (chunk->type_major != CBOR_TYPE_NEGINT)
        && (chunk->type_major != CBOR_TYPE_BYTESTRING)) {
        return false;
    }

    return true;
}

static bool dissect_edhoc_error(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_msg, int *offset, edhoc_session_t *sess) {
    DISSECTOR_ASSERT(offset);
    proto_item *item_msg = proto_tree_get_parent(tree_msg);
    proto_item_append_text(item_msg, ", Error");
    col_set_str(pinfo->cinfo, COL_INFO, "Error");

    {
        proto_item *item = proto_tree_add_uint64(tree_msg, hf_sess_idx, tvb, 0, 0, sess->sess_idx);
        proto_item_set_generated(item);
        item = proto_tree_add_int64(tree_msg, hf_method, tvb, 0, 0, sess->method);
        proto_item_set_generated(item);
        item = proto_tree_add_int64(tree_msg, hf_suite_sel, tvb, 0, 0, sess->suite);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(tree_msg, hf_sess_msg1, tvb, 0, 0, sess->frame_msg1);
        proto_item_set_generated(item);
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    int64_t *code = wscbor_require_int64(pinfo->pool, chunk);
    proto_tree_add_cbor_int64(tree_msg, hf_error_code, pinfo, tvb, chunk, code);
    if (!code) {
        *offset = -1;
        return false;
    }
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "code=%" PRId64, *code);

    tvbuff_t *tvb_info = tvb_new_subset_remaining(tvb, *offset);
    proto_item *item_info = proto_tree_add_item(tree_msg, hf_error_info, tvb_info, 0, -1, ENC_NA);
    proto_tree *tree_info = proto_item_add_subtree(item_info, ett_error_info);

    int sublen = call_dissector_only(handle_cbor, tvb_info, pinfo, tree_info, sess);
    if ((sublen < 0) ||
        ((sublen > 0) && ((unsigned)sublen < tvb_reported_length(tvb_info)))) {
        expert_add_info(pinfo, item_msg, &ei_err_partial_decode);
    }

    sess->seen_error = true;
    sess->frame_error = pinfo->num;
    return true;
}

static bool dissect_edhoc_msg1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_msg, int *offset, edhoc_session_t *sess) {
    DISSECTOR_ASSERT(offset);
    proto_item *item_msg = proto_tree_get_parent(tree_msg);
    proto_item_append_text(item_msg, ", Message 1");
    col_set_str(pinfo->cinfo, COL_INFO, "Message 1");

    proto_item_set_generated(
        proto_tree_add_uint64(tree_msg, hf_sess_idx, tvb, 0, 0, sess->sess_idx)
    );

    // method code point
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    int64_t *method = wscbor_require_int64(pinfo->pool, chunk);
    proto_tree_add_cbor_int64(tree_msg, hf_method, pinfo, tvb, chunk, method);
    if (method && !(sess->method)) {
        sess->method = *method;
    }
    if (!method) {
        expert_add_info_format(pinfo, item_msg, &ei_missing_msg1, "This appears to not be an EDHOC Message 1 as the start of a captured conversation");
        *offset = -1;
        return false;
    }
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "M=%" PRId64, *method);

    // cipher suite code point
    int64_t *sel_suite = NULL;
    chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    if ((chunk->type_major == CBOR_TYPE_UINT) || (chunk->type_major == CBOR_TYPE_NEGINT)) {
        // only one value not in array
        proto_tree_add_uint64(tree_msg, hf_suite_pref_list, tvb, chunk->start, 0, 0);

        sel_suite = wscbor_require_int64(pinfo->pool, chunk);
        proto_tree_add_cbor_int64(tree_msg, hf_suite_sel, pinfo, tvb, chunk, sel_suite);
    }
    else {
        // either an array or show the error
        const uint64_t plist_len = (chunk->head_value > 0) ? chunk->head_value - 1 : 0;
        proto_item *item_plist = proto_tree_add_uint64(tree_msg, hf_suite_pref_list, tvb, chunk->start, chunk->head_length, plist_len);
        wscbor_require_array(chunk);
        if (!wscbor_chunk_mark_errors(pinfo, item_plist, chunk) && plist_len) {
            proto_tree *tree_plist = proto_item_add_subtree(item_plist, ett_suite_list);

            // non-last items are preferences
            for (uint64_t ix = 0; ix < plist_len; ++ix) {
                chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
                int64_t *suite = wscbor_require_int64(pinfo->pool, chunk);
                proto_tree_add_cbor_int64(tree_plist, hf_suite_pref, pinfo, tvb, chunk, suite);
            }
            proto_item_set_end(item_plist, tvb, *offset);

            // last item is selection
            chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
            sel_suite = wscbor_require_int64(pinfo->pool, chunk);
            proto_tree_add_cbor_int64(tree_msg, hf_suite_sel, pinfo, tvb, chunk, sel_suite);
        }
    }
    if (sel_suite) {
        sess->suite = *sel_suite;
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "CS=%" PRId64, *sel_suite);
    }

    chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    tvbuff_t *gx_tvb = wscbor_require_bstr(pinfo->pool, chunk);
    proto_item *item_gx = proto_tree_add_cbor_bstr(tree_msg, hf_pubkey_i, pinfo, tvb, chunk);

    char *cid_hex = NULL;
    dissect_connid(tree_msg, hf_connid_i, pinfo, tvb, offset, &cid_hex);
    if (cid_hex) {
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "C_I=%s", cid_hex);
    }

    sess->seen_msg1 = true;
    sess->frame_msg1 = pinfo->num;
    // handle EAD after setting the msg1 sess
    dissect_ead_list(tree_msg, pinfo, tvb, offset, sess);

    // Copy and store the G_X contents to correlate with secret items
    if (!sess->gx_data) {
        size_t gx_len = tvb_reported_length(gx_tvb);
        uint8_t *gx_raw = g_malloc(gx_len);
        tvb_memcpy(gx_tvb, gx_raw, 0, gx_len);

        GBytes *gx_data = g_bytes_new_take(gx_raw, gx_len);
        sess->gx_data = gx_data;
    }

    if (sel_suite && !(sess->found_cs)) {
        // search once when setting this
        sess->found_cs = g_hash_table_lookup(edhoc_cs_table, &(sess->suite));
    }
    if (sess->found_cs) {
        sess->aead_props = cose_get_aead_props(sess->found_cs->edhoc_aead);
        sess->hash_props = cose_get_hash_props(sess->found_cs->edhoc_hash);
        sess->ecc_props = cose_get_ecc_props(sess->found_cs->edhoc_ke_curve);
    }
    else {
        ws_warning("Unknown cipher sel_suite %"PRId64, sess->suite);
    }

    if (sess->ecc_props) {
        if (sess->ecc_props->pubkey_len != g_bytes_get_size(sess->gx_data)) {
            expert_add_info(pinfo, item_gx, &ei_pubkey_len);
        }
    }

    if (sess->seen_msg2) {
        proto_item_set_generated(
            proto_tree_add_uint(tree_msg, hf_sess_next, tvb, 0, 0, sess->frame_msg2)
        );
    }
    return true;
}

/** Dissect and attempt to decrypt message 2.
 */
static bool dissect_edhoc_msg2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_msg, int *offset, edhoc_session_t *sess) {
    DISSECTOR_ASSERT(offset);
    proto_item *item_msg = proto_tree_get_parent(tree_msg);
    proto_item_append_text(item_msg, ", Message 2");
    col_set_str(pinfo->cinfo, COL_INFO, "Message 2");

    {
        proto_item *item = proto_tree_add_uint64(tree_msg, hf_sess_idx, tvb, 0, 0, sess->sess_idx);
        proto_item_set_generated(item);
        item = proto_tree_add_int64(tree_msg, hf_method, tvb, 0, 0, sess->method);
        proto_item_set_generated(item);
        item = proto_tree_add_int64(tree_msg, hf_suite_sel, tvb, 0, 0, sess->suite);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(tree_msg, hf_sess_msg1, tvb, 0, 0, sess->frame_msg1);
        proto_item_set_generated(item);
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    tvbuff_t *gy_ciphertext_2 = wscbor_require_bstr(pinfo->pool, chunk);
    proto_item *item_gyc = proto_tree_add_cbor_bstr(tree_msg, hf_gy_ciphertext, pinfo, tvb, chunk);
    proto_tree *tree_gyc = proto_item_add_subtree(item_gyc, ett_gyc);

    if (!gy_ciphertext_2) {
        *offset = -1;
        return false;
    }

    // need the cipher suite to know G_Y length
    tvbuff_t *ciphertext_2 = NULL;
    if (!sess->found_cs) {
        expert_add_info_format(pinfo, item_gyc, &ei_missing_msg1, "Cannot extract G_Y without knowing the selected cipher suite from EDHOC Message 1");
    }
    proto_item *item_ctext = NULL;
    if (sess->ecc_props && gy_ciphertext_2) {
        const int gy_len = (int)(sess->ecc_props->pubkey_len);

        tvbuff_t *gy = tvb_new_subset_length(gy_ciphertext_2, 0, gy_len);
        proto_tree_add_item(tree_gyc, hf_pubkey_r, gy, 0, -1, ENC_NA);

        ciphertext_2 = tvb_new_subset_remaining(gy_ciphertext_2, gy_len);
        item_ctext = proto_tree_add_item(tree_gyc, hf_ciphertext, ciphertext_2, 0, -1, ENC_NA);
    }

    sess->seen_msg2 = true;
    sess->frame_msg2 = pinfo->num;

    // Attempt to decrypt if the sess has a G_X correlator
    const edhoc_secrets_t *secrets = NULL;
    if (sess->gx_data) {
        secrets = wmem_map_lookup(uat_secrets.gx_secrets, sess->gx_data);
    }
    if (!secrets) {
        expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No session secrets are available");
    }

    tvbuff_t *tvb_plain = NULL;
    if (secrets && sess->found_cs && ciphertext_2) {

        GBytes *prk_2e = secrets->prk_2e;
        sess->prk_2e = prk_2e;
        GBytes *th_2 = secrets->th_2;

        // From Section 4.1.1.2
        GBytes *prk_3e2m = NULL;
        const bool resp_sign = (sess->method == 0) || (sess->method == 2);
        if (resp_sign) {
            prk_3e2m = prk_2e;
        }
        else {
            prk_3e2m = secrets->prk_3e2m;
        }
        sess->prk_3e2m = prk_3e2m;

#if EDHOC_LOG_DATA
        log_data_bytes(pinfo, "PRK_2e", prk_2e);
        log_data_bytes(pinfo, "TH_2", th_2);
        log_data_bytes(pinfo, "PRK_3e2m", prk_3e2m);
#endif

        if (!prk_2e) {
            expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No PRK_2e is available");
        }
        else if (!th_2) {
            expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No TH_2 is available");
        }
        else {
            // generate the keystream
            size_t scratch_len = tvb_reported_length(ciphertext_2);
            GBytes *scratch = edhoc_kdf(sess, prk_2e, 0, th_2, scratch_len);
            if (!scratch) {
                ws_warning(
                    "Failed to generate keystream_2 with CS %p, prk_2e %p, TH_2 %p, length %zu",
                    sess->found_cs, prk_2e, th_2, scratch_len
                );
            }
            else {
                uint8_t *scratch_raw = g_bytes_unref_to_data(scratch, &scratch_len);
                for (unsigned ix = 0; ix < scratch_len; ++ix) {
                    scratch_raw[ix] ^= tvb_get_uint8(ciphertext_2, (int)ix);
                }

                tvb_plain = tvb_new_child_real_data(ciphertext_2, scratch_raw, (unsigned)scratch_len, (int)scratch_len);
                tvb_set_free_cb(tvb_plain, g_free);
            }
        }

        if (!tvb_plain) {
            expert_add_info(pinfo, item_ctext, &ei_no_decrypt);
        }
    }

    if (tvb_plain) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "decrypted");

        proto_item *item_plain = proto_tree_add_item(tree_msg, hf_plaintext, tvb_plain, 0, -1, ENC_NA);
        proto_item_set_generated(item_plain);
        proto_tree *tree_plain = proto_item_add_subtree(item_plain, ett_plain);
        int plainoff = 0;
        add_new_data_source(pinfo, tvb_plain, "EDHOC Plaintext");

        char *cid_hex = NULL;
        dissect_connid(tree_plain, hf_connid_r, pinfo, tvb_plain, &plainoff, &cid_hex);
        if (cid_hex) {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "C_R=%s", cid_hex);
        }

        dissect_idcred(tree_plain, hf_idcred_r, pinfo, tvb_plain, &plainoff);

        chunk = wscbor_chunk_read(pinfo->pool, tvb_plain, &plainoff);
        wscbor_require_bstr(pinfo->pool, chunk);
        proto_tree_add_cbor_bstr(tree_plain, hf_sigmac, pinfo, tvb_plain, chunk);

        dissect_ead_list(tree_plain, pinfo, tvb_plain, &plainoff, sess);
    }

    if (sess->seen_msg1) {
        proto_item_set_generated(
            proto_tree_add_uint(tree_msg, hf_sess_prev, tvb, 0, 0, sess->frame_msg1)
        );
    }
    if (sess->seen_msg3) {
        proto_item_set_generated(
            proto_tree_add_uint(tree_msg, hf_sess_next, tvb, 0, 0, sess->frame_msg3)
        );
    }
    return true;
}

/** Dissect and attempt to decrypt message 3.
 */
static bool dissect_edhoc_msg3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_msg, int *offset, edhoc_session_t *sess) {
    DISSECTOR_ASSERT(offset);
    proto_item *item_msg = proto_tree_get_parent(tree_msg);
    proto_item_append_text(item_msg, ", Message 3");
    col_set_str(pinfo->cinfo, COL_INFO, "Message 3");

    {
        proto_item *item = proto_tree_add_uint64(tree_msg, hf_sess_idx, tvb, 0, 0, sess->sess_idx);
        proto_item_set_generated(item);
        item = proto_tree_add_int64(tree_msg, hf_method, tvb, 0, 0, sess->method);
        proto_item_set_generated(item);
        item = proto_tree_add_int64(tree_msg, hf_suite_sel, tvb, 0, 0, sess->suite);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(tree_msg, hf_sess_msg1, tvb, 0, 0, sess->frame_msg1);
        proto_item_set_generated(item);
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    tvbuff_t *ciphertext_3 = wscbor_require_bstr(pinfo->pool, chunk);
    proto_item *item_ctext = proto_tree_add_cbor_bstr(tree_msg, hf_ciphertext, pinfo, tvb, chunk);
    if (!ciphertext_3) {
        *offset = -1;
        return false;
    }

    sess->seen_msg3 = true;
    sess->frame_msg3 = pinfo->num;

    // Attempt to decrypt if the sess has a G_X correlator
    const edhoc_secrets_t *secrets = NULL;
    if (sess->gx_data) {
        secrets = wmem_map_lookup(uat_secrets.gx_secrets, sess->gx_data);
    }
    if (!secrets) {
        expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No session secrets are available");
    }

    tvbuff_t *tvb_plain = NULL;
    if (secrets && sess->found_cs && sess->aead_props && sess->hash_props && ciphertext_3) {
        GBytes *prk_3e2m = sess->prk_3e2m;
        GBytes *th_3 = secrets->th_3;

        // From Section 4.1.1.3
        GBytes *prk_4e3m = NULL;
        const bool init_sign = (sess->method == 0) || (sess->method == 1);
        if (init_sign) {
            prk_4e3m = prk_3e2m;
        }
        else {
            prk_4e3m = secrets->prk_4e3m;
        }
        sess->prk_4e3m = prk_4e3m;

        if (!prk_3e2m) {
            expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No PRK_3e2m is available");
        }
        if (!th_3) {
            expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No TH_3 is available");
        }
        else {
            // generate the key and IV
            const size_t key_len = sess->aead_props->key_len;
            GBytes *k_3 = edhoc_kdf(sess, prk_3e2m, 3, th_3, key_len);
            if (!k_3) {
                ws_warning(
                   "Failed to generate K_3 with CS %p, prk_3e2m %p, TH_3 %p, length %zu",
                   sess->found_cs, prk_3e2m, th_3, key_len
               );
            }
            const size_t iv_len = sess->aead_props->iv_len;
            GBytes *iv_3 = edhoc_kdf(sess, prk_3e2m, 4, th_3, iv_len);
            if (!iv_3) {
                ws_warning(
                   "Failed to generate IV_3 with CS %p, prk_3e2m %p, TH_3 %p, length %zu",
                   sess->found_cs, prk_3e2m, th_3, iv_len
               );
            }

            GBytes *th_4 = secrets->th_4;
            size_t hash_len = sess->hash_props->out_len;
            sess->prk_out = edhoc_kdf(sess, prk_4e3m, 7, th_4, hash_len);
            if (!sess->prk_out) {
                ws_warning(
                   "Failed to generate PRK_out with CS %p, prk_4e3m %p, TH_4 %p, length %zu",
                   sess->found_cs, prk_4e3m, th_4, hash_len
               );
            }
            sess->prk_exporter = edhoc_kdf(sess, sess->prk_out, 10, NULL, hash_len);
            if (!sess->prk_exporter) {
                ws_warning(
                   "Failed to generate PRK_exporter with CS %p, prk_out %p, TH_4 %p, length %zu",
                   sess->found_cs, sess->prk_out, th_4, hash_len
               );
            }

    #if EDHOC_LOG_DATA
            log_data_bytes(pinfo, "TH_3", th_3);
            log_data_bytes(pinfo, "K_3", k_3);
            log_data_bytes(pinfo, "IV_3", iv_3);
            log_data_bytes(pinfo, "PRK_4e3m", prk_4e3m);
            log_data_bytes(pinfo, "PRK_out", sess->prk_out);
            log_data_bytes(pinfo, "PRK_exporter", sess->prk_exporter);
    #endif

            // AAD from Section 5.3 of RFC 9052
            GByteArray *aad_buf = g_byte_array_new();
            wscbor_enc_array_head(aad_buf, 3);
            wscbor_enc_tstr(aad_buf, "Encrypt0");
            // protected: h''
            wscbor_enc_bstr(aad_buf, NULL, 0);
            // external_aad: TH_3
            wscbor_enc_bstr(aad_buf, g_bytes_get_data(th_3, NULL), g_bytes_get_size(th_3));
            GBytes *aad_data = g_byte_array_free_to_bytes(aad_buf);

            size_t scratch_len = tvb_reported_length(ciphertext_3);
            // buffer for ciphertext and plaintext scratchpad
            uint8_t *scratch_raw = g_malloc(scratch_len);
            tvb_memcpy(ciphertext_3, scratch_raw, 0, scratch_len);

            int pt_len = edhoc_decrypt(sess->found_cs, k_3, iv_3, aad_data, scratch_raw, scratch_len);

            g_bytes_unref(aad_data);
            g_bytes_unref(k_3);
            g_bytes_unref(iv_3);

            // only set plaintext if the final tag check succeeded
            if (pt_len >= 0) {
                tvb_plain = tvb_new_child_real_data(ciphertext_3, scratch_raw, (unsigned)pt_len, pt_len);
                tvb_set_free_cb(tvb_plain, g_free);
            }
            else {
                g_free(scratch_raw);
            }
        }

        if (!tvb_plain) {
            expert_add_info(pinfo, item_ctext, &ei_no_decrypt);
        }
    }

    if (tvb_plain) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "decrypted");

        proto_item *item_plain = proto_tree_add_item(tree_msg, hf_plaintext, tvb_plain, 0, -1, ENC_NA);
        proto_item_set_generated(item_plain);
        proto_tree *tree_plain = proto_item_add_subtree(item_plain, ett_plain);
        int plainoff = 0;
        add_new_data_source(pinfo, tvb_plain, "EDHOC Plaintext");

        dissect_idcred(tree_plain, hf_idcred_i, pinfo, tvb_plain, &plainoff);

        chunk = wscbor_chunk_read(pinfo->pool, tvb_plain, &plainoff);
        wscbor_require_bstr(pinfo->pool, chunk);
        proto_tree_add_cbor_bstr(tree_plain, hf_sigmac, pinfo, tvb_plain, chunk);

        dissect_ead_list(tree_plain, pinfo, tvb_plain, &plainoff, sess);
    }

    if (sess->seen_msg2) {
        proto_item_set_generated(
            proto_tree_add_uint(tree_msg, hf_sess_prev, tvb, 0, 0, sess->frame_msg2)
        );
    }
    if (sess->seen_msg4) {
        proto_item_set_generated(
            proto_tree_add_uint(tree_msg, hf_sess_next, tvb, 0, 0, sess->frame_msg4)
        );
    }
    return true;
}

/** Dissect and attempt to decrypt message 3.
 */
static bool dissect_edhoc_msg4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_msg, int *offset, edhoc_session_t *sess) {
    DISSECTOR_ASSERT(offset);
    proto_item *item_msg = proto_tree_get_parent(tree_msg);
    proto_item_append_text(item_msg, ", Message 4");
    col_set_str(pinfo->cinfo, COL_INFO, "Message 4");

    {
        proto_item *item = proto_tree_add_uint64(tree_msg, hf_sess_idx, tvb, 0, 0, sess->sess_idx);
        proto_item_set_generated(item);
        item = proto_tree_add_int64(tree_msg, hf_method, tvb, 0, 0, sess->method);
        proto_item_set_generated(item);
        item = proto_tree_add_int64(tree_msg, hf_suite_sel, tvb, 0, 0, sess->suite);
        proto_item_set_generated(item);
        item = proto_tree_add_uint(tree_msg, hf_sess_msg1, tvb, 0, 0, sess->frame_msg1);
        proto_item_set_generated(item);
    }

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, offset);
    tvbuff_t *ciphertext_4 = wscbor_require_bstr(pinfo->pool, chunk);
    proto_item *item_ctext = proto_tree_add_cbor_bstr(tree_msg, hf_ciphertext, pinfo, tvb, chunk);
    if (!ciphertext_4) {
        *offset = -1;
        return false;
    }

    sess->seen_msg4 = true;
    sess->frame_msg4 = pinfo->num;

    // Attempt to decrypt if the sess has a G_X correlator
    const edhoc_secrets_t *secrets = NULL;
    if (sess->gx_data) {
        secrets = wmem_map_lookup(uat_secrets.gx_secrets, sess->gx_data);
    }
    if (!secrets) {
        expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No session secrets are available");
    }

    tvbuff_t *tvb_plain = NULL;
    if (secrets && sess->found_cs && ciphertext_4) {
        GBytes *prk_4e3m = sess->prk_4e3m;
        GBytes *th_4 = secrets->th_4;

        if (!prk_4e3m) {
            expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No PRK_4e3m is available");
        }
        else if (!th_4) {
            expert_add_info_format(pinfo, item_ctext, &ei_no_decrypt, "Message not decrypted: No TH_4 is available");
        }
        else {
            // generate the key and IV
            const size_t key_len = sess->aead_props->key_len;
            GBytes *k_4 = edhoc_kdf(sess, prk_4e3m, 8, th_4, key_len);
            if (!k_4) {
                ws_warning(
                    "Failed to generate K_4 with CS %p, prk_4e3m %p, TH_4 %p, length %zu",
                    sess->found_cs, prk_4e3m, th_4, key_len
               );
            }
            const size_t iv_len = sess->aead_props->iv_len;
            GBytes *iv_4 = edhoc_kdf(sess, prk_4e3m, 9, th_4, iv_len);
            if (!iv_4) {
                ws_warning(
                    "Failed to generate IV_4 with CS %p, prk_4e3m %p, TH_4 %p, length %zu",
                    sess->found_cs, prk_4e3m, th_4, iv_len
                );
            }
#if EDHOC_LOG_DATA
            log_data_bytes(pinfo, "TH_4", th_4);
            log_data_bytes(pinfo, "K_4", k_4);
            log_data_bytes(pinfo, "IV_4", iv_4);
#endif

            // AAD from Section 5.3 of RFC 9052
            GByteArray *aad_buf = g_byte_array_new();
            wscbor_enc_array_head(aad_buf, 3);
            wscbor_enc_tstr(aad_buf, "Encrypt0");
            // protected: h''
            wscbor_enc_bstr(aad_buf, NULL, 0);
            // external_aad: TH_4
            wscbor_enc_bstr(aad_buf, g_bytes_get_data(th_4, NULL), g_bytes_get_size(th_4));
            GBytes *aad_data = g_byte_array_free_to_bytes(aad_buf);

            size_t scratch_len = tvb_reported_length(ciphertext_4);
            // buffer for ciphertext and plaintext scratchpad
            uint8_t *scratch_raw = g_malloc(scratch_len);
            tvb_memcpy(ciphertext_4, scratch_raw, 0, scratch_len);

            int pt_len = edhoc_decrypt(sess->found_cs, k_4, iv_4, aad_data, scratch_raw, scratch_len);

            g_bytes_unref(aad_data);
            g_bytes_unref(k_4);
            g_bytes_unref(iv_4);

            // only set plaintext if the final tag check succeeded
            if (pt_len >= 0) {
                tvb_plain = tvb_new_child_real_data(ciphertext_4, scratch_raw, pt_len, pt_len);
                tvb_set_free_cb(tvb_plain, g_free);
            }
            else {
                g_free(scratch_raw);
            }
        }

        if (!tvb_plain) {
            expert_add_info(pinfo, item_ctext, &ei_no_decrypt);
        }
    }

    if (tvb_plain) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "decrypted");

        proto_item *item_plain = proto_tree_add_item(tree_msg, hf_plaintext, tvb_plain, 0, -1, ENC_NA);
        proto_item_set_generated(item_plain);
        proto_tree *tree_plain = proto_item_add_subtree(item_plain, ett_plain);
        int plainoff = 0;
        if (tvb_reported_length(tvb_plain) > 0) {
            add_new_data_source(pinfo, tvb_plain, "EDHOC Plaintext");
        }

        // just EAD here
        dissect_ead_list(tree_plain, pinfo, tvb_plain, &plainoff, sess);
    }

    if (sess->seen_msg3) {
        proto_item_set_generated(
            proto_tree_add_uint(tree_msg, hf_sess_prev, tvb, 0, 0, sess->frame_msg3)
        );
    }
    return true;
}

/** Embed EDHOC state in a parent transport conversation.
 */
static edhoc_state_t * edhoc_ensure_state(packet_info *pinfo, bool as_request _U_) {
    conversation_t *conv = find_or_create_conversation(pinfo);

    edhoc_state_t *state = (edhoc_state_t *)conversation_get_proto_data(conv, proto_edhoc);
    if (!state) {
        state = edhoc_state_new(conv);
        conversation_add_proto_data(conv, proto_edhoc, state);
    }

    return state;
}

/** Dissect an EDHOC message with explicit state given.
 */
static int dissect_edhoc_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    edhoc_state_t *state = data;
    DISSECTOR_ASSERT(state);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, proto_name_edhoc);
    col_clear(pinfo->cinfo, COL_INFO);

    int offset = 0;
    proto_item *item_msg = proto_tree_add_item(tree, proto_edhoc, tvb, offset, -1, ENC_NA);
    proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_msg);

    // informational only value
    bool cid_is_msg1 = false;
    if (state->prepend_cid) {
        cid_is_msg1 = dissect_connid(tree_msg, hf_connid_corr_bytes, pinfo, tvb, &offset, false);
    }

    edhoc_session_t *sess = wmem_tree_lookup32(state->session_map, pinfo->num);
    if (sess) {
        // already handled this
        if ((sess->seen_error) && (sess->frame_error == pinfo->num)) {
            dissect_edhoc_error(tvb, pinfo, tree_msg, &offset, sess);
        }
        else if ((sess->seen_msg1) && (sess->frame_msg1 == pinfo->num)) {
            dissect_edhoc_msg1(tvb, pinfo, tree_msg, &offset, sess);
        }
        else if ((sess->seen_msg2) && (sess->frame_msg2 == pinfo->num)) {
            dissect_edhoc_msg2(tvb, pinfo, tree_msg, &offset, sess);
        }
        else if ((sess->seen_msg3) && (sess->frame_msg3 == pinfo->num)) {
            dissect_edhoc_msg3(tvb, pinfo, tree_msg, &offset, sess);
        }
        else if ((sess->seen_msg4) && (sess->frame_msg4 == pinfo->num)) {
            dissect_edhoc_msg4(tvb, pinfo, tree_msg, &offset, sess);
        }
    }
    else {
        // try to continue earlier session
        sess = wmem_tree_lookup32_le(state->session_map, pinfo->num);

        if (sess) {
            if (cid_is_msg1) {
                sess = NULL;
            }
            // error structure is unique, so no preconditions
            else if (check_edhoc_error(tvb, pinfo, offset)) {
                dissect_edhoc_error(tvb, pinfo, tree_msg, &offset, sess);
            }
            // any subsequent message 1 is a new session
            else if ((sess->seen_msg3 || sess->seen_msg4 || sess->seen_error)
                && (check_edhoc_msg1(tvb, pinfo, offset))) {
                sess = NULL;
            }
            // try next unseen message
            else if (!(sess->seen_msg2)) {
                dissect_edhoc_msg2(tvb, pinfo, tree_msg, &offset, sess);
            }
            else if (!(sess->seen_msg3)) {
                dissect_edhoc_msg3(tvb, pinfo, tree_msg, &offset, sess);
            }
            else if (!(sess->seen_msg4)) {
                dissect_edhoc_msg4(tvb, pinfo, tree_msg, &offset, sess);
            }
        }

        if (!sess) {
            sess = wmem_alloc0(wmem_file_scope(), sizeof(edhoc_session_t));
            sess->parent = state;
            sess->sess_idx = wmem_list_count(state->session_list);
            wmem_list_append(state->session_list, sess);

            // always start with message 1
            if (!dissect_edhoc_msg1(tvb, pinfo, tree_msg, &offset, sess)) {
                sess = NULL;
            }
        }

        // valid first dissection for this frame
        if (sess) {
            wmem_tree_insert32(state->session_map, pinfo->num, sess);
        }
    }

    return offset;
}

/** Inspect ::media_content_info_t user data.
 */
static int dissect_edhoc_media(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    media_content_info_t *info = data;
    DISSECTOR_ASSERT(info);
    edhoc_state_t *state = edhoc_ensure_state(pinfo, info->type == MEDIA_CONTAINER_HTTP_REQUEST);
    state->prepend_cid = false;
    return dissect_edhoc_msg(tvb, pinfo, tree, state);
}

/** Inspect ::media_content_info_t user data.
 */
static int dissect_edhoc_media_cid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    media_content_info_t *info = data;
    DISSECTOR_ASSERT(info);
    edhoc_state_t *state = edhoc_ensure_state(pinfo, info->type == MEDIA_CONTAINER_HTTP_REQUEST);
    state->prepend_cid = true;
    return dissect_edhoc_msg(tvb, pinfo, tree, state);
}

/** Handle Padding EAD.
 */
static int dissect_ead_padding(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
    // Just provide the label name, don't do anything with the bstr value
    return tvb_reported_length(tvb);
}

/// Initialize for a new file scope
static void edhoc_init(void) {
    wmem_allocator_t *alloc = wmem_file_scope();
    if (!wmem_in_scope(alloc)) {
        return;
    }

    edhoc_convos = wmem_list_new(alloc);
}

/// Clean up after a closed file scope
static void edhoc_cleanup(void) {
    {
        wmem_list_frame_t *it;
        for (it = wmem_list_head(edhoc_convos); it;
                it = wmem_list_frame_next(it)) {
            edhoc_state_t *state = wmem_list_frame_data(it);
            edhoc_state_free_internal(state);
        }
    }
    edhoc_convos = NULL;
}

/// Re-initialize after a configuration change
static void edhoc_reinit(void) {}

/// Shutdown the dissector
static void edhoc_shutdown(void) {
    g_hash_table_destroy(edhoc_cs_table);
    edhoc_cs_table = NULL;

    edhoc_secrets_clear(&uat_secrets);
}

/// UAT representation of edhoc_secrets_t data
typedef struct {
    uint8_t *gx_ptr;
    unsigned gx_len;

    uint8_t *prk_2e_ptr;
    unsigned prk_2e_len;

    uint8_t *th_2_ptr;
    unsigned th_2_len;

    uint8_t *prk_3e2m_ptr;
    unsigned prk_3e2m_len;

    uint8_t *th_3_ptr;
    unsigned th_3_len;

    uint8_t *prk_4e3m_ptr;
    unsigned prk_4e3m_len;

    uint8_t *th_4_ptr;
    unsigned th_4_len;
} edhoc_secrets_uat_t;

/// Registered UAT
uat_t *edhoc_secrets_uat = NULL;
/// UAT_managed secrets list
static edhoc_secrets_uat_t *edhoc_secrets_uat_recs = NULL;
/// Number of items in #edhoc_secrets_uat
static unsigned edhoc_secrets_uat_num = 0;

/* Copy by-value a UAT record */
static void *edhoc_secrets_uat_copy_cb(void *d, const void *s, size_t len _U_) {
    const edhoc_secrets_uat_t *src = (const edhoc_secrets_uat_t*)s;
    edhoc_secrets_uat_t *dst = (edhoc_secrets_uat_t*)d;

    dst->gx_ptr = g_memdup2(src->gx_ptr, src->gx_len);
    dst->gx_len = src->gx_len;

    dst->prk_2e_ptr = g_memdup2(src->prk_2e_ptr, src->prk_2e_len);
    dst->prk_2e_len = src->prk_2e_len;

    dst->th_2_ptr = g_memdup2(src->th_2_ptr, src->th_2_len);
    dst->th_2_len = src->th_2_len;

    dst->prk_3e2m_ptr = g_memdup2(src->prk_3e2m_ptr, src->prk_3e2m_len);
    dst->prk_3e2m_len = src->prk_3e2m_len;

    dst->th_3_ptr = g_memdup2(src->th_3_ptr, src->th_3_len);
    dst->th_3_len = src->th_3_len;

    dst->prk_4e3m_ptr = g_memdup2(src->prk_4e3m_ptr, src->prk_4e3m_len);
    dst->prk_4e3m_len = src->prk_4e3m_len;

    dst->th_4_ptr = g_memdup2(src->th_4_ptr, src->th_4_len);
    dst->th_4_len = src->th_4_len;

    return d;
}

/* Sanity-checks a UAT record. */
static bool edhoc_secrets_uat_update_cb(void *r, char **err) {
    edhoc_secrets_uat_t *rec = (edhoc_secrets_uat_t *)r;
    if (rec->gx_len == 0) {
        *err = g_strdup("Empty G_X value");
        return false;
    }
    if (rec->prk_2e_len == 0) {
        *err = g_strdup("Empty PRK_2e value");
        return false;
    }
    return true;
}

static void edhoc_secrets_uat_free_cb(void *r) {
    edhoc_secrets_uat_t *rec = (edhoc_secrets_uat_t *)r;
    g_free(rec->gx_ptr);
    g_free(rec->prk_2e_ptr);
    g_free(rec->th_2_ptr);
    g_free(rec->prk_3e2m_ptr);
    g_free(rec->th_3_ptr);
    g_free(rec->prk_4e3m_ptr);
    g_free(rec->th_4_ptr);
}

static void edhoc_secrets_uat_post_update_cb(void) {
    ws_debug("loading UAT secrets with %d records", edhoc_secrets_uat_num);
    wmem_allocator_t *alloc = wmem_epan_scope();

    edhoc_secrets_clear(&uat_secrets);
    edhoc_secrets_init(&uat_secrets, alloc);

    for (unsigned ix = 0; ix < edhoc_secrets_uat_num; ++ix) {
        const edhoc_secrets_uat_t *rec = edhoc_secrets_uat_recs + ix;

        GBytes *gx_data = g_bytes_new(rec->gx_ptr, rec->gx_len);
        wmem_list_append(uat_secrets.bytes_list, gx_data);

        edhoc_secrets_t *sec = wmem_map_lookup(uat_secrets.gx_secrets, gx_data);
        if (!sec) {
            sec = wmem_alloc0(alloc, sizeof(edhoc_secrets_t));
            wmem_map_insert(uat_secrets.gx_secrets, gx_data, sec);
        }

        if (rec->prk_2e_ptr) {
            sec->prk_2e = g_bytes_new(rec->prk_2e_ptr, rec->prk_2e_len);
        }
        if (rec->th_2_ptr) {
            sec->th_2 = g_bytes_new(rec->th_2_ptr, rec->th_2_len);
        }
        if (rec->prk_3e2m_ptr) {
            sec->prk_3e2m = g_bytes_new(rec->prk_3e2m_ptr, rec->prk_3e2m_len);
        }
        if (rec->th_3_ptr) {
            sec->th_3 = g_bytes_new(rec->th_3_ptr, rec->th_3_len);
        }
        if (rec->prk_4e3m_ptr) {
            sec->prk_4e3m = g_bytes_new(rec->prk_4e3m_ptr, rec->prk_4e3m_len);
        }
        if (rec->th_4_ptr) {
            sec->th_4 = g_bytes_new(rec->th_4_ptr, rec->th_4_len);
        }
    }
}

/* UAT field callbacks */
UAT_BUFFER_CB_DEF(edhoc_secrets_uat, gx, edhoc_secrets_uat_t, gx_ptr, gx_len)
UAT_BUFFER_CB_DEF(edhoc_secrets_uat, prk_2e, edhoc_secrets_uat_t, prk_2e_ptr, prk_2e_len)
UAT_BUFFER_CB_DEF(edhoc_secrets_uat, th_2, edhoc_secrets_uat_t, th_2_ptr, th_2_len)
UAT_BUFFER_CB_DEF(edhoc_secrets_uat, prk_3e2m, edhoc_secrets_uat_t, prk_3e2m_ptr, prk_3e2m_len)
UAT_BUFFER_CB_DEF(edhoc_secrets_uat, th_3, edhoc_secrets_uat_t, th_3_ptr, th_3_len)
UAT_BUFFER_CB_DEF(edhoc_secrets_uat, prk_4e3m, edhoc_secrets_uat_t, prk_4e3m_ptr, prk_4e3m_len)
UAT_BUFFER_CB_DEF(edhoc_secrets_uat, th_4, edhoc_secrets_uat_t, th_4_ptr, th_4_len)


/// Overall registration of the protocol
void proto_register_edhoc(void) {
    proto_edhoc = proto_register_protocol("Ephemeral Diffie-Hellman Over COSE", proto_name_edhoc, "edhoc");

    // Capture scope data
    register_init_routine(&edhoc_init);
    register_cleanup_routine(&edhoc_cleanup);

    // Global scope data
    register_shutdown_routine(&edhoc_shutdown);
    edhoc_secrets_init(&uat_secrets, wmem_epan_scope());
    edhoc_cs_table = g_hash_table_new(g_int64_hash, g_int64_equal);
    for (edhoc_cs_t *suite = edhoc_cs_list; suite < edhoc_cs_list + array_length(edhoc_cs_list);
         ++suite) {
        g_hash_table_insert(edhoc_cs_table, &(suite->value), suite);
    }

    /// Field definitions
    static hf_register_info fields[] = {
        {&hf_connid_corr_true, {"EDHOC correlator ID", "edhoc.cid_true", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "A correlator outside of a message proper", HFILL}},
        {&hf_connid_corr_bytes, {"EDHOC correlator ID", "edhoc.cid_bytes", FT_BYTES, BASE_NONE, NULL, 0x0, "A correlator outside of a message proper", HFILL}},
        {&hf_method, {"Method", "edhoc.method", FT_INT64, BASE_DEC | BASE_VAL64_STRING, VALS64(edhoc_method_vals), 0x0, NULL, HFILL}},
        {&hf_suite_pref_list, {"Cipher Suite Preference List, Count", "edhoc.suite_pref_list", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_suite_pref, {"Cipher Suite Preference", "edhoc.suite_pref", FT_INT64, BASE_DEC | BASE_VAL64_STRING, VALS64(edhoc_cs_vals), 0x0, NULL, HFILL}},
        {&hf_suite_sel, {"Cipher Suite Selection", "edhoc.suite_sel", FT_INT64, BASE_DEC | BASE_VAL64_STRING, VALS64(edhoc_cs_vals), 0x0, NULL, HFILL}},
        {&hf_pubkey_i, {"Initiator ECDH public bytes", "edhoc.g_x", FT_BYTES, BASE_NONE, NULL, 0x0, "The protocol value G_X", HFILL}},
        {&hf_connid_i, {"Initiator connection ID", "edhoc.c_i", FT_BYTES, BASE_NONE, NULL, 0x0, "The protocol value C_I", HFILL}},
        {&hf_error_code, {"Error Code", "edhoc.err_code", FT_INT64, BASE_DEC | BASE_VAL64_STRING, VALS64(edhoc_err_code_vals), 0x0, "The protocol value ERR_CODE", HFILL}},
        {&hf_error_info, {"Error Info bytes", "edhoc.err_info", FT_BYTES, BASE_NONE, NULL, 0x0, "The protocol value ERR_INFO", HFILL}},
        {&hf_ead_item, {"EAD Item", "edhoc.ead", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_ead_label, {"Label", "edhoc.ead.label", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ead_label_abs, {"Absolute Label", "edhoc.ead.label_abs", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_ead_value, {"Value", "edhoc.ead.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_gy_ciphertext, {"G_Y | Ciphertext", "edhoc.gy_ciphertext", FT_BYTES, BASE_NONE, NULL, 0x0, "The concatenation of public key G_Y and ciphertext_2", HFILL}},
        {&hf_pubkey_r, {"Responder ECDH public bytes", "edhoc.g_y", FT_BYTES, BASE_NONE, NULL, 0x0, "The protocol value G_Y", HFILL}},
        {&hf_ciphertext, {"Ciphertext", "edhoc.ciphertext", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_plaintext, {"Plaintext", "edhoc.plaintext", FT_BYTES, BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL}},
        {&hf_connid_r, {"Responder connection ID", "edhoc.c_r", FT_BYTES, BASE_NONE, NULL, 0x0, "The protocol value C_R", HFILL}},
        {&hf_idcred_r, {"Responder credential ID", "edhoc.id_cred_r", FT_NONE, BASE_NONE, NULL, 0x0, "The protocol structure ID_CRED_R", HFILL}},
        {&hf_idcred_i, {"Initiator credential ID", "edhoc.id_cred_i", FT_NONE, BASE_NONE, NULL, 0x0, "The protocol structure ID_CRED_I", HFILL}},
        {&hf_idcred_kid, {"Only kid value", "edhoc.id_cred_kid", FT_BYTES, BASE_NONE, NULL, 0x0, "A single kid value", HFILL}},
        {&hf_sigmac, {"Signature or MAC", "edhoc.sign_or_mac", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_sess_idx, {"Session Index", "edhoc.sess_idx", FT_UINT64, BASE_DEC, NULL, 0x0, "Index of this session within its parent transport conversation", HFILL}},
        {&hf_sess_msg1, {"Initiator Message 1", "edhoc.sess_msg1", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}},
        {&hf_sess_prev, {"Previous message", "edhoc.sess_prev", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}},
        {&hf_sess_next, {"Next message", "edhoc.sess_next", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_NONE), 0x0, NULL, HFILL}},
    };
    proto_register_field_array(proto_edhoc, fields, array_length(fields));

    /// Tree structures
    static int *ett[] = {
        &ett_msg,
        &ett_suite_list,
        &ett_gyc,
        &ett_plain,
        &ett_idcred,
        &ett_ead_item,
        &ett_ead_value,
        &ett_error_info,
    };
    proto_register_subtree_array(ett, array_length(ett));

    static ei_register_info expertitems[] = {
        {&ei_item_type, { "edhoc.value_type", PI_MALFORMED, PI_ERROR, "Item is not the required type", EXPFILL}},
        {&ei_missing_msg1, { "edhoc.missing_msg1", PI_SEQUENCE, PI_ERROR, "Message 1 is missing from the captured conversation", EXPFILL}},
        {&ei_pubkey_len, { "edhoc.pubkey_len", PI_MALFORMED, PI_ERROR, "Public key length disagrees with selected cipher suite", EXPFILL}},
        {&ei_no_decrypt, { "edhoc.no_decrypt", PI_UNDECODED, PI_WARN, "Message not decrypted", EXPFILL}},
        {&ei_ead_critical, { "edhoc.ead_critical", PI_COMMENTS_GROUP, PI_COMMENT, "EAD item is critical", EXPFILL}},
        {&ei_ead_partial_decode, { "edhoc.ead_partial_decode", PI_UNDECODED, PI_WARN, "Data not fully dissected", EXPFILL}},
        {&ei_ead_embedded_bstr, { "edhoc.ead_embedded_bstr", PI_COMMENTS_GROUP, PI_COMMENT, "Heuristic dissection of CBOR embedded in a byte string", EXPFILL }},
        {&ei_err_partial_decode, { "edhoc.err_partial_decode", PI_UNDECODED, PI_WARN, "Data not fully dissected", EXPFILL}},
    };
    expert_module_t *expert = expert_register_protocol(proto_edhoc);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    module_t *edhoc_module = prefs_register_protocol(proto_edhoc, edhoc_reinit);
    prefs_register_bool_preference(
        edhoc_module,
        "ead_try_heur",
        "Attempt heuristic dissection of EAD values",
        "When dissecting EAD values and the dissector table does not match, attempt heuristic dissection as embedded CBOR.",
        &edhoc_ead_try_heur
    );

    /* UAT for secret management */
    static uat_field_t edhoc_secrets_uat_flds[] = {
        UAT_FLD_BUFFER(edhoc_secrets_uat, gx, "G_X bytes",
                       "Used to correlate with message_1 of an EDHOC session"),
        UAT_FLD_BUFFER(edhoc_secrets_uat, prk_2e, "PRK_2e bytes",
                       "Required for message_2 dissection"),
        UAT_FLD_BUFFER(edhoc_secrets_uat, th_2, "TH_2 bytes",
                       "Required for message_2 decryption"),
        UAT_FLD_BUFFER(edhoc_secrets_uat, prk_3e2m, "PRK_3e2m bytes",
                       "Used only when responder authenticates with DH key"),
        UAT_FLD_BUFFER(edhoc_secrets_uat, th_3, "TH_3 bytes",
                       "Required for message_3 decryption"),
        UAT_FLD_BUFFER(edhoc_secrets_uat, prk_4e3m, "PRK_4e3m bytes",
                       "Used only when initiator authenticates with DH key"),
        UAT_FLD_BUFFER(edhoc_secrets_uat, th_4, "TH_4 bytes",
                       "Required for message_4 decryption and PRK_exporter use"),
        UAT_END_FIELDS
    };
    edhoc_secrets_uat = uat_new("Shared Secrets",
            sizeof(edhoc_secrets_uat_t),   /* record size */
            "edhoc_secrets",            /* filename */
            true,                       /* from_profile */
            &edhoc_secrets_uat_recs,    /* data_ptr */
            &edhoc_secrets_uat_num,     /* numitems_ptr */
            UAT_AFFECTS_DISSECTION,     /* affects dissection of packets, but not set of named fields */
            NULL,                       /* help */
            edhoc_secrets_uat_copy_cb,  /* copy callback */
            edhoc_secrets_uat_update_cb,/* update callback */
            edhoc_secrets_uat_free_cb,  /* free callback */
            edhoc_secrets_uat_post_update_cb, /* post update callback */
            NULL,                       /* reset callback */
            edhoc_secrets_uat_flds);    /* UAT field definitions */
    prefs_register_uat_preference(edhoc_module, "secrets_uat",
                "Shared Secrets",
                "Shared secrets for message decryption",
                edhoc_secrets_uat);

    table_edhoc_ead = register_custom_dissector_table("edhoc.ead", "EDHOC EAD", proto_edhoc, g_int64_hash, g_int64_equal, g_free);
}

void proto_reg_handoff_edhoc(void) {
    handle_cbor = find_dissector("cbor");
    handle_cose_hdrs = find_dissector("cose.msg.headers");

    handle_edhoc_msg = register_dissector("edhoc", dissect_edhoc_msg, proto_edhoc);

    handle_edhoc_media = create_dissector_handle(dissect_edhoc_media, proto_edhoc);
    dissector_add_string("media_type", "application/edhoc+cbor-seq", handle_edhoc_media);

    handle_edhoc_media_cid = create_dissector_handle(dissect_edhoc_media_cid, proto_edhoc);
    dissector_add_string("media_type", "application/cid-edhoc+cbor-seq", handle_edhoc_media_cid);

    // Known EAD labels
    { // From Section 3.8.1 of RFC 9528
        uint64_t *key_int = g_new(uint64_t, 1);
        *key_int = 0;

        dissector_handle_t dis_h = create_dissector_handle_with_name_and_description(dissect_ead_padding, proto_edhoc, "padding", "Padding");
        dissector_add_custom_table_handle("edhoc.ead", key_int, dis_h);
    }
}
