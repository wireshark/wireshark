/* packet-bpsec-cose.c
 * BPSec COSE Context
 * References:
 *     https://datatracker.ietf.org/doc/draft-ietf-dtn-bpsec-cose/
 *
 * Copyright 2019-2024, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "config.h"
#include <stdint.h>

#include "packet-bpsec.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/tfs.h>
#include <epan/wscbor.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <inttypes.h>

void proto_register_bpsec_cose(void);
void proto_reg_handoff_bpsec_cose(void);

/** AAD Scope parameter.
 * Section 3.2.2.
 */
typedef enum {
    AAD_METADATA = 0x01,
    AAD_BTSD = 0x02,
} AadScopeFlag;

/// IANA registered security context ID
static const int64_t bpsec_cose_ctxid = 3;

/// Protocol handles
static int proto_bpsec_cose;

/// Dissect opaque CBOR parameters/results
static dissector_table_t table_cose_msg;
/// Handle for COSE header maps
static dissector_handle_t handle_cose_msg_hdr;

// Field definitions
static int hf_aad_scope;
static int hf_aad_blknum;
static int hf_aad_flags;
static int hf_aad_flags_metadata;
static int hf_aad_flags_btsd;
static int hf_addl_prot_bstr;
static int hf_addl_unprot_bstr;
static int hf_cose_msg;

static int *const aad_flags[] = {
    &hf_aad_flags_metadata,
    &hf_aad_flags_btsd,
    NULL
};

// Tree structures
static int ett_aad_scope;
static int ett_aad_blknum;
static int ett_aad_flags;
static int ett_addl_hdr_bstr;
static int ett_addl_hdr;
static int ett_cose_msg;

/** Dissector for AAD Scope parameter.
 */
static int dissect_param_scope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;

    wscbor_chunk_t *chunk_aad_map = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_map(chunk_aad_map);
    proto_item *item_aad_map = proto_tree_add_cbor_container(tree, hf_aad_scope, pinfo, tvb, chunk_aad_map);
    wscbor_chunk_mark_errors(pinfo, item_aad_map, chunk_aad_map);
    if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_aad_map)) {
        proto_tree *tree_aad_map = proto_item_add_subtree(item_aad_map, ett_aad_scope);

        for (guint64 ix = 0; ix < chunk_aad_map->head_value; ++ix) {
            wscbor_chunk_t *chunk_blknum = wscbor_chunk_read(pinfo->pool, tvb, &offset);
            int64_t *blknum = wscbor_require_int64(pinfo->pool, chunk_blknum);
            proto_item *item_blknum = proto_tree_add_cbor_int64(tree_aad_map, hf_aad_blknum, pinfo, tvb, chunk_blknum, blknum);
            proto_tree *tree_blknum = proto_item_add_subtree(item_blknum, ett_aad_blknum);

            wscbor_chunk_t *chunk_flags = wscbor_chunk_read(pinfo->pool, tvb, &offset);
            guint64 *flags = wscbor_require_uint64(pinfo->pool, chunk_flags);
            proto_tree_add_cbor_bitmask(tree_blknum, hf_aad_flags, ett_aad_flags, aad_flags, pinfo, tvb, chunk_flags, flags);
        }
    }
    proto_item_set_len(item_aad_map, offset);

    return offset;
}

/** Dissector for COSE protected header.
 */
static int dissect_addl_protected(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;

    wscbor_chunk_t *chunk_hdr_bstr = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    tvbuff_t *hdr_bstr = wscbor_require_bstr(pinfo->pool, chunk_hdr_bstr);
    proto_item *item_hdr_bstr = proto_tree_add_cbor_bstr(tree, hf_addl_prot_bstr, pinfo, tvb, chunk_hdr_bstr);
    if (hdr_bstr) {
        proto_tree *tree_hdr_bstr = proto_item_add_subtree(item_hdr_bstr, ett_addl_hdr_bstr);

        int sublen = call_dissector(handle_cose_msg_hdr, hdr_bstr, pinfo, tree_hdr_bstr);
        if (sublen < 0) {
            return sublen;
        }
        offset += sublen;
    }

    return offset;
}

/** Dissector for COSE unprotected header.
 */
static int dissect_addl_unprotected(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;

    wscbor_chunk_t *chunk_hdr_bstr = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    tvbuff_t *hdr_bstr = wscbor_require_bstr(pinfo->pool, chunk_hdr_bstr);
    proto_item *item_hdr_bstr = proto_tree_add_cbor_bstr(tree, hf_addl_unprot_bstr, pinfo, tvb, chunk_hdr_bstr);
    if (hdr_bstr) {
        proto_tree *tree_hdr_bstr = proto_item_add_subtree(item_hdr_bstr, ett_addl_hdr_bstr);

        int sublen = call_dissector(handle_cose_msg_hdr, hdr_bstr, pinfo, tree_hdr_bstr);
        if (sublen < 0) {
            return sublen;
        }
        offset += sublen;
    }

    return offset;
}

/** Dissector for bstr-wrapped CBOR.
 */
static int dissect_cose_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    bpsec_id_t *secid = data;
    DISSECTOR_ASSERT(secid != NULL);
    int offset = 0;

    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    tvbuff_t *tvb_data = wscbor_require_bstr(pinfo->pool, chunk);

    proto_item *item_msg = proto_tree_add_cbor_bstr(tree, hf_cose_msg, pinfo, tvb, chunk);
    proto_tree *tree_msg = proto_item_add_subtree(item_msg, ett_cose_msg);

    if (tvb_data) {
        dissector_handle_t dissector = dissector_get_custom_table_handle(table_cose_msg, &(secid->type_id));
        int sublen = call_dissector(dissector, tvb_data, pinfo, tree_msg);
        if (sublen < 0) {
            return sublen;
        }
    }

    return offset;
}

/// Re-initialize after a configuration change
static void reinit_bpsec_cose(void) {
}

/// Overall registration of the protocol
void proto_register_bpsec_cose(void) {
    static hf_register_info fields[] = {
        {&hf_aad_scope, {"AAD Scope, Block count", "bpsec-cose.aad_scope", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_aad_blknum, {"Block Number", "bpsec-cose.aad_scope.blknum", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_aad_flags, {"Flags", "bpsec-cose.aad_scope.flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_aad_flags_metadata, {"Metadata", "bpsec-cose.aad_scope.flags.metadata", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AAD_METADATA, NULL, HFILL}},
        {&hf_aad_flags_btsd, {"BTSD", "bpsec-cose.aad_scope.flags.btsd", FT_BOOLEAN, 8, TFS(&tfs_set_notset), AAD_BTSD, NULL, HFILL}},
        {&hf_addl_prot_bstr, {"Additional Protected Headers (bstr)", "bpsec-cose.addl_protected_bstr", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_addl_unprot_bstr, {"Additional Unprotected Headers (bstr)", "bpsec-cose.addl_unprotected", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_cose_msg, {"COSE Message (bstr)", "bpsec-cose.msg", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };
    static int *ett[] = {
        &ett_aad_scope,
        &ett_aad_blknum,
        &ett_aad_flags,
        &ett_addl_hdr_bstr,
        &ett_addl_hdr,
        &ett_cose_msg,
    };

    proto_bpsec_cose = proto_register_protocol("BPSec COSE Context", "BPSec COSE", "bpsec-cose");

    proto_register_field_array(proto_bpsec_cose, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));

    prefs_register_protocol(proto_bpsec_cose, reinit_bpsec_cose);
}

static void bpsec_cose_result_register(int64_t result_id, const char *dis_name) {
    bpsec_id_t *rkey = bpsec_id_new(NULL, bpsec_cose_ctxid, result_id);
    const char *description = dissector_handle_get_description(find_dissector_add_dependency(dis_name, proto_bpsec_cose));
    dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_cose_msg, proto_bpsec_cose, NULL, description);
    dissector_add_custom_table_handle("bpsec.result", rkey, hdl);

}

void proto_reg_handoff_bpsec_cose(void) {
    table_cose_msg = find_dissector_table("cose.msgtag");
    handle_cose_msg_hdr = find_dissector_add_dependency("cose.msg.headers", proto_bpsec_cose);

    /* Packaged extensions */
    {
        int64_t *key = g_new0(int64_t, 1);
        *key = 3;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(NULL, proto_bpsec_cose, NULL, "COSE");
        dissector_add_custom_table_handle("bpsec.ctx", key, hdl);
    }
    {
        bpsec_id_t *key = bpsec_id_new(NULL, bpsec_cose_ctxid, 3);
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_addl_protected, proto_bpsec_cose, NULL, "Additional Protected Headers");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = bpsec_id_new(NULL, bpsec_cose_ctxid, 4);
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_addl_unprotected, proto_bpsec_cose, NULL, "Additional Unprotected Headers");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = bpsec_id_new(NULL, bpsec_cose_ctxid, 5);
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_param_scope, proto_bpsec_cose, NULL, "AAD Scope");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }

    // Propagate COSE tags as result IDs
    bpsec_cose_result_register(98, "cose_sign");
    bpsec_cose_result_register(18, "cose_sign1");
    bpsec_cose_result_register(96, "cose_encrypt");
    bpsec_cose_result_register(16, "cose_encrypt0");
    bpsec_cose_result_register(97, "cose_mac");
    bpsec_cose_result_register(17, "cose_mac0");

    reinit_bpsec_cose();
}
