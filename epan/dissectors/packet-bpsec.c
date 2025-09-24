/* packet-bpsec.c
 * Routines for Bundle Protocol Version 7 Security (BPSec) dissection
 * References:
 *     RFC 9172: https://www.rfc-editor.org/rfc/rfc9172.html
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
#include <epan/expert.h>
#include <epan/tfs.h>
#include <epan/wscbor.h>

void proto_register_bpsec(void);
void proto_reg_handoff_bpsec(void);

/// Protocol handles
static int proto_bpsec;

/// Dissect opaque CBOR data
static dissector_handle_t handle_cbor;
/// Context ID sub-dissectors
static dissector_table_t secctx_dissectors;
/// Parameter value sub-dissectors
static dissector_table_t param_dissectors;
/// Result value sub-dissectors
static dissector_table_t result_dissectors;

// Field definitions
static int hf_bib;
static int hf_bcb;
static int hf_asb_target_list;
static int hf_asb_target;
static int hf_asb_ctxid;
static int hf_asb_flags;
static int hf_asb_flags_has_params;
static int hf_asb_secsrc_nodeid;
static int hf_asb_secsrc_uri;
static int hf_asb_param_list;
static int hf_asb_param_pair;
static int hf_asb_param_id;
static int hf_asb_result_all_list;
static int hf_asb_result_tgt_list;
static int hf_asb_result_tgt_ref;
static int hf_asb_result_pair;
static int hf_asb_result_id;

static int *const asb_flags[] = {
    &hf_asb_flags_has_params,
    NULL
};

// Tree structures
static int ett_asb;
static int ett_asb_flags;
static int ett_tgt_list;
static int ett_param_list;
static int ett_param_pair;
static int ett_result_all_list;
static int ett_result_tgt_list;
static int ett_result_pair;

static expert_field ei_secsrc_diff;
static expert_field ei_ctxid_zero;
static expert_field ei_ctxid_priv;
static expert_field ei_target_invalid;
static expert_field ei_value_partial_decode;

bpsec_id_t * bpsec_id_new(wmem_allocator_t *alloc, int64_t context_id, int64_t type_id) {
    bpsec_id_t *obj;
    if (alloc) {
        obj = wmem_new(alloc, bpsec_id_t);
    }
    else {
        obj = g_new(bpsec_id_t, 1);
    }
    obj->context_id = context_id;
    obj->type_id = type_id;
    return obj;
}

static gboolean bpsec_id_equal(const void *a, const void *b) {
    const bpsec_id_t *aobj = a;
    const bpsec_id_t *bobj = b;
    return (
        aobj && bobj
        && (aobj->context_id == bobj->context_id)
        && (aobj->type_id == bobj->type_id)
    );
}

static unsigned bpsec_id_hash(const void *key) {
    const bpsec_id_t *obj = key;
    return (
        g_int64_hash(&(obj->context_id))
        ^ g_int64_hash(&(obj->type_id))
    );
}

/** Dissect an ID-value pair within a context.
 *
 */
static int dissect_value(dissector_handle_t dissector, bpsec_dissector_data_t *const data, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    int sublen = 0;
    if (dissector) {
        sublen = call_dissector_with_data(dissector, tvb, pinfo, tree, data);
        if ((sublen < 0) || ((unsigned)sublen < tvb_captured_length(tvb))) {
            expert_add_info(pinfo, proto_tree_get_parent(tree), &ei_value_partial_decode);
        }
    }
    if (sublen == 0) {
        sublen = call_dissector(handle_cbor, tvb, pinfo, tree);
    }
    return sublen;
}

/** Dissector for abstract security block structure.
 */
static int dissect_block_asb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, const bp_dissector_data_t *const data, int root_hfindex) {
    proto_item *item_asb = proto_tree_add_item(tree, root_hfindex, tvb, 0, -1, ENC_NA);
    proto_tree *tree_asb = proto_item_add_subtree(item_asb, ett_asb);
    int offset = 0;

    wmem_array_t *targets;
    targets = wmem_array_new(pinfo->pool, sizeof(uint64_t));

    wscbor_chunk_t *chunk_tgt_list = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array(chunk_tgt_list);
    proto_item *item_tgt_list = proto_tree_add_cbor_container(tree_asb, hf_asb_target_list, pinfo, tvb, chunk_tgt_list);
    if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_tgt_list)) {
        proto_tree *tree_tgt_list = proto_item_add_subtree(item_tgt_list, ett_tgt_list);

        // iterate all targets
        for (uint64_t param_ix = 0; param_ix < chunk_tgt_list->head_value; ++param_ix) {
            wscbor_chunk_t *chunk_tgt = wscbor_chunk_read(pinfo->pool, tvb, &offset);
            uint64_t *tgt_blknum = wscbor_require_uint64(pinfo->pool, chunk_tgt);
            proto_item *item_tgt = proto_tree_add_cbor_uint64(tree_tgt_list, hf_asb_target, pinfo, tvb, chunk_tgt, tgt_blknum);
            if (tgt_blknum) {
                wmem_array_append(targets, tgt_blknum, 1);

                wmem_map_t *map = NULL;
                if (*tgt_blknum == 0) {
                    map = (root_hfindex == hf_bib)
                        ? data->bundle->primary->sec.data_i
                        : data->bundle->primary->sec.data_c;
                }
                else {
                    bp_block_canonical_t *found = wmem_map_lookup(data->bundle->block_nums, tgt_blknum);
                    if (found) {
                        map = (root_hfindex == hf_bib)
                            ? found->sec.data_i
                            : found->sec.data_c;
                    }
                    else {
                        expert_add_info(pinfo, item_tgt, &ei_target_invalid);
                    }
                }
                if (map && (data->block->block_number)) {
                    wmem_map_insert(
                        map,
                        data->block->block_number,
                        NULL
                    );
                }
            }
        }

        proto_item_set_len(item_tgt_list, offset - chunk_tgt_list->start);
    }

    wscbor_chunk_t *chunk_ctxid = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    int64_t *ctxid = wscbor_require_int64(pinfo->pool, chunk_ctxid);
    proto_item *item_ctxid = proto_tree_add_cbor_int64(tree_asb, hf_asb_ctxid, pinfo, tvb, chunk_ctxid, ctxid);
    if (ctxid && item_ctxid) {
        if (*ctxid == 0) {
            expert_add_info(pinfo, item_ctxid, &ei_ctxid_zero);
        }
        else if (*ctxid < 0) {
            expert_add_info(pinfo, item_ctxid, &ei_ctxid_priv);
        }

        // apply label if registered
        dissector_handle_t ctx_dis = dissector_get_custom_table_handle(secctx_dissectors, ctxid);
        const char *dis_name = dissector_handle_get_description(ctx_dis);
        if (dis_name) {
            const header_field_info *hfinfo = PITEM_HFINFO(item_ctxid);
            proto_item_set_text(item_ctxid, "%s: %s (%" PRId64 ")", hfinfo ? hfinfo->name : NULL, dis_name, *ctxid);
        }
    }

    wscbor_chunk_t *chunk_flags = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *flags = wscbor_require_uint64(pinfo->pool, chunk_flags);
    proto_tree_add_cbor_bitmask(tree_asb, hf_asb_flags, ett_asb_flags, asb_flags, pinfo, tvb, chunk_flags, flags);

    {
        bp_eid_t *secsrc = bp_eid_new(pinfo->pool);
        proto_item *item_secsrc = proto_tree_add_cbor_eid(tree_asb, hf_asb_secsrc_nodeid, hf_asb_secsrc_uri, pinfo, tvb, &offset, secsrc);
        if (!bp_eid_equal(data->bundle->primary->src_nodeid, secsrc)) {
            expert_add_info(pinfo, item_secsrc, &ei_secsrc_diff);
        }
    }

    if (flags && (*flags & BPSEC_ASB_HAS_PARAMS)) {
        wscbor_chunk_t *chunk_param_list = wscbor_chunk_read(pinfo->pool, tvb, &offset);
        wscbor_require_array(chunk_param_list);
        proto_item *item_param_list = proto_tree_add_cbor_container(tree_asb, hf_asb_param_list, pinfo, tvb, chunk_param_list);
        if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_param_list)) {
            proto_tree *tree_param_list = proto_item_add_subtree(item_param_list, ett_param_list);

            // iterate all parameters
            for (uint64_t param_ix = 0; param_ix < chunk_param_list->head_value; ++param_ix) {
                wscbor_chunk_t *chunk_param_pair = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                wscbor_require_array_size(chunk_param_pair, 2, 2);
                proto_item *item_param_pair = proto_tree_add_cbor_container(tree_param_list, hf_asb_param_pair, pinfo, tvb, chunk_param_pair);
                if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_param_pair)) {
                    proto_tree *tree_param_pair = proto_item_add_subtree(item_param_pair, ett_param_pair);

                    wscbor_chunk_t *chunk_paramid = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                    int64_t *paramid = wscbor_require_int64(pinfo->pool, chunk_paramid);
                    proto_tree_add_cbor_int64(tree_param_pair, hf_asb_param_id, pinfo, tvb, chunk_paramid, paramid);

                    const int offset_value = offset;
                    if (!wscbor_skip_next_item(pinfo->pool, tvb, &offset)) {
                        return 0;
                    }
                    tvbuff_t *tvb_value = tvb_new_subset_length(tvb, offset_value, offset - offset_value);

                    bpsec_dissector_data_t bpsec_data = { .bp = data };
                    dissector_handle_t value_dissect = NULL;
                    if (ctxid && paramid) {
                        bpsec_data.id.context_id = *ctxid;
                        bpsec_data.id.type_id = *paramid;
                        value_dissect = dissector_get_custom_table_handle(param_dissectors, &(bpsec_data.id));
                    }
                    const char *dis_name = dissector_handle_get_description(value_dissect);
                    if (paramid) {
                        proto_item_append_text(item_param_pair, ": %s (%" PRId64 ")", dis_name, *paramid);
                    }
                    dissect_value(value_dissect, &bpsec_data, tvb_value, pinfo, tree_param_pair);

                    proto_item_set_len(item_param_pair, offset - chunk_param_pair->start);
                }
            }

            proto_item_set_len(item_param_list, offset - chunk_param_list->start);
        }
    }

    // array sizes should agree
    const unsigned tgt_size = wmem_array_get_count(targets);

    wscbor_chunk_t *chunk_result_all_list = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_array_size(chunk_result_all_list, tgt_size, tgt_size);
    proto_item *item_result_all_list = proto_tree_add_cbor_container(tree_asb, hf_asb_result_all_list, pinfo, tvb, chunk_result_all_list);
    if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_result_all_list)) {
        proto_tree *tree_result_all_list = proto_item_add_subtree(item_result_all_list, ett_result_all_list);

        // iterate each target's results
        for (unsigned tgt_ix = 0; tgt_ix < tgt_size; ++tgt_ix) {
            wscbor_chunk_t *chunk_result_tgt_list = wscbor_chunk_read(pinfo->pool, tvb, &offset);
            wscbor_require_array(chunk_result_tgt_list);
            proto_item *item_result_tgt_list = proto_tree_add_cbor_container(tree_result_all_list, hf_asb_result_tgt_list, pinfo, tvb, chunk_result_tgt_list);
            if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_result_tgt_list)) {
                proto_tree *tree_result_tgt_list = proto_item_add_subtree(item_result_tgt_list, ett_result_tgt_list);

                // Hint at the associated target number
                if (tgt_ix < tgt_size) {
                    const uint64_t *tgt_blknum = wmem_array_index(targets, tgt_ix);
                    proto_item *item_tgt_blknum = proto_tree_add_uint64(tree_result_tgt_list, hf_asb_result_tgt_ref, tvb, 0, 0, *tgt_blknum);
                    proto_item_set_generated(item_tgt_blknum);
                }

                // iterate all results for this target
                for (uint64_t result_ix = 0; result_ix < chunk_result_tgt_list->head_value; ++result_ix) {
                    wscbor_chunk_t *chunk_result_pair = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                    wscbor_require_array_size(chunk_result_pair, 2, 2);
                    proto_item *item_result_pair = proto_tree_add_cbor_container(tree_result_tgt_list, hf_asb_result_pair, pinfo, tvb, chunk_result_pair);
                    if (!wscbor_skip_if_errors(pinfo->pool, tvb, &offset, chunk_result_pair)) {
                        proto_tree *tree_result_pair = proto_item_add_subtree(item_result_pair, ett_result_pair);

                        wscbor_chunk_t *chunk_resultid = wscbor_chunk_read(pinfo->pool, tvb, &offset);
                        int64_t *resultid = wscbor_require_int64(pinfo->pool, chunk_resultid);
                        proto_tree_add_cbor_int64(tree_result_pair, hf_asb_result_id, pinfo, tvb, chunk_resultid, resultid);

                        const int offset_value = offset;
                        if (!wscbor_skip_next_item(pinfo->pool, tvb, &offset)) {
                            return 0;
                        }
                        tvbuff_t *tvb_value = tvb_new_subset_length(tvb, offset_value, offset - offset_value);

                        bpsec_dissector_data_t bpsec_data = { .bp = data };
                        dissector_handle_t value_dissect = NULL;
                        if (ctxid && resultid) {
                            bpsec_data.id.context_id = *ctxid;
                            bpsec_data.id.type_id = *resultid;
                            value_dissect = dissector_get_custom_table_handle(result_dissectors, &(bpsec_data.id));
                        }
                        const char *dis_name = dissector_handle_get_description(value_dissect);
                        if (resultid) {
                            proto_item_append_text(item_result_pair, ": %s (%" PRId64 ")", dis_name, *resultid);
                        }
                        dissect_value(value_dissect, &bpsec_data, tvb_value, pinfo, tree_result_pair);

                        proto_item_set_len(item_result_pair, offset - chunk_result_pair->start);
                    }
                }

                proto_item_set_len(item_result_tgt_list, offset - chunk_result_tgt_list->start);
            }
        }

        proto_item_set_len(item_result_all_list, offset - chunk_result_all_list->start);
    }

    proto_item_set_len(item_asb, offset);
    return offset;
}

/** Dissector for Bundle Integrity block.
 */
static int dissect_block_bib(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_block_asb(tvb, pinfo, tree, (bp_dissector_data_t *)data, hf_bib);
}

/** Dissector for Bundle Confidentiality block.
 */
static int dissect_block_bcb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_block_asb(tvb, pinfo, tree, (bp_dissector_data_t *)data, hf_bcb);
}

/// Re-initialize after a configuration change
static void reinit_bpsec(void) {
}

/// Overall registration of the protocol
void proto_register_bpsec(void) {
    static hf_register_info fields[] = {
        {&hf_bib, {"BPSec Block Integrity Block", "bpsec.bib", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_bcb, {"BPSec Block Confidentiality Block", "bpsec.bcb", FT_PROTOCOL, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_target_list, {"Security Targets, Count", "bpsec.asb.target_count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_target, {"Target Block Number", "bpsec.asb.target", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_ctxid, {"Context ID", "bpsec.asb.ctxid", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_flags, {"Flags", "bpsec.asb.flags", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_flags_has_params, {"Parameters Present", "bpsec.asb.flags.has_params", FT_BOOLEAN, 8, TFS(&tfs_set_notset), BPSEC_ASB_HAS_PARAMS, NULL, HFILL}},
        {&hf_asb_secsrc_nodeid, {"Security Source", "bpsec.asb.secsrc.nodeid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_secsrc_uri, {"Security Source URI", "bpsec.asb.secsrc.uri", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_param_list, {"Security Parameters, Count", "bpsec.asb.param_count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_param_pair, {"Parameter", "bpsec.asb.param", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_param_id, {"Type ID", "bpsec.asb.param.id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_result_all_list, {"Security Result Targets, Count", "bpsec.asb.result_count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_result_tgt_ref, {"Associated Target Block Number", "bpsec.asb.result_tgt_ref", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_result_tgt_list, {"Security Results, Count", "bpsec.asb.result_count", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_result_pair, {"Result", "bpsec.asb.result", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_asb_result_id, {"Type ID", "bpsec.asb.result.id", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    };
    static int *ett[] = {
        &ett_asb,
        &ett_asb_flags,
        &ett_tgt_list,
        &ett_param_list,
        &ett_param_pair,
        &ett_result_all_list,
        &ett_result_tgt_list,
        &ett_result_pair,
    };
    static ei_register_info expertitems[] = {
        {&ei_secsrc_diff, {"bpsec.secsrc_diff", PI_SECURITY, PI_CHAT, "BPSec Security Source different from bundle Source", EXPFILL}},
        {&ei_ctxid_zero, {"bpsec.ctxid_zero", PI_SECURITY, PI_WARN, "BPSec Security Context ID zero is reserved", EXPFILL}},
        {&ei_ctxid_priv, {"bpsec.ctxid_priv", PI_SECURITY, PI_NOTE, "BPSec Security Context ID from private/experimental block", EXPFILL}},
        {&ei_target_invalid, {"bpsec.target_invalid", PI_PROTOCOL, PI_WARN, "Target block number not present", EXPFILL}},
        {&ei_value_partial_decode, {"bpsec.value_partial_decode", PI_UNDECODED, PI_WARN, "Value data not fully dissected", EXPFILL}},
    };

    proto_bpsec = proto_register_protocol(
        "DTN Bundle Protocol Security",
        "BPSec",
        "bpsec"
    );

    proto_register_field_array(proto_bpsec, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_bpsec);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    secctx_dissectors = register_custom_dissector_table("bpsec.ctx", "BPSec Context", proto_bpsec, g_int64_hash, g_int64_equal, g_free);
    param_dissectors = register_custom_dissector_table("bpsec.param", "BPSec Parameter", proto_bpsec, bpsec_id_hash, bpsec_id_equal, g_free);
    result_dissectors = register_custom_dissector_table("bpsec.result", "BPSec Result", proto_bpsec, bpsec_id_hash, bpsec_id_equal, g_free);

    prefs_register_protocol(proto_bpsec, reinit_bpsec);
}

void proto_reg_handoff_bpsec(void) {
    handle_cbor = find_dissector("cbor");

    /* Packaged extensions */
    {
        uint64_t *key = g_new(uint64_t, 1);
        *key = BP_BLOCKTYPE_BIB;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_block_bib, proto_bpsec, NULL, "Block Integrity Block");
        dissector_add_custom_table_handle("bpv7.block_type", key, hdl);
    }
    {
        uint64_t *key = g_new(uint64_t, 1);
        *key = BP_BLOCKTYPE_BCB;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_block_bcb, proto_bpsec, NULL, "Block Confidentiality Block");
        dissector_add_custom_table_handle("bpv7.block_type", key, hdl);
    }

    reinit_bpsec();
}
