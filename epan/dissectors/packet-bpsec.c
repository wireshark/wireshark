/* packet-sec.c
 * Routines for Bundle Protocol Version 7 Security (BPSec) dissection
 * References:
 *     BPSec: https://datatracker.ietf.org/doc/html/draft-ietf-dtn-bpsec-27
 *
 * Copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "config.h"

#include "packet-bpsec.h"
#include "packet-bpv7.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <wsutil/crc16.h>
#include <wsutil/crc32.h>
#include <inttypes.h>
#include "epan/wscbor.h"

/// Glib logging "domain" name
//static const char *LOG_DOMAIN = "bpsec";

/// Protocol handles
static int proto_bpsec = -1;

/// Dissect opaque CBOR data
static dissector_handle_t handle_cbor = NULL;
/// Extension sub-dissectors
static dissector_table_t param_dissectors = NULL;
static dissector_table_t result_dissectors = NULL;

static const val64_string shavar_vals[] = {
    {5, "HMAC 256/256"},
    {6, "HMAC 384/384"},
    {7, "HMAC 512/512"},
    {0, NULL},
};

static const val64_string aesvar_vals[] = {
    {1, "A128GCM"},
    {3, "A256GCM"},
    {0, NULL},
};

static int hf_bib = -1;
static int hf_bcb = -1;
static int hf_asb_target_list = -1;
static int hf_asb_target = -1;
static int hf_asb_ctxid = -1;
static int hf_asb_flags = -1;
static int hf_asb_flags_has_params = -1;
static int hf_asb_secsrc_nodeid = -1;
static int hf_asb_secsrc_uri = -1;
static int hf_asb_param_list = -1;
static int hf_asb_param_pair = -1;
static int hf_asb_param_id = -1;
static int hf_asb_result_all_list = -1;
static int hf_asb_result_tgt_list = -1;
static int hf_asb_result_tgt_ref = -1;
static int hf_asb_result_pair = -1;
static int hf_asb_result_id = -1;

static int hf_defaultsc_shavar = -1;
static int hf_defaultsc_wrapedkey = -1;
static int hf_defaultsc_scope = -1;
static int hf_defaultsc_scope_pri_block = -1;
static int hf_defaultsc_scope_tgt_head = -1;
static int hf_defaultsc_scope_sec_head = -1;
static int hf_defaultsc_hmac = -1;
static int hf_defaultsc_iv = -1;
static int hf_defaultsc_aesvar = -1;
static int hf_defaultsc_authtag = -1;

/// Field definitions
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

    {&hf_defaultsc_shavar, {"SHA Variant", "bpsec.defaultsc.shavar", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(shavar_vals), 0x0, NULL, HFILL}},
    {&hf_defaultsc_wrapedkey, {"Wrapped Key", "bpsec.defaultsc.wrappedkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_defaultsc_scope, {"BIB Scope", "bpsec.defaultsc.scope", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    {&hf_defaultsc_scope_pri_block, {"Primary Block", "bpsec.defaultsc.scope.pri_block", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001, NULL, HFILL}},
    {&hf_defaultsc_scope_tgt_head, {"Target Header", "bpsec.defaultsc.scope.tgt_head", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL}},
    {&hf_defaultsc_scope_sec_head, {"Security Header", "bpsec.defaultsc.scope.sec_head", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL}},
    {&hf_defaultsc_hmac, {"Expected HMAC", "bpsec.defaultsc.hmac", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_defaultsc_iv, {"IV", "bpsec.defaultsc.iv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_defaultsc_aesvar, {"AES Variant", "bpsec.defaultsc.aesvar", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(aesvar_vals), 0x0, NULL, HFILL}},
    {&hf_defaultsc_authtag, {"Authentication Tag", "bpsec.defaultsc.authtag", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
};

static int *const asb_flags[] = {
    &hf_asb_flags_has_params,
    NULL
};

static int *const defaultsc_scope[] = {
    &hf_defaultsc_scope_pri_block,
    &hf_defaultsc_scope_tgt_head,
    &hf_defaultsc_scope_sec_head,
    NULL
};

static int ett_asb = -1;
static int ett_asb_flags = -1;
static int ett_tgt_list = -1;
static int ett_param_list = -1;
static int ett_param_pair = -1;
static int ett_result_all_list = -1;
static int ett_result_tgt_list = -1;
static int ett_result_pair = -1;
static int ett_defaultsc_scope = -1;
/// Tree structures
static int *ett[] = {
    &ett_asb,
    &ett_asb_flags,
    &ett_tgt_list,
    &ett_param_list,
    &ett_param_pair,
    &ett_result_all_list,
    &ett_result_tgt_list,
    &ett_result_pair,
    &ett_defaultsc_scope,
};

static expert_field ei_secsrc_diff = EI_INIT;
static expert_field ei_ctxid_zero = EI_INIT;
static expert_field ei_ctxid_priv = EI_INIT;
static expert_field ei_target_invalid = EI_INIT;
static expert_field ei_value_partial_decode = EI_INIT;
static ei_register_info expertitems[] = {
    {&ei_secsrc_diff, {"bpsec.secsrc_diff", PI_SECURITY, PI_CHAT, "BPSec Security Source different from bundle Source", EXPFILL}},
    {&ei_ctxid_zero, {"bpsec.ctxid_zero", PI_SECURITY, PI_WARN, "BPSec Security Context ID zero is reserved", EXPFILL}},
    {&ei_ctxid_priv, {"bpsec.ctxid_priv", PI_SECURITY, PI_NOTE, "BPSec Security Context ID from private/experimental block", EXPFILL}},
    {&ei_target_invalid, {"bpsec.target_invalid", PI_PROTOCOL, PI_WARN, "Target block number not present", EXPFILL}},
    {&ei_value_partial_decode, {"bpsec.value_partial_decode", PI_UNDECODED, PI_WARN, "Value data not fully dissected", EXPFILL}},
};

bpsec_id_t * bpsec_id_new(wmem_allocator_t *alloc, gint64 context_id, gint64 type_id) {
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

void bpsec_id_free(wmem_allocator_t *alloc, gpointer ptr) {
    //bpsec_id_t *obj = (bpsec_id_t *)ptr;
    wmem_free(alloc, ptr);
}

gboolean bpsec_id_equal(gconstpointer a, gconstpointer b) {
    const bpsec_id_t *aobj = a;
    const bpsec_id_t *bobj = b;
    return (
        aobj && bobj
        && (aobj->context_id == bobj->context_id)
        && (aobj->type_id == bobj->type_id)
    );
}

guint bpsec_id_hash(gconstpointer key) {
    const bpsec_id_t *obj = key;
    return (
        g_int64_hash(&(obj->context_id))
        ^ g_int64_hash(&(obj->type_id))
    );
}

/** Dissect an ID-value pair within a context.
 *
 * @param dissector
 * @param typeid
 * @param tvb
 * @param pinfo
 * @param tree
 */
static gint dissect_value(dissector_handle_t dissector, gint64 *typeid, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    gint sublen = 0;
    if (dissector) {
        sublen = call_dissector_with_data(dissector, tvb, pinfo, tree, typeid);
        if ((sublen < 0) || ((guint)sublen < tvb_captured_length(tvb))) {
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
    gint offset = 0;

    wmem_array_t *targets;
    targets = wmem_array_new(wmem_packet_scope(), sizeof(guint64));

    wscbor_chunk_t *chunk_tgt_list = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array(chunk_tgt_list);
    proto_item *item_tgt_list = proto_tree_add_cbor_container(tree_asb, hf_asb_target_list, pinfo, tvb, chunk_tgt_list);
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_tgt_list)) {
        proto_tree *tree_tgt_list = proto_item_add_subtree(item_tgt_list, ett_tgt_list);

        wscbor_chunk_t *chunk_tgt = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
        guint64 *tgt_blknum = wscbor_require_uint64(wmem_packet_scope(), chunk_tgt);
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

        proto_item_set_len(item_tgt_list, offset - chunk_tgt_list->start);
    }

    wscbor_chunk_t *chunk_ctxid = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    gint64 *ctxid = wscbor_require_int64(wmem_packet_scope(), chunk_ctxid);
    proto_item *item_ctxid = proto_tree_add_cbor_int64(tree_asb, hf_asb_ctxid, pinfo, tvb, chunk_ctxid, ctxid);
    if (ctxid) {
        if (*ctxid == 0) {
            expert_add_info(pinfo, item_ctxid, &ei_ctxid_zero);
        }
        else if (*ctxid < 0) {
            expert_add_info(pinfo, item_ctxid, &ei_ctxid_priv);
        }
    }

    wscbor_chunk_t *chunk_flags = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *flags = wscbor_require_uint64(wmem_packet_scope(), chunk_flags);
    proto_tree_add_cbor_bitmask(tree_asb, hf_asb_flags, ett_asb_flags, asb_flags, pinfo, tvb, chunk_flags, flags);

    {
        bp_eid_t *secsrc = bp_eid_new(wmem_packet_scope());
        proto_item *item_secsrc = proto_tree_add_cbor_eid(tree_asb, hf_asb_secsrc_nodeid, hf_asb_secsrc_uri, pinfo, tvb, &offset, secsrc);
        if (!bp_eid_equal(data->bundle->primary->src_nodeid, secsrc)) {
            expert_add_info(pinfo, item_secsrc, &ei_secsrc_diff);
        }
    }

    if (flags && (*flags & BPSEC_ASB_HAS_PARAMS)) {
        wscbor_chunk_t *chunk_param_list = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
        wscbor_require_array(chunk_param_list);
        proto_item *item_param_list = proto_tree_add_cbor_container(tree_asb, hf_asb_param_list, pinfo, tvb, chunk_param_list);
        if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_param_list)) {
            proto_tree *tree_param_list = proto_item_add_subtree(item_param_list, ett_param_list);

            // iterate all parameters
            for (guint64 param_ix = 0; param_ix < chunk_param_list->head_value; ++param_ix) {
                wscbor_chunk_t *chunk_param_pair = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
                wscbor_require_array_size(chunk_param_pair, 2, 2);
                proto_item *item_param_pair = proto_tree_add_cbor_container(tree_param_list, hf_asb_param_pair, pinfo, tvb, chunk_param_pair);
                if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_param_pair)) {
                    proto_tree *tree_param_pair = proto_item_add_subtree(item_param_pair, ett_param_pair);

                    wscbor_chunk_t *chunk_paramid = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
                    gint64 *paramid = wscbor_require_int64(wmem_packet_scope(), chunk_paramid);
                    proto_tree_add_cbor_int64(tree_param_pair, hf_asb_param_id, pinfo, tvb, chunk_paramid, paramid);
                    if (paramid) {
                        proto_item_append_text(item_param_pair, ", ID: %" G_GINT64_FORMAT, *paramid);
                    }

                    const gint offset_value = offset;
                    wscbor_skip_next_item(wmem_packet_scope(), tvb, &offset);
                    tvbuff_t *tvb_value = tvb_new_subset_length(tvb, offset_value, offset - offset_value);

                    dissector_handle_t value_dissect = NULL;
                    if (ctxid && paramid) {
                        bpsec_id_t *key = bpsec_id_new(wmem_packet_scope(), *ctxid, *paramid);
                        value_dissect = dissector_get_custom_table_handle(param_dissectors, key);
                        bpsec_id_free(wmem_packet_scope(), key);
                    }
                    dissect_value(value_dissect, paramid, tvb_value, pinfo, tree_param_pair);

                    proto_item_set_len(item_param_pair, offset - chunk_param_pair->start);
                }
            }

            proto_item_set_len(item_param_list, offset - chunk_param_list->start);
        }
    }

    // array sizes should agree
    const guint tgt_size = wmem_array_get_count(targets);

    wscbor_chunk_t *chunk_result_all_list = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_array_size(chunk_result_all_list, tgt_size, tgt_size);
    proto_item *item_result_all_list = proto_tree_add_cbor_container(tree_asb, hf_asb_result_all_list, pinfo, tvb, chunk_result_all_list);
    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_result_all_list)) {
        proto_tree *tree_result_all_list = proto_item_add_subtree(item_result_all_list, ett_result_all_list);

        // iterate each target's results
        for (guint tgt_ix = 0; tgt_ix < tgt_size; ++tgt_ix) {
            wscbor_chunk_t *chunk_result_tgt_list = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
            wscbor_require_array(chunk_result_tgt_list);
            proto_item *item_result_tgt_list = proto_tree_add_cbor_container(tree_result_all_list, hf_asb_result_tgt_list, pinfo, tvb, chunk_result_tgt_list);
            if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_result_tgt_list)) {
                proto_tree *tree_result_tgt_list = proto_item_add_subtree(item_result_tgt_list, ett_result_tgt_list);

                // Hint at the associated target number
                if (tgt_ix < tgt_size) {
                    const guint64 *tgt_blknum = wmem_array_index(targets, tgt_ix);
                    proto_item *item_tgt_blknum = proto_tree_add_uint64(tree_result_tgt_list, hf_asb_result_tgt_ref, tvb, 0, 0, *tgt_blknum);
                    PROTO_ITEM_SET_GENERATED(item_tgt_blknum);
                }

                // iterate all results for this target
                for (guint64 result_ix = 0; result_ix < chunk_result_tgt_list->head_value; ++result_ix) {
                    wscbor_chunk_t *chunk_result_pair = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
                    wscbor_require_array_size(chunk_result_pair, 2, 2);
                    proto_item *item_result_pair = proto_tree_add_cbor_container(tree_result_tgt_list, hf_asb_result_pair, pinfo, tvb, chunk_result_pair);
                    if (!wscbor_skip_if_errors(wmem_packet_scope(), tvb, &offset, chunk_result_pair)) {
                        proto_tree *tree_result_pair = proto_item_add_subtree(item_result_pair, ett_result_pair);

                        wscbor_chunk_t *chunk_resultid = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
                        gint64 *resultid = wscbor_require_int64(wmem_packet_scope(), chunk_resultid);
                        proto_tree_add_cbor_int64(tree_result_pair, hf_asb_result_id, pinfo, tvb, chunk_resultid, resultid);
                        if (resultid) {
                            proto_item_append_text(item_result_pair, ", ID: %" G_GINT64_FORMAT, *resultid);
                        }

                        const gint offset_value = offset;
                        wscbor_skip_next_item(wmem_packet_scope(), tvb, &offset);
                        tvbuff_t *tvb_value = tvb_new_subset_length(tvb, offset_value, offset - offset_value);

                        dissector_handle_t value_dissect = NULL;
                        if (ctxid && resultid) {
                            bpsec_id_t *key = bpsec_id_new(wmem_packet_scope(), *ctxid, *resultid);
                            value_dissect = dissector_get_custom_table_handle(result_dissectors, key);
                            bpsec_id_free(wmem_packet_scope(), key);
                        }
                        dissect_value(value_dissect, resultid, tvb_value, pinfo, tree_result_pair);

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

static int dissect_defaultsc_param_shavar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *val = wscbor_require_uint64(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_uint64(tree, hf_defaultsc_shavar, pinfo, tvb, chunk, val);
    return offset;
}

static int dissect_defaultsc_param_wrappedkey(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_bstr(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_bstr(tree, hf_defaultsc_wrapedkey, pinfo, tvb, chunk);
    return offset;
}

static int dissect_defaultsc_param_scope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *flags = wscbor_require_uint64(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_bitmask(tree, hf_defaultsc_scope, ett_defaultsc_scope, defaultsc_scope, pinfo, tvb, chunk, flags);
    return offset;
}

static int dissect_defaultsc_result_hmac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_bstr(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_bstr(tree, hf_defaultsc_hmac, pinfo, tvb, chunk);
    return offset;
}

static int dissect_defaultsc_param_iv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_bstr(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_bstr(tree, hf_defaultsc_iv, pinfo, tvb, chunk);
    return offset;
}

static int dissect_defaultsc_param_aesvar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    guint64 *val = wscbor_require_uint64(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_uint64(tree, hf_defaultsc_aesvar, pinfo, tvb, chunk, val);
    return offset;
}

static int dissect_defaultsc_result_authtag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    gint offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(wmem_packet_scope(), tvb, &offset);
    wscbor_require_bstr(wmem_packet_scope(), chunk);
    proto_tree_add_cbor_bstr(tree, hf_defaultsc_authtag, pinfo, tvb, chunk);
    return offset;
}

/// Re-initialize after a configuration change
static void reinit_bpsec(void) {
}

/// Overall registration of the protocol
void proto_register_bpsec(void) {
    proto_bpsec = proto_register_protocol(
        "DTN Bundle Protocol Security", /* name */
        "BPSec", /* short name */
        "bpsec" /* abbrev */
    );

    proto_register_field_array(proto_bpsec, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t *expert = expert_register_protocol(proto_bpsec);
    expert_register_field_array(expert, expertitems, array_length(expertitems));

    param_dissectors = register_custom_dissector_table("bpsec.param", "BPSec Parameter", proto_bpsec, bpsec_id_hash, bpsec_id_equal);
    result_dissectors = register_custom_dissector_table("bpsec.result", "BPSec Result", proto_bpsec, bpsec_id_hash, bpsec_id_equal);

    prefs_register_protocol(proto_bpsec, reinit_bpsec);
}

void proto_reg_handoff_bpsec(void) {
    handle_cbor = find_dissector("cbor");

    /* Packaged extensions */
    {
        guint64 *key = g_new(guint64, 1);
        *key = 11;
        dissector_handle_t hdl = create_dissector_handle(dissect_block_bib, proto_bpsec);
        dissector_add_custom_table_handle("bpv7.block_type", key, hdl);
    }
    {
        guint64 *key = g_new(guint64, 1);
        *key = 12;
        dissector_handle_t hdl = create_dissector_handle(dissect_block_bcb, proto_bpsec);
        dissector_add_custom_table_handle("bpv7.block_type", key, hdl);
    }

    // Context 1: BIB-HMAC-SHA2
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 1;
        key->type_id = 1;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_param_shavar, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 1;
        key->type_id = 2;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_param_wrappedkey, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 1;
        key->type_id = 3;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_param_scope, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 1;
        key->type_id = 1;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_result_hmac, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.result", key, hdl);
    }
    // Context 2: BCB-AES-GCM
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 1;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_param_iv, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 2;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_param_aesvar, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 3;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_param_wrappedkey, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 4;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_param_scope, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 1;
        dissector_handle_t hdl = create_dissector_handle(dissect_defaultsc_result_authtag, proto_bpsec);
        dissector_add_custom_table_handle("bpsec.result", key, hdl);
    }

    reinit_bpsec();
}
