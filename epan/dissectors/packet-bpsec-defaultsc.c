/* packet-bpsec-defaultsc.c
 * BPSec Default security contexts
 * References:
 *     RFC 9173: https://www.rfc-editor.org/rfc/rfc9173.html
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
#include <stdint.h>

#include "packet-bpsec.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/tfs.h>
#include <epan/wscbor.h>

void proto_register_bpsec_defaultsc(void);
void proto_reg_handoff_bpsec_defaultsc(void);

/// Protocol handles
static int proto_bpsec_defaultsc;

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

// Field definitions
static int hf_defaultsc_shavar;
static int hf_defaultsc_wrapedkey;
static int hf_defaultsc_scope;
static int hf_defaultsc_scope_pri_block;
static int hf_defaultsc_scope_tgt_head;
static int hf_defaultsc_scope_sec_head;
static int hf_defaultsc_hmac;
static int hf_defaultsc_iv;
static int hf_defaultsc_aesvar;
static int hf_defaultsc_authtag;

static int *const defaultsc_scope[] = {
    &hf_defaultsc_scope_pri_block,
    &hf_defaultsc_scope_tgt_head,
    &hf_defaultsc_scope_sec_head,
    NULL
};

// Tree structures
static int ett_defaultsc_scope;

static int dissect_defaultsc_param_shavar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *val = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree, hf_defaultsc_shavar, pinfo, tvb, chunk, val);
    return offset;
}

static int dissect_defaultsc_param_wrappedkey(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_bstr(pinfo->pool, chunk);
    proto_tree_add_cbor_bstr(tree, hf_defaultsc_wrapedkey, pinfo, tvb, chunk);
    return offset;
}

static int dissect_defaultsc_param_scope(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *flags = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_bitmask(tree, hf_defaultsc_scope, ett_defaultsc_scope, defaultsc_scope, pinfo, tvb, chunk, flags);
    return offset;
}

static int dissect_defaultsc_result_hmac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_bstr(pinfo->pool, chunk);
    proto_tree_add_cbor_bstr(tree, hf_defaultsc_hmac, pinfo, tvb, chunk);
    return offset;
}

static int dissect_defaultsc_param_iv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_bstr(pinfo->pool, chunk);
    proto_tree_add_cbor_bstr(tree, hf_defaultsc_iv, pinfo, tvb, chunk);
    return offset;
}

static int dissect_defaultsc_param_aesvar(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    uint64_t *val = wscbor_require_uint64(pinfo->pool, chunk);
    proto_tree_add_cbor_uint64(tree, hf_defaultsc_aesvar, pinfo, tvb, chunk, val);
    return offset;
}

static int dissect_defaultsc_result_authtag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    int offset = 0;
    wscbor_chunk_t *chunk = wscbor_chunk_read(pinfo->pool, tvb, &offset);
    wscbor_require_bstr(pinfo->pool, chunk);
    proto_tree_add_cbor_bstr(tree, hf_defaultsc_authtag, pinfo, tvb, chunk);
    return offset;
}

/// Re-initialize after a configuration change
static void reinit_bpsec_defaultsc(void) {
}

/// Overall registration of the protocol
void proto_register_bpsec_defaultsc(void) {
    static hf_register_info fields[] = {
        {&hf_defaultsc_shavar, {"SHA Variant", "bpsec-defaultsc.shavar", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(shavar_vals), 0x0, NULL, HFILL}},
        {&hf_defaultsc_wrapedkey, {"Wrapped Key", "bpsec-defaultsc.wrappedkey", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_defaultsc_scope, {"BIB Scope", "bpsec-defaultsc.scope", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL}},
        {&hf_defaultsc_scope_pri_block, {"Primary Block", "bpsec-defaultsc.scope.pri_block", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0001, NULL, HFILL}},
        {&hf_defaultsc_scope_tgt_head, {"Target Header", "bpsec-defaultsc.scope.tgt_head", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0002, NULL, HFILL}},
        {&hf_defaultsc_scope_sec_head, {"Security Header", "bpsec-defaultsc.scope.sec_head", FT_BOOLEAN, 16, TFS(&tfs_set_notset), 0x0004, NULL, HFILL}},
        {&hf_defaultsc_hmac, {"Expected HMAC", "bpsec-defaultsc.hmac", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_defaultsc_iv, {"IV", "bpsec-defaultsc.iv", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_defaultsc_aesvar, {"AES Variant", "bpsec-defaultsc.aesvar", FT_UINT64, BASE_DEC | BASE_VAL64_STRING, VALS64(aesvar_vals), 0x0, NULL, HFILL}},
        {&hf_defaultsc_authtag, {"Authentication Tag", "bpsec-defaultsc.authtag", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };
    static int *ett[] = {
        &ett_defaultsc_scope,
    };

    proto_bpsec_defaultsc = proto_register_protocol(
        "BPSec Default Security Contexts", /* name */
        "BPSec Default SC", /* short name */
        "bpsec-defaultsc" /* abbrev */
    );

    proto_register_field_array(proto_bpsec_defaultsc, fields, array_length(fields));
    proto_register_subtree_array(ett, array_length(ett));

    prefs_register_protocol(proto_bpsec_defaultsc, reinit_bpsec_defaultsc);
}

void proto_reg_handoff_bpsec_defaultsc(void) {
    // Context 1: BIB-HMAC-SHA2
    {
        int64_t *key = g_new0(int64_t, 1);
        *key = 1;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(NULL, proto_bpsec_defaultsc, NULL, "BIB-HMAC-SHA2");
        dissector_add_custom_table_handle("bpsec.ctx", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 1;
        key->type_id = 1;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_param_shavar, proto_bpsec_defaultsc, NULL, "BIB-HMAC-SHA2 SHA Variant");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 1;
        key->type_id = 2;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_param_wrappedkey, proto_bpsec_defaultsc, NULL, "BIB-HMAC-SHA2 Wrapped Key");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 1;
        key->type_id = 3;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_param_scope, proto_bpsec_defaultsc, NULL, "BIB-HMAC-SHA2 AAD Scope");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 1;
        key->type_id = 1;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_result_hmac, proto_bpsec_defaultsc, NULL, "BIB-HMAC-SHA2 Tag");
        dissector_add_custom_table_handle("bpsec.result", key, hdl);
    }

    // Context 2: BCB-AES-GCM
    {
        int64_t *key = g_new0(int64_t, 1);
        *key = 2;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(NULL, proto_bpsec_defaultsc, NULL, "BCB-AES-GCM");
        dissector_add_custom_table_handle("bpsec.ctx", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 1;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_param_iv, proto_bpsec_defaultsc, NULL, "BCB-AES-GCM IV");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 2;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_param_aesvar, proto_bpsec_defaultsc, NULL, "BCB-AES-GCM AES Variant");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 3;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_param_wrappedkey, proto_bpsec_defaultsc, NULL, "BCB-AES-GCM Wrapped Key");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 4;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_param_scope, proto_bpsec_defaultsc, NULL, "BCB-AES-GCM AAD Scope");
        dissector_add_custom_table_handle("bpsec.param", key, hdl);
    }
    {
        bpsec_id_t *key = g_new(bpsec_id_t, 1);
        key->context_id = 2;
        key->type_id = 1;
        dissector_handle_t hdl = create_dissector_handle_with_name_and_description(dissect_defaultsc_result_authtag, proto_bpsec_defaultsc, NULL, "BCB-AES-GCM Tag");
        dissector_add_custom_table_handle("bpsec.result", key, hdl);
    }

    reinit_bpsec_defaultsc();
}
