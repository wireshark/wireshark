/* packet-vpp.c
 *
 * Routines for the disassembly of fd.io vpp project
 * dispatch captures
 *
 * Copyright 2019, Dave Barach <wireshark@barachs.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/nlpid.h>
#include <epan/etypes.h>
#include <stdio.h>
#include <wsutil/ws_printf.h>

void proto_register_vpp(void);
void proto_reg_handoff_vpp(void);

static int proto_vpp = -1;
static int proto_vpp_metadata = -1;
static int proto_vpp_opaque = -1;
static int proto_vpp_opaque2 = -1;
static int proto_vpp_trace = -1;
static int hf_vpp_nodename = -1;
static int hf_vpp_metadata = -1;
static int hf_vpp_buffer_index = -1;
static int hf_vpp_buffer_opaque = -1;
static int hf_vpp_buffer_opaque2 = -1;
static int hf_vpp_buffer_trace = -1;
static int hf_vpp_major_version = -1;
static int hf_vpp_minor_version = -1;
static int hf_vpp_protocol_hint = -1;

static expert_module_t* expert_vpp;

static expert_field ei_vpp_major_version_error = EI_INIT;
static expert_field ei_vpp_minor_version_error = EI_INIT;
static expert_field ei_vpp_protocol_hint_error = EI_INIT;

static gint ett_vpp = -1;
static gint ett_vpp_opaque = -1;
static gint ett_vpp_opaque2 = -1;
static gint ett_vpp_metadata = -1;
static gint ett_vpp_trace = -1;

static dissector_handle_t vpp_dissector_handle;
static dissector_handle_t vpp_opaque_dissector_handle;
static dissector_handle_t vpp_opaque2_dissector_handle;
static dissector_handle_t vpp_metadata_dissector_handle;
static dissector_handle_t vpp_trace_dissector_handle;

#define VPP_MAJOR_VERSION       1
#define VPP_MINOR_VERSION       0
#define IP4_TYPICAL_VERSION_LENGTH      0x45
#define IP6_TYPICAL_VERSION_AND_TRAFFIC_CLASS   0x60

typedef enum
  {
    VLIB_NODE_PROTO_HINT_NONE = 0,
    VLIB_NODE_PROTO_HINT_ETHERNET,
    VLIB_NODE_PROTO_HINT_IP4,
    VLIB_NODE_PROTO_HINT_IP6,
    VLIB_NODE_PROTO_HINT_TCP,
    VLIB_NODE_PROTO_HINT_UDP,
    VLIB_NODE_N_PROTO_HINTS,
  } vlib_node_proto_hint_t;

static dissector_handle_t next_dissectors[VLIB_NODE_N_PROTO_HINTS];

/* List of next dissectors hints that we know about */
#define foreach_next_dissector                          \
_(VLIB_NODE_PROTO_HINT_ETHERNET, eth_withoutfcs)        \
_(VLIB_NODE_PROTO_HINT_IP4, ip)                         \
_(VLIB_NODE_PROTO_HINT_IP6, ipv6)                       \
_(VLIB_NODE_PROTO_HINT_TCP, tcp)                        \
_(VLIB_NODE_PROTO_HINT_UDP, udp)

static void
add_multi_line_string_to_tree(proto_tree *tree, tvbuff_t *tvb, gint start,
                              gint len, int hf)
{
    gint next;
    int line_len;
    int data_len;

    while(len > 0) {
        line_len = tvb_find_line_end(tvb, start, len, &next, FALSE);
        data_len = next - start;
        proto_tree_add_string(tree, hf, tvb, start, data_len,
                              tvb_format_stringzpad(tvb, start, line_len));
        start += data_len;
        len -= data_len;
    }
}

static int
dissect_vpp_metadata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                     void* data _U_)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *metadata_tree;
    gint metadata_string_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VPP-Metadata");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vpp_metadata, tvb, offset, -1, ENC_NA);
    metadata_tree = proto_item_add_subtree(ti, ett_vpp_metadata);

    /* How long is the metadata string? */
    metadata_string_length = tvb_strsize(tvb, offset);

    add_multi_line_string_to_tree(metadata_tree, tvb, 0,
                                  metadata_string_length,
                                  hf_vpp_metadata);
    return tvb_captured_length(tvb);
}

static int
dissect_vpp_trace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  void* data _U_)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *trace_tree;
    gint trace_string_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VPP-Trace");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vpp_trace, tvb, offset, -1, ENC_NA);
    trace_tree = proto_item_add_subtree(ti, ett_vpp_trace);

    /* How long is the trace string? */
    trace_string_length = tvb_strsize(tvb, offset);

    add_multi_line_string_to_tree(trace_tree, tvb, 0,
                                  trace_string_length,
                                  hf_vpp_buffer_trace);
    return tvb_captured_length(tvb);
}


static int
dissect_vpp_opaque(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   void* data _U_)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *opaque_tree;
    gint opaque_string_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VPP-Opaque");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vpp_opaque, tvb, offset, -1, ENC_NA);
    opaque_tree = proto_item_add_subtree(ti, ett_vpp_opaque);

    opaque_string_length = tvb_strsize(tvb, offset);
    add_multi_line_string_to_tree(opaque_tree, tvb, 0, opaque_string_length,
                                  hf_vpp_buffer_opaque);

    return tvb_captured_length(tvb);
}

static int
dissect_vpp_opaque2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    void* data _U_)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *opaque2_tree;
    gint opaque2_string_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VPP-Opaque2");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vpp_opaque2, tvb, offset, -1, ENC_NA);
    opaque2_tree = proto_item_add_subtree(ti, ett_vpp_opaque2);

    opaque2_string_length = tvb_strsize(tvb, offset);
    add_multi_line_string_to_tree(opaque2_tree, tvb, 0, opaque2_string_length,
                                  hf_vpp_buffer_opaque2);

    return tvb_captured_length(tvb);
}


static int
dissect_vpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *vpp_tree;
    tvbuff_t *metadata_tvb, *opaque_tvb, *opaque2_tvb, *eth_tvb, *trace_tvb;
    int offset = 0;
    guint8 major_version, minor_version, string_count, protocol_hint;
    guint8 *name;
    guint len;
    guint8 maybe_protocol_id;
    dissector_handle_t use_this_dissector;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VPP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vpp, tvb, offset, -1, ENC_NA);
    vpp_tree = proto_item_add_subtree(ti, ett_vpp);

    major_version = tvb_get_guint8(tvb, offset);
    /* If the major version doesn't match, quit on the spot */
    if(major_version != VPP_MAJOR_VERSION) {
        proto_item *major_version_item;
        major_version_item =
            proto_tree_add_item(tree, hf_vpp_major_version,
                                tvb, offset, 1, ENC_NA);
        expert_add_info_format(pinfo, major_version_item,
                               &ei_vpp_major_version_error,
                               "Major Version Mismatch read %d not %d",
                               (int)major_version, VPP_MAJOR_VERSION);
        return tvb_captured_length(tvb);
    }
    offset++;

    minor_version = tvb_get_guint8(tvb, offset);
    /* If the minor version doesn't match, make a note and try to continue */
    if(minor_version != VPP_MINOR_VERSION) {
        proto_item *minor_version_item;
        minor_version_item =
            proto_tree_add_item(tree, hf_vpp_minor_version,
                                tvb, offset, 1, ENC_NA);
        expert_add_info_format(pinfo, minor_version_item,
                               &ei_vpp_minor_version_error,
                               "Minor Version Mismatch read %d not %d",
                               (int)minor_version, VPP_MINOR_VERSION);
    }
    offset++;

    /* Number of counted strings in this trace record */
    string_count = tvb_get_guint8(tvb, offset);
    offset++;

    /*
     * Hint: protocol which should be at b->data[b->current_data]
     * It will be a while before vpp sends useful hints for every
     * possible node, see heuristic below.
     */
    protocol_hint = tvb_get_guint8(tvb, offset);

    if(protocol_hint >= array_length(next_dissectors)) {
        proto_item *protocol_hint_item;
        protocol_hint_item =
            proto_tree_add_item(tree, hf_vpp_protocol_hint,
                                tvb, offset, 1, ENC_NA);
        expert_add_info_format(pinfo, protocol_hint_item,
                               &ei_vpp_protocol_hint_error,
                               "Protocol hint %d out of range, max %d",
                               (int)protocol_hint,
                               (int)array_length(next_dissectors));
        protocol_hint = 0;
    }

    offset++;

    /* Buffer Index */
    proto_tree_add_item(vpp_tree, hf_vpp_buffer_index, tvb,
                        offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* Nodename */
    len = tvb_strsize(tvb, offset);
    name = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, len,
                              ENC_ASCII);
    proto_tree_add_string(tree, hf_vpp_nodename, tvb, offset, len, name);
    offset += len;

    /* Metadata */
    len = tvb_strsize(tvb, offset);
    metadata_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(vpp_metadata_dissector_handle, metadata_tvb, pinfo, tree);
    offset += len;

    /* Opaque */
    len = tvb_strsize(tvb, offset);
    opaque_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(vpp_opaque_dissector_handle, opaque_tvb, pinfo, tree);
    offset += len;

    /* Opaque2 */
    len = tvb_strsize(tvb, offset);
    opaque2_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(vpp_opaque2_dissector_handle, opaque2_tvb, pinfo, tree);
    offset += len;

    /* Trace, if present */
    if(string_count > 4) {
        len = tvb_strsize(tvb, offset);
        trace_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector(vpp_trace_dissector_handle, trace_tvb, pinfo, tree);
        offset += len;
    }

    eth_tvb = tvb_new_subset_remaining(tvb, offset);

    /*
     * Delegate the rest of the packet dissection to the per-node
     * next dissector in the foreach_node_to_dissector_pair list
     *
     * Failing that, pretend its an ethernet packet
     */
    /* See setup for hint == 0 below */
    use_this_dissector = next_dissectors [protocol_hint];
    if(protocol_hint == 0) {
        maybe_protocol_id = tvb_get_guint8(tvb, offset);

        switch(maybe_protocol_id) {
        case IP4_TYPICAL_VERSION_LENGTH:
            use_this_dissector = next_dissectors[VLIB_NODE_PROTO_HINT_IP4];
            break;
        case IP6_TYPICAL_VERSION_AND_TRAFFIC_CLASS:
            use_this_dissector = next_dissectors[VLIB_NODE_PROTO_HINT_IP6];
            break;
        default:
            break;
        }
    }
    call_dissector(use_this_dissector, eth_tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}

void
proto_register_vpp(void)
{
    static hf_register_info vpp_hf[] = {
        { &hf_vpp_buffer_index,
          { "BufferIndex", "vpp.BufferIndex",  FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_vpp_nodename,
          { "NodeName", "vpp.NodeName",  FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_vpp_major_version,
          { "MajorVersion", "vpp.MajorVersion",  FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_vpp_minor_version,
          { "MinorVersion", "vpp.MinorVersion",  FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL },
        },
        { &hf_vpp_protocol_hint,
          { "ProtocolHint", "vpp.ProtocolHint",  FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL },
        },
    };

    static ei_register_info vpp_ei[] = {
        { &ei_vpp_major_version_error,
          { "vpp.bad_major_version", PI_MALFORMED, PI_ERROR,
            "Bad Major Version", EXPFILL }},
        { &ei_vpp_minor_version_error,
          { "vpp.bad_minor_version", PI_UNDECODED, PI_WARN,
            "Bad Minor Version", EXPFILL }},
        { &ei_vpp_protocol_hint_error,
          { "vpp.bad_protocol_hint", PI_PROTOCOL, PI_WARN,
            "Bad Protocol Hint", EXPFILL }},
    };

    static hf_register_info metadata_hf[] = {
        { &hf_vpp_metadata,
          { "Metadata", "vpp.metadata",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
    };

    static hf_register_info opaque_hf[] = {
        { &hf_vpp_buffer_opaque,
          { "Opaque", "vpp.opaque",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
    };

    static hf_register_info opaque2_hf[] = {
        { &hf_vpp_buffer_opaque2,
          { "Opaque2", "vpp.opaque2",
            FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
        },
    };

    static hf_register_info trace_hf[] = {
        { &hf_vpp_buffer_trace,
          { "Trace", "vpp.trace",  FT_STRINGZ, BASE_NONE, NULL, 0x0,
            NULL, HFILL },
        },
    };

    static gint *vpp_ett[] = {
        &ett_vpp,
    };
    static gint *ett_metadata[] = {
        &ett_vpp_metadata,
    };
    static gint *ett_opaque[] = {
        &ett_vpp_opaque,
    };
    static gint *ett_opaque2[] = {
        &ett_vpp_opaque2,
    };
    static gint *ett_trace[] = {
        &ett_vpp_trace,
    };

    proto_vpp = proto_register_protocol("VPP Dispatch Trace", "VPP", "vpp");
    proto_register_field_array(proto_vpp, vpp_hf, array_length(vpp_hf));
    proto_register_subtree_array(vpp_ett, array_length(vpp_ett));
    register_dissector("vpp", dissect_vpp, proto_vpp);

    expert_vpp = expert_register_protocol(proto_vpp);
    expert_register_field_array(expert_vpp, vpp_ei, array_length(vpp_ei));

    proto_vpp_metadata = proto_register_protocol("VPP Buffer Metadata",
                                                 "VPP-Metadata",
                                                 "vpp-metadata");
    proto_register_field_array(proto_vpp_metadata, metadata_hf,
                               array_length(metadata_hf));
    proto_register_subtree_array(ett_metadata, array_length(ett_metadata));
    register_dissector("vppMetadata", dissect_vpp_metadata, proto_vpp_metadata);

    proto_vpp_opaque = proto_register_protocol("VPP Buffer Opaque", "VPP-Opaque",
                                               "vpp-opaque");
    proto_register_field_array(proto_vpp_opaque, opaque_hf,
                               array_length(opaque_hf));
    proto_register_subtree_array(ett_opaque, array_length(ett_opaque));
    register_dissector("vppOpaque", dissect_vpp_opaque, proto_vpp_opaque);

    proto_vpp_opaque2 = proto_register_protocol("VPP Buffer Opaque2",
                                                "VPP-Opaque2", "vpp-opaque2");
    proto_register_field_array(proto_vpp_opaque2, opaque2_hf,
                               array_length(opaque2_hf));
    proto_register_subtree_array(ett_opaque2, array_length(ett_opaque2));
    register_dissector("vppOpaque2", dissect_vpp_opaque2, proto_vpp_opaque2);


    proto_vpp_trace = proto_register_protocol("VPP Buffer Trace", "VPP-Trace",
                                              "vpp-trace");
    proto_register_field_array(proto_vpp_trace, trace_hf,
                               array_length(trace_hf));
    proto_register_subtree_array(ett_trace, array_length(ett_trace));
    register_dissector("vppTrace", dissect_vpp_trace, proto_vpp_trace);

#define _(idx,dname) next_dissectors[idx] = find_dissector(#dname);
    foreach_next_dissector;
#undef _

    /* if all else fails, dissect data as if ethernet MAC */
    next_dissectors[VLIB_NODE_PROTO_HINT_NONE] =
        next_dissectors [VLIB_NODE_PROTO_HINT_ETHERNET];
}

void
proto_reg_handoff_vpp(void)
{
    vpp_dissector_handle = find_dissector("vpp");
    vpp_metadata_dissector_handle = find_dissector("vppMetadata");
    vpp_opaque_dissector_handle = find_dissector("vppOpaque");
    vpp_opaque2_dissector_handle = find_dissector("vppOpaque2");
    vpp_trace_dissector_handle = find_dissector("vppTrace");
    dissector_add_uint("wtap_encap", WTAP_ENCAP_VPP, vpp_dissector_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
