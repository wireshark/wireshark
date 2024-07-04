/* packet-rtse-template.c
 * Routines for RTSE packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include <wsutil/str_util.h>

#include "packet-ber.h"
#include "packet-pres.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#define PNAME  "X.228 OSI Reliable Transfer Service"
#define PSNAME "RTSE"
#define PFNAME "rtse"

void proto_register_rtse(void);
void proto_reg_handoff_rtse(void);

/* Initialize the protocol and registered fields */
static int proto_rtse;

static bool open_request=false;
static uint32_t app_proto=0;

static proto_tree *top_tree;

/* Preferences */
static bool rtse_reassemble = true;

#include "packet-rtse-hf.c"

/* Initialize the subtree pointers */
static int ett_rtse;
#include "packet-rtse-ett.c"

static expert_field ei_rtse_dissector_oid_not_implemented;
static expert_field ei_rtse_unknown_rtse_pdu;
static expert_field ei_rtse_abstract_syntax;

static dissector_table_t rtse_oid_dissector_table;
static dissector_handle_t rtse_handle;
static int ett_rtse_unknown;

static reassembly_table rtse_reassembly_table;

static int hf_rtse_segment_data;
static int hf_rtse_fragments;
static int hf_rtse_fragment;
static int hf_rtse_fragment_overlap;
static int hf_rtse_fragment_overlap_conflicts;
static int hf_rtse_fragment_multiple_tails;
static int hf_rtse_fragment_too_long_fragment;
static int hf_rtse_fragment_error;
static int hf_rtse_fragment_count;
static int hf_rtse_reassembled_in;
static int hf_rtse_reassembled_length;

static int ett_rtse_fragment;
static int ett_rtse_fragments;

static const fragment_items rtse_frag_items = {
    /* Fragment subtrees */
    &ett_rtse_fragment,
    &ett_rtse_fragments,
    /* Fragment fields */
    &hf_rtse_fragments,
    &hf_rtse_fragment,
    &hf_rtse_fragment_overlap,
    &hf_rtse_fragment_overlap_conflicts,
    &hf_rtse_fragment_multiple_tails,
    &hf_rtse_fragment_too_long_fragment,
    &hf_rtse_fragment_error,
    &hf_rtse_fragment_count,
    /* Reassembled in field */
    &hf_rtse_reassembled_in,
    /* Reassembled length field */
    &hf_rtse_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "RTSE fragments"
};

void
register_rtse_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto, const char *name, bool uses_ros)
{
/* XXX: Note that this fcn is called from proto_reg_handoff in *other* dissectors ... */

  static  dissector_handle_t ros_handle = NULL;

  if (ros_handle == NULL)
    ros_handle = find_dissector("ros");

  /* register RTSE with the BER (ACSE) */
  register_ber_oid_dissector_handle(oid, rtse_handle, proto, name);

  if (uses_ros) {
    /* make sure we call ROS ... */
    dissector_add_string("rtse.oid", oid, ros_handle);

    /* and then tell ROS how to dissect the AS*/
    if (dissector != NULL)
      register_ros_oid_dissector_handle(oid, dissector, proto, name, true);

  } else {
    /* otherwise we just remember how to dissect the AS */
    dissector_add_string("rtse.oid", oid, dissector);
  }
}

static int
call_rtse_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, void* data)
{
    tvbuff_t *next_tvb;
    int len;

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if ((len = dissector_try_string(rtse_oid_dissector_table, oid, next_tvb, pinfo, tree, data)) == 0) {
        proto_item *item;
        proto_tree *next_tree;

        next_tree = proto_tree_add_subtree_format(tree, next_tvb, 0, -1, ett_rtse_unknown, &item,
                "RTSE: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);

        expert_add_info_format(pinfo, item, &ei_rtse_dissector_oid_not_implemented,
                                       "RTSE: Dissector for OID %s not implemented", oid);
        len = dissect_unknown_ber(pinfo, next_tvb, offset, next_tree);
    }

    offset += len;

    return offset;
}

static int
call_rtse_external_type_callback(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
    const char    *oid = NULL;

    if (actx->external.indirect_ref_present) {

        oid = (const char *)find_oid_by_pres_ctx_id(actx->pinfo, actx->external.indirect_reference);

        if (!oid)
            proto_tree_add_expert_format(tree, actx->pinfo, &ei_rtse_abstract_syntax, tvb, offset, tvb_captured_length_remaining(tvb, offset),
                    "Unable to determine abstract syntax for indirect reference: %d.", actx->external.indirect_reference);
    } else if (actx->external.direct_ref_present) {
        oid = actx->external.direct_reference;
    }

    if (oid)
        offset = call_rtse_oid_callback(oid, tvb, offset, actx->pinfo, top_tree ? top_tree : tree, actx->private_data);

    return offset;
}

#include "packet-rtse-fn.c"

/*
* Dissect RTSE PDUs inside a PPDU.
*/
static int
dissect_rtse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
    int offset = 0;
    int old_offset;
    proto_item *item;
    proto_tree *tree;
    proto_tree *next_tree=NULL;
    tvbuff_t *next_tvb = NULL;
    tvbuff_t *data_tvb = NULL;
    fragment_head *frag_msg = NULL;
    uint32_t fragment_length;
    uint32_t rtse_id = 0;
    bool data_handled = false;
    struct SESSION_DATA_STRUCTURE* session;
    conversation_t *conversation = NULL;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    /* do we have application context from the acse dissector? */
    if (data == NULL)
        return 0;
    session = (struct SESSION_DATA_STRUCTURE*)data;

    /* save parent_tree so subdissectors can create new top nodes */
    top_tree=parent_tree;

    asn1_ctx.private_data = session;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSE");
    col_clear(pinfo->cinfo, COL_INFO);

    if (rtse_reassemble &&
        ((session->spdu_type == SES_DATA_TRANSFER) ||
         (session->spdu_type == SES_MAJOR_SYNC_POINT)))
    {
        /* Use conversation index as fragment id */
        conversation  = find_conversation_pinfo(pinfo, 0);
        if (conversation != NULL) {
            rtse_id = conversation->conv_index;
        }
        session->rtse_reassemble = true;
    }
    if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
        frag_msg = fragment_end_seq_next (&rtse_reassembly_table,
                          pinfo, rtse_id, NULL);
        next_tvb = process_reassembled_data (tvb, offset, pinfo, "Reassembled RTSE",
                             frag_msg, &rtse_frag_items, NULL, parent_tree);
    }

    item = proto_tree_add_item(parent_tree, proto_rtse, next_tvb ? next_tvb : tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_rtse);

    if (rtse_reassemble && session->spdu_type == SES_DATA_TRANSFER) {
        /* strip off the OCTET STRING encoding - including any CONSTRUCTED OCTET STRING */
        dissect_ber_octet_string(false, &asn1_ctx, tree, tvb, offset, hf_rtse_segment_data, &data_tvb);

        if (data_tvb) {
            fragment_length = tvb_captured_length_remaining (data_tvb, 0);
            proto_item_append_text(asn1_ctx.created_item, " (%u byte%s)", fragment_length,
                                        plurality(fragment_length, "", "s"));
            frag_msg = fragment_add_seq_next (&rtse_reassembly_table,
                              data_tvb, 0, pinfo,
                              rtse_id, NULL,
                              fragment_length, true);
            if (frag_msg && pinfo->num != frag_msg->reassembled_in) {
                /* Add a "Reassembled in" link if not reassembled in this frame */
                proto_tree_add_uint (tree, *(rtse_frag_items.hf_reassembled_in),
                             data_tvb, 0, 0, frag_msg->reassembled_in);
            }
            pinfo->fragmented = true;
            data_handled = true;
        } else {
            fragment_length = tvb_captured_length_remaining (tvb, offset);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "[RTSE fragment, %u byte%s]",
                    fragment_length, plurality(fragment_length, "", "s"));
    } else if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
        if (next_tvb) {
            /* ROS won't do this for us */
            session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);
            /*offset=*/dissect_ber_external_type(false, tree, next_tvb, 0, &asn1_ctx, -1, call_rtse_external_type_callback);
            top_tree = NULL;
            /* Return other than 0 to indicate that we handled this packet */
            return 1;
        } else {
            offset = tvb_captured_length (tvb);
        }
        pinfo->fragmented = false;
        data_handled = true;
    }

    if (!data_handled) {
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            old_offset=offset;
            offset=dissect_rtse_RTSE_apdus(true, tvb, offset, &asn1_ctx, tree, -1);
            if (offset == old_offset) {
                next_tree = proto_tree_add_subtree(tree, tvb, offset, -1,
                                ett_rtse_unknown, &item, "Unknown RTSE PDU");
                expert_add_info (pinfo, item, &ei_rtse_unknown_rtse_pdu);
                dissect_unknown_ber(pinfo, tvb, offset, next_tree);
                break;
            }
        }
    }

    top_tree = NULL;
    return tvb_captured_length(tvb);
}

/*--- proto_register_rtse -------------------------------------------*/
void proto_register_rtse(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    /* Fragment entries */
    { &hf_rtse_segment_data,
      { "RTSE segment data", "rtse.segment", FT_NONE, BASE_NONE,
    NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragments,
      { "RTSE fragments", "rtse.fragments", FT_NONE, BASE_NONE,
    NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment,
      { "RTSE fragment", "rtse.fragment", FT_FRAMENUM, BASE_NONE,
    NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment_overlap,
      { "RTSE fragment overlap", "rtse.fragment.overlap", FT_BOOLEAN,
    BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_overlap_conflicts,
      { "RTSE fragment overlapping with conflicting data",
    "rtse.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
    NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_multiple_tails,
      { "RTSE has multiple tail fragments",
    "rtse.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
    NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_too_long_fragment,
      { "RTSE fragment too long", "rtse.fragment.too_long_fragment",
    FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_error,
      { "RTSE defragmentation error", "rtse.fragment.error", FT_FRAMENUM,
    BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment_count,
      { "RTSE fragment count", "rtse.fragment.count", FT_UINT32, BASE_DEC,
    NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_reassembled_in,
      { "Reassembled RTSE in frame", "rtse.reassembled.in", FT_FRAMENUM, BASE_NONE,
    NULL, 0x00, "This RTSE packet is reassembled in this frame", HFILL } },
    { &hf_rtse_reassembled_length,
      { "Reassembled RTSE length", "rtse.reassembled.length", FT_UINT32, BASE_DEC,
    NULL, 0x00, "The total length of the reassembled payload", HFILL } },

#include "packet-rtse-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_rtse,
    &ett_rtse_unknown,
    &ett_rtse_fragment,
    &ett_rtse_fragments,
#include "packet-rtse-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_rtse_dissector_oid_not_implemented, { "rtse.dissector_oid_not_implemented", PI_UNDECODED, PI_WARN, "RTSE: Dissector for OID not implemented", EXPFILL }},
     { &ei_rtse_unknown_rtse_pdu, { "rtse.unknown_rtse_pdu", PI_UNDECODED, PI_WARN, "Unknown RTSE PDU", EXPFILL }},
     { &ei_rtse_abstract_syntax, { "rtse.bad_abstract_syntax", PI_PROTOCOL, PI_WARN, "Unable to determine abstract syntax for indirect reference", EXPFILL }},
  };

  expert_module_t* expert_rtse;
  module_t *rtse_module;

  /* Register protocol */
  proto_rtse = proto_register_protocol(PNAME, PSNAME, PFNAME);
  rtse_handle = register_dissector("rtse", dissect_rtse, proto_rtse);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rtse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_rtse = expert_register_protocol(proto_rtse);
  expert_register_field_array(expert_rtse, ei, array_length(ei));

  reassembly_table_register (&rtse_reassembly_table,
                   &addresses_reassembly_table_functions);

  rtse_module = prefs_register_protocol_subtree("OSI", proto_rtse, NULL);

  prefs_register_bool_preference(rtse_module, "reassemble",
                 "Reassemble segmented RTSE datagrams",
                 "Whether segmented RTSE datagrams should be reassembled."
                 " To use this option, you must also enable"
                 " \"Allow subdissectors to reassemble TCP streams\""
                 " in the TCP protocol settings.", &rtse_reassemble);

  rtse_oid_dissector_table = register_dissector_table("rtse.oid", "RTSE OID Dissectors", proto_rtse, FT_STRING, STRING_CASE_SENSITIVE);
}


/*--- proto_reg_handoff_rtse --- */
void proto_reg_handoff_rtse(void) {


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
