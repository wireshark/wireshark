/* packet-rtse-template.c
 * Routines for RTSE packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
static int proto_rtse = -1;

static gboolean open_request=FALSE;
static guint32 app_proto=0;

static proto_tree *top_tree=NULL;

/* Preferences */
static gboolean rtse_reassemble = TRUE;

#include "packet-rtse-hf.c"

/* Initialize the subtree pointers */
static gint ett_rtse = -1;
#include "packet-rtse-ett.c"

static expert_field ei_rtse_dissector_oid_not_implemented = EI_INIT;
static expert_field ei_rtse_unknown_rtse_pdu = EI_INIT;
static expert_field ei_rtse_abstract_syntax = EI_INIT;

static dissector_table_t rtse_oid_dissector_table=NULL;
static GHashTable *oid_table=NULL;
static gint ett_rtse_unknown = -1;

static reassembly_table rtse_reassembly_table;

static int hf_rtse_segment_data = -1;
static int hf_rtse_fragments = -1;
static int hf_rtse_fragment = -1;
static int hf_rtse_fragment_overlap = -1;
static int hf_rtse_fragment_overlap_conflicts = -1;
static int hf_rtse_fragment_multiple_tails = -1;
static int hf_rtse_fragment_too_long_fragment = -1;
static int hf_rtse_fragment_error = -1;
static int hf_rtse_fragment_count = -1;
static int hf_rtse_reassembled_in = -1;
static int hf_rtse_reassembled_length = -1;

static gint ett_rtse_fragment = -1;
static gint ett_rtse_fragments = -1;

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
register_rtse_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto, const char *name, gboolean uses_ros)
{
/* XXX: Note that this fcn is called from proto_reg_handoff in *other* dissectors ... */

  static  dissector_handle_t rtse_handle = NULL;
  static  dissector_handle_t ros_handle = NULL;

  if (rtse_handle == NULL)
    rtse_handle = find_dissector("rtse");
  if (ros_handle == NULL)
    ros_handle = find_dissector("ros");

  /* save the name - but not used */
  g_hash_table_insert(oid_table, (gpointer)oid, (gpointer)name);

  /* register RTSE with the BER (ACSE) */
  register_ber_oid_dissector_handle(oid, rtse_handle, proto, name);

  if (uses_ros) {
    /* make sure we call ROS ... */
    dissector_add_string("rtse.oid", oid, ros_handle);

    /* and then tell ROS how to dissect the AS*/
    if (dissector != NULL)
      register_ros_oid_dissector_handle(oid, dissector, proto, name, TRUE);

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
call_rtse_external_type_callback(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
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
    guint32 fragment_length;
    guint32 rtse_id = 0;
    gboolean data_handled = FALSE;
    struct SESSION_DATA_STRUCTURE* session;
    conversation_t *conversation = NULL;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

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
        conversation  = find_conversation (pinfo->num,
                           &pinfo->src, &pinfo->dst, pinfo->ptype,
                           pinfo->srcport, pinfo->destport, 0);
        if (conversation != NULL) {
            rtse_id = conversation->conv_index;
        }
        session->rtse_reassemble = TRUE;
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
        dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, offset, hf_rtse_segment_data, &data_tvb);

        if (data_tvb) {
            fragment_length = tvb_captured_length_remaining (data_tvb, 0);
            proto_item_append_text(asn1_ctx.created_item, " (%u byte%s)", fragment_length,
                                        plurality(fragment_length, "", "s"));
            frag_msg = fragment_add_seq_next (&rtse_reassembly_table,
                              data_tvb, 0, pinfo,
                              rtse_id, NULL,
                              fragment_length, TRUE);
            if (frag_msg && pinfo->num != frag_msg->reassembled_in) {
                /* Add a "Reassembled in" link if not reassembled in this frame */
                proto_tree_add_uint (tree, *(rtse_frag_items.hf_reassembled_in),
                             data_tvb, 0, 0, frag_msg->reassembled_in);
            }
            pinfo->fragmented = TRUE;
            data_handled = TRUE;
        } else {
            fragment_length = tvb_captured_length_remaining (tvb, offset);
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, "[RTSE fragment, %u byte%s]",
                    fragment_length, plurality(fragment_length, "", "s"));
    } else if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
        if (next_tvb) {
            /* ROS won't do this for us */
            session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);
            /*offset=*/dissect_ber_external_type(FALSE, tree, next_tvb, 0, &asn1_ctx, -1, call_rtse_external_type_callback);
            top_tree = NULL;
            /* Return other than 0 to indicate that we handled this packet */
            return 1;
        } else {
            offset = tvb_captured_length (tvb);
        }
        pinfo->fragmented = FALSE;
        data_handled = TRUE;
    }

    if (!data_handled) {
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            old_offset=offset;
            offset=dissect_rtse_RTSE_apdus(TRUE, tvb, offset, &asn1_ctx, tree, -1);
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

static void rtse_reassemble_init (void)
{
    reassembly_table_init (&rtse_reassembly_table,
                   &addresses_reassembly_table_functions);
}

static void rtse_reassemble_cleanup(void)
{
    reassembly_table_destroy(&rtse_reassembly_table);
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
  static gint *ett[] = {
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
  register_dissector("rtse", dissect_rtse, proto_rtse);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rtse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_rtse = expert_register_protocol(proto_rtse);
  expert_register_field_array(expert_rtse, ei, array_length(ei));
  register_init_routine (&rtse_reassemble_init);
  register_cleanup_routine (&rtse_reassemble_cleanup);
  rtse_module = prefs_register_protocol_subtree("OSI", proto_rtse, NULL);

  prefs_register_bool_preference(rtse_module, "reassemble",
                 "Reassemble segmented RTSE datagrams",
                 "Whether segmented RTSE datagrams should be reassembled."
                 " To use this option, you must also enable"
                 " \"Allow subdissectors to reassemble TCP streams\""
                 " in the TCP protocol settings.", &rtse_reassemble);

  rtse_oid_dissector_table = register_dissector_table("rtse.oid", "RTSE OID Dissectors", proto_rtse, FT_STRING, BASE_NONE);
  oid_table=g_hash_table_new(g_str_hash, g_str_equal);


}


/*--- proto_reg_handoff_rtse --- */
void proto_reg_handoff_rtse(void) {


}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
