/* packet-idmp.c
 * Routines for X.519 Internet Directly Mapped Procotol (IDMP) packet dissection
 * Graeme Lunt 2010
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/ipproto.h>
#include <epan/strutil.h>

#include <wsutil/str_util.h>

#include "packet-tcp.h"

#include "packet-ber.h"
#include "packet-ros.h"
#include "packet-x509ce.h"


#define PNAME  "X.519 Internet Directly Mapped Protocol"
#define PSNAME "IDMP"
#define PFNAME "idmp"

void proto_register_idmp(void);
void proto_reg_handoff_idm(void);
void register_idmp_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name);

static bool           idmp_desegment       = true;
#define IDMP_TCP_PORT     1102 /* made up for now - not IANA registered */
static bool           idmp_reassemble      = true;
static dissector_handle_t idmp_handle;

static proto_tree *top_tree;
static const char *protocolID;
static const char *saved_protocolID;
static uint32_t    opcode           = -1;

/* Initialize the protocol and registered fields */
int proto_idmp;

static int hf_idmp_version;
static int hf_idmp_final;
static int hf_idmp_length;
static int hf_idmp_PDU;

static reassembly_table idmp_reassembly_table;

static int hf_idmp_fragments;
static int hf_idmp_fragment;
static int hf_idmp_fragment_overlap;
static int hf_idmp_fragment_overlap_conflicts;
static int hf_idmp_fragment_multiple_tails;
static int hf_idmp_fragment_too_long_fragment;
static int hf_idmp_fragment_error;
static int hf_idmp_fragment_count;
static int hf_idmp_reassembled_in;
static int hf_idmp_reassembled_length;
static int hf_idmp_segment_data;

static int ett_idmp_fragment;
static int ett_idmp_fragments;

static const fragment_items idmp_frag_items = {
    /* Fragment subtrees */
    &ett_idmp_fragment,
    &ett_idmp_fragments,
    /* Fragment fields */
    &hf_idmp_fragments,
    &hf_idmp_fragment,
    &hf_idmp_fragment_overlap,
    &hf_idmp_fragment_overlap_conflicts,
    &hf_idmp_fragment_multiple_tails,
    &hf_idmp_fragment_too_long_fragment,
    &hf_idmp_fragment_error,
    &hf_idmp_fragment_count,
    /* Reassembled in field */
    &hf_idmp_reassembled_in,
    /* Reassembled length field */
    &hf_idmp_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "IDMP fragments"
};


static int call_idmp_oid_callback(tvbuff_t *tvb, int offset, packet_info *pinfo, int op, proto_tree *tree, struct SESSION_DATA_STRUCTURE *session)
{
    if(session != NULL) {

        /* XXX saved_protocolID should be part of session data */
        if (!saved_protocolID) {
            saved_protocolID = "[ unknown ]";
        }

        /* mimic ROS! */
        session->ros_op = op;
        offset = call_ros_oid_callback(saved_protocolID, tvb, offset, pinfo, tree, session);
    }

    return offset;

}

#include "packet-idmp-hf.c"

/* Initialize the subtree pointers */
static int ett_idmp;
#include "packet-idmp-ett.c"

#include "packet-idmp-fn.c"

void
register_idmp_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name)
{
    /* just register with ROS for now */
    register_ros_protocol_info(oid, rinfo, proto, name, false);
}


static int dissect_idmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    int offset = 0;

    proto_item                    *item;
    proto_tree                    *tree;
    asn1_ctx_t                     asn1_ctx;
    struct SESSION_DATA_STRUCTURE  session;
    bool                           idmp_final;
    uint32_t                       idmp_length;
    fragment_head                 *fd_head;
    conversation_t                *conv;
    uint32_t                       dst_ref = 0;

    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    conv = find_conversation_pinfo(pinfo, 0);
    if (conv) {
        /* Found a conversation, also use index for the generated dst_ref */
        dst_ref = conv->conv_index;
    }

    /* save parent_tree so subdissectors can create new top nodes */
    top_tree=parent_tree;

    item = proto_tree_add_item(parent_tree, proto_idmp, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_idmp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IDMP");

    /* now check the segment fields */

    proto_tree_add_item(tree, hf_idmp_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
    proto_tree_add_item(tree, hf_idmp_final, tvb, offset, 1, ENC_BIG_ENDIAN);
    idmp_final = tvb_get_uint8(tvb, offset); offset++;
    proto_tree_add_item(tree, hf_idmp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    idmp_length = tvb_get_ntohl(tvb, offset); offset += 4;

    asn1_ctx.private_data = &session;

    if(idmp_reassemble) {

        pinfo->fragmented = !idmp_final;

        col_append_fstr(pinfo->cinfo, COL_INFO, " [%sIDMP fragment, %u byte%s]",
                            idmp_final ? "Final " : "" ,
                            idmp_length, plurality(idmp_length, "", "s"));

        fd_head = fragment_add_seq_next(&idmp_reassembly_table, tvb, offset,
                                        pinfo, dst_ref, NULL,
                                        idmp_length, !idmp_final);

        if(fd_head && fd_head->next) {
            proto_tree_add_item(tree, hf_idmp_segment_data, tvb, offset, (idmp_length) ? -1 : 0, ENC_NA);

            if (idmp_final) {
                /* This is the last segment */
                tvb = process_reassembled_data (tvb, offset, pinfo,
                                                "Reassembled IDMP", fd_head, &idmp_frag_items, NULL, tree);
                offset = 0;
            } else if (pinfo->num != fd_head->reassembled_in) {
                /* Add a "Reassembled in" link if not reassembled in this frame */
                proto_tree_add_uint (tree, hf_idmp_reassembled_in,
                                     tvb, 0, 0, fd_head->reassembled_in);
            }
        }

    } else {
        if(!idmp_final) {

            col_append_fstr(pinfo->cinfo, COL_INFO, " [IDMP fragment, %u byte%s, IDMP reassembly not enabled]",
                                idmp_length, plurality(idmp_length, "", "s"));

            proto_tree_add_bytes_format_value(tree, hf_idmp_segment_data, tvb, offset, (idmp_length) ? -1 : 0,
                                NULL, "(IDMP reassembly not enabled)");
        }
    }
    /* not reassembling - just dissect */
    if(idmp_final) {
        asn1_ctx.private_data = &session;
        dissect_idmp_IDM_PDU(false, tvb, offset, &asn1_ctx, tree, hf_idmp_PDU);
    }

    return tvb_captured_length(tvb);
}

static unsigned get_idmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                              int offset, void *data _U_)
{
    uint32_t len;

    len = tvb_get_ntohl(tvb, offset + 2);

    return len + 6;
}

static int dissect_idmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
    tcp_dissect_pdus(tvb, pinfo, parent_tree, idmp_desegment, 0, get_idmp_pdu_len, dissect_idmp, data);
	return tvb_captured_length(tvb);
}

static void idmp_reassemble_cleanup(void)
{
    protocolID = NULL; // packet scoped
    saved_protocolID = NULL; // epan scoped copy of protocolID
    opcode = -1;
}

/*--- proto_register_idmp -------------------------------------------*/
void proto_register_idmp(void)
{
    /* List of fields */
    static hf_register_info hf[] = {
        { &hf_idmp_version,
          { "version", "idmp.version",
            FT_INT8, BASE_DEC, NULL, 0,
            "idmp.INTEGER", HFILL }},
        { &hf_idmp_final,
          { "final", "idmp.final",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            "idmp.BOOLEAN", HFILL }},
        { &hf_idmp_length,
          { "length", "idmp.length",
            FT_INT32, BASE_DEC, NULL, 0,
            "idmp.INTEGER", HFILL }},
        { &hf_idmp_PDU,
          { "IDM-PDU", "idmp.pdu",
            FT_UINT32, BASE_DEC, VALS(idmp_IDM_PDU_vals), 0,
            "idmp.PDU", HFILL }},
        /* Fragment entries */
        { &hf_idmp_fragments,
          { "IDMP fragments", "idmp.fragments", FT_NONE, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment,
          { "IDMP fragment", "idmp.fragment", FT_FRAMENUM, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_overlap,
          { "IDMP fragment overlap", "idmp.fragment.overlap", FT_BOOLEAN,
            BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_overlap_conflicts,
          { "IDMP fragment overlapping with conflicting data",
            "idmp.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_multiple_tails,
          { "IDMP has multiple tail fragments",
            "idmp.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_too_long_fragment,
          { "IDMP fragment too long", "idmp.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_error,
          { "IDMP defragmentation error", "idmp.fragment.error", FT_FRAMENUM,
            BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_fragment_count,
          { "IDMP fragment count", "idmp.fragment.count", FT_UINT32, BASE_DEC,
            NULL, 0x00, NULL, HFILL } },
        { &hf_idmp_reassembled_in,
          { "Reassembled IDMP in frame", "idmp.reassembled.in", FT_FRAMENUM, BASE_NONE,
            NULL, 0x00, "This IDMP packet is reassembled in this frame", HFILL } },
        { &hf_idmp_reassembled_length,
          { "Reassembled IDMP length", "idmp.reassembled.length", FT_UINT32, BASE_DEC,
            NULL, 0x00, "The total length of the reassembled payload", HFILL } },
        { &hf_idmp_segment_data,
          { "IDMP segment data", "idmp.segment_data", FT_BYTES, BASE_NONE,
            NULL, 0x00, NULL, HFILL } },

#include "packet-idmp-hfarr.c"
    };

    /* List of subtrees */
    static int *ett[] = {
        &ett_idmp,
        &ett_idmp_fragment,
        &ett_idmp_fragments,
#include "packet-idmp-ettarr.c"
    };
    module_t *idmp_module;

    /* Register protocol */
    proto_idmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

    /* Register fields and subtrees */
    proto_register_field_array(proto_idmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    idmp_handle = register_dissector("idmp", dissect_idmp_tcp, proto_idmp);

    register_cleanup_routine (&idmp_reassemble_cleanup);
    reassembly_table_register (&idmp_reassembly_table,
                           &addresses_reassembly_table_functions);


    /* Register our configuration options for IDMP, particularly our port */

    idmp_module = prefs_register_protocol_subtree("OSI/X.500", proto_idmp, NULL);

    prefs_register_bool_preference(idmp_module, "desegment_idmp_messages",
                                   "Reassemble IDMP messages spanning multiple TCP segments",
                                   "Whether the IDMP dissector should reassemble messages spanning multiple TCP segments."
                                   " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
                                   &idmp_desegment);

    prefs_register_bool_preference(idmp_module, "reassemble",
                                   "Reassemble segmented IDMP datagrams",
                                   "Whether segmented IDMP datagrams should be reassembled."
                                   " To use this option, you must also enable"
                                   " \"Allow subdissectors to reassemble TCP streams\""
                                   " in the TCP protocol settings.", &idmp_reassemble);
}


/*--- proto_reg_handoff_idm --- */
void proto_reg_handoff_idm(void) {
    dissector_add_uint_with_preference("tcp.port", IDMP_TCP_PORT, idmp_handle);
}
