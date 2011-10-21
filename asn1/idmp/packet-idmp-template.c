/* packet-idmp.c
 * Routines for X.519 Internet Directly Mapped Procotol (IDMP) packet dissection
 * Graeme Lunt 2020
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/ipproto.h>

#include <epan/dissectors/packet-tcp.h>

#include "packet-ber.h"
#include "packet-ros.h"
#include "packet-x509ce.h"

#include <epan/strutil.h>

#define PNAME  "X.519 Internet Directly Mapped Protocol"
#define PSNAME "IDMP"
#define PFNAME "idmp"

static gboolean idmp_desegment = TRUE;
static guint global_idmp_tcp_port = 1102; /* made up for now */
static gboolean idmp_reassemble = TRUE;
static guint tcp_port = 0;
static dissector_handle_t idmp_handle = NULL;

static proto_tree *top_tree = NULL;
static const char *protocolID = NULL;
static const char *saved_protocolID = NULL;
static guint32 opcode = -1;

static void prefs_register_idmp(void); /* forward declaration for use in preferences registration */

/* Initialize the protocol and registered fields */
int proto_idmp = -1;

static int hf_idmp_version = -1;
static int hf_idmp_final = -1;
static int hf_idmp_length = -1;
static int hf_idmp_PDU = -1;

static GHashTable *idmp_segment_table = NULL;
static GHashTable *idmp_reassembled_table = NULL;

static int hf_idmp_fragments = -1;
static int hf_idmp_fragment = -1;
static int hf_idmp_fragment_overlap = -1;
static int hf_idmp_fragment_overlap_conflicts = -1;
static int hf_idmp_fragment_multiple_tails = -1;
static int hf_idmp_fragment_too_long_fragment = -1;
static int hf_idmp_fragment_error = -1;
static int hf_idmp_fragment_count = -1;
static int hf_idmp_reassembled_in = -1;
static int hf_idmp_reassembled_length = -1;

static gint ett_idmp_fragment = -1;
static gint ett_idmp_fragments = -1;

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
	/* Tag */
	"IDMP fragments"
};


static int call_idmp_oid_callback(tvbuff_t *tvb, int offset, packet_info *pinfo, int op, proto_tree *tree _U_)
{
	struct SESSION_DATA_STRUCTURE *session;

	if((session = (struct SESSION_DATA_STRUCTURE*)pinfo->private_data) != NULL) {

		if((!saved_protocolID) && (op == (ROS_OP_BIND | ROS_OP_RESULT))) {
			/* save for subsequent operations - should be into session data */
			saved_protocolID = se_strdup(protocolID);
		}

		/* mimic ROS! */
		session->ros_op = op;
		offset = call_ros_oid_callback(saved_protocolID ? saved_protocolID : protocolID, tvb, offset, pinfo, top_tree);
	}

	return offset;

}

#include "packet-idmp-hf.c"

/* Initialize the subtree pointers */
static gint ett_idmp = -1;
#include "packet-idmp-ett.c"

#include "packet-idmp-fn.c"

void
register_idmp_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name)
{
	/* just register with ROS for now */
	register_ros_protocol_info(oid, rinfo, proto, name, FALSE);
}


static void dissect_idmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;

	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	void *save_private_data;
	struct SESSION_DATA_STRUCTURE session;
	gboolean	idmp_final;
	guint32		idmp_length;
	fragment_data *fd_head;
	conversation_t *conv;
	guint32		dst_ref = 0;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

    conv = find_conversation (pinfo->fd->num, &pinfo->src, &pinfo->dst,
                                pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
    if (conv) {
       /* Found a conversation, also use index for the generated dst_ref */
       dst_ref = conv->index;
    }

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_idmp, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_idmp);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IDMP");

	/* now check the segment fields */

	proto_tree_add_item(tree, hf_idmp_version, tvb, offset, 1, ENC_BIG_ENDIAN); offset++;
	proto_tree_add_item(tree, hf_idmp_final, tvb, offset, 1, ENC_BIG_ENDIAN);
	idmp_final = tvb_get_guint8(tvb, offset); offset++;
	proto_tree_add_item(tree, hf_idmp_length, tvb, offset, 4, ENC_BIG_ENDIAN);
	idmp_length = tvb_get_ntohl(tvb, offset); offset += 4;

	if(idmp_reassemble) {

		pinfo->fragmented = !idmp_final;

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " [%sIDMP fragment, %u byte%s]",
				idmp_final ? "Final " : "" ,
				idmp_length, plurality(idmp_length, "", "s"));

		fd_head = fragment_add_seq_next(tvb, offset, pinfo, dst_ref,
			idmp_segment_table, idmp_reassembled_table,
			idmp_length, !idmp_final);

		if(fd_head && fd_head->next) {
			proto_tree_add_text(tree, tvb, offset, (idmp_length) ? -1 : 0,
			  "IDMP segment data (%u byte%s)", idmp_length,
			  plurality(idmp_length, "", "s"));

			if (idmp_final) {
			/* This is the last segment */
				tvb = process_reassembled_data (tvb, offset, pinfo,
		       		"Reassembled IDMP", fd_head, &idmp_frag_items, NULL, tree);
				offset = 0;
			} else if (pinfo->fd->num != fd_head->reassembled_in) {
				/* Add a "Reassembled in" link if not reassembled in this frame */
				proto_tree_add_uint (tree, hf_idmp_reassembled_in,
		       		tvb, 0, 0, fd_head->reassembled_in);
			}
		}

	} else {
		if(!idmp_final) {

			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, " [IDMP fragment, %u byte%s, IDMP reassembly not enabled]",
					idmp_length, plurality(idmp_length, "", "s"));

			proto_tree_add_text(tree, tvb, offset, (idmp_length) ? -1 : 0,
				"IDMP segment data (%u byte%s) (IDMP reassembly not enabled)", idmp_length,
				plurality(idmp_length, "", "s"));
		}
	}
	/* not reassembling - just dissect */
	if(idmp_final) {
		save_private_data = pinfo->private_data;
		pinfo->private_data = &session;

		offset = dissect_idmp_IDM_PDU(FALSE, tvb, offset, &asn1_ctx, tree, hf_idmp_PDU);

		pinfo->private_data = save_private_data;
	}

}

static guint get_idmp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint32 len;

	len = tvb_get_ntohl(tvb, offset + 2);

	return len + 6;
}

static void dissect_idmp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	tcp_dissect_pdus(tvb, pinfo, parent_tree, idmp_desegment, 0, get_idmp_pdu_len, dissect_idmp);

}

static void idmp_reassemble_init (void)
{
	fragment_table_init (&idmp_segment_table);
	reassembled_table_init (&idmp_reassembled_table);

	saved_protocolID = NULL;
}

/*--- proto_register_idmp -------------------------------------------*/
void proto_register_idmp(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
	{ &hf_idmp_version,
      { "version", "idmp.version",
        FT_INT8, BASE_DEC, NULL, 0,
        "idmp.INTEGER", HFILL }},
	{ &hf_idmp_final,
      { "final", "idmp.final",
        FT_BOOLEAN, 8, NULL, 0,
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

#include "packet-idmp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
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

  register_dissector("idmp", dissect_idmp_tcp, proto_idmp);

  register_init_routine (&idmp_reassemble_init);

  /* Register our configuration options for IDMP, particularly our port */

  idmp_module = prefs_register_protocol_subtree("OSI/X.500", proto_idmp, prefs_register_idmp);

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

  prefs_register_uint_preference(idmp_module, "tcp.port", "IDMP TCP Port",
				 "Set the port for Internet Directly Mapped Protocol requests/responses",
				 10, &global_idmp_tcp_port);

}


/*--- proto_reg_handoff_idm --- */
void proto_reg_handoff_idm(void) {

 /* remember the idm handler for change in preferences */
  idmp_handle = find_dissector(PFNAME);

}


static void
prefs_register_idmp(void)
{

  /* de-register the old port */
  /* port 102 is registered by TPKT - don't undo this! */
  if(idmp_handle)
    dissector_delete_uint("tcp.port", tcp_port, idmp_handle);

  /* Set our port number for future use */
  tcp_port = global_idmp_tcp_port;

  if((tcp_port > 0) && idmp_handle)
    dissector_add_uint("tcp.port", global_idmp_tcp_port, idmp_handle);

}
