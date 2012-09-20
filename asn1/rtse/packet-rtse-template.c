/* packet-rtse_asn1.c
 * Routines for RTSE packet dissection
 * Graeme Lunt 2005
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-pres.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#define PNAME  "X.228 OSI Reliable Transfer Service"
#define PSNAME "RTSE"
#define PFNAME "rtse"

/* Initialize the protocol and registered fields */
static int proto_rtse = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

static gboolean open_request=FALSE;
static guint32 app_proto=0;

static proto_tree *top_tree=NULL;

/* Preferences */
static gboolean rtse_reassemble = TRUE;

#include "packet-rtse-hf.c"

/* Initialize the subtree pointers */
static gint ett_rtse = -1;
#include "packet-rtse-ett.c"


static dissector_table_t rtse_oid_dissector_table=NULL;
static GHashTable *oid_table=NULL;
static gint ett_rtse_unknown = -1;

static GHashTable *rtse_segment_table = NULL;
static GHashTable *rtse_reassembled_table = NULL;

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

  if(uses_ros) {
    /* make sure we call ROS ... */
    dissector_add_string("rtse.oid", oid, ros_handle);

    /* and then tell ROS how to dissect the AS*/
    register_ros_oid_dissector_handle(oid, dissector, proto, name, TRUE);

  } else {
    /* otherwise we just remember how to dissect the AS */
    dissector_add_string("rtse.oid", oid, dissector);
  }
}

static int
call_rtse_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset));
	if(!dissector_try_string(rtse_oid_dissector_table, oid, next_tvb, pinfo, tree)){
		proto_item *item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "RTSE: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);
		proto_tree *next_tree=proto_item_add_subtree(item, ett_rtse_unknown);

		expert_add_info_format (pinfo, item, PI_UNDECODED, PI_WARN,
                                        "RTSE: Dissector for OID %s not implemented", oid);
		dissect_unknown_ber(pinfo, next_tvb, offset, next_tree);
	}

	/*XXX until we change the #.REGISTER signature for _PDU()s
	 * into new_dissector_t   we have to do this kludge with
	 * manually step past the content in the ANY type.
	 */
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}

static int
call_rtse_external_type_callback(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
	const char	*oid = NULL;

        if (actx->external.indirect_ref_present) {
		oid = (const char *)find_oid_by_pres_ctx_id(actx->pinfo, actx->external.indirect_reference);
	} else if (actx->external.direct_ref_present) {
    		oid = actx->external.direct_reference;
	}

	if (oid)
    		offset = call_rtse_oid_callback(oid, tvb, offset, actx->pinfo, top_tree ? top_tree : tree);

	return offset;
}

#include "packet-rtse-fn.c"

/*
* Dissect RTSE PDUs inside a PPDU.
*/
static void
dissect_rtse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	proto_tree *next_tree=NULL;
	tvbuff_t *next_tvb = NULL;
	tvbuff_t *data_tvb = NULL;
	fragment_data *frag_msg = NULL;
	guint32 fragment_length;
	guint32 rtse_id = 0;
	gboolean data_handled = FALSE;
	conversation_t *conversation = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	/* do we have application context from the acse dissector?  */
	if( !pinfo->private_data ){
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, -1,
				"Internal error:can't get application context from ACSE dissector.");
		}
		return  ;
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );

	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSE");
  	col_clear(pinfo->cinfo, COL_INFO);

	if (rtse_reassemble &&
	    ((session->spdu_type == SES_DATA_TRANSFER) ||
	     (session->spdu_type == SES_MAJOR_SYNC_POINT))) {
		/* Use conversation index as fragment id */
		conversation  = find_conversation (pinfo->fd->num,
						   &pinfo->src, &pinfo->dst, pinfo->ptype,
						   pinfo->srcport, pinfo->destport, 0);
		if (conversation != NULL) {
			rtse_id = conversation->index;
		}
		session->rtse_reassemble = TRUE;
	}
	if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
		frag_msg = fragment_end_seq_next (pinfo, rtse_id, rtse_segment_table,
						  rtse_reassembled_table);
		next_tvb = process_reassembled_data (tvb, offset, pinfo, "Reassembled RTSE",
						     frag_msg, &rtse_frag_items, NULL, parent_tree);
	}
	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_rtse, next_tvb ? next_tvb : tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_rtse);
	}
	if (rtse_reassemble && session->spdu_type == SES_DATA_TRANSFER) {
		/* strip off the OCTET STRING encoding - including any CONSTRUCTED OCTET STRING */
		dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, offset, hf_rtse_segment_data, &data_tvb);

		if (data_tvb) {
			fragment_length = tvb_length_remaining (data_tvb, 0);
			proto_item_append_text(asn1_ctx.created_item, " (%u byte%s)", fragment_length,
      	                              plurality(fragment_length, "", "s"));
			frag_msg = fragment_add_seq_next (data_tvb, 0, pinfo,
							  rtse_id, rtse_segment_table,
							  rtse_reassembled_table, fragment_length, TRUE);
			if (frag_msg && pinfo->fd->num != frag_msg->reassembled_in) {
				/* Add a "Reassembled in" link if not reassembled in this frame */
				proto_tree_add_uint (tree, *(rtse_frag_items.hf_reassembled_in),
						     data_tvb, 0, 0, frag_msg->reassembled_in);
			}
			pinfo->fragmented = TRUE;
			data_handled = TRUE;
		} else {
			fragment_length = tvb_length_remaining (tvb, offset);
		}

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, "[RTSE fragment, %u byte%s]",
					fragment_length, plurality(fragment_length, "", "s"));
	} else if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
		if (next_tvb) {
			/* ROS won't do this for us */
			session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);
			offset=dissect_ber_external_type(FALSE, tree, next_tvb, 0, &asn1_ctx, -1, call_rtse_external_type_callback);
		} else {
			offset = tvb_length (tvb);
		}
		pinfo->fragmented = FALSE;
		data_handled = TRUE;
	}

	if (!data_handled) {
		while (tvb_reported_length_remaining(tvb, offset) > 0){
			old_offset=offset;
			offset=dissect_rtse_RTSE_apdus(TRUE, tvb, offset, &asn1_ctx, tree, -1);
			if(offset == old_offset){
				item = proto_tree_add_text(tree, tvb, offset, -1, "Unknown RTSE PDU");

				if(item){
					expert_add_info_format (pinfo, item, PI_UNDECODED, PI_WARN, "Unknown RTSE PDU");
					next_tree=proto_item_add_subtree(item, ett_rtse_unknown);
					dissect_unknown_ber(pinfo, tvb, offset, next_tree);
				}

				break;
			}
		}
	}

	top_tree = NULL;
}

static void rtse_reassemble_init (void)
{
	fragment_table_init (&rtse_segment_table);
	reassembled_table_init (&rtse_reassembled_table);
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

  module_t *rtse_module;

  /* Register protocol */
  proto_rtse = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("rtse", dissect_rtse, proto_rtse);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rtse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine (&rtse_reassemble_init);
  rtse_module = prefs_register_protocol_subtree("OSI", proto_rtse, NULL);

  prefs_register_bool_preference(rtse_module, "reassemble",
				 "Reassemble segmented RTSE datagrams",
				 "Whether segmented RTSE datagrams should be reassembled."
				 " To use this option, you must also enable"
				 " \"Allow subdissectors to reassemble TCP streams\""
				 " in the TCP protocol settings.", &rtse_reassemble);

  rtse_oid_dissector_table = register_dissector_table("rtse.oid", "RTSE OID Dissectors", FT_STRING, BASE_NONE);
  oid_table=g_hash_table_new(g_str_hash, g_str_equal);


}


/*--- proto_reg_handoff_rtse --- */
void proto_reg_handoff_rtse(void) {


}
