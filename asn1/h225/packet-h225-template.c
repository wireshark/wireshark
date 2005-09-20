/* packet-h225.c
 * Routines for h225 packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 *
 * To quote the author of the previous H323/H225/H245 dissector:
 *   "This is a complete replacement of the previous limitied dissector
 * that Ronnie was crazy enough to write by hand. It was a lot of time
 * to hack it by hand, but it is incomplete and buggy and it is good when
 * it will go away."
 * Ronnie did a great job and all the VoIP users had made good use of it!
 * Credit to Tomas Kukosa for developing the Asn2eth compiler.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include <epan/prefs.h>
#include "tap.h"
#include "packet-tpkt.h"
#include "packet-per.h"
#include "packet-h225.h"
#include <epan/t35.h>
#include <epan/h225-persistentdata.h>
#include "packet-ber.h"
#include "packet-h235.h"
#include "packet-h245.h"
#include "packet-q931.h"

#define PNAME  "H323-MESSAGES"
#define PSNAME "H.225.0"
#define PFNAME "h225"

#define UDP_PORT_RAS1 1718
#define UDP_PORT_RAS2 1719
#define TCP_PORT_CS   1720

static void reset_h225_packet_info(h225_packet_info *pi);
static void ras_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, h225_packet_info *pi);
static int dissect_h225_H323UserInformation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static h225_packet_info pi_arr[5]; /* We assuming a maximum of 5 H225 messaages per packet */
static int pi_current=0;
h225_packet_info *h225_pi=NULL;

static dissector_handle_t h225ras_handle;
static dissector_handle_t H323UserInformation_handle;
static dissector_handle_t data_handle;
/* Subdissector tables */
static dissector_table_t nsp_object_dissector_table;
static dissector_table_t nsp_h221_dissector_table;
static dissector_table_t tp_dissector_table;


static dissector_handle_t h245_handle=NULL;
static dissector_handle_t h245dg_handle=NULL;
static dissector_handle_t h4501_handle=NULL;

static dissector_handle_t nsp_handle;
static dissector_handle_t tp_handle;

/* Initialize the protocol and registered fields */
static int h225_tap = -1;
static int proto_h225 = -1;

static int hf_h225_H323_UserInformation = -1;
static int hf_h225_RasMessage = -1;
static int hf_h221Manufacturer = -1;
static int hf_h225_ras_req_frame = -1;
static int hf_h225_ras_rsp_frame = -1;
static int hf_h225_ras_dup = -1;
static int hf_h225_ras_deltatime = -1;
static int hf_h225_fastStart_item_length = -1; 

#include "packet-h225-hf.c"

/* Initialize the subtree pointers */
static gint ett_h225 = -1;
#include "packet-h225-ett.c"

/* Global variables */
static guint32  ipv4_address;
static guint32  ipv4_port;
guint32 T38_manufacturer_code;
static gboolean h225_reassembly = TRUE;
guint32 value;
static gboolean contains_faststart = FALSE;

/* NonStandardParameter */
static char *nsiOID;
static guint32 h221NonStandard;
static guint32 t35CountryCode;
static guint32 t35Extension;
static guint32 manufacturerCode;

/* TunnelledProtocol */
static char *tpOID;

#include "packet-h225-fn.c"


static int
dissect_h225_H323UserInformation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	int offset = 0;

    pi_current++;
    if(pi_current==5){
      pi_current=0;
    }
    h225_pi=&pi_arr[pi_current];

	/* Init struct for collecting h225_packet_info */
    reset_h225_packet_info(h225_pi);
    h225_pi->msg_type = H225_CS;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	it=proto_tree_add_protocol_format(tree, proto_h225, tvb, 0, tvb_length(tvb), PSNAME" CS");
	tr=proto_item_add_subtree(it, ett_h225);

	offset = dissect_h225_H323_UserInformation(tvb, offset,pinfo, tr, hf_h225_H323_UserInformation);

	tap_queue_packet(h225_tap, pinfo, h225_pi);

	return offset;
}
static int
dissect_h225_h225_RasMessage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;

    pi_current++;
    if(pi_current==5){
        pi_current=0;
    }
    h225_pi=&pi_arr[pi_current];

	/* Init struct for collecting h225_packet_info */
    reset_h225_packet_info(h225_pi);
    h225_pi->msg_type = H225_RAS;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
	}

	it=proto_tree_add_protocol_format(tree, proto_h225, tvb, offset, tvb_length(tvb), PSNAME" RAS");
	tr=proto_item_add_subtree(it, ett_h225);

	offset = dissect_h225_RasMessage(tvb, 0, pinfo,tr, hf_h225_RasMessage );

	ras_call_matching(tvb, pinfo, tr, h225_pi);

	tap_queue_packet(h225_tap, pinfo, h225_pi);

	return offset;
}

/*--- proto_register_h225 -------------------------------------------*/
void proto_register_h225(void) {

  /* List of fields */
  static hf_register_info hf[] = {
	{ &hf_h225_H323_UserInformation,
		{ "H323_UserInformation", "h225.H323_UserInformation", FT_NONE, BASE_NONE,
		NULL, 0, "H323_UserInformation sequence", HFILL }},
	{ &hf_h225_RasMessage,
		{ "RasMessage", "h225.RasMessage", FT_UINT32, BASE_DEC,
		VALS(RasMessage_vals), 0, "RasMessage choice", HFILL }},
	{ &hf_h221Manufacturer,
		{ "H.221 Manufacturer", "h221.Manufacturer", FT_UINT32, BASE_HEX,
		VALS(H221ManufacturerCode_vals), 0, "H.221 Manufacturer", HFILL }},
	{ &hf_h225_ras_req_frame,
      		{ "RAS Request Frame", "h225.ras.reqframe", FT_FRAMENUM, BASE_NONE,
      		NULL, 0, "RAS Request Frame", HFILL }},
  	{ &hf_h225_ras_rsp_frame,
      		{ "RAS Response Frame", "h225.ras.rspframe", FT_FRAMENUM, BASE_NONE,
      		NULL, 0, "RAS Response Frame", HFILL }},
  	{ &hf_h225_ras_dup,
      		{ "Duplicate RAS Message", "h225.ras.dup", FT_UINT32, BASE_DEC,
		NULL, 0, "Duplicate RAS Message", HFILL }},
  	{ &hf_h225_ras_deltatime,
      		{ "RAS Service Response Time", "h225.ras.timedelta", FT_RELATIVE_TIME, BASE_NONE,
      		NULL, 0, "Timedelta between RAS-Request and RAS-Response", HFILL }},
	{ &hf_h225_fastStart_item_length,
		{ "fastStart item length", "h225.fastStart_item_length", FT_UINT32, BASE_DEC,
		NULL, 0, "fastStart item length", HFILL }},

#include "packet-h225-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_h225,
#include "packet-h225-ettarr.c"
  };
  module_t *h225_module;

  /* Register protocol */
  proto_h225 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_h225, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  h225_module = prefs_register_protocol(proto_h225, NULL);
  prefs_register_bool_preference(h225_module, "reassembly",
		"Reassemble H.225 messages spanning multiple TCP segments",
		"Whether the H.225 dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&h225_reassembly);

  new_register_dissector("h225", dissect_h225_H323UserInformation, proto_h225);
  new_register_dissector("h323ui",dissect_h225_H323UserInformation, proto_h225);

  nsp_object_dissector_table = register_dissector_table("h225.nsp.object", "H.225 NonStandardParameter (object)", FT_STRING, BASE_NONE);
  nsp_h221_dissector_table = register_dissector_table("h225.nsp.h221", "H.225 NonStandardParameter (h221)", FT_UINT32, BASE_HEX);
  tp_dissector_table = register_dissector_table("h225.tp", "H.225 TunnelledProtocol", FT_STRING, BASE_NONE);

  register_init_routine(&h225_init_routine);
  h225_tap = register_tap("h225");
  register_ber_oid_name("0.0.8.2250.0.2","itu-t(0) recommendation(0) h(8) h225-0(2250) version(0) 2");
  register_ber_oid_name("0.0.8.2250.0.4","itu-t(0) recommendation(0) h(8) h225-0(2250) version(0) 4");


}


/*--- proto_reg_handoff_h225 ---------------------------------------*/
void
proto_reg_handoff_h225(void)
{
	h225ras_handle=new_create_dissector_handle(dissect_h225_h225_RasMessage, proto_h225);
	H323UserInformation_handle=find_dissector("h323ui");

	h245_handle = find_dissector("h245");
	h245dg_handle = find_dissector("h245dg");
	h4501_handle = find_dissector("h4501");
	data_handle = find_dissector("data");

	dissector_add("udp.port", UDP_PORT_RAS1, h225ras_handle);
	dissector_add("udp.port", UDP_PORT_RAS2, h225ras_handle);
}


static void reset_h225_packet_info(h225_packet_info *pi)
{
	if(pi == NULL) {
		return;
	}

	pi->msg_type = H225_OTHERS;
	pi->cs_type = H225_OTHER;
	pi->msg_tag = -1;
	pi->reason = -1;
	pi->requestSeqNum = 0;
	memset(pi->guid,0,16);
	pi->is_duplicate = FALSE;
	pi->request_available = FALSE;
	pi->is_faststart = FALSE;
	pi->is_h245 = FALSE;
	pi->is_h245Tunneling = FALSE;
	pi->h245_address = 0;
	pi->h245_port = 0;
	pi->frame_label[0] = '\0';
	pi->dialedDigits[0] = '\0';
	pi->is_destinationInfo = FALSE;
}

/*
	The following function contains the routines for RAS request/response matching.
	A RAS response matches with a request, if both messages have the same
	RequestSequenceNumber, belong to the same IP conversation and belong to the same
	RAS "category" (e.g. Admission, Registration).

	We use hashtables to access the lists of RAS calls (request/response pairs).
	We have one hashtable for each RAS category. The hashkeys consist of the
	non-unique 16-bit RequestSequenceNumber and values representing the conversation.

	In big capture files, we might get different requests with identical keys.
	These requests aren't necessarily duplicates. They might be valid new requests.
	At the moment we just use the timedelta between the last valid and the new request
	to decide if the new request is a duplicate or not. There might be better ways.
	Two thresholds are defined below.

	However the decision is made, another problem arises. We can't just add those
	requests to our hashtables. Instead we create lists of RAS calls with identical keys.
	The hashtables for RAS calls contain now pointers to the first RAS call in a list of
	RAS calls with identical keys.
	These lists aren't expected to contain more than 3 items and are usually single item
	lists. So we don't need an expensive but intelligent way to access these lists
	(e.g. hashtables). Just walk through such a list.
*/

#define THRESHOLD_REPEATED_RESPONDED_CALL 300
#define THRESHOLD_REPEATED_NOT_RESPONDED_CALL 1800

static void ras_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, h225_packet_info *pi)
{
	conversation_t* conversation = NULL;
	h225ras_call_info_key h225ras_call_key;
	h225ras_call_t *h225ras_call = NULL;
	nstime_t delta;
	guint msg_category;

	if(pi->msg_type == H225_RAS && pi->msg_tag < 21) {
		/* make RAS request/response matching only for tags from 0 to 20 for now */

		msg_category = pi->msg_tag / 3;
		if(pi->msg_tag % 3 == 0) {		/* Request Message */
			conversation = find_conversation(pinfo->fd->num, &pinfo->src,
				&pinfo->dst, pinfo->ptype, pinfo->srcport,
				pinfo->destport, 0);

			if (conversation == NULL) {
				/* It's not part of any conversation - create a new one. */
				conversation = conversation_new(pinfo->fd->num, &pinfo->src,
				    &pinfo->dst, pinfo->ptype, pinfo->srcport,
				    pinfo->destport, 0);

			}

			/* prepare the key data */
			h225ras_call_key.reqSeqNum = pi->requestSeqNum;
			h225ras_call_key.conversation = conversation;

			/* look up the request */
			h225ras_call = find_h225ras_call(&h225ras_call_key ,msg_category);

			if (h225ras_call != NULL) {
				/* We've seen requests with this reqSeqNum, with the same
				   source and destination, before - do we have
				   *this* request already? */
				/* Walk through list of ras requests with identical keys */
				do {
					if (pinfo->fd->num == h225ras_call->req_num) {
						/* We have seen this request before -> do nothing */
						break;
					}

					/* if end of list is reached, exit loop and decide if request is duplicate or not. */
					if (h225ras_call->next_call == NULL) {
						if ( (pinfo->fd->num > h225ras_call->rsp_num && h225ras_call->rsp_num != 0
						   && pinfo->fd->abs_ts.secs > (h225ras_call->req_time.secs + THRESHOLD_REPEATED_RESPONDED_CALL) )
						   ||(pinfo->fd->num > h225ras_call->req_num && h225ras_call->rsp_num == 0
						   && pinfo->fd->abs_ts.secs > (h225ras_call->req_time.secs + THRESHOLD_REPEATED_NOT_RESPONDED_CALL) ) )
						{
							/* if last request has been responded
							   and this request appears after last response (has bigger frame number)
							   and last request occured more than 300 seconds ago,
							   or if last request hasn't been responded
							   and this request appears after last request (has bigger frame number)
							   and last request occured more than 1800 seconds ago,
							   we decide that we have a new request */
							/* Append new ras call to list */
							h225ras_call = append_h225ras_call(h225ras_call, pinfo, pi->guid, msg_category);
						} else {
							/* No, so it's a duplicate request.
							   Mark it as such. */
							pi->is_duplicate = TRUE;
							proto_tree_add_uint_hidden(tree, hf_h225_ras_dup, tvb, 0,0, pi->requestSeqNum);
						}
						break;
					}
					h225ras_call = h225ras_call->next_call;
				} while (h225ras_call != NULL );
			}
			else {
				h225ras_call = new_h225ras_call(&h225ras_call_key, pinfo, pi->guid, msg_category);
			}

			/* add link to response frame, if available */
			if(h225ras_call->rsp_num != 0){
				proto_item *ti =
				proto_tree_add_uint_format(tree, hf_h225_ras_rsp_frame, tvb, 0, 0, h225ras_call->rsp_num,
					                           "The response to this request is in frame %u",
					                           h225ras_call->rsp_num);
				PROTO_ITEM_SET_GENERATED(ti);
			}

  		/* end of request message handling*/
		}
		else { 					/* Confirm or Reject Message */
			conversation = find_conversation(pinfo->fd->num, &pinfo->src,
    				&pinfo->dst, pinfo->ptype, pinfo->srcport,
  				pinfo->destport, 0);
  			if (conversation != NULL) {
				/* look only for matching request, if
				   matching conversation is available. */
				h225ras_call_key.reqSeqNum = pi->requestSeqNum;
				h225ras_call_key.conversation = conversation;
				h225ras_call = find_h225ras_call(&h225ras_call_key ,msg_category);
				if(h225ras_call) {
					/* find matching ras_call in list of ras calls with identical keys */
					do {
						if (pinfo->fd->num == h225ras_call->rsp_num) {
							/* We have seen this response before -> stop now with matching ras call */
							break;
						}

						/* Break when list end is reached */
						if(h225ras_call->next_call == NULL) {
							break;
						}
						h225ras_call = h225ras_call->next_call;
					} while (h225ras_call != NULL) ;

					/* if this is an ACF, ARJ or DCF, DRJ, give guid to tap and make it filterable */
					if (msg_category == 3 || msg_category == 5) {
						memcpy(pi->guid, h225ras_call->guid,16);
						proto_tree_add_guid_hidden(tree, hf_h225_guid, tvb, 0, 16, pi->guid);
					}

					if (h225ras_call->rsp_num == 0) {
						/* We have not yet seen a response to that call, so
						   this must be the first response; remember its
						   frame number. */
						h225ras_call->rsp_num = pinfo->fd->num;
					}
					else {
						/* We have seen a response to this call - but was it
						   *this* response? */
						if (h225ras_call->rsp_num != pinfo->fd->num) {
							/* No, so it's a duplicate response.
							   Mark it as such. */
							pi->is_duplicate = TRUE;
							proto_tree_add_uint_hidden(tree, hf_h225_ras_dup, tvb, 0,0, pi->requestSeqNum);
						}
					}

					if(h225ras_call->req_num != 0){
						proto_item *ti;
						h225ras_call->responded = TRUE;
						pi->request_available = TRUE;

						/* Indicate the frame to which this is a reply. */
						ti = proto_tree_add_uint_format(tree, hf_h225_ras_req_frame, tvb, 0, 0, h225ras_call->req_num,
							"This is a response to a request in frame %u", h225ras_call->req_num);
						PROTO_ITEM_SET_GENERATED(ti);

						/* Calculate RAS Service Response Time */
						nstime_delta(&delta, &pinfo->fd->abs_ts, &h225ras_call->req_time);
						pi->delta_time = delta; /* give it to tap */

						/* display Ras Service Response Time and make it filterable */
						ti = proto_tree_add_time(tree, hf_h225_ras_deltatime, tvb, 0, 0, &(pi->delta_time));
						PROTO_ITEM_SET_GENERATED(ti);
					}
				}
			}
		}
	}
}





