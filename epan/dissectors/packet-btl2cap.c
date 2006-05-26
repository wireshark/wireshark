/* packet-btl2cap.c
 * Routines for the Bluetooth L2CAP dissection
 * Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
 *  From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
 *
 * Refactored for wireshark checkin
 *   Ronnie Sahlberg 2006
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <etypes.h>
#include <epan/emem.h>
#include "packet-bthci_acl.h"
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
static int proto_btl2cap = -1;
static int hf_btl2cap_length = -1;
static int hf_btl2cap_cid = -1;
static int hf_btl2cap_payload = -1;
static int hf_btl2cap_command = -1;
static int hf_btl2cap_cmd_code = -1;
static int hf_btl2cap_cmd_ident = -1;
static int hf_btl2cap_cmd_length = -1;
static int hf_btl2cap_cmd_data = -1;
static int hf_btl2cap_psm = -1;
static int hf_btl2cap_scid = -1;
static int hf_btl2cap_dcid = -1;
static int hf_btl2cap_result = -1;
static int hf_btl2cap_status = -1;
static int hf_btl2cap_rej_reason = -1;
static int hf_btl2cap_sig_mtu = -1;
static int hf_btl2cap_info_mtu = -1;
static int hf_btl2cap_info_type = -1;
static int hf_btl2cap_info_result = -1;
static int hf_btl2cap_continuation_flag = -1;
static int hf_btl2cap_configuration_result = -1;
static int hf_btl2cap_option = -1;
static int hf_btl2cap_option_type = -1;
static int hf_btl2cap_option_length = -1;
static int hf_btl2cap_option_mtu = -1;
static int hf_btl2cap_option_flushTO = -1;
static int hf_btl2cap_option_flags = -1;
static int hf_btl2cap_option_service_type = -1;
static int hf_btl2cap_option_tokenrate = -1;
static int hf_btl2cap_option_tokenbucketsize = -1;
static int hf_btl2cap_option_peakbandwidth = -1;
static int hf_btl2cap_option_latency = -1;
static int hf_btl2cap_option_delayvariation = -1;

/* Initialize the subtree pointers */
static gint ett_btl2cap = -1;
static gint ett_btl2cap_cmd = -1;
static gint ett_btl2cap_option = -1;


/* Initialize dissector table */
dissector_table_t l2cap_psm_dissector_table;

/* This table maps cid values to psm values.
 * The same table is used both for SCID and DCID.
 * For received CIDs we mask the cid with 0x8000 in this table
 */
static se_tree_t *cid_to_psm_table = NULL;
typedef struct _psm_data_t {
	guint16		psm;
} psm_data_t;

static const value_string command_code_vals[] = {
	{ 0x01,	"Command Reject" },
	{ 0x02,	"Connection Request" },
	{ 0x03,	"Connection Response" },
	{ 0x04,	"Configure Request" },
	{ 0x05,	"Configure Response" },
	{ 0x06,	"Disconnect Request" },
	{ 0x07,	"Disconnect Response" },
	{ 0x08,	"Echo Request" },
	{ 0x09,	"Echo Response" },
	{ 0x0A,	"Information Request" },
	{ 0x0B,	"Information Response" },
	{ 0, NULL }
};


static const value_string psm_vals[] = {
	{ 0x0001,	"SDP" },
	{ 0x0003,	"RFCOMM" },
	{ 0x0005,	"TCS-BIN" },
	{ 0x0007,	"TCS-BIN-CORDLESS" },
	{ 0x000F,	"BNEP" },
	{ 0x0011,	"HID_CONTROL" },
	{ 0x0013,	"HID_INTERRUPT" },
	{ 0x0015,	"UPnP" },
	{ 0x0017,	"AVCTP" },
	{ 0x0019,	"AVDTP" },
	{ 0x001D,	"UDI_C-Plane" },
	{ 0, NULL }
};


static const value_string result_vals[] = {
	{ 0x0000,	"Connection successful" },
	{ 0x0001,	"Connection pending" },
	{ 0x0002,	"Connection Refused - PSM not supported" },
	{ 0x0003,	"Connection refused - security block" },
	{ 0x0004,	"Connection refused - no resources available" },
	{ 0, NULL }
};

static const value_string configuration_result_vals[] = {
	{ 0x0000, "Success"},
	{ 0x0001, "Failure - unacceptable parameters" },
	{ 0x0002, "Failure - reject (no reason provided)" },
	{ 0x0003, "Failure - unknown options" },
	{ 0, NULL }
};

static const value_string status_vals[] = {
	{ 0x0000,	"No further information available" },
	{ 0x0001,	"Authentication panding" },
	{ 0x0002,	"Authorization pending" },
	{ 0, NULL }
};

static const value_string reason_vals[] = {
	{ 0x0000,	"Command not understood" },
	{ 0x0001,	"Signaling MTU exceeded" },
	{ 0x0002,	"Invalid CID in request" },
	{ 0, NULL }
};

static const value_string info_type_vals[] = {
	{ 0x0001, "Connectionless MTU" },
	{ 0, NULL }
};

static const value_string info_result_vals[] = {
	{ 0x0000, "Success" },
	{ 0x0001, "Not Supported" },
	{ 0, NULL }
};

static const value_string option_servicetype_vals[] = {
	{ 0x00, "No traffic" },
	{ 0x01, "Best effort (Default)" },
	{ 0x02, "Guaranteed" },
	{ 0, NULL }
};

static const value_string option_type_vals[] = {
	{ 0x01, "Maximum Transmission Unit" },
	{ 0x02, "Flush Timeout" },
	{ 0x03, "Quality of Service" },
	{ 0, NULL }
};


static int 
dissect_comrej(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint16 reason;

	reason = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_btl2cap_rej_reason, tvb, offset, 2, TRUE);
	offset+=2;

	switch(reason){
	case 0x0000: /* Command not understood */
		break;

	case 0x0001: /* Signaling MTU exceeded */
		proto_tree_add_item(tree, hf_btl2cap_sig_mtu, tvb, offset, 2, TRUE);
		offset+=2;
		break;

	case 0x0002: /* Invalid CID in requets */
		proto_tree_add_item(tree, hf_btl2cap_scid, tvb, offset, 2, TRUE);
		offset+=2;

		proto_tree_add_item(tree, hf_btl2cap_dcid, tvb, offset, 2, TRUE);
		offset+=2;

		break;

	default:
		break;
	}

	return offset;
}

static int
dissect_connrequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint16 scid, psm;
	psm_data_t *psm_data;

	psm=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_btl2cap_psm, tvb, offset, 2, TRUE);
	offset+=2;

	scid=tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_btl2cap_scid, tvb, offset, 2, TRUE);
	offset+=2;

	if (pinfo->fd->flags.visited == 0) {
		psm_data=se_alloc(sizeof(psm_data_t));
		psm_data->psm=psm;
		se_tree_insert32(cid_to_psm_table, scid|((pinfo->p2p_dir == P2P_DIR_RECV)?0x8000:0x0000), psm_data);

	}
	return offset;
}


static int
dissect_options(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int length)
{
	proto_item *ti_option=NULL;
	proto_tree *ti_option_subtree=NULL;
	guint8 option_type, option_length;

	if(length>0){
		option_type   = tvb_get_guint8(tvb, offset);
		option_length = tvb_get_guint8(tvb, offset+1);

		ti_option = proto_tree_add_none_format(tree, 
				hf_btl2cap_option, tvb,
				offset, option_length + 2,
				"Option: ");
		ti_option_subtree = proto_item_add_subtree(ti_option, ett_btl2cap_option);
		proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_type, tvb, offset, 1, TRUE);
		proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_length, tvb, offset+1, 1, TRUE);
		offset+=2;

		if(option_length>0){
			switch(option_type){
			case 0x01: /* MTU */
				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_mtu, tvb, offset, 2, TRUE);
				offset+=2;

				proto_item_append_text(ti_option, "MTU");
				break;

			case 0x02: /* Flush timeout */
				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_flushTO, tvb, offset, 2, TRUE);
				offset+=2;

				proto_item_append_text(ti_option, "Flush Timeout");
				break;

			case 0x03: /* QOS */
				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_flags, tvb, offset, 1, TRUE);
				offset++;

				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_service_type, tvb, offset, 1, TRUE);
				offset++;

				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_tokenrate, tvb, offset, 4, TRUE);
				offset+=4;

				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_tokenbucketsize, tvb, offset, 4, TRUE);
				offset+=4;

				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_peakbandwidth, tvb, offset, 4, TRUE);
				offset+=4;

				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_latency, tvb, offset, 4, TRUE);
				offset+=4;

				proto_tree_add_item(ti_option_subtree, hf_btl2cap_option_delayvariation, tvb, offset, 4, TRUE);
				offset+=4;

				proto_item_append_text(ti_option, "QOS");
				break;

			default:
				proto_item_append_text(ti_option, "unknown");
				offset+=tvb_length_remaining(tvb, offset);
				break;
			}
		}
		offset+=dissect_options(tvb, offset, pinfo, tree, tvb_length_remaining(tvb, offset));
	}
	return offset;
}



static int
dissect_configrequest(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_btl2cap_dcid, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_btl2cap_continuation_flag, tvb, offset, 2, TRUE);
	offset+=2;

	if(tvb_length_remaining(tvb, offset)){
		offset=dissect_options(tvb, offset, pinfo, tree, tvb_length_remaining(tvb, offset)); 
	}

	return offset;
}


static int
dissect_inforequest(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_btl2cap_info_type, tvb, offset, 2, TRUE);
	offset+=2;

	return offset;
}

static int
dissect_inforesponse(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint16 info_type;

	info_type=tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_btl2cap_info_type, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_btl2cap_info_result, tvb, offset, 2, TRUE);
	offset+=2;

	if(tvb_length_remaining(tvb, offset)) {
		switch(info_type){
		case 0x0001: /* Connectionless MTU */
			proto_tree_add_item(tree, hf_btl2cap_info_mtu, tvb, offset, 2, TRUE);
			offset+=2;

			break;
		default:
			proto_tree_add_item(tree, hf_btl2cap_cmd_data, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);

			break;
		}
	}

	return offset;
}

static int
dissect_configresponse(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_btl2cap_scid, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_btl2cap_continuation_flag, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_btl2cap_configuration_result, tvb, offset, 2, TRUE);
	offset+=2;

	if(tvb_length_remaining(tvb, offset)){
		offset=dissect_options(tvb, offset, pinfo, tree, tvb_length_remaining(tvb, offset)); 
	}

	return offset;
}

static int 
dissect_connresponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	guint16 scid, dcid;
	psm_data_t *psm_data;

	dcid = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_btl2cap_dcid, tvb, offset, 2, TRUE);
	offset+=2;

	scid = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_btl2cap_scid, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_btl2cap_result, tvb, offset, 2, TRUE);
	offset+=2;

	proto_tree_add_item(tree, hf_btl2cap_status, tvb, offset, 2, TRUE);
	offset+=2;

	if (pinfo->fd->flags.visited == 0) {
		if((psm_data=se_tree_lookup32(cid_to_psm_table, scid|((pinfo->p2p_dir==P2P_DIR_RECV)?0x0000:0x8000)))){
			se_tree_insert32(cid_to_psm_table, dcid|((pinfo->p2p_dir == P2P_DIR_RECV)?0x8000:0x0000), psm_data);
		}
	}

	return offset;
}


static int
dissect_disconnrequestresponse(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
	guint16 scid, dcid;

	dcid = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_btl2cap_dcid, tvb, offset, 2, TRUE);
	offset+=2;

	scid = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(tree, hf_btl2cap_scid, tvb, offset, 2, TRUE);
	offset+=2;

	return offset;
}



/* Code to actually dissect the packets
 * This dissector will only be called ontop of BTHCI ACL
 * and this dissector _REQUIRES_ that 
 * pinfo->private_data points to a valid bthci_acl_data_t structure
 */
static void dissect_btl2cap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset=0;
	proto_item *ti=NULL;
	proto_tree *btl2cap_tree=NULL;
	guint16 length, cid;
	guint16 psm;
	tvbuff_t *next_tvb;
	psm_data_t *psm_data;
	bthci_acl_data_t *acl_data;
	btl2cap_data_t *l2cap_data;

	if(check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "L2CAP");
	}
	if(check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
		col_add_str(pinfo->cinfo, COL_INFO, pinfo->p2p_dir == P2P_DIR_SENT ? "Sent " : "Rcvd ");
	}

	if(tree){
		ti=proto_tree_add_item(tree, proto_btl2cap, tvb, offset, -1, FALSE);
		btl2cap_tree=proto_item_add_subtree(ti, ett_btl2cap);
	}

	length = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(btl2cap_tree, hf_btl2cap_length, tvb, offset, 2, TRUE);
	offset+=2;

	cid = tvb_get_letohs(tvb, offset);
	proto_tree_add_item(btl2cap_tree, hf_btl2cap_cid, tvb, offset, 2, TRUE);
	offset+=2;

	acl_data=(bthci_acl_data_t *)pinfo->private_data;
	l2cap_data=ep_alloc(sizeof(btl2cap_data_t));
	l2cap_data->chandle=acl_data->chandle;
	l2cap_data->cid=cid;
	pinfo->private_data=l2cap_data;

	if(cid==0x0001){ /* This is a command packet*/
		while(offset<(length+4)) {
			proto_tree *btl2cap_cmd_tree=NULL;
			proto_item *ti_command=NULL;
			guint8 cmd_code;
			guint16 cmd_length;

			ti_command=proto_tree_add_none_format(btl2cap_tree, 
					hf_btl2cap_command, tvb,
					offset, -1,
					"Command: ");      
			btl2cap_cmd_tree=proto_item_add_subtree(ti_command, ett_btl2cap_cmd);

			cmd_code=tvb_get_guint8(tvb, offset);
			proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_cmd_code, tvb, offset, 1, TRUE);
			offset++;

			proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_cmd_ident, tvb, offset, 1, TRUE);
			offset++;

			cmd_length=tvb_get_letohs(tvb, offset+2);
			proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_cmd_length, tvb, offset, 2, TRUE);
			proto_item_set_len(ti_command, cmd_length+4);
			offset+=2;

			switch(cmd_code) {
			case 0x01: /* Command Reject */
				offset=dissect_comrej(tvb, offset, pinfo, btl2cap_cmd_tree);
				proto_item_append_text(ti_command, "Command Reject");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Command Reject");
				}
				break;

			case 0x02: /* Connection Request */
				offset=dissect_connrequest(tvb, offset, pinfo, btl2cap_cmd_tree);
				proto_item_append_text(ti_command, "Connection Request");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Connection Request");
				}
				break;

			case 0x03: /* Connection Response */
				offset=dissect_connresponse(tvb, offset, pinfo, btl2cap_cmd_tree);
				proto_item_append_text(ti_command, "Connection Response");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Connection Response");
				}
				break;
			case 0x04: /* Configure Request */
				offset=dissect_configrequest(tvb, offset, pinfo, btl2cap_cmd_tree);
				proto_item_append_text(ti_command, "Configure Request");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Configure Request");
				}
				break;

			case 0x05: /* Configure Response */
				offset=dissect_configresponse(tvb, offset, pinfo, btl2cap_cmd_tree);
				proto_item_append_text(ti_command, "Configure Response");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Configure Response");
				}
				break;

			case 0x06: /* Disconnect Request */
				offset=dissect_disconnrequestresponse(tvb, offset, pinfo, btl2cap_cmd_tree);
				proto_item_append_text(ti_command, "Disconnect Request");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Disconnect Request");
				}
				break;

			case 0x07: /* Disconnect Response */
				offset=dissect_disconnrequestresponse(tvb, offset, pinfo, btl2cap_cmd_tree);   
				proto_item_append_text(ti_command, "Disconnect Response");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Disconnect Response");
				}
				break;    

			case 0x08: /* Echo Request */
				proto_item_append_text(ti_command, "Echo Request");
				offset+=tvb_length_remaining(tvb, offset);
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Echo Request");
				}
				break;

			case 0x09: /* Echo Response */
				proto_item_append_text(ti_command, "Echo Response");
				offset+=tvb_length_remaining(tvb, offset);
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Echo Response");
				}
				break;

			case 0x0a: /* Information Request */
				offset=dissect_inforequest(tvb, offset, pinfo, btl2cap_cmd_tree);

				proto_item_append_text(ti_command, "Information Request");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Information Request");
				}
				break;

			case 0x0b: /* Information Response */
				offset=dissect_inforesponse(tvb, offset, pinfo, btl2cap_cmd_tree);
				proto_item_append_text(ti_command, "Information Response");
				if ((check_col(pinfo->cinfo, COL_INFO))){
					col_append_str(pinfo->cinfo, COL_INFO, "Information Response");
				}
				break;

				default:
					proto_tree_add_item(btl2cap_cmd_tree, hf_btl2cap_cmd_data, tvb, offset, -1, TRUE);
					offset+=tvb_length_remaining(tvb, offset);
					break;
			}
		}
	} else if (cid == 0x0002) { /* Connectionless reception channel */
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_append_str(pinfo->cinfo, COL_INFO, "Connectionless reception channel");
		}

		psm = tvb_get_letohs(tvb, offset);
		proto_tree_add_item(btl2cap_tree, hf_btl2cap_psm, tvb, offset, 2, TRUE);
		offset+=2;


		next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), length);

		/* call next dissector */
		if(!dissector_try_port(l2cap_psm_dissector_table, (guint32) psm, 
					next_tvb, pinfo, tree)){
			/* unknown protocol. declare as data */
			proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, tvb, offset, -1, TRUE);
		}
		offset+=tvb_length_remaining(tvb, offset);
	} else if((cid >= 0x0040) && (cid <= 0xFFFF)){ /* Connection oriented channel */
		if(check_col(pinfo->cinfo, COL_INFO)){ 	
			col_append_str(pinfo->cinfo, COL_INFO, "Connection oriented channel");
		}

		if((psm_data=se_tree_lookup32(cid_to_psm_table, cid|((pinfo->p2p_dir==P2P_DIR_RECV)?0x0000:0x8000)))){
			psm=psm_data->psm;
		} else {
			psm=0;
		}

		next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), length);

		if(psm){
			proto_item *psm_item;

			psm_item=proto_tree_add_uint(btl2cap_tree, hf_btl2cap_psm, tvb, offset, 0, psm);
			PROTO_ITEM_SET_GENERATED(psm_item);

			/* call next dissector */
			if (!dissector_try_port(l2cap_psm_dissector_table, (guint32) psm, 
						next_tvb, pinfo, tree)) {
				/* unknown protocol. declare as data */
				proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, tvb, offset, -1, TRUE);
			}
			offset+=tvb_length_remaining(tvb, offset);
		} else {
			proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, tvb, offset, -1, TRUE);
			offset+=tvb_length_remaining(tvb, offset);
		}
	} else { /* Something else */
		if(check_col(pinfo->cinfo, COL_INFO)){
			col_clear(pinfo->cinfo, COL_INFO);
		}

		proto_tree_add_item(btl2cap_tree, hf_btl2cap_payload, tvb, offset, -1, TRUE);
		offset+=tvb_length_remaining(tvb, offset);
	}
}


/* Register the protocol with Wireshark */
void
proto_register_btl2cap(void)
{                 

	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_btl2cap_length,
			{ "Length",           "btl2cap.length",
				FT_UINT16, BASE_DEC, NULL, 0x0,          
				"L2CAP Payload Length", HFILL }
		},
		{ &hf_btl2cap_cid,
			{ "CID",           "btl2cap.cid",
				FT_UINT16, BASE_HEX, NULL, 0x0,          
				"L2CAP Channel Identifier", HFILL }
		},
		{ &hf_btl2cap_payload,
			{ "Payload",           "btl2cap.payload",
				FT_NONE, BASE_NONE, NULL, 0x0,          
				"L2CAP Payload", HFILL }
		},
		{ &hf_btl2cap_command,
			{ "Command",           "btl2cap.command",
				FT_NONE, BASE_NONE, NULL, 0x0,          
				"L2CAP Command", HFILL }
		},
		{ &hf_btl2cap_cmd_code,
			{ "Command Code",           "btl2cap.cmd_code",
				FT_UINT8, BASE_HEX, VALS(command_code_vals), 0x0,          
				"L2CAP Command Code", HFILL }
		},
		{ &hf_btl2cap_cmd_ident,
			{ "Command Identifier",           "btl2cap.cmd_ident",
				FT_UINT8, BASE_HEX, NULL, 0x0,          
				"L2CAP Command Identifier", HFILL }
		},
		{ &hf_btl2cap_cmd_length,
			{ "Command Length",           "btl2cap.cmd_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,          
				"L2CAP Command Length", HFILL }
		},
		{ &hf_btl2cap_cmd_data,
			{ "Command Data",           "btl2cap.cmd_data",
				FT_NONE, BASE_NONE, NULL, 0x0,          
				"L2CAP Command Data", HFILL }
		},
		{ &hf_btl2cap_psm,
			{ "PSM",           "btl2cap.psm",
				FT_UINT16, BASE_HEX, VALS(psm_vals), 0x0,          
				"Protocol/Service Multiplexor", HFILL }
		},
		{ &hf_btl2cap_scid,
			{ "Source CID",           "btl2cap.scid",
				FT_UINT16, BASE_HEX, NULL, 0x0,          
				"Source Channel Identifier", HFILL }
		},
		{ &hf_btl2cap_dcid,
			{ "Destination CID",           "btl2cap.dcid",
				FT_UINT16, BASE_HEX, NULL, 0x0,          
				"Destination Channel Identifier", HFILL }
		},
		{ &hf_btl2cap_result,
			{ "Result",           "btl2cap.result",
				FT_UINT16, BASE_HEX, VALS(result_vals), 0x0,          
				"Result", HFILL }
		},
		{ &hf_btl2cap_status,
			{ "Status",           "btl2cap.status",
				FT_UINT16, BASE_HEX, VALS(status_vals), 0x0,          
				"Status", HFILL }
		},
		{ &hf_btl2cap_rej_reason,
			{ "Reason",           "btl2cap.rej_reason",
				FT_UINT16, BASE_HEX, VALS(reason_vals), 0x0,          
				"Reason", HFILL }
		},
		{ &hf_btl2cap_sig_mtu,
			{ "Maximum Signalling MTU",           "btl2cap.sig_mtu",
				FT_UINT16, BASE_DEC, NULL, 0x0,          
				"Maximum Signalling MTU", HFILL }
		},
		{ &hf_btl2cap_info_mtu,
			{ "Remote Entity MTU",           "btl2cap.info_mtu",
				FT_UINT16, BASE_DEC, NULL, 0x0,          
				"Remote entitiys acceptable connectionless MTU", HFILL }
		},
		{ &hf_btl2cap_info_type,
			{ "Information Type",           "btl2cap.info_type",
				FT_UINT16, BASE_HEX, VALS(info_type_vals), 0x0,          
				"Type of implementation-specific information", HFILL }
		},
		{ &hf_btl2cap_info_result,
			{ "Result",           "btl2cap.info_result",
				FT_UINT16, BASE_HEX, VALS(info_result_vals), 0x0,          
				"Information about the success of the request", HFILL }
		},
		{ &hf_btl2cap_continuation_flag,
			{ "Continuation Flag",           "btl2cap.continuation",
				FT_BOOLEAN, BASE_DEC, NULL, 0x0001,          
				"Continuation Flag", HFILL }
		},
		{ &hf_btl2cap_configuration_result,
			{ "Result",           "btl2cap.conf_result",
				FT_UINT16, BASE_HEX, VALS(configuration_result_vals), 0x0,
				"Configuration Result", HFILL }
		},
		{ &hf_btl2cap_option_type,
			{ "Type",           "btl2cap.option_type",
				FT_UINT8, BASE_HEX, VALS(option_type_vals), 0x0,          
				"Type of option", HFILL }
		},
		{ &hf_btl2cap_option_length,
			{ "Length",           "btl2cap.option_length",
				FT_UINT8, BASE_DEC, NULL, 0x0,          
				"Number of octets in option payload ", HFILL }
		},
		{ &hf_btl2cap_option_mtu,
			{ "MTU",           "btl2cap.option_mtu",
				FT_UINT16, BASE_DEC, NULL, 0x0,          
				"Maximum Transmission Unit", HFILL }
		},
		{ &hf_btl2cap_option_flushTO,
			{ "Flush Timeout (ms)",           "btl2cap.option_flushto",
				FT_UINT16, BASE_DEC, NULL, 0x0,          
				"Flush Timeout in milliseconds", HFILL }
		},
		{ &hf_btl2cap_option_flags,
			{ "Flags",           "btl2cap.option_flags",
				FT_UINT8, BASE_HEX, NULL, 0x0,          
				"Flags - must be set to 0 (Reserved for future use)", HFILL }
		},
		{ &hf_btl2cap_option_service_type,
			{ "Service Type",           "btl2cap.option_servicetype",
				FT_UINT8, BASE_HEX, VALS(option_servicetype_vals), 0x0,     
				"Level of service required", HFILL }
		},
		{ &hf_btl2cap_option_tokenrate,
			{ "Token Rate (bytes/s)",           "btl2cap.option_tokenrate",
				FT_UINT32, BASE_DEC, NULL, 0x0,          
				"Rate at which traffic credits are granted (bytes/s)", HFILL }
		},
		{ &hf_btl2cap_option_tokenbucketsize,
			{ "Token Bucket Size (bytes)",           "btl2cap.option_tokenbsize",
				FT_UINT32, BASE_DEC, NULL, 0x0,          
				"Size of the token bucket (bytes)", HFILL }
		},
		{ &hf_btl2cap_option_peakbandwidth,
			{ "Peak Bandwidth (bytes/s)",           "btl2cap.option_peakbandwidth",
				FT_UINT32, BASE_DEC, NULL, 0x0,          
				"Limit how fast packets may be sent (bytes/s)", HFILL }
		},
		{ &hf_btl2cap_option_latency,
			{ "Latency (microseconds)",           "btl2cap.option_latency",
				FT_UINT32, BASE_DEC, NULL, 0x0,          
				"Maximal acceptable dealy (microseconds)", HFILL }
		},
		{ &hf_btl2cap_option_delayvariation,
			{ "Delay Variation (microseconds)",           "btl2cap.option_dealyvar",
				FT_UINT32, BASE_DEC, NULL, 0x0,          
				"Difference between maximum and minimum delay (microseconds)", HFILL }
		},
		{ &hf_btl2cap_option,
			{ "Configuration Parameter Option",           "btl2cap.conf_param_option",
				FT_NONE, BASE_NONE, NULL, 0x0,          
				"Configuration Parameter Option", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_btl2cap,
		&ett_btl2cap_cmd,
		&ett_btl2cap_option,
	};

	/* Register the protocol name and description */
	proto_btl2cap = proto_register_protocol("Bluetooth L2CAP Packet", "L2CAP", "btl2cap");

	register_dissector("btl2cap", dissect_btl2cap, proto_btl2cap);

	/* subdissector code */
	l2cap_psm_dissector_table = register_dissector_table("btl2cap.psm", "L2CAP PSM", FT_UINT16, BASE_HEX);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_btl2cap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	cid_to_psm_table=se_tree_create(SE_TREE_TYPE_RED_BLACK, "btl2cap scid to psm");

}


void 
proto_reg_handoff_btl2cap(void)
{

}


