/* packet-elcom.c
 * Routines for elcom packet dissection
 * Copyright 2008, 2011 juha.takala@iki.fi (Juha Takala)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-imap.c
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
 * I found the protocol specification at
 *  http://www.sintef.no/upload/Energiforskning/Energisystemer/ELCOM 90.pdf
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

#define TCP_PORT_ELCOM		5997

/* Application level: */
#define A_CONRQ	0x04
#define A_CONRS	0x05

/* Presentation level: */
#define P_CONRQ	0x00
#define P_CONRS	0x10
#define P_RELRQ	0x20
#define P_RELRS	0x30
#define P_DATRQ	0x80

#define TC_REQ 0x40
#define TC_RSP 0x41

#define LOWADR_LEN 17
#define SUFFIX_LEN 2
#define TOTAL_LEN (LOWADR_LEN + SUFFIX_LEN + 2)

#define ELCOM_UNKNOWN_ENDIAN 0
#define ELCOM_LITTLE_ENDIAN 1
#define ELCOM_BIG_ENDIAN 2

static int proto_elcom = -1;
static int hf_elcom_response = -1;
static int hf_elcom_request = -1;

static int hf_elcom_length = -1;
static int hf_elcom_type = -1;

static int hf_elcom_initiator_endian = -1;
static int hf_elcom_initiator_ip = -1;
static int hf_elcom_initiator_port = -1;
static int hf_elcom_initiator_suff = -1;

static int hf_elcom_responder_endian = -1;
static int hf_elcom_responder_ip = -1;
static int hf_elcom_responder_port = -1;
static int hf_elcom_responder_suff = -1;

static int hf_elcom_userdata_length = -1;
static int hf_elcom_userdata_pduid = -1;
static int hf_elcom_userdata_version = -1;
static int hf_elcom_userdata_result = -1;
static int hf_elcom_userdata_restmark = -1;
static int hf_elcom_userdata_cf = -1;

static int hf_elcom_datarequest_grouptype = -1;
static int hf_elcom_datarequest_result = -1;
static int hf_elcom_datarequest_groupnumber = -1;
static int hf_elcom_datarequest_grouppriority = -1;
static int hf_elcom_datarequest_groupsize = -1;
static int hf_elcom_datarequest_groupindex1 = -1;
static int hf_elcom_datarequest_groupindex2 = -1;
static int hf_elcom_datarequest_oid = -1;

static int hf_elcom_release_reason = -1;
static int hf_elcom_release_result = -1;

static gint ett_elcom = -1;
static gint ett_elcom_initiator = -1;
static gint ett_elcom_responder = -1;
static gint ett_elcom_userdata = -1;
static gint ett_elcom_datarequest = -1;

static gboolean elcom_show_hex = TRUE;


static gint
dissect_lower_address(proto_item *ti_arg, gint ett_arg,
		      tvbuff_t *tvb, gint arg_offset,
		      int hf_endian, int hf_ip, int hf_port, int hf_suff)
{
	gint offset = arg_offset;
	gint endian = ELCOM_UNKNOWN_ENDIAN;
	guint8 len1, len2;
	guint8 *suffix;
	proto_tree *tree;
	proto_item *ti;

	tree = proto_item_add_subtree(ti_arg, ett_arg);
	
	/* 
	 * Coding of address:
	 * ELCOM-90 TRA3825.02 User Element conventions, p. 5-2 and Appendix G
	 */
	len1 = tvb_get_guint8(tvb, offset);
	if (tvb_length_remaining(tvb, offset+len1+1) <= 0)
		return offset;
	len2 = tvb_get_guint8(tvb, offset+len1+1);
	if (tvb_length_remaining(tvb, offset+len1+len2+2) <= 0)
		return offset;
	if ((len1 != LOWADR_LEN) || (len2 != SUFFIX_LEN)) {
		proto_item_append_text(tree, " Invalid structure");
		return offset;
	}


	/* Show pre stuff */
	if (0x82 != tvb_get_guint8(tvb, offset+1)) {
		proto_item_append_text(tree, " Not IPV4 address");
		return offset;
	}
	offset += 2;

	if ((0x02 == tvb_get_guint8(tvb, offset)) &&
	    (0x00 == tvb_get_guint8(tvb, offset+1))) {
		endian = ELCOM_LITTLE_ENDIAN;
	} else if ((0x00 == tvb_get_guint8(tvb, offset)) &&
		   (0x02 == tvb_get_guint8(tvb, offset+1))) {
		endian = ELCOM_BIG_ENDIAN;
	}

	/* endian */
	ti = proto_tree_add_uint(tree, hf_endian, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	if (endian == ELCOM_LITTLE_ENDIAN)
		proto_item_append_text(ti, " Little");
	else if (endian == ELCOM_BIG_ENDIAN)
		proto_item_append_text(ti, " Big");
	else
		proto_item_append_text(ti, " Unknown");
	offset += 2;

	/* port */
	proto_tree_add_uint(tree, hf_port, tvb, offset, 2, tvb_get_ntohs(tvb, offset));
	offset += 2;

	/* ip-addr */
	proto_tree_add_ipv4(tree, hf_ip, tvb, offset, 4, tvb_get_ipv4(tvb, offset));
	offset += 4;

	offset += 8;		/* skip the zero bytes */

	/* SUFFIX */
	suffix = tvb_get_string(tvb, offset+1, len2);
	ti = proto_tree_add_item(tree, hf_suff, tvb, offset, 1, TRUE);
	offset += len2+1;

	if (!(suffix[0] == 'A' || suffix[0] == 'B')) {
		g_free(suffix);
		proto_item_append_text(ti, "  (invalid)");
		return offset;
	}
	proto_item_append_text(ti, "  (%s)",
			       suffix[1] == 'A' ? "Control" :
			       suffix[1] == 'B' ? "Unsolicited" :
			       suffix[1] == 'C' ? "Periodic" :
			       suffix[1] == 'D' ? "Requested, scheduling" :
			       suffix[1] == 'E' ? "Requested, present/archived" :
			       suffix[1] == 'G' ? "Supervisory" :
			       suffix[1] == 'F' ? "Test" :
			       "<<-- WHAT?");

	g_free(suffix);
	return offset;
}

static gint
dissect_userdata(proto_item *ti_arg, gint ett_arg, tvbuff_t *tvb, gint arg_offset)
{
	gint offset = arg_offset;
	guint8 flen, pduid, version, result, lenbytes, restmark;
	guint8 year, month, day, hour, min, sec;
	guint16 msec;
	proto_tree *tree;
	proto_item *ti;

	tree = proto_item_add_subtree(ti_arg, ett_arg);

	/* length of User Data, should be 1 byte field ... */
	flen = tvb_get_guint8(tvb, offset);
	lenbytes = 1;
	
	/* ... but sometimes it seems to be 2 bytes; try to be clever */
	if (flen == 0) {
		flen = tvb_get_guint8(tvb, offset+1);
		lenbytes = 2;
	}
	if (flen == 0 || flen > 79) /* invalid */
		return offset;

	ti = proto_tree_add_uint(tree, hf_elcom_userdata_length, tvb, offset, lenbytes, flen);
	offset += lenbytes;
	if (lenbytes == 2) {
		proto_item_append_text(ti, " (2 bytes, should be 1 byte)");
	}

	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	pduid = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_uint(tree, hf_elcom_userdata_pduid, tvb, offset, 1, pduid);
	offset++;
	switch (pduid) {
	case 0x04: proto_item_append_text(ti, " (connect request)"); break;
	case 0x05: proto_item_append_text(ti, " (connect response)"); break;
	default:   proto_item_append_text(ti, " (unknown)"); return offset;
	}

	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	version = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_uint(tree, hf_elcom_userdata_version, tvb, offset, 1, version);
	offset++;
	switch (version) {
	case 0x00: proto_item_append_text(ti, " (class 0, v0)"); break;
	case 0x01: proto_item_append_text(ti, " (class 1, v0)"); break;
	case 0x02: proto_item_append_text(ti, " (class 2, v0)"); break;
	case 0x12: proto_item_append_text(ti, " (class 2, v1)"); break;
	case 0x13: proto_item_append_text(ti, " (class 3, v1)"); break;
	default:   proto_item_append_text(ti, " (unknown)"); return offset;
	}

	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	result = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_uint(tree, hf_elcom_userdata_result, tvb, offset, 1, result);
	offset++;
	switch (result) {
	case 0x00: proto_item_append_text(ti, " (OK)"); break;
	default:   proto_item_append_text(ti, " (unknown)"); return offset;
	}

	/* show the rest */
	/*	tree2 = proto_tree_add_text(tree, tvb, offset, -1, "User Data"); */
	
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;
	restmark = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_uint(tree, hf_elcom_userdata_restmark, tvb, offset, 1, restmark);
	proto_item_append_text(ti, " <-- '0' = no restart etc.");
	offset +=1;

	if (tvb_length_remaining(tvb, offset+8) <= 0)
		return offset;
	year  = tvb_get_guint8(tvb, offset);
	month = tvb_get_guint8(tvb, offset+1);
	day   = tvb_get_guint8(tvb, offset+2);
	hour  = tvb_get_guint8(tvb, offset+3);
	min   = tvb_get_guint8(tvb, offset+4);
	sec   = tvb_get_guint8(tvb, offset+5);
	msec  = tvb_get_ntohs(tvb, offset+6);

	proto_tree_add_none_format(tree, hf_elcom_userdata_cf, tvb, offset, 8,
				   "Control Field: %4d-%02d-%02d %02d:%02d:%02d.%d",
				   year+1900, month, day, hour, min, sec, msec);

	offset += 12;
	if (tvb_length_remaining(tvb, offset+12) > 0) {
		proto_item_append_text(ti, " Security info: ");
	}
	/* security info field, if present */
	while (tvb_length_remaining(tvb, offset) > 0) {
		proto_item_append_text(ti, elcom_show_hex ? " %02x" : " %03o",
				       tvb_get_guint8(tvb, offset));
		offset++;
	}

	return offset;
}

static gint
dissect_datarequest(proto_item *ti_arg, gint ett_arg, tvbuff_t *tvb, gint arg_offset)
{
	gint offset = arg_offset;
	guint8 gtype,  gnr, prio, gsize, oidlen, result;
	guint16 index1, index2;
	proto_tree *tree, *tree2;
	proto_item *ti;

	tree = proto_item_add_subtree(ti_arg, ett_arg);
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	gtype = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_uint(tree, hf_elcom_datarequest_grouptype,
				 tvb, offset, 1, gtype);
	offset += 1;

	switch (gtype) {
	case TC_REQ:
		proto_item_append_text(ti, " = Test Connection Request");
		break;

	case TC_RSP:
		proto_item_append_text(ti, " = Test Connection Response");

		result = tvb_get_guint8(tvb, offset);
		ti = proto_tree_add_uint(tree, hf_elcom_datarequest_result,
					 tvb, offset, 1, result);
		offset++;

		break;

	default:
		proto_item_append_text(ti, " <<--- meaning WHAT?");
		return offset;
	}
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	gnr = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_elcom_datarequest_groupnumber, tvb, offset, 1, gnr);
	offset += 1;
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	prio = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_elcom_datarequest_grouppriority, tvb, offset, 1, prio);
	offset += 1;
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	gsize = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_elcom_datarequest_groupsize, tvb, offset, 1, gsize);
	offset += 1;
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	index1 = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(tree, hf_elcom_datarequest_groupindex1, tvb, offset, 2, index1);
	offset += 2;
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	index2 = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(tree, hf_elcom_datarequest_groupindex2, tvb, offset, 2, index2);
	offset += 2;
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	while (1) {
		oidlen = tvb_get_guint8(tvb, offset);
		if (oidlen == 0) /* normal termination */
			break;
		if (tvb_length_remaining(tvb, offset+oidlen+1) <= 0)
			return offset;
		proto_tree_add_item(tree, hf_elcom_datarequest_oid, tvb, offset, 1, TRUE);
		offset += oidlen+1;
	}
	offset += 1;		/* the loop exited at the 0 length byte */
	if (tvb_length_remaining(tvb, offset) <= 0)
		return offset;

	/* show the rest */
	tree2 = proto_tree_add_text(tree, tvb, offset, -1, "leftover =");
	while (tvb_length_remaining(tvb, offset) > 0) {
		proto_item_append_text(tree2, elcom_show_hex ? " %02x" : " %03o",
				       tvb_get_guint8(tvb, offset));
		offset++;
	}
	
	return offset;
}

static void
dissect_elcom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
        gboolean        is_request, length_ok;
        proto_tree      *elcom_tree;
        proto_item      *ti, *hidden_item;
	gint		offset = 0;
	guint16		elcom_len;
	guint8		elcom_msg_type, result;
	guint8 		*suffix;

	/* Check that there's enough data */
	if (tvb_length(tvb) < 3)
		return;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ELCOM");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	is_request = (pinfo->match_port == pinfo->destport);
	elcom_len = tvb_get_ntohs(tvb, 0);
	length_ok = (tvb_length(tvb) == (guint16)(elcom_len+2));
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s Len=%d%s",
			     is_request ? "Request" : "Response",
			     elcom_len,
			     length_ok ? "" : " (incorrect)");

		elcom_msg_type = tvb_get_guint8(tvb, 2);
		switch (elcom_msg_type) {
		case P_CONRQ:
		case P_CONRS:
			/* starting after elcom_len and elcom_msg_type,
			   initiator + responder + userdata fields must be there */
			if (tvb_length_remaining(tvb, 3+TOTAL_LEN+TOTAL_LEN+3) < 0) return;
			/* check also that those field lengths are valid */
			if (tvb_get_guint8(tvb, 3)  != LOWADR_LEN) return;
			if (tvb_get_guint8(tvb, 3+1+LOWADR_LEN) != SUFFIX_LEN) return;
			if (tvb_get_guint8(tvb, 3+TOTAL_LEN) != LOWADR_LEN) return;
			if (tvb_get_guint8(tvb, 3+1+TOTAL_LEN+LOWADR_LEN) != SUFFIX_LEN) return;
			/* finally believe that there is valid suffix */
			suffix = tvb_get_string(tvb, 3+2+LOWADR_LEN, 2);
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s Connect", suffix);
			g_free(suffix);
			break;
			
		case P_RELRQ:
		case P_RELRS:
			col_append_str(pinfo->cinfo, COL_INFO, " Release");
			break;
			
		case P_DATRQ:
			col_append_str(pinfo->cinfo, COL_INFO, " Data");
			break;
		}

		switch (elcom_msg_type) {
		case P_CONRQ:
		case P_RELRQ:
			col_append_str(pinfo->cinfo, COL_INFO, " Request");
			break;
			
		case P_CONRS:
		case P_RELRS:
			col_append_str(pinfo->cinfo, COL_INFO, " Response");
			break;
		}
		
		return;
	}

	if (!tree)
		return;

	ti = proto_tree_add_item(tree, proto_elcom, tvb, offset, -1, FALSE);
	elcom_tree = proto_item_add_subtree(ti, ett_elcom);
	
	hidden_item = proto_tree_add_boolean(elcom_tree,
					     is_request ? hf_elcom_request : hf_elcom_response,
					     tvb, 0, 0, TRUE);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	/* 2 first bytes are the frame length */
	offset = 0;
	ti = proto_tree_add_uint(elcom_tree, hf_elcom_length, tvb, offset, 2, elcom_len);
	offset = +2;
	if (! length_ok) {
		proto_item_append_text(ti, " (incorrect)");
	}

	elcom_msg_type = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_uint(elcom_tree, hf_elcom_type, tvb, offset, 1, elcom_msg_type);
	offset++;
	if (tvb_length_remaining(tvb, offset) <= 0)
		return;

	switch (elcom_msg_type) {
	case P_CONRQ:
	case P_CONRS:
		/*
		 * Connection request/release assiciated PDU's,
		 * /ELCOM-90 P Protocol spec/ p. 85...
		 */
		proto_item_append_text(elcom_tree, "  (Connect %s)", 
				       ((elcom_msg_type == P_CONRQ)
					? "Request" : "Response"));
		proto_item_append_text(ti, "  (Connect %s)", 
				       ((elcom_msg_type == P_CONRQ)
					? "Request" : "Response"));
		
		/* We need the lenght here, hardcode the LOWADR_LEN = 21 */
		ti = proto_tree_add_text(elcom_tree, tvb, offset, TOTAL_LEN, "Initiator");
		offset = dissect_lower_address(ti, ett_elcom_initiator, tvb, offset,
					       hf_elcom_initiator_endian,
					       hf_elcom_initiator_ip,
					       hf_elcom_initiator_port,
					       hf_elcom_initiator_suff);
		if (tvb_length_remaining(tvb, offset) <= 0)
			return;
		
		ti = proto_tree_add_text(elcom_tree, tvb, offset, TOTAL_LEN, "Responder");
		offset = dissect_lower_address(ti, ett_elcom_responder, tvb, offset,
					       hf_elcom_responder_endian,
					       hf_elcom_responder_ip,
					       hf_elcom_responder_port,
					       hf_elcom_responder_suff);
		if (tvb_length_remaining(tvb, offset) <= 0)
			return;
		
		/* Rest of the payload is USER-DATA, 0..82 bytes */
		ti = proto_tree_add_text(elcom_tree, tvb, offset, -1, "User Data");
		offset = dissect_userdata(ti, ett_elcom_userdata, tvb, offset);

		break;

	case P_RELRQ:
	case P_RELRS:
		proto_item_append_text(elcom_tree, " (Release %s)", 
				       ((elcom_msg_type == P_RELRQ)
					? "Request" : "Response"));

		proto_item_append_text(ti, "  (Release %s)", 
				       ((elcom_msg_type == P_RELRQ)
					? "Request" : "Response"));

		result = tvb_get_guint8(tvb, offset);
		ti = proto_tree_add_uint(elcom_tree,
					 (elcom_msg_type == P_RELRQ)
					 ? hf_elcom_release_reason
					 : hf_elcom_release_result,
					 tvb, offset, 1, result);
		offset += 1;
		
		break;

	case P_DATRQ:
		proto_item_append_text(ti, "  (Data Request)");
		proto_item_append_text(elcom_tree, " (Data request)");
		ti = proto_tree_add_text(elcom_tree, tvb, offset, -1, "Data Request");
		offset = dissect_datarequest(ti, ett_elcom_datarequest, tvb, offset);
		break;

	default:
		proto_item_append_text(ti, " <<--- meaning WHAT??");
		break;
	}
	

	if (tvb_length_remaining(tvb, offset) <= 0)
		return;

	/* We should not get here, but if we do, show what is left over: */
	ti = proto_tree_add_text(elcom_tree, tvb, offset, -1, "Strange leftover");
	while (tvb_length_remaining(tvb, offset) > 0) {
		proto_item_append_text(ti, elcom_show_hex ? " %02x" : " %03o",
				       tvb_get_guint8(tvb, offset));
		offset++;
	}
}

void
proto_register_elcom(void)
{
	/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_elcom_response,
		  { "Response",		"elcom.response",
		    FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
		},		

		{ &hf_elcom_request,
		  { "Request",		"elcom.request",
		    FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_length,
		  { "Lenght",		"elcom.length",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_type,
		  { "Type",		"elcom.type",
		    FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_initiator_endian,
		  { "Endian",		"elcom.initiator.endian",
		    FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_initiator_ip,
		  { "IP",		"elcom.initiator.ip",
		    FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_initiator_port,
		  { "Port",		"elcom.initiator.port",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_initiator_suff,
		  { "Suffix",		"elcom.initiator.suffix",
		    FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_responder_endian,
		  { "Endian",		"elcom.responder.endian",
		    FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_responder_ip,
		  { "IP",		"elcom.responder.ip",
		    FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_responder_port,
		  { "Port",		"elcom.responder.port",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_responder_suff,
		  { "Suffix",		"elcom.responder.suffix",
		    FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_userdata_length,
		  { "Lenght",		"elcom.userdata.length",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_userdata_pduid,
		  { "PDU-ID",		"elcom.userdata.pduid",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_userdata_version,
		  { "Version",		"elcom.userdata.version",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_userdata_result,
		  { "Result",		"elcom.userdata.result",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_userdata_restmark,
		  { "Restart marking",	"elcom.userdata.response.restartcode",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_userdata_cf,
		  { "Control Field",	"elcom.userdata.response.controlfield",
		    FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_release_reason,
		  { "Reason",	"elcom.release.reason",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_release_result,
		  { "Result",	"elcom.release.result",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_datarequest_grouptype,
		  { "Group Type",	"elcom.datarequest.grouptype",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_datarequest_result,
		  { "Result",	"elcom.datarequest.result",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_datarequest_groupnumber,
		  { "Group Number",	"elcom.datarequest.groupnumber",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_datarequest_grouppriority,
		  { "Group Priority",	"elcom.datarequest.grouppriority",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_datarequest_groupsize,
		  { "Group Size",	"elcom.datarequest.groupsize",
		    FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_datarequest_groupindex1,
		  { "Group Index1",	"elcom.datarequest.groupindex1",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_datarequest_groupindex2,
		  { "Group Index2",	"elcom.datarequest.groupindex2",
		    FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
		},

		{ &hf_elcom_datarequest_oid,
		  { "Obkect Name",	"elcom.datarequest.oid",
		    FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
		}

	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_elcom,
		&ett_elcom_initiator,
		&ett_elcom_responder,
		&ett_elcom_userdata,
		&ett_elcom_datarequest
	};

	/* Register the protocol name and description */
	proto_elcom = proto_register_protocol (
					       "ELCOM Communication Protocol",
					       "ELCOM",
					       "elcom"
					       );

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_elcom, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_elcom(void)
{
	dissector_handle_t elcom_handle;

	elcom_handle = create_dissector_handle(dissect_elcom, proto_elcom);
	dissector_add_uint("tcp.port", TCP_PORT_ELCOM, elcom_handle);
}

/*
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */
