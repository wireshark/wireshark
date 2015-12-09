/* packet-uts.c
 * Routines for UTS WAN protocol dissection
 * Copyright 2007, Fulko Hew, SITA INC Canada, Inc.
 *
 * Copied from packet-ipars.c
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

/* Use tabstops = 4 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <wsutil/str_util.h>

#define	SOH	(0x01)
#define	STX	(0x02)
#define	ETX	(0x03)
#define	EOT	(0x04)
#define	ENQ	(0x05)
#define	BEL	(0x07)
#define	NAK	(0x15)
#define	DLE	(0x10)

#define GRID	(0x20)
#define GSID	(0x50)
#define GDID	(0x70)

#define MAX_POLL_TYPE_MSG_SIZE	(50)

void proto_register_uts(void);

static int	proto_uts	= -1;
static gint	ett_uts		= -1;
static gint	ett_header_uts	= -1;
static gint	ett_trailer_uts	= -1;
static int	hf_rid		= -1;
static int	hf_sid		= -1;
static int	hf_did		= -1;
static int	hf_retxrequest	= -1;
static int	hf_ack		= -1;
static int	hf_replyrequest	= -1;
static int	hf_busy		= -1;
static int	hf_notbusy	= -1;
static int	hf_msgwaiting	= -1;
static int	hf_function	= -1;
static int	hf_data		= -1;

#define MATCH	(1)
#define FETCH	(2)

#define SRC	(1)
#define DST	(2)

static int testchar(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int op, gchar match, gchar *storage)
{
	gchar temp;

	if (tvb_bytes_exist(tvb, offset, 1)) {
		temp = tvb_get_guint8(tvb, offset) & 0x7f;
		if (op == FETCH || (op == MATCH && temp == match)) {
			if (storage != NULL)
				*storage = temp;
			return 1;
		} else {
			return 0;
		}
	} else {
		col_set_str(pinfo->cinfo, COL_INFO, "Unknown Message Format");
		return 0;
	}
}

static void
set_addr(packet_info *pinfo _U_ , int field, gchar rid, gchar sid, gchar did)
{
	if (field == SRC) {
		col_append_fstr(pinfo->cinfo, COL_DEF_SRC, " %2.2X:%2.2X:%2.2X", rid, sid, did);
	} else {
		col_append_fstr(pinfo->cinfo, COL_DEF_DST, " %2.2X:%2.2X:%2.2X", rid, sid, did);
	}
}

static int
dissect_uts(tvbuff_t *tvb, packet_info *pinfo _U_ , proto_tree *tree, void* data _U_)
{
	proto_tree	*uts_tree		= NULL;
	proto_tree	*uts_header_tree	= NULL;
	proto_tree	*uts_trailer_tree	= NULL;
	proto_item	*ti;
	int		length;
	gchar		rid = 0, sid = 0, did = 0;
	int		offset			= 0;
	int		header_length		= -1;
	int		ack_start		= 0;
	int		busy_start		= 0;
	int		notbusy_start		= 0;
	int		replyrequest_start	= 0;
	int		function_start		= 0;
	int		msgwaiting_start	= 0;
	int		nak_start		= 0;
	int		etx_start		= 0;
	int		bcc_start		= 0;
	int		stx_start		= 0;
	gchar		function_code;
	guint8		*data_ptr;

	enum	{ NOTRAFFIC, OTHER }	msg_type = OTHER;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "UTS");

	if (testchar(tvb, pinfo, 0, MATCH, EOT, NULL)	  &&
		testchar(tvb, pinfo, 1, MATCH, EOT, NULL) &&
		testchar(tvb, pinfo, 2, MATCH, ETX, NULL)) {
		msg_type = NOTRAFFIC;
		col_set_str(pinfo->cinfo, COL_INFO, "No Traffic");
	} else {
		if (testchar(tvb, pinfo, 0, MATCH, SOH, NULL)		&&
		    testchar(tvb, pinfo, 1, FETCH, 0, (gchar *)&rid)	&&
		    testchar(tvb, pinfo, 2, FETCH, 0, (gchar *)&sid)	&&
		    testchar(tvb, pinfo, 3, FETCH, 0, (gchar *)&did)) {
			offset = 4;
			if (testchar(tvb, pinfo, offset, MATCH, ETX, NULL)) {
				col_set_str(pinfo->cinfo, COL_INFO, "General Poll");
				set_addr(pinfo, DST, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, MATCH, DLE, NULL)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, '1', NULL)	&&
				   testchar(tvb, pinfo, offset+2, MATCH, ETX, NULL)) {
				ack_start = offset;
				if (sid == GSID && did == GDID) {
					col_set_str(pinfo->cinfo, COL_INFO, "General Poll + ACK");
					set_addr(pinfo, DST, rid, sid, did);
				} else if (sid != GSID && did == GDID) {
					col_set_str(pinfo->cinfo, COL_INFO, "Specific Poll + ACK");
					set_addr(pinfo, DST, rid, sid, did);
				} else if (sid != GSID && did != GDID) {
					col_set_str(pinfo->cinfo, COL_INFO, "No Traffic + ACK");
					set_addr(pinfo, SRC, rid, sid, did);
				} else {
					col_set_str(pinfo->cinfo, COL_INFO, "Unknown Message Format");
					if ((pinfo->pseudo_header->sita.sita_flags & SITA_FRAME_DIR) == SITA_FRAME_DIR_TXED) {
						set_addr(pinfo, DST, rid, sid, did);	/* if the ACN sent it, the address is of the destination... the terminal */
					} else {
						set_addr(pinfo, SRC, rid, sid, did);	/* if the ACN received it, the address if of the source... the terminal */
					}
				}
			} else if (testchar(tvb, pinfo, offset, MATCH, DLE, NULL)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, NAK, NULL)	&&
				   testchar(tvb, pinfo, offset+2, MATCH, ETX, NULL)	&&
				   sid != GSID && did == GDID) {
				nak_start = offset;
				col_set_str(pinfo->cinfo, COL_INFO, "Retransmit Request");
				set_addr(pinfo, DST, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, MATCH, BEL, NULL)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, STX, NULL)	&&
				   testchar(tvb, pinfo, offset+2, MATCH, ETX, NULL)) {
				header_length = offset+2;
				msgwaiting_start = offset;
				col_set_str(pinfo->cinfo, COL_INFO, "Message Waiting");
				set_addr(pinfo, DST, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, MATCH, DLE, NULL)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, '1', NULL)	&&
				   testchar(tvb, pinfo, offset+2, MATCH, STX, NULL)) {
				ack_start = offset;
				header_length = offset+3;
				stx_start = offset+2;
				col_set_str(pinfo->cinfo, COL_INFO, "Text + ACK");
				set_addr(pinfo, SRC, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, MATCH, STX, NULL)) {
				header_length = offset+1;
				stx_start = offset;
				col_set_str(pinfo->cinfo, COL_INFO, "Text");
				if ((pinfo->pseudo_header->sita.sita_flags & SITA_FRAME_DIR) == SITA_FRAME_DIR_TXED) {
					set_addr(pinfo, DST, rid, sid, did);		/* if the ACN sent it, the address is of the destination... the terminal */
				} else {
					set_addr(pinfo, SRC, rid, sid, did);		/* if the ACN received it, the address if of the source... the terminal */
				}
			} else if (testchar(tvb, pinfo, offset, MATCH, DLE, NULL)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, ENQ, NULL)	&&
				   testchar(tvb, pinfo, offset+2, MATCH, ETX, NULL)) {
				replyrequest_start = offset;
				col_set_str(pinfo->cinfo, COL_INFO, "Reply Request");
				set_addr(pinfo, SRC, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, MATCH, DLE, NULL)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, '?', NULL)	&&
				   testchar(tvb, pinfo, offset+2, MATCH, ETX, NULL)) {
				busy_start = offset;
				col_set_str(pinfo->cinfo, COL_INFO, "Busy");
				set_addr(pinfo, SRC, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, MATCH, DLE, NULL)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, ';', NULL)	&&
				   testchar(tvb, pinfo, offset+2, MATCH, ETX, NULL)) {
				notbusy_start = offset;
				col_set_str(pinfo->cinfo, COL_INFO, "Not Busy");
				set_addr(pinfo, SRC, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, MATCH, DLE, NULL)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, '1', NULL)	&&
				   testchar(tvb, pinfo, offset+2, MATCH, DLE, NULL)	&&
				   testchar(tvb, pinfo, offset+3, MATCH, ';', NULL)	&&
				   testchar(tvb, pinfo, offset+4, MATCH, ETX, NULL)) {
				notbusy_start = offset+2;
				ack_start = offset;
				col_set_str(pinfo->cinfo, COL_INFO, "Not Busy + ACK");
				set_addr(pinfo, SRC, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, MATCH, DLE, NULL)		&&
				   testchar(tvb, pinfo, offset+1, MATCH, '1', NULL)		&&
				   testchar(tvb, pinfo, offset+2, FETCH, 0, &function_code)	&&
				   testchar(tvb, pinfo, offset+3, MATCH, ETX, NULL)) {
				ack_start = offset;
				function_start = offset + 2;
				col_add_fstr(pinfo->cinfo, COL_INFO, "Function Message '%c' + ACK", function_code);
				set_addr(pinfo, SRC, rid, sid, did);
			} else if (testchar(tvb, pinfo, offset, FETCH, 0, &function_code)	&&
				   testchar(tvb, pinfo, offset+1, MATCH, ETX, NULL)) {
				function_start = offset;
				col_add_fstr(pinfo->cinfo, COL_INFO, "Function Message '%c'", function_code);
				set_addr(pinfo, SRC, rid, sid, did);
			}
		}
	}

	while (tvb_reported_length_remaining(tvb, offset) > 0) {					/* now look for the ETX */
		if ((tvb_get_guint8(tvb, offset) & 0x7f) == ETX) {
			if (header_length == -1)
				header_length = offset;	/* the header ends at an STX, or if not found, the ETX */
			etx_start = offset;
			offset++;
			break;
		}
		offset++;
	}
	if (tvb_reported_length_remaining(tvb, offset))						/* if there is anything left, it could be the BCC and pads */
		bcc_start = offset;

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_uts, tvb, 0, -1, "UTS");
		uts_tree = proto_item_add_subtree(ti, ett_uts);

		if (msg_type == NOTRAFFIC) {
			proto_tree_add_protocol_format(uts_tree, proto_uts, tvb, 0, 2, "No Traffic");
			proto_tree_add_protocol_format(uts_tree, proto_uts, tvb, 2, -1, "ETX + padding");
		} else {
			uts_header_tree = proto_tree_add_subtree(uts_tree, tvb, 0, header_length, ett_header_uts, NULL, "Header");

			proto_tree_add_protocol_format(uts_header_tree, proto_uts, tvb, 0, 1, "SOH");

			if (rid == GRID)
				proto_tree_add_uint_format(uts_header_tree, hf_rid, tvb, 1, 1, rid, "RID (%02X) (General)", rid);
			else
				proto_tree_add_uint_format(uts_header_tree, hf_rid, tvb, 1, 1, rid, "RID (%02X)", rid);

			if (sid == GSID)
				proto_tree_add_uint_format(uts_header_tree, hf_sid, tvb, 2, 1, sid, "SID (%02X) (General)", sid);
			else
				proto_tree_add_uint_format(uts_header_tree, hf_sid, tvb, 2, 1, sid, "SID (%02X)", sid);

			if (did == GDID)
				proto_tree_add_uint_format(uts_header_tree, hf_did, tvb, 3, 1, did, "DID (%02X) (General)", did);
			else
				proto_tree_add_uint_format(uts_header_tree, hf_did, tvb, 3, 1, did, "DID (%02X)", did);

			if (nak_start)
				proto_tree_add_boolean_format(uts_header_tree, hf_retxrequest,	tvb, nak_start,	2, 1, "Re-transmit Request");
			if (ack_start)
				proto_tree_add_boolean_format(uts_header_tree, hf_ack, tvb, ack_start, 2, 1, "Ack");

			if (replyrequest_start)
				proto_tree_add_boolean_format(uts_header_tree, hf_replyrequest,	tvb, replyrequest_start, 2, 1, "Reply Request");
			if (busy_start)
				proto_tree_add_boolean_format(uts_header_tree, hf_busy,	tvb, busy_start, 2, 1, "Busy");

			if (notbusy_start)
				proto_tree_add_boolean_format(uts_header_tree, hf_notbusy, tvb, notbusy_start, 2, 1, "Not Busy");

			if (msgwaiting_start)
				proto_tree_add_boolean_format(uts_header_tree, hf_msgwaiting, tvb, msgwaiting_start, 1, 1, "Message Waiting");

			if (function_start)
				proto_tree_add_uint_format(uts_header_tree, hf_function, tvb, function_start, 1, function_code, "Function '%c'", function_code	);

			if (stx_start) {
				proto_tree_add_protocol_format(uts_header_tree, proto_uts, tvb, stx_start, 1, "Start of Text");
				length = tvb_captured_length_remaining(tvb, stx_start+1);    /* find out how much message remains      */
				if (etx_start)
					length = (etx_start - stx_start - 1);       /* and the data part is the rest...       */
										    /* whatever preceeds the ETX if it exists */
				data_ptr = tvb_get_string_enc(wmem_packet_scope(), tvb, stx_start+1, length, ENC_ASCII);	/* copy the string for dissecting */
				proto_tree_add_string_format(uts_tree, hf_data, tvb, stx_start + 1, length, data_ptr,
							     "Text (%d byte%s)", length, plurality(length, "", "s"));
			}

			if (etx_start) {
				uts_trailer_tree = proto_tree_add_subtree(uts_tree, tvb, etx_start, -1, ett_trailer_uts, NULL, "Trailer");

				if (etx_start)
					proto_tree_add_protocol_format(uts_trailer_tree, proto_uts, tvb, etx_start, 1, "ETX");
				if (bcc_start)
					proto_tree_add_protocol_format(uts_trailer_tree, proto_uts, tvb, bcc_start, -1, "CCC + padding");
			}
		}
	}
	return tvb_captured_length(tvb);
}

void
proto_register_uts(void)
{
	static hf_register_info hf[] = {
		{ &hf_rid,
		  { "RID",	   "uts.rid",
		    FT_UINT8,	BASE_HEX,	NULL, 0, "Remote Identifier address",	HFILL }},
		{ &hf_sid,
		  { "SID",	   "uts.sid",
		    FT_UINT8,	BASE_HEX,	NULL, 0, "Site Identifier address",	HFILL }},
		{ &hf_did,
		  { "DID",	   "uts.did",
		    FT_UINT8,	BASE_HEX,	NULL, 0, "Device Identifier address",	HFILL }},
		{ &hf_retxrequest,
		  { "ReTxRequst",  "uts.retxrequst",
		    FT_BOOLEAN,	BASE_NONE,	NULL, 0x0, "TRUE if Re-transmit Request", HFILL }},
		{ &hf_ack,
		  { "Ack",	   "uts.ack",
		    FT_BOOLEAN,	BASE_NONE,	NULL, 0x0, "TRUE if Ack",		HFILL }},
		{ &hf_replyrequest,
		  { "ReplyRequst", "uts.replyrequest",
		    FT_BOOLEAN,	BASE_NONE,	NULL, 0x0, "TRUE if Reply Request",	HFILL }},
		{ &hf_busy,
		  { "Busy",	   "uts.busy",
		    FT_BOOLEAN,	BASE_NONE,	NULL, 0x0, "TRUE if Busy",		HFILL }},
		{ &hf_notbusy,
		  { "NotBusy",	   "uts.notbusy",
		    FT_BOOLEAN,	BASE_NONE,	NULL, 0x0, "TRUE if Not Busy",		HFILL }},
		{ &hf_msgwaiting,
		  { "MsgWaiting",  "uts.msgwaiting",
		    FT_BOOLEAN,	BASE_NONE,	NULL, 0x0, "TRUE if Message Waiting",	HFILL }},
		{ &hf_function,
		  { "Function",    "uts.function",
		    FT_UINT8,	BASE_HEX,	NULL, 0, "Function Code value",		HFILL }},
		{ &hf_data,
		  { "Data",	   "uts.data",
		    FT_STRING,	BASE_NONE,	NULL, 0, "User Data Message",		HFILL }},
	};

	static gint *ett[] = {
		&ett_uts,
		&ett_header_uts,
		&ett_trailer_uts,
	};

	proto_uts = proto_register_protocol("Unisys Transmittal System", "UTS", "uts");		/* name, short name, abbrev */
	proto_register_field_array(proto_uts, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("uts", dissect_uts, proto_uts);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
