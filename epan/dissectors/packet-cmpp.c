/* packet-cmpp.c
 * Routines for China Mobile Point to Point dissection
 * Copyright 2007, Andy Chu <chu.dev@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>

#define CMPP_FIX_HEADER_LENGTH  12
#define CMPP_DELIVER_REPORT_LEN 71

/* These are not registered with IANA */
#define CMPP_SP_LONG_PORT    7890
#define CMPP_SP_SHORT_PORT   7900
#define CMPP_ISMG_LONG_PORT  7930
#define CMPP_ISMG_SHORT_PORT 9168

/* Initialize the protocol and registered fields */
static gint proto_cmpp = -1;

/* These are the fix header field */
static gint hf_cmpp_Total_Length = -1;
static gint hf_cmpp_Command_Id = -1;
static gint hf_cmpp_Sequence_Id = -1;

/* CMPP_CONNECT */
static gint hf_cmpp_connect_Source_Addr = -1;
static gint hf_cmpp_connect_AuthenticatorSource = -1;
static gint hf_cmpp_Version = -1;
static gint hf_cmpp_connect_Timestamp = -1;

/* CMPP_CONNECT_RESP */
static gint hf_cmpp_connect_resp_status = -1;
static gint hf_cmpp_connect_resp_AuthenticatorISMG = -1;

/* CMPP_SUBMIT */
static gint hf_cmpp_submit_pk_total = -1;
static gint hf_cmpp_submit_pk_number = -1;
static gint hf_cmpp_submit_Msg_level = -1;
static gint hf_cmpp_submit_Fee_UserType = -1;
static gint hf_cmpp_submit_Fee_terminal_Id = -1;
static gint hf_cmpp_submit_Fee_terminal_type = -1;
static gint hf_cmpp_submit_Msg_src = -1;
static gint hf_cmpp_submit_FeeType = -1;
static gint hf_cmpp_submit_FeeCode = -1;
static gint hf_cmpp_submit_Valld_Time = -1;
static gint hf_cmpp_submit_At_Time = -1;
static gint hf_cmpp_submit_Src_Id = -1;
static gint hf_cmpp_submit_DestUsr_tl = -1;
static gint hf_cmpp_submit_Dest_terminal_type = -1;
static gint hf_cmpp_submit_Registered_Delivery = -1;

/* Field common in CMPP_SUBMIT and CMPP_DELIVER */
static gint hf_cmpp_Dest_terminal_Id = -1;
static gint hf_cmpp_Service_Id = -1;
static gint hf_cmpp_TP_pId = -1;
static gint hf_cmpp_TP_udhi = -1;
static gint hf_cmpp_Msg_Fmt = -1;
static gint hf_cmpp_Msg_Length = -1;
static gint hf_cmpp_Msg_Content = -1;
static gint hf_cmpp_LinkID = -1;

/* CMPP_SUBMIT_RESP */
static gint hf_cmpp_submit_resp_Result = -1;

/* CMPP_QUERY */
/* CMPP_QUERY_RESP */
/* TODO implement CMPP_QUERY and CMPP_QUERY_RESP */

/* CMPP_DELIVER */
static gint hf_cmpp_deliver_Dest_Id = -1;
static gint hf_cmpp_deliver_Src_terminal_Id = -1;
static gint hf_cmpp_deliver_Src_terminal_type = -1;
static gint hf_cmpp_deliver_Registered_Delivery = -1;

static gint hf_cmpp_deliver_resp_Result = -1;

/* CMPP Deliver Report */
static gint hf_cmpp_deliver_Report = -1;
static gint hf_cmpp_deliver_Report_Stat = -1;
static gint hf_cmpp_deliver_Report_Submit_time = -1;
static gint hf_cmpp_deliver_Report_Done_time = -1;
static gint hf_cmpp_deliver_Report_SMSC_sequence = -1;

/* Msg_Id field */
static gint hf_cmpp_msg_id = -1;
static gint hf_msg_id_timestamp = -1;
static gint hf_msg_id_ismg_code = -1;
static gint hf_msg_id_sequence_id = -1;

static gboolean cmpp_desegment = TRUE;

/*
 * Value-arrays for field-contents
 */
#define CMPP_CONNECT			0x00000001
#define CMPP_CONNECT_RESP		0x80000001
#define CMPP_TERMINATE			0x00000002
#define CMPP_TERMINATE_RESP		0x80000002
#define CMPP_SUBMIT			0x00000004
#define CMPP_SUBMIT_RESP		0x80000004
#define CMPP_DELIVER			0x00000005
#define CMPP_DELIVER_RESP		0x80000005
#define CMPP_QUERY			0x00000006
#define CMPP_QUERY_RESP			0x80000006
#define CMPP_CANCEL			0x00000007
#define CMPP_CANCEL_RESP		0x80000007
#define CMPP_ACTIVE_TEST		0x00000008
#define CMPP_ACTIVE_TEST_RESP		0x80000008
#define CMPP_FWD			0x00000009
#define CMPP_FWD_RESP			0x80000009
#define CMPP_MT_ROUTE			0x00000010
#define CMPP_MO_ROUTE			0x00000011
#define CMPP_GET_MT_ROUTE		0x00000012
#define CMPP_MT_ROUTE_UPDATE		0x00000013
#define CMPP_MO_ROUTE_UPDATE		0x00000014
#define CMPP_PUSH_MT_ROUTE_UPDATE	0x00000015
#define CMPP_PUSH_MO_ROUTE_UPDATE	0x00000016
#define CMPP_GET_MO_ROUTE		0x00000017
#define CMPP_MT_ROUTE_RESP		0x80000010
#define CMPP_MO_ROUTE_RESP		0x80000011
#define CMPP_GET_MT_ROUTE_RESP		0x80000012
#define CMPP_MT_ROUTE_UPDATE_RESP	0x80000013
#define CMPP_MO_ROUTE_UPDATE_RESP	0x80000014
#define CMPP_PUSH_MT_ROUTE_UPDATE_RESP	0x80000015
#define CMPP_PUSH_MO_ROUTE_UPDATE_RESP	0x80000016
#define CMPP_GET_MO_ROUTE_RESP		0x80000017
static const value_string vals_command_Id[] = {		/* Operation	*/
	{ CMPP_CONNECT,                   "CMPP_CONNECT" },
	{ CMPP_CONNECT_RESP,              "CMPP_CONNECT_RESP" },
	{ CMPP_TERMINATE,                 "CMPP_TERMINATE" },
	{ CMPP_TERMINATE_RESP,            "CMPP_TERMINATE_RESP" },
	{ CMPP_SUBMIT,                    "CMPP_SUBMIT" },
	{ CMPP_SUBMIT_RESP,               "CMPP_SUBMIT_RESP" },
	{ CMPP_DELIVER,                   "CMPP_DELIVER" },
	{ CMPP_DELIVER_RESP,              "CMPP_DELIVER_RESP" },
	{ CMPP_QUERY,                     "CMPP_QUERY" },
	{ CMPP_QUERY_RESP,                "CMPP_QUERY" },
	{ CMPP_CANCEL,                    "CMPP_CANCEL" },
	{ CMPP_CANCEL_RESP,               "CMPP_CANCEL_RESP" },
	{ CMPP_ACTIVE_TEST,               "CMPP_ACTIVE_TEST" },
	{ CMPP_ACTIVE_TEST_RESP,          "CMPP_ACTIVE_TEST_RESP" },
	{ CMPP_FWD,                       "CMPP_FWD" },
	{ CMPP_FWD_RESP,                  "CMPP_FWD_RESP" },
	{ CMPP_MT_ROUTE,                  "CMPP_MT_ROUTE" },
	{ CMPP_MO_ROUTE,                  "CMPP_MO_ROUTE" },
	{ CMPP_GET_MT_ROUTE,              "CMPP_GET_MT_ROUTE" },
	{ CMPP_MT_ROUTE_UPDATE,           "CMPP_MT_ROUTE_UPDATE" },
	{ CMPP_MO_ROUTE_UPDATE,           "CMPP_MO_ROUTE_UPDATE" },
	{ CMPP_PUSH_MT_ROUTE_UPDATE,      "CMPP_PUSH_MT_ROUTE_UPDATE" },
	{ CMPP_PUSH_MO_ROUTE_UPDATE,      "CMPP_PUSH_MO_ROUTE_UPDATE" },
	{ CMPP_GET_MO_ROUTE,              "CMPP_GET_MO_ROUTE" },
	{ CMPP_MT_ROUTE_RESP,             "CMPP_MT_ROUTE_RESP" },
	{ CMPP_MO_ROUTE_RESP,             "CMPP_MO_ROUTE_RESP" },
	{ CMPP_GET_MT_ROUTE_RESP,         "CMPP_GET_MT_ROUTE_RESP" },
	{ CMPP_MT_ROUTE_UPDATE_RESP,      "CMPP_MT_ROUTE_UPDATE_RESP" },
	{ CMPP_MO_ROUTE_UPDATE_RESP,      "CMPP_MO_ROUTE_UPDATE_RESP" },
	{ CMPP_PUSH_MT_ROUTE_UPDATE_RESP, "CMPP_PUSH_MT_ROUTE_UPDATE_RESP" },
	{ CMPP_PUSH_MO_ROUTE_UPDATE_RESP, "CMPP_PUSH_MO_ROUTE_UPDATE_RESP" },
	{ CMPP_GET_MO_ROUTE_RESP,         "CMPP_GET_MO_ROUTE_RESP" },
	{ 0, NULL }
};

static const value_string vals_connect_resp_status[] = {	/* Connection Status */
	{ 0, "Correct" },
	{ 1, "Message structure error" },
	{ 2, "Illegal source address" },
	{ 3, "Authenticate error" },
	{ 4, "Version too high" },
	{ 0, NULL }
};

static const value_string vals_submit_Fee_UserType[] = { /* Submit Fee_UserType */
	{ 0, "Charging destination MSISDN" },
	{ 1, "Charging source MSISDN" },
	{ 2, "Charging SP" },
	{ 3, "Unuse, Charge info from Fee_terminal_Id" },
	{ 0, NULL }
};

static const value_string vals_Msg_Fmt[] = { /* Message Format */
	{ 0, "ASCII" },
	{ 3, "Short message card" }, /* TODO find the correct string of this value */
	{ 4, "Binary data" },
	{ 8, "UCS2 encoding" },
	{15, "GB encoding" },
	{ 0, NULL }
};

/* Submit Response Result */
static const value_string vals_Submit_Resp_Result[] = {
	{ 0, "Correct" },
	{ 1, "Message format error" },
	{ 2, "Command error" },
	{ 3, "Repeat sequence id" },
	{ 4, "Incorrect message length" },
	{ 5, "Incorrect fee code" },
	{ 6, "Message too long" },
	{ 7, "Incorrect service id" },
	{ 8, "Bandwidth error" },
	{ 9, "Gateway does not service this charging number" },
	{10, "Incorrect Src_Id" },
	{11, "Incorrect Msg_src" },
	{12, "Incorrect Fee_terminal_Id" },
	{13, "Incorrect Dest_terminal_Id" },
	{ 0, NULL }
};

/* Deliver Response Result */
static const value_string vals_Deliver_Resp_Result[] = {
	{ 0, "Correct" },
	{ 1, "Message format error" },
	{ 2, "Command error" },
	{ 3, "Repeat sequence id" },
	{ 4, "Incorrect message length" },
	{ 5, "Incorrect fee code" },
	{ 6, "Message too long" },
	{ 7, "Incorrect service id" },
	{ 8, "Bandwidth error" },
	{ 0, NULL }
};

/* Initialize the subtree pointers */
static gint ett_cmpp = -1;
static gint ett_msg_id = -1;
static gint ett_deliver_report = -1;

/* Helper functions */

static char*
cmpp_octet_string(proto_tree *tree, tvbuff_t *tvb, gint field, gint offset, gint length)
{
	char *display;

	display = (char *)tvb_get_ephemeral_string(tvb, offset, length);
	proto_tree_add_string(tree, field, tvb, offset, length, display);
	return display;
}

static char*
cmpp_version(proto_tree *tree, tvbuff_t *tvb, gint  field, gint offset)
{
	gint8  version, major, minor;
	char  *strval;

	version = tvb_get_guint8(tvb, offset);
	minor   = version & 0x0F;
	major   = (version & 0xF0) >> 4;
	strval  = ep_strdup_printf("%02u.%02u", major, minor);
	/* TODO: the version should be added as a uint_format */
	proto_tree_add_string(tree, field, tvb, offset, 1, strval);
	return strval;
}

static char*
cmpp_timestamp(proto_tree *tree, tvbuff_t *tvb, gint  field, gint offset)
{
	gint8   month, day, hour, minute, second;
	gint32  timevalue;
	char   *strval;

	timevalue = tvb_get_ntohl(tvb, offset);
	second = timevalue % 100;
	timevalue /= 100;
	minute = timevalue % 100;
	timevalue /= 100;
	hour = timevalue % 100;
	timevalue /= 100;
	day = timevalue % 100;
	month = timevalue / 100;
	strval = ep_strdup_printf("%02u/%02u %02u:%02u:%02u", month, day,
		hour, minute, second);
	proto_tree_add_string(tree, field, tvb, offset, 4, strval);
	return strval;
}

/*  TODO: most calls to these (except those that use the return value) should
 *  be replaced by calls to proto_tree_add_item().
 */
static guint8
cmpp_uint1(proto_tree *tree, tvbuff_t *tvb, gint  field, gint offset)
{
	guint8 value;
	value = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, field, tvb, offset, 1, value);
	return value;
}

static guint16
cmpp_uint2(proto_tree *tree, tvbuff_t *tvb, gint  field, gint offset)
{
	guint16 value;
	value = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(tree, field, tvb, offset, 2, value);
	return value;
}

static gint32
cmpp_uint4(proto_tree *tree, tvbuff_t *tvb, gint  field, gint offset)
{
	gint32 value;
	value = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, field, tvb, offset, 4, value);
	return value;
}

static gboolean
cmpp_boolean(proto_tree *tree, tvbuff_t *tvb, gint  field, gint offset)
{
	gint8 value;
	value = tvb_get_guint8(tvb, offset);
	proto_tree_add_boolean(tree, field, tvb, offset, 1, value);
	if (value ==  1)
		return TRUE;
	return FALSE;
}

static void
cmpp_msg_id(proto_tree *tree, tvbuff_t *tvb, gint  field, gint offset)
{
	guint8      month,day,hour,minute,second;
	guint32     ismg_code;
	proto_item *pi;
	proto_tree *sub_tree;
	char       *strval;

	pi = proto_tree_add_item(tree, field, tvb, offset, 8, ENC_BIG_ENDIAN);
	sub_tree = proto_item_add_subtree(pi, ett_msg_id);

	month = (tvb_get_guint8(tvb, offset) & 0xF0) >> 4;
	day = (tvb_get_ntohs(tvb, offset) & 0x0F80) >> 7;
	hour = (tvb_get_guint8(tvb, offset + 1) & 0x7C) >> 2;
	minute = (tvb_get_ntohs(tvb, offset + 1) & 0x03F0) >> 4;
	second = (tvb_get_ntohs(tvb, offset + 2) & 0x0FC0) >> 6;
	strval = ep_strdup_printf("%02u/%02u %02u:%02u:%02u", month, day,
		hour, minute, second);

	ismg_code = (tvb_get_ntohl(tvb, offset + 3) & 0x3FFFFF00) >> 16;

	proto_tree_add_string(sub_tree, hf_msg_id_timestamp, tvb, offset, 4, strval);
	proto_tree_add_uint(sub_tree, hf_msg_id_ismg_code, tvb, offset + 3, 3, ismg_code);
	cmpp_uint2(sub_tree, tvb, hf_msg_id_sequence_id, offset + 6);
}

static void
cmpp_connect(proto_tree *tree, tvbuff_t *tvb)
{
	int offset;
	offset = CMPP_FIX_HEADER_LENGTH;
	cmpp_octet_string(tree, tvb, hf_cmpp_connect_Source_Addr, offset, 6);
	offset += 6;
	proto_tree_add_string(tree, hf_cmpp_connect_AuthenticatorSource, tvb, offset, 16, "MD5 Hash");
	offset += 16;
	cmpp_version(tree, tvb, hf_cmpp_Version, offset);
	offset += 1;
	cmpp_timestamp(tree, tvb, hf_cmpp_connect_Timestamp, offset);
}


static void
cmpp_connect_resp(proto_tree *tree, tvbuff_t *tvb)
{
	int offset;
	offset = CMPP_FIX_HEADER_LENGTH;
	cmpp_uint4(tree, tvb, hf_cmpp_connect_resp_status, offset);
	offset += 4;
	proto_tree_add_string(tree, hf_cmpp_connect_resp_AuthenticatorISMG, tvb, offset, 16, "MD5 Hash");
	offset += 16;
	cmpp_version(tree, tvb, hf_cmpp_Version, offset);
}

static void
cmpp_submit(proto_tree *tree, tvbuff_t *tvb)
{
	int    offset, i;
	guint8 destUsr, msgLen;
	offset = CMPP_FIX_HEADER_LENGTH;
	cmpp_msg_id(tree, tvb, hf_cmpp_msg_id, offset);
	offset += 8;
	cmpp_uint1(tree, tvb, hf_cmpp_submit_pk_total, offset);
	offset++;
	cmpp_uint1(tree, tvb, hf_cmpp_submit_pk_number, offset);
	offset++;
	cmpp_boolean(tree, tvb, hf_cmpp_submit_Registered_Delivery, offset);
	offset++;
	cmpp_uint1(tree, tvb, hf_cmpp_submit_Msg_level, offset);
	offset++;
	cmpp_octet_string(tree, tvb, hf_cmpp_Service_Id, offset, 10);
	offset += 10;
	cmpp_uint1(tree, tvb, hf_cmpp_submit_Fee_UserType, offset);
	offset++;
	cmpp_octet_string(tree, tvb, hf_cmpp_submit_Fee_terminal_Id, offset, 32);
	offset+=32;
	cmpp_boolean(tree, tvb, hf_cmpp_submit_Fee_terminal_type, offset);
	offset++;
	cmpp_uint1(tree, tvb, hf_cmpp_TP_pId, offset);
	offset++;
	cmpp_uint1(tree, tvb, hf_cmpp_TP_udhi, offset);
	offset++;
	cmpp_uint1(tree, tvb, hf_cmpp_Msg_Fmt, offset);
	offset++;
	cmpp_octet_string(tree, tvb, hf_cmpp_submit_Msg_src, offset, 6);
	offset += 6;
	cmpp_octet_string(tree, tvb, hf_cmpp_submit_FeeType, offset, 2);
	offset += 2;
	cmpp_octet_string(tree, tvb, hf_cmpp_submit_FeeCode, offset, 6);
	offset += 6;

	/* TODO create function to handle SMPP time format */
	cmpp_octet_string(tree, tvb, hf_cmpp_submit_Valld_Time, offset, 17);
	offset += 17;
	cmpp_octet_string(tree, tvb, hf_cmpp_submit_At_Time, offset, 17);
	offset += 17;

	cmpp_octet_string(tree, tvb, hf_cmpp_submit_Src_Id, offset, 17);
	offset += 21;
	destUsr = cmpp_uint1(tree, tvb, hf_cmpp_submit_DestUsr_tl, offset);
	offset++;

	/* Loop through each destination address */
	for(i = 0; i < destUsr; i++)
	{
		cmpp_octet_string(tree, tvb, hf_cmpp_Dest_terminal_Id, offset, 32);
		offset += 32;
	}

	cmpp_boolean(tree, tvb, hf_cmpp_submit_Dest_terminal_type, offset);
	offset++;
	msgLen = cmpp_uint1(tree, tvb, hf_cmpp_Msg_Length, offset);
	offset++;
	proto_tree_add_string(tree, hf_cmpp_Msg_Content, tvb, offset, msgLen, "SMS Messages");
	offset += msgLen;
	cmpp_octet_string(tree, tvb, hf_cmpp_LinkID, offset, 20);
}

static void
cmpp_submit_resp(proto_tree *tree, tvbuff_t *tvb)
{
	int offset;
	offset = CMPP_FIX_HEADER_LENGTH;
	cmpp_msg_id(tree, tvb, hf_cmpp_msg_id, offset);
	offset += 8;
	cmpp_uint4(tree, tvb, hf_cmpp_submit_resp_Result, offset);
}

static void
cmpp_deliver_report(proto_tree *tree, tvbuff_t *tvb, gint  field, guint offset)
{
	proto_item *pi;
	proto_tree *sub_tree;

	pi = proto_tree_add_item(tree, field, tvb, offset, CMPP_DELIVER_REPORT_LEN, ENC_BIG_ENDIAN);
	sub_tree = proto_item_add_subtree(pi, ett_deliver_report);
	cmpp_msg_id(sub_tree, tvb, hf_cmpp_msg_id, offset);
	offset += 8;
	cmpp_octet_string(sub_tree, tvb, hf_cmpp_deliver_Report_Stat, offset, 7);
	offset += 7;
	cmpp_octet_string(sub_tree, tvb, hf_cmpp_deliver_Report_Submit_time, offset, 10);
	offset += 10;
	cmpp_octet_string(sub_tree, tvb, hf_cmpp_deliver_Report_Done_time, offset, 10);
	offset += 10;
	cmpp_octet_string(sub_tree, tvb, hf_cmpp_Dest_terminal_Id, offset, 32);
	offset += 32;
	cmpp_uint4(sub_tree, tvb, hf_cmpp_deliver_Report_SMSC_sequence, offset);
}

static void
cmpp_deliver(proto_tree *tree, tvbuff_t *tvb)
{
	guint    offset, msgLen;
	gboolean report;
	offset = CMPP_FIX_HEADER_LENGTH;
	cmpp_msg_id(tree, tvb, hf_cmpp_msg_id, offset);
	offset += 8;
	cmpp_octet_string(tree, tvb, hf_cmpp_deliver_Dest_Id, offset, 21);
	offset += 21;
	cmpp_octet_string(tree, tvb, hf_cmpp_Service_Id, offset, 10);
	offset += 10;
	cmpp_uint1(tree, tvb, hf_cmpp_TP_pId, offset);
	offset++;
	cmpp_uint1(tree, tvb, hf_cmpp_TP_udhi, offset);
	offset++;
	cmpp_uint1(tree, tvb, hf_cmpp_Msg_Fmt, offset);
	offset++;
	cmpp_octet_string(tree, tvb, hf_cmpp_deliver_Src_terminal_Id, offset, 32);
	offset += 32;
	cmpp_boolean(tree, tvb, hf_cmpp_deliver_Src_terminal_type, offset);
	offset++;
	report = cmpp_boolean(tree, tvb, hf_cmpp_deliver_Registered_Delivery, offset);
	offset++;
	msgLen = cmpp_uint1(tree, tvb, hf_cmpp_Msg_Length, offset);
	offset++;
	if (report == FALSE)
		proto_tree_add_string(tree, hf_cmpp_Msg_Content, tvb, offset, msgLen, "SMS Messages");
	else
		cmpp_deliver_report(tree, tvb, hf_cmpp_deliver_Report, offset);
	offset += msgLen;
	cmpp_octet_string(tree, tvb, hf_cmpp_LinkID, offset, 20);
}

static void
cmpp_deliver_resp(proto_tree *tree, tvbuff_t *tvb)
{
	int offset;
	offset = CMPP_FIX_HEADER_LENGTH;
	cmpp_msg_id(tree, tvb, hf_cmpp_msg_id, offset);
	offset += 8;
	/* TODO implement the result field here */
	cmpp_uint4(tree, tvb, hf_cmpp_deliver_resp_Result, offset);
}

/* Code to actually dissect the packets */
static void
dissect_cmpp_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item  *ti;
	proto_tree  *cmpp_tree;
	guint        command_id;
	guint        tvb_len;
	guint        total_length;
	const gchar *command_str; /* Header command string */

	/* Get the length of the PDU */
	tvb_len = tvb_length(tvb);
	/* if the length of the tvb is shorder then the cmpp header length exit */
	if (tvb_len < CMPP_FIX_HEADER_LENGTH)
		return;

	total_length = tvb_get_ntohl(tvb, 0); /* Get the pdu length */
	command_id = tvb_get_ntohl(tvb, 4); /* get the pdu command id */

	if (match_strval(command_id, vals_command_Id) == NULL)
	{
		/* Should never happen: we checked this in dissect_cmpp() */
		return;
	}

	command_str = val_to_str(command_id, vals_command_Id,
				 "(Unknown CMPP Operation 0x%08X)");

	/* tvb has less data then the PDU Header status, return */
	if (tvb_len < total_length)
	{
		/* Should never happen: TCP should have desegmented for us */
		return;
	}

	/* Make entries in Protocol column and Info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMPP");

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s. ", command_str);

	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_cmpp, tvb, 0, -1, ENC_NA);

		cmpp_tree = proto_item_add_subtree(ti, ett_cmpp);

		/* Add the fix header informations to the tree */
		cmpp_uint4(cmpp_tree, tvb, hf_cmpp_Total_Length, 0);
		cmpp_uint4(cmpp_tree, tvb, hf_cmpp_Command_Id, 4);
		cmpp_uint4(cmpp_tree, tvb, hf_cmpp_Sequence_Id, 8);

		switch(command_id)
		{
			case CMPP_CONNECT:
				cmpp_connect(cmpp_tree, tvb);
				break;
			case CMPP_CONNECT_RESP:
				cmpp_connect_resp(cmpp_tree, tvb);
				break;
			/* CMPP_TERMINATE and CMPP_TERMINATE_RESP don't have msg body */
			case CMPP_TERMINATE:
			case CMPP_TERMINATE_RESP:
				break;
			case CMPP_SUBMIT:
				cmpp_submit(cmpp_tree, tvb);
				break;
			case CMPP_SUBMIT_RESP:
				cmpp_submit_resp(cmpp_tree, tvb);
				break;
			case CMPP_DELIVER:
				cmpp_deliver(cmpp_tree, tvb);
				break;
			case CMPP_DELIVER_RESP:
				cmpp_deliver_resp(cmpp_tree, tvb);
				break;
			default:
				/* Implement the rest of the protocol here */
				break;
		}
	}
}


/* Get the CMPP PDU Length */
static guint
get_cmpp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, gint offset)
{
	return tvb_get_ntohl(tvb, offset);
}


static int
dissect_cmpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint total_length, command_id, tvb_len;
	/* Check that there's enough data */
	tvb_len = tvb_length(tvb);
	if (tvb_len < CMPP_FIX_HEADER_LENGTH)
		return 0;

	/* Get some values from the packet header, probably using tvb_get_*() */
	total_length = tvb_get_ntohl(tvb, 0); /* Get the pdu length */
	command_id = tvb_get_ntohl(tvb, 4); /* get the pdu command id */

	/*  Looking at this protocol, it seems unlikely that the messages would
	 *  get as big as a couple hundred bytes but that's not certain; just
	 *  added a hopefully-way-too-big number to strengthen the heuristics.
	 */
	if (total_length < CMPP_FIX_HEADER_LENGTH || total_length > 1000)
		return 0;

	if (match_strval(command_id, vals_command_Id) == NULL)
		return 0;

	col_clear(pinfo->cinfo, COL_INFO);

	tcp_dissect_pdus(tvb, pinfo, tree, cmpp_desegment, CMPP_FIX_HEADER_LENGTH,
			 get_cmpp_pdu_len, dissect_cmpp_tcp_pdu);

	/* Return the amount of data this dissector was able to dissect */
	return tvb_length(tvb);

}

/* Register the protocol with Wireshark */

void
proto_register_cmpp(void) {

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_cmpp_Total_Length,
		  { "Total Length", "cmpp.Total_Length",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Total length of the CMPP PDU.",
		    HFILL }
		},
		{ &hf_cmpp_Command_Id,
		  { "Command Id", "cmpp.Command_Id",
		    FT_UINT32, BASE_HEX, VALS(vals_command_Id), 0x00,
		    "Command Id of the CMPP messages",
		    HFILL }
		},
		{ &hf_cmpp_Sequence_Id,
		  { "Sequence Id", "cmpp.Sequence_Id",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Sequence Id of the CMPP messages",
		    HFILL }
		},
		{ &hf_cmpp_connect_Source_Addr,
		  { "Source Addr", "cmpp.connect.Source_Addr",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Source Address, the SP_Id",
		    HFILL }
		},
		{ &hf_cmpp_connect_AuthenticatorSource,
		  { "Authenticator Source", "cmpp.connect.AuthenticatorSource",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Authenticator source, MD5(Source_addr + 9 zero + shared secret + timestamp)",
		    HFILL }
		},

		{ &hf_cmpp_Version,
		  { "Version", "cmpp.Version",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "CMPP Version",
		    HFILL }
		},
		{ &hf_cmpp_connect_Timestamp,
		  { "Timestamp", "cmpp.connect.Timestamp",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Timestamp MM/DD HH:MM:SS",
		    HFILL }
		},
		{ &hf_cmpp_connect_resp_status,
		  { "Connect Response Status", "cmpp.connect_resp.Status",
		    FT_UINT32, BASE_DEC, VALS(vals_connect_resp_status), 0x00,
		    "Response Status, Value higher then 4 means other error",
		    HFILL }
		},
		{ &hf_cmpp_connect_resp_AuthenticatorISMG,
		  { "SIMG Authenticate result", "cmpp.connect_resp.AuthenticatorISMG",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Authenticator result, MD5(Status + AuthenticatorSource + shared secret)",
		    HFILL }
		},
		{ &hf_cmpp_msg_id,
		  { "Msg_Id", "cmpp.Msg_Id",
		    FT_UINT64, BASE_HEX, NULL, 0x00,
		    "Message ID",
		    HFILL }
		},
		{ &hf_cmpp_submit_pk_total,
		  { "Number of Part", "cmpp.submit.Pk_total",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Total number of parts of the message with the same Msg_Id, start from 1",
		    HFILL }
		},
		{ &hf_cmpp_submit_pk_number,
		  { "Part Number", "cmpp.submit.Pk_number",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Part number of the message with the same Msg_Id, start from 1",
		    HFILL }
		},
		{ &hf_msg_id_timestamp,
		  { "Timestamp", "cmpp.Msg_Id.timestamp",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Timestamp MM/DD HH:MM:SS Bit 64 ~ 39",
		    HFILL }
		},
		{ &hf_msg_id_ismg_code,
		  { "ISMG Code", "cmpp.Msg_Id.ismg_code",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "ISMG Code, bit 38 ~ 17",
		    HFILL }
		},
		{ &hf_msg_id_sequence_id,
		  { "Msg_Id sequence Id", "cmpp.Msg_Id.sequence_id",
		    FT_UINT16, BASE_DEC, NULL, 0x00,
		    "Msg_Id sequence Id, bit 16 ~ 1",
		    HFILL }
		},
		{ &hf_cmpp_submit_Registered_Delivery,
		  { "Registered Delivery", "cmpp.submit.Registered_Delivery",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Registered Delivery flag",
		    HFILL }
		},
		{ &hf_cmpp_submit_Msg_level,
		  { "Message Level", "cmpp.submit.Msg_level",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL,
		    HFILL }
		},
		{ &hf_cmpp_Service_Id,
		  { "Service ID", "cmpp.Servicd_Id",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Service ID, a mix of characters, numbers and symbol",
		    HFILL }
		},
		{ &hf_cmpp_submit_Fee_UserType,
		  { "Charging Informations", "cmpp.submit.Fee_UserType",
		    FT_UINT8, BASE_DEC, VALS(vals_submit_Fee_UserType), 0x00,
		    "Charging Informations, if value is 3, this field will not be used",
		    HFILL }
		},
		{ &hf_cmpp_submit_Fee_terminal_Id,
		  { "Fee Terminal ID", "cmpp.submit.Fee_terminal_Id",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Fee Terminal ID, Valid only when Fee_UserType is 3",
		    HFILL }
		},
		{ &hf_cmpp_submit_Fee_terminal_type,
		  { "Fake Fee Terminal", "cmpp.submit.Fee_terminal_type",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Fee terminal type, 0 is real, 1 is fake",
		    HFILL }
		},
		{ &hf_cmpp_TP_pId,
		  { "TP pId", "cmpp.TP_pId",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "GSM TP pId Field",
		    HFILL }
		},
		{ &hf_cmpp_TP_udhi,
		  { "TP udhi", "cmpp.TP_udhi",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "GSM TP udhi field",
		    HFILL }
		},
		{ &hf_cmpp_Msg_Fmt,
		  { "Message Format", "cmpp.Msg_Fmt",
		    FT_UINT8, BASE_DEC, VALS(vals_Msg_Fmt), 0x00,
		    NULL,
		    HFILL }
		},
		{ &hf_cmpp_submit_Msg_src,
		  { "Message Source SP_Id", "cmpp.submit.Msg_src",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Message source SP ID",
		    HFILL }
		},
		{ &hf_cmpp_submit_FeeType, /* TODO Replace this with a vals_string*/
		  { "Fee Type", "cmpp.submit.FeeType",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    NULL,
		    HFILL }
		},
		{ &hf_cmpp_submit_FeeCode,
		  { "Fee Code", "cmpp.submit.FeeCode",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    NULL,
		    HFILL }
		},
		{ &hf_cmpp_submit_Valld_Time,
		  { "Valid time", "cmpp.submit.Valld_Time",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Message Valid Time, format follow SMPP 3.3",
		    HFILL }
		},
		{ &hf_cmpp_submit_At_Time,
		  { "Send time", "cmpp.submit.At_time",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Message send time, format following SMPP 3.3",
		    HFILL }
		},
		{ &hf_cmpp_submit_Src_Id,
		  { "Source ID", "cmpp.submit.Src_Id",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "This value matches SMPP submit_sm source_addr field",
		    HFILL }
		},
		{ &hf_cmpp_submit_DestUsr_tl,
		  { "Destination Address Count", "cmpp.submit.DestUsr_tl",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "Number of destination address, must smaller then 100",
		    HFILL }
		},
		{ &hf_cmpp_Dest_terminal_Id,
		  { "Destination Address", "cmpp.Dest_terminal_Id",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "MSISDN number which receive the SMS",
		    HFILL }
		},
		{ &hf_cmpp_submit_Dest_terminal_type,
		  { "Fake Destination Terminal", "cmpp.submit.Dest_terminal_type",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "destination terminal type, 0 is real, 1 is fake",
		    HFILL }
		},
		{ &hf_cmpp_Msg_Length,
		  { "Message length", "cmpp.Msg_Length",
		    FT_UINT8, BASE_DEC, NULL, 0x00,
		    "SMS Message length, ASCII must be <= 160 bytes, other must be <= 140 bytes",
		    HFILL }
		},
		{ &hf_cmpp_Msg_Content,
		  { "Message Content", "cmpp.Msg_Content",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    NULL,
		    HFILL }
		},
		{ &hf_cmpp_LinkID,
		  { "Link ID", "cmpp.LinkID",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    NULL,
		    HFILL }
		},
		{ &hf_cmpp_submit_resp_Result,
		  { "Result", "cmpp.submit_resp.Result",
		    FT_UINT32, BASE_DEC, VALS(vals_Submit_Resp_Result), 0x00,
		    "Submit Result",
		    HFILL }
		},
		{ &hf_cmpp_deliver_Dest_Id,
		  { "Destination ID", "cmpp.deliver.Dest_Id",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "SP Service ID or server number",
		    HFILL }
		},
		{ &hf_cmpp_deliver_Src_terminal_Id,
		  { "Src_terminal_Id", "cmpp.deliver.Src_terminal_Id",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Source MSISDN number, if it is deliver report, this will be the CMPP_SUBMIT destination number",
		    HFILL }
		},
		{ &hf_cmpp_deliver_Src_terminal_type,
		  { "Fake source terminal type", "cmpp.deliver.Src_terminal_type",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Type of the source terminal, can be 0 (real) or 1 (fake)",
		    HFILL }
		},
		{ &hf_cmpp_deliver_Registered_Delivery,
		  { "Deliver Report", "cmpp.deliver.Registered_Delivery",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "The message is a deliver report if this value = 1",
		    HFILL }
		},
		{ &hf_cmpp_deliver_Report,
		  { "Detail Deliver Report", "cmpp.deliver.Report",
		    FT_NONE, BASE_NONE, NULL, 0x00,
		    "The detail report",
		    HFILL }
		},
		{ &hf_cmpp_deliver_Report_Stat,
		  { "Deliver Status", "cmpp.deliver.Report.Status",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    NULL,
		    HFILL }
		},
		{ &hf_cmpp_deliver_Report_Submit_time,
		  { "Submit_time", "cmpp.deliver.Report.Submit_time",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Format YYMMDDHHMM",
		    HFILL }
		},
		{ &hf_cmpp_deliver_Report_Done_time,
		  { "Done_time", "cmpp.deliver.Report.Done_time",
		    FT_STRING, BASE_NONE, NULL, 0x00,
		    "Format YYMMDDHHMM",
		    HFILL }
		},
		{ &hf_cmpp_deliver_Report_SMSC_sequence,
		  { "SMSC_sequence", "cmpp.Report.SMSC_sequence",
		    FT_UINT32, BASE_DEC, NULL, 0x00,
		    "Sequence number",
		    HFILL }
		},
		{ &hf_cmpp_deliver_resp_Result,
		  { "Result", "cmpp.deliver_resp.Result",
		    FT_UINT32, BASE_DEC, VALS(vals_Deliver_Resp_Result), 0x00,
		    "Deliver Result",
		    HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_cmpp,
		&ett_msg_id,
		&ett_deliver_report,
	};

	/* Register the protocol name and description */
	proto_cmpp = proto_register_protocol("China Mobile Point to Point Protocol",
					     "CMPP", "cmpp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_cmpp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_cmpp(void)
{
	dissector_handle_t cmpp_handle;

	cmpp_handle = new_create_dissector_handle(dissect_cmpp, proto_cmpp);
	dissector_add_uint("tcp.port", CMPP_SP_LONG_PORT, cmpp_handle);
	dissector_add_uint("tcp.port", CMPP_SP_SHORT_PORT, cmpp_handle);
	dissector_add_uint("tcp.port", CMPP_ISMG_LONG_PORT, cmpp_handle);
	dissector_add_uint("tcp.port", CMPP_ISMG_SHORT_PORT, cmpp_handle);
}
