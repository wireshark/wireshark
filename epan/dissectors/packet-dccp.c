/* packet-dccp.c
 * Routines for Distributed Checksum Clearinghouse packet dissection
 * DCC Home: http://www.rhyolite.com/anti-spam/dcc/
 *
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-tftp.c
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

#include <stdio.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

#include <packet-dccp.h>

static int proto_dccp = -1;
static int hf_dccp_len = -1;
static int hf_dccp_pkt_vers = -1;
static int hf_dccp_op = -1;
static int hf_dccp_clientid = -1;
static int hf_dccp_opnums_host = -1;
static int hf_dccp_opnums_pid = -1;
static int hf_dccp_opnums_report = -1;
static int hf_dccp_opnums_retrans = -1;

static int hf_dccp_signature = -1;
static int hf_dccp_max_pkt_vers = -1;
static int hf_dccp_qdelay_ms = -1;
static int hf_dccp_brand = -1;

static int hf_dccp_ck_type = -1;
static int hf_dccp_ck_len = -1;
static int hf_dccp_ck_sum = -1;

static int hf_dccp_date = -1;

static int hf_dccp_target = -1;

static int hf_dccp_adminop = -1;
static int hf_dccp_adminval = -1;
static int hf_dccp_floodop = -1;
static int hf_dccp_trace = -1;
static int hf_dccp_trace_admin = -1;
static int hf_dccp_trace_anon = -1;
static int hf_dccp_trace_client = -1;
static int hf_dccp_trace_rlim = -1;
static int hf_dccp_trace_query = -1;
static int hf_dccp_trace_ridc = -1;
static int hf_dccp_trace_flood = -1;

static gint ett_dccp = -1;
static gint ett_dccp_opnums = -1;
static gint ett_dccp_op = -1;
static gint ett_dccp_ck = -1;
static gint ett_dccp_trace = -1;

/* Utility macros */
#define D_SIGNATURE() \
	proto_tree_add_item(dccp_optree, hf_dccp_signature, tvb, \
		offset, sizeof(DCC_SIGNATURE), FALSE); \
	offset += sizeof(DCC_SIGNATURE);

#define D_LABEL(label,len) \
	proto_tree_add_text(dccp_optree, tvb, offset, len, label); \
	offset += len;

#define D_TEXT(label, endpad) { \
	int next_offset,linelen,left; \
	const char *line; \
	while (tvb_offset_exists(tvb, offset+endpad)) { \
		left = tvb_length_remaining(tvb,offset) - endpad; \
		linelen = tvb_find_line_end(tvb, offset, left, &next_offset, \
		    FALSE); \
		line = tvb_get_ptr(tvb, offset, linelen); \
		proto_tree_add_text(dccp_optree, tvb, offset, \
			next_offset - offset, "%s: %s", \
			label, tvb_format_text(tvb, offset, next_offset - offset)); \
		offset = next_offset; \
	} \
}


#define D_TARGET() \
	proto_tree_add_item_hidden(dccp_tree, hf_dccp_target, tvb, \
		offset, sizeof(DCC_TGTS), FALSE); \
	proto_tree_add_text(dccp_optree, tvb, offset, sizeof(DCC_TGTS), \
		val_to_str(tvb_get_ntohl(tvb,offset), dccp_target_vals, "Targets (%u)")); \
	offset += sizeof(DCC_TGTS); \

#define D_DATE() { \
	nstime_t ts; \
	ts.nsecs = 0; \
	ts.secs = tvb_get_ntohl(tvb,offset); \
	proto_tree_add_time(dccp_optree, hf_dccp_date, tvb, offset, 4, &ts); \
	offset += 4; \
}


#define D_CHECKSUM() { \
	proto_tree *cktree, *ti; \
	ti = proto_tree_add_text(dccp_optree, tvb, offset, sizeof(DCC_CK), \
		"Checksum - %s", val_to_str(tvb_get_guint8(tvb,offset), \
		dccp_cktype_vals, \
		"Unknown Type: %u")); \
	cktree = proto_item_add_subtree(ti, ett_dccp_ck); \
	proto_tree_add_item(cktree, hf_dccp_ck_type, tvb, offset, 1, FALSE); \
	offset += 1; \
	proto_tree_add_item(cktree, hf_dccp_ck_len, tvb, offset, 1, FALSE); \
	offset += 1; \
	proto_tree_add_item(cktree, hf_dccp_ck_sum, tvb, offset, \
		sizeof(DCC_SUM), FALSE); \
	offset += sizeof(DCC_SUM); \
}


/* Lookup string tables */
static const value_string dccp_op_vals[] = {
	{DCC_OP_INVALID, "Invalid Op"},
	{DCC_OP_NOP, 	"No-Op"},
	{DCC_OP_REPORT, "Report and Query"},
	{DCC_OP_QUERY, "Query"},
	{DCC_OP_QUERY_RESP, "Server Response"},
	{DCC_OP_ADMN, "Admin"},
	{DCC_OP_OK, "Ok"},
	{DCC_OP_ERROR, "Server Failing"},
	{DCC_OP_DELETE, "Delete Checksum(s)"},
	{0, NULL}
};

static const value_string dccp_cktype_vals[] = {
	{DCC_CK_INVALID, "Invalid/Deleted from DB when seen"},
	{DCC_CK_IP, 	"MD5 of binary source IPv6 address"},
	{DCC_CK_ENV_FROM, "MD5 of envelope Mail From value"},
	{DCC_CK_FROM, "MD5 of header From: line"},
	{DCC_CK_SUB, "MD5 of substitute header line"},
	{DCC_CK_MESSAGE_ID, "MD5 of header Message-ID: line"},
	{DCC_CK_RECEIVED, "MD5 of last header Received: line"},
	{DCC_CK_BODY, "MD5 of body"},
	{DCC_CK_FUZ1, "MD5 of filtered body - FUZ1"},
	{DCC_CK_FUZ2, "MD5 of filtered body - FUZ2"},
	{DCC_CK_FUZ3, "MD5 of filtered body - FUZ3"},
	{DCC_CK_FUZ4, "MD5 of filtered body - FUZ4"},
	{DCC_CK_SRVR_ID, "hostname for server-ID check "},
	{DCC_CK_ENV_TO, "MD5 of envelope Rcpt To value"},
	{0, NULL},
};

static const value_string dccp_adminop_vals[] = {
	{DCC_AOP_OK, "Never sent"},
	{DCC_AOP_STOP, "Stop Gracefully"},
	{DCC_AOP_NEW_IDS, "Load keys and client IDs"},
	{DCC_AOP_FLOD, "Flood control"},
	{DCC_AOP_DB_UNLOCK, "Start Switch to new database"},
	{DCC_AOP_DB_NEW, "Finish Switch to new database"},
	{DCC_AOP_STATS, "Return counters"},
	{DCC_AOP_STATS_CLEAR, "Return and zero counters"},
	{DCC_AOP_TRACE_ON, "Enable tracing"},
	{DCC_AOP_TRACE_OFF, "Disable tracing"},
	{DCC_AOP_CUR_CLIENTS, "List clients"},
	{0, NULL},
};

static const value_string dccp_target_vals[] = {
	{DCC_TGTS_TOO_MANY, "Targets (>= 16777200)"},
	{DCC_TGTS_OK, "Certified not spam"},
	{DCC_TGTS_OK2, "Half certified not spam"},
	{DCC_TGTS_DEL, "Deleted checksum"},
	{DCC_TGTS_INVALID, "Invalid"},
	{0, NULL},
};

static const value_string dccp_floodop_vals[] = {
	{DCC_AOP_FLOD_CHECK, "Check"},
	{DCC_AOP_FLOD_SHUTDOWN, "Shutdown"},
	{DCC_AOP_FLOD_HALT, "Halt"},
	{DCC_AOP_FLOD_RESUME, "Resume"},
	{DCC_AOP_FLOD_REWIND, "Rewind"},
	{DCC_AOP_FLOD_LIST, "List"},
	{DCC_AOP_FLOD_STATS, "Stats"},
	{DCC_AOP_FLOD_STATS_CLEAR, "Clear Stats"},
	{0,NULL},
};

static gboolean
dissect_dccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *dccp_tree, *dccp_optree, *dccp_opnumtree, *ti;
	proto_tree *dccp_tracetree;
	int offset = 0;
	int client_is_le = 0;
	int op = 0;
	int i, is_response;

	if (pinfo->srcport != DCC_PORT && pinfo->destport != DCC_PORT) {
		/* Not the right port - not a DCC packet. */
		return FALSE;
	}

	/* get at least a full packet structure */
	if ( !tvb_bytes_exist(tvb, 0, sizeof(DCC_HDR)) ) {
		/* Doesn't have enough bytes to contain packet header. */
		return FALSE;
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCCP");

	offset = 0;
	is_response = pinfo->srcport == DCC_PORT;

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO,
			"%s: %s",
			is_response ? "Response" : "Request",
			val_to_str(tvb_get_guint8(tvb, offset+3),
				 dccp_op_vals, "Unknown Op: %u")
		);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_dccp, tvb, offset, -1,
			FALSE);
		dccp_tree = proto_item_add_subtree(ti, ett_dccp);

		proto_tree_add_item(dccp_tree, hf_dccp_len, tvb,
			offset, 2, FALSE);

		if ( !tvb_bytes_exist(tvb, 0, tvb_get_ntohs(tvb, offset))) {
			/* Doesn't have number of bytes that header claims. */
			proto_tree_add_text(dccp_tree, tvb, offset, 2, "Error - packet is shorter than header claims!");
		}
		offset += 2;

		proto_tree_add_item(dccp_tree, hf_dccp_pkt_vers, tvb,
			offset, 1, FALSE);
		offset += 1;

		op = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(dccp_tree, hf_dccp_op, tvb,
			offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(dccp_tree, hf_dccp_clientid, tvb,
			offset, 4, FALSE);
		offset += 4;

		ti = proto_tree_add_text(dccp_tree, tvb, offset, -1, "Operation Numbers (Opaque to Server)");
		dccp_opnumtree = proto_item_add_subtree(ti, ett_dccp_opnums);

		/* Note - these are indeterminate - they are sortof considered opaque to the client */
		/* Make some attempt to figure out if this data is little endian, not guaranteed to be
		correct if connection went through a firewall or similar. */

		/* Very hokey check - if all three of pid/report/retrans look like little-endian
			numbers, host is probably little endian. Probably innacurate on super-heavily-used
			DCC clients though. This should be good enough for now. */
		client_is_le = ( (tvb_get_guint8(tvb, offset+4) | tvb_get_guint8(tvb, offset+4)) &&
						 (tvb_get_guint8(tvb, offset+8) | tvb_get_guint8(tvb, offset+9)) &&
						 (tvb_get_guint8(tvb, offset+12) | tvb_get_guint8(tvb, offset+13)) );

		proto_tree_add_item(dccp_opnumtree, hf_dccp_opnums_host, tvb,
			offset, 4, client_is_le);
		offset += 4;

		proto_tree_add_item(dccp_opnumtree, hf_dccp_opnums_pid, tvb,
			offset, 4, client_is_le);
		offset += 4;

		proto_tree_add_item(dccp_opnumtree, hf_dccp_opnums_report, tvb,
			offset, 4, client_is_le);
		offset += 4;

		proto_tree_add_item(dccp_opnumtree, hf_dccp_opnums_retrans, tvb,
			offset, 4, client_is_le);
		offset += 4;

		ti = proto_tree_add_text(dccp_tree, tvb, offset, -1, "Operation: %s",
			val_to_str(op, dccp_op_vals, "Unknown Op: %u"));
		dccp_optree = proto_item_add_subtree(ti, ett_dccp_op);

		switch(op) {
			case DCC_OP_NOP:
				D_SIGNATURE();
				break;

			case DCC_OP_REPORT:
				D_TARGET();
				for (i=0; i<=DCC_QUERY_MAX &&
					tvb_bytes_exist(tvb, offset+sizeof(DCC_SIGNATURE),1); i++)
				{
					D_CHECKSUM();
				}
				D_SIGNATURE();
				break;

			case DCC_OP_QUERY_RESP:
				for (i=0; i<=DCC_QUERY_MAX &&
					tvb_bytes_exist(tvb, offset+sizeof(DCC_SIGNATURE),1); i++)
				{
					D_TARGET();
				}
				D_SIGNATURE();
				break;

			case DCC_OP_ADMN:
				if ( is_response )
				{
					int left = tvb_length_remaining(tvb, offset) -
						sizeof(DCC_SIGNATURE);
					if ( left == sizeof(DCC_ADMN_RESP_CLIENTS) )
					{
						D_LABEL("Addr", 16);
						D_LABEL("Id", sizeof(DCC_CLNT_ID));
						D_LABEL("Last Used", 4);
						D_LABEL("Requests", 4);
					}
					else
					{
						D_TEXT("Response Text", sizeof(DCC_SIGNATURE));
					}
					D_SIGNATURE();
				}
				else
				{
					int aop;

					D_DATE();

					aop = tvb_get_guint8(tvb, offset+4);
					proto_tree_add_item(dccp_optree, hf_dccp_adminop, tvb, offset+4,
						1, FALSE);
					if (check_col(pinfo->cinfo, COL_INFO)) {
						col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
							val_to_str(tvb_get_guint8(tvb,offset+4),
							dccp_adminop_vals, "Unknown (%u)"));
					}

					if (aop == DCC_AOP_TRACE_ON || aop == DCC_AOP_TRACE_OFF )
					{
						ti = proto_tree_add_item(dccp_optree, hf_dccp_trace, tvb, offset,
							4, FALSE);
						dccp_tracetree = proto_item_add_subtree(ti, ett_dccp_trace);
						proto_tree_add_item(dccp_tracetree, hf_dccp_trace_admin, tvb, offset, 4, FALSE);
						proto_tree_add_item(dccp_tracetree, hf_dccp_trace_anon, tvb, offset, 4, FALSE);
						proto_tree_add_item(dccp_tracetree, hf_dccp_trace_client, tvb, offset, 4, FALSE);
						proto_tree_add_item(dccp_tracetree, hf_dccp_trace_rlim, tvb, offset, 4, FALSE);
						proto_tree_add_item(dccp_tracetree, hf_dccp_trace_query, tvb, offset, 4, FALSE);
						proto_tree_add_item(dccp_tracetree, hf_dccp_trace_ridc, tvb, offset, 4, FALSE);
						proto_tree_add_item(dccp_tracetree, hf_dccp_trace_flood, tvb, offset, 4, FALSE);
					}
					else if ( aop == DCC_AOP_FLOD )
					{
						proto_tree_add_item(dccp_optree, hf_dccp_floodop,
							tvb, offset, 4, FALSE);
						if (check_col(pinfo->cinfo, COL_INFO)) {
							col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
								val_to_str(tvb_get_ntohl(tvb,offset),
								dccp_floodop_vals, "Unknown (%u)"));
						}
					}
					else
					{
						proto_tree_add_item(dccp_optree, hf_dccp_adminval,
							tvb, offset, 4, FALSE);
					}
					offset += 4;

					offset += 1; /* admin op we did in reverse order */
					D_LABEL("Pad", 3);
					D_SIGNATURE();
				}
				break;

			case DCC_OP_OK:
				proto_tree_add_item(dccp_optree, hf_dccp_max_pkt_vers, tvb,
					offset, 1, FALSE);
				offset += 1;

				D_LABEL("Unused", 1);

				proto_tree_add_item(dccp_optree, hf_dccp_qdelay_ms, tvb,
					offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(dccp_optree, hf_dccp_brand, tvb,
					offset, sizeof(DCC_BRAND), FALSE);
				offset += sizeof(DCC_BRAND);

				D_SIGNATURE();
				break;

			default:
				/* do nothing */
				break;
		}
	}

	return TRUE;
}

void
proto_register_dccp(void)
{
	static hf_register_info hf[] = {
			{ &hf_dccp_len, {
				"Packet Length", "dccp.len", FT_UINT16, BASE_DEC,
				NULL, 0, "Packet Length", HFILL }},

			{ &hf_dccp_pkt_vers, {
				"Packet Version", "dccp.pkt_vers", FT_UINT16, BASE_DEC,
				NULL, 0, "Packet Version", HFILL }},

			{ &hf_dccp_op, {
				"Operation Type", "dccp.op", FT_UINT8, BASE_DEC,
				VALS(dccp_op_vals), 0, "Operation Type", HFILL }},

			{ &hf_dccp_clientid, {
				"Client ID", "dccp.clientid", FT_UINT32, BASE_DEC,
				NULL, 0, "Client ID", HFILL }},

			{ &hf_dccp_opnums_host, {
				"Host", "dccp.opnums.host", FT_UINT32, BASE_DEC,
				NULL, 0, "Host", HFILL }},

			{ &hf_dccp_opnums_pid, {
				"Process ID", "dccp.opnums.pid", FT_UINT32, BASE_DEC,
				NULL, 0, "Process ID", HFILL }},

			{ &hf_dccp_opnums_report, {
				"Report", "dccp.opnums.report", FT_UINT32, BASE_DEC,
				NULL, 0, "Report", HFILL }},

			{ &hf_dccp_opnums_retrans, {
				"Retransmission", "dccp.opnums.retrans", FT_UINT32, BASE_DEC,
				NULL, 0, "Retransmission", HFILL }},

			{ &hf_dccp_signature, {
				"Signature", "dccp.signature", FT_BYTES, BASE_HEX,
				NULL, 0, "Signature", HFILL }},

			{ &hf_dccp_max_pkt_vers, {
				"Maximum Packet Version", "dccp.max_pkt_vers", FT_UINT8, BASE_DEC,
				NULL, 0, "Maximum Packet Version", HFILL }},

			{ &hf_dccp_qdelay_ms, {
				"Client Delay", "dccp.qdelay_ms", FT_UINT16, BASE_DEC,
				NULL, 0, "Client Delay", HFILL }},

			{ &hf_dccp_brand, {
				"Server Brand", "dccp.brand", FT_STRING, BASE_DEC,
				NULL, 0, "Server Brand", HFILL }},

			{ &hf_dccp_ck_type, {
				"Type", "dccp.checksum.type", FT_UINT8, BASE_DEC,
				VALS(dccp_cktype_vals), 0, "Checksum Type", HFILL }},

			{ &hf_dccp_ck_len, {
				"Length", "dccp.checksum.length", FT_UINT8, BASE_DEC,
				NULL, 0, "Checksum Length", HFILL }},

			{ &hf_dccp_ck_sum, {
				"Sum", "dccp.checksum.sum", FT_BYTES, BASE_HEX,
				NULL, 0, "Checksum", HFILL }},

			{ &hf_dccp_target, {
				"Target", "dccp.target", FT_UINT32, BASE_HEX,
				NULL, 0, "Target", HFILL }},

			{ &hf_dccp_date, {
				"Date", "dccp.date", FT_ABSOLUTE_TIME, BASE_DEC,
				NULL, 0, "Date", HFILL }},

			{ &hf_dccp_adminop, {
				"Admin Op", "dccp.adminop", FT_UINT8, BASE_DEC,
				VALS(dccp_adminop_vals), 0, "Admin Op", HFILL }},

			{ &hf_dccp_adminval, {
				"Admin Value", "dccp.adminval", FT_UINT32, BASE_DEC,
				NULL, 0, "Admin Value", HFILL }},

			{ &hf_dccp_trace, {
				"Trace Bits", "dccp.trace", FT_UINT32, BASE_HEX,
				NULL, 0, "Trace Bits", HFILL }},

			{ &hf_dccp_trace_admin, {
				"Admin Requests", "dccp.trace.admin", FT_BOOLEAN, 32,
				NULL, 0x00000001, "Admin Requests", HFILL }},

			{ &hf_dccp_trace_anon, {
				"Anonymous Requests", "dccp.trace.anon", FT_BOOLEAN, 32,
				NULL, 0x00000002, "Anonymous Requests", HFILL }},

			{ &hf_dccp_trace_client, {
				"Authenticated Client Requests", "dccp.trace.client", FT_BOOLEAN, 32,
				NULL, 0x00000004, "Authenticated Client Requests", HFILL }},

			{ &hf_dccp_trace_rlim, {
				"Rate-Limited Requests", "dccp.trace.rlim", FT_BOOLEAN, 32,
				NULL, 0x00000008, "Rate-Limited Requests", HFILL }},

			{ &hf_dccp_trace_query, {
				"Queries and Reports", "dccp.trace.query", FT_BOOLEAN, 32,
				NULL, 0x00000010, "Queries and Reports", HFILL }},

			{ &hf_dccp_trace_ridc, {
				"RID Cache Messages", "dccp.trace.ridc", FT_BOOLEAN, 32,
				NULL, 0x00000020, "RID Cache Messages", HFILL }},

			{ &hf_dccp_trace_flood, {
				"Input/Output Flooding", "dccp.trace.flood", FT_BOOLEAN, 32,
				NULL, 0x00000040, "Input/Output Flooding", HFILL }},

			{ &hf_dccp_floodop, {
				"Flood Control Operation", "dccp.floodop", FT_UINT32, BASE_DEC,
				VALS(dccp_floodop_vals), 0, "Flood Control Operation", HFILL }},

        };
	static gint *ett[] = {
		&ett_dccp,
		&ett_dccp_op,
		&ett_dccp_ck,
		&ett_dccp_opnums,
		&ett_dccp_trace,
	};

	proto_dccp = proto_register_protocol("Distributed Checksum Clearinghouse Protocol",
	    "DCCP", "dccp");

	proto_register_field_array(proto_dccp, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dccp(void)
{
	heur_dissector_add("udp", dissect_dccp, proto_dccp);
}
