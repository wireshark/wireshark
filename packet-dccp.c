/* packet-dcc.c
 * Routines for Distributed Checksum Clearinghouse packet dissection
 * DCC Home: http://www.rhyolite.com/anti-spam/dcc/
 *
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * $Id: packet-dccp.c,v 1.1 2002/05/03 15:50:11 nneul Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

static int proto_dccp = -1;
static int hf_dccp_len = -1;
static int hf_dccp_pkt_vers = -1;
static int hf_dccp_op = -1;
static int hf_dccp_clientid = -1;
static int hf_dccp_opnums_host = -1;
static int hf_dccp_opnums_pid = -1;
static int hf_dccp_opnums_report = -1;
static int hf_dccp_opnums_retrans = -1;

static gint ett_dccp = -1;

#define TCP_PORT_DCC	6277

/* Some structures retrieved from DCC protocol headers */
/* DCC Code Copyright (c) 2002 by Rhyolite Software */

typedef enum {
    DCC_OP_INVALID=0,
    DCC_OP_NOP,                         /* see if the server is alive */
    DCC_OP_REPORT,                      /* client reporting and querying */
    DCC_OP_QUERY,                       /* client querying */
    DCC_OP_QUERY_RESP,                  /* server responding */
    DCC_OP_ADMN,                        /* local control of the server */
    DCC_OP_OK,                          /* administrative operation ok */
    DCC_OP_ERROR,                       /* server failing or complaining */
    DCC_OP_DELETE                       /* delete some checksums */
} DCC_OPS;

typedef struct {
    guint32   h;                      /* client host ID, e.g. IP address */
    guint32   p;                      /* process ID, serial #, timestamp */
    guint32   r;                      /* report ID */
    guint32   t;                      /* client (re)transmission # */
} DCC_OP_NUMS;

/* The start of any DCC packet.
 *      The length and version are early, since they are they only fields
 *      that are constrained in future versions. */
typedef guint32 DCC_CLNT_ID;
typedef struct {
    guint16   len;                    /* total DCC packet length (for TCP) */
    guchar      pkt_vers;               /* packet protocol version */
    guchar      op;                     /* one of DCC_OPS */
    DCC_CLNT_ID sender;                 /* official DCC client-ID */
    DCC_OP_NUMS op_nums;                /* op_num.t must be last */
} DCC_HDR;


/* Lookup string tables */
static const value_string dccp_op_vals[] = {
	{DCC_OP_INVALID, "Invalid Op"},
	{DCC_OP_NOP, 	"No-Op"},
	{DCC_OP_REPORT, "Report and Query"},
	{DCC_OP_QUERY, "Query"},
	{DCC_OP_QUERY_RESP, "Server Response"},
	{DCC_OP_ADMN, "Admin Op"},
	{DCC_OP_OK, "Admin Op Ok"},
	{DCC_OP_ERROR, "Server Failing"},
	{DCC_OP_DELETE, "Delete Checksum(s)"},
	{0, NULL}
};


static gboolean
dissect_dccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *dccp_tree, *ti;
	int offset = 0;
	int client_is_le = 0;

	if (pinfo->srcport != TCP_PORT_DCC && pinfo->destport != TCP_PORT_DCC) {
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
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, 
			"%s: %s", 
			( pinfo->destport == TCP_PORT_DCC ) ? "Request" : "Response", 
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
		offset += 2;

		proto_tree_add_item(dccp_tree, hf_dccp_pkt_vers, tvb, 
			offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(dccp_tree, hf_dccp_op, tvb, 
			offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(dccp_tree, hf_dccp_clientid, tvb, 
			offset, 4, FALSE);
		offset += 4;

		/* Note - these are indeterminate - they are sortof considered opaque to the client */
		/* Make some attempt to figure out if this data is little endian, not guaranteed to be
		correct if connection went through a firewall or similar. */

		/* Very hokey check - if all three of pid/report/retrans look like little-endian 
			numbers, host is probably little endian. Probably innacurate on super-heavily-used
			DCC clients though. This should be good enough for now. */
		client_is_le = ( (tvb_get_guint8(tvb, offset+4) | tvb_get_guint8(tvb, offset+4)) &&
						 (tvb_get_guint8(tvb, offset+8) | tvb_get_guint8(tvb, offset+9)) &&
						 (tvb_get_guint8(tvb, offset+12) | tvb_get_guint8(tvb, offset+13)) );

		proto_tree_add_item(dccp_tree, hf_dccp_opnums_host, tvb, 
			offset, 4, client_is_le);
		offset += 4;

		proto_tree_add_item(dccp_tree, hf_dccp_opnums_pid, tvb, 
			offset, 4, client_is_le);
		offset += 4;

		proto_tree_add_item(dccp_tree, hf_dccp_opnums_report, tvb, 
			offset, 4, client_is_le);
		offset += 4;

		proto_tree_add_item(dccp_tree, hf_dccp_opnums_retrans, tvb, 
			offset, 4, client_is_le);
		offset += 4;
	}

	return TRUE;
}

void
proto_register_dccp(void)
{
	static hf_register_info hf[] = {
			{ &hf_dccp_len, {	
				"Packet Length", "dcc.len", FT_UINT16, BASE_DEC,
				NULL, 0, "Packet Length", HFILL }},

			{ &hf_dccp_pkt_vers, {	
				"Packet Version", "dcc.pkt_vers", FT_UINT16, BASE_DEC,
				NULL, 0, "Packet Version", HFILL }},

			{ &hf_dccp_op, {	
				"Operation Type", "dcc.op", FT_UINT8, BASE_DEC,
				VALS(dccp_op_vals), 0, "Operation Type", HFILL }},

			{ &hf_dccp_clientid, {	
				"Client ID", "dcc.clientid", FT_UINT32, BASE_DEC,
				NULL, 0, "Client ID", HFILL }},

			{ &hf_dccp_opnums_host, {	
				"OpNums: Host", "dcc.opnums.host", FT_IPv4, BASE_DEC,
				NULL, 0, "OpNums: Host", HFILL }},

			{ &hf_dccp_opnums_pid, {	
				"OpNums: Process ID", "dcc.opnums.pid", FT_UINT32, BASE_DEC,
				NULL, 0, "OpNums: Process ID", HFILL }},

			{ &hf_dccp_opnums_report, {	
				"OpNums: Report", "dcc.opnums.report", FT_UINT32, BASE_DEC,
				NULL, 0, "OpNums: Report", HFILL }},

			{ &hf_dccp_opnums_retrans, {	
				"OpNums: Retransmission", "dcc.opnums.retrans", FT_UINT32, BASE_DEC,
				NULL, 0, "OpNums: Retransmission", HFILL }},

        };
	static gint *ett[] = {
		&ett_dccp,
	};

	proto_dccp = proto_register_protocol("Distributed Checksum Clearinghouse Prototocl",
	    "DCCP", "dccp");

	proto_register_field_array(proto_dccp, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dccp(void)
{
	heur_dissector_add("udp", dissect_dccp, proto_dccp);
}
