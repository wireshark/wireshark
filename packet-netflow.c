/* packet-netflow.c
 * Routines for Cisco NetFlow packet disassembly
 * Matthew Smart <smart@monkey.org>
 *
 * $Id: packet-netflow.c,v 1.1 2002/09/04 20:23:53 guy Exp $
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "packet-netflow.h"

static int proto_netflow = -1;
static int hf_netflow_version = -1;
static int hf_netflow_count = -1;
static int hf_netflow_sys_uptime = -1;
static int hf_netflow_unix_sec = -1;
static int hf_netflow_unix_nsec = -1;
static int hf_netflow_flow_sequence = -1;
static int hf_netflow_record = -1;

static gint ett_netflow = -1;
static gint ett_netflow_rec = -1;

static void 
dissect_netflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *netflow_tree = NULL;
	proto_tree *netflow_rec_tree = NULL;
	proto_item *ti = NULL, *tf = NULL; 
	gint offset = 0;
	struct netflow5_hdr nfh;
	struct netflow5_rec nfr;
	guint16 nfh_version, nfh_count;
	guint32 nfh_sys_uptime, nfh_unix_sec, nfh_unix_nsec;
	guint32 nfh_sequence;
	int i;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetFlow");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	/* Determine NetFlow version and number of records */
	tvb_memcpy(tvb, (guint8 *)&nfh, offset, sizeof(nfh));
	nfh_version = ntohs(nfh.version);
	nfh_count = ntohs(nfh.count);
	nfh_sys_uptime = ntohl(nfh.sys_uptime);
	nfh_unix_sec = ntohl(nfh.unix_sec);
	nfh_unix_nsec = ntohl(nfh.unix_nsec);
	nfh_sequence = ntohl(nfh.flow_sequence);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO,
		    "v%u, %u records, sequence number %u",
		    nfh_version, nfh_count, nfh_sequence);

	if (tree != NULL) {
		/* Add NetFlow to to the tree */
		ti = proto_tree_add_protocol_format(tree, proto_netflow, tvb,
		    offset, sizeof(nfh.version) + sizeof(nfh.count)*sizeof(nfr),
		    "Cisco Netflow, v%u, %u records, sequence number %u",
		    nfh_version, nfh_count, nfh_sequence);
		netflow_tree = proto_item_add_subtree(ti, ett_netflow);

		/* Version */
		proto_tree_add_uint(netflow_tree, hf_netflow_version,
		    tvb, offset, sizeof(nfh.version), nfh_version);

		/* Number of records */
		proto_tree_add_uint(netflow_tree, hf_netflow_count,
		    tvb, offset + 2, sizeof(nfh.count), nfh_count);

		/* XXX only support version 5 right now */
		if (nfh_version != 5)
			return;

		/* System (router) uptime */
		proto_tree_add_uint_format(netflow_tree, hf_netflow_sys_uptime,
		    tvb, offset + 4, sizeof(nfh.sys_uptime), nfh_sys_uptime,
		    "System uptime: %u msec", nfh_sys_uptime);

		/* Unix time in seconds */
		proto_tree_add_uint_format(netflow_tree, hf_netflow_unix_sec,
		    tvb, offset + 8, sizeof(nfh.unix_sec), nfh_unix_sec,
		    "Unix time: %u seconds", nfh_unix_sec);

		/* Unix time in seconds */
		proto_tree_add_uint_format(netflow_tree, hf_netflow_unix_nsec,
		    tvb, offset + 12, sizeof(nfh.unix_nsec), nfh_unix_nsec,
		    "Residual: %u nanoseconds", nfh_unix_nsec);

		for (i = 0; i < nfh_count; i++) {
			guint rec_offset = sizeof(nfh) + i * sizeof(nfr);

			tf = proto_tree_add_uint_format(netflow_tree,
			    hf_netflow_record, tvb, rec_offset, sizeof(nfr),
			    i, "Record %d: %u packets, %u bytes", i+1,
			    tvb_get_ntohl(tvb, rec_offset + 16),
			    tvb_get_ntohl(tvb, rec_offset + 20));
			netflow_rec_tree = proto_item_add_subtree(tf,
			    ett_netflow_rec);

			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 0, 4, "Src Addr: %s",
			    ip_to_str(tvb_get_ptr(tvb, rec_offset + 0, 4)));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 4, 4, "Dst Addr: %s",
			    ip_to_str(tvb_get_ptr(tvb, rec_offset + 4, 4)));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 8, 4, "Next Hop: %s",
			    ip_to_str(tvb_get_ptr(tvb, rec_offset + 8, 4)));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 12, 2, "Input Interface: %u",
			    tvb_get_ntohs(tvb, rec_offset + 12));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 14, 2, "Output Interface: %u",
			    tvb_get_ntohs(tvb, rec_offset + 14));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 16, 4, "Packets: %u",
			    tvb_get_ntohl(tvb, rec_offset + 16));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 20, 4, "Bytes: %u",
			    tvb_get_ntohl(tvb, rec_offset + 20));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 24, 4, "Start Time: %u",
			    tvb_get_ntohl(tvb, rec_offset + 24));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 28, 4, "End Time: %u",
			    tvb_get_ntohl(tvb, rec_offset + 28));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 32, 2, "Source Port: %u",
			    tvb_get_ntohs(tvb, rec_offset + 32));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 34, 2, "Dest Port: %u",
			    tvb_get_ntohs(tvb, rec_offset + 34));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 37, 1, "TCP Flags: 0x%0x",
			    tvb_get_guint8(tvb, rec_offset + 37));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 38, 1, "IP Protocol: %u",
			    tvb_get_guint8(tvb, rec_offset + 38));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 39, 1, "Type of service: 0x%02x",
			    tvb_get_guint8(tvb, rec_offset + 39));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 40, 2, "Source AS: %u",
			    tvb_get_ntohs(tvb, rec_offset + 40));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 42, 2, "Dest AS: %u",
			    tvb_get_ntohs(tvb, rec_offset + 42));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 44, 1, "Source Mask: %u",
			    tvb_get_guint8(tvb, rec_offset + 44));
			proto_tree_add_text(netflow_rec_tree, tvb,
			    rec_offset + 45, 1, "Dest Mask: %u",
			    tvb_get_guint8(tvb, rec_offset + 45));
		}
	}
}

void
proto_register_netflow(void)
{
	static hf_register_info hf[] = {
		{ &hf_netflow_version,
		{ "Version", "netflow.version", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_count,
		{ "Number of records", "netflow.count", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_sys_uptime,
		{ "System uptime", "netflow.sys_uptime", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_unix_sec,
		{ "Unix seconds", "netflow.unix_sec", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_unix_nsec,
		{ "Unix nanonseconds", "netflow.unix_nsec", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_flow_sequence,
		{ "Sequence number", "netflow.flow_sequence", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_record,
		{ "Record", "netflow.record", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
	};

	static gint *ett[] = {
		&ett_netflow,
		&ett_netflow_rec
	};

	proto_netflow = proto_register_protocol("Cisco NetFlow",
	    "NetFlow", "netflow");
	proto_register_field_array(proto_netflow, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_netflow(void)
{
	dissector_handle_t netflow_handle;

	netflow_handle = create_dissector_handle(dissect_netflow,
	    proto_netflow);
	dissector_add("udp.port", UDP_PORT_NETFLOW, netflow_handle);
}
