/* packet-netflow.c
 * Routines for Cisco NetFlow packet disassembly
 * Matthew Smart <smart@monkey.org>
 *
 * $Id: packet-netflow.c,v 1.4 2002/09/09 20:22:51 guy Exp $
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
static int hf_netflow_sequence = -1;
static int hf_netflow_engine_type = -1;
static int hf_netflow_engine_id = -1;
static int hf_netflow_aggregation = -1;
static int hf_netflow_agg_version = -1;
static int hf_netflow_sample_rate = -1;
static int hf_netflow_record = -1;

static int hf_netflow_src_addr = -1;
static int hf_netflow_dst_addr = -1;
static int hf_netflow_next_hop = -1;
static int hf_netflow_input_iface = -1;
static int hf_netflow_output_iface = -1;
static int hf_netflow_packets = -1;
static int hf_netflow_bytes = -1;
static int hf_netflow_start_time = -1;
static int hf_netflow_end_time = -1;
static int hf_netflow_src_port = -1;
static int hf_netflow_dst_port = -1;
static int hf_netflow_v7_flags = -1;
static int hf_netflow_tcp_flags = -1;
static int hf_netflow_ip_prot = -1;
static int hf_netflow_tos = -1;
static int hf_netflow_src_as = -1;
static int hf_netflow_dst_as = -1;
static int hf_netflow_src_mask = -1;
static int hf_netflow_dst_mask = -1;
static int hf_netflow_router_sc = -1;

static gint ett_netflow = -1;
static gint ett_netflow_rec = -1;

static void
dissect_netflow_157(tvbuff_t *tvb, proto_tree *tree, guint16 version,
    guint offset)
{
	guint32 addr;

	tvb_memcpy(tvb, (guint8 *)&addr, offset, 4);
	proto_tree_add_ipv4(tree, hf_netflow_src_addr, tvb, offset, 4, addr);
	offset += 4;

	tvb_memcpy(tvb, (guint8 *)&addr, offset, 4);
	proto_tree_add_ipv4(tree, hf_netflow_dst_addr, tvb, offset, 4, addr);
	offset += 4;

	tvb_memcpy(tvb, (guint8 *)&addr, offset, 4);
	proto_tree_add_ipv4(tree, hf_netflow_next_hop, tvb, offset, 4, addr);
	offset += 4;

	proto_tree_add_item(tree, hf_netflow_input_iface,
	    tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_netflow_output_iface,
	    tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_netflow_packets,
	    tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_netflow_bytes,
	    tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_netflow_start_time,
	    tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_netflow_end_time,
	    tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_netflow_src_port,
	    tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(tree, hf_netflow_dst_port,
	    tvb, offset, 2, FALSE);
	offset += 2;

	if (version == 1) {
		offset += 2;	/* Skip pad bytes */

		proto_tree_add_item(tree, hf_netflow_ip_prot,
		    tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(tree, hf_netflow_tos,
		    tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(tree, hf_netflow_tcp_flags,
		    tvb, offset, 1, FALSE);
		offset += 1;
	} else {
		if (version == 7) {
			proto_tree_add_item(tree, hf_netflow_v7_flags,
			    tvb, offset, 1, FALSE);
		}
		offset += 1;	/* v5 pad byte, v7 flags */

		proto_tree_add_item(tree, hf_netflow_tcp_flags,
		    tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(tree, hf_netflow_ip_prot,
		    tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(tree, hf_netflow_tos,
		    tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(tree, hf_netflow_src_as,
		    tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(tree, hf_netflow_dst_as,
		    tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(tree, hf_netflow_src_mask,
		    tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(tree, hf_netflow_dst_mask,
		    tvb, offset, 1, FALSE);
		offset += 1;

		offset += 2;	/* Skip pad bytes */

		if (version == 7) {
			proto_tree_add_item(tree, hf_netflow_router_sc,
			    tvb, offset, 4, FALSE);
			offset += 4;
		}
	}
}

static void 
dissect_netflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *netflow_tree = NULL;
	proto_tree *netflow_rec_tree = NULL;
	proto_item *ti = NULL, *tf = NULL; 
	gint offset = 0;
	guint16 nf_version, nf_count, nf_sample_rate;
	guint32 nf_sequence;
	gint header_size, record_size;
	int i;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetFlow");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	/* Determine NetFlow version and number of records */
	nf_version = tvb_get_ntohs(tvb, offset);
	offset += sizeof(nf_version);

	nf_count = tvb_get_ntohs(tvb, offset);
	offset += sizeof(nf_count);

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO,
		    "v%u, %u records", nf_version, nf_count);

	/* Handle version-specific issues */
	switch (nf_version) {
	case 1:
		header_size = NETFLOW_V1_HDR;
		record_size = NETFLOW_V1_REC;
		break;
	case 5:
		header_size = NETFLOW_V5_HDR;
		record_size = NETFLOW_V5_REC;
		break;
	case 7:
		header_size = NETFLOW_V7_HDR;
		record_size = NETFLOW_V7_REC;
		break;
	case 8:
		header_size = NETFLOW_V8_HDR;
		record_size = NETFLOW_V8_REC;
	case 9:
	default:
		return;
	}

	/* Add NetFlow to the tree */
	if (tree != NULL) {
		ti = proto_tree_add_protocol_format(tree, proto_netflow, tvb,
		    0, header_size, "NetFlow, v%u, %u records",
		    nf_version, nf_count);
		netflow_tree = proto_item_add_subtree(ti, ett_netflow);
	} else {
		return;
	}

	/* Start adding header information */
	offset = 0;

	proto_tree_add_uint(netflow_tree, hf_netflow_version,
	    tvb, offset, sizeof(nf_version), nf_version);
	offset += sizeof(nf_version);

	proto_tree_add_uint(netflow_tree, hf_netflow_count,
	    tvb, offset, sizeof(nf_count), nf_count);
	offset += sizeof(nf_count);

	proto_tree_add_item(netflow_tree, hf_netflow_sys_uptime,
	    tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(netflow_tree, hf_netflow_unix_sec,
	    tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(netflow_tree, hf_netflow_unix_nsec,
	    tvb, offset, 4, FALSE);
	offset += 4;

	/* No more version 1 header */

	if (nf_version != 1) {
		nf_sequence = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(netflow_tree, hf_netflow_sequence,
		    tvb, offset, sizeof(nf_sequence), nf_sequence);
		offset += sizeof(nf_sequence);

		/* Add the sequence number */
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_clear(pinfo->cinfo, COL_INFO);
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "v%u, %u records, sequence # %u",
			    nf_version, nf_count, nf_sequence);
		}

		/* No more version 7 header */

		if (nf_version != 7) {
			/* Engine type and ID */
			proto_tree_add_item(netflow_tree,
			    hf_netflow_engine_type, tvb, offset,
			    1, FALSE);
			offset += 1;

			proto_tree_add_item(netflow_tree,
			    hf_netflow_engine_id, tvb, offset,
			    1, FALSE);
			offset += 1;

			if (nf_version == 8) {
				/* Engine type and ID */
				proto_tree_add_item(netflow_tree,
				    hf_netflow_aggregation, tvb, offset,
				    1, FALSE);
				offset += 1;

				proto_tree_add_item(netflow_tree,
				    hf_netflow_agg_version, tvb, offset,
				    1, FALSE);
				offset += 1;
			}

			/*
			 * On high-speed interfaces often just
			 * statistical sample records are produced.
			 */
			nf_sample_rate = tvb_get_ntohs(tvb, offset);
			if (nf_version == 5) {
				/*
				 * Sample rate.  Junipers and some Ciscos
				 * include sampling rate in the reserved
				 * header field.  Not all the bits are used,
				 * however.
				 */
				if ((nf_sample_rate & 0xc000) == 0x4000) {
					nf_sample_rate &= 0x3fff;
					if (nf_sample_rate == 0)
						nf_sample_rate = 1;
				} else
					nf_sample_rate = 1;
			}
			proto_tree_add_uint_format(netflow_tree,
			    hf_netflow_sample_rate, tvb, offset,
			    sizeof(nf_sample_rate), nf_sample_rate,
			    "Sample_rate: 1/%u", nf_sample_rate);
			offset += sizeof(nf_sample_rate);
		}
	}

	/* XXX Doesn't support v8 records, yet */
	if (nf_version == 8)
		return;

	/* Handle the flow records */
	for (i = 0; i < nf_count; i++) {
		guint rec_offset = header_size + i * record_size;

		tf = proto_tree_add_uint_format(netflow_tree,
		    hf_netflow_record, tvb, rec_offset, record_size,
		    i, "Record %d: %u packets, %u bytes", i + 1,
		    tvb_get_ntohl(tvb, rec_offset + 16),
		    tvb_get_ntohl(tvb, rec_offset + 20));
		netflow_rec_tree = proto_item_add_subtree(tf,
		    ett_netflow_rec);

		dissect_netflow_157(tvb, netflow_rec_tree,
		    nf_version, rec_offset);
	}
}

void
proto_register_netflow(void)
{
	static hf_register_info hf[] = {
		/* Header */
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
		{ &hf_netflow_sequence,
		{ "Sequence number", "netflow.sequence", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_engine_type,
		{ "Engine type", "netflow.engine_type", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_engine_id,
		{ "Engine ID", "netflow.engine_id", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_aggregation,
		{ "Aggregation method", "netflow.aggregation", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_agg_version,
		{ "Aggregation version", "netflow.agg_version", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_sample_rate,
		{ "Sample rate", "netflow.sample_rate", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_record,
		{ "Record", "netflow.record", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		/* Record */
		{ &hf_netflow_src_addr,
		{ "Source address", "netflow.src_addr", FT_IPv4,
		  BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_dst_addr,
		{ "Destination address", "netflow.dst_addr", FT_IPv4,
		  BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_next_hop,
		{ "Next hop", "netflow.next_hop", FT_IPv4,
		  BASE_NONE, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_input_iface,
		{ "Input interface", "netflow.input_iface", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_output_iface,
		{ "Output interface", "netflow.output_iface", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_packets,
		{ "Packets sent", "netflow.packets", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_bytes,
		{ "Bytes sent", "netflow.bytes", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_start_time,
		{ "Start time", "netflow.start_time", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_end_time,
		{ "End time", "netflow.end_time", FT_UINT32,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_src_port,
		{ "Source port", "netflow.src_port", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_dst_port,
		{ "Destination port", "netflow.dst_port", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_v7_flags,
		{ "Valid flags", "netflow.flags", FT_UINT8,
		  BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_tcp_flags,
		{ "TCP flags", "netflow.tcp_flags", FT_UINT8,
		  BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_ip_prot,
		{ "IP protocol", "netflow.ip_prot", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_tos,
		{ "Type of service", "netflow.tos", FT_UINT8,
		  BASE_HEX, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_src_as,
		{ "Source AS", "netflow.src_as", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_dst_as,
		{ "Destination AS", "netflow.dst_as", FT_UINT16,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_src_mask,
		{ "Source mask", "netflow.src_mask", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_dst_mask,
		{ "Destination mask", "netflow.dst_mask", FT_UINT8,
		  BASE_DEC, NULL, 0x0, "", HFILL }},
		{ &hf_netflow_router_sc,
		{ "Router bypass", "netflow.router_sc", FT_IPv4,
		  BASE_NONE, NULL, 0x0, "", HFILL }},
	};

	static gint *ett[] = {
		&ett_netflow,
		&ett_netflow_rec
	};

	proto_netflow = proto_register_protocol("NetFlow",
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
