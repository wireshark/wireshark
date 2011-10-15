/* packet-ipxwan.c
 * Routines for NetWare IPX WAN Protocol
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-ipx.h"

/*
 * See RFC 1362 for version 1 of this protocol; see the NetWare Link
 * Services Protocol Specification, chapter 3, for version 2.
 */
static int proto_ipxwan = -1;

static int hf_ipxwan_identifier = -1;
static int hf_ipxwan_packet_type = -1;
static int hf_ipxwan_node_id = -1;
static int hf_ipxwan_sequence_number = -1;
static int hf_ipxwan_num_options = -1;
static int hf_ipxwan_option_num = -1;
static int hf_ipxwan_accept_option = -1;
static int hf_ipxwan_option_data_len = -1;
static int hf_ipxwan_routing_type = -1;
static int hf_ipxwan_wan_link_delay = -1;
static int hf_ipxwan_common_network_number = -1;
static int hf_ipxwan_router_name = -1;
static int hf_ipxwan_delay = -1;
static int hf_ipxwan_throughput = -1;
static int hf_ipxwan_request_size = -1;
static int hf_ipxwan_delta_time = -1;
static int hf_ipxwan_extended_node_id = -1;
static int hf_ipxwan_node_number = -1;
static int hf_ipxwan_compression_type = -1;

static gint ett_ipxwan = -1;
static gint ett_ipxwan_option = -1;

static const value_string ipxwan_packet_type_vals[] = {
	{ 0,    "Timer Request" },
	{ 1,    "Timer Response" },
	{ 2,    "Information Request" },
	{ 3,    "Information Response" },
	{ 4,    "Throughput Request" },
	{ 5,    "Throughput Response" },
	{ 6,    "Delay Request" },
	{ 7,    "Delay Response" },
	{ 0xFF, "NAK" },
	{ 0,    NULL }
};

#define OPT_ROUTING_TYPE		0x00
#define OPT_RIP_SAP_INFO_EXCHANGE	0x01
#define OPT_NLSP_INFORMATION		0x02
#define OPT_NLSP_RAW_THROUGHPUT_DATA	0x03
#define OPT_EXTENDED_NODE_ID		0x04
#define OPT_NODE_NUMBER			0x05
#define OPT_COMPRESSION			0x80
#define OPT_PAD				0xFF

static const value_string ipxwan_option_num_vals[] = {
	{ OPT_ROUTING_TYPE,             "Routing Type" },
	{ OPT_RIP_SAP_INFO_EXCHANGE,    "RIP/SAP Info Exchange" },
	{ OPT_NLSP_INFORMATION,         "NLSP Information" },
	{ OPT_NLSP_RAW_THROUGHPUT_DATA, "NLSP Raw Throughput Data" },
	{ OPT_EXTENDED_NODE_ID,         "Extended Node ID" },
	{ OPT_NODE_NUMBER,              "Node Number" },
	{ OPT_COMPRESSION,              "Compression" },
	{ OPT_PAD,                      "Pad" },
	{ 0,                            NULL }
};

static const value_string ipxwan_accept_option_vals[] = {
	{ 0, "No" },
	{ 1, "Yes" },
	{ 3, "Not Applicable" },
	{ 0, NULL }
};

static const value_string ipxwan_routing_type_vals[] = {
	{ 0, "RIP" },
	{ 1, "NLSP" },
	{ 2, "Unnumbered RIP" },
	{ 3, "On-demand, static routing" },
	{ 4, "Client-router connection" },
	{ 0, NULL }
};

#define COMP_TYPE_TELEBIT	0

static const value_string ipxwan_compression_type_vals[] = {
	{ COMP_TYPE_TELEBIT, "Telebit" },
	{ 0,                 NULL }
};

static void
dissect_ipxwan(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *ipxwan_tree = NULL;
	int offset = 0;
	guint8 packet_type;
	guint8 num_options;
	guint8 option_number;
	proto_tree *option_tree;
	guint16 option_data_len;
	guint16 wan_link_delay;
	guint32 delay;
	guint32 throughput;
	guint32 delta_time;
	guint8 compression_type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPX WAN");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_ipxwan, tvb, 0, -1,
		    FALSE);
		ipxwan_tree = proto_item_add_subtree(ti, ett_ipxwan);
	}

	if (tree) {
		proto_tree_add_item(ipxwan_tree, hf_ipxwan_identifier, tvb,
		    offset, 4, ENC_ASCII|ENC_NA);
	}
	offset += 4;
	packet_type = tvb_get_guint8(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(packet_type, ipxwan_packet_type_vals,
		        "Unknown packet type %u"));
	}
	if (tree) {
		proto_tree_add_uint(ipxwan_tree, hf_ipxwan_packet_type, tvb,
			offset, 1, packet_type);
		offset += 1;
		proto_tree_add_item(ipxwan_tree, hf_ipxwan_node_id, tvb,
			offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(ipxwan_tree, hf_ipxwan_sequence_number, tvb,
			offset, 1, ENC_BIG_ENDIAN);
		offset += 1;
		num_options = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(ipxwan_tree, hf_ipxwan_num_options, tvb,
			offset, 1, num_options);
		offset += 1;

		while (num_options != 0) {
			option_number = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_text(ipxwan_tree, tvb, offset, -1,
			    "Option: %s",
			    val_to_str(option_number, ipxwan_option_num_vals,
			        "Unknown (%u)"));
			option_tree = proto_item_add_subtree(ti,
			    ett_ipxwan_option);

			proto_tree_add_uint(option_tree, hf_ipxwan_option_num,
			    tvb, offset, 1, option_number);
			offset += 1;
			proto_tree_add_item(option_tree, hf_ipxwan_accept_option,
			    tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			option_data_len = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(option_tree, hf_ipxwan_option_data_len,
			    tvb, offset, 2, option_data_len);
			offset += 2;
			proto_item_set_len(ti, option_data_len+4);
			switch (option_number) {

			case OPT_ROUTING_TYPE:
				if (option_data_len != 1) {
					proto_tree_add_text(option_tree,
					    tvb, offset, option_data_len,
					    "Bogus length: %u, should be 1",
					    option_data_len);
				} else {
					proto_tree_add_item(option_tree,
					    hf_ipxwan_routing_type, tvb,
					    offset, 1, ENC_BIG_ENDIAN);
				}
				break;

			case OPT_RIP_SAP_INFO_EXCHANGE:
				if (option_data_len != 54) {
					proto_tree_add_text(option_tree,
					    tvb, offset, option_data_len,
					    "Bogus length: %u, should be 54",
					    option_data_len);
				} else {
					wan_link_delay = tvb_get_ntohs(tvb,
					    offset);
					proto_tree_add_uint_format(option_tree,
					    hf_ipxwan_wan_link_delay, tvb,
					    offset, 2, wan_link_delay,
					    "WAN Link Delay: %ums",
					    wan_link_delay);
					proto_tree_add_item(option_tree,
					    hf_ipxwan_common_network_number,
					    tvb, offset+2, 4, ENC_NA);
					proto_tree_add_item(option_tree,
					    hf_ipxwan_router_name, tvb,
					    offset+6, 48, ENC_ASCII|ENC_NA);
				}
				break;

			case OPT_NLSP_INFORMATION:
				if (option_data_len != 8) {
					proto_tree_add_text(option_tree,
					    tvb, offset, option_data_len,
					    "Bogus length: %u, should be 8",
					    option_data_len);
				} else {
					delay = tvb_get_ntohl(tvb, offset);
					proto_tree_add_uint_format(option_tree,
					    hf_ipxwan_delay, tvb,
					    offset, 4, delay,
					    "Delay: %uus", delay);
					throughput = tvb_get_ntohl(tvb, offset);
					proto_tree_add_uint_format(option_tree,
					    hf_ipxwan_throughput, tvb,
					    offset, 4, throughput,
					    "Throughput: %uus",
					    throughput);
				}
				break;

			case OPT_NLSP_RAW_THROUGHPUT_DATA:
				if (option_data_len != 8) {
					proto_tree_add_text(option_tree,
					    tvb, offset, option_data_len,
					    "Bogus length: %u, should be 8",
					    option_data_len);
				} else {
					proto_tree_add_item(option_tree,
					    hf_ipxwan_request_size, tvb,
					    offset, 4, ENC_BIG_ENDIAN);
					delta_time = tvb_get_ntohl(tvb, offset);
					proto_tree_add_uint_format(option_tree,
					    hf_ipxwan_delta_time, tvb,
					    offset, 4, delta_time,
					    "Delta Time: %uus",
					    delta_time);
				}
				break;

			case OPT_EXTENDED_NODE_ID:
				if (option_data_len != 4) {
					proto_tree_add_text(option_tree,
					    tvb, offset, option_data_len,
					    "Bogus length: %u, should be 4",
					    option_data_len);
				} else {
					proto_tree_add_item(option_tree,
					    hf_ipxwan_extended_node_id, tvb,
					    offset, 4, ENC_NA);
				}
				break;

			case OPT_NODE_NUMBER:
				if (option_data_len != 6) {
					proto_tree_add_text(option_tree,
					    tvb, offset, option_data_len,
					    "Bogus length: %u, should be 6",
					    option_data_len);
				} else {
					proto_tree_add_item(option_tree,
					    hf_ipxwan_node_number, tvb,
					    offset, 6, FALSE);
				}
				break;

			case OPT_COMPRESSION:
				if (option_data_len < 1) {
					proto_tree_add_text(option_tree,
					    tvb, offset, option_data_len,
					    "Bogus length: %u, should be >= 1",
					    option_data_len);
				} else {
					compression_type = tvb_get_guint8(tvb,
					    offset);
					proto_tree_add_uint(option_tree,
					    hf_ipxwan_compression_type, tvb,
					    offset, 1, compression_type);
					switch (compression_type) {

					case COMP_TYPE_TELEBIT:
						if (option_data_len < 3) {
							proto_tree_add_text(option_tree,
							    tvb, offset+1,
							    option_data_len-1,
							    "Bogus length: %u, should be >= 3",
							    option_data_len);
						} else {
							proto_tree_add_text(
							    option_tree,
							    tvb, offset+1, 1,
							    "Compression options: 0x%02x",
							    tvb_get_guint8(tvb,
							        offset+1));
							proto_tree_add_text(
							    option_tree,
							    tvb, offset+2, 1,
							    "Number of compression slots: %u",
							    tvb_get_guint8(tvb,
							        offset+2));
						}
						break;

					default:
						proto_tree_add_text(option_tree,
						    tvb, offset+1,
						    option_data_len-1,
						    "Option parameters");
						break;
					}
				}
				break;

			case OPT_PAD:
				proto_tree_add_text(option_tree,
				    tvb, offset, option_data_len,
				    "Padding");
				break;

			default:
				proto_tree_add_text(option_tree,
				    tvb, offset, option_data_len,
				    "Option value");
				break;
			}

			offset += option_data_len;
			num_options--;
		}
	}
}

void
proto_register_ipxwan(void)
{
	static hf_register_info hf[] = {
	    { &hf_ipxwan_identifier,
	      { "Identifier",	"ipxwan.identifier",
		FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_packet_type,
	      { "Packet Type", "ipxwan.packet_type",
	        FT_UINT8, BASE_DEC, VALS(ipxwan_packet_type_vals), 0x0, NULL,
	        HFILL }},

	    { &hf_ipxwan_node_id,
	      { "Node ID", "ipxwan.node_id", FT_UINT32,
	         BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_sequence_number,
	      { "Sequence Number", "ipxwan.sequence_number", FT_UINT8,
	         BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_num_options,
	      { "Number of Options", "ipxwan.num_options", FT_UINT8,
	         BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_option_num,
	      { "Option Number", "ipxwan.option_num", FT_UINT8,
	         BASE_HEX, VALS(ipxwan_option_num_vals), 0x0, NULL, HFILL }},

	    { &hf_ipxwan_accept_option,
	      { "Accept Option", "ipxwan.accept_option", FT_UINT8,
	         BASE_DEC, VALS(ipxwan_accept_option_vals), 0x0, NULL, HFILL }},

	    { &hf_ipxwan_option_data_len,
	      { "Option Data Length", "ipxwan.option_data_len", FT_UINT16,
	         BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_routing_type,
	      { "Routing Type", "ipxwan.routing_type", FT_UINT8,
	         BASE_DEC, VALS(ipxwan_routing_type_vals), 0x0, NULL, HFILL }},

	    { &hf_ipxwan_wan_link_delay,
	      { "WAN Link Delay", "ipxwan.rip_sap_info_exchange.wan_link_delay",
	         FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_common_network_number,
	      { "Common Network Number", "ipxwan.rip_sap_info_exchange.common_network_number",
	         FT_IPXNET, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_router_name,
	      { "Router Name", "ipxwan.rip_sap_info_exchange.router_name",
	         FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_delay,
	      { "Delay", "ipxwan.nlsp_information.delay",
	         FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_throughput,
	      { "Throughput", "ipxwan.nlsp_information.throughput",
	         FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_request_size,
	      { "Request Size", "ipxwan.nlsp_raw_throughput_data.request_size",
	         FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_delta_time,
	      { "Delta Time", "ipxwan.nlsp_raw_throughput_data.delta_time",
	         FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_extended_node_id,
	      { "Extended Node ID", "ipxwan.extended_node_id",
	         FT_IPXNET, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_node_number,
	      { "Node Number", "ipxwan.node_number",
	         FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL }},

	    { &hf_ipxwan_compression_type,
	      { "Compression Type", "ipxwan.compression.type",
	         FT_UINT8, BASE_DEC, VALS(ipxwan_compression_type_vals), 0x0,
	         NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_ipxwan,
		&ett_ipxwan_option,
	};

	proto_ipxwan = proto_register_protocol("IPX WAN", "IPX WAN", "ipxwan");
	proto_register_field_array(proto_ipxwan, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ipxwan(void)
{
	dissector_handle_t ipxwan_handle;

	ipxwan_handle = create_dissector_handle(dissect_ipxwan,
	    proto_ipxwan);
	dissector_add_uint("ipx.socket", IPX_SOCKET_IPXWAN, ipxwan_handle);
}
